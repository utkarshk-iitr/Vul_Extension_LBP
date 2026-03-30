import torch
import numpy as np
import warnings
import os
import sys
import json
import argparse
import tempfile
from transformers import RobertaConfig, RobertaModel, RobertaTokenizer, RobertaTokenizerFast
from transformers import RobertaForSequenceClassification
from transformers.utils import logging as hf_logging
from captum.attr import LayerIntegratedGradients

warnings.filterwarnings("ignore")
hf_logging.set_verbosity_error()

# ============================================================================
# CONFIGURATION & PATH SETUP
# ============================================================================

# Paths updated for Desktop/vul_extension execution
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DESKTOP_DIR = os.path.dirname(SCRIPT_DIR)
MODEL_PATH = os.path.join(DESKTOP_DIR, "analysis_vulnerability", "multiview_exps", "four", "mixt", "saved_models", "checkpoint-best-f1", "new7_multiv_moe_10.bin")
MOE_MODULE_PATH = os.path.join(DESKTOP_DIR, "analysis_vulnerability", "multiview_exps", "four", "mixt")
SA_VAF_PATH = os.path.join(DESKTOP_DIR, "analysis_vulnerability", "SA-VAF", "test.sc")
LINEVUL_MODULE_PATH = os.path.join(DESKTOP_DIR, "analysis_vulnerability", "LineVul", "linevul")
LINEVUL_MODEL_PATH = os.path.join(DESKTOP_DIR, "analysis_vulnerability", "LineVul", "linevul", "saved_models", "checkpoint-best-f1", "model.bin")

# Add moe module path to sys.path BEFORE importing
if MOE_MODULE_PATH not in sys.path:
    sys.path.insert(0, MOE_MODULE_PATH)
if LINEVUL_MODULE_PATH not in sys.path:
    sys.path.insert(0, LINEVUL_MODULE_PATH)

# Now import MoEModel after path is set
from moe import MoEModel
from linevul_model import Model as LineVulModel

MODEL_NAME_OR_PATH = "microsoft/graphcodebert-base"
TOKENIZER_NAME = "neulab/codebert-cpp"
LINEVUL_BASE_MODEL = "neulab/codebert-cpp"
BLOCK_SIZE = 512
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ============================================================================
# STEP 1: SETUP - Load Tokenizers and Config
# ============================================================================

raw_tokenizer = RobertaTokenizerFast.from_pretrained(TOKENIZER_NAME)
ast_tokenizer = RobertaTokenizer.from_pretrained(MODEL_NAME_OR_PATH)
pdg_tokenizer = RobertaTokenizer.from_pretrained(MODEL_NAME_OR_PATH)
cfg_tokenizer = RobertaTokenizer.from_pretrained(MODEL_NAME_OR_PATH)

config = RobertaConfig.from_pretrained(MODEL_NAME_OR_PATH)
config.num_labels = 2

# ============================================================================
# STEP 2: LOAD ENCODERS AND CREATE MODEL
# ============================================================================

encoder_raw = RobertaModel.from_pretrained(TOKENIZER_NAME, config=config)
encoder_ast = RobertaModel.from_pretrained(MODEL_NAME_OR_PATH, config=config)
encoder_cfg = RobertaModel.from_pretrained(MODEL_NAME_OR_PATH, config=config)
encoder_pdg = RobertaModel.from_pretrained(MODEL_NAME_OR_PATH, config=config)

model = MoEModel(encoder_raw, encoder_ast, encoder_pdg, encoder_cfg, config, None)
model.to(DEVICE)

# Load trained weights
model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE), strict=False)
model.eval()

# Load LineVul model for line-level localization
linevul_tokenizer = RobertaTokenizerFast.from_pretrained(LINEVUL_BASE_MODEL)
linevul_config = RobertaConfig.from_pretrained(LINEVUL_BASE_MODEL)
linevul_config.num_labels = 1
linevul_encoder = RobertaForSequenceClassification.from_pretrained(
    LINEVUL_BASE_MODEL,
    config=linevul_config,
    ignore_mismatched_sizes=True,
)
linevul_model = LineVulModel(linevul_encoder, linevul_config, linevul_tokenizer, None)
linevul_model.load_state_dict(torch.load(LINEVUL_MODEL_PATH, map_location=DEVICE), strict=False)
linevul_model.to(DEVICE)
linevul_model.eval()

# ============================================================================
# STEP 3: TOKENIZATION HELPER FUNCTION
# ============================================================================

def tokenize_and_pad(text, tokenizer, block_size=512):
    """Tokenize text and pad to block_size."""
    tokens = tokenizer.tokenize(str(text))[:block_size - 2]
    tokens = [tokenizer.cls_token] + tokens + [tokenizer.sep_token]
    ids = tokenizer.convert_tokens_to_ids(tokens)
    ids += [tokenizer.pad_token_id] * (block_size - len(ids))
    return torch.tensor(ids[:block_size])


def tokenize_raw_with_offsets(text, tokenizer, block_size=512):
    """Tokenize raw code with offsets for line attribution mapping."""
    encoding = tokenizer(
        str(text),
        add_special_tokens=True,
        truncation=True,
        max_length=block_size,
        padding="max_length",
        return_offsets_mapping=True,
        return_tensors="pt",
    )
    input_ids = encoding["input_ids"][0]
    attention_mask = encoding["attention_mask"][0]
    offsets = encoding["offset_mapping"][0].tolist()
    return input_ids, attention_mask, offsets

# ============================================================================
# STEP 4: INFERENCE FUNCTION
# ============================================================================

class RawOnlyAttributionWrapper(torch.nn.Module):
    """Wrapper to compute attribution on raw input while keeping graph views fixed."""

    def __init__(self, base_model):
        super().__init__()
        self.base_model = base_model

    def forward(
        self,
        input_ids_raw,
        attention_mask_raw,
        input_ids_ast,
        attention_mask_ast,
        input_ids_pdg,
        attention_mask_pdg,
        input_ids_cfg,
        attention_mask_cfg,
    ):
        probs = self.base_model(
            input_ids_raw=input_ids_raw,
            attention_mask_raw=attention_mask_raw,
            input_ids_ast=input_ids_ast,
            attention_mask_ast=attention_mask_ast,
            input_ids_pdg=input_ids_pdg,
            attention_mask_pdg=attention_mask_pdg,
            input_ids_cfg=input_ids_cfg,
            attention_mask_cfg=attention_mask_cfg,
            labels=None,
        )
        return probs


def get_vulnerable_line_numbers(raw_code, raw_ids, attention_mask_raw, ast_ids, attention_mask_ast, pdg_ids, attention_mask_pdg, cfg_ids, attention_mask_cfg):
    """Estimate vulnerable line numbers using Integrated Gradients on raw-code embeddings."""
    wrapper = RawOnlyAttributionWrapper(model).to(DEVICE)
    wrapper.eval()

    lig = LayerIntegratedGradients(wrapper, wrapper.base_model.encoder_raw.embeddings.word_embeddings)
    baseline_ids = torch.full_like(raw_ids, fill_value=raw_tokenizer.pad_token_id)

    attributions, _ = lig.attribute(
        inputs=raw_ids,
        baselines=baseline_ids,
        additional_forward_args=(
            attention_mask_raw,
            ast_ids,
            attention_mask_ast,
            pdg_ids,
            attention_mask_pdg,
            cfg_ids,
            attention_mask_cfg,
        ),
        target=1,
        return_convergence_delta=True,
    )

    token_scores = np.abs(attributions.sum(dim=-1).squeeze(0).detach().cpu().numpy())
    offsets = raw_tokenizer(
        str(raw_code),
        add_special_tokens=True,
        truncation=True,
        max_length=BLOCK_SIZE,
        padding="max_length",
        return_offsets_mapping=True,
    )["offset_mapping"]

    line_scores = {}
    cumulative_newlines = [0]
    for ch in raw_code:
        cumulative_newlines.append(cumulative_newlines[-1] + (1 if ch == "\n" else 0))

    def char_to_line(idx):
        idx = max(0, min(idx, len(raw_code)))
        return cumulative_newlines[idx] + 1

    for i, (start, end) in enumerate(offsets):
        if i >= len(token_scores):
            break
        if start == end:
            continue
        if i < attention_mask_raw.size(1) and int(attention_mask_raw[0, i].item()) == 0:
            continue

        score = float(token_scores[i])

        start_line = char_to_line(start)
        end_line = char_to_line(max(start, end - 1))
        for ln in range(start_line, end_line + 1):
            line_scores[ln] = line_scores.get(ln, 0.0) + score

    if not line_scores:
        return []

    sorted_lines = sorted(line_scores.items(), key=lambda x: x[1], reverse=True)
    max_lines = min(10, len(sorted_lines))
    arr = [ln for ln, _ in sorted_lines[:max_lines]]
    return sorted(arr)


def get_vulnerable_line_numbers_linevul(raw_code):
    """Use LineVul checkpoint to get line-level vulnerability ranking."""
    if not raw_code.strip():
        return []

    encoding = linevul_tokenizer(
        raw_code,
        add_special_tokens=True,
        truncation=True,
        max_length=BLOCK_SIZE,
        padding="max_length",
        return_offsets_mapping=True,
        return_tensors="pt",
    )
    input_ids = encoding["input_ids"].to(DEVICE)
    offsets = encoding["offset_mapping"][0].tolist()

    def lig_forward(ids):
        probs = linevul_model(input_ids=ids)
        return probs[:, 1]

    ref_input_ids = torch.full_like(input_ids, fill_value=linevul_tokenizer.pad_token_id)
    lig = LayerIntegratedGradients(lig_forward, linevul_model.encoder.roberta.embeddings)
    attributions, _ = lig.attribute(
        inputs=input_ids,
        baselines=ref_input_ids,
        target=None,
        return_convergence_delta=True,
        internal_batch_size=1,
    )

    token_scores = attributions.sum(dim=-1).squeeze(0)
    token_scores = token_scores / (torch.norm(token_scores) + 1e-12)
    token_scores = torch.abs(token_scores).detach().cpu().numpy()

    line_scores = {}
    cumulative_newlines = [0]
    for ch in raw_code:
        cumulative_newlines.append(cumulative_newlines[-1] + (1 if ch == "\n" else 0))

    def char_to_line(idx):
        idx = max(0, min(idx, len(raw_code)))
        return cumulative_newlines[idx] + 1

    for i, (start, end) in enumerate(offsets):
        if i >= len(token_scores):
            break
        if start == end:
            continue
        score = float(token_scores[i])
        if score <= 0:
            continue
        start_line = char_to_line(start)
        end_line = char_to_line(max(start, end - 1))
        for ln in range(start_line, end_line + 1):
            line_scores[ln] = line_scores.get(ln, 0.0) + score

    if not line_scores:
        return []

    ranked = sorted(line_scores.items(), key=lambda x: x[1], reverse=True)
    top_k = min(10, len(ranked))
    return sorted([ln for ln, _ in ranked[:top_k]])


def _vulnerable_probability_from_views(raw_ids, attention_mask_raw, ast_ids, attention_mask_ast, pdg_ids, attention_mask_pdg, cfg_ids, attention_mask_cfg):
    with torch.no_grad():
        probs = model(
            input_ids_raw=raw_ids,
            attention_mask_raw=attention_mask_raw,
            input_ids_ast=ast_ids,
            attention_mask_ast=attention_mask_ast,
            input_ids_pdg=pdg_ids,
            attention_mask_pdg=attention_mask_pdg,
            input_ids_cfg=cfg_ids,
            attention_mask_cfg=attention_mask_cfg,
            labels=None,
        )
    return float(probs[0, 1].detach().cpu().item())


def get_vulnerable_line_numbers_by_ablation(raw_code, base_prob, ast_ids, attention_mask_ast, pdg_ids, attention_mask_pdg, cfg_ids, attention_mask_cfg):
    """Fallback: score each line by vulnerability drop when that line is removed."""
    lines = raw_code.splitlines()
    if not lines:
        return []

    line_impacts = []
    for idx in range(len(lines)):
        if not lines[idx].strip():
            continue
        modified = lines.copy()
        modified[idx] = ""
        modified_code = "\n".join(modified)

        mod_raw_ids, mod_attention_mask, _ = tokenize_raw_with_offsets(modified_code, raw_tokenizer, BLOCK_SIZE)
        mod_raw_ids = mod_raw_ids.unsqueeze(0).to(DEVICE)
        mod_attention_mask = mod_attention_mask.unsqueeze(0).to(DEVICE)

        mod_prob = _vulnerable_probability_from_views(
            mod_raw_ids,
            mod_attention_mask,
            ast_ids,
            attention_mask_ast,
            pdg_ids,
            attention_mask_pdg,
            cfg_ids,
            attention_mask_cfg,
        )
        impact = base_prob - mod_prob
        line_impacts.append((idx + 1, impact))

    if not line_impacts:
        return []

    positive = [(ln, sc) for ln, sc in line_impacts if sc > 0]
    ranked = positive if positive else sorted(line_impacts, key=lambda x: abs(x[1]), reverse=True)
    ranked = sorted(ranked, key=lambda x: x[1], reverse=True)
    max_lines = min(10, len(ranked))
    return [ln for ln, _ in ranked[:max_lines]]


def predict_vulnerability(raw_code, ast_repr, pdg_repr, cfg_repr):
    """
    Predict vulnerability for a single code sample.
    
    Args:
        raw_code (str): Raw code as string
        ast_repr (str): AST representation as string
        pdg_repr (str): PDG representation as string
        cfg_repr (str): CFG representation as string
    
    Returns:
        dict: Contains predictions, probabilities, and label
    """
    # Tokenize all 4 views
    raw_ids, attention_mask_raw, _ = tokenize_raw_with_offsets(raw_code, raw_tokenizer, BLOCK_SIZE)
    raw_ids = raw_ids.unsqueeze(0).to(DEVICE)
    attention_mask_raw = attention_mask_raw.unsqueeze(0).to(DEVICE)
    ast_ids = tokenize_and_pad(ast_repr, ast_tokenizer, BLOCK_SIZE).unsqueeze(0).to(DEVICE)
    pdg_ids = tokenize_and_pad(pdg_repr, pdg_tokenizer, BLOCK_SIZE).unsqueeze(0).to(DEVICE)
    cfg_ids = tokenize_and_pad(cfg_repr, cfg_tokenizer, BLOCK_SIZE).unsqueeze(0).to(DEVICE)
    
    # Create attention masks (0 for padding tokens, 1 for actual tokens)
    attention_mask_ast = ast_ids.ne(1).long()
    attention_mask_pdg = pdg_ids.ne(1).long()
    attention_mask_cfg = cfg_ids.ne(1).long()
    
    # Forward pass
    base_prob = _vulnerable_probability_from_views(
        raw_ids,
        attention_mask_raw,
        ast_ids,
        attention_mask_ast,
        pdg_ids,
        attention_mask_pdg,
        cfg_ids,
        attention_mask_cfg,
    )

    # Use LineVul model for line-level localization first
    vulnerable_lines = []
    try:
        vulnerable_lines = get_vulnerable_line_numbers_linevul(raw_code)
    except Exception:
        vulnerable_lines = []

    # Fallback to existing MoE attribution path
    if not vulnerable_lines:
        try:
            vulnerable_lines = get_vulnerable_line_numbers(
                raw_code,
                raw_ids,
                attention_mask_raw,
                ast_ids,
                attention_mask_ast,
                pdg_ids,
                attention_mask_pdg,
                cfg_ids,
                attention_mask_cfg,
            )
        except Exception:
            vulnerable_lines = []

    # Final fallback when both attribution paths fail
    if not vulnerable_lines:
        vulnerable_lines = get_vulnerable_line_numbers_by_ablation(
            raw_code,
            base_prob,
            ast_ids,
            attention_mask_ast,
            pdg_ids,
            attention_mask_pdg,
            cfg_ids,
            attention_mask_cfg,
        )
    
    return {
        "vulnerable_probability": float(base_prob),
        "vulnerable_lines": vulnerable_lines,
    }


# ============================================================================
# MAIN: Accept raw code, generate AST/PDG/CFG, and run inference
# ============================================================================

def generate_graphs_via_joern(raw_code):
    """
    Run Joern to generate AST, PDG, and CFG from the source code.
    Uses per-request temporary directory to avoid filename collisions.
    """
    import subprocess
    
    with tempfile.TemporaryDirectory(prefix="vul_infer_single_") as tmpdir:
        temp_code_file = os.path.join(tmpdir, "input.c")
        cpg_file = os.path.join(tmpdir, "app.cpg")
        ast_file = os.path.join(tmpdir, "ast.dot")
        pdg_file = os.path.join(tmpdir, "pdg.dot")
        cfg_file = os.path.join(tmpdir, "cfg.dot")

        with open(temp_code_file, "w", encoding="utf-8") as f:
            f.write(raw_code)

        subprocess.run(
            ["joern-parse", temp_code_file, "--output", cpg_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=tmpdir,
        )
        
        joern_cmd = [
            "joern",
            "--script", SA_VAF_PATH,
            "--param", f"cpgFile={cpg_file}",
            "--param", f"outFileast={ast_file}",
            "--param", f"outFilepdg={pdg_file}",
            "--param", f"outFilecfg={cfg_file}",
        ]
        subprocess.run(joern_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=tmpdir)
        
        with open(ast_file, 'r', encoding='utf-8') as f: ast_repr = f.read()
        with open(pdg_file, 'r', encoding='utf-8') as f: pdg_repr = f.read()
        with open(cfg_file, 'r', encoding='utf-8') as f: cfg_repr = f.read()
        
    return ast_repr, pdg_repr, cfg_repr


def parse_cli_args():
    parser = argparse.ArgumentParser(description="Single-code vulnerability inference")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--raw-code", type=str, help="Raw source code as a string")
    group.add_argument("--code-file", type=str, help="Path to file containing source code")
    group.add_argument("--stdin", action="store_true", help="Read raw code from stdin")
    parser.add_argument("--output-file", type=str, default=None, help="Optional JSON output file path")
    parser.add_argument("--compact-json", action="store_true", help="Print compact JSON")
    return parser.parse_args()


def get_raw_code_from_args(args):
    if args.stdin:
        raw_code = sys.stdin.read()
    elif args.code_file:
        with open(args.code_file, "r", encoding="utf-8") as f:
            raw_code = f.read()
    else:
        raw_code = args.raw_code or ""

    if not raw_code.strip():
        raise ValueError("No input code provided. Use --stdin, --raw-code, or --code-file.")
    return raw_code

def main():
    args = parse_cli_args()
    try:
        raw_code = get_raw_code_from_args(args)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)

    # Generate graphs
    try:
        ast_repr, pdg_repr, cfg_repr = generate_graphs_via_joern(raw_code)
    except Exception:
        ast_repr = "AST_GEN_ERROR"
        pdg_repr = "PDG_GEN_ERROR"
        cfg_repr = "CFG_GEN_ERROR"

    result = predict_vulnerability(raw_code, ast_repr, pdg_repr, cfg_repr)

    json_output = {
        "vulnerable_probability": result["vulnerable_probability"],
        "vulnerable_lines": result["vulnerable_lines"],
    }
    if args.compact_json:
        print(json.dumps(json_output, separators=(",", ":")))
    else:
        print(json.dumps(json_output, indent=2))

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            json.dump(json_output, f, indent=2)

if __name__ == "__main__":
    main()
