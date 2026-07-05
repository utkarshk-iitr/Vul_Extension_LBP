import torch
import numpy as np
import warnings
import os
import sys
import json
import argparse
import socketserver
import tempfile
import re
import hashlib
from transformers import RobertaConfig, RobertaModel, RobertaTokenizer, RobertaTokenizerFast
from transformers.utils import logging as hf_logging
from captum.attr import LayerIntegratedGradients

warnings.filterwarnings("ignore")
hf_logging.set_verbosity_error()


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DESKTOP_DIR = os.path.dirname(SCRIPT_DIR)
MODEL_PATH = os.path.join(DESKTOP_DIR, "analysis_vulnerability", "multiview_exps", "four", "mixt", "saved_models", "checkpoint-best-f1", "new7_multiv_moe_10.bin")
MOE_MODULE_PATH = os.path.join(DESKTOP_DIR, "analysis_vulnerability", "multiview_exps", "four", "mixt")
SA_VAF_PATH = os.path.join(DESKTOP_DIR, "analysis_vulnerability", "SA-VAF", "test.sc")

if MOE_MODULE_PATH not in sys.path:
    sys.path.insert(0, MOE_MODULE_PATH)

from moe import MoEModel

MODEL_NAME_OR_PATH = "microsoft/graphcodebert-base"
TOKENIZER_NAME = "neulab/codebert-cpp"
BLOCK_SIZE = 512
FORCE_CPU = str(os.getenv("VUL_FORCE_CPU", "")).strip().lower() in {"1", "true", "yes", "on"}
DEVICE = torch.device("cpu" if FORCE_CPU else ("cuda" if torch.cuda.is_available() else "cpu"))

GENERIC_RISK_PATTERNS = [
    "strcpy(", "strcat(", "sprintf(", "gets(", "memcpy(", "memmove(",
    "malloc(", "calloc(", "realloc(", "free(", "scanf(", "fscanf(",
    "read(", "write(", "system(", "exec", "->", "[", "%n",
]
GENERIC_RISK_KEYWORDS = {
    "overflow", "underflow", "bounds", "buffer", "format", "pointer", "null",
    "integer", "race", "thread", "lock", "unlock", "permission", "auth",
    "injection", "command", "path", "symlink", "double", "free", "use-after-free",
    "taint", "input", "validation", "sanitize", "deserialization", "crypto",
    "overflowing", "unsafe", "copy", "size", "index", "offset", "length",
}

GRAPH_CACHE = {}
GRAPH_CACHE_ORDER = []
RESULT_CACHE = {}
RESULT_CACHE_ORDER = []
MAX_GRAPH_CACHE = 32
MAX_RESULT_CACHE = 64



def _cache_put(cache, order, key, value, max_size):
    if key in cache:
        cache[key] = value
        return
    cache[key] = value
    order.append(key)
    if len(order) > max_size:
        oldest = order.pop(0)
        cache.pop(oldest, None)


def _hash_code(raw_code):
    return hashlib.sha256(str(raw_code).encode("utf-8")).hexdigest()


def _token_set(text):
    return set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_\-]*", str(text).lower()))


def _dedupe_preserve_order(values):
    seen = set()
    ordered = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _normalize_vulnerable_lines(raw_code, lines):
    total_lines = max(1, len(str(raw_code).splitlines()))
    numeric = []
    for value in (lines or []):
        try:
            numeric.append(int(value))
        except Exception:
            continue

    if not numeric:
        return []

    one_based = [line for line in numeric if 1 <= line <= total_lines]
    zero_based = [line + 1 for line in numeric if 0 <= line < total_lines]

    has_explicit_zero = any(line == 0 for line in numeric)
    if has_explicit_zero and len(zero_based) >= len(one_based):
        return _dedupe_preserve_order(zero_based)
    if one_based:
        return _dedupe_preserve_order(one_based)
    return _dedupe_preserve_order(zero_based)


def _score_line_risk(line_text):
    text = str(line_text).strip().lower()
    if not text:
        return 0.0
    if text.startswith("//") or text.startswith("/*") or text.startswith("*"):
        return 0.0

    score = 0.0
    for pattern in GENERIC_RISK_PATTERNS:
        if pattern and pattern in text:
            score += min(2.5, max(0.3, len(pattern) / 7.0))

    keyword_hits = len(_token_set(text).intersection(GENERIC_RISK_KEYWORDS))
    score += min(2.0, 0.35 * keyword_hits)

    if "=" in text and any(tok in text for tok in ["malloc(", "calloc(", "realloc("]):
        score += 0.75
    if any(tok in text for tok in ["strcpy(", "strcat(", "sprintf(", "printf("]):
        score += 0.75
    return score


def _refine_focus_line(raw_code, anchor_line, window):
    lines = str(raw_code).splitlines()
    if not lines:
        return int(anchor_line)

    anchor = max(1, min(int(anchor_line), len(lines)))
    start = max(1, anchor - max(1, int(window)))
    end = min(len(lines), anchor + max(1, int(window)))

    best_line = anchor
    best_score = _score_line_risk(lines[anchor - 1])
    for ln in range(start, end + 1):
        score = _score_line_risk(lines[ln - 1])
        if score > best_score:
            best_line = ln
            best_score = score
        elif score == best_score and abs(ln - anchor) < abs(best_line - anchor):
            best_line = ln

    return best_line


def _refine_vulnerable_lines(raw_code, vulnerable_lines, window=4, max_lines=5):
    refined = []
    for line_no in vulnerable_lines:
        try:
            anchor = int(line_no)
        except Exception:
            continue
        refined_line = _refine_focus_line(raw_code, anchor, window)
        if refined_line not in refined:
            refined.append(refined_line)
        if len(refined) >= max(1, int(max_lines)):
            break
    return refined



raw_tokenizer = RobertaTokenizerFast.from_pretrained(TOKENIZER_NAME)
ast_tokenizer = RobertaTokenizer.from_pretrained(MODEL_NAME_OR_PATH)
pdg_tokenizer = RobertaTokenizer.from_pretrained(MODEL_NAME_OR_PATH)
cfg_tokenizer = RobertaTokenizer.from_pretrained(MODEL_NAME_OR_PATH)

config = RobertaConfig.from_pretrained(MODEL_NAME_OR_PATH)
config.num_labels = 2


encoder_raw = RobertaModel.from_pretrained(TOKENIZER_NAME, config=config)
encoder_ast = RobertaModel.from_pretrained(MODEL_NAME_OR_PATH, config=config)
encoder_cfg = RobertaModel.from_pretrained(MODEL_NAME_OR_PATH, config=config)
encoder_pdg = RobertaModel.from_pretrained(MODEL_NAME_OR_PATH, config=config)

model = MoEModel(encoder_raw, encoder_ast, encoder_pdg, encoder_cfg, config, None)

model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"), strict=False)
model.to(DEVICE)
model.eval()



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
    return [ln for ln, _ in sorted_lines[:max_lines]]


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
        dict: Contains vulnerable_probability, vulnerable_lines, detection_method
    """
    raw_ids, attention_mask_raw, _ = tokenize_raw_with_offsets(raw_code, raw_tokenizer, BLOCK_SIZE)
    raw_ids = raw_ids.unsqueeze(0).to(DEVICE)
    attention_mask_raw = attention_mask_raw.unsqueeze(0).to(DEVICE)
    ast_ids = tokenize_and_pad(ast_repr, ast_tokenizer, BLOCK_SIZE).unsqueeze(0).to(DEVICE)
    pdg_ids = tokenize_and_pad(pdg_repr, pdg_tokenizer, BLOCK_SIZE).unsqueeze(0).to(DEVICE)
    cfg_ids = tokenize_and_pad(cfg_repr, cfg_tokenizer, BLOCK_SIZE).unsqueeze(0).to(DEVICE)

    attention_mask_ast = ast_ids.ne(1).long()
    attention_mask_pdg = pdg_ids.ne(1).long()
    attention_mask_cfg = cfg_ids.ne(1).long()

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

    vulnerable_lines = []
    detection_method = "none"

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
        if vulnerable_lines:
            detection_method = "moe_attribution"
    except Exception:
        vulnerable_lines = []

    if not vulnerable_lines:
        try:
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
            if vulnerable_lines:
                detection_method = "ablation"
        except Exception:
            vulnerable_lines = []

    vulnerable_lines = _normalize_vulnerable_lines(raw_code, vulnerable_lines)
    vulnerable_lines = _refine_vulnerable_lines(raw_code, vulnerable_lines)

    return {
        "vulnerable_probability": float(base_prob),
        "vulnerable_lines": vulnerable_lines,
        "detection_method": detection_method,
    }




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


def generate_graphs_cached(raw_code):
    code_key = _hash_code(raw_code)
    cached = GRAPH_CACHE.get(code_key)
    if cached:
        return cached
    ast_repr, pdg_repr, cfg_repr = generate_graphs_via_joern(raw_code)
    _cache_put(GRAPH_CACHE, GRAPH_CACHE_ORDER, code_key, (ast_repr, pdg_repr, cfg_repr), MAX_GRAPH_CACHE)
    return ast_repr, pdg_repr, cfg_repr




def parse_cli_args():
    parser = argparse.ArgumentParser(description="Single-code vulnerability inference")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--raw-code", type=str, help="Raw source code as a string")
    group.add_argument("--code-file", type=str, help="Path to file containing source code")
    group.add_argument("--stdin", action="store_true", help="Read raw code from stdin")
    parser.add_argument("--output-file", type=str, default=None, help="Optional JSON output file path")
    parser.add_argument("--compact-json", action="store_true", help="Print compact JSON")
    parser.add_argument("--server", action="store_true", help="Run as a persistent inference server")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Server bind host")
    parser.add_argument("--port", type=int, default=9079, help="Server bind port")
    return parser.parse_args()


def get_raw_code_from_args(args):
    if args.server:
        return ""
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


def build_json_output(raw_code):
    try:
        ast_repr, pdg_repr, cfg_repr = generate_graphs_cached(raw_code)
    except Exception:
        ast_repr = "AST_GEN_ERROR"
        pdg_repr = "PDG_GEN_ERROR"
        cfg_repr = "CFG_GEN_ERROR"

    result = predict_vulnerability(raw_code, ast_repr, pdg_repr, cfg_repr)

    return {
        "vulnerable_probability": result["vulnerable_probability"],
        "vulnerable_lines": result["vulnerable_lines"],
        "detection_method": result.get("detection_method", "none"),
    }


class InferenceRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline()
        if not line:
            return

        try:
            payload = json.loads(line.decode("utf-8"))
        except Exception:
            self.wfile.write(json.dumps({"ok": False, "error": "invalid_json"}).encode("utf-8") + b"\n")
            return

        if payload.get("ping") is True:
            self.wfile.write(json.dumps({"ok": True, "pong": True}).encode("utf-8") + b"\n")
            return

        raw_code = str(payload.get("code", ""))
        if not raw_code.strip():
            self.wfile.write(json.dumps({"ok": False, "error": "empty_code"}).encode("utf-8") + b"\n")
            return

        code_key = _hash_code(raw_code)
        cached = RESULT_CACHE.get(code_key)
        if cached:
            self.wfile.write(json.dumps({"ok": True, "result": cached}).encode("utf-8") + b"\n")
            return

        result = build_json_output(raw_code)
        _cache_put(RESULT_CACHE, RESULT_CACHE_ORDER, code_key, result, MAX_RESULT_CACHE)
        self.wfile.write(json.dumps({"ok": True, "result": result}).encode("utf-8") + b"\n")


def run_server(host, port):
    class ThreadedTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    with ThreadedTCPServer((host, int(port)), InferenceRequestHandler) as server:
        print(f"SERVER_READY {host}:{port}", flush=True)
        server.serve_forever()


def main():
    args = parse_cli_args()
    if args.server:
        run_server(args.host, args.port)
        return

    try:
        raw_code = get_raw_code_from_args(args)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)

    json_output = build_json_output(raw_code)
    if args.compact_json:
        print(json.dumps(json_output, separators=(",", ":")))
    else:
        print(json.dumps(json_output, indent=2))

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            json.dump(json_output, f, indent=2)


if __name__ == "__main__":
    main()
