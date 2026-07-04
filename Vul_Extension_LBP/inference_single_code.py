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
import time
import hashlib
import io
import zipfile
import xml.etree.ElementTree as ET
from urllib import request as urllib_request
from urllib import error as urllib_error
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
FORCE_CPU = str(os.getenv("VUL_FORCE_CPU", "")).strip().lower() in {"1", "true", "yes", "on"}
DEVICE = torch.device("cpu" if FORCE_CPU else ("cuda" if torch.cuda.is_available() else "cpu"))
CWE_CATALOG_CACHE_PATH = os.path.join(SCRIPT_DIR, "cwe_catalog_cache.json")
DEFAULT_CWE_CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
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
TEXT_STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "into", "used", "when",
    "where", "which", "while", "than", "then", "have", "has", "had", "using", "user",
    "code", "line", "lines", "data", "over", "under", "before", "after", "each",
    "only", "also", "such", "their", "there", "being", "between", "within", "without",
    "return", "error", "errors", "check", "checks", "value", "values", "valid", "invalid",
}
STATIC_VULN_RULES = [
    {
        "id": "rule-strcpy",
        "title": "Potential Buffer Overflow via strcpy",
        "cwe": "CWE-120",
        "explanation": "strcpy performs unbounded copy and can overflow the destination buffer.",
        "regex": re.compile(r"\bstrcpy\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)"),
        "severity": 3,
        "autofix_kind": "strcpy_to_strncpy",
    },
    {
        "id": "rule-strcat",
        "title": "Potential Buffer Overflow via strcat",
        "cwe": "CWE-120",
        "explanation": "strcat appends without verifying remaining destination capacity.",
        "regex": re.compile(r"\bstrcat\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)"),
        "severity": 3,
        "autofix_kind": "strcat_to_strncat",
    },
    {
        "id": "rule-sprintf",
        "title": "Unbounded Formatted Write via sprintf",
        "cwe": "CWE-787",
        "explanation": "sprintf can write beyond destination bounds when output exceeds buffer size.",
        "regex": re.compile(r"\bsprintf\s*\(\s*([^,]+?)\s*,\s*(.+?)\)\s*;?"),
        "severity": 3,
        "autofix_kind": "sprintf_to_snprintf",
    },
    {
        "id": "rule-gets",
        "title": "Unsafe Input via gets",
        "cwe": "CWE-242",
        "explanation": "gets cannot enforce input limits and should never be used.",
        "regex": re.compile(r"\bgets\s*\(\s*([^)]+?)\s*\)"),
        "severity": 3,
        "autofix_kind": "gets_to_fgets",
    },
    {
        "id": "rule-scanf-string",
        "title": "Potential Unbounded %s Read via scanf",
        "cwe": "CWE-120",
        "explanation": "scanf with %s and no width can overflow destination buffer.",
        "regex": re.compile(r'\bscanf\s*\(\s*"[^"]*%s[^"]*"'),
        "severity": 2,
        "autofix_kind": "scanf_add_width",
    },
    {
        "id": "rule-system",
        "title": "Command Execution Sink via system",
        "cwe": "CWE-78",
        "explanation": "system executes shell commands and can enable command injection if inputs are untrusted.",
        "regex": re.compile(r"\bsystem\s*\(\s*([^)]+?)\s*\)"),
        "severity": 2,
        "autofix_kind": "system_manual_hardening",
    },
]
RAG_CACHE = {}
GRAPH_CACHE = {}
GRAPH_CACHE_ORDER = []
RESULT_CACHE = {}
RESULT_CACHE_ORDER = []
MAX_GRAPH_CACHE = 32
MAX_RESULT_CACHE = 64
CWE_CATALOG_STATE = {
    "entries": None,
    "source": "uninitialized",
    "count": 0,
    "fetched_at": 0,
    "last_error": "",
}


def _env_bool(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _env_float(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _env_csv(name, default_values):
    value = os.getenv(name)
    if value is None:
        return list(default_values)
    parsed = [item.strip() for item in value.split(",") if item and item.strip()]
    return parsed if parsed else list(default_values)


def get_rag_runtime_config():
    prefer_cloud = _env_bool("VUL_MODEL_USE_CLOUD", True)
    local_model = os.getenv("VUL_OLLAMA_LOCAL_MODEL", "qwen2.5-coder:3b")
    cloud_model = os.getenv("VUL_OLLAMA_CLOUD_MODEL", "qwen3-coder:cloud")
    explicit_model = os.getenv("VUL_OLLAMA_MODEL")
    local_url = os.getenv("VUL_OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
    cloud_url = os.getenv("VUL_OLLAMA_CLOUD_URL", "")
    selected_model = explicit_model if explicit_model else (cloud_model if prefer_cloud else local_model)
    selected_url = (cloud_url.strip() if (prefer_cloud and cloud_url and cloud_url.strip()) else local_url)

    return {
        "enabled": _env_bool("VUL_RAG_ENABLED", True),
        "top_k": max(1, _env_int("VUL_RAG_TOP_K", 3)),
        "window": max(1, _env_int("VUL_RAG_WINDOW", 4)),
        "max_lines": max(1, _env_int("VUL_RAG_MAX_LINES", 5)),
        "cache_enabled": _env_bool("VUL_RAG_CACHE", True),
        "llm_enabled": _env_bool("VUL_LLM_ENABLED", True),
        "llm_provider": os.getenv("VUL_LLM_PROVIDER", "ollama"),
        "ollama_url": selected_url,
        "ollama_model": selected_model,
        "prefer_cloud": prefer_cloud,
        "ollama_local_model": local_model,
        "ollama_cloud_model": cloud_model,
        "ollama_api_key": os.getenv("VUL_OLLAMA_API_KEY", ""),
        "ollama_model_fallbacks": _env_csv(
            "VUL_OLLAMA_MODEL_FALLBACKS",
            [
                "qwen3-coder:cloud",
                "llama4:cloud",
                "mistral-large:cloud",
            ],
        ),
        "llm_timeout_ms": max(500, _env_int("VUL_LLM_TIMEOUT_MS", 8000)),
        "total_budget_ms": max(1000, _env_int("VUL_RAG_BUDGET_MS", 25000)),
        "llm_temperature": min(1.0, max(0.0, _env_float("VUL_LLM_TEMPERATURE", 0.1))),
        "min_line_risk": min(2.0, max(0.0, _env_float("VUL_RAG_MIN_LINE_RISK", 0.45))),
        "static_rules_enabled": _env_bool("VUL_STATIC_RULES_ENABLED", True),
        "static_max_findings": max(1, _env_int("VUL_STATIC_MAX_FINDINGS", 6)),
        "cwe_catalog_url": os.getenv("VUL_CWE_CATALOG_URL", DEFAULT_CWE_CATALOG_URL),
        "cwe_cache_path": os.getenv("VUL_CWE_CACHE_PATH", CWE_CATALOG_CACHE_PATH),
        "cwe_refresh_hours": max(1, _env_int("VUL_CWE_REFRESH_HOURS", 168)),
    }


def _clean_text(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _token_set(text):
    return set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_\-]*", str(text).lower()))


def _keywords_from_text(text, limit=28):
    tokens = []
    for token in sorted(_token_set(text)):
        if len(token) < 3:
            continue
        if token in TEXT_STOPWORDS:
            continue
        tokens.append(token)
        if len(tokens) >= limit:
            break
    return tokens


def _load_json_file(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_json_file(path, payload):
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass


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
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True)
    except Exception:
        pass

# def _download_cwe_catalog_xml(url, timeout_seconds=15):
#     req = urllib_request.Request(url, headers={"User-Agent": "vul-extension-cwe-rag/1.0"})
#     with urllib_request.urlopen(req, timeout=max(3, int(timeout_seconds))) as resp:
#         blob = resp.read()

#     if blob[:2] == b"PK":
#         with zipfile.ZipFile(io.BytesIO(blob), "r") as archive:
#             xml_names = [name for name in archive.namelist() if name.lower().endswith(".xml")]
#             if not xml_names:
#                 raise ValueError("cwe_zip_missing_xml")
#             with archive.open(xml_names[0], "r") as xml_file:
#                 return xml_file.read()

#     return blob


# def _parse_cwe_catalog(xml_bytes):
#     root = ET.fromstring(xml_bytes)
#     entries = []
#     for node in root.iter():
#         tag = str(node.tag).lower()
#         if not tag.endswith("weakness"):
#             continue

#         weakness_id = node.attrib.get("ID")
#         weakness_name = _clean_text(node.attrib.get("Name"))
#         if not weakness_id or not weakness_name:
#             continue

#         description = ""
#         for child in node:
#             child_tag = str(child.tag).lower()
#             if child_tag.endswith("description"):
#                 description = _clean_text("".join(child.itertext()))
#                 if description:
#                     break

#         if not description:
#             description = f"{weakness_name} weakness pattern in software behavior."

#         cwe = f"CWE-{weakness_id}"
#         searchable = f"{weakness_name} {description}"
#         entries.append(
#             {
#                 "id": cwe,
#                 "title": weakness_name,
#                 "cwe": cwe,
#                 "why": description[:550],
#                 "keywords": _keywords_from_text(searchable),
#                 "fix_suggestions": [],
#             }
#         )

#     return entries


# def _get_cwe_catalog(runtime_cfg):
#     global CWE_CATALOG_STATE

#     if isinstance(CWE_CATALOG_STATE.get("entries"), list) and CWE_CATALOG_STATE.get("entries"):
#         return CWE_CATALOG_STATE["entries"]

#     cache_path = runtime_cfg.get("cwe_cache_path", CWE_CATALOG_CACHE_PATH)
#     refresh_hours = max(1, int(runtime_cfg.get("cwe_refresh_hours", 168)))
#     refresh_seconds = refresh_hours * 3600
#     now_ts = int(time.time())

#     cached_payload = _load_json_file(cache_path)
#     cached_entries = []
#     cached_fetched_at = 0
#     if isinstance(cached_payload, dict):
#         possible_entries = cached_payload.get("entries", [])
#         if isinstance(possible_entries, list):
#             cached_entries = possible_entries
#         try:
#             cached_fetched_at = int(cached_payload.get("fetched_at", 0))
#         except Exception:
#             cached_fetched_at = 0

#     has_fresh_cache = bool(cached_entries) and (now_ts - cached_fetched_at) <= refresh_seconds
#     if has_fresh_cache:
#         CWE_CATALOG_STATE = {
#             "entries": cached_entries,
#             "source": "cache_fresh",
#             "count": len(cached_entries),
#             "fetched_at": cached_fetched_at,
#             "last_error": "",
#         }
#         return cached_entries

#     catalog_url = str(runtime_cfg.get("cwe_catalog_url", DEFAULT_CWE_CATALOG_URL)).strip()
#     if catalog_url:
#         try:
#             xml_bytes = _download_cwe_catalog_xml(catalog_url, timeout_seconds=20)
#             parsed_entries = _parse_cwe_catalog(xml_bytes)
#             if parsed_entries:
#                 _write_json_file(
#                     cache_path,
#                     {
#                         "source_url": catalog_url,
#                         "fetched_at": now_ts,
#                         "count": len(parsed_entries),
#                         "entries": parsed_entries,
#                     },
#                 )
#                 CWE_CATALOG_STATE = {
#                     "entries": parsed_entries,
#                     "source": "downloaded",
#                     "count": len(parsed_entries),
#                     "fetched_at": now_ts,
#                     "last_error": "",
#                 }
#                 return parsed_entries
#         except Exception as exc:
#             last_error = str(exc)
#             if cached_entries:
#                 CWE_CATALOG_STATE = {
#                     "entries": cached_entries,
#                     "source": "cache_stale",
#                     "count": len(cached_entries),
#                     "fetched_at": cached_fetched_at,
#                     "last_error": last_error,
#                 }
#                 return cached_entries

#             CWE_CATALOG_STATE = {
#                 "entries": [],
#                 "source": "empty",
#                 "count": 0,
#                 "fetched_at": 0,
#                 "last_error": last_error,
#             }
#             return []

#     CWE_CATALOG_STATE = {
#         "entries": cached_entries,
#         "source": "cache_stale" if cached_entries else "empty",
#         "count": len(cached_entries),
#         "fetched_at": cached_fetched_at,
#         "last_error": "",
#     }
#     return cached_entries


def _extract_context_window(raw_code, line_no, window):
    lines = raw_code.splitlines()
    if not lines:
        return {
            "start_line": 1,
            "end_line": 1,
            "focus_line": line_no,
            "focus_line_text": "",
            "snippet_lines": [],
            "snippet": "",
        }

    safe_line = max(1, min(int(line_no), len(lines)))
    start = max(1, safe_line - window)
    end = min(len(lines), safe_line + window)
    snippet_lines = lines[start - 1:end]
    return {
        "start_line": start,
        "end_line": end,
        "focus_line": safe_line,
        "focus_line_text": lines[safe_line - 1],
        "snippet_lines": snippet_lines,
        "snippet": "\n".join(snippet_lines),
    }


# def _retrieve_evidence(line_text, context_text, top_k, cwe_catalog):
#     line_lower = str(line_text).lower()
#     ctx_lower = str(context_text).lower()
#     ctx_tokens = _token_set(f"{line_text}\n{context_text}")
#     candidates = []
#     matched_patterns = [p for p in GENERIC_RISK_PATTERNS if p and (p in line_lower or p in ctx_lower)]

#     keyword_risk_hits = len(ctx_tokens.intersection(GENERIC_RISK_KEYWORDS))
#     risk_bias = min(2.0, 0.2 * len(matched_patterns) + 0.1 * keyword_risk_hits)

#     for item in cwe_catalog:
#         keywords = set(str(k).lower() for k in item.get("keywords", []))
#         if not keywords:
#             keywords = _token_set(f"{item.get('title', '')} {item.get('why', '')}")
#         if not keywords:
#             continue

#         keyword_overlap = len(ctx_tokens.intersection(keywords))
#         keyword_norm = keyword_overlap / max(len(keywords), 1)
#         title_tokens = _token_set(item.get("title", ""))
#         title_overlap = len(ctx_tokens.intersection(title_tokens)) / max(1, len(title_tokens))
#         score = (3.5 * keyword_norm) + (2.0 * title_overlap) + risk_bias

#         if score <= 0.15:
#             continue

#         candidates.append(
#             {
#                 "id": item.get("id", "cwe-unknown"),
#                 "title": item.get("title", "Potential vulnerability pattern"),
#                 "cwe": item.get("cwe", "unknown"),
#                 "why": item.get("why", "Potentially unsafe coding pattern matched."),
#                 "score": round(float(score), 4),
#                 "matched_patterns": matched_patterns[:5],
#                 "fix_suggestions": item.get("fix_suggestions", []),
#             }
#         )

#     candidates.sort(key=lambda x: x.get("score", 0.0), reverse=True)
#     return candidates[:top_k]


# def _default_fix_suggestions(line_text):
#     return [
#         {
#             "rank": 1,
#             "summary": "Replace unsafe operation with bounded or validated variant.",
#             "patch_hint": "Apply input length checks before write/copy and enforce explicit bounds.",
#             "safety_notes": "Reject or safely truncate oversized input; avoid silent overflow.",
#         },
#         {
#             "rank": 2,
#             "summary": "Introduce early guard checks on risky inputs.",
#             "patch_hint": "Validate pointers, sizes, and indices before dereference or memory copy.",
#             "safety_notes": "Keep checks adjacent to the vulnerable operation for maintainability.",
#         },
#     ]


# def _fallback_guidance(line_text, evidence):
#     if evidence:
#         best = evidence[0]
#         fixes = best.get("fix_suggestions", []) or []
#         ranked = []
#         for idx, item in enumerate(fixes[:3], 1):
#             ranked.append(
#                 {
#                     "rank": idx,
#                     "summary": item.get("summary", "Apply a safer replacement."),
#                     "patch_hint": item.get("patch_hint", "Add checks and safe API usage."),
#                     "safety_notes": item.get("safety_notes", "Verify behavior with boundary tests."),
#                 }
#             )
#         if not ranked:
#             ranked = _default_fix_suggestions(line_text)
#         return {
#             "title": best.get("title", "Potential vulnerability pattern"),
#             "cwe": best.get("cwe", "unknown"),
#             "explanation": best.get("why", "Potentially unsafe code pattern detected."),
#             "fix_suggestions": ranked,
#         }

#     return {
#         "title": "Potential vulnerability pattern",
#         "cwe": "unknown",
#         "explanation": "Potentially risky operation detected by line-level localization.",
#         "fix_suggestions": _default_fix_suggestions(line_text),
#     }


# def _safe_json_loads(text):
#     payload = (text or "").strip()
#     if not payload:
#         return None
#     try:
#         return json.loads(payload)
#     except Exception:
#         left = payload.find("{")
#         right = payload.rfind("}")
#         if left >= 0 and right > left:
#             try:
#                 return json.loads(payload[left:right + 1])
#             except Exception:
#                 return None
#     return None


# def _call_ollama_for_guidance(line_no, line_text, context_text, evidence, runtime_cfg, timeout_ms):
#     evidence_lines = []
#     for idx, item in enumerate(evidence[:3], 1):
#         evidence_lines.append(
#             f"{idx}. {item.get('title', 'pattern')} ({item.get('cwe', 'unknown')}), reason={item.get('why', '')}"
#         )

#     prompt = (
#         "You are a secure C/C++ code reviewer.\n"
#         "Given vulnerable line context and CWE candidate evidence, classify the most likely CWE and return strict JSON only with keys: "
#         "title, cwe, explanation, confidence, fix_suggestions.\n"
#         "For cwe, output a canonical CWE id such as CWE-119, CWE-120, CWE-787, CWE-416, etc.\n"
#         "fix_suggestions must be an array of objects with keys: summary, patch_hint, safety_notes.\n"
#         "Keep explanation under 2 sentences and suggestions concise.\n\n"
#         f"Target line number: {line_no}\n"
#         f"Target line text: {line_text}\n\n"
#         "Context window:\n"
#         f"{context_text}\n\n"
#         "Retrieved CWE candidates:\n"
#         + "\n".join(evidence_lines)
#     )

#     candidate_models = []
#     for model_name in [runtime_cfg.get("ollama_model", "")] + list(runtime_cfg.get("ollama_model_fallbacks", [])):
#         normalized = str(model_name).strip()
#         if normalized and normalized not in candidate_models:
#             candidate_models.append(normalized)

#     last_error = None
#     chosen_model = None
#     structured = None

#     for model_name in candidate_models:
#         payload = {
#             "model": model_name,
#             "prompt": prompt,
#             "stream": False,
#             "temperature": runtime_cfg["llm_temperature"],
#         }

#         headers = {"Content-Type": "application/json"}
#         api_key = str(runtime_cfg.get("ollama_api_key", "")).strip()
#         if api_key:
#             headers["Authorization"] = f"Bearer {api_key}"

#         req = urllib_request.Request(
#             runtime_cfg["ollama_url"],
#             data=json.dumps(payload).encode("utf-8"),
#             headers=headers,
#             method="POST",
#         )

#         try:
#             with urllib_request.urlopen(req, timeout=max(1.0, timeout_ms / 1000.0)) as resp:
#                 body = resp.read().decode("utf-8", errors="ignore")
#         except (urllib_error.URLError, TimeoutError, ValueError) as exc:
#             last_error = str(exc)
#             continue
#         except Exception as exc:
#             last_error = str(exc)
#             continue

#         parsed = _safe_json_loads(body)
#         if not isinstance(parsed, dict):
#             last_error = "provider_response_not_json"
#             continue

#         llm_text = parsed.get("response", "")
#         structured = _safe_json_loads(llm_text)
#         if not isinstance(structured, dict):
#             last_error = "model_response_not_structured_json"
#             continue

#         chosen_model = model_name
#         break

#     if not isinstance(structured, dict):
#         return None, last_error

#     fixes = structured.get("fix_suggestions", [])
#     if not isinstance(fixes, list):
#         fixes = []

#     normalized_fixes = []
#     for idx, item in enumerate(fixes[:3], 1):
#         if not isinstance(item, dict):
#             continue
#         normalized_fixes.append(
#             {
#                 "rank": idx,
#                 "summary": str(item.get("summary", "Apply safer coding pattern.")),
#                 "patch_hint": str(item.get("patch_hint", "Add validation and bounded operations.")),
#                 "safety_notes": str(item.get("safety_notes", "Re-test edge cases after patch.")),
#             }
#         )

#     confidence = structured.get("confidence", 0.65)
#     try:
#         confidence = float(confidence)
#     except Exception:
#         confidence = 0.65
#     confidence = min(1.0, max(0.0, confidence))

#     return {
#         "title": str(structured.get("title", "LLM-guided vulnerability finding")),
#         "cwe": str(structured.get("cwe", "unknown")),
#         "explanation": str(structured.get("explanation", "Potentially vulnerable code segment.")),
#         "fix_suggestions": normalized_fixes,
#         "llm_confidence": confidence,
#         "model_used": chosen_model,
#     }, None


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


def _refine_vulnerable_lines(raw_code, vulnerable_lines, window, max_lines):
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


def _line_is_comment_or_blank(line_text):
    text = str(line_text or "").strip()
    if not text:
        return True
    return text.startswith("//") or text.startswith("/*") or text.startswith("*")


def _build_static_autofix(rule, match):
    kind = str(rule.get("autofix_kind", "manual"))

    if kind == "strcpy_to_strncpy":
        return {
            "kind": kind,
            "dest": _clean_text(match.group(1)),
            "src": _clean_text(match.group(2)),
        }
    if kind == "strcat_to_strncat":
        return {
            "kind": kind,
            "dest": _clean_text(match.group(1)),
            "src": _clean_text(match.group(2)),
        }
    if kind == "sprintf_to_snprintf":
        return {
            "kind": kind,
            "dest": _clean_text(match.group(1)),
            "format_args": _clean_text(match.group(2)),
        }
    if kind == "gets_to_fgets":
        return {
            "kind": kind,
            "dest": _clean_text(match.group(1)),
        }
    return {"kind": kind}


def _build_static_fix_suggestions(rule, autofix):
    kind = str((autofix or {}).get("kind", "manual"))

    if kind == "strcpy_to_strncpy":
        dest = autofix.get("dest", "dest")
        src = autofix.get("src", "src")
        return [
            {
                "rank": 1,
                "summary": "Use bounded copy with explicit null termination.",
                "patch_hint": f"strncpy({dest}, {src}, sizeof({dest}) - 1); {dest}[sizeof({dest}) - 1] = '\\0';",
                "safety_notes": "Confirm destination is an actual array, not a pointer with unknown size.",
            }
        ]
    if kind == "strcat_to_strncat":
        dest = autofix.get("dest", "dest")
        src = autofix.get("src", "src")
        return [
            {
                "rank": 1,
                "summary": "Use bounded append based on remaining capacity.",
                "patch_hint": f"strncat({dest}, {src}, sizeof({dest}) - strlen({dest}) - 1);",
                "safety_notes": "Ensure destination is initialized and has compile-time known bounds.",
            }
        ]
    if kind == "sprintf_to_snprintf":
        dest = autofix.get("dest", "dest")
        fmt_args = autofix.get("format_args", "fmt")
        return [
            {
                "rank": 1,
                "summary": "Switch to snprintf with destination size.",
                "patch_hint": f"snprintf({dest}, sizeof({dest}), {fmt_args});",
                "safety_notes": "Check return value for truncation and format errors.",
            }
        ]
    if kind == "gets_to_fgets":
        dest = autofix.get("dest", "buf")
        return [
            {
                "rank": 1,
                "summary": "Replace gets with bounded fgets.",
                "patch_hint": f"fgets({dest}, sizeof({dest}), stdin);",
                "safety_notes": "Trim trailing newline if callers expect stripped input.",
            }
        ]
    if kind == "scanf_add_width":
        return [
            {
                "rank": 1,
                "summary": "Add field width to %s conversions or use fgets + parsing.",
                "patch_hint": "scanf(\"%31s\", buf);  // adjust width to buffer capacity - 1",
                "safety_notes": "Width must match real buffer size to prevent overflow.",
            }
        ]

    return [
        {
            "rank": 1,
            "summary": "Harden this sink with strict validation and safer APIs.",
            "patch_hint": "Validate untrusted input and avoid direct shell-command execution.",
            "safety_notes": "Prefer allowlists and structured subprocess APIs over shell invocation.",
        }
    ]


def _scan_static_vulnerabilities(raw_code, runtime_cfg):
    if not runtime_cfg.get("static_rules_enabled", True):
        return []

    findings = []
    lines = str(raw_code).splitlines()
    seen = set()
    max_findings = max(1, int(runtime_cfg.get("static_max_findings", 6)))

    for line_no, line_text in enumerate(lines, 1):
        if _line_is_comment_or_blank(line_text):
            continue

        for rule in STATIC_VULN_RULES:
            regex = rule.get("regex")
            if not regex:
                continue
            match = regex.search(line_text)
            if not match:
                continue

            finding_key = (line_no, rule.get("id"))
            if finding_key in seen:
                continue
            seen.add(finding_key)

            ctx = _extract_context_window(raw_code, line_no, runtime_cfg.get("window", 4))
            severity = max(1, int(rule.get("severity", 1)))
            local_risk = _score_line_risk(line_text)
            confidence = min(0.98, max(0.35, 0.42 + (0.08 * severity) + min(0.25, local_risk * 0.05)))
            autofix = _build_static_autofix(rule, match)

            findings.append(
                {
                    "line": int(line_no),
                    "title": rule.get("title", "Static vulnerability pattern"),
                    "cwe": rule.get("cwe", "unknown"),
                    "explanation": rule.get("explanation", "Potential vulnerability pattern detected by static rule."),
                    "context_window": {
                        "start_line": ctx["start_line"],
                        "end_line": ctx["end_line"],
                        "snippet": ctx["snippet"],
                    },
                    "evidence": [
                        {
                            "id": rule.get("id", "static-rule"),
                            "title": rule.get("title", "Static vulnerability pattern"),
                            "cwe": rule.get("cwe", "unknown"),
                            "score": round(float(local_risk + severity), 4),
                            "matched_patterns": [str(match.group(0)).strip()[:120]],
                        }
                    ],
                    "fix_suggestions": _build_static_fix_suggestions(rule, autofix),
                    "confidence": {
                        "detector_probability": float(min(1.0, confidence)),
                        "retrieval_score": float(min(1.0, local_risk / 6.0)),
                        "llm_score": 0.0,
                        "final": float(confidence),
                    },
                    "generation_mode": "static_rule",
                    "autofix": autofix,
                }
            )

    findings.sort(
        key=lambda item: (
            -float((item.get("confidence") or {}).get("final", 0.0)),
            int(item.get("line", 0)),
        )
    )
    return findings[:max_findings]


def _merge_fix_suggestions(existing, incoming):
    merged = []
    seen = set()
    for item in list(existing or []) + list(incoming or []):
        if not isinstance(item, dict):
            continue
        summary = _clean_text(item.get("summary", ""))
        if not summary:
            continue
        key = summary.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(
            {
                "rank": len(merged) + 1,
                "summary": summary,
                "patch_hint": _clean_text(item.get("patch_hint", "")),
                "safety_notes": _clean_text(item.get("safety_notes", "")),
            }
        )
        if len(merged) >= 4:
            break
    return merged


def _merge_static_findings(model_findings, static_findings):
    merged = []
    model_by_line = {}

    for item in model_findings or []:
        if not isinstance(item, dict):
            continue
        line_no = item.get("line")
        if isinstance(line_no, int) and line_no not in model_by_line:
            model_by_line[line_no] = item
        merged.append(item)

    for static_item in static_findings or []:
        if not isinstance(static_item, dict):
            continue
        line_no = static_item.get("line")
        if not isinstance(line_no, int):
            continue

        existing = model_by_line.get(line_no)
        if not existing:
            merged.append(static_item)
            model_by_line[line_no] = static_item
            continue

        existing["evidence"] = list(existing.get("evidence", [])) + list(static_item.get("evidence", []))
        existing["fix_suggestions"] = _merge_fix_suggestions(
            existing.get("fix_suggestions", []),
            static_item.get("fix_suggestions", []),
        )

        current_cwe = str(existing.get("cwe", "")).strip().lower()
        if current_cwe in {"", "unknown", "cwe-unknown"}:
            existing["cwe"] = static_item.get("cwe", existing.get("cwe", "unknown"))
            existing["title"] = static_item.get("title", existing.get("title", "Potential vulnerability pattern"))
            existing["explanation"] = static_item.get("explanation", existing.get("explanation", ""))

        mode = str(existing.get("generation_mode", "retrieval_rule"))
        if "static_rule" not in mode:
            existing["generation_mode"] = f"{mode}+static_rule"

        if static_item.get("autofix") and not existing.get("autofix"):
            existing["autofix"] = static_item.get("autofix")

    merged.sort(key=lambda item: int(item.get("line", 0) or 0))
    return merged


# def _build_rag_findings(raw_code, vulnerable_lines, base_prob, runtime_cfg):
#     started = time.time()
#     findings = []
#     llm_used = 0
#     retrieval_hits = 0
#     cache_hits = 0
#     degraded = False
#     errors = []
#     models_used = []
#     processed_lines = set()
#     cwe_catalog = _get_cwe_catalog(runtime_cfg)

#     if not vulnerable_lines:
#         return findings, {
#             "enabled": runtime_cfg.get("enabled", False),
#             "llm_enabled": runtime_cfg.get("llm_enabled", False),
#             "mode": "empty",
#             "elapsed_ms": 0,
#             "cwe_catalog_count": len(cwe_catalog),
#             "cwe_catalog_source": CWE_CATALOG_STATE.get("source", "unknown"),
#         }

#     for rank, line_no in enumerate(vulnerable_lines[:runtime_cfg["max_lines"]], 1):
#         line_no = _refine_focus_line(raw_code, line_no, runtime_cfg["window"])
#         if line_no in processed_lines:
#             continue
#         processed_lines.add(line_no)
#         ctx = _extract_context_window(raw_code, line_no, runtime_cfg["window"])
#         line_text = ctx["focus_line_text"]
#         line_risk = _score_line_risk(line_text)
#         if rank > 1 and line_risk < runtime_cfg.get("min_line_risk", 0.45):
#             continue
#         context_text = ctx["snippet"]

#         cache_key = hashlib.sha256(
#             (
#                 f"{line_no}|{rank}|{context_text}|{line_text}|{runtime_cfg['top_k']}|"
#                 f"{runtime_cfg['max_lines']}|{round(float(base_prob), 6)}"
#             ).encode("utf-8")
#         ).hexdigest()

#         if runtime_cfg.get("cache_enabled") and cache_key in RAG_CACHE:
#             cached = dict(RAG_CACHE[cache_key])
#             cached["line"] = line_no
#             findings.append(cached)
#             cache_hits += 1
#             continue

#         evidence = _retrieve_evidence(line_text, context_text, runtime_cfg["top_k"], cwe_catalog)
#         if evidence:
#             retrieval_hits += 1
#         retrieval_score = evidence[0]["score"] if evidence else 0.0

#         guidance = _fallback_guidance(line_text, evidence)
#         generation_mode = "retrieval_rule"
#         llm_confidence = 0.0
#         llm_result = None
#         llm_error = None

#         if runtime_cfg.get("llm_enabled") and runtime_cfg.get("llm_provider") == "ollama":
#             elapsed_ms = int((time.time() - started) * 1000)
#             if elapsed_ms < runtime_cfg["total_budget_ms"]:
#                 remaining_ms = max(500, runtime_cfg["total_budget_ms"] - elapsed_ms)
#                 timeout_ms = min(runtime_cfg["llm_timeout_ms"], remaining_ms)
#                 llm_result, llm_error = _call_ollama_for_guidance(
#                     line_no=line_no,
#                     line_text=line_text,
#                     context_text=context_text,
#                     evidence=evidence,
#                     runtime_cfg=runtime_cfg,
#                     timeout_ms=timeout_ms,
#                 )
#                 if llm_result:
#                     generation_mode = "llm_rag"
#                     llm_used += 1
#                     llm_confidence = llm_result.get("llm_confidence", 0.65)
#                     if llm_result.get("model_used"):
#                         models_used.append(str(llm_result.get("model_used")))
#                     guidance["title"] = llm_result.get("title", guidance["title"])
#                     guidance["cwe"] = llm_result.get("cwe", guidance["cwe"])
#                     guidance["explanation"] = llm_result.get("explanation", guidance["explanation"])
#                     if llm_result.get("fix_suggestions"):
#                         guidance["fix_suggestions"] = llm_result["fix_suggestions"]
#                 else:
#                     degraded = True
#                     if llm_error:
#                         errors.append(f"llm_unavailable_line_{line_no}:{llm_error}")
#                     else:
#                         errors.append(f"llm_unavailable_line_{line_no}")
#             else:
#                 degraded = True
#                 errors.append(f"llm_budget_exceeded_before_line_{line_no}")

#         retrieval_component = min(1.0, retrieval_score / 6.0)
#         line_rank_component = max(0.2, 1.0 - ((rank - 1) / max(1, runtime_cfg["max_lines"])))
#         final_conf = min(
#             1.0,
#             max(
#                 0.0,
#                 (0.55 * float(base_prob))
#                 + (0.25 * retrieval_component)
#                 + (0.10 * line_rank_component)
#                 + (0.10 * llm_confidence),
#             ),
#         )

#         finding = {
#             "line": int(line_no),
#             "title": guidance["title"],
#             "cwe": guidance["cwe"],
#             "explanation": guidance["explanation"],
#             "context_window": {
#                 "start_line": ctx["start_line"],
#                 "end_line": ctx["end_line"],
#                 "snippet": ctx["snippet"],
#             },
#             "evidence": [
#                 {
#                     "id": item.get("id", "rule-unknown"),
#                     "title": item.get("title", "pattern"),
#                     "cwe": item.get("cwe", "unknown"),
#                     "score": item.get("score", 0.0),
#                     "matched_patterns": item.get("matched_patterns", []),
#                 }
#                 for item in evidence
#             ],
#             "fix_suggestions": guidance["fix_suggestions"],
#             "confidence": {
#                 "detector_probability": float(base_prob),
#                 "retrieval_score": float(retrieval_component),
#                 "llm_score": float(llm_confidence),
#                 "final": float(final_conf),
#             },
#             "generation_mode": generation_mode,
#         }

#         if llm_result and llm_result.get("model_used"):
#             finding["llm_model"] = str(llm_result.get("model_used"))

#         if runtime_cfg.get("cache_enabled"):
#             RAG_CACHE[cache_key] = dict(finding)

#         findings.append(finding)

#     elapsed_ms = max(1, int((time.time() - started) * 1000))
#     metadata = {
#         "enabled": runtime_cfg.get("enabled", False),
#         "llm_enabled": runtime_cfg.get("llm_enabled", False),
#         "provider": runtime_cfg.get("llm_provider", "none"),
#         "selected_model": runtime_cfg.get("ollama_model", ""),
#         "model_fallbacks": runtime_cfg.get("ollama_model_fallbacks", []),
#         "models_used": _dedupe_preserve_order(models_used),
#         "top_k": runtime_cfg.get("top_k", 0),
#         "max_lines": runtime_cfg.get("max_lines", 0),
#         "window": runtime_cfg.get("window", 0),
#         "llm_used": llm_used,
#         "retrieval_hits": retrieval_hits,
#         "cache_hits": cache_hits,
#         "degraded": degraded,
#         "errors": errors[:10],
#         "elapsed_ms": elapsed_ms,
#         "mode": "llm_rag" if llm_used > 0 else "retrieval_rule",
#         "cwe_catalog_count": len(cwe_catalog),
#         "cwe_catalog_source": CWE_CATALOG_STATE.get("source", "unknown"),
#         "cwe_catalog_last_error": CWE_CATALOG_STATE.get("last_error", ""),
#     }
#     return findings, metadata

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

# Load trained weights
model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"), strict=False)
model.to(DEVICE)
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
linevul_model.load_state_dict(torch.load(LINEVUL_MODEL_PATH, map_location="cpu"), strict=False)
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
    return arr


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
    return [ln for ln, _ in ranked[:top_k]]


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

    runtime_cfg = get_rag_runtime_config()
    static_findings = _scan_static_vulnerabilities(raw_code, runtime_cfg)
    static_lines = [
        int(item.get("line"))
        for item in static_findings
        if isinstance(item, dict) and isinstance(item.get("line"), int)
    ]

    # Use LineVul model for line-level localization first
    vulnerable_lines = []
    detection_method = "none"
    try:
        vulnerable_lines = get_vulnerable_line_numbers_linevul(raw_code)
        if vulnerable_lines:
            detection_method = "linevul"
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
            if vulnerable_lines:
                detection_method = "moe_attribution"
        except Exception:
            vulnerable_lines = []

    # Final fallback when both attribution paths fail
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

    if static_lines:
        if detection_method == "none":
            detection_method = "static_rules"
        elif "static_rules" not in detection_method:
            detection_method = f"{detection_method}+static_rules"

    candidate_lines = _dedupe_preserve_order(static_lines + vulnerable_lines)
    vulnerable_lines = _normalize_vulnerable_lines(raw_code, candidate_lines)
    vulnerable_lines = _refine_vulnerable_lines(
        raw_code=raw_code,
        vulnerable_lines=vulnerable_lines,
        window=runtime_cfg.get("window", 4),
        max_lines=runtime_cfg.get("max_lines", 5),
    )

    findings = []
    rag_metadata = {
        "enabled": runtime_cfg.get("enabled", False),
        "mode": "disabled",
        "elapsed_ms": 0,
    }
    # if runtime_cfg.get("enabled"):
    #     findings, rag_metadata = _build_rag_findings(
    #         raw_code=raw_code,
    #         vulnerable_lines=vulnerable_lines,
    #         base_prob=base_prob,
    #         runtime_cfg=runtime_cfg,
    #     )
    #     if findings:
    #         finding_lines = _dedupe_preserve_order(
    #             [
    #                 int(item.get("line"))
    #                 for item in findings
    #                 if isinstance(item, dict) and isinstance(item.get("line"), int)
    #             ]
    #         )
    #         if finding_lines:
    #             vulnerable_lines = finding_lines

    if static_findings:
        findings = _merge_static_findings(findings, static_findings)
        static_lines_merged = _dedupe_preserve_order(
            [
                int(item.get("line"))
                for item in findings
                if isinstance(item, dict) and isinstance(item.get("line"), int)
            ]
        )
        if static_lines_merged:
            vulnerable_lines = static_lines_merged

    rag_metadata["static_rules_enabled"] = bool(runtime_cfg.get("static_rules_enabled", True))
    rag_metadata["static_rule_hits"] = len(static_findings)
    rag_metadata["static_rule_findings"] = len(
        [item for item in findings if isinstance(item, dict) and "static_rule" in str(item.get("generation_mode", ""))]
    )
    if static_findings:
        mode = str(rag_metadata.get("mode", "disabled"))
        if mode in {"disabled", "empty"}:
            rag_metadata["mode"] = "static_rule"
        elif "static_rule" not in mode:
            rag_metadata["mode"] = f"{mode}+static_rule"

    return {
        "vulnerable_probability": float(base_prob),
        "vulnerable_lines": vulnerable_lines,
        "detection_method": detection_method,
        "findings": findings,
        "rag_metadata": rag_metadata,
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
        "findings": result.get("findings", []),
        "rag_metadata": result.get("rag_metadata", {}),
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
