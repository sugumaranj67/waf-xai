#!/usr/bin/env python3
"""
explainability.py

Provides:
  1. Rule-based regex explanations.
  2. Plain-English, token-level SHAP explanations via PartitionExplainer.
"""

import joblib
import numpy as np
import shap
from typing import Dict, Any, List

# ─── 1) Rule-based explanations ────────────────────────────────────────────────
REGEX_EXPLANATIONS: Dict[str, Dict[str, str]] = {
    "XSS": {
        r"<script.*?>.*?</script>":
            "Detected <script>…</script>, a common XSS vector.",
        r"<.*?on\w+\s*=.*?>":
            "Detected inline event handler (on*), often used in XSS.",
        r"<img.*?src=.*?onerror=.*?>":
            "Detected <img> with onerror, a known XSS technique.",
        r"javascript:":
            "Detected 'javascript:' URI, frequently used in XSS."
    },
    "SQLi": {
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)":
            "Detected SQL comment or quote characters.",
        r"(?i)\b(or)\b.*=.*":
            "Detected tautology injection (e.g. OR 1=1).",
        r"(?i)\bunion\b\s+\bselect\b":
            "Detected UNION SELECT, used for data exfiltration.",
        r"(?i)\bselect\b.*\bfrom\b":
            "Detected SELECT…FROM pattern, possible SQLi.",
        r"(?i)\binsert\b\s+\binto\b":
            "Detected INSERT INTO, possible SQL manipulation.",
        r"(?i)\bdrop\b\s+\btable\b":
            "Detected DROP TABLE, destructive SQL command."
    }
}

def explain_regex(label: str, pattern: str) -> str:
    return REGEX_EXPLANATIONS.get(label, {}) \
                             .get(pattern, "Suspicious pattern detected.")

# ─── 2) Load pipeline & build SHAP Explainer ──────────────────────────────────
MODEL_PATH = "models/attack_classifier_pipeline.pkl"
pipeline   = joblib.load(MODEL_PATH)

def predict_proba(texts: List[str]) -> np.ndarray:
    return pipeline.predict_proba(texts)

# Empty-string background for text masker
masker    = shap.maskers.Text()
explainer = shap.Explainer(
    predict_proba,
    masker,
    output_names=list(pipeline.classes_)
)

def explain_ml(payload: str, top_n: int = 5) -> str:
    """
    Return a plain-English summary of the top_n SHAP tokens
    driving the model’s prediction for this payload.
    """
    shap_vals = explainer([payload])[0]
    probs     = pipeline.predict_proba([payload])[0]
    idx       = int(np.argmax(probs))
    label     = pipeline.classes_[idx]
    confidence= probs[idx]

    tokens = shap_vals.data
    values = shap_vals.values[:, idx]
    top_ix = np.argsort(-np.abs(values))[:top_n]
    entries = [f"'{tokens[i]}' ({values[i]:.3f})" for i in top_ix]

    return (
        f"Model classified input as {label} "
        f"(confidence {confidence:.2f}). "
        f"Top contributing tokens: {', '.join(entries)}."
    )

def explain_detection(
    detection_result: Dict[str, Any],
    payload: str,
    top_n: int = 5
) -> str:
    """
    Unified API for regex and ML explanations.
    """
    src     = detection_result.get("detection_source", "")
    label   = detection_result.get("label", "")
    pattern = detection_result.get("pattern", "")

    if src == "regex":
        return explain_regex(label, pattern)
    if src == "ml":
        return explain_ml(payload, top_n)
    return "No explanation available."

# ─── 3) Standalone test harness ───────────────────────────────────────────────
if __name__ == "__main__":
    examples = {
        "benign":  "hello world",
        "sql_inj": "1 OR 1=1",
        "xss":     "<script>alert('XSS')</script>"
    }
    for name, txt in examples.items():
        print()
        if name == "benign":
            print(f"{name}: no block → no explanation\n")
            continue

        src   = "ml"
        label = "SQLi" if name == "sql_inj" else "XSS"
        dr    = {"detection_source": src, "label": label, "pattern": None}

        print(f"{name} [{label}]:")
        print("  Payload:", txt)
        print("  Explanation:", explain_detection(dr, txt, top_n=5))