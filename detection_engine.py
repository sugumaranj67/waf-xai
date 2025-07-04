# detection_engine.py

import re
from typing import Dict, Any

# ─── Regex patterns for XSS and SQLi ──────────────────────────────────────────

# Order matters: specific onerror rule must come before the generic on* handler
XSS_PATTERNS = [
    r"<script.*?>.*?</script>",
    r"<img.*?src=.*?onerror=.*?>",
    r"<.*?on\w+\s*=.*?>",
    r"javascript:"
]

SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # quotes/comments
    r"(?i)\b(or)\b.*=.*",              # tautology
    r"(?i)union select",               # UNION SELECT
    r"(?i)insert\s+into\b",            # INSERT INTO
    r"(?i)drop table"                  # DROP TABLE
]

def detect_attack(user_input: Dict[str, Any]) -> Dict[str, Any]:
    """
    Inspect combined request data for XSS or SQLi patterns.
    Returns:
      - is_malicious: bool
      - label:        "XSS", "SQLi", or "benign"
      - pattern:      the regex that matched (or None)
    """
    combined = " ".join(str(v) for v in user_input.values())

    # 1) XSS checks
    for pat in XSS_PATTERNS:
        if re.search(pat, combined, re.IGNORECASE):
            return {"is_malicious": True, "label": "XSS", "pattern": pat}

    # 2) SQLi checks
    for pat in SQLI_PATTERNS:
        if re.search(pat, combined, re.IGNORECASE):
            return {"is_malicious": True, "label": "SQLi", "pattern": pat}

    # 3) No match → benign
    return {"is_malicious": False, "label": "benign", "pattern": None}