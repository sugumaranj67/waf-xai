# threat_scoring.py

from typing import Dict, Any

# Define integer levels for easy comparison
_SEVERITY_LEVELS = {"Low": 0, "Medium": 1, "High": 2}

# Patterns that elevate SQLi severity
_CRITICAL_SQLI = [
    "drop table",
    "union select"
]


def _clamp_level(level: int) -> int:
    return max(0, min(level, _SEVERITY_LEVELS["High"]))


def _level_to_name(level: int) -> str:
    for name, lvl in _SEVERITY_LEVELS.items():
        if lvl == level:
            return name
    return "Low"


def score_threat(detection_result: Dict[str, Any],
                 payload: str = "") -> str:
    """
    Compute Low/Medium/High severity based on:
      1. attack_type (label): XSS default High, SQLi default Medium
      2. confidence: <0.6 downgrade one level; >0.9 upgrade one level
      3. regex pattern criticality (for SQLi)
      4. payload length: very long payloads bump severity
    """
    label      = detection_result.get("label", "benign")
    confidence = detection_result.get("confidence", 0.0)
    pattern    = (detection_result.get("pattern") or "").lower()

    # 1) Base severity by attack type
    if label == "XSS":
        level = _SEVERITY_LEVELS["High"]
    elif label == "SQLi":
        level = _SEVERITY_LEVELS["Medium"]
    else:
        return "Low"

    # 2) Critical SQLi patterns => force High
    if label == "SQLi":
        for crit in _CRITICAL_SQLI:
            if crit in pattern:
                level = _SEVERITY_LEVELS["High"]
                break

    # 3) Adjust by confidence thresholds
    if confidence < 0.6:
        level -= 1
    elif confidence > 0.9:
        level += 1

    # 4) Bump severity for very long payloads (>200 chars)
    if len(payload) > 200:
        level += 1

    # Clamp and return
    final_level = _clamp_level(level)
    return _level_to_name(final_level)