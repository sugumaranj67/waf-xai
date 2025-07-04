import os
import json
from datetime import datetime

LOG_FILE = "logs/alerts.jsonl"


def log_alert(request, detection_result, explanation, severity, client_ip, user_agent):
    """
    Appends one JSON line per alert. Supports both regex and ML fields.
    """
    # Ensure attack_type is never null by falling back to label
    attack_type = detection_result.get("attack_type") or detection_result.get("label")

    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": detection_result.get("request_id"),  # or None
        "path": str(request.url),
        "method": request.method,
        "client_ip": client_ip,
        "user_agent": user_agent,
        # Core detection results
        "attack_type": attack_type,  # XSS, SQLi, benign
        "pattern": detection_result.get("pattern"),  # regex pattern or None
        "explanation": explanation,  # human-friendly text
        "severity": severity,  # Low/Medium/High
        "source": detection_result.get(
            "detection_source"
        ),  # "regex","ml","allowlist","error"
        "confidence": detection_result.get("confidence"),  # float or None
    }

    # Ensure logs directory exists
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    # Append as a JSON line
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
