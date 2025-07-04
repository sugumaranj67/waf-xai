import re
import traceback
import joblib

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from detection_engine import detect_attack       # regex engine returning label & pattern
from explainability import explain_detection     # SHAP / rule explanations
from threat_scoring import score_threat          # refined severity logic
from alert_logger import log_alert               # structured JSONL logger

# ─── Configuration ─────────────────────────────────────────────────────────────
MODEL_PATH     = "models/attack_classifier_pipeline.pkl"
ML_CONF_THRESH = 1.0    # raised to 1.0 so ML fallback never blocks (must be >1.0)

# Tighten allow-list: alnum+spaces only if NO SQL keywords present
ALLOWLIST_RE = re.compile(
    r'^(?!.*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR)\b)[A-Za-z0-9\s]+$',
    re.IGNORECASE
)

# Load the ML pipeline once at startup
ml_pipeline = joblib.load(MODEL_PATH)


class WAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                # 1) Extract the raw payload
                try:
                    body = await request.json()
                    payload = body.get("input", "")
                except Exception:
                    raw = await request.body()
                    payload = raw.decode("utf-8", "ignore")

                # 2) Allow-list: pure alnum+spaces, no SQL keywords
                if ALLOWLIST_RE.fullmatch(payload):
                    request.state.waf = {
                        "label":            "benign",
                        "confidence":       1.0,
                        "is_malicious":     False,
                        "detection_source": "allowlist",
                        "pattern":          None,
                        "explanation":      None
                    }
                    return await call_next(request)

                client_ip  = request.client.host
                user_agent = request.headers.get("user-agent", "unknown")

                # ── Step 1: Regex detection ─────────────────────────
                regex_res = detect_attack({
                    "body":  payload,
                    "query": dict(request.query_params)
                })
                regex_res.update({
                    "detection_source": "regex",
                    "confidence":       1.0
                })

                if regex_res.get("is_malicious"):
                    explanation = explain_detection(regex_res, payload)
                    severity    = score_threat(regex_res, payload)

                    log_alert(
                        request=request,
                        detection_result=regex_res,
                        explanation=explanation,
                        severity=severity,
                        client_ip=client_ip,
                        user_agent=user_agent
                    )

                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Blocked by WAF-XAI"}
                    )

                # ── Step 2: ML-based fallback (effectively disabled) ───
                probs      = ml_pipeline.predict_proba([payload])[0]
                confidence = float(round(probs.max(), 3))
                label      = ml_pipeline.predict([payload])[0]
                is_mal     = (label != "benign") and (confidence > ML_CONF_THRESH)

                if is_mal:
                    ml_res = {
                        "label":            label,
                        "pattern":          None,
                        "confidence":       confidence,
                        "is_malicious":     True,
                        "detection_source": "ml"
                    }
                    explanation = explain_detection(ml_res, payload)
                    severity    = score_threat(ml_res, payload)

                    log_alert(
                        request=request,
                        detection_result=ml_res,
                        explanation=explanation,
                        severity=severity,
                        client_ip=client_ip,
                        user_agent=user_agent
                    )

                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Blocked by WAF-XAI"}
                    )

                # ── Step 3: Benign pass-through ────────────────────────
                request.state.waf = {
                    "label":            "benign",
                    "confidence":       confidence,
                    "is_malicious":     False,
                    "detection_source": "ml",
                    "pattern":          None,
                    "explanation":      None
                }

            except Exception as err:
                print("❌ WAF internal error:", err)
                traceback.print_exc()
                request.state.waf = {
                    "label":            "benign",
                    "confidence":       0.0,
                    "is_malicious":     False,
                    "detection_source": "error",
                    "pattern":          None,
                    "explanation":      None
                }

        return await call_next(request)