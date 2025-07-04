# app_demo.py

from fastapi import FastAPI, Request
from waf_middleware import WAFMiddleware

app = FastAPI()
app.add_middleware(WAFMiddleware)


@app.get("/")
async def root():
    return {"message": "Welcome to WAF-XAI"}


@app.post("/submit")
async def submit(request: Request):
    """
    Business endpoint for benign requests.
    The WAFMiddleware will block malicious payloads (returning 403)
    before this handler is invoked.
    """
    # 1) Parse JSON body or fallback to raw bytes
    try:
        body = await request.json()
        received = body.get("input", "")
    except Exception:
        raw = await request.body()
        received = raw.decode("utf-8", "ignore")

    # 2) Return only application data—no WAF internals
    return {"received": received}
