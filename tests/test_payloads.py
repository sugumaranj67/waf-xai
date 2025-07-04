from fastapi.testclient import TestClient
from app_demo import app

client = TestClient(app)


def test_payload_submission():
    payload = {...}  # your test case
    response = client.post("/submit", json=payload)
    assert response.status_code == 200
    # more assertions...
