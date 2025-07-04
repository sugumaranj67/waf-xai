from fastapi.testclient import TestClient
from app_demo import app

client = TestClient(app)

def test_root_endpoint():
    res = client.get("/")  
    assert res.status_code == 200