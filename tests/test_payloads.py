import requests

url = "http://localhost:8080/submit"
tests = {
    "benign": {"input": "hello world"},
    "sql_inj": {"input": "1 OR 1=1"},
    "xss": {"input": "<script>alert('XSS')</script>"},
}

for name, payload in tests.items():
    res = requests.post(url, json=payload)
    print(f"\n[{name}] Status: {res.status_code}\n{res.json()}")
