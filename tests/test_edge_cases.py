# test_edge_cases.py

import os
import time
import json
import requests

LOG_FILE = "logs/alerts.jsonl"
URL      = "http://localhost:8080/submit"

def clear_logs():
    """Delete existing log file so we start fresh."""
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    # Ensure the directory exists
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    open(LOG_FILE, "w").close()

def count_logs():
    if not os.path.exists(LOG_FILE):
        return 0
    with open(LOG_FILE, "r") as f:
        return len(f.readlines())

def get_last_log():
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    return json.loads(lines[-1]) if lines else None

def run_test(name, payload,
             expect_log=False,
             exp_attack_type=None,
             exp_severity=None,
             exp_pattern_substr=None):
    pre = count_logs()

    res = requests.post(URL, json={"input": payload})
    time.sleep(0.1)  # give server a moment to flush logs
    post = count_logs()
    body = res.json()

    # Determine expected status code
    exp_status = 200 if not expect_log else 403
    assert res.status_code == exp_status, (
        f"{name}: expected HTTP {exp_status}, got {res.status_code}"
    )

    if expect_log:
        assert post == pre + 1, (
            f"{name}: expected log count {pre+1}, got {post}"
        )
        log = get_last_log()
        assert log["attack_type"] == exp_attack_type, (
            f"{name}: attack_type {log['attack_type']} != {exp_attack_type}"
        )
        assert log["severity"] == exp_severity, (
            f"{name}: severity {log['severity']} != {exp_severity}"
        )
        if exp_pattern_substr:
            assert exp_pattern_substr.lower() in log["pattern"].lower(), (
                f"{name}: pattern '{log['pattern']}' "
                f"does not contain '{exp_pattern_substr}'"
            )
    else:
        assert post == pre, (
            f"{name}: expected no new log, but count went {pre}→{post}"
        )
    print(f"[PASS] {name}")

def main():
    clear_logs()

    tests = [
        # name                payload                                    expect_log, attack, severity, pattern fragment
        ("benign",             "hello world",                             False, None,    None,   None),
        ("long_benign",        "a" * 250,                                 False, None,    None,   None),
        ("sql_tautology",      "1 OR 1=1",                                True,  "SQLi",   "High", "or)\\b"),
        ("sql_drop",           "DROP TABLE users",                        True,  "SQLi",   "High", "drop table"),
        ("sql_union",          "1 UNION SELECT name FROM users",         True,  "SQLi",   "High", "union select"),
        ("sql_union_evasion",  "1 UNION/*foo*/SELECT * FROM users",      False, None,    None,   None),
        ("xss_basic",          "<script>alert('XSS')</script>",          True,  "XSS",    "High", "<script"),
        ("xss_inline",         "<img src=x onerror=alert(1)>",            True,  "XSS",    "High", "onerror"),
    ]

    for name, payload, expect_log, attack, sev, pat in tests:
        run_test(name, payload,
                 expect_log=expect_log,
                 exp_attack_type=attack,
                 exp_severity=sev,
                 exp_pattern_substr=pat)

    print("\nAll edge‐case tests passed!")

if __name__ == "__main__":
    main()