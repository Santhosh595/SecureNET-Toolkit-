# APIGuard — In-Depth Learning Guide

## Architecture

APIGuard is organized into five subsystems:

### 1. Discovery Layer
- **Spec Parser** (`discovery/spec_parser.py`): Parses OpenAPI 2.0/3.0/3.1 specs (YAML/JSON). Extracts paths, methods, parameters, auth requirements, and response schemas.
- **Path Brute-Force** (`discovery/path_bruteforce.py`): Probes a 300-entry wordlist against the target base URL. Filters meaningful responses (200, 401, 403, 405) from silent failures (404, connection errors).
- **Response Crawler** (`discovery/response_crawler.py`): Extracts `href`, `url`, `link` fields from JSON responses to discover additional endpoints.

### 2. Auth Layer (`auth/authenticator.py`)
- Parses the `--auth` flag string into structured config
- Supports: bearer, apikey, basic, cookie, oauth2, custom header, and dual-mode (user + admin)
- Token values are NEVER stored in SQLite (stored as `[REDACTED]`)

### 3. Test Engine (`tests/`)
- 10 OWASP API Top 10 2023 modules + 1 bonus injection module
- Each module exports a `run(requester, endpoints) -> List[Dict]` function
- Shared infrastructure in `tests/__init__.py`:
  - `ApiRequester` — HTTP wrapper with auth, timeout, safe mode enforcement
  - `check_auth_bypass` — helper for unauthenticated access checks
  - `cvss_for` — estimates CVSS v3 from severity label

### 4. Analysis Layer
- **Baseline Tracker** (`analyzer/baseline.py`): Records normal response behavior (status, timing, size, content-type) for anomaly detection.
- **Response Analyzer** (`analyzer/response_analyzer.py`): Post-request analysis — status code, timing deviation, sensitive field scanning, error message detection, input reflection.

### 5. Output Layer
- **CLI** (`main.py`): Rich-formatted findings table and summary
- **Dashboard** (`dashboard.py` + `templates/index.html`): Flask app at port 5018 with 6 tabs
- **Reporter** (`reporter.py`): JSON, CSV, SARIF v2.1.0, and PDF (via reportlab) export

## How Tests Work

Each test module:
1. Receives `ApiRequester` (authenticated HTTP client) and discovered `endpoints` list
2. Iterates over matching endpoints
3. Sends probes and analyzes responses
4. Returns structured findings dicts with: owasp_category, endpoint, method, test_name, severity, evidence, request/response, remediation, cvss_score, cwe_ref

### Safety Mechanisms

| Mechanism | Detail |
|-----------|--------|
| Safe mode | Only GET/OPTIONS/HEAD unless `--unsafe` set |
| BOLA limits | ±1, ±2 ID increments only |
| Rate test cap | 20 rapid requests maximum |
| SSRF probes | 127.0.0.1/localhost only (no external callbacks) |
| Injection phases | Single char first, stop on 500 |
| Token storage | `[REDACTED]` in SQLite |

## Customization

### Adding a new test

```python
# tests/my_test.py
from tests import ApiRequester

def run(requester: ApiRequester, endpoints):
    findings = []
    for ep in endpoints:
        resp = requester.get(ep['path'])
        # ... analyze ...
        findings.append({
            "owasp_category": "CUSTOM",
            "endpoint": ep['path'],
            "method": "GET",
            "test_name": "My custom test",
            "severity": "HIGH",
            "evidence": "Evidence text",
            "request_sent": f"GET {ep['path']}",
            "response_received": f"HTTP {resp.status_code}",
            "remediation": "Fix instructions",
            "cvss_score": 7.5,
            "cwe_ref": "CWE-123",
        })
    return findings
```

## Dashboard API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Health check |
| `/api/scan` | POST | Start scan |
| `/api/scan/progress` | GET | Poll scan progress |
| `/api/findings` | GET | List findings (supports `?scan_id=&severity=&owasp=`) |
| `/api/endpoints` | GET | List endpoints (`?scan_id=`) |
| `/api/history` | GET | Past scans |
| `/api/export/json` | GET | Export JSON |
| `/api/export/csv` | GET | Export CSV |
| `/api/export/sarif` | GET | Export SARIF |
