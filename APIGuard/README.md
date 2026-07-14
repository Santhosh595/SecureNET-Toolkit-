# APIGuard

Automated REST API security testing against the OWASP API Security Top 10 (2023 edition).

Tests for broken object level authorization (BOLA/IDOR), broken authentication, excessive data exposure, mass assignment, rate limiting bypass, SSRF, CORS misconfiguration, injection vulnerabilities, and more.

## Quick Start

```bash
cd APIGuard
pip install -r requirements.txt

# Scan a public API (read-only, safe mode)
python main.py https://api.example.com

# With a Bearer token
python main.py https://api.example.com --auth bearer TOKEN

# Plus OpenAPI spec import
python main.py https://api.example.com --auth bearer TOKEN --spec openapi.json

# Single category
python main.py https://api.example.com --category API1,API3,API8

# JSON report
python main.py https://api.example.com --auth bearer TOKEN --json report.json

# Dashboard
python dashboard.py
# → http://localhost:5018
```

## Features

- **Full OWASP API Top 10 2023 coverage** — API1 through API10
- **API discovery** — path brute-force (300-entry wordlist), OpenAPI/Swagger parsing, response link crawling
- **Multiple auth modes** — Bearer, API key header, Basic, Cookie, OAuth2, Custom header, dual-mode (user + admin)
- **Rich CLI output** — color-coded findings table, summary stats
- **Flask dashboard** (port 5018) — 6 tabs: Setup, OWASP Coverage, Findings, Endpoints, History, Report
- **Report export** — JSON, CSV, SARIF, PDF
- **Safe by default** — read-only GET/OPTIONS/HEAD requests unless `--unsafe` flag is set
- **Injection bonus tests** — SQLi, XSS, path traversal, NoSQL injection

## Usage

```
usage: main.py [-h] [--auth AUTH] [--auth-user AUTH_USER] [--auth-admin AUTH_ADMIN]
               [--spec SPEC] [--category CATEGORY] [--unsafe]
               [--user-agent USER_AGENT] [--timeout TIMEOUT] [--delay DELAY]
               [--no-disclaimer] [--json JSON] [--csv CSV] [--sarif SARIF]
               [--pdf PDF]
               [url]
```

### Auth Formats

| Format | Example |
|--------|---------|
| `bearer TOKEN` | `--auth bearer eyJhbG...` |
| `apikey KEY:VALUE` | `--auth apikey X-API-Key:abc123` |
| `basic user:pass` | `--auth basic admin:secret` |
| `cookie VALUE` | `--auth cookie session=abc123` |
| `oauth TOKEN` | `--auth oauth ya29...` |
| `header NAME:VALUE` | `--auth header X-Custom:val` |
| `none` | `--auth none` |

### Dual-Mode Auth (Privilege Escalation)

```bash
python main.py https://api.example.com --auth-user "bearer USER_TOKEN" --auth-admin "bearer ADMIN_TOKEN"
```

### OpenAPI Spec

```bash
python main.py https://api.example.com --spec openapi.json
python main.py https://api.example.com --spec swagger.yaml
```

Supports OpenAPI 2.0, 3.0, and 3.1.

## Test Categories

| ID | Category | Severity |
|----|----------|----------|
| API1 | Broken Object Level Authorization (BOLA) | CRITICAL |
| API2 | Broken Authentication | CRITICAL |
| API3 | Broken Object Property Level Auth | HIGH |
| API4 | Unrestricted Resource Consumption | MEDIUM |
| API5 | Broken Function Level Authorization | CRITICAL |
| API6 | Unrestricted Access to Sensitive Business Flows | MEDIUM |
| API7 | Server Side Request Forgery (SSRF) | CRITICAL |
| API8 | Security Misconfiguration | HIGH |
| API9 | Improper Inventory Management | MEDIUM |
| API10 | Unsafe Consumption of APIs | HIGH |
| BONUS | Injection (SQLi, XSS, Path Traversal, NoSQL) | CRITICAL |

## Safe Testing

APIGuard is **safe by default**:
- Sends only GET, OPTIONS, and HEAD requests in safe mode
- BOLA testing increments IDs by ±1, ±2 only (no mass enumeration)
- Rate limit testing caps at 20 rapid requests
- SSRF testing uses 127.0.0.1/localhost probes only (no external callback services)
- Injection tests start with single-character probes before multi-char payloads
- Stops probing after a 500 error
- **Never sends DELETE requests or modifies data** without `--unsafe` flag
- Bearer tokens are stored as `[REDACTED]` in SQLite

## Dashboard

```bash
python dashboard.py
# Open http://localhost:5018
```

Tabs:
1. **Setup** — configure and launch scans
2. **OWASP Coverage** — 10 category cards with PASS/FAIL/PARTIAL status
3. **Findings** — filterable table with detail drawer
4. **Endpoints** — all discovered endpoints with auth status
5. **History** — past scan results
6. **Report** — JSON/CSV/SARIF export

## Project Structure

```
APIGuard/
├── main.py                    # CLI entry point
├── discovery/
│   ├── spec_parser.py         # OpenAPI/Swagger parser
│   ├── path_bruteforce.py     # API path discovery
│   └── response_crawler.py    # Link extraction
├── auth/
│   └── authenticator.py       # Auth method handler
├── tests/
│   ├── api1_bola.py           # API1: BOLA/IDOR
│   ├── api2_broken_auth.py    # API2: Broken Auth
│   ├── api3_object_props.py   # API3: Mass Assignment
│   ├── api4_rate_limiting.py  # API4: Rate Limiting
│   ├── api5_function_auth.py  # API5: Function Level Auth
│   ├── api6_business_flows.py # API6: Business Flows
│   ├── api7_ssrf.py           # API7: SSRF
│   ├── api8_misconfiguration.py # API8: Misconfig
│   ├── api9_inventory.py      # API9: Inventory
│   ├── api10_unsafe_consumption.py # API10: Unsafe Consumption
│   └── injection.py           # Bonus injection tests
├── analyzer/
│   ├── response_analyzer.py   # Response analysis
│   └── baseline.py            # Baseline tracking
├── wordlists/
│   └── api_paths.txt          # 300 API paths
├── database.py                # SQLite storage
├── reporter.py                # Export (JSON, CSV, SARIF, PDF)
├── dashboard.py               # Flask dashboard (port 5018)
├── templates/
│   └── index.html             # Dashboard template
├── LEARN.md
├── README.md
└── requirements.txt
```

## License

APIGuard is for testing APIs you own or have explicit written permission to test. Unauthorized API testing is illegal.
