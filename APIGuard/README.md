# APIGuard — OWASP API Security Top 10 Tester

> Automated security testing for REST APIs — BOLA, broken auth, injection, SSRF, misconfigurations, and more.

APIGuard tests REST APIs against the **OWASP API Security Top 10** categories (API1–API10) plus injection. It discovers endpoints, authenticates via 6 modes, and runs targeted probes to find BOLA, broken authentication, excessive data exposure, mass assignment, rate-limit gaps, BFLA, business-flow flaws, SSRF, misconfigurations, inventory leaks, unsafe consumption, and injection vulnerabilities — all with **read-only safety by default**.

> **⚠️ Authorized use only.** Scanning APIs without explicit permission is illegal. APIGuard is for security professionals testing systems they own or are authorized to assess. By default every request is **safe (read-only)** — destructive probes require the `--unsafe` flag.

---

## Features

- **Full OWASP API Top 10 coverage** — API1 (BOLA) through API10 (Unsafe Consumption) + injection.
- **6 authentication modes** — none, bearer, apikey, basic, cookie, OAuth2.
- **OpenAPI spec parsing** — auto-discover endpoints from 2.0/3.0/3.1 specs.
- **Path brute-force** — 545-entry built-in wordlist when no spec is provided.
- **Safety by design** — BOLA limited to ±1/±2, rate-limit stops at 20 requests, SSRF targets 127.0.0.1 only, injection single-char + stop-on-500, tokens stored as `[REDACTED]`, destructive only with `--unsafe` flag.
- **CVE correlation** — maps findings to known CVEs where applicable.
- **CLI + Dashboard + Export** — Rich streaming CLI; Flask dashboard (Scan / Results / OWASP / Endpoints / History / Settings); JSON and PDF reports.
- **SQLite persistence** — scans, findings, and endpoints stored locally.

## Tech Stack

`Python 3.8+` · `requests` · `Flask` · `sqlite3` · `rich` · `PyYAML` · `reportlab`

---

## Installation

```bash
cd APIGuard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI Usage

```bash
# Scan an API with bearer authentication
python main.py https://api.example.com/v2 --auth "bearer eyJhbGci..."

# Scan without authentication (public API)
python main.py https://api.example.com/v2

# Filter by OWASP category
python main.py https://api.example.com --auth "bearer TOKEN" --category api1,api2

# Enable destructive tests (unsafe)
python main.py https://api.example.com --auth "bearer TOKEN" --unsafe

# Specify an OpenAPI spec for endpoint discovery
python main.py https://api.example.com --auth "bearer TOKEN" --spec ./openapi.yaml

# Export results
python main.py https://api.example.com --auth "bearer TOKEN" --export json results.json
python main.py https://api.example.com --auth "bearer TOKEN" --export pdf report.pdf

# Scan with API key auth
python main.py https://api.example.com --auth "apikey X-API-Key:sk_test_123"

# Scan using cookie auth
python main.py https://api.example.com --auth "cookie session=abc123"

# Scan with OAuth2
python main.py https://api.example.com --auth "oauth2 secret=XXXX|client_id=YYY|scope=read"
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `target` | — | API base URL (`https://api.example.com/v2`) |
| `--auth` | `none` | Auth mode: `none`, `bearer TOKEN`, `apikey NAME:VALUE`, `basic user:pass`, `cookie NAME=VALUE`, `oauth2 KEY=VALS` |
| `--category` | `all` | Comma-separated: `api1,api2,api3,api4,api5,api6,api7,api8,api9,api10,injection` |
| `--spec` | — | Path to an OpenAPI 2.0/3.0/3.1 spec file |
| `--unsafe` | off | Enable destructive tests (e.g., DELETE, PUT modifications) |
| `--export` | — | Export format: `json` or `pdf`, requires a filename |
| `--no-disclaimer` | off | Skip the authorization prompt |

---

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5018
```

**Tabs**
1. **Scan** — target URL, auth config, category selector, unsafe toggle, progress bar, stats.
2. **Results** — filterable findings table (severity/OWASP category), click for detail.
3. **OWASP Top 10** — coverage matrix showing tested vs untested categories.
4. **Endpoints** — discovered API endpoints from OpenAPI parsing or brute-force.
5. **History** — past scans with finding counts.
6. **Settings** — version info, safety constraint summary.

### API endpoints

| Endpoint | Response |
|----------|----------|
| `GET /api/status` | `{tool, version, status, modes}` |
| `POST /api/scan` | Start a scan; `{scan_id, summary, findings[], endpoints[], tests_run}` |
| `GET /api/history` | `[{id, target_url, findings_count, tests_run, timestamp}]` |

---

## Integration with SecureNET Control Panel

- `securenet.yaml`: `apiguard` entry (port `5018`, entry `dashboard.py`).
- `quick_scan.py`: `quick_scan_apiguard(url, auth)` + `POST /api/quickscan/apiguard`.
- Landing page: tool card "APIGuard".

## Safety Guarantees

- **Read-only by default** — destructive requests (`DELETE`, `PUT` modifications) require `--unsafe` flag.
- **BOLA fuzzing limited** — only tries resource ID ±1 and ±2 (not a brute-forcer).
- **Rate-limit testing capped** — stops after 20 requests to the same endpoint.
- **SSRF local-only** — only targets `127.0.0.1`; no external callback services.
- **Injection single-char first** — sends one character, stops on 500 response.
- **Bearer tokens redacted** — stored as `[REDACTED]` in SQLite database.
- **Auth values never logged** — no secrets written to terminal output.

## Folder Structure

```
APIGuard/
├── main.py              # CLI entry point
├── dashboard.py         # Flask web dashboard
├── database.py          # SQLite operations
├── reporter.py          # JSON / CSV / SARIF / PDF report export
├── LEARN.md             # Beginner-friendly learning guide
├── README.md
├── requirements.txt
├── auth/
│   └── authenticator.py # 6 auth modes
├── discovery/
│   ├── spec_parser.py   # OpenAPI 2.0/3.0/3.1 parser
│   ├── path_bruteforce.py  # Wordlist-based path discovery
│   └── response_crawler.py # Link crawler
├── analyzer/
│   ├── baseline.py      # Endpoint baseline (normal responses)
│   └── response_analyzer.py # Sensitive field detection
├── tests/               # 10 OWASP test modules + injection
│   ├── api1_bola.py     # Broken Object Level Authorization
│   ├── api2_broken_auth.py
│   ├── api3_excessive_data.py
│   ├── api4_rate_limit.py
│   ├── api5_bfla.py
│   ├── api6_business_flow.py
│   ├── api7_ssrf.py
│   ├── api8_misconfiguration.py
│   ├── api9_inventory.py
│   ├── api10_unsafe_consumption.py
│   └── injection.py
├── wordlists/
│   └── api_paths.txt    # 545 common API paths
└── templates/
    └── index.html       # Flask dashboard template
```

## License

MIT — SecureNET Toolkit.
