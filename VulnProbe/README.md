# VulnProbe — Template-Based HTTP Vulnerability Scanner

> Nuclei-style, read-only HTTP vulnerability scanning for authorized penetration testing.

VulnProbe loads YAML **probe templates**, sends read-only HTTP requests to a
target, and evaluates **multi-condition matchers** to detect exposed admin
panels, sensitive files, misconfigurations, version leaks, and CVEs. It ships
with **60 built-in templates across 8 categories**, a CLI with live streaming
output, a 5-tab Flask dashboard, SQLite persistence, and PDF/JSON/CSV reporting.

> **⚠️ Authorized use only.** Scanning targets without explicit permission is
> illegal. VulnProbe is for security professionals testing systems they own or
> are authorized to assess. Every request is **read-only (GET) by default** —
> no destructive payloads are ever sent.

---

## Features

- **60+ built-in templates** across 8 categories (exposed panels, sensitive
  files, version leaks, default-cred pages, misconfigurations, CVEs, API
  security, SSL/headers).
- **6 matcher types:** `status`, `word`, `regex`, `size`, `binary`, `header`.
- **Multi-condition logic:** each matcher block has an `operator` (AND/OR);
  blocks combine with `matchers_condition`.
- **Custom templates:** Nuclei-compatible YAML schema, validated on load,
  with a live validator in the dashboard.
- **Safety by design:** read-only GET by default; `--dry-run` plans requests
  without sending; open-redirect protection; per-host rate limiting; 429
  auto-backoff; max 20 paths per template.
- **CLI + Dashboard + Reports:** Rich streaming CLI; Flask dashboard
  (Scan / Findings / Template Library / History / Report); JSON, CSV, PDF.

## Tech Stack

`Python 3.8+` · `requests` · `PyYAML` · `rich` · `Flask` · `sqlite3` ·
`concurrent.futures` · `reportlab`

---

## Installation

```bash
cd VulnProbe
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI Usage

```bash
# Scan a single URL
python main.py https://target.com

# Filter by severity
python main.py https://target.com --severity high,critical

# Filter by category or tags
python main.py https://target.com --category exposed-panels --tags admin

# Scan a file of URLs or a bare domain (auto http/https)
python main.py targets.txt
python main.py example.com

# Throttle / parallelize
python main.py https://target.com --rate-limit 120 --threads 40

# Plan only — send nothing
python main.py https://target.com --dry-run

# JSON report to stdout
python main.py https://target.com --json

# Load custom templates too
python main.py https://target.com --templates ./my-templates
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `target` | — | URL, `@file` of URLs, or domain |
| `--templates` / `--template` | built-ins | Custom template dir or file |
| `--severity` | all | `critical,high,medium,low,info` |
| `--category` | all | Category slug |
| `--tags` | all | Comma-separated tag match (any) |
| `--rate-limit` | 150 | Requests/minute per host |
| `--threads` | 25 | Worker threads |
| `--timeout` | 10 | Per-request timeout (s) |
| `--dry-run` | off | Plan requests, send nothing |
| `--json` | off | Print JSON report to stdout |
| `--no-disclaimer` | off | Skip the authorization prompt |

---

## Dashboard

```bash
python dashboard.py
# http://127.0.0.1:5013
```

**Tabs**
1. **Scan** — target / filters / rate / threads / live output.
2. **Findings** — filterable, severity-colored table; click a row for the full
   detail drawer (request, response, triggering matcher, remediation).
3. **Template Library** — browse/filter templates, preview YAML, upload custom
   templates, and validate pasted YAML.
4. **Scan History** — past scans with finding counts; re-run a scan.
5. **Report** — export JSON / CSV / PDF (executive summary + findings + remediation).

### API endpoints

| Endpoint | Response |
|----------|----------|
| `GET /status` | `{tool, status, port, active_scan, templates_loaded}` |
| `GET /stats` | `{total_scans, total_findings, critical_findings, high_findings, templates_available}` |
| `GET /recent` | `{recent:[{tool, event, severity, timestamp}]}` |
| `POST /api/scan` | start a scan; `{scan_id, status, template_count}` |
| `GET /api/templates` | filtered template catalog |
| `POST /api/templates/validate` | validate pasted YAML |
| `POST /api/templates/upload` | upload + validate a template file |
| `GET /api/findings` | findings (filter by `scan_id`, `severity`, `category`, `template_id`) |
| `GET /api/report?format=json|csv|pdf` | export report |

---

## Template Schema

```yaml
id: exposed-admin-panel           # unique slug
name: Exposed Admin Panel Detection
description: >
  Detects publicly accessible admin panels.
author: SecureNET
severity: HIGH                    # CRITICAL/HIGH/MEDIUM/LOW/INFO
category: exposed-panels
tags: [admin, panel, exposure]
references:
  - https://owasp.org/www-project-top-ten/

requests:
  - method: GET                   # GET by default; POST requires safe: true
    path: [/admin, /administrator]
    headers:
      User-Agent: "Mozilla/5.0 (compatible; SecureNET/1.0)"
    follow_redirects: true
    timeout: 10
    matchers:                     # multi-condition matcher block
      operator: OR                # AND/OR within this block
      conditions:
        - type: status
          values: [200, 302]
        - type: word
          part: body              # body/header/all
          words: [admin, dashboard]
          condition: AND
        - type: regex
          part: body
          pattern: "(admin|panel)"
          case_insensitive: true
    matchers_condition: AND       # how this block combines with others
    extractors:
      - type: regex
        name: title
        part: body
        pattern: "<title>(.*?)</title>"

remediation: >
  Restrict admin panel access to internal IPs...
```

See **TEMPLATES.md** for the full schema reference, matcher reference, and
annotated examples.

---

## Integration with SecureNET Control Panel

- `securenet.yaml`: `vulnprobe` entry (port `5013`, entry `dashboard.py`).
- `quick_scan.py`: `quick_scan_vulnprobe(url, severity)` + `POST /api/quickscan/vulnprobe`.
- Landing page: tool card "VulnProbe".

## Safety Guarantees

- **Read-only by default** — only `GET`/`HEAD`/`OPTIONS` are sent unless a
  template sets `safe: true` *and* explains why with `safe_reason`.
- **`--dry-run`** shows exactly what would be sent, with zero requests.
- **Open-redirect protection** — redirects to a different host are never followed.
- **Rate limiting** — 150 req/min/host by default; honors `Retry-After`; pauses
  a host for 60s after 3 consecutive `429`s.
- **Duplicate-ID detection** — loader errors on duplicate template IDs.
- **Path cap** — max 20 paths per template (accidental DoS guard).

## Folder Structure

```
VulnProbe/
├── main.py              # CLI entry point
├── engine/              # loader, scanner, matchers, extractors, ratelimiter
├── templates/           # 60 built-in YAML templates (8 categories)
├── database.py          # SQLite operations
├── reporter.py          # JSON/CSV/PDF reports
├── dashboard.py         # Flask app
├── templates_web/index.html
├── TEMPLATES.md         # Custom template authoring guide
├── LEARN.md             # Beginner guide
├── requirements.txt
└── README.md
```

## License

MIT — SecureNET Toolkit.
