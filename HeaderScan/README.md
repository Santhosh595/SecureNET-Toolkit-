# HeaderScan — HTTP Security Header Analyzer

**Author:** Santhosh L
**License:** MIT

## Overview

HeaderScan analyzes HTTP response headers of any URL for security misconfigurations. It checks 10 critical security headers, assigns risk levels (SAFE / WARNING / CRITICAL), computes an overall security score out of 100, and provides actionable fix recommendations.

Works as both a **CLI tool** (with Rich tables) and a **web dashboard** (Flask).

## What It Checks

| # | Header | Why It Matters |
|---|--------|----------------|
| 1 | Strict-Transport-Security | Forces HTTPS, prevents downgrade attacks |
| 2 | Content-Security-Policy | Prevents XSS by restricting resource loading |
| 3 | X-Frame-Options | Prevents clickjacking via iframe embedding |
| 4 | X-Content-Type-Options | Prevents MIME-type sniffing attacks |
| 5 | Referrer-Policy | Controls how much referrer info is leaked |
| 6 | Permissions-Policy | Restricts browser feature access (camera, mic, etc.) |
| 7 | X-XSS-Protection | Legacy XSS filter (should be disabled in favor of CSP) |
| 8 | Cache-Control | Prevents caching of sensitive content |
| 9 | Set-Cookie | Checks for Secure, HttpOnly, SameSite flags |
| 10 | Server / X-Powered-By | Detects technology stack information leakage |

## Scoring

- Each header has a weight (critical headers like HSTS and CSP are worth 20 points each)
- SAFE = full points, WARNING = half points, CRITICAL = 0 points
- Total possible: 100 points
- Grades: A (90-100), B (75-89), C (50-74), F (below 50)

## Installation

```bash
pip install -r requirements.txt
```

## CLI Usage

```bash
# Basic scan
python main.py https://example.com

# JSON output
python main.py https://example.com --json

# Custom timeout
python main.py https://example.com --timeout 10
```

### CLI Output Example

```
Score: 74/100  Grade: B
7/10 security headers present

┌─────────────────────────────┬────────┬───────────┬──────────────────────────────────┐
│ Header                      │ Status │ Risk      │ Current Value / Recommendation   │
├─────────────────────────────┼────────┼───────────┼──────────────────────────────────┤
│ Strict-Transport-Security   │  YES   │ SAFE      │ max-age=31536000                  │
│ Content-Security-Policy     │  NO    │ CRITICAL  │ Set a strict CSP...              │
│ X-Frame-Options             │  YES   │ SAFE      │ DENY                             │
│ ...                         │  ...   │ ...       │ ...                              │
└─────────────────────────────┴────────┴───────────┴──────────────────────────────────┘
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5100
```

Features:
- URL input form
- Prominent score and grade display
- Color-coded results table (green/yellow/red)
- Expandable rows with current values and recommendations
- Export results as JSON file

## Project Structure

```
HeaderScan/
├── main.py           # CLI entry point (Rich tables)
├── analyzer.py       # Core analysis engine
├── dashboard.py      # Flask web dashboard
├── templates/
│   └── index.html    # Dashboard UI
├── requirements.txt
└── README.md
```

## Error Handling

- Follows up to 5 redirects
- 5-second timeout (configurable)
- Handles connection errors, timeouts, and invalid URLs gracefully
- Works with both HTTP and HTTPS

## Disclaimer

For educational and authorized use only. HeaderScan does not store or log any URLs analyzed.
