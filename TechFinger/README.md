# TechFinger — Web Technology Fingerprinter & Stack Analyzer

> WhatWeb / httpx-style fingerprinting: identify server software, frameworks,
> CMS platforms, CDN providers, analytics tools, and JavaScript libraries
> from a single HTTP request — then correlate detected versions with known CVEs.

TechFinger inspects **response headers, HTML body, cookies, meta tags,
HTML comments, JS/CSS file URLs, inline JS, favicon hash, plus optional
`robots.txt` / `sitemap.xml`** to detect **27+ signatures across 7 categories**,
score confidence, assess header coverage, and map versions to CVEs.

## 7 categories (27 signatures)

| # | Category | Signatures |
|---|----------|-------------|
| 1 | Server | Apache, Nginx, Microsoft IIS, LiteSpeed |
| 2 | Framework | Django, Laravel, Ruby on Rails, Express.js, ASP.NET |
| 3 | CMS | WordPress, Drupal, Joomla, Magento, Shopify |
| 4 | CDN | Cloudflare, AWS CloudFront, Fastly |
| 5 | Analytics | Google Analytics, Hotjar / Clarity |
| 6 | JS Libraries | jQuery, React, Bootstrap |
| 7 | Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy |

## Confidence scoring

- Each indicator has a `confidence_weight` (0-100). Final = **highest single weight**
  (not additive); **+10 boost if 3+ indicators match** (capped 100).
- Labels: `CERTAIN` 90-100 · `LIKELY` 70-89 · `POSSIBLE` 50-69 · `UNCERTAIN` <50.
- Version extracted from `version_patterns` (first match wins).

## CVE correlation

Detected tech + version is checked against `data/tech_cve_map.json`
(e.g. `WordPress 6.2.3 → CVE-2024-29803 (HIGH)`). Includes
Apache, nginx, IIS, WordPress, Drupal, Joomla, Magento, Laravel, Express,
Django, ASP.NET, jQuery, React, Bootstrap, PHP EOL rules.

## Usage

```bash
# Single target
python main.py https://example.com --no-disclaimer
python main.py https://example.com --full          # also robots.txt + sitemap.xml

# Custom UA / WAF evasion friendliness
python main.py https://example.com --user-agent "Googlebot/2.1"

# Bulk
python main.py --bulk urls.txt --csv out.csv --delay 2

# Dashboard (port 5017)
python dashboard.py
```

### CLI flags

| Flag | Description |
|------|-------------|
| `--full` | Also fetch `robots.txt` + `sitemap.xml` |
| `--delay N` | Seconds between bulk requests (default 1) |
| `--user-agent` | Custom User-Agent (default: realistic browser UA) |
| `--timeout N` | Request timeout (default 8s) |
| `--bulk FILE` | Scan URLs from file (one per line) |
| `--csv FILE` | Export bulk results to CSV |
| `--no-disclaimer` | Skip the authorization prompt |

## Dashboard (`localhost:5017`)

1. **Scan** — URL input, UA selector, `--full` toggle.
2. **Technology Stack** — category cards, confidence badges, version, risk summary.
3. **Security Headers** — pass/fail grid with current values.
4. **CVE Correlations** — tech / version / CVE / severity / CVSS + NVD link.
5. **Raw Evidence** — which indicators matched per technology (transparency).
6. **Bulk Scan** — upload URLs, results table, CSV export.
7. **History** — past scans with tech/CVE summary.

## SQLite schema (5 tables)

`scans` · `technologies` · `header_checks` · `cve_correlations` · `raw_indicators`.

## Tech stack

Python 3.8+ · `requests` · `beautifulsoup4` · `rich` · `flask` · `sqlite3` (stdlib).

## Signatures are JSON (community-extensible)

All rules live in `signatures/*.json` (one file per category) — **no Python changes
needed to add a detection**. See `SIGNATURES.md` for the format.

## Safety

- **Read-only**: a single GET (or GET + robots/sitemap with `--full`). Never modifies the target.
- **Realistic browser User-Agent** by default, so WAFs don't block the scan.
- **WAF detection**: if a challenge page is returned, TechFinger still reports
  the CDN/WAF it identified.
- **Rate-limited** bulk scans (1 req/s, configurable).
- **Disclaimer**: *"TechFinger sends a single read-only HTTP request. Only
  fingerprint sites you own or have permission to assess."*
