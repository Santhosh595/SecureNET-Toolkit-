# 🛡️ TechFinger — Learn Before You Use

New to web technology fingerprinting? This guide gets you started — no security background needed.

## What is fingerprinting?

Every website is built from *technologies*: a web server (Apache, nginx, IIS),
a framework (Django, Laravel, Express), a CMS (WordPress, Drupal), a CDN
(Cloudflare, CloudFront), analytics (Google Analytics), and JavaScript libraries
(jQuery, React, Bootstrap). These leave **telltale traces** in the HTTP response —
server headers, HTML comments, cookie names, meta tags, and file paths.

TechFinger reads those traces from a **single HTTP GET** and tells you the stack.

## Why does it matter?

- **Attack surface**: an exposed `Apache/2.4.49` header tells an attacker exactly
  which CVE to try (CVE-2021-41773, CVSS 9.8).
- **Outdated libraries**: jQuery < 3.5.0 ships known XSS vectors.
- **Missing defenses**: no `Strict-Transport-Security` → SSL-strip risk.
- **CVE correlation**: TechFinger maps each detected tech + version to known CVEs.

## The 7 categories (27 signatures)

| # | Category | Example signatures |
|---|----------|--------------------|
| 1 | Server | Apache, Nginx, IIS, LiteSpeed |
| 2 | Framework | Django, Laravel, Rails, Express, ASP.NET |
| 3 | CMS | WordPress, Drupal, Joomla, Magento, Shopify |
| 4 | CDN | Cloudflare, CloudFront, Fastly |
| 5 | Analytics | Google Analytics, Hotjar/Clarity |
| 6 | JS Libraries | jQuery, React, Bootstrap |
| 7 | Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy |

## Confidence scoring (how sure are we?)

Each signature has indicators, each with a weight (0-100). TechFinger takes the
**highest single weight** (not additive) and adds +10 if **3+ indicators** match:

- `CERTAIN` 90-100 · `LIKELY` 70-89 · `POSSIBLE` 50-69 · `UNCERTAIN` <50

## Quick start

```bash
pip install requests beautifulsoup4 rich flask
python main.py https://example.com --no-disclaimer
python main.py --bulk urls.txt --csv out.csv --delay 2
python dashboard.py   # http://localhost:5017
```

## Cautions

- **Read-only.** TechFinger never modifies the target. Only scan sites you own or
  are authorized to assess.
- **Realistic UA.** The default User-Agent is a normal browser, so WAFs don't
  block the request. If a WAF challenge page is returned, TechFinger still reports
  the CDN/WAF (e.g. Cloudflare) it detected.
- **Single request per target** by default. `--full` adds `robots.txt` + `sitemap.xml`.
- **Bulk rate-limit**: 1 request/sec by default (`--delay` to override).
- Signatures are **JSON** in `signatures/` — add your own without touching code.
  See `SIGNATURES.md`.
