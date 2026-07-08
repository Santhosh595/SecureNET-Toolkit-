# TechFinger — Web Technology Fingerprinting (WhatWeb/httpx-style)

**Author:** Santhosh L
**License:** MIT
**Maps to trending tools:** [urbanadventurer/whatweb](https://github.com/urbanadventurer/whatweb) / [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)

## Overview

TechFinger identifies the technologies behind a web target by inspecting HTTP response headers,
cookies, and body signatures — the SecureNET-styled, Python-native answer to **WhatWeb** and
**httpx**. It detects servers (nginx/Apache/IIS), frameworks (Django/Flask/Laravel/ASP.NET),
CMS platforms (WordPress/Drupal/Joomla/Shopify), CDNs, analytics, JS libraries, and security
headers (HSTS/CSP). Fully **read-only**.

## CLI Usage

```bash
python main.py https://example.com
python main.py https://example.com --no-disclaimer
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5017
```

## Detection Categories

| Category | Examples |
|----------|----------|
| Server | nginx, Apache, Microsoft-IIS, Cloudflare |
| Framework | Django, Flask, Express, Laravel, PHP, ASP.NET |
| CMS | WordPress, Drupal, Joomla, Shopify |
| CDN | Cloudflare, Akamai, Amazon CloudFront |
| Analytics | Google Analytics, Matomo |
| JS-Lib | React, Vue, jQuery |
| Security | HSTS, Content-Security-Policy |

## Project Structure

```
TechFinger/
├── main.py            # CLI entry point (Rich tables)
├── engine.py          # Signature-based fingerprint engine
├── database.py        # SQLite persistence
├── dashboard.py       # Flask web dashboard
├── requirements.txt
└── README.md
```

## Legal Disclaimer

**TechFinger is for authorized reconnaissance only.** Scan only hosts you own or have explicit
permission to test.

## License

MIT License — free for personal, educational, and commercial use.
