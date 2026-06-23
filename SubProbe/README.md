# SubProbe — Subdomain Enumerator & Recon Tool

**Author:** Santhosh L
**License:** MIT

## Overview

SubProbe enumerates subdomains of a target domain using three methods: wordlist brute-force, Certificate Transparency logs, and DNS record analysis. It resolves found subdomains to IPs, checks HTTP status, and flags interesting results.

All processing is local — no external APIs except crt.sh for CT log queries.

## What is Subdomain Enumeration?

Subdomain enumeration is a reconnaissance technique used in security assessments to discover all public-facing subdomains of a target organization. This helps identify attack surface, forgotten services, and potential entry points.

## Enumeration Methods

### Method 1 — Wordlist Brute-Force
- Built-in wordlist of 500 common subdomains (www, mail, ftp, admin, api, dev, etc.)
- Custom wordlist supported via `--wordlist` flag
- Multi-threaded DNS resolution (100 workers)
- Wildcard DNS detection and filtering

### Method 2 — Certificate Transparency (crt.sh)
- Queries crt.sh API for SSL/TLS certificate logs
- Extracts all unique subdomains from certificate records
- Handles wildcard certificates and SANs
- Rate-limited with 0.5s delay between requests

### Method 3 — DNS Record Analysis
- Queries MX, NS, TXT, CNAME, A records for the root domain
- Extracts hostnames found in record data
- Identifies mail servers, name servers, and other infrastructure

## CLI Usage

```bash
# Full enumeration (all 3 methods)
python main.py example.com

# Wordlist only
python main.py example.com --methods wordlist

# With custom wordlist
python main.py example.com --wordlist /path/to/subdomains.txt

# Skip disclaimer
python main.py example.com --no-disclaimer
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5500
```

Features: domain input, method checkboxes, results table with filters (live/interesting), stats cards, JSON/TXT export.

## Project Structure

```
SubProbe/
├── main.py              # CLI entry point (Rich tables)
├── enumerator.py        # Core enumeration engine
├── resolver.py          # DNS resolution + HTTP status checks
├── ctlogs.py            # crt.sh API integration
├── database.py          # SQLite operations
├── dashboard.py         # Flask web dashboard
├── wordlists/
│   └── subdomains.txt   # Built-in 500 subdomain wordlist
├── templates/
│   └── index.html       # Dashboard UI
├── requirements.txt
└── README.md
```

## Custom Wordlist Format

Plain text file, one subdomain prefix per line:

```
www
mail
ftp
admin
api
dev
staging
```

## Legal Disclaimer

**SubProbe is for authorized reconnaissance only.**

- Only scan domains you own or have explicit written permission to test.
- Unauthorized scanning may be illegal in your jurisdiction.
- The author assumes no liability for misuse.
- Always comply with applicable laws and regulations.

## License

MIT License — free for personal, educational, and commercial use.
