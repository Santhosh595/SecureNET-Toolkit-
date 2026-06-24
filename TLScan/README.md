# TLScan — SSL/TLS Security Scanner & Certificate Auditor

**Author:** Santhosh L
**License:** MIT

## Overview

TLScan performs comprehensive SSL/TLS security audits on any domain or IP. It tests protocol versions, enumerates cipher suites, analyzes certificate chains, checks for 10 known CVE vulnerabilities, and grades the configuration from A+ to F — fully offline, no SSL Labs dependency.

## What TLS Security Means

SSL/TLS (Transport Layer Security) encrypts communication between clients and servers. A misconfigured TLS setup can expose traffic to interception, enable downgrade attacks, or allow certificate forgery. Regular TLS auditing is essential for maintaining trust and compliance (PCI-DSS, HIPAA, GDPR).

## Vulnerability Checks

| # | Vulnerability | CVE | Severity | Detection |
|---|--------------|-----|----------|-----------|
| 1 | POODLE | CVE-2014-3566 | CRITICAL | SSLv3 + CBC cipher |
| 2 | BEAST | CVE-2011-3389 | HIGH | TLS 1.0 + CBC cipher |
| 3 | CRIME | CVE-2012-4929 | HIGH | TLS compression enabled |
| 4 | BREACH | CVE-2013-3587 | MEDIUM | HTTP compression on HTTPS |
| 5 | Heartbleed | CVE-2014-0160 | CRITICAL | OpenSSL version check |
| 6 | ROBOT | CVE-2017-13099 | HIGH | RSA key exchange without FS |
| 7 | SWEET32 | CVE-2016-2183 | MEDIUM | 3DES cipher suite |
| 8 | DROWN | CVE-2016-0800 | CRITICAL | SSLv2 support |
| 9 | Weak DH (Logjam) | CVE-2015-4000 | HIGH | DH params < 2048 bit |
| 10 | Certificate Pinning | N/A | INFO | HPKP/Expect-CT headers |

## Grading System

Start at 100 points, deduct for each finding:

| Finding | Deduction |
|---------|-----------|
| Each CRITICAL | -20 |
| Each HIGH | -10 |
| Each MEDIUM | -5 |
| Each WEAK cipher | -2 |
| SSLv2/SSLv3 supported | Cap at F |
| Expired cert | Cap at F |
| Self-signed | Cap at B |

| Grade | Score |
|-------|-------|
| A+ | 95-100 |
| A | 90-94 |
| B | 75-89 |
| C | 50-74 |
| D | 35-49 |
| F | <35 or capped |

## CLI Usage

```bash
# Basic scan
python main.py example.com

# Custom port
python main.py example.com --port 8443

# Save report
python main.py example.com --save report.json

# Skip disclaimer
python main.py example.com --no-disclaimer
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5700
```

Features: live progress, tabbed results (Overview, Certificates, Protocols & Ciphers, Vulnerabilities), grade display, scan history, JSON export.

## Project Structure

```
TLScan/
├── main.py                # CLI entry point (Rich panels)
├── connector.py           # SSL connection + certificate extraction
├── protocol_tester.py     # Protocol version testing (SSLv2-TLS1.3)
├── cipher_enumerator.py   # Cipher suite enumeration (200+ ciphers)
├── vuln_checks/
│   └── __init__.py        # 10 vulnerability checks
├── grader.py              # SSL Labs-style A+ to F grading
├── database.py            # SQLite operations
├── dashboard.py           # Flask web dashboard
├── templates/
│   └── index.html         # Dashboard UI
├── requirements.txt
└── README.md
```

## Comparison with SSL Labs

| Feature | SSL Labs | TLScan |
|---------|----------|--------|
| Protocol testing | Yes | Yes |
| Cipher enumeration | Yes | Yes |
| Certificate chain | Yes | Yes |
| Vulnerability checks | 10+ | 10 |
| Grading | A-F | A+-F |
| Online required | Yes | No |
| Rate limited | Yes | No |
| API available | Yes | No (local only) |
| Cost | Free tier | Free |

## Legal Disclaimer

**TLScan is for authorized security auditing only.**

- Only scan domains you own or have explicit written permission to test.
- Unauthorized scanning may be illegal in your jurisdiction.
- Heartbleed PoC sends a malformed heartbeat request (clearly warned).
- The author assumes no liability for misuse.

## License

MIT License — free for personal, educational, and commercial use.
