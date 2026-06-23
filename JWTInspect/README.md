# JWTInspect — JWT Security Analyzer & Vulnerability Tester

**Author:** Santhosh L
**License:** MIT

## Overview

JWTInspect is a production-grade security audit tool that decodes, analyzes, and actively tests JWT tokens for 8 known vulnerability classes. It performs algorithm confusion attacks, weak secret brute-forcing, claim manipulation detection, and generates proof-of-concept forged tokens.

All analysis is fully local and offline — no tokens are sent externally.

## What is JWT?

JSON Web Tokens (JWT) are a compact, URL-safe means of representing claims to be transferred between two parties. They are widely used for authentication and information exchange in web applications, APIs, and microservices.

## Security Tests

| # | Test | CVE Reference | Severity |
|---|------|---------------|----------|
| 1 | Algorithm Confusion (alg:none) | CVE-2015-9235 | CRITICAL |
| 2 | Weak Secret Brute Force | — | CRITICAL |
| 3 | Algorithm Substitution (RS256→HS256) | CVE-2018-0114 | CRITICAL |
| 4 | Expiration Check | — | CRITICAL/HIGH |
| 5 | Sensitive Data Exposure | — | HIGH |
| 6 | Kid Header Injection | CVE-2018-0114 | HIGH |
| 7 | JKU/X5U Header Abuse | — | HIGH |
| 8 | Claim Manipulation Detection | — | MEDIUM/HIGH |

## CLI Usage

```bash
# Analyze a token
python main.py eyJhbGciOiJIUzI1NiIs...

# With secret cracking
python main.py <token> --crack

# Custom wordlist for cracking
python main.py <token> --crack --wordlist /path/to/secrets.txt

# Compare two tokens (claim diff)
python main.py <token1> --compare <token2>

# Save report to file
python main.py <token> --save report.json

# Skip disclaimer
python main.py <token> --no-disclaimer
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5600
```

Features: 4-tab interface (Decoded Token, Claims Analysis, Security Tests, Forged Tokens), verdict banner, color-coded severity badges, JSON export.

## Project Structure

```
JWTInspect/
├── main.py              # CLI entry point (Rich panels)
├── parser.py            # JWT decode + claims extraction
├── tests/
│   └── __init__.py      # 8 security test modules
├── wordlists/
│   └── secrets.txt      # Built-in 1000 JWT secrets
├── reporter.py          # Report generation
├── dashboard.py         # Flask web dashboard
├── templates/
│   └── index.html       # Dashboard UI
├── requirements.txt
└── README.md
```

## References

- PortSwigger JWT Attacks: https://portswigger.net/web-security/jwt
- RFC 7519 (JWT): https://datatracker.ietf.org/doc/html/rfc7519
- RFC 7517 (JWK): https://datatracker.ietf.org/doc/html/rfc7517
- CVE-2015-9235: alg:none bypass
- CVE-2018-0114: Key confusion in JWT

## Legal Disclaimer

**JWTInspect is for authorized security testing only.**

- Only test tokens you own or have explicit written permission to test.
- Unauthorized access to computer systems is illegal.
- All forged tokens are testing artifacts only.
- The author assumes no liability for misuse.

## License

MIT License — free for personal, educational, and commercial use.
