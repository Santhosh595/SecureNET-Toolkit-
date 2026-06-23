# SecureNET Toolkit

**Author:** Santhosh L
**License:** MIT

## Overview

SecureNET Toolkit is an open-source cybersecurity toolkit built with Python. It provides three independent security tools: a file encryption system, a network intrusion detection system, and an HTTP security header analyzer.

All tools are lightweight, offline-first (except for target URL/header lookups), and designed for developers, security students, and penetration testers.

## Tools

### FileGuard — AES-256 File Encryption

Encrypt and decrypt files with AES-256 symmetric encryption. Keys are derived from passwords using PBKDF2 (480,000 iterations). Every decryption verifies file integrity against a stored SHA-256 hash. Includes a Tkinter GUI.

**Tech:** Python, Tkinter, cryptography, hashlib

[View source](FileGuard-AES-SHA256/) | [README](FileGuard-AES-SHA256/README.md)

### Network Sniffer — Real-Time IDS

Capture live network packets, store them in SQLite, and detect intrusion patterns including port scans and packet floods. Includes a real-time Flask web dashboard with live stats and color-coded alerts.

**Tech:** Python, Scapy, Flask, SQLite

[View source](network-sniffer/) | [README](network-sniffer/README.md)

### HeaderScan — HTTP Security Header Analyzer

Analyze any website's HTTP response headers for security misconfigurations. Checks 10 critical headers, assigns risk levels (SAFE / WARNING / CRITICAL), computes an overall security score out of 100, and provides actionable fix recommendations. Works as both a CLI tool (with Rich tables) and a web dashboard.

**Tech:** Python, Flask, Requests, Rich

[View source](HeaderScan/) | [README](HeaderScan/README.md)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Santhosh595/SecureNET-Toolkit-.git
cd SecureNET-Toolkit--main
```

### FileGuard

```bash
cd FileGuard-AES-SHA256
pip install -r requirements.txt
python main.py
```

### Network Sniffer

Requires administrator/root privileges for packet capture.

```bash
cd network-sniffer
pip install -r requirements.txt
# Terminal 1: Start the sniffer
python sniffer_alert2.py
# Terminal 2: Start the dashboard
python app.py
# Open http://127.0.0.1:5000
```

### HeaderScan

```bash
cd HeaderScan
pip install -r requirements.txt

# CLI scan
python main.py https://example.com

# JSON output
python main.py https://example.com --json

# Web dashboard
python dashboard.py
# Open http://127.0.0.1:5100
```

## Running Tests

```bash
# FileGuard tests (15 tests)
cd FileGuard-AES-SHA256
python -m pytest test_main.py -v

# Network Sniffer tests (11 tests)
cd network-sniffer
python -m pytest test_sniffer.py -v
```

## Project Structure

```
SecureNET-Toolkit--main/
├── .gitignore
├── README.md
├── FileGuard-AES-SHA256/
│   ├── main.py              # GUI application (Tkinter)
│   ├── test_main.py         # Unit tests (15 tests)
│   ├── requirements.txt     # cryptography
│   ├── LICENSE.txt          # MIT License
│   ├── README.md            # Tool documentation
│   └── sample_files/        # Sample test files
├── network-sniffer/
│   ├── sniffer_alert2.py    # Main packet capture orchestrator
│   ├── app.py               # Flask dashboard server
│   ├── db.py                # SQLite database layer
│   ├── detector2.py         # Intrusion detection rules
│   ├── test_sniffer.py      # Unit tests (11 tests)
│   ├── requirements.txt     # flask, scapy
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── README.md            # Tool documentation
├── HeaderScan/
│   ├── main.py              # CLI entry point (Rich tables)
│   ├── analyzer.py          # Core header analysis engine
│   ├── dashboard.py         # Flask web dashboard
│   ├── requirements.txt     # requests, rich, flask
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── README.md            # Tool documentation
└── landing-page/
    ├── index.html           # Static landing page
    ├── styles.css           # Stylesheet
    └── script.js            # Scroll animations
```

## Tech Stack Summary

| Tool | Python | Flask | Requests | Scapy | Tkinter | cryptography | Rich |
|------|--------|-------|----------|-------|---------|--------------|------|
| FileGuard | Yes | — | — | — | Yes | Yes | — |
| Network Sniffer | Yes | Yes | — | Yes | — | — | — |
| HeaderScan | Yes | Yes | Yes | — | — | — | Yes |

## Scoring Methodology (HeaderScan)

HeaderScan uses a weighted scoring system out of 100:

| Header | Weight |
|--------|--------|
| Strict-Transport-Security | 20 |
| Content-Security-Policy | 20 |
| X-Frame-Options | 15 |
| X-Content-Type-Options | 10 |
| Referrer-Policy | 8 |
| Permissions-Policy | 7 |
| X-XSS-Protection | 5 |
| Cache-Control | 5 |
| Set-Cookie | 5 |
| Server / X-Powered-By | 5 |

- **SAFE** = full points, **WARNING** = half points, **CRITICAL** = 0 points
- Grade: A (90-100), B (75-89), C (50-74), F (below 50)

## Landing Page

A static landing page showcasing all tools is available in `landing-page/`. Open `index.html` in a browser to view it. Features dark theme, scroll animations, responsive layout, and tool cards with feature lists.

## License

MIT License — free for personal, educational, and commercial use.

## Disclaimer

This toolkit is intended for educational purposes and authorized security testing only. Always obtain proper authorization before scanning networks or systems you do not own.
