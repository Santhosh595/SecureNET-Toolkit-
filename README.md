# SecureNET Toolkit

**Author:** Santhosh L
**License:** MIT

## Overview

SecureNET Toolkit is an open-source cybersecurity toolkit built with Python. It provides **eighteen** independent security tools: a file encryption system, a network intrusion detection system, an HTTP security header analyzer, a multi-threaded port scanner, a hash identifier & cracker, a real-time ARP spoof detector, a subdomain enumerator, a JWT security analyzer, an SSL/TLS security scanner, a hardcoded secret scanner, a DNS security auditor, a template-based HTTP vulnerability scanner (Nuclei-style), a web content/path discovery tool (feroxbuster-style), a multi-cloud security posture checker (Prowler/ScoutSuite-style), a container/dependency CVE scanner (Trivy-style), a web technology fingerprinter (WhatWeb/httpx-style), and a unified control panel dashboard.

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

### PortMap — Multi-threaded Port Scanner

Scan any host for open ports using raw sockets — no Nmap dependency. Identifies running services on 70+ known ports, assigns risk levels (LOW / MEDIUM / HIGH), and provides actionable risk notes. Supports 4 scan profiles with multi-threaded scanning (100 workers). Works as both a CLI tool and a web dashboard with live polling.

**Tech:** Python, Sockets, Threading, Flask, Rich

[View source](PortMap/) | [README](PortMap/README.md)

### HashDetect — Hash Identifier & Cracker

Identify hash types from any string using length and pattern matching. Supports 18+ hash formats with confidence scoring and algorithm category tagging. Optional wordlist-based cracking for weak hashes (MD5, SHA-1, etc.). Fully local processing.

**Tech:** Python, Flask, hashlib, Rich

[View source](HashDetect/) | [README](HashDetect/README.md)

### ARPWatch — Real-Time ARP Spoof Detector

Passively monitors local network for ARP spoofing and poisoning attacks. Tracks IP-to-MAC mappings against a trusted baseline with 4 detection rules (MAC mismatch, gratuitous ARP, flood, gateway spoof). Real-time alerts with severity levels and SQLite logging.

**Tech:** Python, Scapy, Flask, SQLite, Rich

[View source](ARPWatch/) | [README](ARPWatch/README.md)

### SubProbe — Subdomain Enumerator

Enumerate subdomains via wordlist brute-force, Certificate Transparency logs (crt.sh), and DNS record analysis. Resolves IPs, checks HTTP status, flags interesting results (200/403), and detects wildcard DNS.

**Tech:** Python, DNS, Requests, Flask, Rich

[View source](SubProbe/) | [README](SubProbe/README.md)

### JWTInspect — JWT Security Analyzer

Decode and actively test JWT tokens for 8 vulnerability classes: alg:none confusion, weak secret brute-force, RS256→HS256 substitution, expiration issues, sensitive data exposure, kid injection, JKU/X5U abuse, and claim manipulation. Generates proof-of-concept forged tokens.

**Tech:** Python, Flask, PyJWT, Cryptography, Rich

[View source](JWTInspect/) | [README](JWTInspect/README.md)

### TLScan — SSL/TLS Security Scanner

Comprehensive SSL/TLS audit: protocol testing (SSLv2-TLS1.3), 200+ cipher enumeration, full certificate chain analysis, 10 CVE vulnerability checks (Heartbleed, POODLE, BEAST, etc.), and A+ to F grading. Fully offline, no SSL Labs dependency.

**Tech:** Python, Flask, SSL, Cryptography, Rich

[View source](TLScan/) | [README](TLScan/README.md)

### SecretSniff — Secret & API Key Scanner

Scan codebases, git history, and environment configs for 50+ types of hardcoded secrets. Integrates with pre-commit hooks and CI/CD pipelines via SARIF/JUnit output.

**Tech:** Python, Flask, Git, Regex, Entropy Analysis

[View source](DNSAudit/) | [README](DNSAudit/README.md)

### VulnProbe — Template-Based Vulnerability Scanner (Nuclei-style)

Send templated HTTP requests to a target and evaluate matchers (status / word / regex) to surface misconfigurations, exposed files, and version disclosure. Checks are read-only and safe; new checks are added by dropping a `.yaml` template — no code changes.

**Tech:** Python, Flask, Requests, PyYAML, Rich

[View source](VulnProbe/) | [README](VulnProbe/README.md)

### PathProbe — Web Content / Path Discovery (feroxbuster-style)

Discover hidden or forgotten web paths by brute-forcing a wordlist of common paths (admin panels, backups, configs, API roots). Multi-threaded, reports only "interesting" HTTP status codes. Read-only.

**Tech:** Python, Flask, Requests, Rich

[View source](PathProbe/) | [README](PathProbe/README.md)

### CloudSentry — Multi-Cloud Security Posture (Prowler/ScoutSuite-style)

Run read-only security posture checks across AWS, GCP, and Azure (S3 public access, IAM root MFA, root access keys, and more). Without credentials it reports INFO with guidance, so it never mutates cloud state.

**Tech:** Python, Flask, Rich

[View source](CloudSentry/) | [README](CloudSentry/README.md)

### ImgScan — Container / Dependency CVE Scanner (Trivy-style)

Find known vulnerabilities in `requirements.txt` (delegates to `pip-audit` when available, else a built-in offline rule set) and in image SBOMs (CycloneDX/SPDX JSON). Read-only and offline-first.

**Tech:** Python, Flask, Rich

[View source](ImgScan/) | [README](ImgScan/README.md)

### TechFinger — Web Technology Fingerprinting (WhatWeb/httpx-style)

Identify the technologies behind a web target by inspecting response headers, cookies, and body signatures. Detects servers, frameworks, CMS platforms, CDNs, analytics, JS libraries, and security headers. Fully read-only.

**Tech:** Python, Flask, Requests, Rich

[View source](TechFinger/) | [README](TechFinger/README.md)

### SecureNET Control Panel

Unified web dashboard that orchestrates all 12 security tools. Launch, monitor, and manage every tool from a single interface with real-time health checks, unified alerts, and quick-scan capabilities.

- [View source](SecureNET-Control-Panel/) | [README](SecureNET-Control-Panel/README.md)

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

### PortMap

```bash
cd PortMap
pip install -r requirements.txt

# Quick scan
python main.py 192.168.1.1

# Web dashboard
python dashboard.py
# Open http://127.0.0.1:5200
```

### HashDetect

```bash
cd HashDetect
pip install -r requirements.txt

# Identify a hash
python main.py 5f4dcc3b5aa765d61d8327deb882cf99

# Identify + crack
python main.py 5f4dcc3b5aa765d61d8327deb882cf99 --crack

# Web dashboard
python dashboard.py
# Open http://127.0.0.1:5300
```

### ARPWatch

```bash
cd ARPWatch
pip install -r requirements.txt

# Start monitoring (requires root)
sudo python main.py

# Web dashboard
python dashboard.py
# Open http://127.0.0.1:5400
```

### Sub Probe

```bash
cd SubProbe
pip install -r requirements.txt

# Full enumeration
python main.py example.com

# Web dashboard
python dashboard.py
# Open http://127.0.0.1:5500
```

### JWTInspect

```bash
cd JWTInspect
pip install -r requirements.txt

# Analyze a token
python main.py eyJhbG...NiIs...

# With secret cracking
python main.py <token> --crack

# Web dashboard
python dashboard.py
# Open http://127.0.0.1:5600
```

### TLScan

```bash
cd TLScan
pip install -r requirements.txt

# Basic scan
python main.py example.com

# Custom port
python main.py example.com --port 8443

# Web dashboard
python dashboard.py
# Open http://127.0.0.1:5700
```

### SecretSniff

```bash
cd SecretSniff
pip install -r requirements.txt

# Scan a directory
python main.py scan --path ./myproject

# Scan git history
python main.py scan --repo ./myrepo --history

# Export SARIF for GitHub Code Scanning
python main.py scan --path . --output results.sarif

# Install pre-commit hook
python main.py install-hook
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
├── PortMap/
│   ├── main.py              # CLI entry point (Rich progress bar)
│   ├── scanner.py           # Core scanning engine (raw sockets)
│   ├── dashboard.py         # Flask web dashboard
│   ├── requirements.txt     # rich, flask
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── README.md            # Tool documentation
├── HashDetect/
│   ├── main.py              # CLI entry point (Rich tables)
│   ├── detector.py          # Hash identification logic
│   ├── cracker.py           # Wordlist cracking engine
│   ├── wordlists/
│   │   └── common.txt       # Built-in wordlist (1000 passwords)
│   ├── dashboard.py         # Flask web dashboard
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── README.md            # Tool documentation
├── SubProbe/
│   ├── main.py              # CLI entry point (Rich tables)
│   ├── enumerator.py        # Core enumeration engine
│   ├── resolver.py          # DNS resolution + HTTP status checks
│   ├── ctlogs.py            # crt.sh API integration
│   ├── database.py          # SQLite operations
│   ├── dashboard.py         # Flask web dashboard
│   ├── wordlists/
│   │   └── subdomains.txt   # Built-in 500 subdomain wordlist
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── README.md            # Tool documentation
├── ARPWatch/
│   ├── main.py              # CLI entry point (Rich live display)
│   ├── sniffer.py           # Scapy ARP packet capture
│   ├── detector.py          # Detection rules (4 rules)
│   ├── baseline.py          # Baseline management
│   ├── database.py          # SQLite operations
│   ├── dashboard.py         # Flask web dashboard
│   ├── baseline.json        # Auto-generated baseline
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── README.md            # Tool documentation
├── JWTInspect/
│   ├── main.py              # CLI entry point (Rich panels)
│   ├── parser.py            # JWT decode + claims extraction
│   ├── tests/
│   │   └── __init__.py      # 8 security test modules
│   ├── wordlists/
│   │   └── secrets.txt      # Built-in 1000 JWT secrets
│   ├── reporter.py          # Report generation
│   ├── dashboard.py         # Flask web dashboard
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── README.md            # Tool documentation
├── TLScan/
│   ├── main.py              # CLI entry point (Rich panels)
│   ├── connector.py         # SSL connection + certificate extraction
│   ├── protocol_tester.py   # Protocol version testing
│   ├── cipher_enumerator.py # Cipher suite enumeration
│   ├── vuln_checks/
│   │   └── __init__.py      # 10 vulnerability checks
│   ├── grader.py            # SSL Labs-style grading
│   ├── database.py          # SQLite operations
│   ├── dashboard.py         # Flask web dashboard
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── README.md            # Tool documentation
├── SecretSniff/
│   ├── main.py              # CLI entry point (Rich output)
│   ├── scanner/
│   │   ├── file_scanner.py  # File/directory scanning
│   │   ├── git_scanner.py   # Git repo + history scanning
│   │   ├── env_scanner.py   # Env file targeting
│   │   └── entropy.py       # Shannon entropy calculator
│   ├── patterns/
│   │   └── rules.py         # 50+ regex patterns
│   ├── allowlist.py         # Allowlist management
│   ├── baseline.py          # Baseline comparison
│   ├── output/
│   │   ├── sarif.py         # SARIF format export
│   │   ├── junit.py         # JUnit XML export
│   │   └── reporter.py      # PDF report generation
│   ├── database.py          # SQLite operations
│   ├── dashboard/
│   │   ├── app.py           # Flask web dashboard
│   │   └── templates/
│   │       └── index.html   # Dashboard UI
│   └── README.md            # Tool documentation
├── SecureNET-Control-Panel/
│   ├── hub.py                # Main Flask app (control panel)
│   ├── start_all.py          # Master launcher script
│   ├── stop_all.py           # Graceful shutdown script
│   ├── process_manager.py    # Subprocess management
│   ├── health_monitor.py     # Background health checker
│   ├── alert_aggregator.py   # Pulls alerts from all tools
│   ├── quick_scan.py         # Quick scan orchestration
│   ├── proxy.py              # Tool dashboard proxy
│   ├── database.py           # SQLite for hub data
│   ├── securenet.yaml        # Master configuration
│   ├── static/
│   │   ├── css/
│   │   │   ├── main.css      # Design system + layout
│   │   │   └── components.css
│   │   └── js/
│   │       └── main.js       # Core app logic
│   ├── templates/
│   │   ├── base.html         # Base layout + nav
│   │   ├── command_center.html
│   │   ├── analytics.html
│   │   ├── alerts.html
│   │   ├── history.html
│   │   ├── tools_manager.html
│   │   └── docs.html
│   ├── logs/
│   └── requirements.txt
└── landing-page/
    ├── index.html           # Static landing page
    ├── styles.css           # Stylesheet
    └── script.js            # Scroll animations
```

## Tech Stack Summary

| Tool | Python | Flask | Requests | Scapy | Tkinter | Sockets | cryptography | Rich | hashlib | SQLite |
|------|--------|-------|----------|-------|---------|---------|--------------|------|---------|---------|
| FileGuard | Yes | — | — | — | Yes | — | Yes | — | — | — |
| Network Sniffer | Yes | Yes | — | Yes | — | — | — | — | — | — |
| HeaderScan | Yes | Yes | Yes | — | — | — | — | Yes | — | — |
| PortMap | Yes | Yes | — | — | — | Yes | — | Yes | — | — |
| HashDetect | Yes | Yes | — | — | — | — | — | Yes | Yes | — |
| ARPWatch | Yes | Yes | — | Yes | — | — | — | Yes | — | Yes |
| SubProbe | Yes | Yes | — | — | — | — | — | Yes | — | — |
| JWTInspect | Yes | Yes | — | — | — | — | — | Yes | — | — |
| TLScan | Yes | Yes | — | — | — | — | — | Yes | — | — |
| LogSentry | Yes | — | — | — | — | — | — | Yes | — | Yes |
| SecretSniff | Yes | — | — | — | — | — | — | Yes | — | Yes |
| DNSAudit | Yes | — | — | — | — | — | — | Yes | — | Yes |
| Control Panel | Yes | Yes | Yes | — | — | — | — | Yes | — | Yes |

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
