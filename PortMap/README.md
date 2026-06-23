# PortMap — Multi-threaded Port Scanner & Risk Analyzer

**Author:** Santhosh L
**License:** MIT

## Overview

PortMap scans any target host for open ports using raw sockets — no Nmap dependency. Identifies running services, assigns risk levels, and provides actionable risk notes. Multi-threaded with 100 workers for speed.

Works as both a **CLI tool** (Rich progress bar + color-coded tables) and a **web dashboard** (Flask with live polling).

## Port Profiles

| Profile | Ports | Count |
|---------|-------|-------|
| quick   | Top 20 most common | 20 |
| common  | Top 100 ports | ~100 |
| full    | 1-1024 | 1024 |
| custom  | User-defined range | Varies |

## Service Detection

Recognizes 70+ services: FTP, SSH, Telnet, SMTP, DNS, HTTP, HTTPS, SMB, RDP, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, VNC, and more.

## Risk Levels

| Risk | Meaning | Examples |
|------|---------|----------|
| LOW | Encrypted / low-risk | SSH (22), HTTPS (443), LDAPS (636) |
| MEDIUM | Needs hardening | HTTP (80), SMTP (25), LDAP (389) |
| HIGH | Known attack vector | Telnet (23), FTP (21), SMB (445), RDP (3389), Redis (6379), MongoDB (27017) |

## CLI Usage

```bash
# Quick scan (default)
python main.py 192.168.1.1

# Common ports
python main.py example.com --profile common

# Full scan
python main.py 10.0.0.1 --profile full

# Custom range
python main.py 192.168.1.1 --profile custom --custom 8000-9000

# Custom timeout and workers
python main.py target.com --timeout 2 --workers 50

# Skip disclaimer
python main.py 192.168.1.1 --yes

# Safe mode (refuse private IPs)
python main.py 192.168.1.1 --safe
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5200
```

Features: target input with profile dropdown, live progress bar, summary cards, color-coded results table, JSON export.

## Technical Details

- **Raw sockets** — no Nmap or third-party scanning libraries
- **Thread pool** — 100 concurrent workers (configurable)
- **Timeout** — 1 second per port (configurable)
- **DNS resolution** — hostnames resolved to IPv4
- **No data persistence** — results never stored server-side

## Legal Disclaimer

**PortMap is for authorized security testing only.**

- Scanning hosts without explicit written permission is illegal in most jurisdictions.
- You are solely responsible for ensuring you have authorization.
- The author assumes no liability for misuse.
- Always comply with local laws and regulations.

## License

MIT License — free for personal, educational, and commercial use.
