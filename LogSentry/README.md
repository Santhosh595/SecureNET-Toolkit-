# LogSentry — Multi-Source Log Analyzer & Threat Detector

```
  _                _   _               
 | |    ___   __ _| |_| |_ ___ _ __ ___ 
 | |   / _ \ / _` | __| __/ _ \ '__/ __|
 | |__| (_) | (_| | |_| ||  __/ |  \__ \
 |_____\___/ \__, |\__|\__\___|_|  |___/
             |___/                        
    Multi-Source Log Analyzer & Threat Detector
```

## What is LogSentry?

SOC analysts use log analysis to detect intrusions, identify attack patterns, and respond to security incidents in real time. LogSentry automates this process by ingesting logs from multiple sources (Linux auth, web servers, Windows Event Logs, firewalls), normalizing them into a unified schema, running 15 detection rules mapped to MITRE ATT&CK, correlating events across sources, and generating actionable incident reports — all offline and locally.

---

## Features

- **6 log formats**: Linux auth, Apache/Nginx access & error, Windows Event Logs, UFW/iptables, JSON/CSV
- **15 detection rules** with MITRE ATT&CK mapping
- **Cross-source IP correlation** and attacker profiling
- **Real-time monitoring** + historical analysis modes
- **ATT&CK Navigator JSON export**
- **Incident report**: JSON, CSV, PDF
- **Web dashboard** at localhost:5000
- **Offline processing**: No data leaves your system

---

## Supported Log Formats

### Format 1 — Linux Auth Log (`/var/log/auth.log`)
```
Jun 24 14:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jun 24 14:30:05 server sshd[1235]: Accepted password for admin from 10.0.0.5 port 44321 ssh2
Jun 24 14:31:00 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
```

### Format 2 — Apache/Nginx Access Log
```
192.168.1.100 - - [24/Jun/2024:14:30:00 +0000] "GET /admin/login HTTP/1.1" 200 4523 "-" "Mozilla/5.0"
10.0.0.5 - - [24/Jun/2024:14:30:05 +0000] "GET /../../etc/passwd HTTP/1.1" 404 124 "-" "sqlmap/1.5.2"
```

### Format 3 — Apache/Nginx Error Log
```
[Mon Jun 24 14:30:00.123456 2024] [auth_basic:error] [pid 1234] [client 192.168.1.100] AH01617: user admin: authentication failure
[Mon Jun 24 14:31:00.654321 2024] [error] [pid 1235] [client 10.0.0.5] File does not exist: /var/www/html/admin
```

### Format 4 — Windows Event Log (CSV/JSON)
```json
{"EventID": 4625, "TimeCreated": "2024-06-24T14:30:00Z", "Message": "An account failed to log on. Account Name: admin, Source Network Address: 192.168.1.100"}
{"EventID": 4728, "TimeCreated": "2024-06-24T14:31:00Z", "Message": "A member was added to a security-enabled global group. Member: attacker, Group: Domain Admins"}
```

### Format 5 — UFW/iptables Firewall Log
```
Jun 24 14:30:00 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0
```

### Format 6 — Generic JSON/CSV
```json
{"timestamp": "2024-06-24T14:30:00Z", "ip": "192.168.1.100", "user": "admin", "action": "login", "status": "failure"}
```

---

## Detection Rules (15 Rules)

| # | Rule | Severity | MITRE | Description |
|---|------|----------|-------|-------------|
| 1 | SSH Brute Force | HIGH | T1110.001 | 5+ failed SSH logins from same IP within 60s |
| 2 | SSH Success After Failures | CRITICAL | T1078 | Successful SSH login from IP with 3+ prior failures |
| 3 | Credential Stuffing | HIGH | T1110.003 | Same IP attempting login to 5+ different usernames |
| 4 | Off-Hours Login | MEDIUM | T1078 | Successful login between 11PM - 6AM |
| 5 | Root Login Attempt | HIGH | T1078.003 | Any direct root login attempt via SSH |
| 6 | Web Scanner Detection | MEDIUM | T1595 | User agent matching sqlmap, nikto, nmap, etc. |
| 7 | Directory Traversal | HIGH | T1083 | HTTP request containing `../`, `%2e%2e`, etc. |
| 8 | SQL Injection | HIGH | T1190 | HTTP request with SQLi patterns (union+select, etc.) |
| 9 | XSS Attempt | MEDIUM | T1059.007 | HTTP request with `<script`, `javascript:`, etc. |
| 10 | Port Scan | HIGH | T1046 | Same IP hitting 10+ different ports within 30s |
| 11 | Privilege Escalation | CRITICAL | T1078.002 | Windows EventID 4728/4732/4756 |
| 12 | New Service Installed | HIGH | T1543.003 | Windows EventID 7045 |
| 13 | Repeated 403/401 | MEDIUM | T1110 | 20+ forbidden responses from same IP in 5 min |
| 14 | Large Data Transfer | HIGH | T1030 | HTTP response > 10MB (possible exfil) |
| 15 | Geographic Anomaly | MEDIUM | T1078 | Login from country outside baseline |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Santhosh595/SecureNET-Toolkit--main.git
cd SecureNET-Toolkit--main/LogSentry

# Install dependencies
pip install -r requirements.txt

# (Optional) Download MaxMind GeoLite2 City database for geo anomaly detection
# 1. Create free account at https://www.maxmind.com/en/geolite2/signup
# 2. Generate license key
# 3. Download GeoLite2-City.mmdb and place in data/GeoLite2-City.mmdb
```

### Requirements
```
rich>=13.0.0
flask>=2.3.0
watchdog>=3.0.0
geoip2>=4.7.0
reportlab>=4.0.0
```

---

## CLI Usage

### Mode 1 — Historical Analysis
```bash
# Analyze single file (auto-detect type)
python main.py analyze --file /var/log/auth.log

# Analyze with type hint
python main.py analyze --file auth.log --type auth

# Analyze entire directory
python main.py analyze --dir /var/log/ --all

# Export report
python main.py analyze --file auth.log --output json --export-path report.json
python main.py analyze --file auth.log --output csv --export-path report.csv
python main.py analyze --file auth.log --output pdf --export-path report.pdf

# Export ATT&CK Navigator layer
python main.py analyze --file auth.log --attack --attack-path layer.json
```

### Mode 2 — Real-Time Monitoring
```bash
# Monitor auth log in real time
python main.py monitor --file /var/log/auth.log

# Monitor with type hint
python main.py monitor --file /var/log/access.log --type apache_access
```

### Mode 3 — Multi-Source Correlation
```bash
# Correlate multiple log sources
python main.py correlate --auth /var/log/auth.log --web /var/log/apache2/access.log --firewall /var/log/ufw.log

# Include Windows Event Logs
python main.py correlate --auth auth.log --web access.log --windows events.csv

# Export ATT&CK layer
python main.py correlate --auth auth.log --web access.log --attack-path correlate_layer.json
```

### Launch Web Dashboard
```bash
python main.py dashboard
# Open http://localhost:5000

# Custom port
python main.py dashboard --port 8080
```

---

## Web Dashboard

The Flask dashboard runs at `http://localhost:5000` with 6 pages:

1. **Overview** — Upload files, view stats, top attackers, recent alerts
2. **Timeline** — Chronological event list with severity/IP/rule filters
3. **Profiles** — Per-IP drill-down with kill chain mapping
4. **Rules** — All 15 rules with trigger counts and progress bars
5. **MITRE ATT&CK** — Technique heatmap, Navigator export
6. **Reports** — Generate and download JSON/CSV/PDF reports

### Dashboard Screenshots
*(Place actual screenshots here)*
- `docs/screenshots/overview.png` — Overview page with stats cards
- `docs/screenshots/timeline.png` — Threat timeline with filters
- `docs/screenshots/profiles.png` — Attacker profile drill-down
- `docs/screenshots/rules.png` — Rule analysis page
- `docs/screenshots/mitre.png` — MITRE ATT&CK mapping
- `docs/screenshots/reports.png` — Report generation page

---

## ATT&CK Navigator Export

1. Run analysis with `--attack` flag
2. Open https://mitre-attack.github.io/attack-navigator/
3. Click "Open Existing Layer" → "Upload Layer File"
4. Select your exported `logsentry_attack_layer.json`
5. View detected techniques on the ATT&CK matrix

---

## Updating Threat Intel IP List

The bundled threat intel database includes ~10,000 known malicious IPs from:
- abuse.ch (URLhaus, Threat Fox)
- Emerging Threats (ET Open)
- Spamhaus DROP lists
- Tor exit node lists

To update:
```bash
# Option 1: Replace data/ip_list.txt with your own CSV (ip,source,category)
# Option 2: Use the update script (when available)
python -c "from threat_intel.checker import load_threat_intel; load_threat_intel()"

# The bundled list uses RFC 5737 documentation ranges for demonstration.
# Replace with real threat intel for production use.
```

---

## Configuration

Edit `logsentry.yaml` to customize thresholds:

```yaml
detection:
  ssh_brute_force:
    threshold: 5          # Number of failures before alert
    time_window_seconds: 60
  port_scan:
    port_threshold: 10
    time_window_seconds: 30
  large_transfer:
    size_threshold_mb: 10
```

---

## Architecture

```
LogSentry/
├── main.py                 # CLI entry point
├── normalizer.py           # Unified schema mapping
├── database.py             # SQLite operations
├── ingester/               # 6 log format parsers
├── rules/                  # 15 detection rules
├── correlator.py           # Cross-source correlation
├── threat_intel/           # IP reputation checker
├── mitre/                  # ATT&CK mapping & Navigator export
├── reporter.py             # Report generation (JSON/CSV/PDF)
├── dashboard/              # Flask web interface
└── data/                   # GeoLite2 DB, threat intel
```

---

## Security & Legal

**LogSentry is for analyzing logs from systems you own or have explicit authorization to monitor.**

- All processing is fully local and offline
- No data is sent to external services
- No network connections during analysis
- GeoLite2 database is downloaded separately (free, requires MaxMind account)
- Bundled threat intel uses documentation ranges for demonstration

**Disclaimer**: This tool is intended for authorized security operations only. Users are responsible for ensuring compliance with all applicable laws and regulations.

---

## License

MIT License — See LICENSE file for details.
