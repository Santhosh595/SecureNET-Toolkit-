# ARPWatch — Real-Time ARP Spoof Detector

**Author:** Santhosh L
**License:** MIT

## Overview

ARPWatch passively monitors your local network for ARP spoofing and poisoning attacks. It tracks IP-to-MAC mappings against a trusted baseline and fires instant alerts when inconsistencies are detected.

All processing is local. No packets are modified — read-only passive monitoring only.

## What is ARP Spoofing?

ARP spoofing (or ARP poisoning) is an attack where a malicious actor sends falsified ARP messages on a local network. This links the attacker's MAC address with the IP address of a legitimate device (often the gateway), allowing the attacker to intercept, redirect, or modify traffic.

## Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| MAC Mismatch | Known IP seen with different MAC | WARNING |
| Gratuitous ARP | ARP reply with sender IP = target IP from unknown MAC | WARNING |
| ARP Flood | >50 ARP packets from one MAC in 10 seconds | WARNING |
| Gateway Spoof | Gateway IP seen with different MAC from baseline | CRITICAL |

## Installation

```bash
pip install -r requirements.txt
```

**Note:** Requires root/sudo for packet capture.

## CLI Usage

```bash
# Start monitoring (auto-detect interface and gateway)
sudo python main.py

# Specify network interface
sudo python main.py --iface eth0

# Rebuild baseline from current ARP table
sudo python main.py --reset

# Load saved baseline
sudo python main.py --file baseline.json
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5400
```

Features: live event table, critical alert banner, baseline viewer, stats cards, JSON export, alert filter.

## Baseline Management

- **First run:** ARP table is scanned automatically, baseline saved to `baseline.json`
- **--reset:** Clears baseline and rebuilds from current ARP table
- **--file path:** Loads a previously saved baseline from JSON
- Baseline format: `{ "192.168.1.1": "aa:bb:cc:dd:ee:ff", ... }`

## Cooldown

Same alert type for the same IP is suppressed for 60 seconds to prevent spam.

## Project Structure

```
ARPWatch/
├── main.py            # CLI entry point (Rich live display)
├── sniffer.py         # Scapy ARP packet capture
├── detector.py        # Detection rules (4 rules)
├── baseline.py        # Baseline management
├── database.py        # SQLite operations
├── dashboard.py       # Flask web dashboard
├── baseline.json      # Auto-generated on first run
├── templates/
│   └── index.html     # Dashboard UI
├── requirements.txt
└── README.md
```

## Database Schema

**arp_log:** id, timestamp, src_ip, src_mac, dst_ip, alert_type, severity
**baseline:** ip, mac, first_seen, last_seen
**alerts:** id, timestamp, type, severity, ip, expected_mac, seen_mac, verdict

## Legal Disclaimer

**ARPWatch is for use on networks you own or have explicit permission to monitor.**

- Unauthorized network monitoring is illegal in most jurisdictions.
- This tool is for defensive security purposes only.
- The author assumes no liability for misuse.
- Always comply with applicable laws and regulations.

## License

MIT License — free for personal, educational, and commercial use.
