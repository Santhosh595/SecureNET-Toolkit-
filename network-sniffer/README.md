# Network Sniffer — Real-Time IDS Dashboard

**Author:** Santhosh L
**License:** MIT

## Overview

A Python-based network packet sniffer with a real-time Flask dashboard. Monitors live network traffic, logs packets to SQLite, and detects suspicious activity using rule-based intrusion detection.

This project demonstrates the basics of an Intrusion Detection System (IDS) and real-time security monitoring.

## Features

- Real-time packet capture via Scapy
- SQLite-backed packet and alert storage
- Rule-based detection: port scan and high-rate flood
- Real-time Flask web dashboard with live stats
- Alert cooldown to prevent notification spam
- Graceful shutdown with packet/alert summary

## Tech Stack

- Python 3.10+
- Scapy (packet capture)
- Flask (web dashboard)
- SQLite (storage)

## Architecture

```
network-sniffer/
├── app.py              # Flask dashboard server
├── db.py               # Database layer (SQLite)
├── detector2.py        # Detection rules engine
├── sniffer_alert2.py   # Main sniffer orchestrator
├── requirements.txt    # Python dependencies
├── templates/
│   └── index.html      # Dashboard frontend
└── README.md           # This file
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Requires administrator/root privileges for packet capture.

**Terminal 1 — Start the sniffer:**
```bash
sudo python sniffer_alert2.py
```

**Terminal 2 — Start the dashboard:**
```bash
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Detection Rules

| Rule | Window | Threshold | Description |
|------|--------|-----------|-------------|
| PORT_SCAN | 10s | 10 unique ports | Source probes many destination ports |
| HIGH_RATE | 5s | 50 packets | Source sends excessive traffic |

Alerts have a 15-second cooldown per source to prevent duplicates.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Dashboard UI |
| `/packets` | Latest 50 packets (JSON) |
| `/alerts` | Latest 50 alerts (JSON) |
| `/stats` | Packet and alert counts (JSON) |

## License

MIT License — free for personal and educational use.
