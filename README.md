# SecureNET Toolkit

**Author:** Santhosh L
**License:** MIT

## Overview

SecureNET Toolkit is an open-source cybersecurity toolkit built with Python. It provides two independent security tools: a file encryption system and a network intrusion detection system.

## Tools

### FileGuard — AES-256 File Encryption
Encrypt and decrypt files with AES-256 symmetric encryption. Keys are derived from passwords using PBKDF2 (480,000 iterations). Every decryption verifies file integrity against a stored SHA-256 hash.

**Tech:** Python, Tkinter, cryptography, hashlib

[View source](FileGuard-AES-SHA256/) | [README](FileGuard-AES-SHA256/README.md)

### Network Sniffer — Real-Time IDS
Capture live network packets, store them in SQLite, and detect intrusion patterns including port scans and packet floods. Includes a real-time Flask web dashboard.

**Tech:** Python, Scapy, Flask, SQLite

[View source](network-sniffer/) | [README](network-sniffer/README.md)

## Landing Page

A static landing page showcasing the toolkit is available in `landing-page/`. Open `index.html` in a browser to view it.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Santhosh595/SecureNET-Toolkit-.git
cd SecureNET-Toolkit--main

# FileGuard
cd FileGuard-AES-SHA256
pip install -r requirements.txt
python main.py

# Network Sniffer (requires admin/root)
cd ../network-sniffer
pip install -r requirements.txt
python sniffer_alert2.py    # Terminal 1
python app.py               # Terminal 2
# Open http://127.0.0.1:5000
```

## Running Tests

```bash
# FileGuard tests
cd FileGuard-AES-SHA256
python -m pytest test_main.py -v

# Network Sniffer tests
cd ../network-sniffer
python -m pytest test_sniffer.py -v
```

## Project Structure

```
SecureNET-Toolkit--main/
├── .gitignore
├── README.md
├── FileGuard-AES-SHA256/
│   ├── main.py              # GUI application
│   ├── test_main.py         # Unit tests
│   ├── requirements.txt
│   └── README.md
├── network-sniffer/
│   ├── app.py               # Flask dashboard
│   ├── db.py                # Database layer
│   ├── detector2.py         # Detection engine
│   ├── sniffer_alert2.py    # Main sniffer
│   ├── test_sniffer.py      # Unit tests
│   ├── requirements.txt
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── README.md
└── landing-page/
    ├── index.html
    ├── styles.css
    └── script.js
```

## License

MIT License — free for personal, educational, and commercial use.
