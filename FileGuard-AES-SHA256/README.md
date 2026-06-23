# FileGuard — Secure File Encryption & Integrity Verification

**Author:** Santhosh L
**License:** MIT

## Overview

FileGuard is a Python-based encryption tool that provides AES-256 encryption and SHA-256 integrity verification for files. It includes a GUI built with Tkinter for key generation, encryption, decryption, and integrity checking.

This project demonstrates real-world cybersecurity principles: data confidentiality, integrity, and secure cryptographic practices.

## Features

- AES-256 encryption via the `cryptography` library (Fernet symmetric encryption)
- SHA-256 hash verification for file integrity
- Tkinter GUI for key generation, encryption, and decryption
- Automatic folder management for `encrypted/` and `decrypted/` output
- Integrity check alerts to detect tampering

## Tech Stack

- Python 3.10+
- `cryptography` library (Fernet)
- `hashlib` (SHA-256)
- Tkinter (GUI)

## Installation

```bash
git clone https://github.com/Santhosh595/SecureNET-Toolkit-.git
cd SecureNET-Toolkit--main/FileGuard-AES-SHA256
pip install -r requirements.txt
python main.py
```

## Usage

1. Click **Generate Key** — creates `secret.key` (only needed once)
2. Click **Browse File** — select the file to encrypt
3. Click **Encrypt File** — file is encrypted and saved to `/encrypted/`
4. Click **Decrypt File** — decrypts the file and verifies SHA-256 integrity

## Project Structure

```
FileGuard-AES-SHA256/
├── main.py            # GUI application entry point
├── requirements.txt   # Python dependencies
├── README.md          # This file
├── LICENSE.txt        # MIT License
└── sample_files/      # Sample files for testing
```

## License

MIT License — see [LICENSE.txt](LICENSE.txt) for details.
