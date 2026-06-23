# HashDetect — Hash Identifier & Wordlist Cracker

**Author:** Santhosh L
**License:** MIT

## Overview

HashDetect identifies hash types from a given string using length and pattern matching. It supports 18+ hash formats, assigns confidence scores, categorizes algorithms, and optionally attempts wordlist-based cracking for weak hashes.

All processing is fully local and offline — no external APIs.

## How Hash Identification Works

HashDetect uses a two-step identification process:

1. **Length matching** — The input length is compared against known hash lengths (e.g., 32 chars → MD5, NTLM, LM; 64 chars → SHA-256, SHA3-256).

2. **Pattern matching** — Regex patterns and charset analysis refine the match:
   - Hex-only input → cryptographic/weak hash
   - `$2a$` or `$2b$` prefix → bcrypt
   - `$argon2` prefix → Argon2
   - All uppercase 32 hex → likely LM Hash
   - Base64 characters → flagged as encoding, not hash

### Confidence Levels

| Confidence | Meaning |
|------------|---------|
| HIGH | Unique length + unmistakable pattern (e.g., bcrypt `$2a$...`) |
| MEDIUM | Shared length with distinguishable charset (e.g., MD5 vs NTLM — both 32 hex) |
| LOW | Ambiguous or variable length match |

### Algorithm Categories

| Category | Description | Examples |
|----------|-------------|----------|
| CRYPTOGRAPHIC | Secure hashing algorithms | SHA-256, SHA-512, SHA3-256, Whirlpool |
| WEAK | Known broken or deprecated | MD5, SHA-1, MySQL4, LM Hash |
| PASSWORD | Password storage hashes | NTLM, bcrypt, Argon2 |
| CHECKSUM | Non-cryptographic checksums | CRC32 |
| ENCODING | Not a hash — encoded data | Base64 |

## CLI Usage

```bash
# Identify a hash
python main.py 5f4dcc3b5aa765d61d8327deb882cf99

# Identify + attempt cracking
python main.py 5f4dcc3b5aa765d61d8327deb882cf99 --crack

# Use custom wordlist
python main.py 5f4dcc3b5aa765d61d8327deb882cf99 --crack --wordlist /path/to/wordlist.txt

# Custom timeout
python main.py <hash> --crack --timeout 60
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5300
```

Features: hash input, crack toggle, results table with confidence badges, green/red crack result box, JSON export.

## Project Structure

```
HashDetect/
├── main.py            # CLI entry point (Rich tables)
├── detector.py        # Hash identification logic
├── cracker.py         # Wordlist cracking engine
├── wordlists/
│   └── common.txt     # Built-in wordlist (1000 passwords)
├── dashboard.py       # Flask web dashboard
├── templates/
│   └── index.html     # Dashboard UI
├── requirements.txt
└── README.md
```

## Wordlist Format

Custom wordlists should be plain text files with one password per line:

```
password
123456
qwerty
admin
letmein
```

Lines starting with `#` are ignored. Empty lines are skipped.

## Legal & Ethical Disclaimer

**This tool is for educational and authorized use only.**

- Do not use HashDetect to crack hashes you do not own or without explicit permission.
- Unauthorized access to computer systems is illegal in most jurisdictions.
- The author assumes no liability for misuse of this tool.
- Always comply with applicable laws and regulations.

## License

MIT License — free for personal, educational, and commercial use.
