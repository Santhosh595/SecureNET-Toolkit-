# PathProbe — Web Content / Path Discovery (feroxbuster-style)

**Author:** Santhosh L
**License:** MIT
**Maps to trending tool:** [feroxbuster](https://github.com/epi052/feroxbuster) / [dirsearch](https://github.com/maurosoria/dirsearch)

## Overview

PathProbe discovers hidden or forgotten web paths on a target host by brute-forcing a wordlist of
common paths (admin panels, backups, config files, API roots). It is the Python-native,
SecureNET-styled equivalent of **feroxbuster** / **dirsearch**, using a thread pool for speed and
reporting only "interesting" HTTP status codes (2xx, 3xx redirects, 401/403, 5xx).

Multi-threaded and **read-only** — it never writes to or mutates the target.

## CLI Usage

```bash
# Discover paths with the built-in wordlist
python main.py https://example.com

# Custom wordlist + more threads
python main.py https://example.com --wordlist my-paths.txt --threads 50

# Skip disclaimer
python main.py https://example.com --no-disclaimer
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5014
```

## Project Structure

```
PathProbe/
├── main.py            # CLI entry point (Rich tables)
├── engine.py          # Multi-threaded discovery engine
├── database.py        # SQLite persistence
├── dashboard.py       # Flask web dashboard
├── wordlists/
│   └── common.txt     # 50+ common web paths
├── requirements.txt
└── README.md
```

## Legal Disclaimer

**PathProbe is for authorized testing only.** Scan only hosts you own or have explicit written
permission to test.

## License

MIT License — free for personal, educational, and commercial use.
