# PathProbe — Multi-Threaded Web Content Discovery

> feroxbuster / dirsearch-style content discovery for authorized penetration testing.

PathProbe brute-forces URL paths from wordlists to find hidden files,
directories, backup files, admin panels, and API endpoints — with smart
false-positive filtering, extension fuzzing, recursive scanning, and a live
Flask dashboard.

## Features

- **4 built-in wordlists** — `common` (500), `api` (300), `files` (200), `large` (5000)
- **Extension fuzzing** — `--extensions php,html,bak,zip` tests `/admin`, `/admin.php`, `/admin.bak`…
- **Wildcard detection** — 3 random probes detect "200 for everything" servers and switch to content-length filtering
- **Recursive scanning** — `--recursive --depth N` maps the full directory tree
- **Smart filtering** — status, size, size-range, and word filtering; auto-drop of 404 noise
- **Read-only** — only `GET` requests; never POST/PUT/DELETE
- **Live streaming** — Rich CLI progress + Flask dashboard with live table, stats, tree, history, export
- **Rate limiting** — `--rate-limit`, `--delay`, auto-backoff on 429
- **Proxy / custom UA / headers / cookies** support

## Quick Start

```bash
# install
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# CLI — scan with the common wordlist
.venv/bin/python main.py https://example.com --wordlist common

# with extension fuzzing + recursion
.venv/bin/python main.py https://example.com \
    --wordlist common,api --extensions php,bak,zip \
    --recursive --depth 3 --threads 80

# Flask dashboard (http://127.0.0.1:5014)
.venv/bin/python dashboard.py
```

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `target` | — | Base URL (https added if missing) |
| `--wordlist` | `common` | Built-in name(s) or file(s), comma-separated |
| `--extensions` | — | Append extensions: `php,html,bak,old,zip` |
| `--no-extension-original` | off | Skip bare word (only extensions) |
| `--prefix` | — | Path prefix for all words: `/api/v1` |
| `--threads` | `50` | Concurrency (hard cap 200) |
| `--timeout` | `10` | Per-request timeout (s) |
| `--rate-limit` | — | Max requests per second |
| `--delay` | `0` | Fixed delay between requests (ms) |
| `--headers` | — | `X-Fwd-For: 1.1.1.1; Auth: Bearer x` |
| `--cookies` | — | `session=abc; uid=1` |
| `--user-agent` | rotate | Custom UA (default rotates 5 browser UAs) |
| `--proxy` | — | `http://127.0.0.1:8080` |
| `--recursive` | off | Recursively scan found directories |
| `--depth` | `2` | Max recursion depth |
| `--recursive-status` | `200,301,302` | Status codes that trigger recursion |
| `--filter-status` | — | Only show these codes |
| `--hide-status` | — | Hide these codes |
| `--filter-size` | — | Hide exact response size |
| `--filter-size-range` | — | Hide size range `100-200` |
| `--filter-words` | — | Hide responses containing `not found,404` |
| `--no-wildcard` | off | Disable wildcard detection |
| `--respect-robots` | off | Skip `robots.txt` disallowed paths |
| `--output` | — | Write found URLs (one per line) to file |

## Dashboard (port 5014)

Six sections: **Scan Config**, **Live Results** (streaming table + stats),
**Results** (filter/sort, click row for header preview), **Directory Tree**
(visual tree of discovered paths), **History** (past scans + re-run),
**Export** (JSON / CSV / plain-text URL list, interesting-only filter).

Endpoints: `/status`, `/stats`, `/recent`, `/api/wordlists`, `/api/scan`,
`/api/scan/stop`, `/api/results`, `/api/findings/<id>`, `/api/tree/<id>`,
`/api/scans`, `/api/export`.

## Built-in Wordlists

| File | Entries | Contents |
|------|---------|----------|
| `wordlists/common.txt` | 500 | admin, login, api, dashboard, backup, config, uploads, wp-admin, .git, .env, robots.txt… |
| `wordlists/api.txt` | 300 | /api/v1, /api/users, /graphql, /swagger, /health, /actuator, /api-docs… |
| `wordlists/files.txt` | 200 | .htaccess, .htpasswd, web.config, .env, config.php, id_rsa, authorized_keys… |
| `wordlists/large.txt` | 5000 | Combined deep-discovery list |

## Safety Limits

- Max threads **200** (prevents accidental DoS)
- Max **50,000** requests per scan (warns if exceeded)
- **GET only** — never mutates the target
- Target unreachable after 3 attempts → aborts with a clear error
- Deduplicates words across merged wordlists
- Auto-detects `429` and reduces rate

## Disclaimer

> PathProbe is for authorized testing only. Scanning websites without permission is illegal.

## Tech Stack

Python 3.8+ · requests · rich · Flask · sqlite3 · concurrent.futures
