"""PathProbe core — web content/path discovery engine (feroxbuster-style).

Brute-forces common paths on a target host using a wordlist and reports
interesting HTTP status codes. Multi-threaded, read-only, safe.
"""

from __future__ import annotations

import concurrent.futures as cf
from pathlib import Path

import requests

DEFAULT_HEADERS = {
    "User-Agent": "PathProbe/1.0 (+https://github.com/Santhosh595/SecureNET-Toolkit-)"
}

# Status codes we consider "interesting" (excluding noise like 404).
INTERESTING = {200, 201, 202, 203, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 502}


def load_wordlist(path: str) -> list[str]:
    """Load wordlist; falls back to a tiny built-in list if missing."""
    p = Path(path)
    if p.is_file():
        words = [w.strip() for w in p.read_text().splitlines() if w.strip() and not w.startswith("#")]
        if words:
            return words
    return ["admin", "login", "dashboard", "api", "robots.txt", "config", "backup", ".env", "status"]


def probe(base_url: str, word: str, timeout: float) -> dict | None:
    url = base_url.rstrip("/") + "/" + word.lstrip("/")
    try:
        resp = requests.request("GET", url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None
    if resp.status_code not in INTERESTING:
        return None
    return {
        "path": "/" + word.lstrip("/"),
        "status": resp.status_code,
        "size": len(resp.content),
        "redirect": resp.headers.get("Location") if resp.is_redirect else None,
    }


def discover(base_url: str, wordlist: list[str], threads: int = 30, timeout: float = 6.0) -> list[dict]:
    """Discover interesting paths. Returns a list of finding dicts."""
    results: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(probe, base_url, w, timeout): w for w in wordlist}
        for fut in cf.as_completed(futures):
            res = fut.result()
            if res:
                res["target"] = base_url
                results.append(res)
    results.sort(key=lambda r: (r["status"], r["path"]))
    return results
