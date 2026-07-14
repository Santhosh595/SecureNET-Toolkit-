"""APIGuard — API path brute-force discovery (300-entry wordlist)."""

from __future__ import annotations

import os
from typing import Callable, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORDLIST = os.path.join(_HERE, "..", "wordlists", "api_paths.txt")


def load_wordlist(path: Optional[str] = None) -> List[str]:
    """Load API paths from the bundled wordlist."""
    p = path or _WORDLIST
    with open(p) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def probe_path(
    base_url: str,
    path: str,
    requester: Callable,
) -> Optional[dict]:
    """Probe a single path on the target. Returns {method, path, status, content_type} or None."""
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        resp = requester("GET", url)
        if resp is None:
            return None
        return {
            "method": "GET",
            "path": "/" + path.lstrip("/"),
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
        }
    except Exception:
        return None


def discover(
    base_url: str,
    requester: Callable,
    wordlist_path: Optional[str] = None,
    concurrency: int = 5,
) -> List[dict]:
    """Brute-force discover API endpoints. Returns list of {method, path, status, content_type}."""
    paths = load_wordlist(wordlist_path)
    results: List[dict] = []
    for i, p in enumerate(paths):
        result = probe_path(base_url, p, requester)
        if result:
            results.append(result)
    return results
