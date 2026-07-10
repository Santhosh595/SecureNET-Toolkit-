"""PathProbe — HTTP request engine.

Read-only GET probing with connection pooling, rotating user agents,
proxy support, redirect-chain capture (without following cross-domain),
and a single retry on connection reset.
"""

from __future__ import annotations

import random
import time

import requests

DEFAULT_UA = "PathProbe/1.0 (+https://github.com/Santhosh595/SecureNET-Toolkit-)"

ROTATING_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

_session = None
_adapter = None


def get_session() -> requests.Session:
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update({"Accept": "*/*", "Connection": "keep-alive"})
    return _session


def build_url(base_url: str, word: str) -> str:
    """Normalize base + word into a single URL (no double slashes)."""
    base = base_url.rstrip("/")
    w = word.strip()
    if w.startswith("/"):
        w = w[1:]
    # collapse accidental double slashes inside the word
    while "//" in w:
        w = w.replace("//", "/")
    return f"{base}/{w}"


def probe(base_url: str, word: str, *, timeout: float = 10.0,
          headers: dict | None = None, cookies: dict | None = None,
          user_agent: str | None = None, proxy: str | None = None,
          verify_ssl: bool = True) -> dict | None:
    """Send a single GET. Returns a result dict or None on transport failure
    (after one retry on connection reset)."""
    url = build_url(base_url, word)
    ua = user_agent or random.choice(ROTATING_UAS)
    req_headers = {"User-Agent": ua}
    if headers:
        req_headers.update(headers)

    attempt = 0
    last_exc = None
    while attempt <= 1:
        try:
            resp = get_session().request(
                "GET", url, headers=req_headers, cookies=cookies,
                timeout=timeout, allow_redirects=False, proxies={"http": proxy, "https": proxy} if proxy else None,
                verify=verify_ssl,
            )
            return _parse(resp, base_url, word, url)
        except requests.exceptions.ConnectionError as e:
            last_exc = e
            # retry once on connection reset / broken pipe
            attempt += 1
            time.sleep(0.3)
            continue
        except requests.RequestException as e:
            last_exc = e
            break
    return {"url": url, "error": str(last_exc)[:200], "status": 0, "size": 0,
            "content_type": "", "time_ms": 0, "redirect_to": None,
            "word_count": 0, "line_count": 0, "interesting": False, "word": word}


def _parse(resp, base_url, word, url) -> dict:
    t0 = time.time()
    body = resp.content
    size = len(body)
    ct = resp.headers.get("Content-Type", "")
    redirect_to = None
    if resp.is_redirect:
        loc = resp.headers.get("Location", "")
        # only record same-domain redirects as real; flag cross-domain
        if loc:
            redirect_to = loc
    text = body.decode("utf-8", errors="replace")
    words = len(text.split())
    lines = text.count("\n") + 1
    return {
        "url": url,
        "status": resp.status_code,
        "size": size,
        "content_type": ct,
        "time_ms": int((time.time() - t0) * 1000),
        "redirect_to": redirect_to,
        "word_count": words,
        "line_count": lines,
        "interesting": False,
        "word": word,
        "headers": dict(resp.headers),
        "_text": text,
    }
