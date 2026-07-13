"""TechFinger — HTTP fetch + response parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests
from bs4 import BeautifulSoup

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

WAF_BODIES = ["cf-chl", "checking your browser", "ddos-guard", "enable javascript and cookies to continue"]


@dataclass
class Response:
    url: str
    status: Optional[int]
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    title: str = ""
    meta: Dict[str, str] = field(default_factory=dict)
    favicon: bytes = b""
    waf_detected: bool = False
    error: str = ""
    final_url: str = ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def fetch(url: str, timeout: float = 8.0, user_agent: str = BROWSER_UA,
          full: bool = False) -> dict:
    """Fetch target + optionally robots.txt / sitemap. Returns a Response."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    resp = Response(url=url, status=None)
    try:
        r = requests.get(url, headers=headers, timeout=timeout,
                         allow_redirects=True)
    except requests.RequestException as e:
        resp.error = str(e)
        return resp
    resp.status = r.status_code
    resp.final_url = r.url
    resp.headers = {k.lower(): v for k, v in r.headers.items()}
    resp.cookies = {k: v for k, v in r.cookies.items()}
    resp.body = r.text or ""
    resp.waf_detected = any(tok in resp.body.lower() for tok in WAF_BODIES)

    soup = BeautifulSoup(resp.body, "html.parser")
    t = soup.find("title")
    resp.title = (t.get_text(strip=True)[:80] if t else "")
    # meta tags
    for m in soup.find_all("meta"):
        name = (m.get("name") or m.get("property") or "").lower()
        content = m.get("content", "")
        if name:
            resp.meta[name] = content
    # favicon
    try:
        furl = None
        link = soup.find("link", rel=lambda r: r and "icon" in str(r).lower())
        if link and link.get("href"):
            href = link["href"]
            furl = href if href.startswith("http") else \
                (url.rstrip("/") + "/" + href.lstrip("/"))
        if furl:
            fr = requests.get(furl, headers=headers, timeout=timeout)
            if fr.ok:
                resp.favicon = fr.content
    except requests.RequestException:
        pass

    if full:
        _fetch_extra(resp, headers, timeout)
    return resp


def _fetch_extra(resp: Response, headers: dict, timeout: float) -> None:
    base = resp.final_url or resp.url
    from urllib.parse import urlparse, urlunparse
    p = urlparse(base)
    root = urlunparse((p.scheme, p.netloc, "", "", "", ""))
    for path in ("/robots.txt", "/sitemap.xml"):
        try:
            er = requests.get(root + path, headers=headers, timeout=timeout)
            if er.ok:
                resp.meta[f"extra:{path}"] = er.text[:4000]
        except requests.RequestException:
            pass


def get_response(url: str, **kw) -> Response:
    """Return a Response object (dataclass) from a fetch."""
    d = fetch(url, **kw)
    return d
