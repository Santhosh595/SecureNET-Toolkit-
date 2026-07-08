"""TechFinger core — web technology fingerprinting (WhatWeb/httpx-style).

Fingerprints a target web server by inspecting response headers, cookies, and body
signatures against a rule set (server, frameworks, CDNs, CMS, analytics). Read-only.
"""

from __future__ import annotations

import re

import requests

DEFAULT_HEADERS = {
    "User-Agent": "TechFinger/1.0 (+https://github.com/Santhosh595/SecureNET-Toolkit-)"
}

# (category, name, regex_or_literal, where)  where in {header, body, cookie, server}
RULES = [
    ("Server", "nginx", r"nginx", "server"),
    ("Server", "Apache", r"Apache", "server"),
    ("Server", "Microsoft-IIS", r"Microsoft-IIS", "server"),
    ("Server", "Cloudflare", r"cloudflare", "server"),
    ("Framework", "Django", r"(csrftoken|__admin__|Django|djdt)", "any"),
    ("Framework", "Flask", r"Werkzeug|Flask", "any"),
    ("Framework", "Express", r"X-Powered-By: Express", "header"),
    ("Framework", "Laravel", r"laravel_session", "cookie"),
    ("Framework", "PHP", r"X-Powered-By: PHP|X-Powered-By:.*PHP|PHPSESSID", "any"),
    ("Framework", "ASP.NET", r"ASP.NET|ASPSESSIONID|\.aspx", "any"),
    ("CMS", "WordPress", r"wp-content|wp-includes|wordpress", "body"),
    ("CMS", "Drupal", r"Drupal|drupal_settings|jQuery.extend", "body"),
    ("CMS", "Joomla", r"joomla|option=com_", "body"),
    ("CMS", "Shopify", r"cdn.shopify.com|Shopify", "body"),
    ("CDN", "Cloudflare", r"cloudflare|__cfduid|cf_clearance", "any"),
    ("CDN", "Akamai", r"akamai|akamaized", "any"),
    ("CDN", "Amazon CloudFront", r"CloudFront", "server"),
    ("Analytics", "Google Analytics", r"google-analytics.com|gtag|ga\\(", "body"),
    ("Analytics", "Matomo", r"matomo|piwik", "body"),
    ("JS-Lib", "React", r"react(\.production|\.development)?\.js|/_next/|reactjs", "body"),
    ("JS-Lib", "Vue", r"vue(\.min)?\.js|__vue__", "body"),
    ("JS-Lib", "jQuery", r"jquery[.-][0-9]", "body"),
    ("Security", "HSTS", r"max-age=", "hsts"),
    ("Security", "CSP", r"content-security-policy", "header"),
]


def fingerprint(url: str, timeout: float = 8.0) -> dict:
    """Return a dict with detected tech, headers, server, status."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        return {"url": url, "error": str(e), "detected": [], "headers": {}, "status": None}

    headers = {k.lower(): v for k, v in resp.headers.items()}
    server = headers.get("server", "")
    body = resp.text or ""
    cookies = ";".join(resp.cookies.keys())
    hsts = headers.get("strict-transport-security", "")

    haystack = {
        "header": " ".join(f"{k}:{v}" for k, v in headers.items()),
        "body": body,
        "cookie": cookies,
        "server": server,
        "hsts": hsts,
        "any": " ".join(f"{k}:{v}" for k, v in headers.items()) + " " + body + " " + cookies,
    }

    detected = []
    for category, name, pattern, where in RULES:
        if where == "hsts":
            if hsts:
                detected.append({"category": category, "name": name, "evidence": hsts[:40]})
            continue
        text = haystack.get(where, "")
        if re.search(pattern, text, re.I):
            detected.append({"category": category, "name": name, "evidence": name})

    return {
        "url": url,
        "status": resp.status_code,
        "server": server,
        "title": _extract_title(body),
        "detected": detected,
        "headers": dict(headers),
    }


def _extract_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return m.group(1).strip()[:80] if m else ""
