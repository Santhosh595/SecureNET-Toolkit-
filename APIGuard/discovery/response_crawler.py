"""APIGuard — Response link extraction for endpoint discovery."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set

_URL_RE = re.compile(r'"((?:https?://[^"]+)|(?:/[a-zA-Z0-9_/.-]+))"')


def extract_urls_from_json(body: str, base_url: str) -> List[str]:
    """Extract URL-looking strings from JSON responses (href, url, link fields)."""
    urls: Set[str] = set()
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        # Fallback to regex
        for m in _URL_RE.finditer(body):
            urls.add(m.group(1))
        return sorted(urls)

    def _walk(obj: Any, _depth: int = 0) -> None:
        if _depth > 10:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_lower = k.lower()
                if k_lower in ("href", "url", "link", "self", "next", "prev", "first", "last", "api_url", "endpoint"):
                    if isinstance(v, str) and v and (v.startswith("http") or v.startswith("/")):
                        urls.add(v)
                elif isinstance(v, (dict, list)):
                    _walk(v, _depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, _depth + 1)

    _walk(data)

    # Normalize relative URLs
    normalized: List[str] = []
    base = base_url.rstrip("/")
    for u in sorted(urls):
        if u.startswith("/"):
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            normalized.append(f"{parsed.scheme}://{parsed.netloc}{u}")
        else:
            normalized.append(u)
    return normalized
