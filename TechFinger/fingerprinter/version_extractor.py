"""TechFinger — version extraction from matched indicators."""

from __future__ import annotations

import re
from typing import List, Optional


def normalize(version: str) -> str:
    """Strip v prefix and keep at most 3 numeric parts."""
    if not version:
        return ""
    v = version.strip().lstrip("vV")
    m = re.match(r"(\d+(?:\.\d+){0,2})", v)
    return m.group(1) if m else v


def extract(version_patterns: List[dict], response) -> Optional[str]:
    """Try each version_pattern in order; first match wins.

    `response` is a dict-like object with helpers:
      resp.body, resp.headers (dict lowercased), resp.cookies (dict),
      resp.meta (dict attr->content).
    """
    for vp in version_patterns:
        src = vp.get("source")
        regex = vp.get("regex")
        if not regex:
            continue
        text = _source_text(src, vp, response)
        m = re.search(regex, text, re.I)
        if m:
            grp = vp.get("version_group", 1)
            try:
                val = m.group(grp)
            except (IndexError, error := Exception):
                val = m.group(1)
            return normalize(val)
    return None


def _source_text(src: str, vp: dict, response) -> str:
    if src == "body":
        return response.body or ""
    if src == "header":
        field = vp.get("field", "")
        return f"{field}: {response.headers.get(field, '')}" if field else \
            " ".join(f"{k}:{v}" for k, v in response.headers.items())
    if src == "cookie":
        return " ".join(f"{k}:{v}" for k, v in response.cookies.items())
    if src == "meta":
        attr = vp.get("attribute", "")
        return f"{attr}: {response.meta.get(attr, '')}" if attr else \
            " ".join(f"{k}:{v}" for k, v in response.meta.items())
    return response.body or ""
