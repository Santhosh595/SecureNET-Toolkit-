"""TechFinger — favicon hash matching (secondary detection)."""

from __future__ import annotations

import hashlib
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_DATA = os.path.join(os.path.dirname(_HERE), "data")


def favicon_md5(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def match_favicon(content: bytes) -> list:
    """Return list of tech names whose known favicon hash matches."""
    if not content:
        return []
    h = favicon_md5(content)
    path = os.path.join(_DATA, "favicon_hashes.json")
    try:
        import json
        data = json.load(open(path))
    except (json.JSONDecodeError, OSError):
        return []
    return [e["tech"] for e in data.get("favicon_hashes", [])
            if e.get("hash") == h]
