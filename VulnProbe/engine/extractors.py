"""Value extraction logic -- runs when a template matches.

Two extractor types:
    regex  -- capture named/numbered groups from body/header/all
    kval   -- extract a header or body key/value pair
"""

from __future__ import annotations

import re


def _part_text(resp, part: str) -> str:
    if part == "header":
        return "\n".join(f"{k}:{v}" for k, v in resp.headers.items())
    if part == "body":
        return resp.text or ""
    headers = "\n".join(f"{k}:{v}" for k, v in resp.headers.items())
    return f"{headers}\n{resp.text or ''}"


def _extract_regex(resp, ex: dict) -> dict:
    out = {}
    part = str(ex.get("part", "body")).lower()
    pattern = ex.get("pattern")
    if not pattern:
        return out
    flags = re.IGNORECASE if ex.get("case_insensitive") else 0
    haystack = _part_text(resp, part)
    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        return out
    name = ex.get("name", "extract")
    group = ex.get("group")
    m = compiled.search(haystack)
    if not m:
        return out
    if group is not None:
        try:
            out[name] = m.group(int(group))
        except (IndexError, TypeError):
            out[name] = ""
    elif m.groups():
        out[name] = m.group(1) if len(m.groups()) == 1 else list(m.groups())
    else:
        out[name] = m.group(0)
    return out


def _extract_kval(resp, ex: dict) -> dict:
    out = {}
    name = ex.get("name")
    part = str(ex.get("part", "body")).lower()
    if part == "header":
        key = ex.get("key", name)
        val = resp.headers.get(key) if key else None
        if val is not None:
            out[name or key] = val
    else:
        # key=value pair in body
        key = ex.get("key", name)
        if key:
            pattern = re.escape(key) + r"\s*[:=]\s*([^\s\"'<>]+)"
            m = re.search(pattern, resp.text or "", re.IGNORECASE)
            if m:
                out[name or key] = m.group(1)
    return out


def run_extractors(resp, extractors: list[dict]) -> dict:
    """Run all extractors; return a flat dict of name -> value."""
    result: dict = {}
    if not extractors:
        return result
    for ex in extractors:
        if not isinstance(ex, dict):
            continue
        etype = ex.get("type", "regex")
        if etype == "regex":
            result.update(_extract_regex(resp, ex))
        elif etype == "kval":
            result.update(_extract_kval(resp, ex))
    return result
