"""Matcher implementations -- all 6 types.

A matcher evaluates a *single* condition block. The scanner combines
multiple matchers with the block-level ``operator`` (OR / AND) and the
request-level ``matchers_condition``.
"""

from __future__ import annotations

import binascii
import re

from urllib.parse import urlparse


def _part_text(resp, part: str) -> str:
    """Return the text to search for the given matcher ``part``."""
    if part == "header":
        return "\n".join(f"{k}:{v}" for k, v in resp.headers.items())
    if part == "body":
        return resp.text or ""
    # "all" -> headers + body
    headers = "\n".join(f"{k}:{v}" for k, v in resp.headers.items())
    return f"{headers}\n{resp.text or ''}"


# --- Type 1: status --------------------------------------------------------

def _match_status(resp, matcher: dict) -> bool:
    values = matcher.get("values", [])
    if not values:
        return False
    hit = resp.status_code in set(values)
    return not hit if matcher.get("negate") else hit


# --- Type 2: word ----------------------------------------------------------

def _match_word(resp, matcher: dict) -> bool:
    part = str(matcher.get("part", "body")).lower()
    words = matcher.get("words", [])
    if not words:
        return False
    haystack = _part_text(resp, part)
    if matcher.get("case_insensitive"):
        haystack = haystack.lower()
        words = [w.lower() for w in words]
    condition = str(matcher.get("condition", "or")).lower()
    found = [w for w in words if w in haystack]
    if condition == "and":
        return len(found) == len(words)
    return len(found) > 0


# --- Type 3: regex ---------------------------------------------------------

def _match_regex(resp, matcher: dict) -> bool:
    part = str(matcher.get("part", "body")).lower()
    pattern = matcher.get("pattern")
    if not pattern:
        return False
    flags = re.IGNORECASE if matcher.get("case_insensitive") else 0
    haystack = _part_text(resp, part)
    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        return False
    if matcher.get("negate"):
        return compiled.search(haystack) is None
    return compiled.search(haystack) is not None


# --- Type 4: size ----------------------------------------------------------

_COMPARE = {
    "gt": lambda a, b: a > b,
    "lt": lambda a, b: a < b,
    "eq": lambda a, b: a == b,
    "gte": lambda a, b: a >= b,
    "lte": lambda a, b: a <= b,
}


def _match_size(resp, matcher: dict) -> bool:
    cmp = str(matcher.get("comparison", "gt")).lower()
    target = matcher.get("size")
    if target is None or cmp not in _COMPARE:
        return False
    actual = len(resp.content or b"")
    return _COMPARE[cmp](actual, int(target))


# --- Type 5: binary --------------------------------------------------------

def _match_binary(resp, matcher: dict) -> bool:
    hexstr = matcher.get("hex")
    if not hexstr:
        return False
    try:
        needle = binascii.unhexlify(hexstr.replace(" ", "").replace(":", ""))
    except (binascii.Error, ValueError):
        return False
    condition = str(matcher.get("condition", "or")).lower()
    haystack = resp.content or b""
    if matcher.get("negate"):
        return needle not in haystack
    if condition == "and":
        return needle in haystack  # single binary pattern: AND == presence
    return needle in haystack


# --- Type 6: header --------------------------------------------------------

def _match_header(resp, matcher: dict) -> bool:
    header = matcher.get("header")
    values = matcher.get("values", [])
    if not header or not values:
        return False
    actual = resp.headers.get(header)
    if actual is None:
        return bool(matcher.get("negate"))
    condition = str(matcher.get("condition", "or")).lower()
    case_insensitive = matcher.get("case_insensitive", False)

    def norm(v):
        return v.lower() if case_insensitive else v

    actual_n = norm(actual)
    wanted = [norm(v) for v in values]
    hit = any(a == actual_n for a in wanted)
    if condition == "and":
        hit = all(norm(v) == actual_n for v in values)
    return not hit if matcher.get("negate") else hit


_DISPATCH = {
    "status": _match_status,
    "word": _match_word,
    "regex": _match_regex,
    "size": _match_size,
    "binary": _match_binary,
    "header": _match_header,
}


def evaluate_matcher(matcher: dict, resp) -> bool:
    """Evaluate one matcher block against a response. Returns bool."""
    mtype = str(matcher.get("type", "word")).lower()
    fn = _DISPATCH.get(mtype)
    if fn is None:
        return False
    try:
        return fn(resp, matcher)
    except Exception:
        return False


def _flat_conditions(block: dict) -> list[dict]:
    """Return the list of condition matchers for a matcher block, whether
    the block is a Nuclei-style ``{operator, conditions:[...]}`` or a bare
    matcher dict."""
    if isinstance(block, dict) and "conditions" in block:
        return block.get("conditions") or []
    return [block]


def evaluate_matchers_block(matchers: list[dict], resp) -> tuple[bool, list[dict]]:
    """Evaluate a list of matcher blocks combined by ``operator``.

    Supports two shapes per block:
      * Nuclei-style: {operator: OR/AND, conditions: [ {type:...}, ... ]}
      * bare matcher: {type: status, values: [...]}

    The request-level ``matchers_condition`` (AND/OR) combines *blocks*.
    Returns (matched: bool, triggered_conditions: list of condition dicts
    that returned True, across all blocks).
    """
    if not matchers:
        return False, []
    mcond = str(matchers[0].get("matchers_condition", "and")).lower()

    block_results = []
    triggered: list[dict] = []
    for block in matchers:
        operator = str(block.get("operator", "or")).lower() if isinstance(block, dict) else "or"
        conds = _flat_conditions(block)
        results = []
        for c in conds:
            ok = evaluate_matcher(c, resp)
            if ok:
                triggered.append(c)
            results.append(ok)
            if operator == "or" and ok:
                block_results.append(True)
                break
        else:
            block_results.append(all(results) if operator == "and" else any(results))
        if mcond == "or" and block_results[-1]:
            return True, triggered  # short-circuit at block level

    combined = all(block_results) if mcond == "and" else any(block_results)
    return combined, triggered
