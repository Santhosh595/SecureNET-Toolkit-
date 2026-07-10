"""PathProbe — wildcard / false-positive baseline detection.

Before scanning, send 3 requests to random UUID-ish paths. If the target
returns 200 (or 302) for *everything* with similar content length, ordinary
status-code filtering is useless. We detect it and switch to content-length
based filtering: responses within 10% of the baseline length are dropped.
"""

from __future__ import annotations

import uuid

from engine import requester

PROBE_COUNT = 3
SIMILARITY_PCT = 0.10  # within 10% of baseline length = wildcard noise


def _random_paths(n: int) -> list[str]:
    return [str(uuid.uuid4()).replace("-", "")[:10] for _ in range(n)]


def detect_baseline(base_url: str, **req_kwargs) -> dict:
    """Probe 3 random paths and characterize the target's wildcard behavior.

    Returns:
        { "wildcard_200": bool, "baseline_len": int,
          "wildcard_302": bool, "redirect_loc": str|None,
          "statuses": [..], "lengths": [..] }
    """
    paths = _random_paths(PROBE_COUNT)
    statuses, lengths, redirect_locs = [], [], []
    for p in paths:
        r = requester.probe(base_url, p, **req_kwargs)
        if r is None or r.get("error"):
            # unreachable / transport error -> bail
            return {"wildcard_200": False, "wildcard_302": False, "baseline_len": -1,
                    "redirect_loc": None, "statuses": [], "lengths": [], "error": r.get("error") if r else "no response"}
        statuses.append(r["status"])
        lengths.append(r["size"])
        redirect_locs.append(r.get("redirect_to"))

    result = {"statuses": statuses, "lengths": lengths, "redirect_loc": None}

    # 200 wildcard: all 200 and lengths cluster within 10%
    if statuses.count(200) == PROBE_COUNT and lengths:
        lo, hi = min(lengths), max(lengths)
        if lo == 0 or (hi - lo) <= max(1, lo * SIMILARITY_PCT):
            result["wildcard_200"] = True
            result["baseline_len"] = sum(lengths) // len(lengths)
        else:
            result["wildcard_200"] = False
            result["baseline_len"] = -1
    else:
        result["wildcard_200"] = False
        result["baseline_len"] = -1

    # 302 wildcard: all redirect to the SAME location
    if statuses.count(302) == PROBE_COUNT and len(set(redirect_locs)) == 1 and redirect_locs[0]:
        result["wildcard_302"] = True
        result["redirect_loc"] = redirect_locs[0]
    else:
        result["wildcard_302"] = False

    return result


def is_wildcard_noise(result: dict, candidate: dict) -> bool:
    """Given a baseline result and a candidate finding, decide if it is
    wildcard noise that should be filtered out."""
    if result.get("wildcard_200") and result.get("baseline_len", -1) > 0:
        base = result["baseline_len"]
        lo = base * (1 - SIMILARITY_PCT)
        hi = base * (1 + SIMILARITY_PCT)
        if candidate["status"] == 200 and lo <= candidate["size"] <= hi:
            return True
    if result.get("wildcard_302") and result.get("redirect_loc"):
        if candidate["status"] in (301, 302, 303, 307, 308) and \
           candidate.get("redirect_to") == result["redirect_loc"]:
            return True
    return False
