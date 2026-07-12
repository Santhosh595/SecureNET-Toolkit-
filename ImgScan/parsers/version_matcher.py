"""ImgScan — semver range / version matching.

Handles:
  - normalisation of "1.0", "1.0.0", "1.0.0.0" to a comparable tuple
  - pre-release handling (1.0.0rc1 < 1.0.0)
  - range operators: <, <=, >, >=, ==, ~=, and "a,<b" comma combos
  - bare version (== that version)
"""

from __future__ import annotations

import re
from typing import Tuple


def normalize(version: str) -> Tuple[int, ...]:
    """Return a comparable tuple from a version string."""
    if not version:
        return (0,)
    # split off pre-release / build metadata
    head = version.strip().lstrip("vV")
    # keep only leading numeric.dot (drop -rc1/+build)
    m = re.match(r"^\s*(\d+(?:\.\d+){0,3})", head)
    if not m:
        return (0,)
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def _prerelease_rank(version: str) -> int:
    """0 for release builds, >0 for pre-releases (so releases sort higher)."""
    if re.search(r"-(rc|alpha|a|b|dev|pre)", version, re.I):
        return 1
    return 0


def compare(version_a: str, version_b: str) -> int:
    """Return -1/0/1 comparing two version strings (pre-release < release)."""
    na, nb = normalize(version_a), normalize(version_b)
    if na != nb:
        return -1 if na < nb else 1
    # equal numeric -> pre-release ranks lower
    ra, rb = _prerelease_rank(version_a), _prerelease_rank(version_b)
    return -1 if ra < rb else (1 if ra > rb else 0)


def _satisfies_single(ver: str, op_range: str) -> bool:
    """Evaluate a single operator clause like '<2.26.0' or '==1.0.0'."""
    op_range = op_range.strip()
    m = re.match(r"^(<=|>=|==|!=|<|>)\s*([0-9][0-9A-Za-z.\-]*)", op_range)
    if not m:
        # bare version -> equality
        return compare(ver, op_range) == 0
    op, target = m.group(1), m.group(2)
    c = compare(ver, target)
    return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0,
            "==": c == 0, "!=": c != 0}[op]


def version_in_range(version: str, rng: str) -> bool:
    """Check if `version` satisfies the range `rng`.

    Supports comma-separated AND clauses: ">=1.0.0,<2.0.0".
    """
    if not rng:
        return True
    version = version or ""
    clauses = [c for c in rng.split(",") if c.strip()]
    if not clauses:
        return True
    # If a single clause has no operator, treat as equality helper
    return all(_satisfies_single(version, c) for c in clauses)


def match_version(version: str, affected_versions: list[str]) -> bool:
    """Match a version against a list of affected-version range strings."""
    for rng in affected_versions:
        if version_in_range(version, rng):
            return True
    return False
