"""TechFinger — confidence scoring."""

from __future__ import annotations

from typing import List


def label_for(confidence: int) -> str:
    if confidence >= 90:
        return "CERTAIN"
    if confidence >= 70:
        return "LIKELY"
    if confidence >= 50:
        return "POSSIBLE"
    return "UNCERTAIN"


def score(weighted: List[int]) -> int:
    """Confidence scoring.

    - Take the highest single indicator weight (not additive).
    - If 3+ indicators matched: boost by 10 (cap 100).
    """
    if not weighted:
        return 0
    base = max(weighted)
    if len(weighted) >= 3:
        base = min(100, base + 10)
    return min(100, base)
