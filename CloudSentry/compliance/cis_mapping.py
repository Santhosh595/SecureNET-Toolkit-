"""CloudSentry — CIS Benchmark mapping + scoring.

Each check in catalog.py carries a `cis` field (e.g. "CIS AWS 1.4").
This module groups checks by their CIS control family and computes a
pass percentage per provider.
"""

from __future__ import annotations

from collections import defaultdict


def cis_family(check_cis: str) -> str:
    """Normalize a CIS ref to its benchmark family label."""
    if not check_cis:
        return "Unmapped"
    if check_cis.startswith("CIS AWS"):
        return "CIS AWS Benchmark"
    if check_cis.startswith("CIS GCP"):
        return "CIS GCP Benchmark"
    if check_cis.startswith("CIS Azure"):
        return "CIS Azure Benchmark"
    return "Other"


def score(results: list) -> dict:
    """Return per-provider CIS pass percentage and control breakdown."""
    by_provider = defaultdict(lambda: {"total": 0, "pass": 0, "families": defaultdict(lambda: {"total": 0, "pass": 0})})
    for r in results:
        fam = cis_family(r.cis_ref)
        slot = by_provider[r.provider]
        slot["total"] += 1
        if r.status == "PASS":
            slot["pass"] += 1
        fslot = slot["families"][fam]
        fslot["total"] += 1
        if r.status == "PASS":
            fslot["pass"] += 1
    out = {}
    for prov, slot in by_provider.items():
        pct = round(100 * slot["pass"] / slot["total"], 1) if slot["total"] else 0.0
        fams = {f: {"total": s["total"], "pass": s["pass"],
                    "pct": round(100 * s["pass"] / s["total"], 1) if s["total"] else 0.0}
                 for f, s in slot["families"].items()}
        out[prov] = {"total": slot["total"], "pass": slot["pass"], "pct": pct, "families": fams}
    return out
