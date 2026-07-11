"""CloudSentry — OWASP Cloud Top 10 mapping + scoring.

OWASP Cloud Top 10 (2022) categories used here:
  OC1 Accountability & Traceability
  OC2 Asset Management
  OC3 Configuration Management
  OC4 Logging & Monitoring
  OC5 Secure Access & Config
  OC6 Vulnerability Management
  OC7 IAM & Entitlements
  OC8 Data Protection
  OC9 Data Security
  OC10 Infrastructure Security

Each check carries an `owasp` field (e.g. "OC2 (Asset Management)").
This module maps check status onto the ten categories and reports how many
categories are "clear" (no FAIL/ERROR) vs affected.
"""

from __future__ import annotations

from collections import defaultdict

OWASP_CATEGORIES = [
    "OC1 Accountability & Traceability",
    "OC2 Asset Management",
    "OC3 Configuration Management",
    "OC4 Logging & Monitoring",
    "OC5 Secure Access & Config",
    "OC6 Vulnerability Management",
    "OC7 IAM & Entitlements",
    "OC8 Data Protection",
    "OC9 Data Security",
    "OC10 Infrastructure Security",
]


def _category_key(ref: str) -> str:
    if not ref:
        return "OC2 Asset Management"
    # ref looks like "OC2 (Asset Management)"
    code = ref.split()[0]
    for c in OWASP_CATEGORIES:
        if c.startswith(code):
            return c
    return "OC2 Asset Management"


def score(results: list) -> dict:
    by_cat = defaultdict(lambda: {"total": 0, "fail": 0})
    for r in results:
        key = _category_key(r.owasp_ref)
        by_cat[key]["total"] += 1
        if r.status in ("FAIL", "ERROR"):
            by_cat[key]["fail"] += 1
    cats = {}
    clear = 0
    for c in OWASP_CATEGORIES:
        slot = by_cat.get(c, {"total": 0, "fail": 0})
        is_clear = slot["fail"] == 0 and slot["total"] > 0
        if is_clear:
            clear += 1
        cats[c] = {"total": slot["total"], "fail": slot["fail"], "clear": is_clear}
    return {"categories": cats, "clear": clear, "total": len(OWASP_CATEGORIES)}
