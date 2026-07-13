"""TechFinger — signature matching engine (core)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .confidence import score, label_for
from .version_extractor import extract
from .favicon import match_favicon

_HERE = os.path.dirname(os.path.abspath(__file__))
_SIG = os.path.join(os.path.dirname(_HERE), "signatures")
_DATA = os.path.join(os.path.dirname(_HERE), "data")


@dataclass
class IndicatorHit:
    source: str
    pattern: str
    matched_text: str = ""


@dataclass
class TechResult:
    name: str
    category: str
    confidence: int
    confidence_label: str
    version: Optional[str]
    risk: str
    indicators: List[IndicatorHit] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    website: str = ""
    cve_check_key: Optional[str] = None


@dataclass
class HeaderCheck:
    name: str
    present: bool
    value: str
    status: str          # PASS / FAIL
    severitiy: str


@dataclass
class CveCorrelation:
    tech: str
    version: Optional[str]
    cve: str
    severitiy: str
    cvss: float
    description: str


def _load_sig(file: str) -> list:
    try:
        return json.load(open(os.path.join(_SIG, file)))
    except (json.JSONDecodeError, OSError):
        return []


def _load_cve_map() -> dict:
    try:
        return json.load(open(os.path.join(_DATA, "tech_cve_map.json")))
    except (json.JSONDecodeError, OSError):
        return {}


def _source_text(src: str, field: str, resp) -> str:
    if src == "header":
        return f"{field}: {resp.header(field)}" if field else \
            " ".join(f"{k}:{v}" for k, v in resp.headers.items())
    if src == "cookie":
        return " ".join(f"{k}:{v}" for k, v in resp.cookies.items())
    if src == "meta":
        return f"{field}: {resp.meta.get(field, '')}" if field else \
            " ".join(f"{k}:{v}" for k, v in resp.meta.items())
    return resp.body or ""


def _match_indicator(ind: dict, resp) -> Optional[IndicatorHit]:
    src = ind.get("source", "body")
    pat = ind.get("pattern", "")
    if not pat or pat == ".*":
        # presence-only indicator (e.g. any value)
        if src == "header":
            if ind.get("field") in resp.headers:
                return IndicatorHit(src, pat, resp.header(ind.get("field", "")))
        return None
    text = _source_text(src, ind.get("field", ""), resp)
    m = re.search(pat, text, re.I)
    if m:
        grp = ind.get("version_group", 0)
        mt = m.group(grp) if grp else m.group(0)
        return IndicatorHit(src, pat, mt)
    return None


def match_tech(sig: dict, resp) -> Optional[TechResult]:
    hits: List[IndicatorHit] = []
    weights: List[int] = []
    for ind in sig.get("indicators", []):
        h = _match_indicator(ind, resp)
        if h:
            hits.append(h)
            weights.append(int(ind.get("confidence_weight", 50)))
    if not hits:
        return None
    conf = score(weights)
    version = extract(sig.get("version_patterns", []), resp)
    risk = _assess_risk(sig, version, hits)
    return TechResult(
        name=sig["name"], category=sig["category"], confidence=conf,
        confidence_label=label_for(conf), version=version, risk=risk,
        indicators=hits, tags=sig.get("tags", []),
        website=sig.get("website", ""),
        cve_check_key=(sig.get("cve_check") or {}).get("lookup_key"),
    )


def _assess_risk(sig: dict, version: Optional[str], hits) -> str:
    # explicit version-below rule
    rb = sig.get("risk_if_version_below")
    if rb and version and _ver_lt(version, rb["value"]):
        return rb["severity"]
    # generic version-exposed risk
    if version and sig.get("risk_if_version_exposed"):
        return sig["risk_if_version_exposed"]
    if not version and sig.get("risk_if_version_exposed"):
        # CDN/analytics: INFO even without version
        return sig.get("risk_if_version_exposed", "INFO")
    return "INFO"


def _ver_lt(a: str, b: str) -> bool:
    def t(v):
        return [int(x) for x in re.findall(r"\d+", v)]
    try:
        return t(a) < t(b)
    except Exception:
        return False


def correlate_cves(results: List[TechResult], cve_map: dict) -> List[CveCorrelation]:
    out: List[CveCorrelation] = []
    for r in results:
        key = r.cve_check_key
        if not key or key not in cve_map:
            continue
        for entry in cve_map[key]:
            if r.version and _version_in_range(r.version, entry.get("affected", "")):
                out.append(CveCorrelation(
                    tech=r.name, version=r.version, cve=entry["cve"],
                    severitiy=entry.get("severity", "MEDIUM"),
                    cvss=float(entry.get("cvss_score", 0)),
                    description=entry.get("description", ""),
                ))
    return out


def _version_in_range(version: str, affected: str) -> bool:
    """affected like '<2.4.51' or '>=1.0.0,<2.0.0' or ''."""
    if not affected:
        return True
    for part in affected.split(","):
        part = part.strip()
        m = re.match(r"^(<=?|>=?)\s*([\d.]+)$", part)
        if not m:
            continue
        op, ver = m.group(1), m.group(2)
        a, b = _t(version), _t(ver)
        if op == "<" and not (a < b):
            return False
        if op == "<=" and not (a <= b):
            return False
        if op == ">" and not (a > b):
            return False
        if op == ">=" and not (a >= b):
            return False
    return True


def _t(v: str):
    return [int(x) for x in re.findall(r"\d+", v)]


def check_headers(resp) -> List[HeaderCheck]:
    sigs = _load_sig("security_headers.json")
    out: List[HeaderCheck] = []
    for s in sigs:
        name = s["header_name"]
        val = resp.header(name)
        present = bool(val)
        out.append(HeaderCheck(
            name=name, present=present, value=val[:120] if present else "",
            status="PASS" if present else "FAIL",
            severitiy=s.get("fail_severity", "MEDIUM"),
        ))
    return out


def fingerprint(resp) -> dict:
    """Run all signature files + header checks + favicon.

    Returns dict with: technologies, header_checks, cve_correlations,
    waf_detected.
    """
    files = ["server.json", "framework.json", "cms.json", "cdn.json",
             "analytics.json", "jslibs.json"]
    results: List[TechResult] = []
    for f in files:
        for sig in _load_sig(f):
            r = match_tech(sig, resp)
            if r:
                results.append(r)
    # favicon secondary detection
    for tech in match_favicon(resp.favicon):
        if not any(t.name == tech for t in results):
            results.append(TechResult(
                name=tech, category="favicon", confidence=40,
                confidence_label="POSSIBLE", version=None, risk="INFO",
                indicators=[IndicatorHit("favicon", "hash-match")],
                tags=[], website="", cve_check_key=None))
    headers = check_headers(resp)
    cves = correlate_cves(results, _load_cve_map())
    return {
        "technologies": results,
        "header_checks": headers,
        "cve_correlations": cves,
        "waf_detected": resp.waf_detected,
    }
