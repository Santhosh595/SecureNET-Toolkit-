"""ImgScan — SARIF v2.1.0 export (GitHub Code Scanning)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import List

from scanners.common import VulnFinding

_SEV = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
        "LOW": "note", "INFO": "none"}


def _rule_index(findings: List[VulnFinding]) -> "tuple":
    rules = {}
    order = []
    for f in findings:
        key = f.cve_id
        if key not in rules:
            rules[key] = {
                "id": f.cve_id,
                "name": f"{f.package} {f.cve_id}",
                "shortDescription": {"text": f"{f.package} {f.cve_id} ({f.severity})"},
                "fullDescription": {"text": f.description or f.cve_id},
                "helpUri": f.reference or f"https://nvd.nist.gov/vuln/detail/{f.cve_id}",
            }
            order.append(key)
    return rules, order


def to_sarif(findings: List[VulnFinding], target: str = "dependencies") -> dict:
    rules, order = _rule_index(findings)
    results = []
    for f in findings:
        results.append({
            "ruleId": f.cve_id,
            "level": _SEV.get(f.severity, "warning"),
            "message": {
                "text": (f"{f.package} {f.version}: {f.cve_id} "
                         f"({f.severity}, CVSS {f.cvss_score}). "
                         f"Fix: upgrade to {f.fixed_version}.")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "package": f.package,
                "version": f.version,
                "ecosystem": f.ecosystem,
                "cvss": f.cvss_score,
                "in_kev": f.in_kev,
                "fixed_version": f.fixed_version,
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ImgScan",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/Santhosh595/SecureNET-Toolkit-",
                    "rules": [rules[k] for k in order],
                }
            },
            "results": results,
        }],
    }
    return sarif


def write_sarif(findings: List[VulnFinding], path: str, target: str = "dependencies") -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_sarif(findings, target), f, indent=2)
