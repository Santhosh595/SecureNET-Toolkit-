"""SecretSniff — SARIF output format."""

from __future__ import annotations
import json
from typing import Any


def generate_sarif(findings: list[dict], tool_name: str = "SecretSniff") -> dict:
    """Generate SARIF report.

    Args:
        findings: List of finding dicts.
        tool_name: Tool name for SARIF.

    Returns:
        SARIF-compatible dict.
    """
    runs = []
    rules = {}
    results = []

    for finding in findings:
        rule_id = finding.get("rule", "Unknown")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"Detected: {rule_id}"},
                "defaultConfiguration": {"level": _sarif_level(finding.get("severity", "MEDIUM"))},
            }
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(finding.get("severity", "MEDIUM")),
            "message": {"text": f"{finding.get('rule', 'Secret')} found in {finding.get('file', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.get("file", "")},
                    "region": {
                        "startLine": finding.get("line", 1),
                    }
                }
            }],
        })

    runs.append({
        "tool": {
            "driver": {
                "name": tool_name,
                "rules": list(rules.values()),
            }
        },
        "results": results,
    })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}.get(severity, "warning")
