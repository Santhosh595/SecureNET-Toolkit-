"""SecretSniff - SARIF output format.

Generates SARIF 2.1.0 compatible reports for GitHub/GitLab CI integration.
"""

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
                "fullDescription": {"text": finding.get("context", f"Secret pattern match: {rule_id}")},
                "defaultConfiguration": {"level": _sarif_level(finding.get("severity", "MEDIUM"))},
                "properties": {
                    "category": "security",
                    "tags": ["security", "secret", "api-key"],
                },
            }

        result = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.get("severity", "MEDIUM")),
            "message": {"text": f"{rule_id} found in {finding.get('file', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.get("file", "")},
                    "region": {
                        "startLine": finding.get("line", 1),
                    }
                }
            }],
            "properties": {
                "confidence": finding.get("confidence", "MEDIUM"),
                "severity": finding.get("severity", "MEDIUM"),
            },
        }

        if finding.get("commit_hash"):
            result["properties"]["commit"] = finding["commit_hash"]
        if finding.get("entropy"):
            result["properties"]["entropy"] = finding["entropy"]

        results.append(result)

    runs.append({
        "tool": {
            "driver": {
                "name": tool_name,
                "version": "1.0.0",
                "informationUri": "https://github.com/Santhosh595/SecureNET-Toolkit-",
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
