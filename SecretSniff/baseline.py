"""SecretSniff — Baseline management.

Save current findings as accepted baseline, compare future scans against it.
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Optional


def compute_finding_hash(finding: dict) -> str:
    """Compute a hash for a finding to detect changes.

    Uses file + line + rule + value for unique identification.
    """
    key = f"{finding.get('file', '')}:{finding.get('line', '')}:{finding.get('rule', '')}:{finding.get('value_redacted', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def save_baseline(findings: list[dict], baseline_path: Path) -> None:
    """Save findings as baseline.

    Args:
        findings: Current findings to accept.
        baseline_path: Path to save baseline file.
    """
    baseline = {
        "version": "1.0",
        "total_findings": len(findings),
        "findings": [
            {
                "hash": compute_finding_hash(f),
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "rule": f.get("rule", ""),
                "severity": f.get("severity", ""),
                "value_redacted": f.get("value_redacted", ""),
            }
            for f in findings
        ]
    }

    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, ensure_ascii=False)


def load_baseline(baseline_path: Path) -> Optional[dict]:
    """Load baseline from file.

    Args:
        baseline_path: Path to baseline file.

    Returns:
        Baseline dict or None if file doesn't exist.
    """
    if not baseline_path.exists():
        return None
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def compare_with_baseline(findings: list[dict], baseline_path: Path) -> tuple[list[dict], list[dict]]:
    """Compare current findings with baseline.

    Args:
        findings: Current scan findings.
        baseline_path: Path to baseline file.

    Returns:
        Tuple of (new_findings, known_findings).
    """
    baseline = load_baseline(baseline_path)
    if not baseline:
        return findings, []

    baseline_hashes = {f["hash"] for f in baseline.get("findings", [])}

    new_findings = []
    known_findings = []

    for finding in findings:
        finding_hash = compute_finding_hash(finding)
        finding["baseline_hash"] = finding_hash
        if finding_hash in baseline_hashes:
            known_findings.append(finding)
        else:
            new_findings.append(finding)

    return new_findings, known_findings
