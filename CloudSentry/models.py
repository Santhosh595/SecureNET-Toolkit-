"""CloudSentry — shared data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CheckResult:
    check_id: str
    name: str
    provider: str            # aws | gcp | azure
    category: str            # IAM | Storage | Network | Logging | Database
    status: str              # PASS | FAIL | INFO | ERROR | TIMEOUT
    severity: str            # critical | high | medium | low | info
    description: str = ""    # plain-English finding
    risk: str = ""           # what could go wrong
    remediation: str = ""    # exact CLI command or console steps
    affected: list[str] = field(default_factory=list)  # resource ids/names
    cis_ref: str = ""        # CIS benchmark control
    owasp_ref: str = ""      # OWASP Cloud Top 10 category
    region: str = "global"


@dataclass
class AuditSummary:
    providers: list[str]
    total: int = 0
    pass_count: int = 0
    fail_count: int = 0
    info_count: int = 0
    error_count: int = 0
    duration: float = 0.0
    by_severity: dict = field(default_factory=dict)
    by_provider: dict = field(default_factory=dict)
    compliance: dict = field(default_factory=dict)  # provider -> {cis%, owasp%}


def severity_counts(results: list[CheckResult]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        if r.status == "PASS":
            continue
        counts[r.severity] = counts.get(r.severity, 0) + 1
    return counts
