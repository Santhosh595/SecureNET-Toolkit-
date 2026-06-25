"""
DNSAudit Scoring Module
========================
Scores DNS security audit findings across multiple categories and produces
an overall security grade with structured breakdown.

Categories (each scored 0-10):
  1. SPF (Sender Policy Framework)
  2. DKIM (DomainKeys Identified Mail)
  3. DMARC (Domain-based Message Authentication)
  4. DNSSEC
  5. Zone Transfer
  6. Subdomain Takeover
  7. Open Resolver
  8. Mail Server Security (MX records)
  9. CAA Records
  10. DNS Cache Poisoning / Spoofing
  11. Nameserver Security
  12. General DNS Hygiene

Maximum total raw score: 12 categories × 10 points = 120 points.
Overall percentage = (sum of category scores / 120) × 100.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_CATEGORY_SCORE = 10
NUM_CATEGORIES = 12
MAX_RAW_SCORE = MAX_CATEGORY_SCORE * NUM_CATEGORIES  # 120

# Severity deductions per finding
SEVERITY_DEDUCTIONS = {
    "CRITICAL": 4,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,  # LOW findings do not deduct points but are recorded
}

# Hard-cap triggers
CAP_ZONE_TRANSFER_OPEN = "F"
CAP_NO_EMAIL_AUTH = "D"  # No SPF + No DMARC + No DKIM
CAP_SUBDOMAIN_TAKEOVER = "C"


class Grade(Enum):
    """Letter grades with their percentage ranges."""
    A_PLUS = ("A+", 95, 100)
    A = ("A", 85, 94)
    B = ("B", 70, 84)
    C = ("C", 50, 69)
    D = ("D", 30, 49)
    F = ("F", 0, 29)

    def __init__(self, label: str, low: int, high: int):
        self.label = label
        self.low = low
        self.high = high

    @classmethod
    def from_percentage(cls, pct: float) -> "Grade":
        """Return the Grade matching *pct* (clamped to 0-100)."""
        pct = max(0.0, min(100.0, pct))
        for grade in cls:
            if grade.low <= pct <= grade.high:
                return grade
        return cls.F  # fallback


# Category names (canonical order)
CATEGORY_NAMES = [
    "SPF",
    "DKIM",
    "DMARC",
    "DNSSEC",
    "Zone Transfer",
    "Subdomain Takeover",
    "Open Resolver",
    "Mail Server Security",
    "CAA Records",
    "DNS Cache Poisoning",
    "Nameserver Security",
    "DNS Hygiene",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single audit finding."""
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    category: str = ""     # optional override; defaults to the category it's added to

    def __post_init__(self):
        self.severity = self.severity.upper()


@dataclass
class CategoryScore:
    """Score breakdown for a single category."""
    name: str
    max_score: int = MAX_CATEGORY_SCORE
    deductions: list[dict[str, Any]] = field(default_factory=list)
    final_score: float = MAX_CATEGORY_SCORE
    findings: list[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        deduction = SEVERITY_DEDUCTIONS.get(finding.severity, 0)
        self.deductions.append({
            "severity": finding.severity,
            "description": finding.description,
            "deduction": deduction,
        })
        self.final_score = max(0.0, self.final_score - deduction)


@dataclass
class AuditScore:
    """Complete audit score result."""
    domain: str
    categories: dict[str, CategoryScore]
    raw_total: float
    overall_percentage: float
    grade: str
    caps_applied: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "overall_percentage": round(self.overall_percentage, 2),
            "grade": self.grade,
            "raw_total": self.raw_total,
            "max_raw_score": MAX_RAW_SCORE,
            "caps_applied": self.caps_applied,
            "categories": {
                name: {
                    "name": cat.name,
                    "final_score": cat.final_score,
                    "max_score": cat.max_score,
                    "findings": [
                        {"severity": f.severity, "description": f.description}
                        for f in cat.findings
                    ],
                    "deductions": cat.deductions,
                }
                for name, cat in self.categories.items()
            },
            "recommendations": self.recommendations,
        }


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class DNSScorer:
    """
    Scores DNS audit findings and produces a structured grade.

    Usage::

        scorer = DNSScorer("example.com")
        scorer.add_finding("SPF", "CRITICAL", "No SPF record found")
        scorer.add_finding("DMARC", "HIGH", "DMARC policy set to p=none")
        result = scorer.calculate()
        print(result.grade)  # e.g. "D"
    """

    def __init__(self, domain: str):
        self.domain = domain
        self.categories: dict[str, CategoryScore] = {
            name: CategoryScore(name=name) for name in CATEGORY_NAMES
        }

    # -- public API --------------------------------------------------------

    def add_finding(self, category: str, severity: str, description: str) -> None:
        """Add a finding to *category*."""
        if category not in self.categories:
            raise ValueError(
                f"Unknown category '{category}'. "
                f"Valid categories: {list(self.categories)}"
            )
        finding = Finding(severity=severity, description=description, category=category)
        self.categories[category].add_finding(finding)

    def add_findings_bulk(self, category: str, findings: list[dict[str, str]]) -> None:
        """Add multiple findings at once. Each dict must have 'severity' and 'description' keys."""
        for f in findings:
            self.add_finding(category, f["severity"], f["description"])

    def calculate(self) -> AuditScore:
        """Calculate the final score, apply caps, and return an AuditScore."""
        # 1. Sum raw category scores
        raw_total = sum(cat.final_score for cat in self.categories.values())

        # 2. Compute percentage
        overall_pct = (raw_total / MAX_RAW_SCORE) * 100

        # 3. Determine base grade
        grade = Grade.from_percentage(overall_pct)

        # 4. Apply hard caps
        caps_applied: list[str] = []
        grade = self._apply_hard_caps(grade, caps_applied)

        # 5. Generate recommendations
        recommendations = self._generate_recommendations()

        return AuditScore(
            domain=self.domain,
            categories=self.categories,
            raw_total=raw_total,
            overall_percentage=overall_pct,
            grade=grade.label,
            caps_applied=caps_applied,
            recommendations=recommendations,
        )

    # -- internal helpers --------------------------------------------------

    def _apply_hard_caps(self, current_grade: Grade, caps_applied: list[str]) -> Grade:
        """
        Apply hard caps that override the computed grade.

        Caps (worst wins):
          - Zone Transfer open            → cap at F
          - No SPF + No DMARC + No DKIM   → cap at D
          - Subdomain Takeover confirmed  → cap at C
        """
        worst_grade = current_grade

        # --- Zone Transfer open ---
        zone_transfer_cat = self.categories.get("Zone Transfer")
        if zone_transfer_cat and any(
            "open" in f.description.lower() or "allowed" in f.description.lower()
            for f in zone_transfer_cat.findings
            if f.severity in ("CRITICAL", "HIGH")
        ):
            worst_grade = self._worse_grade(worst_grade, Grade.F)
            caps_applied.append("Zone Transfer is open → grade capped at F")

        # --- No SPF + No DMARC + No DKIM ---
        spf_findings = self.categories["SPF"].findings
        dkim_findings = self.categories["DKIM"].findings
        dmarc_findings = self.categories["DMARC"].findings

        spf_missing = any(
            "no spf" in f.description.lower() or "missing" in f.description.lower()
            for f in spf_findings
        )
        dkim_missing = any(
            "no dkim" in f.description.lower() or "missing" in f.description.lower()
            for f in dkim_findings
        )
        dmarc_missing = any(
            "no dmarc" in f.description.lower() or "missing" in f.description.lower()
            for f in dmarc_findings
        )

        if spf_missing and dkim_missing and dmarc_missing:
            worst_grade = self._worse_grade(worst_grade, Grade.D)
            caps_applied.append(
                "No SPF + No DMARC + No DKIM → grade capped at D"
            )

        # --- Subdomain Takeover confirmed ---
        takeover_cat = self.categories.get("Subdomain Takeover")
        if takeover_cat and any(
            "confirmed" in f.description.lower() or "vulnerable" in f.description.lower()
            for f in takeover_cat.findings
            if f.severity in ("CRITICAL", "HIGH")
        ):
            worst_grade = self._worse_grade(worst_grade, Grade.C)
            caps_applied.append(
                "Subdomain takeover confirmed → grade capped at C"
            )

        return worst_grade

    @staticmethod
    def _worse_grade(a: Grade, b: Grade) -> Grade:
        """Return the worse (lower) of two grades."""
        # Grades are ordered best-to-worst in the Enum definition;
        # higher enum value = worse grade.
        order = [Grade.A_PLUS, Grade.A, Grade.B, Grade.C, Grade.D, Grade.F]
        idx_a = order.index(a)
        idx_b = order.index(b)
        return order[max(idx_a, idx_b)]

    def _generate_recommendations(self) -> list[str]:
        """Generate actionable recommendations based on findings."""
        recs: list[str] = []

        for cat_name, cat in self.categories.items():
            if cat.findings:
                severities = {f.severity for f in cat.findings}
                if "CRITICAL" in severities:
                    recs.append(
                        f"[CRITICAL] {cat_name}: Address critical findings immediately."
                    )
                elif "HIGH" in severities:
                    recs.append(
                        f"[HIGH] {cat_name}: Prioritize remediation of high-severity issues."
                    )

        # Specific recommendations
        if any("no spf" in f.description.lower() for f in self.categories["SPF"].findings):
            recs.append("Publish an SPF record (TXT) to authorize legitimate mail senders.")
        if any("no dkim" in f.description.lower() for f in self.categories["DKIM"].findings):
            recs.append("Configure DKIM signing and publish the public key in DNS.")
        if any("no dmarc" in f.description.lower() for f in self.categories["DMARC"].findings):
            recs.append("Publish a DMARC policy (start with p=none, then enforce).")
        if any("open" in f.description.lower() for f in self.categories["Zone Transfer"].findings):
            recs.append("Restrict zone transfers to authorized secondary nameservers only.")
        if any("vulnerable" in f.description.lower() or "confirmed" in f.description.lower()
               for f in self.categories["Subdomain Takeover"].findings):
            recs.append("Remove dangling DNS records and reclaim orphaned cloud resources.")

        return recs


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def score_audit(domain: str, findings: dict[str, list[dict[str, str]]]) -> AuditScore:
    """
    Convenience function to score an entire audit in one call.

    Parameters
    ----------
    domain : str
        The domain being audited.
    findings : dict[str, list[dict]]
        Mapping of category name → list of {"severity": ..., "description": ...}.

    Returns
    -------
    AuditScore
    """
    scorer = DNSScorer(domain)
    for category, items in findings.items():
        scorer.add_findings_bulk(category, items)
    return scorer.calculate()


# ---------------------------------------------------------------------------
# CLI / demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Demo usage
    demo_findings = {
        "SPF": [
            {"severity": "CRITICAL", "description": "No SPF record found"},
        ],
        "DKIM": [
            {"severity": "HIGH", "description": "No DKIM selector found"},
        ],
        "DMARC": [
            {"severity": "HIGH", "description": "No DMARC record found"},
        ],
        "Zone Transfer": [
            {"severity": "MEDIUM", "description": "Zone transfer allowed to any"},
        ],
        "Subdomain Takeover": [
            {"severity": "CRITICAL", "description": "Subdomain takeover confirmed on dev.example.com"},
        ],
    }

    result = score_audit("example.com", demo_findings)
    import json
    print(json.dumps(result.to_dict(), indent=2))
