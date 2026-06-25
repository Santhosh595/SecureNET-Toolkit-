"""
DMARC Audit Module - Category 3 of DNSAudit Tool
=================================================
Queries and evaluates DMARC (Domain-based Message Authentication, Reporting & Conformance)
records for a given domain.

DMARC Maturity Model:
  Level 0 - No DMARC record found                    -> CRITICAL
  Level 1 - p=none (monitoring only)                  -> HIGH
  Level 2 - p=quarantine, pct=100                     -> MEDIUM
  Level 3 - p=reject, pct=100                         -> GOOD
  Level 4 - p=reject, pct=100 + strict alignment      -> EXCELLENT

Findings Categories:
  - DMARC record existence
  - Policy (p=) evaluation
  - Subdomain policy (sp=)
  - Percentage (pct=)
  - Reporting URIs (rua=, ruf=)
  - DMARC alignment (adkim=, aspf=)
  - Multiple DMARC records detection
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# ---------------------------------------------------------------------------
# Severity & Maturity Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Finding severity levels."""
    INFO = "INFO"
    WARNING = "WARNING"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    GOOD = "GOOD"
    EXCELLENT = "EXCELLENT"


class MaturityLevel(int, Enum):
    """DMARC maturity levels."""
    LEVEL_0 = 0  # No DMARC
    LEVEL_1 = 1  # p=none
    LEVEL_2 = 2  # p=quarantine, pct=100
    LEVEL_3 = 3  # p=reject, pct=100
    LEVEL_4 = 4  # p=reject, pct=100, strict alignment


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class DMARCFinding:
    """A single DMARC audit finding."""
    title: str
    severity: Severity
    description: str
    recommendation: str
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "details": self.details or {},
        }


@dataclass
class DMARCRecord:
    """Parsed DMARC record data."""
    raw: str
    version: Optional[str] = None
    policy: Optional[str] = None
    subdomain_policy: Optional[str] = None
    percentage: int = 100
    reporting_uris_rua: List[str] = field(default_factory=list)
    reporting_uris_ruf: List[str] = field(default_factory=list)
    alignment_dkim: str = "r"  # relaxed by default
    alignment_spf: str = "r"   # relaxed by default
    forensic_reporting: Optional[str] = None
    aggregate_reporting_interval: Optional[int] = None
    failure_reporting_options: Optional[str] = None

    @classmethod
    def parse(cls, record: str) -> "DMARCRecord":
        """Parse a DMARC TXT record string into structured data."""
        record = record.strip().strip('"')
        # Handle multiple TXT segments that may be concatenated
        # Some DNS libraries return the record as a single string
        parts = record.split(";")
        dmarc = cls(raw=record)

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Split on first '='
            if "=" not in part:
                continue
            key, _, value = part.partition("=")
            key = key.strip().lower()
            value = value.strip()

            if key == "v":
                dmarc.version = value
            elif key == "p":
                dmarc.policy = value.lower()
            elif key == "sp":
                dmarc.subdomain_policy = value.lower()
            elif key == "pct":
                try:
                    dmarc.percentage = int(value)
                except ValueError:
                    dmarc.percentage = 100
            elif key == "rua":
                dmarc.reporting_uris_rua = [uri.strip() for uri in value.split(",") if uri.strip()]
            elif key == "ruf":
                dmarc.reporting_uris_ruf = [uri.strip() for uri in value.split(",") if uri.strip()]
            elif key == "adkim":
                dmarc.alignment_dkim = value.lower()
            elif key == "aspf":
                dmarc.alignment_spf = value.lower()
            elif key == "fo":
                dmarc.forensic_reporting = value
            elif key == "ri":
                try:
                    dmarc.aggregate_reporting_interval = int(value)
                except ValueError:
                    pass
            elif key == "rf":
                dmarc.failure_reporting_options = value

        return dmarc


@dataclass
class DMARCAuditResult:
    """Complete DMARC audit result for a domain."""
    domain: str
    dmarc_domain: str
    records_found: int
    maturity_level: MaturityLevel
    maturity_label: str
    findings: List[DMARCFinding]
    parsed_records: List[DMARCRecord]
    path_to_enforcement: List[str]
    dns_query_successful: bool
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "dmarc_domain": self.dmarc_domain,
            "records_found": self.records_found,
            "maturity_level": self.maturity_level.value,
            "maturity_label": self.maturity_label,
            "findings": [f.to_dict() for f in self.findings],
            "parsed_records": [
                {
                    "raw": r.raw,
                    "version": r.version,
                    "policy": r.policy,
                    "subdomain_policy": r.subdomain_policy,
                    "percentage": r.percentage,
                    "reporting_uris_rua": r.reporting_uris_rua,
                    "reporting_uris_ruf": r.reporting_uris_ruf,
                    "alignment_dkim": r.alignment_dkim,
                    "alignment_spf": r.alignment_spf,
                }
                for r in self.parsed_records
            ],
            "path_to_enforcement": self.path_to_enforcement,
            "dns_query_successful": self.dns_query_successful,
            "error_message": self.error_message,
        }


# ---------------------------------------------------------------------------
# DNS Query Function
# ---------------------------------------------------------------------------

def query_dmarc_record(domain: str) -> List[str]:
    """
    Query the DMARC TXT record for a domain.
    Looks up _dmarc.domain
    
    Returns a list of raw TXT record strings.
    Raises exceptions if DNS resolution fails.
    """
    if not HAS_DNSPYTHON:
        raise ImportError(
            "dnspython is required for DMARC auditing. "
            "Install it with: pip install dnspython"
        )

    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        records = []
        for rdata in answers:
            # rdata.strings contains the TXT data segments
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            records.append(txt)
        return records
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NoNameservers:
        return []
    except dns.exception.Timeout:
        raise TimeoutError(f"DNS query timed out for {dmarc_domain}")
    except dns.exception.DNSException as e:
        raise RuntimeError(f"DNS query failed for {dmarc_domain}: {e}")


# ---------------------------------------------------------------------------
# Maturity Assessment
# ---------------------------------------------------------------------------

def assess_maturity(records: List[DMARCRecord]) -> tuple:
    """
    Determine the DMARC maturity level based on parsed records.
    
    Returns:
        (MaturityLevel, label_string, path_to_enforcement_list)
    """
    if not records:
        return (
            MaturityLevel.LEVEL_0,
            "Level 0 - No DMARC Record (CRITICAL)",
            [
                "Publish a DMARC record with p=none to begin monitoring",
                "Collect and analyze aggregate reports for 2-4 weeks",
                "Move to p=quarantine with pct=100 after confirming legitimate mail flow",
                "Progress to p=reject with pct=100",
                "Enable strict alignment (adkim=s, aspf=s) for Level 4",
            ],
        )

    # Use the first (primary) record for maturity assessment
    record = records[0]

    policy = record.policy
    pct = record.percentage
    adkim = record.alignment_dkim
    aspf = record.alignment_spf

    # Level 4: p=reject, pct=100, strict alignment
    if policy == "reject" and pct == 100 and adkim == "s" and aspf == "s":
        return (
            MaturityLevel.LEVEL_4,
            "Level 4 - Full Enforcement with Strict Alignment (EXCELLENT)",
            [
                "DMARC is at maximum maturity",
                "Continue monitoring aggregate and forensic reports",
                "Consider implementing BIMI for brand protection",
                "Regularly review DMARC policy as part of security governance",
            ],
        )

    # Level 3: p=reject, pct=100
    if policy == "reject" and pct == 100:
        return (
            MaturityLevel.LEVEL_3,
            "Level 3 - Full Enforcement (GOOD)",
            [
                "Upgrade to strict alignment: set adkim=s and aspf=s",
                "This achieves Level 4 maturity",
                "Monitor reports after enabling strict mode",
            ],
        )

    # Level 2: p=quarantine, pct=100
    if policy == "quarantine" and pct == 100:
        return (
            MaturityLevel.LEVEL_2,
            "Level 2 - Quarantine Full Enforcement (MEDIUM)",
            [
                "Upgrade policy from quarantine to reject: change p=quarantine to p=reject",
                "This achieves Level 3 maturity",
                "Then enable strict alignment for Level 4",
            ],
        )

    # Level 1: p=none
    if policy == "none":
        path = [
            "Increase pct to 100 if not already",
            "Upgrade policy from none to quarantine: change p=none to p=quarantine",
            "Monitor for 1-2 weeks, then upgrade to p=reject",
            "Finally enable strict alignment (adkim=s, aspf=s) for Level 4",
        ]
        if pct < 100:
            path.insert(0, f"Set pct=100 (currently at {pct}%)")
        return (
            MaturityLevel.LEVEL_1,
            "Level 1 - Monitoring Only (HIGH)",
            path,
        )

    # Fallback for unexpected policies
    return (
        MaturityLevel.LEVEL_1,
        "Level 1 - Partial/Unknown Configuration (HIGH)",
        [
            "Ensure DMARC policy is set to p=none, p=quarantine, or p=reject",
            "Progress through maturity levels toward p=reject with strict alignment",
        ],
    )


# ---------------------------------------------------------------------------
# Individual Check Functions
# ---------------------------------------------------------------------------

def check_record_existence(records_raw: List[str]) -> Optional[DMARCFinding]:
    """Check if DMARC record exists."""
    if not records_raw:
        return DMARCFinding(
            title="DMARC Record Missing",
            severity=Severity.CRITICAL,
            description="No DMARC TXT record found on _dmarc.domain. The domain is vulnerable to email spoofing and phishing attacks.",
            recommendation="Publish a DMARC record immediately. Start with 'v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com' to begin monitoring.",
        )
    return None


def check_multiple_records(records_raw: List[str]) -> Optional[DMARCFinding]:
    """Check for multiple DMARC records (invalid per RFC)."""
    if len(records_raw) > 1:
        return DMARCFinding(
            title="Multiple DMARC Records Detected",
            severity=Severity.CRITICAL,
            description=f"Found {len(records_raw)} DMARC records. Per RFC 7489, multiple DMARC records are invalid and behavior is undefined.",
            recommendation="Consolidate all DMARC policy into a single TXT record on _dmarc.domain.",
            details={"record_count": len(records_raw)},
        )
    return None


def check_policy(record: DMARCFinding) -> Optional[DMARCFinding]:
    """Check the DMARC policy (p=)."""
    policy = record.policy
    if policy is None:
        return DMARCFinding(
            title="DMARC Policy Missing",
            severity=Severity.HIGH,
            description="DMARC record does not contain a policy (p=) tag. Without a policy, the record provides no protection.",
            recommendation="Add 'p=none', 'p=quarantine', or 'p=reject' to your DMARC record.",
        )

    severity_map = {
        "none": (Severity.HIGH, "Policy is set to 'none' - monitoring only, no protection against spoofing."),
        "quarantine": (Severity.MEDIUM, "Policy is set to 'quarantine' - suspicious emails will be quarantined."),
        "reject": (Severity.GOOD, "Policy is set to 'reject' - spoofed emails will be rejected at the mail server."),
    }

    if policy in severity_map:
        sev, desc = severity_map[policy]
        if policy == "none":
            rec = "Upgrade to p=quarantine after monitoring legitimate mail flow, then progress to p=reject."
        elif policy == "quarantine":
            rec = "Progress to p=reject for full enforcement once confident in mail flow."
        else:
            rec = "Policy is at maximum enforcement. Consider strict alignment for Level 4 maturity."
        return DMARCFinding(
            title=f"DMARC Policy: p={policy}",
            severity=sev,
            description=desc,
            recommendation=rec,
            details={"policy": policy},
        )

    return DMARCFinding(
        title=f"Unknown DMARC Policy: p={policy}",
        severity=Severity.HIGH,
        description=f"DMARC policy value '{policy}' is not recognized. Valid values: none, quarantine, reject.",
        recommendation="Set p= to one of: none, quarantine, or reject.",
        details={"policy": policy},
    )


def check_subdomain_policy(record: DMARCRecord) -> Optional[DMARCFinding]:
    """Check subdomain policy (sp=)."""
    sp = record.subdomain_policy
    if sp is None:
        return DMARCFinding(
            title="Subdomain Policy Not Set",
            severity=Severity.WARNING,
            description="No subdomain policy (sp=) specified. Subdomains inherit the main policy by default.",
            recommendation="Explicitly set sp=none, sp=quarantine, or sp=reject to define subdomain behavior.",
        )

    severity_map = {
        "none": Severity.HIGH,
        "quarantine": Severity.MEDIUM,
        "reject": Severity.GOOD,
    }

    sev = severity_map.get(sp, Severity.WARNING)
    return DMARCFinding(
        title=f"Subdomain Policy: sp={sp}",
        severity=sev,
        description=f"Subdomain policy is set to '{sp}'.",
        recommendation="Ensure subdomain policy aligns with your security requirements.",
        details={"subdomain_policy": sp},
    )


def check_percentage(record: DMARCRecord) -> Optional[DMARCFinding]:
    """Check DMARC percentage (pct=)."""
    pct = record.percentage
    if pct < 100:
        return DMARCFinding(
            title=f"DMARC Percentage Below 100%: pct={pct}",
            severity=Severity.WARNING,
            description=f"DMARC policy is only applied to {pct}% of emails. This leaves {100 - pct}% of mail unprotected by DMARC policy.",
            recommendation="Set pct=100 to apply the DMARC policy to all emails for full protection.",
            details={"percentage": pct},
        )
    return None


def check_reporting_uris(record: DMARCRecord) -> Optional[DMARCFinding]:
    """Check reporting URIs (rua= and ruf=)."""
    issues = []
    details = {}

    if not record.reporting_uris_rua:
        issues.append("No aggregate reporting URI (rua=) configured.")
        details["rua"] = []
    else:
        details["rua"] = record.reporting_uris_rua

    if not record.reporting_uris_ruf:
        issues.append("No forensic reporting URI (ruf=) configured.")
        details["ruf"] = []
    else:
        details["ruf"] = record.reporting_uris_ruf

    if issues:
        return DMARCFinding(
            title="DMARC Reporting URIs Missing",
            severity=Severity.WARNING,
            description=" ".join(issues) + " Without reporting URIs, you cannot receive DMARC reports to monitor authentication results.",
            recommendation="Add rua=mailto:dmarc-reports@yourdomain.com for aggregate reports and ruf=mailto:dmarc-forensic@yourdomain.com for forensic reports.",
            details=details,
        )

    return DMARCFinding(
        title="DMARC Reporting URIs Configured",
        severity=Severity.GOOD,
        description=f"Aggregate reports: {len(record.reporting_uris_rua)} URI(s). Forensic reports: {len(record.reporting_uris_ruf)} URI(s).",
        recommendation="Ensure the reporting mailboxes are actively monitored and reports are reviewed regularly.",
        details=details,
    )


def check_alignment(record: DMARCRecord) -> Optional[DMARCFinding]:
    """Check DMARC alignment (adkim= and aspf=)."""
    adkim = record.alignment_dkim
    aspf = record.alignment_spf

    details = {"adkim": adkim, "aspf": aspf}

    if adkim == "s" and aspf == "s":
        return DMARCFinding(
            title="Strict Alignment Enabled",
            severity=Severity.EXCELLENT,
            description="Both DKIM (adkim=s) and SPF (aspf=s) are set to strict alignment. This provides the strongest DMARC protection.",
            recommendation="Strict alignment is optimal. Continue monitoring reports for any delivery issues.",
            details=details,
        )

    if adkim == "r" and aspf == "r":
        return DMARCFinding(
            title="Relaxed Alignment (Default)",
            severity=Severity.INFO,
            description="Both DKIM and SPF are using relaxed alignment (default). This allows organizational domain matching but is less strict.",
            recommendation="Consider upgrading to strict alignment (adkim=s; aspf=s) for Level 4 maturity after verifying mail flow compatibility.",
            details=details,
        )

    return DMARCFinding(
        title="Mixed Alignment Configuration",
        severity=Severity.INFO,
        description=f"DKIM alignment: {adkim}, SPF alignment: {aspf}. Mixed alignment settings may cause inconsistent behavior.",
        recommendation="Consider using strict alignment (adkim=s; aspf=s) for maximum protection, or ensure mixed settings are intentional.",
        details=details,
    )


# ---------------------------------------------------------------------------
# Main Audit Function
# ---------------------------------------------------------------------------

def audit_dmarc(domain: str) -> DMARCAuditResult:
    """
    Perform a complete DMARC audit for the given domain.
    
    Args:
        domain: The domain to audit (e.g., "example.com")
        
    Returns:
        DMARCAuditResult with all findings, maturity assessment, and recommendations.
    """
    dmarc_domain = f"_dmarc.{domain}"
    findings: List[DMARCFinding] = []
    parsed_records: List[DMARCRecord] = []
    dns_successful = True
    error_msg = None

    # Step 1: Query DNS
    try:
        raw_records = query_dmarc_record(domain)
    except ImportError as e:
        return DMARCAuditResult(
            domain=domain,
            dmarc_domain=dmarc_domain,
            records_found=0,
            maturity_level=MaturityLevel.LEVEL_0,
            maturity_label="Level 0 - Unable to Audit (CRITICAL)",
            findings=[
                DMARCFinding(
                    title="DNS Library Missing",
                    severity=Severity.CRITICAL,
                    description=str(e),
                    recommendation="Install dnspython: pip install dnspython",
                )
            ],
            parsed_records=[],
            path_to_enforcement=["Install dnspython to enable DMARC auditing"],
            dns_query_successful=False,
            error_message=str(e),
        )
    except TimeoutError as e:
        dns_successful = False
        error_msg = str(e)
        return DMARCAuditResult(
            domain=domain,
            dmarc_domain=dmarc_domain,
            records_found=0,
            maturity_level=MaturityLevel.LEVEL_0,
            maturity_label="Level 0 - DNS Timeout (CRITICAL)",
            findings=[
                DMARCFinding(
                    title="DNS Query Timeout",
                    severity=Severity.CRITICAL,
                    description=f"DNS query timed out for {dmarc_domain}.",
                    recommendation="Check DNS server availability and network connectivity.",
                )
            ],
            parsed_records=[],
            path_to_enforcement=["Resolve DNS connectivity issues and retry audit"],
            dns_query_successful=False,
            error_message=error_msg,
        )
    except RuntimeError as e:
        dns_successful = False
        error_msg = str(e)
        return DMARCAuditResult(
            domain=domain,
            dmarc_domain=dmarc_domain,
            records_found=0,
            maturity_level=MaturityLevel.LEVEL_0,
            maturity_label="Level 0 - DNS Query Failed (CRITICAL)",
            findings=[
                DMARCFinding(
                    title="DNS Query Failed",
                    severity=Severity.CRITICAL,
                    description=str(e),
                    recommendation="Verify DNS resolver configuration and domain existence.",
                )
            ],
            parsed_records=[],
            path_to_enforcement=["Resolve DNS issues and retry audit"],
            dns_query_successful=False,
            error_msg=error_msg,
        )

    # Step 2: Check record existence
    existence_finding = check_record_existence(raw_records)
    if existence_finding:
        findings.append(existence_finding)
        # No records to parse further
        maturity_level, maturity_label, path = assess_maturity([])
        return DMARCAuditResult(
            domain=domain,
            dmarc_domain=dmarc_domain,
            records_found=0,
            maturity_level=maturity_level,
            maturity_label=maturity_label,
            findings=findings,
            parsed_records=[],
            path_to_enforcement=path,
            dns_query_successful=True,
        )

    # Step 3: Check for multiple records
    multi_finding = check_multiple_records(raw_records)
    if multi_finding:
        findings.append(multi_finding)

    # Step 4: Parse all records
    for raw in raw_records:
        parsed_records.append(DMARCRecord.parse(raw))

    # Step 5: Assess maturity
    maturity_level, maturity_label, path = assess_maturity(parsed_records)

    # Step 6: Run individual checks on primary record
    primary = parsed_records[0]

    # Policy check
    policy_finding = check_policy(primary)
    if policy_finding:
        findings.append(policy_finding)

    # Subdomain policy check
    sp_finding = check_subdomain_policy(primary)
    if sp_finding:
        findings.append(sp_finding)

    # Percentage check
    pct_finding = check_percentage(primary)
    if pct_finding:
        findings.append(pct_finding)

    # Reporting URIs check
    reporting_finding = check_reporting_uris(primary)
    if reporting_finding:
        findings.append(reporting_finding)

    # Alignment check
    alignment_finding = check_alignment(primary)
    if alignment_finding:
        findings.append(alignment_finding)

    return DMARCAuditResult(
        domain=domain,
        dmarc_domain=dmarc_domain,
        records_found=len(raw_records),
        maturity_level=maturity_level,
        maturity_label=maturity_label,
        findings=findings,
        parsed_records=parsed_records,
        path_to_enforcement=path,
        dns_query_successful=dns_successful,
        error_message=error_msg,
    )


# ---------------------------------------------------------------------------
# Convenience / Display Functions
# ---------------------------------------------------------------------------

def format_audit_report(result: DMARCAuditResult) -> str:
    """Format the audit result as a human-readable report string."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"  DMARC Audit Report: {result.domain}")
    lines.append("=" * 70)
    lines.append(f"  DMARC Domain:     {result.dmarc_domain}")
    lines.append(f"  Records Found:    {result.records_found}")
    lines.append(f"  Maturity Level:   {result.maturity_label}")
    lines.append(f"  DNS Query Status: {'Success' if result.dns_query_successful else 'Failed'}")
    if result.error_message:
        lines.append(f"  Error:            {result.error_message}")
    lines.append("-" * 70)
    lines.append("  FINDINGS:")
    lines.append("-" * 70)

    if not result.findings:
        lines.append("  No findings - DMARC configuration looks good!")
    else:
        for i, finding in enumerate(result.findings, 1):
            lines.append(f"  [{finding.severity.value}] {finding.title}")
            lines.append(f"    {finding.description}")
            lines.append(f"    → {finding.recommendation}")
            lines.append("")

    lines.append("-" * 70)
    lines.append("  PATH TO FULL ENFORCEMENT:")
    lines.append("-" * 70)
    for step_num, step in enumerate(result.path_to_enforcement, 1):
        lines.append(f"    {step_num}. {step}")

    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dmarc.py <domain>")
        print("Example: python dmarc.py example.com")
        sys.exit(1)

    target_domain = sys.argv[1].strip()
    print(f"[*] Auditing DMARC for: {target_domain}")
    print()

    result = audit_dmarc(target_domain)
    report = format_audit_report(result)
    print(report)

    # Exit code based on maturity
    if result.maturity_level <= MaturityLevel.LEVEL_0:
        sys.exit(2)  # Critical
    elif result.maturity_level <= MaturityLevel.LEVEL_1:
        sys.exit(1)  # Warning
    else:
        sys.exit(0)  # OK
