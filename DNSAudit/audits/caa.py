"""
CAA Audit Module - Category 10 of DNSAudit Tool
================================================
Audits Certification Authority Authorization (CAA) records for a domain:
- CAA record existence (MEDIUM if missing)
- issue tag validation (allows specific CAs to issue certificates)
- issuewild tag validation (wildcard certificate issuance rules)
- iodef tag validation (incident reporting contact)
- Overly permissive issue tag (empty ';' = allows any CA = MEDIUM)

Uses dnspython for DNS CAA record resolution.
"""

import re
import logging
import dns.resolver
import dns.exception
import dns.name
import dns.rdatatype
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity & Data Models
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Finding severity levels aligned with the DNSAudit taxonomy."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    WARNING = "WARNING"
    INFO = "INFO"
    GOOD = "GOOD"


@dataclass
class Finding:
    """A single structured finding from the CAA audit."""
    severity: Severity
    title: str
    description: str
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class CAARecord:
    """Represents a parsed CAA DNS record."""
    flags: int
    tag: str
    value: str
    raw: str

    def to_dict(self) -> dict:
        return {
            "flags": self.flags,
            "tag": self.tag,
            "value": self.value,
            "raw": self.raw,
        }


@dataclass
class CAAAuditResult:
    """Complete result of a CAA audit for a domain."""
    domain: str
    caa_records: List[CAARecord] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    issue_tags: List[CAARecord] = field(default_factory=list)
    issuewild_tags: List[CAARecord] = field(default_factory=list)
    iodef_tags: List[CAARecord] = field(default_factory=list)
    has_caa: bool = False
    overall_severity: str = "GOOD"

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "has_caa": self.has_caa,
            "caa_records": [r.to_dict() for r in self.caa_records],
            "findings": [f.to_dict() for f in self.findings],
            "issue_tags": [r.to_dict() for r in self.issue_tags],
            "issuewild_tags": [r.to_dict() for r in self.issuewild_tags],
            "iodef_tags": [r.to_dict() for r in self.iodef_tags],
            "overall_severity": self.overall_severity,
        }

    def compute_overall_severity(self):
        """Compute the worst severity among all findings."""
        severity_order = {
            "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
            "LOW": 3, "WARNING": 4, "INFO": 5, "GOOD": 6,
        }
        if not self.findings:
            self.overall_severity = "GOOD"
            return
        worst = min(self.findings, key=lambda f: severity_order.get(f.severity.value, 5))
        self.overall_severity = worst.severity.value


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Valid CAA property tags per RFC 8659
VALID_CAA_TAGS = {"issue", "issuewild", "iodef", "contactemail", "contactphone", "auth", "path", "policy"}

# Known public CAs for validation hints
KNOWN_PUBLIC_CAS = {
    "digicert.com": "DigiCert",
    "letsencrypt.org": "Let's Encrypt",
    "globalsign.com": "GlobalSign",
    "comodoca.com": "Comodo/Sectigo",
    "geotrust.com": "GeoTrust",
    "thawte.com": "Thawte",
    "rapidssl.com": "RapidSSL",
    "symantec.com": "Symantec",
    "amazon.com": "Amazon",
    "google.com": "Google Trust Services",
    "microsoft.com": "Microsoft",
    "cloudflare.com": "Cloudflare",
    "pki.goog": "Google Trust Services",
    "encryptioneverywhere.dev": "Let's Encrypt (Encryption Everywhere)",
    "ssl.com": "SSL.com",
    "actalis.it": "Actalis",
    "trustprovider.bv": "TrustProvider",
    "buypass.com": "Buypass",
    "zerossl.com": "ZeroSSL",
}

# Critical flag (bit 7) - issuer MUST understand the property before issuance
CRITICAL_FLAG = 128


# ---------------------------------------------------------------------------
# DNS Query Helpers
# ---------------------------------------------------------------------------

def query_caa_records(domain: str) -> List[str]:
    """
    Query DNS CAA records for a domain.
    Returns list of raw CAA record strings.
    """
    try:
        answers = dns.resolver.resolve(domain, "CAA")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        raise RuntimeError(f"DNS CAA query failed for {domain}: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Unexpected DNS error for {domain}: {e}") from e

    records = []
    for rdata in answers:
        # rdata has: flags (int), tag (bytes), value (bytes)
        raw = f"{rdata.flags} {rdata.tag.decode('utf-8')} \"{rdata.value.decode('utf-8')}\""
        records.append(raw)
    return records


# ---------------------------------------------------------------------------
# CAA Record Parsing
# ---------------------------------------------------------------------------

def parse_caa_record(raw: str) -> Optional[CAARecord]:
    """
    Parse a CAA record string into a CAARecord object.
    Expected format: <flags> <tag> "<value>"
    Example: 0 issue "digicert.com"
    """
    # Match: flags (number), tag (word), value (quoted string)
    match = re.match(r'^(\d+)\s+(\S+)\s+"?([^"]*)"?\s*$', raw.strip())
    if match:
        flags = int(match.group(1))
        tag = match.group(2).lower()
        value = match.group(3)
        return CAARecord(flags=flags, tag=tag, value=value, raw=raw.strip())

    # Fallback: try without quotes
    match = re.match(r'^(\d+)\s+(\S+)\s+(\S+)\s*$', raw.strip())
    if match:
        flags = int(match.group(1))
        tag = match.group(2).lower()
        value = match.group(3)
        return CAARecord(flags=flags, tag=tag, value=value, raw=raw.strip())

    logger.warning("Could not parse CAA record: %s", raw)
    return None


def parse_caa_records(raw_records: List[str]) -> List[CAARecord]:
    """Parse a list of raw CAA record strings into CAARecord objects."""
    records = []
    for raw in raw_records:
        parsed = parse_caa_record(raw)
        if parsed:
            records.append(parsed)
    return records


# ---------------------------------------------------------------------------
# Individual Check Functions
# ---------------------------------------------------------------------------

def check_caa_exists(records: List[CAARecord], domain: str) -> Optional[Finding]:
    """Check if CAA records exist for the domain."""
    if not records:
        return Finding(
            severity=Severity.MEDIUM,
            title="CAA records missing",
            description=(
                f"No CAA records found for {domain}. "
                "Without CAA, any Certificate Authority can issue certificates "
                "for this domain, increasing the risk of unauthorized certificate issuance."
            ),
            recommendation=(
                "Publish CAA records to restrict which CAs can issue certificates "
                "for this domain. Example: 0 issue \"letsencrypt.org\""
            ),
        )
    return Finding(
        severity=Severity.GOOD,
        title="CAA records present",
        description=f"Found {len(records)} CAA record(s) for {domain}.",
        recommendation="No action needed. Review the CAA records to ensure they match your intended policy.",
    )


def check_issue_tag(records: List[CAARecord]) -> List[Finding]:
    """Check the 'issue' tag - which CAs are authorized to issue non-wildcard certs."""
    findings = []
    issue_records = [r for r in records if r.tag == "issue"]

    if not issue_records:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Missing 'issue' tag",
            description=(
                "No 'issue' CAA record found. The 'issue' tag specifies which "
                "Certificate Authorities are authorized to issue non-wildcard certificates "
                "for this domain. Without it, the CAA policy may be incomplete."
            ),
            recommendation=(
                "Add an 'issue' tag to specify authorized CAs. "
                "Example: 0 issue \"letsencrypt.org\""
            ),
        ))
        return findings

    for record in issue_records:
        # Check for overly permissive: empty value or just ';'
        if record.value.strip() in (";", "", "; ;"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Overly permissive 'issue' tag (empty/semicolon)",
                description=(
                    f"The 'issue' tag value is '{record.value}' which effectively "
                    "allows ANY Certificate Authority to issue certificates for this domain. "
                    "This defeats the purpose of CAA."
                ),
                recommendation=(
                    "Replace the empty/semicolon 'issue' value with your authorized CA domain. "
                    "Example: 0 issue \"digicert.com\""
                ),
            ))
        elif record.value.strip() == "*":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Overly permissive 'issue' tag (wildcard)",
                description=(
                    f"The 'issue' tag value is '*' (wildcard) which allows any CA "
                    "to issue certificates. This is equivalent to having no restriction."
                ),
                recommendation=(
                    "Replace the wildcard with a specific CA domain. "
                    "Example: 0 issue \"letsencrypt.org\""
                ),
            ))
        else:
            # Validate the CA domain looks reasonable
            ca_domain = record.value.strip().lower()
            # Check if it's a known CA
            ca_name = KNOWN_PUBLIC_CAS.get(ca_domain, None)
            if ca_name:
                findings.append(Finding(
                    severity=Severity.GOOD,
                    title=f"Authorized CA: {ca_name}",
                    description=f"The 'issue' tag authorizes {ca_name} ({ca_domain}) to issue certificates.",
                    recommendation="No action needed. Verify this is your intended CA.",
                ))
            else:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Custom CA authorized: {ca_domain}",
                    description=(
                        f"The 'issue' tag authorizes '{ca_domain}' to issue certificates. "
                        "This does not match known public CAs. Verify this is intentional."
                    ),
                    recommendation=(
                        "If this is your internal CA or a lesser-known provider, ensure "
                        "the domain is correct. If you intended a public CA, check for typos."
                    ),
                ))

        # Check critical flag
        if record.flags & CRITICAL_FLAG:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Critical flag set on 'issue' tag",
                description=(
                    f"The critical flag (0x80) is set on the 'issue' tag. "
                    "CAs MUST understand this property before issuing."
                ),
                recommendation=(
                    "This is informational. Ensure your CA supports CAA critical flags. "
                    "Most modern CAs do, but unknown flags may cause issuance failures "
                    "with some CAs."
                ),
            ))

    return findings


def check_issuewild_tag(records: List[CAARecord]) -> List[Finding]:
    """Check the 'issuewild' tag - which CAs are authorized to issue wildcard certs."""
    findings = []
    issuewild_records = [r for r in records if r.tag == "issuewild"]

    if not issuewild_records:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Missing 'issuewild' tag",
            description=(
                "No 'issuewild' CAA record found. The 'issuewild' tag controls "
                "which CAs can issue wildcard certificates (*.domain.com). "
                "Without it, wildcard issuance follows the 'issue' tag rules."
            ),
            recommendation=(
                "Add an 'issuewild' tag to explicitly control wildcard certificate issuance. "
                "Example: 0 issuewild \"digicert.com\" "
                "Or to block all wildcard issuance: 0 issuewild \";\""
            ),
        ))
        return findings

    for record in issuewild_records:
        # Check for overly permissive
        if record.value.strip() in (";", "", "; ;"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Overly permissive 'issuewild' tag (empty/semicolon)",
                description=(
                    f"The 'issuewild' tag value is '{record.value}' which allows "
                    "any CA to issue wildcard certificates for this domain."
                ),
                recommendation=(
                    "To block wildcard issuance entirely, use: 0 issuewild \";\" "
                    "To allow a specific CA: 0 issuewild \"letsencrypt.org\""
                ),
            ))
        elif record.value.strip() == "*":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Overly permissive 'issuewild' tag (wildcard)",
                description=(
                    f"The 'issuewild' tag value is '*' (wildcard) which allows any CA "
                    "to issue wildcard certificates."
                ),
                recommendation=(
                    "Replace the wildcard with a specific CA domain to restrict "
                    "wildcard certificate issuance."
                ),
            ))
        else:
            ca_domain = record.value.strip().lower()
            ca_name = KNOWN_PUBLIC_CAS.get(ca_domain, None)
            if ca_name:
                findings.append(Finding(
                    severity=Severity.GOOD,
                    title=f"Wildcard CA authorized: {ca_name}",
                    description=f"The 'issuewild' tag authorizes {ca_name} to issue wildcard certificates.",
                    recommendation="No action needed.",
                ))
            else:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Custom wildcard CA: {ca_domain}",
                    description=f"The 'issuewild' tag authorizes '{ca_domain}' for wildcard issuance.",
                    recommendation="Verify this domain is correct and intentional.",
                ))

    return findings


def check_iodef_tag(records: List[CAARecord]) -> List[Finding]:
    """Check the 'iodef' tag - how CAs should report invalid certificate requests."""
    findings = []
    iodef_records = [r for r in records if r.tag == "iodef"]

    if not iodef_records:
        findings.append(Finding(
            severity=Severity.LOW,
            title="Missing 'iodef' tag",
            description=(
                "No 'iodef' CAA record found. The 'iodef' tag specifies how CAs "
                "should report invalid certificate requests (RFC 8659). "
                "This helps detect unauthorized certificate issuance attempts."
            ),
            recommendation=(
                "Add an 'iodef' tag to receive violation reports from CAs. "
                "Example: 0 iodef \"mailto:security@domain.com\" "
                "Or: 0 iodef \"https://domain.com/caa-report\""
            ),
        ))
        return findings

    for record in iodef_records:
        value = record.value.strip()

        # Validate iodef format
        if value.startswith("mailto:"):
            email = value[7:]
            if re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                findings.append(Finding(
                    severity=Severity.GOOD,
                    title="IODEF email contact configured",
                    description=f"CA violation reports will be sent to: {email}",
                    recommendation="No action needed. Ensure this mailbox is monitored.",
                ))
            else:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Invalid IODEF email address",
                    description=f"The IODEF mailto address '{email}' does not appear to be a valid email.",
                    recommendation="Verify the email address format. Example: mailto:security@domain.com",
                ))
        elif value.startswith("http://") or value.startswith("https://"):
            findings.append(Finding(
                severity=Severity.GOOD,
                title="IODEF webhook/URL configured",
                description=f"CA violation reports will be sent to: {value}",
                recommendation="No action needed. Ensure the endpoint is active and monitored.",
            ))
        else:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Unrecognized IODEF format",
                description=(
                    f"The IODEF value '{value}' does not match expected formats. "
                    "Valid formats: mailto:email@domain.com or https://domain.com/report"
                ),
                recommendation=(
                    "Use a valid IODEF format: "
                    "mailto: for email or http(s):// for a webhook URL."
                ),
            ))

    return findings


def check_unknown_tags(records: List[CAARecord]) -> List[Finding]:
    """Check for unknown or non-standard CAA tags."""
    findings = []
    for record in records:
        if record.tag not in VALID_CAA_TAGS:
            findings.append(Finding(
                severity=Severity.WARNING,
                title=f"Unknown CAA tag: '{record.tag}'",
                description=(
                    f"The tag '{record.tag}' is not a standard CAA property tag per RFC 8659. "
                    "CAs may ignore unknown tags, making this record ineffective."
                ),
                recommendation=(
                    f"Use standard CAA tags: {', '.join(sorted(VALID_CAA_TAGS))}. "
                    "Remove or correct unknown tags."
                ),
            ))
    return findings


def check_critical_flags(records: List[CAARecord]) -> List[Finding]:
    """Check for critical flags on non-standard tags that could cause issuance failures."""
    findings = []
    for record in records:
        if record.flags & CRITICAL_FLAG and record.tag not in VALID_CAA_TAGS:
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Critical flag on unknown tag '{record.tag}'",
                description=(
                    f"The critical flag (0x80) is set on the unknown tag '{record.tag}'. "
                    "CAs MUST NOT issue certificates if they encounter a critical flag "
                    "on an unknown property. This will cause certificate issuance to FAIL."
                ),
                recommendation=(
                    "Remove the critical flag from unknown tags, or replace the tag "
                    "with a standard CAA property tag."
                ),
            ))
    return findings


def check_issue_before_issuewild(records: List[CAARecord]) -> List[Finding]:
    """
    Check if 'issue' and 'issuewild' are both present.
    issuewild takes precedence over issue for wildcard certs.
    """
    findings = []
    has_issue = any(r.tag == "issue" for r in records)
    has_issuewild = any(r.tag == "issuewild" for r in records)

    if has_issue and has_issuewild:
        findings.append(Finding(
            severity=Severity.GOOD,
            title="Both 'issue' and 'issuewild' tags present",
            description=(
                "Both tags are configured. 'issuewild' takes precedence for wildcard "
                "certificates, while 'issue' controls non-wildcard issuance."
            ),
            recommendation="No action needed. This is the recommended configuration.",
        ))
    elif has_issue and not has_issuewild:
        # This is already flagged in check_issuewild_tag, so we skip duplicate
        pass

    return findings


# ---------------------------------------------------------------------------
# Main Audit Function
# ---------------------------------------------------------------------------

def audit_caa(domain: str, caa_records_raw: Optional[List[str]] = None) -> CAAAuditResult:
    """
    Perform a complete CAA audit for the given domain.

    Args:
        domain: The domain to audit (e.g., "example.com").
        caa_records_raw: Optional pre-fetched CAA record strings. If None,
                         the function will query DNS.

    Returns:
        CAAAuditResult with all findings and parsed records.
    """
    result = CAAAuditResult(domain=domain)

    # -----------------------------------------------------------------------
    # Step 1: Query CAA records
    # -----------------------------------------------------------------------
    if caa_records_raw is None:
        try:
            caa_records_raw = query_caa_records(domain)
        except RuntimeError as e:
            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title="DNS CAA query failed",
                description=str(e),
                recommendation=(
                    "Verify the domain exists and DNS is reachable. "
                    "Check for typos in the domain name."
                ),
            ))
            result.compute_overall_severity()
            return result

    # -----------------------------------------------------------------------
    # Step 2: Parse records
    # -----------------------------------------------------------------------
    records = parse_caa_records(caa_records_raw)
    result.caa_records = records
    result.has_caa = len(records) > 0

    # Categorize by tag
    result.issue_tags = [r for r in records if r.tag == "issue"]
    result.issuewild_tags = [r for r in records if r.tag == "issuewild"]
    result.iodef_tags = [r for r in records if r.tag == "iodef"]

    # -----------------------------------------------------------------------
    # Step 3: Check CAA existence
    # -----------------------------------------------------------------------
    existence_finding = check_caa_exists(records, domain)
    if existence_finding:
        result.findings.append(existence_finding)

    if not records:
        result.compute_overall_severity()
        return result

    # -----------------------------------------------------------------------
    # Step 4: Check 'issue' tag
    # -----------------------------------------------------------------------
    issue_findings = check_issue_tag(records)
    result.findings.extend(issue_findings)

    # -----------------------------------------------------------------------
    # Step 5: Check 'issuewild' tag
    # -----------------------------------------------------------------------
    issuewild_findings = check_issuewild_tag(records)
    result.findings.extend(issuewild_findings)

    # -----------------------------------------------------------------------
    # Step 6: Check 'iodef' tag
    # -----------------------------------------------------------------------
    iodef_findings = check_iodef_tag(records)
    result.findings.extend(iodef_findings)

    # -----------------------------------------------------------------------
    # Step 7: Check for unknown tags
    # -----------------------------------------------------------------------
    unknown_findings = check_unknown_tags(records)
    result.findings.extend(unknown_findings)

    # -----------------------------------------------------------------------
    # Step 8: Check critical flags on unknown tags
    # -----------------------------------------------------------------------
    critical_findings = check_critical_flags(records)
    result.findings.extend(critical_findings)

    # -----------------------------------------------------------------------
    # Step 9: Check issue/issuewild combination
    # -----------------------------------------------------------------------
    combo_findings = check_issue_before_issuewild(records)
    result.findings.extend(combo_findings)

    # -----------------------------------------------------------------------
    # Final: Compute overall severity
    # -----------------------------------------------------------------------
    result.compute_overall_severity()

    return result


# ---------------------------------------------------------------------------
# Pretty-Print / CLI Output
# ---------------------------------------------------------------------------

def format_audit_report(result: CAAAuditResult) -> str:
    """Format the CAA audit result as a human-readable report."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"  CAA AUDIT REPORT: {result.domain}")
    lines.append("=" * 70)

    # Summary
    lines.append(f"\nCAA Records Found: {len(result.caa_records)}")
    lines.append(f"Overall Severity: {result.overall_severity}")
    lines.append(f"Issue Tags: {len(result.issue_tags)}")
    lines.append(f"Issuewild Tags: {len(result.issuewild_tags)}")
    lines.append(f"IODEF Tags: {len(result.iodef_tags)}")

    # CAA Records Table
    lines.append("\n" + "-" * 70)
    lines.append("CAA RECORDS")
    lines.append("-" * 70)
    lines.append(f"{'#':<4} {'Flags':<8} {'Tag':<15} {'Value':<40}")
    lines.append("-" * 70)
    for i, r in enumerate(result.caa_records, 1):
        flag_str = str(r.flags)
        if r.flags & CRITICAL_FLAG:
            flag_str += " (critical)"
        lines.append(f"{i:<4} {flag_str:<8} {r.tag:<15} {r.value:<40}")

    # Findings
    lines.append("\n" + "-" * 70)
    lines.append("FINDINGS")
    lines.append("-" * 70)
    for f in result.findings:
        lines.append(f"\n[{f.severity.value}] {f.title}")
        lines.append(f"  Description: {f.description}")
        lines.append(f"  Recommendation: {f.recommendation}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python caa.py <domain> [--json]")
        print("Example: python caa.py example.com")
        print("         python caa.py example.com --json")
        sys.exit(1)

    target_domain = sys.argv[1]
    output_json = "--json" in sys.argv

    audit_result = audit_caa(target_domain)

    if output_json:
        print(json.dumps(audit_result.to_dict(), indent=2))
    else:
        print(format_audit_report(audit_result))
