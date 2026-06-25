"""DNSAudit - DANE/TLSA Audit Module (Category 12)"""

from __future__ import annotations
import dns.resolver
import dns.name
from dataclasses import dataclass, field
from typing import Optional


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    WARNING = "WARNING"
    INFO = "INFO"
    GOOD = "GOOD"


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    description: str
    recommendation: str = ""


@dataclass
class TLSARecord:
    usage: int
    selector: int
    matching_type: int
    certificate_data: str
    raw: str


@dataclass
class DANEAuditResult:
    findings: list = field(default_factory=list)
    tlsa_records: list = field(default_factory=list)
    dane_enabled: bool = False
    matches_certificate: Optional[bool] = None
    dnssec_required: bool = True


def audit_dane(domain: str, resolver: dns.resolver.Resolver = None) -> DANEAuditResult:
    """Audit DANE/TLSA records for a domain."""
    result = DANEAuditResult()

    if resolver is None:
        resolver = dns.resolver.Resolver()

    # Query TLSA records on _443._tcp.domain
    tlsa_name = f"_443._tcp.{domain}"

    try:
        answers = resolver.resolve(tlsa_name, "TLSA")
        result.dane_enabled = True
        result.tlsa_records = []

        for rdata in answers:
            record = TLSARecord(
                usage=rdata.usage,
                selector=rdata.selector,
                matching_type=rdata.matching_type,
                certificate_data=rdata.cert.hex() if hasattr(rdata.cert, 'hex') else str(rdata.cert),
                raw=str(rdata)
            )
            result.tlsa_records.append(record)

        result.findings.append(Finding(
            check="DANE Enabled",
            severity=Severity.GOOD,
            title="DANE/TLSA records found",
            description=f"Found {len(result.tlsa_records)} TLSA record(s) for {tlsa_name}",
            recommendation="Ensure DNSSEC is enabled for DANE to be effective."
        ))

        # Check each TLSA record
        for record in result.tlsa_records:
            # Certificate usage
            usage_map = {0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE"}
            usage_name = usage_map.get(record.usage, f"Unknown ({record.usage})")

            if record.usage in (0, 1):
                result.findings.append(Finding(
                    check="TLSA Usage",
                    severity=Severity.WARNING,
                    title=f"TLSA usage is {usage_name}",
                    description="PKIX usage requires additional PKIX validation. DANE usage (2 or 3) is preferred.",
                    recommendation="Consider using DANE-TA (2) or DANE-EE (3) for direct DANE validation."
                ))

            # Selector
            if record.selector == 0:
                result.findings.append(Finding(
                    check="TLSA Selector",
                    severity=Severity.INFO,
                    title="Full certificate selector",
                    description="Selector 0 matches the full certificate. Selector 1 (public key) is more flexible.",
                    recommendation="Consider using selector 1 (public key) for easier certificate rotation."
                ))

            # Matching type
            matching_map = {0: "Full", 1: "SHA-256", 2: "SHA-512"}
            matching_name = matching_map.get(record.matching_type, f"Unknown ({record.matching_type})")

            if record.matching_type == 0:
                result.findings.append(Finding(
                    check="TLSA Matching",
                    severity=Severity.WARNING,
                    title="Full matching type",
                    description="Full matching (0) requires exact certificate match. SHA-256 (1) or SHA-512 (2) is more efficient.",
                    recommendation="Consider using SHA-256 (1) matching type."
                ))

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result.findings.append(Finding(
            check="DANE Enabled",
            severity=Severity.MEDIUM,
            title="No DANE/TLSA records found",
            description=f"No TLSA records found at {tlsa_name}",
            recommendation="Consider implementing DANE to bind your TLS certificate to DNSSEC."
        ))
    except dns.resolver.NoNameservers:
        result.findings.append(Finding(
            check="DANE Query",
            severity=Severity.WARNING,
            title="Could not query TLSA records",
            description="No nameservers responded to TLSA query.",
            recommendation="Check DNS resolver configuration."
        ))
    except Exception as e:
        result.findings.append(Finding(
            check="DANE Query",
            severity=Severity.WARNING,
            title="TLSA query failed",
            description=f"Error: {str(e)}",
            recommendation="Check DNS resolver configuration."
        ))

    # DNSSEC requirement
    result.findings.append(Finding(
        check="DNSSEC Requirement",
        severity=Severity.INFO,
        title="DANE requires DNSSEC",
        description="DANE is only effective when DNSSEC is enabled on the zone.",
        recommendation="Enable DNSSEC at your registrar to make DANE effective."
    ))

    return result


def format_dane_report(result: DANEAuditResult) -> str:
    """Format DANE audit result as a readable report."""
    lines = []
    lines.append("=== DANE/TLSA Audit ===")
    lines.append(f"DANE Enabled: {'Yes' if result.dane_enabled else 'No'}")
    lines.append(f"TLSA Records: {len(result.tlsa_records)}")
    lines.append("")

    if result.tlsa_records:
        lines.append("TLSA Records:")
        for i, rec in enumerate(result.tlsa_records, 1):
            usage_map = {0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE"}
            selector_map = {0: "Full Certificate", 1: "Public Key"}
            matching_map = {0: "Full", 1: "SHA-256", 2: "SHA-512"}
            lines.append(f"  [{i}] Usage: {usage_map.get(rec.usage, rec.usage)}, "
                        f"Selector: {selector_map.get(rec.selector, rec.selector)}, "
                        f"Matching: {matching_map.get(rec.matching_type, rec.matching_type)}")

    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title}")
            if f.description:
                lines.append(f"    {f.description}")
            if f.recommendation:
                lines.append(f"    Recommendation: {f.recommendation}")

    return "\n".join(lines)
