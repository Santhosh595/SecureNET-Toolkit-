"""
DNSAudit - Zone Transfer Audit Module (Category 5)

Tests for insecure DNS zone transfers (AXFR/IXFR) on all authoritative nameservers.
Successful zone transfers are CRITICAL vulnerabilities as they expose the entire DNS zone,
including all subdomains, internal infrastructure, and potentially sensitive records.

Severity Levels:
- CRITICAL: AXFR/IXFR succeeds, exposing entire zone
- HIGH: IXFR partially succeeds or zone transfer misconfigured
- LOW: Zone transfer properly restricted
- INFO: Nameservers identified and tested
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

try:
    import dns.name
    import dns.query
    import dns.rdatatype
    import dns.resolver
    import dns.zone
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# ─── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class ZoneTransferRecord:
    """Represents a single DNS record exposed via zone transfer."""
    name: str
    rrtype: str
    value: str
    ttl: int = 0


@dataclass
class NameserverTransferResult:
    """Result of zone transfer attempt against a single nameserver."""
    nameserver: str
    nameserver_ip: Optional[str] = None
    axfr_success: bool = False
    ixfr_success: bool = False
    axfr_records_exposed: list = field(default_factory=list)
    ixfr_records_exposed: list = field(default_factory=list)
    axfr_record_count: int = 0
    ixfr_record_count: int = 0
    soa_serial: Optional[int] = None
    error_message: Optional[str] = None
    response_time_ms: float = 0.0


@dataclass
class ZoneTransferFinding:
    """Structured finding for zone transfer audit."""
    finding_id: str = ""
    category: str = "zone_transfer"
    severity: str = "LOW"
    title: str = ""
    description: str = ""
    target_domain: str = ""
    nameserver: str = ""
    nameserver_ip: str = ""
    transfer_type: str = ""  # AXFR, IXFR, or BOTH
    records_exposed: list = field(default_factory=list)
    record_count: int = 0
    soa_serial: Optional[int] = None
    remediation: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class ZoneTransferAuditResult:
    """Complete result of zone transfer audit for a domain."""
    domain: str = ""
    findings: list = field(default_factory=list)
    nameservers_tested: int = 0
    nameservers_vulnerable: int = 0
    total_records_exposed: int = 0
    scan_duration_seconds: float = 0.0
    success: bool = True
    error: Optional[str] = None


# ─── Core Audit Functions ──────────────────────────────────────────────────────

def resolve_nameservers(domain: str) -> list:
    """
    Resolve all authoritative nameservers for a given domain.
    Returns a list of tuples: (ns_name, ns_ip)
    """
    if not HAS_DNSPYTHON:
        return []

    nameservers = []
    try:
        # Query for NS records
        answers = dns.resolver.resolve(domain, dns.rdatatype.NS)
        for rdata in answers:
            ns_name = str(rdata.target).rstrip('.')
            # Resolve the nameserver's IP address
            try:
                ip_answers = dns.resolver.resolve(ns_name, dns.rdatatype.A)
                for ip_rdata in ip_answers:
                    nameservers.append((ns_name, str(ip_rdata)))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                # Try AAAA if no A record
                try:
                    ip_answers = dns.resolver.resolve(ns_name, dns.rdatatype.AAAA)
                    for ip_rdata in ip_answers:
                        nameservers.append((ns_name, str(ip_rdata)))
                except Exception:
                    nameservers.append((ns_name, None))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass

    return nameservers


def attempt_axfr(domain: str, nameserver_ip: str, timeout: int = 10) -> tuple:
    """
    Attempt a full zone transfer (AXFR) from a specific nameserver.
    
    Returns:
        tuple: (success: bool, records: list[ZoneTransferRecord], serial: int or None, error: str or None)
    """
    if not HAS_DNSPYTHON:
        return False, [], None, "dnspython library not available"

    records = []
    serial = None
    try:
        # Attempt AXFR query
        xfr = dns.query.xfr(nameserver_ip, domain, timeout=timeout)
        # If we get here, the transfer was accepted - iterate through messages
        for message in xfr:
            for rrset in message.answer:
                rrtype = dns.rdatatype.to_text(rrset.rdtype)
                ttl = rrset.ttl
                for rdata in rrset:
                    record = ZoneTransferRecord(
                        name=str(rrset.name),
                        rrtype=rrtype,
                        value=str(rdata),
                        ttl=ttl
                    )
                    records.append(record)

        # Extract SOA serial from records
        for rec in records:
            if rec.rrtype == "SOA":
                soa_parts = rec.value.split()
                if len(soa_parts) >= 3:
                    try:
                        serial = int(soa_parts[2])
                    except (ValueError, IndexError):
                        pass
                break

        return True, records, serial, None

    except dns.query.TransferError as e:
        return False, [], None, f"Transfer refused: {str(e)}"
    except dns.exception.Timeout:
        return False, [], None, "Connection timed out"
    except ConnectionRefusedError:
        return False, [], None, "Connection refused"
    except OSError as e:
        return False, [], None, f"Network error: {str(e)}"
    except Exception as e:
        return False, [], None, f"Unexpected error: {str(e)}"


def attempt_ixfr(domain: str, nameserver_ip: str, serial: int = 0, timeout: int = 10) -> tuple:
    """
    Attempt an incremental zone transfer (IXFR) from a specific nameserver.
    
    Args:
        domain: The zone to transfer
        nameserver_ip: The nameserver IP to query
        serial: The current SOA serial to use as the basis for incremental transfer
        timeout: Query timeout in seconds
    
    Returns:
        tuple: (success: bool, records: list[ZoneTransferRecord], error: str or None)
    """
    if not HAS_DNSPYTHON:
        return False, [], "dnspython library not available"

    records = []
    try:
        # Attempt IXFR query with the provided serial
        xfr = dns.query.xfr(nameserver_ip, domain, timeout=timeout,
                            rdtype=dns.rdatatype.IXFR, serial=serial)
        for message in xfr:
            for rrset in message.answer:
                rrtype = dns.rdatatype.to_text(rrset.rdtype)
                ttl = rrset.ttl
                for rdata in rrset:
                    record = ZoneTransferRecord(
                        name=str(rrset.name),
                        rrtype=rrtype,
                        value=str(rdata),
                        ttl=ttl
                    )
                    records.append(record)

        return True, records, None

    except dns.query.TransferError as e:
        return False, [], f"IXFR transfer refused: {str(e)}"
    except dns.exception.Timeout:
        return False, [], "Connection timed out"
    except ConnectionRefusedError:
        return False, [], "Connection refused"
    except OSError as e:
        return False, [], f"Network error: {str(e)}"
    except Exception as e:
        return False, [], f"Unexpected error: {str(e)}"


def test_nameserver_zone_transfer(domain: str, ns_name: str, ns_ip: Optional[str]) -> NameserverTransferResult:
    """
    Test a single nameserver for zone transfer vulnerabilities (AXFR and IXFR).
    """
    result = NameserverTransferResult(
        nameserver=ns_name,
        nameserver_ip=ns_ip
    )

    if not ns_ip:
        result.error_message = "Could not resolve nameserver IP address"
        return result

    if not HAS_DNSPYTHON:
        result.error_message = "dnspython library not available"
        return result

    # Attempt AXFR
    start_time = time.time()
    axfr_success, axfr_records, soa_serial, axfr_error = attempt_axfr(domain, ns_ip)
    result.response_time_ms = (time.time() - start_time) * 1000

    result.axfr_success = axfr_success
    result.axfr_records_exposed = axfr_records
    result.axfr_record_count = len(axfr_records)
    result.soa_serial = soa_serial

    if axfr_error:
        result.error_message = axfr_error

    # Attempt IXFR (use SOA serial if available)
    if soa_serial:
        ixfr_success, ixfr_records, ixfr_error = attempt_ixfr(domain, ns_ip, serial=soa_serial)
        result.ixfr_success = ixfr_success
        result.ixfr_records_exposed = ixfr_records
        result.ixfr_record_count = len(ixfr_records)

    return result


# ─── Main Audit Entry Point ────────────────────────────────────────────────────

def audit_zone_transfer(domain: str, timeout: int = 10) -> ZoneTransferAuditResult:
    """
    Perform a complete zone transfer audit on the given domain.
    
    This function:
    1. Resolves all authoritative nameservers for the domain
    2. Attempts AXFR on each nameserver
    3. Attempts IXFR on each nameserver
    4. Returns structured findings with severity ratings
    
    Args:
        domain: The domain to audit (e.g., "example.com")
        timeout: Query timeout in seconds (default: 10)
    
    Returns:
        ZoneTransferAuditResult with all findings
    """
    start_time = time.time()
    result = ZoneTransferAuditResult(domain=domain)

    if not HAS_DNSPYTHON:
        result.success = False
        result.error = "dnspython library is required. Install with: pip install dnspython"
        return result

    # Step 1: Resolve nameservers
    nameservers = resolve_nameservers(domain)
    result.nameservers_tested = len(nameservers)

    if not nameservers:
        result.findings.append(ZoneTransferFinding(
            target_domain=domain,
            severity="INFO",
            title="No authoritative nameservers found",
            description=f"Could not resolve NS records for {domain}. Zone transfer test skipped.",
            remediation="Ensure the domain has properly configured NS records."
        ))
        result.scan_duration_seconds = time.time() - start_time
        return result

    # Step 2: Test each nameserver
    for ns_name, ns_ip in nameservers:
        ns_result = test_nameserver_zone_transfer(domain, ns_name, ns_ip)

        if ns_result.axfr_success:
            # CRITICAL: Full zone transfer succeeded
            result.nameservers_vulnerable += 1
            result.total_records_exposed += ns_result.axfr_record_count

            # Build record summary for description
            record_types = {}
            for rec in ns_result.axfr_records_exposed:
                record_types[rec.rrtype] = record_types.get(rec.rrtype, 0) + 1

            record_summary = ", ".join(
                f"{count} {rtype}" for rtype, count in sorted(record_types.items())
            )

            finding = ZoneTransferFinding(
                target_domain=domain,
                severity="CRITICAL",
                title=f"AXFR zone transfer permitted by {ns_name}",
                description=(
                    f"Nameserver {ns_name} ({ns_ip}) allows full zone transfers (AXFR). "
                    f"The entire DNS zone has been exposed, revealing {ns_result.axfr_record_count} "
                    f"records ({record_summary}). This is a critical security vulnerability as it "
                    f"exposes all subdomains, mail servers, and internal infrastructure to attackers."
                ),
                nameserver=ns_name,
                nameserver_ip=ns_ip or "",
                transfer_type="AXFR",
                records_exposed=[
                    {"name": r.name, "type": r.rrtype, "value": r.value, "ttl": r.ttl}
                    for r in ns_result.axfr_records_exposed
                ],
                record_count=ns_result.axfr_record_count,
                soa_serial=ns_result.soa_serial,
                remediation=(
                    "Configure your nameserver to restrict zone transfers to authorized "
                    "secondary nameservers only. For BIND: use 'allow-transfer' directive. "
                    "For Windows DNS: disable zone transfers or restrict to specific IPs. "
                    "Consider using TSIG authentication for zone transfers."
                )
            )
            result.findings.append(finding)

        elif ns_result.ixfr_success:
            # HIGH: IXFR succeeded but AXFR was blocked
            result.nameservers_vulnerable += 1
            result.total_records_exposed += ns_result.ixfr_record_count

            finding = ZoneTransferFinding(
                target_domain=domain,
                severity="HIGH",
                title=f"IXFR zone transfer permitted by {ns_name}",
                description=(
                    f"Nameserver {ns_name} ({ns_ip}) allows incremental zone transfers (IXFR). "
                    f"While less severe than AXFR, this can still expose zone changes over time. "
                    f"{ns_result.ixfr_record_count} records were retrieved via IXFR."
                ),
                nameserver=ns_name,
                nameserver_ip=ns_ip or "",
                transfer_type="IXFR",
                records_exposed=[
                    {"name": r.name, "type": r.rrtype, "value": r.value, "ttl": r.ttl}
                    for r in ns_result.ixfr_records_exposed
                ],
                record_count=ns_result.ixfr_record_count,
                remediation=(
                    "Restrict zone transfers to authorized secondary nameservers. "
                    "Review IXFR configuration to ensure only necessary incremental "
                    "transfers are permitted."
                )
            )
            result.findings.append(finding)

        else:
            # LOW: Zone transfer properly restricted
            finding = ZoneTransferFinding(
                target_domain=domain,
                severity="LOW",
                title=f"Zone transfer restricted on {ns_name}",
                description=(
                    f"Nameserver {ns_name} ({ns_ip}) properly refuses zone transfers. "
                    f"AXFR was denied."
                ),
                nameserver=ns_name,
                nameserver_ip=ns_ip or "",
                transfer_type="NONE",
                record_count=0,
                remediation="No action needed. Zone transfer is properly restricted."
            )
            result.findings.append(finding)

    result.scan_duration_seconds = time.time() - start_time
    return result


# ─── Report Formatting ─────────────────────────────────────────────────────────

def format_audit_report(audit_result: ZoneTransferAuditResult) -> str:
    """
    Format the audit result as a human-readable report.
    """
    lines = []
    lines.append("=" * 72)
    lines.append("DNS ZONE TRANSFER AUDIT REPORT")
    lines.append("=" * 72)
    lines.append(f"Domain: {audit_result.domain}")
    lines.append(f"Nameservers Tested: {audit_result.nameservers_tested}")
    lines.append(f"Vulnerable Nameservers: {audit_result.nameservers_vulnerable}")
    lines.append(f"Total Records Exposed: {audit_result.total_records_exposed}")
    lines.append(f"Scan Duration: {audit_result.scan_duration_seconds:.2f}s")
    lines.append("")

    if audit_result.error:
        lines.append(f"ERROR: {audit_result.error}")
        lines.append("")

    # Group findings by severity
    critical_findings = [f for f in audit_result.findings if f.severity == "CRITICAL"]
    high_findings = [f for f in audit_result.findings if f.severity == "HIGH"]
    low_findings = [f for f in audit_result.findings if f.severity == "LOW"]
    info_findings = [f for f in audit_result.findings if f.severity == "INFO"]

    if critical_findings:
        lines.append("!" * 72)
        lines.append("CRITICAL FINDINGS")
        lines.append("!" * 72)
        for finding in critical_findings:
            lines.append(f"  [{finding.severity}] {finding.title}")
            lines.append(f"    Nameserver: {finding.nameserver} ({finding.nameserver_ip})")
            lines.append(f"    Transfer Type: {finding.transfer_type}")
            lines.append(f"    Records Exposed: {finding.record_count}")
            if finding.soa_serial:
                lines.append(f"    SOA Serial: {finding.soa_serial}")
            lines.append(f"    Description: {finding.description}")
            lines.append(f"    Remediation: {finding.remediation}")
            if finding.records_exposed:
                lines.append(f"    Exposed Records (first 20):")
                for rec in finding.records_exposed[:20]:
                    lines.append(f"      {rec['name']} {rec['ttl']} {rec['type']} {rec['value']}")
                if len(finding.records_exposed) > 20:
                    lines.append(f"      ... and {len(finding.records_exposed) - 20} more records")
            lines.append("")

    if high_findings:
        lines.append("-" * 72)
        lines.append("HIGH SEVERITY FINDINGS")
        lines.append("-" * 72)
        for finding in high_findings:
            lines.append(f"  [{finding.severity}] {finding.title}")
            lines.append(f"    Nameserver: {finding.nameserver} ({finding.nameserver_ip})")
            lines.append(f"    Records Exposed: {finding.record_count}")
            lines.append(f"    Description: {finding.description}")
            lines.append(f"    Remediation: {finding.remediation}")
            lines.append("")

    if low_findings:
        lines.append("-" * 72)
        lines.append("LOW SEVERITY FINDINGS (Zone Transfer Restricted)")
        lines.append("-" * 72)
        for finding in low_findings:
            lines.append(f"  [{finding.severity}] {finding.title}")
            lines.append(f"    Nameserver: {finding.nameserver} ({finding.nameserver_ip})")
            lines.append("")

    if info_findings:
        lines.append("-" * 72)
        lines.append("INFORMATIONAL")
        lines.append("-" * 72)
        for finding in info_findings:
            lines.append(f"  [{finding.severity}] {finding.title}")
            lines.append(f"    {finding.description}")
            lines.append("")

    lines.append("=" * 72)
    lines.append("END OF REPORT")
    lines.append("=" * 72)

    return "\n".join(lines)


# ─── CLI Entry Point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python zone_transfer.py <domain> [timeout]")
        print("Example: python zone_transfer.py example.com 15")
        sys.exit(1)

    target_domain = sys.argv[1]
    query_timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    print(f"[*] Starting zone transfer audit for: {target_domain}")
    print(f"[*] Timeout: {query_timeout}s")
    print()

    audit_result = audit_zone_transfer(target_domain, timeout=query_timeout)

    report = format_audit_report(audit_result)
    print(report)

    # Exit with appropriate code
    critical_count = sum(1 for f in audit_result.findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in audit_result.findings if f.severity == "HIGH")

    if critical_count > 0:
        sys.exit(2)  # Critical findings
    elif high_count > 0:
        sys.exit(1)  # High findings
    else:
        sys.exit(0)  # Clean
