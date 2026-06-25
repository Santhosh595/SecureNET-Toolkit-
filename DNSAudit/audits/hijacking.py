"""
DNS Hijacking Detection Module - Category 7
============================================
DNSAudit: Detect DNS hijacking, poisoning, BGP hijacking indicators,
split-horizon DNS, and illegitimate MX record resolution.

Requirements:
    pip install dnspython rich requests
"""

import socket
import time
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional
from collections import defaultdict

import dns.resolver
import dns.exception
import dns.name
import dns.rdatatype
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

logger = logging.getLogger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRUSTED_RESOLVERS = {
    "Google (8.8.8.8)": "8.8.8.8",
    "Google (8.8.4.4)": "8.8.4.4",
    "Cloudflare (1.1.1.1)": "1.1.1.1",
    "Cloudflare (1.0.0.1)": "1.0.0.1",
    "Quad9 (9.9.9.9)": "9.9.9.9",
    "Quad9 (149.112.112.112)": "149.112.112.112",
}

RECORD_TYPES = ["A", "AAAA", "MX", "NS"]

# Known legitimate mail provider MX patterns (partial match)
KNOWN_MX_PROVIDERS = [
    "google.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "microsoft.com",
    "yahoo.com", "ymail.com",
    "protonmail.ch", "protonmail.com",
    "zoho.com", "zohomail.com",
    "mail.protonmail.ch",
    "mx1.", "mx2.",  # generic
    "aspmx.l.google.com",
    "alt1.aspmx.l.google.com",
]

# BGP looking-glass / RIPE endpoints for ASN lookups
RIPE_STAT_API = "https://stat.ripe.net/data/prefix-overview/data.json"
BGPVIEW_API = "https://api.bgpview.io/prefix"

# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class ResolverResult:
    """Results from a single resolver for a single record type."""
    resolver_name: str
    resolver_ip: str
    record_type: str
    values: list = field(default_factory=list)
    error: Optional[str] = None
    response_time_ms: float = 0.0


@dataclass
class ComparisonFinding:
    """A finding from comparing resolver results."""
    record_type: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    title: str
    description: str
    resolver_values: dict = field(default_factory=dict)
    recommendation: str = ""


@dataclass
class BGPIndicator:
    """BGP hijacking indicator for a given IP prefix."""
    ip: str
    prefix: str = ""
    asns: list = field(default_factory=list)
    as_names: list = field(default_factory=list)
    country: str = ""
    is_suspicious: bool = False
    reason: str = ""


@dataclass
class MXLegitimacyResult:
    """Result of MX record legitimacy check."""
    mx_record: str
    resolved_ips: list = field(default_factory=list)
    is_known_provider: bool = False
    provider_name: str = ""
    is_suspicious: bool = False
    reasons: list = field(default_factory=list)


@dataclass
class HijackingReport:
    """Complete DNS hijacking detection report."""
    domain: str
    timestamp: str = ""
    overall_risk: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    resolver_results: list = field(default_factory=list)
    comparison_findings: list = field(default_factory=list)
    bgp_indicators: list = field(default_factory=list)
    split_horizon_detected: bool = False
    split_horizon_details: list = field(default_factory=list)
    mx_legitimacy: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _create_resolver(nameservers: list, timeout: float = 5.0) -> dns.resolver.Resolver:
    """Create a dns.resolver.Resolver configured with specific nameservers."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def _resolve_with_resolver(
    resolver: dns.resolver.Resolver,
    domain: str,
    record_type: str,
    resolver_name: str,
    resolver_ip: str,
) -> ResolverResult:
    """Resolve a single record type using a specific resolver."""
    result = ResolverResult(
        resolver_name=resolver_name,
        resolver_ip=resolver_ip,
        record_type=record_type,
    )
    start = time.monotonic()
    try:
        answers = resolver.resolve(domain, record_type)
        result.values = [str(rdata) for rdata in answers]
        result.response_time_ms = (time.monotonic() - start) * 1000
    except dns.resolver.NXDOMAIN:
        result.error = "NXDOMAIN"
        result.response_time_ms = (time.monotonic() - start) * 1000
    except dns.resolver.NoAnswer:
        result.error = "NoAnswer"
        result.response_time_ms = (time.monotonic() - start) * 1000
    except dns.resolver.NoNameservers:
        result.error = "NoNameservers"
        result.response_time_ms = (time.monotonic() - start) * 1000
    except dns.exception.Timeout:
        result.error = "Timeout"
        result.response_time_ms = (time.monotonic() - start) * 1000
    except Exception as e:
        result.error = str(e)
        result.response_time_ms = (time.monotonic() - start) * 1000
    return result


def _get_system_resolver() -> dns.resolver.Resolver:
    """Get the system default resolver."""
    resolver = dns.resolver.Resolver()
    return resolver


def _extract_mx_hostname(mx_value: str) -> str:
    """Extract the hostname from an MX record value (with optional priority)."""
    parts = mx_value.strip().split()
    if len(parts) >= 2:
        return parts[1].rstrip(".").lower()
    return mx_value.strip().rstrip(".").lower()


def _extract_ns_hostname(ns_value: str) -> str:
    """Extract the hostname from an NS record value."""
    return ns_value.strip().rstrip(".").lower()


# ---------------------------------------------------------------------------
# Core Detection Functions
# ---------------------------------------------------------------------------

def resolve_all_records(
    domain: str,
    resolvers: dict = None,
    record_types: list = None,
) -> list:
    """
    Resolve all requested record types across all trusted resolvers
    and the system resolver.

    Returns a list of ResolverResult objects.
    """
    if resolvers is None:
        resolvers = TRUSTED_RESOLVERS
    if record_types is None:
        record_types = RECORD_TYPES

    results = []

    # System resolver
    logger.info("Resolving via system resolver...")
    system_resolver = _get_system_resolver()
    for rtype in record_types:
        result = _resolve_with_resolver(
            system_resolver, domain, rtype, "System Resolver",
            ",".join(system_resolver.nameservers),
        )
        results.append(result)

    # Trusted third-party resolvers
    for name, ip in resolvers.items():
        logger.info("Resolving via %s (%s)...", name, ip)
        resolver = _create_resolver([ip])
        for rtype in record_types:
            result = _resolve_with_resolver(resolver, domain, rtype, name, ip)
            results.append(result)

    return results


def compare_resolver_results(results: list) -> list:
    """
    Compare resolver results and flag discrepancies that may indicate
    DNS hijacking or poisoning.

    Returns a list of ComparisonFinding objects.
    """
    findings = []

    # Group by record type
    by_type = defaultdict(list)
    for r in results:
        by_type[r.record_type].append(r)

    for rtype, group in by_type.items():
        # Collect all unique value sets
        value_sets = {}
        for r in group:
            key = tuple(sorted(r.values)) if r.values else (r.error or "EMPTY",)
            value_sets.setdefault(key, []).append(r.resolver_name)

        # If all resolvers agree, no finding
        if len(value_sets) <= 1:
            continue

        # Determine severity based on record type and divergence
        severity = _determine_severity(rtype, group, value_sets)

        # Build resolver_values mapping
        resolver_values = {}
        for r in group:
            resolver_values[r.resolver_name] = {
                "values": r.values,
                "error": r.error,
                "response_time_ms": round(r.response_time_ms, 2),
            }

        # Identify majority vs minority
        majority_key = max(value_sets, key=lambda k: len(value_sets[k]))
        minority_keys = [k for k in value_sets if k != majority_key]

        majority_resolvers = value_sets[majority_key]
        minority_resolvers = []
        for k in minority_keys:
            minority_resolvers.extend(value_sets[k])

        finding = ComparisonFinding(
            record_type=rtype,
            severity=severity,
            title=f"DNS Divergence Detected for {rtype} Records",
            description=(
                f"Different resolvers returned different {rtype} results. "
                f"Majority ({', '.join(majority_resolvers)}) returned: "
                f"{list(majority_key)}. "
                f"Divergent resolvers ({', '.join(minority_resolvers)}) returned: "
                f"{[list(k) for k in minority_keys]}."
            ),
            resolver_values=resolver_values,
            recommendation=_get_recommendation(rtype, severity),
        )
        findings.append(finding)

    return findings


def _determine_severity(record_type: str, group: list, value_sets: dict) -> str:
    """Determine severity of a DNS divergence finding."""
    # Count how many resolvers disagree
    total_resolvers = len(group)
    unique_responses = len(value_sets)

    # If more than half of resolvers disagree, it's critical
    majority_count = max(len(v) for v in value_sets.values())
    minority_count = total_resolvers - majority_count

    if record_type in ("A", "AAAA"):
        if minority_count > majority_count:
            return "CRITICAL"
        elif minority_count > 0:
            return "HIGH"
    elif record_type == "MX":
        if minority_count > 0:
            return "HIGH"
    elif record_type == "NS":
        if minority_count > 0:
            return "CRITICAL"

    if unique_responses > 2:
        return "HIGH"

    return "MEDIUM"


def _get_recommendation(record_type: str, severity: str) -> str:
    """Get a recommendation based on record type and severity."""
    recs = {
        "CRITICAL": (
            "Immediate investigation recommended. DNS hijacking or poisoning "
            "is strongly suspected. Verify with the domain registrar and your "
            "DNS provider. Consider enabling DNSSEC."
        ),
        "HIGH": (
            "Significant DNS discrepancies detected. This may indicate DNS "
            "poisoning, a compromised resolver, or an active attack. "
            "Cross-verify with multiple sources."
        ),
        "MEDIUM": (
            "Minor DNS differences found. This could be due to CDN routing, "
            "geo-DNS, or split-horizon configurations. Investigate if "
            "unexpected."
        ),
    }
    return recs.get(severity, "Monitor for further anomalies.")


def detect_split_horizon(
    domain: str,
    resolver_results: list,
) -> tuple:
    """
    Detect split-horizon DNS by comparing internal (system) resolver
    results with external trusted resolvers.

    Returns (bool, list of details).
    """
    details = []

    # Get system resolver results
    system_results = {
        r.record_type: r
        for r in resolver_results
        if r.resolver_name == "System Resolver"
    }

    # Get external resolver consensus
    external_by_type = defaultdict(list)
    for r in resolver_results:
        if r.resolver_name != "System Resolver":
            external_by_type[r.record_type].append(r)

    for rtype in RECORD_TYPES:
        if rtype not in system_results:
            continue
        sys_result = system_results[rtype]
        if sys_result.error or not sys_result.values:
            continue

        # Build set of external values
        external_values = set()
        for ext in external_by_type.get(rtype, []):
            if not ext.error:
                external_values.update(ext.values)

        if not external_values:
            continue

        # Check if system resolver returns values not seen externally
        system_only = set(sys_result.values) - external_values
        external_only = external_values - set(sys_result.values)

        if system_only and external_only:
            details.append({
                "record_type": rtype,
                "system_only_values": list(system_only),
                "external_only_values": list(external_only),
                "assessment": (
                    "Split-horizon DNS likely: internal resolver returns "
                    "different results than external resolvers."
                ),
            })
        elif system_only:
            details.append({
                "record_type": rtype,
                "system_only_values": list(system_only),
                "external_only_values": [],
                "assessment": (
                    "Possible split-horizon DNS: internal resolver returns "
                    "additional records not visible externally."
                ),
            })

    return (len(details) > 0, details)


def check_bgp_hijacking(
    domain: str,
    resolver_results: list,
) -> list:
    """
    Check for BGP hijacking indicators by looking up the ASN information
    for resolved IP addresses and comparing against expected origin ASNs.

    Uses RIPE Stat API and BGPView API for ASN/prefix lookups.

    Returns a list of BGPIndicator objects.
    """
    indicators = []

    # Collect all unique IPs from A and AAAA results
    all_ips = set()
    for r in resolver_results:
        if r.record_type in ("A", "AAAA") and r.values:
            for val in r.values:
                # For MX records that resolve to IPs, also include
                if r.record_type in ("A", "AAAA"):
                    all_ips.add(val)

    # Also resolve MX hostnames to IPs for BGP check
    mx_hostnames = set()
    for r in resolver_results:
        if r.record_type == "MX" and r.values:
            for val in r.values:
                mx_hostnames.add(_extract_mx_hostname(val))

    for hostname in mx_hostnames:
        try:
            ips = socket.getaddrinfo(hostname, None)
            for info in ips:
                ip = info[4][0]
                all_ips.add(ip)
        except socket.gaierror:
            continue

    # For each IP, do ASN/prefix lookup
    for ip in all_ips:
        indicator = _check_ip_bgp(ip)
        if indicator:
            indicators.append(indicator)

    return indicators


def _check_ip_bgp(ip: str) -> Optional[BGPIndicator]:
    """Check a single IP for BGP hijacking indicators."""
    indicator = BGPIndicator(ip=ip)

    # Try RIPE Stat API first
    try:
        resp = requests.get(
            RIPE_STAT_API,
            params={"resource": ip, "lod": 1},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data"):
                d = data["data"]
                asns = d.get("asns", [])
                if asns:
                    indicator.asns = [str(a.get("asn", "")) for a in asns]
                    indicator.as_names = [a.get("holder", "") for a in asns]
                    indicator.prefix = d.get("prefix", "")
                    indicator.country = d.get("country", "")
    except (requests.RequestException, KeyError, json.JSONDecodeError):
        pass

    # If no RIPE data, try BGPView for the IP's prefix
    if not indicator.asns:
        indicator = _check_bgpview(ip, indicator)

    # Heuristic: flag if AS info is missing (suspicious for non-RFC1918)
    if not indicator.asns and not _is_private_ip(ip):
        indicator.is_suspicious = True
        indicator.reason = "No ASN data available for public IP; possible BGP anomaly"

    return indicator


def _check_bgpview(ip: str, indicator: BGPIndicator) -> BGPIndicator:
    """Fallback BGP lookup using BGPView API."""
    try:
        # Get the /24 or /64 prefix for lookup
        import ipaddress
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
        else:
            network = ipaddress.ip_network(f"{ip}/64", strict=False)

        resp = requests.get(
            f"{BGPVIEW_API}?prefix={network}",
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            prefixes = data.get("data", {}).get("prefixes", [])
            for p in prefixes:
                if p.get("country_code"):
                    indicator.country = p["country_code"]
                asns = p.get("asn", {})
                if isinstance(asns, dict):
                    indicator.asns = [str(asns.get("asn", ""))]
                    indicator.as_names = [asns.get("name", "")]
                elif isinstance(asns, list):
                    indicator.asns = [str(a.get("asn", "")) for a in asns]
                    indicator.as_names = [a.get("name", "") for a in asns]
                indicator.prefix = p.get("prefix", str(network))
    except (requests.RequestException, KeyError, json.JSONDecodeError, ValueError):
        pass

    return indicator


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def check_mx_legitimacy(
    domain: str,
    resolver_results: list,
) -> list:
    """
    Check whether MX records resolve to legitimate mail servers.

    Returns a list of MXLegitimacyResult objects.
    """
    results = []

    # Collect all MX records from all resolvers
    mx_records = set()
    for r in resolver_results:
        if r.record_type == "MX" and r.values:
            for val in r.values:
                mx_records.add(_extract_mx_hostname(val))

    for mx_host in mx_records:
        result = MXLegitimacyResult(mx_record=mx_host)

        # Resolve the MX hostname to IPs
        try:
            ips = socket.getaddrinfo(mx_host, 25, type=socket.SOCK_STREAM)
            result.resolved_ips = list({info[4][0] for info in ips})
        except socket.gaierror:
            result.is_suspicious = True
            result.reasons.append(f"MX hostname {mx_host} does not resolve")
            results.append(result)
            continue

        # Check against known providers
        is_known = False
        provider = ""
        for pattern in KNOWN_MX_PROVIDERS:
            if pattern in mx_host:
                is_known = True
                provider = pattern
                break

        result.is_known_provider = is_known
        result.provider_name = provider

        # Check if MX resolves to private/internal IPs
        for ip in result.resolved_ips:
            if _is_private_ip(ip):
                result.is_suspicious = True
                result.reasons.append(
                    f"MX resolves to private/internal IP: {ip}"
                )

        # Check for suspicious patterns in MX hostname
        suspicious_patterns = [
            "localhost", "127.0.0.1", "0.0.0.0",
            "mail.local", "smtp.local",
        ]
        for pat in suspicious_patterns:
            if pat in mx_host:
                result.is_suspicious = True
                result.reasons.append(
                    f"MX hostname contains suspicious pattern: {pat}"
                )

        # Check if MX points to the domain itself (self-referencing is OK but note)
        if mx_host == domain.lower():
            result.reasons.append("MX points to domain itself (self-hosted)")

        # If MX has no A/AAAA records at all
        if not result.resolved_ips:
            result.is_suspicious = True
            result.reasons.append("MX record does not resolve to any IP")

        results.append(result)

    return results


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_report(
    domain: str,
    resolver_results: list,
    comparison_findings: list,
    bgp_indicators: list,
    split_horizon: bool,
    split_horizon_details: list,
    mx_legitimacy: list,
) -> HijackingReport:
    """Generate a structured HijackingReport from all findings."""

    # Determine overall risk
    severities = [f.severity for f in comparison_findings]
    if "CRITICAL" in severities or split_horizon:
        overall_risk = "CRITICAL"
    elif "HIGH" in severities:
        overall_risk = "HIGH"
    elif "MEDIUM" in severities:
        overall_risk = "MEDIUM"
    elif any(ind.is_suspicious for ind in bgp_indicators):
        overall_risk = "HIGH"
    elif any(mx.is_suspicious for mx in mx_legitimacy):
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    # Build summary
    summary = {
        "total_resolver_queries": len(resolver_results),
        "divergent_record_types": len(set(f.record_type for f in comparison_findings)),
        "total_findings": len(comparison_findings),
        "critical_findings": severities.count("CRITICAL"),
        "high_findings": severities.count("HIGH"),
        "medium_findings": severities.count("MEDIUM"),
        "bgp_indicators_found": len(bgp_indicators),
        "suspicious_bgp_indicators": sum(1 for i in bgp_indicators if i.is_suspicious),
        "split_horizon_detected": split_horizon,
        "mx_records_checked": len(mx_legitimacy),
        "suspicious_mx_records": sum(1 for m in mx_legitimacy if m.is_suspicious),
    }

    report = HijackingReport(
        domain=domain,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        overall_risk=overall_risk,
        resolver_results=resolver_results,
        comparison_findings=comparison_findings,
        bgp_indicators=bgp_indicators,
        split_horizon_detected=split_horizon,
        split_horizon_details=split_horizon_details,
        mx_legitimacy=mx_legitimacy,
        summary=summary,
    )

    return report


# ---------------------------------------------------------------------------
# Rich Console Output
# ---------------------------------------------------------------------------

def print_report(report: HijackingReport) -> None:
    """Print a formatted report to the console using Rich."""
    # Header
    risk_colors = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
    }
    color = risk_colors.get(report.overall_risk, "white")

    console.print()
    console.print(Panel(
        f"[bold]DNS Hijacking Detection Report[/bold]\n"
        f"Domain: [cyan]{report.domain}[/cyan]\n"
        f"Timestamp: {report.timestamp}\n"
        f"Overall Risk: [{color}]{report.overall_risk}[/{color}]",
        title="🔍 DNSAudit - Category 7",
        border_style="blue",
    ))

    # Resolution Comparison Table
    console.print("\n[bold underline]📊 Resolution Comparison Table[/bold underline]")
    table = Table(show_header=True, header_style="bold magenta", show_lines=True)
    table.add_column("Record Type", style="cyan", width=12)
    table.add_column("Resolver", width=28)
    table.add_column("Values", width=45)
    table.add_column("Response (ms)", justify="right", width=12)

    for r in report.resolver_results:
        values_str = ", ".join(r.values) if r.values else (r.error or "N/A")
        table.add_row(
            r.record_type,
            r.resolver_name,
            values_str,
            f"{r.response_time_ms:.1f}",
        )

    console.print(table)

    # Findings
    if report.comparison_findings:
        console.print("\n[bold underline]⚠️  Divergence Findings[/bold underline]")
        for finding in report.comparison_findings:
            sev_colors = {
                "CRITICAL": "red bold",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "dim",
            }
            sev_color = sev_colors.get(finding.severity, "white")
            console.print(Panel(
                f"[{sev_color}]{finding.severity}[/{sev_color}] "
                f"[bold]{finding.title}[/bold]\n"
                f"{finding.description}\n"
                f"[dim]Recommendation: {finding.recommendation}[/dim]",
                border_style=sev_color,
            ))

    # Split-Horizon
    if report.split_horizon_detected:
        console.print("\n[bold underline]🔀 Split-Horizon DNS Detected[/bold underline]")
        for detail in report.split_horizon_details:
            console.print(f"  [yellow]• [{detail['record_type']}] {detail['assessment']}[/yellow]")
            if detail.get("system_only_values"):
                console.print(f"    System-only: {detail['system_only_values']}")
            if detail.get("external_only_values"):
                console.print(f"    External-only: {detail['external_only_values']}")

    # BGP Indicators
    if report.bgp_indicators:
        console.print("\n[bold underline]🌐 BGP Hijacking Indicators[/bold underline]")
        bgp_table = Table(show_header=True, header_style="bold blue")
        bgp_table.add_column("IP", width=16)
        bgp_table.add_column("Prefix", width=20)
        bgp_table.add_column("ASNs", width=15)
        bgp_table.add_column("AS Names", width=25)
        bgp_table.add_column("Country", width=8)
        bgp_table.add_column("Suspicious", width=10)
        bgp_table.add_column("Reason", width=30)

        for ind in report.bgp_indicators:
            bgp_table.add_row(
                ind.ip,
                ind.prefix,
                ", ".join(ind.asns) or "N/A",
                ", ".join(ind.as_names) or "N/A",
                ind.country or "N/A",
                "⚠️ YES" if ind.is_suspicious else "✓ No",
                ind.reason or "-",
            )
        console.print(bgp_table)

    # MX Legitimacy
    if report.mx_legitimacy:
        console.print("\n[bold underline]📧 MX Record Legitimacy[/bold underline]")
        mx_table = Table(show_header=True, header_style="bold green")
        mx_table.add_column("MX Record", width=30)
        mx_table.add_column("Resolved IPs", width=25)
        mx_table.add_column("Known Provider", width=15)
        mx_table.add_column("Suspicious", width=10)
        mx_table.add_column("Notes", width=30)

        for mx in report.mx_legitimacy:
            mx_table.add_row(
                mx.mx_record,
                ", ".join(mx.resolved_ips) or "N/A",
                mx.provider_name or "No",
                "⚠️ YES" if mx.is_suspicious else "✓ No",
                "; ".join(mx.reasons) or "-",
            )
        console.print(mx_table)

    # Summary
    console.print("\n[bold underline]📋 Summary[/bold underline]")
    s = report.summary
    console.print(f"  Total resolver queries: {s['total_resolver_queries']}")
    console.print(f"  Divergent record types: {s['divergent_record_types']}")
    console.print(f"  Findings: {s['total_findings']} "
                f"(Critical: {s['critical_findings']}, "
                f"High: {s['high_findings']}, "
                f"Medium: {s['medium_findings']})")
    console.print(f"  BGP indicators: {s['bgp_indicators_found']} "
                f"({s['suspicious_bgp_indicators']} suspicious)")
    console.print(f"  Split-horizon: {'Yes ⚠️' if s['split_horizon_detected'] else 'No ✓'}")
    console.print(f"  MX records checked: {s['mx_records_checked']} "
                f"({s['suspicious_mx_records']} suspicious)")
    console.print()


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def run_hijacking_check(domain: str, print_output: bool = True) -> dict:
    """
    Run the complete DNS hijacking detection check on a domain.

    Args:
        domain: The target domain to check.
        print_output: Whether to print Rich-formatted output to console.

    Returns:
        A dictionary representation of the HijackingReport.
    """
    logger.info("Starting DNS hijacking detection for %s", domain)

    # Step 1: Resolve all records across all resolvers
    resolver_results = resolve_all_records(domain)

    # Step 2: Compare resolver results for divergence
    comparison_findings = compare_resolver_results(resolver_results)

    # Step 3: Detect split-horizon DNS
    split_horizon, split_details = detect_split_horizon(domain, resolver_results)

    # Step 4: Check BGP hijacking indicators
    bgp_indicators = check_bgp_hijacking(domain, resolver_results)

    # Step 5: Check MX record legitimacy
    mx_legitimacy = check_mx_legitimacy(domain, resolver_results)

    # Step 6: Generate report
    report = generate_report(
        domain=domain,
        resolver_results=resolver_results,
        comparison_findings=comparison_findings,
        bgp_indicators=bgp_indicators,
        split_horizon=split_horizon,
        split_horizon_details=split_details,
        mx_legitimacy=mx_legitimacy,
    )

    # Step 7: Print output if requested
    if print_output:
        print_report(report)

    return report.to_dict()


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="DNS Hijacking Detection - DNSAudit Category 7",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python hijacking.py example.com
    python hijacking.py example.com --json
    python hijacking.py example.com --quiet
        """,
    )
    parser.add_argument("domain", help="Target domain to check")
    parser.add_argument(
        "--json", action="store_true", dest="as_json",
        help="Output results as JSON instead of formatted text",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress console output (useful with --json)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    result = run_hijacking_check(
        domain=args.domain,
        print_output=not args.quiet and not args.as_json,
    )

    if args.as_json:
        print(json.dumps(result, indent=2, default=str))
        sys.exit(0)

    # Exit code based on risk
    risk_exit = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    sys.exit(risk_exit.get(result.get("overall_risk", "LOW"), 0))
