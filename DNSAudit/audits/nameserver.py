#!/usr/bin/env python3
"""
DNSAudit Nameserver Analysis Module (Category 9)
================================================
Comprehensive nameserver audit including:
  - NS record count validation (1=CRITICAL, 2=MINIMUM, 3+=GOOD)
  - NS on different IP ranges (diversity check)
  - Lame delegation detection (CRITICAL)
  - NS records consistency across resolvers
  - Glue records validation
  - NS software fingerprinting (BIND version disclosure = MEDIUM)

Requirements:
    pip install dnspython
"""

import logging
import re
import socket
import struct
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone

import dns.resolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.message
import dns.query
import dns.flags

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 5.0
MAX_RETRIES = 3
COMPARISON_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# BIND version disclosure patterns
BIND_VERSION_PATTERNS = [
    re.compile(r"BIND\s+(\d+\.\d+\.\d+[\w.-]*)", re.IGNORECASE),
    re.compile(r"named\s+(\d+\.\d+\.\d+[\w.-]*)", re.IGNORECASE),
    re.compile(r"dnsmasq\s+(\d+\.\d+[\w.-]*)", re.IGNORECASE),
    re.compile(r"PowerDNS\s+(\d+\.\d+[\w.-]*)", re.IGNORECASE),
    re.compile(r"Unbound\s+(\d+\.\d+[\w.-]*)", re.IGNORECASE),
    re.compile(r"Knot\s+DNS\s+(\d+\.\d+[\w.-]*)", re.IGNORECASE),
    re.compile(r"NSD\s+(\d+\.\d+[\w.-]*)", re.IGNORECASE),
]

# Well-known port for version query
DNS_PORT = 53

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("dnsaudit.audits.nameserver")
logger.setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# Enums & Data Classes
# ---------------------------------------------------------------------------

class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    GOOD = "GOOD"


@dataclass
class Finding:
    """Represents a single audit finding."""
    check: str
    severity: Severity
    title: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class NSServer:
    """Represents a single nameserver with resolved details."""
    hostname: str
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    software_version: str = ""
    software_type: str = ""
    is_lame: bool = False
    has_glue: bool = False
    glue_addresses: List[str] = field(default_factory=list)
    query_time_ms: float = 0.0
    query_status: str = "SUCCESS"
    error_message: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NameserverAuditResult:
    """Complete result of the nameserver audit."""
    domain: str
    checked_at: str = ""
    findings: List[Finding] = field(default_factory=list)
    ns_servers: List[NSServer] = field(default_factory=list)
    ns_record_count: int = 0
    ip_range_diversity: Dict[str, Any] = field(default_factory=dict)
    lame_delegations: List[str] = field(default_factory=list)
    consistency_issues: List[str] = field(default_factory=list)
    glue_records_valid: bool = True
    software_fingerprints: List[Dict[str, str]] = field(default_factory=list)
    overall_score: int = 0  # 0-100

    def __post_init__(self):
        if not self.checked_at:
            self.checked_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "checked_at": self.checked_at,
            "findings": [f.to_dict() for f in self.findings],
            "ns_servers": [ns.to_dict() for ns in self.ns_servers],
            "ns_record_count": self.ns_record_count,
            "ip_range_diversity": self.ip_range_diversity,
            "lame_delegations": self.lame_delegations,
            "consistency_issues": self.consistency_issues,
            "glue_records_valid": self.glue_records_valid,
            "software_fingerprints": self.software_fingerprints,
            "overall_score": self.overall_score,
        }

    def add_finding(self, check: str, severity: Severity, title: str,
                    description: str, details: Optional[Dict] = None):
        self.findings.append(Finding(
            check=check,
            severity=severity,
            title=title,
            description=description,
            details=details or {},
        ))


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _ip_to_network(ip: str, prefix_len: int = 24) -> Optional[str]:
    """Convert an IP address to its /24 network prefix."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        # For /24, take first 3 octets
        if prefix_len == 24:
            return ".".join(parts[:3]) + ".0/24"
        # For /16, take first 2 octets
        elif prefix_len == 16:
            return ".".join(parts[:2]) + ".0.0/16"
        else:
            packed = socket.inet_aton(ip)
            addr = struct.unpack("!I", packed)[0]
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
            network = addr & mask
            return socket.inet_ntoa(struct.pack("!I", network)) + f"/{prefix_len}"
    except (OSError, ValueError):
        return None


def _get_soa_mname(domain: str, resolver_ip: str = "8.8.8.8") -> str:
    """Get the SOA MNAME (primary nameserver) for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [resolver_ip]
        resolver.timeout = DEFAULT_TIMEOUT
        resolver.lifetime = DEFAULT_TIMEOUT * 2
        answer = resolver.resolve(domain, "SOA")
        if answer:
            return str(answer[0].mname).rstrip(".")
    except Exception as e:
        logger.debug("SOA MNAME query failed for %s: %s", domain, e)
    return ""


def _query_ns_from_resolver(domain: str, resolver_ip: str) -> List[str]:
    """Query NS records from a specific resolver."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [resolver_ip]
        resolver.timeout = DEFAULT_TIMEOUT
        resolver.lifetime = DEFAULT_TIMEOUT * 2
        answer = resolver.resolve(domain, "NS")
        return [str(rdata).rstrip(".") for rdata in answer]
    except Exception as e:
        logger.debug("NS query to %s for %s failed: %s", resolver_ip, domain, e)
        return []


def _resolve_hostname_to_ips(hostname: str, resolver_ip: str = "8.8.8.8") -> Tuple[List[str], List[str]]:
    """Resolve a hostname to its A and AAAA records."""
    ipv4 = []
    ipv6 = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [resolver_ip]
    resolver.timeout = DEFAULT_TIMEOUT
    resolver.lifetime = DEFAULT_TIMEOUT * 2

    # A records
    try:
        answer = resolver.resolve(hostname, "A")
        ipv4 = [str(rdata) for rdata in answer]
    except Exception:
        pass

    # AAAA records
    try:
        answer = resolver.resolve(hostname, "AAAA")
        ipv6 = [str(rdata) for rdata in answer]
    except Exception:
        pass

    return ipv4, ipv6


def _check_lame_delegation(domain: str, ns_hostname: str, resolver_ip: str = "8.8.8.8") -> bool:
    """
    Check if a nameserver is a lame delegation.
    A lame server is listed in the parent zone's NS records but is NOT
    authoritative for the domain (does not respond with AA flag or returns
    NXDOMAIN/REFUSED/SERVFAIL).
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [resolver_ip]
        resolver.timeout = DEFAULT_TIMEOUT
        resolver.lifetime = DEFAULT_TIMEOUT * 2

        # Resolve the NS hostname to IP
        try:
            answer = resolver.resolve(ns_hostname, "A")
            ns_ip = str(answer[0])
        except Exception:
            # Can't resolve NS hostname - definitely lame
            return True

        # Query the domain's NS records directly from this nameserver
        direct_resolver = dns.resolver.Resolver()
        direct_resolver.nameservers = [ns_ip]
        direct_resolver.timeout = DEFAULT_TIMEOUT
        direct_resolver.lifetime = DEFAULT_TIMEOUT * 2

        try:
            answer = direct_resolver.resolve(domain, "NS")
            # Check if the response has the Authoritative Answer flag
            if answer.response.flags & dns.flags.AA:
                return False  # Server is authoritative
            else:
                return True  # Responded but without AA flag - lame
        except dns.resolver.NXDOMAIN:
            return True  # Server says domain doesn't exist - lame
        except dns.resolver.NoAnswer:
            return True  # No NS records returned - lame
        except dns.resolver.NoNameservers:
            return True  # Can't reach - treat as lame
        except dns.exception.Timeout:
            return True  # Timeout - treat as lame
        except Exception:
            return True

    except Exception as e:
        logger.debug("Lame check failed for %s: %s", ns_hostname, e)
        return True


def _check_glue_records(domain: str, ns_hostnames: List[str],
                        resolver_ip: str = "8.8.8.8") -> Dict[str, List[str]]:
    """
    Check for glue records in the parent zone.
    Glue records are A/AAAA records for NS hostnames that are in-bailiwick
    (subordinate to the zone being delegated).

    Returns dict mapping NS hostname -> list of glue addresses found.
    """
    glue_found = {}
    domain_parts = domain.rstrip(".").lower().split(".")

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [resolver_ip]
    resolver.timeout = DEFAULT_TIMEOUT
    resolver.lifetime = DEFAULT_TIMEOUT * 2

    for ns_hostname in ns_hostnames:
        ns_parts = ns_hostname.rstrip(".").lower().split(".")
        # Check if NS hostname is in-bailiwick (is or is a subdomain of the domain)
        is_in_bailiwick = False
        if len(ns_parts) > len(domain_parts):
            if ".".join(ns_parts[-len(domain_parts):]) == ".".join(domain_parts):
                is_in_bailiwick = True

        if is_in_bailiwick:
            # Try to get glue from parent zone (additional section)
            glue_addrs = []
            try:
                # Query parent zone for A records of the NS hostname
                answer = resolver.resolve(ns_hostname, "A")
                glue_addrs = [str(rdata) for rdata in answer]
            except Exception:
                pass

            try:
                answer = resolver.resolve(ns_hostname, "AAAA")
                glue_addrs.extend([str(rdata) for rdata in answer])
            except Exception:
                pass

            glue_found[ns_hostname] = glue_addrs

    return glue_found


def _fingerprint_ns_software(ns_ip: str) -> Tuple[str, str]:
    """
    Attempt to fingerprint the DNS software running on a nameserver.
    Uses the CHAOS TXT version.bind query.

    Returns (software_type, version_string)
    """
    try:
        # Send a CHAOS TXT query for version.bind
        query = dns.message.make_query("version.bind", dns.rdatatype.TXT, dns.rdataclass.CH)
        query.flags = 0  # Standard query

        response = dns.query.udp(query, ns_ip, timeout=DEFAULT_TIMEOUT, port=DNS_PORT)

        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.TXT:
                for rdata in rrset:
                    version_str = rdata.to_text().strip('"')
                    for pattern in BIND_VERSION_PATTERNS:
                        match = pattern.search(version_str)
                        if match:
                            version = match.group(1)
                            # Determine software type
                            version_lower = version_str.lower()
                            if "bind" in version_lower:
                                return ("BIND", version)
                            elif "dnsmasq" in version_lower:
                                return ("dnsmasq", version)
                            elif "powerdns" in version_lower or "pdns" in version_lower:
                                return ("PowerDNS", version)
                            elif "unbound" in version_lower:
                                return ("Unbound", version)
                            elif "knot" in version_lower:
                                return ("Knot DNS", version)
                            elif "nsd" in version_lower:
                                return ("NSD", version)
                            else:
                                return ("Unknown", version_str)
                    return ("Unknown", version_str)

    except dns.query.BadResponse:
        pass
    except dns.exception.Timeout:
        pass
    except ConnectionRefusedError:
        pass
    except OSError:
        pass
    except Exception as e:
        logger.debug("Software fingerprinting failed for %s: %s", ns_ip, e)

    return ("", "")


def _check_version_disclosure_udp(ns_ip: str) -> Tuple[str, str]:
    """
    Alternative method: try to get version via UDP to the NS directly.
    """
    try:
        query = dns.message.make_query("version.server", dns.rdatatype.TXT, dns.rdataclass.CH)
        response = dns.query.udp(query, ns_ip, timeout=DEFAULT_TIMEOUT, port=DNS_PORT)

        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.TXT:
                for rdata in rrset:
                    version_str = rdata.to_text().strip('"')
                    for pattern in BIND_VERSION_PATTERNS:
                        match = pattern.search(version_str)
                        if match:
                            version = match.group(1)
                            version_lower = version_str.lower()
                            if "bind" in version_lower:
                                return ("BIND", version)
                            elif "dnsmasq" in version_lower:
                                return ("dnsmasq", version)
                            else:
                                return ("Unknown", version)
                    return ("Unknown", version_str)
    except Exception:
        pass

    return ("", "")


# ---------------------------------------------------------------------------
# Main Audit Class
# ---------------------------------------------------------------------------

class NameserverAuditor:
    """
    Performs comprehensive nameserver audit for a domain.
    """

    def __init__(
        self,
        domain: str,
        resolvers: Optional[List[str]] = None,
        timeout: float = DEFAULT_TIMEOUT,
        check_lame: bool = True,
        check_glue: bool = True,
        check_fingerprint: bool = True,
    ):
        self.domain = domain.rstrip(".").lower()
        self.resolvers = resolvers or COMPARISON_RESOLVERS
        self.timeout = timeout
        self.check_lame = check_lame
        self.check_glue = check_glue
        self.check_fingerprint = check_fingerprint
        self._result = NameserverAuditResult(domain=domain)

    def run(self) -> NameserverAuditResult:
        """Execute the full nameserver audit and return structured results."""
        logger.info("Starting nameserver audit for %s", self.domain)

        # Step 1: Get NS records from multiple resolvers for consistency check
        ns_per_resolver = self._collect_ns_from_resolvers()

        # Step 2: Determine the canonical set of NS records
        canonical_ns = self._determine_canonical_ns(ns_per_resolver)
        self._result.ns_record_count = len(canonical_ns)

        # Step 3: NS record count check
        self._check_ns_count()

        # Step 4: NS consistency across resolvers
        self._check_ns_consistency(ns_per_resolver)

        # Step 5: Resolve each NS hostname and collect details
        self._resolve_ns_details(canonical_ns)

        # Step 6: IP range diversity check
        self._check_ip_diversity()

        # Step 7: Lame delegation check
        if self.check_lame:
            self._check_lame_delegations()

        # Step 8: Glue records check
        if self.check_glue:
            self._check_glue_records(canonical_ns)

        # Step 9: Software fingerprinting
        if self.check_fingerprint:
            self._fingerprint_software()

        # Step 10: Calculate overall score
        self._calculate_score()

        logger.info("Nameserver audit complete for %s: score=%d, findings=%d",
                     self.domain, self._result.overall_score, len(self._result.findings))

        return self._result

    def _collect_ns_from_resolvers(self) -> Dict[str, List[str]]:
        """Query NS records from each comparison resolver."""
        ns_per_resolver = {}
        for resolver_ip in self.resolvers:
            ns_list = _query_ns_from_resolver(self.domain, resolver_ip)
            ns_per_resolver[resolver_ip] = ns_list
            logger.debug("Resolver %s returned NS: %s", resolver_ip, ns_list)
        return ns_per_resolver

    def _determine_canonical_ns(self, ns_per_resolver: Dict[str, List[str]]) -> List[str]:
        """
        Determine the canonical set of NS records.
        Uses the union of all resolver responses, preferring the most common set.
        """
        if not ns_per_resolver:
            return []

        # Count occurrences of each NS set
        from collections import Counter
        set_counts = Counter()
        for ns_list in ns_per_resolver.values():
            key = tuple(sorted(ns_list))
            set_counts[key] += 1

        # Use the most common set as canonical
        if set_counts:
            canonical = list(set_counts.most_common(1)[0][0])
        else:
            # Fallback: union of all
            canonical = list(set(ns for ns_list in ns_per_resolver.values() for ns in ns_list))

        return sorted(set(canonical))

    def _check_ns_count(self):
        """Check NS record count against best practices."""
        count = self._result.ns_record_count

        if count == 0:
            self._result.add_finding(
                check="ns_count",
                severity=Severity.CRITICAL,
                title="No NS Records Found",
                description="The domain has no NS records, meaning it cannot be resolved by DNS clients.",
                details={"count": count},
            )
        elif count == 1:
            self._result.add_finding(
                check="ns_count",
                severity=Severity.CRITICAL,
                title="Single Nameserver (Single Point of Failure)",
                description="Only 1 NS record exists. This is a critical single point of failure. "
                            "RFC 1034 recommends at least 2 name servers for redundancy.",
                details={"count": count, "ns": [ns.hostname for ns in self._result.ns_servers]},
            )
        elif count == 2:
            self._result.add_finding(
                check="ns_count",
                severity=Severity.MEDIUM,
                title="Minimum Nameserver Count",
                description="Only 2 NS records exist. This meets the minimum requirement but provides "
                            "limited redundancy. Best practice is 3+ servers across different networks.",
                details={"count": count, "ns": [ns.hostname for ns in self._result.ns_servers]},
            )
        elif count <= 6:
            self._result.add_finding(
                check="ns_count",
                severity=Severity.GOOD,
                title="Adequate Nameserver Count",
                description=f"{count} NS records found. This provides good redundancy.",
                details={"count": count, "ns": [ns.hostname for ns in self._result.ns_servers]},
            )
        else:
            self._result.add_finding(
                check="ns_count",
                severity=Severity.INFO,
                title="High Number of Nameservers",
                description=f"{count} NS records found. While redundant, this may indicate unnecessary complexity.",
                details={"count": count, "ns": [ns.hostname for ns in self._result.ns_servers]},
            )

    def _check_ns_consistency(self, ns_per_resolver: Dict[str, List[str]]):
        """Check if NS records are consistent across resolvers."""
        if len(ns_per_resolver) < 2:
            return

        all_ns_sets = []
        for resolver_ip, ns_list in ns_per_resolver.items():
            all_ns_sets.append((resolver_ip, set(ns_list)))

        # Check if all resolvers return the same set
        reference = all_ns_sets[0][1]
        inconsistent = []

        for resolver_ip, ns_set in all_ns_sets[1:]:
            if ns_set != reference:
                missing = reference - ns_set
                extra = ns_set - reference
                issue_parts = []
                if missing:
                    issue_parts.append(f"missing: {sorted(missing)}")
                if extra:
                    issue_parts.append(f"extra: {sorted(extra)}")
                inconsistent.append(f"Resolver {resolver_ip}: {'; '.join(issue_parts)}")

        if inconsistent:
            self._result.consistency_issues = inconsistent
            self._result.add_finding(
                check="ns_consistency",
                severity=Severity.HIGH,
                title="NS Records Inconsistent Across Resolvers",
                description="Different resolvers return different NS record sets. This may indicate "
                            "DNS propagation issues, misconfiguration, or an ongoing attack.",
                details={"inconsistencies": inconsistent},
            )
        else:
            self._result.add_finding(
                check="ns_consistency",
                severity=Severity.GOOD,
                title="NS Records Consistent",
                description="All comparison resolvers return the same NS record set.",
                details={},
            )

    def _resolve_ns_details(self, canonical_ns: List[str]):
        """Resolve each NS hostname to IP addresses and check properties."""
        for ns_hostname in canonical_ns:
            ns_server = NSServer(hostname=ns_hostname)

            # Resolve A and AAAA records
            ipv4, ipv6 = _resolve_hostname_to_ips(ns_hostname)
            ns_server.ipv4_addresses = ipv4
            ns_server.ipv6_addresses = ipv6

            if not ipv4 and not ipv6:
                ns_server.query_status = "FAILED"
                ns_server.error_message = "Could not resolve NS hostname to any IP address"
                logger.warning("NS hostname %s could not be resolved", ns_hostname)

            self._result.ns_servers.append(ns_server)

    def _check_ip_diversity(self):
        """Check if NS servers are on different IP ranges (BGP diversity)."""
        all_ipv4 = []
        for ns in self._result.ns_servers:
            all_ipv4.extend(ns.ipv4_addresses)

        if len(all_ipv4) < 2:
            self._result.ip_range_diversity = {
                "diverse": False,
                "reason": "Insufficient IPv4 addresses to check diversity",
                "networks": [],
            }
            self._result.add_finding(
                check="ip_diversity",
                severity=Severity.HIGH,
                title="Cannot Verify IP Diversity",
                description="Not enough NS servers have resolvable IPv4 addresses to verify network diversity.",
                details={"ipv4_count": len(all_ipv4)},
            )
            return

        # Check /24 diversity
        networks_24 = set()
        networks_16 = set()
        for ip in all_ipv4:
            net24 = _ip_to_network(ip, 24)
            net16 = _ip_to_network(ip, 16)
            if net24:
                networks_24.add(net24)
            if net16:
                networks_16.add(net16)

        # Ideal: each NS on a different /24
        is_diverse_24 = len(networks_24) == len(all_ipv4)
        # Minimum: NS on different /16 networks
        is_diverse_16 = len(networks_16) >= 2

        self._result.ip_range_diversity = {
            "d diverse": is_diverse_24,
            "partial_diversity": is_diverse_16,
            "networks_24": sorted(networks_24),
            "networks_16": sorted(networks_16),
            "total_ips": len(all_ipv4),
            "unique_24": len(networks_24),
            "unique_16": len(networks_16),
        }

        if is_diverse_24:
            self._result.add_finding(
                check="ip_diversity",
                severity=Severity.GOOD,
                title="Good IP Network Diversity",
                description=f"All {len(all_ipv4)} NS servers are on different /24 networks.",
                details=self._result.ip_range_diversity,
            )
        elif is_diverse_16:
            self._result.add_finding(
                check="ip_diversity",
                severity=Severity.MEDIUM,
                title="Partial IP Network Diversity",
                description=f"NS servers are on different /16 networks but share some /24 ranges. "
                            f"Consider distributing across entirely different networks.",
                details=self._result.ip_range_diversity,
            )
        else:
            self._result.add_finding(
                check="ip_diversity",
                severity=Severity.HIGH,
                title="Poor IP Network Diversity",
                description="Multiple NS servers are on the same /16 network. This creates a single "
                            "point of failure at the network level.",
                details=self._result.ip_range_diversity,
            )

    def _check_lame_delegations(self):
        """Check for lame delegations."""
        lame_servers = []

        for ns in self._result.ns_servers:
            if ns.query_status == "FAILED":
                ns.is_lame = True
                lame_servers.append(ns.hostname)
                continue

            # Check each IPv4 address
            for ns_ip in ns.ipv4_addresses:
                if _check_lame_delegation(self.domain, ns.hostname, ns_ip):
                    ns.is_lame = True
                    lame_servers.append(ns.hostname)
                    break

        self._result.lame_delegations = lame_servers

        if lame_servers:
            self._result.add_finding(
                check="lame_delegation",
                severity=Severity.CRITICAL,
                title="Lame Delegation Detected",
                description=f"The following nameservers are listed as NS but are not authoritative "
                            f"for the domain: {lame_servers}. This causes resolution failures and "
                            f"increases DNS latency.",
                details={"lame_servers": lame_servers},
            )
        else:
            self._result.add_finding(
                check="lame_delegation",
                severity=Severity.GOOD,
                title="No Lame Delegations",
                description="All nameservers are authoritative for the domain.",
                details={},
            )

    def _check_glue_records(self, canonical_ns: List[str]):
        """Validate glue records for in-bailiwick nameservers."""
        glue_results = _check_glue_records(self.domain, canonical_ns)

        if not glue_results:
            # No in-bailiwick NS, nothing to check
            self._result.add_finding(
                check="glue_records",
                severity=Severity.GOOD,
                title="No In-Bailiwick NS (Glue Not Required)",
                description="No nameservers are in-bailiwick, so glue records are not required.",
                details={},
            )
            return

        missing_glue = []
        for ns_hostname, glue_addrs in glue_results.items():
            if not glue_addrs:
                missing_glue.append(ns_hostname)
            else:
                # Mark the NS server as having glue
                for ns in self._result.ns_servers:
                    if ns.hostname == ns_hostname:
                        ns.has_glue = True
                        ns.glue_addresses = glue_addrs

        if missing_glue:
            self._result.glue_records_valid = False
            self._result.add_finding(
                check="glue_records",
                severity=Severity.HIGH,
                title="Missing Glue Records",
                description=f"The following in-bailiwick nameservers are missing glue records "
                            f"in the parent zone: {missing_glue}. This can cause resolution failures "
                            f"for clients performing iterative resolution.",
                details={"missing_glue": missing_glue, "glue_found": glue_results},
            )
        else:
            self._result.add_finding(
                check="glue_records",
                severity=Severity.GOOD,
                title="Glue Records Present",
                description="All in-bailiwick nameservers have glue records in the parent zone.",
                details={"glue_records": glue_results},
            )

    def _fingerprint_software(self):
        """Fingerprint nameserver software via version.bind CHAOS queries."""
        fingerprints = []

        for ns in self._result.ns_servers:
            if ns.query_status == "FAILED":
                continue

            for ns_ip in ns.ipv4_addresses:
                # Try version.bind first
                sw_type, version = _fingerprint_software(ns_ip)
                if not sw_type:
                    # Try alternative
                    sw_type, version = _check_version_disclosure_udp(ns_ip)

                if sw_type:
                    ns.software_type = sw_type
                    ns.software_version = version
                    fingerprints.append({
                        "ns_hostname": ns.hostname,
                        "ns_ip": ns_ip,
                        "software": sw_type,
                        "version": version,
                    })
                    break  # Found for this NS, move to next

        self._result.software_fingerprints = fingerprints

        if fingerprints:
            # Check for BIND version disclosure specifically
            bind_disclosed = [f for f in fingerprints if f["software"] == "BIND"]
            other_disclosed = [f for f in fingerprints if f["software"] != "BIND"]

            if bind_disclosed:
                self._result.add_finding(
                    check="software_fingerprinting",
                    severity=Severity.MEDIUM,
                    title="BIND Version Disclosed",
                    description=f"One or more nameservers disclose their BIND version. "
                                f"This aids attackers in identifying known vulnerabilities. "
                                f"Consider hiding version information.",
                    details={"bind_servers": bind_disclosed, "all_fingerprints": fingerprints},
                )
            elif other_disclosed:
                self._result.add_finding(
                    check="software_fingerprinting",
                    severity=Severity.LOW,
                    title="DNS Software Version Disclosed",
                    description=f"One or more nameservers disclose their DNS software version. "
                                f"Consider hiding version information.",
                    details={"fingerprints": fingerprints},
                )
            else:
                self._result.add_finding(
                    check="software_fingerprinting",
                    severity=Severity.GOOD,
                    title="No Software Version Disclosed",
                    description="No nameservers disclose their software version.",
                    details={},
                )
        else:
            self._result.add_finding(
                check="software_fingerprinting",
                severity=Severity.GOOD,
                title="Software Fingerprinting Inconclusive",
                description="Could not determine software versions. This is generally positive "
                            "as it indicates version hiding is enabled.",
                details={},
            )

    def _calculate_score(self):
        """Calculate an overall score (0-100) based on findings."""
        score = 100

        for finding in self._result.findings:
            severity = finding.severity
            if severity == Severity.CRITICAL:
                score -= 30
            elif severity == Severity.HIGH:
                score -= 15
            elif severity == Severity.MEDIUM:
                score -= 8
            elif severity == Severity.LOW:
                score -= 3
            # GOOD and INFO don't reduce score

        self._result.overall_score = max(0, min(100, score))


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------

def audit_nameservers(
    domain: str,
    resolvers: Optional[List[str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    check_lame: bool = True,
    check_glue: bool = True,
    check_fingerprint: bool = True,
) -> NameserverAuditResult:
    """
    Run a comprehensive nameserver audit for a domain.

    Args:
        domain: Domain name to audit
        resolvers: List of resolver IPs for consistency comparison
        timeout: Query timeout in seconds
        check_lame: Whether to check for lame delegations
        check_glue: Whether to check glue records
        check_fingerprint: Whether to fingerprint NS software

    Returns:
        NameserverAuditResult with all findings
    """
    auditor = NameserverAuditor(
        domain=domain,
        resolvers=resolvers,
        timeout=timeout,
        check_lame=check_lame,
        check_glue=check_glue,
        check_fingerprint=check_fingerprint,
    )
    return auditor.run()


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    """Command-line interface for the nameserver audit."""
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="DNSAudit Nameserver Analysis Module (Category 9)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --no-lame-check
  %(prog)s example.com --resolvers 8.8.8.8 1.1.1.1
  %(prog)s example.com --json
        """,
    )
    parser.add_argument("domain", help="Domain to audit")
    parser.add_argument(
        "--resolvers", nargs="+", default=None,
        help="Resolver IPs for consistency comparison (default: 8.8.8.8 1.1.1.1 9.9.9.9)",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Query timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument("--no-lame-check", action="store_true", help="Skip lame delegation check")
    parser.add_argument("--no-glue-check", action="store_true", help="Skip glue records check")
    parser.add_argument("--no-fingerprint", action="store_true", help="Skip software fingerprinting")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Setup logging
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    fmt = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    result = audit_nameservers(
        domain=args.domain,
        resolvers=args.resolvers,
        timeout=args.timeout,
        check_lame=not args.no_lame_check,
        check_glue=not args.no_glue_check,
        check_fingerprint=not args.no_fingerprint,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"\n{'='*70}")
        print(f"  NAMESERVER AUDIT: {result.domain}")
        print(f"  Score: {result.overall_score}/100")
        print(f"{'='*70}")

        # NS Servers
        print(f"\n  Nameservers ({result.ns_record_count}):")
        for ns in result.ns_servers:
            status = "✗ LAME" if ns.is_lame else "✓"
            ips = ", ".join(ns.ipv4_addresses[:2]) if ns.ipv4_addresses else "UNRESOLVED"
            version_str = f" [{ns.software_type} {ns.software_version}]" if ns.software_type else ""
            glue_str = f" (glue: {', '.join(ns.glue_addresses)})" if ns.has_glue else ""
            print(f"    {status} {ns.hostname} -> {ips}{version_str}{glue_str}")

        # IP Diversity
        div = result.ip_range_diversity
        if div:
            div_status = "✓ Diverse" if div.get("diverse") else ("~ Partial" if div.get("partial_diversity") else "✗ Concentrated")
            print(f"\n  IP Diversity: {div_status}")
            print(f"    /24 networks: {div.get('unique_24', '?')} | /16 networks: {div.get('unique_16', '?')}")

        # Lame delegations
        if result.lame_delegations:
            print(f"\n  ⚠ Lame Delegations: {', '.join(result.lame_delegations)}")

        # Consistency
        if result.consistency_issues:
            print(f"\n  ⚠ Consistency Issues:")
            for issue in result.consistency_issues:
                print(f"    • {issue}")

        # Findings
        print(f"\n{'─'*70}")
        print(f"  FINDINGS ({len(result.findings)}):")
        for finding in result.findings:
            icon = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵",
                Severity.INFO: "ℹ️",
                Severity.GOOD: "🟢",
            }.get(finding.severity, "•")
            print(f"    {icon} [{finding.severity.value}] {finding.title}")
            print(f"       {finding.description[:100]}")

        print(f"\n{'='*70}\n")


if __name__ == "__main__":
    main()
