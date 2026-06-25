#!/usr/bin/env python3
"""
DNSAudit Record Inventory Module (Category 11)
==============================================
Comprehensive DNS record inventory that queries all standard record types
(A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, PTR, NAPTR, TLSA, SSHFP, HINFO),
analyzes SOA records in detail, flags anomalies, and returns structured findings.

Requirements:
    pip install dnspython
"""

import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone

import dns.resolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.rdataclass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

from resolver import (
    DNSResolverEngine,
    DNSResponse,
    DNSAnswer,
    ResponseStatus,
    DEFAULT_COMPARISON_RESOLVERS,
    DEFAULT_TIMEOUT,
    normalize_domain,
)

# All record types specified for Category 11 inventory
ALL_RECORD_TYPES = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA",
    "CAA", "SRV", "PTR", "NAPTR", "TLSA", "SSHFP", "HINFO",
]

# SOA field indices
SOA_PRIMARY_NS = 0
SOA_MAILBOX = 1
SOA_SERIAL = 2
SOA_REFRESH = 3
SOA_RETRY = 4
SOA_EXPIRE = 5
SOA_MINIMUM_TTL = 6

# Anomaly thresholds
SOA_REFRESH_MIN = 300          # 5 minutes - below is suspicious
SOA_REFRESH_MAX = 43200        # 12 hours - above is unusually high
SOA_RETRY_MAX_REFRESH_RATIO = 0.5  # retry should be <= 50% of refresh
SOA_EXPIRE_MIN = 604800        # 1 week - below is suspicious for production
SOA_EXPIRE_MAX = 2419200       # 4 weeks - above is unusually high
SOA_SERIAL_CURRENT_YEAR_BASE = 2024000000  # YYYYMMDDnn format baseline
STALE_SERIAL_DAYS = 30          # Flag if serial hasn't changed in 30 days

# ---------------------------------------------------------------------------
# Data Classes & Enums
# ---------------------------------------------------------------------------

class Severity(Enum):
    """Severity levels for anomalies."""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class RecordFinding:
    """A single finding/record entry for a record type."""
    record_type: str
    rdata: str
    ttl: int
    rrclass: str = "IN"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    anomaly_id: str
    severity: str  # INFO, WARNING, CRITICAL
    category: str  # e.g., "SOA", "GENERAL", "DELEGATION"
    description: str
    record_type: str
    detail: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SOADetail:
    """Detailed SOA record analysis."""
    primary_ns: str
    mailbox: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum_ttl: int
    primary_ns_reachable: Optional[bool] = None
    serial_format_valid: bool = True
    serial_age_days: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RecordInventory:
    """
    Complete DNS record inventory for a domain.
    Contains all records found, per-type analysis, and anomalies.
    """
    domain: str
    query_time: str
    resolver: str
    total_record_types_queried: int = 0
    total_record_types_found: int = 0
    total_records: int = 0
    records: Dict[str, List[RecordFinding]] = field(default_factory=dict)
    soa_detail: Optional[SOADetail] = None
    anomalies: List[Anomaly] = field(default_factory=list)
    query_errors: Dict[str, str] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)

    def add_record(self, rrtype: str, finding: RecordFinding):
        if rrtype not in self.records:
            self.records[rrtype] = []
        self.records[rrtype].append(finding)
        self.total_records += 1

    def add_anomaly(self, anomaly: Anomaly):
        self.anomalies.append(anomaly)

    def add_error(self, rrtype: str, error_msg: str):
        self.query_errors[rrtype] = error_msg

    def build_summary(self):
        """Build a summary of the inventory."""
        self.total_record_types_queried = len(ALL_RECORD_TYPES)
        self.total_record_types_found = len(self.records)

        # Record types found vs missing
        found_types = set(self.records.keys())
        missing_types = set(ALL_RECORD_TYPES) - found_types

        # Categorize findings
        has_a = "A" in found_types or "AAAA" in found_types
        has_cname = "CNAME" in found_types
        has_ns = "NS" in found_types
        has_mx = "MX" in found_types
        has_soa = "SOA" in found_types
        has_txt = "TXT" in found_types
        has_ptr = "PTR" in found_types

        # Determine zone type
        zone_type = "unknown"
        if has_soa:
            zone_type = "authoritative_zone"
        elif has_ns and not has_soa:
            zone_type = "delegated_zone"
        elif has_a or has_cname:
            zone_type = "leaf_zone"
        elif has_ptr:
            zone_type = "reverse_zone"

        # Check for potential issues
        critical_count = sum(1 for a in self.anomalies if a.severity == Severity.CRITICAL.value)
        warning_count = sum(1 for a in self.anomalies if a.severity == Severity.WARNING.value)
        info_count = sum(1 for a in self.anomalies if a.severity == Severity.INFO.value)

        # Check for SPF/DKIM/DMARC presence
        spf_present = False
        dkim_present = False
        dmarc_present = False
        if has_txt:
            for finding in self.records["TXT"]:
                rdata_lower = finding.rdata.lower()
                if "v=spf1" in rdata_lower:
                    spf_present = True
                if "v=dkim1" in rdata_lower or "_domainkey" in rdata_lower:
                    dkim_present = True
                if "v=dmarc1" in rdata_lower or "_dmarc" in rdata_lower:
                    dmarc_present = True

        self.summary = {
            "zone_type": zone_type,
            "record_types_found": sorted(list(found_types)),
            "record_types_missing": sorted(list(missing_types)),
            "has_address_record": has_a,
            "has_cname": has_cname,
            "has_nameservers": has_ns,
            "has_mail_records": has_mx,
            "has_soa": has_soa,
            "has_txt_records": has_txt,
            "has_ptr": has_ptr,
            "spf_present": spf_present,
            "dkim_present": dkim_present,
            "dmarc_present": dmarc_present,
            "anomaly_counts": {
                "critical": critical_count,
                "warning": warning_count,
                "info": info_count,
                "total": len(self.anomalies),
            },
            "record_type_coverage": (
                f"{self.total_record_types_found}/{len(ALL_RECORD_TYPES)}"
            ),
        }

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "domain": self.domain,
            "query_time": self.query_time,
            "resolver": self.resolver,
            "total_record_types_queried": self.total_record_types_queried,
            "total_record_types_found": self.total_record_types_found,
            "total_records": self.total_records,
            "records": {
                k: [r.to_dict() for r in v] for k, v in self.records.items()
            },
            "soa_detail": self.soa_detail.to_dict() if self.soa_detail else None,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "query_errors": self.query_errors,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# SOA Analysis Functions
# ---------------------------------------------------------------------------

def _parse_soa_rdata(rdata_str: str) -> Optional[Dict[str, Any]]:
    """
    Parse an SOA rdata string into its component fields.
    
    SOA format: primary_ns mailbox serial refresh retry expire minimum_ttl
    """
    try:
        parts = rdata_str.split()
        if len(parts) < 7:
            return None

        primary_ns = parts[SOA_PRIMARY_NS].rstrip(".")
        mailbox = parts[SOA_MAILBOX].rstrip(".")

        # Handle mailbox first label escaping (email@domain -> email.domain)
        mailbox_normalized = mailbox.replace("\\.", "@")
        if "@" not in mailbox_normalized:
            # Convert first dot to @ for standard format
            dot_idx = mailbox.find(".")
            if dot_idx > 0:
                mailbox_normalized = mailbox[:dot_idx] + "@" + mailbox[dot_idx + 1:]

        serial = int(parts[SOA_SERIAL])
        refresh = int(parts[SOA_REFRESH])
        retry = int(parts[SOA_RETRY])
        expire = int(parts[SOA_EXPIRE])
        minimum_ttl = int(parts[SOA_MINIMUM_TTL])

        return {
            "primary_ns": primary_ns,
            "mailbox": mailbox_normalized,
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum_ttl": minimum_ttl,
        }
    except (ValueError, IndexError) as e:
        logger.warning("Failed to parse SOA rdata: %s | error: %s", rdata_str, e)
        return None


def _analyze_serial_format(serial: int) -> Tuple[bool, Optional[int]]:
    """
    Analyze SOA serial number format.
    
    Returns:
        Tuple of (is_valid_format, age_in_days)
    """
    serial_str = str(serial)

    # Common format: YYYYMMDDnn (10 digits)
    if len(serial_str) == 10:
        try:
            year = int(serial_str[:4])
            month = int(serial_str[4:6])
            day = int(serial_str[6:8])
            # variant = int(serial_str[8:10])

            # Validate date components
            if 1990 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31:
                # Calculate age
                try:
                    serial_date = datetime(year, month, day)
                    now = datetime.now()
                    age_days = (now - serial_date).days
                    return True, max(0, age_days)
                except ValueError:
                    return False, None
            return False, None
        except ValueError:
            return False, None

    # Alternative: Unix timestamp format (common for automated systems)
    if len(serial_str) <= 10:
        # Could be unix timestamp
        if serial > 1000000000:  # After 2001
            try:
                serial_date = datetime.fromtimestamp(serial)
                age_days = (datetime.now() - serial_date).days
                return True, max(0, age_days)
            except (OSError, ValueError):
                pass

    # If we can't parse it, mark as non-standard but not necessarily wrong
    return False, None


def _check_ns_reachability(primary_ns: str, resolver_engine: DNSResolverEngine) -> Optional[bool]:
    """
    Quick reachability check for the primary NS.
    Returns True if reachable, False if not, None if check failed.
    """
    try:
        resp = resolver_engine.query(primary_ns, "A", use_cache=True)
        if resp.status == ResponseStatus.SUCCESS and resp.answers:
            return True
        return False
    except Exception:
        return None


def analyze_soa(
    soa_answer: RecordFinding,
    resolver_engine: DNSResolverEngine,
    inventory: RecordInventory,
) -> SOADetail:
    """
    Perform detailed analysis of a SOA record.
    
    Checks:
    - Primary NS validity
    - Mailbox format
    - Serial number format and age
    - Refresh value range
    - Retry vs Refresh ratio
    - Expire value range
    - Minimum TTL value
    """
    parsed = _parse_soa_rdata(soa_answer.rdata)
    if not parsed:
        inventory.add_anomaly(Anomaly(
            anomaly_id="SOA_PARSE_ERROR",
            severity=Severity.WARNING.value,
            category="SOA",
            description="SOA record could not be parsed",
            record_type="SOA",
            detail=f"Raw SOA data: {soa_answer.rdata}",
            recommendation="Verify SOA record configuration at the registrar/DNS provider",
        ))
        # Return minimal detail
        return SOADetail(
            primary_ns="unknown",
            mailbox="unknown",
            serial=0,
            refresh=0,
            retry=0,
            expire=0,
            minimum_ttl=0,
            serial_format_valid=False,
        )

    serial_valid, serial_age = _analyze_serial_format(parsed["serial"])

    # Check primary NS reachability
    primary_reachable = _check_ns_reachability(parsed["primary_ns"], resolver_engine)

    detail = SOADetail(
        primary_ns=parsed["primary_ns"],
        mailbox=parsed["mailbox"],
        serial=parsed["serial"],
        refresh=parsed["refresh"],
        retry=parsed["retry"],
        expire=parsed["expire"],
        minimum_ttl=parsed["minimum_ttl"],
        primary_ns_reachable=primary_reachable,
        serial_format_valid=serial_valid,
        serial_age_days=serial_age,
    )

    anomaly_counter = 0
    next_id = lambda: f"SOA_ANOMALY_{anomaly_counter:03d}"

    # --- Primary NS checks ---
    if primary_reachable is False:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.CRITICAL.value,
            category="DELEGATION",
            description=f"Primary nameserver {parsed['primary_ns']} is not reachable",
            record_type="SOA",
            detail=f"The SOA MNAME field points to {parsed['primary_ns']} which failed to respond to A record queries",
            recommendation="Ensure the primary nameserver is properly configured and reachable",
        ))

    # --- Serial analysis ---
    if not serial_valid:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.INFO.value,
            category="SOA",
            description=f"SOA serial number {parsed['serial']} is not in standard YYYYMMDDnn format",
            record_type="SOA",
            detail="Non-standard serial format detected. May be intentional (Unix timestamp) or misconfigured",
            recommendation="Consider using YYYYMMDDnn format for clarity and compatibility",
        ))

    if serial_age is not None and serial_age > STALE_SERIAL_DAYS:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.WARNING.value,
            category="SOA",
            description=f"SOA serial has not been updated in {serial_age} days",
            record_type="SOA",
            detail=f"Stale SOA serial suggests the zone may not be actively managed",
            recommendation="Verify that the zone is being properly maintained and serials are updating",
        ))

    # --- Refresh analysis ---
    if parsed["refresh"] < SOA_REFRESH_MIN:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.WARNING.value,
            category="SOA",
            description=f"SOA refresh value ({parsed['refresh']}s) is very low",
            record_type="SOA",
            detail=f"Refresh interval of {parsed['refresh']}s is below recommended minimum of {SOA_REFRESH_MIN}s (5 min). "
                   f"High refresh rates increase DNS server load",
            recommendation="Consider increasing refresh to at least 3600s (1 hour) for most zones",
        ))
    elif parsed["refresh"] > SOA_REFRESH_MAX:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.WARNING.value,
            category="SOA",
            description=f"SOA refresh value ({parsed['refresh']}s) is unusually high",
            record_type="SOA",
            detail=f"Refresh interval of {parsed['refresh']}s exceeds {SOA_REFRESH_MAX}s (12 hours). "
                   f"Changes will propagate slowly",
            recommendation="Consider reducing refresh to 3600s-14400s for faster propagation",
        ))

    # --- Retry vs Refresh ratio ---
    if parsed["refresh"] > 0:
        retry_ratio = parsed["retry"] / parsed["refresh"]
        if retry_ratio > SOA_RETRY_MAX_REFRESH_RATIO:
            anomaly_counter += 1
            inventory.add_anomaly(Anomaly(
                anomaly_id=next_id(),
                severity=Severity.INFO.value,
                category="SOA",
                description=f"SOA retry value ({parsed['retry']}s) is high relative to refresh ({parsed['refresh']}s)",
                record_type="SOA",
                detail=f"Retry/refresh ratio is {retry_ratio:.2f}, recommended <= {SOA_RETRY_MAX_REFRESH_RATIO}",
                recommendation=f"Retry should typically be <= 50% of refresh value",
            ))

    # --- Expire analysis ---
    if parsed["expire"] < SOA_EXPIRE_MIN:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.WARNING.value,
            category="SOA",
            description=f"SOA expire value ({parsed['expire']}s) is low",
            record_type="SOA",
            detail=f"Expire of {parsed['expire']}s is below recommended minimum of {SOA_EXPIRE_MIN}s (1 week). "
                   f"Secondary nameservers may lose zone data during extended outages",
            recommendation="Consider increasing expire to at least 604800s (1 week)",
        ))
    elif parsed["expire"] > SOA_EXPIRE_MAX:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.INFO.value,
            category="SOA",
            description=f"SOA expire value ({parsed['expire']}s) is very high",
            record_type="SOA",
            detail=f"Expire of {parsed['expire']}s exceeds {SOA_EXPIRE_MAX}s (4 weeks). "
                   f"Stale records will persist longer on secondaries",
            recommendation="Consider setting expire between 604800s-1209600s",
        ))

    # --- Minimum TTL analysis ---
    if parsed["minimum_ttl"] > 86400:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.INFO.value,
            category="SOA",
            description=f"SOA minimum TTL ({parsed['minimum_ttl']}s) is very high",
            record_type="SOA",
            detail=f"Minimum TTL of {parsed['minimum_ttl']}s means negative caching will last a long time. "
                   f"Records missing for this duration will be treated as non-existent",
            recommendation="Consider setting minimum TTL between 300s-3600s for most use cases",
        ))
    elif parsed["minimum_ttl"] < 60:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.WARNING.value,
            category="SOA",
            description=f"SOA minimum TTL ({parsed['minimum_ttl']}s) is very low",
            record_type="SOA",
            detail=f"Very low minimum TTL increases DNS query volume significantly",
            recommendation="Consider increasing minimum TTL to 300s+ to reduce query load",
        ))

    return detail


# ---------------------------------------------------------------------------
# General Record Anomaly Detection
# ---------------------------------------------------------------------------

def _detect_record_anomalies(inventory: RecordInventory):
    """
    Detect anomalies across all record types in the inventory.
    """
    anomaly_counter = 0
    next_id = lambda: f"REC_ANOMALY_{anomaly_counter:03d}"

    # --- Check for A + CNAME conflict ---
    if "A" in inventory.records and "CNAME" in inventory.records:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.CRITICAL.value,
            category="RECORDS",
            description="CNAME record coexists with A/AAAA records",
            record_type="CNAME",
            detail="CNAME cannot coexist with other record types per RFC 1034. "
                   "This may cause unpredictable behavior",
            recommendation="Remove either CNAME or A/AAAA records; use A/AAAA for the apex",
        ))

    # --- Check for missing address records ---
    if "A" not in inventory.records and "AAAA" not in inventory.records and "CNAME" not in inventory.records:
        if "NS" not in inventory.records:  # Only flag if this isn't just a delegation
            anomaly_counter += 1
            inventory.add_anomaly(Anomaly(
                anomaly_id=next_id(),
                severity=Severity.WARNING.value,
                category="RECORDS",
                description="No address records (A/AAAA/CNAME) found",
                record_type="A",
                detail="The domain has no resolvable address records",
                recommendation="Ensure A or AAAA records are configured for the domain",
            ))

    # --- Check for missing NS records ---
    if "NS" not in inventory.records and "SOA" in inventory.records:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.CRITICAL.value,
            category="DELEGATION",
            description="SOA record exists but no NS records found",
            record_type="NS",
            detail="A zone with SOA should have NS records for delegation",
            recommendation="Configure NS records for the zone",
        ))

    # --- Check for very low TTLs on critical records ---
    for rrtype in ["A", "AAAA", "MX", "NS"]:
        if rrtype in inventory.records:
            for finding in inventory.records[rrtype]:
                if finding.ttl == 0:
                    anomaly_counter += 1
                    inventory.add_anomaly(Anomaly(
                        anomaly_id=next_id(),
                        severity=Severity.WARNING.value,
                        category="RECORDS",
                        description=f"{rrtype} record has TTL of 0",
                        record_type=rrtype,
                        detail=f"TTL=0 means the record should not be cached. "
                               f"This causes excessive DNS query load",
                        recommendation="Consider setting a reasonable TTL (300s+) even for dynamic records",
                    ))
                    break  # Only flag once per type

    # --- Check for CNAME at zone apex ---
    if "CNAME" in inventory.records:
        if "NS" in inventory.records or "SOA" in inventory.records:
            anomaly_counter += 1
            inventory.add_anomaly(Anomaly(
                anomaly_id=next_id(),
                severity=Severity.CRITICAL.value,
                category="RECORDS",
                description="CNAME at zone apex with SOA/NS records",
                record_type="CNAME",
                detail="CNAME at zone apex violates RFC 1034 when other records exist",
                recommendation="Use A/AAAA records at the apex instead",
            ))

    # --- Check for email security if MX exists ---
    if "MX" in inventory.records:
        if not inventory.summary.get("spf_present"):
            anomaly_counter += 1
            inventory.add_anomaly(Anomaly(
                anomaly_id=next_id(),
                severity=Severity.WARNING.value,
                category="EMAIL_SECURITY",
                description="MX records present but no SPF record found",
                record_type="TXT",
                detail="Without SPF, domain is vulnerable to email spoofing",
                recommendation="Add an SPF TXT record to authorize sending mail servers",
            ))
        if not inventory.summary.get("dmarc_present"):
            anomaly_counter += 1
            inventory.add_anomaly(Anomaly(
                anomaly_id=next_id(),
                severity=Severity.INFO.value,
                category="EMAIL_SECURITY",
                description="MX records present but no DMARC record found",
                record_type="TXT",
                detail="DMARC provides policy enforcement and reporting for email authentication",
                recommendation="Add a DMARC TXT record (_dmarc.domain.tld)",
            ))

    # --- Check for excessive TXT records (potential abuse) ---
    if "TXT" in inventory.records and len(inventory.records["TXT"]) > 10:
        anomaly_counter += 1
        inventory.add_anomaly(Anomaly(
            anomaly_id=next_id(),
            severity=Severity.INFO.value,
            category="RECORDS",
            description=f"Unusually high number of TXT records ({len(inventory.records['TXT'])})",
            record_type="TXT",
            detail="Many TXT records may indicate SPF record issues or unnecessary complexity",
            recommendation="Review TXT records and consolidate where possible",
        ))

    # --- Check for SRV records pointing to non-existent services ---
    if "SRV" in inventory.records:
        for finding in inventory.records["SRV"]:
            rdata_parts = finding.rdata.split()
            if len(rdata_parts) >= 4:
                target = rdata_parts[3].rstrip(".")
                if target.endswith(".local") or target == "":
                    anomaly_counter += 1
                    inventory.add_anomaly(Anomaly(
                        anomaly_id=next_id(),
                        severity=Severity.WARNING.value,
                        category="RECORDS",
                        description=f"SRV record points to non-routable target: {target}",
                        record_type="SRV",
                        detail=f"Target {target} may not be publicly resolvable",
                        recommendation="Ensure SRT targets are valid, publicly resolvable hosts",
                    ))
                    break

    # --- Check for HINFO leak (information disclosure) ---
    if "HINFO" in inventory.records:
        for finding in inventory.records["HINFO"]:
            anomaly_counter += 1
            inventory.add_anomaly(Anomaly(
                anomaly_id=next_id(),
                severity=Severity.WARNING.value,
                category="INFORMATION_DISCLOSURE",
                description="HINFO record exposes host platform information",
                record_type="HINFO",
                detail=f"HINFO record: {finding.rdata}. This reveals OS/platform details to attackers",
                recommendation="Remove HINFO records unless specifically required. "
                               "They are rarely used legitimately and aid reconnaissance",
            ))

    # --- Check NS targets resolve ---
    if "NS" in inventory.records:
        for finding in inventory.records["NS"]:
            ns_target = finding.rdata.rstrip(".")
            if not ns_target or "." not in ns_target:
                anomaly_counter += 1
                inventory.add_anomaly(Anomaly(
                    anomaly_id=next_id(),
                    severity=Severity.CRITICAL.value,
                    category="DELEGATION",
                    description=f"NS record points to invalid target: {ns_target}",
                    record_type="NS",
                    detail="NS target must be a valid, fully-qualified domain name",
                    recommendation="Fix the NS record to point to a valid nameserver",
                ))
                break


# ---------------------------------------------------------------------------
# Main Inventory Function
# ---------------------------------------------------------------------------

def run_inventory(
    domain: str,
    resolver_ip: Optional[str] = None,
    record_types: Optional[List[str]] = None,
    analyze_soa: bool = True,
    detect_anomalies: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
) -> RecordInventory:
    """
    Run a comprehensive DNS record inventory on the specified domain.
    
    Args:
        domain: Domain name to inventory
        resolver_ip: Optional resolver IP (uses system/default if None)
        record_types: List of record types to query (default: ALL_RECORD_TYPES)
        analyze_soa: Whether to perform detailed SOA analysis
        detect_anomalies: Whether to detect and flag anomalies
        timeout: Query timeout in seconds
    
    Returns:
        RecordInventory with all findings
    """
    rtypes = record_types or ALL_RECORD_TYPES

    logger.info(
        "Starting DNS record inventory for %s | %d record types",
        domain, len(rtypes),
    )

    # Initialize resolver engine
    engine = DNSResolverEngine(
        resolver_ip=resolver_ip,
        timeout=timeout,
        enable_audit_log=True,
    )

    # Initialize inventory
    inventory = RecordInventory(
        domain=domain,
        query_time=datetime.now(timezone.utc).isoformat(),
        resolver=engine.resolver_ip or "default",
    )

    # Query each record type
    for rrtype in rtypes:
        logger.debug("Querying %s records for %s", rrtype, domain)
        try:
            response = engine.query(domain, rrtype)

            if response.status == ResponseStatus.SUCCESS:
                for answer in response.answers:
                    finding = RecordFinding(
                        record_type=rrtype,
                        rdata=answer.rdata,
                        ttl=answer.ttl,
                        rrclass=answer.rrclass,
                    )
                    inventory.add_record(rrtype, finding)

                    logger.info(
                        "  %s %s -> %s (TTL: %d)",
                        domain, rrtype, answer.rdata[:80], answer.ttl,
                    )

                    # Perform SOA analysis when we find the SOA record
                    if rrtype == "SOA" and analyze_soa:
                        # Check for multi-line SOA (dnspython gives one answer with all fields)
                        soa_detail = analyze_soa(finding, engine, inventory)
                        inventory.soa_detail = soa_detail
            else:
                inventory.add_error(rrtype, f"{response.status.value}: {response.error_message}")
                logger.debug("  %s %s -> %s: %s", domain, rrtype, response.status.value, response.error_message)

        except Exception as e:
            inventory.add_error(rrtype, str(e))
            logger.error("  %s %s -> Exception: %s", domain, rrtype, e)

        # Small delay between queries to be polite
        time.sleep(0.1)

    # Build summary first (some anomaly checks depend on it)
    inventory.build_summary()

    # Detect general anomalies
    if detect_anomalies:
        _detect_record_anomalies(inventory)

    # Log summary
    logger.info(
        "Inventory complete for %s | %d/%d types found | %d records | %d anomalies",
        domain,
        inventory.total_record_types_found,
        inventory.total_record_types_queried,
        inventory.total_records,
        len(inventory.anomalies),
    )

    return inventory


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------

def quick_inventory(domain: str, resolver_ip: Optional[str] = None) -> Dict[str, Any]:
    """
    Quick inventory returning just the dictionary output.
    
    Args:
        domain: Domain to inventory
        resolver_ip: Optional resolver IP
    
    Returns:
        Dictionary with all inventory findings
    """
    inventory = run_inventory(domain, resolver_ip=resolver_ip)
    return inventory.to_dict()


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    """Command-line interface for the DNS record inventory."""
    import argparse
    import json as json_mod

    parser = argparse.ArgumentParser(
        description="DNSAudit Record Inventory (Category 11)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --resolver 8.8.8.8
  %(prog)s example.com --types A AAAA MX
  %(prog)s example.com --no-soa-analysis
  %(prog)s example.com --json
        """,
    )
    parser.add_argument("domain", help="Domain to inventory")
    parser.add_argument(
        "--resolver", "-r", default=None,
        help="DNS resolver IP (default: system)",
    )
    parser.add_argument(
        "--types", "-t", nargs="+", default=None,
        help="Record types to query (default: all 14 types)",
    )
    parser.add_argument(
        "--no-soa-analysis", action="store_true",
        help="Skip detailed SOA analysis",
    )
    parser.add_argument(
        "--no-anomaly-detection", action="store_true",
        help="Skip anomaly detection",
    )
    parser.add_argument(
        "--json", "-j", action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Query timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Setup logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Run inventory
    inventory = run_inventory(
        domain=args.domain,
        resolver_ip=args.resolver,
        record_types=args.types,
        analyze_soa=not args.no_soa_analysis,
        detect_anomalies=not args.no_anomaly_detection,
        timeout=args.timeout,
    )

    # Output
    if args.json:
        print(json_mod.dumps(inventory.to_dict(), indent=2))
    else:
        print(f"\n{'='*70}")
        print(f"  DNS Record Inventory: {inventory.domain}")
        print(f"{'='*70}")
        print(f"  Query Time: {inventory.query_time}")
        print(f"  Resolver:   {inventory.resolver}")
        print(f"  Coverage:   {inventory.summary.get('record_type_coverage', '?')}")
        print(f"  Zone Type:  {inventory.summary.get('zone_type', '?')}")
        print(f"{'─'*70}")

        # Records by type
        if inventory.records:
            print(f"\n  Records Found:")
            for rrtype in sorted(inventory.records.keys()):
                records = inventory.records[rrtype]
                print(f"\n    {rrtype} ({len(records)} records):")
                for rec in records:
                    rdata_display = rec.rdata[:60] + "..." if len(rec.rdata) > 60 else rec.rdata
                    print(f"      {rdata_display} (TTL: {rec.ttl})")

        # SOA Detail
        if inventory.soa_detail:
            soa = inventory.soa_detail
            print(f"\n  SOA Analysis:")
            print(f"    Primary NS:     {soa.primary_ns}")
            print(f"    Admin Mailbox:  {soa.mailbox}")
            print(f"    Serial:         {soa.serial}")
            print(f"    Refresh:        {soa.refresh}s ({soa.refresh/3600:.1f}h)")
            print(f"    Retry:          {soa.retry}s")
            print(f"    Expire:         {soa.expire}s ({soa.expire/86400:.1f} days)")
            print(f"    Minimum TTL:    {soa.minimum_ttl}s")
            if soa.serial_age_days is not None:
                print(f"    Serial Age:     {soa.serial_age_days} days")
            if soa.primary_ns_reachable is not None:
                r = "YES" if soa.primary_ns_reachable else "NO"
                print(f"    NS Reachable:   {r}")

        # Anomalies
        if inventory.anomalies:
            print(f"\n  Anomalies ({len(inventory.anomalies)}):")
            for anomaly in inventory.anomalies:
                severity_icon = {
                    Severity.CRITICAL.value: "🔴",
                    Severity.WARNING.value: "🟡",
                    Severity.INFO.value: "🔵",
                }.get(anomaly.severity, "⚪")
                print(f"    {severity_icon} [{anomaly.severity}] {anomaly.description}")
                if anomaly.detail:
                    print(f"       Detail: {anomaly.detail[:80]}")
                if anomaly.recommendation:
                    print(f"       Recommendation: {anomaly.recommendation[:80]}")

        # Query errors
        if inventory.query_errors:
            print(f"\n  Query Errors ({len(inventory.query_errors)}):")
            for rrtype, err in inventory.query_errors.items():
                print(f"    {rrtype}: {err[:60]}")

        # Email security summary
        if inventory.summary.get("has_mail_records"):
            print(f"\n  Email Security:")
            print(f"    SPF:   {'✓' if inventory.summary.get('spf_present') else '✗'}")
            print(f"    DKIM:  {'✓' if inventory.summary.get('dkim_present') else '✗ (or static)'}")
            print(f"    DMARC: {'✓' if inventory.summary.get('dmarc_present') else '✗'}")

        print(f"\n{'='*70}\n")


if __name__ == "__main__":
    main()
