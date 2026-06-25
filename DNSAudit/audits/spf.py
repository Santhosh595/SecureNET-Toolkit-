"""
SPF Audit Module - Category 1 of DNSAudit Tool
================================================
Audits Sender Policy Framework (SPF) records for security best practices,
syntax correctness, DNS lookup efficiency, and common misconfigurations.

Uses dnspython for DNS TXT record resolution.
"""

import re
import dns.resolver
import dns.exception
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


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
    """A single structured finding from the SPF audit."""
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
class ParsedMechanism:
    """Represents a single parsed SPF mechanism."""
    mechanism: str       # e.g. "include", "a", "mx", "ip4", "ptr", etc.
    qualifier: str       # "+", "-", "~", "?"  (default "+")
    value: str           # the value after the qualifier
    dns_lookup: bool      # whether this mechanism triggers a DNS lookup
    raw: str             # original raw token from the SPF record

    def to_dict(self) -> dict:
        return {
            "mechanism": self.mechanism,
            "qualifier": self.qualifier,
            "value": self.value,
            "dns_lookup": self.dns_lookup,
            "raw": self.raw,
        }


@dataclass
class SPFAuditResult:
    """Complete result of an SPF audit for a domain."""
    domain: str
    spf_record: Optional[str]
    findings: list = field(default_factory=list)
    mechanisms: list = field(default_factory=list)
    dns_lookup_count: int = 0
    issues_found: int = 0
    recommended_spf: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "spf_record": self.spf_record,
            "findings": [f.to_dict() for f in self.findings],
            "mechanisms": [m.to_dict() for m in self.mechanisms],
            "dns_lookup_count": self.dns_lookup_count,
            "issues_found": self.issues_found,
            "recommended_spf": self.recommended_spf,
        }


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Mechanisms that trigger a DNS lookup per RFC 7208 §4.6.4
DNS_LOOKUP_MECHANISMS = {"include", "a", "mx", "exists", "redirect"}

# Qualifier severity mapping for the `all` mechanism
ALL_QUALIFIER_SEVERITY = {
    "+": Severity.CRITICAL,   # +all — allow anyone (effectively no SPF)
    "?": Severity.HIGH,       # ?all — neutral (no fail policy)
    "~": Severity.MEDIUM,     # ~all — softfail (weak fail policy)
    "-": Severity.GOOD,       # -all — hard fail (strong policy)
}

# Broad netmask thresholds
BROAD_NETMASK_IPV4_HIGH = 8    # /8 or larger for ip4 → HIGH
BROAD_NETMASK_IPV4_MED = 24    # /24 → MEDIUM
BROAD_NETMASK_IPV6_HIGH = 16   # /16 or larger for ip6 → HIGH
BROAD_NETMASK_IPV6_MED = 48    # /48 → MEDIUM (common assignment boundary)

MAX_DNS_LOOKUPS = 10           # RFC 7208 §4.6.4
MAX_INCLUDE_DEPTH = 5          # recommended chain depth limit


# ---------------------------------------------------------------------------
# SPF Parsing & Validation Helpers
# ---------------------------------------------------------------------------

def query_txt_records(domain: str) -> list[str]:
    """Query DNS TXT records for a domain. Returns list of record strings."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        raise RuntimeError(f"DNS query failed for {domain}: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Unexpected DNS error for {domain}: {e}") from e

    records = []
    for rdata in answers:
        # rdata.strings is a list of bytes chunks; join and decode
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        records.append(txt)
    return records


def find_spf_record(txt_records: list[str]) -> list[str]:
    """Filter TXT records to those that are SPF records (start with v=spf1)."""
    return [r for r in txt_records if r.strip().startswith("v=spf1")]


def parse_mechanisms(spf_record: str) -> list[ParsedMechanism]:
    """
    Parse an SPF record string into a list of ParsedMechanism objects.
    Handles qualifiers, mechanisms, and the special 'all' mechanism.
    """
    tokens = spf_record.split()
    mechanisms = []

    for token in tokens:
        # Skip the version tag
        if token.lower() == "v=spf1":
            continue

        # Determine qualifier
        qualifier = "+"
        body = token
        if token and token[0] in "+-~?":
            qualifier = token[0]
            body = token[1:]

        # Normalize
        body_lower = body.lower()

        # Identify mechanism name
        if body_lower == "all":
            mech = "all"
            value = ""
        elif body_lower.startswith("include:"):
            mech = "include"
            value = body[8:]
        elif body_lower.startswith("a") and (len(body) == 1 or body[1] in ":"):
            mech = "a"
            value = body[2:] if len(body) > 1 and body[1] == ":" else ""
        elif body_lower.startswith("mx") and (len(body) == 2 or body[2] in ":"):
            mech = "mx"
            value = body[3:] if len(body) > 2 and body[2] == ":" else ""
        elif body_lower.startswith("ptr") and (len(body) == 3 or body[3] in ":"):
            mech = "ptr"
            value = body[4:] if len(body) > 3 and body[3] == ":" else ""
        elif body_lower.startswith("ip4:"):
            mech = "ip4"
            value = body[4:]
        elif body_lower.startswith("ip6:"):
            mech = "ip6"
            value = body[4:]
        elif body_lower.startswith("exists:"):
            mech = "exists"
            value = body[7:]
        elif body_lower.startswith("redirect="):
            mech = "redirect"
            value = body[9:]
        elif body_lower.startswith("exp="):
            mech = "exp"
            value = body[4:]
        else:
            # Unknown modifier or mechanism — treat as raw
            mech = "unknown"
            value = body

        dns_lookup = mech in DNS_LOOKUP_MECHANISMS
        mechanisms.append(ParsedMechanism(
            mechanism=mech,
            qualifier=qualifier,
            value=value,
            dns_lookup=dns_lookup,
            raw=token,
        ))

    return mechanisms


def count_dns_lookups(mechanisms: list[ParsedMechanism]) -> int:
    """Count total DNS lookups triggered by the SPF record."""
    return sum(1 for m in mechanisms if m.dns_lookup)


def check_ip_range_scope(mechanism: ParsedMechanism) -> Optional[Finding]:
    """Check if an ip4/ip6 range is too broad."""
    if mechanism.mechanism == "ip4":
        # value format: ip/prefix
        match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$", mechanism.value)
        if match:
            prefix = int(match.group(2)) if match.group(2) else 32
            if prefix <= BROAD_NETMASK_IPV4_HIGH:
                return Finding(
                    severity=Severity.HIGH,
                    title="Overly broad ip4 range",
                    description=(
                        f"ip4:{mechanism.value} allows a /{prefix} network "
                        f"({2 ** (32 - prefix):,} IP addresses). This is extremely permissive."
                    ),
                    recommendation=(
                        "Restrict ip4 ranges to the minimum required. "
                        "Use /24 or smaller for most use cases."
                    ),
                )
            elif prefix <= BROAD_NETMASK_IPV4_MED:
                return Finding(
                    severity=Severity.MEDIUM,
                    title="Broad ip4 range",
                    description=(
                        f"ip4:{mechanism.value} allows a /{prefix} network "
                        f"({2 ** (32 - prefix):,} IP addresses)."
                    ),
                    recommendation=(
                        "Consider narrowing the ip4 range to reduce exposure."
                    ),
                )

    elif mechanism.mechanism == "ip6":
        match = re.match(r"^([0-9a-fA-F:]+)(?:/(\d{1,3}))?$", mechanism.value)
        if match:
            prefix = int(match.group(2)) if match.group(2) else 128
            if prefix <= BROAD_NETMASK_IPV6_HIGH:
                return Finding(
                    severity=Severity.HIGH,
                    title="Overly broad ip6 range",
                    description=(
                        f"ip6:{mechanism.value} allows a /{prefix} network. "
                        f"This is extremely permissive for IPv6."
                    ),
                    recommendation=(
                        "Restrict ip6 ranges to the minimum required. "
                        "Use /48 or smaller for most use cases."
                    ),
                )
            elif prefix <= BROAD_NETMASK_IPV6_MED:
                return Finding(
                    severity=Severity.MEDIUM,
                    title="Broad ip6 range",
                    description=(
                        f"ip6:{mechanism.value} allows a /{prefix} network."
                    ),
                    recommendation=(
                        "Consider narrowing the ip6 range to reduce exposure."
                    ),
                )

    return None


def check_deprecated_mechanisms(mechanisms: list[ParsedMechanism]) -> list[Finding]:
    """Check for deprecated mechanisms (ptr)."""
    findings = []
    for m in mechanisms:
        if m.mechanism == "ptr":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Deprecated mechanism: ptr",
                description=(
                    "The 'ptr' mechanism is deprecated per RFC 7208 §5.5. "
                    "It is slow, unreliable, and may not be evaluated by all receivers."
                ),
                recommendation=(
                    "Remove the ptr mechanism and use ip4/ip6 or include: mechanisms instead."
                ),
            ))
    return findings


def check_all_mechanism(mechanisms: list[ParsedMechanism]) -> Optional[Finding]:
    """Check the qualifier on the 'all' mechanism."""
    for m in mechanisms:
        if m.mechanism == "all":
            severity = ALL_QUALIFIER_SEVERITY.get(m.qualifier, Severity.INFO)
            descriptions = {
                "+": "SPF record ends with '+all', allowing ANY server to send mail on behalf of this domain. This effectively nullifies SPF protection.",
                "?": "SPF record ends with '?all' (neutral), providing no fail policy. Spoofed emails may pass SPF checks.",
                "~": "SPF record ends with '~all' (softfail). Spoofed emails may still be accepted by some receivers.",
                "-": "SPF record ends with '-all' (hard fail). This is the recommended strict policy.",
            }
            recommendations = {
                "+": "Replace '+all' with '-all' to enforce a hard fail policy for unauthorized senders.",
                "?": "Replace '?all' with '-all' or '~all' to provide meaningful SPF enforcement.",
                "~": "Consider upgrading '~all' to '-all' for stronger protection.",
                "-": "No action needed. '-all' is the recommended SPF policy.",
            }
            desc = descriptions.get(m.qualifier, f"Unknown qualifier '{m.qualifier}' on all mechanism.")
            rec = recommendations.get(m.qualifier, "Review the all mechanism qualifier.")
            return Finding(
                severity=severity,
                title=f"SPF 'all' mechanism qualifier: {m.qualifier}all",
                description=desc,
                recommendation=rec,
            )
    return None


def check_syntax_issues(spf_record: str, mechanisms: list[ParsedMechanism]) -> list[Finding]:
    """Check for common SPF syntax issues."""
    findings = []

    # Check for spaces inside mechanisms (common error)
    if re.search(r"\s", spf_record.replace("v=spf1", "").strip()):
        # Multiple tokens are normal, but check for malformed tokens
        pass

    # Check for unknown modifiers
    for m in mechanisms:
        if m.mechanism == "unknown":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Unknown SPF mechanism/modifier",
                description=f"Token '{m.raw}' contains an unrecognized mechanism or modifier.",
                recommendation=(
                    "Review the SPF record syntax per RFC 7208. "
                    "Valid mechanisms: all, include, a, mx, ptr, ip4, ip6, exists. "
                    "Valid modifiers: redirect, exp."
                ),
            ))

    # Check for 'all' not at the end
    all_indices = [i for i, m in enumerate(mechanisms) if m.mechanism == "all"]
    if all_indices and all_indices[-1] != len(mechanisms) - 1:
        findings.append(Finding(
            severity=Severity.LOW,
            title="'all' mechanism not at end of record",
            description=(
                "The 'all' mechanism appears before other mechanisms. "
                "Per RFC 7208, 'all' should be the last mechanism as it is the default policy."
            ),
            recommendation="Move the 'all' mechanism to the end of the SPF record.",
        ))

    # Check for empty record
    if not mechanisms:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Empty SPF record",
            description="The SPF record contains no mechanisms.",
            recommendation=(
                "Add SPF mechanisms to define authorized senders. "
                "Example: v=spf1 include:_spf.google.com -all"
            ),
        ))

    # Check for trailing without all
    if mechanisms and all(not m.mechanism == "all" for m in mechanisms):
        findings.append(Finding(
            severity=Severity.HIGH,
            title="Missing 'all' mechanism",
            description=(
                "The SPF record does not contain an 'all' mechanism. "
                "Without it, there is no default policy for non-matching senders."
            ),
            recommendation=(
                "Add '-all' at the end of the SPF record to define a default fail policy."
            ),
        ))

    return findings


def check_redirect_loops(mechanisms: list[ParsedMechanism], domain: str, depth: int = 0, visited: set = None) -> list[Finding]:
    """
    Detect redirect= loops by following redirect chains.
    Also checks include: chain depth.
    """
    if visited is None:
        visited = set()
    findings = []

    for m in mechanisms:
        if m.mechanism == "redirect":
            target = m.value.lower().rstrip(".")
            if target in visited:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="SPF redirect loop detected",
                    description=(
                        f"The redirect to '{m.value}' forms a circular reference. "
                        f"Visited: {visited} -> {target}"
                    ),
                    recommendation=(
                        "Remove the circular redirect reference. "
                        "Ensure redirect= targets point to records that do not redirect back."
                    ),
                ))
            else:
                new_visited = visited | {target}
                # Attempt to resolve the redirect target
                try:
                    target_txts = query_txt_records(target)
                    target_spf = find_spf_record(target_txts)
                    if target_spf:
                        target_mechs = parse_mechanisms(target_spf[0])
                        findings.extend(
                            check_redirect_loops(target_mechs, target, depth + 1, new_visited)
                        )
                except RuntimeError:
                    pass  # DNS resolution failed; skip loop check for this target

        elif m.mechanism == "include" and m.value:
            # Check include chain depth
            if depth + 1 > MAX_INCLUDE_DEPTH:
                findings.append(Finding(
                    severity=Severity.WARNING,
                    title="SPF include chain too deep",
                    description=(
                        f"Include chain depth ({depth + 1}) exceeds recommended "
                        f"maximum of {MAX_INCLUDE_DEPTH}. This may cause SPF evaluation failures."
                    ),
                    recommendation=(
                        "Flatten the include chain. Consolidate SPF records to reduce nesting depth."
                    ),
                ))

    return findings


def generate_recommended_spf(mechanisms: list[ParsedMechanism], domain: str) -> str:
    """
    Generate a recommended SPF record based on the current mechanisms,
    applying best practices.
    """
    parts = ["v=spf1"]

    # Collect non-all mechanisms, replacing +all with -all
    has_all = False
    all_qualifier = "-"

    for m in mechanisms:
        if m.mechanism == "all":
            has_all = True
            # Recommend -all regardless of current qualifier
            continue
        # Skip deprecated ptr mechanisms
        if m.mechanism == "ptr":
            continue
        # Keep the mechanism as-is
        parts.append(m.raw)

    if not has_all:
        pass  # We'll add -all below

    # Add -all at the end
    parts.append("-all")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Main Audit Function
# ---------------------------------------------------------------------------

def audit_spf(domain: str, spf_record: Optional[str] = None) -> SPFAuditResult:
    """
    Perform a complete SPF audit for the given domain.

    Args:
        domain: The domain to audit (e.g., "example.com").
        spf_record: Optional pre-fetched SPF record string. If None,
                    the function will query DNS.

    Returns:
        SPFAuditResult with all findings, mechanisms, and recommendations.
    """
    result = SPFAuditResult(domain=domain, spf_record=None)

    # -----------------------------------------------------------------------
    # Step 1: Query TXT records and find SPF record(s)
    # -----------------------------------------------------------------------
    if spf_record is None:
        try:
            txt_records = query_txt_records(domain)
        except RuntimeError as e:
            result.findings.append(Finding(
                severity=Severity.CRITICAL,
                title="DNS query failed",
                description=str(e),
                recommendation=(
                    "Verify the domain exists and DNS is reachable. "
                    "Check for typos in the domain name."
                ),
            ))
            result.issues_found = len(result.findings)
            result.recommended_spf = "v=spf1 -all"
            return result
    else:
        txt_records = [spf_record]

    spf_records = find_spf_record(txt_records)

    # -----------------------------------------------------------------------
    # Step 2: Check SPF record existence
    # -----------------------------------------------------------------------
    if not spf_records:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title="SPF record missing",
            description=(
                f"No SPF TXT record found on {domain}. "
                "The domain is vulnerable to email spoofing."
            ),
            recommendation=(
                "Publish an SPF TXT record for this domain. "
                "Example: v=spf1 include:_spf.google.com -all"
            ),
        ))
        result.issues_found = len(result.findings)
        result.recommended_spf = "v=spf1 -all"
        return result

    # -----------------------------------------------------------------------
    # Step 3: Check for multiple SPF records
    # -----------------------------------------------------------------------
    if len(spf_records) > 1:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Multiple SPF records",
            description=(
                f"Found {len(spf_records)} SPF records on {domain}. "
                "Multiple SPF records cause permerror and undefined behavior."
            ),
            recommendation=(
                "Merge all SPF mechanisms into a single TXT record starting with 'v=spf1'. "
                "Having multiple SPF records is a syntax error per RFC 7208."
            ),
        ))
        # Use the first one for further analysis
        spf_record = spf_records[0]
    else:
        spf_record = spf_records[0]

    result.spf_record = spf_record

    # -----------------------------------------------------------------------
    # Step 4: Parse mechanisms
    # -----------------------------------------------------------------------
    mechanisms = parse_mechanisms(spf_record)
    result.mechanisms = mechanisms

    # -----------------------------------------------------------------------
    # Step 5: Syntax validation
    # -----------------------------------------------------------------------
    syntax_findings = check_syntax_issues(spf_record, mechanisms)
    result.findings.extend(syntax_findings)

    # -----------------------------------------------------------------------
    # Step 6: Check 'all' mechanism
    # -----------------------------------------------------------------------
    all_finding = check_all_mechanism(mechanisms)
    if all_finding:
        result.findings.append(all_finding)

    # -----------------------------------------------------------------------
    # Step 7: Count DNS lookups
    # -----------------------------------------------------------------------
    lookup_count = count_dns_lookups(mechanisms)
    result.dns_lookup_count = lookup_count

    if lookup_count > MAX_DNS_LOOKUPS:
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="SPF DNS lookup limit exceeded",
            description=(
                f"The SPF record triggers {lookup_count} DNS lookups, "
                f"exceeding the RFC 7208 limit of {MAX_DNS_LOOKUPS}. "
                "This causes permerror and SPF evaluation failures."
            ),
            recommendation=(
                f"Reduce DNS lookups to {MAX_DNS_LOOKUPS} or fewer. "
                "Flatten include: chains, remove unnecessary mechanisms, "
                "and consider using SPF flattening services."
            ),
        ))

    # -----------------------------------------------------------------------
    # Step 8: Check deprecated mechanisms
    # -----------------------------------------------------------------------
    deprecated_findings = check_deprecated_mechanisms(mechanisms)
    result.findings.extend(deprecated_findings)

    # -----------------------------------------------------------------------
    # Step 9: Check ip4/ip6 range scope
    # -----------------------------------------------------------------------
    for m in mechanisms:
        range_finding = check_ip_range_scope(m)
        if range_finding:
            result.findings.append(range_finding)

    # -----------------------------------------------------------------------
    # Step 10: Check redirect loops and include depth
    # -----------------------------------------------------------------------
    loop_findings = check_redirect_loops(mechanisms, domain)
    result.findings.extend(loop_findings)

    # -----------------------------------------------------------------------
    # Step 11: Generate recommended SPF
    # -----------------------------------------------------------------------
    result.recommended_spf = generate_recommended_spf(mechanisms, domain)

    # -----------------------------------------------------------------------
    # Final: Count issues (excluding GOOD findings)
    # -----------------------------------------------------------------------
    result.issues_found = sum(
        1 for f in result.findings if f.severity != Severity.GOOD
    )

    return result


# ---------------------------------------------------------------------------
# Pretty-Print / CLI Output
# ---------------------------------------------------------------------------

def format_audit_report(result: SPFAuditResult) -> str:
    """Format the SPF audit result as a human-readable report."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"  SPF AUDIT REPORT: {result.domain}")
    lines.append("=" * 70)

    # SPF Record
    lines.append(f"\nSPF Record: {result.spf_record or 'NOT FOUND'}")
    lines.append(f"DNS Lookups: {result.dns_lookup_count}")
    lines.append(f"Issues Found: {result.issues_found}")

    # Mechanisms Table
    lines.append("\n" + "-" * 70)
    lines.append("PARSED MECHANISMS")
    lines.append("-" * 70)
    lines.append(f"{'#':<4} {'Qualifier':<10} {'Mechanism':<12} {'Value':<30} {'DNS Lookup'}")
    lines.append("-" * 70)
    for i, m in enumerate(result.mechanisms, 1):
        lines.append(
            f"{i:<4} {m.qualifier:<10} {m.mechanism:<12} "
            f"{m.value:<30} {'Yes' if m.dns_lookup else 'No'}"
        )

    # Findings
    lines.append("\n" + "-" * 70)
    lines.append("FINDINGS")
    lines.append("-" * 70)
    for f in result.findings:
        lines.append(f"\n[{f.severity.value}] {f.title}")
        lines.append(f"  Description: {f.description}")
        lines.append(f"  Recommendation: {f.recommendation}")

    # Recommended SPF
    lines.append("\n" + "-" * 70)
    lines.append("RECOMMENDED SPF RECORD")
    lines.append("-" * 70)
    lines.append(result.recommended_spf or "N/A")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python spf.py <domain> [--json]")
        print("Example: python spf.py example.com")
        print("         python spf.py example.com --json")
        sys.exit(1)

    target_domain = sys.argv[1]
    output_json = "--json" in sys.argv

    audit_result = audit_spf(target_domain)

    if output_json:
        print(json.dumps(audit_result.to_dict(), indent=2))
    else:
        print(format_audit_report(audit_result))
