"""
DKIM Audit Module - Category 2 of DNSAudit Tool

Audits DKIM (DomainKeys Identified Mail) records by querying TXT records
on common DKIM selectors and analyzing the DKIM key configuration.
"""

import dns.resolver
import re
import base64
from dataclasses import dataclass, field
from typing import Optional



@dataclass
class DKIMFinding:
    """Structured finding for a single DKIM selector."""
    selector: str
    domain: str
    record_found: bool
    record_valid: bool
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    key_size_rating: Optional[str] = None
    key_empty: Optional[bool] = None  # p= tag is empty (CRITICAL)
    hash_algorithm: Optional[str] = None
    hash_algorithm_rating: Optional[str] = None
    testing_flag: Optional[bool] = None  # t=y
    service_type_restriction: Optional[str] = None
    p_value: Optional[str] = None
    issues: list = field(default_factory=list)
    severity: str = "INFO"  # CRITICAL, HIGH, WARNING, GOOD, EXCELLENT


@dataclass
class DKIMAuditResult:
    """Complete DKIM audit result for a domain."""
    domain: str
    findings: list = field(default_factory=list)
    selectors_found: int = 0
    selectors_queried: int = 0
    has_critical_issues: bool = False


# Common DKIM selectors used by major email providers and default configurations
COMMON_DKIM_SELECTORS = [
    "default",
    "google",
    "mail",
    "email",
    "smtp",
    "dkim",
    "selector1",
    "selector2",
    "k1",
    "key1",
    "s1",
    "s2",
    "mandrill",
    "mailchimp",
    "sendgrid",
    "amazonses",
    "protonmail",
    "zoho",
    "outlook",
    "office365",
]

DKIM_TAGS = {
    "v": "Version",
    "k": "Key type",
    "p": "Public key (base64 encoded)",
    "h": "Hash algorithm",
    "t": "Flags",
    "s": "Service type",
    "n": "Notes",
    "g": "Granularity",
    "d": "Domain (for verification)",
    "i": "Agent/User Identifier",
    "l": "Body length limit",
    "q": "Query method",
    "x": "Expire time",
    "r": "Responsible Domain",
}


def parse_dkim_record(txt_record: str) -> dict:
    """
    Parse a DKIM TXT record into its component tags.
    
    DKIM records are formatted as tag=value pairs separated by semicolons:
    v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ...
    
    Args:
        txt_record: The raw TXT record string
        
    Returns:
        Dictionary of parsed DKIM tags
    """
    tags = {}
    if not txt_record:
        return tags

    # Remove surrounding quotes and whitespace
    txt_record = txt_record.strip().strip('"').strip("'")

    # Split by semicolons and parse key=value pairs
    parts = txt_record.split(";")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, value = part.partition("=")
            key = key.strip().lower()
            value = value.strip()
            tags[key] = value

    return tags


def get_rsa_key_size(public_key_b64: str) -> int:
    """
    Determine the RSA key size in bits from a base64-encoded DER public key.
    
    Attempts to parse the DER structure of an RSA public key to extract
    the modulus and determine key length.
    
    Args:
        public_key_b64: Base64-encoded public key (from p= tag)
        
    Returns:
        Key size in bits, or 0 if unable to determine
    """
    if not public_key_b64:
        return 0

    try:
        # Decode base64
        key_data = base64.b64decode(public_key_b64)

        # Try to use cryptography library if available
        try:
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            from cryptography.hazmat.backends import default_backend
            public_key = load_der_public_key(key_data, default_backend())
            return public_key.key_size
        except ImportError:
            pass

        # Fallback: manual DER parsing for RSA public keys
        # RSA public key DER structure:
        # SEQUENCE {
        #   SEQUENCE { OID INTEGER }  -- for PKCS#1
        #   BIT STRING { INTEGER }    -- for SubjectPublicKeyInfo
        # }
        idx = 0

        # Skip outer SEQUENCE tag and length
        if key_data[0] == 0x30:
            idx = 1
            # Parse length
            length_byte = key_data[idx]
            idx += 1
            if length_byte & 0x80:
                num_length_bytes = length_byte & 0x7F
                idx += num_length_bytes

        # Check for PKCS#1 format (starts with SEQUENCE containing OID)
        if key_data[idx] == 0x30:
            # Skip the algorithm identifier SEQUENCE
            idx += 1
            length_byte = key_data[idx]
            idx += 1
            if length_byte & 0x80:
                num_length_bytes = length_byte & 0x7F
                idx += num_length_bytes
            idx += length_byte if length_byte < 0x80 else 0

        # Now should be at BIT STRING containing the RSA modulus
        if key_data[idx] == 0x03:
            idx += 1
            # Parse BIT STRING length
            length_byte = key_data[idx]
            idx += 1
            if length_byte & 0x80:
                num_length_bytes = length_byte & 0x7F
                idx += num_length_bytes
            # Skip unused bits byte
            idx += 1

        # Now at the INTEGER containing the modulus
        if key_data[idx] == 0x02:
            idx += 1
            # Parse INTEGER length
            length_byte = key_data[idx]
            idx += 1
            if length_byte & 0x80:
                num_length_bytes = length_byte & 0x7F
                modulus_length = int.from_bytes(
                    key_data[idx:idx + num_length_bytes], 'big'
                )
                idx += num_length_bytes
            else:
                modulus_length = length_byte

            # Key size is the modulus length in bits
            if idx + modulus_length <= len(key_data):
                modulus = key_data[idx:idx + modulus_length]
                # Remove leading zero if present (for positive integers)
                if modulus[0] == 0x00:
                    modulus = modulus[1:]
                return len(modulus) * 8

    except Exception:
        pass

    # Last resort: estimate from base64 string length
    # Base64 length * 3/4 gives approximate byte count
    byte_estimate = len(public_key_b64) * 3 // 4
    if byte_estimate >= 512:
        return 4096
    elif byte_estimate >= 256:
        return 2048
    elif byte_estimate >= 192:
        return 1536
    elif byte_estimate >= 128:
        return 1024
    return 512


def check_key_size(key_size: int) -> tuple:
    """
    Evaluate RSA key size and return rating.
    
    Args:
        key_size: Key size in bits
        
    Returns:
        Tuple of (rating_string, severity_string)
    """
    if key_size == 0:
        return ("UNKNOWN", "WARNING")
    elif key_size < 1024:
        return ("CRITICAL", "CRITICAL")
    elif key_size == 1024:
        return ("HIGH", "HIGH")
    elif key_size == 2048:
        return ("GOOD", "GOOD")
    elif key_size >= 4096:
        return ("EXCELLENT", "EXCELLENT")
    else:
        # Between 1024 and 2048 (e.g., 1536)
        return ("HIGH", "HIGH")


def check_hash_algorithm(h_tag: str) -> tuple:
    """
    Evaluate the hash algorithm specified in the h= tag.
    
    Args:
        h_tag: Value of the h= tag
        
    Returns:
        Tuple of (algorithm_name, rating_string)
    """
    if not h_tag:
        return ("unspecified", "WARNING")

    algorithms = [a.strip().lower() for a in h_tag.split(":")]

    if "sha256" in algorithms:
        return ("sha256", "GOOD")
    elif "sha1" in algorithms:
        return ("sha1", "HIGH")
    elif "sha512" in algorithms:
        return ("sha512", "GOOD")
    elif "sha384" in algorithms:
        return ("sha384", "GOOD")
    else:
        return (algorithms[0] if algorithms else "unknown", "WARNING")


def check_testing_flag(t_tag: str) -> tuple:
    """
    Evaluate the t= (flags) tag.
    
    Args:
        t_tag: Value of the t= tag
        
    Returns:
        Tuple of (is_testing, flag_description, severity)
    """
    if not t_tag:
        return (False, "none", "INFO")

    flags = t_tag.lower().split(":")

    if "y" in flags:
        return (True, "y (testing mode)", "WARNING")
    elif "s" in flags:
        return (False, "s (strict subdomain matching)", "INFO")
    else:
        return (False, ",".join(flags), "INFO")


def audit_dkim_selector(domain: str, selector: str, resolver: dns.resolver.Resolver = None) -> DKIMFinding:
    """
    Audit a single DKIM selector for a domain.
    
    Args:
        domain: The domain to audit
        selector: The DKIM selector name
        resolver: Optional DNS resolver instance
        
    Returns:
        DKIMFinding with structured results
    """
    if resolver is None:
        resolver = dns.resolver.get_default_resolver()

    dkim_domain = f"{selector}._domainkey.{domain}"
    finding = DKIMFinding(
        selector=selector,
        domain=domain,
        record_found=False,
        record_valid=False,
    )

    try:
        answers = resolver.resolve(dkim_domain, "TXT")
        finding.record_found = True

        # Process the first TXT record (should be the DKIM record)
        for rdata in answers:
            txt_record = rdata.to_text()
            # Remove surrounding quotes
            txt_record = txt_record.strip('"').strip("'")

            # Check if this looks like a DKIM record
            if not txt_record.startswith("v=DKIM1") and "DKIM" not in txt_record.upper():
                finding.issues.append(f"Record found but does not appear to be a valid DKIM record: {txt_record[:50]}...")
                finding.severity = "WARNING"
                continue

            finding.record_valid = True
            tags = parse_dkim_record(txt_record)

            # Check key type (k=)
            key_type = tags.get("k", "").lower()
            if key_type:
                finding.key_type = key_type
                if key_type != "rsa":
                    finding.issues.append(f"Non-RSA key type: {key_type}")
                    finding.severity = "WARNING"
            else:
                finding.issues.append("No key type (k=) specified, defaulting to rsa")
                finding.key_type = "rsa (assumed)"

            # Check public key (p=)
            p_value = tags.get("p", "")
            finding.p_value = p_value

            if not p_value:
                finding.key_empty = True
                finding.issues.append("CRITICAL: Public key (p=) is empty - mail receivers will reject DKIM")
                finding.severity = "CRITICAL"
            else:
                finding.key_empty = False
                key_size = get_rsa_key_size(p_value)
                finding.key_size = key_size
                key_rating, key_severity = check_key_size(key_size)
                finding.key_size_rating = key_rating

                if key_severity == "CRITICAL":
                    finding.issues.append(f"CRITICAL: RSA key size {key_size} bits is too weak (< 1024)")
                    finding.severity = "CRITICAL"
                elif key_severity == "HIGH":
                    finding.issues.append(f"HIGH: RSA key size {key_size} bits is weak (recommend 2048+)")
                    if finding.severity not in ("CRITICAL",):
                        finding.severity = "HIGH"
                elif key_severity == "GOOD":
                    finding.issues.append(f"GOOD: RSA key size {key_size} bits")
                    if finding.severity not in ("CRITICAL", "HIGH"):
                        finding.severity = "GOOD"
                elif key_severity == "EXCELLENT":
                    finding.issues.append(f"EXCELLENT: RSA key size {key_size} bits")
                    if finding.severity not in ("CRITICAL", "HIGH", "GOOD"):
                        finding.severity = "EXCELLENT"

            # Check hash algorithm (h=)
            h_value = tags.get("h", "")
            if h_value:
                algo_name, algo_rating = check_hash_algorithm(h_value)
                finding.hash_algorithm = algo_name
                finding.hash_algorithm_rating = algo_rating
                if algo_rating == "HIGH":
                    finding.issues.append(f"HIGH: Hash algorithm '{algo_name}' is deprecated, use sha256")
                    if finding.severity not in ("CRITICAL",):
                        finding.severity = "HIGH"
                elif algo_rating == "GOOD":
                    finding.issues.append(f"GOOD: Hash algorithm '{algo_name}'")
            else:
                finding.issues.append("No hash algorithm (h=) specified, defaulting to sha256")
                finding.hash_algorithm = "sha256 (assumed)"
                finding.hash_algorithm_rating = "GOOD"

            # Check flags (t=)
            t_value = tags.get("t", "")
            is_testing, flag_desc, flag_severity = check_testing_flag(t_value)
            finding.testing_flag = is_testing
            if is_testing:
                finding.issues.append(f"WARNING: DKIM testing mode active (t=y) - signatures will not be enforced")
                if finding.severity not in ("CRITICAL", "HIGH"):
                    finding.severity = "WARNING"

            # Check service type restriction (s=)
            s_value = tags.get("s", "")
            if s_value:
                finding.service_type_restriction = s_value
                services = [svc.strip() for svc in s_value.split(":")]
                finding.issues.append(f"INFO: Service type restriction: {', '.join(services)}")

            # Check version
            version = tags.get("v", "")
            if version and version != "DKIM1":
                finding.issues.append(f"WARNING: Unexpected DKIM version: {version}")

            break  # Only process the first valid TXT record

    except dns.resolver.NXDOMAIN:
        finding.issues.append(f"No DKIM record found for selector '{selector}' ({dkim_domain})")
    except dns.resolver.NoAnswer:
        finding.issues.append(f"No TXT record at {dkim_domain}")
    except dns.resolver.NoNameservers:
        finding.issues.append("No nameservers available for DNS query")
    except dns.exception.Timeout:
        finding.issues.append(f"DNS query timed out for {dkim_domain}")
    except Exception as e:
        finding.issues.append(f"Error querying DKIM: {str(e)}")

    return finding


def audit_dkim(
    domain: str,
    selectors: list = None,
    timeout: float = 5.0,
    nameservers: list = None,
) -> DKIMAuditResult:
    """
    Perform a complete DKIM audit for a domain.
    
    Queries TXT records on common DKIM selectors and analyzes the DKIM
    key configuration for each found selector.
    
    Args:
        domain: The domain to audit (e.g., "example.com")
        selectors: Optional list of selectors to check (defaults to COMMON_DKIM_SELECTORS)
        timeout: DNS query timeout in seconds
        nameservers: Optional list of nameservers to use
        
    Returns:
        DKIMAuditResult with structured findings for all selectors
    """
    if selectors is None:
        selectors = COMMON_DKIM_SELECTORS

    # Configure resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    if nameservers:
        resolver.nameservers = nameservers

    result = DKIMAuditResult(domain=domain)
    result.selectors_queried = len(selectors)

    for selector in selectors:
        finding = audit_dkim_selector(domain, selector, resolver)
        result.findings.append(finding)

        if finding.record_found and finding.record_valid:
            result.selectors_found += 1

        if finding.severity == "CRITICAL":
            result.has_critical_issues = True

    return result


def format_audit_report(result: DKIMAuditResult) -> str:
    """
    Format the DKIM audit result as a human-readable report.
    
    Args:
        result: DKIMAuditResult from audit_dkim()
        
    Returns:
        Formatted string report
    """
    lines = []
    lines.append("=" * 70)
    lines.append(f"DKIM Audit Report for: {result.domain}")
    lines.append("=" * 70)
    lines.append(f"Selectors queried: {result.selectors_queried}")
    lines.append(f"Selectors found: {result.selectors_found}")
    lines.append(f"Critical issues: {'YES' if result.has_critical_issues else 'No'}")
    lines.append("")

    for finding in result.findings:
        if not finding.record_found:
            continue

        lines.append("-" * 50)
        lines.append(f"Selector: {finding.selector}")
        lines.append(f"  DKIM Domain: {finding.selector}._domainkey.{finding.domain}")
        lines.append(f"  Record Found: {'Yes' if finding.record_found else 'No'}")
        lines.append(f"  Record Valid: {'Yes' if finding.record_valid else 'No'}")
        lines.append(f"  Severity: {finding.severity}")

        if finding.key_type:
            lines.append(f"  Key Type: {finding.key_type}")
        if finding.key_size:
            lines.append(f"  Key Size: {finding.key_size} bits ({finding.key_size_rating})")
        if finding.key_empty is not None:
            lines.append(f"  Key Empty: {'Yes (CRITICAL)' if finding.key_empty else 'No'}")
        if finding.hash_algorithm:
            lines.append(f"  Hash Algorithm: {finding.hash_algorithm} ({finding.hash_algorithm_rating})")
        if finding.testing_flag is not None:
            lines.append(f"  Testing Mode: {'Yes' if finding.testing_flag else 'No'}")
        if finding.service_type_restriction:
            lines.append(f"  Service Restriction: {finding.service_type_restriction}")

        if finding.issues:
            lines.append("  Issues:")
            for issue in finding.issues:
                lines.append(f"    - {issue}")

        lines.append("")

    if result.selectors_found == 0:
        lines.append("-" * 50)
        lines.append("WARNING: No DKIM records found for any selector!")
        lines.append("This domain is not configured for DKIM signing.")
        lines.append("")

    lines.append("=" * 70)
    lines.append("End of DKIM Audit Report")
    lines.append("=" * 70)

    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dkim.py <domain> [selector1 selector2 ...]")
        print("Example: python dkim.py google.com")
        print("Example: python dkim.py example.com google mail default")
        sys.exit(1)

    target_domain = sys.argv[1]
    custom_selectors = sys.argv[2:] if len(sys.argv) > 2 else None

    print(f"Running DKIM audit for: {target_domain}")
    print()

    audit_result = audit_dkim(target_domain, selectors=custom_selectors)
    report = format_audit_report(audit_result)
    print(report)
