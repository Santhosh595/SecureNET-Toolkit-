"""
DNSSEC Audit Module - Category 4
=================================
Audits DNSSEC configuration for a domain:
- DNSKEY, RRSIG, DS, NSEC/NSEC3 record queries
- Signature algorithm strength assessment
- Key size validation (ZSK/KSK)
- NSEC/NSEC3 configuration checks
- DS record presence at parent zone
"""

import datetime
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.dnssec

logger = logging.getLogger(__name__)

# Signature algorithm -> (name, severity, severity_score)
SIGNATURE_ALGORITHMS = {
    1: ("RSA/MD5", "CRITICAL", 5),
    3: ("DSA/SHA-1", "HIGH", 4),
    5: ("RSA/SHA-1", "HIGH", 4),
    6: ("DSA-NSEC3-SHA-1", "HIGH", 4),
    7: ("RSASHA1-NSEC3-SHA1", "HIGH", 4),
    8: ("RSA/SHA-256", "GOOD", 2),
    10: ("RSA/SHA-512", "GOOD", 2),
    12: ("ECC-GOST", "MEDIUM", 3),
    13: ("ECDSA/SHA-256", "EXCELLENT", 1),
    14: ("ECDSA/SHA-384", "EXCELLENT", 1),
    15: ("Ed25519", "EXCELLENT", 1),
    16: ("Ed448", "EXCELLENT", 1),
}

# Minimum key sizes
ZSK_MIN_SIZE = 1024
KSK_MIN_SIZE = 2048

# NSEC3 max iterations
NSEC3_MAX_ITERATIONS = 150


@dataclass
class DNSSECFinding:
    """Represents a single DNSSEC audit finding."""
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, GOOD, EXCELLENT, INFO
    description: str
    record_type: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class DNSSECResult:
    """Complete DNSSEC audit result."""
    domain: str
    dnssec_enabled: bool = False
    findings: List[DNSSECFinding] = field(default_factory=list)
    dnskey_records: list = field(default_factory=list)
    rrsig_records: list = field(default_factory=list)
    ds_records: list = field(default_factory=list)
    nsec_records: list = field(default_factory=list)
    nsec3_records: list = field(default_factory=list)
    overall_severity: str = "GOOD"

    def add_finding(self, finding: DNSSECFinding):
        self.findings.append(finding)

    def compute_overall_severity(self):
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "GOOD": 5, "EXCELLENT": 6}
        if not self.findings:
            self.overall_severity = "GOOD"
            return
        worst = min(self.findings, key=lambda f: severity_order.get(f.severity, 5))
        self.overall_severity = worst.severity


def _resolve_records(domain: str, rdtype: str, rdclass: int = dns.rdataclass.IN) -> list:
    """Resolve DNS records of a given type, return list of rdata objects."""
    try:
        name = dns.name.from_text(domain)
        answer = dns.resolver.resolve(name, rdtype, rdclass=rdclass, want_dnssec=True)
        return list(answer)
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoNameservers:
        return []
    except dns.exception.Timeout:
        logger.warning("Timeout resolving %s %s", domain, rdtype)
        return []
    except Exception as e:
        logger.warning("Error resolving %s %s: %s", domain, rdtype, e)
        return []


def _query_with_dnssec(domain: str, rdtype: int) -> dns.message.Message:
    """Query with DNSSEC OK (DO) bit set and return the full message."""
    try:
        name = dns.name.from_text(domain)
        request = dns.message.make_query(name, rdtype, want_dnssec=True)
        # Try multiple nameservers
        response = dns.query.udp(request, dns.resolver.Resolver().nameservers[0], timeout=5)
        return response
    except Exception as e:
        logger.warning("DNSSEC query failed for %s type %d: %s", domain, rdtype, e)
        return None


def check_dnssec_enabled(domain: str) -> DNSSECFinding:
    """Check if DNSSEC is enabled by looking for RRSIG records."""
    rrsig_records = _resolve_records(domain, dns.rdatatype.RRSIG)
    if rrsig_records:
        return DNSSECFinding(
            title="DNSSEC Enabled",
            severity="GOOD",
            description="DNSSEC is enabled. RRSIG records found for the zone.",
            record_type="RRSIG",
            details={"count": len(rrsig_records)}
        )
    else:
        return DNSSECFinding(
            title="DNSSEC Not Enabled",
            severity="HIGH",
            description="DNSSEC is not enabled. No RRSIG records found. The zone is not signed.",
            record_type="RRSIG",
            details={}
        )


def check_dnskey_records(domain: str) -> DNSSECResult:
    """Check DNSKEY records and validate key sizes."""
    result = DNSSECResult(domain=domain)
    try:
        name = dns.name.from_text(domain)
        answer = dns.resolver.resolve(name, dns.rdatatype.DNSKEY, want_dnssec=True)
        result.dnskey_records = list(answer)

        if not result.dnskey_records:
            result.add_finding(DNSSECFinding(
                title="No DNSKEY Records",
                severity="HIGH",
                description="No DNSKEY records found. DNSSEC cannot function without DNSKEY records.",
                record_type="DNSKEY"
            ))
            return result

        for key in result.dnskey_records:
            key_type = "KSK" if key.flags == 257 else "ZSK" if key.flags == 256 else f"Unknown({key.flags})"
            key_size = dns.dnssec.key_id(key)  # key_id gives algorithm-specific info

            # Determine actual key size from the key material
            algorithm = key.algorithm
            actual_size = len(key.key) * 8  # rough estimate; better to use algorithm-specific parsing

            # More accurate key size based on algorithm
            if algorithm in (1, 3, 5, 6, 7, 8, 10):  # RSA keys
                # RSA key size = modulus length in bits
                from Crypto.PublicKey import RSA
                try:
                    # The key bytes contain the exponent and modulus
                    actual_size = _rsa_key_size(key.key)
                except Exception:
                    actual_size = len(key.key) * 8
            elif algorithm in (13, 14):  # ECDSA
                actual_size = 256 if algorithm == 13 else 384
            elif algorithm in (15, 16):  # EdDSA
                actual_size = 256 if algorithm == 15 else 456

            severity = "GOOD"
            if key_type == "ZSK" and actual_size < ZSK_MIN_SIZE:
                severity = "CRITICAL"
            elif key_type == "KSK" and actual_size < KSK_MIN_SIZE:
                severity = "HIGH"

            algo_name = SIGNATURE_ALGORITHMS.get(algorithm, (f"Unknown({algorithm})", "MEDIUM", 3))

            result.add_finding(DNSSECFinding(
                title=f"DNSKEY Record ({key_type})",
                severity=severity,
                description=f"DNSKEY record found: {algo_name[0]}, key size ~{actual_size} bits",
                record_type="DNSKEY",
                details={
                    "key_type": key_type,
                    "algorithm": algorithm,
                    "algorithm_name": algo_name[0],
                    "key_size": actual_size,
                    "flags": key.flags,
                }
            ))

    except Exception as e:
        logger.error("Error checking DNSKEY records: %s", e)
        result.add_finding(DNSSECFinding(
            title="DNSKEY Query Error",
            severity="MEDIUM",
            description=f"Could not query DNSKEY records: {e}",
            record_type="DNSKEY"
        ))

    return result


def _rsa_key_size(key_bytes: bytes) -> int:
    """Extract RSA key size in bits from DNSKEY key material."""
    try:
        # DNSKEY key field for RSA: exponent length (1 or 3 bytes) + exponent + modulus
        if len(key_bytes) < 2:
            return 0
        exp_len = key_bytes[0]
        if exp_len == 0:
            exp_len = int.from_bytes(key_bytes[1:3], 'big')
            offset = 3
        else:
            offset = 1
        # Modulus starts at offset
        modulus = key_bytes[offset + exp_len:]
        return len(modulus) * 8
    except Exception:
        return len(key_bytes) * 8


def check_rrsig_validity(domain: str) -> List[DNSSECFinding]:
    """Check RRSIG record validity - signature lifetime and algorithm."""
    findings = []
    try:
        name = dns.name.from_text(domain)
        answer = dns.resolver.resolve(name, dns.rdatatype.RRSIG, want_dnssec=True)
        rrsig_records = list(answer)

        if not rrsig_records:
            findings.append(DNSSECFinding(
                title="No RRSIG Records",
                severity="HIGH",
                description="No RRSIG records found. Zone is not signed.",
                record_type="RRSIG"
            ))
            return findings

        now = datetime.datetime.now(datetime.timezone.utc)

        for rrsig in rrsig_records:
            # Check signature algorithm
            algo = rrsig.algorithm
            algo_info = SIGNATURE_ALGORITHMS.get(algo, (f"Unknown({algo})", "MEDIUM", 3))
            algo_name, algo_severity, _ = algo_info

            # Check expiration
            expiration = datetime.datetime.fromtimestamp(rrsig.expiration, tz=datetime.timezone.utc)
            inception = datetime.datetime.fromtimestamp(rrsig.inception, tz=datetime.timezone.utc)

            if now > expiration:
                findings.append(DNSSECFinding(
                    title="RRSIG Expired",
                    severity="CRITICAL",
                    description=f"Signature expired on {expiration.isoformat()}. Algorithm: {algo_name}",
                    record_type="RRSIG",
                    details={
                        "algorithm": algo,
                        "algorithm_name": algo_name,
                        "expiration": expiration.isoformat(),
                        "inception": inception.isoformat(),
                        "signed_type": dns.rdatatype.to_text(rrsig.type_covered),
                    }
                ))
            elif (expiration - now).days < 30:
                findings.append(DNSSECFinding(
                    title="RRSIG Expiring Soon",
                    severity="MEDIUM",
                    description=f"Signature expires in {(expiration - now).days} days ({expiration.isoformat()}).",
                    record_type="RRSIG",
                    details={
                        "algorithm": algo,
                        "algorithm_name": algo_name,
                        "expiration": expiration.isoformat(),
                        "signed_type": dns.rdatatype.to_text(rrsig.type_covered),
                    }
                ))
            else:
                # Signature is valid, report algorithm severity
                sig_severity = algo_severity if algo_severity in ("CRITICAL", "HIGH") else "GOOD"
                findings.append(DNSSECFinding(
                    title="RRSIG Valid",
                    severity=sig_severity,
                    description=f"Valid signature for {dns.rdatatype.to_text(rrsig.type_covered)} using {algo_name}. Expires: {expiration.isoformat()}",
                    record_type="RRSIG",
                    details={
                        "algorithm": algo,
                        "algorithm_name": algo_name,
                        "expiration": expiration.isoformat(),
                        "inception": inception.isoformat(),
                        "signed_type": dns.rdatatype.to_text(rrsig.type_covered),
                        "key_tag": rrsig.key_tag,
                    }
                ))

    except Exception as e:
        logger.error("Error checking RRSIG validity: %s", e)
        findings.append(DNSSECFinding(
            title="RRSIG Query Error",
            severity="MEDIUM",
            description=f"Could not query RRSIG records: {e}",
            record_type="RRSIG"
        ))

    return findings


def check_ds_record(domain: str) -> List[DNSSECFinding]:
    """Check for DS records at the parent zone."""
    findings = []
    try:
        name = dns.name.from_text(domain)
        # DS records are at the parent zone
        # We query the parent zone for DS records of the child
        labels = name.labels
        if len(labels) < 2:
            findings.append(DNSSECFinding(
                title="DS Record Check - TLD",
                severity="INFO",
                description="Cannot check DS records for a TLD. DS records are only applicable to non-TLD zones.",
                record_type="DS"
            ))
            return findings

        parent_name = dns.name.from_text(b'.'.join(labels[1:]).decode() if isinstance(labels[1:], bytes) else b'.'.join(labels[1:]).decode())
        child_name = dns.name.from_text(b'.'.join(labels[:1]).decode() if isinstance(labels[0:], bytes) else b'.'.join(labels[:1]).decode())

        try:
            answer = dns.resolver.resolve(parent_name, dns.rdatatype.DS)
            ds_records = list(answer)

            # Filter DS records that match our domain
            matching_ds = [ds for ds in ds_records if dns.name.from_text(domain).is_subdomain(name.parent if hasattr(name, 'parent') else parent_name)]

            if ds_records:
                for ds in ds_records:
                    algo = ds.algorithm
                    algo_info = SIGNATURE_ALGORITHMS.get(algo, (f"Unknown({algo})", "MEDIUM", 3))
                    digest_type = ds.digest_type

                    findings.append(DNSSECFinding(
                        title="DS Record Present at Parent",
                        severity="GOOD",
                        description=f"DS record found at parent zone. Algorithm: {algo_info[0]}, Digest type: {digest_type}",
                        record_type="DS",
                        details={
                            "algorithm": algo,
                            "algorithm_name": algo_info[0],
                            "digest_type": digest_type,
                            "key_tag": ds.key_tag,
                        }
                    ))
            else:
                findings.append(DNSSECFinding(
                    title="No DS Record at Parent Zone",
                    severity="HIGH",
                    description="No DS records found at the parent zone. DNSSEC chain of trust may be broken.",
                    record_type="DS",
                    details={"parent_zone": str(parent_name)}
                ))
        except dns.resolver.NoAnswer:
            findings.append(DNSSECFinding(
                title="No DS Record at Parent Zone",
                severity="HIGH",
                description="No DS records found at the parent zone. DNSSEC chain of trust may be broken.",
                record_type="DS",
                details={"parent_zone": str(parent_name)}
            ))
        except dns.resolver.NXDOMAIN:
            findings.append(DNSSECFinding(
                title="Parent Zone Not Found",
                severity="MEDIUM",
                description=f"Could not resolve parent zone for DS record check.",
                record_type="DS"
            ))

    except Exception as e:
        logger.error("Error checking DS records: %s", e)
        findings.append(DNSSECFinding(
            title="DS Record Query Error",
            severity="MEDIUM",
            description=f"Could not query DS records: {e}",
            record_type="DS"
        ))

    return findings


def check_nsec_nsec3(domain: str) -> List[DNSSECFinding]:
    """Check NSEC/NSEC3 configuration."""
    findings = []
    try:
        name = dns.name.from_text(domain)

        # Check for NSEC records (indicates potential zone enumeration)
        try:
            answer = dns.resolver.resolve(name, dns.rdatatype.NSEC, want_dnssec=True)
            nsec_records = list(answer)
            if nsec_records:
                findings.append(DNSSECFinding(
                    title="NSEC Records Present (Zone Enumeration Risk)",
                    severity="MEDIUM",
                    description="NSEC records are present, which allows zone enumeration. Consider using NSEC3 instead.",
                    record_type="NSEC",
                    details={"count": len(nsec_records)}
                ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            pass

        # Check for NSEC3 records
        try:
            answer = dns.resolver.resolve(name, dns.rdatatype.NSEC3, want_dnssec=True)
            nsec3_records = list(answer)
            if nsec3_records:
                for nsec3 in nsec3_records:
                    iterations = nsec3.iterations
                    if iterations > NSEC3_MAX_ITERATIONS:
                        findings.append(DNSSECFinding(
                            title="NSEC3 High Iterations",
                            severity="HIGH",
                            description=f"NSEC3 iterations ({iterations}) exceeds recommended maximum ({NSEC3_MAX_ITERATIONS}). This can cause resolver issues.",
                            record_type="NSEC3",
                            details={
                                "iterations": iterations,
                                "hash_algorithm": nsec3.algorithm,
                                "flags": nsec3.flags,
                            }
                        ))
                    else:
                        findings.append(DNSSECFinding(
                            title="NSEC3 Record Present",
                            severity="GOOD",
                            description=f"NSEC3 record present with {iterations} iterations. Zone enumeration is mitigated.",
                            record_type="NSEC3",
                            details={
                                "iterations": iterations,
                                "hash_algorithm": nsec3.algorithm,
                                "flags": nsec3.flags,
                            }
                        ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            pass

        # Check for NSEC3PARAM
        try:
            answer = dns.resolver.resolve(name, dns.rdatatype.NSEC3PARAM, want_dnssec=True)
            nsec3param_records = list(answer)
            if nsec3param_records:
                for nsec3p in nsec3param_records:
                    findings.append(DNSSECFinding(
                        title="NSEC3PARAM Record Present",
                        severity="INFO",
                        description=f"NSEC3PARAM found: iterations={nsec3p.iterations}, algorithm={nsec3p.algorithm}",
                        record_type="NSEC3PARAM",
                        details={
                            "iterations": nsec3p.iterations,
                            "hash_algorithm": nsec3p.algorithm,
                            "flags": nsec3p.flags,
                        }
                    ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass

    except Exception as e:
        logger.error("Error checking NSEC/NSEC3: %s", e)
        findings.append(DNSSECFinding(
            title="NSEC/NSEC3 Query Error",
            severity="MEDIUM",
            description=f"Could not query NSEC/NSEC3 records: {e}",
            record_type="NSEC"
        ))

    return findings


def check_dnskey_algorithm(domain: str) -> List[DNSSECFinding]:
    """Check the algorithm used in DNSKEY records."""
    findings = []
    try:
        name = dns.name.from_text(domain)
        answer = dns.resolver.resolve(name, dns.rdatatype.DNSKEY, want_dnssec=True)
        dnskey_records = list(answer)

        if not dnskey_records:
            return findings

        for key in dnskey_records:
            algo = key.algorithm
            algo_info = SIGNATURE_ALGORITHMS.get(algo, (f"Unknown({algo})", "MEDIUM", 3))
            algo_name, algo_severity, _ = algo_info
            key_type = "KSK" if key.flags == 257 else "ZSK" if key.flags == 256 else f"Unknown({key.flags})"

            findings.append(DNSSECFinding(
                title=f"DNSKEY Algorithm ({key_type})",
                severity=algo_severity,
                description=f"DNSKEY uses {algo_name} (algorithm {algo}) for {key_type}.",
                record_type="DNSKEY",
                details={
                    "algorithm": algo,
                    "algorithm_name": algo_name,
                    "key_type": key_type,
                    "flags": key.flags,
                }
            ))

    except Exception as e:
        logger.error("Error checking DNSKEY algorithm: %s", e)
        findings.append(DNSSECFinding(
            title="DNSKEY Algorithm Check Error",
            severity="MEDIUM",
            description=f"Could not check DNSKEY algorithm: {e}",
            record_type="DNSKEY"
        ))

    return findings


def audit_dnssec(domain: str, nameservers: Optional[List[str]] = None) -> DNSSECResult:
    """
    Run a complete DNSSEC audit for the given domain.
    
    Args:
        domain: The domain to audit
        nameservers: Optional list of nameservers to use
        
    Returns:
        DNSSECResult with all findings
    """
    if nameservers:
        dns.resolver.Resolver().nameservers = nameservers

    result = DNSSECResult(domain=domain)

    # 1. Check if DNSSEC is enabled
    dnssec_check = check_dnssec_enabled(domain)
    result.add_finding(dnssec_check)
    result.dnssec_enabled = dnssec_check.severity == "GOOD"

    # 2. Check DNSKEY records and key sizes
    dnskey_result = check_dnskey_records(domain)
    result.dnskey_records = dnskey_result.dnskey_records
    result.findings.extend(dnskey_result.findings)

    # 3. Check DNSKEY algorithms
    algo_findings = check_dnskey_algorithm(domain)
    result.findings.extend(algo_findings)

    # 4. Check RRSIG validity
    rrsig_findings = check_rrsig_validity(domain)
    result.findings.extend(rrsig_findings)

    # 5. Check DS records at parent
    ds_findings = check_ds_record(domain)
    result.findings.extend(ds_findings)

    # 6. Check NSEC/NSEC3
    nsec_findings = check_nsec_nsec3(domain)
    result.findings.extend(nsec_findings)

    # Compute overall severity
    result.compute_overall_severity()

    return result


def format_report(result: DNSSECResult) -> str:
    """Format the DNSSEC audit result as a human-readable report."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"  DNSSEC Audit Report: {result.domain}")
    lines.append("=" * 60)
    lines.append(f"  Overall Severity: {result.overall_severity}")
    lines.append(f"  DNSSEC Enabled: {'Yes' if result.dnssec_enabled else 'No'}")
    lines.append(f"  Total Findings: {len(result.findings)}")
    lines.append("-" * 60)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "GOOD", "EXCELLENT"]
    for severity in severity_order:
        sev_findings = [f for f in result.findings if f.severity == severity]
        if sev_findings:
            lines.append(f"\n  [{severity}] ({len(sev_findings)} findings)")
            for finding in sev_findings:
                lines.append(f"    • {finding.title}")
                lines.append(f"      {finding.description}")
                if finding.details:
                    for k, v in finding.details.items():
                        lines.append(f"        - {k}: {v}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dnssec.py <domain> [nameserver1] [nameserver2] ...")
        sys.exit(1)

    target_domain = sys.argv[1]
    ns = sys.argv[2:] if len(sys.argv) > 2 else None

    print(f"Running DNSSEC audit for: {target_domain}")
    audit_result = audit_dnssec(target_domain, nameservers=ns)
    print(format_report(audit_result))
