"""TLScan — SSL Labs-style grading system.

Calculates scores and grades based on certificate, protocol, cipher, and vulnerability findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from connector import CertInfo
from protocol_tester import ProtocolResult
from cipher_enumerator import CipherResult
from vuln_checks import VulnResult


@dataclass
class GradeResult:
    """Overall scan grade."""
    grade: str  # A+, A, B, C, D, F
    score: int  # 0-100
    cap_reason: Optional[str] = None
    deductions: list[str] = None

    def __post_init__(self):
        if self.deductions is None:
            self.deductions = []


def calculate_grade(
    certificates: list[CertInfo],
    protocols: list[ProtocolResult],
    ciphers: list[CipherResult],
    vulnerabilities: list[VulnResult],
) -> GradeResult:
    """Calculate overall grade from all scan results.

    Starts at 100, deducts points for issues.
    Applies caps for critical issues.
    """
    score = 100
    deductions = []
    cap_reason = None

    # ── Certificate deductions ──
    for cert in certificates:
        if cert.is_self_signed:
            score -= 20
            deductions.append(f"Self-signed certificate: {cert.subject_cn}")

        if cert.days_until_expiry < 0:
            score -= 30
            deductions.append(f"Expired certificate: {cert.subject_cn} (expired {abs(cert.days_until_expiry)} days ago)")
            cap_reason = "Expired certificate — grade capped at F"
        elif cert.days_until_expiry < 30:
            score -= 15
            deductions.append(f"Certificate expiring soon: {cert.subject_cn} ({cert.days_until_expiry} days)")
        elif cert.days_until_expiry < 90:
            score -= 5
            deductions.append(f"Certificate expiring within 90 days: {cert.subject_cn}")

        if "SHA1" in cert.signature_algorithm.upper() or "MD5" in cert.signature_algorithm.upper():
            score -= 20
            deductions.append(f"Weak signature algorithm: {cert.signature_algorithm}")

        if cert.key_size < 2048 and "RSA" in cert.key_type:
            score -= 15
            deductions.append(f"RSA key too small: {cert.key_size} bits")

    # ── Protocol deductions ──
    protocol_map = {p.protocol: p for p in protocols}

    sslv2 = protocol_map.get("SSLv2")
    if sslv2 and sslv2.supported:
        score -= 30
        deductions.append("SSLv2 supported (broken)")
        cap_reason = "SSLv2 supported — grade capped at F"

    sslv3 = protocol_map.get("SSLv3")
    if sslv3 and sslv3.supported:
        score -= 25
        deductions.append("SSLv3 supported (POODLE)")
        if not cap_reason:
            cap_reason = "SSLv3 supported — grade capped at F"

    tls10 = protocol_map.get("TLS 1.0")
    if tls10 and tls10.supported:
        score -= 10
        deductions.append("TLS 1.0 supported (deprecated)")

    tls11 = protocol_map.get("TLS 1.1")
    if tls11 and tls11.supported:
        score -= 5
        deductions.append("TLS 1.1 supported (deprecated)")

    # ── Cipher deductions ──
    accepted_ciphers = [c for c in ciphers if c.accepted]
    secure_count = sum(1 for c in accepted_ciphers if c.category == "SECURE")
    weak_count = sum(1 for c in accepted_ciphers if c.category == "WEAK")
    insecure_count = sum(1 for c in accepted_ciphers if c.category == "INSECURE")

    if insecure_count > 0:
        score -= insecure_count * 5
        deductions.append(f"{insecure_count} insecure cipher suites accepted")

    if weak_count > 0:
        score -= weak_count * 2
        deductions.append(f"{weak_count} weak cipher suites accepted")

    # ── Vulnerability deductions ──
    for vuln in vulnerabilities:
        if vuln.vulnerable:
            if vuln.severity == "CRITICAL":
                score -= 20
                deductions.append(f"{vuln.name} ({vuln.cve})")
            elif vuln.severity == "HIGH":
                score -= 10
                deductions.append(f"{vuln.name} ({vuln.cve})")
            elif vuln.severity == "MEDIUM":
                score -= 5
                deductions.append(f"{vuln.name} ({vuln.cve})")

    # ── Apply caps ──
    if cap_reason:
        score = min(score, 34)  # F cap

    # Ensure score doesn't go below 0
    score = max(0, score)

    # ── Determine grade ──
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return GradeResult(grade=grade, score=score, cap_reason=cap_reason, deductions=deductions)
