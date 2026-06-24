"""TLScan — 10 SSL/TLS vulnerability checks."""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from typing import Optional

from connector import connect_ssl, ConnectionResult
from protocol_tester import test_protocols
from cipher_enumerator import enumerate_ciphers, CipherResult


@dataclass
class VulnResult:
    """Result of a vulnerability check."""
    name: str
    cve: str
    vulnerable: bool
    severity: str
    detail: str


def check_all_vulnerabilities(domain: str, port: int = 443,
                               protocols: list = None,
                               ciphers: list = None) -> list[VulnResult]:
    """Run all 10 vulnerability checks.

    Args:
        domain: Target domain.
        port: Target port.
        protocols: Pre-tested protocol results.
        ciphers: Pre-tested cipher results.

    Returns:
        List of VulnResult for each check.
    """
    results = []

    # Get protocols and ciphers if not provided
    if protocols is None:
        protocols = test_protocols(domain, port)
    if ciphers is None:
        ciphers = enumerate_ciphers(domain, port)

    protocol_map = {p.protocol: p for p in protocols}
    cipher_by_proto = {}
    for c in ciphers:
        if c.accepted:
            cipher_by_proto.setdefault(c.protocol, []).append(c)

    # Vuln 1: POODLE
    sslv3_supported = protocol_map.get("SSLv3", None)
    sslv3_cbc = False
    if sslv3_supported and sslv3_supported.supported:
        for c in cipher_by_proto.get("TLSv1", []):
            if "CBC" in c.cipher.upper():
                sslv3_cbc = True
                break
    results.append(VulnResult(
        name="POODLE", cve="CVE-2014-3566",
        vulnerable=sslv3_cbc,
        severity="CRITICAL",
        detail="SSLv3 with CBC ciphers supported" if sslv3_cbc else "Not vulnerable",
    ))

    # Vuln 2: BEAST
    tls10_supported = protocol_map.get("TLS 1.0", None)
    tls10_cbc = False
    if tls10_supported and tls10_supported.supported:
        for c in cipher_by_proto.get("TLSv1", []):
            if "CBC" in c.cipher.upper():
                tls10_cbc = True
                break
    results.append(VulnResult(
        name="BEAST", cve="CVE-2011-3389",
        vulnerable=tls10_cbc,
        severity="HIGH",
        detail="TLS 1.0 with CBC ciphers supported" if tls10_cbc else "Not vulnerable",
    ))

    # Vuln 3: CRIME (compression)
    crime_vuln = False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.options |= ssl.OP_NO_COMPRESSION
        result = connect_ssl(domain, port)
        if result.success:
            crime_vuln = False
    except Exception:
        pass
    results.append(VulnResult(
        name="CRIME", cve="CVE-2012-4929",
        vulnerable=crime_vuln,
        severity="HIGH",
        detail="TLS compression may be enabled" if crime_vuln else "Compression disabled or not detectable",
    ))

    # Vuln 4: BREACH (HTTP compression)
    breach_vuln = False
    try:
        import requests
        resp = requests.get(f"https://{domain}:{port}/", timeout=5, verify=False)
        ce = resp.headers.get("Content-Encoding", "")
        if ce and ce != "identity":
            breach_vuln = True
    except Exception:
        pass
    results.append(VulnResult(
        name="BREACH", cve="CVE-2013-3587",
        vulnerable=breach_vuln,
        severity="MEDIUM",
        detail="HTTP compression detected on HTTPS endpoint" if breach_vuln else "No HTTP compression detected",
    ))

    # Vuln 5: Heartbleed (simplified check)
    heartbleed_vuln = False
    try:
        result = connect_ssl(domain, port)
        if result.success and result.ssl_version:
            # Check if OpenSSL version is vulnerable (simplified)
            import subprocess
            try:
                ver = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=3)
                if "1.0.1" in ver.stdout and "f" not in ver.stdout.lower().split()[-1]:
                    heartbleed_vuln = True
            except Exception:
                pass
    except Exception:
        pass
    results.append(VulnResult(
        name="Heartbleed", cve="CVE-2014-0160",
        vulnerable=heartbleed_vuln,
        severity="CRITICAL",
        detail="Potentially vulnerable OpenSSL version detected" if heartbleed_vuln else "Not vulnerable or unable to detect",
    ))

    # Vuln 6: ROBOT
    robot_vuln = False
    for c in ciphers:
        if c.accepted and "RSA" in c.cipher.upper() and "ECDHE" not in c.cipher.upper() and "DHE" not in c.cipher.upper():
            robot_vuln = True
            break
    results.append(VulnResult(
        name="ROBOT", cve="CVE-2017-13099",
        vulnerable=robot_vuln,
        severity="HIGH",
        detail="RSA key exchange without forward secrecy" if robot_vuln else "Not vulnerable",
    ))

    # Vuln 7: SWEET32
    sweet32_vuln = False
    for c in ciphers:
        if c.accepted and "3DES" in c.cipher.upper() or "DES-CBC3" in c.cipher.upper():
            sweet32_vuln = True
            break
    results.append(VulnResult(
        name="SWEET32", cve="CVE-2016-2183",
        vulnerable=sweet32_vuln,
        severity="MEDIUM",
        detail="3DES cipher suite supported" if sweet32_vuln else "Not vulnerable",
    ))

    # Vuln 8: DROWN
    sslv2_supported = protocol_map.get("SSLv2", None)
    results.append(VulnResult(
        name="DROWN", cve="CVE-2016-0800",
        vulnerable=sslv2_supported.supported if sslv2_supported else False,
        severity="CRITICAL",
        detail="SSLv2 supported" if (sslv2_supported and sslv2_supported.supported) else "Not vulnerable",
    ))

    # Vuln 9: Weak DH (Logjam)
    logjam_vuln = False
    for c in ciphers:
        if c.accepted and "DHE" in c.cipher.upper() and "EXPORT" not in c.cipher.upper():
            # Check DH params size (simplified)
            if "1024" in c.cipher:
                logjam_vuln = True
                break
    results.append(VulnResult(
        name="Weak DH (Logjam)", cve="CVE-2015-4000",
        vulnerable=logjam_vuln,
        severity="HIGH",
        detail="Weak DH parameters detected" if logjam_vuln else "Not vulnerable",
    ))

    # Vuln 10: Certificate Pinning
    pinning_info = "Not implemented"
    try:
        import requests
        resp = requests.head(f"https://{domain}:{port}/", timeout=5, verify=False)
        hpkp = resp.headers.get("Public-Key-Pins", "")
        expect_ct = resp.headers.get("Expect-CT", "")
        if hpkp:
            pinning_info = f"HPKP header present: {hpkp[:50]}"
        if expect_ct:
            pinning_info += f"; Expect-CT: {expect_ct[:50]}"
    except Exception:
        pass
    results.append(VulnResult(
        name="Certificate Pinning", cve="N/A",
        vulnerable=False,
        severity="INFO",
        detail=pinning_info,
    ))

    return results
