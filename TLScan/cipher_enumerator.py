"""TLScan — Cipher suite enumeration.

Tests which cipher suites are accepted by the target for each TLS version.
"""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from typing import Optional

from connector import connect_ssl


# Known cipher suite categories
SECURE_CIPHERS = [
    "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256",
    "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
]

WEAK_CIPHERS = [
    "RC4-SHA", "RC4-MD5", "DES-CBC3-SHA", "DES-CBC-SHA",
    "EXP-RC4-MD5", "EXP-DES-CBC-SHA", "EXP-RC2-CBC-MD5",
    "NULL-SHA", "NULL-MD5", "aNULL", "eNULL",
    "EXPORT", "LOW", "MEDIUM",
]

INSECURE_CIPHERS = [
    "anon", "NULL", "EXPORT", "DES", "RC2", "RC4", "MD5",
    "SHA1", "CBC", "3DES",
]


@dataclass
class CipherResult:
    """Result of testing a single cipher suite."""
    protocol: str
    cipher: str
    category: str  # SECURE / WEAK / INSECURE
    forward_secrecy: bool
    accepted: bool


def categorize_cipher(cipher_name: str) -> tuple[str, bool]:
    """Categorize a cipher suite and check forward secrecy.

    Returns:
        (category, forward_secrecy)
    """
    cipher_upper = cipher_name.upper()

    # Check insecure
    for pattern in INSECURE_CIPHERS:
        if pattern.upper() in cipher_upper:
            return "INSECURE", False

    # Check weak
    for pattern in WEAK_CIPHERS:
        if pattern.upper() in cipher_upper:
            return "WEAK", False

    # Check secure
    for pattern in SECURE_CIPHERS:
        if pattern.upper() in cipher_upper:
            fs = "ECDHE" in cipher_upper or "DHE" in cipher_upper
            return "SECURE", fs

    # Default
    fs = "ECDHE" in cipher_upper or "DHE" in cipher_upper
    return "WEAK", fs


def enumerate_ciphers(domain: str, port: int = 443,
                      timeout: float = 3.0) -> list[CipherResult]:
    """Enumerate accepted cipher suites.

    Args:
        domain: Target domain.
        port: Target port.
        timeout: Connection timeout per cipher.

    Returns:
        List of CipherResult for each cipher tested.
    """
    results = []

    # Get all available ciphers
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        all_ciphers = ctx.get_ciphers()
    except Exception:
        all_ciphers = []

    # Also try OpenSSL-style cipher strings
    cipher_strings = set()
    for c in all_ciphers:
        cipher_strings.add(c["name"])
        if "openssl_name" in c:
            cipher_strings.add(c["openssl_name"])

    # Add common ciphers
    common = [
        "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305",
        "AES256-GCM-SHA384", "AES128-GCM-SHA256", "CHACHA20-POLY1305-SHA256",
        "ECDHE-RSA-AES256-SHA384", "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA",
        "AES256-SHA256", "AES128-SHA256", "AES256-SHA", "AES128-SHA",
        "ECDHE-RSA-DES-CBC3-SHA", "DES-CBC3-SHA", "RC4-SHA",
        "ECDHE-RSA-RC4-SHA", "ECDHE-RSA-NULL-SHA",
    ]
    cipher_strings.update(common)

    for cipher in sorted(cipher_strings):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cipher)

            result = connect_ssl(domain, port, timeout=timeout)
            if result.success and result.cipher:
                cat, fs = categorize_cipher(result.cipher[0])
                results.append(CipherResult(
                    protocol=result.ssl_version or "Unknown",
                    cipher=result.cipher[0], category=cat,
                    forward_secrecy=fs, accepted=True,
                ))
            else:
                results.append(CipherResult(
                    protocol="Unknown", cipher=cipher,
                    category="INSECURE", forward_secrecy=False, accepted=False,
                ))
        except Exception:
            results.append(CipherResult(
                protocol="Unknown", cipher=cipher,
                category="INSECURE", forward_secrecy=False, accepted=False,
            ))

        time.sleep(0.05)  # Rate limit

    return results
