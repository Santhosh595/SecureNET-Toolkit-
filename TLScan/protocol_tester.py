"""TLScan — Protocol version testing.

Tests which SSL/TLS protocol versions are supported by the target.
"""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from typing import Optional

from connector import connect_ssl


# Protocol mappings
PROTOCOLS = {
    "SSLv2": {"id": ssl.PROTOCOL_SSLv23 if hasattr(ssl, "PROTOCOL_SSLv23") else None, "risk": "CRITICAL"},
    "SSLv3": {"id": ssl.PROTOCOL_SSLv23 if hasattr(ssl, "PROTOCOL_SSLv23") else None, "risk": "CRITICAL"},
    "TLS 1.0": {"id": ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None, "risk": "HIGH"},
    "TLS 1.1": {"id": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None, "risk": "MEDIUM"},
    "TLS 1.2": {"id": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, "PROTOCOL_TLSv1_2") else None, "risk": "GOOD"},
    "TLS 1.3": {"id": ssl.PROTOCOL_TLS if hasattr(ssl, "PROTOCOL_TLS") else None, "risk": "EXCELLENT"},
}


@dataclass
class ProtocolResult:
    """Result of testing a single protocol."""
    protocol: str
    supported: bool
    risk: str
    cipher: Optional[str] = None
    error: Optional[str] = None


def test_protocols(domain: str, port: int = 443,
                   timeout: float = 5.0) -> list[ProtocolResult]:
    """Test which protocol versions are supported.

    Args:
        domain: Target domain.
        port: Target port.
        timeout: Connection timeout per protocol.

    Returns:
        List of ProtocolResult for each protocol tested.
    """
    results = []

    for proto_name, proto_info in PROTOCOLS.items():
        if proto_info["id"] is None:
            continue

        try:
            result = connect_ssl(domain, port, timeout=timeout, protocol=proto_info["id"])
            if result.success:
                cipher_str = f"{result.cipher[0]} {result.cipher[2]}" if result.cipher else "Unknown"
                results.append(ProtocolResult(
                    protocol=proto_name, supported=True, risk=proto_info["risk"],
                    cipher=cipher_str,
                ))
            else:
                results.append(ProtocolResult(
                    protocol=proto_name, supported=False, risk=proto_info["risk"],
                    error=result.error,
                ))
        except Exception as e:
            results.append(ProtocolResult(
                protocol=proto_name, supported=False, risk=proto_info["risk"],
                error=str(e),
            ))

        time.sleep(0.1)  # Rate limit between probes

    return results
