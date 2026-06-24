"""TLScan — SSL/TLS connection and certificate extraction.

Handles connection establishment, SNI, proxy support, and certificate chain extraction.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend


@dataclass
class CertInfo:
    """Parsed certificate information."""
    position: int  # 0=leaf, 1=intermediate, etc.
    subject_cn: str
    subject_o: str
    subject_ou: str
    issuer_cn: str
    issuer_o: str
    serial_number: str
    not_before: str
    not_until: str
    days_until_expiry: int
    signature_algorithm: str
    key_type: str
    key_size: int
    fingerprint_sha256: str
    san: list[str]
    is_self_signed: bool
    is_ca: bool
    has_sct: bool
    raw_cert: Optional[object] = None


@dataclass
class ConnectionResult:
    """Result of an SSL connection attempt."""
    success: bool
    domain: str
    port: int
    ip_address: Optional[str]
    ssl_version: Optional[str]
    cipher: Optional[tuple]
    certificates: list[CertInfo] = field(default_factory=list)
    error: Optional[str] = None
    connect_time: float = 0.0
    handshake_time: float = 0.0


def create_ssl_context(protocol: Optional[int] = None) -> ssl.SSLContext:
    """Create an SSL context with optional protocol restriction."""
    if protocol:
        ctx = ssl.SSLContext(protocol)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


def connect_ssl(domain: str, port: int = 443,
                timeout: float = 10.0,
                protocol: Optional[int] = None,
                proxy: Optional[str] = None,
                ipv6: bool = False) -> ConnectionResult:
    """Establish an SSL connection and extract certificates.

    Args:
        domain: Target domain or IP.
        port: Target port (default 443).
        timeout: Connection timeout in seconds.
        protocol: Force specific SSL protocol (e.g., ssl.PROTOCOL_TLSv1).
        proxy: Proxy address (host:port).
        ipv6: Force IPv6 connection.

    Returns:
        ConnectionResult with certificates and connection info.
    """
    start = time.time()
    try:
        # Resolve address
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        try:
            addr_info = socket.getaddrinfo(domain, port, family, socket.SOCK_STREAM)
            if not addr_info:
                return ConnectionResult(success=False, domain=domain, port=port,
                                         ip_address=None, ssl_version=None, cipher=None,
                                         error="DNS resolution failed")
            ip_address = addr_info[0][4][0]
        except socket.gaierror:
            ip_address = domain  # Already an IP

        # Create socket
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Proxy support (basic CONNECT)
        if proxy:
            proxy_host, proxy_port = proxy.rsplit(":", 1)
            proxy_port = int(proxy_port)
            sock.connect((proxy_host, proxy_port))
            connect_cmd = f"CONNECT {domain}:{port} HTTP/1.1\r\nHost: {domain}:{port}\r\n\r\n"
            sock.sendall(connect_cmd.encode())
            response = sock.recv(4096).decode(errors="ignore")
            if "200" not in response.split("\r\n")[0]:
                sock.close()
                return ConnectionResult(success=False, domain=domain, port=port,
                                         ip_address=ip_address, ssl_version=None,
                                         cipher=None, error="Proxy CONNECT failed")
        else:
            sock.connect((ip_address, port))

        connect_time = time.time() - start

        # Create SSL context and wrap
        ctx = create_ssl_context(protocol)
        ssock = ctx.wrap_socket(sock, server_hostname=domain)
        handshake_start = time.time()
        # Handshake happens on wrap
        handshake_time = time.time() - handshake_start

        ssl_version = ssock.version()
        cipher = ssock.cipher()

        # Extract certificates
        cert_bin = ssock.getpeercert(binary_form=True)
        certificates = []

        if cert_bin:
            # Build chain from DER certs
            certs_der = []
            # Leaf cert
            certs_der.append(cert_bin)

            # Try to get chain via getpeercert
            cert_dict = ssock.getpeercert()
            if cert_dict:
                certificates = _parse_cert_chain(cert_dict, certs_der)

        ssock.close()

        return ConnectionResult(
            success=True, domain=domain, port=port,
            ip_address=ip_address, ssl_version=ssl_version,
            cipher=cipher, certificates=certificates,
            connect_time=round(connect_time, 3),
            handshake_time=round(handshake_time, 3),
        )

    except ssl.SSLError as e:
        return ConnectionResult(success=False, domain=domain, port=port,
                                 ip_address=ip_address, ssl_version=None,
                                 cipher=None, error=f"SSL error: {e}")
    except socket.timeout:
        return ConnectionResult(success=False, domain=domain, port=port,
                                 ip_address=ip_address, ssl_version=None,
                                 cipher=None, error="Connection timed out")
    except ConnectionRefusedError:
        return ConnectionResult(success=False, domain=domain, port=port,
                                 ip_address=ip_address, ssl_version=None,
                                 cipher=None, error="Connection refused")
    except Exception as e:
        return ConnectionResult(success=False, domain=domain, port=port,
                                 ip_address=ip_address, ssl_version=None,
                                 cipher=None, error=f"Connection failed: {e}")


def _parse_cert_chain(cert_dict: dict, der_certs: list) -> list[CertInfo]:
    """Parse certificate chain from SSL cert dict."""
    certificates = []
    for i, cert_entry in enumerate(cert_dict.get("chain", [cert_dict])):
        try:
            if "cert" in cert_entry:
                cert = cert_entry["cert"]
            else:
                # Parse from dict format
                cert = _dict_to_cert_info(cert_entry, i)
                certificates.append(cert)
                continue
            certificates.append(_der_to_cert_info(cert, i))
        except Exception:
            pass

    # If no chain found, parse the leaf
    if not certificates and der_certs:
        try:
            cert = x509.load_der_x509_certificate(der_certs[0], default_backend())
            certificates.append(_x509_to_cert_info(cert, 0))
        except Exception:
            pass

    return certificates


def _der_to_cert_info(der_data: bytes, position: int) -> CertInfo:
    """Parse DER certificate bytes to CertInfo."""
    cert = x509.load_der_x509_certificate(der_data, default_backend())
    return _x509_to_cert_info(cert, position)


def _x509_to_cert_info(cert: x509.Certificate, position: int) -> CertInfo:
    """Convert x509.Certificate to CertInfo."""
    from cryptography.hazmat.primitives import hashes

    # Subject
    subject = cert.subject
    cn = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    o = subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
    ou = subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)

    # Issuer
    issuer = cert.issuer
    issuer_cn = issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    issuer_o = issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)

    # Validity
    not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
    not_until = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
    now = not_before.tzinfo.now() if hasattr(not_before, 'tzinfo') and not_before.tzinfo else not_before.replace(tzinfo=not_until.tzinfo) if not_until.tzinfo else not_before
    try:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        days_until = (not_until - now).days
    except Exception:
        days_until = 0

    # Signature algorithm
    sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)

    # Key info
    key = cert.public_key()
    key_type = key.__class__.__name__.replace("PublicKey", "").replace("public", "").upper()
    try:
        key_size = key.key_size
    except Exception:
        key_size = 0

    # Fingerprint
    fp = cert.fingerprint(hashes.SHA256()).hex()

    # SANs
    san = []
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    # SCT (Certificate Transparency)
    has_sct = False
    try:
        cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        has_sct = True
    except x509.ExtensionNotFound:
        pass

    # Self-signed
    is_self_signed = (subject == issuer)

    # CA
    is_ca = False
    try:
        bc_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bc_ext.value.ca
    except x509.ExtensionNotFound:
        pass

    return CertInfo(
        position=position,
        subject_cn=cn[0].value if cn else "N/A",
        subject_o=o[0].value if o else "",
        subject_ou=ou[0].value if ou else "",
        issuer_cn=issuer_cn[0].value if issuer_cn else "N/A",
        issuer_o=issuer_o[0].value if issuer_o else "",
        serial_number=str(cert.serial_number),
        not_before=str(not_before),
        not_until=str(not_until),
        days_until_expiry=days_until,
        signature_algorithm=sig_algo,
        key_type=key_type,
        key_size=key_size,
        fingerprint_sha256=fp,
        san=san,
        is_self_signed=is_self_signed,
        is_ca=is_ca,
        has_sct=has_sct,
        raw_cert=cert,
    )


def _dict_to_cert_info(cert_dict: dict, position: int) -> CertInfo:
    """Parse cert info from dictionary format."""
    subject = cert_dict.get("subject", ())
    issuer = cert_dict.get("issuer", ())

    def get_name(name_tuple, oid_val):
        if isinstance(name_tuple, tuple):
            for attr in name_tuple:
                if isinstance(attr, tuple) and len(attr) == 2:
                    if attr[0].oid.dotted_string == oid_val or str(attr[0].oid) == oid_val:
                        return attr[1]
        return ""

    # Flatten subject/issuer
    subject_cn = _extract_cn(subject)
    issuer_cn = _extract_cn(issuer)

    not_after = cert_dict.get("notAfter", "")
    not_before = cert_dict.get("notBefore", "")

    try:
        from datetime import datetime, timezone
        fmt = "%b %d %H:%M:%S %Y %Z"
        not_until = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_until = (not_until - now).days
    except Exception:
        days_until = 0

    return CertInfo(
        position=position,
        subject_cn=subject_cn,
        subject_o="",
        subject_ou="",
        issuer_cn=issuer_cn,
        issuer_o="",
        serial_number=cert_dict.get("serialNumber", ""),
        not_before=not_before,
        not_until=not_after,
        days_until_expiry=days_until,
        signature_algorithm=cert_dict.get("sigAlg", "Unknown"),
        key_type="Unknown",
        key_size=0,
        fingerprint_sha256=cert_dict.get("sha256", ""),
        san=cert_dict.get("subjectAltName", []),
        is_self_signed=(subject_cn == issuer_cn),
        is_ca=False,
        has_sct=False,
    )


def _extract_cn(name_tuple) -> str:
    """Extract CN from a name tuple."""
    if isinstance(name_tuple, tuple):
        for item in name_tuple:
            if isinstance(item, tuple) and len(item) == 2:
                if "commonName" in str(item[0]) or "2.5.4.3" in str(item[0]):
                    return item[1]
    return ""
