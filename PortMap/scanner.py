"""PortMap — Multi-threaded port scanner with service detection and risk analysis.

Uses raw sockets (no Nmap dependency). Thread pool of 100 workers.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PortState(Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# Port profiles
PORT_PROFILES: dict[str, list[int]] = {
    "quick": [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
    ],
    "common": [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137,
        138, 139, 143, 161, 162, 389, 443, 445, 465, 514, 515, 587, 636,
        993, 995, 1080, 1433, 1434, 1521, 2049, 3306, 3389, 4443, 5432,
        5900, 5901, 6379, 6443, 7001, 8000, 8008, 8080, 8443, 8888, 9000,
        9090, 9200, 9300, 11211, 27017, 27018, 27019, 28017, 50000, 50030,
        50070, 50075, 50090, 61616, 61617,
    ],
    "full": list(range(1, 1025)),
}

# Service database
SERVICE_MAP: dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD", 587: "SMTP-Sub", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-Mon",
    1521: "Oracle-DB", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    4443: "Pharos", 5432: "PostgreSQL", 5900: "VNC", 5901: "VNC-1",
    6379: "Redis", 6443: "K8s-API", 7001: "WebLogic", 8000: "HTTP-Alt",
    8008: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "SonarQube", 9090: "Web-Console", 9200: "Elasticsearch",
    9300: "ES-Transport", 11211: "Memcached", 27017: "MongoDB",
    27018: "MongoDB-S", 27019: "MongoDB-CS", 28017: "MongoDB-Web",
    50000: "Hadoop", 50030: "Hadoop-JT", 50070: "Hadoop-NN",
    50075: "Hadoop-DN", 50090: "Hadoop-SNN", 61616: "ActiveMQ",
    61617: "ActiveMQ-Web",
}

# Risk database: port -> (risk_level, note)
RISK_MAP: dict[int, tuple[RiskLevel, str]] = {
    20: (RiskLevel.MEDIUM, "FTP data channel — often unencrypted"),
    21: (RiskLevel.HIGH, "FTP transmits credentials in plaintext"),
    22: (RiskLevel.LOW, "SSH is encrypted — ensure key-based auth"),
    23: (RiskLevel.HIGH, "Telnet transmits everything in plaintext"),
    25: (RiskLevel.MEDIUM, "SMTP — ensure TLS is enforced"),
    53: (RiskLevel.LOW, "DNS — monitor for amplification attacks"),
    67: (RiskLevel.MEDIUM, "DHCP — rogue server risk"),
    68: (RiskLevel.MEDIUM, "DHCP client — rogue server risk"),
    69: (RiskLevel.HIGH, "TFTP has no authentication"),
    80: (RiskLevel.MEDIUM, "HTTP — should redirect to HTTPS"),
    110: (RiskLevel.MEDIUM, "POP3 — ensure TLS is used"),
    111: (RiskLevel.MEDIUM, "RPCBind — can reveal service info"),
    123: (RiskLevel.LOW, "NTP — monitor for amplification"),
    135: (RiskLevel.MEDIUM, "MS-RPC — common attack vector on Windows"),
    137: (RiskLevel.MEDIUM, "NetBIOS — can leak host info"),
    138: (RiskLevel.MEDIUM, "NetBIOS — can leak host info"),
    139: (RiskLevel.MEDIUM, "NetBIOS-SSN — SMB over NetBIOS"),
    143: (RiskLevel.MEDIUM, "IMAP — ensure TLS is used"),
    161: (RiskLevel.HIGH, "SNMP — default community strings are common"),
    389: (RiskLevel.MEDIUM, "LDAP — use LDAPS instead"),
    443: (RiskLevel.LOW, "HTTPS — encrypted web traffic"),
    445: (RiskLevel.HIGH, "SMB — major attack vector (EternalBlue, etc.)"),
    514: (RiskLevel.MEDIUM, "Syslog — unencrypted log transport"),
    515: (RiskLevel.MEDIUM, "LPD — legacy print service"),
    587: (RiskLevel.LOW, "SMTP submission with TLS"),
    636: (RiskLevel.LOW, "LDAPS — encrypted directory access"),
    993: (RiskLevel.LOW, "IMAPS — encrypted IMAP"),
    995: (RiskLevel.LOW, "POP3S — encrypted POP3"),
    1080: (RiskLevel.MEDIUM, "SOCKS proxy — can be abused"),
    1433: (RiskLevel.HIGH, "MSSQL — ensure strong auth and firewall"),
    1434: (RiskLevel.HIGH, "MSSQL Monitor — used in SQL Slammer worm"),
    1521: (RiskLevel.MEDIUM, "Oracle DB — ensure patched"),
    2049: (RiskLevel.MEDIUM, "NFS — ensure proper export restrictions"),
    3306: (RiskLevel.HIGH, "MySQL — should not be publicly exposed"),
    3389: (RiskLevel.HIGH, "RDP — major attack vector, use VPN or NLA"),
    5432: (RiskLevel.HIGH, "PostgreSQL — should not be publicly exposed"),
    5900: (RiskLevel.HIGH, "VNC — often unencrypted, use SSH tunnel"),
    5901: (RiskLevel.HIGH, "VNC display :1 — same risks as :5900"),
    6379: (RiskLevel.HIGH, "Redis — no auth by default, major risk"),
    8000: (RiskLevel.MEDIUM, "HTTP alternate — check what is running"),
    8008: (RiskLevel.MEDIUM, "HTTP alternate — check what is running"),
    8080: (RiskLevel.MEDIUM, "HTTP proxy/alt — common for web apps"),
    8443: (RiskLevel.LOW, "HTTPS alternate — encrypted"),
    8888: (RiskLevel.MEDIUM, "HTTP alternate — check what is running"),
    9000: (RiskLevel.MEDIUM, "Dev tools — may expose source code"),
    9090: (RiskLevel.MEDIUM, "Web console — may expose management"),
    9200: (RiskLevel.HIGH, "Elasticsearch — no auth by default"),
    9300: (RiskLevel.MEDIUM, "ES transport — cluster communications"),
    11211: (RiskLevel.HIGH, "Memcached — no auth, used in DDoS amplification"),
    27017: (RiskLevel.HIGH, "MongoDB — no auth by default, major risk"),
    27018: (RiskLevel.MEDIUM, "MongoDB shard — check auth"),
    27019: (RiskLevel.MEDIUM, "MongoDB config server — check auth"),
    28017: (RiskLevel.MEDIUM, "MongoDB web interface — may expose data"),
}


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    risk: str
    risk_note: str


@dataclass
class ScanReport:
    target: str
    resolved_ip: str
    ports_scanned: int
    ports_open: int
    high_risk_count: int
    scan_time: float
    results: list[PortResult] = field(default_factory=list)
    error: Optional[str] = None


def get_service_name(port: int) -> str:
    return SERVICE_MAP.get(port, "Unknown")


def get_risk(port: int) -> tuple[RiskLevel, str]:
    if port in RISK_MAP:
        return RISK_MAP[port]
    return (RiskLevel.MEDIUM, "Unknown service — verify what is running")


def scan_port(ip: str, port: int, timeout: float = 1.0) -> PortResult:
    service = get_service_name(port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            risk_level, risk_note = get_risk(port)
            return PortResult(port=port, state=PortState.OPEN.value,
                              service=service, risk=risk_level.value, risk_note=risk_note)
        return PortResult(port=port, state=PortState.CLOSED.value,
                          service=service, risk=RiskLevel.LOW.value, risk_note="Port is closed")
    except socket.timeout:
        return PortResult(port=port, state=PortState.FILTERED.value,
                          service=service, risk=RiskLevel.LOW.value, risk_note="Filtered (timeout)")
    except Exception:
        return PortResult(port=port, state=PortState.CLOSED.value,
                          service=service, risk=RiskLevel.LOW.value, risk_note="Error scanning")


def resolve_host(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {target}")


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def scan_target(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    max_workers: int = 100,
    progress_callback=None,
) -> ScanReport:
    resolved_ip = resolve_host(target)
    total = len(ports)
    results: list[PortResult] = []
    scanned = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, resolved_ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            result = future.result()
            results.append(result)
            scanned += 1
            if progress_callback:
                progress_callback(scanned, total)

    elapsed = time.time() - start_time
    results.sort(key=lambda r: r.port)

    open_results = [r for r in results if r.state == PortState.OPEN.value]
    high_risk = [r for r in open_results if r.risk == RiskLevel.HIGH.value]

    return ScanReport(
        target=target, resolved_ip=resolved_ip,
        ports_scanned=total, ports_open=len(open_results),
        high_risk_count=len(high_risk), scan_time=round(elapsed, 2),
        results=results,
    )
