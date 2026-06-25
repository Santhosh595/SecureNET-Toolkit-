"""
Mail Server Security Audit Module - Category 8
DNSAudit Tool

Audits MX records, PTR records, TLS configuration, and open relay status
of mail servers associated with a domain.
"""

import socket
import ssl
import smtplib
import dns.resolver
import dns.reversename
import dns.exception
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class Severity(Enum):
    """Finding severity levels."""
    GOOD = "GOOD"
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    """A single audit finding."""
    title: str
    description: str
    severity: Severity
    category: str = "mail_server"
    details: Optional[Dict[str, Any]] = None


@dataclass
class TLSServerInfo:
    """TLS information for a single MX server."""
    server: str
    port: int
    port_open: bool = False
    starttls_supported: bool = False
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    cipher_bits: Optional[int] = None
    certificate_valid: Optional[bool] = None
    certificate_issuer: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_expiry: Optional[str] = None
    banner: Optional[str] = None
    open_relay: Optional[bool] = None
    open_relay_detail: Optional[str] = None
    errors: List[str] = field(default_factory=list)


@dataclass
class MXRecordInfo:
    """Information about a single MX record."""
    hostname: str
    priority: int
    resolved_ips: List[str] = field(default_factory=list)
    ptr_records: Dict[str, List[str]] = field(default_factory=dict)
    missing_ptr: bool = False
    is_cname: bool = False
    same_as_webserver: bool = False
    tls: Optional[TLSServerInfo] = None


@dataclass
class MailServerAuditResult:
    """Complete result of a mail server audit."""
    domain: str
    mx_records: List[MXRecordInfo] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    web_server_ips: List[str] = field(default_factory=list)
    total_mx: int = 0


def resolve_a_records(hostname: str) -> List[str]:
    """Resolve A records for a hostname."""
    ips = []
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        for rdata in answers:
            ips.append(str(rdata))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    return ips


def resolve_ptr_record(ip: str) -> List[str]:
    """Resolve PTR record for an IP address."""
    ptr_records = []
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        for rdata in answers:
            ptr_records.append(str(rdata).rstrip('.'))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.exception.SyntaxError):
        pass
    return ptr_records


def check_cname(hostname: str) -> bool:
    """Check if a hostname resolves to a CNAME (not directly to A record)."""
    try:
        answers = dns.resolver.resolve(hostname, 'CNAME')
        return len(answers) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return False


def grab_banner(server: str, port: int, timeout: int = 10) -> Optional[str]:
    """Grab the SMTP banner from a server."""
    try:
        sock = socket.create_connection((server, port), timeout=timeout)
        banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
        sock.close()
        return banner
    except (socket.timeout, socket.error, OSError):
        return None


def check_port_open(server: str, port: int, timeout: int = 10) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.create_connection((server, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, socket.error, OSError):
        return False


def check_starttls_and_tls(server: str, port: int, timeout: int = 10) -> TLSServerInfo:
    """
    Check STARTTLS support, TLS version, cipher, and certificate info.
    Returns a TLSServerInfo object with findings.
    """
    tls_info = TLSServerInfo(server=server, port=port)

    try:
        # First, try direct TLS connection (for implicit TLS on 465, etc.)
        # For port 25, we use STARTTLS
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((server, port), timeout=timeout)

        if port == 25 or port == 587:
            # Read banner first
            try:
                banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
                tls_info.banner = banner
            except socket.error:
                pass

            # Send EHLO
            sock.send(b'EHLO audit.local\r\n')
            try:
                sock.recv(1024)
            except socket.error:
                pass

            # Send STARTTLS
            sock.send(b'STARTTLS\r\n')
            response = sock.recv(1024).decode('utf-8', errors='replace').strip()

            if '220' in response:
                tls_info.starttls_supported = True
                # Wrap socket with TLS
                secure_sock = context.wrap_socket(sock, server_hostname=server)
                tls_info.tls_version = secure_sock.version()
                cipher_info = secure_sock.cipher()
                if cipher_info:
                    tls_info.cipher = cipher_info[0]
                    tls_info.cipher_bits = cipher_info[2]

                # Get certificate info
                try:
                    cert = secure_sock.getpeercert()
                    if cert:
                        tls_info.certificate_valid = True
                        subject = dict(x[0] for x in cert.get('subject', ()))
                        tls_info.certificate_subject = subject.get('commonName', '')
                        issuer = dict(x[0] for x in cert.get('issuer', ()))
                        tls_info.certificate_issuer = issuer.get('commonName', '')
                        tls_info.certificate_expiry = cert.get('notAfter', '')
                except Exception:
                    tls_info.certificate_valid = False

                secure_sock.close()
            else:
                tls_info.starttls_supported = False
                tls_info.errors.append(f"STARTTLS not supported: {response}")
                sock.close()
        else:
            # Direct TLS (ports like 465)
            secure_sock = context.wrap_socket(sock, server_hostname=server)
            tls_info.starttls_supported = True
            tls_info.tls_version = secure_sock.version()
            cipher_info = secure_sock.cipher()
            if cipher_info:
                tls_info.cipher = cipher_info[0]
                tls_info.cipher_bits = cipher_info[2]
            try:
                cert = secure_sock.getpeercert()
                if cert:
                    tls_info.certificate_valid = True
                    subject = dict(x[0] for x in cert.get('subject', ()))
                    tls_info.certificate_subject = subject.get('commonName', '')
                    issuer = dict(x[0] for x in cert.get('issuer', ()))
                    tls_info.certificate_issuer = issuer.get('commonName', '')
                    tls_info.certificate_expiry = cert.get('notAfter', '')
            except Exception:
                tls_info.certificate_valid = False
            secure_sock.close()

    except ssl.SSLError as e:
        tls_info.errors.append(f"SSL Error: {str(e)}")
    except socket.timeout:
        tls_info.errors.append("Connection timeout")
    except socket.error as e:
        tls_info.errors.append(f"Socket error: {str(e)}")
    except Exception as e:
        tls_info.errors.append(f"Error: {str(e)}")

    return tls_info


def test_open_relay(server: str, port: int, timeout: int = 10) -> tuple:
    """
    Test if a server is an open relay.
    Attempts RCPT TO with an external domain and checks the response.
    Returns (is_open_relay: bool, detail: str)
    """
    try:
        sock = socket.create_connection((server, port), timeout=timeout)

        # Read banner
        try:
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
        except socket.error:
            sock.close()
            return None, "Could not read banner"

        # Send EHLO
        sock.send(b'EHLO audit.local\r\n')
        try:
            sock.recv(1024)
        except socket.error:
            pass

        # Try STARTTLS first (for port 25)
        if port == 25 or port == 587:
            sock.send(b'STARTTLS\r\n')
            response = sock.recv(1024).decode('utf-8', errors='replace').strip()
            if '220' in response:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    sock = context.wrap_socket(sock, server_hostname=server)
                except ssl.SSLError:
                    pass
                else:
                    # Re-send EHLO after TLS
                    sock.send(b'EHLO audit.local\r\n')
                    try:
                        sock.recv(1024)
                    except socket.error:
                        pass

        # MAIL FROM with external sender
        sock.send(b'MAIL FROM:<test@external-domain-example.com>\r\n')
        try:
            mail_from_resp = sock.recv(1024).decode('utf-8', errors='replace').strip()
        except socket.error:
            sock.close()
            return None, "No response to MAIL FROM"

        if not mail_from_resp.startswith('250'):
            sock.send(b'QUIT\r\n')
            sock.close()
            return False, f"MAIL FROM rejected: {mail_from_resp}"

        # RCPT TO with external recipient - this is the relay test
        sock.send(b'RCPT TO:<relay-test@external-domain-example.com>\r\n')
        try:
            rcpt_resp = sock.recv(1024).decode('utf-8', errors='replace').strip()
        except socket.error:
            sock.send(b'QUIT\r\n')
            sock.close()
            return None, "No response to RCPT TO"

        # Clean up
        sock.send(b'QUIT\r\n')
        try:
            sock.recv(1024)
        except socket.error:
            pass
        sock.close()

        if rcpt_resp.startswith('250'):
            return True, f"OPEN RELAY - RCPT TO accepted: {rcpt_resp}"
        elif rcpt_resp.startswith('550'):
            return False, f"Relay rejected (550): {rcpt_resp}"
        elif rcpt_resp.startswith('551') or rcpt_resp.startswith('552'):
            return False, f"Relay rejected (relay not permitted): {rcpt_resp}"
        else:
            return False, f"RCPT TO response: {rcpt_resp}"

    except socket.timeout:
        return None, "Connection timeout during relay test"
    except socket.error as e:
        return None, f"Socket error: {str(e)}"
    except Exception as e:
        return None, f"Error: {str(e)}"


def audit_mail_server(domain: str, web_server_ips: Optional[List[str]] = None,
                       test_port: int = 25, timeout: int = 10) -> MailServerAuditResult:
    """
    Perform a complete mail server security audit for a domain.

    Args:
        domain: The domain to audit
        web_server_ips: Optional list of web server IPs for comparison
        test_port: Port to test (default 25)
        timeout: Connection timeout in seconds

    Returns:
        MailServerAuditResult with all findings
    """
    result = MailServerAuditResult(domain=domain)
    if web_server_ips:
        result.web_server_ips = web_server_ips

    # --- Step 1: Query MX records ---
    mx_records_raw = []
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        for rdata in mx_answers:
            mx_records_raw.append({
                'hostname': str(rdata.exchange).rstrip('.'),
                'priority': int(rdata.preference)
            })
    except dns.resolver.NoAnswer:
        result.findings.append(Finding(
            title="No MX Records Found",
            description=f"Domain {domain} has no MX records. Email delivery will fail.",
            severity=Severity.HIGH,
            details={"domain": domain}
        ))
        return result
    except dns.resolver.NXDOMAIN:
        result.findings.append(Finding(
            title="Domain Does Not Exist",
            description=f"Domain {domain} does not exist (NXDOMAIN).",
            severity=Severity.CRITICAL,
            details={"domain": domain}
        ))
        return result
    except dns.exception.Timeout:
        result.findings.append(Finding(
            title="DNS Timeout",
            description=f"DNS query for {domain} MX records timed out.",
            severity=Severity.WARNING,
            details={"domain": domain}
        ))
        return result
    except Exception as e:
        result.findings.append(Finding(
            title="MX Record Query Failed",
            description=f"Failed to query MX records for {domain}: {str(e)}",
            severity=Severity.WARNING,
            details={"domain": domain, "error": str(e)}
        ))
        return result

    result.total_mx = len(mx_records_raw)

    # --- Step 2: MX Priority Configuration Check ---
    if len(mx_records_raw) == 1:
        result.findings.append(Finding(
            title="Single MX Record (No Redundancy)",
            description=f"Domain {domain} has only one MX record. This creates a single point of failure.",
            severity=Severity.WARNING,
            details={"mx_hostname": mx_records_raw[0]['hostname'], "priority": mx_records_raw[0]['priority']}
        ))
    else:
        # Check if priorities are the same (good for load balancing)
        priorities = set(r['priority'] for r in mx_records_raw)
        if len(priorities) == 1:
            result.findings.append(Finding(
                title="Multiple MX Records with Equal Priority",
                description=f"Domain {domain} has {len(mx_records_raw)} MX records with equal priority for load balancing.",
                severity=Severity.GOOD,
                details={"count": len(mx_records_raw), "priority": list(priorities)[0]}
            ))
        else:
            result.findings.append(Finding(
                title="Multiple MX Records with Different Priorities",
                description=f"Domain {domain} has {len(mx_records_raw)} MX records configured with backup priorities.",
                severity=Severity.GOOD,
                details={"count": len(mx_records_raw), "priorities": sorted(priorities)}
            ))

    # --- Step 3: Process each MX record ---
    for mx_raw in mx_records_raw:
        hostname = mx_raw['hostname']
        priority = mx_raw['priority']

        mx_info = MXRecordInfo(hostname=hostname, priority=priority)

        # Resolve A records for the MX hostname
        resolved_ips = resolve_a_records(hostname)
        mx_info.resolved_ips = resolved_ips

        if not resolved_ips:
            result.findings.append(Finding(
                title="MX Hostname Does Not Resolve",
                description=f"MX record hostname {hostname} does not resolve to any IP address.",
                severity=Severity.HIGH,
                details={"hostname": hostname, "priority": priority}
            ))
            result.mx_records.append(mx_info)
            continue

        # Check if MX hostname is a CNAME
        if check_cname(hostname):
            mx_info.is_cname = True
            result.findings.append(Finding(
                title="MX Points to CNAME",
                description=f"MX record {hostname} points to a CNAME. RFC 5321 discourages CNAME in MX records.",
                severity=Severity.HIGH,
                details={"hostname": hostname}
            ))

        # Check if MX IP matches web server
        if web_server_ips:
            for ip in resolved_ips:
                if ip in web_server_ips:
                    mx_info.same_as_webserver = True
                    result.findings.append(Finding(
                        title="MX IP Same as Web Server",
                        description=f"MX server {hostname} ({ip}) is the same as the web server. This may indicate a single point of failure or shared infrastructure.",
                        severity=Severity.WARNING,
                        details={"hostname": hostname, "ip": ip}
                    ))
                    break

        # Check PTR records for each resolved IP
        for ip in resolved_ips:
            ptrs = resolve_ptr_record(ip)
            mx_info.ptr_records[ip] = ptrs
            if not ptrs:
                mx_info.missing_ptr = True
                result.findings.append(Finding(
                    title="Missing PTR Record",
                    description=f"MX server {hostname} ({ip}) has no PTR (reverse DNS) record. This may cause email delivery issues and spam filtering.",
                    severity=Severity.HIGH,
                    details={"hostname": hostname, "ip": ip}
                ))

        # --- Step 4: Per-server checks ---
        for ip in resolved_ips:
            # Check port open
            port_open = check_port_open(ip, test_port, timeout=timeout)

            if port_open:
                # TLS / STARTTLS check
                tls_info = check_starttls_and_tls(ip, test_port, timeout=timeout)
                tls_info.port_open = True

                if tls_info.banner and not result.findings:
                    pass  # Banner captured

                if not tls_info.starttls_supported:
                    result.findings.append(Finding(
                        title="STARTTLS Not Supported",
                        description=f"Mail server {hostname} ({ip}) does not support STARTTLS. Email is transmitted in plaintext.",
                        severity=Severity.HIGH,
                        details={"hostname": hostname, "ip": ip, "port": test_port}
                    ))
                else:
                    # Check TLS version
                    if tls_info.tls_version:
                        if 'TLSv1.0' in tls_info.tls_version or 'TLSv1.1' in tls_info.tls_version:
                            result.findings.append(Finding(
                                title="Deprecated TLS Version",
                                description=f"Mail server {hostname} ({ip}) uses {tls_info.tls_version}. TLS 1.0/1.1 are deprecated.",
                                severity=Severity.HIGH,
                                details={"hostname": hostname, "ip": ip, "tls_version": tls_info.tls_version}
                            ))
                        elif 'TLSv1.2' in tls_info.tls_version:
                            result.findings.append(Finding(
                                title="TLS 1.2 Supported",
                                description=f"Mail server {hostname} ({ip}) uses TLS 1.2.",
                                severity=Severity.GOOD,
                                details={"hostname": hostname, "ip": ip, "tls_version": tls_info.tls_version}
                            ))
                        elif 'TLSv1.3' in tls_info.tls_version:
                            result.findings.append(Finding(
                                title="TLS 1.3 Supported",
                                description=f"Mail server {hostname} ({ip}) uses TLS 1.3 (latest).",
                                severity=Severity.GOOD,
                                details={"hostname": hostname, "ip": ip, "tls_version": tls_info.tls_version}
                            ))

                    # Check cipher strength
                    if tls_info.cipher_bits and tls_info.cipher_bits < 128:
                        result.findings.append(Finding(
                            title="Weak Cipher",
                            description=f"Mail server {hostname} ({ip}) uses weak cipher ({tls_info.cipher_bits}-bit).",
                            severity=Severity.HIGH,
                            details={"hostname": hostname, "ip": ip, "cipher": tls_info.cipher, "bits": tls_info.cipher_bits}
                        ))

                # Banner finding
                if tls_info.banner:
                    result.findings.append(Finding(
                        title="SMTP Banner Exposed",
                        description=f"Mail server {hostname} ({ip}) exposes banner: {tls_info.banner[:100]}",
                        severity=Severity.INFO,
                        details={"hostname": hostname, "ip": ip, "banner": tls_info.banner}
                    ))

                # Open relay test
                is_relay, relay_detail = test_open_relay(ip, test_port, timeout=timeout)
                tls_info.open_relay = is_relay
                tls_info.open_relay_detail = relay_detail

                if is_relay is True:
                    result.findings.append(Finding(
                        title="Open Relay Detected",
                        description=f"Mail server {hostname} ({ip}) appears to be an open relay. This is a serious security risk.",
                        severity=Severity.CRITICAL,
                        details={"hostname": hostname, "ip": ip, "detail": relay_detail}
                    ))
                elif is_relay is False:
                    result.findings.append(Finding(
                        title="Relay Restricted",
                        description=f"Mail server {hostname} ({ip}) rejects external relay attempts.",
                        severity=Severity.GOOD,
                        details={"hostname": hostname, "ip":ip, "detail": relay_detail}
                    ))

                mx_info.tls = tls_info
            else:
                result.findings.append(Finding(
                    title="Port 25 Closed",
                    description=f"Mail server {hostname} ({ip}) has port {test_port} closed.",
                    severity=Severity.WARNING,
                    details={"hostname": hostname, "ip": ip, "port": test_port}
                ))
                mx_info.tls = TLSServerInfo(server=ip, port=test_port, port_open=False)

        result.mx_records.append(mx_info)

    # --- Summary finding ---
    if result.total_mx > 0 and not any(f.severity == Severity.CRITICAL for f in result.findings):
        critical_count = sum(1 for f in result.findings if f.severity == Severity.HIGH)
        if critical_count == 0:
            result.findings.insert(0, Finding(
                title="Mail Server Audit Complete",
                description=f"Domain {domain} has {result.total_mx} MX record(s). No critical issues found.",
                severity=Severity.GOOD,
                details={"domain": domain, "mx_count": result.total_mx}
            ))

    return result


def format_audit_report(result: MailServerAuditResult) -> str:
    """Format the audit result as a human-readable report."""
    lines = []
    lines.append(f"{'='*60}")
    lines.append(f"  Mail Server Security Audit Report")
    lines.append(f"  Domain: {result.domain}")
    lines.append(f"{'='*60}")
    lines.append("")

    # MX Records Summary
    lines.append(f"MX Records Found: {result.total_mx}")
    for mx in result.mx_records:
        lines.append(f"  - {mx.hostname} (Priority: {mx.priority})")
        if mx.resolved_ips:
            for ip in mx.resolved_ips:
                ptr = mx.ptr_records.get(ip, [])
                ptr_str = ', '.join(ptr) if ptr else 'MISSING'
                lines.append(f"      IP: {ip} | PTR: {ptr_str}")
        else:
            lines.append(f"      [DOES NOT RESOLVE]")
    lines.append("")

    # Findings
    lines.append(f"Findings ({len(result.findings)}):")
    lines.append(f"{'-'*40}")

    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.WARNING, Severity.INFO, Severity.GOOD]
    for sev in severity_order:
        sev_findings = [f for f in result.findings if f.severity == sev]
        for finding in sev_findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "WARNING": "🟡", "INFO": "🔵", "GOOD": "🟢"}
            lines.append(f"  {icon.get(sev.value, '•')} [{sev.value}] {finding.title}")
            lines.append(f"      {finding.description}")
            if finding.details:
                for k, v in finding.details.items():
                    lines.append(f"      {k}: {v}")
            lines.append("")

    # Per-Server TLS Summary
    lines.append(f"{'-'*40}")
    lines.append("Per-Server TLS & Relay Status:")
    for mx in result.mx_records:
        if mx.tls:
            t = mx.tls
            lines.append(f"  Server: {mx.hostname}")
            lines.append(f"    Port Open: {'Yes' if t.port_open else 'No'}")
            lines.append(f"    STARTTLS: {'Yes' if t.starttls_supported else 'No'}")
            lines.append(f"    TLS Version: {t.tls_version or 'N/A'}")
            lines.append(f"    Cipher: {t.cipher or 'N/A'} ({t.cipher_bits or '?'} bits)")
            lines.append(f"    Banner: {t.banner or 'N/A'}")
            lines.append(f"    Open Relay: {'YES ⚠️' if t.open_relay else 'No' if t.open_relay is False else 'Unknown'}")
            if t.open_relay_detail:
                lines.append(f"    Relay Detail: {t.open_relay_detail}")
            if t.errors:
                for err in t.errors:
                    lines.append(f"    Error: {err}")
            lines.append("")

    lines.append(f"{'='*60}")
    return '\n'.join(lines)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python mail_server.py <domain> [web_server_ip]")
        print("Example: python mail_server.py example.com 93.184.216.34")
        sys.exit(1)

    target_domain = sys.argv[1]
    web_ips = sys.argv[2:] if len(sys.argv) > 2 else None

    print(f"[*] Auditing mail servers for: {target_domain}")
    print(f"[*] Web server IPs: {web_ips or 'Not provided'}")
    print()

    audit_result = audit_mail_server(target_domain, web_server_ips=web_ips)
    report = format_audit_report(audit_result)
    print(report)
