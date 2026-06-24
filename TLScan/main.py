"""TLScan — CLI entry point with Rich panels.

Usage:
    python main.py <domain>
    python main.py <domain> --port 8443
    python main.py <domain> --json
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich import box
from rich.prompt import Confirm

from connector import connect_ssl
from protocol_tester import test_protocols
from cipher_enumerator import enumerate_ciphers
from vuln_checks import check_all_vulnerabilities
from grader import calculate_grade
from database import init_db, save_scan

console = Console()


def severity_color(severity: str) -> str:
    return {"CRITICAL": "bold red", "HIGH": "bold orange", "MEDIUM": "bold yellow",
            "LOW": "bold blue", "GOOD": "bold green", "EXCELLENT": "bold green",
            "INFO": "dim"}.get(severity, "white")


def display_cert_chain(certificates: list) -> None:
    """Display certificate chain as a tree."""
    if not certificates:
        console.print("[yellow]No certificates retrieved.[/]")
        return

    table = Table(show_header=True, header_style="bold white", box=box.SIMPLE)
    table.add_column("Position", min_width=8)
    table.add_column("Subject CN", min_width=30)
    table.add_column("Issuer CN", min_width=30)
    table.add_column("Expires", min_width=12)
    table.add_column("Key", min_width=10)
    table.add_column("Status", min_width=10)

    for cert in certificates:
        status = ""
        if cert.is_self_signed:
            status = "[yellow]Self-signed[/]"
        if cert.days_until_expiry < 0:
            status = "[red]EXPIRED[/]"
        elif cert.days_until_expiry < 30:
            status = "[yellow]Expiring[/]"

        pos = "Leaf" if cert.position == 0 else f"Intermediate {cert.position}"
        table.add_row(
            pos, cert.subject_cn, cert.issuer_cn,
            str(cert.days_until_expiry),
            f"{cert.key_type}-{cert.key_size}" if cert.key_size else "Unknown",
            status,
        )

    console.print(table)


def display_protocols(protocols: list) -> None:
    """Display protocol support table."""
    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED)
    table.add_column("Protocol", min_width=12)
    table.add_column("Supported", min_width=10, justify="center")
    table.add_column("Risk", min_width=10, justify="center")
    table.add_column("Cipher", min_width=30)

    for p in protocols:
        color = severity_color(p.risk)
        supported = "[green]YES[/]" if p.supported else "[red]NO[/]"
        table.add_row(p.protocol, supported, f"[{color}]{p.risk}[/]", p.cipher or "—")

    console.print(table)


def display_ciphers(ciphers: list) -> None:
    """Display cipher suite results."""
    accepted = [c for c in ciphers if c.accepted]
    if not accepted:
        console.print("[yellow]No ciphers enumerated.[/]")
        return

    table = Table(show_header=True, header_style="bold white", box=box.SIMPLE)
    table.add_column("Protocol", min_width=10)
    table.add_column("Cipher", min_width=40)
    table.add_column("Category", min_width=10, justify="center")
    table.add_column("FS", min_width=4, justify="center")

    for c in accepted[:30]:  # Limit display
        color = severity_color(c.category)
        fs = "[green]✓[/]" if c.forward_secrecy else "[red]✗[/]"
        table.add_row(c.protocol, c.cipher[:50], f"[{color}]{c.category}[/]", fs)

    console.print(table)

    # Summary
    secure = sum(1 for c in accepted if c.category == "SECURE")
    weak = sum(1 for c in accepted if c.category == "WEAK")
    insecure = sum(1 for c in accepted if c.category == "INSECURE")
    console.print(f"\n  [bold]Summary: [/][green]{secure} secure[/]  [yellow]{weak} weak[/]  [red]{insecure} insecure[/]")


def display_vulnerabilities(vulns: list) -> None:
    """Display vulnerability check results."""
    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED)
    table.add_column("Vulnerability", min_width=20)
    table.add_column("CVE", min_width=16)
    table.add_column("Status", min_width=10, justify="center")
    table.add_column("Severity", min_width=10, justify="center")
    table.add_column("Detail", min_width=30)

    for v in vulns:
        color = severity_color(v.severity)
        status = "[red]VULNERABLE[/]" if v.vulnerable else "[green]PASS[/]"
        table.add_row(v.name, v.cve, status, f"[{color}]{v.severity}[/]", v.detail[:50])

    console.print(table)


def display_grade(grade_result) -> None:
    """Display final grade panel."""
    grade_colors = {"A+": "bold green", "A": "bold green", "B": "bold blue",
                    "C": "bold yellow", "D": "bold orange", "F": "bold red"}
    color = grade_colors.get(grade_result.grade, "white")

    text = Text()
    text.append(f"Grade: {grade_result.grade}\n", style=color)
    text.append(f"Score: {grade_result.score}/100\n", style="bold")
    if grade_result.cap_reason:
        text.append(f"Cap: {grade_result.cap_reason}\n", style="yellow")
    if grade_result.deductions:
        text.append(f"\nDeductions:\n", style="bold")
        for d in grade_result.deductions[:10]:
            text.append(f"  - {d}\n", style="dim")

    console.print(Panel(text, title="[bold]Final Grade[/]", border_style=color.split()[-1]))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TLScan — SSL/TLS security scanner",
        epilog="Example: python main.py example.com",
    )
    parser.add_argument("domain", help="Target domain or IP")
    parser.add_argument("--port", "-p", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    parser.add_argument("--proxy", type=str, default=None, help="Proxy (host:port)")
    parser.add_argument("--ipv6", action="store_true", help="Force IPv6")
    parser.add_argument("--save", type=str, default=None, help="Save report to file")
    parser.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer")
    args = parser.parse_args()

    if not args.no_disclaimer:
        if not Confirm.ask("[bold]Do you have authorization to scan this domain?[/]", default=False):
            console.print("[dim]Scan cancelled.[/]")
            sys.exit(0)

    domain = args.domain.strip()
    init_db()

    start_time = time.time()

    # Connect
    console.print(f"\n[dim]Connecting to {domain}:{args.port}...[/]")
    conn_result = connect_ssl(domain, args.port, proxy=args.proxy, ipv6=args.ipv6)

    if not conn_result.success:
        console.print(f"[red]Connection failed: {conn_result.error}[/]")
        sys.exit(1)

    # Certificate chain
    console.print("[dim]Analyzing certificate chain...[/]")
    certificates = conn_result.certificates

    # Protocol testing
    console.print("[dim]Testing protocol versions...[/]")
    protocols = test_protocols(domain, args.port)

    # Cipher enumeration
    console.print("[dim]Enumerating cipher suites...[/]")
    ciphers = enumerate_ciphers(domain, args.port)

    # Vulnerability checks
    console.print("[dim]Running vulnerability checks...[/]")
    vulnerabilities = check_all_vulnerabilities(domain, args.port, protocols, ciphers)

    # Grade
    grade_result = calculate_grade(certificates, protocols, ciphers, vulnerabilities)

    duration = time.time() - start_time

    # Display results
    console.print()
    console.rule(f"[bold cyan]TLScan — {domain}:{args.port}", style="cyan")
    console.print()

    console.print(Panel(
        f"IP: {conn_result.ip_address}\nSSL Version: {conn_result.ssl_version}\n"
        f"Cipher: {conn_result.cipher[0] if conn_result.cipher else 'N/A'}\n"
        f"Connect: {conn_result.connect_time}s | Handshake: {conn_result.handshake_time}s",
        title="[bold]Connection Info[/]", border_style="cyan",
    ))

    console.print()
    console.print("[bold]Certificate Chain:[/]")
    display_cert_chain(certificates)

    console.print()
    console.print("[bold]Protocol Support:[/]")
    display_protocols(protocols)

    console.print()
    console.print("[bold]Cipher Suites:[/]")
    display_ciphers(ciphers)

    console.print()
    console.print("[bold]Vulnerability Checks:[/]")
    display_vulnerabilities(vulns)

    console.print()
    display_grade(grade_result)

    console.print(f"\n  [dim]Scan completed in {duration:.1f}s[/]")

    # Save to database
    scan_id = save_scan(domain, args.port, grade_result.grade, grade_result.score,
                         duration, certificates, protocols, ciphers, vulnerabilities)

    # Save JSON if requested
    if args.save:
        report = {
            "domain": domain, "port": args.port,
            "scan_id": scan_id, "duration": round(duration, 2),
            "grade": grade_result.grade, "score": grade_result.score,
            "certificates": [{"subject_cn": c.subject_cn, "issuer_cn": c.issuer_cn,
                              "days_until_expiry": c.days_until_expiry, "key_size": c.key_size}
                             for c in certificates],
            "protocols": [{"protocol": p.protocol, "supported": p.supported, "risk": p.risk}
                          for p in protocols],
            "ciphers": [{"cipher": c.cipher, "category": c.category, "forward_secrecy": c.forward_secrecy}
                        for c in ciphers if c.accepted],
            "vulnerabilities": [{"name": v.name, "cve": v.cve, "vulnerable": v.vulnerable,
                                 "severity": v.severity} for v in vulnerabilities],
        }
        with open(args.save, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        console.print(f"\n[green]Report saved to {args.save}[/]")


if __name__ == "__main__":
    main()
