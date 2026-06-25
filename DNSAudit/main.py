"""DNSAudit - Comprehensive DNS Security Auditor

Usage:
    python main.py <domain>
    python main.py <domain> --resolver 8.8.8.8
    python main.py <domain> --output report.json
    python main.py bulk --file domains.txt
    python main.py dashboard
"""

from __future__ import annotations

import argparse
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Confirm

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="DNSAudit - Comprehensive DNS Security Auditor",
        epilog="Example: python main.py example.com",
    )
    parser.add_argument("domain", nargs="?", help="Domain to audit")
    parser.add_argument("--resolver", "-r", type=str, default=None,
                        help="DNS resolver (8.8.8.8, 1.1.1.1, 9.9.9.9, or custom IP)")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output file (.json, .csv, .pdf)")
    parser.add_argument("--brief", action="store_true", help="Show only failures")
    parser.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer")
    parser.add_argument("--categories", "-c", type=str, default=None,
                        help="Comma-separated categories to run (default: all)")

    # Bulk subcommand
    subparsers = parser.add_subparsers(dest="command")
    bulk_parser = subparsers.add_parser("bulk", help="Bulk domain scanning")
    bulk_parser.add_argument("--file", "-f", type=str, required=True, help="File with domains")
    bulk_parser.add_argument("--output", "-o", type=str, default="bulk_results.json",
                             help="Output file")
    bulk_parser.add_argument("--workers", "-w", type=int, default=5, help="Worker threads")

    # Dashboard subcommand
    dashboard_parser = subparsers.add_parser("dashboard", help="Launch web dashboard")
    dashboard_parser.add_argument("--port", type=int, default=5900, help="Dashboard port")

    args = parser.parse_args()

    if not args.command and not args.domain:
        parser.print_help()
        sys.exit(1)

    if not args.no_disclaimer:
        if not Confirm.ask("[bold]Do you have authorization to audit this domain?[/]", default=False):
            console.print("[dim]Scan cancelled.[/]")
            sys.exit(0)

    if args.command == "bulk":
        from bulk import run_bulk_scan
        run_bulk_scan(args.file, args.output, args.workers)
    elif args.command == "dashboard":
        from dashboard.app import main as run_dashboard
        run_dashboard(port=args.port)
    else:
        run_single_scan(args)


def run_single_scan(args):
    """Run a single domain scan."""
    from resolver import DNSResolver
    from scorer import calculate_grade, calculate_score
    from database import init_db, save_scan

    domain = args.domain.strip().lower().rstrip(".")
    resolver = DNSResolver(custom_resolver=args.resolver)

    start_time = time.time()

    console.print()
    console.rule(f"[bold cyan]DNSAudit - {domain}", style="cyan")
    console.print()

    # Import audit modules
    from audits.spf import audit_spf
    from audits.dkim import audit_dkim
    from audits.dmarc import audit_dmarc
    from audits.dnssec import audit_dnssec
    from audits.zone_transfer import audit_zone_transfer
    from audits.takeover import audit_takeover
    from audits.hijacking import audit_hijacking
    from audits.mail_server import audit_mail_server
    from audits.nameserver import audit_nameserver
    from audits.caa import audit_caa
    from audits.inventory import audit_inventory
    from audits.dane import audit_dane

    categories = {
        "SPF": audit_spf,
        "DKIM": audit_dkim,
        "DMARC": audit_dmarc,
        "DNSSEC": audit_dnssec,
        "Zone Transfer": audit_zone_transfer,
        "Subdomain Takeover": audit_takeover,
        "DNS Hijacking": audit_hijacking,
        "Mail Server": audit_mail_server,
        "Nameserver": audit_nameserver,
        "CAA": audit_caa,
        "DNS Inventory": audit_inventory,
        "DANE/TLSA": audit_dane,
    }

    if args.categories:
        selected = [c.strip() for c in args.categories.split(",")]
        categories = {k: v for k, v in categories.items() if k in selected}

    results = {}
    all_findings = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(categories))

        for name, audit_func in categories.items():
            progress.update(task, description=f"Scanning {name}...")
            try:
                result = audit_func(domain, resolver.resolver)
                results[name] = result
                # Extract findings
                if hasattr(result, 'findings'):
                    all_findings[name] = [
                        {
                            "check": f.check if hasattr(f, 'check') else "",
                            "severity": f.severity if hasattr(f, 'severity') else f.get("severity", ""),
                            "title": f.title if hasattr(f, 'title') else f.get("title", ""),
                            "description": f.description if hasattr(f, 'description') else f.get("description", ""),
                            "recommendation": f.recommendation if hasattr(f, 'recommendation') else f.get("recommendation", ""),
                        }
                        for f in result.findings
                    ]
                elif isinstance(result, dict):
                    all_findings[name] = result.get("findings", [])
            except Exception as e:
                all_findings[name] = [{"check": "Error", "severity": "WARNING",
                                        "title": f"{name} scan failed",
                                        "description": str(e)}]
            progress.advance(task)

    duration = time.time() - start_time

    # Calculate scores
    category_scores = {}
    for name, result in results.items():
        if hasattr(result, 'findings'):
            findings = result.findings
        elif isinstance(result, dict):
            findings = result.get("findings", [])
        else:
            findings = []
        category_scores[name] = calculate_score(findings)

    overall_score = sum(category_scores.values())
    grade = calculate_grade(overall_score, all_findings)

    # Display results
    console.print()
    console.print(Panel(
        f"[bold]Grade: {grade}[/]  Score: {overall_score}/120\n"
        f"Duration: {duration:.1f}s  Resolver: {args.resolver or 'system'}",
        title="[bold]Scan Complete[/]",
        border_style="green" if overall_score >= 70 else "yellow" if overall_score >= 40 else "red",
    ))

    # Summary table
    table = Table(show_header=True, header_style="bold white")
    table.add_column("Category", min_width=18)
    table.add_column("Score", min_width=8, justify="center")
    table.add_column("Critical", min_width=8, justify="center")
    table.add_column("High", min_width=8, justify="center")
    table.add_column("Medium", min_width=8, justify="center")

    for name, score in category_scores.items():
        findings = all_findings.get(name, [])
        crit = sum(1 for f in findings if (f.get("severity", "") == "CRITICAL"))
        high = sum(1 for f in findings if (f.get("severity", "") == "HIGH"))
        med = sum(1 for f in findings if (f.get("severity", "") == "MEDIUM"))
        table.add_row(name, str(score), str(crit), str(high), str(med))

    console.print(table)

    # Save to database
    init_db()
    save_scan(domain, args.resolver or "system", grade, overall_score, duration, all_findings)

    # Export
    if args.output:
        output_path = args.output
        if output_path.endswith(".json"):
            import json
            with open(output_path, "w") as f:
                json.dump({
                    "domain": domain,
                    "grade": grade,
                    "score": overall_score,
                    "duration": duration,
                    "findings": all_findings,
                }, f, indent=2, default=str)
        elif output_path.endswith(".pdf"):
            from reporter import generate_pdf_report
            generate_pdf_report(domain, all_findings, output_path, grade, overall_score)
        console.print(f"\n[green]Report saved to {output_path}[/]")


if __name__ == "__main__":
    main()
