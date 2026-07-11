"""CloudSentry — CLI entry point.

Usage:
    python main.py                         # audit all providers (INFO mode w/o creds)
    python main.py --provider aws
    python main.py --provider aws --provider gcp
    python main.py --provider aws --profile default --region us-east-1
    python main.py --info                  # force INFO mode (list checks)
    python main.py --output report.json    # export
    python main.py --all-regions

Always read-only. Without credentials it runs in INFO mode and never prompts.
"""

from __future__ import annotations

import argparse
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

import database as db
from catalog import CHECKS
from models import severity_counts
from compliance.cis_mapping import score as cis_score
from compliance.owasp_mapping import score as owasp_score
from info_mode import build_info_results, cred_setup_lines
from reporter import to_json, to_csv, to_txt, to_pdf

console = Console()

DISCLAIMER = ("CloudSentry uses read-only API calls only.\n"
              "Ensure you have authorization to audit the cloud accounts being assessed.")

SEV_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
STATUS_COLOR = {"PASS": "bold green", "FAIL": "bold red", "INFO": "dim", "ERROR": "red", "TIMEOUT": "yellow"}


def _detected_providers():
    from providers.aws.connector import AWSConnector
    from providers.gcp.connector import GCPConnector
    from providers.azure.connector import AzureConnector
    det = {}
    det["aws"] = AWSConnector().available
    det["gcp"] = GCPConnector().available
    det["azure"] = AzureConnector().available
    return det


def main() -> None:
    ap = argparse.ArgumentParser(description="CloudSentry — multi-cloud security posture (read-only)")
    ap.add_argument("--provider", action="append", choices=["aws", "gcp", "azure"],
                    help="Limit to provider(s); repeatable. Default: all.")
    ap.add_argument("--profile", default=None, help="AWS named profile.")
    ap.add_argument("--region", default=None, help="AWS default region override.")
    ap.add_argument("--project", default=None, help="GCP project ID.")
    ap.add_argument("--subscription", default=None, help="Azure subscription ID.")
    ap.add_argument("--all-regions", action="store_true", help="Scan all AWS regions (slower).")
    ap.add_argument("--info", action="store_true", help="Force INFO mode (list checks, no API calls).")
    ap.add_argument("--output", default=None, help="Export report path (.json/.csv/.txt/.pdf).")
    ap.add_argument("--format", default=None, choices=["json", "csv", "txt", "pdf"],
                    help="Export format (else inferred from --output extension).")
    ap.add_argument("--no-disclaimer", action="store_true", help="Skip the disclaimer banner.")
    args = ap.parse_args()

    if not args.no_disclaimer:
        console.print(Panel(DISCLAIMER, border_style="cyan", title="CloudSentry", padding=(1, 2)))

    providers = args.provider or ["aws", "gcp", "azure"]

    # Credential status banner
    det = _detected_providers()
    status_line = " | ".join(
        f"{p.upper()}: {'credentials found' if det[p] else 'INFO mode (no creds)'}"
        for p in providers
    )
    console.print(f"[dim]{status_line}[/]")
    console.print()

    # Decide mode
    any_creds = any(det[p] for p in providers)
    info_mode = args.info or not any_creds

    start = time.time()
    results = []
    if info_mode:
        console.print("[yellow]INFO MODE[/] — listing all checks with guidance (no API calls).")
        results = build_info_results(providers)
        for p in providers:
            lines = cred_setup_lines(p)
            if lines:
                console.print(f"\n[cyan]To enable automated {p.upper()} checks:[/]")
                for ln in lines:
                    console.print(f"  [dim]{ln}[/]")
    else:
        # Import heavy providers lazily
        from providers import run_audit
        console.print("[cyan]Running automated read-only checks...[/]")
        kwargs = {}
        if "aws" in providers:
            kwargs.update({"profile": args.profile, "region": args.region})
        if "gcp" in providers:
            kwargs.update({"project": args.project})
        if "azure" in providers:
            kwargs.update({"subscription": args.subscription})

        def on_result(r):
            sc = SEV_COLOR.get(r.severity, "white")
            stc = STATUS_COLOR.get(r.status, "white")
            console.print(f"  [{stc}]{r.status:<6}[/] [dim]{r.check_id}[/] {r.name} "
                          f"[{sc}]{r.severity}[/]")
        results = run_audit(providers, on_result=on_result, **kwargs)

    duration = time.time() - start

    # Persist
    try:
        db.init_db()
        db.save_audit(providers, results, duration)
    except Exception as e:
        console.print(f"[red]DB error: {e}[/]")

    # Summary table
    sev = severity_counts(results)
    pass_c = sum(1 for r in results if r.status == "PASS")
    fail_c = sum(1 for r in results if r.status == "FAIL")
    info_c = sum(1 for r in results if r.status == "INFO")
    console.print()
    console.print(Panel(
        f"Total checks: {len(results)}\n"
        f"PASS: {pass_c}  FAIL: {fail_c}  INFO: {info_c}\n"
        f"critical: {sev['critical']} | high: {sev['high']} | medium: {sev['medium']} | low: {sev['low']}",
        border_style="cyan", title="Summary"))

    # Per-provider table
    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED, expand=True)
    table.add_column("Provider", justify="center")
    table.add_column("Check", justify="center")
    table.add_column("Name", min_width=30)
    table.add_column("Cat", justify="center")
    table.add_column("Sev", justify="center")
    table.add_column("Status", justify="center")
    for r in results:
        sc = SEV_COLOR.get(r.severity, "white")
        stc = STATUS_COLOR.get(r.status, "white")
        table.add_row(r.provider.upper(), r.check_id, r.name, r.category,
                      f"[{sc}]{r.severity}[/]", f"[{stc}]{r.status}[/]")
    console.print(table)

    # Compliance summary
    cis = cis_score(results)
    owasp = owasp_score(results)
    comp_lines = []
    for prov, s in cis.items():
        comp_lines.append(f"CIS {prov.upper()}: {s['pct']}% ({s['pass']}/{s['total']} controls passing)")
    comp_lines.append(f"OWASP Cloud Top 10: {owasp['clear']}/{owasp['total']} categories clear")
    console.print(Panel("\n".join(comp_lines), border_style="cyan", title="Compliance"))

    # Export
    if args.output:
        fmt = args.format or args.output.rsplit(".", 1)[-1].lower()
        if fmt == "json":
            data = to_json(results, providers)
        elif fmt == "csv":
            data = to_csv(results)
        elif fmt == "txt":
            data = to_txt(results, providers)
        elif fmt == "pdf":
            to_pdf(results, providers, path=args.output)
            data = None
        else:
            data = to_txt(results, providers)
        if data is not None:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(data)
        console.print(f"[green]Report written to {args.output}[/]")


if __name__ == "__main__":
    main()
