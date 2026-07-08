"""CloudSentry — CLI entry point (multi-cloud posture, Prowler/ScoutSuite-style).

Usage:
    python main.py
    python main.py --provider aws
    python main.py --provider aws --provider gcp
"""

from __future__ import annotations

import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from engine import run_checks, summarize
from database import init_db, save_results

console = Console()

STATUS_COLOR = {"PASS": "bold green", "WARN": "yellow", "FAIL": "bold red", "INFO": "dim"}
SEV_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow",
             "low": "cyan", "info": "dim"}


def main() -> None:
    parser = argparse.ArgumentParser(description="CloudSentry — multi-cloud security posture")
    parser.add_argument("--provider", action="append", default=None,
                        choices=["aws", "gcp", "azure"],
                        help="Limit to provider(s); repeatable. Default: all.")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]CloudSentry — Multi-Cloud Security Posture (read-only)[/]\n\n"
        "Runs safe, read-only configuration checks. Set cloud credentials in the environment\n"
        "to perform real API checks; without them, checks report INFO with guidance.",
        border_style="cyan", padding=(1, 2),
    ))
    console.print()

    results = run_checks(args.provider)
    init_db()
    save_results(results)
    summary = summarize(results)

    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED, expand=True)
    table.add_column("Provider", min_width=10, justify="center")
    table.add_column("Check", min_width=12, justify="center")
    table.add_column("Title", min_width=34)
    table.add_column("Severity", min_width=10, justify="center")
    table.add_column("Status", min_width=9, justify="center")
    table.add_column("Detail", min_width=34)
    for r in results:
        sc = SEV_COLOR.get(r.severity, "white")
        stc = STATUS_COLOR.get(r.status, "white")
        table.add_row(r.provider.upper(), r.check_id, r.title,
                      f"[{sc}]{r.severity.upper()}[/]", f"[{stc}]{r.status}[/]", r.detail or "—")
    console.print(table)

    stats = " | ".join(f"{k}:{v}" for k, v in summary["by_status"].items())
    console.print()
    console.print(Panel(f"Total checks: {summary['total']}\n{stats}",
                        border_style="cyan", padding=(1, 2)))


if __name__ == "__main__":
    main()
