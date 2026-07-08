"""VulnProbe — CLI entry point (Nuclei-style template probe engine).

Usage:
    python main.py https://example.com
    python main.py https://example.com --severity high,medium
    python main.py https://example.com --templates templates --no-disclaimer
"""

from __future__ import annotations

import argparse
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.prompt import Confirm

from engine import load_templates, build_session, scan_target
from database import init_db, create_scan, add_finding, update_scan

console = Console()

SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def show_disclaimer() -> bool:
    console.print(Panel(
        "[bold red]DISCLAIMER[/]\n\n"
        "VulnProbe is for authorized testing only.\n"
        "Only scan hosts you own or have explicit permission to test.",
        border_style="red", padding=(1, 2),
    ))
    console.print()
    return Confirm.ask("[bold]Do you have authorization to scan this target?[/]", default=False)


def display_findings(findings: list[dict], duration: float, target: str) -> None:
    console.print()
    console.rule("[bold cyan]VulnProbe — Template Vulnerability Scanner", style="cyan")
    console.print()

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    summary = f"Target: {target}\nFindings: {len(findings)}"
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev_counts.get(sev):
            summary += f"  |  {sev.capitalize()}: {sev_counts[sev]}"
    summary += f"  |  Time: {duration:.1f}s"
    console.print(Panel(summary, border_style="cyan", padding=(1, 2)))

    if not findings:
        console.print("[green]No findings matched the loaded templates.[/]")
        return

    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED, expand=True)
    table.add_column("Severity", min_width=10, justify="center")
    table.add_column("Finding", min_width=28)
    table.add_column("Method", min_width=7, justify="center")
    table.add_column("Path", min_width=22)
    table.add_column("HTTP", min_width=6, justify="center")
    table.add_column("Template", min_width=18)

    for f in findings:
        color = SEVERITY_COLOR.get(f["severity"], "white")
        table.add_row(
            f"[{color}]{f['severity'].upper()}[/]",
            f["name"],
            f["method"],
            f["path"],
            str(f["status_code"]),
            f["template_file"],
        )
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="VulnProbe — template-based HTTP vulnerability scanner")
    parser.add_argument("target", help="Base URL (e.g., https://example.com)")
    parser.add_argument("--templates", default="templates", help="Directory of YAML probe templates")
    parser.add_argument("--severity", default=None,
                        help="Comma-separated severities to report (critical,high,medium,low,info)")
    parser.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer prompt")
    args = parser.parse_args()

    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if not args.no_disclaimer and not show_disclaimer():
        console.print("[dim]Scan cancelled.[/]")
        sys.exit(0)

    templates = load_templates(args.templates)
    if not templates:
        console.print(f"[red]No templates loaded from '{args.templates}'.[/]")
        sys.exit(1)
    console.print(f"[dim]Loaded {len(templates)} templates.[/]")

    wanted = None
    if args.severity:
        wanted = {s.strip().lower() for s in args.severity.split(",")}

    init_db()
    scan_id = create_scan(target)
    start = time.time()
    session = build_session()
    all_findings = scan_target(target, templates, session)
    session.close()
    duration = time.time() - start

    shown = [f for f in all_findings if not wanted or f["severity"] in wanted]
    for f in shown:
        add_finding(scan_id, f)
    update_scan(scan_id, len(shown), duration)
    display_findings(shown, duration, target)


if __name__ == "__main__":
    main()
