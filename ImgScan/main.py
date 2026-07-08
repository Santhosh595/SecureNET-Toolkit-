"""ImgScan — CLI entry point (Trivy-style container/dependency CVE scan).

Usage:
    python main.py --requirements requirements.txt
    python main.py --sbom image-sbom.json
    python main.py --requirements requirements.txt --sbom image-sbom.json
"""

from __future__ import annotations

import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from engine import scan_dependencies, scan_image_sbom, summarize
from database import init_db, save_findings

console = Console()

SEV_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow",
             "low": "cyan", "unknown": "dim", "info": "dim"}


def display(findings, summary) -> None:
    console.print()
    console.rule("[bold cyan]ImgScan — Container / Dependency CVE Scanner", style="cyan")
    console.print()
    if not findings:
        console.print(Panel("[green]No known vulnerabilities matched the offline rule set.[/]\n"
                            "For full coverage run with pip-audit installed or supply a Trivy SBOM.",
                            border_style="cyan", padding=(1, 2)))
        return
    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED, expand=True)
    table.add_column("Component", min_width=16)
    table.add_column("Version", min_width=12, justify="center")
    table.add_column("CVE", min_width=18)
    table.add_column("Severity", min_width=10, justify="center")
    table.add_column("Source", min_width=14, justify="center")
    table.add_column("Detail", min_width=34)
    for f in findings:
        c = SEV_COLOR.get(f.severity, "white")
        table.add_row(f.component, f.version, f.cve, f"[{c}]{f.severity.upper()}[/]",
                      f.source, f.detail or "—")
    console.print(table)
    stats = " | ".join(f"{k}:{v}" for k, v in summary["by_severity"].items())
    console.print(Panel(f"Total findings: {summary['total']}\n{stats}",
                        border_style="cyan", padding=(1, 2)))


def main() -> None:
    parser = argparse.ArgumentParser(description="ImgScan — container/dependency CVE scanner")
    parser.add_argument("--requirements", help="Path to requirements.txt to scan")
    parser.add_argument("--sbom", help="Path to image SBOM JSON (CycloneDX/SPDX)")
    args = parser.parse_args()

    if not args.requirements and not args.sbom:
        parser.error("Provide --requirements and/or --sbom")

    init_db()
    findings: list = []
    if args.requirements:
        findings += scan_dependencies(args.requirements)
    if args.sbom:
        findings += scan_image_sbom(args.sbom)
    save_findings(findings)
    display(findings, summarize(findings))


if __name__ == "__main__":
    main()
