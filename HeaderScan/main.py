"""HeaderScan — CLI entry point.

Usage:
    python main.py <url>
    python main.py https://example.com
    python main.py https://example.com --json
"""

from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from analyzer import scan_url, RiskLevel, Grade


console = Console()


def _risk_style(risk: str) -> str:
    mapping = {
        RiskLevel.SAFE.value: "bold green",
        RiskLevel.WARNING.value: "bold yellow",
        RiskLevel.CRITICAL.value: "bold red",
    }
    return mapping.get(risk, "white")


def _grade_style(grade: str) -> str:
    mapping = {
        Grade.A.value: "bold green",
        Grade.B.value: "bold blue",
        Grade.C.value: "bold yellow",
        Grade.F.value: "bold red",
    }
    return mapping.get(grade, "white")


def display_report(report) -> None:
    """Render a ScanReport to the terminal using Rich."""

    # Header
    console.print()
    console.rule("[bold cyan] HeaderScan — HTTP Security Header Analyzer", style="cyan")
    console.print()

    if report.error:
        console.print(Panel(
            f"[bold red]Error:[/] {report.error}",
            title=report.url,
            border_style="red",
        ))
        return

    # Score panel
    grade_styled = f"[{_grade_style(report.grade)}]{report.grade}[/]"
    score_text = Text()
    score_text.append("Score: ", style="bold")
    score_text.append(f"{report.score}/100", style=f"bold {_grade_style(report.grade)}")
    score_text.append(f"  Grade: {grade_styled}")
    score_text.append(f"\n{report.headers_found}/{report.headers_checked} security headers present")
    score_text.append(f"  Status: {report.status_code}", style="dim")

    console.print(Panel(
        score_text,
        title=f"[bold]{report.url}[/]",
        border_style="cyan",
        padding=(1, 2),
    ))
    console.print()

    # Results table
    table = Table(
        show_header=True,
        header_style="bold white",
        box=box.ROUNDED,
        expand=True,
        pad_edge=False,
    )
    table.add_column("Header", style="bold", min_width=28, max_width=35)
    table.add_column("Status", min_width=8, justify="center")
    table.add_column("Risk", min_width=10, justify="center")
    table.add_column("Current Value / Explanation", min_width=40)
    table.add_column("Recommendation", min_width=40)

    for result in report.results:
        status = "[green]YES[/green]" if result.present else "[red]NO[/red]"
        risk_styled = f"[{_risk_style(result.risk)}]● {result.risk}[/]"
        value_display = result.value if result.value else "[dim]—[/dim]"
        table.add_row(
            result.header,
            status,
            risk_styled,
            f"{value_display}\n[dim]{result.explanation}[/dim]",
            result.recommendation,
        )

    console.print(table)

    # Summary
    safe_count = sum(1 for r in report.results if r.risk == RiskLevel.SAFE.value)
    warn_count = sum(1 for r in report.results if r.risk == RiskLevel.WARNING.value)
    crit_count = sum(1 for r in report.results if r.risk == RiskLevel.CRITICAL.value)

    summary_parts = []
    if safe_count:
        summary_parts.append(f"[green]{safe_count} safe[/green]")
    if warn_count:
        summary_parts.append(f"[yellow]{warn_count} warning[/yellow]")
    if crit_count:
        summary_parts.append(f"[red]{crit_count} critical[/red]")

    console.print()
    console.print(
        f"  Score: [{_grade_style(report.grade)}]{report.score}/100 — Grade: {report.grade}[/]"
        f"  |  {' | '.join(summary_parts)}"
    )
    console.print(f"  [dim]HeaderScan v1.0 — For educational and authorized use only[/dim]")
    console.print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HeaderScan — Analyze HTTP security headers of any URL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python main.py https://example.com",
    )
    parser.add_argument("url", help="URL to scan (e.g., https://example.com)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds (default: 5)")
    args = parser.parse_args()

    url = args.url.strip()

    if not args.json:
        console.print(f"\n[dim]Scanning {url} ...[/dim]")

    report = scan_url(url, timeout=args.timeout)

    if args.json:
        print(report.to_json())
    else:
        display_report(report)


if __name__ == "__main__":
    main()
