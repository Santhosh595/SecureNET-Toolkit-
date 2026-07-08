"""TechFinger — CLI entry point (WhatWeb/httpx-style fingerprinting).

Usage:
    python main.py https://example.com
    python main.py https://example.com --no-disclaimer
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.prompt import Confirm

from engine import fingerprint
from database import init_db, save_result

console = Console()

CAT_COLOR = {
    "Server": "bold cyan", "Framework": "green", "CMS": "magenta",
    "CDN": "blue", "Analytics": "yellow", "JS-Lib": "cyan", "Security": "bold green",
}


def show_disclaimer() -> bool:
    console.print(Panel(
        "[bold red]DISCLAIMER[/]\n\n"
        "TechFinger is for authorized reconnaissance only.\n"
        "Only scan hosts you own or have explicit permission to test.",
        border_style="red", padding=(1, 2),
    ))
    console.print()
    return Confirm.ask("[bold]Do you have authorization to scan this target?[/]", default=False)


def display(result: dict) -> None:
    console.print()
    console.rule("[bold cyan]TechFinger — Web Technology Fingerprinting", style="cyan")
    console.print()
    if result.get("error"):
        console.print(f"[red]Error: {result['error']}[/]")
        return
    info = (f"URL: {result['url']}\nStatus: {result['status']}  |  Server: "
            f"{result['server'] or '—'}  |  Title: {result['title'] or '—'}")
    console.print(Panel(info, border_style="cyan", padding=(1, 2)))

    if not result["detected"]:
        console.print("[yellow]No technologies confidently identified.[/]")
        return
    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED, expand=True)
    table.add_column("Category", min_width=14)
    table.add_column("Technology", min_width=18)
    table.add_column("Evidence", min_width=30)
    for d in result["detected"]:
        c = CAT_COLOR.get(d["category"], "white")
        table.add_row(f"[{c}]{d['category']}[/]", d["name"], d.get("evidence", "")[:40])
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="TechFinger — web technology fingerprinting")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer prompt")
    args = parser.parse_args()

    if not args.no_disclaimer and not show_disclaimer():
        console.print("[dim]Scan cancelled.[/]")
        sys.exit(0)

    init_db()
    result = fingerprint(args.target)
    save_result(result)
    display(result)


if __name__ == "__main__":
    main()
