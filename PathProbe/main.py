"""PathProbe — CLI entry point (feroxbuster-style content discovery).

Usage:
    python main.py https://example.com
    python main.py https://example.com --wordlist paths.txt --threads 50
    python main.py https://example.com --no-disclaimer
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

from engine import load_wordlist, discover
from database import init_db, create_scan, add_path, update_scan

console = Console()

STATUS_COLOR = {
    200: "bold green", 201: "bold green", 204: "bold green",
    301: "yellow", 302: "yellow", 303: "yellow", 307: "yellow", 308: "yellow",
    401: "red", 403: "red", 405: "cyan", 500: "bold red", 502: "bold red",
}


def show_disclaimer() -> bool:
    console.print(Panel(
        "[bold red]DISCLAIMER[/]\n\n"
        "PathProbe is for authorized testing only.\n"
        "Only scan hosts you own or have explicit permission to test.",
        border_style="red", padding=(1, 2),
    ))
    console.print()
    return Confirm.ask("[bold]Do you have authorization to scan this target?[/]", default=False)


def display(results: list[dict], duration: float, target: str, checked: int) -> None:
    console.print()
    console.rule("[bold cyan]PathProbe — Web Content Discovery", style="cyan")
    console.print()
    summary = (f"Target: {target}\nPaths checked: {checked}  |  Interesting: {len(results)}"
               f"  |  Time: {duration:.1f}s")
    console.print(Panel(summary, border_style="cyan", padding=(1, 2)))
    if not results:
        console.print("[yellow]No interesting paths found.[/]")
        return
    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED, expand=True)
    table.add_column("Path", min_width=28)
    table.add_column("Status", min_width=8, justify="center")
    table.add_column("Size", min_width=9, justify="right")
    table.add_column("Redirect", min_width=24)
    for r in results:
        color = STATUS_COLOR.get(r["status"], "white")
        table.add_row(r["path"], f"[{color}]{r['status']}[/]", str(r["size"]),
                      r["redirect"] or "—")
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="PathProbe — web content/path discovery")
    parser.add_argument("target", help="Base URL (e.g., https://example.com)")
    parser.add_argument("--wordlist", default="wordlists/common.txt", help="Path wordlist file")
    parser.add_argument("--threads", type=int, default=30, help="Concurrent threads")
    parser.add_argument("--timeout", type=float, default=6.0, help="Per-request timeout (s)")
    parser.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer prompt")
    args = parser.parse_args()

    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if not args.no_disclaimer and not show_disclaimer():
        console.print("[dim]Scan cancelled.[/]")
        sys.exit(0)

    wordlist = load_wordlist(args.wordlist)
    console.print(f"[dim]Loaded {len(wordlist)} words.[/]")
    init_db()
    scan_id = create_scan(target)
    start = time.time()
    results = discover(target, wordlist, threads=args.threads, timeout=args.timeout)
    duration = time.time() - start
    for r in results:
        add_path(scan_id, r)
    update_scan(scan_id, len(results), duration)
    display(results, duration, target, len(wordlist))


if __name__ == "__main__":
    main()
