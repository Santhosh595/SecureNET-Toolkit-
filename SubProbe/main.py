"""SubProbe — CLI entry point.

Usage:
    python main.py <domain>
    python main.py <domain> --methods wordlist ct dns
    python main.py <domain> --wordlist /path/to/list.txt
"""

from __future__ import annotations

import argparse
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.prompt import Confirm

from enumerator import enumerate_domain
from database import init_db, create_scan, update_scan, add_subdomain, get_subdomains
from resolver import check_wildcard_dns

console = Console()


def show_disclaimer() -> bool:
    """Show legal disclaimer and ask for confirmation."""
    console.print(Panel(
        "[bold red]DISCLAIMER[/]\n\n"
        "SubProbe is for authorized reconnaissance only.\n"
        "Only scan domains you own or have explicit permission to test.",
        border_style="red", padding=(1, 2),
    ))
    console.print()
    return Confirm.ask("[bold]Do you have authorization to scan this domain?[/]", default=False)


def display_results(results: list[dict], duration: float, domain: str) -> None:
    """Render results with Rich."""
    console.print()
    console.rule("[bold cyan]SubProbe — Subdomain Enumerator", style="cyan")
    console.print()

    # Summary
    live = sum(1 for r in results if r["status"] in ("LIVE", "REDIRECT"))
    interesting = sum(1 for r in results if r["interesting"])

    s = Text()
    s.append(f"Domain: {domain}\n", style="bold")
    s.append(f"Found: {len(results)} subdomains")
    s.append(f"  |  Live: {live}")
    s.append(f"  |  Interesting: {interesting}")
    s.append(f"  |  Time: {duration:.1f}s")
    console.print(Panel(s, border_style="cyan", padding=(1, 2)))

    if not results:
        console.print("\n[yellow]No subdomains found.[/]")
        return

    # Results table
    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED, expand=True)
    table.add_column("Subdomain", min_width=30)
    table.add_column("IP", min_width=16)
    table.add_column("HTTP", min_width=6, justify="center")
    table.add_column("Status", min_width=10, justify="center")
    table.add_column("Source", min_width=12, justify="center")
    table.add_column("Interesting", min_width=11, justify="center")

    for r in results:
        status_color = {"LIVE": "bold green", "REDIRECT": "bold yellow", "DEAD": "dim"}.get(r["status"], "white")
        interesting = "[bold green]YES[/]" if r["interesting"] else "[dim]NO[/]"
        table.add_row(
            r["subdomain"],
            r["ip"] or "—",
            str(r["http_status"]) if r["http_status"] else "—",
            f"[{status_color}]{r['status']}[/]",
            r["source"],
            interesting,
        )

    console.print(table)

    # Interesting subdomains section
    interesting_subs = [r for r in results if r["interesting"]]
    if interesting_subs:
        console.print()
        console.print("[bold green]Interesting Subdomains (HTTP 200 or 403):[/]")
        for r in interesting_subs:
            console.print(f"  [bold]{r['subdomain']}[/] — {r['ip']} — HTTP {r['http_status']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SubProbe — Subdomain enumeration tool",
        epilog="Example: python main.py example.com",
    )
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument(
        "--methods", nargs="+", choices=["wordlist", "ct", "dns"],
        default=["wordlist", "ct", "dns"], help="Enumeration methods",
    )
    parser.add_argument("--wordlist", type=str, default=None, help="Custom wordlist file")
    parser.add_argument("--workers", type=int, default=100, help="Thread pool size (default: 100)")
    parser.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer")
    args = parser.parse_args()

    domain = args.domain.lower().strip()

    if not args.no_disclaimer and not show_disclaimer():
        console.print("[dim]Scan cancelled.[/]")
        sys.exit(0)

    # Init database
    init_db()
    scan_id = create_scan(domain)

    # Check wildcard
    console.print(f"\n[dim]Checking wildcard DNS for {domain}...[/]")
    is_wildcard, wildcard_ip = check_wildcard_dns(domain)
    if is_wildcard:
        console.print(f"[yellow]Wildcard DNS detected (IP: {wildcard_ip}). Results will be filtered.[/]")

    console.print(f"[dim]Starting enumeration of {domain}...[/]\n")

    start_time = time.time()

    # Progress callback
    def progress(current, total):
        pass  # Rich Progress handles this

    try:
        results = enumerate_domain(
            domain=domain,
            use_wordlist="wordlist" in args.methods,
            use_ct="ct" in args.methods,
            use_dns="dns" in args.methods,
            wordlist_path=args.wordlist,
            max_workers=args.workers,
            progress_callback=progress,
        )
    except ValueError as e:
        console.print(f"[red]Error: {e}[/]")
        sys.exit(1)

    duration = time.time() - start_time

    # Save to database
    live_count = sum(1 for r in results if r["status"] in ("LIVE", "REDIRECT"))
    for r in results:
        add_subdomain(scan_id, r["subdomain"], r["ip"], r["http_status"],
                       r["status"], r["source"], r["interesting"])
    update_scan(scan_id, len(results), live_count, duration)

    # Display
    display_results(results, duration, domain)


if __name__ == "__main__":
    main()
