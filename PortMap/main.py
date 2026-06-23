"""PortMap — CLI entry point.

Usage:
    python main.py <target>
    python main.py 192.168.1.1 --profile quick
    python main.py example.com --profile common --timeout 2
    python main.py 10.0.0.1 --custom 8000-9000
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.prompt import Confirm

from scanner import PORT_PROFILES, scan_target, resolve_host, is_private_ip, RiskLevel

console = Console()


def _risk_style(risk: str) -> str:
    m = {RiskLevel.LOW.value: "bold green", RiskLevel.MEDIUM.value: "bold yellow", RiskLevel.HIGH.value: "bold red"}
    return m.get(risk, "white")


def show_disclaimer() -> bool:
    console.print(Panel(
        "[bold red]DISCLAIMER[/]\n\n"
        "PortMap is for authorized testing only.\n"
        "Scanning hosts without permission is illegal.\n"
        "You are responsible for ensuring you have authorization.",
        border_style="red", padding=(1, 2),
    ))
    console.print()
    return Confirm.ask("[bold]Do you have authorization to scan this target?[/]", default=False)


def display_report(report) -> None:
    console.print()
    console.rule("[bold cyan]PortMap — Port Scanner & Risk Analyzer", style="cyan")
    console.print()

    open_ports = [r for r in report.results if r.state == "OPEN"]
    hi = sum(1 for r in open_ports if r.risk == RiskLevel.HIGH.value)
    mid = sum(1 for r in open_ports if r.risk == RiskLevel.MEDIUM.value)
    lo = sum(1 for r in open_ports if r.risk == RiskLevel.LOW.value)

    s = Text()
    s.append(f"Target: {report.target}", style="bold")
    s.append(f"  |  Resolved: {report.resolved_ip}\n")
    s.append(f"Scanned: {report.ports_scanned} ports")
    s.append(f"  |  Open: {report.ports_open}")
    s.append(f"  |  Time: {report.scan_time}s\n")
    s.append(f"High-risk: {hi}", style="bold red")
    s.append(f"  |  Medium: {mid}", style="bold yellow")
    s.append(f"  |  Low: {lo}", style="bold green")
    console.print(Panel(s, border_style="cyan", padding=(1, 2)))

    if not open_ports:
        console.print("\n[yellow]No open ports found.[/]")
        return

    t = Table(show_header=True, header_style="bold white", box=box.ROUNDED, expand=True)
    t.add_column("Port", style="bold", justify="right", min_width=6)
    t.add_column("State", min_width=8, justify="center")
    t.add_column("Service", min_width=16)
    t.add_column("Risk", min_width=10, justify="center")
    t.add_column("Risk Note", min_width=40)

    for r in open_ports:
        t.add_row(str(r.port), f"[bold green]{r.state}[/]", r.service,
                   f"[{_risk_style(r.risk)}] {r.risk}[/]", r.risk_note)
    console.print(t)
    console.print(f"\n  [bold]{report.ports_open} ports open[/]  |  [red]{hi} high-risk[/]  |  [dim]Time: {report.scan_time}s[/]")
    console.print("  [dim]PortMap v1.0 — For authorized use only[/]\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PortMap — Multi-threaded port scanner with risk analysis",
        epilog="Example: python main.py 192.168.1.1 --profile quick",
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--profile", choices=["quick", "common", "full", "custom"], default="quick")
    parser.add_argument("--custom", type=str, default=None, help="Custom range e.g. 8000-9000")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout per port (default: 1s)")
    parser.add_argument("--workers", type=int, default=100, help="Thread pool size (default: 100)")
    parser.add_argument("--safe", action="store_true", help="Refuse private IP ranges")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip disclaimer")
    args = parser.parse_args()

    try:
        resolved = resolve_host(args.target)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/]")
        sys.exit(1)

    if args.safe and is_private_ip(resolved):
        console.print("[red]Safe mode: refusing to scan private IP range.[/]")
        sys.exit(1)

    if not args.yes and not show_disclaimer():
        console.print("[dim]Scan cancelled.[/]")
        sys.exit(0)

    if args.profile == "custom":
        if not args.custom:
            console.print("[red]--custom requires a range like 8000-9000[/]")
            sys.exit(1)
        try:
            p = args.custom.split("-")
            s, e = int(p[0]), int(p[1])
            if s < 1 or e > 65535 or s >= e:
                raise ValueError
            ports = list(range(s, e + 1))
        except (ValueError, IndexError):
            console.print("[red]Invalid range. Use format: 8000-9000[/]")
            sys.exit(1)
    else:
        ports = PORT_PROFILES.get(args.profile, PORT_PROFILES["quick"])

    console.print(f"\n[dim]Scanning {args.target} ({resolved}) — {len(ports)} ports, profile: {args.profile}[/]\n")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.percentage:>3.0f}%"),
                  TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Scanning...", total=len(ports))
        def cb(scanned, total): progress.update(task, completed=scanned)
        report = scan_target(args.target, ports, args.timeout, args.workers, cb)

    display_report(report)


if __name__ == "__main__":
    main()
