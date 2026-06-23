"""ARPWatch — CLI entry point with Rich live display.

Requires root/sudo for packet capture.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box

from database import init_db, log_packet, log_alert, get_baseline, get_recent_packets, get_recent_alerts, get_stats
from baseline import get_default_gateway, rebuild_baseline, load_baseline, load_or_build_baseline
from detector import ARPDetector, Alert
from sniffer import ARPSniffer

console = Console()


def check_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def severity_color(severity: str) -> str:
    return {"INFO": "dim", "WARNING": "bold yellow", "CRITICAL": "bold red"}.get(severity, "white")


def build_live_table(sniffer, recent_packets, recent_alerts) -> Table:
    """Build the live display table."""
    table = Table(box=box.SIMPLE, expand=True, show_edge=False)
    table.add_column("Time", style="dim", min_width=10)
    table.add_column("Event", min_width=12)
    table.add_column("Source IP", min_width=15)
    table.add_column("Source MAC", min_width=18)
    table.add_column("Details", min_width=30)

    for pkt in recent_packets[:10]:
        ts = time.strftime("%H:%M:%S", time.localtime(pkt["timestamp"]))
        color = severity_color(pkt["severity"])
        table.add_row(
            ts, f"[{color}]{pkt['alert_type']}[/]",
            pkt["src_ip"] or "—", pkt["src_mac"] or "—",
            pkt["dst_ip"] or "—",
        )

    for alert in recent_alerts[:10]:
        ts = time.strftime("%H:%M:%S", time.localtime(alert["timestamp"]))
        color = severity_color(alert["severity"])
        table.add_row(
            ts, f"[{color}]{alert['type']}[/]",
            alert["ip"] or "—",
            f"{alert.get('expected_mac', '—')} → {alert.get('seen_mac', '—')}",
            alert["details"][:50] if alert.get("details") else "",
        )

    return table


def run_cli(args) -> None:
    """Main CLI entry point."""
    if not check_root():
        console.print(Panel(
            "[bold red]ARPWatch requires root privileges.[/]\n\n"
            "Please run with: [bold]sudo python main.py[/]",
            border_style="red",
        ))
        sys.exit(1)

    # Init database
    init_db()

    # Detect gateway
    gateway = get_default_gateway()
    if not gateway:
        console.print("[yellow]Warning: Could not detect default gateway.[/]")

    # Handle baseline args
    if args.reset:
        console.print("[yellow]Rebuilding baseline from ARP table...[/]")
        baseline = rebuild_baseline()
        console.print(f"[green]Baseline rebuilt with {len(baseline)} entries.[/]")
        if not args.interface:
            return

    if args.load:
        try:
            baseline = load_baseline(args.file)
            from database import upsert_baseline
            for ip, mac in baseline.items():
                upsert_baseline(ip, mac)
            console.print(f"[green]Loaded {len(baseline)} baseline entries from {args.file}[/]")
        except Exception as e:
            console.print(f"[red]Error loading baseline: {e}[/]")
            sys.exit(1)
    else:
        baseline = load_or_build_baseline()

    console.print(f"[dim]Baseline: {len(baseline)} entries, Gateway: {gateway}[/]")

    # Setup detector
    detector = ARPDetector(gateway_ip=gateway)
    detector.set_baseline(baseline)

    # Recent packets/alerts storage
    recent_packets = []
    recent_alerts = []

    def on_packet(src_ip, src_mac, dst_ip, op):
        recent_packets.insert(0, {
            "timestamp": time.time(),
            "src_ip": src_ip, "src_mac": src_mac, "dst_ip": dst_ip,
            "alert_type": "ARP", "severity": "INFO",
        })
        recent_packets[:] = recent_packets[:100]
        log_packet(src_ip, src_mac, dst_ip)

    def on_alert(alert: Alert):
        recent_alerts.insert(0, {
            "timestamp": alert.timestamp, "type": alert.alert_type,
            "severity": alert.severity, "ip": alert.ip,
            "expected_mac": alert.expected_mac, "seen_mac": alert.seen_mac,
            "verdict": alert.verdict, "details": alert.details,
        })
        recent_alerts[:] = recent_alerts[:50]
        log_alert(alert.alert_type, alert.severity, alert.ip,
                  alert.expected_mac, alert.seen_mac, alert.verdict)
        # Print alert immediately
        color = severity_color(alert.severity)
        console.print(
            f"[{color} bold]ALERT: {alert.type}[/] — IP {alert.ip} — "
            f"Expected: {alert.expected_mac}, Seen: {alert.seen_mac} — {alert.verdict}"
        )

    # Setup sniffer
    sniffer = ARPSniffer(
        detector=detector,
        iface=args.interface,
        on_alert=on_alert,
        on_packet=on_packet,
    )

    console.print(Panel(
        f"[bold cyan]ARPWatch — Real-Time ARP Spoof Detector[/]\n\n"
        f"Interface: {args.interface or 'auto'}\n"
        f"Gateway: {gateway or 'unknown'}\n"
        f"Baseline: {len(baseline)} entries\n\n"
        f"[dim]Press Ctrl+C to stop[/]",
        border_style="cyan",
    ))

    sniffer.start()

    try:
        with Live(console=console, refresh_per_second=2) as live:
            while sniffer.is_running:
                stats = get_stats()
                layout = build_live_table(sniffer, recent_packets, recent_alerts)
                live.update(layout)
                time.sleep(0.5)
    except KeyboardInterrupt:
        sniffer.stop()
        console.print()
        console.rule("[bold]Session Summary", style="cyan")
        stats = get_stats()
        console.print(f"  Packets captured: {stats['total_packets']}")
        console.print(f"  Alerts triggered:  {stats['total_alerts']}")
        console.print(f"  Critical alerts:  {stats['critical_alerts']}")
        console.print(f"  Uptime: {sniffer.uptime:.0f}s")
        console.print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ARPWatch — Real-time ARP spoof detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Requires root: sudo python main.py",
    )
    parser.add_argument("--iface", "-i", type=str, default=None,
                        help="Network interface (default: auto)")
    parser.add_argument("--reset", action="store_true",
                        help="Rebuild baseline from current ARP table")
    parser.add_argument("--file", "-f", type=str, default=None,
                        help="Load baseline from JSON file")
    args = parser.parse_args()
    run_cli(args)


if __name__ == "__main__":
    main()
