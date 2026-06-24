"""
LogSentry CLI Entry Point
Usage:
    logsentry analyze --file auth.log [--type ssh]
    logsentry analyze --dir /var/log/ --all
    logsentry monitor --file /var/log/auth.log
    logsentry correlate --auth auth.log --web access.log --firewall ufw.log
    logsentry dashboard
"""

import argparse
import sys
import os
import time
from datetime import datetime, timezone

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, create_session, close_session, insert_events_batch, insert_alerts_batch
from normalizer import normalize_event, deduplicate_events
from ingester.auth_parser import parse_auth_file
from ingester.apache_parser import parse_access_file, parse_error_file
from ingester.windows_parser import parse_windows_file
from ingester.firewall_parser import parse_firewall_file
from ingester.generic_parser import parse_generic_file
from correlator import correlate_events
from mitre import build_attack_navigator_layer
from reporter import generate_json_report, generate_csv_report, generate_pdf_report
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box
from rich.live import Live
from rich.columns import Columns

console = Console()

BANNER = r"""
  _                _   _               
 | |    ___   __ _| |_| |_ ___ _ __ ___ 
 | |   / _ \ / _` | __| __/ _ \ '__/ __|
 | |__| (_) | (_| | |_| ||  __/ |  \__ \
 |_____\___/ \__, |\__|\__\___|_|  |___/
             |___/                        
    Multi-Source Log Analyzer & Threat Detector
"""

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "white",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def detect_log_type(filename: str, hint: str = None) -> str:
    """Auto-detect log type from filename and content."""
    if hint:
        hint_map = {
            "ssh": "auth", "auth": "auth", "auth.log": "auth",
            "access": "apache_access", "access.log": "apache_access",
            "error": "apache_error", "error.log": "apache_error",
            "windows": "windows", "evtx": "windows", "event": "windows",
            "firewall": "firewall", "ufw": "firewall", "iptables": "firewall",
            "json": "generic", "csv": "generic", "log": "generic",
        }
        for key, val in hint_map.items():
            if key in hint.lower():
                return val

    fname = os.path.basename(filename).lower()
    for key, val in {
        "auth": "auth", "secure": "auth",
        "access": "apache_access", "access.log": "apache_access",
        "error": "apache_error", "error.log": "apache_error",
        "syslog": "auth", "messages": "auth",
        "security": "windows", "system": "windows",
        "ufw": "firewall", "iptables": "firewall", "firewall": "firewall",
        ".csv": "generic", ".json": "generic",
    }.items():
        if key in fname:
            return val

    # Try content-based detection
    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i > 20:
                    break
                if "SSHD" in line.upper() or "PAM_" in line or "sudo:" in line:
                    return "auth"
                if "HTTP/" in line and ("GET " in line or "POST " in line):
                    return "apache_access"
                if "[error]" in line.lower() or "[warn]" in line.lower():
                    return "apache_error"
                if "UFW" in line or "iptables" in line.lower() or "IN=" in line:
                    return "firewall"
                if line.strip().startswith("{"):
                    return "generic"
    except Exception:
        pass

    return "generic"


def get_parser(log_type: str):
    """Return the appropriate parser function."""
    parsers = {
        "auth": parse_auth_file,
        "apache_access": parse_access_file,
        "apache_error": parse_error_file,
        "windows": parse_windows_file,
        "firewall": parse_firewall_file,
        "generic": parse_generic_file,
    }
    return parsers.get(log_type, parse_generic_file)


def ingest_file(filepath: str, log_type: str = None, session_id: int = None, db_path: str = None):
    """Ingest a single file, return (events, errors, log_type)."""
    if not os.path.exists(filepath):
        console.print(f"[red]File not found: {filepath}[/red]")
        return [], 0, log_type or "unknown"

    detected_type = detect_log_type(filepath, log_type)
    parser = get_parser(detected_type)

    console.print(f"[cyan]Ingesting:[/cyan] {filepath} (type: {detected_type})")

    events = []
    errors = 0
    raw_events = []

    for parsed in parser(filepath):
        if parsed is None:
            errors += 1
            continue

        event = normalize_event(parsed, filepath, detected_type)
        if event:
            raw_events.append(event)

    # Deduplicate
    events = deduplicate_events(raw_events)

    # Store in DB
    if session_id and events:
        insert_events_batch(events, session_id, db_path)

    return events, errors, detected_type


def run_rules(events: list, session_id: int = None, db_path: str = None):
    """Run all 15 detection rules on events."""
    from rules import ALL_RULES

    all_alerts = []
    for rule in ALL_RULES:
        try:
            alerts = rule.check(events)
            if alerts:
                all_alerts.extend(alerts)
        except Exception as e:
            console.print(f"[dim]Rule {rule.name} error: {e}[/dim]")

    # Sort by severity
    all_alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.get("severity", "INFO"), 99))

    # Store alerts
    if session_id and all_alerts:
        insert_alerts_batch(all_alerts, session_id, db_path)

    return all_alerts


def display_results(events: list, alerts: list, errors: int, duration: float, files_analyzed: int):
    """Display analysis results with Rich panels."""
    console.print()
    console.print(BANNER)
    console.print()

    # Panel 1: Ingestion Stats
    stats_text = Text()
    stats_text.append(f"Files Analyzed: {files_analyzed}\n", style="cyan")
    stats_text.append(f"Lines Parsed: {len(events) + errors:,}\n", style="cyan")
    stats_text.append(f"Events Normalized: {len(events):,}\n", style="green")
    stats_text.append(f"Parse Errors: {errors:,}\n", style="red" if errors > 0 else "dim")
    stats_text.append(f"Duration: {duration:.2f}s\n", style="cyan")
    stats_text.append(f"Alerts Generated: {len(alerts)}\n", style="bold yellow")

    stats_panel = Panel(stats_text, title="[bold]Ingestion Stats[/bold]", border_style="blue")

    # Panel 2: Top Attacker IPs
    ip_counts = {}
    for alert in alerts:
        ip = alert.get("src_ip", "")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    attacker_table = Table(title="[bold]Top Attacker IPs[/bold]", box=box.SIMPLE)
    attacker_table.add_column("IP", style="cyan")
    attacker_table.add_column("Alerts", justify="right", style="red")
    attacker_table.add_column("Rules", style="yellow")

    for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
        rules_for_ip = set(a.get("rule_name", "") for a in alerts if a.get("src_ip") == ip)
        attacker_table.add_row(ip, str(count), ", ".join(rules_for_ip)[:50])

    attacker_panel = Panel(attacker_table, border_style="red")

    # Panel 3: Rule Triggers Summary
    rule_counts = {}
    for alert in alerts:
        rule = alert.get("rule_name", "Unknown")
        rule_counts[rule] = rule_counts.get(rule, 0) + 1

    rule_table = Table(title="[bold]Rule Triggers[/bold]", box=box.SIMPLE)
    rule_table.add_column("Rule", style="white")
    rule_table.add_column("Count", justify="right")
    rule_table.add_column("Severity", justify="center")
    rule_table.add_column("MITRE", style="dim")

    for rule_name, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
        sample_alert = next((a for a in alerts if a.get("rule_name") == rule_name), {})
        severity = sample_alert.get("severity", "MEDIUM")
        mitre = sample_alert.get("mitre_id", "")
        color = SEVERITY_COLORS.get(severity, "white")
        rule_table.add_row(rule_name, str(count), f"[{color}]{severity}[/{color}]", mitre)

    rule_panel = Panel(rule_table, border_style="yellow")

    # Panel 4: Threat Timeline (last 20 events)
    timeline_table = Table(title="[bold]Recent Threats (Last 20)[/bold]", box=box.SIMPLE, show_lines=False)
    timeline_table.add_column("Time", style="dim", width=20)
    timeline_table.add_column("Severity", justify="center", width=10)
    timeline_table.add_column("IP", width=16)
    timeline_table.add_column("Rule", width=30)
    timeline_table.add_column("Details", width=40)

    sorted_alerts = sorted(alerts, key=lambda a: a.get("timestamp", ""))
    for alert in sorted_alerts[-20:]:
        severity = alert.get("severity", "MEDIUM")
        color = SEVERITY_COLORS.get(severity, "white")
        ts = alert.get("timestamp", "")
        if hasattr(ts, "strftime"):
            ts = ts.strftime("%H:%M:%S")
        timeline_table.add_row(
            str(ts)[:19],
            f"[{color}]{severity}[/{color}]",
            alert.get("src_ip", ""),
            alert.get("rule_name", "")[:30],
            alert.get("details", "")[:40],
        )

    timeline_panel = Panel(timeline_table, border_style="cyan")

    # Panel 5: Critical Alerts
    critical_alerts = [a for a in alerts if a.get("severity") in ("CRITICAL", "HIGH")]
    if critical_alerts:
        crit_text = Text()
        for alert in critical_alerts[:15]:
            color = SEVERITY_COLORS.get(alert.get("severity", ""), "red")
            ts = alert.get("timestamp", "")
            if hasattr(ts, "strftime"):
                ts = ts.strftime("%H:%M:%S")
            crit_text.append(f"[{color}]{ts}[/{color}] ")
            crit_text.append(f"[{color}]{alert.get('severity')}[/{color}] ")
            crit_text.append(f"{alert.get('src_ip', 'N/A')} -> {alert.get('rule_name', '')}\n")
            if alert.get("details"):
                crit_text.append(f"     {alert['details'][:80]}\n", style="dim")
        crit_panel = Panel(crit_text, title="[bold red]Critical/High Alerts[/bold red]", border_style="red bold")
    else:
        crit_panel = Panel("[green]No critical or high alerts detected.[/green]", title="[bold]Critical Alerts[/bold]", border_style="green")

    # Display layout
    console.print(Columns([stats_panel, attacker_panel], expand=True))
    console.print()
    console.print(rule_panel)
    console.print()
    console.print(timeline_panel)
    console.print()
    console.print(crit_panel)


def cmd_analyze(args):
    """Handle the 'analyze' command."""
    start_time = time.time()

    db_path = init_db()
    session_id = create_session(db_path)

    all_events = []
    all_errors = 0
    files_analyzed = 0

    if args.file:
        events, errors, log_type = ingest_file(args.file, args.type, session_id, db_path)
        all_events.extend(events)
        all_errors += errors
        files_analyzed += 1

    if args.dir:
        for root, dirs, files in os.walk(args.dir):
            for fname in files:
                if args.all or any(k in fname.lower() for k in ["auth", "access", "error", "firewall", "secure", "syslog", "event", "security"]):
                    fpath = os.path.join(root, fname)
                    events, errors, log_type = ingest_file(fpath, None, session_id, db_path)
                    all_events.extend(events)
                    all_errors += errors
                    files_analyzed += 1

    # Run detection rules
    alerts = run_rules(all_events, session_id, db_path)

    # Run correlation
    if len(all_events) > 0:
        profiles = correlate_events(all_events, alerts)
        for profile in profiles:
            from database import update_ip_profile
            update_ip_profile(profile, db_path)

    # Close session
    close_session(session_id, db_path)

    duration = time.time() - start_time

    # Display results
    display_results(all_events, alerts, all_errors, duration, files_analyzed)

    # Export if requested
    if args.output:
        fmt = args.output.lower()
        if fmt == "json":
            generate_json_report(session_id, db_path, args.export_path or "logsentry_report.json")
            console.print(f"[green]JSON report saved to {args.export_path or 'logsentry_report.json'}[/green]")
        elif fmt == "csv":
            generate_csv_report(session_id, db_path, args.export_path or "logsentry_report.csv")
            console.print(f"[green]CSV report saved to {args.export_path or 'logsentry_report.csv'}[/green]")
        elif fmt == "pdf":
            generate_pdf_report(session_id, db_path, args.export_path or "logsentry_report.pdf")
            console.print(f"[green]PDF report saved to {args.export_path or 'logsentry_report.pdf'}[/green]")

    # ATT&CK export
    if args.attack:
        layer = build_attack_navigator_layer(alerts)
        export_path = args.attack_path or "logsentry_attack_layer.json"
        import json
        with open(export_path, "w") as f:
            json.dump(layer, f, indent=2)
        console.print(f"[green]ATT&CK Navigator layer saved to {export_path}[/green]")


def cmd_monitor(args):
    """Handle the 'monitor' command - real-time file tailing."""
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    class LogHandler(FileSystemEventHandler):
        def __init__(self, filepath, log_type, session_id, db_path):
            self.filepath = filepath
            self.log_type = log_type
            self.session_id = session_id
            self.db_path = db_path
            self.position = 0
            # Read existing content to get file size
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(0, 2)
                    self.position = f.tell()
            except FileNotFoundError:
                self.position = 0

        def on_modified(self, event):
            if event.src_path != self.filepath:
                return
            try:
                with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(self.position)
                    new_lines = f.readlines()
                    self.position = f.tell()

                if not new_lines:
                    return

                parser = get_parser(self.log_type)
                events = []
                for parsed in parser.__wrapped__(self.filepath, lines=new_lines) if hasattr(parser, '__wrapped__') else parser(self.filepath, from_lines=new_lines):
                    if parsed:
                        event = normalize_event(parsed, self.filepath, self.log_type)
                        if event:
                            events.append(event)

                if events:
                    insert_events_batch(events, self.session_id, self.db_path)
                    alerts = run_rules(events, self.session_id, self.db_path)

                    for alert in alerts:
                        severity = alert.get("severity", "MEDIUM")
                        color = SEVERITY_COLORS.get(severity, "white")
                        ts = alert.get("timestamp", "")
                        if hasattr(ts, "strftime"):
                            ts = ts.strftime("%H:%M:%S")
                        console.print(f"[{color} bold][ALERT {severity}][/{color} bold] {ts} {alert.get('src_ip', '')} -> {alert.get('rule_name', '')}")
                        if alert.get("details"):
                            console.print(f"  [dim]{alert['details'][:100]}[/dim]")
            except Exception as e:
                console.print(f"[red]Monitor error: {e}[/red]")

    db_path = init_db()
    session_id = create_session(db_path)

    filepath = args.file
    log_type = detect_log_type(filepath, args.type)

    console.print(Panel(f"[bold]LogSentry Monitor Mode[/bold]\nWatching: {filepath}\nType: {log_type}\nPress Ctrl+C to stop", border_style="cyan"))

    handler = LogHandler(filepath, log_type, session_id, db_path)
    observer = Observer()
    observer.schedule(handler, os.path.dirname(filepath) or ".", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        close_session(session_id, db_path)
        console.print("\n[yellow]Monitor stopped. Session closed.[/yellow]")
    observer.join()


def cmd_correlate(args):
    """Handle the 'correlate' command - multi-source analysis."""
    start_time = time.time()

    db_path = init_db()
    session_id = create_session(db_path)

    all_events = []
    all_errors = 0
    files_analyzed = 0

    sources = []
    if args.auth:
        events, errors, lt = ingest_file(args.auth, "auth", session_id, db_path)
        all_events.extend(events)
        all_errors += errors
        files_analyzed += 1
        sources.append("auth")
    if args.web:
        events, errors, lt = ingest_file(args.web, "apache_access", session_id, db_path)
        all_events.extend(events)
        all_errors += errors
        files_analyzed += 1
        sources.append("web")
    if args.firewall:
        events, errors, lt = ingest_file(args.firewall, "firewall", session_id, db_path)
        all_events.extend(events)
        all_errors += errors
        files_analyzed += 1
        sources.append("firewall")
    if args.windows:
        events, errors, lt = ingest_file(args.windows, "windows", session_id, db_path)
        all_events.extend(events)
        all_errors += errors
        files_analyzed += 1
        sources.append("windows")
    if args.generic:
        events, errors, lt = ingest_file(args.generic, "generic", session_id, db_path)
        all_events.extend(events)
        all_errors += errors
        files_analyzed += 1
        sources.append("generic")

    if not all_events:
        console.print("[red]No events ingested. Check file paths.[/red]")
        return

    console.print(f"[cyan]Correlating {len(all_events)} events from {len(sources)} sources...[/cyan]")

    # Run detection rules
    alerts = run_rules(all_events, session_id, db_path)

    # Run correlation engine
    profiles = correlate_events(all_events, alerts)

    # Store profiles
    from database import update_ip_profile
    for profile in profiles:
        update_ip_profile(profile, db_path)

    # Check threat intel
    from threat_intel.checker import check_ips
    threat_matches = check_ips([p["ip"] for p in profiles])
    if threat_matches:
        console.print(f"\n[red bold]⚠ {len(threat_matches)} IPs matched known threat actors![/red bold]")
        for match in threat_matches:
            console.print(f"  [red]{match['ip']} — {match.get('source', 'unknown')}: {match.get('category', 'malicious')}[/red]")

    close_session(session_id, db_path)
    duration = time.time() - start_time

    # Display results
    display_results(all_events, alerts, all_errors, duration, files_analyzed)

    # Show correlation summary
    if profiles:
        corr_table = Table(title="[bold]Cross-Source Correlation[/bold]", box=box.ROUNDED)
        corr_table.add_column("IP", style="cyan")
        corr_table.add_column("Sources", style="yellow")
        corr_table.add_column("Events", justify="right")
        corr_table.add_column("Rules Triggered", style="red")
        corr_table.add_column("Kill Chain Stages", style="magenta")

        for prof in sorted(profiles, key=lambda p: -p.get("event_count", 0))[:20]:
            corr_table.add_row(
                prof["ip"],
                prof.get("sources_seen", ""),
                str(prof.get("event_count", 0)),
                prof.get("rules_triggered", ""),
                prof.get("kill_chain", ""),
            )
        console.print()
        console.print(corr_table)

    # Export ATT&CK layer
    layer = build_attack_navigator_layer(alerts)
    export_path = args.attack_path or "logsentry_correlate_layer.json"
    import json
    with open(export_path, "w") as f:
        json.dump(layer, f, indent=2)
    console.print(f"\n[green]ATT&CK Navigator layer: {export_path}[/green]")


def cmd_dashboard(args):
    """Launch the Flask dashboard."""
    console.print("[cyan]Starting LogSentry Dashboard at http://localhost:5000[/cyan]")
    from dashboard.app import launch_dashboard
    launch_dashboard(port=args.port or 5000)


def main():
    parser = argparse.ArgumentParser(
        prog="logsentry",
        description="LogSentry — Multi-Source Log Analyzer & Threat Detector"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze log file(s)")
    analyze_parser.add_argument("--file", "-f", help="Single log file to analyze")
    analyze_parser.add_argument("--dir", "-d", help="Directory to scan for logs")
    analyze_parser.add_argument("--all", action="store_true", help="Process all files in directory")
    analyze_parser.add_argument("--type", "-t", help="Log type hint (auth, apache_access, etc.)")
    analyze_parser.add_argument("--output", "-o", choices=["json", "csv", "pdf"], help="Export format")
    analyze_parser.add_argument("--export-path", help="Export file path")
    analyze_parser.add_argument("--attack", action="store_true", help="Export ATT&CK Navigator layer")
    analyze_parser.add_argument("--attack-path", help="ATT&CK export path")

    # monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Real-time log monitoring")
    monitor_parser.add_argument("--file", "-f", required=True, help="File to monitor")
    monitor_parser.add_argument("--type", "-t", help="Log type hint")

    # correlate command
    corr_parser = subparsers.add_parser("correlate", help="Multi-source correlation")
    corr_parser.add_argument("--auth", help="Auth log file")
    corr_parser.add_argument("--web", help="Web access log file")
    corr_parser.add_argument("--firewall", help="Firewall log file")
    corr_parser.add_argument("--windows", help="Windows event log file")
    corr_parser.add_argument("--generic", help="Generic log file")
    corr_parser.add_argument("--attack-path", help="ATT&CK export path")

    # dashboard command
    dash_parser = subparsers.add_parser("dashboard", help="Launch web dashboard")
    dash_parser.add_argument("--port", "-p", type=int, default=5000, help="Dashboard port")

    args = parser.parse_args()

    if not args.command:
        console.print(BANNER)
        parser.print_help()
        return

    commands = {
        "analyze": cmd_analyze,
        "monitor": cmd_monitor,
        "correlate": cmd_correlate,
        "dashboard": cmd_dashboard,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
