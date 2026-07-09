"""VulnProbe — CLI entry point (Nuclei-style template probe engine).

Usage:
    python main.py https://example.com
    python main.py https://example.com --severity high,critical
    python main.py targets.txt --category exposed-panels --rate-limit 200
    python main.py https://example.com --dry-run
    python main.py https://example.com --templates ./my-templates --custom

All requests are read-only (GET) by default. POST is only allowed when a
template explicitly sets ``safe: true`` with a ``safe_reason``.
"""

from __future__ import annotations

import argparse
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich import box
from rich.prompt import Confirm

from engine import load_templates, Scanner
from engine.scanner import resolve_targets
from database import init_db, create_scan, add_finding, update_scan, sync_templates
from reporter import to_json

console = Console()

SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

DISCLAIMER = (
    "[bold red]DISCLAIMER[/]\n\n"
    "VulnProbe is for authorized security testing only.\n"
    "Scanning targets without permission is illegal."
)


def show_disclaimer() -> bool:
    console.print(Panel(DISCLAIMER, border_style="red", padding=(1, 2)))
    return Confirm.ask("[bold]Do you have authorization to scan this target?[/]", default=False)


def _split(val):
    if not val:
        return None
    return {v.strip().lower() for v in val.split(",") if v.strip()}


def run_scan(args) -> int:
    target = args.target.strip()
    targets = resolve_targets(target)
    if not targets:
        console.print("[red]No valid targets resolved.[/]")
        return 1

    console.print(f"[dim]Resolved {len(targets)} target(s):[/]")
    for t in targets:
        console.print(f"  [cyan]{t}[/]")

    sev = _split(args.severity)
    cat = _split(args.category)
    tags = _split(args.tags)

    # load built-ins + optional custom dir(s)
    templates, errors = load_templates(
        severity_filter=sev, category_filter=cat, tag_filter=tags
    )
    if args.templates:
        extra, err2 = load_templates(
            args.templates, severity_filter=sev, category_filter=cat, tag_filter=tags
        )
        templates += extra
        errors += err2

    if errors:
        for fname, msg in errors:
            console.print(f"[yellow][WARN][/] template '{fname}': {msg}")
    if not templates:
        console.print("[red]No valid templates loaded (check filters/paths).[/]")
        return 1
    console.print(f"[green]Loaded {len(templates)} templates.[/]")

    if args.dry_run:
        console.print(Panel("[bold]DRY RUN[/] — no requests will be sent", border_style="yellow"))
        scanner = Scanner(templates, workers=args.threads, rate_limit=args.rate_limit,
                          timeout=args.timeout, dry_run=True)
        total = len(targets) * len(templates)
        with console.status(f"[cyan]Planning {total} requests...[/]"):
            scanner.run(targets)
        console.print(f"[yellow]Dry run complete: {total} requests planned across {len(templates)} templates.[/]")
        return 0

    init_db()
    sync_templates(templates)
    scan_id = create_scan(target, template_filter=f"sev={args.severity}", templates_run=len(templates))
    start = time.time()

    state = {"done": 0, "total": len(targets) * len(templates),
              "findings": 0, "critical": 0, "high": 0}
    bar_len = 30

    def render_progress() -> Table:
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("")
        done, total = state["done"], max(1, state["total"])
        filled = int(bar_len * done / total)
        bar = "[" + "#" * filled + "-" * (bar_len - filled) + "]"
        t.add_row(Text(f"{bar} {done}/{total} templates | findings: {state['findings']} "
                       f"({state['critical']} CRIT, {state['high']} HIGH)", style="cyan"))
        return t

    live = Live(render_progress(), console=console, refresh_per_second=4)

    def on_finding(f):
        if f.get("dry_run"):
            return
        state["findings"] += 1
        sev_k = f.get("severity", "info")
        if sev_k == "critical":
            state["critical"] += 1
        elif sev_k == "high":
            state["high"] += 1
        color = SEVERITY_COLOR.get(sev_k, "white")
        console.print(
            f"[{color}][{sev_k.upper()}][/] {f['template_id']} → "
            f"{f['url']}{f.get('matched_path','')}"
        )
        if f.get("extracted"):
            console.print(f"    [dim]extracted: {f['extracted']}[/]")

    def on_progress(done, total):
        state["done"] = done
        state["total"] = total

    scanner = Scanner(
        templates, workers=args.threads, rate_limit=args.rate_limit,
        timeout=args.timeout, on_finding=on_finding, on_progress=on_progress,
    )
    live.start()
    all_findings = scanner.run(targets)
    live.stop()

    duration = time.time() - start
    # only persist findings passing the severity filter (for display parity)
    for f in all_findings:
        add_finding(scan_id, f)
    update_scan(scan_id, len(all_findings), duration)

    display_summary(all_findings, duration, target, len(templates))
    console.print(f"[dim]Scan saved as scan_id={scan_id}.[/]")
    return 0


def display_summary(findings, duration, target, tmpl_count):
    console.print()
    console.rule("[bold cyan]VulnProbe — Template Vulnerability Scanner[/]", style="cyan")
    console.print()

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    summary = f"Target: {target}\nFindings: {len(findings)} | Templates: {tmpl_count}"
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
    table.add_column("Template", min_width=26)
    table.add_column("URL", min_width=30)
    table.add_column("Matched Path", min_width=20)
    table.add_column("HTTP", min_width=6, justify="center")

    for f in findings:
        color = SEVERITY_COLOR.get(f["severity"], "white")
        table.add_row(
            f"[{color}]{f['severity'].upper()}[/]",
            f["template_id"],
            f["url"],
            f.get("matched_path", ""),
            str(f.get("status_code", "")),
        )
    console.print(table)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VulnProbe — template-based HTTP vulnerability scanner (Nuclei-style)"
    )
    parser.add_argument("target", help="URL, @file-of-URLs, or domain name")
    parser.add_argument("--templates", help="Custom template directory or .yaml file")
    parser.add_argument("--template", help="Single template file (alias of --templates)")
    parser.add_argument("--severity", help="Comma list: critical,high,medium,low,info")
    parser.add_argument("--category", help="Category slug filter")
    parser.add_argument("--tags", help="Comma-separated tags (match any)")
    parser.add_argument("--rate-limit", type=int, default=150, help="Requests/min per host")
    parser.add_argument("--threads", type=int, default=25, help="Worker threads")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout (s)")
    parser.add_argument("--dry-run", action="store_true", help="Plan only; send no requests")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout")
    parser.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer prompt")
    args = parser.parse_args()

    if args.template:
        args.templates = args.template

    if not args.no_disclaimer and not args.dry_run:
        if not show_disclaimer():
            console.print("[dim]Scan cancelled.[/]")
            return 0

    rc = run_scan(args)
    return rc


if __name__ == "__main__":
    sys.exit(main())
