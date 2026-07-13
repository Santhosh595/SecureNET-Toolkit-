"""TechFinger — CLI entry point (WhatWeb/httpx-style fingerprinting).

Usage:
    python main.py https://example.com
    python main.py https://example.com --full --no-disclaimer
    python main.py --bulk urls.txt --csv out.csv --delay 2
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
from rich.text import Text

from fingerprinter import fetch, fingerprint, BROWSER_UA
from database import (init_db, save_scan, save_technologies,
                     save_header_checks, save_cves)
from bulk import scan_urls, export_csv

console = Console()

CAT_ORDER = ["server", "framework", "cms", "cdn",
              "analytics", "jslibs", "favicon"]
CAT_LABEL = {"server": "Server", "framework": "Framework", "cms": "CMS",
             "cdn": "CDN", "analytics": "Analytics", "jslibs": "JS Library",
             "favicon": "Favicon"}
CONF_COLOR = {"CERTAIN": "bold green", "LIKELY": "green",
               "POSSIBLE": "yellow", "UNCERTAIN": "dim"}
RISK_COLOR = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
               "INFO": "blue"}

DISCLAIMER = ("[bold red]DISCLAIMER[/]\n\n"
    "TechFinger sends a single read-only HTTP request.\n"
    "Only fingerprint sites you own or have permission to assess.")


def show_disclaimer() -> bool:
    console.print(Panel(DISCLAIMER, border_style="red", padding=(1, 2)))
    console.print()
    return Confirm.ask("[bold]Do you have authorization to scan this target?[/]",
                        default=False)


def _display_summary(res: dict, url: str, status, dur: float,
                     size_kb: float) -> None:
    console.rule("[bold cyan]TechFinger — Web Technology Fingerprinting[/]",
                  style="cyan")
    console.print()
    info = (f"Target: [cyan]{url}[/]\n"
            f"Scan time: [green]{dur:.1f}s[/] | "
            f"Response: [green]{status or 'ERR'}[/] | "
            f"Size: [green]{size_kb:.1f}KB[/]")
    if res.get("waf_detected"):
        info += "\n[bold yellow]⚠ WAF / bot-protection challenge detected — "
        info += "reporting CDN/WAF where identifiable.[/]"
    console.print(Panel(info, border_style="cyan", padding=(1, 2)))

    techs = res["technologies"]
    console.print("[bold]DETECTED TECHNOLOGIES[/]")
    if not techs:
        console.print("[yellow]No technologies confidently identified.[/]")
    else:
        t = Table(show_header=True, header_style="bold white", box=box.ROUNDED)
        t.add_column("Category", min_width=12, max_width=14)
        t.add_column("Technology", min_width=18, max_width=22)
        t.add_column("Version", min_width=14, max_width=18)
        t.add_column("Confidence", min_width=12, max_width=12, justify="center")
        t.add_column("Risk", min_width=10, max_width=10, justify="center")
        for cat in CAT_ORDER:
            for tech in sorted(techs, key=lambda x: -x.confidence):
                if tech.category != cat:
                    continue
                cc = CONF_COLOR.get(tech.confidence_label, "white")
                rc = RISK_COLOR.get(tech.risk, "white")
                t.add_row(
                    CAT_LABEL.get(cat, cat), tech.name,
                    f"{tech.name} {tech.version}" if tech.version else
                    f"{tech.name} (version unknown)",
                    f"[{cc}]{tech.confidence_label} ({tech.confidence})[/]",
                    f"[{rc}]{tech.risk}[/]")
        console.print(t)

    _display_headers(res["header_checks"])
    _display_cves(res["cve_correlations"])
    _display_risk(res["technologies"])


def _display_headers(checks) -> None:
    console.print("\n[bold]SECURITY HEADERS[/]")
    t = Table(show_header=True, header_style="bold white", box=box.ROUNDED)
    t.add_column("Header", min_width=28, max_width=32)
    t.add_column("Status", min_width=12, justify="center")
    t.add_column("Value", min_width=20, max_width=40)
    for c in checks:
        if c.status == "PASS":
            st = Text("✓ PRESENT", style="bold green")
            val = Text((c.value or "")[:38], style="green")
        else:
            st = Text("✗ MISSING", style="bold red")
            val = Text(c.severitiy, style="red")
        t.add_row(c.name, st, val)
    console.print(t)


def _display_cves(cves) -> None:
    if not cves:
        return
    console.print("\n[bold red]CVE CORRELATIONS[/]")
    for c in sorted(cves, key=lambda x: -x.cvss):
        color = RISK_COLOR.get(c.severitiy, "white")
        ver = c.version or "?"
        console.print(f"  [{color}]{c.tech} {ver} → {c.cve} "
                      f"({c.severitiy}, CVSS {c.cvss})[/]")


def _display_risk(techs) -> None:
    tally = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for t in techs:
        sev = t.risk.upper()
        for k in tally:
            if sev.startswith(k[:4]):
                tally[k] += 1
                break
    console.print("\n[bold]RISK SUMMARY[/]")
    console.print(f"  Critical: {tally['CRITICAL']} | High: {tally['HIGH']} "
                  f"| Medium: {tally['MEDIUM']} | Info: {tally['INFO']}")


def run_single(url: str, full: bool, ua: str, timeout: float) -> None:
    t0 = time.time()
    resp = fetch(url, timeout=timeout, full=full, user_agent=ua)
    if resp.error:
        console.print(f"[red]Error: {resp.error}[/]")
        return
    res = fingerprint(resp)
    dur = time.time() - t0
    size_kb = (len(resp.body.encode("utf-8", "ignore")) / 1024.0)
    _display_summary(res, url, resp.status, dur, size_kb)
    try:
        init_db()
        sid = save_scan(url, len(res["technologies"]),
                       len(res["cve_correlations"]), dur, resp.status,
                       resp.waf_detected)
        save_technologies(sid, res["technologies"])
        save_header_checks(sid, res["header_checks"])
        save_cves(sid, res["cve_correlations"])
    except Exception as e:
        console.print(f"[dim]DB save skipped: {e}[/]")


def main() -> None:
    p = argparse.ArgumentParser(
        description="TechFinger — web technology fingerprinting")
    p.add_argument("target", nargs="?", help="Target URL")
    p.add_argument("--bulk", metavar="FILE", help="Bulk-scan URLs from file")
    p.add_argument("--csv", metavar="FILE", help="Export bulk results to CSV")
    p.add_argument("--full", action="store_true",
                    help="Also fetch robots.txt + sitemap.xml")
    p.add_argument("--delay", type=float, default=1.0,
                    help="Seconds between bulk requests (default 1)")
    p.add_argument("--user-agent", default="", help="Custom User-Agent")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--no-disclaimer", action="store_true",
                    help="Skip disclaimer prompt")
    args = p.parse_args()

    if not args.target and not args.bulk:
        p.print_help()
        sys.exit(1)

    if not args.no_disclaimer and not show_disclaimer():
        console.print("[dim]Scan cancelled.[/]")
        sys.exit(0)

    ua = args.user_agent or BROWSER_UA

    if args.bulk:
        urls = [u.strip() for u in open(args.bulk) if u.strip()]
        results = scan_urls(urls, delay=args.delay, full=args.full,
                            user_agent=ua, timeout=args.timeout)
        t = Table(show_header=True, header_style="bold white", box=box.ROUNDED)
        for col in ("URL", "Tech", "CVE", "Crit", "High", "Med", "Info", "WAF"):
            t.add_column(col, justify="center" if col != "URL" else "left")
        for r in results:
            rk = r["risk"]
            t.add_row(r["url"], str(r["tech_count"]), str(r["cve_count"]),
                       str(rk["CRITICAL"]), str(rk["HIGH"]), str(rk["MEDIUM"]),
                       str(rk["INFO"]), "yes" if r["waf"] else "—")
        console.print(t)
        if args.csv:
            export_csv(results, args.csv)
            console.print(f"[green]CSV → {args.csv}[/]")
        return

    run_single(args.target, args.full, ua, args.timeout)


if __name__ == "__main__":
    main()
