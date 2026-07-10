"""PathProbe — CLI entry point (feroxbuster-style content discovery).

Usage:
    python main.py https://example.com
    python main.py https://example.com --wordlist common,api
    python main.py https://example.com --extensions php,bak,zip --threads 80
    python main.py https://example.com --recursive --depth 3 --prefix /api/v1
"""

from __future__ import annotations

import argparse
import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

from engine import Scanner
from engine import filter as filt
from engine.wordlist import available_wordlists
from database import init_db, create_scan, add_finding, update_scan, register_wordlists

console = Console()

DISCLAIMER = (
    "[bold red]DISCLAIMER[/]\n\n"
    "PathProbe is for authorized testing only.\n"
    "Scanning websites without permission is illegal."
)

STATUS_COLOR = {
    200: "bold green", 201: "bold green", 204: "bold green",
    301: "yellow", 302: "yellow", 303: "yellow", 307: "yellow", 308: "yellow",
    401: "red", 403: "red", 405: "cyan", 500: "bold red", 502: "bold red",
    503: "bold red",
}


def show_disclaimer() -> bool:
    console.print(Panel(DISCLAIMER, border_style="red", padding=(1, 2)))
    return True


def parse_list(s: str | None) -> list[str] | None:
    if not s:
        return None
    return [x.strip() for x in s.split(",") if x.strip()]


def parse_status_set(s: str | None) -> set[int] | None:
    if not s:
        return None
    out = set()
    for part in s.split(","):
        part = part.strip()
        if part.isdigit():
            out.add(int(part))
    return out


def run(target: str, args) -> int:
    init_db()
    register_wordlists(available_wordlists())

    extensions = parse_list(args.extensions)
    show = parse_status_set(args.filter_status)
    hide = parse_status_set(args.hide_status)

    # large scan guard
    from engine.wordlist import build_wordlist
    approx = len(build_wordlist(args.wordlist, extensions, args.prefix, args.no_extension_original))
    if approx > Scanner.MAX_REQUESTS:
        console.print(f"[yellow]Warning:[/] ~{approx} requests exceed the 50,000 cap. Truncating wordlist.")
        # trimming happens in scanner via MAX_REQUESTS guard

    scanner = Scanner(
        target, args.wordlist,
        extensions=extensions, prefix=args.prefix,
        no_original=args.no_extension_original,
        threads=min(args.threads, Scanner.MAX_THREADS),
        timeout=args.timeout,
        rate_limit=args.rate_limit, delay_ms=args.delay,
        headers=parse_headers(args.headers),
        cookies=parse_kv(args.cookies),
        user_agent=args.user_agent,
        proxy=args.proxy,
        recursive=args.recursive, depth=args.depth,
        recursive_status=parse_status_set(args.recursive_status) or {200, 301, 302},
        show=show, hide=hide,
        filter_size=args.filter_size,
        filter_size_range=parse_range(args.filter_size_range),
        filter_words=parse_list(args.filter_words),
        wildcard_check=not args.no_wildcard,
        respect_robots=args.respect_robots,
    )

    scan_id = create_scan(target, args.wordlist,
                          ",".join(extensions) if extensions else "", args.threads)

    findings: list[dict] = []
    state = {"done": 0, "total": scanner.total, "found": 0, "start": time.time(),
             "reqs": 0}
    rate_window: list[float] = []

    def on_result(r):
        findings.append(r)
        state["found"] = len(findings)
        color = STATUS_COLOR.get(r["status"], "white")
        star = " ★ INTERESTING" if r.get("interesting") else ""
        warn = " ⚠" if r["status"] in (401, 403) else ""
        redirect = f" → {r['redirect_to']}" if r.get("redirect_to") else ""
        console.print(
            f"[{color}]{r['status']}[/]  {r['size']}B  {r['time_ms']}ms  "
            f"{r['url']}{redirect}{warn}{star}"
        )
        if args.output:
            try:
                with open(args.output, "a", encoding="utf-8") as fh:
                    fh.write(r["url"] + "\n")
            except OSError:
                pass

    def on_progress(done, total):
        state["done"] = done
        rate_window.append(time.time())
        rate_window[:] = [t for t in rate_window if time.time() - t <= 1]
        state["rate"] = len(rate_window)

    def on_status(s):
        pass

    # baseline warning
    console.print(f"[dim]Loaded {scanner.total} candidate paths from '{args.wordlist}'.[/]")
    console.print(f"[dim]Threads: {scanner.threads} | Extensions: {extensions or 'none'} | "
                   f"Recursive: {args.recursive} (depth {args.depth})[/]")

    scanner.on_result = on_result
    scanner.on_progress = on_progress
    scanner.on_status = on_status

    try:
        results, duration = scanner.run()
        # on_result already streamed; ensure DB written
        for r in results:
            add_finding(scan_id, r)
        update_scan(scan_id, scanner.total, scanner.found, duration)
    except KeyboardInterrupt:
        scanner.stop()
        console.print("\n[yellow]Interrupted by user.[/]")
        results, duration = findings, time.time() - state["start"]
        for r in results:
            add_finding(scan_id, r)
        update_scan(scan_id, scanner.done, scanner.found, duration)
        return 1

    _summary(target, scanner, findings, duration)
    return 0


def parse_headers(s: str | None) -> dict:
    if not s:
        return {}
    out = {}
    for part in s.split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def parse_kv(s: str | None) -> dict:
    if not s:
        return {}
    out = {}
    for part in s.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def parse_range(s: str | None) -> tuple[int, int] | None:
    if not s or "-" not in s:
        return None
    lo, hi = s.split("-", 1)
    try:
        return (int(lo), int(hi))
    except ValueError:
        return None


def _summary(target, scanner, findings, duration):
    console.print()
    console.rule("[bold cyan]PathProbe — Scan Complete", style="cyan")
    cats = {"found": 0, "redirect": 0, "protected": 0, "error": 0}
    for f in findings:
        cats[filt.category(f["status"])] = cats.get(filt.category(f["status"]), 0) + 1
    interesting = sum(1 for f in findings if f.get("interesting"))
    avg = scanner.total / duration if duration else 0
    summary = (
        f"Target: {target}\n"
        f"Total requests: {scanner.total}\n"
        f"Interesting findings: {interesting}\n"
        f"Protected (401/403): {cats['protected']}\n"
        f"Redirects: {cats['redirect']}\n"
        f"Errors: {cats['error']}\n"
        f"Total time: {duration:.1f}s  ({avg:.1f} req/s avg)"
    )
    console.print(Panel(summary, border_style="cyan", padding=(1, 2)))
    if findings:
        table = Table(show_header=True, header_style="bold white", expand=True)
        table.add_column("Status", justify="center", min_width=8)
        table.add_column("URL", min_width=40)
        table.add_column("Size", justify="right", min_width=8)
        table.add_column("Time", justify="right", min_width=8)
        table.add_column("Redirect", min_width=24)
        for f in sorted(findings, key=lambda x: (x["status"], x["url"])):
            color = STATUS_COLOR.get(f["status"], "white")
            table.add_row(f"[{color}]{f['status']}[/]", f["url"], str(f["size"]),
                          f"{f['time_ms']}ms", f.get("redirect_to") or "—")
        console.print(table)


def main() -> None:
    p = argparse.ArgumentParser(description="PathProbe — multi-threaded web content discovery")
    p.add_argument("target", help="Base URL (e.g., https://example.com)")
    p.add_argument("--wordlist", default="common", help="Built-in name(s) or file(s), comma-separated")
    p.add_argument("--extensions", help="Append extensions: php,html,bak,zip")
    p.add_argument("--no-extension-original", action="store_true", help="Skip bare word (only extensions)")
    p.add_argument("--prefix", default="", help="Path prefix for all words: /api/v1")
    p.add_argument("--threads", type=int, default=50, help="Threads (max 200)")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (s)")
    p.add_argument("--rate-limit", type=int, default=None, help="Max requests per second")
    p.add_argument("--delay", type=int, default=0, help="Fixed delay between requests (ms)")
    p.add_argument("--headers", help='Custom headers: "X-Fwd-For: 1.1.1.1; Auth: Bearer x"')
    p.add_argument("--cookies", help='Custom cookies: "session=abc; uid=1"')
    p.add_argument("--user-agent", help="Custom User-Agent (default: rotate 5 UAs)")
    p.add_argument("--proxy", help="HTTP/HTTPS proxy: http://127.0.0.1:8080")
    p.add_argument("--recursive", action="store_true", help="Recursively scan found directories")
    p.add_argument("--depth", type=int, default=2, help="Max recursion depth")
    p.add_argument("--recursive-status", default="200,301,302", help="Status codes that trigger recursion")
    p.add_argument("--filter-status", help="Only show these status codes: 200,301,403")
    p.add_argument("--hide-status", help="Hide these status codes")
    p.add_argument("--filter-size", type=int, default=None, help="Hide exact response size")
    p.add_argument("--filter-size-range", help="Hide size range: 100-200")
    p.add_argument("--filter-words", help="Hide responses containing: not found,404,error")
    p.add_argument("--no-wildcard", action="store_true", help="Disable wildcard false-positive detection")
    p.add_argument("--respect-robots", action="store_true", help="Skip paths disallowed by robots.txt")
    p.add_argument("--output", help="Write found URLs (one per line) to this file")
    p.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer")
    args = p.parse_args()

    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if not args.no_disclaimer:
        show_disclaimer()
    console.print()
    sys.exit(run(target, args))


if __name__ == "__main__":
    main()
