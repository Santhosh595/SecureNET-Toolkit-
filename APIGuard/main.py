"""APIGuard — CLI entry point.

Usage:
    python main.py https://api.example.com --no-disclaimer
    python main.py https://api.example.com --auth bearer TOKEN
    python main.py https://api.example.com --spec openapi.json --auth bearer TOKEN
    python main.py https://api.example.com --category API1,API3,API8 --json report.json
    python main.py https://api.example.com --unsafe  # enable POST/PUT/DELETE
"""

from __future__ import annotations

import importlib
import os
import pkgutil
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import database as db
import reporter as rpt
from analyzer import ResponseAnalyzer
from auth import AuthConfig
from discovery import SpecParser, discover, extract_urls_from_json

_HERE = os.path.dirname(os.path.abspath(__file__))

# All OWASP test modules (API1-API10 + injection)
_TEST_MODULES: List[Tuple[str, str]] = [
    ("api1_bola", "API1:2023"),
    ("api2_broken_auth", "API2:2023"),
    ("api3_object_props", "API3:2023"),
    ("api4_rate_limiting", "API4:2023"),
    ("api5_function_auth", "API5:2023"),
    ("api6_business_flows", "API6:2023"),
    ("api7_ssrf", "API7:2023"),
    ("api8_misconfiguration", "API8:2023"),
    ("api9_inventory", "API9:2023"),
    ("api10_unsafe_consumption", "API10:2023"),
    ("injection", "BONUS"),
]


def _load_test_module(module_name: str) -> Optional[Callable]:
    """Dynamically import a test module and return its run() function."""
    try:
        mod = importlib.import_module(f"tests.{module_name}")
        return getattr(mod, "run", None)  # type: ignore
    except (ImportError, AttributeError):
        return None


def run_scan(
    target: str,
    auth_config: AuthConfig,
    spec_path: str = "",
    categories: Optional[List[str]] = None,
    unsafe: bool = False,
    user_agent: str = "APIGuard/1.0",
    timeout: int = 10,
    delay: float = 0.1,
    no_disclaimer: bool = False,
) -> Dict[str, Any]:
    """Run a full APIGuard scan. Returns results dict."""
    if not no_disclaimer:
        print("\n[!] APIGuard is for testing APIs you own or have explicit written permission to test.")
        print("[!] Unauthorized API testing is illegal.\n")

    from tests import ApiRequester

    requester = ApiRequester(target, auth_config, timeout=timeout, unsafe=unsafe)
    requester.session.headers["User-Agent"] = user_agent

    # 1. API Discovery
    all_endpoints: List[Dict] = []
    spec_endpoints: List[str] = []

    if spec_path and os.path.exists(spec_path):
        parser = SpecParser(spec_path)
        spec_eps = parser.parse()
        all_endpoints.extend(spec_eps)
        spec_endpoints = [e["path"] for e in spec_eps]
        print(f"[*] Parsed {len(spec_eps)} endpoints from {os.path.basename(spec_path)}")

    # Brute-force discovery
    discovered = discover(target, requester.request)
    for d in discovered:
        path = d.get("path", "")
        method = d.get("method", "GET")
        if not any(e["path"] == path and e["method"] == method for e in all_endpoints):
            all_endpoints.append({
                "method": method,
                "path": path,
                "parameters": "",
                "auth_required": 1,
                "source": "discovered",
            })
    print(f"[*] Brute-force: {len(discovered)} endpoints found (300 paths probed)")

    # Response crawling
    if all_endpoints:
        first_resp = requester.get(all_endpoints[0]["path"])
        if first_resp and first_resp.content:
            urls = extract_urls_from_json(first_resp.content.decode(errors="replace"), target)
            for url in urls[:20]:
                from urllib.parse import urlparse
                rel_path = urlparse(url).path
                if rel_path and not any(e["path"] == rel_path for e in all_endpoints):
                    all_endpoints.append({
                        "method": "GET",
                        "path": rel_path,
                        "parameters": "",
                        "auth_required": 0,
                        "source": "crawled",
                    })
        print(f"[*] Response crawling: extracted additional endpoints")

    # Store spec endpoints on requester for API9 shadow-API check
    requester._spec_endpoints = spec_endpoints  # type: ignore

    # 2. Save scan + endpoints to DB
    scan_id = db.save_scan(target, auth_config.auth_type, spec_path)
    for ep in all_endpoints:
        db.save_endpoint(
            scan_id,
            ep.get("method", "GET"),
            ep.get("path", "/"),
            ep.get("parameters", ""),
            ep.get("auth_required", 1),
            ep.get("source", "discovered"),
        )
    db.update_scan(scan_id, endpoints_found=len(all_endpoints))
    print(f"[*] Endpoints discovered: {len(all_endpoints)}")

    # 3. Filter by category
    category_filter = [c.upper() for c in (categories or [])]
    modules_to_run = _TEST_MODULES
    if category_filter:
        modules_to_run = [
            (mod, label) for mod, label in _TEST_MODULES
            if any(c in label or c in mod.upper() for c in category_filter)
        ]
    print(f"[*] Test modules: {len(modules_to_run)}")

    # 4. Run tests
    all_findings: List[Dict] = []
    total_tests = 0

    analyzer = ResponseAnalyzer()
    start_time = time.time()

    for mod_name, label in modules_to_run:
        run_func = _load_test_module(mod_name)
        if run_func is None:
            print(f"  [WARN] Could not load {mod_name}")
            continue
        try:
            findings = run_func(requester, all_endpoints)
            if findings:
                all_findings.extend(findings)
                for f_ in findings:
                    db.save_finding(scan_id, **f_)
            total_tests += 1
            print(f"  [{'VULN' if findings else 'OK '}] {label} ({mod_name}) — {len(findings)} finding(s)")
        except Exception as e:
            print(f"  [ERR ] {label} ({mod_name}) — {e}")
        time.sleep(delay)  # Polite scanning

    duration = time.time() - start_time
    db.update_scan(scan_id, tests_run=total_tests, findings_count=len(all_findings), duration=duration)

    return {
        "scan_id": scan_id,
        "target": target,
        "auth_type": auth_config.auth_type,
        "endpoints_found": len(all_endpoints),
        "tests_run": total_tests,
        "findings_count": len(all_findings),
        "findings": all_findings,
        "duration": round(duration, 2),
        "summary": rpt._summary(all_findings),
    }


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="APIGuard — OWASP API Top 10 Security Tester")
    ap.add_argument("url", nargs="?", help="Target API base URL")
    ap.add_argument("--auth", default="none", help="Auth: 'bearer TOKEN', 'apikey X-Key:Val', 'basic user:pass', 'cookie val', 'oauth TOKEN', 'header X:Y'")
    ap.add_argument("--auth-user", help="Low-privilege auth string (dual-mode)")
    ap.add_argument("--auth-admin", help="High-privilege auth string (dual-mode)")
    ap.add_argument("--spec", default="", help="OpenAPI/Swagger spec file path")
    ap.add_argument("--category", default="", help="Comma-separated: API1,API2,... or ALL")
    ap.add_argument("--unsafe", action="store_true", help="Enable POST/PUT/DELETE tests")
    ap.add_argument("--user-agent", default="APIGuard/1.0", help="Custom User-Agent")
    ap.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    ap.add_argument("--delay", type=float, default=0.1, help="Delay between tests (seconds)")
    ap.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer")
    ap.add_argument("--json", default="", help="Export findings to JSON file")
    ap.add_argument("--csv", default="", help="Export findings to CSV file")
    ap.add_argument("--sarif", default="", help="Export findings to SARIF file")
    ap.add_argument("--pdf", default="", help="Export findings to PDF file")

    args = ap.parse_args()

    if not args.url:
        ap.print_help()
        sys.exit(1)

    auth_config = AuthConfig.parse(args.auth)

    # Apply --unsafe flag
    os.environ["APIGUARD_UNSAFE"] = "1" if args.unsafe else "0"

    # Init DB
    db.init_db()

    # Parse categories
    cats = []
    if args.category and args.category.upper() != "ALL":
        cats = [c.strip() for c in args.category.split(",")]

    result = run_scan(
        target=args.url,
        auth_config=auth_config,
        spec_path=args.spec,
        categories=cats,
        unsafe=args.unsafe,
        user_agent=args.user_agent,
        timeout=args.timeout,
        delay=args.delay,
        no_disclaimer=args.no_disclaimer,
    )

    # === Rich Output ===
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.columns import Columns

        console = Console()
        console.print()
        console.print(Panel(f"[bold cyan]APIGuard — OWASP API Top 10 Scanner[/]\n[dim]Target:[/] {result['target']}\n[dim]Auth:[/] {result['auth_type']}\n[dim]Endpoints:[/] {result['endpoints_found']} | [dim]Tests:[/] {result['tests_run']} | [dim]Duration:[/] {result['duration']}s"))
        console.print()

        # Summary
        s = result["summary"]
        summary_parts = [
            f"[bold]Findings[/]: {s['total']}",
            f"[red]Critical[/]: {s['critical']}",
            f"[orange3]High[/]: {s['high']}",
            f"[yellow]Medium[/]: {s['medium']}",
            f"[cyan]Low[/]: {s['low']}",
        ]
        console.print(Columns(summary_parts))
        console.print()

        # Findings table
        if result["findings"]:
            table = Table(show_header=True, header_style="bold", expand=True)
            table.add_column("OWASP", style="cyan")
            table.add_column("Endpoint", style="white")
            table.add_column("Method", style="dim")
            table.add_column("Severity")
            table.add_column("Test", style="white", no_wrap=False)
            for f_ in result["findings"]:
                sev = f_.get("severity", "MEDIUM")
                sev_style = {"CRITICAL":"red", "HIGH":"orange3", "MEDIUM":"yellow", "LOW":"cyan", "INFO":"dim"}.get(sev, "white")
                table.add_row(
                    f_.get("owasp_category", ""),
                    f_.get("endpoint", "")[:40],
                    f_.get("method", ""),
                    f"[{sev_style}]{sev}[/]",
                    f_.get("test_name", "")[:50],
                )
            console.print(table)
    except ImportError:
        # Fallback plain text
        print(f"\nAPIGuard Scan Complete — {result['findings_count']} findings ({result['duration']}s)")
        for f_ in result["findings"]:
            print(f"  [{f_['severity']}] {f_['owasp_category']} @ {f_['endpoint']}: {f_['test_name']}")

    # Exports
    scan_info = {"target": result["target"], "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "auth_type": result["auth_type"], "findings_count": result["findings_count"]}
    if args.json:
        rpt.export_json(result["findings"], args.json, scan_info)
        print(f"[*] JSON report: {args.json}")
    if args.csv:
        rpt.export_csv(result["findings"], args.csv)
        print(f"[*] CSV report: {args.csv}")
    if args.sarif:
        rpt.export_sarif(result["findings"], args.sarif)
        print(f"[*] SARIF report: {args.sarif}")
    if args.pdf:
        rpt.export_pdf(result["findings"], args.pdf, scan_info)
        print(f"[*] PDF report: {args.pdf}")


if __name__ == "__main__":
    main()
