"""JWTInspect — CLI entry point with Rich panels.

Usage:
    python main.py <token>
    python main.py <token> --crack
    python main.py <token> --compare <other_token>
    python main.py <token> --wordlist /path/to/secrets.txt
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich import box
from rich.prompt import Confirm

from parser import parse_jwt, format_timestamp, format_duration
from tests import run_all_tests, get_verdict, _severity_color
from reporter import generate_report

console = Console()

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "secrets.txt")


def load_wordlist(path: str) -> list[str]:
    """Load wordlist file."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]Wordlist not found: {path}[/]")
        return []


def display_parsed(parsed: ParsedJWT) -> None:
    """Display decoded token with Rich."""
    # Header
    header_json = json.dumps(parsed.header, indent=2)
    console.print(Panel(
        Syntax(header_json, "json", theme="monokai"),
        title="[bold]Header[/]", border_style="cyan",
    ))

    # Payload
    payload_json = json.dumps(parsed.payload, indent=2)
    console.print(Panel(
        Syntax(payload_json, "json", theme="monokai"),
        title="[bold]Payload[/]", border_style="cyan",
    ))

    # Signature info
    sig_info = Text()
    sig_info.append(f"Algorithm: {parsed.algorithm}\n", style="bold")
    sig_info.append(f"Token Type: {parsed.token_type}\n")
    sig_info.append(f"Signature: {parsed.signature[:40]}..." if len(parsed.signature) > 40 else f"Signature: {parsed.signature}")
    console.print(Panel(sig_info, title="[bold]Signature[/]", border_style="cyan"))


def display_claims(parsed: ParsedJWT) -> None:
    """Display claims analysis."""
    claims = parsed.claims
    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED)
    table.add_column("Claim", min_width=12)
    table.add_column("Value", min_width=30)
    table.add_column("Status", min_width=15, justify="center")

    # Standard claims
    claim_rows = [
        ("iss (Issuer)", claims.iss or "—"),
        ("sub (Subject)", claims.sub or "—"),
        ("aud (Audience)", claims.aud or "—"),
        ("exp (Expires)", f"{claims.exp} ({format_timestamp(claims.exp)})" if claims.exp else "MISSING"),
        ("iat (Issued At)", f"{claims.iat} ({format_timestamp(claims.iat)})" if claims.iat else "MISSING"),
        ("nbf (Not Before)", f"{claims.nbf} ({format_timestamp(claims.nbf)})" if claims.nbf else "—"),
        ("jti (JWT ID)", claims.jti or "—"),
    ]

    for name, value in claim_rows:
        status = ""
        if "MISSING" in str(value):
            status = "[red]MISSING[/]"
        elif "exp" in name.lower() and parsed.is_expired:
            status = "[red]EXPIRED[/]"
        elif "exp" in name.lower() and parsed.expires_in and parsed.expires_in < 3600:
            status = "[yellow]EXPIRING SOON[/]"
        else:
            status = "[green]OK[/]"
        table.add_row(name, str(value), status)

    # Time analysis
    table.add_row("Token Age", format_duration(parsed.issued_ago))
    table.add_row("Time to Expiry", format_duration(parsed.expires_in))
    table.add_row("Time Valid", "YES" if parsed.is_valid_time else "NO")

    console.print(table)


def display_test_results(results: list) -> None:
    """Display security test results."""
    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED, expand=True)
    table.add_column("Test", min_width=30)
    table.add_column("Result", min_width=8, justify="center")
    table.add_column("Severity", min_width=10, justify="center")
    table.add_column("Finding", min_width=40)

    for r in results:
        color = _severity_color(r.severity)
        result_color = {"PASS": "green", "FAIL": "red", "WARNING": "yellow", "INFO": "dim"}.get(r.result, "white")
        table.add_row(
            r.test_name,
            f"[{result_color}]{r.result}[/]",
            f"[{color}]{r.severity}[/]",
            r.finding[:80],
        )

    console.print(table)

    # Detailed findings for FAIL/WARNING
    for r in results:
        if r.result in ("FAIL", "WARNING"):
            console.print()
            color = _severity_color(r.severity)
            console.print(Panel(
                f"[{color}]{r.finding}[/]\n\n"
                f"[bold]Proof:[/] {r.proof}\n\n"
                f"[bold]Remediation:[/] {r.remediation}",
                title=f"[bold]{r.test_name}[/]",
                border_style=color.split()[-1] if color != "dim" else "dim",
            ))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="JWTInspect — JWT security analyzer",
        epilog="Example: python main.py eyJhbGciOiJIUzI1NiIs...",
    )
    parser.add_argument("token", help="JWT token to analyze")
    parser.add_argument("--crack", action="store_true", help="Attempt secret brute force")
    parser.add_argument("--wordlist", type=str, default=None, help="Custom wordlist for cracking")
    parser.add_argument("--compare", type=str, default=None, help="Second token for claim diff")
    parser.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer")
    parser.add_argument("--save", type=str, default=None, help="Save report to JSON file")
    args = parser.parse_args()

    if not args.no_disclaimer:
        if not Confirm.ask("[bold]Do you have authorization to test this token?[/]", default=False):
            console.print("[dim]Analysis cancelled.[/]")
            sys.exit(0)

    start_time = time.time()

    # Parse token
    parsed = parse_jwt(args.token)

    if parsed.errors:
        console.print(f"[red]Error: {'; '.join(parsed.errors)}[/]")
        sys.exit(1)

    # Display decoded
    console.print()
    console.rule("[bold cyan]JWTInspect — Security Analyzer", style="cyan")
    console.print()

    display_parsed(parsed)
    console.print()
    display_claims(parsed)

    # Load wordlist if cracking
    wordlist = []
    if args.crack:
        wl_path = args.wordlist or DEFAULT_WORDLIST
        wordlist = load_wordlist(wl_path)
        console.print(f"\n[dim]Loaded {len(wordlist)} secrets from {os.path.basename(wl_path)}[/]")

    # Run tests
    console.print("\n[dim]Running security tests...[/]")
    results = run_all_tests(parsed, wordlist, args.compare)

    console.print()
    display_test_results(results)

    # Verdict
    verdict, verdict_color = get_verdict(results)
    console.print()
    console.print(Panel(
        f"[{verdict_color}]{verdict}[/]",
        title="[bold]Overall Verdict[/]",
        border_style=verdict_color.split()[-1] if verdict_color != "dim" else "dim",
        padding=(1, 2),
    ))

    # Save report
    if args.save:
        duration = time.time() - start_time
        report = generate_report(parsed, results, len(wordlist), duration)
        with open(args.save, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        console.print(f"\n[green]Report saved to {args.save}[/]")


if __name__ == "__main__":
    main()
