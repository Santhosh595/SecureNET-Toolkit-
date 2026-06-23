"""HashDetect — CLI entry point.

Usage:
    python main.py <hash>
    python main.py <hash> --crack
    python main.py <hash> --crack --wordlist /path/to/list.txt
"""

from __future__ import annotations

import argparse
import os
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.prompt import Confirm

from detector import detect_hash, Confidence
from cracker import load_wordlist, crack_hash

console = Console()

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "common.txt")


def display_result(result, crack_result=None) -> None:
    """Render detection results with Rich."""
    console.print()
    console.rule("[bold cyan]HashDetect — Hash Identifier & Cracker", style="cyan")
    console.print()

    # Input info
    inp = Text()
    inp.append("Input: ", style="bold")
    inp.append(result.input_hash[:80])
    if len(result.input_hash) > 80:
        inp.append("...")
    console.print(inp)

    if result.error:
        console.print(f"\n[red]Error: {result.error}[/]")
        return

    # Summary
    hi = sum(1 for m in result.matches if m.confidence == Confidence.HIGH.value)
    console.print(f"\n[dim]Hex: {result.is_valid_hex}[/]  |  [dim]Base64: {result.is_base64}[/]  |  [bold]{len(result.matches)} possible types detected[/]")

    # Results table
    table = Table(show_header=True, header_style="bold white", box=box.ROUNDED, expand=True)
    table.add_column("Hash Type", min_width=14)
    table.add_column("Confidence", min_width=10, justify="center")
    table.add_column("Category", min_width=14, justify="center")
    table.add_column("Crackable", min_width=9, justify="center")
    table.add_column("Note", min_width=40)

    for m in result.matches:
        conf_color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(m.confidence, "white")
        crack_color = "green" if m.crackable else "red"
        table.add_row(
            m.name,
            f"[{conf_color}]{m.confidence}[/]",
            m.category,
            f"[{crack_color}]{'YES' if m.crackable else 'NO'}[/]",
            m.note,
        )

    console.print(table)

    # Crack result
    if crack_result:
        found, attempted, elapsed = crack_result
        console.print()
        if found:
            console.print(Panel(
                f"[bold green]CRACKED![/]\n\n"
                f"Plaintext: [bold]{found}[/]\n"
                f"Attempts: {attempted}\n"
                f"Time: {elapsed}s",
                border_style="green", padding=(1, 2),
            ))
        else:
            console.print(Panel(
                f"[bold yellow]Not found in wordlist[/]\n\n"
                f"Attempts: {attempted}\n"
                f"Time: {elapsed}s",
                border_style="yellow", padding=(1, 2),
            ))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HashDetect — Identify and crack hash types",
        epilog="Example: python main.py 5f4dcc3b5aa765d61d8327deb882cf99",
    )
    parser.add_argument("hash", help="Hash string to analyze")
    parser.add_argument("--crack", action="store_true", help="Attempt wordlist cracking")
    parser.add_argument("--wordlist", type=str, default=None, help="Custom wordlist file path")
    parser.add_argument("--timeout", type=float, default=30.0, help="Crack timeout in seconds (default: 30)")
    args = parser.parse_args()

    # Detect
    result = detect_hash(args.hash)

    if result.error:
        console.print(f"[red]Error: {result.error}[/]")
        sys.exit(1)

    # Crack if requested
    crack_result = None
    if args.crack and result.matches:
        crackable = [m for m in result.matches if m.crackable]
        if crackable:
            # Load wordlist
            wl_path = args.wordlist or DEFAULT_WORDLIST
            try:
                words = load_wordlist(wl_path)
            except (FileNotFoundError, RuntimeError) as e:
                console.print(f"[red]Wordlist error: {e}[/]")
                sys.exit(1)

            console.print(f"\n[dim]Loaded {len(words)} words from {os.path.basename(wl_path)}[/]")
            console.print(f"[dim]Attempting to crack {len(crackable)} crackable type(s)...[/]\n")

            # Try each crackable type
            for match in crackable:
                console.print(f"  [dim]Trying {match.name}...[/]", end=" ")
                found, attempted, elapsed = crack_hash(
                    result.normalized_hash, match.name, words, timeout=args.timeout,
                )
                if found:
                    console.print(f"[bold green]CRACKED: {found}[/]")
                    crack_result = (found, attempted, elapsed)
                    break
                else:
                    console.print(f"[dim]failed ({attempted} words, {elapsed}s)[/]")
            if not crack_result:
                crack_result = (None, len(words), 0.0)

    display_result(result, crack_result)


if __name__ == "__main__":
    main()
