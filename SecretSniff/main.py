"""SecretSniff — CLI entry point with Rich output.

Usage:
    python main.py scan --path ./myproject
    python main.py scan --repo ./myrepo --history --depth 100
    python main.py scan --stdin
    python main.py baseline --save baseline.json
    python main.py scan --path . --baseline baseline.json
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Confirm

from patterns.rules import get_patterns
from scanner.file_scanner import scan_file, iter_files
from scanner.git_scanner import scan_git_history, scan_git_worktree, is_git_repo, get_repo_root
from scanner.env_scanner import scan_env_files
from allowlist import Allowlist
from baseline import save_baseline, compare_with_baseline
from output.sarif import generate_sarif
from output.junit import generate_junit
from output.reporter import generate_pdf_report
from database import init_db, save_scan

console = Console()


def severity_color(severity: str) -> str:
    return {"CRITICAL": "bold red", "HIGH": "bold orange", "MEDIUM": "bold yellow",
            "LOW": "bold blue", "INFO": "dim"}.get(severity, "white")


def display_findings(findings: list[dict], group_by_file: bool = False) -> None:
    """Display findings with Rich table."""
    if not findings:
        console.print(Panel("[bold green]No secrets detected![/]", border_style="green"))
        return

    if group_by_file:
        # Group by file
        by_file = {}
        for f in findings:
            by_file.setdefault(f["file"], []).append(f)
        for file_path, file_findings in by_file.items():
            table = Table(show_header=True, header_style="bold white")
            table.add_column("Line", min_width=6, justify="center")
            table.add_column("Rule", min_width=25)
            table.add_column("Severity", min_width=10, justify="center")
            table.add_column("Confidence", min_width=10, justify="center")
            table.add_column("Value", min_width=30)
            for f in file_findings:
                color = severity_color(f["severity"])
                table.add_row(
                    str(f["line"]), f["rule"],
                    f"[{color}]{f['severity']}[/]", f["confidence"],
                    f["value_redacted"],
                )
            console.print(Panel(table, title=f"[bold]{file_path}[/]", border_style="cyan"))
    else:
        table = Table(show_header=True, header_style="bold white")
        table.add_column("Severity", min_width=10, justify="center")
        table.add_column("File", min_width=30)
        table.add_column("Line", min_width=6, justify="center")
        table.add_column("Rule", min_width=25)
        table.add_column("Confidence", min_width=10, justify="center")
        table.add_column("Value", min_width=30)

        for f in findings:
            color = severity_color(f["severity"])
            table.add_row(
                f"[{color}]{f['severity']}[/]",
                f["file"][:50], str(f["line"]),
                f["rule"], f["confidence"],
                f["value_redacted"],
            )
        console.print(table)


def cmd_scan(args) -> None:
    """Handle scan command."""
    init_db()
    start_time = time.time()

    target = args.path or args.repo or "stdin"
    scan_type = "file"
    findings = []
    files_scanned = 0

    # Load allowlist
    allowlist = Allowlist()
    if os.path.exists(".secretsniff-ignore"):
        ignore_file = Path(".secretsniff-ignore")
        allowlist = Allowlist(ignore_file)

    patterns = get_patterns()

    if args.stdin:
        # Stdin mode
        scan_type = "stdin"
        import tempfile
        content = sys.stdin.read()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)
        findings = scan_file(tmp_path, patterns)
        tmp_path.unlink()
        files_scanned = 1

    elif args.repo:
        # Git repo scan
        repo_path = Path(args.repo).resolve()
        if not is_git_repo(repo_path):
            console.print(f"[red]Not a git repository: {repo_path}[/]")
            sys.exit(1)

        scan_type = "git"
        if args.history:
            scan_type = "git-history"
            console.print(f"[dim]Scanning git history (depth={args.depth or 'all'})...[/]")
            findings = scan_git_history(repo_path, depth=args.depth or 0)
        else:
            console.print(f"[dim]Scanning git working tree...[/]")
            findings = scan_git_worktree(repo_path, include_tests=args.include_tests)
        files_scanned = len(set(f["file"] for f in findings)) if findings else 0

    else:
        # File/directory scan
        target_path = Path(args.path or ".").resolve()
        if not target_path.exists():
            console.print(f"[red]Path not found: {target_path}[/]")
            sys.exit(1)

        console.print(f"[dim]Scanning {target_path}...[/]")
        for file_path in iter_files(target_path, respect_gitignore=not args.no_gitignore,
                                     include_tests=args.include_tests):
            files_scanned += 1
            file_findings = scan_file(file_path, patterns)
            findings.extend(file_findings)

        # Also scan env files
        env_findings = scan_env_files(target_path, include_tests=args.include_tests)
        findings.extend(env_findings)

    # Apply allowlist
    allowlist.filter_findings(findings)

    # Apply baseline
    if args.baseline:
        from pathlib import Path
        new_findings, known_findings = compare_with_baseline(findings, Path(args.baseline))
        if not args.show_known:
            findings = new_findings
        console.print(f"[dim]Baseline: {len(known_findings)} known, {len(new_findings)} new[/]")

    duration = time.time() - start_time

    # Display results
    console.print()
    console.rule(f"[bold cyan]SecretSniff — {scan_type.upper()}", style="cyan")
    console.print()

    # Summary
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")

    summary = Text()
    summary.append(f"Files scanned: {files_scanned} | ", style="dim")
    summary.append(f"Findings: {len(findings)}", style="bold")
    summary.append(f"  Critical: {critical} | ", style="red")
    summary.append(f"High: {high} | ", style="orange")
    summary.append(f"Medium: {medium} | ", style="yellow")
    summary.append(f"Low: {low}", style="blue")
    summary.append(f"Duration: {duration:.1f}s", style="dim")
    console.print(Panel(summary, title="[bold]Scan Summary[/]", border_style="cyan"))
    console.print()

    # Show findings
    if findings:
        display_findings(findings, group_by_file=args.group_by_file)
    else:
        console.print(Panel("[bold green]No secrets detected![/]", border_style="green"))

    # Save to database
    scan_id = save_scan(target, scan_type, files_scanned, findings, duration)

    # Export
    if args.output:
        output_path = args.output
        if output_path.endswith(".sarif"):
            sarif = generate_sarif(findings)
            with open(output_path, "w") as f:
                import json
                json.dump(sarif, f, indent=2)
        elif output_path.endswith(".junit") or output_path.endswith(".xml"):
            junit = generate_junit(findings)
            with open(output_path, "w") as f:
                f.write(junit)
        elif output_path.endswith(".pdf"):
            generate_pdf_report(findings, output_path, target, scan_type)
        else:
            # Default JSON
            import json
            export_data = {
                "scan_id": scan_id, "target": target, "scan_type": scan_type,
                "duration": round(duration, 2), "files_scanned": files_scanned,
                "findings": findings,
            }
            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]Report saved to {output_path}[/]")

    # Exit code
    sys.exit(1 if findings else 0)


def cmd_baseline(args) -> None:
    """Handle baseline command."""
    init_db()
    # Run scan and save as baseline
    patterns = get_patterns()
    target_path = Path(args.path or ".").resolve()
    findings = []

    for file_path in iter_files(target_path, respect_gitignore=True):
        file_findings = scan_file(file_path, patterns)
        findings.extend(file_findings)

    save_baseline(findings, Path(args.save))
    console.print(f"[green]Baseline saved: {len(findings)} findings accepted[/]")


def cmd_install_hook(args) -> None:
    """Install pre-commit hook."""
    hook_path = Path(".git/hooks/pre-commit")
    hook_content = """#!/bin/bash
# SecretSniff pre-commit hook
# Scans staged files for secrets before commit

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

echo "🔍 SecretSniff: Scanning staged files..."

# Run secretsniff on staged files
python -m main.py scan --path . --stdin <<EOF
$(git diff --cached -- '*.py' '*.js' '*.ts' '*.yml' '*.yaml' '*.json' '*.env' '*.tf' '*.sh')
EOF

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ SecretSniff: Secrets detected! Commit blocked."
    echo "   To bypass (not recommended): git commit --no-verify"
    exit 1
fi

echo "✅ SecretSniff: No secrets detected."
exit 0
"""
    hook_path.write_text(hook_content)
    hook_path.chmod(0o755)
    console.print(f"[green]Pre-commit hook installed at {hook_path}[/]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecretSniff — Secret & API Key Scanner",
        epilog="Example: python main.py scan --path ./src",
    )
    subparsers = parser.add_subparsers(dest="command")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan for secrets")
    scan_parser.add_argument("--path", "-p", type=str, default=".", help="Directory to scan")
    scan_parser.add_argument("--repo", "-r", type=str, default=None, help="Git repository to scan")
    scan_parser.add_argument("--history", action="store_true", help="Scan git history")
    scan_parser.add_argument("--depth", type=int, default=0, help="Git history depth")
    scan_parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    scan_parser.add_argument("--output", "-o", type=str, default=None, help="Output file (.json, .sarif, .junit, .pdf)")
    scan_parser.add_argument("--baseline", type=str, default=None, help="Baseline file for comparison")
    scan_parser.add_argument("--show-known", action="store_true", help="Show known/baseline findings")
    scan_parser.add_argument("--include-tests", action="store_true", help="Include test files")
    scan_parser.add_argument("--no-gitignore", action="store_true", help="Don't respect .gitignore")
    scan_parser.add_argument("--group-by-file", action="store_true", help="Group findings by file")
    scan_parser.add_argument("--no-disclaimer", action="store_true", help="Skip disclaimer")

    # Baseline command
    baseline_parser = subparsers.add_parser("baseline", help="Manage baseline")
    baseline_parser.add_argument("--path", "-p", type=str, default=".", help="Directory to scan")
    baseline_parser.add_argument("--save", "-s", type=str, default="baseline.json", help="Baseline file path")

    # Install hook command
    subparsers.add_parser("install-hook", help="Install git pre-commit hook")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if not args.no_disclaimer and args.command == "scan":
        if not Confirm.ask("[bold]Do you have authorization to scan this repository?[/]", default=False):
            console.print("[dim]Scan cancelled.[/]")
            sys.exit(0)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "baseline":
        cmd_baseline(args)
    elif args.command == "install-hook":
        cmd_install_hook(args)


if __name__ == "__main__":
    main()
