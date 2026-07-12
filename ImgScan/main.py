"""ImgScan — CLI entry point (Trivy-style dependency/container CVE scanner).

Usage:
    imgscan scan --path ./myproject            # Mode 1: auto-detect manifests
    imgscan scan --sbom sbom.json              # Mode 2: SBOM scan
    imgscan dockerfile --file Dockerfile       # Mode 3: Dockerfile audit
    imgscan pip --requirements requirements.txt # Mode 4: pip-audit mode
    imgscan check requests==2.25.1             # Mode 5: single package

    Common flags:
      --generate-sbom sbom.json   emit CycloneDX SBOM
      --json out.json  --csv out.csv  --sarif out.sarif  --pdf report.pdf
      --no-disclaimer              skip the auth prompt
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text

import database as db
from scanners import (scan_directory, scan_component_list, check_package,
                      scan_requirements, audit_dockerfile, PIP_AUDIT_HINT,
                      NPM_AUDIT_HINT)
from parsers.sbom_parser import parse_sbom, Component
from parsers.sbom_generator import generate_sbom
import output.sarif as sarif
import output.reporter as reporter

console = Console()
DISCLAIMER = ("ImgScan scans dependency manifests read-only. "
              "Only scan projects you own or maintain.")

SEV_COLOR = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
             "LOW": "cyan", "INFO": "dim"}


def _disclaimer(force: bool) -> None:
    if force:
        return
    console.print(Panel(DISCLAIMER, border_style="cyan", padding=(1, 2)))
    ans = input("Do you own or maintain the target? (y/N): ").strip().lower()
    if ans != "y":
        console.print("[yellow]Aborted.[/]")
        sys.exit(0)


def _print_findings(findings, title="Vulnerabilities") -> None:
    if not findings:
        console.print(Panel("[green]No known vulnerabilities matched the bundled "
                            "CVE rule set for this target.[/]", border_style="cyan"))
        return
    table = Table(show_header=True, header_style="bold white",
                  box=box.ROUNDED)
    table.add_column("Package", min_width=15, max_width=18)
    table.add_column("Version", min_width=9, max_width=11, justify="center")
    table.add_column("CVE", min_width=16, max_width=18)
    table.add_column("Severity", min_width=9, max_width=10, justify="center")
    table.add_column("CVSS", min_width=5, max_width=6, justify="center")
    table.add_column("KEV", min_width=9, max_width=9, justify="center", no_wrap=True)
    table.add_column("Fixed", min_width=9, max_width=11, justify="center")
    for f in sorted(findings, key=lambda x: x.cvss_score, reverse=True):
        c = SEV_COLOR.get(f.severity, "white")
        kev_txt = "EXPLOITED" if console.is_terminal else "KEV"
        kev = Text(kev_txt, style="bold red") if f.in_kev else Text("—", style="dim")
        table.add_row(f.package, f.version, f.cve_id,
                      f"[{c}]{f.severity}[/]", f"{f.cvss_score:.1f}",
                      kev, f.fixed_version or "—")
    console.print(table)


def _print_docker(findings) -> None:
    if not findings:
        console.print(Panel("[green]No Dockerfile security issues found.[/]",
                            border_style="cyan"))
        return
    table = Table(show_header=True, header_style="bold white",
                  box=box.ROUNDED, expand=True)
    table.add_column("ID", min_width=10)
    table.add_column("Line", min_width=6, justify="center")
    table.add_column("Severity", min_width=10, justify="center")
    table.add_column("Issue", min_width=60)
    for d in sorted(findings, key=lambda x: x.severity):
        c = SEV_COLOR.get(d.severity, "white")
        table.add_row(d.check_id, str(d.line_number), f"[{c}]{d.severity}[/]",
                      d.description)
    console.print(table)


def _summary(findings, docker) -> None:
    sev = {}
    kev = 0
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
        if f.in_kev:
            kev += 1
    line = (f"Vulnerable: {len(findings)} "
            f"(CRIT:{sev.get('CRITICAL',0)} HIGH:{sev.get('HIGH',0)} "
            f"MED:{sev.get('MEDIUM',0)} LOW:{sev.get('LOW',0)})  "
            f"Exploited in wild: {kev}  Dockerfile issues: {len(docker)}")
    console.print(Panel(line, border_style="cyan", padding=(1, 2)))


def _parse_pkg_arg(arg: str):
    m = re.match(r"^([A-Za-z0-9_.\-]+)==(.+)$", arg)
    if m:
        return m.group(1), m.group(2)
    return arg, ""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ImgScan — dependency & container CVE scanner")
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--no-disclaimer", action="store_true",
                        help="Skip disclaimer prompt")
    parent.add_argument("--json", metavar="FILE", help="Export JSON")
    parent.add_argument("--csv", metavar="FILE", help="Export CSV")
    parent.add_argument("--sarif", metavar="FILE", help="Export SARIF")
    parent.add_argument("--pdf", metavar="FILE", help="Export PDF report")
    sub = parser.add_subparsers(dest="mode")

    p_scan = sub.add_parser("scan", parents=[parent], help="Scan a path or SBOM")
    p_scan.add_argument("--path", help="Directory or manifest to scan (Mode 1)")
    p_scan.add_argument("--sbom", help="SBOM file to scan (Mode 2)")
    p_scan.add_argument("--generate-sbom", metavar="FILE", help="Emit CycloneDX SBOM")

    p_dock = sub.add_parser("dockerfile", parents=[parent], help="Audit a Dockerfile (Mode 3)")
    p_dock.add_argument("--file", required=True, help="Path to Dockerfile")

    p_pip = sub.add_parser("pip", parents=[parent], help="pip-audit mode (Mode 4)")
    p_pip.add_argument("--requirements", required=True, help="requirements.txt")

    p_check = sub.add_parser("check", parents=[parent], help="Check a single package (Mode 5)")
    p_check.add_argument("package", help="name==version")

    args = parser.parse_args()
    if not args.mode:
        parser.error("Choose a mode: scan | dockerfile | pip | check")

    _disclaimer(args.no_disclaimer)
    db.init_db()
    t0 = time.time()
    findings = []
    docker = []
    scan_type = args.mode
    target = ""

    if args.mode == "scan":
        if args.sbom:
            target = args.sbom
            comps = parse_sbom(args.sbom)
            findings = scan_component_list(comps)
            scan_type = "sbom"
        elif args.path:
            target = args.path
            findings = scan_directory(args.path)
            scan_type = "directory"
            if args.generate_sbom:
                comps = _collect_components(args.path)
                generate_sbom(comps, args.generate_sbom)
                console.print(f"[green]SBOM written to {args.generate_sbom}[/]")
        else:
            parser.error("scan needs --path or --sbom")
    elif args.mode == "dockerfile":
        target = args.file
        docker = audit_dockerfile(args.file)
        scan_type = "dockerfile"
    elif args.mode == "pip":
        target = args.requirements
        findings = scan_requirements(args.requirements)
        scan_type = "pip"
        if shutil.which("pip-audit"):
            pass
        else:
            console.print(f"[yellow]{PIP_AUDIT_HINT}[/]")
    elif args.mode == "check":
        name, ver = _parse_pkg_arg(args.package)
        target = f"{name}=={ver}"
        findings = check_package(name, ver)
        scan_type = "package"

    duration = round(time.time() - t0, 2)

    _print_findings(findings)
    if docker:
        _print_docker(docker)
    if findings or docker:
        _summary(findings, docker)

    # persist
    sid = db.save_scan(target, scan_type, len({f.package for f in findings}),
                       len(findings), duration)
    if findings:
        db.save_vulnerabilities(sid, findings)
    if docker:
        db.save_dockerfile_findings(sid, docker)

    # exports
    if args.json:
        open(args.json, "w").write(reporter.to_json(findings, docker))
        console.print(f"[green]JSON -> {args.json}[/]")
    if args.csv:
        open(args.csv, "w").write(reporter.to_csv(findings))
        console.print(f"[green]CSV -> {args.csv}[/]")
    if args.sarif:
        sarif.write_sarif(findings, args.sarif, target)
        console.print(f"[green]SARIF -> {args.sarif}[/]")
    if args.pdf:
        if reporter.write_pdf(findings, docker, args.pdf, target):
            console.print(f"[green]PDF -> {args.pdf}[/]")
        else:
            txt = args.pdf.rsplit(".", 1)[0] + ".txt"
            open(txt, "w").write(reporter.to_json(findings, docker))
            console.print(f"[yellow]reportlab not installed; text report -> {txt}[/]")

    # CI/CD exit code
    crit_high = sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH"))
    if crit_high:
        sys.exit(1)


def _collect_components(path: str):
    """Collect (name, version, ecosystem) tuples for SBOM generation."""
    from scanners import scan_directory
    # reuse parse of manifests to gather deps; simple approach via pip/node/java parsers
    comps = []
    if os.path.isdir(path):
        for root, _d, files in os.walk(path):
            for fn in files:
                if fn == "requirements.txt":
                    from scanners.python_scanner import parse_requirements
                    for n, v in parse_requirements(os.path.join(root, fn)).items():
                        comps.append(Component(name=n, version=v, ecosystem="python"))
                elif fn in ("package-lock.json", "yarn.lock"):
                    if fn.endswith(".json"):
                        from scanners.node_scanner import parse_package_lock
                        for n, v in parse_package_lock(os.path.join(root, fn)).items():
                            comps.append(Component(name=n, version=v, ecosystem="npm"))
                    else:
                        from scanners.node_scanner import parse_yarn_lock
                        for n, v in parse_yarn_lock(os.path.join(root, fn)).items():
                            comps.append(Component(name=n, version=v, ecosystem="npm"))
    return comps


if __name__ == "__main__":
    main()
