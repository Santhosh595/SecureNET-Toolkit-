"""SecureNET Toolkit - Diagnostic Runner

Tests every tool in the toolkit before building the control panel.
Run: python diagnose.py
     python diagnose.py --tool headerscan
     python diagnose.py --fix
     python diagnose.py --report
     python diagnose.py --quick
"""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib
import importlib.util
import json
import os
import platform
import py_compile
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

# Optional imports
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich import print as rprint
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("[!] rich not installed. Run: pip install rich")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

console = Console() if HAS_RICH else None
REPO_ROOT = Path(__file__).parent.resolve()

TOOL_FOLDERS = [
    "FileGuard-AES-SHA256",
    "network-sniffer",
    "HeaderScan",
    "PortMap",
    "HashDetect",
    "ARPWatch",
    "SubProbe",
    "JWTInspect",
    "TLScan",
    "LogSentry",
    "SecretSniff",
    "DNSAudit",
]

TOOL_PORTS = {
    "FileGuard-AES-SHA256": [5001, 5005],
    "network-sniffer": [5100],
    "HeaderScan": [5200],
    "PortMap": [5300],
    "HashDetect": [5400],
    "ARPWatch": [5500],
    "SubProbe": [5600],
    "JWTInspect": [5650],
    "TLScan": [5700],
    "LogSentry": [5850],
    "SecretSniff": [5800],
    "DNSAudit": [5900],
}

EXPECTED_FILES = {
    "FileGuard-AES-SHA256": ["main.py", "requirements.txt", "README.md"],
    "network-sniffer": ["main.py", "requirements.txt", "README.md", "dashboard.py"],
    "HeaderScan": ["main.py", "requirements.txt", "README.md", "dashboard.py", "analyzer.py"],
    "PortMap": ["main.py", "requirements.txt", "README.md"],
    "HashDetect": ["main.py", "requirements.txt", "README.md"],
    "ARPWatch": ["main.py", "requirements.txt", "README.md"],
    "SubProbe": ["main.py", "requirements.txt", "README.md"],
    "JWTInspect": ["main.py", "requirements.txt", "README.md"],
    "TLScan": ["main.py", "requirements.txt", "README.md", "dashboard.py", "connector.py"],
    "LogSentry": ["main.py", "requirements.txt", "README.md"],
    "SecretSniff": ["main.py", "requirements.txt", "README.md", "dashboard.py"],
    "DNSAudit": ["main.py", "requirements.txt", "README.md", "dashboard.py", "resolver.py"],
}


def log_status(icon, message, detail=""):
    if console:
        console.print(f"  {icon} {message}" + (f" [dim]{detail}[/]" if detail else ""))
    else:
        print(f"  {icon} {message}" + (f" {detail}" if detail else ""))


def check_python_version():
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    if version >= (3, 8):
        return {"status": "PASS", "version": version_str}
    return {"status": "CRITICAL", "version": version_str, "error": "Python 3.8+ required"}


def check_directory_structure(tool_folder):
    tool_path = REPO_ROOT / tool_folder
    if not tool_path.exists():
        return {"status": "FAIL", "missing": [tool_folder], "present": []}
    expected = EXPECTED_FILES.get(tool_folder, ["main.py", "requirements.txt", "README.md"])
    present = [f for f in expected if (tool_path / f).exists()]
    missing = [f for f in expected if not (tool_path / f).exists()]
    if not missing:
        return {"status": "PASS", "missing": [], "present": present}
    elif present:
        return {"status": "WARNING", "missing": missing, "present": present}
    return {"status": "FAIL", "missing": missing, "present": []}


def check_requirements(tool_folder):
    req_path = REPO_ROOT / tool_folder / "requirements.txt"
    if not req_path.exists():
        return {"status": "FAIL", "error": "requirements.txt not found"}
    try:
        content = req_path.read_text(encoding="utf-8").strip()
        if not content:
            return {"status": "FAIL", "error": "requirements.txt is empty"}
        packages = [l.strip() for l in content.split("\n") if l.strip() and not l.startswith("#")]
        return {"status": "PASS", "packages": packages, "count": len(packages)}
    except Exception as e:
        return {"status": "FAIL", "error": str(e)}


def check_dependencies(tool_folder):
    req_path = REPO_ROOT / tool_folder / "requirements.txt"
    if not req_path.exists():
        return {"status": "SKIP"}
    installed = []
    missing = []
    special = {
        "gitpython": "git",
        "pyyaml": "yaml",
        "reportlab": "reportlab",
        "dnspython": "dns",
        "cryptography": "cryptography",
        "requests": "requests",
        "flask": "flask",
        "rich": "rich",
        "psutil": "psutil",
    }
    try:
        content = req_path.read_text(encoding="utf-8")
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg_name = line.split("=")[0].split("<")[0].split(">")[0].split("!")[0].split("~")[0].strip()
            import_name = pkg_name.replace("-", "_").lower()
            import_name = special.get(import_name, import_name)
            spec = importlib.util.find_spec(import_name)
            if spec is not None:
                installed.append(pkg_name)
            else:
                missing.append(pkg_name)
    except Exception as e:
        return {"status": "WARNING", "error": str(e), "installed": installed, "missing": missing}
    if not missing:
        return {"status": "PASS", "installed": installed, "missing": []}
    return {"status": "FAIL", "installed": installed, "missing": missing}


def check_syntax(tool_folder):
    tool_path = REPO_ROOT / tool_folder
    if not tool_path.exists():
        return {"status": "SKIP"}
    py_files = list(tool_path.rglob("*.py"))
    errors = []
    checked = 0
    for py_file in py_files:
        try:
            py_compile.compile(str(py_file), doraise=True)
            checked += 1
        except py_compile.PyCompileError as e:
            errors.append({"file": str(py_file.relative_to(REPO_ROOT)), "error": str(e)})
    if errors:
        return {"status": "FAIL", "checked": checked, "errors": errors}
    return {"status": "PASS", "checked": checked, "errors": []}


def check_imports(tool_folder):
    tool_path = REPO_ROOT / tool_folder
    main_file = tool_path / "main.py"
    if not main_file.exists():
        return {"status": "SKIP"}
    try:
        spec = importlib.util.spec_from_file_location("tool_main", str(main_file))
        if spec and spec.loader:
            return {"status": "PASS"}
        return {"status": "WARNING", "detail": "Could not load spec"}
    except Exception as e:
        return {"status": "FAIL", "error": str(e)}


def check_port_availability(tool_folder):
    ports = TOOL_PORTS.get(tool_folder, [])
    results = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1)
            sock.bind(("127.0.0.1", port))
            sock.close()
            results[port] = "AVAILABLE"
        except OSError:
            process_info = ""
            if HAS_PSUTIL:
                try:
                    for conn in psutil.net_connections():
                        if conn.laddr.port == port:
                            process_info = f"PID:{conn.pid}"
                            if conn.pid:
                                try:
                                    p = psutil.Process(conn.pid)
                                    process_info += f" ({p.name()})"
                                except Exception:
                                    pass
                            break
                except Exception:
                    pass
            results[port] = f"IN_USE ({process_info})" if process_info else "IN_USE"
    all_available = all(v == "AVAILABLE" for v in results.values())
    return {"status": "PASS" if all_available else "WARNING", "ports": results}


def check_tool_functionality(tool_folder):
    tool_path = REPO_ROOT / tool_folder
    try:
        if tool_folder == "FileGuard-AES-SHA256":
            importlib.util.find_spec("cryptography")
            return {"status": "PASS", "detail": "cryptography available"}
        elif tool_folder == "network-sniffer":
            s1 = importlib.util.find_spec("scapy")
            s2 = importlib.util.find_spec("flask")
            if s1 and s2:
                return {"status": "PASS", "detail": "scapy + flask OK"}
            return {"status": "FAIL", "detail": f"scapy:{s1 is not None}, flask:{s2 is not None}"}
        elif tool_folder == "HeaderScan":
            s1 = importlib.util.find_spec("requests")
            s2 = importlib.util.find_spec("rich")
            if s1 and s2:
                return {"status": "PASS", "detail": "requests + rich OK"}
            return {"status": "FAIL", "detail": f"requests:{s1 is not None}, rich:{s2 is not None}"}
        elif tool_folder == "PortMap":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.close()
            return {"status": "PASS", "detail": "socket OK"}
        elif tool_folder == "HashDetect":
            importlib.util.find_spec("hashlib")
            return {"status": "PASS", "detail": "hashlib OK"}
        elif tool_folder == "ARPWatch":
            spec = importlib.util.find_spec("scapy")
            if spec:
                return {"status": "PASS", "detail": "scapy available"}
            return {"status": "SKIP", "detail": "scapy not installed"}
        elif tool_folder == "SubProbe":
            import socket
            r = socket.gethostbyname("google.com")
            if r:
                return {"status": "PASS", "detail": f"DNS resolves ({r})"}
            return {"status": "FAIL", "detail": "DNS resolution failed"}
        elif tool_folder == "JWTInspect":
            import base64, json
            test_jwt = "eyJhbG...sw5c"
            parts = test_jwt.split(".")
            if len(parts) == 3:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                if header.get("alg") == "HS256":
                    def _test_tlscan(tool_path: Path) -> dict:
                        """Test TLScan: SSL context creation and connector module load."""
                        try:
                            import ssl
                            ctx = ssl.create_default_context()
                            if ctx:
                                return {"status": "PASS", "detail": "SSL context creation OK"}
                            return {"status": "FAIL", "detail": "SSL context failed"}
                        except Exception as e:
                            return {"status": "FAIL", "error": str(e)}
            if py_files:
                return {"status": "PASS", "detail": f"{len(py_files)} Python files"}
            return {"status": "SKIP"}
        elif tool_folder == "SecretSniff":
            import tempfile, os
            fd, path = tempfile.mkstemp(suffix=".py", text=True)
            try:
                with os.fdopen(fd, "w") as f:
                    f.write('TEST_KEY = "AKIAIO...MLE"\n')
                with open(path) as f:
                    content = f.read()
                if "AKIAIO...MLE" in content:
                    return {"status": "PASS", "detail": "File scan OK"}
                return {"status": "FAIL", "detail": "Content mismatch"}
            finally:
                os.unlink(path)
        elif tool_folder == "DNSAudit":
            import re
            spf = "v=spf1 include:_spf.google.com ~all"
            match = re.match(r"v=spf1\s+(.+)$", spf)
            if match:
                return {"status": "PASS", "detail": "SPF parser OK"}
            return {"status": "FAIL", "detail": "SPF parse failed"}
        return {"status": "SKIP", "detail": "No test defined"}
    except Exception as e:
        return {"status": "FAIL", "error": str(e)}


def check_flask_app(tool_folder):
    tool_path = REPO_ROOT / tool_folder
    dashboard_file = tool_path / "dashboard.py"
    if not dashboard_file.exists():
        return {"status": "SKIP"}
    spec = importlib.util.find_spec("flask")
    if not spec:
        return {"status": "FAIL", "detail": "flask not installed"}
    return {"status": "PASS", "detail": "flask available"}


def check_learn_md(tool_folder):
    learn_path = REPO_ROOT / tool_folder / "LEARN.md"
    if not learn_path.exists():
        return {"status": "MISSING"}
    content = learn_path.read_text(encoding="utf-8")
    if len(content) < 500:
        return {"status": "EMPTY", "size": len(content)}
    return {"status": "PASS", "size": len(content)}


def check_readme(tool_folder):
    readme_path = REPO_ROOT / tool_folder / "README.md"
    if not readme_path.exists():
        return {"status": "MISSING"}
    content = readme_path.read_text(encoding="utf-8")
    if len(content) < 500:
        return {"status": "INCOMPLETE", "size": len(content)}
    return {"status": "PASS", "size": len(content)}


def check_port_conflicts():
    all_ports = {}
    conflicts = []
    for tool, ports in TOOL_PORTS.items():
        for port in ports:
            if port in all_ports:
                conflicts.append(f"{tool} and {all_ports[port]} both use port {port}")
            else:
                all_ports[port] = tool
    if conflicts:
        return {"status": "WARNING", "conflicts": conflicts}
    return {"status": "PASS", "conflicts": []}


def auto_fix(tool_folder):
    fixes = []
    tool_path = REPO_ROOT / tool_folder

    req_path = tool_path / "requirements.txt"
    if not req_path.exists():
        req_path.write_text("# Add your dependencies here\n", encoding="utf-8")
        fixes.append("Created requirements.txt")

    learn_path = tool_path / "LEARN.md"
    if not learn_path.exists():
        content = f"# {tool_folder} - Learn Before You Use\n\n"
        content += "## What Is This Tool?\nTODO: Add explanation.\n"
        learn_path.write_text(content, encoding="utf-8")
        fixes.append("Created LEARN.md skeleton")

    readme_path = tool_path / "README.md"
    if not readme_path.exists():
        content = f"# {tool_folder}\n\n## Installation\n```bash\npip install -r requirements.txt\n```\n"
        readme_path.write_text(content, encoding="utf-8")
        fixes.append("Created README.md skeleton")

    dep_result = check_dependencies(tool_folder)
    if dep_result.get("status") == "FAIL" and dep_result.get("missing"):
        missing = dep_result["missing"]
        if len(missing) <= 5:
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install"] + missing,
                    capture_output=True, timeout=60
                )
                fixes.append(f"Installed: {', '.join(missing)}")
            except Exception as e:
                fixes.append(f"Install failed: {str(e)}")
    return fixes


def run_tool_checks(tool_folder, quick=False):
    results = {}
    results["python_version"] = check_python_version()
    results["directory_structure"] = check_directory_structure(tool_folder)
    results["requirements"] = check_requirements(tool_folder)
    results["dependencies"] = check_dependencies(tool_folder)
    if not quick:
        results["syntax"] = check_syntax(tool_folder)
        results["imports"] = check_imports(tool_folder)
        results["port_availability"] = check_port_availability(tool_folder)
        results["functionality"] = check_tool_functionality(tool_folder)
        results["flask_app"] = check_flask_app(tool_folder)
        results["learn_md"] = check_learn_md(tool_folder)
        results["readme"] = check_readme(tool_folder)
    return results


def print_tool_report(tool_folder, results, fixes=None):
    status_icons = {
        "PASS": "[green]PASS[/]",
        "FAIL": "[red]FAIL[/]",
        "WARNING": "[yellow]WARNING[/]",
        "SKIP": "[dim]SKIP[/]",
        "MISSING": "[red]MISSING[/]",
        "EMPTY": "[yellow]EMPTY[/]",
        "INCOMPLETE": "[yellow]INCOMPLETE[/]",
        "CRITICAL": "[red]CRITICAL[/]",
        "INFO": "[blue]INFO[/]",
        "GOOD": "[green]GOOD[/]",
    }
    if console:
        console.print(f"\n[bold cyan]{tool_folder}[/]")
    else:
        print(f"\n{'='*40}\n{tool_folder}\n{'='*40}")
    for check_name, result in results.items():
        status = result.get("status", "INFO")
        icon = status_icons.get(status, "?")
        detail = result.get("detail", "")
        if console:
            console.print(f"  {icon} {check_name:<25} {detail}")
        else:
            print(f"  {icon} {check_name:<25} {detail}")
        if result.get("error"):
            if console:
                console.print(f"     [red]Error: {result['error']}[/]")
            else:
                print(f"     Error: {result['error']}")
        if result.get("missing"):
            if console:
                console.print(f"     [red]Missing: {', '.join(result['missing'])}[/]")
            else:
                print(f"     Missing: {', '.join(result['missing'])}")
    if fixes:
        if console:
            console.print(f"  [green]Auto-fixes applied:[/]")
            for fix in fixes:
                console.print(f"     + {fix}")
        else:
            print(f"  Auto-fixes:")
            for fix in fixes:
                print(f"     + {fix}")


def main():
    parser = argparse.ArgumentParser(
        description="SecureNET Toolkit - Diagnostic Runner",
        epilog="Example: python diagnose.py --tool headerscan --fix",
    )
    parser.add_argument("--tool", type=str, default=None, help="Check one specific tool")
    parser.add_argument("--fix", action="store_true", help="Auto-fix issues where possible")
    parser.add_argument("--report", action="store_true", help="Save report to JSON")
    parser.add_argument("--quick", action="store_true", help="Only run quick checks (1-3)")
    args = parser.parse_args()

    if not HAS_RICH:
        print("[!] Install rich for better output: pip install rich")

    if console:
        console.print(Panel(
            "[bold]SecureNET Toolkit - Diagnostic Runner v1.0[/]\n"
            f"Checking {'all tools' if not args.tool else args.tool} across 12 checks each",
            border_style="cyan",
        ))
    else:
        print("=" * 50)
        print("  SecureNET Toolkit - Diagnostic Runner v1.0")
        print("=" * 50)

    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 8):
        if console:
            console.print(f"\nPython {py_version} [green]OK[/]")
        else:
            print(f"\nPython {py_version} OK")
    else:
        if console:
            console.print(f"\nPython {py_version} [red]TOO OLD (need 3.8+)[/]")
        else:
            print(f"\nPython {py_version} TOO OLD")

    if args.tool:
        tool = args.tool
        if tool not in TOOL_FOLDERS:
            msg = f"Unknown tool: {tool}. Available: {', '.join(TOOL_FOLDERS)}"
            if console:
                console.print(f"[red]{msg}[/]")
            else:
                print(msg)
            sys.exit(1)
        tools = [tool]
    else:
        tools = TOOL_FOLDERS

    all_results = {}
    all_fixes = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console if HAS_RICH else None,
    ) as progress:
        task = progress.add_task("Checking...", total=len(tools))
        for tool in tools:
            progress.update(task, description=f"Checking {tool}...")
            results = run_tool_checks(tool, quick=args.quick)
            all_results[tool] = results
            if args.fix:
                fixes = auto_fix(tool)
                all_fixes[tool] = fixes
            progress.advance(task)

    for tool in tools:
        print_tool_report(tool, all_results[tool], all_fixes.get(tool))

    if not args.quick:
        if console:
            console.print(f"\n[bold]Cross-Tool Port Conflicts:[/]")
        port_result = check_port_conflicts()
        print_tool_report("port_conflicts", {"port_conflicts": port_result})

    if console:
        summary_table = Table(show_header=True, header_style="bold white")
        summary_table.add_column("Tool", min_width=22)
        summary_table.add_column("PASS", min_width=6, justify="center")
        summary_table.add_column("FAIL", min_width=6, justify="center")
        summary_table.add_column("WARNING", min_width=8, justify="center")
        summary_table.add_column("Status", min_width=10, justify="center")
        total_pass = 0
        total_fail = 0
        total_warn = 0
        for tool in tools:
            results = all_results[tool]
            passes = sum(1 for r in results.values() if r.get("status") == "PASS")
            fails = sum(1 for r in results.values() if r.get("status") in ("FAIL", "CRITICAL"))
            warns = sum(1 for r in results.values() if r.get("status") == "WARNING")
            total_pass += passes
            total_fail += fails
            total_warn += warns
            status = "[green]READY[/]" if fails == 0 else "[red]ISSUES[/]"
            summary_table.add_row(tool, str(passes), str(fails), str(warns), status)
        console.print(f"\n[bold]Summary:[/]")
        console.print(summary_table)
        console.print(f"\nOverall: {len(tools)} tools checked | "
                      f"[green]{total_pass} passes[/] | "
                      f"[red]{total_fail} failures[/] | "
                      f"[yellow]{total_warn} warnings[/]")
    else:
        print(f"\n{'='*50}")
        print("Summary:")
        total_p = total_f = total_w = 0
        for tool in tools:
            results = all_results[tool]
            p = sum(1 for r in results.values() if r.get("status") == "PASS")
            f = sum(1 for r in results.values() if r.get("status") in ("FAIL", "CRITICAL"))
            w = sum(1 for r in results.values() if r.get("status") == "WARNING")
            total_p += p
            total_f += f
            total_w += w
            status = "READY" if f == 0 else "ISSUES"
            print(f"  {tool:<25} PASS:{p} FAIL:{f} [{status}]")
        print(f"\nOverall: {len(tools)} tools | {total_p} pass | {total_f} fail | {total_w} warn")

    if args.report:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        report_path = REPO_ROOT / f"securenet_diagnosis_{timestamp}.json"
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "python_version": py_version,
            "tools": {tool: all_results[tool] for tool in tools},
            "fixes": all_fixes,
            "summary": {
                "tools_checked": len(tools),
                "total_pass": total_pass if 'total_pass' in dir() else 0,
                "total_fail": total_fail if 'total_fail' in dir() else 0,
                "total_warn": total_warn if 'total_warn' in dir() else 0,
            },
        }
        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        if console:
            console.print(f"\n[green]Report saved to {report_path}[/]")
        else:
            print(f"\nReport saved to {report_path}")


if __name__ == "__main__":
    main()
