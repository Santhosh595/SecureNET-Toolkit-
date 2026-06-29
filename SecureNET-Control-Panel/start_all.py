"""SecureNET Control Panel - Master Launcher

Starts all tool subprocesses and manages their lifecycle.
Run: python start_all.py
     python start_all.py --demo
     python start_all.py --tool headerscan
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.resolve()
LOGS_DIR = REPO_ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)


def load_config():
    """Load securenet.yaml configuration."""
    config_path = REPO_ROOT / "securenet.yaml"
    if not config_path.exists():
        print(f"[ERROR] {config_path} not found!")
        sys.exit(1)
    with open(config_path) as f:
        return yaml.safe_load(f)


def check_python_version():
    """Check Python >= 3.8."""
    if sys.version_info < (3, 8):
        print(f"[ERROR] Python 3.8+ required. Current: {sys.version}")
        sys.exit(1)
    print(f"[OK] Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")


def check_port_available(port):
    """Check if a port is available."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.bind(("127.0.0.1", port))
        s.close()
        return True
    except OSError:
        return False


def check_tool_requirements(tool_path):
    """Check if requirements are installed."""
    req_file = tool_path / "requirements.txt"
    if not req_file.exists():
        return True  # No requirements = OK

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return False

        import json
        installed = {p["name"].lower() for p in json.loads(result.stdout)}

        for line in req_file.read_text().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg = line.split("=")[0].split("<")[0].split(">")[0].strip().lower()
            if pkg not in installed:
                print(f"  [WARN] Missing: {pkg}")
                return False
        return True
    except Exception:
        return False


def start_tool(tool_key, tool_config, demo_mode=False):
    """Start a single tool as subprocess."""
    tool_path = REPO_ROOT / tool_config["path"]
    entry = tool_config.get("entry", "dashboard.py")
    port = tool_config["port"]
    name = tool_config.get("name", tool_key)

    if not tool_path.exists():
        print(f"  [SKIP] {name}: path not found ({tool_path})")
        return None

    entry_file = tool_path / entry
    if not entry_file.exists():
        print(f"  [SKIP] {name}: {entry} not found")
        return None

    if not check_port_available(port):
        print(f"  [WARN] {name}: port {port} already in use")
        return None

    env = os.environ.copy()
    env["PORT"] = str(port)

    if demo_mode:
        env["DEMO_MODE"] = "1"

    try:
        process = subprocess.Popen(
            [sys.executable, str(entry_file)],
            cwd=str(tool_path),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # Detach from terminal (Linux/macOS compatible)
        )

        # Wait briefly to check if process started
        time.sleep(1)
        if process.poll() is not None:
            print(f"  [FAIL] {name}: process exited immediately")
            return None

        print(f"  [OK] {name} started (PID:{process.pid}, port:{port})")
        return process

    except Exception as e:
        print(f"  [FAIL] {name}: {str(e)}")
        return None


def main():
    parser = argparse.ArgumentParser(description="SecureNET Control Panel Launcher")
    parser.add_argument("--tool", type=str, default=None, help="Start only one tool")
    parser.add_argument("--demo", action="store_true", help="Enable demo mode")
    args = parser.parse_args()

    print("=" * 60)
    print("  SecureNET Control Panel - Master Launcher")
    print("=" * 60)

    check_python_version()

    config = load_config()
    tools = config.get("tools", {})
    settings = config.get("settings", {})
    hub_port = settings.get("hub_port", 5000)

    # Check hub port
    if not check_port_available(hub_port):
        print(f"\n[WARN] Hub port {hub_port} is already in use!")
        print("The control panel may already be running.")
        print("To restart: python stop_all.py && python start_all.py")
        sys.exit(1)

    # Filter tools
    if args.tool:
        if args.tool not in tools:
            print(f"[ERROR] Unknown tool: {args.tool}")
            print(f"Available: {', '.join(tools.keys())}")
            sys.exit(1)
        tools = {args.tool: tools[args.tool]}

    print(f"\nStarting {len(tools)} tools...")
    if args.demo:
        print("[DEMO MODE] Tools will use synthetic data")

    processes = {}
    for key, tool_config in tools.items():
        if not tool_config.get("enabled", True):
            print(f"  [SKIP] {key}: disabled in config")
            continue
        process = start_tool(key, tool_config, args.demo)
        if process:
            processes[key] = process

    print(f"\n{len(processes)}/{len(tools)} tools started successfully")
    print(f"\nStarting control panel on port {hub_port}...")

    # Start hub
    try:
        hub_process = subprocess.Popen(
            [sys.executable, "hub.py"],
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # Detach from terminal (Linux/macOS compatible)
        )
        print(f"\n[OK] Control panel started (PID:{hub_process.pid})")
        print(f"\n  Dashboard: http://127.0.0.1:{hub_port}")
        print(f"\n  Press Ctrl+C to stop all tools")
        print("=" * 60)

        # Wait for all processes
        try:
            while True:
                time.sleep(1)
                # Check if any process died
                for key, proc in list(processes.items()):
                    if proc.poll() is not None:
                        print(f"\n  [WARN] {key} stopped (exit code: {proc.returncode})")
                        del processes[key]
                if hub_process.poll() is not None:
                    break
        except KeyboardInterrupt:
            print("\n\nShutting down...")
            for key, proc in processes.items():
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
            hub_process.terminate()
            try:
                hub_process.wait(timeout=5)
            except Exception:
                hub_process.kill()
            print("All tools stopped.")

    except Exception as e:
        print(f"[ERROR] Failed to start control panel: {str(e)}")
        # Cleanup
        for proc in processes.values():
            try:
                proc.terminate()
            except Exception:
                pass
        sys.exit(1)


if __name__ == "__main__":
    main()
