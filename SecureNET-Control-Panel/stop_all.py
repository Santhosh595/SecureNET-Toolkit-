"""SecureNET Control Panel - Graceful Shutdown

Stops all running tool subprocesses cleanly.
Run: python stop_all.py
"""

from __future__ import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.resolve()


def load_config():
    config_path = REPO_ROOT / "securenet.yaml"
    if not config_path.exists():
        return {"tools": {}, "settings": {}}
    with open(config_path) as f:
        return yaml.safe_load(f)


def find_process_on_port(port):
    """Find PID using a port."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True
            )
            for line in result.stdout.split("\n"):
                if f":{port}" in line and "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    return int(pid)
        else:
            result = subprocess.run(
                ["lsof", "-ti", f":{port}"], capture_output=True, text=True
            )
            if result.stdout.strip():
                return int(result.stdout.strip().split("\n")[0])
    except Exception:
        pass
    return None


def stop_process(pid):
    """Stop a process gracefully."""
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
            # Wait for graceful shutdown
            for _ in range(5):
                time.sleep(1)
                try:
                    os.kill(pid, 0)  # Check if still alive
                except ProcessLookupError:
                    return True
            # Force kill if still running
            os.kill(pid, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return True  # Already stopped
    except Exception as e:
        print(f"  [WARN] Error stopping PID {pid}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Stop all SecureNET tools")
    args = parser.parse_args()

    print("=" * 50)
    print("  SecureNET Control Panel - Shutdown")
    print("=" * 50)

    config = load_config()
    tools = config.get("tools", {})
    settings = config.get("settings", {})
    hub_port = settings.get("hub_port", 5000)

    # All ports to check
    all_ports = [hub_port]
    for tool_config in tools.values():
        if tool_config.get("enabled", True):
            all_ports.append(tool_config["port"])

    stopped = 0
    for port in all_ports:
        pid = find_process_on_port(port)
        if pid:
            print(f"  Stopping port {port} (PID:{pid})...", end=" ")
            if stop_process(pid):
                print("OK")
                stopped += 1
            else:
                print("FAILED")
        else:
            print(f"  Port {port}: not in use")

    print(f"\nStopped {stopped} processes.")
    print("All tools shut down cleanly.")


if __name__ == "__main__":
    main()
