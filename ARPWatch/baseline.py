"""ARPWatch — Baseline management.

Handles loading, saving, and rebuilding the trusted IP→MAC mapping.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from database import (
    get_baseline, upsert_baseline, clear_baseline,
)

BASELINE_FILE = Path("baseline.json")


def get_default_gateway() -> Optional[str]:
    """Detect the default gateway IP."""
    # Try netifaces first
    try:
        import netifaces
        gateways = netifaces.gateways()
        default = gateways.get("default", {})
        if default:
            for family, (gw_ip, iface) in default.items():
                return gw_ip
    except (ImportError, Exception):
        pass

    # Fallback: try subprocess
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout:
            parts = result.stdout.strip().split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass

    # Fallback: try Windows
    try:
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    ip = parts[1].strip()
                    if ip:
                        return ip
    except Exception:
        pass

    return None


def get_local_ips() -> list[str]:
    """Get all local IP addresses on this machine."""
    ips = []
    try:
        import netifaces
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            inet = addrs.get(netifaces.AF_INET, [])
            for addr in inet:
                ip = addr.get("addr")
                if ip and not ip.startswith("127."):
                    ips.append(ip)
    except Exception:
        pass

    if not ips:
        # Fallback: use hostname
        import socket
        try:
            ip = socket.gethostbyname(socket.gethostname())
            if not ip.startswith("127."):
                ips.append(ip)
        except Exception:
            pass

    return ips


def build_baseline_from_arp_table() -> dict[str, str]:
    """Build baseline by reading the current system ARP table."""
    baseline = {}
    try:
        from scapy.all import ARP, Ether, srp
        local_ips = get_local_ips()
        if not local_ips:
            return baseline

        local_ip = local_ips[0]
        ip_parts = local_ip.split(".")
        subnet = ".".join(ip_parts[:3]) + ".1/24"

        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=3, verbose=0,
        )
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc.lower()
            baseline[ip] = mac

    except Exception as e:
        print(f"[ARPWatch] Error building baseline from ARP scan: {e}")

    return baseline


def save_baseline(baseline: dict[str, str], path: Path = BASELINE_FILE) -> None:
    """Save baseline to JSON file."""
    data = {
        "created": time.time(),
        "entries": baseline,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_baseline(path: Path = BASELINE_FILE) -> dict[str, str]:
    """Load baseline from JSON file."""
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")
    with open(path, "r") as f:
        data = json.load(f)
    entries = data.get("entries", {})
    if not isinstance(entries, dict):
        raise ValueError("Invalid baseline file format")
    return entries


def rebuild_baseline() -> dict[str, str]:
    """Rebuild baseline from current ARP table and save."""
    clear_baseline()
    baseline = build_baseline_from_arp_table()
    for ip, mac in baseline.items():
        upsert_baseline(ip, mac)
    save_baseline(baseline)
    return baseline


def load_or_build_baseline(path: Path = BASELINE_FILE) -> dict[str, str]:
    """Load existing baseline or build from ARP table."""
    if path.exists():
        try:
            entries = load_baseline(path)
            for ip, mac in entries.items():
                upsert_baseline(ip, mac)
            return entries
        except Exception:
            pass
    return rebuild_baseline()
