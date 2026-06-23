"""Detection engine for the Network Sniffer.

Implements rule-based intrusion detection:
- Port scan detection (many unique destination ports from one source)
- High-rate detection (packet flood from a single source)
"""

from __future__ import annotations

import json
import time
from typing import Protocol

# --- Thresholds ---
PORT_SCAN_WINDOW = 10.0      # seconds to look back
PORT_SCAN_THRESHOLD = 10     # unique destination ports that trigger an alert
RATE_WINDOW = 5.0            # seconds to look back
RATE_THRESHOLD = 50          # packets in window that trigger an alert
COOLDOWN = 15.0              # seconds to suppress repeated alerts per (rule, src)


class DBModule(Protocol):
    """Interface the detector expects from a database module."""
    def get_recent_packets(self, seconds: float = ...) -> list: ...


_last_alert_ts: dict[tuple[str, str], float] = {}


def _cooldown_ok(rule: str, src: str) -> bool:
    """Check if enough time has passed since the last alert for this rule+src."""
    key = (rule, src)
    now = time.time()
    last = _last_alert_ts.get(key, 0.0)
    if now - last >= COOLDOWN:
        _last_alert_ts[key] = now
        return True
    return False


def detect_port_scan(db: DBModule) -> list[tuple[str, str, str]]:
    """Detect port scan activity.

    Returns a list of (rule_name, source_ip, meta_json) tuples.
    """
    rows = db.get_recent_packets(PORT_SCAN_WINDOW)
    by_src: dict[str, set[int]] = {}

    for row in rows:
        src = row[1]  # src column
        dport = row[5]  # dport column
        if not src:
            continue
        by_src.setdefault(src, set())
        if dport is not None:
            try:
                by_src[src].add(int(dport))
            except (ValueError, TypeError):
                pass

    alerts: list[tuple[str, str, str]] = []
    for src, ports in by_src.items():
        if len(ports) >= PORT_SCAN_THRESHOLD and _cooldown_ok("PORT_SCAN", src):
            meta = {"unique_ports": len(ports), "sample": sorted(ports)[:10]}
            alerts.append(("PORT_SCAN", src, json.dumps(meta)))

    return alerts


def detect_high_rate(db: DBModule) -> list[tuple[str, str, str]]:
    """Detect high packet rate from a single source.

    Returns a list of (rule_name, source_ip, meta_json) tuples.
    """
    rows = db.get_recent_packets(RATE_WINDOW)
    counts: dict[str, int] = {}

    for row in rows:
        src = row[1]  # src column
        if not src:
            continue
        counts[src] = counts.get(src, 0) + 1

    alerts: list[tuple[str, str, str]] = []
    for src, count in counts.items():
        if count >= RATE_THRESHOLD and _cooldown_ok("HIGH_RATE", src):
            meta = {"count": count, "window_seconds": RATE_WINDOW}
            alerts.append(("HIGH_RATE", src, json.dumps(meta)))

    return alerts
