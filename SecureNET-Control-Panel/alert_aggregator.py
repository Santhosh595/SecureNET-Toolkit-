"""Alert aggregator for SecureNET Control Panel.

Polls each tool's /status and /stats endpoints, normalizes the responses,
and stores them in the unified alerts table (database.py).
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta

import requests

import database

logger = logging.getLogger(__name__)

# Tool name -> port (matches securenet.yaml)
TOOLS: dict[str, int] = {
    "ARPWatch": 5006,
    "Network Sniffer": 5002,
    "LogSentry": 5010,
    "SecretSniff": 5011,
    "TLScan": 5009,
    "DNSAudit": 5012,
    "SubProbe": 5007,
    "HeaderScan": 5003,
}

POLL_INTERVAL = 10  # seconds
REQUEST_TIMEOUT = 3


def _severity_from_stats(stats: dict, tool_name: str) -> str | None:
    """Derive a severity label from a tool's /stats response, or None."""
    # Common keys across tools: total_alerts, critical_alerts
    critical = stats.get("critical_alerts", 0)
    alerts = stats.get("total_alerts", 0)
    if isinstance(critical, int) and critical > 0:
        return "critical"
    if isinstance(alerts, int) and alerts > 0:
        return "high"
    return None


def _poll_tool(name: str, port: int) -> list[dict]:
    """Poll one tool's /status and /stats. Returns normalized alert dicts."""
    alerts: list[dict] = []
    base = f"http://127.0.0.1:{port}"

    # --- /status ---
    status_ok = False
    try:
        r = requests.get(f"{base}/status", timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            status_ok = True
    except requests.RequestException:
        pass

    # --- /stats ---
    try:
        r = requests.get(f"{base}/stats", timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            return alerts
        stats = r.json()
    except (requests.RequestException, ValueError):
        return alerts

    # If the tool is down (no /status) but /stats responded, still record.
    # If /stats is unreachable, skip.
    if not status_ok:
        alerts.append({
            "tool_name": name,
            "severity": "warning",
            "title": f"{name} status endpoint unreachable",
            "target": f"127.0.0.1:{port}",
            "description": f"/status returned non-200 or timed out",
        })

    # Synthesize an alert if the tool reports active alerts
    sev = _severity_from_stats(stats, name)
    if sev:
        alerts.append({
            "tool_name": name,
            "severity": sev,
            "title": f"{name} reports {stats.get('total_alerts', 0)} alert(s)",
            "target": f"127.0.0.1:{port}",
            "description": str(stats),
        })

    return alerts


def _poll_all() -> list[dict]:
    """Poll every registered tool. Returns all normalized alerts."""
    all_alerts: list[dict] = []
    for name, port in TOOLS.items():
        try:
            all_alerts.extend(_poll_tool(name, port))
        except Exception as exc:
            logger.exception("Polling %s failed: %s", name, exc)
    return all_alerts


def _ingest(alerts: list[dict]) -> None:
    """Persist normalized alerts into the unified table."""
    now = datetime.utcnow().isoformat()
    for a in alerts:
        database.save_alert(
            tool_name=a["tool_name"],
            severity=a["severity"],
            title=a["title"],
            target=a.get("target"),
            description=a.get("description"),
            timestamp=a.get("timestamp", now),
        )


class AlertAggregator:
    """Background poller that aggregates alerts from all tools."""

    def __init__(self, interval: int = POLL_INTERVAL) -> None:
        self._interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            alerts = _poll_all()
            if alerts:
                with self._lock:
                    _ingest(alerts)
            self._stop_event.wait(self._interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="alert-aggregator"
        )
        self._thread.start()
        logger.info("Alert aggregator started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("Alert aggregator stopped")

    def poll_now(self) -> list[dict]:
        """Force an immediate poll and ingest. Returns the alerts found."""
        alerts = _poll_all()
        if alerts:
            with self._lock:
                _ingest(alerts)
        return alerts


# ---------------------------------------------------------------------------
# Query functions (read from the unified alerts table)
# ---------------------------------------------------------------------------

def get_unified_alerts() -> list[dict]:
    """Return all alerts from all tools."""
    return database.get_recent_alerts(limit=10_000)


def get_alerts_by_tool(tool_name: str) -> list[dict]:
    """Return alerts filtered by tool name."""
    conn = database.get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts_unified WHERE tool_name = ? ORDER BY id DESC",
        (tool_name,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alerts_by_severity(severity: str) -> list[dict]:
    """Return alerts filtered by severity."""
    conn = database.get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts_unified WHERE severity = ? ORDER BY id DESC",
        (severity,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_alerts(minutes: int = 60) -> list[dict]:
    """Return alerts from the last N minutes."""
    cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    conn = database.get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts_unified WHERE timestamp >= ? ORDER BY id DESC",
        (cutoff,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    database.init_db()
    aggregator = AlertAggregator()
    found = aggregator.poll_now()
    print(f"Polled {len(TOOLS)} tools, found {len(found)} alert(s)")
    for a in found:
        print(f"  [{a['severity']}] {a['tool_name']}: {a['title']}")
    print(f"Unified alerts in DB: {len(get_unified_alerts())}")
    print("OK")
