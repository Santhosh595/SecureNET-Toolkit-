"""ARPWatch — SQLite database operations.

Stores ARP events, baseline entries, and alerts.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path("arpwatch.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database tables."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS arp_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT,
            src_mac TEXT,
            dst_ip TEXT,
            alert_type TEXT,
            severity TEXT
        );

        CREATE TABLE IF NOT EXISTS baseline (
            ip TEXT PRIMARY KEY,
            mac TEXT NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            ip TEXT,
            expected_mac TEXT,
            seen_mac TEXT,
            verdict TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_arp_log_ts ON arp_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
    """)
    conn.commit()
    conn.close()


def log_packet(
    src_ip: str, src_mac: str, dst_ip: str,
    alert_type: str = "INFO", severity: str = "INFO",
) -> int:
    """Log an ARP packet. Returns row id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO arp_log (timestamp, src_ip, src_mac, dst_ip, alert_type, severity) VALUES (?, ?, ?, ?, ?, ?)",
        (time.time(), src_ip, src_mac, dst_ip, alert_type, severity),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def log_alert(
    alert_type: str, severity: str,
    ip: str, expected_mac: str, seen_mac: str, verdict: str,
) -> int:
    """Log an alert. Returns row id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO alerts (timestamp, type, severity, ip, expected_mac, seen_mac, verdict) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (time.time(), alert_type, severity, ip, expected_mac, seen_mac, verdict),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def upsert_baseline(ip: str, mac: str) -> None:
    """Add or update a baseline entry."""
    now = time.time()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO baseline (ip, mac, first_seen, last_seen) VALUES (?, ?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, last_seen=excluded.last_seen""",
        (ip, mac, now, now),
    )
    conn.commit()
    conn.close()


def get_baseline() -> dict[str, str]:
    """Get all baseline entries as {ip: mac} dict."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT ip, mac FROM baseline")
    result = {row["ip"]: row["mac"] for row in cur.fetchall()}
    conn.close()
    return result


def clear_baseline() -> None:
    """Remove all baseline entries."""
    conn = get_connection()
    conn.execute("DELETE FROM baseline")
    conn.commit()
    conn.close()


def get_recent_packets(limit: int = 100) -> list[sqlite3.Row]:
    """Get most recent ARP log entries."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM arp_log ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


def get_recent_alerts(limit: int = 50) -> list[sqlite3.Row]:
    """Get most recent alerts."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


def get_alerts_since(timestamp: float) -> list[sqlite3.Row]:
    """Get alerts since a given timestamp."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts WHERE timestamp > ? ORDER BY id DESC", (timestamp,))
    rows = cur.fetchall()
    conn.close()
    return rows


def get_packets_since(timestamp: float) -> list[sqlite3.Row]:
    """Get ARP packets since a given timestamp."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM arp_log WHERE timestamp > ? ORDER BY id DESC", (timestamp,))
    rows = cur.fetchall()
    conn.close()
    return rows


def get_stats() -> dict[str, Any]:
    """Get database statistics."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as total FROM arp_log")
    total_packets = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM alerts")
    total_alerts = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM baseline")
    total_baseline = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM alerts WHERE severity = 'CRITICAL'")
    critical_alerts = cur.fetchone()["total"]
    conn.close()
    return {
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "total_baseline": total_baseline,
        "critical_alerts": critical_alerts,
    }
