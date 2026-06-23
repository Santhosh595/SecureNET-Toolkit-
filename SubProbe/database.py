"""SubProbe — SQLite database operations.

Stores scan results and found subdomains.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path("subprobe.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database tables."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            timestamp REAL NOT NULL,
            total_found INTEGER DEFAULT 0,
            live_count INTEGER DEFAULT 0,
            duration REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            subdomain TEXT NOT NULL,
            ip TEXT,
            http_status INTEGER DEFAULT 0,
            status TEXT,
            source TEXT,
            interesting INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
        CREATE INDEX IF NOT EXISTS idx_subdomains_name ON subdomains(subdomain);
    """)
    conn.commit()
    conn.close()


def create_scan(domain: str) -> int:
    """Create a new scan entry. Returns scan ID."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (domain, timestamp) VALUES (?, ?)",
                (domain, time.time()))
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def update_scan(scan_id: int, total_found: int, live_count: int, duration: float) -> None:
    """Update scan statistics."""
    conn = get_connection()
    conn.execute(
        "UPDATE scans SET total_found=?, live_count=?, duration=? WHERE id=?",
        (total_found, live_count, duration, scan_id),
    )
    conn.commit()
    conn.close()


def add_subdomain(
    scan_id: int, subdomain: str, ip: Optional[str],
    http_status: int, status: str, source: str, interesting: bool,
) -> int:
    """Add a subdomain result. Returns row ID."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO subdomains (scan_id, subdomain, ip, http_status, status, source, interesting)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, subdomain, ip, http_status, status, source, int(interesting)),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def get_scan(scan_id: int) -> Optional[dict]:
    """Get scan details by ID."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def get_subdomains(scan_id: int) -> list[dict]:
    """Get all subdomains for a scan."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM subdomains WHERE scan_id = ? ORDER BY subdomain", (scan_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_recent_scans(limit: int = 20) -> list[dict]:
    """Get recent scans."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_stats() -> dict[str, Any]:
    """Get overall statistics."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as total FROM scans")
    total_scans = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM subdomains")
    total_subs = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM subdomains WHERE interesting = 1")
    total_interesting = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM subdomains WHERE status = 'LIVE'")
    total_live = cur.fetchone()["total"]
    conn.close()
    return {
        "total_scans": total_scans,
        "total_subdomains": total_subs,
        "total_interesting": total_interesting,
        "total_live": total_live,
    }
