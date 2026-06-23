"""Database module for the Network Sniffer.

Handles SQLite initialization, packet storage, alert logging,
and query operations.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path("packets.db")


def get_connection() -> sqlite3.Connection:
    """Create and return a new database connection."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the database schema."""
    Path("logs").mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            src TEXT,
            dst TEXT,
            proto TEXT,
            sport INTEGER,
            dport INTEGER,
            length INTEGER,
            flags TEXT,
            alert TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            rule TEXT NOT NULL,
            src TEXT,
            meta TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
        CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src);
    """)
    conn.commit()
    conn.close()


def insert_packet(
    ts: float,
    src: Optional[str],
    dst: Optional[str],
    proto: str,
    sport: Optional[int],
    dport: Optional[int],
    length: int,
    flags: str,
    alert: str = "",
) -> int:
    """Insert a captured packet. Returns the row id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO packets (ts, src, dst, proto, sport, dport, length, flags, alert)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts, src, dst, proto, sport, dport, length, flags, alert),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def insert_alert(rule: str, src: Optional[str], meta: str = "") -> int:
    """Insert an alert entry. Returns the row id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO alerts (ts, rule, src, meta) VALUES (?, ?, ?, ?)",
        (time.time(), rule, src, meta),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def get_recent_packets(seconds: float = 10.0) -> list[sqlite3.Row]:
    """Return packets captured within the last `seconds` seconds."""
    cutoff = time.time() - seconds
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT ts, src, dst, proto, sport, dport, length, flags, alert FROM packets WHERE ts >= ?",
        (cutoff,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_latest_packets(limit: int = 50) -> list[sqlite3.Row]:
    """Return the most recent packets ordered newest first."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, ts, src, dst, proto, sport, dport, length, flags, alert "
        "FROM packets ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_alerts(limit: int = 50) -> list[sqlite3.Row]:
    """Return the most recent alerts ordered newest first."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, ts, rule, src, meta FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def count_packets() -> int:
    """Return total number of packets stored."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM packets")
    count = cur.fetchone()[0]
    conn.close()
    return count


def count_alerts() -> int:
    """Return total number of alerts stored."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts")
    count = cur.fetchone()[0]
    conn.close()
    return count
