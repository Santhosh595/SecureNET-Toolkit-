"""CloudSentry — SQLite persistence for posture check results."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from engine import CheckResult

DB_PATH = Path("cloudsentry.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT,
            check_id TEXT,
            title TEXT,
            status TEXT,
            severity TEXT,
            detail TEXT,
            timestamp REAL
        );
        CREATE INDEX IF NOT EXISTS idx_checks_provider ON checks(provider);
    """)
    conn.commit()
    conn.close()


def save_results(results: list[CheckResult]) -> None:
    conn = get_connection()
    ts = time.time()
    conn.executemany(
        "INSERT INTO checks (provider, check_id, title, status, severity, detail, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(r.provider, r.check_id, r.title, r.status, r.severity, r.detail, ts) for r in results],
    )
    conn.commit()
    conn.close()
