"""ImgScan — SQLite persistence for CVE findings."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from engine import Finding

DB_PATH = Path("imgscan.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component TEXT,
            version TEXT,
            cve TEXT,
            severity TEXT,
            source TEXT,
            detail TEXT,
            timestamp REAL
        );
        CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);
    """)
    conn.commit()
    conn.close()


def save_findings(findings: list[Finding]) -> None:
    conn = get_connection()
    ts = time.time()
    conn.executemany(
        "INSERT INTO findings (component, version, cve, severity, source, detail, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(f.component, f.version, f.cve, f.severity, f.source, f.detail, ts) for f in findings],
    )
    conn.commit()
    conn.close()
