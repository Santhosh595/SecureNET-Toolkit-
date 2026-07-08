"""VulnProbe — SQLite persistence for scan findings."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

DB_PATH = Path("vulnprobe.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp REAL NOT NULL,
            findings INTEGER DEFAULT 0,
            duration REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            tid TEXT,
            name TEXT,
            severity TEXT,
            method TEXT,
            path TEXT,
            status_code INTEGER,
            template_file TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
    """)
    conn.commit()
    conn.close()


def create_scan(target: str) -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (target, timestamp) VALUES (?, ?)", (target, time.time()))
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def add_finding(scan_id: int, finding: dict) -> None:
    conn = get_connection()
    conn.execute(
        "INSERT INTO findings (scan_id, tid, name, severity, method, path, status_code, template_file) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, finding.get("id"), finding.get("name"), finding.get("severity"),
         finding.get("method"), finding.get("path"), finding.get("status_code"),
         finding.get("template_file")),
    )
    conn.commit()
    conn.close()


def update_scan(scan_id: int, findings: int, duration: float) -> None:
    conn = get_connection()
    conn.execute("UPDATE scans SET findings=?, duration=? WHERE id=?", (findings, duration, scan_id))
    conn.commit()
    conn.close()
