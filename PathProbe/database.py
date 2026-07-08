"""PathProbe — SQLite persistence for discovered paths."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

DB_PATH = Path("pathprobe.db")


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
            checked INTEGER DEFAULT 0,
            found INTEGER DEFAULT 0,
            duration REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            path TEXT,
            status INTEGER,
            size INTEGER,
            redirect TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
        CREATE INDEX IF NOT EXISTS idx_paths_scan ON paths(scan_id);
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


def add_path(scan_id: int, r: dict) -> None:
    conn = get_connection()
    conn.execute(
        "INSERT INTO paths (scan_id, path, status, size, redirect) VALUES (?, ?, ?, ?, ?)",
        (scan_id, r.get("path"), r.get("status"), r.get("size"), r.get("redirect")),
    )
    conn.commit()
    conn.close()


def update_scan(scan_id: int, found: int, duration: float) -> None:
    conn = get_connection()
    conn.execute("UPDATE scans SET found=?, duration=? WHERE id=?", (found, duration, scan_id))
    conn.commit()
    conn.close()
