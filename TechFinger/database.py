"""TechFinger — SQLite persistence for fingerprint results."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

DB_PATH = Path("techfinger.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            status INTEGER,
            server TEXT,
            title TEXT,
            detected TEXT,
            timestamp REAL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url);
    """)
    conn.commit()
    conn.close()


def save_result(result: dict) -> None:
    conn = get_connection()
    import json
    detected = json.dumps(result.get("detected", []))
    conn.execute(
        "INSERT INTO scans (url, status, server, title, detected, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (result.get("url"), result.get("status"), result.get("server"),
         result.get("title"), detected, time.time()),
    )
    conn.commit()
    conn.close()
