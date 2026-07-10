"""PathProbe — SQLite persistence.

Tables:
  scans(id, target, wordlist, extensions, threads, timestamp,
        total_requests, found_count, duration)
  findings(id, scan_id, url, status_code, content_length, content_type,
           response_ms, redirect_to, interesting, word_count, line_count)
  wordlists(id, name, path, entry_count, built_in)
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "pathprobe.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            wordlist TEXT,
            extensions TEXT,
            threads INTEGER,
            timestamp REAL NOT NULL,
            total_requests INTEGER DEFAULT 0,
            found_count INTEGER DEFAULT 0,
            duration REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            url TEXT,
            status_code INTEGER,
            content_length INTEGER,
            content_type TEXT,
            response_ms INTEGER,
            redirect_to TEXT,
            interesting INTEGER DEFAULT 0,
            word_count INTEGER,
            line_count INTEGER,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS wordlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            path TEXT,
            entry_count INTEGER,
            built_in INTEGER DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        """
    )
    conn.commit()
    conn.close()


def create_scan(target: str, wordlist: str, extensions: str, threads: int) -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target, wordlist, extensions, threads, timestamp) VALUES (?,?,?,?,?)",
        (target, wordlist, extensions, threads, time.time()),
    )
    sid = cur.lastrowid
    conn.commit()
    conn.close()
    return sid


def add_finding(scan_id: int, f: dict) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT INTO findings
           (scan_id, url, status_code, content_length, content_type, response_ms,
            redirect_to, interesting, word_count, line_count)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (scan_id, f.get("url"), f.get("status_code"), f.get("size"),
         f.get("content_type"), f.get("time_ms"), f.get("redirect_to"),
         1 if f.get("interesting") else 0, f.get("word_count"), f.get("line_count")),
    )
    conn.commit()
    conn.close()


def update_scan(scan_id: int, total: int, found: int, duration: float) -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE scans SET total_requests=?, found_count=?, duration=? WHERE id=?",
        (total, found, duration, scan_id),
    )
    conn.commit()
    conn.close()


def register_wordlists(rows: list[dict]) -> None:
    conn = get_connection()
    for r in rows:
        conn.execute(
            "INSERT OR REPLACE INTO wordlists (name, path, entry_count, built_in) VALUES (?,?,?,?)",
            (r["name"], r["path"], r["entry_count"], 1 if r["built_in"] else 0),
        )
    conn.commit()
    conn.close()


def get_scans(limit: int = 50) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_findings(scan_id: int, severity: str | None = None) -> list[dict]:
    conn = get_connection()
    if severity:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? AND interesting=1", (scan_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    conn = get_connection()
    r = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return dict(r) if r else None


def stats() -> dict:
    conn = get_connection()
    total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    total_paths = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    interesting = conn.execute("SELECT COUNT(*) FROM findings WHERE interesting=1").fetchone()[0]
    row = conn.execute(
        "SELECT target, COUNT(*) c FROM scans GROUP BY target ORDER BY c DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return {
        "total_scans": total_scans,
        "total_paths_found": total_paths,
        "interesting_findings": interesting,
        "most_scanned_target": row["target"] if row else None,
    }
