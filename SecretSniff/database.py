"""SecretSniff - SQLite database operations.

Stores scan history, findings, and allowlist in a local SQLite database.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path("secretsniff.db")


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
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            timestamp REAL NOT NULL,
            files_scanned INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            duration REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            value_redacted TEXT NOT NULL,
            entropy REAL,
            commit_hash TEXT,
            author TEXT,
            commit_date TEXT,
            allowlisted INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            reason TEXT,
            added_by TEXT,
            added_at REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_name);
        CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path);
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
    """)
    conn.commit()
    conn.close()


def save_scan(target: str, scan_type: str, files_scanned: int,
              findings: list[dict], duration: float) -> int:
    """Save scan results. Returns scan ID."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target, scan_type, timestamp, files_scanned, findings_count, duration) VALUES (?, ?, ?, ?, ?, ?)",
        (target, scan_type, time.time(), files_scanned, len(findings), duration),
    )
    scan_id = cur.lastrowid

    for f in findings:
        cur.execute(
            """INSERT INTO findings (scan_id, file_path, line_number, rule_name,
               severity, confidence, value_redacted, entropy, commit_hash, author,
               commit_date, allowlisted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, f.get("file", ""), f.get("line", 0), f.get("rule", ""),
             f.get("severity", ""), f.get("confidence", ""), f.get("value_redacted", ""),
             f.get("entropy"), f.get("commit_hash"), f.get("author"),
             f.get("date"), int(f.get("allowlisted", False))),
        )

    conn.commit()
    conn.close()
    return scan_id


def get_recent_scans(limit: int = 20) -> list[dict]:
    """Get recent scans."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_findings(scan_id: int) -> list[dict]:
    """Get findings for a scan."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_findings_by_severity(severity: str, limit: int = 100) -> list[dict]:
    """Get findings by severity across all scans."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM findings WHERE severity = ? LIMIT ?", (severity, limit))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_top_rules(limit: int = 10) -> list[dict]:
    """Get most triggered rules."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT rule_name, COUNT(*) as count
        FROM findings GROUP BY rule_name
        ORDER BY count DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_top_files(limit: int = 10) -> list[dict]:
    """Get most affected files."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT file_path, COUNT(*) as count
        FROM findings GROUP BY file_path
        ORDER BY count DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_authors_stats(limit: int = 10) -> list[dict]:
    """Get author leaderboard (who introduced most secrets)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT author, COUNT(*) as count
        FROM findings WHERE author IS NOT NULL
        GROUP BY author ORDER BY count DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_stats() -> dict[str, Any]:
    """Get overall statistics."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as total FROM scans")
    total_scans = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM findings")
    total_findings = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM findings WHERE severity = 'CRITICAL'")
    critical = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM findings WHERE severity = 'HIGH'")
    high = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM findings WHERE severity = 'MEDIUM'")
    medium = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM findings WHERE severity = 'LOW'")
    low = cur.fetchone()["total"]
    conn.close()
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


def save_allowlist(entry_type: str, value: str, reason: str = "", added_by: str = "") -> int:
    """Save an allowlist entry. Returns entry ID."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO allowlist (type, value, reason, added_by, added_at) VALUES (?, ?, ?, ?, ?)",
        (entry_type, value, reason, added_by, time.time()),
    )
    entry_id = cur.lastrowid
    conn.commit()
    conn.close()
    return entry_id


def get_allowlist_entries() -> list[dict]:
    """Get all allowlist entries."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM allowlist ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def delete_allowlist_entry(entry_id: int) -> bool:
    """Delete an allowlist entry."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM allowlist WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
    return True
