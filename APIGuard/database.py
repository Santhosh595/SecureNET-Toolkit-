"""APIGuard — SQLite storage (4 tables)."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apiguard.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            auth_type TEXT DEFAULT 'none',
            spec_file TEXT,
            endpoints_found INTEGER DEFAULT 0,
            tests_run INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            timestamp TEXT NOT NULL,
            duration REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            parameters TEXT,
            auth_required INTEGER DEFAULT 1,
            source TEXT DEFAULT 'discovered',
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            owasp_category TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            test_name TEXT NOT NULL,
            severity TEXT DEFAULT 'MEDIUM',
            evidence TEXT,
            request_sent TEXT,
            response_received TEXT,
            remediation TEXT,
            cvss_score REAL,
            cwe_ref TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            endpoint_id INTEGER,
            test_name TEXT NOT NULL,
            status TEXT NOT NULL,
            response_code INTEGER,
            response_time REAL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        """)


def save_scan(target: str, auth_type: str = "none", spec_file: str = "") -> int:
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, auth_type, spec_file, timestamp) VALUES (?,?,?,?)",
            (target, auth_type, spec_file, datetime.utcnow().isoformat()),
        )
        return cur.lastrowid or 0


def update_scan(
    scan_id: int,
    endpoints_found: int = 0,
    tests_run: int = 0,
    findings_count: int = 0,
    duration: float = 0.0,
) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE scans SET endpoints_found=?, tests_run=?, findings_count=?, duration=? WHERE id=?",
            (endpoints_found, tests_run, findings_count, duration, scan_id),
        )


def save_endpoint(scan_id: int, method: str, path: str, parameters: str = "", auth_required: int = 1, source: str = "discovered") -> int:
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO endpoints (scan_id, method, path, parameters, auth_required, source) VALUES (?,?,?,?,?,?)",
            (scan_id, method, path, parameters, auth_required, source),
        )
        return cur.lastrowid or 0


def save_finding(
    scan_id: int,
    owasp_category: str,
    endpoint: str,
    method: str,
    test_name: str,
    severity: str = "MEDIUM",
    evidence: str = "",
    request_sent: str = "",
    response_received: str = "",
    remediation: str = "",
    cvss_score: Optional[float] = None,
    cwe_ref: str = "",
) -> int:
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO findings (scan_id, owasp_category, endpoint, method, test_name, severity, evidence, request_sent, response_received, remediation, cvss_score, cwe_ref) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, owasp_category, endpoint, method, test_name, severity, evidence, request_sent, response_received, remediation, cvss_score, cwe_ref),
        )
        return cur.lastrowid or 0


def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    """Get a single scan by ID."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None


def get_scans(limit: int = 20) -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def get_findings(scan_id: Optional[int] = None, owasp_category: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
    with get_db() as conn:
        q = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []
        if scan_id:
            q += " AND scan_id=?"
            params.append(scan_id)
        if owasp_category:
            q += " AND owasp_category=?"
            params.append(owasp_category)
        if severity:
            q += " AND severity=?"
            params.append(severity)
        q += " ORDER BY id DESC"
        rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]


def get_endpoints(scan_id: int) -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM endpoints WHERE scan_id=? ORDER BY path", (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def get_test_results(scan_id: int) -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM test_results WHERE scan_id=?", (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def save_test_result(scan_id: int, endpoint_id: Optional[int], test_name: str, status: str, response_code: Optional[int] = None, response_time: Optional[float] = None) -> int:
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO test_results (scan_id, endpoint_id, test_name, status, response_code, response_time) VALUES (?,?,?,?,?,?)",
            (scan_id, endpoint_id, test_name, status, response_code, response_time),
        )
        return cur.lastrowid or 0
