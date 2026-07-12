"""ImgScan — SQLite storage (4 tables)."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from typing import List, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "imgscan.db")


def init_db(path: str = DB_PATH) -> None:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_path TEXT,
            scan_type TEXT,
            timestamp TEXT,
            packages_scanned INTEGER,
            vuln_count INTEGER,
            duration REAL
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            package TEXT,
            version TEXT,
            ecosystem TEXT,
            cve_id TEXT,
            severity TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            description TEXT,
            fixed_version TEXT,
            in_kev INTEGER,
            upgrade_command TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS dockerfile_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            check_id TEXT,
            line_number INTEGER,
            severity TEXT,
            description TEXT,
            remediation TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS sbom_components (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            name TEXT,
            version TEXT,
            purl TEXT,
            license TEXT,
            ecosystem TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
        """
    )
    conn.commit()
    conn.close()


def save_scan(target_path: str, scan_type: str, packages_scanned: int,
              vuln_count: int, duration: float, path: str = DB_PATH) -> int:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target_path, scan_type, timestamp, packages_scanned, "
        "vuln_count, duration) VALUES (?,?,?,?,?,?)",
        (target_path, scan_type, datetime.now().isoformat(), packages_scanned,
         vuln_count, duration),
    )
    sid = cur.lastrowid
    conn.commit()
    conn.close()
    return sid


def save_vulnerabilities(scan_id: int, findings: List, path: str = DB_PATH) -> None:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    for f in findings:
        cur.execute(
            "INSERT INTO vulnerabilities (scan_id, package, version, ecosystem, "
            "cve_id, severity, cvss_score, cvss_vector, description, fixed_version, "
            "in_kev, upgrade_command) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, f.package, f.version, f.ecosystem, f.cve_id, f.severity,
             f.cvss_score, f.cvss_vector, f.description, f.fixed_version,
             1 if f.in_kev else 0, f.upgrade_command),
        )
    conn.commit()
    conn.close()


def save_dockerfile_findings(scan_id: int, findings: List, path: str = DB_PATH) -> None:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    for f in findings:
        cur.execute(
            "INSERT INTO dockerfile_findings (scan_id, check_id, line_number, "
            "severity, description, remediation) VALUES (?,?,?,?,?,?)",
            (scan_id, f.check_id, f.line_number, f.severity,
             f.description, f.remediation),
        )
    conn.commit()
    conn.close()


def save_sbom_components(scan_id: int, components: List, path: str = DB_PATH) -> None:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    for c in components:
        cur.execute(
            "INSERT INTO sbom_components (scan_id, name, version, purl, license, "
            "ecosystem) VALUES (?,?,?,?,?,?)",
            (scan_id, c.name, c.version, getattr(c, "purl", ""),
             getattr(c, "license", ""), getattr(c, "ecosystem", "unknown")),
        )
    conn.commit()
    conn.close()


def get_scans(path: str = DB_PATH) -> List[dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_vulnerabilities(scan_id: int = None, path: str = DB_PATH) -> List[dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    if scan_id is None:
        rows = conn.execute("SELECT * FROM vulnerabilities ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM vulnerabilities WHERE scan_id=?",
                            (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_dockerfile_findings(scan_id: int = None, path: str = DB_PATH) -> List[dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    if scan_id is None:
        rows = conn.execute("SELECT * FROM dockerfile_findings ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM dockerfile_findings WHERE scan_id=?",
                            (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_sbom_components(scan_id: int = None, path: str = DB_PATH) -> List[dict]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    if scan_id is None:
        rows = conn.execute("SELECT * FROM sbom_components ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM sbom_components WHERE scan_id=?",
                            (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
