"""TLScan — SQLite database operations.

Stores scan history, certificates, protocols, ciphers, and vulnerability results.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path("tlscan.db")


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
            domain TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 443,
            timestamp REAL NOT NULL,
            grade TEXT,
            score INTEGER,
            duration REAL
        );

        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            position INTEGER NOT NULL,
            subject_cn TEXT,
            subject_o TEXT,
            issuer_cn TEXT,
            issuer_o TEXT,
            serial_number TEXT,
            not_before TEXT,
            not_until TEXT,
            days_until_expiry INTEGER,
            signature_algorithm TEXT,
            key_type TEXT,
            key_size INTEGER,
            fingerprint_sha256 TEXT,
            san TEXT,
            is_self_signed INTEGER,
            is_ca INTEGER,
            has_sct INTEGER,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS protocols (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            supported INTEGER NOT NULL,
            risk TEXT,
            cipher TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS ciphers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            protocol TEXT,
            cipher TEXT NOT NULL,
            category TEXT NOT NULL,
            forward_secrecy INTEGER,
            accepted INTEGER NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            cve TEXT,
            vulnerable INTEGER NOT NULL,
            severity TEXT NOT NULL,
            detail TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
        CREATE INDEX IF NOT EXISTS idx_certificates_scan ON certificates(scan_id);
        CREATE INDEX IF NOT EXISTS idx_protocols_scan ON protocols(scan_id);
        CREATE INDEX IF NOT EXISTS idx_ciphers_scan ON ciphers(scan_id);
        CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
    """)
    conn.commit()
    conn.close()


def save_scan(domain: str, port: int, grade: str, score: int,
              duration: float, certificates: list, protocols: list,
              ciphers: list, vulnerabilities: list) -> int:
    """Save a complete scan result. Returns scan ID."""
    conn = get_connection()
    cur = conn.cursor()

    # Insert scan
    cur.execute(
        "INSERT INTO scans (domain, port, timestamp, grade, score, duration) VALUES (?, ?, ?, ?, ?, ?)",
        (domain, port, time.time(), grade, score, duration),
    )
    scan_id = cur.lastrowid

    # Insert certificates
    for cert in certificates:
        cur.execute(
            """INSERT INTO certificates (scan_id, position, subject_cn, subject_o,
               issuer_cn, issuer_o, serial_number, not_before, not_until,
               days_until_expiry, signature_algorithm, key_type, key_size,
               fingerprint_sha256, san, is_self_signed, is_ca, has_sct)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, cert.position, cert.subject_cn, cert.subject_o,
             cert.issuer_cn, cert.issuer_o, cert.serial_number,
             cert.not_before, cert.not_until, cert.days_until_expiry,
             cert.signature_algorithm, cert.key_type, cert.key_size,
             cert.fingerprint_sha256, ",".join(cert.san),
             int(cert.is_self_signed), int(cert.is_ca), int(cert.has_sct)),
        )

    # Insert protocols
    for proto in protocols:
        cur.execute(
            "INSERT INTO protocols (scan_id, protocol, supported, risk, cipher) VALUES (?, ?, ?, ?, ?)",
            (scan_id, proto.protocol, int(proto.supported), proto.risk, proto.cipher),
        )

    # Insert ciphers
    for cipher in ciphers:
        cur.execute(
            "INSERT INTO ciphers (scan_id, protocol, cipher, category, forward_secrecy, accepted) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, cipher.protocol, cipher.cipher, cipher.category,
             int(cipher.forward_secrecy), int(cipher.accepted)),
        )

    # Insert vulnerabilities
    for vuln in vulnerabilities:
        cur.execute(
            "INSERT INTO vulnerabilities (scan_id, name, cve, vulnerable, severity, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, vuln.name, vuln.cve, int(vuln.vulnerable), vuln.severity, vuln.detail),
        )

    conn.commit()
    conn.close()
    return scan_id


def get_scan(scan_id: int) -> Optional[dict]:
    """Get scan details by ID."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def get_certificates(scan_id: int) -> list[dict]:
    """Get certificates for a scan."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM certificates WHERE scan_id = ? ORDER BY position", (scan_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_protocols(scan_id: int) -> list[dict]:
    """Get protocols for a scan."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM protocols WHERE scan_id = ?", (scan_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_ciphers(scan_id: int) -> list[dict]:
    """Get ciphers for a scan."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ciphers WHERE scan_id = ? AND accepted = 1", (scan_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_vulnerabilities(scan_id: int) -> list[dict]:
    """Get vulnerabilities for a scan."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_recent_scans(limit: int = 20) -> list[dict]:
    """Get recent scans."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_stats() -> dict[str, Any]:
    """Get overall statistics."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as total FROM scans")
    total_scans = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM certificates")
    total_certs = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as total FROM vulnerabilities WHERE vulnerable = 1")
    total_vulns = cur.fetchone()["total"]
    conn.close()
    return {
        "total_scans": total_scans,
        "total_certificates": total_certs,
        "total_vulnerabilities": total_vulns,
    }
