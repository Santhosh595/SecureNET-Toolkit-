"""CloudSentry — SQLite persistence.

Tables:
  audits(id, providers, timestamp, total_checks, pass_count, fail_count, duration)
  findings(id, audit_id, check_id, check_name, provider, category, status,
           severity, affected_resources, description, remediation, cis_ref, owasp_ref)
  resources(id, audit_id, provider, resource_type, resource_id, resource_name, region)
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "cloudsentry.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    providers TEXT,
    timestamp REAL,
    total_checks INTEGER,
    pass_count INTEGER,
    fail_count INTEGER,
    duration REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER,
    check_id TEXT,
    check_name TEXT,
    provider TEXT,
    category TEXT,
    status TEXT,
    severity TEXT,
    affected_resources TEXT,
    description TEXT,
    remediation TEXT,
    cis_ref TEXT,
    owasp_ref TEXT
);
CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER,
    provider TEXT,
    resource_type TEXT,
    resource_id TEXT,
    resource_name TEXT,
    region TEXT
);
"""


def init_db(path=None) -> None:
    conn = sqlite3.connect(str(path or DB_PATH))
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def _conn(path=None):
    return sqlite3.connect(str(path or DB_PATH))


def save_audit(providers: list, results: list, duration: float, path=None) -> int:
    conn = _conn(path)
    cur = conn.cursor()
    total = len(results)
    pass_c = sum(1 for r in results if r.status == "PASS")
    fail_c = sum(1 for r in results if r.status == "FAIL")
    cur.execute(
        "INSERT INTO audits (providers, timestamp, total_checks, pass_count, fail_count, duration) "
        "VALUES (?,?,?,?,?,?)",
        (",".join(providers), time.time(), total, pass_c, fail_c, duration),
    )
    audit_id = cur.lastrowid
    for r in results:
        cur.execute(
            "INSERT INTO findings (audit_id, check_id, check_name, provider, category, status, "
            "severity, affected_resources, description, remediation, cis_ref, owasp_ref) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (audit_id, r.check_id, r.name, r.provider, r.category, r.status, r.severity,
             "\n".join(r.affected), r.description, r.remediation, r.cis_ref, r.owasp_ref),
        )
    conn.commit()
    conn.close()
    return audit_id


def get_audits(limit=20, path=None) -> list:
    conn = _conn(path)
    rows = conn.execute(
        "SELECT id, providers, timestamp, total_checks, pass_count, fail_count, duration "
        "FROM audits ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [
        {"id": r[0], "providers": r[1], "timestamp": r[2], "total": r[3],
         "pass": r[4], "fail": r[5], "duration": r[6]}
        for r in rows
    ]


def get_findings(audit_id=None, path=None, status=None, severity=None, provider=None) -> list:
    conn = _conn(path)
    q = "SELECT id, audit_id, check_id, check_name, provider, category, status, severity, " \
        "affected_resources, description, remediation, cis_ref, owasp_ref FROM findings"
    where, args = [], []
    if audit_id is not None:
        where.append("audit_id=?")
        args.append(audit_id)
    if status:
        where.append("status=?")
        args.append(status)
    if severity:
        where.append("severity=?")
        args.append(severity)
    if provider:
        where.append("provider=?")
        args.append(provider)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY id DESC"
    rows = conn.execute(q, args).fetchall()
    conn.close()
    return [
        {"id": r[0], "audit_id": r[1], "check_id": r[2], "name": r[3], "provider": r[4],
         "category": r[5], "status": r[6], "severity": r[7], "affected": r[8], "description": r[9],
         "remediation": r[10], "cis": r[11], "owasp": r[12]}
        for r in rows
    ]


def get_latest_audit(path=None):
    audits = get_audits(1, path)
    return audits[0] if audits else None
