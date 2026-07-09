"""VulnProbe — SQLite persistence.

Tables (per spec):
    scans     -- one row per scan run
    findings  -- one row per matched path
    templates -- catalog of all loaded templates (built-in flag)
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "vulnprobe.db"


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
            timestamp REAL NOT NULL,
            templates_run INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            duration REAL DEFAULT 0,
            template_filter TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            template_id TEXT,
            template_name TEXT,
            severity TEXT,
            category TEXT,
            url TEXT,
            matched_path TEXT,
            matched_condition TEXT,
            extracted_values TEXT,
            status_code INTEGER,
            response_size INTEGER,
            response_ms INTEGER,
            method TEXT,
            remediation TEXT,
            timestamp REAL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_id TEXT UNIQUE,
            name TEXT,
            severity TEXT,
            category TEXT,
            tags TEXT,
            author TEXT,
            built_in INTEGER DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(timestamp);
        """
    )
    conn.commit()
    conn.close()


def create_scan(target: str, template_filter: str = "", templates_run: int = 0) -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target, timestamp, template_filter, templates_run) "
        "VALUES (?, ?, ?, ?)",
        (target, time.time(), template_filter, templates_run),
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def update_scan(scan_id: int, findings_count: int, duration: float) -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE scans SET findings_count=?, duration=? WHERE id=?",
        (findings_count, duration, scan_id),
    )
    conn.commit()
    conn.close()


def add_finding(scan_id: int, finding: dict) -> None:
    conn = get_connection()
    import json as _json

    conn.execute(
        """
        INSERT INTO findings (
            scan_id, template_id, template_name, severity, category, url,
            matched_path, matched_condition, extracted_values, status_code,
            response_size, response_ms, method, remediation, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            finding.get("template_id"),
            finding.get("name"),
            finding.get("severity"),
            finding.get("category"),
            finding.get("url"),
            finding.get("matched_path"),
            finding.get("matched_condition"),
            _json.dumps(finding.get("extracted") or {}, ensure_ascii=False),
            finding.get("status_code"),
            finding.get("response_size"),
            finding.get("response_ms"),
            finding.get("method"),
            finding.get("remediation", ""),
            finding.get("timestamp", time.time()),
        ),
    )
    conn.commit()
    conn.close()


def upsert_template(tpl: dict, built_in: bool = True) -> None:
    conn = get_connection()
    import json as _json

    conn.execute(
        """
        INSERT INTO templates (template_id, name, severity, category, tags, author, built_in)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(template_id) DO UPDATE SET
            name=excluded.name, severity=excluded.severity,
            category=excluded.category, tags=excluded.tags,
            author=excluded.author, built_in=excluded.built_in
        """,
        (
            tpl.get("id"),
            tpl.get("name"),
            tpl.get("severity"),
            tpl.get("category", "uncategorized"),
            _json.dumps(tpl.get("tags") or [], ensure_ascii=False),
            tpl.get("author", "SecureNET"),
            1 if built_in else 0,
        ),
    )
    conn.commit()
    conn.close()


def sync_templates(templates: list[dict]) -> None:
    for t in templates:
        upsert_template(t, built_in=t.get("_built_in", True))


# --- readers -------------------------------------------------------------

def get_scans(limit: int = 50) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    conn = get_connection()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_findings(scan_id: int = None, **filters) -> list[dict]:
    conn = get_connection()
    sql = "SELECT * FROM findings"
    where = []
    params = []
    if scan_id is not None:
        where.append("scan_id=?")
        params.append(scan_id)
    if filters.get("severity"):
        where.append("severity=?")
        params.append(filters["severity"])
    if filters.get("category"):
        where.append("category=?")
        params.append(filters["category"])
    if filters.get("template_id"):
        where.append("template_id=?")
        params.append(filters["template_id"])
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    out = [dict(r) for r in rows]
    # parse extracted_values JSON
    for o in out:
        import json as _json

        try:
            o["extracted_values_parsed"] = _json.loads(o["extracted_values"] or "{}")
        except (ValueError, TypeError):
            o["extracted_values_parsed"] = {}
    return out


def get_template_catalog() -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM templates ORDER BY category, severity, template_id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_counts() -> dict:
    conn = get_connection()
    total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    crit = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE severity='critical'"
    ).fetchone()[0]
    high = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE severity='high'"
    ).fetchone()[0]
    tmpls = conn.execute("SELECT COUNT(*) FROM templates").fetchone()[0]
    conn.close()
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "critical_findings": crit,
        "high_findings": high,
        "templates_available": tmpls,
    }


def get_recent_events(limit: int = 20) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT f.severity, f.template_id, f.url, s.timestamp AS scan_ts, "
        "f.timestamp AS found_ts FROM findings f "
        "JOIN scans s ON s.id=f.scan_id ORDER BY f.timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        out.append(
            {
                "tool": "VulnProbe",
                "event": f"{d['template_id']} found on {d['url']}",
                "severity": d["severity"],
                "timestamp": d["found_ts"],
            }
        )
    return out
