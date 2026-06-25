"""
SQLite database module for DNSAudit.

Handles persistence of scan results, DNS records, findings, and zone
takeover indicators.
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dnsaudit.db")


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Return a connection with row-factory enabled and WAL mode active."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT    NOT NULL,
   timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
    resolver    TEXT,
    grade       TEXT,
    score       INTEGER,
    duration    REAL
);

CREATE TABLE IF NOT EXISTS spf_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL,
    record       TEXT,
    lookup_count INTEGER,
    policy       TEXT,
    issues       TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dkim_results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL,
    selector   TEXT,
    key_size   INTEGER,
    algorithm  TEXT,
    issues     TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dmarc_results (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL,
    record         TEXT,
    policy         TEXT,
    pct            INTEGER,
    maturity_level TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dnssec_results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL,
    enabled    INTEGER,
    algorithm  TEXT,
    key_sizes  TEXT,
    issues     TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    category        TEXT,
    check_name      TEXT,
    severity        TEXT,
    description     TEXT,
    recommendation  TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS records (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  INTEGER NOT NULL,
    type     TEXT,
    name     TEXT,
    value    TEXT,
    ttl      INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS takeovers (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL,
    subdomain    TEXT,
    cname        TEXT,
    service      TEXT,
    vulnerable   INTEGER,
    evidence     TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
CREATE INDEX IF NOT EXISTS idx_spf_scan_id ON spf_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_dkim_scan_id ON dkim_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_dmarc_scan_id ON dmarc_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_dnssec_scan_id ON dnssec_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_records_scan_id ON records(scan_id);
CREATE INDEX IF NOT EXISTS idx_takeovers_scan_id ON takeovers(scan_id);
CREATE INDEX IF NOT EXISTS idx_levels_severity ON findings(severity);
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Create database file and schema if they don't already exist."""
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Save helpers (private)
# ---------------------------------------------------------------------------

def _insert_json_column(value: Any) -> Optional[str]:
    """Serialize a value to JSON for storage in a TEXT column."""
    if value is None:
        return None
    return json.dumps(value)


def _parse_json_row(value: Optional[str]) -> Any:
    """Deserialize a JSON-encoded TEXT column back into Python."""
    if value is None:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


# ---------------------------------------------------------------------------
# save_scan — the primary write path
# ---------------------------------------------------------------------------

def save_scan(
    domain: str,
    resolver: Optional[str] = None,
    grade: Optional[str] = None,
    score: Optional[int] = None,
    duration: Optional[float] = None,
    timestamp: Optional[str] = None,
    spf_results: Optional[List[Dict[str, Any]]] = None,
    dkim_results: Optional[List[Dict[str, Any]]] = None,
    dmarc_results: Optional[List[Dict[str, Any]]] = None,
    dnssec_results: Optional[List[Dict[str, Any]]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    records: Optional[List[Dict[str, Any]]] = None,
    takeovers: Optional[List[Dict[str, Any]]] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """
    Persist a full scan (parent row + all child tables).

    Parameters
    ----------
    domain : str
        The scanned FQDN.
    resolver : str, optional
        DNS resolver used for the scan.
    grade : str, optional
        Overall security grade (e.g. 'A', 'B', 'F').
    score : int, optional
        Numeric score (0-100).
    duration : float, optional
        Scan wall-clock time in seconds.
    timestamp : str, optional
        ISO-8601 timestamp.  Defaults to ``datetime.utcnow()``.
    spf_results : list of dict, optional
        Each dict may contain ``record``, ``lookup_count``, ``policy``, ``issues``.
    dkim_results : list of dict, optional
        Each dict may contain ``selector``, ``key_size``, ``algorithm``, ``issues``.
    dmarc_results : list of dict, optional
        Each dict may contain ``record``, ``policy``, ``pct``, ``maturity_level``.
    dnssec_results : list of dict, optional
        Each dict may contain ``enabled``, ``algorithm``, ``key_sizes``, ``issues``.
    findings : list of dict, optional
        Each dict may contain ``category``, ``check_name``, ``severity``,
        ``description``, ``recommendation``.
    records : list of dict, optional
        Each dict may contain ``type``, ``name``, ``value``, ``ttl``.
    takeovers : list of dict, optional
        Each dict may contain ``subdomain``, ``cname``, ``service``,
        ``vulnerable``, ``evidence``.
    db_path : str, optional
        Path to the SQLite file.

    Returns
    -------
    int
        The ``id`` of the inserted ``scans`` row.
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    conn = get_connection(db_path)
    try:
        cur = conn.cursor()

        # -- scans -----------------------------------------------------------
        cur.execute(
            """INSERT INTO scans (domain, timestamp, resolver, grade, score, duration)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (domain, timestamp, resolver, grade, score, duration),
        )
        scan_id = cur.lastrowid

        # -- spf_results -----------------------------------------------------
        for row in spf_results or []:
            cur.execute(
                """INSERT INTO spf_results
                   (scan_id, record, lookup_count, policy, issues)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    row.get("record"),
                    row.get("lookup_count"),
                    row.get("policy"),
                    _insert_json_column(row.get("issues")),
                ),
            )

        # -- dkim_results ----------------------------------------------------
        for row in dkim_results or []:
            cur.execute(
                """INSERT INTO dkim_results
                   (scan_id, selector, key_size, algorithm, issues)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    row.get("selector"),
                    row.get("key_size"),
                    row.get("algorithm"),
                    _insert_json_column(row.get("issues")),
                ),
            )

        # -- dmarc_results ---------------------------------------------------
        for row in dmarc_results or []:
            cur.execute(
                """INSERT INTO dmarc_results
                   (scan_id, record, policy, pct, maturity_level)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    row.get("record"),
                    row.get("policy"),
                    row.get("pct"),
                    row.get("maturity_level"),
                ),
            )

        # -- dnssec_results --------------------------------------------------
        for row in dnssec_results or []:
            cur.execute(
                """INSERT INTO dnssec_results
                   (scan_id, enabled, algorithm, key_sizes, issues)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    int(bool(row.get("enabled"))),
                    row.get("algorithm"),
                    _insert_json_column(row.get("key_sizes")),
                    _insert_json_column(row.get("issues")),
                ),
            )

        # -- findings --------------------------------------------------------
        for row in findings or []:
            cur.execute(
                """INSERT INTO findings
                   (scan_id, category, check_name, severity, description, recommendation)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    row.get("category"),
                    row.get("check_name"),
                    row.get("severity"),
                    row.get("description"),
                    row.get("recommendation"),
                ),
            )

        # -- records ---------------------------------------------------------
        for row in records or []:
            cur.execute(
                """INSERT INTO records
                   (scan_id, type, name, value, ttl)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    row.get("type"),
                    row.get("name"),
                    row.get("value"),
                    row.get("ttl"),
                ),
            )

        # -- takeovers -------------------------------------------------------
        for row in takeovers or []:
            cur.execute(
                """INSERT INTO takeovers
                   (scan_id, subdomain, cname, service, vulnerable, evidence)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    row.get("subdomain"),
                    row.get("cname"),
                    row.get("service"),
                    int(bool(row.get("vulnerable"))),
                    row.get("evidence"),
                ),
            )

        conn.commit()
        return scan_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def get_recent_scans(
    limit: int = 20,
    domain: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """
    Return the most recent scans, optionally filtered by domain.

    Parameters
    ----------
    limit : int
        Maximum number of rows to return.
    domain : str, optional
        If given, only return scans for this domain.
    db_path : str, optional

    Returns
    -------
    list of dict
    """
    conn = get_connection(db_path)
    try:
        if domain:
            rows = conn.execute(
                "SELECT * FROM scans WHERE domain = ? ORDER BY timestamp DESC LIMIT ?",
                (domain, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_scan_findings(
    scan_id: int,
    severity_filter: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """
    Return findings for a given scan, optionally filtered by severity.

    Parameters
    ----------
    scan_id : int
    severity_filter : str, optional
        e.g. ``"critical"``, ``"high"``, etc.
    db_path : str, optional

    Returns
    -------
    list of dict
    """
    conn = get_connection(db_path)
    try:
        if severity_filter:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND severity = ? ORDER BY id",
                (scan_id, severity_filter),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id",
                (scan_id,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_stats(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """
    Return aggregate statistics across all stored scans.

    Returns
    -------
    dict
        Keys: ``total_scans``, ``unique_domains``, ``grade_distribution``,
        ``avg_score``, ``avg_duration``, ``severity_counts``,
        ``vulnerable_takeovers``.
    """
    conn = get_connection(db_path)
    try:
        total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        unique_domains = conn.execute("SELECT COUNT(DISTINCT domain) FROM scans").fetchone()[0]

        grade_rows = conn.execute(
            "SELECT grade, COUNT(*) as cnt FROM scans GROUP BY grade"
        ).fetchall()
        grade_distribution = {r["grade"]: r["cnt"] for r in grade_rows}

        avg_row = conn.execute(
            "SELECT AVG(score) as avg_score, AVG(duration) as avg_duration FROM scans"
        ).fetchone()
        avg_score = avg_row["avg_score"]
        avg_duration = avg_row["avg_duration"]

        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        ).fetchall()
        severity_counts = {r["severity"]: r["cnt"] for r in severity_rows}

        vulnerable_takeovers = conn.execute(
            "SELECT COUNT(*) FROM takeovers WHERE vulnerable = 1"
        ).fetchone()[0]

        return {
            "total_scans": total_scans,
            "unique_domains": unique_domains,
            "grade_distribution": grade_distribution,
            "avg_score": round(avg_score, 2) if avg_score is not None else None,
            "avg_duration": round(avg_duration, 2) if avg_duration is not None else None,
            "severity_counts": severity_counts,
            "vulnerable_takeovers": vulnerable_takeovers,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Convenience: fetch a full scan with all child rows
# ---------------------------------------------------------------------------

def get_full_scan(scan_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """
    Retrieve a complete scan record including all related child tables.

    Returns ``None`` if the scan does not exist.
    """
    conn = get_connection(db_path)
    try:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if scan is None:
            return None

        result = dict(scan)

        result["spf_results"] = [
            {**dict(r), "issues": _parse_json_row(r["issues"])}
            for r in conn.execute(
                "SELECT * FROM spf_results WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]
        result["dkim_results"] = [
            {**dict(r), "issues": _parse_json_row(r["issues"])}
            for r in conn.execute(
                "SELECT * FROM dkim_results WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]
        result["dmarc_results"] = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM dmarc_results WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]
        result["dnssec_results"] = [
            {
                **dict(r),
                "enabled": bool(r["enabled"]),
                "key_sizes": _parse_json_row(r["key_sizes"]),
                "issues": _parse_json_row(r["issues"]),
            }
            for r in conn.execute(
                "SELECT * FROM dnssec_results WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]
        result["findings"] = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]
        result["records"] = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM records WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]
        result["takeovers"] = [
            {**dict(r), "vulnerable": bool(r["vulnerable"])}
            for r in conn.execute(
                "SELECT * FROM takeovers WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]

        return result
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Module self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        test_db = tmp.name

    try:
        init_db(test_db)

        sid = save_scan(
            domain="example.com",
            resolver="8.8.8.8",
            grade="A",
            score=92,
            duration=1.23,
            spf_results=[{"record": "v=spf1 include:_spf.google.com ~all", "lookup_count": 2, "policy": "softfail", "issues": ["Too many lookups"]}],
            dkim_results=[{"selector": "default", "key_size": 2048, "algorithm": "rsa-sha256", "issues": None}],
            dmarc_results=[{"record": "v=DMARC1; p=reject; pct=100", "policy": "reject", "pct": 100, "maturity_level": "ready"}],
            dnssec_results=[{"enabled": True, "algorithm": "RSASHA256", "key_sizes": [2048], "issues": []}],
            findings=[{"category": "SPF", "check_name": "lookup_count", "severity": "medium", "description": "SPF record has excessive DNS lookups", "Recommendation": "Flatten SPF record"}],
            records=[{"type": "A", "name": "example.com", "value": "93.184.216.34", "ttl": 300}],
            takeovers=[{"subdomain": "mail.example.com", "cname": "ghs.google.com", "service": "Google Workspace", "vulnerable": False, "evidence": None}],
            db_path=test_db,
        )

        print(f"Saved scan id: {sid}")
        print("Recent scans:", get_recent_scans(db_path=test_db))
        print("Findings:", get_scan_findings(sid, db_path=test_db))
        print("Stats:", get_stats(db_path=test_db))
        print("Full scan:", get_full_scan(sid, db_path=test_db))
    finally:
        os.unlink(test_db)
