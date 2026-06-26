"""SQLite database manager for SecureNET Control Panel hub."""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "control_panel.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tool_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            port INTEGER,
            last_seen TEXT,
            uptime_start TEXT
        );

        CREATE TABLE IF NOT EXISTS health_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL,
            response_time_ms INTEGER
        );

        CREATE TABLE IF NOT EXISTS alerts_unified (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            target TEXT,
            description TEXT,
            timestamp TEXT NOT NULL,
            acknowledged INTEGER DEFAULT 0,
            acknowledged_at TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_log_unified (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name TEXT NOT NULL,
            target TEXT,
            scan_type TEXT,
            result_summary TEXT,
            severity TEXT,
            duration_ms INTEGER,
            timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        );
    """)
    conn.commit()
    conn.close()


def save_tool_status(tool_name, status, port=None, last_seen=None, uptime_start=None):
    now = last_seen or datetime.utcnow().isoformat()
    conn = get_conn()
    conn.execute(
        """INSERT INTO tool_status (tool_name, status, port, last_seen, uptime_start)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(tool_name) DO UPDATE SET
                status=excluded.status,
                port=excluded.port,
                last_seen=excluded.last_seen,
                uptime_start=excluded.uptime_start""",
        (tool_name, status, port, now, uptime_start),
    )
    conn.commit()
    conn.close()


def log_health_alert(tool_name, status, response_time_ms=None, timestamp=None):
    ts = timestamp or datetime.utcnow().isoformat()
    conn = get_conn()
    conn.execute(
        "INSERT INTO health_log (tool_name, timestamp, status, response_time_ms) VALUES (?, ?, ?, ?)",
        (tool_name, ts, status, response_time_ms),
    )
    conn.commit()
    conn.close()


def save_alert(tool_name, severity, title, target=None, description=None, timestamp=None):
    ts = timestamp or datetime.utcnow().isoformat()
    conn = get_conn()
    conn.execute(
        """INSERT INTO alerts_unified (tool_name, severity, title, target, description, timestamp)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (tool_name, severity, title, target, description, ts),
    )
    conn.commit()
    conn.close()


def save_scan_log(tool_name, target=None, scan_type=None, result_summary=None, severity=None, duration_ms=None, timestamp=None):
    ts = timestamp or datetime.utcnow().isoformat()
    conn = get_conn()
    conn.execute(
        """INSERT INTO scan_log_unified (tool_name, target, scan_type, result_summary, severity, duration_ms, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (tool_name, target, scan_type, result_summary, severity, duration_ms, ts),
    )
    conn.commit()
    conn.close()


def get_recent_alerts(limit=50):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts_unified ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_history(limit=50, offset=0):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM scan_log_unified ORDER BY id DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    conn = get_conn()
    tool_count = conn.execute("SELECT COUNT(*) FROM tool_status").fetchone()[0]
    active_count = conn.execute("SELECT COUNT(*) FROM tool_status WHERE status='active'").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts_unified").fetchone()[0]
    unacknowledged = conn.execute("SELECT COUNT(*) FROM alerts_unified WHERE acknowledged=0").fetchone()[0]
    total_scans = conn.execute("SELECT COUNT(*) FROM scan_log_unified").fetchone()[0]
    conn.close()
    return {
        "total_tools": tool_count,
        "active_tools": active_count,
        "total_alerts": total_alerts,
        "unacknowledged_alerts": unacknowledged,
        "total_scans": total_scans,
    }


def update_setting(key, value):
    now = datetime.utcnow().isoformat()
    conn = get_conn()
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, now),
    )
    conn.commit()
    conn.close()


def get_all_settings():
    conn = get_conn()
    rows = conn.execute("SELECT key, value, updated_at FROM settings").fetchall()
    conn.close()
    return {r["key"]: {"value": r["value"], "updated_at": r["updated_at"]} for r in rows}


if __name__ == "__main__":
    init_db()
    save_tool_status("scanner-alpha", "active", port=8080, uptime_start=datetime.utcnow().isoformat())
    save_alert("scanner-alpha", "high", "Open port detected", target="10.0.0.1", description="Port 22 open")
    save_scan_log("scanner-alpha", target="10.0.0.1", scan_type="nmap", result_summary="22/tcp open ssh", severity="high", duration_ms=3400)
    log_health_alert("scanner-alpha", "ok", response_time_ms=120)
    update_setting("scan_interval", "60")
    assert get_stats()["total_tools"] == 1
    assert get_recent_alerts(1)[0]["title"] == "Open port detected"
    print("OK")
