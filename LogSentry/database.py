"""
LogSentry Database Layer
SQLite storage for sessions, events, alerts, IP profiles, and threat intel.
"""

import sqlite3
import os
from datetime import datetime, timezone
from typing import Optional


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "logsentry.db")


def get_db_path(custom_path: str = None) -> str:
    if custom_path:
        return custom_path
    return DB_PATH


def init_db(db_path: str = None):
    """Initialize database with all required tables."""
    path = get_db_path(db_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TEXT NOT NULL,
            end_time TEXT,
            files_analyzed INTEGER DEFAULT 0,
            total_events INTEGER DEFAULT 0,
            total_alerts INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            log_type TEXT NOT NULL,
            src_ip TEXT DEFAULT '',
            dst_ip TEXT DEFAULT '',
            src_port INTEGER DEFAULT 0,
            dst_port INTEGER DEFAULT 0,
            username TEXT DEFAULT '',
            action TEXT DEFAULT '',
            status TEXT DEFAULT 'UNKNOWN',
            raw TEXT DEFAULT '',
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            mitre_id TEXT DEFAULT '',
            src_ip TEXT DEFAULT '',
            username TEXT DEFAULT '',
            timestamp TEXT NOT NULL,
            details TEXT DEFAULT '',
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS ip_profiles (
            ip TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            event_count INTEGER DEFAULT 0,
            rules_triggered TEXT DEFAULT '',
            sources_seen TEXT DEFAULT '',
            country TEXT DEFAULT '',
            is_threat_intel INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS threat_intel (
            ip TEXT PRIMARY KEY,
            source TEXT DEFAULT '',
            category TEXT DEFAULT '',
            last_updated TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
        CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
    """)

    conn.close()
    return path


def create_session(db_path: str = None) -> int:
    """Create a new analysis session, return session ID."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO sessions (start_time) VALUES (?)", (now,)
    )
    session_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return session_id


def close_session(session_id: int, db_path: str = None):
    """Close a session with final stats."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    now = datetime.now(timezone.utc).isoformat()

    stats = conn.execute(
        "SELECT COUNT(*) FROM events WHERE session_id = ?", (session_id,)
    ).fetchone()[0]
    alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE session_id = ?", (session_id,)
    ).fetchone()[0]

    conn.execute(
        "UPDATE sessions SET end_time = ?, total_events = ?, total_alerts = ? WHERE id = ?",
        (now, stats, alerts, session_id)
    )
    conn.commit()
    conn.close()


def insert_event(event: dict, session_id: int, db_path: str = None):
    """Insert a normalized event into the database."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.execute(
        """INSERT INTO events 
           (session_id, timestamp, log_type, src_ip, dst_ip, src_port, dst_port, username, action, status, raw)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            session_id,
            event["timestamp"].isoformat() if hasattr(event["timestamp"], "isoformat") else str(event["timestamp"]),
            event.get("log_type", ""),
            event.get("src_ip", ""),
            event.get("dst_ip", ""),
            event.get("src_port", 0),
            event.get("dst_port", 0),
            event.get("username", ""),
            event.get("action", ""),
            event.get("status", "UNKNOWN"),
            event.get("raw", ""),
        )
    )
    conn.commit()
    conn.close()


def insert_events_batch(events: list, session_id: int, db_path: str = None):
    """Bulk insert events for performance."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.executemany(
        """INSERT INTO events 
           (session_id, timestamp, log_type, src_ip, dst_ip, src_port, dst_port, username, action, status, raw)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                session_id,
                e["timestamp"].isoformat() if hasattr(e["timestamp"], "isoformat") else str(e["timestamp"]),
                e.get("log_type", ""),
                e.get("src_ip", ""),
                e.get("dst_ip", ""),
                e.get("src_port", 0),
                e.get("dst_port", 0),
                e.get("username", ""),
                e.get("action", ""),
                e.get("status", "UNKNOWN"),
                e.get("raw", ""),
            )
            for e in events
        ]
    )
    conn.commit()
    conn.close()


def insert_alert(alert: dict, session_id: int, db_path: str = None):
    """Insert an alert into the database."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.execute(
        """INSERT INTO alerts 
           (session_id, rule_name, severity, mitre_id, src_ip, username, timestamp, details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            session_id,
            alert.get("rule_name", ""),
            alert.get("severity", "MEDIUM"),
            alert.get("mitre_id", ""),
            alert.get("src_ip", ""),
            alert.get("username", ""),
            alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
            alert.get("details", ""),
        )
    )
    conn.commit()
    conn.close()


def insert_alerts_batch(alerts: list, session_id: int, db_path: str = None):
    """Bulk insert alerts."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.executemany(
        """INSERT INTO alerts 
           (session_id, rule_name, severity, mitre_id, src_ip, username, timestamp, details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                session_id,
                a.get("rule_name", ""),
                a.get("severity", "MEDIUM"),
                a.get("mitre_id", ""),
                a.get("src_ip", ""),
                a.get("username", ""),
                a.get("timestamp", datetime.now(timezone.utc).isoformat()),
                a.get("details", ""),
            )
            for a in alerts
        ]
    )
    conn.commit()
    conn.close()


def update_ip_profile(profile: dict, db_path: str = None):
    """Upsert an IP profile."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.execute(
        """INSERT INTO ip_profiles (ip, first_seen, last_seen, event_count, rules_triggered, sources_seen, country, is_threat_intel)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET
               last_seen = excluded.last_seen,
               event_count = excluded.event_count,
               rules_triggered = excluded.rules_triggered,
               sources_seen = excluded.sources_seen,
               country = excluded.country,
               is_threat_intel = excluded.is_threat_intel""",
        (
            profile.get("ip", ""),
            profile.get("first_seen", ""),
            profile.get("last_seen", ""),
            profile.get("event_count", 0),
            profile.get("rules_triggered", ""),
            profile.get("sources_seen", ""),
            profile.get("country", ""),
            profile.get("is_threat_intel", 0),
        )
    )
    conn.commit()
    conn.close()


def get_session_stats(session_id: int, db_path: str = None) -> dict:
    """Get statistics for a session."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row

    row = conn.execute(
        "SELECT * FROM sessions WHERE id = ?", (session_id,)
    ).fetchone()

    events_by_type = conn.execute(
        "SELECT log_type, COUNT(*) as count FROM events WHERE session_id = ? GROUP BY log_type ORDER BY count DESC",
        (session_id,)
    ).fetchall()

    alerts_by_severity = conn.execute(
        "SELECT severity, COUNT(*) as count FROM alerts WHERE session_id = ? GROUP BY severity",
        (session_id,)
    ).fetchall()

    top_attackers = conn.execute(
        """SELECT src_ip, COUNT(*) as count FROM alerts 
           WHERE session_id = ? AND src_ip != '' 
           GROUP BY src_ip ORDER BY count DESC LIMIT 10""",
        (session_id,)
    ).fetchall()

    conn.close()

    return {
        "session": dict(row) if row else {},
        "events_by_type": [dict(r) for r in events_by_type],
        "alerts_by_severity": [dict(r) for r in alerts_by_severity],
        "top_attackers": [dict(r) for r in top_attackers],
    }


def get_all_events(session_id: int, limit: int = 1000, db_path: str = None) -> list:
    """Get all events for a session."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
        (session_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_alerts(session_id: int, limit: int = 500, db_path: str = None) -> list:
    """Get all alerts for a session."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
        (session_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_ip_profile(ip: str, db_path: str = None) -> Optional[dict]:
    """Get profile for a specific IP."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM ip_profiles WHERE ip = ?", (ip,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_ip_profiles(db_path: str = None) -> list:
    """Get all IP profiles."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM ip_profiles ORDER BY event_count DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_alerts(session_id: int, limit: int = 10, db_path: str = None) -> list:
    """Get most recent alerts."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
        (session_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
