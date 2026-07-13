"""TechFinger — SQLite storage (5 tables)."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from typing import List, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "techfinger.db")


def init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_url TEXT,
        timestamp TEXT,
        tech_count INTEGER,
        cve_count INTEGER,
        duration REAL,
        status INTEGER,
        waf_detected INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS technologies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        category TEXT,
        tech_name TEXT,
        version TEXT,
        confidence INTEGER,
        confidence_label TEXT,
        risk_level TEXT
    );
    CREATE TABLE IF NOT EXISTS header_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        header_name TEXT,
        present INTEGER,
        value TEXT,
        status TEXT
    );
    CREATE TABLE IF NOT EXISTS cve_correlations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        tech_name TEXT,
        version TEXT,
        cve_id TEXT,
        severity TEXT,
        cvss_score REAL,
        description TEXT
    );
    CREATE TABLE IF NOT EXISTS raw_indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        tech_id INTEGER,
        tech_name TEXT,
        source TEXT,
        matched_pattern TEXT
    );
    """)
    con.commit()
    con.close()


def save_scan(target_url: str, tech_count: int, cve_count: int,
              duration: float, status: Optional[int] = None,
              waf: bool = False) -> int:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO scans (target_url, timestamp, tech_count, cve_count, "
        "duration, status, waf_detected) VALUES (?,?,?,?,?,?,?)",
        (target_url, datetime.utcnow().isoformat(), tech_count, cve_count,
         round(duration, 2), status, int(waf)))
    sid = cur.lastrowid
    con.commit()
    con.close()
    return sid


def save_technologies(scan_id: int, techs: list,
                      raw_indicators: bool = True) -> List[int]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    ids = []
    for t in techs:
        cur.execute(
            "INSERT INTO technologies (scan_id, category, tech_name, version, "
            "confidence, confidence_label, risk_level) VALUES (?,?,?,?,?,?,?)",
            (scan_id, getattr(t, "category", ""), getattr(t, "name", ""),
             getattr(t, "version", None) or "", getattr(t, "confidence", 0),
             getattr(t, "confidence_label", ""), getattr(t, "risk", "INFO")))
        tid = cur.lastrowid
        ids.append(tid)
        if raw_indicators:
            for ind in getattr(t, "indicators", []):
                cur.execute(
                    "INSERT INTO raw_indicators (scan_id, tech_id, tech_name, "
                    "source, matched_pattern) VALUES (?,?,?,?,?)",
                    (scan_id, tid, getattr(t, "name", ""),
                     getattr(ind, "source", ""), getattr(ind, "pattern", "")))
    con.commit()
    con.close()
    return ids


def save_header_checks(scan_id: int, checks: list) -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    for c in checks:
        cur.execute(
            "INSERT INTO header_checks (scan_id, header_name, present, value, "
            "status) VALUES (?,?,?,?,?)",
            (scan_id, getattr(c, "name", ""), int(getattr(c, "present", False)),
             getattr(c, "value", ""), getattr(c, "status", "")))
    con.commit()
    con.close()


def save_cves(scan_id: int, cves: list) -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    for c in cves:
        cur.execute(
            "INSERT INTO cve_correlations (scan_id, tech_name, version, cve_id, "
            "severity, cvss_score, description) VALUES (?,?,?,?,?,?,?)",
            (scan_id, getattr(c, "tech", ""), getattr(c, "version", None) or "",
             getattr(c, "cve", ""), getattr(c, "severitiy", ""),
             getattr(c, "cvss", 0.0), getattr(c, "description", "")))
    con.commit()
    con.close()


def get_history(limit: int = 50) -> List[dict]:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows


def get_scan(scan_id: int) -> Optional[dict]:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    r = cur.fetchone()
    if not r:
        con.close()
        return None
    out = dict(r)
    for tbl, key in (("technologies", "techs"), ("header_checks", "headers"),
                     ("cve_correlations", "cves"),
                     ("raw_indicators", "indicators")):
        cur.execute(f"SELECT * FROM {tbl} WHERE scan_id=?", (scan_id,))
        out[key] = [dict(x) for x in cur.fetchall()]
    con.close()
    return out
