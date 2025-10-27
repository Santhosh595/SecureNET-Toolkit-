# db.py
import sqlite3
import time
import os

DB = "packets.db"

def init_db():
    os.makedirs("db", exist_ok=True)  # optional folder if you want separation
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS packets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts REAL,
      src TEXT,
      dst TEXT,
      proto TEXT,
      sport INTEGER,
      dport INTEGER,
      length INTEGER,
      flags TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts REAL,
      rule TEXT,
      src TEXT,
      meta TEXT
    )""")
    conn.commit()
    conn.close()

def insert_packet(ts, src, dst, proto, sport, dport, length, flags):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO packets (ts,src,dst,proto,sport,dport,length,flags) VALUES (?,?,?,?,?,?,?,?)",
        (ts, src, dst, proto, sport, dport, length, flags)
    )
    conn.commit()
    conn.close()

def insert_alert(rule, src, meta=""):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("INSERT INTO alerts (ts,rule,src,meta) VALUES (?,?,?,?)",
                (time.time(), rule, src, meta))
    conn.commit()
    conn.close()

def get_recent_packets(seconds=10):
    cutoff = time.time() - seconds
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT ts,src,dst,proto,sport,dport,length,flags FROM packets WHERE ts>=?", (cutoff,))
    rows = cur.fetchall()
    conn.close()
    return rows

def count_packets():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM packets")
    c = cur.fetchone()[0]
    conn.close()
    return c

def get_alerts(limit=50):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT ts,rule,src,meta FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows
