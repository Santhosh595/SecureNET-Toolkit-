"""Flask dashboard for the Network Sniffer.

Serves a real-time web interface showing captured packets and alerts.
"""

from __future__ import annotations

import time
from typing import Any

from flask import Flask, render_template, jsonify

import db

app = Flask(__name__)


def _row_to_dict(row: Any) -> dict[str, Any]:
    """Convert a sqlite3.Row to a plain dict."""
    return dict(row)


@app.route("/")
def index() -> str:
    """Serve the dashboard page."""
    return render_template("index.html")


@app.route("/packets")
def packets() -> dict:
    """Return the latest captured packets as JSON."""
    rows = db.get_latest_packets(limit=50)
    result = []
    for row in rows:
        result.append({
            "id": row["id"],
            "timestamp": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(row["ts"])
            ),
            "src": row["src"] or "",
            "dst": row["dst"] or "",
            "proto": row["proto"] or "",
            "sport": row["sport"],
            "dport": row["dport"],
            "length": row["length"],
            "flags": row["flags"] or "",
            "alert": row["alert"] or "",
        })
    return jsonify(result)


@app.route("/alerts")
def alerts() -> dict:
    """Return the latest alerts as JSON."""
    rows = db.get_alerts(limit=50)
    result = []
    for row in rows:
        result.append({
            "id": row["id"],
            "timestamp": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(row["ts"])
            ),
            "rule": row["rule"],
            "src": row["src"] or "",
            "meta": row["meta"] or "",
        })
    return jsonify(result)


@app.route("/stats")
def stats() -> dict:
    """Return summary statistics."""
    return jsonify({
        "total_packets": db.count_packets(),
        "total_alerts": db.count_alerts(),
    })


def main() -> None:
    """Initialize database and start the Flask development server."""
    db.init_db()
    print("[*] Starting Sniffer Dashboard on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
