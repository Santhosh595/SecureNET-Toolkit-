"""ARPWatch — Flask web dashboard.

Run: python dashboard.py
Open: http://127.0.0.1:5400
"""

from __future__ import annotations

import json
import time
from flask import Flask, render_template, request, jsonify, Response

from database import (
    init_db, get_recent_packets, get_recent_alerts,
    get_packets_since, get_alerts_since, get_baseline, get_stats,
)

app = Flask(__name__)
init_db()

START_TIME = time.time()


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/events")
def events() -> dict:
    """Get recent events for polling."""
    since = float(request.args.get("since", 0))
    packets = get_packets_since(since) if since > 0 else get_recent_packets(50)
    alerts = get_alerts_since(since) if since > 0 else get_recent_alerts(20)
    return jsonify({
        "packets": [dict(r) for r in packets],
        "alerts": [dict(r) for r in alerts],
        "stats": get_stats(),
        "baseline": get_baseline(),
        "uptime": round(time.time() - START_TIME, 1),
        "server_time": time.time(),
    })


@app.route("/export")
def export() -> Response:
    """Download all alerts as JSON."""
    alerts = get_recent_alerts(1000)
    data = {
        "exported_at": time.time(),
        "total_alerts": len(alerts),
        "alerts": [dict(r) for r in alerts],
    }
    return Response(
        json.dumps(data, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=arpwatch_alerts.json"},
    )


def main() -> None:
    print("[*] Starting ARPWatch Dashboard on http://127.0.0.1:5400")
    app.run(host="127.0.0.1", port=5400, debug=False)


if __name__ == "__main__":
    main()
