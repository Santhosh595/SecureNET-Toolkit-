"""PortMap — Flask web dashboard.

Run: python dashboard.py
Open: http://127.0.0.1:5200
"""

from __future__ import annotations

import json
import threading
import time
from flask import Flask, render_template, request, jsonify, Response

from scanner import PORT_PROFILES, scan_target, resolve_host, RiskLevel

app = Flask(__name__)
_scan_progress: dict[str, dict] = {}
_scan_results: dict[str, dict] = {}


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan() -> tuple:
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    profile = data.get("profile", "quick")
    custom_range = data.get("custom", "")
    timeout = float(data.get("timeout", 1.0))

    if not target:
        return jsonify({"error": "No target provided"}), 400

    try:
        resolved = resolve_host(target)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if profile == "custom" and custom_range:
        try:
            p = custom_range.split("-")
            s, e = int(p[0]), int(p[1])
            ports = list(range(s, e + 1))
        except (ValueError, IndexError):
            return jsonify({"error": "Invalid range. Use format: 8000-9000"}), 400
    else:
        ports = PORT_PROFILES.get(profile, PORT_PROFILES["quick"])

    scan_id = f"{target}_{time.time()}"
    _scan_progress[scan_id] = {"scanned": 0, "total": len(ports), "done": False}

    def run_scan():
        def on_progress(scanned, total):
            _scan_progress[scan_id]["scanned"] = scanned
        report = scan_target(target, ports, timeout, progress_callback=on_progress)
        _scan_results[scan_id] = {
            "target": report.target, "resolved_ip": report.resolved_ip,
            "ports_scanned": report.ports_scanned, "ports_open": report.ports_open,
            "high_risk_count": report.high_risk_count, "scan_time": report.scan_time,
            "results": [{"port": r.port, "state": r.state, "service": r.service,
                         "risk": r.risk, "risk_note": r.risk_note}
                        for r in report.results if r.state == "OPEN"],
        }
        _scan_progress[scan_id]["done"] = True

    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"scan_id": scan_id})


@app.route("/status/<scan_id>")
def status(scan_id: str) -> dict:
    if scan_id not in _scan_progress:
        return jsonify({"error": "Scan not found"}), 404
    p = _scan_progress[scan_id]
    resp = {"scanned": p["scanned"], "total": p["total"], "done": p["done"],
            "percent": round(p["scanned"] / p["total"] * 100, 1) if p["total"] else 0}
    if p["done"] and scan_id in _scan_results:
        resp["results"] = _scan_results[scan_id]
    return jsonify(resp)


@app.route("/export/<scan_id>")
def export(scan_id: str) -> tuple:
    if scan_id not in _scan_results:
        return jsonify({"error": "Results not ready"}), 404
    data = _scan_results[scan_id]
    return Response(json.dumps(data, indent=2, ensure_ascii=False),
                    mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=portmap_{data['target'].replace(':','_').replace('/','_')}.json"})


def main() -> None:
    print("[*] Starting PortMap Dashboard on http://127.0.0.1:5200")
    app.run(host="127.0.0.1", port=5200, debug=False)


if __name__ == "__main__":
    main()
