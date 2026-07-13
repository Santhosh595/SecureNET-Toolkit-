"""TechFinger — Flask dashboard (port 5017)."""

from __future__ import annotations

import os
import threading

from flask import Flask, render_template, request, jsonify

import database as db
from fingerprinter import fetch, fingerprint
from bulk import scan_urls, export_csv

app = Flask(__name__)
db.init_db()

CAT_ORDER = ["server", "framework", "cms", "cdn", "analytics", "jslibs", "favicon"]


def _scan(url: str, full: bool = False, ua: str = "") -> dict:
    resp = fetch(url, full=full, user_agent=ua)
    if resp.error:
        return {"error": resp.error, "url": url}
    fp = fingerprint(resp)
    techs = fp["technologies"]
    cves = fp["cve_correlations"]
    try:
        sid = db.save_scan(url, len(techs), len(cves), 0.0, resp.status,
                           resp.waf_detected)
        db.save_technologies(sid, techs)
        db.save_header_checks(sid, fp["header_checks"])
        db.save_cves(sid, cves)
    except Exception:
        sid = -1
    return {
        "scan_id": sid, "url": url, "status": resp.status,
        "waf": resp.waf_detected,
        "technologies": [
            {"name": t.name, "category": t.category, "version": t.version,
             "confidence": t.confidence, "label": t.confidence_label,
             "risk": t.risk,
             "indicators": [{"source": i.source, "pattern": i.pattern}
                             for i in t.indicators]}
            for t in techs],
        "headers": [{"name": h.name, "present": h.present,
                      "value": h.value, "status": h.status,
                      "severity": h.severitiy}
                     for h in fp["header_checks"]],
        "cves": [{"tech": c.tech, "version": c.version, "cve": c.cve,
                    "severity": c.severitiy, "cvss": c.cvss,
                    "description": c.description} for c in cves],
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({"tool": "TechFinger", "version": "1.0.0",
                    "status": "online"})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "")
    full = bool(data.get("full"))
    ua = data.get("user_agent", "")
    if not url:
        return jsonify({"error": "url required"}), 400
    return jsonify(_scan(url, full=full, ua=ua))


@app.route("/api/bulk", methods=["POST"])
def api_bulk():
    data = request.get_json(force=True, silent=True) or {}
    urls = data.get("urls", [])
    delay = float(data.get("delay", 1.0))
    full = bool(data.get("full"))
    res = scan_urls(urls, delay=delay, full=full)
    return jsonify({"results": res})


@app.route("/api/history")
def api_history():
    rows = db.get_history(50)
    return jsonify(rows)


@app.route("/api/scan/<int:scan_id>")
def api_scan_detail(scan_id: int):
    return jsonify(db.get_scan(scan_id) or {"error": "not found"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5017, debug=False)
