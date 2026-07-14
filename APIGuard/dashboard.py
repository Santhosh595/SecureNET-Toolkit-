"""APIGuard — Flask dashboard (port 5018)."""

from __future__ import annotations

import os
import sys
import json
import threading
import time
from typing import Any, Dict, List, Optional

from flask import Flask, render_template, request, jsonify, send_file

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import database as db
import reporter as rpt
from auth import AuthConfig
from discovery import SpecParser
from main import run_scan

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
_scan_lock = threading.Lock()
_scan_in_progress = False
_scan_progress: Dict[str, Any] = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    return jsonify({"status": "online", "tool": "APIGuard", "port": 5018})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    global _scan_in_progress, _scan_progress
    data = request.get_json(silent=True) or {}
    target = data.get("url", "")
    if not target:
        return jsonify({"error": "No URL provided"}), 400
    if _scan_in_progress:
        return jsonify({"error": "Scan already in progress"}), 409

    auth_str = data.get("auth", "none")
    spec_path = data.get("spec", "")
    categories = data.get("categories", "")
    unsafe = data.get("unsafe", False)
    user_agent = data.get("user_agent", "APIGuard/1.0")

    auth_config = AuthConfig.parse(auth_str)
    cats = [c.strip() for c in categories.split(",")] if categories else []

    def _run():
        global _scan_in_progress, _scan_progress
        db.init_db()
        result = run_scan(
            target=target,
            auth_config=auth_config,
            spec_path=spec_path,
            categories=cats,
            unsafe=unsafe,
            user_agent=user_agent,
            no_disclaimer=True,
        )
        with _scan_lock:
            _scan_in_progress = False
            _scan_progress = result

    with _scan_lock:
        _scan_in_progress = True
        _scan_progress = {"status": "running", "target": target}

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"status": "started", "target": target})


@app.route("/api/scan/progress")
def api_scan_progress():
    with _scan_lock:
        if _scan_in_progress:
            return jsonify({"status": "running"})
        return jsonify(_scan_progress)


@app.route("/api/history")
def api_history():
    scans = db.get_scans(limit=20)
    return jsonify(scans)


@app.route("/api/findings")
def api_findings():
    scan_id = request.args.get("scan_id", type=int)
    owasp = request.args.get("owasp", "")
    severity = request.args.get("severity", "")
    findings = db.get_findings(scan_id=scan_id, owasp_category=owasp, severity=severity)
    return jsonify(findings)


@app.route("/api/endpoints")
def api_endpoints():
    scan_id = request.args.get("scan_id", type=int)
    if not scan_id:
        return jsonify([])
    return jsonify(db.get_endpoints(scan_id))


@app.route("/api/export/<fmt>")
def api_export(fmt: str):
    scan_id = request.args.get("scan_id", type=int)
    findings = db.get_findings(scan_id=scan_id)
    if fmt == "json":
        path = os.path.join(_HERE, "apiguard_export.json")
        rpt.export_json(findings, path)
        return send_file(path, as_attachment=True, download_name="apiguard_report.json")
    elif fmt == "csv":
        path = os.path.join(_HERE, "apiguard_export.csv")
        rpt.export_csv(findings, path)
        return send_file(path, as_attachment=True, download_name="apiguard_report.csv")
    elif fmt == "sarif":
        path = os.path.join(_HERE, "apiguard_export.sarif")
        rpt.export_sarif(findings, path)
        return send_file(path, as_attachment=True, download_name="apiguard_report.sarif")
    return jsonify({"error": "unsupported format"}), 400


if __name__ == "__main__":
    db.init_db()
    app.run(host="0.0.0.0", port=5018, debug=True)
