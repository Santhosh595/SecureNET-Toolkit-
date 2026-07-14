"""APIGuard — Flask dashboard (port 5018)."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List

from flask import Flask, render_template, request, jsonify

import database as db
from tests import cvss_for

# Add parent so tests/ can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
db.init_db()


# ── Import helpers from main modules ──────────────────────────
def _run_scan_impl(url: str, auth_spec: str = "none",
                   spec_path: str = "", unsafe: bool = False,
                   category: str = "all") -> dict:
    """Run a full APIGuard scan and return serialisable results."""
    # Import inline to keep dashboard startup fast
    from auth import AuthConfig
    from tests import ApiRequester, BASELINE

    auth = AuthConfig.parse(auth_spec)
    requester = ApiRequester(url, auth)
    findings: List[Dict] = []
    endpoints: List[Dict] = []
    tests_run = 0

    test_modules = [
        ("API1", "tests.api1_bola"),
        ("API2", "tests.api2_broken_auth"),
        ("API3", "tests.api3_object_props"),
        ("API4", "tests.api4_rate_limiting"),
        ("API5", "tests.api5_function_auth"),
        ("API6", "tests.api6_business_flows"),
        ("API7", "tests.api7_ssrf"),
        ("API8", "tests.api8_misconfiguration"),
        ("API9", "tests.api9_inventory"),
        ("API10", "tests.api10_unsafe_consumption"),
        ("INJECTION", "tests.injection"),
    ]

    if category != "all":
        test_modules = [(cat, mod) for cat, mod in test_modules
                        if cat.lower() == category.lower()]

    import importlib
    for cat, mod_name in test_modules:
        try:
            mod = importlib.import_module(mod_name)
            if hasattr(mod, "run_tests"):
                result = mod.run_tests(requester, BASELINE, unsafe=unsafe)
                findings.extend(result.get("findings", []))
                endpoints.extend(result.get("endpoints", []))
                tests_run += result.get("tests_run", 0)
        except Exception:
            pass

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(findings)}
    for f in findings:
        sev = f.get("severity", "").upper()
        for k in summary:
            if sev.startswith(k.upper()[:4]):
                summary[k] = summary.get(k, 0) + 1
                break
        else:
            summary["info"] = summary.get("info", 0) + 1

    return {
        "url": url,
        "auth_type": auth.auth_type,
        "summary": summary,
        "findings": findings,
        "endpoints": endpoints,
        "tests_run": tests_run,
    }


# ── Routes ────────────────────────────────────────────────────


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({"tool": "APIGuard", "version": "1.0.0", "status": "online"})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    auth = data.get("auth", "none")
    spec = data.get("spec", "")
    unsafe = bool(data.get("unsafe", False))
    category = data.get("category", "all")
    if not url:
        return jsonify({"error": "url required"}), 400

    result = _run_scan_impl(url, auth_spec=auth, spec_path=spec,
                            unsafe=unsafe, category=category)

    # Persist to database
    try:
        sid = db.save_scan(url, auth, spec)
        for ep in result.get("endpoints", []):
            db.save_endpoint(sid, ep.get("method", ""), ep.get("path", ""),
                             ep.get("params", ""), ep.get("status", 0), "discovered")
        for f in result.get("findings", []):
            db.save_finding(
                sid,
                owasp_category=f.get("owasp_category", ""),
                endpoint=f.get("endpoint", ""),
                method=f.get("method", ""),
                test_name=f.get("test_name", ""),
                severity=f.get("severity", ""),
                evidence=f.get("evidence", ""),
                request_sent=f.get("request_sent", ""),
                response_received=f.get("response_received", ""),
                remediation=f.get("remediation", ""),
                cvss_score=cvss_for(f.get("severity", "MEDIUM")),
                cwe_ref=f.get("cwe_ref", ""),
            )
        db.update_scan(sid, endpoints_found=len(result["endpoints"]),
                       tests_run=result["tests_run"],
                       findings_count=len(result["findings"]),
                       duration=0.0)
        result["scan_id"] = sid
    except Exception:
        result["scan_id"] = -1

    return jsonify(result)


@app.route("/api/history")
def api_history():
    rows = db.get_scans(limit=50)
    return jsonify(rows)


@app.route("/api/scan/<int:scan_id>")
def api_scan_detail(scan_id: int):
    scan = db.get_scan(scan_id) or {}
    findings = db.get_findings(scan_id=scan_id)
    endpoints = db.get_endpoints(scan_id)
    return jsonify({"scan": scan, "findings": findings, "endpoints": endpoints})


@app.route("/api/report/<int:scan_id>/<fmt>")
def api_report(scan_id: int, fmt: str):
    """Export scan findings in requested format."""
    import tempfile
    import reporter as rpt

    findings = db.get_findings(scan_id=scan_id)
    if not findings:
        return jsonify({"error": "no findings"}), 404

    tmp = tempfile.mkdtemp()
    if fmt == "json":
        path = rpt.export_json(findings, os.path.join(tmp, "report.json"))
        with open(path) as f:
            return jsonify(json.load(f))
    elif fmt == "csv":
        path = rpt.export_csv(findings, os.path.join(tmp, "report.csv"))
        with open(path) as f:
            return f.read(), 200, {"Content-Type": "text/csv",
                                    "Content-Disposition": "attachment; filename=apiguard_report.csv"}
    elif fmt == "sarif":
        path = rpt.export_sarif(findings, os.path.join(tmp, "report.sarif"))
        with open(path) as f:
            return json.load(f)
    return jsonify({"error": "unsupported format"}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5018, debug=False)
