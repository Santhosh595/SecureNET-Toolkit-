"""CloudSentry — Flask dashboard (port 5015)."""

from __future__ import annotations

import threading
import time

from flask import Flask, render_template, request, jsonify

import database as db
from catalog import CHECKS
from compliance.cis_mapping import score as cis_score
from compliance.owasp_mapping import score as owasp_score
from info_mode import build_info_results
from reporter import to_json, to_csv, to_pdf

app = Flask(__name__)

ACTIVE = {
    "running": False,
    "providers": [],
    "results": [],
    "done": 0,
    "total": 0,
    "available": {"aws": False, "gcp": False, "azure": False},
}

PROVIDERS = ["aws", "gcp", "azure"]


def _detect():
    from providers.aws.connector import AWSConnector
    from providers.gcp.connector import GCPConnector
    from providers.azure.connector import AzureConnector
    return {
        "aws": AWSConnector().available,
        "gcp": GCPConnector().available,
        "azure": AzureConnector().available,
    }


@app.route("/")
def index():
    return render_template("index.html", providers=PROVIDERS)


@app.route("/status")
def status():
    return jsonify({
        "tool": "CloudSentry",
        "status": "running" if not ACTIVE["running"] else "busy",
        "port": 5015,
        "providers_available": [p for p in PROVIDERS if ACTIVE["available"][p]],
        "active_audit": ACTIVE["running"],
    })


@app.route("/api/credentials")
def credentials():
    ACTIVE["available"] = _detect()
    return jsonify(ACTIVE["available"])


@app.route("/api/checks")
def api_checks():
    return jsonify([
        {"id": c["id"], "name": c["name"], "provider": c["provider"],
         "category": c["category"], "severity": c["severity"],
         "cis": c["cis"], "owasp": c["owasp"]}
        for c in CHECKS
    ])


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if ACTIVE["running"]:
        return jsonify({"error": "audit already running"}), 409
    body = request.get_json(silent=True) or {}
    providers = body.get("providers") or PROVIDERS
    if isinstance(providers, str):
        providers = [providers]
    profile = body.get("profile")
    region = body.get("region")
    project = body.get("project")
    subscription = body.get("subscription")
    ACTIVE["running"] = True
    ACTIVE["providers"] = providers
    ACTIVE["results"] = []
    ACTIVE["done"] = 0
    ACTIVE["total"] = sum(1 for c in CHECKS if c["provider"] in providers)
    t = threading.Thread(target=_worker, args=(providers, profile, region, project, subscription),
                         daemon=True)
    t.start()
    return jsonify({"status": "started", "providers": providers, "total": ACTIVE["total"]})


def _worker(providers, profile, region, project, subscription):
    try:
        det = _detect()
        if any(det[p] for p in providers):
            from providers import run_audit
            kwargs = {}
            if "aws" in providers:
                kwargs.update({"profile": profile, "region": region})
            if "gcp" in providers:
                kwargs.update({"project": project})
            if "azure" in providers:
                kwargs.update({"subscription": subscription})
            res = run_audit(providers, on_result=_on_result, **kwargs)
        else:
            res = build_info_results(providers)
            for r in res:
                _on_result(r)
        ACTIVE["results"] = res
        dur = time.time()
        try:
            db.init_db()
            db.save_audit(providers, res, 0.0)
        except Exception:
            pass
    finally:
        ACTIVE["running"] = False


def _on_result(r):
    ACTIVE["results"].append(r)
    ACTIVE["done"] += 1


@app.route("/api/results")
def api_results():
    clean = [{k: v for k, v in r.__dict__.items() if k != "_"} for r in ACTIVE["results"]]
    return jsonify({"running": ACTIVE["running"], "done": ACTIVE["done"],
                    "total": ACTIVE["total"], "results": clean})


@app.route("/api/compliance")
def api_compliance():
    res = ACTIVE["results"] or [r for r in build_info_results()]
    cis = cis_score(res)
    owasp = owasp_score(res)
    return jsonify({"cis": cis, "owasp": owasp})


@app.route("/api/findings")
def api_findings():
    audit_id = request.args.get("audit_id", type=int)
    f = db.get_findings(audit_id)
    return jsonify(f)


@app.route("/api/audits")
def api_audits():
    return jsonify(db.get_audits(30))


@app.route("/api/export")
def api_export():
    fmt = request.args.get("format", "json")
    res = ACTIVE["results"] or [r for r in build_info_results()]
    if fmt == "csv":
        return to_csv(res), 200, {"Content-Type": "text/csv"}
    if fmt == "pdf":
        data = to_pdf(res, path=None)
        return data, 200, {"Content-Type": "application/pdf",
                            "Content-Disposition": "attachment; filename=cloudsentry.pdf"}
    return to_json(res), 200, {"Content-Type": "application/json"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5015, debug=False)
