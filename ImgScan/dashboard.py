"""ImgScan — Flask dashboard (port 5016)."""

from __future__ import annotations

import os
import threading

from flask import Flask, render_template, request, jsonify

import database as db
from scanners import (scan_directory, scan_component_list, check_package,
                      audit_dockerfile, PIP_AUDIT_HINT)
from parsers.sbom_parser import parse_sbom, Component
from parsers.sbom_generator import generate_sbom

app = Flask(__name__)

db.init_db()

# in-memory latest scan handles for dashboard display
STATE = {"last_findings": [], "last_docker": [], "last_target": ""}


def _run_scan(payload: dict):
    mode = payload.get("mode", "directory")
    target = payload.get("target", "")
    findings = []
    docker = []
    comps = []
    if mode == "directory" and target:
        findings = scan_directory(target)
        # collect SBOM components
        for f in findings:
            comps.append(Component(name=f.package, version=f.version,
                                    ecosystem=f.ecosystem))
    elif mode == "sbom" and target:
        comps_parsed = parse_sbom(target)
        findings = scan_component_list(comps_parsed)
        comps = comps_parsed
    elif mode == "dockerfile" and target:
        docker = audit_dockerfile(target)
    elif mode == "package" and target:
        name, _, ver = target.partition("==")
        findings = check_package(name.strip(), ver.strip())
    elif mode == "pip" and target:
        from scanners import scan_requirements
        findings = scan_requirements(target)
        if not findings:
            findings = []  # offline fallback already inside
    duration = 0.1
    sid = db.save_scan(target, mode, len({f.package for f in findings}),
                       len(findings), duration)
    if findings:
        db.save_vulnerabilities(sid, findings)
    if docker:
        db.save_dockerfile_findings(sid, docker)
    STATE["last_findings"] = findings
    STATE["last_docker"] = docker
    STATE["last_target"] = target
    return {"scan_id": sid, "findings": len(findings),
            "docker": len(docker), "comps": len(comps)}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({
        "tool": "ImgScan",
        "version": "1.0.0",
        "status": "online",
        "modes": ["directory", "sbom", "dockerfile", "pip", "package"],
        "ecosystems": ["python", "npm", "java", "ruby"],
        "note": PIP_AUDIT_HINT,
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    try:
        res = _run_scan(data)
    except Exception as e:  # surface errors to UI, never crash
        return jsonify({"error": str(e)}), 500
    return jsonify(res)


@app.route("/api/results")
def api_results():
    out = []
    for f in STATE["last_findings"]:
        out.append({"package": f.package, "version": f.version,
                    "ecosystem": f.ecosystem, "cve_id": f.cve_id,
                    "severity": f.severity, "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector, "description": f.description,
                    "fixed_version": f.fixed_version, "in_kev": f.in_kev,
                    "upgrade_command": f.upgrade_command, "source": f.source})
    return jsonify({"target": STATE["last_target"], "findings": out})


@app.route("/api/dockerfile")
def api_docker():
    return jsonify([{"check_id": d.check_id, "line": d.line_number,
                     "severity": d.severity, "description": d.description,
                     "remediation": d.remediation}
                    for d in STATE["last_docker"]])


@app.route("/api/sbom")
def api_sbom():
    comps = []
    for f in STATE["last_findings"]:
        comps.append({"name": f.package, "version": f.version,
                      "ecosystem": f.ecosystem,
                      "purl": f"pkg:{f.ecosystem}/{f.package}@{f.version}"})
    return jsonify(comps)


@app.route("/api/history")
def api_history():
    scans = db.get_scans()
    return jsonify([{"id": s["id"], "target": s["target_path"],
                     "type": s["scan_type"], "packages": s["packages_scanned"],
                     "vulns": s["vuln_count"], "time": s["timestamp"]}
                    for s in scans])


@app.route("/api/export")
def api_export():
    fmt = request.args.get("format", "json")
    findings = STATE["last_findings"]
    docker = STATE["last_docker"]
    if fmt == "csv":
        from output import reporter
        return reporter.to_csv(findings), 200, {"Content-Type": "text/csv"}
    if fmt == "sarif":
        from output import sarif
        import json
        return json.dumps(sarif.to_sarif(findings, STATE["last_target"])), 200, \
            {"Content-Type": "application/json"}
    from output import reporter
    import json
    return reporter.to_json(findings, docker), 200, \
        {"Content-Type": "application/json"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5016, debug=False)
