"""VulnProbe — Flask dashboard (5 tabs + API endpoints).

Tabs:   Scan | Findings | Template Library | Scan History | Report
API:    /status  /stats  /recent  /api/scan  /api/templates
        /api/findings  /api/report  /api/quickscan/vulnprobe
"""

from __future__ import annotations

import json
import os
import threading
import time

from flask import (
    Flask, request, jsonify, Response, render_template_string, send_file,
)

from engine import load_templates, Scanner
from engine.loader import builtin_template_count, TemplateError
from database import (
    init_db, create_scan, update_scan, add_finding, sync_templates,
    get_scans, get_findings, get_template_catalog, get_counts,
    get_recent_events, get_scan,
)
from reporter import to_json, to_csv, to_pdf

app = Flask(__name__)

# Active scan state (single-threaded access for the /status endpoint)
_active_scan = {"running": False, "target": None, "started": 0.0, "progress": (0, 0)}

INDEX_HTML = None  # loaded lazily from templates_web/index.html


def _load_index():
    global INDEX_HTML
    if INDEX_HTML is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates_web", "index.html")
        with open(p, "r", encoding="utf-8") as fh:
            INDEX_HTML = fh.read()
    return INDEX_HTML


# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(_load_index())


# ---------------------------------------------------------------------------
# API: status / stats / recent
# ---------------------------------------------------------------------------

@app.route("/status")
def status():
    return jsonify({
        "tool": "VulnProbe",
        "status": "running" if app.config.get("started") else "idle",
        "port": 5013,
        "active_scan": _active_scan["running"],
        "templates_loaded": builtin_template_count(),
    })


@app.route("/stats")
def stats():
    return jsonify(get_counts())


@app.route("/recent")
def recent():
    return jsonify({"recent": get_recent_events(20)})


# ---------------------------------------------------------------------------
# API: templates
# ---------------------------------------------------------------------------

@app.route("/api/templates")
def api_templates():
    sev = _split(request.args.get("severity"))
    cat = _split(request.args.get("category"))
    tags = _split(request.args.get("tags"))
    templates, errors = load_templates(
        severity_filter=sev or None,
        category_filter=cat or None,
        tag_filter=tags or None,
    )
    return jsonify({
        "templates": [
            {
                "id": t["id"], "name": t["name"], "severity": t["severity"],
                "category": t.get("category"), "tags": t.get("tags", []),
                "author": t.get("author", "SecureNET"), "built_in": t.get("_built_in", True),
            }
            for t in templates
        ],
        "errors": [{"file": f, "message": m} for f, m in errors],
        "total": len(templates),
    })


@app.route("/api/templates/<template_id>/yaml")
def api_template_yaml(template_id):
    templates, _ = load_templates()
    for t in templates:
        if t["id"] == template_id:
            import yaml
            return Response(yaml.safe_dump(t, sort_keys=False), mimetype="text/yaml")
    return jsonify({"error": "not found"}), 404


@app.route("/api/templates/validate", methods=["POST"])
def api_template_validate():
    """Validate a pasted YAML template. Returns errors or ok."""
    body = request.get_json(force=True, silent=True) or {}
    raw = body.get("yaml", "")
    import yaml
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        return jsonify({"valid": False, "errors": [str(e)]})
    try:
        from engine.loader import validate_template
        validate_template(data, filename="<paste>")
        return jsonify({"valid": True, "id": data.get("id"), "name": data.get("name")})
    except TemplateError as e:
        return jsonify({"valid": False, "errors": [str(e)]})


@app.route("/api/templates/upload", methods=["POST"])
def api_template_upload():
    """Accept an uploaded .yaml template file, validate, save to custom dir."""
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "custom")
    os.makedirs(upload_dir, exist_ok=True)
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "no file"}), 400
    raw = f.read().decode("utf-8", "replace")
    import yaml
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        return jsonify({"valid": False, "error": str(e)}), 400
    try:
        from engine.loader import validate_template
        validate_template(data, filename=f.filename)
    except TemplateError as e:
        return jsonify({"valid": False, "error": str(e)}), 400
    dest = os.path.join(upload_dir, os.path.basename(f.filename))
    with open(dest, "w", encoding="utf-8") as out:
        out.write(raw)
    return jsonify({"valid": True, "saved": dest})


# ---------------------------------------------------------------------------
# API: scan
# ---------------------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def api_scan():
    body = request.get_json(force=True, silent=True) or {}
    target = body.get("target", "").strip()
    if not target:
        return jsonify({"error": "no target"}), 400

    sev = _split(body.get("severity"))
    cat = _split(body.get("category"))
    tags = _split(body.get("tags"))
    workers = int(body.get("workers", 25))
    rate = int(body.get("rate_limit", 150))
    timeout = int(body.get("timeout", 10))

    templates, errors = load_templates(
        severity_filter=sev or None,
        category_filter=cat or None,
        tag_filter=tags or None,
    )
    if not templates:
        return jsonify({"error": "no templates matched filters", "errors": errors}), 400

    targets = Scanner and __import__("engine.scanner", fromlist=["resolve_targets"]).resolve_targets(target)
    sync_templates(templates)
    init_db()
    scan_id = create_scan(
        target, template_filter=json.dumps(body), templates_run=len(templates)
    )

    def _run():
        _active_scan["running"] = True
        _active_scan["target"] = target
        _active_scan["started"] = time.time()
        scanner = Scanner(
            templates, workers=workers, rate_limit=rate, timeout=timeout,
            on_finding=lambda f: None,
            on_progress=lambda d, t: _active_scan.update(progress=(d, t)),
        )
        findings = scanner.run(targets)
        for f in findings:
            add_finding(scan_id, f)
        update_scan(scan_id, len(findings), time.time() - _active_scan["started"])
        _active_scan["running"] = False

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"scan_id": scan_id, "status": "started", "template_count": len(templates)})


# ---------------------------------------------------------------------------
# API: findings / history / report
# ---------------------------------------------------------------------------

@app.route("/api/findings")
def api_findings():
    scan_id = request.args.get("scan_id", type=int)
    sev = request.args.get("severity")
    cat = request.args.get("category")
    tid = request.args.get("template_id")
    findings = get_findings(scan_id=scan_id, severity=sev, category=cat, template_id=tid)
    return jsonify({"findings": findings, "total": len(findings)})


@app.route("/api/scans")
def api_scans():
    scans = get_scans(50)
    return jsonify({"scans": scans})


@app.route("/api/report")
def api_report():
    fmt = request.args.get("format", "json").lower()
    scan_id = request.args.get("scan_id", type=int)
    findings = get_findings(scan_id=scan_id)
    meta = get_scan(scan_id) if scan_id else None
    meta = dict(meta) if meta else {}
    if fmt == "csv":
        return Response(to_csv(findings), mimetype="text/csv",
                         headers={"Content-Disposition": "attachment; filename=vulnprobe.csv"})
    if fmt == "pdf":
        try:
            path = to_pdf(findings, meta)
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 500
        return send_file(path, mimetype="application/pdf",
                         as_attachment=True, download_name="vulnprobe_report.pdf")
    return Response(to_json(findings, meta), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=vulnprobe.json"})


# ---------------------------------------------------------------------------
# quick_scan integration (Control Panel)
# ---------------------------------------------------------------------------

@app.route("/api/quickscan/vulnprobe", methods=["POST"])
def api_quickscan():
    body = request.get_json(force=True, silent=True) or {}
    url = body.get("url", "").strip()
    sev = body.get("severity")  # e.g. "HIGH,CRITICAL"
    if not url:
        return jsonify({"error": "no url"}), 400
    templates, _ = load_templates(
        severity_filter={s.strip().lower() for s in sev.split(",")} if sev else None
    )
    targets = __import__("engine.scanner", fromlist=["resolve_targets"]).resolve_targets(url)
    init_db()
    scanner = Scanner(templates, workers=25, rate_limit=150)
    findings = scanner.run(targets)
    return jsonify({"job_id": f"vulnprobe-{int(time.time())}", "status": "started",
                    "findings": len(findings)})


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _split(val):
    if not val:
        return []
    return [v.strip().lower() for v in val.split(",") if v.strip()]


def run_dashboard(host="127.0.0.1", port=5013, debug=False):
    init_db()
    app.config["started"] = True
    print(f"[*] VulnProbe Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    run_dashboard()
