"""SecretSniff — Flask web dashboard."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response

from patterns.rules import get_patterns
from scanner.file_scanner import scan_file, iter_files
from scanner.env_scanner import scan_env_files
from allowlist import Allowlist
from database import init_db, save_scan, get_recent_scans, get_findings, get_stats

app = Flask(__name__)
init_db()


@app.route("/")
def index() -> str:
    return render_template("index.html", stats=get_stats())


@app.route("/scan", methods=["POST"])
def scan() -> tuple:
    """Run a scan."""
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    scan_type = data.get("type", "file")
    include_tests = data.get("include_tests", False)

    if not target:
        return jsonify({"error": "No target provided"}), 400

    start = time.time()
    patterns = get_patterns()
    findings = []
    files_scanned = 0

    if scan_type == "stdin":
        content = data.get("content", "")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)
        findings = scan_file(tmp_path, patterns)
        tmp_path.unlink()
        files_scanned = 1
    else:
        target_path = Path(target).resolve()
        for file_path in iter_files(target_path, respect_gitignore=True, include_tests=include_tests):
            files_scanned += 1
            file_findings = scan_file(file_path, patterns)
            for f in file_findings:
                try:
                    f["file"] = str(file_path.relative_to(target_path))
                except ValueError:
                    f["file"] = str(file_path)
            findings.extend(file_findings)
        env_findings = scan_env_files(target_path)
        findings.extend(env_findings)

    duration = time.time() - start
    scan_id = save_scan(target, scan_type, files_scanned, findings, duration)

    return jsonify({
        "scan_id": scan_id,
        "files_scanned": files_scanned,
        "findings": findings,
        "duration": round(duration, 2),
        "stats": {
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
        }
    })


@app.route("/history")
def history() -> dict:
    return jsonify({"scans": get_recent_scans()})


@app.route("/export/<int:scan_id>/<format_name>")
def export(scan_id: int, format_name: str) -> tuple:
    findings = get_findings(scan_id)
    if format_name == "json":
        return Response(json.dumps(findings, indent=2),
                        mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=findings.json"})
    return jsonify({"error": "Format not supported"}), 400


def main() -> None:
    print("[*] Starting SecretSniff Dashboard on http://127.0.0.1:5800")
    app.run(host="127.0.0.1", port=5800, debug=False)


if __name__ == "__main__":
    main()
