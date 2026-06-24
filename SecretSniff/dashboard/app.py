"""SecretSniff - Flask web dashboard.

Single-page dashboard for scan control, findings review, and export.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from flask import Flask, render_template, request, jsonify, Response

from patterns.rules import get_patterns, get_pattern_names
from scanner.file_scanner import scan_file, iter_files
from scanner.git_scanner import scan_git_history, scan_git_worktree, is_git_repo
from scanner.env_scanner import scan_env_files
from allowlist import Allowlist
from database import (init_db, save_scan, get_recent_scans, get_findings,
                      get_stats, get_top_rules, get_top_files, get_authors_stats,
                      save_allowlist, get_allowlist_entries, delete_allowlist_entry)
from output.sarif import generate_sarif
from output.junit import generate_junit

app = Flask(__name__)
init_db()


@app.route("/")
def index() -> str:
    stats = get_stats()
    return render_template("index.html", stats=stats)


@app.route("/scan", methods=["POST"])
def scan() -> tuple:
    """Run a scan."""
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    scan_type = data.get("type", "file")
    include_tests = data.get("include_tests", False)
    use_history = data.get("history", False)
    depth = data.get("depth", 0)

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
    elif scan_type == "git" or scan_type == "git-history":
        from scanner.git_scanner import is_git_repo
        target_path = Path(target).resolve()
        if not is_git_repo(target_path):
            return jsonify({"error": "Not a git repository"}), 400
        if use_history:
            findings = scan_git_history(target_path, depth=depth)
        else:
            findings = scan_git_worktree(target_path, include_tests=include_tests)
        files_scanned = len(set(f["file"] for f in findings)) if findings else 0
    else:
        target_path = Path(target).resolve()
        if not target_path.exists():
            return jsonify({"error": "Path not found"}), 404
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


@app.route("/stats")
def stats() -> dict:
    return jsonify({
        "overall": get_stats(),
        "top_rules": get_top_rules(),
        "top_files": get_top_files(),
        "authors": get_authors_stats(),
    })


@app.route("/allowlist", methods=["GET"])
def get_allowlist_route() -> dict:
    return jsonify({"entries": get_allowlist_entries()})


@app.route("/allowlist", methods=["POST"])
def add_allowlist_route() -> tuple:
    data = request.get_json(force=True)
    entry_type = data.get("type", "pattern")
    value = data.get("value", "")
    reason = data.get("reason", "")
    if not value:
        return jsonify({"error": "Value required"}), 400
    entry_id = save_allowlist(entry_type, value, reason)
    return jsonify({"id": entry_id, "type": entry_type, "value": value})


@app.route("/allowlist/<int:entry_id>", methods=["DELETE"])
def delete_allowlist_route(entry_id: int) -> dict:
    delete_allowlist_entry(entry_id)
    return jsonify({"deleted": entry_id})


@app.route("/export/<int:scan_id>/<format_name>")
def export(scan_id: int, format_name: str) -> tuple:
    findings = get_findings(scan_id)
    if format_name == "json":
        return Response(json.dumps(findings, indent=2),
                        mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=findings.json"})
    elif format_name == "sarif":
        sarif = generate_sarif(findings)
        return Response(json.dumps(sarif, indent=2),
                        mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=findings.sarif"})
    elif format_name == "junit" or format_name == "xml":
        junit = generate_junit(findings)
        return Response(junit,
                        mimetype="application/xml",
                        headers={"Content-Disposition": "attachment; filename=findings.xml"})
    elif format_name == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["File", "Line", "Rule", "Severity", "Confidence", "Value", "Commit"])
        for f in findings:
            writer.writerow([
                f.get("file", ""), f.get("line", ""), f.get("rule", ""),
                f.get("severity", ""), f.get("confidence", ""),
                f.get("value_redacted", ""), f.get("commit_hash", ""),
            ])
        return Response(output.getvalue(),
                        mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=findings.csv"})
    return jsonify({"error": "Format not supported"}), 400


@app.route("/patterns")
def patterns_route() -> dict:
    return jsonify({"patterns": get_pattern_names()})


def main() -> None:
    print("")
    print("=" * 50)
    print("  SecretSniff Dashboard")
    print("  http://127.0.0.1:5800")
    print("=" * 50)
    print("")
    app.run(host="127.0.0.1", port=5800, debug=False)


if __name__ == "__main__":
    main()
