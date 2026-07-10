"""PathProbe — Flask web dashboard (port 5014)."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from flask import Flask, render_template, request, jsonify, Response

from engine import Scanner
from engine.wordlist import available_wordlists
from engine import recursive as recmod
from database import init_db, create_scan, add_finding, update_scan, register_wordlists, get_scans, get_findings, stats

app = Flask(__name__)

ACTIVE = {"scanner": None, "scan_id": None, "running": False, "target": None,
          "started": 0.0, "done": 0, "total": 0, "found": 0, "findings": []}

PORT = 5014


def _parse_list(s):
    return [x.strip() for x in s.split(",") if x.strip()] if s else None


def _parse_status(s):
    out = set()
    if s:
        for p in s.split(","):
            p = p.strip()
            if p.isdigit():
                out.add(int(p))
    return out or None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/status")
def status():
    return jsonify({
        "tool": "PathProbe",
        "status": "running" if ACTIVE["running"] else "idle",
        "port": PORT,
        "active_scan": ACTIVE["running"],
        "wordlists_available": len(available_wordlists()),
        "done": ACTIVE["done"], "total": ACTIVE["total"], "found": ACTIVE["found"],
    })


@app.route("/stats")
def stats_route():
    return jsonify(stats())


@app.route("/recent")
def recent():
    return jsonify({"scans": get_scans(10)})


@app.route("/api/wordlists")
def api_wordlists():
    return jsonify({"wordlists": available_wordlists()})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if ACTIVE["running"]:
        return jsonify({"error": "A scan is already running"}), 409
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    wl = data.get("wordlist") or "common"
    extensions = _parse_list(data.get("extensions", ""))
    scanner = Scanner(
        target, wl,
        extensions=extensions,
        threads=min(int(data.get("threads", 50)), Scanner.MAX_THREADS),
        timeout=float(data.get("timeout", 10)),
        recursive=bool(data.get("recursive", False)),
        depth=int(data.get("depth", 2)),
        show=_parse_status(data.get("show_status")),
        hide=_parse_status(data.get("hide_status")),
        wildcard_check=not data.get("no_wildcard", False),
        respect_robots=bool(data.get("respect_robots", False)),
    )
    ACTIVE["scanner"] = scanner
    ACTIVE["running"] = True
    ACTIVE["target"] = target
    ACTIVE["started"] = time.time()
    ACTIVE["done"] = 0
    ACTIVE["total"] = scanner.total
    ACTIVE["found"] = 0
    ACTIVE["findings"] = []

    init_db()
    register_wordlists(available_wordlists())
    scan_id = create_scan(target, wl, ",".join(extensions) if extensions else "",
                          scanner.threads)
    ACTIVE["scan_id"] = scan_id

    def on_r(r):
        ACTIVE["findings"].append(r)
        ACTIVE["found"] = len(ACTIVE["findings"])

    def on_p(done, total):
        ACTIVE["done"] = done

    scanner.on_result = on_r
    scanner.on_progress = on_p

    def _worker():
        results, duration = scanner.run()
        for r in results:
            add_finding(scan_id, r)
        update_scan(scan_id, scanner.total, scanner.found, duration)
        ACTIVE["running"] = False

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"scan_id": scan_id, "target": target, "total": scanner.total,
                    "status": "started"})


@app.route("/api/scan/stop", methods=["POST"])
def api_stop():
    if ACTIVE["scanner"]:
        ACTIVE["scanner"].stop()
    ACTIVE["running"] = False
    return jsonify({"status": "stopped"})


@app.route("/api/results")
def api_results():
    clean = [{k: v for k, v in f.items() if k not in ("_text", "headers")}
             for f in ACTIVE["findings"][-200:]]
    return jsonify({"done": ACTIVE["done"], "total": ACTIVE["total"],
                    "found": ACTIVE["found"], "findings": clean})


@app.route("/api/findings/<int:scan_id>")
def api_findings(scan_id):
    only = request.args.get("interesting")
    rows = get_findings(scan_id, only == "1")
    return jsonify({"findings": rows})


@app.route("/api/tree/<int:scan_id>")
def api_tree(scan_id):
    rows = get_findings(scan_id)
    tree = recmod.build_tree(rows)
    lines = recmod.render_tree(tree)
    return jsonify({"tree": lines})


@app.route("/api/scans")
def api_scans():
    return jsonify({"scans": get_scans(50)})


@app.route("/api/export")
def api_export():
    fmt = request.args.get("format", "json")
    scan_id = request.args.get("scan_id")
    interesting_only = request.args.get("interesting") == "1"
    rows = []
    if scan_id:
        rows = get_findings(int(scan_id), interesting_only)
    else:
        # latest scan in DB
        scans = get_scans(1)
        if scans:
            rows = get_findings(scans[0]["id"], interesting_only)
    if fmt == "csv":
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["url", "status_code", "content_length", "content_type", "response_ms", "redirect_to", "interesting"])
        for r in rows:
            w.writerow([r["url"], r["status_code"], r["content_length"], r["content_type"],
                        r["response_ms"], r["redirect_to"], r["interesting"]])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=pathprobe.csv"})
    if fmt == "txt":
        body = "\n".join(r["url"] for r in rows) + "\n"
        return Response(body, mimetype="text/plain",
                        headers={"Content-Disposition": "attachment; filename=pathprobe_urls.txt"})
    return jsonify({"findings": rows})


def run_dashboard(host="127.0.0.1", port=PORT, debug=False):
    init_db()
    register_wordlists(available_wordlists())
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_dashboard()
