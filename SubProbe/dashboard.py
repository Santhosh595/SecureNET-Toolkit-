"""SubProbe — Flask web dashboard.

Run: python dashboard.py
Open: http://127.0.0.1:5500
"""

from __future__ import annotations

import json
import time
from flask import Flask, render_template, request, jsonify, Response

from database import init_db, create_scan, update_scan, get_subdomains, get_recent_scans, get_stats
from enumerator import enumerate_domain

app = Flask(__name__)
init_db()

_scan_progress = {"current": 0, "total": 0, "running": False}


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan() -> tuple:
    """Start a subdomain scan."""
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower()
    methods = data.get("methods", ["wordlist", "ct", "dns"])
    wordlist = data.get("wordlist")

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    scan_id = create_scan(domain)
    _scan_progress["running"] = True
    _scan_progress["current"] = 0
    _scan_progress["total"] = 0

    start = time.time()
    try:
        results = enumerate_domain(
            domain=domain,
            use_wordlist="wordlist" in methods,
            use_ct="ct" in methods,
            use_dns="dns" in methods,
            wordlist_path=wordlist,
        )
    except ValueError as e:
        _scan_progress["running"] = False
        return jsonify({"error": str(e)}), 400

    duration = time.time() - start
    live_count = sum(1 for r in results if r["status"] in ("LIVE", "REDIRECT"))

    for r in results:
        from database import add_subdomain
        add_subdomain(scan_id, r["subdomain"], r["ip"], r["http_status"],
                       r["status"], r["source"], r["interesting"])
    update_scan(scan_id, len(results), live_count, duration)

    _scan_progress["running"] = False
    return jsonify({
        "scan_id": scan_id,
        "total": len(results),
        "live": live_count,
        "duration": round(duration, 1),
        "results": results,
    })


@app.route("/progress")
def progress() -> dict:
    """Get current scan progress."""
    return jsonify(_scan_progress)


@app.route("/history")
def history() -> dict:
    """Get recent scans."""
    return jsonify({"scans": get_recent_scans()})


@app.route("/export/<int:scan_id>")
def export(scan_id: int) -> tuple:
    """Export scan results as JSON or TXT."""
    fmt = request.args.get("format", "json")
    subdomains = get_subdomains(scan_id)

    if fmt == "txt":
        content = "\n".join(s["subdomain"] for s in subdomains) + "\n"
        return Response(content, mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename=subprobe_{scan_id}.txt"})
    else:
        return Response(json.dumps(subdomains, indent=2),
                        mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename=subprobe_{scan_id}.json"})


def main() -> None:
    print("[*] Starting SubProbe Dashboard on http://127.0.0.1:5500")
    app.run(host="127.0.0.1", port=5500, debug=False)


if __name__ == "__main__":
    main()
