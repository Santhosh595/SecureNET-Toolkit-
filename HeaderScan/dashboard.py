"""HeaderScan — Flask web dashboard.

Run: python dashboard.py
Open: http://127.0.0.1:5100
"""

from __future__ import annotations

import json
from flask import Flask, render_template, request, jsonify, Response

from analyzer import scan_url

app = Flask(__name__)


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan() -> Response:
    """API endpoint to scan a URL and return JSON results."""
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    report = scan_url(url)
    return Response(report.to_json(), mimetype="application/json")


@app.route("/export", methods=["POST"])
def export() -> Response:
    """Download scan results as a JSON file."""
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    report = scan_url(url)
    return Response(
        report.to_json(indent=2),
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=headerscan_{url.replace('://', '_').replace('/', '_')}.json"
        },
    )


def main() -> None:
    print("[*] Starting HeaderScan Dashboard on http://127.0.0.1:5100")
    app.run(host="127.0.0.1", port=5100, debug=False)


if __name__ == "__main__":
    main()
