"""CloudSentry — minimal Flask dashboard (read-only posture summary)."""

from __future__ import annotations

from flask import Flask, render_template, request, jsonify

from engine import run_checks

app = Flask(__name__)


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan() -> jsonify:  # type: ignore
    data = request.get_json(force=True) or {}
    providers = data.get("providers")
    results = run_checks(providers)
    return jsonify([
        {"provider": r.provider, "check_id": r.check_id, "title": r.title,
         "status": r.status, "severity": r.severity, "detail": r.detail}
        for r in results
    ])


if __name__ == "__main__":
    print("[*] Starting CloudSentry Dashboard on http://127.0.0.1:5015")
    app.run(host="127.0.0.1", port=5015, debug=False)
