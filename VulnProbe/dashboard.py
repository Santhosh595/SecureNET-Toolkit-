"""VulnProbe — Flask web dashboard."""

from __future__ import annotations

from flask import Flask, render_template, request, jsonify, Response

from engine import load_templates, build_session, scan_target

app = Flask(__name__)


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan() -> Response:
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    templates = load_templates("templates")
    session = build_session()
    findings = scan_target(target, templates, session)
    session.close()
    return jsonify({"target": target, "findings": findings, "template_count": len(templates)})


if __name__ == "__main__":
    print("[*] Starting VulnProbe Dashboard on http://127.0.0.1:5013")
    app.run(host="127.0.0.1", port=5013, debug=False)
