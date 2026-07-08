"""TechFinger — Flask web dashboard."""

from __future__ import annotations

from flask import Flask, render_template, request, jsonify

from engine import fingerprint

app = Flask(__name__)


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan() -> jsonify:  # type: ignore
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    result = fingerprint(target)
    return jsonify(result)


if __name__ == "__main__":
    print("[*] Starting TechFinger Dashboard on http://127.0.0.1:5017")
    app.run(host="127.0.0.1", port=5017, debug=False)
