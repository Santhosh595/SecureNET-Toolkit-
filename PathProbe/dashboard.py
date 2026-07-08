"""PathProbe — Flask web dashboard."""

from __future__ import annotations

from flask import Flask, render_template, request, jsonify

from engine import load_wordlist, discover

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
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    words = load_wordlist("wordlists/common.txt")
    results = discover(target, words)
    return jsonify({"target": target, "count": len(results), "results": results})


if __name__ == "__main__":
    print("[*] Starting PathProbe Dashboard on http://127.0.0.1:5014")
    app.run(host="127.0.0.1", port=5014, debug=False)
