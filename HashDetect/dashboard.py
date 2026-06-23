"""HashDetect — Flask web dashboard.

Run: python dashboard.py
Open: http://127.0.0.1:5300
"""

from __future__ import annotations

import json
import os
import tempfile
from flask import Flask, render_template, request, jsonify, Response

from detector import detect_hash, Confidence
from cracker import load_wordlist, crack_hash

app = Flask(__name__)

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "common.txt")


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze() -> tuple:
    data = request.get_json(force=True)
    hash_input = data.get("hash", "").strip()
    do_crack = data.get("crack", False)
    custom_wl = data.get("custom_wordlist", [])

    if not hash_input:
        return jsonify({"error": "No hash provided"}), 400

    result = detect_hash(hash_input)
    if result.error:
        return jsonify({"error": result.error}), 400

    response = {
        "input": result.input_hash,
        "normalized": result.normalized_hash,
        "is_hex": result.is_valid_hex,
        "is_base64": result.is_base64,
        "matches": [
            {"name": m.name, "confidence": m.confidence, "length": m.length,
             "category": m.category, "crackable": m.crackable, "note": m.note}
            for m in result.matches
        ],
    }

    # Crack if requested
    if do_crack and result.matches:
        crackable = [m for m in result.matches if m.crackable]
        if crackable:
            # Use custom wordlist or default
            if custom_wl:
                words = custom_wl
            else:
                try:
                    words = load_wordlist(DEFAULT_WORDLIST)
                except Exception:
                    words = []

            if words:
                cracked = False
                total_attempted = 0
                total_time = 0.0
                for match in crackable:
                    found, attempted, elapsed = crack_hash(
                        result.normalized_hash, match.name, words, timeout=30.0
                    )
                    total_attempted += attempted
                    total_time += elapsed
                    if found:
                        response["cracked"] = True
                        response["plaintext"] = found
                        response["attempted"] = total_attempted
                        response["time"] = round(total_time, 2)
                        cracked = True
                        break
                if not cracked:
                    response["cracked"] = False
                    response["attempted"] = total_attempted
                    response["time"] = round(total_time, 2)

    return jsonify(response)


@app.route("/export", methods=["POST"])
def export() -> tuple:
    data = request.get_json(force=True)
    return Response(
        json.dumps(data, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=hashdetect_result.json"},
    )


def main() -> None:
    print("[*] Starting HashDetect Dashboard on http://127.0.0.1:5300")
    app.run(host="127.0.0.1", port=5300, debug=False)


if __name__ == "__main__":
    main()
