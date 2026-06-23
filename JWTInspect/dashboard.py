"""JWTInspect — Flask web dashboard.

Run: python dashboard.py
Open: http://127.0.0.1:5600
"""

from __future__ import annotations

import json
import os
import time
from flask import Flask, render_template, request, jsonify, Response

from parser import parse_jwt
from tests import run_all_tests, get_verdict
from reporter import generate_report

app = Flask(__name__)

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "secrets.txt")


def load_wordlist(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze() -> tuple:
    data = request.get_json(force=True)
    token = data.get("token", "").strip()
    do_crack = data.get("crack", False)
    compare_token = data.get("compare", None)
    wordlist_file = data.get("wordlist_file", None)

    if not token:
        return jsonify({"error": "No token provided"}), 400

    parsed = parse_jwt(token)
    if parsed.errors:
        return jsonify({"error": parsed.errors[0]}), 400

    wordlist = []
    if do_crack:
        wl_path = wordlist_file or DEFAULT_WORDLIST
        wordlist = load_wordlist(wl_path)

    results = run_all_tests(parsed, wordlist, compare_token)
    verdict, _ = get_verdict(results)

    report = generate_report(parsed, results, len(wordlist))

    return jsonify({
        "header": parsed.header,
        "payload": parsed.payload,
        "signature": parsed.signature,
        "algorithm": parsed.algorithm,
        "token_type": parsed.token_type,
        "claims": {
            "iss": parsed.claims.iss,
            "sub": parsed.claims.sub,
            "aud": parsed.claims.aud,
            "exp": parsed.claims.exp,
            "iat": parsed.claims.iat,
            "nbf": parsed.claims.nbf,
            "jti": parsed.claims.jti,
        },
        "time_analysis": {
            "is_expired": parsed.is_expired,
            "expires_in": parsed.expires_in,
            "issued_ago": parsed.issued_ago,
            "is_valid_time": parsed.is_valid_time,
        },
        "results": [
            {"test": r.test_name, "result": r.result, "severity": r.severity,
             "finding": r.finding, "proof": r.proof, "remediation": r.remediation}
            for r in results
        ],
        "verdict": verdict,
        "report": report,
    })


@app.route("/export", methods=["POST"])
def export() -> tuple:
    data = request.get_json(force=True)
    return Response(
        json.dumps(data, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=jwtinspect_report.json"},
    )


def main() -> None:
    print("[*] Starting JWTInspect Dashboard on http://127.0.0.1:5600")
    app.run(host="127.0.0.1", port=5600, debug=False)


if __name__ == "__main__":
    main()
