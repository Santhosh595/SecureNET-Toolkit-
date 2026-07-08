"""ImgScan — Flask web dashboard."""

from __future__ import annotations

from flask import Flask, render_template, request, jsonify

from engine import scan_dependencies, scan_image_sbom

app = Flask(__name__)


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan() -> jsonify:  # type: ignore
    data = request.get_json(force=True) or {}
    findings = []
    if data.get("requirements"):
        findings += scan_dependencies(data["requirements"])
    if data.get("sbom"):
        findings += scan_image_sbom(data["sbom"])
    return jsonify([
        {"component": f.component, "version": f.version, "cve": f.cve,
         "severity": f.severity, "source": f.source, "detail": f.detail}
        for f in findings
    ])


if __name__ == "__main__":
    print("[*] Starting ImgScan Dashboard on http://127.0.0.1:5016")
    app.run(host="127.0.0.1", port=5016, debug=False)
