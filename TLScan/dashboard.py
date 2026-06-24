"""TLScan — Flask web dashboard.

Run: python dashboard.py
Open: http://127.0.0.1:5700
"""

from __future__ import annotations

import json
import time
from flask import Flask, render_template, request, jsonify, Response

from connector import connect_ssl
from protocol_tester import test_protocols
from cipher_enumerator import enumerate_ciphers
from vuln_checks import check_all_vulnerabilities
from grader import calculate_grade
from database import init_db, save_scan, get_scan, get_certificates, get_protocols, get_ciphers, get_vulnerabilities, get_recent_scans

app = Flask(__name__)
init_db()

_scan_progress = {"step": 0, "total": 6, "running": False, "current": ""}


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan() -> tuple:
    """Run a full TLS scan."""
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip()
    port = int(data.get("port", 443))

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    _scan_progress["running"] = True
    _scan_progress["step"] = 0
    _scan_progress["total"] = 6

    start = time.time()

    # Step 1: Connect
    _scan_progress["step"] = 1
    _scan_progress["current"] = "Connecting..."
    conn_result = connect_ssl(domain, port)
    if not conn_result.success:
        _scan_progress["running"] = False
        return jsonify({"error": conn_result.error}), 400

    # Step 2: Certificate chain
    _scan_progress["step"] = 2
    _scan_progress["current"] = "Analyzing certificate chain..."
    certificates = conn_result.certificates

    # Step 3: Protocol testing
    _scan_progress["step"] = 3
    _scan_progress["current"] = "Testing protocol versions..."
    protocols = test_protocols(domain, port)

    # Step 4: Cipher enumeration
    _scan_progress["step"] = 4
    _scan_progress["current"] = "Enumerating cipher suites..."
    ciphers = enumerate_ciphers(domain, port)

    # Step 5: Vulnerability checks
    _scan_progress["step"] = 5
    _scan_progress["current"] = "Running vulnerability checks..."
    vulnerabilities = check_all_vulnerabilities(domain, port, protocols, ciphers)

    # Step 6: Generate report
    _scan_progress["step"] = 6
    _scan_progress["current"] = "Generating report..."
    grade_result = calculate_grade(certificates, protocols, ciphers, vulnerabilities)
    duration = time.time() - start

    # Save to database
    scan_id = save_scan(domain, port, grade_result.grade, grade_result.score,
                         duration, certificates, protocols, ciphers, vulnerabilities)

    _scan_progress["running"] = False

    return jsonify({
        "scan_id": scan_id,
        "domain": domain, "port": port,
        "grade": grade_result.grade,
        "score": grade_result.score,
        "cap_reason": grade_result.cap_reason,
        "deductions": grade_result.deductions,
        "duration": round(duration, 2),
        "certificates": [{"subject_cn": c.subject_cn, "issuer_cn": c.issuer_cn,
                          "days_until_expiry": c.days_until_expiry, "key_type": c.key_type,
                          "key_size": c.key_size, "is_self_signed": c.is_self_signed,
                          "san": c.san, "fingerprint_sha256": c.fingerprint_sha256}
                         for c in certificates],
        "protocols": [{"protocol": p.protocol, "supported": p.supported, "risk": p.risk,
                        "cipher": p.cipher} for p in protocols],
        "ciphers": [{"protocol": c.protocol, "cipher": c.cipher, "category": c.category,
                     "forward_secrecy": c.forward_secrecy, "accepted": c.accepted}
                    for c in ciphers if c.accepted],
        "vulnerabilities": [{"name": v.name, "cve": v.cve, "vulnerable": v.vulnerable,
                              "severity": v.severity, "detail": v.detail} for v in vulnerabilities],
        "connection": {"ip": conn_result.ip_address, "ssl_version": conn_result.ssl_version,
                       "cipher": conn_result.cipher[0] if conn_result.cipher else None,
                       "connect_time": conn_result.connect_time},
    })


@app.route("/progress")
def progress() -> dict:
    """Get current scan progress."""
    return jsonify(_scan_progress)


@app.route("/history")
def history() -> dict:
    """Get scan history."""
    return jsonify({"scans": get_recent_scans()})


@app.route("/export/<int:scan_id>")
def export(scan_id: int) -> tuple:
    """Export scan as JSON."""
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    report = {
        "scan": scan,
        "certificates": get_certificates(scan_id),
        "protocols": get_protocols(scan_id),
        "ciphers": get_ciphers(scan_id),
        "vulnerabilities": get_vulnerabilities(scan_id),
    }
    return Response(json.dumps(report, indent=2, ensure_ascii=False),
                    mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=tlscan_{scan_id}.json"})


def main() -> None:
    print("[*] Starting TLScan Dashboard on http://127.0.0.1:5700")
    app.run(host="127.0.0.1", port=5700, debug=False)


if __name__ == "__main__":
    main()
