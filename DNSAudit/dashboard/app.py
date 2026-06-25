"""DNSAudit - Flask Web Dashboard"""

from __future__ import annotations

import json
import time
from flask import Flask, render_template, request, jsonify, Response

from database import init_db, get_recent_scans, get_stats

app = Flask(__name__)
init_db()


@app.route("/")
def index() -> str:
    return render_template("scan.html")


@app.route("/scan", methods=["POST"])
def scan() -> tuple:
    """Run a DNS audit scan."""
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower().rstrip(".")
    resolver_ip = data.get("resolver", None)

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    start = time.time()

    try:
        from resolver import DNSResolver
        from audits.spf import audit_spf
        from audits.dkim import audit_dkim
        from audits.dmarc import audit_dmarc
        from audits.dnssec import audit_dnssec
        from audits.zone_transfer import audit_zone_transfer
        from audits.takeover import audit_takeover
        from audits.hijacking import audit_hijacking
        from audits.mail_server import audit_mail_server
        from audits.nameserver import audit_nameserver
        from audits.caa import audit_caa
        from audits.inventory import audit_inventory
        from audits.dane import audit_dane
        from scorer import calculate_grade, calculate_score

        resolver = DNSResolver(custom_resolver=resolver_ip)

        categories = {
            "SPF": audit_spf,
            "DKIM": audit_dkim,
            "DMARC": audit_dmarc,
            "DNSSEC": audit_dnssec,
            "Zone Transfer": audit_zone_transfer,
            "Subdomain Takeover": audit_takeover,
            "DNS Hijacking": audit_hijacking,
            "Mail Server": audit_mail_server,
            "Nameserver": audit_nameserver,
            "CAA": audit_caa,
            "DNS Inventory": audit_inventory,
            "DANE/TLSA": audit_dane,
        }

        all_findings = {}
        category_scores = {}

        for name, audit_func in categories.items():
            try:
                result = audit_func(domain, resolver.resolver)
                if hasattr(result, 'findings'):
                    all_findings[name] = [
                        {
                            "check": getattr(f, 'check', ''),
                            "severity": getattr(f, 'severity', ''),
                            "title": getattr(f, 'title', ''),
                            "description": getattr(f, 'description', ''),
                            "recommendation": getattr(f, 'recommendation', ''),
                        }
                        for f in result.findings
                    ]
                category_scores[name] = calculate_score(getattr(result, 'findings', []))
            except Exception as e:
                all_findings[name] = [{"check": "Error", "severity": "WARNING",
                                        "title": f"{name} failed", "description": str(e)}]
                category_scores[name] = 10

        overall_score = sum(category_scores.values())
        grade = calculate_grade(overall_score, all_findings)
        duration = time.time() - start

        return jsonify({
            "domain": domain,
            "grade": grade,
            "score": overall_score,
            "duration": round(duration, 2),
            "findings": all_findings,
            "category_scores": category_scores,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/history")
def history() -> dict:
    return jsonify({"scans": get_recent_scans()})


@app.route("/stats")
def stats() -> dict:
    return jsonify(get_stats())


@app.route("/export/<format_name>")
def export(format_name: str) -> tuple:
    """Export scan results."""
    # Placeholder - would need to store last scan in session
    return jsonify({"error": "Not implemented yet"}), 501


def main(port: int = 5900) -> None:
    print("")
    print("=" * 50)
    print("  DNSAudit Dashboard")
    print(f"  http://127.0.0.1:{port}")
    print("=" * 50)
    print("")
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
