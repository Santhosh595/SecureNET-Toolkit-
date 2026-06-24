"""
LogSentry Flask Dashboard
Multi-page web interface for log analysis and threat visualization.
"""

import os
import json
from datetime import datetime, timezone

from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file

from database import (
    init_db, get_db_path, create_session, close_session,
    insert_events_batch, insert_alerts_batch, get_session_stats,
    get_all_events, get_all_alerts, get_all_ip_profiles, get_recent_alerts
)
from normalizer import deduplicate_events
from ingester.auth_parser import parse_auth_file
from ingester.apache_parser import parse_access_file, parse_error_file
from ingester.windows_parser import parse_windows_file
from ingester.firewall_parser import parse_firewall_file
from ingester.generic_parser import parse_generic_file
from rules import ALL_RULES
from correlator import correlate_events
from mitre.mapping import build_attack_navigator_layer, get_tactics_covered, get_techniques_triggered
from reporter import generate_json_report, generate_csv_report
from threat_intel.checker import check_ips, get_threat_intel_stats

app = Flask(__name__)
app.secret_key = "logsentry-secret-key-change-in-production"

CURRENT_SESSION = None
CURRENT_EVENTS = []
CURRENT_ALERTS = []


def _detect_type(filename):
    """Detect log type from filename."""
    fname = filename.lower()
    if any(k in fname for k in ["auth", "secure"]):
        return "auth"
    if "access" in fname:
        return "apache_access"
    if "error" in fname:
        return "apache_error"
    if any(k in fname for k in ["windows", "event", "security.evtx"]):
        return "windows"
    if any(k in fname for k in ["firewall", "ufw", "iptables"]):
        return "firewall"
    return "generic"


def _get_parser(log_type):
    """Get parser function for log type."""
    parsers = {
        "auth": parse_auth_file,
        "apache_access": parse_access_file,
        "apache_error": parse_error_file,
        "windows": parse_windows_file,
        "firewall": parse_firewall_file,
        "generic": parse_generic_file,
    }
    return parsers.get(log_type, parse_generic_file)


def _run_rules(events):
    """Run all rules on events."""
    all_alerts = []
    for rule in ALL_RULES:
        try:
            alerts = rule.check(events)
            if alerts:
                all_alerts.extend(alerts)
        except Exception:
            pass
    return all_alerts


@app.route("/")
def index():
    """Overview page."""
    stats = None
    recent_alerts = []
    top_attackers = []
    alerts_by_severity = []
    events_by_type = []
    threat_stats = get_threat_intel_stats()

    if CURRENT_SESSION:
        stats = get_session_stats(CURRENT_SESSION)
        recent_alerts = get_recent_alerts(CURRENT_SESSION, limit=10)
        top_attackers = stats.get("top_attackers", [])[:5]
        alerts_by_severity = stats.get("alerts_by_severity", [])
        events_by_type = stats.get("events_by_type", [])

    return render_template(
        "overview.html",
        stats=stats,
        recent_alerts=recent_alerts,
        top_attackers=top_attackers,
        alerts_by_severity=alerts_by_severity,
        events_by_type=events_by_type,
        threat_stats=threat_stats,
        session_id=CURRENT_SESSION,
    )


@app.route("/upload", methods=["POST"])
def upload():
    """Handle file upload and analysis."""
    global CURRENT_SESSION, CURRENT_EVENTS, CURRENT_ALERTS

    log_type = request.form.get("log_type", "auto")
    mode = request.form.get("mode", "analyze")

    # Handle file uploads
    uploaded_files = request.files.getlist("logfile")
    if not uploaded_files or all(f.filename == "" for f in uploaded_files):
        return redirect(url_for("index"))

    # Create new session
    db_path = init_db()
    CURRENT_SESSION = create_session(db_path)
    all_events = []
    all_alerts = []

    for uploaded_file in uploaded_files:
        if uploaded_file.filename == "":
            continue

        # Save uploaded file temporarily
        temp_path = os.path.join("/tmp", uploaded_file.filename)
        uploaded_file.save(temp_path)

        # Detect type
        detected_type = log_type if log_type != "auto" else _detect_type(uploaded_file.filename)
        parser = _get_parser(detected_type)

        # Parse events
        raw_events = list(parser(temp_path))
        from normalizer import normalize_event
        normalized = []
        for parsed in raw_events:
            event = normalize_event(parsed, uploaded_file.filename, detected_type)
            if event:
                normalized.append(event)

        events = deduplicate_events(normalized)
        all_events.extend(events)

        # Clean up temp file
        try:
            os.remove(temp_path)
        except Exception:
            pass

    # Store events
    if all_events:
        insert_events_batch(all_events, CURRENT_SESSION, db_path)

    # Run rules
    all_alerts = _run_rules(all_events)
    if all_alerts:
        insert_alerts_batch(all_alerts, CURRENT_SESSION, db_path)

    # Run correlation
    if all_events:
        profiles = correlate_events(all_events, all_alerts)
        from database import update_ip_profile
        for profile in profiles:
            update_ip_profile(profile, db_path)

        # Check threat intel
        threat_matches = check_ips([p["ip"] for p in profiles])
        if threat_matches:
            for match in threat_matches:
                # Add threat intel alerts
                all_alerts.append({
                    "rule_name": "Known Threat Actor",
                    "severity": "CRITICAL",
                    "mitre_id": "",
                    "src_ip": match["ip"],
                    "username": "",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "details": f"IP matches threat intel: {match.get('source', 'unknown')} ({match.get('category', 'malicious')})",
                })
            insert_alerts_batch(all_alerts, CURRENT_SESSION, db_path)

    CURRENT_EVENTS = all_events
    CURRENT_ALERTS = all_alerts

    close_session(CURRENT_SESSION, db_path)
    return redirect(url_for("index"))


@app.route("/analyze_path", methods=["POST"])
def analyze_path():
    """Analyze logs from a file path."""
    global CURRENT_SESSION, CURRENT_EVENTS, CURRENT_ALERTS

    path = request.form.get("path", "")
    log_type = request.form.get("log_type", "auto")

    if not path or not os.path.exists(path):
        return redirect(url_for("index"))

    db_path = init_db()
    CURRENT_SESSION = create_session(db_path)
    all_events = []

    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(root, fname)
                detected_type = log_type if log_type != "auto" else _detect_type(fname)
                parser = _get_parser(detected_type)
                raw_events = list(parser(fpath))
                from normalizer import normalize_event
                for parsed in raw_events:
                    event = normalize_event(parsed, fpath, detected_type)
                    if event:
                        all_events.append(event)
    else:
        detected_type = log_type if log_type != "auto" else _detect_type(path)
        parser = _get_parser(detected_type)
        raw_events = list(parser(path))
        from normalizer import normalize_event
        for parsed in raw_events:
            event = normalize_event(parsed, path, detected_type)
            if event:
                all_events.append(event)

    all_events = deduplicate_events(all_events)

    if all_events:
        insert_events_batch(all_events, CURRENT_SESSION, db_path)

    all_alerts = _run_rules(all_events)
    if all_alerts:
        insert_alerts_batch(all_alerts, CURRENT_SESSION, db_path)

    if all_events:
        profiles = correlate_events(all_events, all_alerts)
        from database import update_ip_profile
        for profile in profiles:
            update_ip_profile(profile, db_path)

    CURRENT_EVENTS = all_events
    CURRENT_ALERTS = all_alerts

    close_session(CURRENT_SESSION, db_path)
    return redirect(url_for("index"))


@app.route("/timeline")
def timeline():
    """Threat timeline page."""
    alerts = []
    if CURRENT_SESSION:
        alerts = get_all_alerts(CURRENT_SESSION, limit=500)
    return render_template("timeline.html", alerts=alerts, session_id=CURRENT_SESSION)


@app.route("/profiles")
def profiles():
    """Attacker profiles page."""
    all_profiles = get_all_ip_profiles()
    return render_template("profiles.html", profiles=all_profiles, session_id=CURRENT_SESSION)


@app.route("/rules")
def rules():
    """Rule analysis page."""
    rule_stats = []
    if CURRENT_SESSION:
        alerts = get_all_alerts(CURRENT_SESSION, limit=5000)
        for rule in ALL_RULES:
            count = sum(1 for a in alerts if a.get("rule_name") == rule.name)
            rule_stats.append({
                "name": rule.name,
                "severity": rule.severity,
                "mitre_id": rule.mitre_id,
                "description": rule.description,
                "count": count,
                "enabled": rule.enabled,
            })
    else:
        for rule in ALL_RULES:
            rule_stats.append({
                "name": rule.name,
                "severity": rule.severity,
                "mitre_id": rule.mitre_id,
                "description": rule.description,
                "count": 0,
                "enabled": rule.enabled,
            })

    return render_template("rules.html", rules=rule_stats, session_id=CURRENT_SESSION)


@app.route("/mitre")
def mitre():
    """MITRE ATT&CK page."""
    techniques = []
    tactics = []
    navigator_layer = None

    if CURRENT_SESSION:
        alerts = get_all_alerts(CURRENT_SESSION, limit=5000)
        techniques = get_techniques_triggered(alerts)
        tactics = get_tactics_covered(alerts)
        navigator_layer = build_attack_navigator_layer(alerts)

    return render_template(
        "mitre.html",
        techniques=techniques,
        tactics=tactics,
        navigator_layer=navigator_layer,
        session_id=CURRENT_SESSION,
    )


@app.route("/reports")
def reports():
    """Reports page."""
    return render_template("reports.html", session_id=CURRENT_SESSION)


@app.route("/export/<format_type>")
def export(format_type):
    """Export report."""
    if not CURRENT_SESSION:
        return redirect(url_for("index"))

    if format_type == "json":
        output_path = "logsentry_report.json"
        generate_json_report(CURRENT_SESSION, output_path=output_path)
        return send_file(output_path, as_attachment=True)
    elif format_type == "csv":
        output_path = "logsentry_report.csv"
        generate_csv_report(CURRENT_SESSION, output_path=output_path)
        return send_file(output_path, as_attachment=True)
    elif format_type == "attack":
        alerts = get_all_alerts(CURRENT_SESSION, limit=5000)
        layer = build_attack_navigator_layer(alerts)
        output_path = "logsentry_attack_layer.json"
        with open(output_path, "w") as f:
            json.dump(layer, f, indent=2)
        return send_file(output_path, as_attachment=True)

    return redirect(url_for("reports"))


@app.route("/api/events")
def api_events():
    """API endpoint for events."""
    if not CURRENT_SESSION:
        return jsonify([])
    events = get_all_events(CURRENT_SESSION, limit=100)
    return jsonify(events)


@app.route("/api/alerts")
def api_alerts():
    """API endpoint for alerts."""
    if not CURRENT_SESSION:
        return jsonify([])
    alerts = get_all_alerts(CURRENT_SESSION, limit=100)
    return jsonify(alerts)


def launch_dashboard(port: int = 5000):
    """Launch the Flask dashboard."""
    init_db()
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    launch_dashboard()
