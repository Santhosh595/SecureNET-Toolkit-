"""
LogSentry Incident Report Generator
Generates reports in JSON, CSV, and PDF formats.
"""

import json
import csv
import os
import io
from datetime import datetime, timezone
from typing import Optional

from database import get_db_path, get_session_stats, get_all_events, get_all_alerts, get_all_ip_profiles


def generate_json_report(session_id: int, db_path: str = None, output_path: str = None) -> str:
    """Generate a JSON incident report."""
    stats = get_session_stats(session_id, db_path)
    events = get_all_events(session_id, limit=10000, db_path=db_path)
    alerts = get_all_alerts(session_id, limit=5000, db_path=db_path)
    profiles = get_all_ip_profiles(db_path)

    # Build MITRE summary
    mitre_techniques = {}
    for alert in alerts:
        mid = alert.get("mitre_id", "")
        if mid:
            if mid not in mitre_techniques:
                mitre_techniques[mid] = {"id": mid, "count": 0, "alerts": []}
            mitre_techniques[mid]["count"] += 1
            mitre_techniques[mid]["alerts"].append(alert.get("rule_name", ""))

    report = {
        "report_metadata": {
            "tool": "LogSentry",
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
        },
        "executive_summary": _generate_executive_summary(stats, alerts, profiles),
        "statistics": {
            "total_events": stats["session"].get("total_events", 0),
            "total_alerts": stats["session"].get("total_alerts", 0),
            "events_by_type": stats["events_by_type"],
            "alerts_by_severity": stats["alerts_by_severity"],
        },
        "attack_timeline": alerts,
        "attacker_profiles": profiles,
        "mitre_attck_techniques": list(mitre_techniques.values()),
        "recommendations": _generate_recommendations(alerts),
        "appendix": {
            "raw_events_count": len(events),
            "raw_alerts_count": len(alerts),
        }
    }

    output = json.dumps(report, indent=2, default=str)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)

    return output


def generate_csv_report(session_id: int, db_path: str = None, output_path: str = None) -> str:
    """Generate a CSV incident report (alerts table)."""
    alerts = get_all_alerts(session_id, limit=5000, db_path=db_path)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp", "Severity", "Rule", "MITRE ID", "Source IP", "Username", "Details"
    ])

    for alert in alerts:
        writer.writerow([
            alert.get("timestamp", ""),
            alert.get("severity", ""),
            alert.get("rule_name", ""),
            alert.get("mitre_id", ""),
            alert.get("src_ip", ""),
            alert.get("username", ""),
            alert.get("details", ""),
        ])

    csv_content = output.getvalue()

    if output_path:
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            f.write(csv_content)

    return csv_content


def generate_pdf_report(session_id: int, db_path: str = None, output_path: str = None) -> str:
    """Generate a PDF incident report."""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor, black, red, orange, yellow
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib import colors
    except ImportError:
        # Fallback: generate HTML-like text report
        return _generate_text_report(session_id, db_path, output_path)

    stats = get_session_stats(session_id, db_path)
    alerts = get_all_alerts(session_id, limit=5000, db_path=db_path)
    profiles = get_all_ip_profiles(db_path)

    if not output_path:
        output_path = "logsentry_report.pdf"

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=24,
        spaceAfter=30,
        textColor=HexColor("#1a1a2e"),
    )
    story.append(Paragraph("LogSentry Incident Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        styles["Normal"]
    ))
    story.append(Spacer(1, 20))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary", styles["Heading1"]))
    summary = _generate_executive_summary(stats, alerts, profiles)
    story.append(Paragraph(summary, styles["Normal"]))
    story.append(Spacer(1, 20))

    # Statistics
    story.append(Paragraph("2. Statistics", styles["Heading1"]))
    stats_data = [
        ["Metric", "Value"],
        ["Total Events", str(stats["session"].get("total_events", 0))],
        ["Total Alerts", str(stats["session"].get("total_alerts", 0))],
        ["Unique Attacker IPs", str(len(profiles))],
    ]
    stats_table = Table(stats_data, colWidths=[3 * inch, 3 * inch])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#16213e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#f8f9fa"), HexColor("#ffffff")]),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 20))

    # Attack Timeline
    story.append(Paragraph("3. Attack Timeline", styles["Heading1"]))
    if alerts:
        timeline_data = [["Time", "Severity", "IP", "Rule", "Details"]]
        for alert in alerts[:50]:  # Limit to 50 for PDF
            timeline_data.append([
                alert.get("timestamp", "")[:19],
                alert.get("severity", ""),
                alert.get("src_ip", ""),
                alert.get("rule_name", "")[:30],
                alert.get("details", "")[:50],
            ])
        timeline_table = Table(timeline_data, colWidths=[1.3 * inch, 0.8 * inch, 1.1 * inch, 1.3 * inch, 2 * inch])
        timeline_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
        ]))
        story.append(timeline_table)
    else:
        story.append(Paragraph("No alerts generated.", styles["Normal"]))

    story.append(PageBreak())

    # Attacker Profiles
    story.append(Paragraph("4. Attacker Profiles", styles["Heading1"]))
    if profiles:
        for profile in profiles[:20]:
            story.append(Paragraph(f"<b>IP: {profile['ip']}</b>", styles["Heading3"]))
            profile_data = [
                ["First Seen", profile.get("first_seen", "")],
                ["Last Seen", profile.get("last_seen", "")],
                ["Event Count", str(profile.get("event_count", 0))],
                ["Rules Triggered", profile.get("rules_triggered", "")],
                ["Sources Seen", profile.get("sources_seen", "")],
                ["Kill Chain", profile.get("kill_chain", "")],
                ["Priority", profile.get("priority", "")],
            ]
            p_table = Table(profile_data, colWidths=[2 * inch, 4 * inch])
            p_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
                ("BACKGROUND", (0, 0), (0, -1), HexColor("#f0f0f0")),
            ]))
            story.append(p_table)
            story.append(Spacer(1, 10))

    # Recommendations
    story.append(Spacer(1, 20))
    story.append(Paragraph("5. Recommendations", styles["Heading1"]))
    recommendations = _generate_recommendations(alerts)
    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", styles["Normal"]))
        story.append(Spacer(1, 5))

    doc.build(story)
    return output_path


def _generate_text_report(session_id: int, db_path: str = None, output_path: str = None) -> str:
    """Fallback text report when reportlab is not available."""
    stats = get_session_stats(session_id, db_path)
    alerts = get_all_alerts(session_id, limit=5000, db_path=db_path)
    profiles = get_all_ip_profiles(db_path)

    lines = []
    lines.append("=" * 70)
    lines.append("LOGSENTRY INCIDENT REPORT")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("=" * 70)
    lines.append("")
    lines.append("1. EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(_generate_executive_summary(stats, alerts, profiles))
    lines.append("")
    lines.append("2. STATISTICS")
    lines.append("-" * 40)
    lines.append(f"Total Events: {stats['session'].get('total_events', 0)}")
    lines.append(f"Total Alerts: {stats['session'].get('total_alerts', 0)}")
    lines.append(f"Unique Attacker IPs: {len(profiles)}")
    lines.append("")
    lines.append("3. ATTACK TIMELINE")
    lines.append("-" * 40)
    for alert in alerts[:50]:
        lines.append(f"  [{alert.get('severity', '')}] {alert.get('timestamp', '')} {alert.get('src_ip', '')} -> {alert.get('rule_name', '')}")
    lines.append("")
    lines.append("4. ATTACKER PROFILES")
    lines.append("-" * 40)
    for profile in profiles[:20]:
        lines.append(f"  IP: {profile['ip']} | Events: {profile.get('event_count', 0)} | Priority: {profile.get('priority', '')}")
        lines.append(f"    Rules: {profile.get('rules_triggered', '')}")
        lines.append(f"    Sources: {profile.get('sources_seen', '')}")
        lines.append("")
    lines.append("5. RECOMMENDATIONS")
    lines.append("-" * 40)
    for rec in _generate_recommendations(alerts):
        lines.append(f"  • {rec}")

    content = "\n".join(lines)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    return content


def _generate_executive_summary(stats: dict, alerts: list, profiles: list) -> str:
    """Generate a plain-English executive summary."""
    total_events = stats["session"].get("total_events", 0)
    total_alerts = stats["session"].get("total_alerts", 0)
    critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    high = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium = sum(1 for a in alerts if a.get("severity") == "MEDIUM")

    severity_counts = stats.get("alerts_by_severity", [])
    sev_str = ", ".join(f"{s['severity']}: {s['count']}" for s in severity_counts)

    summary = (
        f"LogSentry analyzed {total_events:,} log events and generated {total_alerts} alerts. "
        f"Alerts by severity: {sev_str if sev_str else 'none'}. "
    )

    if critical > 0:
        summary += f"CRITICAL findings ({critical}): Immediate investigation required. "
    if high > 0:
        summary += f"HIGH severity findings ({high}): Review recommended within 24 hours. "

    if profiles:
        top_attackers = sorted(profiles, key=lambda p: -p.get("event_count", 0))[:3]
        summary += f"Top attacker sources: {', '.join(p['ip'] + ' (' + str(p.get('event_count', 0)) + ' events)' for p in top_attackers)}. "

    if total_alerts == 0:
        summary += "No suspicious activity detected."

    return summary


def _generate_recommendations(alerts: list) -> list:
    """Generate actionable recommendations based on alerts."""
    recommendations = []
    rules_seen = set()

    for alert in alerts:
        rule = alert.get("rule_name", "")
        if rule in rules_seen:
            continue
        rules_seen.add(rule)

        rec_map = {
            "SSH Brute Force": "Implement fail2ban or similar brute-force protection. Restrict SSH access by IP.",
            "SSH Success After Failures": "Investigate successful login immediately. Consider password rotation for affected accounts.",
            "Credential Stuffing": "Enforce multi-factor authentication. Monitor for unauthorized account usage.",
            "Off-Hours Login": "Verify if off-hours access was authorized. Review access policies.",
            "Root Login Attempt": "Disable direct root SSH login. Use sudo for privileged operations.",
            "Web Scanner Detection": "Review web application firewall rules. Ensure applications are patched.",
            "Directory Traversal": "Harden web application input validation. Implement chroot or containerization.",
            "SQL Injection": "Audit application for SQL injection vulnerabilities. Use parameterized queries.",
            "XSS Attempt": "Implement Content Security Policy headers. Sanitize user inputs.",
            "Port Scan Detected": "Review firewall rules. Ensure only necessary ports are exposed.",
            "Privilege Escalation (Windows)": "Audit group membership changes. Verify admin group modifications were authorized.",
            "New Service Installed": "Verify service installation was authorized. Review service account permissions.",
            "Repeated 403/401 Responses": "Block offending IP at firewall level. Review authentication mechanisms.",
            "Large Data Transfer": "Investigate data transfer. Verify if authorized. Implement DLP controls.",
            "Geographic Anomaly": "Verify user location. Consider geo-blocking for sensitive systems.",
        }

        if rule in rec_map:
            recommendations.append(f"[{rule}] {rec_map[rule]}")

    if not recommendations:
        recommendations.append("No specific recommendations. Continue monitoring.")

    return recommendations
