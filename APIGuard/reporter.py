"""APIGuard — Reporter (JSON, CSV, SARIF, PDF export)."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


def export_json(findings: List[Dict], path: str, scan_info: Optional[Dict] = None) -> str:
    report = {
        "tool": "APIGuard",
        "timestamp": datetime.utcnow().isoformat(),
        "scan": scan_info or {},
        "findings": findings,
        "summary": _summary(findings),
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path


def export_csv(findings: List[Dict], path: str) -> str:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["OWASP Category", "Endpoint", "Method", "Test", "Severity", "CVSS", "CWE", "Evidence"])
        for f_ in findings:
            w.writerow([
                f_.get("owasp_category", ""),
                f_.get("endpoint", ""),
                f_.get("method", ""),
                f_.get("test_name", ""),
                f_.get("severity", ""),
                f_.get("cvss_score", ""),
                f_.get("cwe_ref", ""),
                f_.get("evidence", ""),
            ])
    return path


def export_sarif(findings: List[Dict], path: str) -> str:
    """Generate SARIF v2.1.0 output."""
    rules = {}
    results = []
    for i, f_ in enumerate(findings):
        rule_id = f_.get("owasp_category", "GENERAL") + "-" + str(i)
        rules[rule_id] = {
            "id": rule_id,
            "shortDescription": {"text": f_.get("test_name", "")},
            "fullDescription": {"text": f_.get("evidence", "")},
            "defaultConfiguration": {"level": _sarif_level(f_.get("severity", "MEDIUM"))},
            "helpUri": f"https://owasp.org/API-Security/editions/2023/en/_{f_.get('owasp_category','').lower()}/",
            "properties": {"tags": [f_.get("owasp_category",""), f_.get("cwe_ref","")]},
        }
        results.append({
            "ruleId": rule_id,
            "message": {"text": f_.get("evidence", "")},
            "locations": [{
                "physicalLocation": {
                    "address": {"fullyQualifiedName": f_.get("endpoint", "")},
                    "artifactLocation": {"uri": f_.get("endpoint", "")},
                }
            }],
            "properties": {
                "severity": f_.get("severity", ""),
                "cvss": f_.get("cvss_score", 0),
                "remediation": f_.get("remediation", ""),
            },
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "APIGuard", "version": "1.0", "rules": list(rules.values())}},
            "results": results,
        }]
    }
    with open(path, "w") as f:
        json.dump(sarif, f, indent=2)
    return path


def export_pdf(findings: List[Dict], path: str, scan_info: Optional[Dict] = None) -> str:
    """Generate PDF via reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
    except ImportError:
        # Fallback to text file
        with open(path.replace(".pdf", ".txt"), "w") as f:
            f.write("APIGuard Report (PDF requires reportlab)\n\n")
            for f_ in findings:
                f.write(f"[{f_['severity']}] {f_['owasp_category']} @ {f_['endpoint']}: {f_['test_name']}\n")
        return path.replace(".pdf", ".txt")

    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph("APIGuard — OWASP API Security Report", styles["Title"]))
    elements.append(Spacer(1, 12))
    if scan_info:
        elements.append(Paragraph(f"Target: {scan_info.get('target','')}", styles["Normal"]))
        elements.append(Paragraph(f"Date: {scan_info.get('timestamp','')}", styles["Normal"]))
        elements.append(Spacer(1, 12))
    s = _summary(findings)
    elements.append(Paragraph(f"Findings: {s['total']} | Critical: {s['critical']} | High: {s['high']} | Medium: {s['medium']} | Low: {s['low']}", styles["Normal"]))
    elements.append(Spacer(1, 12))
    # Table
    data = [["OWASP", "Endpoint", "Severity", "Test"]]
    for f_ in findings:
        data.append([
            f_.get("owasp_category", ""),
            f_.get("endpoint", "")[:30],
            f_.get("severity", ""),
            f_.get("test_name", "")[:40],
        ])
    t = Table(data, colWidths=[60, 140, 60, 200])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0c1220")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#243044")),
    ]))
    elements.append(t)
    doc.build(elements)
    return path


def _summary(findings: List[Dict]) -> Dict[str, int]:
    return {
        "total": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
        "medium": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "low": sum(1 for f in findings if f.get("severity") == "LOW"),
        "info": sum(1 for f in findings if f.get("severity") == "INFO"),
    }


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}.get(severity.upper(), "warning")
