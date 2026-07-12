"""ImgScan — report generation (JSON / CSV / TXT / PDF)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import List

from scanners.common import VulnFinding, DockerFinding


def to_json(findings: List[VulnFinding], docker: List[DockerFinding] = None) -> str:
    payload = {
        "tool": "ImgScan",
        "generated": datetime.now().isoformat(),
        "vulnerabilities": [
            {"package": f.package, "version": f.version, "ecosystem": f.ecosystem,
             "cve_id": f.cve_id, "severity": f.severity, "cvss_score": f.cvss_score,
             "cvss_vector": f.cvss_vector, "description": f.description,
             "fixed_version": f.fixed_version, "in_kev": f.in_kev,
             "upgrade_command": f.upgrade_command, "source": f.source}
            for f in findings
        ],
        "dockerfile_findings": [
            {"check_id": d.check_id, "line": d.line_number, "severity": d.severity,
             "description": d.description, "remediation": d.remediation}
            for d in (docker or [])
        ],
    }
    return json.dumps(payload, indent=2)


def to_csv(findings: List[VulnFinding]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["package", "version", "ecosystem", "cve_id", "severity",
                "cvss_score", "in_kev", "fixed_version", "upgrade_command"])
    for f in findings:
        w.writerow([f.package, f.version, f.ecosystem, f.cve_id, f.severity,
                    f.cvss_score, "YES" if f.in_kev else "NO", f.fixed_version,
                    f.upgrade_command])
    return buf.getvalue()


def write_pdf(findings: List[VulnFinding], docker: List[DockerFinding],
              path: str, target: str = "dependencies") -> bool:
    """Generate a PDF report. Returns True on success, False if reportlab absent
    (caller should then fall back to a .txt report)."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle)
    except ImportError:
        return False

    styles = getSampleStyleSheet()
    sev_color = {"CRITICAL": colors.red, "HIGH": colors.orange, "MEDIUM": colors.gold,
                 "LOW": colors.lightblue, "INFO": colors.grey}
    doc = SimpleDocTemplate(path, pagesize=letter)
    el = []
    el.append(Paragraph("ImgScan — Dependency & Container CVE Report",
                        styles["Title"]))
    el.append(Paragraph(f"Target: {target}", styles["Normal"]))
    el.append(Paragraph(f"Generated: {datetime.now().isoformat()}", styles["Normal"]))
    el.append(Spacer(1, 12))

    counts = {}
    kev = 0
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        if f.in_kev:
            kev += 1
    summary = (f"Total vulnerabilities: {len(findings)} | "
               f"Kev-exploited: {kev} | " +
               " ".join(f"{k}:{v}" for k, v in counts.items()))
    el.append(Paragraph(summary, styles["Heading2"]))
    el.append(Spacer(1, 8))

    data = [["Package", "Version", "CVE", "Sev", "CVSS", "KEV", "Fix"]]
    for f in findings:
        data.append([f.package, f.version, f.cve_id, f.severity,
                     str(f.cvss_score), "YES" if f.in_kev else "NO",
                     f.fixed_version])
    tbl = Table(data, repeatRows=1, colWidths=[80, 55, 95, 45, 35, 30, 60])
    st = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
          ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
          ("FONTSIZE", (0, 0), (-1, -1), 7),
          ("GRID", (0, 0), (-1, -1), 0.4, colors.grey)]
    for i, f in enumerate(findings, 1):
        st.append(("TEXTCOLOR", (3, i), (3, i), sev_color.get(f.severity, colors.black)))
    tbl.setStyle(TableStyle(st))
    el.append(tbl)

    if docker:
        el.append(Spacer(1, 14))
        el.append(Paragraph("Dockerfile Findings", styles["Heading2"]))
        ddata = [["ID", "Line", "Sev", "Issue"]]
        for d in docker:
            ddata.append([d.check_id, str(d.line_number), d.severity, d.description])
        dt = Table(ddata, repeatRows=1, colWidths=[50, 35, 50, 360])
        dt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ]))
        el.append(dt)

    doc.build(el)
    return True
