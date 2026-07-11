"""CloudSentry — report generation (JSON, CSV, PDF)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime


def _serializable(results: list) -> list[dict]:
    return [
        {
            "check_id": r.check_id, "name": r.name, "provider": r.provider,
            "category": r.category, "status": r.status, "severity": r.severity,
            "description": r.description, "risk": r.risk, "remediation": r.remediation,
            "affected": r.affected, "cis_ref": r.cis_ref, "owasp_ref": r.owasp_ref,
            "region": r.region,
        }
        for r in results
    ]


def to_json(results: list, providers=None) -> str:
    return json.dumps({
        "tool": "CloudSentry",
        "generated": datetime.utcnow().isoformat() + "Z",
        "providers": providers or sorted({r.provider for r in results}),
        "total": len(results),
        "findings": _serializable(results),
    }, indent=2)


def to_csv(results: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["check_id", "name", "provider", "category", "status", "severity",
                "affected", "description", "remediation", "cis_ref", "owasp_ref"])
    for r in results:
        w.writerow([r.check_id, r.name, r.provider, r.category, r.status, r.severity,
                    "; ".join(r.affected), r.description, r.remediation, r.cis_ref, r.owasp_ref])
    return buf.getvalue()


def to_txt(results: list, providers=None) -> str:
    lines = ["CloudSentry — Security Posture Report", "=" * 40, ""]
    for r in results:
        lines.append(f"[{r.check_id}] {r.name}  ({r.provider}/{r.category})")
        lines.append(f"  Status: {r.status} | Severity: {r.severity}")
        lines.append(f"  Description: {r.description}")
        if r.affected:
            lines.append(f"  Affected: {', '.join(r.affected)}")
        if r.remediation:
            lines.append(f"  Remediation: {r.remediation}")
        lines.append("")
    return "\n".join(lines)


def to_pdf(results: list, providers=None, path=None) -> bytes:
    """Generate a PDF remediation report (reportlab). Falls back to text if
    reportlab is unavailable."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from xml.sax.saxutils import escape
    except ImportError:
        # graceful fallback: return a text blob
        text = to_txt(results, providers).encode("utf-8")
        if path:
            with open(path, "wb") as f:
                f.write(text)
        return text

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("title", parent=styles["Title"], fontSize=18)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#0ea5e9"))
    story = [Paragraph("CloudSentry — Executive Remediation Report", title),
             Spacer(1, 6),
             Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", styles["Normal"]),
             Spacer(1, 10)]
    crit = sum(1 for r in results if r.severity == "critical" and r.status == "FAIL")
    high = sum(1 for r in results if r.severity == "high" and r.status == "FAIL")
    story.append(Paragraph(
        f"Executive summary: {len(results)} checks run. "
        f"<b>{crit}</b> critical and <b>{high}</b> high-severity failures require attention.",
        styles["Normal"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Findings & Remediation Plan", h2))
    story.append(Spacer(1, 6))
    data = [["Check", "Sev", "Status", "Affected", "Remediation"]]
    for r in results:
        if r.status in ("PASS", "INFO"):
            continue
        data.append([
            Paragraph(f"{escape(r.check_id)}<br/>{escape(r.name)}", styles["Normal"]),
            r.severity.upper(),
            r.status,
            Paragraph(escape(", ".join(r.affected[:3])), styles["Normal"]),
            Paragraph(escape(r.remediation[:200]), styles["Normal"]),
        ])
    if len(data) == 1:
        data.append(["No failing findings.", "", "", "", ""])
    t = Table(data, colWidths=[42 * mm, 16 * mm, 16 * mm, 40 * mm, 60 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0c1220")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#1a2538")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
    ]))
    story.append(t)
    doc.build(story)
    pdf = buf.getvalue()
    if path:
        with open(path, "wb") as f:
            f.write(pdf)
    return pdf
