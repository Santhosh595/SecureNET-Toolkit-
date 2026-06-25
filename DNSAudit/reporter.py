"""DNSAudit - Reporter Module (PDF Report Generation)"""

from __future__ import annotations
from typing import Optional


def generate_pdf_report(domain: str, findings: dict, output_path: str,
                         grade: str = "", score: int = 0) -> None:
    """Generate a comprehensive PDF remediation report.

    Args:
        domain: Scanned domain.
        findings: Dict of category -> list of finding dicts.
        output_path: Path to save PDF.
        grade: Overall grade.
        score: Overall score.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, PageBreak)
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    except ImportError:
        print("[!] reportlab not installed. Run: pip install reportlab")
        return

    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle("CustomTitle", parent=styles["Title"],
                                  fontSize=24, spaceAfter=20)
    story.append(Paragraph(f"DNS Security Audit Report", title_style))
    story.append(Spacer(1, 10*mm))
    story.append(Paragraph(f"Domain: {domain}", styles["Normal"]))
    story.append(Paragraph(f"Grade: {grade} ({score}/100)", styles["Normal"]))
    story.append(Spacer(1, 10*mm))

    # Summary
    critical = sum(1 for cat in findings.values() for f in cat if f.get("severity") == "CRITICAL")
    high = sum(1 for cat in findings.values() for f in cat if f.get("severity") == "HIGH")
    medium = sum(1 for cat in findings.values() for f in cat if f.get("severity") == "MEDIUM")

    summary_data = [
        ["Metric", "Count"],
        ["Critical Findings", str(critical)],
        ["High Findings", str(high)],
        ["Medium Findings", str(medium)],
    ]
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a2538")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#e2e8f0")),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#243044")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10*mm))

    # Findings per category
    for category, cat_findings in findings.items():
        if not cat_findings:
            continue
        story.append(Paragraph(f"<b>{category}</b>", styles["Heading2"]))
        finding_data = [["Severity", "Check", "Description"]]
        for f in cat_findings:
            finding_data.append([
                f.get("severity", ""),
                f.get("check", ""),
                f.get("description", "")[:80],
            ])
        finding_table = Table(finding_data, repeatRows=1)
        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a2538")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#243044")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(finding_table)
        story.append(Spacer(1, 6*mm))

    # Disclaimer
    story.append(Spacer(1, 10*mm))
    story.append(Paragraph(
        "<i>This report is for authorized security auditing only. "
        "All checks are read-only passive queries.</i>",
        styles["Italic"]
    ))

    doc.build(story)
