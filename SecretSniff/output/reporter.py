"""SecretSniff — PDF report generation."""

from __future__ import annotations
from typing import Any


def generate_pdf_report(findings: list[dict], output_path: str,
                         target: str = "", scan_type: str = "file") -> None:
    """Generate PDF report.

    Args:
        findings: List of finding dicts.
        output_path: Path to save PDF.
        target: Scan target.
        scan_type: Type of scan.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
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
    story.append(Paragraph("SecretSniff Security Report", title_style))
    story.append(Spacer(1, 10*mm))
    story.append(Paragraph(f"Target: {target}", styles["Normal"]))
    story.append(Paragraph(f"Scan Type: {scan_type}", styles["Normal"]))
    story.append(Spacer(1, 10*mm))

    # Summary
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low = sum(1 for f in findings if f.get("severity") == "LOW")

    summary_data = [
        ["Metric", "Count"],
        ["Total Findings", str(len(findings))],
        ["Critical", str(critical)],
        ["High", str(high)],
        ["Medium", str(medium)],
        ["Low", str(low)],
    ]
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a2538")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#e2e8f0")),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#243044")),
        ("BACKGROUND", (0, 1), (-1, -1), HexColor("#0c1220")),
        ("TEXTCOLOR", (0, 1), (-1, -1), HexColor("#e2e8f0")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10*mm))

    # Findings table
    if findings:
        findings_data = [["File", "Line", "Rule", "Severity", "Value"]]
        for f in findings[:100]:  # Limit to 100 for PDF
            findings_data.append([
                f.get("file", "")[:40],
                str(f.get("line", "")),
                f.get("rule", "")[:30],
                f.get("severity", ""),
                f.get("value_redacted", "")[:30],
            ])
        findings_table = Table(findings_data, repeatRows=1)
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a2538")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#243044")),
            ("BACKGROUND", (0, 1), (-1, -1), HexColor("#0c1220")),
            ("TEXTCOLOR", (0, 1), (-1, -1), HexColor("#e2e8f0")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(findings_table)

    doc.build(story)
