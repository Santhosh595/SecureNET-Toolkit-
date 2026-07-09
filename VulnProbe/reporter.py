"""Report generation -- JSON, CSV, and PDF (executive summary + findings)."""

from __future__ import annotations

import csv
import io
import json
import time
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 9), f.get("template_id", "")),
    )


def to_json(findings: list[dict], scan_meta: dict | None = None) -> str:
    payload = {
        "tool": "VulnProbe",
        "generated_at": time.time(),
        "scan": scan_meta or {},
        "findings_count": len(findings),
        "findings": _sort_findings(findings),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_csv(findings: list[dict]) -> str:
    buf = io.StringIO()
    fields = [
        "severity", "template_id", "name", "category", "url", "matched_path",
        "matched_condition", "status_code", "response_size", "response_ms",
        "method", "extracted", "timestamp", "remediation",
    ]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for f in _sort_findings(findings):
        row = dict(f)
        row["extracted"] = json.dumps(f.get("extracted") or {}, ensure_ascii=False)
        writer.writerow(row)
    return buf.getvalue()


def to_pdf(findings: list[dict], scan_meta: dict | None = None, path: str | None = None) -> str:
    """Build a PDF report. Returns the path written. Requires reportlab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
        )
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "reportlab is required for PDF export: pip install reportlab"
        ) from e

    findings = _sort_findings(findings)
    path = path or str(
        Path(__file__).resolve().parent
        / f"vulnprobe_report_{int(time.time())}.pdf"
    )

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title="VulnProbe Security Report",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="VPH1", parent=styles["Heading1"], textColor=colors.HexColor("#0ea5e9")))
    styles.add(ParagraphStyle(name="VPMeta", parent=styles["Normal"], fontSize=9, textColor=colors.grey))
    title_style = styles["VPH1"]
    normal = styles["Normal"]

    sev_color = {
        "critical": colors.HexColor("#b91c1c"),
        "high": colors.HexColor("#ea580c"),
        "medium": colors.HexColor("#ca8a04"),
        "low": colors.HexColor("#0891b2"),
        "info": colors.HexColor("#64748b"),
    }

    story = []
    story.append(Paragraph("VulnProbe Vulnerability Report", title_style))
    meta = scan_meta or {}
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Target: <b>{meta.get('target', 'N/A')}</b><br/>"
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}<br/>"
        f"Templates run: {meta.get('templates_run', 'N/A')} &nbsp;|&nbsp; "
        f"Scan time: {meta.get('duration', 0):.1f}s",
        styles["VPMeta"],
    ))
    story.append(Spacer(1, 10))

    # Executive summary
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    summary_rows = [["Severity", "Count"]]
    for sev in ("critical", "high", "medium", "low", "info"):
        summary_rows.append([sev.capitalize(), str(sev_counts.get(sev, 0))])
    summary_rows.append(["Total", str(len(findings))])
    t = Table(summary_rows, colWidths=[40 * mm, 30 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    if not findings:
        story.append(Paragraph("No findings matched the loaded templates.", normal))
    else:
        story.append(Paragraph("Findings & Remediation", styles["Heading2"]))
        story.append(Spacer(1, 6))
        for f in findings:
            c = sev_color.get(f.get("severity", "info"), colors.black)
            hdr = Table(
                [[
                    Paragraph(f"<b>{f.get('name')}</b>", normal),
                    Paragraph(f"<font color='{c.hexval()}'><b>{f.get('severity', '').upper()}</b></font>", normal),
                ]],
                colWidths=[140 * mm, 30 * mm],
            )
            hdr.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("LINEBELOW", (0, 0), (-1, -1), 0.6, c),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(hdr)
            extracted = f.get("extracted") or {}
            ext_str = ", ".join(f"{k}={v}" for k, v in extracted.items()) if extracted else "-"
            detail = (
                f"<b>Template:</b> {f.get('template_id')} &nbsp; "
                f"<b>Category:</b> {f.get('category')}<br/>"
                f"<b>URL:</b> {f.get('url')}{f.get('matched_path', '')}<br/>"
                f"<b>Matched on:</b> {f.get('matched_condition')} &nbsp; "
                f"<b>HTTP:</b> {f.get('status_code')} &nbsp; "
                f"<b>Size:</b> {f.get('response_size')}B &nbsp; "
                f"<b>Time:</b> {f.get('response_ms')}ms<br/>"
                f"<b>Extracted:</b> {ext_str}"
            )
            story.append(Paragraph(detail, normal))
            rem = f.get("remediation") or "No remediation guidance provided."
            story.append(Paragraph(f"<b>Remediation:</b> {rem}", normal))
            story.append(Spacer(1, 8))

    doc.build(story)
    return path
