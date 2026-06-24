"""SecretSniff - PDF report generation.

Generates comprehensive PDF reports with findings and remediation guidance.
"""

from __future__ import annotations
from typing import Any, Optional


# Remediation guidance per rule category
REMEDIATION = {
    "AWS": {
        "danger": "AWS keys provide full access to AWS resources. Leaked keys can lead to data breaches, resource abuse, and financial loss.",
        "immediate": "Revoke the key in IAM console immediately. Rotate to new key.",
        "fix": "Use AWS Secrets Manager or Parameter Store. Prefer IAM roles over static keys.",
        "tools": "AWS Secrets Manager, AWS Systems Manager Parameter Store",
    },
    "GCP": {
        "danger": "GCP API keys can access cloud resources. Service account keys have broad permissions.",
        "immediate": "Delete the key in GCP Console. Create new key with minimal permissions.",
        "fix": "Use Workload Identity or Application Default Credentials instead of service account keys.",
        "tools": "GCP Secret Manager, Workload Identity",
    },
    "GitHub": {
        "danger": "GitHub tokens provide access to repositories. Leaked tokens can expose source code and modify code.",
        "immediate": "Revoke the token in GitHub Settings > Developer settings > Personal access tokens.",
        "fix": "Use GitHub App installations or fine-grained tokens with minimal scopes.",
        "tools": "GitHub Apps, Doppler, HashiCorp Vault",
    },
    "Stripe": {
        "danger": "Live Stripe keys can process payments and access financial data.",
        "immediate": "Rotate the key in Stripe Dashboard immediately.",
        "fix": "Use environment variables for keys. Never commit live keys.",
        "tools": "Stripe Dashboard, environment variables",
    },
    "OpenAI": {
        "danger": "OpenAI API keys can be used to consume API credits and access services.",
        "immediate": "Revoke the key in OpenAI Platform > API keys.",
        "fix": "Use environment variables or a secrets manager for API keys.",
        "tools": "OpenAI Platform, HashiCorp Vault, Doppler",
    },
    "default": {
        "danger": "Leaked credentials can be exploited for unauthorized access, data theft, or service abuse.",
        "immediate": "Revoke or rotate the exposed credential immediately.",
        "fix": "Move secrets to environment variables or a dedicated secrets manager.",
        "tools": "HashiCorp Vault, AWS Secrets Manager, Doppler, 1Password Secrets",
    },
}


def get_remediation(rule_name: str) -> dict:
    """Get remediation guidance for a rule."""
    for key, guidance in REMEDIATION.items():
        if key.lower() in rule_name.lower():
            return guidance
    return REMEDIATION["default"]


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
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
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
        for f in findings[:200]:  # Limit to 200 for PDF
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

        # Remediation section
        story.append(PageBreak())
        story.append(Paragraph("Remediation Guidance", styles["Heading1"]))
        story.append(Spacer(1, 5*mm))

        # Get unique rules
        seen_rules = set()
        for f in findings:
            rule = f.get("rule", "")
            if rule in seen_rules:
                continue
            seen_rules.add(rule)
            rem = get_remediation(rule)
            story.append(Paragraph(f"<b>{rule}</b>", styles["Heading3"]))
            story.append(Paragraph(f"<b>Why it is dangerous:</b> {rem['danger']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Immediate action:</b> {rem['immediate']}", styles["Normal"]))
            story.append(Paragraph(f"<b>How to fix:</b> {rem['fix']}", styles["Normal"]))
            story.append(Paragraph(f"<b>Recommended tools:</b> {rem['tools']}", styles["Normal"]))
            story.append(Spacer(1, 5*mm))

    # Disclaimer
    story.append(Spacer(1, 10*mm))
    story.append(Paragraph(
        "<i>SecretSniff is for scanning repositories you own or have explicit authorization to audit. "
        "All scanning is performed locally. No data is transmitted externally.</i>",
        styles["Italic"]
    ))

    doc.build(story)
