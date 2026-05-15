"""AEGIS SOC — PDF Report Generator (ReportLab)"""
import os
from backend.config import settings

async def generate_pdf_report(incident_id: str, report_md: str, state: dict) -> str:
    """Generate a PDF incident report. Returns the file path."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
    except ImportError:
        # Fallback: save as text
        path = os.path.join(settings.reports_dir, f"{incident_id}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(report_md)
        return path

    path = os.path.join(settings.reports_dir, f"{incident_id}.pdf")
    doc = SimpleDocTemplate(path, pagesize=A4,
                            topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title2", parent=styles["Title"],
                                  textColor=HexColor("#1a1a2e"), fontSize=18)
    body_style = ParagraphStyle("Body2", parent=styles["Normal"],
                                 fontSize=10, leading=14)
    story = []
    story.append(Paragraph(f"🛡️ AEGIS SOC — Incident Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph(f"<b>Incident ID:</b> {incident_id}", body_style))
    story.append(Paragraph(f"<b>Severity:</b> {state.get('severity','N/A')}", body_style))
    story.append(Paragraph(f"<b>Confidence:</b> {state.get('confidence',0):.0%}", body_style))
    story.append(Paragraph(f"<b>Decision:</b> {state.get('decision','N/A')}", body_style))
    story.append(Spacer(1, 0.2*inch))

    # Convert markdown lines to paragraphs
    for line in report_md.split("\n"):
        line = line.strip()
        if not line:
            story.append(Spacer(1, 0.1*inch))
        elif line.startswith("# "):
            story.append(Paragraph(line[2:], styles["Heading1"]))
        elif line.startswith("## "):
            story.append(Paragraph(line[3:], styles["Heading2"]))
        elif line.startswith("### "):
            story.append(Paragraph(line[4:], styles["Heading3"]))
        else:
            # Escape XML special chars for ReportLab
            safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(safe, body_style))

    doc.build(story)
    return path
