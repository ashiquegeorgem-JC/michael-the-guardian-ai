"""Reports router - generate downloadable PDF incident reports."""

import os
import uuid
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

router = APIRouter()
REPORTS_DIR = "./reports"


class ReportRequest(BaseModel):
    session_id: Optional[str] = None
    title: Optional[str] = None
    include_raw_logs: bool = False


@router.post("/generate")
async def generate_report(req: ReportRequest):
    """Generate a PDF incident report for a session."""
    from app.services.store import store

    sid = req.session_id or store.active_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No session specified.")

    entries = store.get_entries(sid)
    anomalies = store.get_anomalies(sid)
    incidents = store.get_incidents(sid)
    metrics = store.get_metrics(sid)

    if not entries:
        raise HTTPException(status_code=400, detail="No data to report. Upload and analyse logs first.")

    os.makedirs(REPORTS_DIR, exist_ok=True)
    report_id = str(uuid.uuid4())[:8]
    filename = f"MICHAEL_Report_{report_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    try:
        _generate_pdf(
            filepath=filepath,
            session_id=sid,
            entries=entries,
            anomalies=anomalies,
            incidents=incidents,
            metrics=metrics,
            title=req.title or f"MICHAEL Guardian Report – Session {sid[:8]}",
            include_raw_logs=req.include_raw_logs,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    return {
        "report_id": report_id,
        "filename": filename,
        "download_url": f"/api/reports/download/{filename}",
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/download/{filename}")
async def download_report(filename: str):
    """Download a generated report PDF."""
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        filepath,
        media_type="application/pdf",
        filename=filename,
    )


def _generate_pdf(filepath, session_id, entries, anomalies, incidents, metrics, title, include_raw_logs):
    """Generate PDF using ReportLab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from collections import Counter

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    NAVY = colors.HexColor("#0A0E1A")
    BLUE = colors.HexColor("#3B82F6")
    RED = colors.HexColor("#EF4444")
    GREEN = colors.HexColor("#10B981")
    AMBER = colors.HexColor("#F59E0B")
    GREY = colors.HexColor("#94A3B8")

    title_style = ParagraphStyle("title", parent=styles["Title"], textColor=NAVY, fontSize=22, spaceAfter=6)
    h2_style = ParagraphStyle("h2", parent=styles["Heading2"], textColor=BLUE, fontSize=14, spaceBefore=12, spaceAfter=6)
    body_style = ParagraphStyle("body", parent=styles["Normal"], fontSize=10, spaceAfter=4)
    note_style = ParagraphStyle("note", parent=styles["Normal"], fontSize=9, textColor=GREY, spaceAfter=4)

    story = []

    # ── Cover ──────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("MICHAEL – THE GUARDIAN AI", title_style))
    story.append(Paragraph(title, styles["Heading2"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", note_style))
    story.append(Paragraph(f"Session ID: {session_id}", note_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE))
    story.append(Spacer(1, 0.5*cm))

    # ── Executive Summary ───────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2_style))
    level_dist = Counter(e.level.value for e in entries)
    severity_dist = Counter(i.severity for i in incidents)

    summary_data = [
        ["Metric", "Value"],
        ["Total Log Entries", str(len(entries))],
        ["Anomalies Detected", str(len(anomalies))],
        ["Total Incidents", str(len(incidents))],
        ["Critical Incidents", str(severity_dist.get("CRITICAL", 0))],
        ["High Severity", str(severity_dist.get("HIGH", 0))],
        ["Medium Severity", str(severity_dist.get("MEDIUM", 0))],
        ["Error Log Entries", str(level_dist.get("ERROR", 0))],
        ["Critical Log Entries", str(level_dist.get("CRITICAL", 0))],
    ]
    if metrics:
        summary_data.append(["Analysis Duration (s)", str(metrics.analysis_duration_seconds)])

    t = Table(summary_data, colWidths=[8*cm, 8*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    # ── Incidents ───────────────────────────────────────────────────────────────
    story.append(Paragraph("Incident Details", h2_style))
    story.append(Paragraph(
        "Evidence rows are grounded in actual log data. "
        "Root cause and impact marked [AI HYPOTHESIS] are AI-generated and require human verification.",
        note_style,
    ))
    story.append(Spacer(1, 0.3*cm))

    sev_hex = {"CRITICAL": "#EF4444", "HIGH": "#F59E0B", "MEDIUM": "#F97316", "LOW": "#10B981"}

    for incident in incidents[:20]:  # Cap at 20
        color_hex = sev_hex.get(incident.severity, "#94A3B8")
        story.append(Paragraph(
            f'<font color="{color_hex}"><b>[{incident.severity}]</b></font> {incident.title}',
            styles["Heading3"],
        ))
        story.append(Paragraph(f"Category: {incident.category.value} | Status: {incident.status.value}", note_style))
        story.append(Paragraph(f"First seen: {incident.first_seen}", note_style))
        story.append(Paragraph(f"Description: {incident.description}", body_style))

        if incident.evidence:
            story.append(Paragraph("<b>Evidence (from log data):</b>", body_style))
            for ev in incident.evidence[:3]:
                story.append(Paragraph(f"  • {ev[:200]}", note_style))

        story.append(Paragraph(f"<b>Root Cause:</b> {incident.root_cause_hypothesis[:500]}", body_style))
        story.append(Paragraph(f"<b>Impact:</b> {incident.potential_impact[:300]}", body_style))

        if incident.remediation_steps:
            story.append(Paragraph("<b>Remediation Steps:</b>", body_style))
            for step in incident.remediation_steps[:5]:
                story.append(Paragraph(f"  {step}", note_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        story.append(Spacer(1, 0.2*cm))

    # ── Model Metrics ───────────────────────────────────────────────────────────
    if metrics:
        story.append(PageBreak())
        story.append(Paragraph("ML Model Evaluation", h2_style))
        ml_data = [
            ["Parameter", "Value"],
            ["Detection Methods", ", ".join(metrics.detection_methods)],
            ["Contamination Rate", str(metrics.contamination_rate)],
            ["Total Logs Analysed", str(metrics.total_logs)],
            ["Anomalies Found", str(metrics.anomalies_detected)],
            ["Analysis Duration", f"{metrics.analysis_duration_seconds}s"],
            ["Evaluated At", metrics.evaluated_at.strftime("%Y-%m-%d %H:%M UTC")],
        ]
        t2 = Table(ml_data, colWidths=[8*cm, 8*cm])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t2)

        if metrics.tfidf_top_terms:
            story.append(Spacer(1, 0.5*cm))
            story.append(Paragraph("Top TF-IDF Terms (Most Significant Log Keywords)", h2_style))
            tf_data = [["Term", "TF-IDF Score"]] + [
                [t["term"], f"{t['score']:.4f}"] for t in metrics.tfidf_top_terms[:10]
            ]
            t3 = Table(tf_data, colWidths=[10*cm, 6*cm])
            t3.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(t3)

    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        "MICHAEL – The Guardian AI | Intelligent Log Analysis and Anomaly Detection | "
        "Confidential – For Authorized Use Only",
        note_style,
    ))

    doc.build(story)
