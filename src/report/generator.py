"""
PDF report generator for STRIDE threat modeling results.
Produces a professional PDF document with all threat findings and recommendations.
"""

import io
import os
from datetime import datetime
from typing import Optional

import numpy as np
from PIL import Image

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.platypus import Image as RLImage
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

from src.vulnerabilities.database import STRIDE

# ── colour palette ────────────────────────────────────────────────────────────
C_PRIMARY    = colors.HexColor("#1A237E")   # deep blue
C_SECONDARY  = colors.HexColor("#283593")
C_ACCENT     = colors.HexColor("#E53935")   # red for critical
C_HEADER_BG  = colors.HexColor("#1A237E")
C_ROW_ALT    = colors.HexColor("#F5F5F5")
C_CRITICAL   = colors.HexColor("#B71C1C")
C_HIGH       = colors.HexColor("#E53935")
C_MEDIUM     = colors.HexColor("#FB8C00")
C_LOW        = colors.HexColor("#43A047")
C_UNKNOWN    = colors.HexColor("#757575")

SEVERITY_COLORS = {
    "Critical": C_CRITICAL,
    "High":     C_HIGH,
    "Medium":   C_MEDIUM,
    "Low":      C_LOW,
}

STRIDE_FULL = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}


def _styles():
    ss = getSampleStyleSheet()
    base = ss["Normal"]

    custom = {
        "Title": ParagraphStyle("Title", parent=base, fontSize=26, textColor=C_PRIMARY,
                                spaceAfter=6, alignment=TA_CENTER, fontName="Helvetica-Bold"),
        "Subtitle": ParagraphStyle("Subtitle", parent=base, fontSize=13, textColor=C_SECONDARY,
                                   spaceAfter=4, alignment=TA_CENTER),
        "H1": ParagraphStyle("H1", parent=base, fontSize=16, textColor=C_PRIMARY,
                              spaceBefore=14, spaceAfter=6, fontName="Helvetica-Bold"),
        "H2": ParagraphStyle("H2", parent=base, fontSize=13, textColor=C_SECONDARY,
                              spaceBefore=10, spaceAfter=4, fontName="Helvetica-Bold"),
        "H3": ParagraphStyle("H3", parent=base, fontSize=11, textColor=colors.black,
                              spaceBefore=6, spaceAfter=3, fontName="Helvetica-Bold"),
        "Body": ParagraphStyle("Body", parent=base, fontSize=10, leading=15,
                               spaceAfter=4, alignment=TA_JUSTIFY),
        "Bullet": ParagraphStyle("Bullet", parent=base, fontSize=10, leading=14,
                                 leftIndent=16, bulletIndent=8, spaceAfter=2),
        "Small": ParagraphStyle("Small", parent=base, fontSize=8, textColor=colors.grey),
        "SevCritical": ParagraphStyle("SevCritical", parent=base, fontSize=10,
                                      textColor=C_CRITICAL, fontName="Helvetica-Bold"),
        "SevHigh":     ParagraphStyle("SevHigh", parent=base, fontSize=10,
                                      textColor=C_HIGH, fontName="Helvetica-Bold"),
        "SevMedium":   ParagraphStyle("SevMedium", parent=base, fontSize=10,
                                      textColor=C_MEDIUM, fontName="Helvetica-Bold"),
        "SevLow":      ParagraphStyle("SevLow", parent=base, fontSize=10,
                                      textColor=C_LOW, fontName="Helvetica-Bold"),
    }
    return custom


def _severity_para(text: str, styles: dict) -> Paragraph:
    key = f"Sev{text}" if f"Sev{text}" in styles else "Body"
    return Paragraph(text, styles.get(key, styles["Body"]))


class ReportGenerator:
    PAGE_W, PAGE_H = A4

    def __init__(self):
        self.styles = _styles()

    def generate(
        self,
        analysis: dict,
        annotated_image: Optional[np.ndarray],
        output_path: str = "stride_report.pdf",
    ) -> str:
        """
        Generate a full PDF threat modeling report.

        Args:
            analysis: output from StrideAnalyzer.analyze()
            annotated_image: BGR numpy array with bounding boxes (can be None)
            output_path: destination PDF path

        Returns:
            Absolute path to the generated PDF
        """
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2.5*cm, bottomMargin=2*cm,
        )
        story = []
        s = self.styles

        # ── Cover ─────────────────────────────────────────────────────────────
        story += self._cover(analysis, s)

        # ── Annotated image ───────────────────────────────────────────────────
        if annotated_image is not None:
            story += self._image_section(annotated_image, s)

        # ── Executive Summary ─────────────────────────────────────────────────
        story += self._exec_summary(analysis, s)

        # ── Detected components ───────────────────────────────────────────────
        story += self._components_section(analysis, s)

        # ── STRIDE matrix ─────────────────────────────────────────────────────
        story += self._stride_matrix(analysis, s)

        # ── Threats by component ──────────────────────────────────────────────
        story += self._threats_detail(analysis, s)

        # ── Data flow threats ─────────────────────────────────────────────────
        story += self._dataflow_threats(analysis, s)

        # ── Recommendations ───────────────────────────────────────────────────
        story += self._recommendations(analysis, s)

        # ── Footer note ───────────────────────────────────────────────────────
        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", color=colors.lightgrey))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            "Generated by STRIDE AI Threat Modeling System · FIAP Software Security Hackathon 2025",
            s["Small"]
        ))

        doc.build(story)
        return os.path.abspath(output_path)

    # ── Section builders ───────────────────────────────────────────────────────

    def _cover(self, analysis: dict, s: dict) -> list:
        risk = analysis.get("risk_level", "Unknown")
        risk_color = SEVERITY_COLORS.get(risk, C_UNKNOWN)

        story = [
            Spacer(1, 2*cm),
            Paragraph("STRIDE THREAT MODELING REPORT", s["Title"]),
            Paragraph("AI-Powered Architecture Security Analysis", s["Subtitle"]),
            Spacer(1, 0.5*cm),
            HRFlowable(width="80%", color=C_PRIMARY, thickness=2),
            Spacer(1, 0.5*cm),
        ]

        meta = [
            ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M")],
            ["Methodology:", "STRIDE (Microsoft Threat Modeling)"],
            ["Components Detected:", str(len(analysis.get("components", [])))],
            ["Overall Risk Level:", risk],
        ]
        tbl = Table(meta, colWidths=[5*cm, 10*cm])
        tbl.setStyle(TableStyle([
            ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 10),
            ("FONT", (1, 0), (1, -1), "Helvetica", 10),
            ("TEXTCOLOR", (1, 3), (1, 3), risk_color),
            ("FONT", (1, 3), (1, 3), "Helvetica-Bold", 10),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, C_ROW_ALT]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        story += [Spacer(1, 1*cm), tbl, PageBreak()]
        return story

    def _image_section(self, annotated_image: np.ndarray, s: dict) -> list:
        from PIL import Image as PILImage
        import cv2

        story = [Paragraph("Analyzed Architecture Diagram", s["H1"])]
        story.append(Paragraph(
            "Bounding boxes highlight components detected by the YOLOv8 model.", s["Small"]
        ))
        story.append(Spacer(1, 0.3*cm))

        rgb = cv2.cvtColor(annotated_image, cv2.COLOR_BGR2RGB)
        pil_img = PILImage.fromarray(rgb)
        buf = io.BytesIO()
        pil_img.save(buf, format="PNG")
        buf.seek(0)

        max_w = 16 * cm
        max_h = 10 * cm
        iw, ih = pil_img.size
        ratio = min(max_w / iw, max_h / ih)
        rl_img = RLImage(buf, width=iw * ratio, height=ih * ratio)
        story += [rl_img, Spacer(1, 0.5*cm)]
        return story

    def _exec_summary(self, analysis: dict, s: dict) -> list:
        story = [Paragraph("Executive Summary", s["H1"])]

        ai_text = analysis.get("ai_analysis", "No AI analysis available.")
        for para in ai_text.split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), s["Body"]))

        # severity counts table
        counts = analysis.get("severity_counts", {})
        if counts:
            story.append(Spacer(1, 0.4*cm))
            story.append(Paragraph("Risk Summary", s["H2"]))
            rows = [["Severity", "Count"]]
            for sev in ["Critical", "High", "Medium", "Low"]:
                rows.append([sev, str(counts.get(sev, 0))])
            tbl = Table(rows, colWidths=[8*cm, 5*cm])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), C_HEADER_BG),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("FONT",       (0, 0), (-1, 0), "Helvetica-Bold", 10),
                ("FONT",       (0, 1), (-1, -1), "Helvetica", 10),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TEXTCOLOR", (0, 1), (0, 1), C_CRITICAL),
                ("TEXTCOLOR", (0, 2), (0, 2), C_HIGH),
                ("TEXTCOLOR", (0, 3), (0, 3), C_MEDIUM),
                ("TEXTCOLOR", (0, 4), (0, 4), C_LOW),
                ("FONT", (0, 1), (0, 4), "Helvetica-Bold", 10),
            ]))
            story.append(tbl)
        return story

    def _components_section(self, analysis: dict, s: dict) -> list:
        story = [
            Spacer(1, 0.5*cm),
            Paragraph("Detected Architecture Components", s["H1"]),
        ]
        counts = analysis.get("component_counts", {})
        if not counts:
            story.append(Paragraph("No components detected.", s["Body"]))
            return story

        rows = [["Component Type", "Instances"]]
        for comp, cnt in sorted(counts.items()):
            rows.append([comp.replace("_", " ").title(), str(cnt)])

        tbl = Table(rows, colWidths=[10*cm, 5*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_HEADER_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONT",       (0, 0), (-1, 0), "Helvetica-Bold", 10),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(tbl)
        return story

    def _stride_matrix(self, analysis: dict, s: dict) -> list:
        story = [
            Spacer(1, 0.5*cm),
            Paragraph("STRIDE Threat Matrix", s["H1"]),
            Paragraph(
                "Threats grouped by STRIDE category across all detected components.", s["Body"]
            ),
        ]
        stride_summary = analysis.get("stride_summary", {})

        rows = [["Category", "Category Name", "Identified Threats"]]
        for cat, full_name in STRIDE_FULL.items():
            threats = stride_summary.get(cat, [])
            if threats:
                threats_text = "\n".join(f"• {t}" for t in threats)
            else:
                threats_text = "None identified"
            rows.append([cat, full_name, threats_text])

        col_widths = [1.5*cm, 4*cm, 11*cm]
        tbl = Table(rows, colWidths=col_widths)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), C_HEADER_BG),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONT",         (0, 0), (-1, 0), "Helvetica-Bold", 10),
            ("FONT",         (0, 1), (1, -1), "Helvetica-Bold", 9),
            ("FONT",         (2, 1), (2, -1), "Helvetica", 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(tbl)
        return story

    def _threats_detail(self, analysis: dict, s: dict) -> list:
        story = [
            PageBreak(),
            Paragraph("Detailed Threat Analysis by Component", s["H1"]),
        ]
        threats_by_component = analysis.get("threats_by_component", {})

        for comp, threats in threats_by_component.items():
            comp_title = comp.replace("_", " ").title()
            story.append(Spacer(1, 0.4*cm))
            story.append(Paragraph(f"{comp_title}", s["H2"]))

            for t in threats:
                sev = t.get("severity", "Low")
                sev_color = SEVERITY_COLORS.get(sev, C_UNKNOWN)

                block = [
                    Paragraph(f"{STRIDE_FULL.get(t['stride_category'], t['stride_category'])} — {t['threat_name']}", s["H3"]),
                ]

                meta_rows = [
                    ["STRIDE:", t["stride_category"], "Severity:", sev],
                    ["CWEs:", ", ".join(t.get("cwe_ids", [])), "", ""],
                ]
                meta_tbl = Table(meta_rows, colWidths=[2*cm, 5*cm, 2*cm, 5*cm])
                meta_tbl.setStyle(TableStyle([
                    ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
                    ("FONT", (2, 0), (2, -1), "Helvetica-Bold", 9),
                    ("FONT", (1, 0), (1, -1), "Helvetica", 9),
                    ("FONT", (3, 0), (3, -1), "Helvetica-Bold", 9),
                    ("TEXTCOLOR", (3, 0), (3, 0), sev_color),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]))
                block.append(meta_tbl)
                block.append(Paragraph(t["description"], s["Body"]))
                block.append(Paragraph("Countermeasures:", s["H3"]))
                for cm_item in t.get("countermeasures", []):
                    block.append(Paragraph(f"• {cm_item}", s["Bullet"]))

                story.append(KeepTogether(block))
                story.append(HRFlowable(width="100%", color=colors.lightgrey, thickness=0.5))

        return story

    def _dataflow_threats(self, analysis: dict, s: dict) -> list:
        df_threats = analysis.get("data_flow_threats", [])
        if not df_threats:
            return []

        story = [
            Spacer(1, 0.5*cm),
            Paragraph("Data Flow Threat Analysis", s["H1"]),
            Paragraph("Threats identified along component communication paths.", s["Body"]),
        ]

        rows = [["Data Flow", "STRIDE", "Severity", "Threat", "Countermeasure"]]
        for dft in df_threats:
            sev = dft.get("severity", "Low")
            rows.append([
                dft.get("flow", ""),
                dft.get("stride_category", ""),
                sev,
                dft.get("threat", ""),
                dft.get("countermeasure", ""),
            ])

        col_widths = [3.5*cm, 1.5*cm, 1.8*cm, 5*cm, 5*cm]
        tbl = Table(rows, colWidths=col_widths)

        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), C_HEADER_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONT",       (0, 0), (-1, 0), "Helvetica-Bold", 9),
            ("FONT",       (0, 1), (-1, -1), "Helvetica", 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("WORDWRAP",   (0, 0), (-1, -1), True),
        ]
        for i, dft in enumerate(df_threats, start=1):
            sev = dft.get("severity", "Low")
            c = SEVERITY_COLORS.get(sev, C_UNKNOWN)
            style_cmds.append(("TEXTCOLOR", (2, i), (2, i), c))
            style_cmds.append(("FONT", (2, i), (2, i), "Helvetica-Bold", 8))

        tbl.setStyle(TableStyle(style_cmds))
        story.append(tbl)
        return story

    def _recommendations(self, analysis: dict, s: dict) -> list:
        recs = analysis.get("recommendations", [])
        if not recs:
            return []

        story = [
            PageBreak(),
            Paragraph("Security Recommendations", s["H1"]),
            Paragraph(
                "Prioritized list of security improvements based on the threat analysis.", s["Body"]
            ),
            Spacer(1, 0.3*cm),
        ]

        rows = [["#", "Action", "Rationale", "Effort", "Impact"]]
        for r in recs:
            rows.append([
                str(r.get("priority", "")),
                r.get("action", ""),
                r.get("rationale", ""),
                r.get("effort", ""),
                r.get("impact", ""),
            ])

        col_widths = [0.8*cm, 5*cm, 5.5*cm, 2*cm, 2*cm]
        tbl = Table(rows, colWidths=col_widths)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_HEADER_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONT",       (0, 0), (-1, 0), "Helvetica-Bold", 9),
            ("FONT",       (0, 1), (-1, -1), "Helvetica", 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(tbl)
        return story


def generate_report(analysis: dict, annotated_image, output_path: str = "stride_report.pdf") -> str:
    gen = ReportGenerator()
    return gen.generate(analysis, annotated_image, output_path)
