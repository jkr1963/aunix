"""
PDF audit report generation using ReportLab.

Two report types:
  - per-machine: detailed audit of one target
  - fleet:       executive summary across all of a user's targets

The visual style matches the dashboard: navy/slate base palette with
severity colors only where they convey information. Layout is built
with platypus flowables so content flows across pages naturally.
"""

from datetime import datetime
from io import BytesIO
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend


# --- Palette (mirrors styles.css) ---
NAVY = colors.HexColor("#1f3a64")
INK = colors.HexColor("#1a2942")
INK_SOFT = colors.HexColor("#4a5b75")
INK_MUTED = colors.HexColor("#7a8aa3")
INK_FAINT = colors.HexColor("#aab5c5")
SURFACE_ALT = colors.HexColor("#f0f3f8")
BORDER = colors.HexColor("#dde3ec")

SEV_CRITICAL = colors.HexColor("#a01e25")
SEV_CRITICAL_BG = colors.HexColor("#fdeeee")
SEV_HIGH = colors.HexColor("#b45309")
SEV_HIGH_BG = colors.HexColor("#fdf3e6")
SEV_MEDIUM = colors.HexColor("#8c6c12")
SEV_MEDIUM_BG = colors.HexColor("#fbf7e8")
GOOD = colors.HexColor("#2d6a3e")
GOOD_BG = colors.HexColor("#ecf4ee")


def _styles():
    """Pre-built paragraph styles used across the report."""
    base = getSampleStyleSheet()

    s = {
        "brand": ParagraphStyle(
            "brand", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=22, leading=26,
            textColor=NAVY, alignment=TA_LEFT, spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"],
            fontName="Helvetica", fontSize=10, leading=12,
            textColor=INK_SOFT, spaceAfter=18,
        ),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"],
            fontName="Helvetica-Bold", fontSize=15, leading=18,
            textColor=INK, spaceBefore=14, spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"],
            fontName="Helvetica-Bold", fontSize=11, leading=14,
            textColor=INK_SOFT, spaceBefore=10, spaceAfter=6,
            keepWithNext=True,
        ),
        "label": ParagraphStyle(
            "label", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=8, leading=10,
            textColor=INK_SOFT, spaceAfter=2,
        ),
        "value": ParagraphStyle(
            "value", parent=base["Normal"],
            fontName="Helvetica", fontSize=10, leading=13,
            textColor=INK,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"],
            fontName="Helvetica", fontSize=9.5, leading=13,
            textColor=INK_SOFT, spaceAfter=6,
        ),
        "narrative": ParagraphStyle(
            "narrative", parent=base["Normal"],
            fontName="Helvetica", fontSize=10, leading=14,
            textColor=INK,
        ),
        "evidence": ParagraphStyle(
            "evidence", parent=base["Normal"],
            fontName="Courier", fontSize=8, leading=10,
            textColor=INK_MUTED, leftIndent=8, spaceAfter=2,
        ),
        "fix": ParagraphStyle(
            "fix", parent=base["Normal"],
            fontName="Helvetica-Oblique", fontSize=9, leading=12,
            textColor=GOOD, leftIndent=8, spaceAfter=4,
        ),
        "finding_title": ParagraphStyle(
            "finding_title", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=10, leading=12,
            textColor=INK, spaceAfter=2,
        ),
        "finding_desc": ParagraphStyle(
            "finding_desc", parent=base["Normal"],
            fontName="Helvetica", fontSize=9, leading=11,
            textColor=INK_SOFT, spaceAfter=2,
        ),
        "score_label": ParagraphStyle(
            "score_label", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=8, leading=10,
            textColor=INK_SOFT, alignment=TA_CENTER,
        ),
        "score_value": ParagraphStyle(
            "score_value", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=44, leading=46,
            textColor=INK, alignment=TA_CENTER,
        ),
        "score_band": ParagraphStyle(
            "score_band", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=11, leading=14,
            textColor=INK_SOFT, alignment=TA_CENTER, spaceAfter=4,
        ),
        "footer": ParagraphStyle(
            "footer", parent=base["Normal"],
            fontName="Helvetica", fontSize=8, leading=10,
            textColor=INK_MUTED, alignment=TA_CENTER,
        ),
    }
    return s


def _sev_color(severity: str) -> tuple:
    """Return (foreground, background) for a severity level."""
    return {
        "critical": (SEV_CRITICAL, SEV_CRITICAL_BG),
        "high": (SEV_HIGH, SEV_HIGH_BG),
        "medium": (SEV_MEDIUM, SEV_MEDIUM_BG),
        "info": (INK_MUTED, SURFACE_ALT),
    }.get(severity, (INK_MUTED, SURFACE_ALT))


def _band_for_score(score: int) -> tuple:
    """Return (band_name, color) for a posture score."""
    if score >= 90: return ("Good", GOOD)
    if score >= 70: return ("Fair", SEV_MEDIUM)
    if score >= 50: return ("Poor", SEV_HIGH)
    return ("Critical", SEV_CRITICAL)


def _posture_score_box(score: int, width: float, height: float):
    """A square-ish box with a big score number and a band label, color-banded."""
    band_name, band_color = _band_for_score(score)

    d = Drawing(width, height)
    # Box background: a soft tint of the band color, with band-color stripe on left
    bg_color = {
        "Good": GOOD_BG, "Fair": SEV_MEDIUM_BG,
        "Poor": SEV_HIGH_BG, "Critical": SEV_CRITICAL_BG,
    }[band_name]

    d.add(Rect(0, 0, width, height, fillColor=bg_color, strokeColor=BORDER, strokeWidth=0.5))
    d.add(Rect(0, 0, 4, height, fillColor=band_color, strokeColor=None))

    label = String(width / 2, height - 18, "POSTURE SCORE",
                   textAnchor="middle", fontSize=9, fontName="Helvetica-Bold",
                   fillColor=INK_SOFT)
    d.add(label)

    value = String(width / 2, height - 60, str(score),
                   textAnchor="middle", fontSize=44, fontName="Helvetica-Bold",
                   fillColor=INK)
    d.add(value)

    band = String(width / 2, height - 78, band_name.upper(),
                  textAnchor="middle", fontSize=11, fontName="Helvetica-Bold",
                  fillColor=band_color)
    d.add(band)

    explainer = String(width / 2, 14, "100 - 8(critical) - 3(high) - 1(medium)",
                       textAnchor="middle", fontSize=7, fontName="Helvetica",
                       fillColor=INK_MUTED)
    d.add(explainer)

    return d


def _algorithm_chart(distribution: dict, width=4.5*inch, height=1.5*inch):
    """Horizontal bar chart of key algorithm distribution."""
    if not distribution:
        d = Drawing(width, height)
        d.add(String(width / 2, height / 2, "(no SSH keys discovered)",
                     textAnchor="middle", fontSize=10, fillColor=INK_MUTED))
        return d

    labels = list(distribution.keys())
    values = [distribution[k] for k in labels]

    # Color each bar by algorithm strength
    def _color_for(label):
        if label.startswith("DSA"): return SEV_CRITICAL
        if label in ("RSA-1024", "RSA-768"): return SEV_CRITICAL
        if label == "ED25519" or label.startswith("RSA-4096") or label.startswith("ECDSA"):
            return NAVY
        if label == "RSA-2048": return colors.HexColor("#5a7ba8")
        return INK_FAINT

    # Make height proportional to number of bars (15pt per bar + padding)
    bar_count = len(labels)
    actual_height = max(60, bar_count * 18 + 30)
    d = Drawing(width, actual_height)
    bc = HorizontalBarChart()
    bc.x = 90
    bc.y = 12
    bc.width = width - 110
    bc.height = actual_height - 30

    bc.data = [values]
    bc.categoryAxis.categoryNames = labels
    bc.categoryAxis.labels.fontName = "Helvetica"
    bc.categoryAxis.labels.fontSize = 8
    bc.categoryAxis.labels.textAnchor = "end"
    bc.categoryAxis.tickLeft = 0
    bc.categoryAxis.strokeWidth = 0

    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueStep = max(1, max(values) // 4 + 1)
    bc.valueAxis.labels.fontName = "Helvetica"
    bc.valueAxis.labels.fontSize = 7
    bc.valueAxis.labels.fillColor = INK_MUTED
    bc.valueAxis.strokeColor = BORDER

    # Color bars
    for i, label in enumerate(labels):
        bc.bars[(0, i)].fillColor = _color_for(label)
    bc.bars.strokeWidth = 0
    bc.barWidth = 12

    d.add(bc)
    return d


def _severity_pie(crit: int, high: int, med: int, width=2.5*inch, height=2*inch):
    """Pie chart of severity distribution."""
    if crit + high + med == 0:
        d = Drawing(width, height)
        d.add(String(width / 2, height / 2, "(no findings)",
                     textAnchor="middle", fontSize=10, fillColor=GOOD))
        return d

    d = Drawing(width, height)
    pie = Pie()
    pie.x = 25
    pie.y = 12
    pie.width = height - 30
    pie.height = height - 30
    pie.data = [crit, high, med]
    pie.labels = None
    pie.slices.strokeWidth = 0.5
    pie.slices.strokeColor = colors.white
    pie.slices[0].fillColor = SEV_CRITICAL
    pie.slices[1].fillColor = SEV_HIGH
    pie.slices[2].fillColor = SEV_MEDIUM
    d.add(pie)

    legend = Legend()
    legend.x = height + 10
    legend.y = height - 25
    legend.fontName = "Helvetica"
    legend.fontSize = 8
    legend.alignment = "right"
    legend.colorNamePairs = [
        (SEV_CRITICAL, f"Critical: {crit}"),
        (SEV_HIGH, f"High: {high}"),
        (SEV_MEDIUM, f"Medium: {med}"),
    ]
    d.add(legend)
    return d


def _kv_table(rows: list, key_width=1.2*inch, value_width=4*inch) -> Table:
    """Simple two-column key/value table for machine info."""
    data = []
    for k, v in rows:
        data.append([
            Paragraph(k.upper(), _styles()["label"]),
            Paragraph(str(v) if v else "—", _styles()["value"]),
        ])
    t = Table(data, colWidths=[key_width, value_width])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def _severity_summary_table(severity_counts: dict) -> Table:
    """Side-by-side severity counts with color coding."""
    crit = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    med = severity_counts.get("medium", 0)

    headers = ["", "Critical", "High", "Medium", "Total"]
    row = ["Findings", str(crit), str(high), str(med), str(crit + high + med)]

    t = Table([headers, row], colWidths=[1.0*inch] + [0.9*inch]*4)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SURFACE_ALT),
        ("TEXTCOLOR", (0, 0), (-1, 0), INK_SOFT),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),

        ("FONTNAME", (0, 1), (0, 1), "Helvetica-Bold"),
        ("FONTNAME", (1, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 12),

        ("TEXTCOLOR", (1, 1), (1, 1), SEV_CRITICAL),
        ("TEXTCOLOR", (2, 1), (2, 1), SEV_HIGH),
        ("TEXTCOLOR", (3, 1), (3, 1), SEV_MEDIUM),
        ("TEXTCOLOR", (4, 1), (4, 1), INK),

        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, BORDER),
    ]))
    return t


def _finding_block(severity: str, title: str, evidence: Optional[str],
                   recommendation: Optional[str], description: Optional[str] = None):
    """A single finding rendered as a colored card."""
    fg, bg = _sev_color(severity)
    s = _styles()

    inner = []
    pill_data = [[severity.upper()]]
    pill = Table(pill_data, colWidths=[0.6*inch])
    pill.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), fg),
        ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
        ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (0, 0), 7),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
        ("TOPPADDING", (0, 0), (0, 0), 2),
        ("BOTTOMPADDING", (0, 0), (0, 0), 2),
    ]))

    body_parts = [
        Paragraph(title, s["finding_title"]),
    ]
    if description:
        body_parts.append(Paragraph(description, s["finding_desc"]))
    if evidence:
        body_parts.append(Paragraph(f"<b>Evidence:</b> {evidence}", s["evidence"]))
    if recommendation:
        body_parts.append(Paragraph(f"<b>Recommendation:</b> {recommendation}", s["fix"]))

    outer_data = [[pill, body_parts]]
    outer = Table(outer_data, colWidths=[0.7*inch, 5.6*inch])
    outer.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBEFORE", (0, 0), (0, -1), 3, fg),
    ]))
    return KeepTogether(outer)


def _header(user_name: str, user_email: str, title: str, subtitle: str):
    """The cover header at the top of every report."""
    s = _styles()

    flowables = [
        Paragraph("AUNIX", s["brand"]),
        Paragraph("Audit for Unix", s["subtitle"]),
        Spacer(1, 4),
        Paragraph(title, s["h1"]),
        Paragraph(subtitle, s["body"]),
    ]

    meta_rows = [
        ("Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")),
        ("Generated By", f"{user_name} ({user_email})"),
    ]
    flowables.append(_kv_table(meta_rows))
    flowables.append(Spacer(1, 14))
    return flowables


def _footer_canvas(canvas, doc):
    """Add a footer with page number and 'CONFIDENTIAL' tag."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(INK_MUTED)
    page_num = f"Page {doc.page}"
    canvas.drawCentredString(letter[0] / 2, 0.4 * inch, "AUNIX security audit  ·  CONFIDENTIAL  ·  " + page_num)
    canvas.restoreState()


# ============================================================================
# Per-machine report
# ============================================================================

def build_machine_report(
    user_name: str, user_email: str,
    machine: dict, severity_counts: dict, posture_score: int,
    keys: list, key_findings: list, policy_findings: list,
    algorithm_distribution: dict,
) -> bytes:
    """
    Returns the PDF as bytes.

    machine: {hostname, ip_address, operating_system, last_scan_at, status}
    severity_counts: {critical, high, medium}
    keys: list of dicts with key fields (file_path, key_algorithm, etc.)
    key_findings: list of {severity, title, evidence, recommendation}
    policy_findings: list of {severity, title, description, evidence,
                              recommendation, file_path, category}
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        topMargin=0.6 * inch, bottomMargin=0.7 * inch,
        title="AUNIX Audit Report",
    )
    s = _styles()
    story = []

    story.extend(_header(
        user_name, user_email,
        "Machine Security Audit",
        f"Detailed audit of <b>{machine.get('hostname', 'unknown host')}</b> — "
        "SSH key hygiene and configuration policy review.",
    ))

    # ---- Posture box + severity summary side by side ----
    score_box = _posture_score_box(score=posture_score,
                                   width=2.0*inch, height=1.6*inch)
    severity_table = _severity_summary_table(severity_counts)

    side_by_side = Table(
        [[score_box, severity_table]],
        colWidths=[2.2 * inch, 4.8 * inch],
    )
    side_by_side.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(side_by_side)
    story.append(Spacer(1, 14))

    # ---- Machine info ----
    story.append(Paragraph("Machine Details", s["h1"]))
    story.append(_kv_table([
        ("Hostname", machine.get("hostname")),
        ("IP Address", machine.get("ip_address")),
        ("Operating System", machine.get("operating_system")),
        ("Status", (machine.get("status") or "unknown").capitalize()),
        ("Last Scan", machine.get("last_scan_at_str") or "never"),
        ("SSH Keys Discovered", len(keys)),
    ]))

    # ---- Algorithm chart ----
    if algorithm_distribution:
        story.append(Paragraph("SSH Key Algorithms", s["h1"]))
        story.append(Paragraph(
            "Algorithms in use across this machine. Red bars indicate "
            "weak or deprecated algorithms.",
            s["body"]))
        story.append(_algorithm_chart(algorithm_distribution))
        story.append(Spacer(1, 10))

    # ---- SSH key findings ----
    story.append(Paragraph("SSH Key Findings", s["h1"]))
    visible_kf = [f for f in key_findings if f.get("severity") != "info"]
    if not visible_kf:
        story.append(Paragraph(
            "No SSH key issues detected.", s["body"]))
    else:
        for f in visible_kf:
            story.append(_finding_block(
                severity=f.get("severity"),
                title=f.get("title", ""),
                evidence=f.get("evidence"),
                recommendation=f.get("recommendation"),
            ))
            story.append(Spacer(1, 4))

    # ---- Policy findings ----
    story.append(Paragraph("Configuration Policy Findings", s["h1"]))
    visible_pf = [f for f in policy_findings if f.get("severity") != "info"]
    if not visible_pf:
        story.append(Paragraph(
            "No configuration policy issues detected. (sshd, /etc/passwd, "
            "/etc/shadow, sudoers all clean.)",
            s["body"]))
    else:
        # Group by category
        by_category = {}
        for f in visible_pf:
            by_category.setdefault(f.get("category", "other"), []).append(f)

        for category, items in by_category.items():
            story.append(Paragraph(category.upper(), s["h2"]))
            for f in items:
                story.append(_finding_block(
                    severity=f.get("severity"),
                    title=f.get("title", ""),
                    description=f.get("description"),
                    evidence=f.get("evidence"),
                    recommendation=f.get("recommendation"),
                ))
                story.append(Spacer(1, 4))

    # ---- Full inventory table (page break before, since it's bulky) ----
    if keys:
        story.append(PageBreak())
        story.append(Paragraph("Full SSH Key Inventory", s["h1"]))
        story.append(Paragraph(
            "All SSH keys discovered on this machine, sorted by severity.",
            s["body"]))

        sev_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
        sorted_keys = sorted(keys, key=lambda k: sev_order.get(k.get("severity", "info"), 9))

        rows = [["SEV", "USER", "PATH", "ALGO", "PERMS", "KIND"]]
        for k in sorted_keys:
            algo = k.get("key_algorithm", "")
            if algo and k.get("key_bits"):
                algo = f"{algo}-{k['key_bits']}"
            rows.append([
                (k.get("severity") or "info").upper()[:4],
                (k.get("username") or "")[:14],
                _truncate(k.get("file_path", ""), 36),
                algo,
                k.get("permissions") or "",
                k.get("key_kind") or "",
            ])

        t = Table(rows, colWidths=[
            0.5*inch, 0.9*inch, 2.4*inch, 0.9*inch, 0.7*inch, 0.7*inch
        ])
        ts = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SURFACE_ALT),
            ("TEXTCOLOR", (0, 0), (-1, 0), INK_SOFT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 7),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTNAME", (2, 1), (2, -1), "Courier"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, BORDER),
            ("LINEBELOW", (0, "splitlast"), (-1, "splitlast"), 0.25, BORDER),
        ])
        # Color severity column
        for i, k in enumerate(sorted_keys, start=1):
            sev = k.get("severity", "info")
            ts.add("TEXTCOLOR", (0, i), (0, i), _sev_color(sev)[0])
            ts.add("FONTNAME", (0, i), (0, i), "Helvetica-Bold")
        t.setStyle(ts)
        story.append(t)

    doc.build(story, onFirstPage=_footer_canvas, onLaterPages=_footer_canvas)
    return buf.getvalue()


def _truncate(value: str, max_len: int) -> str:
    if value and len(value) > max_len:
        return "…" + value[-(max_len - 1):]
    return value or ""


# ============================================================================
# Fleet report
# ============================================================================

def build_fleet_report(
    user_name: str, user_email: str,
    fleet_summary: dict,
    machines: list,    # [{hostname, ip, os, last_scan, severity_counts, key_count}]
) -> bytes:
    """Executive summary across all of a user's targets."""
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        topMargin=0.6 * inch, bottomMargin=0.7 * inch,
        title="AUNIX Fleet Audit Report",
    )
    s = _styles()
    story = []

    story.extend(_header(
        user_name, user_email,
        "Fleet Security Posture Report",
        f"Estate-wide summary across {fleet_summary.get('total_machines', 0)} "
        "registered machines.",
    ))

    # ---- Posture + severity summary ----
    score_box = _posture_score_box(
        score=fleet_summary.get("posture_score", 100),
        width=2.0*inch, height=1.6*inch,
    )
    severity_table = _severity_summary_table(
        fleet_summary.get("findings_by_severity", {})
    )
    side_by_side = Table(
        [[score_box, severity_table]],
        colWidths=[2.2 * inch, 4.8 * inch],
    )
    side_by_side.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(side_by_side)
    story.append(Spacer(1, 14))

    # ---- Estate KPIs ----
    story.append(Paragraph("Estate Snapshot", s["h1"]))

    kpi_rows = [
        ("Total Machines", fleet_summary.get("total_machines", 0)),
        ("Reporting", fleet_summary.get("machines_reporting", 0)),
        ("Silent (>7 days)", fleet_summary.get("machines_silent", 0)),
        ("Never Scanned", fleet_summary.get("machines_never_scanned", 0)),
        ("Total SSH Keys", fleet_summary.get("total_keys", 0)),
        ("Unique Fingerprints", fleet_summary.get("unique_fingerprints", 0)),
    ]
    story.append(_kv_table(kpi_rows))

    # ---- Algorithm distribution chart ----
    if fleet_summary.get("algorithm_distribution"):
        story.append(Paragraph("Key Algorithm Distribution", s["h1"]))
        story.append(Paragraph(
            "Algorithms in use across the estate. Weak algorithms shown in red.",
            s["body"]))
        story.append(_algorithm_chart(fleet_summary["algorithm_distribution"]))
        story.append(Spacer(1, 10))

    # ---- Top risk machines ----
    top_risk = fleet_summary.get("top_risk_machines", [])
    if top_risk:
        story.append(Paragraph("Top Risk Machines", s["h1"]))
        story.append(Paragraph(
            "Machines with the highest counts of critical and high-severity "
            "findings. Address these first.", s["body"]))

        rows = [["MACHINE", "CRITICAL", "HIGH", "MEDIUM", "KEYS"]]
        for m in top_risk:
            rows.append([
                m["hostname"],
                str(m.get("critical", 0)),
                str(m.get("high", 0)),
                str(m.get("medium", 0)),
                str(m.get("key_count", 0)),
            ])
        t = Table(rows, colWidths=[3.0*inch, 0.9*inch, 0.9*inch, 0.9*inch, 0.6*inch])
        ts = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SURFACE_ALT),
            ("TEXTCOLOR", (0, 0), (-1, 0), INK_SOFT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, BORDER),
        ])
        for i, m in enumerate(top_risk, start=1):
            if m.get("critical", 0) > 0:
                ts.add("TEXTCOLOR", (1, i), (1, i), SEV_CRITICAL)
                ts.add("FONTNAME", (1, i), (1, i), "Helvetica-Bold")
            if m.get("high", 0) > 0:
                ts.add("TEXTCOLOR", (2, i), (2, i), SEV_HIGH)
            if m.get("medium", 0) > 0:
                ts.add("TEXTCOLOR", (3, i), (3, i), SEV_MEDIUM)
        t.setStyle(ts)
        story.append(t)

    # ---- Shared keys ----
    shared_keys = fleet_summary.get("shared_keys", [])
    if shared_keys:
        story.append(Paragraph("Keys Shared Across Machines", s["h1"]))
        story.append(Paragraph(
            "The same private key on multiple hosts means a compromise of one "
            "compromises them all. Consider replacing shared keys with "
            "per-machine keys.", s["body"]))

        rows = [["FINGERPRINT", "ALGO", "HOSTS", "MACHINES"]]
        for k in shared_keys[:15]:
            algo = k.get("algorithm", "")
            if algo and k.get("bits"):
                algo = f"{algo}-{k['bits']}"
            rows.append([
                _truncate(k.get("fingerprint", ""), 28),
                algo,
                str(k.get("machine_count", 0)),
                _truncate(", ".join(k.get("hostnames", [])), 30),
            ])
        t = Table(rows, colWidths=[2.4*inch, 0.9*inch, 0.6*inch, 2.4*inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SURFACE_ALT),
            ("TEXTCOLOR", (0, 0), (-1, 0), INK_SOFT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("FONTNAME", (0, 1), (0, -1), "Courier"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, BORDER),
        ]))
        story.append(t)

    # ---- Per-machine summary cards ----
    if machines:
        story.append(PageBreak())
        story.append(Paragraph("Per-Machine Summary", s["h1"]))
        story.append(Paragraph(
            "One row per machine. For full per-machine detail, generate "
            "individual machine reports from the dashboard.",
            s["body"]))

        rows = [["MACHINE", "OS", "LAST SCAN", "C", "H", "M", "KEYS"]]
        for m in machines:
            sev = m.get("severity_counts", {})
            rows.append([
                m.get("hostname", ""),
                _truncate(m.get("operating_system", "") or "—", 18),
                m.get("last_scan_at_str") or "never",
                str(sev.get("critical", 0)),
                str(sev.get("high", 0)),
                str(sev.get("medium", 0)),
                str(m.get("key_count", 0)),
            ])
        t = Table(rows, colWidths=[
            1.6*inch, 1.4*inch, 1.4*inch, 0.4*inch, 0.4*inch, 0.4*inch, 0.4*inch
        ])
        ts = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SURFACE_ALT),
            ("TEXTCOLOR", (0, 0), (-1, 0), INK_SOFT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("ALIGN", (3, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, BORDER),
        ])
        for i, m in enumerate(machines, start=1):
            sev = m.get("severity_counts", {})
            if sev.get("critical", 0) > 0:
                ts.add("TEXTCOLOR", (3, i), (3, i), SEV_CRITICAL)
                ts.add("FONTNAME", (3, i), (3, i), "Helvetica-Bold")
            if sev.get("high", 0) > 0:
                ts.add("TEXTCOLOR", (4, i), (4, i), SEV_HIGH)
            if sev.get("medium", 0) > 0:
                ts.add("TEXTCOLOR", (5, i), (5, i), SEV_MEDIUM)
        t.setStyle(ts)
        story.append(t)

    doc.build(story, onFirstPage=_footer_canvas, onLaterPages=_footer_canvas)
    return buf.getvalue()
