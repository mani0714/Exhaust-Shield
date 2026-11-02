"""Render HANDBOOK_Copilot_Hybrid.md → ExhaustShield_Copilot_Hybrid_Handbook.pdf"""
from __future__ import annotations

import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parent
MD = ROOT / "HANDBOOK_Copilot_Hybrid.md"
OUT = ROOT / "ExhaustShield_Copilot_Hybrid_Handbook.pdf"

INK = colors.HexColor("#111c2e")
MUTED = colors.HexColor("#5b6b7c")
TEAL = colors.HexColor("#0f766e")
TEAL_LT = colors.HexColor("#ccfbf1")
NAVY = colors.HexColor("#0f172a")
BAND = colors.HexColor("#f8fafc")
RULE = colors.HexColor("#dde5ee")
CODE_BG = colors.HexColor("#f1f5f9")
AMBER_LT = colors.HexColor("#fef3c7")

PAGE_W, PAGE_H = LETTER
ML = MR = 0.65 * inch
MT = 0.55 * inch
MB = 0.6 * inch
CW = PAGE_W - ML - MR


def styles():
    b = getSampleStyleSheet()
    return {
        "cover_k": ParagraphStyle(
            "cover_k", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=10, leading=13, textColor=TEAL, alignment=TA_CENTER, spaceAfter=6,
        ),
        "cover_t": ParagraphStyle(
            "cover_t", parent=b["Title"], fontName="Helvetica-Bold",
            fontSize=22, leading=26, textColor=NAVY, alignment=TA_CENTER, spaceAfter=8,
        ),
        "cover_s": ParagraphStyle(
            "cover_s", parent=b["Normal"], fontName="Helvetica",
            fontSize=10, leading=14, textColor=MUTED, alignment=TA_CENTER, spaceAfter=6,
        ),
        "h1": ParagraphStyle(
            "h1", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=14, leading=18, textColor=NAVY, spaceBefore=14, spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "h2", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=11.5, leading=15, textColor=TEAL, spaceBefore=10, spaceAfter=5,
        ),
        "h3": ParagraphStyle(
            "h3", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=10, leading=13, textColor=INK, spaceBefore=8, spaceAfter=4,
        ),
        "h4": ParagraphStyle(
            "h4", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=9.5, leading=12, textColor=MUTED, spaceBefore=6, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body", parent=b["Normal"], fontName="Helvetica",
            fontSize=9, leading=12.5, textColor=INK, spaceAfter=4,
        ),
        "li": ParagraphStyle(
            "li", parent=b["Normal"], fontName="Helvetica",
            fontSize=9, leading=12, textColor=INK,
        ),
        "note": ParagraphStyle(
            "note", parent=b["Normal"], fontName="Helvetica-Oblique",
            fontSize=8, leading=11, textColor=MUTED, spaceAfter=4,
        ),
        "code": ParagraphStyle(
            "code", parent=b["Code"], fontName="Courier",
            fontSize=7.2, leading=9.5, textColor=INK, backColor=CODE_BG,
        ),
        "cell": ParagraphStyle(
            "cell", parent=b["Normal"], fontName="Helvetica",
            fontSize=7.5, leading=10, textColor=INK,
        ),
        "cell_b": ParagraphStyle(
            "cell_b", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=7.5, leading=10, textColor=NAVY,
        ),
        "cell_w": ParagraphStyle(
            "cell_w", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=7.5, leading=10, textColor=colors.white,
        ),
        "toc": ParagraphStyle(
            "toc", parent=b["Normal"], fontName="Helvetica",
            fontSize=9, leading=13, textColor=INK, leftIndent=8, spaceAfter=2,
        ),
    }


def esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def inline_md(text: str) -> str:
    """Convert basic markdown inline to ReportLab-ish rich text."""
    t = esc(text)
    t = re.sub(r"`([^`]+)`", r"<font face='Courier' size='8'><b>\1</b></font>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", t)
    def _link(m: re.Match) -> str:
        label, href = m.group(1), m.group(2).strip()
        # ReportLab needs a real URL scheme — drop TOC/anchor-only links
        if href.startswith("#") or not re.match(r"^https?://", href, re.I):
            return f"<b>{label}</b>"
        safe = href.replace("'", "%27")
        return f"<link href='{safe}' color='#0f766e'><u>{label}</u></link>"

    t = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _link, t)
    return t


def footer(c, doc):
    c.saveState()
    c.setStrokeColor(TEAL)
    c.setLineWidth(1.1)
    y = MB - 0.22 * inch
    c.line(ML, y + 0.16 * inch, PAGE_W - MR, y + 0.16 * inch)
    c.setFont("Helvetica", 7)
    c.setFillColor(MUTED)
    c.drawString(ML, y, "ExhaustShield · Copilot Hybrid Handbook")
    c.setFillColor(TEAL)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawCentredString(PAGE_W / 2, y, "Designed by Manikandan")
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 7)
    c.drawRightString(PAGE_W - MR, y, f"Page {doc.page}")
    c.restoreState()


def color_bar():
    w = CW / 6
    t = Table([[""] * 6], colWidths=[w] * 6, rowHeights=[5])
    fills = [
        TEAL, colors.HexColor("#059669"), colors.HexColor("#0369a1"),
        colors.HexColor("#b45309"), colors.HexColor("#be123c"), colors.HexColor("#6d28d9"),
    ]
    t.setStyle(TableStyle(
        [("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]
        + [("BACKGROUND", (i, 0), (i, 0), c) for i, c in enumerate(fills)]
    ))
    return t


def make_table(rows: list[list[str]], st: dict) -> Table:
    if not rows:
        return Spacer(1, 1)
    ncols = max(len(r) for r in rows)
    norm = [r + [""] * (ncols - len(r)) for r in rows]
    data = []
    for i, row in enumerate(norm):
        style = "cell_w" if i == 0 else "cell"
        cells = []
        for j, cell in enumerate(row):
            if i == 0:
                cells.append(Paragraph(inline_md(cell), st["cell_w"]))
            elif j == 0:
                cells.append(Paragraph(inline_md(cell), st["cell_b"]))
            else:
                cells.append(Paragraph(inline_md(cell), st[style if i else "cell"]))
        data.append(cells)
    col_w = CW / ncols
    t = Table(data, colWidths=[col_w] * ncols, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BAND]),
        ("GRID", (0, 0), (-1, -1), 0.35, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def parse_md(md: str, st: dict) -> list:
    lines = md.splitlines()
    story: list = []
    i = 0
    # Skip first H1 — cover handles title
    while i < len(lines) and not lines[i].startswith("# "):
        i += 1
    if i < len(lines) and lines[i].startswith("# "):
        i += 1

    in_code = False
    code_lines: list[str] = []
    table_buf: list[list[str]] = []
    list_buf: list[str] = []

    def flush_list():
        nonlocal list_buf
        if not list_buf:
            return
        items = []
        for raw in list_buf:
            items.append(ListItem(Paragraph(inline_md(raw), st["li"]), leftIndent=12, bulletColor=TEAL))
        story.append(ListFlowable(items, bulletType="bullet", start="•", leftIndent=16, bulletFontSize=8))
        story.append(Spacer(1, 3))
        list_buf = []

    def flush_table():
        nonlocal table_buf
        if not table_buf:
            return
        # Drop markdown separator rows like |---|---|
        cleaned = []
        for row in table_buf:
            joined = "".join(row)
            if re.fullmatch(r"[\s\-:|]+", joined):
                continue
            cleaned.append(row)
        if cleaned:
            story.append(Spacer(1, 3))
            story.append(make_table(cleaned, st))
            story.append(Spacer(1, 6))
        table_buf = []

    def flush_code():
        nonlocal code_lines
        if not code_lines:
            return
        text = "\n".join(code_lines)
        # Cap extremely long code blocks visually
        if len(text) > 4500:
            text = text[:4500] + "\n… (truncated in PDF — see .md for full text)"
        pre = Preformatted(text, st["code"])
        box = Table([[pre]], colWidths=[CW])
        box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, RULE),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(Spacer(1, 3))
        story.append(box)
        story.append(Spacer(1, 5))
        code_lines = []

    while i < len(lines):
        line = lines[i]
        raw = line.rstrip()

        if raw.startswith("```"):
            flush_list()
            flush_table()
            if in_code:
                flush_code()
                in_code = False
            else:
                in_code = True
                code_lines = []
            i += 1
            continue

        if in_code:
            code_lines.append(raw)
            i += 1
            continue

        if not raw.strip():
            flush_list()
            flush_table()
            i += 1
            continue

        if raw.strip() == "---":
            flush_list()
            flush_table()
            i += 1
            continue

        # Table row
        if raw.strip().startswith("|") and raw.strip().endswith("|"):
            flush_list()
            cells = [c.strip() for c in raw.strip().strip("|").split("|")]
            table_buf.append(cells)
            i += 1
            continue
        else:
            flush_table()

        # Headings
        if raw.startswith("# "):
            flush_list()
            story.append(PageBreak())
            story.append(Paragraph(inline_md(raw[2:].strip()), st["h1"]))
            i += 1
            continue
        if raw.startswith("## "):
            flush_list()
            story.append(Paragraph(inline_md(raw[3:].strip()), st["h2"]))
            i += 1
            continue
        if raw.startswith("### "):
            flush_list()
            story.append(Paragraph(inline_md(raw[4:].strip()), st["h3"]))
            i += 1
            continue
        if raw.startswith("#### "):
            flush_list()
            story.append(Paragraph(inline_md(raw[5:].strip()), st["h4"]))
            i += 1
            continue

        # Lists
        m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", raw)
        if m:
            item = m.group(3)
            # checkbox
            item = re.sub(r"^\[ \]\s*", "☐ ", item)
            item = re.sub(r"^\[x\]\s*", "☑ ", item, flags=re.I)
            list_buf.append(item)
            i += 1
            continue
        else:
            flush_list()

        # Blockquote / note
        if raw.startswith(">"):
            story.append(Paragraph(inline_md(raw.lstrip("> ").strip()), st["note"]))
            i += 1
            continue

        story.append(Paragraph(inline_md(raw), st["body"]))
        i += 1

    flush_list()
    flush_table()
    flush_code()
    return story


def cover(st: dict) -> list:
    out = [
        color_bar(),
        Spacer(1, 28),
        Paragraph("EXHAUSTSHIELD · BEGINNER HANDBOOK", st["cover_k"]),
        Paragraph("Copilot Hybrid Setup", st["cover_t"]),
        Paragraph(
            "Users → Copilot Agent (Teams) → FastAPI → ExhaustShield engine",
            st["cover_s"],
        ),
        Spacer(1, 10),
    ]
    box = Table(
        [[
            Paragraph(
                "<b>What this PDF is for</b><br/>"
                "Follow every part in order to create the hybrid setup end to end: "
                "host the gateway, wire Copilot Studio, publish to Teams, and pin the 5-tab dashboard.<br/><br/>"
                "<b>Golden rule</b><br/>"
                "Never let Studio classify secrets. Always call "
                "<font face='Courier'>/api/generate</font> and trust the lane it returns.",
                st["body"],
            )
        ]],
        colWidths=[CW],
    )
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), TEAL_LT),
        ("BOX", (0, 0), (-1, -1), 1.2, TEAL),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    out += [
        box,
        Spacer(1, 16),
        Paragraph(
            "Source markdown: <b>HANDBOOK_Copilot_Hybrid.md</b><br/>"
            "APIs aligned to this repo’s <b>gateway.py</b><br/>"
            "Designed by Manikandan",
            st["cover_s"],
        ),
        Spacer(1, 20),
        Paragraph("Contents", st["h2"]),
        Paragraph("1. What you are building", st["toc"]),
        Paragraph("2. Licences checklist", st["toc"]),
        Paragraph("3. Architecture and workflows", st["toc"]),
        Paragraph("4. Lane formulas", st["toc"]),
        Paragraph("5. Cost formulas", st["toc"]),
        Paragraph("6. Part A — Prepare FastAPI on your server", st["toc"]),
        Paragraph("7. Part B — Prove the three APIs", st["toc"]),
        Paragraph("8. Part C — Create the Copilot Studio agent", st["toc"]),
        Paragraph("9. Part D — Connect Studio to FastAPI", st["toc"]),
        Paragraph("10. Part E — Build the topics", st["toc"]),
        Paragraph("11. Part F — Publish to Teams", st["toc"]),
        Paragraph("12. Part G — Pin the 5-tab dashboard", st["toc"]),
        Paragraph("13. Part H — Test script", st["toc"]),
        Paragraph("14. Part I — Rollout and go-live", st["toc"]),
        Paragraph("15. Troubleshooting", st["toc"]),
        Paragraph("16. Adaptive Card JSON", st["toc"]),
        Paragraph("17. Questions for IT / admin", st["toc"]),
        PageBreak(),
    ]
    return out


def build():
    if not MD.exists():
        raise FileNotFoundError(MD)
    st = styles()
    md = MD.read_text(encoding="utf-8")
    story = cover(st) + parse_md(md, st)

    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=LETTER,
        leftMargin=ML,
        rightMargin=MR,
        topMargin=MT,
        bottomMargin=MB,
        title="ExhaustShield — Copilot Hybrid Handbook",
        author="Manikandan",
        subject="Beginner end-to-end setup: Studio agent + FastAPI gate",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    build()
