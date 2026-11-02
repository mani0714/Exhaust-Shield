"""ExhaustShield — board decision deck: 3 options, sourced pricing, 500-3000 users.
Packed into 6 filled pages — no orphan half-blank pages.
"""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUT = Path(__file__).resolve().parent / "ExhaustShield_Board_Three_Options.pdf"

INK = colors.HexColor("#111c2e")
MUTED = colors.HexColor("#5b6b7c")
TEAL = colors.HexColor("#0f766e")
TEAL_LT = colors.HexColor("#ccfbf1")
BLUE = colors.HexColor("#1d4ed8")
BLUE_LT = colors.HexColor("#dbeafe")
AMBER = colors.HexColor("#b45309")
AMBER_LT = colors.HexColor("#fef3c7")
ROSE = colors.HexColor("#be123c")
ROSE_LT = colors.HexColor("#ffe4e6")
VIOLET = colors.HexColor("#6d28d9")
VIOLET_LT = colors.HexColor("#ede9fe")
GREEN = colors.HexColor("#059669")
GREEN_LT = colors.HexColor("#d1fae5")
SKY = colors.HexColor("#0369a1")
SKY_LT = colors.HexColor("#e0f2fe")
BAND = colors.HexColor("#f8fafc")
WHITE = colors.white
RULE = colors.HexColor("#dde5ee")
NAVY = colors.HexColor("#0f172a")

PAGE_W, PAGE_H = LETTER
ML = MR = 0.55 * inch
MT = 0.42 * inch
MB = 0.52 * inch
CW = PAGE_W - ML - MR

PAD = [
    ("LEFTPADDING", (0, 0), (-1, -1), 7),
    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ("TOPPADDING", (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
]


def S():
    b = getSampleStyleSheet()
    return {
        "kicker": ParagraphStyle(
            "kicker", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=8.5, leading=11, textColor=TEAL, alignment=TA_CENTER, spaceAfter=2,
        ),
        "title": ParagraphStyle(
            "title", parent=b["Title"], fontName="Helvetica-Bold",
            fontSize=18, leading=22, textColor=NAVY, alignment=TA_CENTER, spaceAfter=4,
        ),
        "sub": ParagraphStyle(
            "sub", parent=b["Normal"], fontName="Helvetica",
            fontSize=9, leading=12, textColor=MUTED, alignment=TA_CENTER, spaceAfter=6,
        ),
        "h1": ParagraphStyle(
            "h1", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=14, leading=17, textColor=NAVY, spaceBefore=0, spaceAfter=4,
        ),
        "h2": ParagraphStyle(
            "h2", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=10, leading=13, textColor=TEAL, spaceBefore=4, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body", parent=b["Normal"], fontName="Helvetica",
            fontSize=9, leading=12, textColor=INK, spaceAfter=3,
        ),
        "cell": ParagraphStyle(
            "cell", parent=b["Normal"], fontName="Helvetica",
            fontSize=7.8, leading=10.2, textColor=INK,
        ),
        "cell_b": ParagraphStyle(
            "cell_b", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=7.8, leading=10.2, textColor=NAVY,
        ),
        "cell_w": ParagraphStyle(
            "cell_w", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=7.8, leading=10.2, textColor=WHITE,
        ),
        "note": ParagraphStyle(
            "note", parent=b["Normal"], fontName="Helvetica",
            fontSize=7.5, leading=10, textColor=MUTED, spaceAfter=2,
        ),
        "stat_n": ParagraphStyle(
            "stat_n", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=16, leading=18, textColor=NAVY, alignment=TA_CENTER,
        ),
        "stat_t": ParagraphStyle(
            "stat_t", parent=b["Normal"], fontName="Helvetica",
            fontSize=7, leading=9, textColor=MUTED, alignment=TA_CENTER,
        ),
        "flow": ParagraphStyle(
            "flow", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=10, textColor=NAVY, alignment=TA_CENTER,
        ),
        "flow_s": ParagraphStyle(
            "flow_s", parent=b["Normal"], fontName="Helvetica",
            fontSize=6.8, leading=8.8, textColor=MUTED, alignment=TA_CENTER,
        ),
        "arr": ParagraphStyle(
            "arr", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=11, leading=12, textColor=TEAL, alignment=TA_CENTER,
        ),
        "sec": ParagraphStyle(
            "sec", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=10, leading=13, textColor=WHITE,
        ),
        "sec_s": ParagraphStyle(
            "sec_s", parent=b["Normal"], fontName="Helvetica",
            fontSize=8, leading=10.5, textColor=colors.HexColor("#e6edf5"),
        ),
        "big_w": ParagraphStyle(
            "big_w", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=11, leading=14, textColor=WHITE, alignment=TA_CENTER,
        ),
        "mid_w": ParagraphStyle(
            "mid_w", parent=b["Normal"], fontName="Helvetica",
            fontSize=8.2, leading=11, textColor=colors.HexColor("#d1fae5"), alignment=TA_CENTER,
        ),
        "mid_w2": ParagraphStyle(
            "mid_w2", parent=b["Normal"], fontName="Helvetica",
            fontSize=8.2, leading=11, textColor=colors.HexColor("#fecdd3"), alignment=TA_CENTER,
        ),
    }


def P(text, style="cell"):
    return Paragraph(text, S()[style])


def color_bar(h=5):
    w = CW / 6
    t = Table([[""] * 6], colWidths=[w] * 6, rowHeights=[h])
    fills = [TEAL, GREEN, SKY, AMBER, ROSE, VIOLET]
    t.setStyle(TableStyle(
        [("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]
        + [("BACKGROUND", (i, 0), (i, 0), c) for i, c in enumerate(fills)]
    ))
    return t


def banner(title, sub, bg):
    t = Table([[P(title, "sec")], [P(sub, "sec_s")]], colWidths=[CW])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (0, 0), 7),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
        ("TOPPADDING", (0, 1), (0, 1), 0),
    ]))
    return t


def stat_cards(items):
    n = len(items)
    gap = 0.08 * inch
    w = (CW - gap * (n - 1)) / n
    cells, widths = [], []
    for i, (num, cap, bg) in enumerate(items):
        inner = Table([[P(num, "stat_n")], [P(cap, "stat_t")]], colWidths=[w])
        inner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("BOX", (0, 0), (-1, -1), 0.5, RULE),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (0, 0), 6),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
            ("TOPPADDING", (0, 1), (0, 1), 1),
        ]))
        cells.append(inner)
        widths.append(w)
        if i < n - 1:
            cells.append("")
            widths.append(gap)
    t = Table([cells], colWidths=widths)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def node(label, sub, bg, w):
    t = Table([[P(label, "flow")], [P(sub, "flow_s")]], colWidths=[w])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.6, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (0, 0), 5),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 5),
        ("TOPPADDING", (0, 1), (0, 1), 1),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def hflow(boxes):
    """Horizontal flow: box → box → box."""
    n = len(boxes)
    aw = 0.16 * inch
    bw = (CW - aw * (n - 1)) / n
    row, widths = [], []
    for i, (label, sub, bg) in enumerate(boxes):
        row.append(node(label, sub, bg, bw))
        widths.append(bw)
        if i < n - 1:
            row.append(P("→", "arr"))
            widths.append(aw)
    t = Table([row], colWidths=widths)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return t


def lane_row(lanes):
    n = len(lanes)
    w = CW / n
    cells = [node(a, b, c, w - 3) for a, b, c in lanes]
    t = Table([cells], colWidths=[w] * n)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 1.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 1.5),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def grid(rows, widths, header_bg=NAVY, last_hl=False):
    t = Table(rows, colWidths=widths)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, RULE),
        *PAD,
    ]
    if last_hl:
        style.append(("ROWBACKGROUNDS", (0, 1), (-1, -2), [WHITE, BAND]))
        style.append(("BACKGROUND", (0, -1), (-1, -1), TEAL_LT))
    else:
        style.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, BAND]))
    t.setStyle(TableStyle(style))
    return t


def callout(title, body, bg, border, body_style="mid_w"):
    t = Table([[P(title, "big_w")], [P(body, body_style)]], colWidths=[CW])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 1.2, border),
        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 11),
        ("TOPPADDING", (0, 0), (0, 0), 8),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
        ("TOPPADDING", (0, 1), (0, 1), 2),
    ]))
    return t


def footer(c, doc):
    c.saveState()
    c.setStrokeColor(TEAL)
    c.setLineWidth(1.2)
    y = MB - 0.2 * inch
    c.line(ML, y + 0.16 * inch, PAGE_W - MR, y + 0.16 * inch)
    c.setFont("Helvetica", 7)
    c.setFillColor(MUTED)
    c.drawString(ML, y, "ExhaustShield · Board decision deck · list prices verified Sep 2026")
    c.setFillColor(TEAL)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawCentredString(PAGE_W / 2, y, "Designed by Manikandan")
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 7)
    c.drawRightString(PAGE_W - MR, y, f"Page {doc.page} of 5")
    c.restoreState()


def build():
    st = []

    # ═══════════════ PAGE 1 — WHY (need + Meta trigger) ═══════════════
    st.append(color_bar())
    st.append(Spacer(1, 5))
    st.append(P("BOARD DECISION DECK · CONFIDENTIAL", "kicker"))
    st.append(P("Your prompts are now a priced asset", "title"))
    st.append(P(
        "Three options to govern employee AI use, costed end to end for 500 – 3,000 people. "
        "Every figure is a published list price or a named published study.",
        "sub",
    ))
    st.append(callout(
        "The trigger: Meta now publishes what your data is worth",
        "Meta’s Muse Spark 1.3 rate card: <b>$1.25 / $4.25</b> per million tokens on Standard "
        "(never train) vs <b>$0.10 / $0.20</b> on Contributor — a <b>92–95% discount</b> for the right "
        "to train on your prompts. That spread is about <b>$1.24 per million tokens</b> of business "
        "prompt data. Our employees are giving that away for free today.",
        TEAL, GREEN,
    ))
    st.append(Spacer(1, 8))
    st.append(P("What the market pays for content and data", "h2"))
    st.append(grid(
        [
            [P("<b>Buyer → seller</b>", "cell_w"), P("<b>Published value</b>", "cell_w"), P("<b>Why it matters</b>", "cell_w")],
            [P("Meta → News Corp", "cell_b"), P("Up to <b>$50M / year</b> (3-yr, ~$150M)", "cell"), P("Proprietary text has a market price", "cell")],
            [P("OpenAI → News Corp", "cell_b"), P("<b>$250M</b> over 5 years", "cell"), P("Largest known single-publisher deal", "cell")],
            [P("Google → Reddit", "cell_b"), P("~<b>$60M / year</b>", "cell"), P("Even user chatter is monetised", "cell")],
            [P("Meta → Scale AI", "cell_b"), P("<b>$14.3B</b> for 49% stake (2025)", "cell"), P("Data pipelines valued in billions", "cell")],
            [P("Meta → <b>you</b>", "cell_b"), P("<b>$1.24 / 1M tokens</b> discount", "cell"), P("<b>They will pay to read our prompts</b>", "cell")],
        ],
        [1.5 * inch, 2.4 * inch, CW - 3.9 * inch],
        header_bg=VIOLET,
    ))
    st.append(Spacer(1, 8))
    st.append(P("Meanwhile, this is what leaves the building today", "h2"))
    st.append(stat_cards([
        ("11%", "of pastes into ChatGPT<br/>are sensitive · <b>Cyberhaven</b>", ROSE_LT),
        ("39.7%", "of AI interactions involve<br/>sensitive data · <b>Cyberhaven</b>", AMBER_LT),
        ("82%", "of GenAI pastes from<br/>unmanaged accounts · <b>LayerX</b>", VIOLET_LT),
        ("$19.5M", "avg annual insider-risk<br/>cost · <b>Insider Risks 2026</b>", SKY_LT),
    ]))
    st.append(Spacer(1, 7))
    st.append(grid(
        [
            [P("<b>Finding</b>", "cell_w"), P("<b>Number</b>", "cell_w"), P("<b>Source</b>", "cell_w")],
            [P("GenAI is #1 route for company→personal data movement", "cell"), P("<b>32%</b> of that exfiltration", "cell"), P("LayerX", "cell")],
            [P("Orgs that found staff using unapproved AI with company data", "cell"), P("<b>65%</b> in last 12 months", "cell"), P("Kiteworks 2026", "cell")],
            [P("Orgs with AI-specific DLP actually deployed", "cell"), P("<b>under 30%</b>", "cell"), P("Kiteworks 2026", "cell")],
            [P("Outright AI bans collapsed — without controls replacing them", "cell"), P("<b>28% → 7%</b>", "cell"), P("Cisco 2026", "cell")],
            [P("How often an employee feeds sensitive data to AI", "cell"), P("<b>once every 3 days</b>", "cell"), P("Cyberhaven 2026", "cell")],
        ],
        [3.4 * inch, 1.7 * inch, CW - 5.1 * inch],
        header_bg=ROSE,
    ))
    st.append(Spacer(1, 6))
    st.append(P(
        "<b>Board question:</b> when up to 3,000 people paste company text into models that bid for training "
        "rights, who decides what is allowed to leave? Three options follow.",
        "body",
    ))

    st.append(PageBreak())

    # ═══════════════ PAGE 2 — MATH + OPTION 1 start ═══════════════
    st.append(color_bar())
    st.append(Spacer(1, 5))
    st.append(P("How every number is calculated", "h1"))
    st.append(P("One formula · three usage scenarios · published rate cards. No blended estimates.", "sub"))

    st.append(P("Published rate cards (verified Sep 2026)", "h2"))
    st.append(grid(
        [
            [P("<b>Line item</b>", "cell_w"), P("<b>List price</b>", "cell_w"), P("<b>Line item</b>", "cell_w"), P("<b>List price</b>", "cell_w")],
            [P("M365 E3", "cell_b"), P("<b>$39</b>/user/mo (from Jul 2026)", "cell"),
             P("M365 E5", "cell_b"), P("<b>$60</b>/user/mo (from Jul 2026)", "cell")],
            [P("Copilot add-on", "cell_b"), P("<b>$30</b>/user/mo annual", "cell"),
             P("Purview Suite (E3)", "cell_b"), P("~<b>$12</b>/user/mo", "cell")],
            [P("Studio PAYG", "cell_b"), P("<b>$0.01</b>/credit", "cell"),
             P("Studio pack", "cell_b"), P("<b>$200</b> / 25k credits/mo", "cell")],
            [P("Groq gpt-oss-120b", "cell_b"), P("<b>$0.15</b> in / <b>$0.60</b> out /1M", "cell"),
             P("Azure GPT-4o-mini", "cell_b"), P("<b>$0.15</b> in / <b>$0.60</b> out /1M", "cell")],
            [P("Azure GPT-5-mini", "cell_b"), P("<b>$0.50</b> in / <b>$2.00</b> out /1M", "cell"),
             P("Azure GPT-5", "cell_b"), P("<b>$5.00</b> in / <b>$20.00</b> out /1M", "cell")],
            [P("Azure VM D2s_v5", "cell_b"), P("<b>$70.08</b>/mo East US Linux", "cell"),
             P("Studio credits", "cell_b"), P("classic 1 · gen 2 · action 5 · graph 10", "cell")],
        ],
        [1.35 * inch, 2.15 * inch, 1.45 * inch, CW - 4.95 * inch],
        header_bg=SKY,
    ))
    st.append(Spacer(1, 7))

    st.append(P("Cost of one gated chat = 1,000 input + 500 output tokens", "h2"))
    st.append(grid(
        [
            [P("<b>Model</b>", "cell_w"), P("<b>Input</b>", "cell_w"), P("<b>Output</b>", "cell_w"), P("<b>Per chat</b>", "cell_w")],
            [P("Groq gpt-oss-120b", "cell_b"), P("0.001M × $0.15 = $0.00015", "cell"), P("0.0005M × $0.60 = $0.00030", "cell"), P("<b>$0.00045</b>", "cell")],
            [P("Azure GPT-4o-mini", "cell_b"), P("same as Groq", "cell"), P("same as Groq", "cell"), P("<b>$0.00045</b>", "cell")],
            [P("Azure GPT-5-mini", "cell_b"), P("0.001M × $0.50 = $0.00050", "cell"), P("0.0005M × $2.00 = $0.00100", "cell"), P("<b>$0.00150</b>", "cell")],
            [P("Azure GPT-5 flagship", "cell_b"), P("0.001M × $5.00 = $0.00500", "cell"), P("0.0005M × $20 = $0.01000", "cell"), P("<b>$0.01500</b>", "cell")],
        ],
        [1.55 * inch, 2.0 * inch, 2.05 * inch, CW - 5.6 * inch],
        header_bg=TEAL,
    ))
    st.append(Spacer(1, 2))
    st.append(P("Groq and Azure GPT-4o-mini are priced identically — model choice is quality, not lock-in.", "note"))
    st.append(Spacer(1, 6))

    st.append(P("Three usage scenarios (22 working days / month)", "h2"))
    st.append(grid(
        [
            [P("<b>Scenario</b>", "cell_w"), P("<b>Chats / user / day</b>", "cell_w"),
             P("<b>500 users</b>", "cell_w"), P("<b>1,500 users</b>", "cell_w"), P("<b>3,000 users</b>", "cell_w")],
            [P("BEST — light pilot", "cell_b"), P("1", "cell"), P("11,000 / mo", "cell"), P("33,000 / mo", "cell"), P("66,000 / mo", "cell")],
            [P("NORMAL — steady", "cell_b"), P("3", "cell"), P("33,000 / mo", "cell"), P("99,000 / mo", "cell"), P("198,000 / mo", "cell")],
            [P("WORST — heavy", "cell_b"), P("8", "cell"), P("88,000 / mo", "cell"), P("264,000 / mo", "cell"), P("528,000 / mo", "cell")],
        ],
        [1.7 * inch, 1.25 * inch, 1.2 * inch, 1.25 * inch, CW - 5.4 * inch],
        header_bg=AMBER,
    ))
    st.append(Spacer(1, 5))
    st.append(P(
        "<b>Conservative:</b> tables below bill 100% of chats to a paid model. ~4 in 10 are local policy "
        "answers with <b>no model call</b>, so live bills come in lower.",
        "note",
    ))
    st.append(Spacer(1, 8))

    # Option 1 starts on same page to fill space
    st.append(banner(
        "OPTION 1 — Stay with existing Copilot (few E5 · majority E3 + basic Copilot Chat)",
        "No build. No new dashboard. Governance = whatever that licence tier already gives.",
        SKY,
    ))
    st.append(Spacer(1, 6))
    st.append(hflow([
        ("Employee", "Copilot Chat — or quietly ChatGPT / Claude in a browser", BLUE_LT),
        ("Copilot Chat", "Included with E3/E5 · Microsoft-hosted", SKY_LT),
        ("Purview DLP", "SIT match → block prompt or block web grounding", AMBER_LT),
    ]))
    st.append(Spacer(1, 5))
    st.append(lane_row([
        ("COVERED", "Prompt inside Copilot", GREEN_LT),
        ("NOT COVERED", "Same person on chatgpt.com", ROSE_LT),
        ("NOT COVERED", "No scrub-then-send", ROSE_LT),
        ("NOT COVERED", "No private model for secrets", ROSE_LT),
    ]))

    st.append(PageBreak())

    # ═══════════════ PAGE 3 — OPTION 1 cost + OPTION 2 ═══════════════
    st.append(color_bar())
    st.append(Spacer(1, 5))
    st.append(P("Option 1 — cost and verdict", "h2"))
    st.append(grid(
        [
            [P("<b>Cost line</b>", "cell_w"), P("<b>500 users</b>", "cell_w"), P("<b>1,500 users</b>", "cell_w"), P("<b>3,000 users</b>", "cell_w")],
            [P("Licences already paid<br/><font size=6.5>20% E5 @$60 + 80% E3 @$39</font>", "cell_b"),
             P("$21,600 / mo<br/><b>$259,200 / yr</b>", "cell"),
             P("$64,800 / mo<br/><b>$777,600 / yr</b>", "cell"),
             P("$129,600 / mo<br/><b>$1,555,200 / yr</b>", "cell")],
            [P("<b>New spend to keep as-is</b>", "cell_b"), P("<b>$0</b>", "cell"), P("<b>$0</b>", "cell"), P("<b>$0</b>", "cell")],
            [P("Purview depth for E3 majority<br/><font size=6.5>~$12 × E3 headcount</font>", "cell_b"),
             P("<b>$57,600 / yr</b>", "cell"), P("<b>$172,800 / yr</b>", "cell"), P("<b>$345,600 / yr</b>", "cell")],
            [P("Full Copilot for everyone<br/><font size=6.5>$30 × headcount</font>", "cell_b"),
             P("<b>$180,000 / yr</b>", "cell"), P("<b>$540,000 / yr</b>", "cell"), P("<b>$1,080,000 / yr</b>", "cell")],
        ],
        [2.4 * inch, (CW - 2.4 * inch) / 3, (CW - 2.4 * inch) / 3, (CW - 2.4 * inch) / 3],
        header_bg=SKY,
    ))
    st.append(Spacer(1, 5))
    st.append(grid(
        [
            [P("<b>Strength</b>", "cell_w"), P("<b>Limitation</b>", "cell_w")],
            [P("Zero new spend, zero build, familiar in Office", "cell"),
             P("Controls apply <b>only inside Copilot</b>. ChatGPT = no gate, no log. Purview blocks — cannot scrub-then-answer. No private-model lane.", "cell")],
        ],
        [2.6 * inch, CW - 2.6 * inch],
        header_bg=NAVY,
    ))
    st.append(Spacer(1, 8))

    st.append(banner(
        "OPTION 2 — ExhaustShield gate + Microsoft brain (Azure OpenAI instead of Groq)",
        "Our four lanes decide what may leave · approved text goes to a Microsoft-hosted GPT model",
        VIOLET,
    ))
    st.append(Spacer(1, 6))
    st.append(hflow([
        ("Any employee", "Any licence · one URL or Teams tab", GREEN_LT),
        ("ExhaustShield gate", "Scan → classify → confirm / scrub / hold", TEAL_LT),
        ("Azure OpenAI", "Our tenant · Key Vault · no Copilot seat", SKY_LT),
    ]))
    st.append(Spacer(1, 5))
    st.append(lane_row([
        ("SAFE", "Clean → send after confirm", GREEN_LT),
        ("MEDIUM", "Hide values → scrubbed send", AMBER_LT),
        ("HIGH", "Keys / PHI → private model only", ROSE_LT),
        ("LOCAL", "Policy → our files, no model", VIOLET_LT),
    ]))
    st.append(Spacer(1, 6))
    st.append(P("How to implement in the enterprise", "h2"))
    st.append(grid(
        [
            [P("<b>#</b>", "cell_w"), P("<b>Action</b>", "cell_w")],
            [P("1", "cell_b"), P("<b>Host</b> — deploy gateway to internal VM / App Service with TLS", "cell")],
            [P("2", "cell_b"), P("<b>Identity</b> — Entra SSO so every prompt is attributable (E3, E5, or no Copilot)", "cell")],
            [P("3", "cell_b"), P("<b>Model</b> — Azure OpenAI resource · key in Key Vault · point gate external-AI setting at it", "cell")],
            [P("4", "cell_b"), P("<b>Lanes</b> — Safe + scrubbed Medium → Azure OpenAI · High stays private · Local never calls a model", "cell")],
            [P("5", "cell_b"), P("<b>Assurance</b> — InfoSec test: High-lane text never appears in any Azure OpenAI request log", "cell")],
        ],
        [0.4 * inch, CW - 0.4 * inch],
        header_bg=VIOLET,
    ))
    st.append(Spacer(1, 6))
    st.append(P("Cost — NORMAL scenario (3 chats / user / day), all chats billed", "h2"))
    st.append(grid(
        [
            [P("<b>Model behind gate</b>", "cell_w"), P("<b>500 · 33k chats</b>", "cell_w"),
             P("<b>1,500 · 99k chats</b>", "cell_w"), P("<b>3,000 · 198k chats</b>", "cell_w")],
            [P("Azure GPT-4o-mini @ $0.00045", "cell_b"), P("$14.85 / mo", "cell"), P("$44.55 / mo", "cell"), P("$89.10 / mo", "cell")],
            [P("Azure GPT-5-mini @ $0.00150", "cell_b"), P("$49.50 / mo", "cell"), P("$148.50 / mo", "cell"), P("$297.00 / mo", "cell")],
            [P("Hosting (D2s_v5 × instances)", "cell_b"), P("$70 / mo", "cell"), P("$140 / mo", "cell"), P("$280 / mo", "cell")],
            [P("<b>Total with GPT-5-mini</b>", "cell_b"), P("<b>$120 / mo · $1,434 / yr</b>", "cell"),
             P("<b>$289 / mo · $3,462 / yr</b>", "cell"), P("<b>$577 / mo · $6,924 / yr</b>", "cell")],
        ],
        [2.2 * inch, (CW - 2.2 * inch) / 3, (CW - 2.2 * inch) / 3, (CW - 2.2 * inch) / 3],
        header_bg=TEAL,
        last_hl=True,
    ))
    st.append(Spacer(1, 4))
    st.append(callout(
        "Caution: routing through the real Copilot Chat brain costs ~100× more",
        "Copilot Chat API / Work IQ needs a <b>per-user M365 Copilot licence</b> — "
        "<b>$180k / $540k / $1.08M</b> a year at 500 / 1,500 / 3,000 people. "
        "<b>Azure OpenAI = GPT-class quality, no per-seat fee.</b>",
        ROSE, colors.HexColor("#fda4af"), "mid_w2",
    ))

    st.append(PageBreak())

    # ═══════════════ PAGE 4 — OPTION 3 ═══════════════
    st.append(color_bar())
    st.append(Spacer(1, 5))
    st.append(banner(
        "OPTION 3 — Standalone ExhaustShield dashboard (our pilot, as built)",
        "One front door for everyone · five tabs · Groq as low-cost external brain · runs today",
        TEAL,
    ))
    st.append(Spacer(1, 6))
    st.append(hflow([
        ("Any employee", "Intranet link or Teams website tab · Entra SSO", GREEN_LT),
        ("5-tab dashboard", "Overview · Knowledge · Gate · Vault · Lab", TEAL_LT),
        ("Four lanes", "Safe / Medium / High / Local · every ask logged", AMBER_LT),
        ("External brain", "Groq (or swap to Azure OpenAI later)", SKY_LT),
    ]))
    st.append(Spacer(1, 5))
    st.append(lane_row([
        ("SAFE", "Groq after user confirms", GREEN_LT),
        ("MEDIUM", "Scrubbed text only → Groq", AMBER_LT),
        ("HIGH", "Private Ollama · never external", ROSE_LT),
        ("LOCAL", "Local files or human vault", VIOLET_LT),
    ]))
    st.append(Spacer(1, 7))
    st.append(P("How to implement in the enterprise", "h2"))
    st.append(grid(
        [
            [P("<b>#</b>", "cell_w"), P("<b>Action</b>", "cell_w"), P("<b>Owner</b>", "cell_w")],
            [P("1", "cell_b"), P("<b>Host</b> — existing gateway onto one internal VM with HTTPS", "cell"), P("IT infra", "cell")],
            [P("2", "cell_b"), P("<b>Identity</b> — Entra SSO; all 3,000 can sign in, no Copilot seat needed", "cell"), P("Identity", "cell")],
            [P("3", "cell_b"), P("<b>Brain</b> — Groq key in server env (or Azure OpenAI later — same setting)", "cell"), P("Platform", "cell")],
            [P("4", "cell_b"), P("<b>Private lane</b> — Ollama on same or second VM for High lane", "cell"), P("Platform", "cell")],
            [P("5", "cell_b"), P("<b>Reach</b> — publish as intranet link + Teams website tab", "cell"), P("Comms / IT", "cell")],
            [P("6", "cell_b"), P("<b>Evidence</b> — Overview tab: sensitive words, lanes, team breakdown", "cell"), P("Security", "cell")],
        ],
        [0.4 * inch, 5.0 * inch, CW - 5.4 * inch],
        header_bg=TEAL,
    ))
    st.append(Spacer(1, 7))
    st.append(P("Cost across BEST / NORMAL / WORST (Groq @ $0.00045 + hosting)", "h2"))
    st.append(grid(
        [
            [P("<b>Scenario</b>", "cell_w"), P("<b>500 users</b>", "cell_w"),
             P("<b>1,500 users</b>", "cell_w"), P("<b>3,000 users</b>", "cell_w")],
            [P("BEST — 1 chat/day<br/><font size=6.5>Groq + hosting</font>", "cell_b"),
             P("$4.95 + $70<br/><b>$900 / yr</b>", "cell"),
             P("$14.85 + $140<br/><b>$1,858 / yr</b>", "cell"),
             P("$29.70 + $280<br/><b>$3,716 / yr</b>", "cell")],
            [P("NORMAL — 3 chats/day<br/><font size=6.5>Groq + hosting</font>", "cell_b"),
             P("$14.85 + $70<br/><b>$1,018 / yr</b>", "cell"),
             P("$44.55 + $140<br/><b>$2,215 / yr</b>", "cell"),
             P("$89.10 + $280<br/><b>$4,429 / yr</b>", "cell")],
            [P("WORST — 8 chats/day<br/><font size=6.5>Groq + hosting</font>", "cell_b"),
             P("$39.60 + $70<br/><b>$1,315 / yr</b>", "cell"),
             P("$118.80 + $140<br/><b>$3,106 / yr</b>", "cell"),
             P("$237.60 + $280<br/><b>$6,211 / yr</b>", "cell")],
        ],
        [1.7 * inch, (CW - 1.7 * inch) / 3, (CW - 1.7 * inch) / 3, (CW - 1.7 * inch) / 3],
        header_bg=GREEN,
    ))
    st.append(Spacer(1, 5))
    st.append(callout(
        "Worst case at 3,000 people ≈ $6,200 / year",
        "528,000 governed conversations a month — roughly <b>two Copilot seats</b>. "
        "Vs Option 1: covers all staff + four lanes. Vs Option 2: same gate, lower bill today, swap to Azure OpenAI later.",
        GREEN, colors.HexColor("#6ee7b7"),
    ))
    st.append(Spacer(1, 6))
    st.append(P("Final comparison — net new annual spend (NORMAL · 3 chats / user / day)", "h2"))
    st.append(grid(
        [
            [P("<b></b>", "cell_w"),
             P("<b>OPTION 1<br/>Existing Copilot</b>", "cell_w"),
             P("<b>OPTION 2<br/>Gate + Azure OpenAI</b>", "cell_w"),
             P("<b>OPTION 3<br/>Standalone dashboard</b>", "cell_w")],
            [P("Net new — 500", "cell_b"),
             P("$0 · +$57.6k Purview depth", "cell"),
             P("<b>$1,434</b>", "cell"), P("<b>$1,018</b>", "cell")],
            [P("Net new — 1,500", "cell_b"),
             P("$0 · +$172.8k Purview depth", "cell"),
             P("<b>$3,462</b>", "cell"), P("<b>$2,215</b>", "cell")],
            [P("Net new — 3,000", "cell_b"),
             P("$0 · +$345.6k Purview depth", "cell"),
             P("<b>$6,924</b>", "cell"), P("<b>$4,429</b>", "cell")],
            [P("Worst case — 3,000", "cell_b"), P("Unchanged ($0 new)", "cell"), P("~$10,900", "cell"), P("<b>~$6,211</b>", "cell")],
            [P("Covers non-Copilot staff", "cell_b"), P("No", "cell"), P("<b>Yes</b>", "cell"), P("<b>Yes</b>", "cell")],
            [P("Blocks / scrub / private / local", "cell_b"), P("SIT block only", "cell"), P("<b>All four</b>", "cell"), P("<b>All four</b>", "cell")],
        ],
        [1.85 * inch, (CW - 1.85 * inch) / 3, (CW - 1.85 * inch) / 3, (CW - 1.85 * inch) / 3],
        header_bg=NAVY,
    ))

    st.append(PageBreak())

    # ═══════════════ PAGE 5 — RECOMMENDATION + ASK + SOURCES ═══════════════
    st.append(color_bar())
    st.append(Spacer(1, 6))
    st.append(P("Recommendation · board ask · sources", "h1"))
    st.append(Spacer(1, 5))
    st.append(grid(
        [
            [P("<b></b>", "cell_w"),
             P("<b>OPTION 1</b>", "cell_w"),
             P("<b>OPTION 2</b>", "cell_w"),
             P("<b>OPTION 3</b>", "cell_w")],
            [P("Sensitive words + lanes by team", "cell_b"), P("Adoption reports only", "cell"), P("<b>Yes</b>", "cell"), P("<b>Yes</b>", "cell")],
            [P("Answer quality", "cell_b"), P("GPT-class", "cell"), P("<b>GPT-class</b>", "cell"), P("Open models (swappable)", "cell")],
            [P("Training-data control", "cell_b"), P("Vendor terms", "cell"), P("<b>We decide per lane</b>", "cell"), P("<b>We decide per lane</b>", "cell")],
            [P("Time to live", "cell_b"), P("Live now", "cell"), P("3 – 5 weeks", "cell"), P("<b>1 – 2 weeks (built)</b>", "cell")],
            [P("Board risk if we do nothing", "cell_b"), P("<b>High</b> — 82% unmanaged", "cell"), P("Low", "cell"), P("Low", "cell")],
        ],
        [2.0 * inch, (CW - 2.0 * inch) / 3, (CW - 2.0 * inch) / 3, (CW - 2.0 * inch) / 3],
        header_bg=NAVY,
    ))
    st.append(Spacer(1, 10))
    st.append(callout(
        "RECOMMENDATION — Adopt Option 3 now · keep Option 1 · hold Option 2 as upgrade path",
        "Dashboard for every employee: <b>~$1,000 – $4,400 / year</b> (up to ~$6,200 worst at 3,000). "
        "Keep Copilot + Purview for Office — complementary, not a substitute. "
        "Want GPT-class behind the gate? Switch to <b>Azure OpenAI</b> (~+$2,500 / year) — "
        "never buy Copilot seats for everyone at <b>$180k – $1.08M</b>.",
        TEAL, GREEN,
    ))
    st.append(Spacer(1, 10))
    st.append(P("Three sentences for the minutes", "h2"))
    st.append(grid(
        [
            [P("<b>#</b>", "cell_w"), P("<b>Minute</b>", "cell_w")],
            [P("1", "cell_b"),
             P("Meta discounts tokens <b>92–95%</b> for training rights (~<b>$1.24 / 1M tokens</b>). Today we hand that over for nothing.", "cell")],
            [P("2", "cell_b"),
             P("<b>82%</b> of AI pastes are unmanaged; <b>11%</b> of paste content is sensitive — Copilot-only covers a minority of traffic.", "cell")],
            [P("3", "cell_b"),
             P("A gate for all <b>3,000</b> people ≈ <b>$4,400 / year</b> (NORMAL) — less than <b>13 Copilot seats</b>.", "cell")],
        ],
        [0.35 * inch, CW - 0.35 * inch],
        header_bg=TEAL,
    ))
    st.append(Spacer(1, 10))
    st.append(P("Decision requested", "h2"))
    st.append(grid(
        [
            [P("<b>Decision</b>", "cell_w"), P("<b>Detail</b>", "cell_w")],
            [P("Approve Option 3 pilot", "cell_b"),
             P("Deploy org-wide or phased 500 → 1,500 → 3,000. Budget <b>~$1k – $6.2k / year</b>.", "cell")],
            [P("Keep Option 1 as-is", "cell_b"),
             P("Keep Copilot / Purview for Office. Do not rely on them alone for ChatGPT / Claude traffic.", "cell")],
            [P("Park Option 2 upgrade", "cell_b"),
             P("If quality complaints arise, switch gate to Azure OpenAI (~+$2.5k / yr). Do <b>not</b> buy Copilot for all 3,000.", "cell")],
            [P("Success (90 days)", "cell_b"),
             P("% of AI chats through the gate · High holds · scrubbed Medium sends · zero High text in external logs.", "cell")],
        ],
        [1.55 * inch, CW - 1.55 * inch],
        header_bg=NAVY,
    ))
    st.append(Spacer(1, 10))
    st.append(KeepTogether([
        P("Sources", "h2"),
        P(
            "Microsoft 365 (E3 $39, E5 $60 from Jul 2026; Copilot $30). Copilot Studio Licensing Guide Jun 2026 "
            "($200/25k credits; PAYG $0.01). Microsoft Learn credit rates + Purview DLP for Copilot. Purview Suite ~$12/user/mo (E3). "
            "Azure OpenAI (GPT-4o-mini $0.15/$0.60; GPT-5-mini $0.50/$2; GPT-5 $5/$20 per 1M). Groq gpt-oss-120b $0.15/$0.60. "
            "Azure VM D2s_v5 East US $70.08/mo. Meta Muse Spark 1.3 Standard $1.25/$4.25 vs Contributor $0.10/$0.20. "
            "Meta–News Corp up to $50M/yr; OpenAI–News Corp $250M/5yr; Google–Reddit ~$60M/yr; Meta–Scale AI $14.3B (49%). "
            "Cyberhaven 2026 (11%; 39.7%; every 3 days). LayerX (82% unmanaged; GenAI 32% of corp→personal). "
            "Kiteworks 2026 (65%; AI DLP &lt;30%; $19.5M). Cisco 2026 (bans 28%→7%). List prices; EA discounts may vary.",
            "note",
        ),
    ]))

    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=LETTER,
        leftMargin=ML,
        rightMargin=MR,
        topMargin=MT,
        bottomMargin=MB,
        title="ExhaustShield — Board Decision Deck: Three Options",
        author="Manikandan",
        subject="Governed enterprise AI: cost and architecture comparison",
    )
    doc.build(st, onFirstPage=footer, onLaterPages=footer)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    build()
