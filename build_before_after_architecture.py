"""ExhaustShield — 2-page Before / After architecture PDF (clean layout, no canvas glitches)."""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUT = Path(__file__).resolve().parent / "ExhaustShield_Before_After_Architecture.pdf"
DASHBOARD_TABS_IMG = Path(__file__).resolve().parent / "assets" / "dashboard_tabs.png"

INK = colors.HexColor("#142033")
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
BAND = colors.HexColor("#f8fafc")
WHITE = colors.white
RULE = colors.HexColor("#e2e8f0")
NAVY = colors.HexColor("#0f172a")
BRAND = colors.HexColor("#9bd6c4")

PAGE_W, PAGE_H = LETTER
MARGIN_L = 0.6 * inch
MARGIN_R = 0.6 * inch
MARGIN_T = 0.42 * inch
MARGIN_B = 0.48 * inch
CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R

PAD = 8
CELL_PAD = [
    ("LEFTPADDING", (0, 0), (-1, -1), PAD),
    ("RIGHTPADDING", (0, 0), (-1, -1), PAD),
    ("TOPPADDING", (0, 0), (-1, -1), 6),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
]


def S():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=18, leading=22, textColor=NAVY, alignment=TA_CENTER, spaceAfter=2,
        ),
        "sub": ParagraphStyle(
            "sub", parent=base["Normal"], fontName="Helvetica",
            fontSize=9, leading=12, textColor=MUTED, alignment=TA_CENTER, spaceAfter=4,
        ),
        "sec": ParagraphStyle(
            "sec", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=9.5, leading=12, textColor=WHITE,
        ),
        "secsub": ParagraphStyle(
            "secsub", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=10, textColor=colors.HexColor("#e2e8f0"),
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=9, leading=11, textColor=TEAL, spaceBefore=4, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=12, textColor=INK, spaceAfter=2,
        ),
        "cell": ParagraphStyle(
            "cell", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=11, textColor=INK,
        ),
        "cell_w": ParagraphStyle(
            "cell_w", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=11, textColor=WHITE,
        ),
        "cell_b": ParagraphStyle(
            "cell_b", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=11, textColor=NAVY,
        ),
        "flow": ParagraphStyle(
            "flow", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=11, textColor=NAVY, alignment=TA_CENTER,
        ),
        "flow_sub": ParagraphStyle(
            "flow_sub", parent=base["Normal"], fontName="Helvetica",
            fontSize=7.5, leading=10, textColor=MUTED, alignment=TA_CENTER,
        ),
        "arrow": ParagraphStyle(
            "arrow", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=10, leading=10, textColor=TEAL, alignment=TA_CENTER,
        ),
        "plus_head": ParagraphStyle(
            "plus_head", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=11, leading=14, textColor=WHITE, alignment=TA_CENTER, spaceAfter=3,
        ),
        "plus_tag": ParagraphStyle(
            "plus_tag", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=12, textColor=colors.HexColor("#ccfbf1"),
            alignment=TA_CENTER, spaceAfter=4,
        ),
        "plus_col": ParagraphStyle(
            "plus_col", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8.5, leading=11, textColor=TEAL,
        ),
    }


def P(text: str, style: str = "cell") -> Paragraph:
    return Paragraph(text, S()[style])


def color_bar(width: float) -> Table:
    w = width / 5
    t = Table([["", "", "", "", ""]], colWidths=[w] * 5, rowHeights=[6])
    fills = [TEAL, BLUE, AMBER, ROSE, VIOLET]
    style = [("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]
    for i, c in enumerate(fills):
        style.append(("BACKGROUND", (i, 0), (i, 0), c))
    t.setStyle(TableStyle(style))
    return t


def section_banner(title: str, subtitle: str, bg) -> Table:
    st = S()
    t = Table(
        [[Paragraph(title, st["sec"])], [Paragraph(subtitle, st["secsub"])]],
        colWidths=[CONTENT_W],
    )
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BOX", (0, 0), (-1, -1), 0.5, bg),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (0, 0), 7),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
                ("TOPPADDING", (0, 1), (0, 1), 0),
            ]
        )
    )
    return t


def flow_step(label: str, sub: str, bg, width: float) -> Table:
    st = S()
    t = Table(
        [[Paragraph(label, st["flow"])], [Paragraph(sub, st["flow_sub"])]],
        colWidths=[width],
    )
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BOX", (0, 0), (-1, -1), 0.6, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (0, 0), 5),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 5),
                ("TOPPADDING", (0, 1), (0, 1), 1),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return t


def arrow_cell() -> Paragraph:
    return P("&#8595;", "arrow")


def before_flow() -> Table:
    """Vertical flow using tables — reliable spacing, no canvas."""
    cw = CONTENT_W
    bw = cw * 0.72
    side = (cw - bw) / 2
    steps = [
        flow_step("Employee laptop / browser", "Opens public AI in a new tab", BLUE_LT, bw),
        arrow_cell(),
        flow_step("Public AI sites", "ChatGPT &nbsp;·&nbsp; Groq &nbsp;·&nbsp; Claude &nbsp;·&nbsp; Copilot", AMBER_LT, bw),
        arrow_cell(),
        flow_step("Vendor cloud", "No scan · no confirm · no audit trail", ROSE_LT, bw),
    ]
    rows = [[steps[i]] for i in range(len(steps))]
    t = Table(rows, colWidths=[cw])
    t.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), side),
                ("RIGHTPADDING", (0, 0), (-1, -1), side),
                ("TOPPADDING", (0, 0), (-1, -1), 1),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ]
        )
    )
    return t


def after_flow() -> Table:
    cw = CONTENT_W
    bw = cw * 0.78
    side = (cw - bw) / 2
    lane_w = (cw - 0.24 * inch) / 4
    gap = 0.08 * inch

    top = [
        flow_step("Employees → ExhaustShield Dashboard", "One front door · Tabs 1–5", TEAL_LT, bw),
        arrow_cell(),
        flow_step("GATE: Detect secrets → Route lane", "Tab 2 policy + Tab 3 chat use same gate", BRAND, bw),
        arrow_cell(),
    ]
    lanes = Table(
        [
            [
                flow_step("SAFE", "Outside AI<br/>(after confirm)", GREEN_LT, lane_w),
                flow_step("MEDIUM", "Scrub first<br/>then outside", AMBER_LT, lane_w),
                flow_step("HIGH", "Private Ollama<br/>never external", ROSE_LT, lane_w),
                flow_step("LOCAL", "Docs / human<br/>no outside LLM", VIOLET_LT, lane_w),
            ]
        ],
        colWidths=[lane_w] * 4,
        hAlign="CENTER",
    )
    lanes.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    rows = [[item] for item in top] + [[lanes]] + [[P("<i>ChatGPT convenience — with enterprise rules</i>", "flow_sub")]]
    t = Table(rows, colWidths=[cw])
    t.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), max(side, gap)),
                ("RIGHTPADDING", (0, 0), (-1, -1), max(side, gap)),
                ("TOPPADDING", (0, 0), (-1, -1), 1),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ]
        )
    )
    return t


def two_col_cards(left_title: str, left_lines: list[str], left_bg, right_title: str, right_lines: list[str], right_bg) -> Table:
    st = S()
    half = (CONTENT_W - 0.1 * inch) / 2

    def card(title, lines, bg):
        rows = [[Paragraph(f"<b>{title}</b>", st["cell_b"])]]
        for line in lines:
            rows.append([Paragraph(f"• {line}", st["cell"])])
        t = Table(rows, colWidths=[half])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), bg),
                    ("BOX", (0, 0), (-1, -1), 0.5, RULE),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    *CELL_PAD,
                ]
            )
        )
        return t

    outer = Table([[card(left_title, left_lines, left_bg), card(right_title, right_lines, right_bg)]], colWidths=[half, half])
    outer.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (0, 0), 4),
                ("RIGHTPADDING", (1, 0), (1, 0), 0),
            ]
        )
    )
    return outer


def lane_table() -> Table:
    st = S()
    header = [
        P("<b>Lane</b>", "cell_w"),
        P("<b>When it applies</b>", "cell_w"),
        P("<b>Where it goes</b>", "cell_w"),
    ]
    data = [
        header,
        [P("<font color='#059669'><b>SAFE</b></font>", "cell_b"), P("No secrets in the prompt", "cell"), P("Groq after you confirm", "cell")],
        [P("<font color='#b45309'><b>MEDIUM</b></font>", "cell_b"), P("Company names, deal amounts", "cell"), P("Scrubbed text only → Groq", "cell")],
        [P("<font color='#be123c'><b>HIGH</b></font>", "cell_b"), P("Keys, PHI, employee IDs", "cell"), P("Private Ollama — never external", "cell")],
        [P("<font color='#6d28d9'><b>LOCAL</b></font>", "cell_b"), P("Policy doc keyword match", "cell"), P("Local files or human vault", "cell")],
    ]
    t = Table(data, colWidths=[0.85 * inch, 2.35 * inch, CONTENT_W - 0.85 * inch - 2.35 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("BACKGROUND", (0, 1), (-1, 1), GREEN_LT),
                ("BACKGROUND", (0, 2), (-1, 2), AMBER_LT),
                ("BACKGROUND", (0, 3), (-1, 3), ROSE_LT),
                ("BACKGROUND", (0, 4), (-1, 4), VIOLET_LT),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, RULE),
                *CELL_PAD,
            ]
        )
    )
    return t


def one_dashboard_box() -> Table:
    """Standout callout — one dashboard for policy search + generic AI."""
    st = S()
    half = (CONTENT_W - 0.12 * inch) / 2

    def col(title: str, accent: str, lines: list[str], bg) -> Table:
        rows = [[Paragraph(f"<font color='{accent}'><b>{title}</b></font>", st["plus_col"])]]
        for line in lines:
            rows.append([Paragraph(line, st["cell"])])
        t = Table(rows, colWidths=[half])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), bg),
                    ("BOX", (0, 0), (-1, -1), 0.6, RULE),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    *CELL_PAD,
                ]
            )
        )
        return t

    cols = Table(
        [[
            col(
                "Tab 2 · Company knowledge",
                "#6d28d9",
                [
                    "<b>Policy &amp; doc questions</b> — HR rules, deal facts, acquisitions.",
                    "Searches local files on this machine.",
                    "Answers from documents — <b>no outside LLM</b>.",
                ],
                VIOLET_LT,
            ),
            col(
                "Tab 3 · Outbound Gate",
                "#b45309",
                [
                    "<b>Generic AI chat</b> — drafts, summaries, brainstorming.",
                    "Same gate scans every prompt before it leaves.",
                    "Safe / Medium / High routing — <b>ChatGPT with rules</b>.",
                ],
                AMBER_LT,
            ),
        ]],
        colWidths=[half, half],
    )
    cols.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (0, 0), 5),
                ("RIGHTPADDING", (1, 0), (1, 0), 0),
            ]
        )
    )

    outer = Table(
        [
            [Paragraph("<b>One dashboard — policy search and AI chat</b>", st["plus_head"])],
            [Paragraph(
                "Employees stop switching between SharePoint and ChatGPT. "
                "<b>One login, one screen</b> — company policy search <b>and</b> generic AI chat, "
                "both behind the same security gate and audit trail.",
                st["plus_tag"],
            )],
            [cols],
        ],
        colWidths=[CONTENT_W],
    )
    outer.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), TEAL),
                ("BOX", (0, 0), (-1, -1), 1.2, GREEN),
                ("LINEBELOW", (0, 1), (-1, 1), 0.5, colors.HexColor("#0d9488")),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (0, 0), 7),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
                ("TOPPADDING", (0, 1), (0, 1), 2),
                ("BOTTOMPADDING", (0, 1), (0, 1), 5),
                ("TOPPADDING", (0, 2), (0, 2), 0),
            ]
        )
    )
    return outer


def dashboard_tabs_screenshot() -> Table:
    if not DASHBOARD_TABS_IMG.exists():
        raise FileNotFoundError(
            f"Missing dashboard screenshot: {DASHBOARD_TABS_IMG}. "
            "Capture the live dashboard header + tabs and save it there."
        )
    from reportlab.lib.utils import ImageReader

    iw, ih = ImageReader(str(DASHBOARD_TABS_IMG)).getSize()
    w = CONTENT_W
    h = w * ih / iw
    img = Image(str(DASHBOARD_TABS_IMG), width=w, height=h)
    frame = Table([[img]], colWidths=[w])
    frame.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#334155")),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )
    frame.hAlign = "CENTER"
    return frame


def risk_examples_table() -> Table:
    """Fill page 1 — concrete leak scenarios in a compact grid."""
    rows = [
        [P("<b>Scenario</b>", "cell_w"), P("<b>What gets pasted</b>", "cell_w"), P("<b>Why it hurts</b>", "cell_w")],
        [
            P("HR question", "cell_b"),
            P("Salary bands, employee IDs, termination notes", "cell"),
            P("PHI/PII stored on vendor servers forever", "cell"),
        ],
        [
            P("Sales prep", "cell_b"),
            P("Deal names, pricing, customer contracts", "cell"),
            P("Competitive intelligence leaves the building", "cell"),
        ],
        [
            P("Engineering debug", "cell_b"),
            P("API keys, stack traces, internal URLs", "cell"),
            P("Credentials may enter model training pipelines", "cell"),
        ],
    ]
    cw = CONTENT_W
    t = Table(rows, colWidths=[1.05 * inch, 2.45 * inch, cw - 3.5 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [ROSE_LT, AMBER_LT, BLUE_LT]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, RULE),
                *CELL_PAD,
            ]
        )
    )
    return t


def info_box(title: str, lines: list[str], bg) -> Table:
    st = S()
    rows = [[Paragraph(f"<b>{title}</b>", st["cell_b"])]]
    for line in lines:
        rows.append([Paragraph(line, st["body"])])
    t = Table(rows, colWidths=[CONTENT_W])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BOX", (0, 0), (-1, -1), 0.5, RULE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                *CELL_PAD,
            ]
        )
    )
    return t


def page_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(TEAL)
    canvas.setLineWidth(1.5)
    y = MARGIN_B - 0.12 * inch
    canvas.line(MARGIN_L, y + 0.14 * inch, PAGE_W - MARGIN_R, y + 0.14 * inch)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN_L, y - 0.02 * inch, "ExhaustShield · Before / After Architecture")
    canvas.setFillColor(TEAL)
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.drawCentredString(PAGE_W / 2, y - 0.02 * inch, "Designed by Manikandan")
    canvas.drawRightString(PAGE_W - MARGIN_R, y - 0.02 * inch, f"Page {doc.page} of 2")
    canvas.restoreState()


def build():
    st = S()
    story = []

    # ── PAGE 1 ──
    story.append(color_bar(CONTENT_W))
    story.append(Spacer(1, 3))
    story.append(P("Before ExhaustShield", "title"))
    story.append(P("Ungoverned AI — employees send company data straight to the public cloud.", "sub"))
    story.append(section_banner(
        "THE OLD MODEL: Shadow AI",
        "Convenient for users · invisible and risky for the enterprise",
        ROSE,
    ))
    story.append(Spacer(1, 4))
    story.append(before_flow())
    story.append(Spacer(1, 5))
    story.append(two_col_cards(
        "What employees do today",
        [
            "Open ChatGPT, Groq, Claude, or Copilot in a browser.",
            "Paste policy text, deal names, salaries, and API keys.",
            "No scanner, no confirm step, no audit of what left.",
            "Every team picks its own tool — no single choke point.",
        ],
        ROSE_LT,
        "Why security loses sleep",
        [
            "<b>Data leak</b> — prompts live on vendor servers.",
            "<b>Wrong audience</b> — anyone can ask anything.",
            "<b>Guesswork</b> — models invent policy instead of reading files.",
            "<b>No proof</b> — audits cannot show who sent what.",
        ],
        AMBER_LT,
    ))
    story.append(Spacer(1, 5))
    story.append(P("Real-world leak scenarios (no gate today)", "h2"))
    story.append(risk_examples_table())
    story.append(Spacer(1, 5))
    story.append(info_box(
        "Bottom line",
        [
            "Public AI feels productive until a secret, salary, or customer name hits the vendor cloud. "
            "Policy slides are not a control — you need a <b>technical door</b> that scans, routes, and logs every prompt.",
        ],
        colors.HexColor("#fff1f2"),
    ))

    story.append(PageBreak())

    # ── PAGE 2 ──
    story.append(color_bar(CONTENT_W))
    story.append(Spacer(1, 3))
    story.append(P("After ExhaustShield — Live", "title"))
    story.append(P(
        "One dashboard for company policy search and generic AI chat — every prompt scanned first.",
        "sub",
    ))
    story.append(section_banner(
        "THE NEW MODEL: Control plane + AI",
        "Employees chat here · gateway decides what may leave · everything is logged",
        TEAL,
    ))
    story.append(Spacer(1, 4))
    story.append(one_dashboard_box())
    story.append(Spacer(1, 4))
    story.append(after_flow())
    story.append(Spacer(1, 4))
    story.append(P("Four routing lanes", "h2"))
    story.append(lane_table())
    story.append(Spacer(1, 4))
    story.append(P("Five dashboard tabs", "h2"))
    story.append(dashboard_tabs_screenshot())
    story.append(Spacer(1, 2))
    story.append(P(
        "<i>Same dashboard — Tab 2 for policy docs, Tab 3 for AI chat. "
        "Safe/Medium prompts can still reach outside AI after confirm or scrub.</i>",
        "flow_sub",
    ))

    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=LETTER,
        leftMargin=MARGIN_L,
        rightMargin=MARGIN_R,
        topMargin=MARGIN_T,
        bottomMargin=MARGIN_B,
        title="ExhaustShield Before / After Architecture",
        author="Manikandan",
    )
    doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    build()
