"""Board brief: Option A Copilot Studio vs Option B standalone dashboard (500 people)."""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUT = Path(__file__).resolve().parent / "ExhaustShield_Board_Options_A_B.pdf"

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

PAGE_W, PAGE_H = LETTER
ML, MR, MT, MB = 0.52 * inch, 0.52 * inch, 0.4 * inch, 0.48 * inch
CW = PAGE_W - ML - MR
PAD = [
    ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ("TOPPADDING", (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
]


def S():
    b = getSampleStyleSheet()
    return {
        "kicker": ParagraphStyle(
            "kicker", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=8, textColor=TEAL, alignment=TA_CENTER, spaceAfter=2,
        ),
        "title": ParagraphStyle(
            "title", parent=b["Title"], fontName="Helvetica-Bold",
            fontSize=16, leading=19, textColor=NAVY, alignment=TA_CENTER, spaceAfter=3,
        ),
        "sub": ParagraphStyle(
            "sub", parent=b["Normal"], fontName="Helvetica",
            fontSize=8.2, leading=11, textColor=MUTED, alignment=TA_CENTER, spaceAfter=5,
        ),
        "h2": ParagraphStyle(
            "h2", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=9.5, leading=12, textColor=TEAL, spaceBefore=2, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body", parent=b["Normal"], fontName="Helvetica",
            fontSize=8, leading=11, textColor=INK, spaceAfter=3,
        ),
        "cell": ParagraphStyle(
            "cell", parent=b["Normal"], fontName="Helvetica",
            fontSize=7.4, leading=10, textColor=INK,
        ),
        "cell_b": ParagraphStyle(
            "cell_b", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=7.4, leading=10, textColor=NAVY,
        ),
        "cell_w": ParagraphStyle(
            "cell_w", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=7.4, leading=10, textColor=WHITE,
        ),
        "tiny": ParagraphStyle(
            "tiny", parent=b["Normal"], fontName="Helvetica",
            fontSize=7, leading=9, textColor=MUTED, spaceAfter=2,
        ),
        "flow": ParagraphStyle(
            "flow", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=7.3, leading=9.5, textColor=NAVY, alignment=TA_CENTER,
        ),
        "flow_s": ParagraphStyle(
            "flow_s", parent=b["Normal"], fontName="Helvetica",
            fontSize=6.3, leading=8.2, textColor=MUTED, alignment=TA_CENTER,
        ),
        "arr": ParagraphStyle(
            "arr", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=11, leading=12, textColor=TEAL, alignment=TA_CENTER,
        ),
        "rec": ParagraphStyle(
            "rec", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=10.5, leading=13, textColor=WHITE, alignment=TA_CENTER,
        ),
        "rec_s": ParagraphStyle(
            "rec_s", parent=b["Normal"], fontName="Helvetica",
            fontSize=8, leading=11, textColor=colors.HexColor("#ccfbf1"), alignment=TA_CENTER,
        ),
        "sec": ParagraphStyle(
            "sec", parent=b["Normal"], fontName="Helvetica-Bold",
            fontSize=9, leading=11, textColor=WHITE,
        ),
        "sec_s": ParagraphStyle(
            "sec_s", parent=b["Normal"], fontName="Helvetica",
            fontSize=7.4, leading=10, textColor=colors.HexColor("#e2e8f0"),
        ),
    }


def P(text: str, style: str = "cell") -> Paragraph:
    return Paragraph(text, S()[style])


def color_bar() -> Table:
    w = CW / 5
    t = Table([["", "", "", "", ""]], colWidths=[w] * 5, rowHeights=[6])
    t.setStyle(
        TableStyle(
            [("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]
            + [("BACKGROUND", (i, 0), (i, 0), c) for i, c in enumerate([TEAL, BLUE, AMBER, ROSE, VIOLET])]
        )
    )
    return t


def banner(title: str, sub: str, bg) -> Table:
    t = Table([[P(title, "sec")], [P(sub, "sec_s")]], colWidths=[CW])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (0, 0), 7),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
                ("TOPPADDING", (0, 1), (0, 1), 0),
            ]
        )
    )
    return t


def rec_box() -> Table:
    t = Table(
        [
            [P("BOARD RECOMMENDATION — Choose Option B", "rec")],
            [
                P(
                    "Standalone ExhaustShield dashboard for all 500 Entra users. "
                    "Expected extra cost about <b>$120–$2,100 per year</b> versus Option A "
                    "<b>$20,000–$23,000</b> (Studio credits) or about <b>$181,000/year</b> if you buy "
                    "Copilot seats so Studio usage is zero-rated. Same gate. Broader coverage. "
                    "Keep Microsoft Copilot for Office.",
                    "rec_s",
                )
            ],
        ],
        colWidths=[CW],
    )
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), TEAL),
                ("BOX", (0, 0), (-1, -1), 1.2, GREEN),
                ("LEFTPADDING", (0, 0), (-1, -1), 11),
                ("RIGHTPADDING", (0, 0), (-1, -1), 11),
                ("TOPPADDING", (0, 0), (0, 0), 8),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
                ("TOPPADDING", (0, 1), (0, 1), 2),
            ]
        )
    )
    return t


def step(label: str, sub: str, bg, w: float) -> Table:
    t = Table([[P(label, "flow")], [P(sub, "flow_s")]], colWidths=[w])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BOX", (0, 0), (-1, -1), 0.5, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return t


def flow_row(boxes: list) -> Table:
    aw = 0.14 * inch
    bw = (CW - 3 * aw) / 4
    row = [boxes[0], P("→", "arr"), boxes[1], P("→", "arr"), boxes[2], P("→", "arr"), boxes[3]]
    t = Table([row], colWidths=[bw, aw, bw, aw, bw, aw, bw])
    t.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 1),
                ("RIGHTPADDING", (0, 0), (-1, -1), 1),
            ]
        )
    )
    return t


def grid(rows, widths, header_bg=NAVY) -> Table:
    t = Table(rows, colWidths=widths)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), header_bg),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, RULE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, BAND]),
                *PAD,
            ]
        )
    )
    return t


def money_grid(rows, widths) -> Table:
    t = Table(rows, colWidths=widths)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("BACKGROUND", (0, -1), (-1, -1), TEAL_LT),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, RULE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [WHITE, BAND]),
                *PAD,
            ]
        )
    )
    return t


def footer(c, doc):
    c.saveState()
    c.setStrokeColor(TEAL)
    c.setLineWidth(1.4)
    y = MB - 0.14 * inch
    c.line(ML, y + 0.16 * inch, PAGE_W - MR, y + 0.16 * inch)
    c.setFont("Helvetica", 7)
    c.setFillColor(MUTED)
    c.drawString(ML, y, "ExhaustShield · Board options A vs B · 500 people · list prices Sep 2026")
    c.setFillColor(TEAL)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawCentredString(PAGE_W / 2, y, "Designed by Manikandan")
    c.drawRightString(PAGE_W - MR, y, f"Page {doc.page} of 4")
    c.restoreState()


def build():
    bw = (CW - 0.42 * inch) / 4
    story = []

    # PAGE 1
    story.append(color_bar())
    story.append(Spacer(1, 4))
    story.append(P("CONFIDENTIAL · BOARD BRIEF · 500 PEOPLE", "kicker"))
    story.append(P("How to run ExhaustShield in the organisation", "title"))
    story.append(
        P(
            "Option A — Copilot Studio agent wrapping the ExhaustShield gate. "
            "Option B — one standalone dashboard every Entra user can open. "
            "Prices: Microsoft Copilot Studio Licensing Guide (Jun 2026), Learn billing rates, "
            "M365 Copilot $30/user/month, Groq gpt-oss-120b (Sep 2026).",
            "sub",
        )
    )
    story.append(rec_box())
    story.append(Spacer(1, 6))
    story.append(P("What we are deciding", "h2"))
    story.append(
        P(
            "ExhaustShield is a <b>prompt gate</b> (scan → Safe / Medium / High / Local), not a chatbot SKU. "
            "Microsoft 365 Copilot + Purview DLP is a <b>filter on Copilot</b>. "
            "Not everyone is E5 or Copilot-licensed. The question: where do <b>all 500 people</b> go "
            "for governed AI — and what does that cost <b>on top of</b> licences you already buy.",
            "body",
        )
    )
    story.append(
        grid(
            [
                [P("<b>Item</b>", "cell_w"), P("<b>Assumption used in the math</b>", "cell_w")],
                [P("Population", "cell_b"), P("500 people, mixed E3 / E5 — <b>not all Copilot-licensed</b>", "cell")],
                [P("Workdays", "cell_b"), P("22 per month", "cell")],
                [
                    P("Expected usage", "cell_b"),
                    P("<b>2 gated chats / user / day</b> = <b>22,000</b> conversations / month", "cell"),
                ],
                [P("Heavy usage", "cell_b"), P("8 chats / user / day = 88,000 / month (sensitivity case)", "cell")],
                [P("Mix", "cell_b"), P("~40% policy (Tab 2, no outside LLM) · ~60% generic chat (Tab 3)", "cell")],
                [
                    P("Groq (outside brain)", "cell_b"),
                    P("$0.15 / 1M input · $0.60 / 1M output · about $0.0004–$0.0007 per short chat", "cell"),
                ],
                [
                    P("Studio credits", "cell_b"),
                    P(
                        "PAYG <b>$0.01 / credit</b> · pack <b>$200 / 25,000 credits</b> (~$0.008). "
                        "Unused packs <b>do not roll</b> to next month.",
                        "cell",
                    ),
                ],
                [
                    P("Agent action", "cell_b"),
                    P(
                        "<b>5 credits</b> per HTTP/tool call. M365 Copilot users: often <b>no charge</b> "
                        "in Teams/Copilot. Everyone else <b>pays credits</b>.",
                        "cell",
                    ),
                ],
            ],
            [1.4 * inch, CW - 1.4 * inch],
        )
    )
    story.append(Spacer(1, 5))
    story.append(
        P(
            "<b>Honest definition of Option A:</b> Studio cannot be the classifier. "
            "“ExhaustShield in Studio” means a Studio <b>chat skin</b> that calls <b>your</b> gateway. "
            "You still host the Python gate (and Groq/Ollama). A Studio-only agent with Purview is "
            "<b>not</b> this pilot.",
            "body",
        )
    )

    story.append(PageBreak())

    # PAGE 2 Option A
    story.append(color_bar())
    story.append(Spacer(1, 4))
    story.append(
        banner(
            "OPTION A — Copilot Studio agent + ExhaustShield API",
            "Employees chat in Teams / Copilot · Studio must call our gate · High must never hit Microsoft’s model",
            VIOLET,
        )
    )
    story.append(Spacer(1, 5))
    story.append(P("Architecture", "h2"))
    story.append(
        flow_row(
            [
                step("1 · Employee", "Teams or Copilot Chat", BLUE_LT, bw),
                step("2 · Studio agent", "Topics only — no self-answer", VIOLET_LT, bw),
                step("3 · ExhaustShield API", "/ask-knowledge · /generate · confirm", TEAL_LT, bw),
                step("4 · Lane", "Safe/Med → Groq · High → Ollama · Local → files", AMBER_LT, bw),
            ]
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        P(
            "You pay <b>Studio consumption</b> (for people without M365 Copilot) <b>plus</b> the same "
            "hosting + Groq as Option B. Overview / team insights stay on the dashboard unless rebuilt in Purview.",
            "tiny",
        )
    )
    story.append(P("Credit math (people without M365 Copilot)", "h2"))
    story.append(
        P(
            "Policy turn ≈ 1 agent action (5 cr). Chat turn ≈ Check (5) + often Confirm (5) ≈ 10 cr. "
            "Blended ≈ <b>8 credits / conversation</b>.",
            "tiny",
        )
    )
    story.append(
        grid(
            [
                [
                    P("<b>Volume</b>", "cell_w"),
                    P("<b>Credits / month</b>", "cell_w"),
                    P("<b>PAYG $0.01</b>", "cell_w"),
                    P("<b>Packs $200</b>", "cell_w"),
                ],
                [
                    P("Expected 22,000 chats", "cell_b"),
                    P("176,000", "cell"),
                    P("<b>$1,760</b>", "cell"),
                    P("8 packs = <b>$1,600</b>", "cell"),
                ],
                [
                    P("Heavy 88,000 chats", "cell_b"),
                    P("704,000", "cell"),
                    P("<b>$7,040</b>", "cell"),
                    P("29 packs = <b>$5,800</b>", "cell"),
                ],
            ],
            [2.05 * inch, 1.45 * inch, 1.5 * inch, CW - 5.0 * inch],
            header_bg=VIOLET,
        )
    )
    story.append(Spacer(1, 5))
    story.append(P("Option A monthly cash — expected 22k chats (all 500 can use it)", "h2"))
    story.append(
        money_grid(
            [
                [P("<b>Line</b>", "cell_w"), P("<b>What it is</b>", "cell_w"), P("<b>USD / month</b>", "cell_w")],
                [
                    P("Studio credits", "cell_b"),
                    P("If most of 500 do <b>not</b> have M365 Copilot ($30 USL)", "cell"),
                    P("$1,600 – $1,760", "cell"),
                ],
                [
                    P("ExhaustShield host", "cell_b"),
                    P("Still required — VM / App Service + TLS", "cell"),
                    P("$90 – $150", "cell"),
                ],
                [
                    P("Groq API", "cell_b"),
                    P("Safe / scrubbed Medium only", "cell"),
                    P("$10 – $25", "cell"),
                ],
                [P("Ollama High", "cell_b"), P("Same VM — no licence", "cell"), P("$0", "cell")],
                [P("Entra / Teams channel", "cell_b"), P("Existing M365", "cell"), P("$0", "cell")],
                [
                    P("Build / connector", "cell_b"),
                    P("Custom connector + topics (internal weeks, not a SKU)", "cell"),
                    P("Labour", "cell"),
                ],
                [
                    P("<b>A1 TOTAL extra</b>", "cell_b"),
                    P("<b>Studio skin + same brain as B</b>", "cell"),
                    P("<b>$1,700 – $1,940</b>", "cell"),
                ],
            ],
            [1.55 * inch, 4.15 * inch, CW - 5.7 * inch],
        )
    )
    story.append(Spacer(1, 4))
    story.append(P("If the board “makes Studio cheap” by buying Copilot for all 500", "h2"))
    story.append(
        money_grid(
            [
                [P("<b>Line</b>", "cell_w"), P("<b>Math</b>", "cell_w"), P("<b>USD</b>", "cell_w")],
                [
                    P("M365 Copilot USL", "cell_b"),
                    P("500 × $30 / month (list, billed yearly)", "cell"),
                    P("$15,000 / mo · $180,000 / yr", "cell"),
                ],
                [
                    P("Studio credits", "cell_b"),
                    P("Often $0 for those users in Teams/Copilot (fair use)", "cell"),
                    P("$0", "cell"),
                ],
                [
                    P("Host + Groq", "cell_b"),
                    P("Still required for the real gate", "cell"),
                    P("~$100 – $175 / mo", "cell"),
                ],
                [
                    P("<b>A2 TOTAL extra</b>", "cell_b"),
                    P("<b>Only if they do not already own 500 Copilot seats</b>", "cell"),
                    P("<b>~$181k / year</b>", "cell"),
                ],
            ],
            [1.55 * inch, 3.55 * inch, CW - 5.1 * inch],
        )
    )
    story.append(
        P(
            "A2 does <b>not</b> replace Option B’s cost advantage: you still run ExhaustShield. "
            "You bought Copilot for Office plus zero-rated agent clicks.",
            "tiny",
        )
    )

    story.append(PageBreak())

    # PAGE 3 Option B
    story.append(color_bar())
    story.append(Spacer(1, 4))
    story.append(
        banner(
            "OPTION B — Standalone ExhaustShield dashboard (recommended)",
            "One URL / Teams website tab · Entra login · all 500 · code you already have",
            TEAL,
        )
    )
    story.append(Spacer(1, 5))
    story.append(P("Architecture", "h2"))
    story.append(
        flow_row(
            [
                step("1 · Any employee", "Browser or Teams website tab", GREEN_LT, bw),
                step("2 · Dashboard", "Tabs 1–5 · one front door", TEAL_LT, bw),
                step("3 · Gate on our VM", "Detect → route · audit", AMBER_LT, bw),
                step("4 · Lane", "Groq / Ollama / files / human", ROSE_LT, bw),
            ]
        )
    )
    story.append(Spacer(1, 5))
    story.append(P("Option B monthly cash — same 22k chats, all 500 can log in", "h2"))
    story.append(
        money_grid(
            [
                [P("<b>Line</b>", "cell_w"), P("<b>What it is</b>", "cell_w"), P("<b>USD / month</b>", "cell_w")],
                [
                    P("Application", "cell_b"),
                    P("Existing FastAPI dashboard — no Microsoft agent SKU", "cell"),
                    P("$0", "cell"),
                ],
                [
                    P("Host", "cell_b"),
                    P("Internal VM (often $0 extra) or Azure B-series", "cell"),
                    P("$0 – $150", "cell"),
                ],
                [
                    P("Groq", "cell_b"),
                    P("~13k external chats × ~$0.0005 (policy stays local)", "cell"),
                    P("$10 – $25", "cell"),
                ],
                [P("Ollama", "cell_b"), P("High lane on same box", "cell"), P("$0", "cell")],
                [P("Identity", "cell_b"), P("Entra SSO — existing tenant", "cell"), P("$0", "cell")],
                [
                    P("Distribution", "cell_b"),
                    P("Intranet link + Teams <b>website tab</b> (not Studio)", "cell"),
                    P("$0", "cell"),
                ],
                [
                    P("Copilot seats", "cell_b"),
                    P("Unchanged — keep for Word / Excel / Teams", "cell"),
                    P("$0 extra", "cell"),
                ],
                [
                    P("<b>B TOTAL extra</b>", "cell_b"),
                    P("<b>If you already have a server: Groq only</b>", "cell"),
                    P("<b>$10 – $175</b>", "cell"),
                ],
            ],
            [1.4 * inch, 4.35 * inch, CW - 5.75 * inch],
        )
    )
    story.append(Spacer(1, 5))
    story.append(P("Year-1 extra cost (expected usage) — like-for-like", "h2"))
    story.append(
        grid(
            [
                [
                    P("<b></b>", "cell_w"),
                    P("<b>A1 Studio credits</b>", "cell_w"),
                    P("<b>A2 + 500 Copilot</b>", "cell_w"),
                    P("<b>B dashboard</b>", "cell_w"),
                ],
                [
                    P("Monthly extra", "cell_b"),
                    P("$1,700 – $1,940", "cell"),
                    P("~$15,100 – $15,175", "cell"),
                    P("$10 – $175", "cell"),
                ],
                [
                    P("Year extra", "cell_b"),
                    P("<b>$20k – $23k</b>", "cell"),
                    P("<b>~$181k</b>", "cell"),
                    P("<b>$120 – $2,100</b>", "cell"),
                ],
                [
                    P("Covers non-Copilot staff", "cell_b"),
                    P("Yes, but they <b>generate the credit bill</b>", "cell"),
                    P("Yes, after $180k seats", "cell"),
                    P("<b>Yes — Entra only</b>", "cell"),
                ],
                [
                    P("True Exhaust lanes", "cell_b"),
                    P("Yes, if API is wired correctly", "cell"),
                    P("Yes — same API", "cell"),
                    P("<b>Yes — native UI</b>", "cell"),
                ],
                [
                    P("Management scoreboard", "cell_b"),
                    P("Split: Studio + our /api/stats", "cell"),
                    P("Same split", "cell"),
                    P("<b>Overview tab built-in</b>", "cell"),
                ],
                [
                    P("Heavy 88k chats / mo", "cell_b"),
                    P("Studio ~$5.8k–$7k + host + Groq", "cell"),
                    P("Still ~$15k Copilot + Groq", "cell"),
                    P("Groq ~$40–$80 + host", "cell"),
                ],
            ],
            [1.5 * inch, 1.85 * inch, 1.9 * inch, CW - 5.25 * inch],
            header_bg=TEAL,
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        P(
            "Pilot-only (20 people, simulate or Groq free): Option B can be <b>$0</b>. "
            "Option A still needs Studio PAYG/packs as soon as non-Copilot users hit HTTP actions at scale.",
            "tiny",
        )
    )

    story.append(PageBreak())

    # PAGE 4 Purview + rec
    story.append(color_bar())
    story.append(Spacer(1, 4))
    story.append(
        banner(
            "THIS PILOT vs COPILOT + PURVIEW DLP",
            "Purview is already useful — it is not ExhaustShield and it does not cover non-Copilot staff",
            ROSE,
        )
    )
    story.append(Spacer(1, 5))
    half = (CW - 1.35 * inch) / 2
    story.append(
        grid(
            [
                [
                    P("<b>Board question</b>", "cell_w"),
                    P("<b>Copilot + Purview DLP</b>", "cell_w"),
                    P("<b>ExhaustShield dashboard</b>", "cell_w"),
                ],
                [
                    P("What it is", "cell_b"),
                    P(
                        "Microsoft <b>filter on Copilot prompts</b> (SITs). Included with Copilot / Copilot Chat — "
                        "configure, not a new Exhaust SKU.",
                        "cell",
                    ),
                    P(
                        "Company <b>door</b>: scan then four lanes, confirm, scrub, private High, local no-LLM.",
                        "cell",
                    ),
                ],
                [
                    P("Who is in scope", "cell_b"),
                    P(
                        "People using <b>Copilot</b>. No Copilot / many E3 = <b>gap</b>. ChatGPT.com still invisible.",
                        "cell",
                    ),
                    P("<b>Any of 500</b> with Entra + the URL.", "cell"),
                ],
                [
                    P("Sensitive words", "cell_b"),
                    P("SITs you defined (SSN, PAN, custom). Default policy often starts in <b>simulation</b>.", "cell"),
                    P("Exact hide-spans used for mask/rewrite — demo scoreboard.", "cell"),
                ],
                [
                    P("Which team used AI more", "cell_b"),
                    P("Copilot Dashboard / Viva: <b>adoption</b>, not lanes.", "cell"),
                    P("Lanes by team + sensitive-by-team on Overview.", "cell"),
                ],
                [
                    P("Scrub then send", "cell_b"),
                    P("<b>No</b> — block processing or block web search.", "cell"),
                    P("<b>Yes — Medium</b>.", "cell"),
                ],
                [
                    P("Private model / never leave", "cell_b"),
                    P("<b>No</b> — Copilot is Microsoft cloud.", "cell"),
                    P("<b>Yes — High → Ollama</b>.", "cell"),
                ],
                [
                    P("Policy without an LLM", "cell_b"),
                    P("<b>No</b> — Graph + model.", "cell"),
                    P("<b>Yes — Tab 2</b>.", "cell"),
                ],
                [
                    P("Cost to cover 500 this way", "cell_b"),
                    P(
                        "Buy Copilot for the rest: e.g. 300 × $30 = <b>$9,000/mo</b> — still not four lanes.",
                        "cell",
                    ),
                    P("Option B extra <b>~$10–$175/mo</b>.", "cell"),
                ],
            ],
            [1.35 * inch, half, half],
            header_bg=ROSE,
        )
    )
    story.append(Spacer(1, 5))
    story.append(P("Purview limitations (say this once)", "h2"))
    story.append(
        P(
            "1. It does not sit in front of Groq / ChatGPT / Claude. "
            "2. It does not implement Safe-confirm / Medium-scrub / High-Ollama / Local-files. "
            "3. Insights are compliance (DLP hits) and Copilot usage — not “what would have left.” "
            "4. Mixed E5 means mixed Purview depth. "
            "5. Keep Purview <b>on</b> for Copilot users — complementary, not a substitute.",
            "body",
        )
    )
    story.append(P("Why B outperforms A on benefits and cost", "h2"))
    story.append(
        grid(
            [
                [P("<b>Benefit</b>", "cell_w"), P("<b>Winner</b>", "cell_w"), P("<b>Why</b>", "cell_w")],
                [
                    P("Cash at 500 mixed licences", "cell_b"),
                    P("B", "cell"),
                    P("~10–20× cheaper than A1 credits; ~80–100× cheaper than A2 Copilot seats", "cell"),
                ],
                [
                    P("All 500 people", "cell_b"),
                    P("B", "cell"),
                    P("Entra + Teams tab. A bills or excludes non-Copilot users", "cell"),
                ],
                [
                    P("Faithful Exhaust plan", "cell_b"),
                    P("B", "cell"),
                    P("Native UI for confirm / scrub / scoreboard. A is a thin chat wrapper + same API", "cell"),
                ],
                [
                    P("Microsoft familiarity", "cell_b"),
                    P("A", "cell"),
                    P("Chat lives in Teams/Copilot — higher comfort, higher meter", "cell"),
                ],
                [
                    P("Time to org pilot", "cell_b"),
                    P("B", "cell"),
                    P("Code exists. A needs connector, DLP allow-list, prompt-never-to-GPT tests", "cell"),
                ],
            ],
            [1.75 * inch, 0.72 * inch, CW - 2.47 * inch],
            header_bg=TEAL,
        )
    )
    story.append(Spacer(1, 5))
    story.append(
        banner(
            "ASK OF THE BOARD",
            "Approve Option B as the org pilot (Entra + Teams tab + Groq). Keep Copilot + Purview for licensed "
            "Copilot work. Revisit Azure OpenAI / Copilot Chat API later as a Groq swap — not a Studio rebuild.",
            NAVY,
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        P(
            "Sources: Microsoft Copilot Studio Licensing Guide (16 Jun 2026); Learn “Billing rates and management” "
            "(classic 1 / generative 2 / agent action 5 credits; PAYG $0.01; pack $200 / 25k); "
            "M365 Copilot $30/user/month list; Groq gpt-oss-120b $0.15 / $0.60 per 1M tokens (Sep 2026). "
            "Your EA may discount Copilot. Credits unused in a pack month are lost. Azure VM quotes vary by region.",
            "tiny",
        )
    )

    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=LETTER,
        leftMargin=ML,
        rightMargin=MR,
        topMargin=MT,
        bottomMargin=MB,
        title="ExhaustShield Board Options A vs B",
        author="Manikandan",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    build()
