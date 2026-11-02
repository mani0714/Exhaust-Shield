"""ExhaustShield CEO Demo Playbook — colorful, precise, Q&A-ready PDF."""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUT = Path(__file__).resolve().parent / "ExhaustShield_CEO_Demo_Playbook.pdf"

# Palette
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
SLATE = colors.HexColor("#334155")
BAND = colors.HexColor("#f8fafc")
WHITE = colors.white
RULE = colors.HexColor("#e2e8f0")
NAVY = colors.HexColor("#0f172a")


class ColorBar(Flowable):
    def __init__(self, width, height=6, fills=None):
        Flowable.__init__(self)
        self.width = width
        self.height = height
        self.fills = fills or [TEAL, BLUE, AMBER, ROSE]

    def draw(self):
        n = len(self.fills)
        w = self.width / n
        for i, c in enumerate(self.fills):
            self.canv.setFillColor(c)
            self.canv.rect(i * w, 0, w + 0.5, self.height, fill=1, stroke=0)


class Banner(Flowable):
    def __init__(self, text, width, bg=TEAL, fg=WHITE, height=28):
        Flowable.__init__(self)
        self.text = text
        self.width = width
        self.bg = bg
        self.fg = fg
        self.height = height

    def wrap(self, availWidth, availHeight):
        self.width = min(self.width, availWidth)
        return self.width, self.height

    def draw(self):
        self.canv.setFillColor(self.bg)
        self.canv.roundRect(0, 0, self.width, self.height, 6, fill=1, stroke=0)
        self.canv.setFillColor(self.fg)
        self.canv.setFont("Helvetica-Bold", 11)
        self.canv.drawString(12, 9, self.text)


def styles():
    base = getSampleStyleSheet()
    return {
        "cover_kicker": ParagraphStyle(
            "cover_kicker", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=10, textColor=TEAL, alignment=TA_CENTER, spaceAfter=6,
            letterSpacing=1,
        ),
        "cover_title": ParagraphStyle(
            "cover_title", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=26, leading=30, textColor=NAVY, alignment=TA_CENTER, spaceAfter=6,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub", parent=base["Normal"], fontName="Helvetica",
            fontSize=10.5, leading=14, textColor=MUTED, alignment=TA_CENTER, spaceAfter=4,
        ),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=13.5, leading=17, textColor=NAVY, spaceBefore=12, spaceAfter=6,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=10.5, leading=13, textColor=TEAL, spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontName="Helvetica",
            fontSize=9, leading=12, textColor=INK, alignment=TA_JUSTIFY, spaceAfter=4,
        ),
        "bullet": ParagraphStyle(
            "bullet", parent=base["Normal"], fontName="Helvetica",
            fontSize=9, leading=11.5, textColor=INK, spaceAfter=1,
        ),
        "callout": ParagraphStyle(
            "callout", parent=base["Normal"], fontName="Helvetica-Oblique",
            fontSize=9, leading=12, textColor=TEAL, spaceBefore=2, spaceAfter=6,
        ),
        "say": ParagraphStyle(
            "say", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=9, leading=12, textColor=BLUE, spaceBefore=2, spaceAfter=6,
        ),
        "qa_q": ParagraphStyle(
            "qa_q", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=9, leading=11.5, textColor=NAVY, spaceBefore=6, spaceAfter=1,
        ),
        "qa_a": ParagraphStyle(
            "qa_a", parent=base["Normal"], fontName="Helvetica",
            fontSize=9, leading=11.5, textColor=INK, leftIndent=4, spaceAfter=2,
        ),
        "toc": ParagraphStyle(
            "toc", parent=base["Normal"], fontName="Helvetica",
            fontSize=9.5, leading=14, textColor=INK, leftIndent=2,
        ),
        "small": ParagraphStyle(
            "small", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=10, textColor=MUTED, spaceAfter=2,
        ),
        "cell": ParagraphStyle(
            "cell", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=10.5, textColor=INK,
        ),
        "cell_b": ParagraphStyle(
            "cell_b", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=10.5, textColor=NAVY,
        ),
        "term": ParagraphStyle(
            "term", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8.5, leading=11, textColor=TEAL, spaceBefore=3, spaceAfter=0,
        ),
        "tdef": ParagraphStyle(
            "tdef", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=11, textColor=INK, leftIndent=6, spaceAfter=2,
        ),
        "pro": ParagraphStyle(
            "pro", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=11, textColor=colors.HexColor("#065f46"),
        ),
        "con": ParagraphStyle(
            "con", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=11, textColor=colors.HexColor("#9f1239"),
        ),
        "fix": ParagraphStyle(
            "fix", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=11, textColor=colors.HexColor("#1e40af"),
        ),
    }


def bullets(items, st, color=TEAL):
    return ListFlowable(
        [ListItem(Paragraph(i, st["bullet"]), leftIndent=10, bulletColor=color) for i in items],
        bulletType="bullet", start="•", leftIndent=14, spaceBefore=1, spaceAfter=4,
    )


def table(rows, col_widths, header_bg=TEAL, header_fg=WHITE):
    st = styles()
    data = []
    for ri, r in enumerate(rows):
        row = []
        for c in r:
            if ri == 0:
                sty = ParagraphStyle(
                    "hdr", parent=st["cell_b"], textColor=header_fg, fontSize=8,
                )
            else:
                sty = st["cell"]
            row.append(Paragraph(str(c), sty))
        data.append(row)
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), header_bg),
                ("TEXTCOLOR", (0, 0), (-1, 0), header_fg),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, BAND]),
            ]
        )
    )
    return t


def pcf_table(rows, col_widths):
    """Pros / Cons / Fix in production — colored header bands."""
    st = styles()
    header = [
        Paragraph("<font color='white'><b>PRO</b> — what works</font>", st["cell_b"]),
        Paragraph("<font color='white'><b>CON</b> — challenge</font>", st["cell_b"]),
        Paragraph("<font color='white'><b>FIX IN PRODUCTION</b></font>", st["cell_b"]),
    ]
    data = [header]
    for r in rows:
        data.append([
            Paragraph(r[0], st["pro"]),
            Paragraph(r[1], st["con"]),
            Paragraph(r[2], st["fix"]),
        ])
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), TEAL),
                ("BACKGROUND", (1, 0), (1, 0), ROSE),
                ("BACKGROUND", (2, 0), (2, 0), BLUE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, BAND]),
            ]
        )
    )
    return t


CONTENT_W = 7.1 * inch


def add_page_number(canvas, doc):
    canvas.saveState()
    # top accent line
    canvas.setStrokeColor(TEAL)
    canvas.setLineWidth(2)
    canvas.line(0.65 * inch, LETTER[1] - 0.4 * inch, LETTER[0] - 0.65 * inch, LETTER[1] - 0.4 * inch)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(0.65 * inch, 0.42 * inch, "ExhaustShield · CEO Demo Playbook")
    canvas.drawRightString(LETTER[0] - 0.65 * inch, 0.42 * inch, f"Page {doc.page}")
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.5)
    canvas.line(0.65 * inch, 0.55 * inch, LETTER[0] - 0.65 * inch, 0.55 * inch)
    canvas.restoreState()


def build():
    st = styles()
    story = []
    cw = CONTENT_W

    # ── COVER ──
    story.append(Spacer(1, 0.9 * inch))
    story.append(ColorBar(cw, 8, [TEAL, BLUE, AMBER, ROSE, VIOLET]))
    story.append(Spacer(1, 0.35 * inch))
    story.append(Paragraph("PERSONAL EXECUTIVE REFERENCE", st["cover_kicker"]))
    story.append(Paragraph("ExhaustShield", st["cover_title"]))
    story.append(Paragraph("CEO Demo Playbook", st["cover_title"]))
    story.append(Spacer(1, 0.12 * inch))
    story.append(
        Paragraph(
            "Precise · Color-coded · Q&A ready<br/>"
            "Plain English · Pros / Cons / Production fixes · File ownership",
            st["cover_sub"],
        )
    )
    story.append(Spacer(1, 0.35 * inch))
    story.append(
        Paragraph(
            "<b>Goal:</b> Whatever question they throw — answer with clarity and confidence.",
            st["cover_sub"],
        )
    )
    story.append(Spacer(1, 0.45 * inch))
    story.append(
        Paragraph(
            "Start demo: <b>start_demo.bat</b> → open <b>http://127.0.0.1:8000/</b><br/>"
            "Reset Demo before the room walks in · Ctrl+F5 after UI updates",
            st["cover_sub"],
        )
    )
    story.append(Spacer(1, 0.5 * inch))
    story.append(ColorBar(cw, 8, [TEAL, BLUE, AMBER, ROSE, VIOLET]))
    story.append(PageBreak())

    # ── TOC ──
    story.append(Banner("CONTENTS", cw, TEAL))
    story.append(Spacer(1, 8))
    for line in [
        "1. One-minute story",
        "2. Word list (simple English)",
        "3. Start the demo — checklist",
        "4. 8-minute talk track",
        "5. Pilot vs production",
        "6. Three paths (Safe · Medium · High)",
        "7. Every tab — what to show",
        "8. Scoreboard — how to read numbers",
        "9. Hide & rewrite — without changing the ask",
        "10. Private AI honesty",
        "11. Pros · Cons · Fix in production",
        "12. Killer Q&A (say these out loud)",
        "13. Demo recovery lines",
        "14. File & folder guide + who speaks",
        "15. What we ship today · What’s next",
        "16. One-page cheat sheet",
    ]:
        story.append(Paragraph(line, st["toc"]))
    story.append(PageBreak())

    # ── 1 ──
    story.append(Banner("1 · ONE-MINUTE STORY", cw, TEAL))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "<b>ExhaustShield is the security guard in front of AI.</b> "
            "It checks every prompt before data can leave. Then it picks a path:",
            st["body"],
        )
    )
    story.append(
        bullets(
            [
                "<b>Safe</b> — clean text → confirm → outside AI (e.g. Groq).",
                "<b>Medium</b> — hide/rewrite business secrets → then outside AI.",
                "<b>High</b> — hard secrets → private AI only. Never outside.",
            ],
            st,
        )
    )
    story.append(
        Paragraph(
            "Company knowledge answers come from files or humans — not from a guessing model.",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "SAY: “People will use AI. We stop secrets leaving quietly — and when we don’t know, a human answers.”",
            st["say"],
        )
    )

    # ── 2 ──
    story.append(Banner("2 · WORD LIST — SIMPLE ENGLISH", cw, BLUE))
    story.append(Spacer(1, 4))
    glossary = [
        ("AI / model / LLM", "Chat assistant software that answers in normal language."),
        ("Prompt", "What someone types into the AI."),
        ("Outside AI / Groq", "AI on someone else’s computers (internet). Pilot live option = Groq."),
        ("Private AI / Ollama", "AI on this laptop (or later: company network). High lane uses this."),
        ("Lane / path", "Risk bucket: Safe, Medium, or High."),
        ("Hide / redact", "Cover secrets so clear text does not leave."),
        ("Rewrite", "Same question, safer words (fake names, softer $/%)."),
        ("Confirm", "Pause: “Send outside?” before anything leaves."),
        ("Last-mile re-scan", "Final auto-check right before send."),
        ("Fail-closed", "If unsure or private AI is down → block outside send. No leak."),
        ("Simulate mode", "Fake outside reply for demo; gate decisions still real."),
        ("Human vault", "Approved answers written by people. Not used to train AI."),
        ("RAG", "Find docs, then ask AI. Normal RAG often sends clear text; we add a gate."),
        ("Egress", "Data leaving to the public internet / vendor."),
        ("Evidence / audit", "Saved proof of what happened and why."),
        ("Reset Demo", "Clears scoreboard + evidence. Keeps human vault on purpose."),
        ("127.0.0.1 / localhost", "This computer — not a public website."),
    ]
    for t, d in glossary:
        story.append(Paragraph(t, st["term"]))
        story.append(Paragraph(d, st["tdef"]))
    story.append(PageBreak())

    # ── 3 ──
    story.append(Banner("3 · START THE DEMO", cw, AMBER))
    story.append(Spacer(1, 6))
    story.append(
        bullets(
            [
                "Optional: start Ollama + model <b>llama3.2</b> (needed for High answers).",
                "Optional: real key in <b>groq_key.local.bat</b> for live outside replies.",
                "Run <b>start_demo.bat</b> → open <b>http://127.0.0.1:8000/</b>.",
                "Ctrl+F5 if UI looks stale · click <b>Reset Demo</b> for a clean board.",
            ],
            st,
            AMBER,
        )
    )
    story.append(
        Paragraph(
            "SAY UP FRONT: “Outside AI is live” or “Outside AI is simulated — the gate is still real.”",
            st["say"],
        )
    )

    # ── 4 ──
    story.append(Banner("4 · 8-MINUTE TALK TRACK", cw, VIOLET))
    story.append(Spacer(1, 6))
    story.append(
        table(
            [
                ["Time", "Where", "Do / Say"],
                ["0–1", "Overview", "RAG vs us card · Reset · Promise: catch → protect → prove"],
                ["1–3", "Knowledge", "Ask policy Q · show file answer · no AI call"],
                ["3–4", "Human vault", "Save fix · re-ask · vault hit"],
                ["4–7", "Outbound", "Safe confirm · Medium rewrite · High private"],
                ["7–8", "Overview/Lab", "Numbers · optional dry-run + evidence"],
            ],
            [0.7 * inch, 1.2 * inch, 5.2 * inch],
            header_bg=VIOLET,
        )
    )
    story.append(Spacer(1, 10))

    # ── 5 ──
    story.append(Banner("5 · PILOT vs PRODUCTION", cw, TEAL))
    story.append(Spacer(1, 6))
    story.append(
        table(
            [
                ["Topic", "Pilot (today)", "Production (later)"],
                ["Gate decisions", "Real Safe/Medium/High", "Same + SIEM, SSO, policy packs"],
                ["Outside AI", "Groq live or simulate", "Approved vendor under contract"],
                ["Private AI", "Laptop Ollama", "GPU cluster / private cloud"],
                ["Knowledge", "Local files + vault JSON", "Internal search + approved vault"],
                ["Evidence", "Files on this PC", "Central audit + retention"],
                ["Users", "Demo room", "Company-wide, managed"],
            ],
            [1.3 * inch, 2.6 * inch, 3.2 * inch],
        )
    )
    story.append(
        Paragraph(
            "SAY: “Simulated reply ≠ fake security. Detection, hide, confirm, and High fail-closed are live.”",
            st["say"],
        )
    )
    story.append(PageBreak())

    # ── 6 ──
    story.append(Banner("6 · THREE PATHS", cw, ROSE))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "Uncertainty fails <b>up</b> (toward Medium/High) — never quietly down to Safe.",
            st["body"],
        )
    )
    story.append(
        table(
            [
                ["Path", "When", "Leaves?", "Who answers?", "Demo example"],
                [
                    "Safe",
                    "Clean text",
                    "Yes after confirm",
                    "Outside AI",
                    "Unit-test checklist",
                ],
                [
                    "Medium",
                    "Business secrets (names, $)",
                    "Yes, cleaned",
                    "Outside AI",
                    "Deal $ / company name",
                ],
                [
                    "High",
                    "Keys, IDs, PHI-class",
                    "No",
                    "Private AI only",
                    "API key / EMP + salary",
                ],
            ],
            [0.75 * inch, 1.45 * inch, 1.2 * inch, 1.2 * inch, 2.5 * inch],
            header_bg=ROSE,
        )
    )
    story.append(Spacer(1, 8))
    story.append(Paragraph("Medium rewrite rule", st["h2"]))
    story.append(
        bullets(
            [
                "Same question meaning — not a new request.",
                "Real company → made-up company (never “our company”).",
                "Exact $ / % → softer wording (“tens of millions,” “sizable decline”).",
            ],
            st,
            ROSE,
        )
    )

    # ── 7 ──
    story.append(Banner("7 · EVERY TAB", cw, BLUE))
    story.append(Spacer(1, 6))
    story.append(
        table(
            [
                ["Tab", "Purpose", "Punch line"],
                ["1 Overview", "Scoreboard + charts", "Catch → protect → prove"],
                ["2 Knowledge", "Policy Q from files/vault", "No AI call on this tab"],
                ["3 Outbound Gate", "Free-form prompts", "Safe / Medium / High live"],
                ["4 Human vault", "People fix gaps", "Never trains a model"],
                ["5 Pilot Lab", "Dry-run + evidence", "Prove without calling AI"],
            ],
            [1.35 * inch, 2.5 * inch, 3.25 * inch],
            header_bg=BLUE,
        )
    )
    story.append(PageBreak())

    # ── 8 ──
    story.append(Banner("8 · SCOREBOARD — READ THE NUMBERS", cw, TEAL))
    story.append(Spacer(1, 6))
    story.append(
        table(
            [
                ["Number", "Means"],
                ["Could have leaked", "Hide-path secrets in outbound prompts (synced to what we mask)"],
                ["Sensitive in docs", "Sensitive wording in local file answers (not sent to AI)"],
                ["Latest leak risk %", "Risk on last ask (local knowledge = no outside risk)"],
                ["Outside AI skipped", "Answered from files/human — no outside call"],
                ["Human answers saved", "Vault writes"],
                ["Boundary split", "Local vs external vs blocked"],
                ["Lanes by team", "Safe/Medium/High by team"],
                ["Knowledge by team", "Local / human-corrected / human gap"],
                ["Sensitive by team", "Last ask vs cumulative so far"],
            ],
            [1.8 * inch, 5.3 * inch],
        )
    )

    # ── 9 ──
    story.append(Banner("9 · HIDE & REWRITE", cw, AMBER))
    story.append(Spacer(1, 6))
    story.append(
        table(
            [
                ["Risky original", "Safer same ask"],
                [
                    "Amazon Inc after a 30% drop?",
                    "Bluefinch Technologies after a sizable decline?",
                ],
                [
                    "Flipkart Inc cutting costs 12%",
                    "Cedar Peak Labs cutting costs by a modest %",
                ],
                [
                    "Sarah Chen · Contoso · $45M",
                    "Cameron Shaw · Ironwood · tens of millions",
                ],
            ],
            [3.4 * inch, 3.7 * inch],
            header_bg=AMBER,
        )
    )
    story.append(Spacer(1, 8))

    # ── 10 ──
    story.append(Banner("10 · PRIVATE AI — HONEST LINE", cw, ROSE))
    story.append(Spacer(1, 6))
    story.append(
        bullets(
            [
                "High ≠ Safe. Safe = okay to send outside. High = kept inside.",
                "Ollama on this PC does not publish High prompts to the public (localhost).",
                "Private AI may still <b>see</b> the secret — containment, not “harmless.”",
                "Model saying “no” = safety filter. Win = refusal stayed on-box, not at a vendor.",
                "Private-only for everything is valid; hybrid is cost/quality after the gate.",
            ],
            st,
            ROSE,
        )
    )
    story.append(
        Paragraph(
            "SAY: “Private AI reduces who can steal the secret. It does not make pasting secrets into chat OK.”",
            st["say"],
        )
    )
    story.append(PageBreak())

    # ── 11 PROS CONS FIX ──
    story.append(Banner("11 · PROS · CONS · FIX IN PRODUCTION", cw, NAVY))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "Use this table when challenged. Own the con — then land the fix. That is what amazes rooms.",
            st["body"],
        )
    )
    story.append(
        pcf_table(
            [
                [
                    "Real gate before AI: detect → route → prove",
                    "Pattern detector can miss novel secret shapes",
                    "Add ML classifiers + continuous rule packs + human review queue for misses",
                ],
                [
                    "High never goes to outside AI (fail-closed)",
                    "Private model may still see cleartext secrets",
                    "Always strip/replace secrets before private call; optional zero-LLM High playbooks",
                ],
                [
                    "Medium keeps ask meaning with fictional names",
                    "Rewrite quality can feel stiff on edge cases",
                    "Enterprise rewrite model + human edit before send; A/B tune synonyms",
                ],
                [
                    "Knowledge tab never invents policy via LLM",
                    "Gaps need humans — slower than auto-guess",
                    "SLA on vault queue; specialist owners; autocomplete from approved corpus",
                ],
                [
                    "Pilot runs on one laptop — easy to demo",
                    "Not enterprise scale / SSO / HA yet",
                    "Gateway cluster, SSO, SIEM hooks, retention policies",
                ],
                [
                    "Simulate mode = demo without vendor spend",
                    "Simulated prose can look “fake” if not disclosed",
                    "Always disclose mode; turn live Groq for executive rooms that need it",
                ],
                [
                    "Local Ollama = no public egress on High",
                    "Small models refuse / weak answers on secrets",
                    "Private GPU fleet + enterprise system prompt or fixed rotate/revoke templates",
                ],
                [
                    "Evidence locker for auditors",
                    "Local JSONL is not a compliance vault",
                    "Central immutable audit store, access control, legal hold",
                ],
            ],
            [2.25 * inch, 2.25 * inch, 2.6 * inch],
        )
    )
    story.append(PageBreak())

    # ── 12 Q&A ──
    story.append(Banner("12 · KILLER Q&A — SAY THESE OUT LOUD", cw, BLUE))
    story.append(Spacer(1, 4))
    qa = [
        (
            "Q: How is this different from normal “docs + AI”?",
            "A: Normal setups often send clear company text to a vendor AI. We add a control plane: "
            "detect secrets, hide before egress, High stays private, humans fill gaps — vault never trains a model. "
            "Show the Overview comparison card.",
        ),
        (
            "Q: Why use outside AI if we have private AI?",
            "A: You can go private-only — most secure. Hybrid is optional: save private capacity for High; "
            "use stronger/cheaper outside AI only after the gate says clean or cleaned. "
            "ExhaustShield decides what may leave — it does not require leaving.",
        ),
        (
            "Q: Is High “safe”?",
            "A: High is contained — not “Safe lane.” Safer against public leak. "
            "Best practice still: never paste live secrets. We catch, contain, and push safer asks.",
        ),
        (
            "Q: Will Ollama leak High to the public?",
            "A: In this pilot, High calls localhost only. Nothing is sent to Groq for High. "
            "Production = private inference inside our network with the same rule.",
        ),
        (
            "Q: Why does private AI often say no?",
            "A: Model safety training refuses key/password topics. "
            "That refusal happened on our machine — not at a public vendor. "
            "Production fix: playbook answers (rotate/revoke) without feeding raw secrets.",
        ),
        (
            "Q: What if detection misses something?",
            "A: No system is 100%. We fail closed on uncertainty, re-scan before send, expand rules, keep evidence. "
            "We manage residual risk — we don’t pretend zero risk.",
        ),
        (
            "Q: Is simulate mode cheating?",
            "A: No — we disclose it. Routing and redaction are live. Only outside prose may be stubbed without a key. "
            "Live Groq is one restart away.",
        ),
        (
            "Q: Will this slow people down?",
            "A: Safe = one confirm. Medium = short clean-up. High = automatic private. "
            "Friction where risk is high; clean work stays fast.",
        ),
        (
            "Q: Who owns wrong answers?",
            "A: Knowledge comes from files or humans. Gaps go to people. Vault is approved truth — not model invention.",
        ),
        (
            "Q: Build vs buy?",
            "A: This pilot proves the pattern with working evidence. Rollout is IT + Security + Policy. "
            "You’re buying a control plane story you can demo today — not a slide.",
        ),
        (
            "Q: How does Groq fit?",
            "A: Groq is the outside AI for Safe and cleaned Medium only — after confirm and last-mile check. "
            "High never goes to Groq.",
        ),
        (
            "Q: Does Reset wipe human work?",
            "A: Scoreboard and evidence clear. Human vault and review queue stay — corrections survive demos.",
        ),
    ]
    for q, a in qa:
        story.append(Paragraph(q, st["qa_q"]))
        story.append(Paragraph(a, st["qa_a"]))
    story.append(PageBreak())

    # ── 13 ──
    story.append(Banner("13 · DEMO RECOVERY LINES", cw, AMBER))
    story.append(Spacer(1, 6))
    story.append(
        table(
            [
                ["What goes wrong", "Recovery line"],
                [
                    "High = model refusal",
                    "“Safety filter on-box. Important: it never left. Production = playbook answer.”",
                ],
                [
                    "Ollama down",
                    "“Fail-closed. Still refused outside send. That’s a security win.”",
                ],
                [
                    "Canned outside reply",
                    "“Simulate mode. Gate is real; prose is stubbed. We can go live.”",
                ],
                [
                    "Stale numbers after reset",
                    "Ctrl+F5 · restart start_demo.bat if needed.",
                ],
                [
                    "Weak rewrite",
                    "“Edit before send — human stays in control.”",
                ],
                [
                    "They demand private-only",
                    "“Valid. Hybrid is optional. Gate supports either policy.”",
                ],
            ],
            [2.0 * inch, 5.1 * inch],
            header_bg=AMBER,
        )
    )
    story.append(Spacer(1, 10))

    # ── 14 FILES ──
    story.append(Banner("14 · FILE GUIDE + WHO SPEAKS", cw, VIOLET))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "When someone asks “where does this live?” — point to the file and the owner voice.",
            st["body"],
        )
    )
    story.append(
        table(
            [
                ["File / folder", "Used for", "Who speaks"],
                [
                    "static/index.html",
                    "All screens people see — tabs, charts, buttons",
                    "Product / Demo lead",
                ],
                [
                    "gateway.py",
                    "Server: APIs, session stats, Reset Demo, wiring",
                    "Engineering",
                ],
                [
                    "router.py",
                    "Safe/Medium/High decisions · Groq vs Ollama",
                    "Security + Eng",
                ],
                [
                    "detector.py",
                    "Finds secrets · mask · rewrite hints",
                    "Security",
                ],
                [
                    "knowledge.py",
                    "Tab 2 answers from company files",
                    "Knowledge / Ops",
                ],
                [
                    "protection.py",
                    "Evidence / audit helpers for Pilot Lab",
                    "Security / Audit",
                ],
                [
                    "start_demo.bat",
                    "One-click demo start · loads Groq settings",
                    "Demo lead",
                ],
                [
                    "start_gateway.py",
                    "Starts the API server",
                    "Engineering",
                ],
                [
                    "groq_key.local.bat",
                    "Live outside-AI key (local only — don’t share)",
                    "Demo lead / Eng",
                ],
                [
                    "confidential_data/",
                    "Sample policy docs for Knowledge tab",
                    "Product / Knowledge",
                ],
                [
                    "reviews/corrections.json",
                    "Human vault — approved answers",
                    "Ops / Knowledge",
                ],
                [
                    "reviews/queue.json",
                    "Gaps waiting for a human",
                    "Ops",
                ],
                [
                    "reviews/protection_audit.jsonl",
                    "Evidence locker records",
                    "Security / Audit",
                ],
                [
                    "reviews/demo_session.json",
                    "Live scoreboard state for this run",
                    "Demo lead",
                ],
                [
                    "build_ceo_playbook.py",
                    "Builds this PDF",
                    "You (presenter)",
                ],
                [
                    "ExhaustShield_CEO_Demo_Playbook.pdf",
                    "This guide",
                    "You (presenter)",
                ],
            ],
            [1.85 * inch, 3.35 * inch, 1.9 * inch],
            header_bg=VIOLET,
        )
    )
    story.append(
        Paragraph(
            "TIP: Name-drop three files in the room — <b>router.py</b> (decide), <b>detector.py</b> (find secrets), "
            "<b>static/index.html</b> (prove on screen).",
            st["callout"],
        )
    )
    story.append(PageBreak())

    # ── 15 ──
    story.append(Banner("15 · TODAY · NEXT", cw, TEAL))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Ships in this pilot", st["h2"]))
    story.append(
        bullets(
            [
                "Three-lane Outbound Gate + confirm + last-mile re-scan",
                "Knowledge without LLM · Human vault · Pilot Lab evidence",
                "Overview analytics · rewrite with fictional names · expanded High rules",
                "Full Reset Demo · collapsible RAG vs us card",
            ],
            st,
        )
    )
    story.append(Paragraph("Credible next steps", st["h2"]))
    story.append(
        bullets(
            [
                "SSO · per-team policy · SIEM / tickets on High",
                "Private GPU inference · High playbooks without raw secrets",
                "Connectors for chat tools / coding assistants",
                "Admin rule tuning · retention · compliance export packs",
            ],
            st,
            BLUE,
        )
    )
    story.append(Spacer(1, 8))

    # ── 16 ──
    story.append(Banner("16 · ONE-PAGE CHEAT SHEET", cw, ROSE))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "<b>Start:</b> start_demo.bat → http://127.0.0.1:8000/ → Reset Demo → Ctrl+F5 if needed.",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Story:</b> Catch → Protect (hide / private) → Prove (numbers + evidence).",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Safe</b> = confirm → outside · <b>Medium</b> = clean → outside · <b>High</b> = private only.",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Honesty:</b> High ≠ Safe · Private ≠ harmless · Simulate ≠ fake gate · Refusal ≠ public leak.",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>When challenged:</b> Own the CON → land the FIX IN PRODUCTION (Section 11).",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "CLOSE: “People will use AI. ExhaustShield makes sure the risky stuff doesn’t leave quietly — "
            "and when we don’t know, a human answers, not a guessing model.”",
            st["say"],
        )
    )
    story.append(Spacer(1, 12))
    story.append(ColorBar(cw, 6, [TEAL, BLUE, AMBER, ROSE, VIOLET]))
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            "— End — Re-read Sections 11 + 12 the night before any executive demo.",
            st["small"],
        )
    )

    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=LETTER,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.7 * inch,
        title="ExhaustShield CEO Demo Playbook",
        author="ExhaustShield",
    )
    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    build()
