# ExhaustShield Hybrid Handbook

**Users → Copilot Agent (Teams) → FastAPI → ExhaustShield engine**

This handbook is written for a beginner. If you follow every step in order, you can stand up the hybrid setup end to end.

**Designed for:** ExhaustShield project in this folder  
**Pattern:** Copilot Studio is only the front door. FastAPI (`gateway.py`) is the brain.  
**Golden rule:** Never let Copilot Studio classify secrets. Always send the raw prompt to `/api/generate` and trust the lane it returns.

---

## Table of contents

1. [What you are building](#1-what-you-are-building)
2. [Licences checklist](#2-licences-checklist)
3. [Architecture and workflows](#3-architecture-and-workflows)
4. [Lane formulas (how the engine decides)](#4-lane-formulas-how-the-engine-decides)
5. [Cost formulas (simple math)](#5-cost-formulas-simple-math)
6. [Part A — Prepare the FastAPI engine on your server](#6-part-a--prepare-the-fastapi-engine-on-your-server)
7. [Part B — Prove the three APIs work](#7-part-b--prove-the-three-apis-work)
8. [Part C — Create the Copilot Studio agent](#8-part-c--create-the-copilot-studio-agent)
9. [Part D — Connect Studio to FastAPI](#9-part-d--connect-studio-to-fastapi)
10. [Part E — Build the topics (menu + knowledge + gate)](#10-part-e--build-the-topics-menu--knowledge--gate)
11. [Part F — Publish to Teams](#11-part-f--publish-to-teams)
12. [Part G — Pin the full 5-tab dashboard](#12-part-g--pin-the-full-5-tab-dashboard)
13. [Part H — Test script](#13-part-h--test-script)
14. [Part I — Rollout and go-live](#14-part-i--rollout-and-go-live)
15. [Troubleshooting](#15-troubleshooting)
16. [Copy-paste Adaptive Card JSON](#16-copy-paste-adaptive-card-json)
17. [Questions to ask IT / admin](#17-questions-to-ask-it--admin)

---

## 1. What you are building

### End state

| Piece | What the user sees | What actually runs |
|---|---|---|
| Copilot Agent in Teams | Chat menu: Policy / AI chat / Open dashboard | Studio topics + HTTP calls |
| FastAPI on company server | Invisible | `gateway.py` lanes + knowledge |
| Web dashboard | 5 tabs in browser / Teams website tab | Same FastAPI + `static/index.html` |

### Flow (one picture)

```text
┌─────────────────────┐
│  Employee in Teams  │
└──────────┬──────────┘
           │ opens agent
           ▼
┌─────────────────────┐
│  Copilot Studio     │  Topics + Confirm / Cancel cards
│  Agent              │  NO secret classifier here
└──────────┬──────────┘
           │ HTTPS JSON
           ▼
┌─────────────────────┐
│  FastAPI gateway    │  /api/ask-knowledge
│  ExhaustShield      │  /api/generate
│  https://ai-gate…   │  /api/generate/confirm
└──────────┬──────────┘
           │
     ┌─────┴──────────────────────────┐
     ▼                                ▼
 Local docs / Human vault      External AI (Groq etc.)
 Private Ollama (HIGH)         only after SAFE/MEDIUM confirm
```

### What this handbook does **not** do

- It does **not** rebuild Overview / Vault / Lab as Studio screens.
- It does **not** replace Microsoft Purview.
- It does **not** require buying M365 Copilot ($30) seats for everyone.

---

## 2. Licences checklist

Print this and tick with IT.

### Required

| # | Licence / access | Why | Do you need to buy new? |
|---|---|---|---|
| 1 | Microsoft 365 work account (E3 or E5 typical) | Teams + Entra sign-in | Usually already have |
| 2 | Access to a **Power Platform environment** | Where Studio agents live | Ask admin |
| 3 | **Copilot Studio** maker permission | Create and edit the agent | Ask admin (role / licence) |
| 4 | Permission to **publish to Microsoft Teams** | Users can open the agent | Admin approval often needed |
| 5 | Company server (or VM) you can run Python on | Hosts FastAPI | Prefer existing server |
| 6 | Outbound HTTPS from that server | Call Groq / Azure OpenAI | Network allowlist |

### Usage / consumption (not always a “seat”)

| # | Item | When it costs money |
|---|---|---|
| 7 | **Copilot Studio credits / capacity** | Each conversation with *your* custom agent may consume credits (especially users without full M365 Copilot fair-use coverage). Ask admin for Dev trial + Prod PAYG or credit pack. |
| 8 | **Groq (or Azure OpenAI) tokens** | Only when SAFE/MEDIUM confirm sends text to external AI |

### Optional (not required for hybrid)

| Item | Notes |
|---|---|
| M365 Copilot add-on **$30 / user / month** | For Word/Excel Copilot productivity — **not required** for this agent |
| Microsoft 365 E5 (vs E3) | Deeper Purview — complementary, not required for FastAPI gate |
| Purview Suite add-on (~$12 on E3) | Helps Copilot-side DLP — does not replace ExhaustShield lanes |
| Power Automate Premium | Only if you refuse HTTP/custom connector and use premium connectors |

### List prices to remember (USD, annual commit, Sep 2026 context)

| SKU | Per user / month |
|---|---|
| Microsoft 365 E3 | **$39** (from Jul 2026; was $36) |
| Microsoft 365 E5 | **$60** (from Jul 2026; was $57) |
| M365 Copilot add-on | **$30** |
| ExhaustShield hybrid on existing server | **~$0 seats** + tokens + Studio credits |

---

## 3. Architecture and workflows

### Workflow A — Company knowledge (Tab 2 behaviour)

```text
User types policy question
        ↓
Studio Topic "Knowledge"
        ↓
POST /api/ask-knowledge  { "question": "..." }
        ↓
FastAPI: vault → local near-match → human gap
        ↓
NEVER calls external LLM on this path
        ↓
Studio shows answer (+ sources if present)
```

### Workflow B — Governed AI chat (Tab 3 behaviour)

```text
User types free-form prompt
        ↓
Studio Topic "Gated chat"
        ↓
POST /api/generate  { "prompt": "..." }
        ↓
FastAPI detector + classify_route
        ↓
┌─────────────┬──────────────────┬─────────────────┐
│ SAFE        │ MEDIUM           │ HIGH            │
│ awaiting    │ awaiting         │ private only /  │
│ confirm     │ confirm          │ never external  │
└──────┬──────┴────────┬─────────┴────────┬────────┘
       │               │                  │
       ▼               ▼                  ▼
 Confirm card     Confirm card      Show message
 chosen=as_is     redacted|rewrite  Stop (or local
       │               │             private answer)
       └───────┬───────┘
               ▼
 POST /api/generate/confirm
               ▼
 Last-mile re-scan → then external AI (if still allowed)
               ▼
 Studio shows final answer
```

### Workflow C — Full 5-tab dashboard

```text
User chooses "Open full dashboard"
        ↓
Link / Teams Website tab
        ↓
https://ai-gate.company.com/
        ↓
Overview | Company knowledge | Outbound Gate | Human vault | Pilot Lab
```

---

## 4. Lane formulas (how the engine decides)

These are the product rules your FastAPI already implements. Studio must display them, not reinvent them.

### Risk levels

| API `guardian.risk_level` | User-facing lane | What happens |
|---|---|---|
| `safe` | SAFE | Pause → user confirms → send **as written** to external AI |
| `moderate` | MEDIUM | Pause → user picks **redacted** or **rewrite** → then external AI |
| `high` | HIGH | **Fail-closed** → private / blocked — **do not** call external AI from Studio |

### Confirm formulas (exact values your API accepts)

After `/api/generate` returns `awaiting_confirm: true` and a `pending_id`:

| Situation | `POST /api/generate/confirm` body |
|---|---|
| SAFE — send as typed | `{ "pending_id": "<id>", "chosen": "as_is" }` |
| MEDIUM — placeholders | `{ "pending_id": "<id>", "chosen": "redacted" }` |
| MEDIUM — suggested rewrite | `{ "pending_id": "<id>", "chosen": "rewrite" }` |
| Cancel anything | `{ "pending_id": "<id>", "chosen": "cancel" }` |

Alias: `version` is accepted instead of `chosen` (same values).

### Knowledge formula

```text
IF question empty → error
ELSE search vault / local policy docs
IF good local match → answer locally (sent_to_llm = false)
ELSE human gap / review path
NEVER silent fallback to Groq/Ollama on /api/ask-knowledge
```

---

## 5. Cost formulas (simple math)

### Per chat (external model)

Assume one gated chat = **1,000 input + 500 output** tokens.

**Groq gpt-oss-120b (list):**  
`$0.15 / 1M input` and `$0.60 / 1M output`

```text
Cost_per_chat =
  (1000 / 1_000_000) * 0.15
+ (500  / 1_000_000) * 0.60
= 0.00015 + 0.00030
= $0.00045
```

### Monthly token cost (existing server → hosting = $0)

```text
Chats_per_month = Users × Chats_per_user_per_day × 22
Token_cost_month = Chats_per_month × 0.00045
Token_cost_year  = Token_cost_month × 12
```

| Scenario | Chats / user / day | 500 users / yr | 3,000 users / yr |
|---|---|---|---|
| BEST | 1 | ~$59 | ~$356 |
| NORMAL | 3 | ~$178 | ~$1,070 |
| WORST | 8 | ~$475 | ~$2,851 |

Add **Studio credits** on top (ask admin for your tenant’s meter).  
Do **not** add $30×users unless you separately buy full Copilot.

---

## 6. Part A — Prepare the FastAPI engine on your server

### A1. Choose URL

Pick a hostname, for example:

```text
https://ai-gate.yourcompany.com
```

You will use this everywhere in Studio.

### A2. Copy project (no secrets)

Copy this folder to the server **except**:

- `.env` (never copy keys into Git / tickets)
- Use `.env.example` as template

### A3. Install Python packages

On the server (PowerShell or bash):

```bash
cd "/path/to/Exhaust Shield"
python -m pip install -r requirements.txt
```

### A4. Configure external AI

1. Copy `.env.example` → `.env` (or set the same env vars in the Linux service).
2. Set:

```text
EXTERNAL_AI_MODE=live          # or simulate for zero-cost pilot
EXTERNAL_AI_BASE_URL=https://api.groq.com/openai/v1
EXTERNAL_AI_API_KEY=gsk_...    # real key only on server
EXTERNAL_AI_MODEL=openai/gpt-oss-120b
```

3. For a **$0 pilot**, use:

```text
EXTERNAL_AI_MODE=simulate
```

### A5. Start the gateway

Windows (from project folder):

```bash
python start_gateway.py
```

Default listen: `http://127.0.0.1:8000`

### A6. Put HTTPS in front (IIS / nginx)

Reverse-proxy:

```text
https://ai-gate.yourcompany.com  →  http://127.0.0.1:8000
```

Checklist:

- [ ] TLS certificate valid  
- [ ] App runs as a service (survives reboot)  
- [ ] Firewall allows Power Platform / Teams egress to this host  
- [ ] Prefer auth (Entra / API key) before production  

### A7. Optional High lane (Ollama)

If HIGH should call a private model on the same box:

1. Install Ollama  
2. Pull a model (e.g. `llama3.2`)  
3. Keep default `OLLAMA_URL=http://127.0.0.1:11434/api/generate`  

If Ollama is missing, HIGH still **must not** go external — fail closed.

---

## 7. Part B — Prove the three APIs work

Use browser, Postman, or `curl`. Replace the base URL.

### B1. Health

```http
GET https://ai-gate.yourcompany.com/api/health
```

Expect JSON with `"ok": true`.

### B2. Knowledge

```http
POST https://ai-gate.yourcompany.com/api/ask-knowledge
Content-Type: application/json

{
  "question": "What is our leave policy?",
  "prefer_local_corrections": true
}
```

Expect fields like:

- `ok` (if present) / `answer` / `sources` / `needs_human_review`

### B3. Generate (SAFE or pending)

```http
POST https://ai-gate.yourcompany.com/api/generate
Content-Type: application/json

{
  "prompt": "Explain the difference between TCP and UDP in simple words"
}
```

Important response fields:

| Field | Meaning |
|---|---|
| `awaiting_confirm` | `true` = nothing sent yet |
| `pending_id` | Pass this to confirm |
| `confirm_kind` | `safe` or `moderate` |
| `guardian.risk_level` | `safe` / `moderate` / `high` |
| `redacted_sent` | Placeholder version (MEDIUM) |
| `rewrite_suggestion` | Suggested rewrite (MEDIUM) |
| `response` / final answer | Often empty until confirm |

### B4. Confirm SAFE

```http
POST https://ai-gate.yourcompany.com/api/generate/confirm
Content-Type: application/json

{
  "pending_id": "PASTE_ID_FROM_GENERATE",
  "chosen": "as_is"
}
```

### B5. Confirm MEDIUM (hide secrets)

```json
{
  "pending_id": "PASTE_ID",
  "chosen": "redacted"
}
```

### B6. Cancel

```json
{
  "pending_id": "PASTE_ID",
  "chosen": "cancel"
}
```

**Do not continue to Studio until B1–B4 work.**

---

## 8. Part C — Create the Copilot Studio agent

### C1. Open Studio

1. Go to https://copilotstudio.microsoft.com  
2. Sign in with work account  
3. Select **Dev** environment (ask admin for the name)

### C2. Create agent

1. **Create** → **New agent**  
2. Name: `ExhaustShield Gate`  
3. Description:

```text
Governed company policy search and outbound AI chat.
All risk decisions are made by our ExhaustShield FastAPI gateway.
```

4. Create the agent.

### C3. Paste system instructions (important)

In agent instructions / overview instructions, paste:

```text
You are the Teams front door for ExhaustShield.

Rules:
1. Never classify whether a prompt is secret, safe, or high risk yourself.
2. For policy questions, always call AskKnowledge (our API).
3. For free-form AI questions, always call Generate (our API) first.
4. If Generate returns awaiting_confirm=true, show Confirm/Cancel and wait.
5. Only call ConfirmGenerate after the user confirms.
6. If guardian.risk_level is high, tell the user nothing was sent externally.
7. Never invent scrubbed text. Only show redacted_sent or rewrite_suggestion from the API.
8. Offer a link to the full dashboard for Overview, Vault, and Pilot Lab.
```

### C4. Turn off unsafe generative shortcuts

If the UI offers “generative orchestration” that answers without tools:

- Prefer **topics + actions** for Knowledge and Gate  
- Or force “use tools / call connectors” for those intents  

Beginners: build **explicit topics** (next sections). Do not rely on the model guessing.

---

## 9. Part D — Connect Studio to FastAPI

You have two beginner-friendly options. Start with **D-Option 1**.

### D-Option 1 — HTTP request actions inside topics (fastest learning)

In each topic you will add **Call HTTP request** (name varies slightly by Studio version):

- Method POST  
- URL full path  
- Header `Content-Type: application/json`  
- Body JSON  

Skip to [Part E](#10-part-e--build-the-topics-menu--knowledge--gate).

### D-Option 2 — Custom connector (better for enterprise)

1. Open https://make.powerapps.com → same environment  
2. **Custom connectors** → **New** → **Blank**  
3. Connector name: `ExhaustShieldAPI`  
4. Host: `ai-gate.yourcompany.com`  
5. Base URL: `/`  
6. Scheme: HTTPS  

#### Action 1 — AskKnowledge

- Operation ID: `AskKnowledge`  
- Request: `POST /api/ask-knowledge`  
- Body:

```json
{
  "question": "string",
  "prefer_local_corrections": true
}
```

#### Action 2 — Generate

- Operation ID: `Generate`  
- Request: `POST /api/generate`  
- Body:

```json
{
  "prompt": "string"
}
```

#### Action 3 — ConfirmGenerate

- Operation ID: `ConfirmGenerate`  
- Request: `POST /api/generate/confirm`  
- Body:

```json
{
  "pending_id": "string",
  "chosen": "string"
}
```

7. Auth: as IT requires (API key header recommended for v1)  
8. **Create connector** → **Test** each operation with real payloads from Part B  
9. In Copilot Studio → **Tools** / **Actions** → add `ExhaustShieldAPI` actions to the agent  

---

## 10. Part E — Build the topics (menu + knowledge + gate)

Create **four** topics.

---

### Topic E0 — Conversation Start / Main menu

**Name:** `Main menu`  
**Trigger:** On conversation start (and a phrase trigger `menu`)

**Message node:**

```text
Welcome to ExhaustShield

I can help with:
1) Company knowledge (policies — local answers)
2) Governed AI chat (scanned before anything leaves)
3) Open full dashboard (all 5 tabs)

What do you want to do?
```

**Ask a question** with options:

| Option text | Navigate to |
|---|---|
| Company knowledge | Topic E1 |
| Governed AI chat | Topic E2 |
| Open full dashboard | Topic E3 |

---

### Topic E1 — Company knowledge

**Name:** `Company knowledge`  
**Trigger phrases:** `policy`, `company knowledge`, `handbook`, `leave policy`

**Steps:**

1. **Ask:** `What is your policy question?`  
   Save answer → variable `UserQuestion` (text)

2. **Call action / HTTP** `AskKnowledge`  
   Body:

```json
{
  "question": "{UserQuestion}",
  "prefer_local_corrections": true
}
```

3. **Parse response** into variables (names depend on Studio UI):

| Variable | JSON path (typical) |
|---|---|
| `KnowledgeAnswer` | `answer` or `restored_response` |
| `NeedsHuman` | `needs_human_review` |
| `BestScore` | `best_score` |

4. **Condition:**

- If `NeedsHuman` is true →  
  `I could not find a solid local policy match. Please use Human vault in the full dashboard, or rephrase.`  
- Else →  
  `Here is the local policy answer:`  
  then show `{KnowledgeAnswer}`

5. **Message:**  
   `Tip: this path does not call an outside AI model.`

6. **Go to** Main menu (or End)

---

### Topic E2 — Governed AI chat (full gate workflow)

**Name:** `Governed AI chat`  
**Trigger phrases:** `ask ai`, `chat`, `generate`, `outbound gate`

#### Step E2.1 — Collect prompt

Ask: `What do you want to ask the AI?`  
Save → `UserPrompt`

#### Step E2.2 — Call Generate

HTTP / action `Generate`:

```json
{
  "prompt": "{UserPrompt}"
}
```

Save into variables:

| Variable | From response |
|---|---|
| `Awaiting` | `awaiting_confirm` |
| `PendingId` | `pending_id` |
| `ConfirmKind` | `confirm_kind` |
| `RiskLevel` | `guardian.risk_level` |
| `LaneBadge` | `guardian.lane_badge` |
| `Redacted` | `redacted_sent` |
| `Rewrite` | `rewrite_suggestion` |
| `RiskScore` | `risk_analysis.risk_score` (if present) |
| `DirectResponse` | `response` (may be empty) |

#### Step E2.3 — Branch on risk

**Condition group:**

##### Branch HIGH (`RiskLevel` equals `high`)

Message:

```text
HIGH lane — this prompt was held by ExhaustShield.
Nothing was sent to external AI.
Open the full dashboard Outbound Gate / Pilot Lab if you need the private-path details.
```

→ Main menu. **Do not call ConfirmGenerate.**

##### Branch SAFE (`RiskLevel` equals `safe` AND `Awaiting` is true)

Message:

```text
SAFE lane — no secrets detected.
Risk score: {RiskScore}
Pending id: {PendingId}

Send this prompt to external AI as written?
```

Adaptive Card / choice:

- **Confirm send** → E2.4a  
- **Cancel** → E2.4c  

##### Branch MEDIUM (`RiskLevel` equals `moderate` AND `Awaiting` is true)

Message:

```text
MEDIUM lane — sensitive spans found. Nothing sent yet.
Risk score: {RiskScore}

Hidden/placeholder version:
{Redacted}

Suggested rewrite:
{Rewrite}

How do you want to proceed?
```

Choices:

- **Send hidden version** → E2.4b with `chosen=redacted`  
- **Send suggested rewrite** → E2.4b with `chosen=rewrite`  
- **Cancel** → E2.4c  

##### Branch other / error

Show raw error or `Unknown or expired pending_id` guidance → ask user to retry Generate.

#### Step E2.4a — Confirm SAFE

Call `ConfirmGenerate`:

```json
{
  "pending_id": "{PendingId}",
  "chosen": "as_is"
}
```

Show final answer from confirm response (`response` / `restored_response` / message fields — inspect one real response and map the field once).

#### Step E2.4b — Confirm MEDIUM

```json
{
  "pending_id": "{PendingId}",
  "chosen": "redacted"
}
```

or

```json
{
  "pending_id": "{PendingId}",
  "chosen": "rewrite"
}
```

Show final answer.

#### Step E2.4c — Cancel

```json
{
  "pending_id": "{PendingId}",
  "chosen": "cancel"
}
```

Message: `Outbound cancelled — nothing sent to any AI.`

#### Step E2.5 — Return to menu

Always offer **Main menu** after the flow.

---

### Topic E3 — Open full dashboard

**Name:** `Open full dashboard`  
**Trigger:** `dashboard`, `overview`, `vault`, `pilot lab`

Message:

```text
Open the full ExhaustShield dashboard (all 5 tabs):

Overview · Company knowledge · Outbound Gate · Human vault · Pilot Lab

https://ai-gate.yourcompany.com/

Use this for live metrics, vault corrections, and Pilot Lab evidence.
```

(Replace with your real URL.)

---

## 11. Part F — Publish to Teams

### F1. Publish the agent

1. In Copilot Studio → **Publish**  
2. Wait until publish succeeds  

### F2. Turn on Teams channel

1. **Channels** → **Microsoft Teams**  
2. Enable / connect  
3. Open Teams link / availability settings  

### F3. Availability stages

| Stage | Who can use it |
|---|---|
| 1 | Only you |
| 2 | Security + 5 pilot users |
| 3 | One Team / channel |
| 4 | Org-wide (after tests) |

### F4. Admin approval

If users cannot see the app:

1. Teams admin centre → Manage apps  
2. Find `ExhaustShield Gate`  
3. Allow for org / specific users  

### F5. First user open

Teams → Apps → search agent name → Add → chat **Main menu**

---

## 12. Part G — Pin the full 5-tab dashboard

This is how beginners get **all 5 tabs** without rebuilding them in Studio.

1. Open the Team where the agent is used  
2. Channel → **+** → **Website**  
3. Tab name: `ExhaustShield`  
4. URL: `https://ai-gate.yourcompany.com/`  
5. Save  

Now:

- Chat agent = Knowledge + Gate  
- Website tab = Overview + Vault + Lab + full UI  

---

## 13. Part H — Test script

Run these exact tests. Tick each box.

### Knowledge

| # | Input | Pass if |
|---|---|---|
| H1 | “What is our leave policy?” (with a matching local doc uploaded) | Local answer, not external model |
| H2 | Nonsense question with no policy | Human gap / no silent LLM invent |

### SAFE

| # | Input | Pass if |
|---|---|---|
| H3 | “Explain TCP vs UDP simply” | `risk_level=safe`, confirm required |
| H4 | Confirm | External answer returns (or simulate answer) |
| H5 | Cancel instead | Message says nothing sent |

### MEDIUM

| # | Input | Pass if |
|---|---|---|
| H6 | Prompt including a fake deal value / employee salary style text your detector flags | `moderate`, shows redacted + rewrite |
| H7 | Confirm `redacted` | Answer returns; outbound was scrubbed |
| H8 | Cancel | Nothing sent |

### HIGH

| # | Input | Pass if |
|---|---|---|
| H9 | Prompt with API key / password / obvious secret | `high`; Studio never calls confirm-to-external |
| H10 | Check server audit / Overview traffic | Shows High / private path |

### Hybrid plumbing

| # | Check | Pass if |
|---|---|---|
| H11 | User with only basic Copilot Chat (no $30 seat) | Can open your agent (if Studio licensing allows) |
| H12 | Website tab | All 5 tabs load |
| H13 | `/api/health` | `ok: true` |

---

## 14. Part I — Rollout and go-live

### Phase 0 — Builder (you)

- [ ] FastAPI live on HTTPS  
- [ ] APIs tested with curl/Postman  
- [ ] Agent topics work for you  

### Phase 1 — Pilot (20–50 people, 30–60 days)

- [ ] `EXTERNAL_AI_MODE=simulate` or free tier if possible  
- [ ] Budget cap suggestion: **$500** total  
- [ ] Collect: High holds, Medium scrubs, user complaints  

### Phase 2 — Production

- [ ] `EXTERNAL_AI_MODE=live` + real key in server secret store  
- [ ] Studio Prod environment + credit plan agreed  
- [ ] InfoSec sign-off on HIGH never in external logs  

### Success metrics (90 days)

```text
Adoption %     = Users who opened agent or dashboard / invited users
Gate coverage  = Gated chats / (gated chats + known shadow AI incidents)
High holds     = Count of HIGH lanes
Medium scrubs  = Count of moderate confirms with chosen=redacted|rewrite
Cost           = Groq invoice + Studio credits
```

---

## 15. Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| Studio HTTP 401/403 | Auth missing | Add API key / Entra to connector |
| Studio HTTP timeout | Network blocked | Allow Power Platform → ai-gate |
| `Unknown or expired pending_id` | Confirm too late or server restarted | Pending store is in-memory — re-run Generate; for production use sticky single instance |
| SAFE never asks confirm | You showed `response` early | Always check `awaiting_confirm` |
| HIGH still “answers” from Studio model | Generative orchestration answered alone | Disable free answer; force tool call |
| Knowledge invents policy | Wrong endpoint or generative fallback | Must call `/api/ask-knowledge` only |
| Teams users can’t find agent | App not approved | Teams admin allow app |
| Cost spike | Studio credits + heavy chat | Cap pilots; check credit report |

**Production note:** `pending_id` values live in process memory (`pending_moderate`). Run **one** gateway instance (or later add shared cache) so Confirm always hits the same process that created the pending id.

---

## 16. Copy-paste Adaptive Card JSON

Use in Topic E2 for SAFE confirm (paste into Adaptive Card node if available).

```json
{
  "type": "AdaptiveCard",
  "version": "1.5",
  "body": [
    {
      "type": "TextBlock",
      "text": "ExhaustShield — SAFE confirm",
      "weight": "Bolder",
      "size": "Medium"
    },
    {
      "type": "TextBlock",
      "text": "No secrets detected. Send this prompt to external AI as written?",
      "wrap": true
    },
    {
      "type": "TextBlock",
      "text": "Pending: ${PendingId}",
      "wrap": true,
      "size": "Small"
    }
  ],
  "actions": [
    {
      "type": "Action.Submit",
      "title": "Confirm send",
      "data": { "choice": "as_is" }
    },
    {
      "type": "Action.Submit",
      "title": "Cancel",
      "data": { "choice": "cancel" }
    }
  ]
}
```

MEDIUM card — same pattern with three actions: `redacted`, `rewrite`, `cancel`.

---

## 17. Questions to ask IT / admin

Copy-paste into an email:

```text
Subject: ExhaustShield hybrid — access needed

1) Which Power Platform environment should I use for Dev and Prod?
2) Do I have Copilot Studio maker rights? If not, which licence/role?
3) How are Copilot Studio credits billed for a custom agent in Teams?
4) Can Power Platform reach https://ai-gate.yourcompany.com?
5) Preferred API auth for the connector (API key vs Entra)?
6) Can we publish a custom Copilot Studio agent to Teams for a pilot group?
7) Can we add a Website tab in Team <NAME> to https://ai-gate.yourcompany.com/?
8) Who owns TLS + Windows/Linux service for the FastAPI process?
9) Is Groq (or Azure OpenAI) approved for SAFE/MEDIUM outbound after scrubbing?
10) Do we need InfoSec test that HIGH prompts never appear in external provider logs?
```

---

## Quick end-to-end checklist (one page)

1. [ ] Server runs ExhaustShield on HTTPS  
2. [ ] `/api/health`, `/api/ask-knowledge`, `/api/generate`, `/api/generate/confirm` work  
3. [ ] Copilot Studio agent created with “never classify yourself” instructions  
4. [ ] HTTP or custom connector points at the three APIs  
5. [ ] Topics: Main menu, Knowledge, Gated chat (SAFE/MEDIUM/HIGH branches), Dashboard link  
6. [ ] Publish → Teams channel enabled → admin approved  
7. [ ] Website tab pinned for full 5-tab UI  
8. [ ] Test script H1–H13 passed  
9. [ ] Pilot users invited; credits + token budget agreed  
10. [ ] Production go-live only after HIGH fail-closed proof  

---

## Remember for the board (one paragraph)

We keep Microsoft Copilot Chat and Purview for Office AI. ExhaustShield hybrid puts a **Copilot Agent in front of our FastAPI gate** so staff work in Teams, while **our engine** still decides SAFE / MEDIUM / HIGH / LOCAL. Full five tabs stay on the web dashboard. On an existing server, new cash cost is mainly **model tokens** (about **$0.00045 per gated chat**) plus **Studio credits** — not $30 Copilot seats for everyone.

---

*Handbook aligned to this repo’s `gateway.py` endpoints and confirm contract (`pending_id` + `chosen`). Designed by Manikandan / ExhaustShield pilot materials.*
