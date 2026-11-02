import json
import re
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone

import requests
from fastapi import FastAPI, File, Form, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from detector import ExhaustDetector
from document_extract import (
    SUPPORTED_EXTENSIONS,
    build_prompt_with_attachments,
    extract_attachment,
)
from knowledge import (
    KNOWLEDGE_ENGINE_VERSION,
    answer_from_local_policy,
    build_local_answer_from_hits,
    ensure_dirs as ensure_knowledge_dirs,
    is_close_policy_match,
    list_documents,
    missing_key_terms,
    normalize_question,
    retrieve_context,
    save_document,
)
from protection import (
    REVIEW_DIR,
    append_audit,
    build_evidence_brief,
    clear_audit,
    create_dispute_ticket,
    create_unanswered_ticket,
    delete_review,
    dispute_and_correct,
    ensure_dirs as ensure_protection_dirs,
    find_local_answer,
    list_queue,
    protection_status,
    read_audit_tail,
    submit_correction,
)
from router import (
    EXTERNAL_AI_MODE,
    HIGH_RISK_CATALOG,
    SAFE_MAX_SCORE,
    MODERATE_MAX_SCORE,
    answer_high_private,
    call_external_ai,
    classify_route,
    last_mile_classify,
    probe_external_ai,
    probe_live_web,
    refresh_external_ai_config,
    route_inference,
    external_runtime_status,
    suggest_rewrite,
    _normalize_chat_history,
)

app = FastAPI(title="ExhaustShield Gateway")
detector = ExhaustDetector()
ensure_knowledge_dirs()
ensure_protection_dirs()

SESSION_FILE = REVIEW_DIR / "demo_session.json"

app.mount("/static", StaticFiles(directory="static"), name="static")

active_websockets = []
# Moderate-lane preflight: wait for user to approve redacted vs rewrite before egress
pending_moderate: dict[str, dict] = {}
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

# Bumps on Reset Demo so in-flight Tab 2/3 handlers cannot rehydrate cleared stats.
_session_epoch = 0
_request_epoch: ContextVar[int | None] = ContextVar("request_epoch", default=None)


class _EpochGuardedSession(dict):
    """Ignore assignments from HTTP requests that started before the latest Reset Demo."""

    def __setitem__(self, key, value):
        if key == "session_epoch" or _session_writes_allowed():
            super().__setitem__(key, value)

    def update(self, *args, **kwargs):
        if not _session_writes_allowed():
            return
        super().update(*args, **kwargs)


class _SessionEpochMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = _request_epoch.set(_session_epoch)
        try:
            return await call_next(request)
        finally:
            _request_epoch.reset(token)


app.add_middleware(_SessionEpochMiddleware)


def _session_writes_allowed() -> bool:
    """False when this request started before the latest Reset Demo."""
    bound = _request_epoch.get()
    if bound is None:
        return True
    return int(bound) == int(_session_epoch)


def _norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def _primary_department(data: dict, depts: list[str]) -> list[str]:
    """One team per traffic row so Lanes-by-team totals match the sync line."""
    if not depts:
        return []
    top = (data.get("top_blocked_category") or "").strip().lower()
    if top and top != "none" and top in depts:
        return [top]
    return [depts[0]]


# Topic / process words that may remain in a Medium rewrite on purpose
_OUTBOUND_TOPIC_ALLOW = frozenset(
    {
        "company", "the company", "our company", "a company",
        "resume", "cv", "curriculum vitae", "offer letter", "employment contract",
        "appointment letter", "relieving letter", "performance review", "pip",
        "payroll", "payslip", "pay stub", "compensation", "salary", "bonus",
        "severance", "headcount", "hiring plan", "background check",
        "revenue", "ebitda", "profit", "pricing", "discount", "acquisition",
        "confidential", "nda", "contract", "forecast", "pipeline", "margin",
        "growth", "yoy", "quarter", "report", "summary", "analyze", "summarize",
    }
)


def _assert_sanitized_moderate_outbound(
    sent: str,
    raw_prompt: str,
    analysis: dict,
) -> tuple[bool, str]:
    """Block Medium confirm when outbound is cleartext or still holds HIDE values."""
    sent_n = _norm_text(sent)
    raw_n = _norm_text(raw_prompt)
    if not sent_n:
        return False, "Outbound text is empty — choose placeholders or a rewrite."
    if sent_n == raw_n:
        return (
            False,
            "Outbound matches the original cleartext. Use placeholders or the "
            "suggested rewrite — secrets must not be restored before send.",
        )
    hide_items = [
        it
        for it in (analysis.get("flagged_items") or [])
        if (it.get("action") or "hide") == "hide"
    ]
    sent_l = (sent or "").lower()
    leaked = []
    # Prefer analysis-scale restore originals; else concrete hide values.
    # Skip topic words (e.g. "Resume") that legitimately remain in the rewrite.
    restore_vals = list(
        ((analysis.get("analysis_scrub") or {}).get("restore_map") or {}).values()
    )
    check_vals = restore_vals or [
        str(it.get("value") or "").strip() for it in hide_items
    ]
    for val in check_vals:
        val = str(val or "").strip()
        if len(val) < 3:
            continue
        vl = val.lower()
        if vl in _OUTBOUND_TOPIC_ALLOW:
            continue
        # Single generic dictionary word without digits/$/@ — not a concrete secret
        if (
            re.fullmatch(r"[A-Za-z][A-Za-z\- ]{1,40}", val)
            and not re.search(r"\d|@|\$", val)
            and len(val.split()) <= 3
            and vl
            in {
                "resume",
                "salary",
                "bonus",
                "payroll",
                "headcount",
                "acquisition",
                "revenue",
                "forecast",
                "pipeline",
                "contract",
                "nda",
            }
        ):
            continue
        if vl in sent_l:
            leaked.append(val[:40] + ("…" if len(val) > 40 else ""))
    if leaked:
        return (
            False,
            "Cleartext secret(s) still present in outbound: "
            + ", ".join(leaked[:4])
            + ". Remove them or use placeholders / rewrite.",
        )
    return True, ""


def _fresh_session_stats() -> dict:
    return _EpochGuardedSession({
        "total_prompts": 0,
        "total_blocked": 0,
        "leak_items_caught": 0,
        "doc_sensitivity_items": 0,
        "total_risk_sum": 0,
        "knowledge_queries": 0,
        "local_answers_served": 0,
        "shielded_rag_answers": 0,
        "unanswered_to_human": 0,
        "human_corrections": 0,
        "llm_calls_avoided": 0,
        "llm_calls_made": 0,
        "vault_gaps_closed": 0,
        "routes_safe": 0,
        "routes_moderate": 0,
        "routes_high": 0,
        "external_calls": 0,
        "private_calls": 0,
        "boundary_stayed_local": 0,
        "boundary_left_device": 0,
        "boundary_blocked": 0,
        "recent_blocked_items": [],
        "recent_leak_items": [],
        "recent_doc_items": [],
        "recent_traffic": [],
        "lane_prompts": {"safe": [], "moderate": [], "high": []},
        "last_shield_event": None,
        "last_knowledge_event": None,
        "session_epoch": _session_epoch,
        "by_department": {d: 0 for d in ExhaustDetector.PATTERNS.keys()},
        "blocked_by_department": {d: 0 for d in ExhaustDetector.PATTERNS.keys()},
        "leak_by_department": {d: 0 for d in ExhaustDetector.PATTERNS.keys()},
        "doc_by_department": {d: 0 for d in ExhaustDetector.PATTERNS.keys()},
        "history": [],
    })


def _dedupe_traffic_items(items: list) -> list:
    """Keep first occurrence of each ask (normalized what + lane). Collapses twins."""
    out: list = []
    seen: set[str] = set()
    for it in items or []:
        if not isinstance(it, dict):
            continue
        what = re.sub(r"\s+", " ", str(it.get("what") or "")).strip().lower()
        key = f"{what}|{it.get('cls')}"
        if not what or key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out[:12]


def _load_session_stats() -> dict:
    """Restore demo KPIs from disk — metrics stay until Reset Demo."""
    base = _fresh_session_stats()
    try:
        if not SESSION_FILE.exists():
            return base
        raw = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return base
        merged = {**base, **raw}
        # Ensure nested dicts / lists exist with correct shapes
        for key in (
            "by_department",
            "blocked_by_department",
            "leak_by_department",
            "doc_by_department",
        ):
            if not isinstance(merged.get(key), dict):
                merged[key] = {d: 0 for d in ExhaustDetector.PATTERNS.keys()}
            else:
                for d in ExhaustDetector.PATTERNS.keys():
                    merged[key].setdefault(d, 0)
        if not isinstance(merged.get("lane_prompts"), dict):
            merged["lane_prompts"] = {"safe": [], "moderate": [], "high": []}
        else:
            for k in ("safe", "moderate", "high"):
                merged["lane_prompts"].setdefault(k, [])
        # Drop legacy independent counter — Lanes by team derives from recent_traffic
        merged.pop("lanes_by_department", None)
        for key in (
            "recent_blocked_items",
            "recent_leak_items",
            "recent_doc_items",
            "recent_traffic",
            "history",
        ):
            if not isinstance(merged.get(key), list):
                merged[key] = []
        merged["recent_traffic"] = _dedupe_traffic_items(merged.get("recent_traffic") or [])
        # Disk may carry an old epoch; live counter wins after process start / Reset Demo.
        merged["session_epoch"] = _session_epoch
        return _EpochGuardedSession(merged)
    except Exception:
        return base


def _persist_session_stats() -> None:
    """Write demo metrics to disk so refresh/restart does not wipe or invent KPIs."""
    try:
        ensure_protection_dirs()
        # Drop non-JSON / oversized blobs carefully — last_* events are needed for UI restore
        payload = dict(session_stats)
        SESSION_FILE.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
    except Exception:
        pass


session_stats = _load_session_stats()


def reset_session_stats() -> dict:
    """Only path that clears dashboard metrics — Reset Demo button."""
    global session_stats, pending_moderate, _session_epoch
    _session_epoch = int(_session_epoch or 0) + 1
    # Re-bind so the remainder of this Reset Demo request can persist the fresh session.
    _request_epoch.set(_session_epoch)
    session_stats = _fresh_session_stats()
    pending_moderate = {}
    try:
        if SESSION_FILE.exists():
            SESSION_FILE.unlink()
    except Exception:
        pass
    # Full wipe — do not leave an audit_reset row that reappears in Pilot Lab.
    clear_audit(record_marker=False)
    _persist_session_stats()
    return _session_snapshot(persist=False)


_DATA_BOUNDARY_COPY = {
    "left_device": "This request was sent to an external AI (Groq).",
    "stayed_local": (
        "This request was answered entirely on this machine. Nothing was sent externally."
    ),
    "blocked_no_ai_call": "This request was blocked. No AI call was made at all.",
}


def _data_boundary_fields(
    boundary: str,
    *,
    explanation: str | None = None,
    count: bool = True,
) -> dict:
    """Attach an explicit data-boundary verdict (additive — does not change routing)."""
    key = boundary if boundary in _DATA_BOUNDARY_COPY else "stayed_local"
    if count and _session_writes_allowed():
        if key == "left_device":
            session_stats["boundary_left_device"] = int(
                session_stats.get("boundary_left_device") or 0
            ) + 1
        elif key == "blocked_no_ai_call":
            session_stats["boundary_blocked"] = int(
                session_stats.get("boundary_blocked") or 0
            ) + 1
        else:
            session_stats["boundary_stayed_local"] = int(
                session_stats.get("boundary_stayed_local") or 0
            ) + 1
    return {
        "data_boundary": key,
        "data_boundary_explanation": explanation or _DATA_BOUNDARY_COPY[key],
    }


def _boundary_from_guardian_route(
    decision: dict,
    call_meta: dict | None,
    *,
    response_text: str = "",
) -> dict:
    """Map existing SAFE / HIGH route outcomes to a data_boundary (no logic change)."""
    meta = call_meta or {}
    level = (decision or {}).get("risk_level") or ""
    dest = (decision or {}).get("destination") or ""
    if level == "safe" or (dest == "external" and level != "high"):
        return _data_boundary_fields("left_device")
    if dest == "private" or level == "high":
        unavailable = str(response_text or "").startswith("PRIVATE LLM UNAVAILABLE")
        if (meta.get("fail_closed") and not meta.get("ok")) or unavailable:
            return _data_boundary_fields("blocked_no_ai_call")
        return _data_boundary_fields("stayed_local")
    return _data_boundary_fields("stayed_local")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_websockets:
            active_websockets.remove(websocket)


async def broadcast_event(data: dict):
    # Drop late broadcasts from requests that started before Reset Demo.
    if not _session_writes_allowed() and (data or {}).get("type") != "session_reset":
        return
    _remember_ui_event(data)
    # Refresh session snapshot after traffic/last-event persistence so clients get ids
    if isinstance(data, dict) and "session" in data:
        if (data.get("type") or "") == "session_reset":
            # Keep the fresh snap from reset_session_stats — do not re-merge stale fields.
            data["session"] = _session_snapshot(persist=False)
            data["recent_traffic"] = []
            data["session_epoch"] = _session_epoch
        else:
            data["session"] = _session_snapshot()
            if "recent_traffic" in (data.get("session") or {}):
                data["recent_traffic"] = data["session"].get("recent_traffic") or []
            data["session_epoch"] = session_stats.get("session_epoch", _session_epoch)
    dead = []
    try:
        payload = json.dumps(data, default=str)
    except Exception:
        payload = json.dumps({"type": "broadcast_error", "error": "non-serializable event"}, default=str)
    for ws in active_websockets:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in active_websockets:
            active_websockets.remove(ws)


def _remember_lane_prompt(
    level: str | None,
    prompt: str | None,
    *,
    brief: str | None = None,
    source: str = "tab3",
) -> None:
    """Keep per-lane prompt lists for the Overview 'Lane categories' dropdown."""
    if not _session_writes_allowed():
        return
    key = (level or "").lower()
    if key == "moderate":
        bucket = "moderate"
    elif key in {"safe", "high"}:
        bucket = key
    else:
        return
    text = (prompt or "").strip()
    if not text:
        return
    session_stats.setdefault(
        "lane_prompts", {"safe": [], "moderate": [], "high": []}
    )
    lanes = session_stats["lane_prompts"]
    lanes.setdefault(bucket, [])
    entry = {
        "prompt": text[:180],
        "brief": (brief or "")[:160] or None,
        "source": source,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    # De-dupe identical prompt at head of same lane
    existing = lanes[bucket]
    if existing and (existing[0].get("prompt") or "") == entry["prompt"]:
        lanes[bucket][0] = entry
    else:
        lanes[bucket] = [entry, *existing][:12]


def _prompt_from_traffic_what(what: str) -> str:
    """Extract the quoted prompt preview from a traffic 'what' label."""
    text = what or ""
    m = re.search(r"[“\"](.+?)[”\"]", text)
    if m:
        return m.group(1).replace("…", "").strip()
    # Fallback: strip common prefixes
    for prefix in (
        "Free-form prompt:",
        "Policy / knowledge question:",
        "Policy question — no good match:",
        "Marked local answer incorrect:",
    ):
        if text.startswith(prefix):
            return text[len(prefix) :].strip(" “\"”")
    return text.strip()


def _infer_departments_from_text(text: str) -> list[str]:
    """Run detector on prompt text so Lanes-by-team can pick a real team."""
    prompt = (text or "").strip()
    if not prompt or len(prompt) < 3:
        return []
    try:
        analysis = detector.analyze_prompt(prompt)
    except Exception:
        return []
    by_dept = analysis.get("by_department") or {}
    ranked = sorted(
        ((str(d).lower(), int(c or 0)) for d, c in by_dept.items() if c),
        key=lambda kv: (-kv[1], kv[0]),
    )
    known = ExhaustDetector.PATTERNS.keys()
    return [d for d, _ in ranked if d in known]


def _departments_from_event(data: dict) -> list[str]:
    """Departments touched by this ask — for Lanes-by-team (synced to traffic rows)."""
    if not isinstance(data, dict):
        return []
    known = ExhaustDetector.PATTERNS.keys()
    seen: list[str] = []
    scores: dict[str, int] = {}

    def _add(dept: str | None, weight: int = 1) -> None:
        d = (dept or "").strip().lower()
        if d in known:
            scores[d] = scores.get(d, 0) + weight
            if d not in seen:
                seen.append(d)

    analysis = data.get("risk_analysis") if isinstance(data.get("risk_analysis"), dict) else {}
    by_dept = data.get("by_department") or analysis.get("by_department") or {}
    if isinstance(by_dept, dict):
        for dept, count in by_dept.items():
            if count:
                _add(dept, int(count))
    for it in data.get("flagged_items") or analysis.get("flagged_items") or []:
        if isinstance(it, dict):
            _add(it.get("department") or it.get("type"), 1)
    for it in data.get("placeholders") or analysis.get("placeholders") or []:
        if isinstance(it, dict):
            _add(it.get("department") or it.get("type"), 1)
    top = data.get("top_blocked_category") or analysis.get("top_blocked_category")
    if top and top != "none":
        _add(top, 2)

    # If event payload lacked spans (older rows / thin broadcasts), re-scan the prompt
    if not seen:
        prompt = (data.get("original_prompt") or data.get("question") or "").strip()
        for d in _infer_departments_from_text(prompt):
            _add(d, 1)

    if not seen:
        return []
    # Highest signal first (primary team for the chart)
    return sorted(seen, key=lambda d: (-scores.get(d, 0), d))


def _backfill_traffic_departments(items: list) -> list:
    """Attach a real team to traffic rows that only had General / missing tags."""
    out = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        row = dict(it)
        depts = row.get("departments")
        if not (isinstance(depts, list) and depts):
            prompt = _prompt_from_traffic_what(str(row.get("what") or ""))
            inferred = _infer_departments_from_text(prompt)
            if inferred:
                row["departments"] = [inferred[0]]
        # Stamp knowledge path for Overview "Knowledge by team" (legacy rows)
        if not row.get("kpath"):
            cls = str(row.get("cls") or "").lower()
            where = str(row.get("where") or "").lower()
            if cls == "human":
                row["kpath"] = "human"
            elif cls == "local":
                row["kpath"] = (
                    "vault"
                    if ("human vault" in where or "vault" in where)
                    else "local"
                )
        out.append(row)
    return out


# Backfill team tags now that helpers exist (fixes older General-only traffic)
try:
    session_stats["recent_traffic"] = _backfill_traffic_departments(
        _dedupe_traffic_items(list(session_stats.get("recent_traffic") or []))
    )
    _persist_session_stats()
except Exception:
    pass


def _traffic_item_from_event(data: dict) -> dict | None:
    """Build a compact traffic-board row that survives page refresh."""
    if not isinstance(data, dict):
        return None
    # Never turn control/status broadcasts into traffic rows (esp. deletes)
    t = (data.get("type") or "").strip()
    if t in {
        "traffic_deleted",
        "human_correction",
        "human_review_deleted",
        "broadcast_error",
        "session_reset",
    }:
        return None
    g = data.get("guardian") or {}
    cls = "local"
    where = "Stayed on this machine (local files)"
    what = "Policy / knowledge question"
    kpath = None
    if g.get("risk_level") == "safe":
        cls, where, what = "safe", "Safe → sent to outside AI as written", "Free-form prompt"
    elif g.get("risk_level") == "moderate":
        cls, where, what = "moderate", "Medium → secrets hidden, then outside AI", "Free-form prompt"
    elif g.get("risk_level") == "high":
        cls, where, what = "high", "High → private AI only (nothing left the building)", "Free-form prompt"
    elif (
        data.get("needs_human_review")
        or data.get("lane") == "human_gap"
        or data.get("logic_path") in {"disputed_to_human", "no_local_context"}
    ):
        cls, where = "human", "Sent to human vault (no model guess)"
        kpath = "human"
        what = (
            "Marked local answer incorrect"
            if data.get("logic_path") == "disputed_to_human"
            else "Policy question — no good match"
        )
    elif data.get("lane") == "local" or data.get("logic_path") in {"local_near_match", "vault_hit"}:
        cls = "local"
        if data.get("logic_path") == "vault_hit":
            where = "Answered from human vault (no LLM)"
            kpath = "vault"
        else:
            where = "Answered from local policy files (no LLM)"
            kpath = "local"
        what = "Policy / knowledge question"
    elif data.get("type") == "prompt_shield" or data.get("original_prompt"):
        cls, where, what = "safe", "Routed through Outbound Gate", "Free-form prompt"
    else:
        return None

    preview = (data.get("question") or data.get("original_prompt") or "").strip()
    if preview:
        short = preview if len(preview) <= 56 else preview[:53] + "…"
        what = f"{what}: “{short}”"
    item = {
        "id": uuid.uuid4().hex[:12],
        "cls": cls,
        "what": what,
        "where": where,
    }
    if kpath:
        item["kpath"] = kpath
    depts = _departments_from_event(data)
    primary = _primary_department(data, depts)
    if primary:
        item["departments"] = primary
    return item


def _remember_ui_event(data: dict) -> None:
    """Persist UI-facing session pieces so a browser refresh does not wipe the demo."""
    if not isinstance(data, dict):
        return
    if (data.get("type") or "") in {
        "session_reset",
        "traffic_deleted",
        "human_correction",
        "human_review_deleted",
        "broadcast_error",
    }:
        return
    if not _session_writes_allowed():
        return
    session_stats.setdefault("recent_traffic", [])
    # Pre-flight holds are not a final destination — only record after confirm/cancel/block.
    awaiting = bool(
        data.get("awaiting_confirm")
        or (data.get("guardian") or {}).get("awaiting_confirm")
    )
    if not awaiting:
        item = _traffic_item_from_event(data)
        if item:
            traffic = list(session_stats.get("recent_traffic") or [])
            what_n = re.sub(r"\s+", " ", str(item.get("what") or "")).strip().lower()
            key = f"{what_n}|{item.get('cls')}"
            existing_idx = None
            for i, row in enumerate(traffic):
                row_what = re.sub(r"\s+", " ", str(row.get("what") or "")).strip().lower()
                if f"{row_what}|{row.get('cls')}" == key:
                    existing_idx = i
                    break
            if existing_idx is not None:
                head = traffic[existing_idx]
                if item.get("departments") and not head.get("departments"):
                    head["departments"] = list(item["departments"])
                head["where"] = item.get("where") or head.get("where")
                if item.get("kpath") and not head.get("kpath"):
                    head["kpath"] = item["kpath"]
                if existing_idx != 0:
                    traffic.pop(existing_idx)
                    traffic.insert(0, head)
            else:
                traffic.insert(0, item)
            session_stats["recent_traffic"] = _dedupe_traffic_items(traffic)
    else:
        # Scrub any prior identical pending/confirm twins left in the session file
        session_stats["recent_traffic"] = _dedupe_traffic_items(
            session_stats.get("recent_traffic") or []
        )

    t = data.get("type") or ""
    if t == "prompt_shield" or data.get("guardian") or data.get("original_prompt"):
        g = data.get("guardian") or {}
        level = g.get("risk_level")
        reasons = g.get("reasons") or []
        _remember_lane_prompt(
            level,
            data.get("original_prompt"),
            brief=(reasons[0] if reasons else None),
            source="tab3",
        )
        # Drop websocket-only bulk; keep fields the dashboard pipes need
        session_stats["last_shield_event"] = {
            k: data.get(k)
            for k in (
                "type",
                "timestamp",
                "original_prompt",
                "redacted_prompt",
                "rewrite_suggestion",
                "prompt_sent_to_model",
                "llm_raw_response",
                "restored_response",
                "risk_score",
                "flagged_items",
                "placeholders",
                "placeholder_policy",
                "prevention",
                "guardian",
                "data_boundary",
                "data_boundary_explanation",
                "token_bridge",
                "department_risk",
                "top_blocked_category",
                "logic_path",
                "lane",
                "lane_badge",
                "comparison",
                "wow",
                "awaiting_confirm",
                "confirm_choice",
                "confirm_kind",
                "pending_id",
                "data_boundary",
                "data_boundary_explanation",
            )
            if k in data
        }
    if t.startswith("knowledge_") or data.get("logic_path") in {
        "local_near_match",
        "vault_hit",
        "no_local_context",
        "disputed_to_human",
        "human_override",
    }:
        session_stats["last_knowledge_event"] = {
            k: data.get(k)
            for k in (
                "type",
                "timestamp",
                "question",
                "answer",
                "restored_response",
                "explanation",
                "logic_path",
                "answer_source",
                "needs_human_review",
                "sources",
                "lane",
                "lane_badge",
                "comparison",
                "wow",
                "risk_score",
                "content_sensitivity_score",
                "flagged_items",
                "placeholders",
                "department_risk",
                "review",
                "data_boundary",
                "data_boundary_explanation",
            )
            if k in data
        }


def _call_ollama(model: str, prompt: str) -> str:
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=120,
            proxies={"http": None, "https": None},
        )
        ollama_data = response.json() if response.status_code == 200 else {}
        return ollama_data.get("response", "Error connecting to Ollama")
    except Exception as exc:
        return f"Error connecting to Ollama: {exc}"


def _session_snapshot(*, persist: bool = True) -> dict:
    """Return current demo metrics. Persist so only Reset Demo clears them."""
    if persist:
        _persist_session_stats()
    leak_dept = session_stats.get("leak_by_department") or {}
    ranked = sorted(leak_dept.items(), key=lambda kv: kv[1], reverse=True)
    top_cat, top_count = ("none", 0)
    if ranked and ranked[0][1] > 0:
        top_cat, top_count = ranked[0]
    # Fallback: overall blocked mix if no leak traffic yet
    if top_count == 0:
        blocked = session_stats["blocked_by_department"]
        ranked = sorted(blocked.items(), key=lambda kv: kv[1], reverse=True)
        if ranked and ranked[0][1] > 0:
            top_cat, top_count = ranked[0]
    return {
        **session_stats,
        "top_blocked_category": top_cat,
        "top_blocked_count": top_count,
        "category_mix": dict(session_stats["blocked_by_department"]),
        "ceo_scoreboard": {
            "secrets_blocked": session_stats.get("leak_items_caught", session_stats["total_blocked"]),
            "leak_items_caught": session_stats.get("leak_items_caught", 0),
            "doc_sensitivity_items": session_stats.get("doc_sensitivity_items", 0),
            "llm_calls_avoided": session_stats["llm_calls_avoided"],
            "llm_calls_made": session_stats["llm_calls_made"],
            "vault_gaps_closed": session_stats["vault_gaps_closed"],
            "routes_safe": session_stats["routes_safe"],
            "routes_moderate": session_stats["routes_moderate"],
            "routes_high": session_stats["routes_high"],
            "external_calls": session_stats["external_calls"],
            "private_calls": session_stats["private_calls"],
            "boundary_stayed_local": session_stats.get("boundary_stayed_local", 0),
            "boundary_left_device": session_stats.get("boundary_left_device", 0),
            "boundary_blocked": session_stats.get("boundary_blocked", 0),
            "recent_blocked_items": session_stats["recent_blocked_items"][-12:],
            "recent_leak_items": session_stats.get("recent_leak_items", [])[-12:],
            "recent_doc_items": session_stats.get("recent_doc_items", [])[-12:],
            "recent_traffic": _backfill_traffic_departments(
                _dedupe_traffic_items(session_stats.get("recent_traffic", []))
            ),
            "lane_prompts": {
                "safe": list((session_stats.get("lane_prompts") or {}).get("safe") or [])[:12],
                "moderate": list((session_stats.get("lane_prompts") or {}).get("moderate") or [])[:12],
                "high": list((session_stats.get("lane_prompts") or {}).get("high") or [])[:12],
            },
        },
        "recent_traffic": _backfill_traffic_departments(
            _dedupe_traffic_items(session_stats.get("recent_traffic", []))
        ),
        "lane_prompts": {
            "safe": list((session_stats.get("lane_prompts") or {}).get("safe") or [])[:12],
            "moderate": list((session_stats.get("lane_prompts") or {}).get("moderate") or [])[:12],
            "high": list((session_stats.get("lane_prompts") or {}).get("high") or [])[:12],
        },
        "last_shield_event": session_stats.get("last_shield_event"),
        "last_knowledge_event": session_stats.get("last_knowledge_event"),
        "session_epoch": session_stats.get("session_epoch", _session_epoch),
    }


def _lane_payload(lane: str, plain_rag_would_send: str, exhaustshield_sent: str, wow: str) -> dict:
    labels = {
        "local": "LOCAL · NO LLM",
        "shielded": "SHIELDED",
        "human_gap": "HUMAN GAP",
        "prompt_shield": "SHIELDED",
        "external_safe": "SAFE · OUTSIDE AI",
        "external_sanitized": "MEDIUM · HIDE THEN OUTSIDE",
        "private_high": "HIGH · PRIVATE AI ONLY",
    }
    return {
        "lane": lane,
        "lane_badge": labels.get(lane, lane.upper()),
        "comparison": {
            "plain_rag_would_send": plain_rag_would_send,
            "exhaustshield_sent": exhaustshield_sent,
        },
        "wow": wow,
    }


def _hide_spans_only(analysis: dict) -> list[dict]:
    """Spans that are actually masked/redacted — not topic 'keep' words.

    Overview 'Could have leaked' must list only what the hide pipeline treats,
    matching redacted_text / rewrite substitutions for the same request.
    """
    out: list[dict] = []
    for item in analysis.get("flagged_items") or []:
        action = (item.get("action") or "hide").lower()
        if action != "hide":
            continue
        raw = str(item.get("value") or item.get("original") or "").strip()
        if not raw:
            continue
        out.append(item)
    return out


def _track_analysis(analysis: dict, event_type: str = "prompt", *, kind: str = "leak") -> None:
    """kind='leak' = egress/Tab3 (could leave to an AI); kind='doc' = local policy wording only."""
    if not _session_writes_allowed():
        return
    session_stats["total_prompts"] += 1
    # Only concrete hide spans — topic/keep words stay for risk scoring but are
    # not masked outbound, so they must not appear under "Could have leaked".
    flagged = _hide_spans_only(analysis)
    blocked = len(flagged)
    if not blocked:
        blocked = int((analysis.get("prevention") or {}).get("secrets_blocked") or 0)

    kind = "doc" if kind == "doc" else "leak"
    if kind == "leak":
        session_stats["leak_items_caught"] = session_stats.get("leak_items_caught", 0) + blocked
        session_stats["total_blocked"] = session_stats["leak_items_caught"]
        session_stats["total_risk_sum"] += analysis.get("risk_score") or 0
    else:
        session_stats["doc_sensitivity_items"] = session_stats.get("doc_sensitivity_items", 0) + blocked

    # Department tallies for risk UI still use full analysis; leak-caught list uses hide-only.
    by_dept_all = analysis.get("by_department") or {}
    by_dept: dict[str, int] = {}
    for item in flagged:
        dept = item.get("department") or item.get("type") or "unknown"
        by_dept[dept] = by_dept.get(dept, 0) + 1
    dept_bucket = "leak_by_department" if kind == "leak" else "doc_by_department"
    if dept_bucket not in session_stats:
        session_stats[dept_bucket] = {d: 0 for d in ExhaustDetector.PATTERNS.keys()}
    for dept, count in by_dept_all.items():
        session_stats["by_department"][dept] = (
            session_stats["by_department"].get(dept, 0) + count
        )
    for dept, count in by_dept.items():
        if kind == "leak":
            session_stats["blocked_by_department"][dept] = (
                session_stats["blocked_by_department"].get(dept, 0) + count
            )
        session_stats[dept_bucket][dept] = (
            session_stats[dept_bucket].get(dept, 0) + count
        )

    for key in ("recent_blocked_items", "recent_leak_items", "recent_doc_items"):
        if key not in session_stats:
            session_stats[key] = []

    def _append_item(raw: str, dept: str, token: str = "") -> None:
        preview = raw if len(raw) <= 64 else raw[:61] + "…"
        entry = {
            "department": dept,
            "value": preview,
            "token": token,
            "event": event_type,
            "kind": kind,
            "action": "hide",
        }
        session_stats["recent_blocked_items"].append(entry)
        if kind == "leak":
            session_stats["recent_leak_items"].append(entry)
        else:
            session_stats["recent_doc_items"].append(entry)

    for item in flagged:
        raw = str(item.get("value") or item.get("original") or "")
        if not raw.strip():
            continue
        _append_item(
            raw,
            item.get("department") or item.get("type") or "unknown",
            item.get("token") or "",
        )
    if blocked and not flagged:
        for dept, count in by_dept_all.items():
            for _ in range(int(count or 0)):
                _append_item(f"(sensitive {dept} term)", dept)

    session_stats["recent_blocked_items"] = session_stats["recent_blocked_items"][-40:]
    session_stats["recent_leak_items"] = session_stats["recent_leak_items"][-30:]
    session_stats["recent_doc_items"] = session_stats["recent_doc_items"][-30:]
    stamp = datetime.now(timezone.utc).isoformat()
    session_stats["history"].append(
        {
            "ts": stamp,
            "type": event_type,
            "kind": kind,
            "risk_score": analysis.get("risk_score") or 0,
            "blocked": blocked,
            "departments": by_dept,
            "top_category": (
                max(by_dept, key=by_dept.get)
                if by_dept
                else "none"
            ),
        }
    )
    session_stats["history"] = session_stats["history"][-40:]


@app.get("/")
def get_dashboard():
    with open("static/index.html", encoding="utf-8") as f:
        html = f.read()
    return HTMLResponse(
        content=html,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )


@app.post("/api/session/reset")
async def api_reset_session():
    """Full demo wipe: session metrics, traffic, last events, pending confirms, audit locker."""
    snap = reset_session_stats()
    await broadcast_event(
        {
            "type": "session_reset",
            "session": snap,
            "recent_traffic": [],
            "protection": protection_status(),
        }
    )
    return {"ok": True, "session": snap, "audit_cleared": True}


@app.delete("/api/traffic/{item_id}")
async def api_delete_traffic(item_id: str):
    """Remove one row from the Overview 'Where did it go?' board."""
    tid = (item_id or "").strip()
    if not tid:
        return {"ok": False, "error": "item_id is required"}
    rows = list(session_stats.get("recent_traffic") or [])
    kept = [r for r in rows if str(r.get("id") or "") != tid]
    if len(kept) == len(rows):
        return {"ok": False, "error": f"Traffic item not found: {tid}"}
    session_stats["recent_traffic"] = kept
    snap = _session_snapshot()
    await broadcast_event(
        {
            "type": "traffic_deleted",
            "item_id": tid,
            "recent_traffic": kept[:12],
            "session": snap,
        }
    )
    return {"ok": True, "item_id": tid, "recent_traffic": kept[:12], "session": snap}


@app.get("/api/stats")
def get_stats():
    snap = _session_snapshot()
    avg_risk = (
        round(session_stats["total_risk_sum"] / session_stats["total_prompts"], 1)
        if session_stats["total_prompts"]
        else 0
    )
    return {
        **snap,
        "average_risk": avg_risk,
        "prevention_rate": round(
            (session_stats["total_blocked"] / max(1, session_stats["total_prompts"])) * 100,
            1,
        ),
        "protection": protection_status(),
    }


@app.get("/api/documents")
def api_list_documents():
    return {"documents": list_documents(), "folder": "confidential_data/"}


@app.post("/api/documents")
async def api_upload_document(
    content: str = Form(...),
    filename: str = Form("policy.txt"),
):
    doc = save_document(filename, content)
    append_audit({"event": "document_saved", "doc": doc["id"], "sent_to_llm": False})
    return {"ok": True, "document": doc}


@app.post("/api/attachments/extract")
async def api_extract_attachments(files: list[UploadFile] = File(...)):
    """Local-only extract of PDF/Word/Excel/images/text for chat attach.

    Does NOT call any LLM. Text is returned to the browser; Tab 3 generate
    then runs detector + table/analysis scrub before external AI.
    """
    results = []
    for f in files[:8]:
        raw = await f.read()
        name = f.filename or "upload.bin"
        # Soft size guard (~12 MB each)
        if len(raw) > 12 * 1024 * 1024:
            results.append(
                {
                    "ok": False,
                    "filename": name,
                    "text": "",
                    "kind": "too_large",
                    "warnings": ["File exceeds 12 MB limit"],
                    "chars": 0,
                }
            )
            continue
        results.append(extract_attachment(name, raw))
    append_audit(
        {
            "event": "attachments_extracted",
            "count": len(results),
            "ok_count": sum(1 for r in results if r.get("ok")),
            "sent_to_llm": False,
            "names": [r.get("filename") for r in results][:8],
        }
    )
    return {
        "ok": True,
        "attachments": results,
        "supported_extensions": sorted(SUPPORTED_EXTENSIONS),
        "sent_to_llm": False,
        "note": (
            "Extracted on-gateway only. Outbound Gate will scrub tables/figures "
            "(synthetic / scaled) before any external model sees them."
        ),
    }


@app.post("/api/documents/upload")
async def api_upload_file(file: UploadFile = File(...)):
    raw = await file.read()
    name = file.filename or "upload.txt"
    # Prefer rich extract for office docs; fall back to utf-8
    extracted = extract_attachment(name, raw)
    text = extracted.get("text") if extracted.get("ok") else raw.decode("utf-8", errors="ignore")
    doc = save_document(name, text or "")
    scrub_meta = None
    # Full table/dataset → synthetic scrub preview (same path as Medium rewrite)
    if text and ExhaustDetector.looks_like_dataset(text):
        scrub = ExhaustDetector.build_table_scrub(text)
        if scrub.get("applicable"):
            scrub_meta = {
                "mode": scrub.get("mode"),
                "factor": scrub.get("factor"),
                "counts": scrub.get("counts"),
                "column_kinds": scrub.get("column_kinds"),
                "scrubbed_preview": (scrub.get("scrubbed") or "")[:4000],
                "restore_on_reply": True,
                "note": (
                    "Numeric cells scaled to same magnitude; names/emails fictionalized; "
                    "keys format-preserved. Paste the table into Tab 3 Check & send to "
                    "analyze with restore-to-original on the answer."
                ),
            }
    append_audit(
        {
            "event": "document_uploaded",
            "doc": doc["id"],
            "sent_to_llm": False,
            "table_synthetic": bool(scrub_meta),
            "extract_kind": extracted.get("kind"),
        }
    )
    return {
        "ok": True,
        "document": doc,
        "table_scrub": scrub_meta,
        "extract": {
            "ok": extracted.get("ok"),
            "kind": extracted.get("kind"),
            "chars": extracted.get("chars"),
            "warnings": extracted.get("warnings") or [],
        },
    }


@app.get("/api/protection")
def api_protection():
    return protection_status()


@app.get("/api/audit")
def api_audit(limit: int = 40):
    """Newest local audit events — pilot evidence for InfoSec / board walkthroughs."""
    rows = read_audit_tail(limit)
    return {
        "ok": True,
        "count": len(rows),
        "events": rows,
        "path": "reviews/protection_audit.jsonl",
        "sent_to_llm": False,
    }


@app.post("/api/audit/reset")
def api_audit_reset():
    """Clear the evidence locker for a clean pilot demo. Vault/queue unchanged."""
    result = clear_audit()
    return {
        **result,
        "path": "reviews/protection_audit.jsonl",
        "sent_to_llm": False,
        "note": "Evidence locker cleared. Knowledge vault and human queue were not touched.",
    }


@app.post("/api/pilot/dry-run")
def api_pilot_dry_run(data: dict):
    """Classify outbound + knowledge outcome without calling any AI.

    Safe for live demos: nothing leaves the device; no Ollama/Groq call.
    """
    text = normalize_question((data.get("prompt") or data.get("question") or "").strip())
    if not text:
        return {"ok": False, "error": "prompt is required"}

    analysis = detector.analyze_prompt(text)
    decision = classify_route(analysis, text)
    rewrite = None
    if decision.get("risk_level") == "moderate":
        rewrite = suggest_rewrite(text, analysis)

    local_policy = answer_from_local_policy(text)
    knowledge = {
        "would_answer": bool(local_policy),
        "logic_path": "local_near_match" if local_policy else "no_local_context",
        "best_score": (local_policy or {}).get("best_score"),
        "answer_preview": ((local_policy or {}).get("answer") or "")[:360] or None,
        "sources": [
            {"doc_name": s.get("doc_name"), "score": s.get("score")}
            for s in ((local_policy or {}).get("sources") or [])[:4]
        ],
        "note": (
            "Keyword overlap → suggested local answer (confirm in Tab 2)"
            if local_policy
            else "No keyword match → Human vault only (Tab 4)"
        ),
    }

    hide_items = [
        f
        for f in (analysis.get("flagged_items") or [])
        if (f.get("action") or "hide") == "hide"
    ]
    evidence = build_evidence_brief(
        analysis,
        decision,
        prompt=text,
        knowledge=knowledge,
        event="pilot_dry_run",
    )
    append_audit(
        {
            "event": "pilot_dry_run",
            "sent_to_llm": False,
            **evidence,
            "knowledge_path": knowledge["logic_path"],
        }
    )
    return {
        "ok": True,
        "sent_to_any_ai": False,
        "prompt": text,
        "egress": {
            "risk_level": decision.get("risk_level"),
            "lane_badge": decision.get("lane_badge"),
            "destination": decision.get("destination"),
            "destination_label": {
                "external": "External AI",
                "private": "Private Ollama only",
            }.get(decision.get("destination") or "", decision.get("destination")),
            "sanitize": decision.get("sanitize"),
            "reasons": decision.get("reasons") or [],
            "dynamic_high_signals": decision.get("dynamic_high_signals") or [],
            "risk_score": analysis.get("risk_score"),
            "redacted_preview": analysis.get("redacted_text"),
            "hide_count": len(hide_items),
            "hide_preview": [
                {
                    "department": f.get("department") or f.get("type"),
                    "value": (f.get("value") or "")[:80],
                    "rewrite_as": ExhaustDetector.sanitize_rewrite_hint(
                        f.get("generalization_hint") or f.get("token"),
                        f.get("value") or "",
                    )
                    or f.get("token"),
                }
                for f in hide_items[:8]
            ],
            "rewrite_suggestion": (rewrite or {}).get("rewrite_suggestion") if rewrite else None,
        },
        "knowledge": knowledge,
        "evidence": evidence,
        "board_line": (
            f"Dry-run only — zero AI calls. Outbound would be "
            f"{(decision.get('risk_level') or '?').upper()}; "
            f"knowledge would be {knowledge['logic_path']}. "
            f"Why: {evidence.get('why_path') or '—'}"
        ),
    }


@app.get("/api/reviews")
def api_reviews(status: str | None = None):
    return {"queue": list_queue(status)}


@app.delete("/api/reviews/{review_id}")
async def api_delete_review(review_id: str):
    """Drop a question from the human vault queue without saving an answer."""
    try:
        deleted = delete_review(review_id)
    except FileNotFoundError:
        return {"ok": False, "error": f"Review ID not found: {review_id}"}
    except Exception as exc:
        return {"ok": False, "error": f"Delete failed: {exc}"}

    # Keep session "waiting on human" counter in sync when a pending gap is removed
    prior = deleted.get("prior_status")
    if prior in {"awaiting_human_answer", "pending_review"}:
        session_stats["unanswered_to_human"] = max(
            0, int(session_stats.get("unanswered_to_human") or 0) - 1
        )

    snap = _session_snapshot()
    protection = protection_status()
    await broadcast_event(
        {
            "type": "human_review_deleted",
            "review_id": review_id,
            "protection": protection,
            "session": snap,
            "message": "Queued question removed from human vault.",
        }
    )
    return {"ok": True, "deleted": deleted, "protection": protection, "session": snap}


@app.post("/api/reviews/{review_id}/correct")
async def api_correct(review_id: str, data: dict):
    corrected = data.get("corrected_answer", "").strip()
    reviewer = data.get("reviewer", "human_reviewer")
    if not corrected:
        return {"ok": False, "error": "corrected_answer is required"}
    try:
        record = submit_correction(review_id, corrected, reviewer=reviewer)
    except FileNotFoundError:
        return {"ok": False, "error": f"Review ID not found: {review_id}"}
    except Exception as exc:
        return {"ok": False, "error": f"Save failed: {exc}"}
    session_stats["human_corrections"] += 1
    session_stats["vault_gaps_closed"] += 1
    snap = _session_snapshot()
    await broadcast_event(
        {
            "type": "human_correction",
            "correction": record,
            "protection": protection_status(),
            "session": snap,
            **_lane_payload(
                "human_gap",
                plain_rag_would_send="(N/A — gap closed by human; plain RAG would have guessed or leaked)",
                exhaustshield_sent="NOTHING — correction stored only in local Human Review Vault",
                wow="Gap closed locally. This correction will never train the open-source model.",
            ),
            "message": "Human answer stored locally — never sent to LLM training.",
        }
    )
    return {"ok": True, "correction": record, "protection": protection_status(), "session": snap}


def _safe_sources(sources) -> list:
    out = []
    for s in sources or []:
        if isinstance(s, dict):
            out.append(
                {
                    "doc_name": str(s.get("doc_name") or s.get("name") or ""),
                    "score": s.get("score"),
                    "preview": str(s.get("preview") or "")[:500],
                }
            )
        else:
            out.append({"doc_name": str(s), "score": None, "preview": ""})
    return out


@app.post("/api/knowledge/send-to-review")
async def api_send_to_review(data: dict):
    """Wrong local answer → queue for Human Review Vault (answer typed in Tab 4)."""
    question = normalize_question(data.get("question") or "")
    rejected = (data.get("rejected_answer") or "").strip() or "(no prior answer text captured)"
    logic_path = data.get("logic_path") or "local_near_match"
    sources = _safe_sources(data.get("sources") or [])

    if not question:
        return {"ok": False, "error": "question is required"}

    try:
        review = create_dispute_ticket(
            question,
            rejected,
            sources=sources,
            logic_path=logic_path,
        )
    except Exception as exc:
        return {"ok": False, "error": f"Could not queue for review: {exc}"}

    session_stats["unanswered_to_human"] += 1
    session_stats["llm_calls_avoided"] += 1
    snap = _session_snapshot()
    payload = {
        "type": "knowledge_needs_human",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "question": question,
        "rejected_answer": rejected,
        "answer": (
            "Local answer was marked incorrect. Queued for human review — "
            "provide the approved answer in the Human Review Vault."
        ),
        "restored_response": (
            "Local answer was marked incorrect. Queued for human review — "
            "provide the approved answer in the Human Review Vault."
        ),
        "answer_source": "human_review_queue",
        "needs_human_review": True,
        "sent_to_llm": False,
        "review": review,
        "sources": sources,
        "logic_path": "disputed_to_human",
        "protection": protection_status(),
        "explanation": (
            "You marked the local answer incorrect. Question is now in the Human Review Vault. "
            "No LLM was called."
        ),
        **_lane_payload(
            "human_gap",
            plain_rag_would_send=(
                f"QUESTION: {question}\n\n"
                f"(Plain RAG would keep a wrong near-match or send cleartext to an LLM.)\n"
                f"REJECTED LOCAL ANSWER:\n{rejected}"
            ),
            exhaustshield_sent="NOTHING TO LLM — disputed question queued in local Human Review Vault",
            wow="Wrong local answer rejected. Human writes the company-true answer in the vault.",
        ),
        "session": snap,
        **_knowledge_stamp(),
    }
    await broadcast_event(payload)
    return {"ok": True, **payload}


@app.post("/api/knowledge/dispute-correct")
async def api_dispute_correct(data: dict):
    """Wrong near-match / vault answer → human types the right one → saved to vault only."""
    question = normalize_question(data.get("question") or "")
    rejected = (data.get("rejected_answer") or "").strip()
    corrected = (data.get("corrected_answer") or "").strip()
    reviewer = (data.get("reviewer") or "policy_owner").strip() or "policy_owner"
    logic_path = data.get("logic_path") or "local_near_match"
    sources = _safe_sources(data.get("sources") or [])

    if not question:
        return {"ok": False, "error": "question is required"}
    if not corrected:
        return {"ok": False, "error": "corrected_answer is required"}
    if not rejected:
        rejected = "(no prior answer text captured)"

    try:
        result = dispute_and_correct(
            question,
            rejected,
            corrected,
            reviewer=reviewer,
            sources=sources,
            logic_path=logic_path,
        )
    except Exception as exc:
        return {"ok": False, "error": f"Save failed: {exc}"}

    session_stats["human_corrections"] += 1
    session_stats["vault_gaps_closed"] += 1
    session_stats["unanswered_to_human"] += 1
    session_stats["llm_calls_avoided"] += 1
    snap = _session_snapshot()
    payload = {
        "type": "knowledge_human_override",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "question": question,
        "rejected_answer": rejected,
        "answer": corrected,
        "restored_response": corrected,
        "answer_source": "human_review_vault",
        "needs_human_review": False,
        "sent_to_llm": False,
        "review": result["review"],
        "correction": result["correction"],
        "logic_path": "human_override",
        "protection": protection_status(),
        "explanation": (
            "Local answer was marked incorrect. Approved human answer saved to the vault only — "
            "never sent to any LLM for training. Future asks can reuse this vault answer."
        ),
        **_lane_payload(
            "human_gap",
            plain_rag_would_send=(
                f"QUESTION: {question}\n\n"
                f"(Plain RAG would keep a wrong near-match or re-send cleartext to an LLM.)\n"
                f"REJECTED LOCAL ANSWER:\n{rejected}"
            ),
            exhaustshield_sent="NOTHING TO LLM — human override stored in local vault only",
            wow="Wrong near-match fixed by a human. Correction stays off-model forever.",
        ),
        "session": snap,
        **_knowledge_stamp(),
    }
    await broadcast_event(payload)
    return {"ok": True, **payload}


@app.post("/api/generate")
async def generate(data: dict):
    """Exhaust Guardian: SAFE→external, MODERATE→suggest rewrite & wait, HIGH→private only."""
    raw_prompt = data.get("prompt", "")
    # Optional pre-extracted attachments (PDF/Word/Excel/…) — scrubbed before egress
    attachments = data.get("attachments") or []
    if attachments:
        raw_prompt = build_prompt_with_attachments(raw_prompt, attachments)
    private_model = data.get("model", "llama3.2")
    external_model = data.get("external_model")
    chat_history = _normalize_chat_history(
        data.get("history") or data.get("messages") or []
    )

    analysis = detector.analyze_prompt(raw_prompt)
    decision = classify_route(analysis, raw_prompt)
    redacted_prompt = analysis["redacted_text"]
    token_map = analysis["token_map"]

    # MODERATE: only open approval UI when placeholders and/or rewrite actually change
    rewrite_info = None
    if decision["risk_level"] == "moderate":
        rewrite_info = suggest_rewrite(raw_prompt, analysis)
        # Analysis-scale scrub updates redacted_text + token_map in place
        redacted_prompt = analysis.get("redacted_text") or redacted_prompt
        token_map = analysis.get("token_map") or token_map
        if not (
            rewrite_info.get("placeholders_differ")
            or rewrite_info.get("differs_from_original")
        ):
            # Strict Safe: cannot scrub → fail closed to HIGH (never Silent Safe)
            decision = {
                **decision,
                "risk_level": "high",
                "destination": "private",
                "sanitize": False,
                "lane": "private_high",
                "lane_badge": "HIGH · PRIVATE AI ONLY",
                "reasons": list(decision.get("reasons") or [])
                + [
                    "Medium sanitize would not change outbound text — "
                    "fail-closed to private (strict Safe)"
                ],
            }
            rewrite_info = None

    # MODERATE: analyze + rewrite suggestion only — do NOT call external AI yet
    if decision["risk_level"] == "moderate":
        assert rewrite_info is not None
        pending_id = uuid.uuid4().hex
        pending_moderate[pending_id] = {
            "kind": "moderate",
            "raw_prompt": raw_prompt,
            "analysis": analysis,
            "decision": decision,
            "redacted_prompt": redacted_prompt,
            "rewrite_suggestion": rewrite_info["rewrite_suggestion"],
            "private_model": private_model,
            "external_model": external_model,
            "history": chat_history,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        _track_analysis(analysis, "guardian_moderate_pending", kind="leak")
        session_stats["routes_moderate"] += 1
        append_audit(
            {
                "event": "exhaust_guardian_moderate_pending",
                "pending_id": pending_id,
                "awaiting_confirm": True,
                "sanitize": True,
                "secrets_blocked": analysis["prevention"]["secrets_blocked"],
                **build_evidence_brief(
                    analysis,
                    decision,
                    prompt=raw_prompt,
                    event="exhaust_guardian_moderate_pending",
                    stage="Awaiting your hide/rewrite confirm.",
                ),
            }
        )

        top_cat = (
            max(analysis["by_department"], key=analysis["by_department"].get)
            if analysis["by_department"]
            else "none"
        )
        event_payload = {
            "type": "prompt_shield",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model": external_model or "external",
            "original_prompt": raw_prompt,
            "redacted_prompt": redacted_prompt,
            "rewrite_suggestion": rewrite_info["rewrite_suggestion"],
            "pending_id": pending_id,
            "awaiting_confirm": True,
            "confirm_kind": "moderate",
            "prompt_sent_to_model": None,
            "llm_raw_response": "(not sent yet — approve an outbound version below)",
            "restored_response": "",
            "risk_score": analysis["risk_score"],
            "sensitivity_kind": "leak",
            "flagged_count": len(analysis["flagged_items"]),
            "flagged_items": analysis["flagged_items"],
            "by_department": analysis.get("by_department", {}),
            "department_risk": analysis.get("department_risk", {}),
            "placeholders": analysis.get("placeholders", []),
            "placeholder_policy": analysis.get("placeholder_policy")
            or ExhaustDetector.placeholder_policy(),
            "prevention": {
                **analysis.get("prevention", {}),
                "summary": (
                    f"Moderate lane: {len(analysis['flagged_items'])} sensitive span(s) found. "
                    "Nothing sent externally yet — pick the literal placeholders or the "
                    "suggested rewrite, then confirm."
                ),
            },
            "top_blocked_category": top_cat,
            "guardian": {
                **decision,
                "destination_label": "External AI (awaiting confirm)",
                "call_meta": {"ok": False, "awaiting_confirm": True},
                "token_map_size": len(token_map),
                "awaiting_confirm": True,
                "pending_id": pending_id,
                "confirm_kind": "moderate",
            },
            "logic_path": "guardian_moderate_pending",
            "token_bridge": {
                "title": "Exhaust Guardian — pre-flight rewrite",
                "points": [
                    "Risk level: MODERATE → MEDIUM · HIDE THEN OUTSIDE",
                    "Outbound paused for your approval.",
                    "Literal path keeps <DEPT_N> placeholders; suggested rewrite keeps meaning without specifics.",
                    "External AI is called only after you confirm (last-mile re-scan enforced).",
                ],
            },
            **_lane_payload(
                decision["lane"],
                plain_rag_would_send=(
                    f"(Uncontrolled chat would send cleartext to whatever model is handy)\n{raw_prompt}"
                ),
                exhaustshield_sent="NOT SENT YET — waiting for rewrite / placeholder approval",
                wow=(
                    "Moderate lane: review the placeholder version or the generalized rewrite "
                    "before anything leaves for external AI."
                ),
            ),
            # Pending approval: nothing has left the device yet (do not count toward session split)
            **_data_boundary_fields(
                "stayed_local",
                explanation=(
                    "This request is paused for your approval. No AI call has been made yet — "
                    "nothing has left this device."
                ),
                count=False,
            ),
            "session": _session_snapshot(),
            "protection": protection_status(),
        }
        await broadcast_event(event_payload)
        return {
            "model": event_payload["model"],
            "response": "",
            "redacted_sent": redacted_prompt,
            "rewrite_suggestion": rewrite_info["rewrite_suggestion"],
            "pending_id": pending_id,
            "awaiting_confirm": True,
            "confirm_kind": "moderate",
            "prompt_sent": None,
            "data_boundary": event_payload["data_boundary"],
            "data_boundary_explanation": event_payload["data_boundary_explanation"],
            "guardian": event_payload["guardian"],
            "risk_analysis": analysis,
            "event": event_payload,
        }

    # SAFE + HIGH: send immediately (Safe → external as-is; High → private).
    # Medium still pauses above for hide/rewrite approval.
    routed = route_inference(
        raw_prompt=raw_prompt,
        analysis=analysis,
        private_model=private_model,
        external_model=external_model,
        history=chat_history,
    )
    decision = routed["decision"]
    ai_raw_response = routed["llm_raw_response"]
    restored_response = routed["restored_response"]

    _track_analysis(analysis, f"guardian_{decision['risk_level']}", kind="leak")
    session_stats["llm_calls_made"] += 1
    level_key = f"routes_{decision['risk_level']}"
    if level_key in session_stats:
        session_stats[level_key] += 1
    if decision["destination"] == "private":
        session_stats["private_calls"] += 1
    else:
        session_stats["external_calls"] += 1

    append_audit(
        {
            "event": "exhaust_guardian_route",
            "sanitize": decision["sanitize"],
            "lane": decision["lane"],
            "call_meta": routed["call_meta"],
            "secrets_blocked": analysis["prevention"]["secrets_blocked"],
            **build_evidence_brief(
                analysis,
                decision,
                prompt=raw_prompt,
                event="exhaust_guardian_route",
                stage="Routed.",
            ),
        }
    )

    top_cat = (
        max(analysis["by_department"], key=analysis["by_department"].get)
        if analysis["by_department"]
        else "none"
    )

    wow_by_level = {
        "safe": "Safe lane: prompt went to external AI as-is — no sensitive exhaust detected.",
        "moderate": "Moderate lane: secrets tokenized, sanitized prompt sent externally, values restored only on-gateway.",
        "high": "High lane: private LLM only (scrubbed when hide spans exist). Fail-closed — nothing left to an external platform.",
    }
    exhaust_sent_desc = (
        f"[{routed['destination_label']}]\n{routed['prompt_sent']}"
        if routed["prompt_sent"]
        else "(empty)"
    )

    boundary = _boundary_from_guardian_route(
        decision,
        routed.get("call_meta"),
        response_text=ai_raw_response,
    )

    event_payload = {
        "type": "prompt_shield",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": private_model if decision["destination"] == "private" else (
            routed["call_meta"].get("model") or external_model or "external"
        ),
        "original_prompt": raw_prompt,
        "redacted_prompt": redacted_prompt,
        "rewrite_suggestion": None,
        "awaiting_confirm": False,
        "prompt_sent_to_model": routed["prompt_sent"],
        "llm_raw_response": ai_raw_response,
        "restored_response": restored_response,
        "risk_score": analysis["risk_score"],
        "sensitivity_kind": "leak",
        "flagged_count": len(analysis["flagged_items"]),
        "flagged_items": analysis["flagged_items"],
        "by_department": analysis.get("by_department", {}),
        "department_risk": analysis.get("department_risk", {}),
        "placeholders": analysis.get("placeholders", []),
        "placeholder_policy": analysis.get("placeholder_policy")
        or ExhaustDetector.placeholder_policy(),
        "prevention": analysis.get("prevention", {}),
        "top_blocked_category": top_cat,
        "guardian": {
            **decision,
            "destination_label": routed["destination_label"],
            "call_meta": routed["call_meta"],
            "token_map_size": len(token_map),
            "awaiting_confirm": False,
        },
        "logic_path": f"guardian_{decision['risk_level']}",
        "token_bridge": {
            "title": "Exhaust Guardian — 3-level routing",
            "points": [
                f"Risk level: {decision['risk_level'].upper()} → {decision['lane_badge']}",
                f"Destination: {routed['destination_label']}",
                *decision["reasons"],
                "SAFE: external as-is · MODERATE: sanitize then external · HIGH: private LLM only (fail-closed).",
                "The open/external model never chooses the lane — the gateway decides before egress.",
            ],
        },
        **_lane_payload(
            decision["lane"],
            plain_rag_would_send=(
                f"(Uncontrolled chat would send cleartext to whatever model is handy)\n{raw_prompt}"
            ),
            exhaustshield_sent=exhaust_sent_desc,
            wow=wow_by_level[decision["risk_level"]],
        ),
        **boundary,
        "session": _session_snapshot(),
        "protection": protection_status(),
    }
    await broadcast_event(event_payload)
    return {
        "model": event_payload["model"],
        "response": restored_response,
        "redacted_sent": redacted_prompt,
        "rewrite_suggestion": None,
        "awaiting_confirm": False,
        "prompt_sent": routed["prompt_sent"],
        "data_boundary": event_payload["data_boundary"],
        "data_boundary_explanation": event_payload["data_boundary_explanation"],
        "guardian": event_payload["guardian"],
        "risk_analysis": analysis,
        "event": event_payload,
    }


@app.post("/api/generate/confirm")
async def generate_confirm(data: dict):
    """Complete pending SAFE or MODERATE egress after user confirm (last-mile re-scan)."""
    pending_id = (data.get("pending_id") or "").strip()
    chosen = data.get("chosen")
    if chosen is None:
        chosen = data.get("version")  # alias
    if not pending_id or pending_id not in pending_moderate:
        return {"ok": False, "error": "Unknown or expired pending_id. Re-run Check & send."}

    pending = pending_moderate.pop(pending_id)
    kind = (pending.get("kind") or "moderate").lower()
    analysis = pending["analysis"]
    decision = pending["decision"]
    redacted_prompt = pending["redacted_prompt"]
    rewrite_suggestion = pending.get("rewrite_suggestion")
    token_map = analysis.get("token_map") or {}
    private_model = pending.get("private_model") or "llama3.2"
    external_model = pending.get("external_model")
    raw_prompt = pending["raw_prompt"]

    chosen_str = "" if chosen is None else str(chosen)
    choice_key = chosen_str.strip().lower()

    if choice_key in {"cancel", "abort", "no"}:
        cancel_level = (decision.get("risk_level") if decision else kind) or kind
        lane_path = {
            "safe": "Safe → outside AI",
            "moderate": "Medium → hide secrets first",
            "high": "High → private AI only",
        }.get(str(cancel_level).lower(), str(cancel_level))
        append_audit(
            {
                "event": "exhaust_guardian_confirm_cancelled",
                "pending_id": pending_id,
                "confirm_kind": kind,
                "sent_to_llm": False,
                "tab": "Tab 3",
                "title": "Outbound cancelled",
                "path": lane_path,
                "brief": "User cancelled — nothing sent to any AI.",
                "why_path": "Outbound cancelled before any AI call",
                "prompt_preview": (raw_prompt or "")[:200] or None,
                "risk_level": cancel_level,
            }
        )
        return {
            "ok": True,
            "cancelled": True,
            "awaiting_confirm": False,
            "message": "Outbound cancelled — nothing sent to any AI.",
        }

    if kind == "safe":
        sent = raw_prompt
        choice_label = "as_is"
        use_restore = False
        expect_sanitized = False
        allow_levels = {"safe"}
    else:
        if choice_key == "redacted":
            sent = redacted_prompt
            choice_label = "redacted"
        elif choice_key == "rewrite":
            sent = rewrite_suggestion or ""
            choice_label = "rewrite"
        else:
            # UI posts the edited rewrite textarea as `chosen` (full text).
            sent = chosen_str
            choice_label = "rewrite_edited"
        # Always restore after Medium egress (tokens + analysis-scale reverse divide)
        use_restore = True
        expect_sanitized = True
        allow_levels = {"safe", "moderate"}
        ok_out, err_out = _assert_sanitized_moderate_outbound(sent, raw_prompt, analysis)
        if not ok_out:
            # Restore pending so the user can fix outbound without re-running Check & send
            pending_moderate[pending_id] = pending
            return {"ok": False, "error": err_out}

    mile = last_mile_classify(sent, detector)
    mile_decision = mile["decision"]
    mile_level = mile_decision.get("risk_level") or "high"

    if mile_level == "high" or mile_level not in allow_levels:
        append_audit(
            {
                "event": "exhaust_guardian_last_mile_blocked",
                "pending_id": pending_id,
                "confirm_kind": kind,
                "choice": choice_label,
                "rescued_level": mile_level,
                "sent_to_llm": False,
                **build_evidence_brief(
                    mile["analysis"],
                    mile_decision,
                    prompt=sent or raw_prompt,
                    event="exhaust_guardian_last_mile_blocked",
                    stage="Last-mile re-scan blocked external.",
                ),
            }
        )
        if mile_level == "high":
            restored_private, call_meta, private_sent, high_rw = answer_high_private(
                private_model, raw_prompt, mile.get("analysis") or analysis
            )
            if high_rw.get("rewrite_suggestion") and not rewrite_suggestion:
                rewrite_suggestion = high_rw.get("rewrite_suggestion")
            session_stats["llm_calls_made"] += 1
            session_stats["private_calls"] += 1
            session_stats["routes_high"] += 1
            destination_label = "Private LLM (Ollama) — last-mile blocked external"
            event_payload = {
                "type": "prompt_shield",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model": private_model,
                "original_prompt": raw_prompt,
                "redacted_prompt": redacted_prompt,
                "rewrite_suggestion": rewrite_suggestion,
                "pending_id": pending_id,
                "awaiting_confirm": False,
                "confirm_choice": choice_label,
                "confirm_kind": kind,
                "last_mile_blocked": True,
                "prompt_sent_to_model": private_sent,
                "llm_raw_response": restored_private,
                "restored_response": restored_private,
                "risk_score": mile["analysis"].get("risk_score", analysis["risk_score"]),
                "sensitivity_kind": "leak",
                "flagged_count": len(mile["analysis"].get("flagged_items") or []),
                "flagged_items": mile["analysis"].get("flagged_items") or [],
                "by_department": mile["analysis"].get("by_department", {}),
                "department_risk": mile["analysis"].get("department_risk", {}),
                "placeholders": mile["analysis"].get("placeholders", []),
                "placeholder_policy": mile["analysis"].get("placeholder_policy")
                or ExhaustDetector.placeholder_policy(),
                "prevention": {
                    **(mile["analysis"].get("prevention") or {}),
                    "summary": (
                        f"Last-mile re-scan reclassified outbound as {mile_level.upper()} — "
                        "external blocked; routed to private AI only."
                    ),
                },
                "top_blocked_category": "security",
                "guardian": {
                    **mile_decision,
                    "destination_label": destination_label,
                    "call_meta": call_meta,
                    "last_mile_blocked": True,
                    "prior_kind": kind,
                    "confirm_choice": choice_label,
                },
                "logic_path": "guardian_last_mile_private",
                "token_bridge": {
                    "title": "Strict Safe — last-mile curtain",
                    "points": [
                        f"Confirm kind was {kind}; outbound re-scan → {mile_level.upper()}",
                        "External AI was not called.",
                        *list(mile_decision.get("reasons") or [])[:3],
                    ],
                },
                **_lane_payload(
                    mile_decision["lane"],
                    plain_rag_would_send=f"(Would have sent)\n{sent}",
                    exhaustshield_sent=f"[{destination_label}]\n(private — external blocked)",
                    wow="Last-mile re-scan blocked external egress and kept the call private.",
                ),
                **_data_boundary_fields(
                    "stayed_local",
                    explanation="Last-mile blocked external AI; private model only (or fail-closed).",
                ),
                "session": _session_snapshot(),
                "protection": protection_status(),
            }
            await broadcast_event(event_payload)
            return {
                "ok": True,
                "last_mile_blocked": True,
                "model": private_model,
                "response": restored_private,
                "awaiting_confirm": False,
                "confirm_choice": choice_label,
                "confirm_kind": kind,
                "prompt_sent": private_sent,
                "guardian": event_payload["guardian"],
                "risk_analysis": mile["analysis"],
                "event": event_payload,
            }

        return {
            "ok": False,
            "error": (
                f"Last-mile re-scan blocked external send "
                f"(reclassified as {mile_level}). Re-run Check & send."
            ),
            "rescued_decision": mile_decision,
        }

    ai_raw, call_meta = call_external_ai(
        external_model,
        sent,
        sanitized=expect_sanitized or mile_level == "moderate",
        history=_normalize_chat_history(pending.get("history") or []),
    )
    restored = ai_raw
    if use_restore:
        scrub = analysis.get("analysis_scrub") or {}
        # Always merge analysis restore_map (scaled $ → original, Org_1 → name, …)
        restore_map = dict(token_map or {})
        restore_map.update(scrub.get("restore_map") or {})
        restored = detector.restore_text(
            ai_raw, restore_map, analysis_scrub=scrub or None
        )

    session_stats["llm_calls_made"] += 1
    session_stats["external_calls"] += 1

    if kind == "safe":
        destination_label = "External AI (Safe · confirmed as-is)"
        audit_event = "exhaust_guardian_safe_confirmed"
        logic_path = "guardian_safe"
        wow = "Strict Safe confirmed: last-mile re-scan stayed Safe; sent as-is to external AI."
    else:
        destination_label = (
            "External AI (sanitized · rewrite)"
            if choice_label == "rewrite"
            else "External AI (sanitized · placeholders)"
            if choice_label == "redacted"
            else "External AI (sanitized · user-edited)"
        )
        audit_event = "exhaust_guardian_moderate_confirmed"
        logic_path = "guardian_moderate"
        wow = (
            "Moderate lane: you approved the outbound text. Last-mile re-scan passed; "
            "external AI only saw the approved version."
        )

    append_audit(
        {
            "event": audit_event,
            "pending_id": pending_id,
            "choice": choice_label,
            "confirm_kind": kind,
            "sanitize": expect_sanitized,
            "last_mile_ok": True,
            "call_meta": call_meta,
            "secrets_blocked": analysis["prevention"]["secrets_blocked"],
            **build_evidence_brief(
                mile["analysis"],
                mile_decision,
                prompt=raw_prompt,
                event=audit_event,
                stage="Confirmed and sent." if kind == "safe" else "Confirmed sanitized send.",
            ),
        }
    )

    top_cat = (
        max(analysis["by_department"], key=analysis["by_department"].get)
        if analysis["by_department"]
        else "none"
    )
    exhaust_sent_desc = f"[{destination_label}]\n{sent}"

    event_payload = {
        "type": "prompt_shield",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": call_meta.get("model") or external_model or "external",
        "original_prompt": raw_prompt,
        "redacted_prompt": redacted_prompt,
        "rewrite_suggestion": rewrite_suggestion,
        "pending_id": pending_id,
        "awaiting_confirm": False,
        "confirm_choice": choice_label,
        "confirm_kind": kind,
        "last_mile_ok": True,
        "prompt_sent_to_model": sent,
        "llm_raw_response": ai_raw,
        "restored_response": restored,
        "risk_score": analysis["risk_score"],
        "sensitivity_kind": "leak",
        "flagged_count": len(analysis["flagged_items"]),
        "flagged_items": analysis["flagged_items"],
        "by_department": analysis.get("by_department", {}),
        "department_risk": analysis.get("department_risk", {}),
        "placeholders": analysis.get("placeholders", []),
        "placeholder_policy": analysis.get("placeholder_policy")
        or ExhaustDetector.placeholder_policy(),
        "prevention": analysis.get("prevention", {}),
        "top_blocked_category": top_cat,
        "guardian": {
            **decision,
            "destination_label": destination_label,
            "call_meta": call_meta,
            "token_map_size": len(token_map),
            "awaiting_confirm": False,
            "confirm_choice": choice_label,
            "confirm_kind": kind,
            "last_mile_level": mile_level,
        },
        "logic_path": logic_path,
        "token_bridge": {
            "title": f"Exhaust Guardian — {kind} confirmed",
            "points": [
                f"User approved outbound version: {choice_label}",
                f"Destination: {destination_label}",
                "Last-mile re-scan passed before external call.",
            ],
        },
        **_lane_payload(
            decision["lane"],
            plain_rag_would_send=(
                f"(Uncontrolled chat would send cleartext to whatever model is handy)\n{raw_prompt}"
            ),
            exhaustshield_sent=exhaust_sent_desc,
            wow=wow,
        ),
        **_data_boundary_fields("left_device"),
        "session": _session_snapshot(),
        "protection": protection_status(),
    }
    await broadcast_event(event_payload)
    return {
        "ok": True,
        "model": event_payload["model"],
        "response": restored,
        "redacted_sent": redacted_prompt,
        "rewrite_suggestion": rewrite_suggestion,
        "awaiting_confirm": False,
        "confirm_choice": choice_label,
        "confirm_kind": kind,
        "prompt_sent": sent,
        "data_boundary": event_payload["data_boundary"],
        "data_boundary_explanation": event_payload["data_boundary_explanation"],
        "guardian": event_payload["guardian"],
        "risk_analysis": analysis,
        "event": event_payload,
    }



def _knowledge_stamp(**extra) -> dict:
    """Fingerprint so a stale server can't pretend to be local-first."""
    return {
        "knowledge_engine_version": KNOWLEDGE_ENGINE_VERSION,
        "ask_knowledge_may_call_llm": False,
        "sent_to_llm": False,
        **extra,
    }


@app.post("/api/ask-knowledge")
async def ask_knowledge(data: dict):
    """Near-match policy Q&A: vault → local extractive (forced) → human gap only.

    Hard rule: this endpoint NEVER calls Ollama. If policy hits exist, answer
    locally. If not, human vault only. No silent LLM fallback.
    """
    question = normalize_question(data.get("question") or "")
    prefer_local = data.get("prefer_local_corrections", True)
    chat_history = _normalize_chat_history(
        data.get("history") or data.get("messages") or []
    )

    if not question:
        return {"ok": False, "error": "question is required"}

    # Follow-ups like "what about the other one?" need prior turns for local match.
    search_question = question
    if chat_history:
        prior_bits = []
        for turn in chat_history[-6:]:
            label = "User" if turn["role"] == "user" else "Assistant"
            prior_bits.append(f"{label}: {turn['content'][:500]}")
        search_question = (
            "Prior conversation:\n"
            + "\n".join(prior_bits)
            + f"\n\nCurrent question: {question}"
        )

    session_stats["knowledge_queries"] += 1

    async def _emit_local(local_policy: dict, answer_source: str = "local_near_match") -> dict:
        session_stats["local_answers_served"] += 1
        session_stats["llm_calls_avoided"] += 1
        # Scan the local answer so we can list sensitive words found in the doc excerpt…
        analysis = detector.analyze_prompt(local_policy["answer"])
        content_sensitivity = analysis["risk_score"]
        # …but Latest risk % = egress/leak risk. Local path never left the gateway → 0%.
        analysis = {
            **analysis,
            "risk_score": 0,
            "content_sensitivity_score": content_sensitivity,
            "egress_risk_score": 0,
            "prevention": {
                **analysis.get("prevention", {}),
                "summary": (
                    f"Answered locally (no LLM). Doc excerpt still contains "
                    f"{len(analysis.get('flagged_items') or [])} sensitive term(s) "
                    f"(content sensitivity {content_sensitivity}%), but egress risk is 0% — "
                    f"nothing was sent to an outside or private model."
                ),
            },
        }
        _track_analysis(analysis, "local_policy_answer", kind="doc")
        append_audit(
            {
                "event": "local_near_match_answer",
                "best_score": local_policy["best_score"],
                "chunks_used": len(local_policy["hits"]),
                "sent_to_llm": False,
                "egress_risk_score": 0,
                "content_sensitivity_score": content_sensitivity,
                "answer_source": answer_source,
                "knowledge_engine_version": KNOWLEDGE_ENGINE_VERSION,
                "tab": "Tab 2",
                "title": "Local near-match answer",
                "path": "Local → no LLM",
                "brief": (
                    f"Keyword overlap score {local_policy['best_score']} — "
                    "answered from local policy; nothing sent to any AI."
                ),
                "why_path": (
                    f"Keyword overlap score {local_policy['best_score']} — "
                    "answered from local policy excerpts; nothing sent to any AI"
                ),
                "knowledge_path": "local_near_match",
                "prompt_preview": (question or "")[:200] or None,
            }
        )
        plain_context = "\n\n".join(
            f"[{s['doc_name']} | score={s['score']}]\n{s.get('preview', '')}"
            for s in local_policy["sources"]
        )
        plain = f"QUESTION: {question}\n\nRETRIEVED CLEARTEXT POLICY:\n{plain_context}"
        payload = {
            "type": "knowledge_local_answer",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "question": question,
            "answer_source": answer_source,
            "answer": local_policy["answer"],
            "restored_response": local_policy["answer"],
            "sources": local_policy["sources"],
            "best_score": local_policy["best_score"],
            "needs_human_review": False,
            "risk_score": 0,
            "egress_risk_score": 0,
            "content_sensitivity_score": content_sensitivity,
            "sensitivity_kind": "doc",
            "flagged_count": len(analysis["flagged_items"]),
            "flagged_items": analysis["flagged_items"],
            "placeholders": analysis.get("placeholders", []),
            "placeholder_policy": analysis.get("placeholder_policy")
            or ExhaustDetector.placeholder_policy(),
            "department_risk": analysis.get("department_risk", {}),
            "by_department": analysis.get("by_department", {}),
            "prevention": analysis.get("prevention", {}),
            "knowledge_protection": local_policy["protection"],
            "protection": protection_status(),
            "explanation": (
                f"Keyword match in local policy (score {local_policy['best_score']}). "
                f"Suggested answer on-gateway with no LLM call — egress risk 0%. "
                f"Confirm if correct, or mark incorrect to send to the Human vault. "
                f"Excerpt content sensitivity {content_sensitivity}%."
            ),
            "logic_path": "local_near_match",
            **_lane_payload(
                "local",
                plain_rag_would_send=plain,
                exhaustshield_sent="NOTHING SENT TO LLM — answered locally from near-match policy excerpts",
                wow="Local near-match: confidential policy used in-place. Open model saw zero bytes.",
            ),
            **_data_boundary_fields("stayed_local"),
            "session": _session_snapshot(),
            **_knowledge_stamp(),
        }
        if payload.get("sent_to_llm"):
            raise RuntimeError("Invariant broken: local knowledge answer marked sent_to_llm")
        await broadcast_event(payload)
        return {"ok": True, **payload}

    # 1) Vault hit
    if prefer_local:
        local = find_local_answer(question)
        if local:
            session_stats["local_answers_served"] += 1
            session_stats["llm_calls_avoided"] += 1
            append_audit(
                {
                    "event": "served_local_human_answer",
                    "correction_id": local["id"],
                    "sent_to_llm": False,
                    "knowledge_engine_version": KNOWLEDGE_ENGINE_VERSION,
                    "tab": "Tab 2",
                    "title": "Human vault answer",
                    "path": "Local → human vault",
                    "brief": "Vault hit — reused approved human correction; no LLM call.",
                    "why_path": (
                        "Exact/near vault hit — reused approved human correction; "
                        "no LLM call"
                    ),
                    "knowledge_path": "vault_hit",
                    "prompt_preview": (question or "")[:200] or None,
                }
            )
            plain = (
                f"QUESTION: {question}\n\n"
                f"(Plain RAG would also re-send prior proprietary correction text to the LLM.)\n"
                f"PRIOR APPROVED ANSWER:\n{local['corrected_answer']}"
            )
            payload = {
                "type": "knowledge_local_answer",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "question": question,
                "answer_source": "human_review_vault",
                "answer": local["corrected_answer"],
                "restored_response": local["corrected_answer"],
                "needs_human_review": False,
                "protection": protection_status(),
                "explanation": "Approved human vault answer reused locally. LLM was not called.",
                "logic_path": "vault_hit",
                **_lane_payload(
                    "local",
                    plain_rag_would_send=plain,
                    exhaustshield_sent="NOTHING SENT TO LLM — served from local Human Review Vault",
                    wow="Vault hit: proprietary correction reused without ever touching the open model.",
                ),
                **_data_boundary_fields("stayed_local"),
                "session": _session_snapshot(),
                **_knowledge_stamp(),
            }
            await broadcast_event(payload)
            return {"ok": True, **payload}

    # 2) Local keyword / near-match suggestion (user can confirm correct/incorrect)
    local_policy = answer_from_local_policy(question)
    if local_policy:
        return await _emit_local(local_policy)

    # 3) Safety net: any retrieved chunk with keyword overlap
    hits = retrieve_context(question)
    keyword_hits = [h for h in hits if is_close_policy_match(question, h)]
    if keyword_hits:
        forced = build_local_answer_from_hits(question, keyword_hits)
        append_audit(
            {
                "event": "local_forced_from_hits",
                "best_score": forced["best_score"],
                "sent_to_llm": False,
                "knowledge_engine_version": KNOWLEDGE_ENGINE_VERSION,
                "note": "Keyword-overlap safety net — suggested local answer for user confirm.",
                "tab": "Tab 2",
                "title": "Local safety-net answer",
                "path": "Local → safety net",
                "brief": (
                    f"Keyword-overlap safety net (score {forced['best_score']}) — "
                    "suggest local answer; no LLM."
                ),
                "why_path": (
                    f"Keyword-overlap safety net (score {forced['best_score']}) — "
                    "suggest local answer for confirm; no LLM"
                ),
                "knowledge_path": "local_forced_safety_net",
                "prompt_preview": (question or "")[:200] or None,
            }
        )
        return await _emit_local(forced, answer_source="local_forced_safety_net")

    # 4) True gap — no keyword overlap with any policy chunk
    session_stats["unanswered_to_human"] += 1
    session_stats["llm_calls_avoided"] += 1
    review = create_unanswered_ticket(
        question,
        "No keyword match in local policy documents. "
        "Please provide the approved company answer.",
    )
    miss = missing_key_terms(question, "")
    append_audit(
        {
            "event": "routed_to_human_no_context",
            "review_id": review["id"],
            "sent_to_llm": False,
            "knowledge_engine_version": KNOWLEDGE_ENGINE_VERSION,
            "missing_key_terms": miss,
            "tab": "Tab 2",
            "title": "Queued for human vault",
            "path": "Human vault → no keyword match",
            "brief": (
                "No keyword overlap with local policy — queued for a human answer. "
                f"Missing terms: {', '.join(miss[:6]) or 'n/a'}."
            ),
            "why_path": (
                "No keyword overlap with local policy — queued for human vault "
                f"(missing terms: {', '.join(miss[:6]) or 'n/a'})"
            ),
            "knowledge_path": "human_no_context",
            "prompt_preview": (question or "")[:200] or None,
        }
    )
    payload = {
        "type": "knowledge_needs_human",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "question": question,
        "answer_source": "awaiting_human",
        "answer": (
            "No keyword match was found in local policy documents for this question. "
            "It was sent to the Human Review Vault."
        ),
        "needs_human_review": True,
        "review": review,
        "sources": [],
        "missing_key_terms": missing_key_terms(question, ""),
        "protection": protection_status(),
        "explanation": (
            "Human review is used only when the question shares no strong keywords "
            "with local policy — we do not invent an answer."
        ),
        "logic_path": "no_local_context",
        **_lane_payload(
            "human_gap",
            plain_rag_would_send=(
                f"QUESTION: {question}\n\n"
                "(Plain RAG would still call the LLM with weak/empty context and risk hallucination.)"
            ),
            exhaustshield_sent="NOTHING SENT TO LLM — routed to Human Review Vault (no keyword match)",
            wow="True gap only: no policy keywords matched, so we asked a human instead of guessing.",
        ),
        **_data_boundary_fields("stayed_local"),
        "session": _session_snapshot(),
        **_knowledge_stamp(),
    }
    await broadcast_event(payload)
    return {"ok": True, **payload}


@app.get("/api/health")
def api_health():
    cfg = refresh_external_ai_config()
    runtime = external_runtime_status()
    try:
        # Force re-probe when soft/hard degraded so Avast blocks clear quickly in the UI.
        groq = probe_external_ai(
            force=bool(runtime.get("degraded") or runtime.get("soft"))
        )
    except Exception as exc:
        groq = {
            "reachable": False,
            "degraded": True,
            "soft": True,
            "effective_mode": "backup",
            "reason": f"probe_error:{exc}"[:160],
            "model": cfg.get("model"),
            "model_available": None,
        }
    runtime = external_runtime_status()
    try:
        live_web = probe_live_web(force=False)
    except Exception as exc:
        live_web = {
            "enabled": True,
            "ok": False,
            "snippet_count": 0,
            "reason": f"probe_error:{exc}"[:160],
        }
    try:
        placeholder_policy = ExhaustDetector.placeholder_policy()
    except Exception:
        placeholder_policy = []
    return {
        "ok": True,
        "local_first": True,
        "knowledge_engine_version": KNOWLEDGE_ENGINE_VERSION,
        "ask_knowledge_may_call_llm": False,
        "knowledge_docs": len(list_documents()),
        "demo_ready": True,
        "exhaust_guardian": {
            "enabled": True,
            "levels": ["safe", "moderate", "high"],
            "safe_max_score": SAFE_MAX_SCORE,
            "moderate_max_score": MODERATE_MAX_SCORE,
            "external_mode": cfg.get("mode") or EXTERNAL_AI_MODE,
            "external_effective": groq.get("effective_mode") or runtime.get("effective_mode"),
            "external_model": cfg.get("model"),
            "external_reachable": bool(groq.get("reachable")),
            "external_degraded": bool(groq.get("degraded") or runtime.get("degraded")),
            "external_soft": bool(groq.get("soft") or runtime.get("soft")),
            "external_probe": {
                "reason": groq.get("reason"),
                "model_available": groq.get("model_available"),
                "model": groq.get("model"),
            },
            "live_web_enabled": bool(live_web.get("enabled")),
            "live_web_ok": bool(live_web.get("ok")),
            "live_web_snippets": int(live_web.get("snippet_count") or 0),
            "live_web_reason": live_web.get("reason") or "",
            "high_fail_closed": True,
            "strict_safe": True,
            "high_risk_catalog": HIGH_RISK_CATALOG,
            "placeholder_policy": placeholder_policy,
        },
        "features": [
            "local_near_match",
            "acronym_entity_force",
            "no_silent_llm_fallback_when_hits_exist",
            "shielded_llm_knowledge_path_disabled",
            "exhaust_guardian_3_level_router",
            "live_web_snippets",
        ],
    }


@app.on_event("startup")
def _startup_banner():
    cfg = refresh_external_ai_config()
    print(
        f"[ExhaustShield] knowledge engine={KNOWLEDGE_ENGINE_VERSION} "
        "ask-knowledge=LOCAL-ONLY (LLM fallback disabled)"
    )
    print(
        f"[ExhaustShield] guardian=SAFE->external / MODERATE->sanitize->external / "
        f"HIGH->private (fail-closed) · external_mode={cfg.get('mode') or EXTERNAL_AI_MODE}"
    )
    if cfg.get("mode") == "live":
        groq = probe_external_ai(force=True)
        if groq.get("reachable"):
            print(
                f"[ExhaustShield] Groq live · model={cfg.get('model')} · "
                f"fallback={cfg.get('fallback_model')} · key_ok={cfg.get('has_key')}"
            )
        else:
            print(
                f"[ExhaustShield] Groq not reachable ({groq.get('reason')}). "
                "Demo backup answers are on — the presentation will still complete."
            )
        live_web = probe_live_web(force=True)
        if live_web.get("ok"):
            print(
                f"[ExhaustShield] Live web OK · snippets={live_web.get('snippet_count')}"
            )
        else:
            print(
                f"[ExhaustShield] Live web LAGGING ({live_web.get('reason')}) — "
                "latest news/sports answers will use model memory only until search works."
            )
