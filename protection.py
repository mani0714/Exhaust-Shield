"""Local-only human review + data protection ledger.

Corrected answers are stored on disk and NEVER sent to Ollama/LLMs for training.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from detector import ExhaustDetector

ROOT = Path(__file__).resolve().parent
REVIEW_DIR = ROOT / "reviews"
QUEUE_FILE = REVIEW_DIR / "queue.json"
CORRECTIONS_FILE = REVIEW_DIR / "corrections.json"
AUDIT_FILE = REVIEW_DIR / "protection_audit.jsonl"


def ensure_dirs() -> None:
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    if not QUEUE_FILE.exists():
        QUEUE_FILE.write_text("[]", encoding="utf-8")
    if not CORRECTIONS_FILE.exists():
        CORRECTIONS_FILE.write_text("[]", encoding="utf-8")


def _load(path: Path) -> list:
    ensure_dirs()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save(path: Path, data: list) -> None:
    ensure_dirs()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def append_audit(event: dict) -> None:
    ensure_dirs()
    event = {
        **event,
        "ts": datetime.now(timezone.utc).isoformat(),
        "data_residency": "local_disk_only",
        "llm_training_opt_out": True,
    }
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


# Friendly labels for Pilot Lab evidence locker (Tab 2 / Tab 3 / Lab).
_LANE_PATH = {
    "safe": "Safe → outside AI",
    "moderate": "Medium → hide secrets first",
    "high": "High → private AI only",
}

_EVENT_META = {
    "pilot_dry_run": ("Lab", "Dry-run (no AI call)"),
    "exhaust_guardian_safe_pending": ("Tab 3", "Safe — awaiting confirm"),
    "exhaust_guardian_moderate_pending": ("Tab 3", "Medium — awaiting confirm"),
    "exhaust_guardian_safe_confirmed": ("Tab 3", "Safe — sent outside"),
    "exhaust_guardian_moderate_confirmed": ("Tab 3", "Medium — sent outside (sanitized)"),
    "exhaust_guardian_route": ("Tab 3", "Outbound route"),
    "exhaust_guardian_last_mile_blocked": ("Tab 3", "Last-mile blocked external"),
    "exhaust_guardian_confirm_cancelled": ("Tab 3", "Outbound cancelled"),
    "local_near_match_answer": ("Tab 2", "Local near-match answer"),
    "served_local_human_answer": ("Tab 2", "Human vault answer"),
    "local_forced_from_hits": ("Tab 2", "Local safety-net answer"),
    "routed_to_human_no_context": ("Tab 2", "Queued for human vault"),
    "document_saved": ("Docs", "Document saved"),
    "document_uploaded": ("Docs", "Document uploaded"),
}


def build_evidence_brief(
    analysis: dict | None,
    decision: dict | None,
    *,
    prompt: str = "",
    knowledge: dict | None = None,
    event: str | None = None,
    stage: str | None = None,
) -> dict:
    """Compact why-this-path payload for Pilot Lab evidence locker / fine-tuning.

    Captures lane, reasons, dynamic signals, and the concrete trigger spans/words
    that pushed High or Medium — so demos and later tuning are inspectable.
    """
    analysis = analysis or {}
    decision = decision or {}
    flagged = analysis.get("flagged_items") or []
    hide_items = [f for f in flagged if (f.get("action") or "hide") == "hide"]
    keep_items = [f for f in flagged if (f.get("action") or "") == "keep"]

    triggers: list[dict] = []
    for f in hide_items[:10]:
        val = str(f.get("value") or "").strip()
        if not val:
            continue
        triggers.append(
            {
                "kind": "hide",
                "department": f.get("department") or f.get("type") or "?",
                "word": val[:80],
                "rewrite_as": (
                    ExhaustDetector.sanitize_rewrite_hint(
                        f.get("generalization_hint") or f.get("token"),
                        f.get("value") or "",
                    )
                    or f.get("token")
                    or ""
                )[:60]
                or None,
            }
        )
    for f in keep_items[:6]:
        val = str(f.get("value") or "").strip()
        if not val:
            continue
        triggers.append(
            {
                "kind": "topic",
                "department": f.get("department") or f.get("type") or "?",
                "word": val[:80],
            }
        )

    dyn = list(decision.get("dynamic_high_signals") or [])[:6]
    reasons = list(decision.get("reasons") or [])[:6]
    level = (decision.get("risk_level") or "?").lower()
    dest = decision.get("destination") or "?"
    path = _LANE_PATH.get(level) or f"{level} → {dest}"

    hide_words = [t["word"] for t in triggers if t.get("kind") == "hide"][:4]
    topic_words = [t["word"] for t in triggers if t.get("kind") == "topic"][:4]

    why_bits: list[str] = []
    if reasons:
        why_bits.append(reasons[0])
    if dyn:
        why_bits.append("Dynamic: " + "; ".join(dyn[:2]))
    if hide_words:
        why_bits.append("Hide words: " + ", ".join(hide_words))
    elif topic_words:
        why_bits.append("Topic words: " + ", ".join(topic_words))
    if not why_bits:
        why_bits.append("No sensitive spans — strict Safe candidate")

    knowledge = knowledge or {}
    know_path = knowledge.get("logic_path") or knowledge.get("path")
    know_note = knowledge.get("note")

    why_path = " · ".join(why_bits)[:420]

    # One clean board-ready sentence
    stage_note = (stage or "").strip()
    if level == "high":
        brief = (
            f"High — private AI only. {reasons[0] if reasons else 'Sensitive signal detected.'}"
        )
    elif level == "moderate":
        brief = (
            f"Medium — hide/rewrite {len(hide_items)} span(s) before outside AI. "
            + (f"Words: {', '.join(hide_words)}." if hide_words else "")
        )
    elif level == "safe":
        brief = "Safe — no concrete secrets; confirm then send as-is to outside AI."
    else:
        brief = why_path
    if stage_note:
        brief = f"{stage_note} {brief}".strip()
    brief = brief[:280]

    tab, title = _EVENT_META.get(event or "", ("", ""))
    if not title and level in _LANE_PATH:
        tab, title = "Tab 3", _LANE_PATH[level]
    if know_path and not tab:
        tab, title = "Tab 2", "Knowledge path"

    return {
        "tab": tab or None,
        "title": title or None,
        "brief": brief,
        "path": path,
        "risk_level": level,
        "lane_badge": decision.get("lane_badge") or path,
        "destination": dest,
        "why_path": why_path,
        "reasons": reasons,
        "dynamic_signals": dyn,
        "trigger_words": triggers,
        "risk_score": analysis.get("risk_score"),
        "hard_secret": bool(decision.get("hard_secret_detected")),
        "suspicious_entropy": bool(decision.get("suspicious_entropy")),
        "prompt_preview": (prompt or "").strip()[:500] or None,
        "knowledge_path": know_path,
        "knowledge_note": know_note,
        "tune_hint": (
            "High: BASIC_HIGH_RISK_CUES / dynamic_high_signals · "
            "Medium: detector hide patterns · Safe: last-mile still clean"
        ),
    }


def enqueue_for_review(item: dict) -> dict:
    ensure_dirs()
    queue = _load(QUEUE_FILE)
    record = {
        "id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "awaiting_human_answer",
        "reason": item.get("reason", "no_local_answer"),
        "question": item.get("question", ""),
        "model_answer": item.get("model_answer", ""),
        "restored_answer": item.get("restored_answer", ""),
        "sources": item.get("sources", []),
        "risk_score": item.get("risk_score", 0),
        "shielded_prompt_preview": item.get("shielded_prompt_preview", ""),
        "never_train_on_llm": True,
        "logic": (
            "Queued only because no approved local answer / insufficient policy context was found. "
            "Human answer will be stored in the vault and reused later without calling the LLM."
        ),
    }
    queue.insert(0, record)
    _save(QUEUE_FILE, queue[:100])
    append_audit(
        {
            "event": "review_enqueued",
            "review_id": record["id"],
            "reason": record["reason"],
            "sent_to_llm_for_training": False,
        }
    )
    return record


def list_queue(status: str | None = None) -> list:
    queue = _load(QUEUE_FILE)
    if status:
        return [q for q in queue if q.get("status") == status]
    return queue


def delete_review(review_id: str) -> dict:
    """Remove a queued question from the human vault queue (local disk only)."""
    ensure_dirs()
    queue = _load(QUEUE_FILE)
    target = next((q for q in queue if q.get("id") == review_id), None)
    if not target:
        raise FileNotFoundError(review_id)

    remaining = [q for q in queue if q.get("id") != review_id]
    _save(QUEUE_FILE, remaining)
    append_audit(
        {
            "event": "review_deleted",
            "review_id": review_id,
            "question": (target.get("question") or "")[:200],
            "prior_status": target.get("status"),
            "sent_to_llm": False,
        }
    )
    return {
        "id": review_id,
        "deleted": True,
        "prior_status": target.get("status"),
        "question": target.get("question", ""),
    }


def submit_correction(review_id: str, corrected_answer: str, reviewer: str = "human") -> dict:
    """Store policy answer locally. Explicitly never forwarded to LLMs."""
    queue = _load(QUEUE_FILE)
    target = next((q for q in queue if q["id"] == review_id), None)
    if not target:
        raise FileNotFoundError(review_id)

    correction = {
        "id": str(uuid.uuid4()),
        "review_id": review_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reviewer": reviewer,
        "question": target["question"],
        "model_answer": target.get("restored_answer") or target.get("model_answer") or None,
        "corrected_answer": corrected_answer,
        "sources": target.get("sources", []),
        "storage": "local_reviews/corrections.json",
        "sent_to_llm": False,
        "used_for_model_training": False,
        "data_protection": {
            "layer": "ExhaustShield Human Vault",
            "guarantee": (
                "Answer is persisted only on enterprise disk. "
                "It is never posted to Ollama, cloud LLM APIs, or fine-tuning endpoints."
            ),
        },
    }

    corrections = _load(CORRECTIONS_FILE)
    corrections.insert(0, correction)
    _save(CORRECTIONS_FILE, corrections[:200])

    for q in queue:
        if q["id"] == review_id:
            q["status"] = "answered_local_only"
            q["corrected_answer"] = corrected_answer
            q["corrected_at"] = correction["created_at"]
            q["reviewer"] = reviewer
    _save(QUEUE_FILE, queue)

    append_audit(
        {
            "event": "human_answer_saved",
            "review_id": review_id,
            "correction_id": correction["id"],
            "sent_to_llm": False,
            "used_for_model_training": False,
        }
    )
    return correction


def create_unanswered_ticket(question: str, detail: str = "") -> dict:
    """Direct path: no policy hit → human must answer; nothing useful to send to LLM."""
    return enqueue_for_review(
        {
            "question": question,
            "model_answer": "",
            "restored_answer": detail
            or "No matching policy excerpt found. A human reviewer must provide the approved answer.",
            "sources": [],
            "risk_score": 0,
            "reason": "no_local_answer",
        }
    )


def create_dispute_ticket(
    question: str,
    rejected_answer: str,
    *,
    sources: list | None = None,
    logic_path: str = "local_near_match",
) -> dict:
    """Near-match / vault answer was wrong — route to human for the approved answer."""
    return enqueue_for_review(
        {
            "question": question,
            "model_answer": rejected_answer,
            "restored_answer": rejected_answer,
            "sources": sources or [],
            "risk_score": 0,
            "reason": "disputed_local_answer",
            "shielded_prompt_preview": f"logic_path={logic_path}",
        }
    )


def dispute_and_correct(
    question: str,
    rejected_answer: str,
    corrected_answer: str,
    *,
    reviewer: str = "policy_owner",
    sources: list | None = None,
    logic_path: str = "local_near_match",
) -> dict:
    """One step: flag wrong local answer → human writes approved answer → vault only."""
    ticket = create_dispute_ticket(
        question,
        rejected_answer,
        sources=sources,
        logic_path=logic_path,
    )
    correction = submit_correction(ticket["id"], corrected_answer, reviewer=reviewer)
    append_audit(
        {
            "event": "disputed_local_answer_corrected",
            "review_id": ticket["id"],
            "correction_id": correction["id"],
            "prior_logic_path": logic_path,
            "sent_to_llm": False,
            "used_for_model_training": False,
        }
    )
    return {"review": ticket, "correction": correction}


def find_local_answer(question: str) -> dict | None:
    """Prefer prior human-approved answers over re-querying the LLM."""
    q_norm = " ".join(question.lower().split())
    for item in _load(CORRECTIONS_FILE):
        stored = " ".join(str(item.get("question", "")).lower().split())
        if stored == q_norm or (len(q_norm) > 12 and q_norm in stored) or (len(stored) > 12 and stored in q_norm):
            return item
    return None


def protection_status() -> dict:
    ensure_dirs()
    queue = _load(QUEUE_FILE)
    corrections = _load(CORRECTIONS_FILE)
    audit_lines = 0
    if AUDIT_FILE.exists():
        try:
            # Fast size-based estimate — avoid scanning huge JSONL on every /api/stats
            size = AUDIT_FILE.stat().st_size
            if size <= 0:
                audit_lines = 0
            elif size < 512_000:
                audit_lines = sum(1 for line in AUDIT_FILE.open(encoding="utf-8") if line.strip())
            else:
                # Approximate: ~180 bytes/event typical
                audit_lines = max(1, size // 180)
        except Exception:
            audit_lines = 0

    return {
        "layer_name": "ExhaustShield Data Protection Layer",
        "residency": "local_disk",
        "confidential_folder": "confidential_data/",
        "review_vault": "reviews/",
        "pending_reviews": len(
            [q for q in queue if q.get("status") in ("pending_review", "awaiting_human_answer")]
        ),
        "local_corrections": len(corrections),
        "audit_events": audit_lines,
        "guarantees": [
            "Policy documents are read only from confidential_data/ on this machine.",
            "Sensitive spans are redacted to placeholders before any LLM call.",
            "Human corrections are stored locally and never sent to LLMs for training.",
            "Open-source model outputs are treated as untrusted until human review.",
            "Protection audit trail remains on enterprise disk (reviews/protection_audit.jsonl).",
        ],
    }


def read_audit_tail(limit: int = 40) -> list[dict]:
    """Newest-first audit events from the local JSONL ledger (pilot evidence)."""
    ensure_dirs()
    limit = max(1, min(int(limit or 40), 200))
    if not AUDIT_FILE.exists():
        return []
    rows: list[dict] = []
    try:
        # Only read the tail of large ledgers — full-file reads froze the dashboard
        size = AUDIT_FILE.stat().st_size
        with AUDIT_FILE.open("rb") as f:
            if size > 256_000:
                f.seek(max(0, size - 256_000))
                f.readline()  # drop partial first line
                chunk = f.read().decode("utf-8", errors="ignore")
            else:
                chunk = f.read().decode("utf-8", errors="ignore")
        lines = chunk.splitlines()
    except Exception:
        return []
    for line in reversed(lines):
        line = (line or "").strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
        if len(rows) >= limit:
            break
    return rows


def clear_audit(*, record_marker: bool = True) -> dict:
    """Wipe the local evidence locker (pilot demo reset). Does not touch vault/queue.

    record_marker=False leaves the JSONL fully empty (Reset Demo / empty Pilot Lab).
    record_marker=True appends a single audit_reset row (locker-only reset button).
    """
    ensure_dirs()
    cleared = 0
    if AUDIT_FILE.exists():
        try:
            cleared = sum(1 for line in AUDIT_FILE.open(encoding="utf-8") if line.strip())
        except Exception:
            cleared = 0
        AUDIT_FILE.write_text("", encoding="utf-8")
    else:
        AUDIT_FILE.write_text("", encoding="utf-8")
    if record_marker:
        append_audit(
            {
                "event": "audit_reset",
                "cleared_events": cleared,
                "sent_to_llm": False,
            }
        )
    return {"ok": True, "cleared_events": cleared, "path": str(AUDIT_FILE.name)}
