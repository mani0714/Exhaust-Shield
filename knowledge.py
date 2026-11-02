"""Local confidential knowledge base — near-match retrieval + local-first answers."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from detector import ExhaustDetector

ROOT = Path(__file__).resolve().parent
CONFIDENTIAL_DIR = ROOT / "confidential_data"
ALLOWED_SUFFIXES = {".txt", ".md", ".markdown", ".csv", ".json", ".log", ".policy"}

STOPWORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "any", "can", "had", "her",
    "was", "one", "our", "out", "has", "have", "been", "from", "they", "this", "that",
    "with", "will", "what", "when", "where", "which", "who", "whom", "why", "how",
    "did", "does", "do", "is", "am", "were", "about", "into", "than", "then", "also",
    "just", "only", "over", "such", "some", "could", "would", "should", "please",
    "tell", "describe", "explain", "give", "based", "according", "company", "policy",
    "policies", "question", "answer", "near", "under", "your", "ours", "their",
    # Too common in every policy file — alone must not create a "match"
    "employee", "employees", "staff", "worker", "workers", "information", "data",
    "document", "section", "procedure", "process", "guideline", "guidelines",
    "currently", "status", "year", "years", "internal", "team", "teams", "use",
    "using", "used", "make", "made", "need", "needs", "know", "like", "get",
}

# Weak generics after stemming/synonym expand — ignore for grounding checks
WEAK_CONTENT = {
    "employ", "policy", "policies", "company", "confiden", "information", "data",
    "staff", "worker", "document", "section", "process", "procedure", "status",
}

SYNONYMS = {
    "acquir": {"acquire", "acquired", "acquires", "acquiring", "acquisition", "acquisitions",
               "buy", "bought", "purchase", "purchased", "merger", "merge"},
    "sever": {"severance", "exit", "termination", "terminated", "fired", "layoff", "laid",
              "furlough", "leave", "leaving", "dismissed", "dismissal"},
    "compens": {"compensation", "salary", "salaries", "pay", "payroll", "wage", "wages",
                "remuneration", "earning", "earnings"},
    "bonus": {"bonus", "bonuses", "incentive", "incentives"},
    "discount": {"discount", "discounts", "pricing", "price", "ceiling"},
    "incident": {"incident", "breach", "ransomware", "compromise", "intrusion"},
    "vulnerab": {"vulnerability", "vulnerabilities", "cve", "exploit", "zero-day", "zeroday"},
    "mfa": {"mfa", "2fa", "totp", "otp", "authentication"},
    "confiden": {"confidential", "restricted", "proprietary", "secret"},
    "deal": {"deal", "deals", "transaction"},
    "employ": {"employee", "employees", "staff", "worker", "workers"},
    "pip": {"pip", "performance"},
    "rsu": {"rsu", "rsus", "equity", "stock"},
    "msa": {"msa"},
    "rfp": {"rfp", "rfi", "rfq", "proposal"},
    "northwind": {"northwind"},
}

HARD_SECRET_PATTERNS = [
    r"sk-[a-zA-Z0-9]{20,}",
    r"sk-proj-[a-zA-Z0-9_-]+",
    r"(?i)\bAKIA[0-9A-Z]{16}\b",
    r"(?i)\bghp_[A-Za-z0-9]{36}\b",
    r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*\S+",
    r"\b\d{3}-\d{2}-\d{4}\b",
    r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b",
    r"(?i)bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*",
    r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
]

# Stricter near-match: weak keyword overlap must not invent an answer
LOCAL_ANSWER_MIN_SCORE = 0.32
RETRIEVE_MIN_SCORE = 0.20
FORCE_LOCAL_SCORE = 0.95
MIN_CONTENT_OVERLAP = 2


def ensure_dirs() -> None:
    CONFIDENTIAL_DIR.mkdir(parents=True, exist_ok=True)


def list_documents() -> list[dict]:
    ensure_dirs()
    docs = []
    for path in sorted(CONFIDENTIAL_DIR.rglob("*")):
        if path.is_file() and path.suffix.lower() in ALLOWED_SUFFIXES:
            rel = path.relative_to(CONFIDENTIAL_DIR).as_posix()
            docs.append(
                {
                    "id": rel,
                    "name": path.name,
                    "path": rel,
                    "size_bytes": path.stat().st_size,
                    "updated_at": datetime.fromtimestamp(
                        path.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
            )
    return docs


def save_document(filename: str, content: str) -> dict:
    ensure_dirs()
    safe = re.sub(r"[^A-Za-z0-9._\- ]+", "_", filename).strip() or f"policy-{uuid.uuid4().hex[:8]}.txt"
    if Path(safe).suffix.lower() not in ALLOWED_SUFFIXES:
        safe += ".txt"
    path = CONFIDENTIAL_DIR / safe
    path.write_text(content, encoding="utf-8")
    return {
        "id": safe,
        "name": safe,
        "path": safe,
        "size_bytes": path.stat().st_size,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def read_document(doc_id: str) -> str:
    ensure_dirs()
    path = (CONFIDENTIAL_DIR / doc_id).resolve()
    if not str(path).startswith(str(CONFIDENTIAL_DIR.resolve())):
        raise ValueError("Invalid document path")
    if not path.exists() or path.suffix.lower() not in ALLOWED_SUFFIXES:
        raise FileNotFoundError(doc_id)
    return path.read_text(encoding="utf-8", errors="ignore")


def normalize_question(question: str) -> str:
    q = (question or "").strip()
    for a, b in {
        "\u201c": '"', "\u201d": '"', "\u2018": "'", "\u2019": "'",
        "\u2014": "-", "\u2013": "-",
    }.items():
        q = q.replace(a, b)
    return q.strip().strip('"').strip("'").strip()


def _stem(token: str) -> str:
    t = token.lower()
    # Prefer longer suffixes first; handle employees→employee before employees→employe
    for suf in ("tion", "sion", "ings", "ing", "ers", "ies", "ied", "ees", "es", "ed", "s"):
        if len(t) > len(suf) + 3 and t.endswith(suf):
            return t[: -len(suf)]
    return t


def _expand_terms(tokens: set[str]) -> set[str]:
    expanded = set(tokens)
    for tok in list(tokens):
        st = _stem(tok)
        expanded.add(st)
        for family, members in SYNONYMS.items():
            if tok in members or st in members or st.startswith(family) or tok.startswith(family):
                expanded |= members
                expanded.add(family)
    return expanded


def _tokenize(text: str) -> set[str]:
    raw = {t.lower() for t in re.findall(r"[A-Za-z0-9_]{3,}", text)}
    return {t for t in raw if t not in STOPWORDS}


def _chunk_text(text: str) -> list[str]:
    parts = re.split(r"(?:\n\s*\n|\n(?=\s*\d+\.)|(?<=[.!?])\s+)", text)
    chunks = [p.strip() for p in parts if p and p.strip() and len(p.strip()) > 20]
    if chunks:
        return chunks
    words = text.split()
    return [" ".join(words[i : i + 80]).strip() for i in range(0, len(words), 60) if words[i : i + 80]]


def _extract_acronyms(text: str) -> set[str]:
    # Include both PIP and pip-style from questions typed in mixed case
    found = {m.group(0).upper() for m in re.finditer(r"\b[A-Z]{2,6}\b", text)}
    found |= {m.group(0).upper() for m in re.finditer(r"\b(?:pip|rsu|msa|nda|cve|mfa|otp)\b", text, flags=re.I)}
    return found


def _extract_entity_phrases(text: str) -> list[str]:
    phrases = re.findall(
        r"\b(?:[A-Z][a-zA-Z0-9&\-]+(?:\s+[A-Z][a-zA-Z0-9&\-]+){0,4})\b",
        text,
    )
    skip = {"Did", "Are", "What", "How", "The", "Our", "Any", "Yes", "Based", "Who"}
    return [p for p in phrases if p not in skip and len(p) >= 3]


def _force_grounded_score(question: str, chunk: str) -> float | None:
    chunk_l = chunk.lower()
    for acr in _extract_acronyms(question):
        if re.search(rf"\b{re.escape(acr)}\b", chunk, flags=re.IGNORECASE):
            return FORCE_LOCAL_SCORE
    for phrase in _extract_entity_phrases(question):
        if len(phrase.split()) >= 2 and phrase.lower() in chunk_l:
            return FORCE_LOCAL_SCORE
        if len(phrase) >= 6 and phrase.lower() in chunk_l:
            return FORCE_LOCAL_SCORE
    return None


def _score_chunk(question: str, chunk: str) -> float:
    forced = _force_grounded_score(question, chunk)
    if forced is not None:
        return forced

    q_terms = _tokenize(question)
    if not q_terms:
        return 0.0

    c_terms = _tokenize(chunk)
    q_exp = _expand_terms(q_terms)
    c_exp = _expand_terms(c_terms)
    overlap = q_exp & c_exp
    strong_overlap = {t for t in overlap if t not in WEAK_CONTENT}
    if not strong_overlap and not overlap:
        return 0.0

    use_overlap = strong_overlap or overlap
    coverage = len(use_overlap) / max(1, len(q_exp))
    absolute = min(1.0, len(use_overlap) / 3.0)
    proper = {t for t in re.findall(r"\b[A-Z][a-zA-Z0-9\-]+\b", question)}
    proper_hit = sum(1 for p in proper if p.lower() in chunk.lower())
    boost = min(0.35, 0.12 * proper_hit)
    score = min(1.0, 0.65 * coverage + 0.35 * absolute + boost)
    if not strong_overlap:
        score *= 0.35
    return score


def _content_overlap_count(question: str, text: str) -> int:
    q_exp = {t for t in _expand_terms(_tokenize(question)) if t not in WEAK_CONTENT}
    c_exp = {t for t in _expand_terms(_tokenize(text)) if t not in WEAK_CONTENT}
    return len(q_exp & c_exp)


def _key_terms(question: str) -> list[str]:
    """Important question words/phrases that must appear (or synonym) in the policy."""
    question = normalize_question(question)
    keys: list[str] = []
    seen: set[str] = set()

    def _add(key: str) -> None:
        k = key.strip()
        if not k:
            return
        marker = k.lower()
        if marker in seen:
            return
        seen.add(marker)
        keys.append(k)

    for acr in sorted(_extract_acronyms(question)):
        _add(acr)
    for phrase in _extract_entity_phrases(question):
        if len(phrase.split()) >= 2 or len(phrase) >= 6:
            _add(phrase)
    for tok in sorted(_tokenize(question)):
        st = _stem(tok)
        if tok in WEAK_CONTENT or st in WEAK_CONTENT:
            continue
        if tok in STOPWORDS or st in STOPWORDS:
            continue
        _add(tok)
    return keys


def _key_covered(key: str, text: str) -> bool:
    """True if this key word/phrase (or an equivalent meaning) appears in policy text."""
    text_l = text.lower()
    key_l = key.lower()

    # Multi-word / proper entity phrase
    if " " in key_l or (key[:1].isupper() and len(key) >= 6 and not key.isupper()):
        if key_l in text_l:
            return True

    # Acronyms (PIP, MFA, …)
    if key.isupper() and 2 <= len(key) <= 6:
        if re.search(rf"\b{re.escape(key)}\b", text, flags=re.IGNORECASE):
            return True

    # Single token + synonym / stem family
    key_forms = _expand_terms({key_l, _stem(key_l)})
    text_forms = _expand_terms(_tokenize(text))
    if key_forms & text_forms:
        return True
    # Phrase-level fallback for stemmed word inside text
    for form in key_forms:
        if len(form) >= 4 and form in text_l:
            return True
    return False


def missing_key_terms(question: str, text: str) -> list[str]:
    """Key question terms whose word/meaning is missing from the policy excerpt."""
    return [k for k in _key_terms(question) if not _key_covered(k, text)]


def is_close_policy_match(question: str, hit: dict) -> bool:
    """Suggest a local answer when strong keywords overlap the policy chunk.

    Rules (company-knowledge):
    - Matching uses key words (entities, acronyms, content tokens) — not stopwords.
    - Any overlapping key word → treat as a suggested local answer (user can confirm).
    - Reject only when there is essentially zero keyword overlap with this chunk.
    """
    text = hit.get("text") or ""
    keys = _key_terms(question)
    missing = missing_key_terms(question, text)
    hit["missing_key_terms"] = missing
    score = float(hit.get("score") or 0)
    overlap = _content_overlap_count(question, text)
    covered_n = max(0, len(keys) - len(missing)) if keys else 0

    # Hard grounded / entity force
    if hit.get("forced") or score >= FORCE_LOCAL_SCORE:
        return True

    # Any strong keyword from the question appears in this excerpt → suggest
    if covered_n >= 1 or overlap >= 1:
        return True

    # No extractable keys but retrieval still scored real content
    if not keys and score >= LOCAL_ANSWER_MIN_SCORE and overlap >= 1:
        return True

    return False


def has_keyword_policy_overlap(question: str, hits: list[dict] | None = None) -> bool:
    """True if any retrieved hit shares at least one strong keyword with the question."""
    question = normalize_question(question)
    pool = hits if hits is not None else retrieve_context(question)
    return any(is_close_policy_match(question, h) for h in pool)


def retrieve_context(question: str, top_k: int = 4, min_score: float = RETRIEVE_MIN_SCORE) -> list[dict]:
    question = normalize_question(question)
    hits = []
    for doc in list_documents():
        try:
            text = read_document(doc["id"])
        except Exception:
            continue
        for idx, chunk in enumerate(_chunk_text(text)):
            score = _score_chunk(question, chunk)
            if score >= min_score:
                hits.append(
                    {
                        "doc_id": doc["id"],
                        "doc_name": doc["name"],
                        "chunk_index": idx,
                        "score": round(score, 3),
                        "text": chunk,
                        "forced": score >= FORCE_LOCAL_SCORE,
                    }
                )
    hits.sort(key=lambda h: h["score"], reverse=True)
    return hits[:top_k]


def _best_sentences(question: str, chunk: str, limit: int = 2) -> list[str]:
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", chunk) if s.strip()]
    if not sentences:
        return [chunk.strip()]
    ranked = sorted(sentences, key=lambda s: _score_chunk(question, s), reverse=True)
    return [s for s in ranked[:limit] if _score_chunk(question, s) >= 0.05] or ranked[:1]


def _is_yes_no_question(question: str) -> bool:
    q = normalize_question(question).lower()
    return bool(
        re.match(
            r"^(did|do|does|is|are|was|were|can|could|has|have|had|will|would|should)\b",
            q,
        )
    )


def build_local_answer_from_hits(question: str, hits: list[dict]) -> dict:
    question = normalize_question(question)
    best = hits[0]
    support = _best_sentences(question, best["text"], limit=2)
    support_text = " ".join(support)

    if _is_yes_no_question(question):
        grounded = (
            bool(_expand_terms(_tokenize(question)) & _expand_terms(_tokenize(support_text)))
            or _force_grounded_score(question, support_text) is not None
            or best.get("forced")
            or best["score"] >= LOCAL_ANSWER_MIN_SCORE
        )
        answer = (
            f"Yes. Based on local policy ({best['doc_name']}): {support_text}"
            if grounded
            else f"Based on the closest local policy excerpt ({best['doc_name']}): {support_text}"
        )
    else:
        answer = f"Based on local policy ({best['doc_name']}): {support_text}"

    return {
        "answer": answer,
        "hits": hits,
        "best_score": best["score"],
        "sources": [
            {
                "doc_id": h["doc_id"],
                "doc_name": h["doc_name"],
                "score": h["score"],
                "preview": h["text"][:180] + ("…" if len(h["text"]) > 180 else ""),
            }
            for h in hits
        ],
        "sent_to_llm": False,
        "logic_path": "local_near_match",
        "protection": {
            "cleartext_sent_to_llm": False,
            "answer_source": "local_policy_extractive",
            "chunks_used": len(hits),
            "note": (
                "Answered locally from near-matching policy text. "
                "Open-source LLM was not called, so confidential excerpts did not leave the gateway."
            ),
        },
    }


def answer_from_local_policy(question: str, top_k: int = 4) -> dict | None:
    """Suggest a local extractive answer when policy keywords overlap the question.

    Human gap is reserved for zero keyword overlap (handled by the gateway).
    Partial key coverage still returns a suggestion so the user can mark
    correct / incorrect instead of jumping straight to 'not available'.
    """
    question = normalize_question(question)
    hits = retrieve_context(question, top_k=max(top_k, 8), min_score=RETRIEVE_MIN_SCORE)
    if not hits:
        return None
    matched = [h for h in hits if is_close_policy_match(question, h)]
    if not matched:
        return None
    result = build_local_answer_from_hits(question, matched[:top_k])
    # Annotate when some question keys were not in the top excerpt (suggestion, not perfect)
    top_missing = matched[0].get("missing_key_terms") or []
    if top_missing:
        note = result.get("protection", {}).get("note") or ""
        result["protection"] = {
            **result.get("protection", {}),
            "suggested": True,
            "missing_key_terms": top_missing,
            "note": (
                note
                + " Suggested from keyword overlap — confirm if this answer is correct; "
                "mark incorrect to send to the Human vault."
            ).strip(),
        }
    return result


def _redact_hard_secrets_only(text: str) -> tuple[str, dict, list]:
    redacted = text
    token_map = {}
    flagged = []
    counter = 1
    for pattern in HARD_SECRET_PATTERNS:
        for match in list(re.finditer(pattern, redacted)):
            raw = match.group(0)
            token = f"<SECRET_{counter}>"
            flagged.append({"type": "engineering", "value": raw, "token": token, "department": "engineering"})
            token_map[token] = raw
            redacted = redacted.replace(raw, token, 1)
            counter += 1
    return redacted, token_map, flagged


def _question_aware_business_redact(text: str, question: str, detector: ExhaustDetector) -> dict:
    analysis = detector.analyze_prompt(text)
    q_lower = question.lower()
    redacted = text
    token_map = {}
    kept_flagged = []
    counter = 1
    items = sorted(analysis["flagged_items"], key=lambda x: len(x["value"]), reverse=True)
    keep_words = {
        "acquired", "acquire", "acquisition", "merger", "revenue", "deal of",
        "confidential", "internal only", "severance", "salary", "bonus",
    }
    for item in items:
        val = item["value"]
        if val.lower() in q_lower or val.lower() in keep_words:
            continue
        token = f"<{item['type'].upper()}_{counter}>"
        if val in redacted:
            redacted = redacted.replace(val, token, 1)
            token_map[token] = val
            kept_flagged.append({**item, "token": token})
            counter += 1

    hard_text, hard_map, hard_flagged = _redact_hard_secrets_only(redacted)
    token_map.update(hard_map)
    kept_flagged.extend(hard_flagged)
    score = min(100, len(kept_flagged) * 25)
    by_department = {}
    for item in kept_flagged:
        by_department[item["type"]] = by_department.get(item["type"], 0) + 1

    return {
        "redacted_text": hard_text,
        "token_map": token_map,
        "flagged_items": kept_flagged,
        "placeholders": [
            {"token": i["token"], "original": i["value"], "department": i["type"]}
            for i in kept_flagged
        ],
        "risk_score": score,
        "by_department": by_department,
        "department_risk": {
            d: min(100, by_department.get(d, 0) * 25) for d in ExhaustDetector.PATTERNS
        },
        "prevention": {
            "secrets_blocked": len(kept_flagged),
            "departments_involved": list(by_department.keys()),
            "llm_exposed_secrets": 0,
            "summary": (
                f"Question-aware shield kept user-mentioned entities readable and blocked "
                f"{len(kept_flagged)} sensitive span(s) before the LLM call."
            ),
        },
    }


KNOWLEDGE_ENGINE_VERSION = "local-first-v2"


def build_shielded_prompt(question: str, detector: ExhaustDetector, top_k: int = 4) -> dict:
    """Disabled on purpose.

    The old shielded-RAG path over-redacted policy text, called Ollama, then
    silently fell back to human review. Knowledge Q&A is local-extractive only.
    """
    raise RuntimeError(
        "Shielded LLM knowledge path is permanently disabled "
        f"({KNOWLEDGE_ENGINE_VERSION}). Use answer_from_local_policy() / "
        "retrieve_context() instead — never call an LLM when policy hits exist."
    )
