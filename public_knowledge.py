"""Enterprise sensitivity gate — open-web vs company-private.

Flow (as designed for ExhaustShield):
  1. Strip numbers and sensitive tokens → generic ask
  2. If strong company-private / HR / custom-report markers → scrub
  3. Else check whether that generic topic appears on the open web
  4. Open-web hit → Safe (no scrub); otherwise treat as company-specific → scrub

"Public" here means available to the common public on the open web —
not "publicly traded company."
"""
from __future__ import annotations

import re
import time
from typing import Any

# Fast-path well-known entities (open-web obvious; avoids a network hop)
_OPEN_WEB_ENTITY_ALLOWLIST = frozenset(
    {
        "microsoft", "apple", "google", "alphabet", "amazon", "meta", "facebook",
        "netflix", "tesla", "nvidia", "intel", "amd", "ibm", "oracle", "salesforce",
        "adobe", "cisco", "samsung", "sony", "toyota", "walmart", "jpmorgan",
        "jp morgan", "goldman sachs", "morgan stanley", "visa", "mastercard",
        "paypal", "uber", "airbnb", "spotify", "twitter", "openai", "anthropic",
        "infosys", "tcs", "wipro", "hcl", "accenture", "deloitte", "cognizant",
        "capgemini", "sap", "siemens", "reliance", "hdfc", "icici", "sbi",
        "exxon", "shell", "unilever", "disney", "verizon", "alibaba", "tencent",
        "flipkart", "paytm", "nasa", "united nations", "world bank", "imf",
    }
)

# Company-private / HR / custom internal — always scrub when present
_PRIVATE_MARKERS_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:our company|our team|our firm|our org(?:anization)?|"
    r"internal only|under NDA|confidential|proprietary|"
    r"do not (?:share|forward|distribute)|trade secret|"
    r"employee id|emp[-_]?\d|badge id|staff id|"
    r"deal ref|opportunity id|opp(?:ortunity)?\s*(?:id|#)|CRM\b|"
    r"base salary|total comp|compensation review|severance|"
    r"payroll|payslip|performance review|PIP\b|"
    r"custom report|internal report|board deck|roster|"
    r"attached (?:file|report|sheet|workbook)|upload(?:ed)?\s+(?:file|report))\b|"
    r"\b(?:my|our)\s+(?:revenue|ebitda|profit|salary|headcount|pipeline)\b|"
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b|"
    r"\b(?:AC|OPP|DEAL|REF|CRM|EMP)[-_]?\d{3,}\b"
    r")"
)

_ORG_CANDIDATE_RE = re.compile(
    r"\b((?:[A-Z][A-Za-z0-9&.\-]*(?:\s+[A-Z][A-Za-z0-9&.\-]*){0,3})"
    r"(?:\s+(?:Inc|Corp|Corporation|Ltd|LLC|Company|Holdings|Partners|"
    r"Ventures|Group|Systems|Solutions|Technologies|Analytics|Consulting|"
    r"Services|Labs|Networks|Dynamics))?|"
    r"[A-Z][a-z]+(?:[A-Z][A-Za-z0-9]+)+)\b"
)

_ORG_STOP = frozenset(
    {
        "the", "our", "and", "for", "with", "from", "this", "that", "what", "how",
        "when", "where", "why", "who", "ebitda", "revenue", "profit", "quarter",
        "growth", "margin", "net", "gross", "usd", "ceo", "cfo", "is", "are",
        "was", "were", "a", "an", "of", "in", "on", "to", "by", "as",
        "yoy", "arr", "mrr", "acv", "tcv", "gaap", "ifrs", "opex", "capex",
        "eps", "roi", "kpi", "q1", "q2", "q3", "q4", "summarize", "analyze",
        "analysis", "report", "please", "thanks",
    }
)

_wiki_cache: dict[str, tuple[bool, float]] = {}
_WIKI_TTL_SEC = 3600.0
_assess_cache: dict[str, tuple[dict[str, Any], float]] = {}
_ASSESS_TTL_SEC = 120.0


def has_private_enterprise_markers(text: str) -> bool:
    """HR / internal / custom-report / identity signals that always need scrubbing."""
    return bool(_PRIVATE_MARKERS_RE.search(text or ""))


def build_generic_query(text: str) -> str:
    """Strip numbers and sensitive tokens — keep the open topical ask."""
    t = text or ""
    t = re.sub(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", " ", t
    )
    t = re.sub(r"\b(?:AC|OPP|DEAL|REF|CRM|EMP)[-_]?\d{3,}\b", " ", t, flags=re.I)
    t = re.sub(
        r"(?i)(?:\$|USD|EUR|GBP|INR|₹)\s*[\d,]+(?:\.\d+)?\s*"
        r"(?:billion|million|thousand|trillion|bn|mn|mm|[BbMmKk])?",
        " ",
        t,
    )
    t = re.sub(r"\d[\d,]*(?:\.\d+)?\s*%", " ", t)
    t = re.sub(r"\d[\d,]*(?:\.\d+)?", " ", t)
    t = re.sub(r"[<>|_]+", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    # Prefer a compact search string
    return t[:220]


def extract_org_candidates(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for m in _ORG_CANDIDATE_RE.finditer(text or ""):
        name = re.sub(r"[.?!,:;]+$", "", (m.group(1) or "").strip()).strip()
        if len(name) < 3:
            continue
        parts = name.split()
        if parts and parts[0].lower() in _ORG_STOP:
            continue
        key = name.lower()
        if key in _ORG_STOP or key.replace(" ", "") in _ORG_STOP:
            continue
        if re.fullmatch(r"(?i)yoy|ebitda|q[1-4]", name):
            continue
        if re.fullmatch(r"[A-Z]{2,6}", name) and key not in _OPEN_WEB_ENTITY_ALLOWLIST:
            continue
        if re.search(r"\d", name) and not re.search(
            r"(?i)\b(?:Inc|Corp|Ltd|LLC|Holdings|Group)\b", name
        ):
            continue
        if key in seen:
            continue
        seen.add(key)
        found.append(name)
        if len(found) >= 8:
            break
    return found


def is_allowlisted_open_web_entity(name: str) -> bool:
    n = re.sub(r"\s+", " ", (name or "").strip().lower())
    if not n:
        return False
    if n in _OPEN_WEB_ENTITY_ALLOWLIST:
        return True
    for pub in _OPEN_WEB_ENTITY_ALLOWLIST:
        if len(n) >= 4 and (n == pub or n.startswith(pub + " ") or pub.startswith(n + " ")):
            return True
    return False


def _wikipedia_supports(query: str) -> bool:
    key = (query or "").strip().lower()
    if not key:
        return False
    now = time.time()
    hit = _wiki_cache.get(key)
    if hit and hit[1] > now:
        return hit[0]

    ok = False
    try:
        from router import _fetch_wikipedia_extracts

        # Prefer entity-sized query (first ~6 words / main org)
        q = query.strip()
        orgs = extract_org_candidates(q)
        search = orgs[0] if orgs else " ".join(q.split()[:8])
        results = _fetch_wikipedia_extracts(search, max_results=2) or []
        tokens = {t for t in re.findall(r"[a-z0-9]+", search.lower()) if len(t) > 2}
        for r in results:
            blob = f"{r.get('title') or ''} {r.get('body') or ''}".lower()
            if not blob.strip():
                continue
            overlap = sum(1 for t in tokens if t in blob)
            if overlap >= max(1, min(3, len(tokens) // 2)):
                ok = True
                break
    except Exception:
        ok = False

    _wiki_cache[key] = (ok, now + _WIKI_TTL_SEC)
    return ok


def open_web_attests(generic_query: str, orgs: list[str]) -> tuple[bool, str]:
    """True when the generic ask (or its main entity) is attested on the open web."""
    for org in orgs:
        if is_allowlisted_open_web_entity(org):
            return True, f"Open-web entity allowlist: {org}"
    # Network: Wikipedia on primary entity or generic skeleton
    if orgs and _wikipedia_supports(orgs[0]):
        return True, f"Open Wikipedia attestation: {orgs[0]}"
    if generic_query and _wikipedia_supports(generic_query):
        return True, "Open Wikipedia attestation for generic ask"
    return False, "No open-web attestation for this ask"


def assess_enterprise_sensitivity(
    text: str, *, allow_network: bool = True
) -> dict[str, Any]:
    """Return whether enterprise scrubbing should run.

    scrub_enterprise True  → company-private / HR / custom / not on open web
    scrub_enterprise False → generic open-web topic → Safe / clear
    """
    raw = text or ""
    cache_key = f"{int(allow_network)}|{hash(raw)}"
    now = time.time()
    cached = _assess_cache.get(cache_key)
    if cached and cached[1] > now:
        return dict(cached[0])

    reasons: list[str] = []
    private = has_private_enterprise_markers(raw)
    generic = build_generic_query(raw)
    orgs = extract_org_candidates(raw)

    # 1) Company-private / HR / custom report → always scrub
    if private:
        result = {
            "scrub_enterprise": True,
            "open_web": False,
            "has_private_markers": True,
            "generic_query": generic,
            "public_orgs": [],
            "private_orgs": orgs[:],
            "public_org_keys": set(),
            "reasons": [
                "Company-private / HR / custom-report markers — scrub before external AI"
            ],
        }
        _assess_cache[cache_key] = (result, now + _ASSESS_TTL_SEC)
        return dict(result)

    # 2) Generic ask attested on open web → Safe / no scrub
    open_web = False
    attest_reason = "Open-web check skipped"
    if allow_network or any(is_allowlisted_open_web_entity(o) for o in orgs):
        if any(is_allowlisted_open_web_entity(o) for o in orgs):
            open_web, attest_reason = True, (
                "Open-web entity: "
                + ", ".join(o for o in orgs if is_allowlisted_open_web_entity(o))[:80]
            )
        elif allow_network:
            open_web, attest_reason = open_web_attests(generic, orgs)

    public_orgs = [o for o in orgs if is_allowlisted_open_web_entity(o) or (
        allow_network and _wikipedia_supports(o)
    )]
    private_orgs = [o for o in orgs if o not in public_orgs]

    if open_web:
        reasons.append(attest_reason)
        reasons.append("Generic ask matches open-web knowledge — Safe / no scrub")
        scrub = False
    else:
        # 3) Not found openly → treat as company-specific / personal
        scrub = True
        if orgs:
            reasons.append(
                "No open-web attestation — treating as company-specific: "
                + ", ".join((private_orgs or orgs)[:4])
            )
        else:
            reasons.append(
                "No open-web attestation for this ask — scrub enterprise specifics"
            )

    result = {
        "scrub_enterprise": scrub,
        "open_web": open_web,
        "has_private_markers": False,
        "generic_query": generic,
        "public_orgs": public_orgs,
        "private_orgs": private_orgs if scrub else [],
        "public_org_keys": {o.lower() for o in public_orgs},
        "reasons": reasons,
    }
    _assess_cache[cache_key] = (result, now + _ASSESS_TTL_SEC)
    if len(_assess_cache) > 64:
        for k, _ in sorted(_assess_cache.items(), key=lambda kv: kv[1][1])[:16]:
            _assess_cache.pop(k, None)
    return dict(result)


def is_public_org_span(value: str, assessment: dict[str, Any] | None = None) -> bool:
    """True if this span is an open-web-known entity (leave clear)."""
    v = (value or "").strip()
    if not v:
        return False
    if is_allowlisted_open_web_entity(v):
        return True
    keys = (assessment or {}).get("public_org_keys") or set()
    vl = v.lower()
    if vl in keys:
        return True
    for pub in keys:
        if pub in vl or vl in pub:
            return True
    # When assessment says open_web overall, don't hide allowlisted-shaped brands
    if (assessment or {}).get("open_web") and is_allowlisted_open_web_entity(v):
        return True
    return False


# Back-compat aliases used by detector/router
def is_allowlisted_public_org(name: str) -> bool:
    return is_allowlisted_open_web_entity(name)


def is_publicly_known_org(name: str, *, allow_network: bool = True) -> bool:
    if is_allowlisted_open_web_entity(name):
        return True
    if not allow_network:
        return False
    return _wikipedia_supports(name)
