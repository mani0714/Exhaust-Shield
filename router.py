"""Exhaust Guardian — 3-level risk router.

Lane contract (stable — do not blur these):

SAFE      → strictly clean (no hide spans, no entropy/risk cues) → external as-is
MODERATE  → business specifics (logos, prices, deal $) → must HIDE/REWRITE
            then external AI (only when outbound text actually changes)
HIGH      → credentials / regulated people-data / PHI / hard IDs
            OR hide-spans that could not be redacted
            → private LLM only (fail-closed; never external)

Strict Safe rule: uncertainty fails UP (Moderate/High), never down to Safe.
"""

from __future__ import annotations

import html as html_lib
import json
import math
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from typing import Any

import requests

from detector import ExhaustDetector, normalize_for_match, text_variants_for_secret_scan

try:
    import truststore

    truststore.inject_into_ssl()
except Exception:
    # Fallback: still try system/default SSL if truststore is unavailable
    pass


def _groq_ssl_context() -> ssl.SSLContext:
    """Python 3.13 sets VERIFY_X509_STRICT by default; some Windows CA chains fail that check."""
    ctx = ssl.create_default_context()
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        try:
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        except Exception:
            pass
    return ctx


try:
    ssl._create_default_https_context = _groq_ssl_context  # type: ignore[attr-defined]
except Exception:
    pass

_GROQ_UA = "ExhaustShield/1.0"

# Force HIGH when these shapes appear (credentials / regulated identifiers)
# Grounded in OWASP LLM Top 10 2025 (LLM01/LLM07), CISA/NSA AI data security,
# GitHub secret-scanning partner patterns, and real exfil cases (e.g. EchoLeak).
HARD_SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"sk-proj-[a-zA-Z0-9_-]+"),
    re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}"),
    re.compile(r"(?i)\bgsk_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bhf_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bxai-[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bAIDA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bAROA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"(?i)\bgho_[A-Za-z0-9]{36}\b"),
    re.compile(r"(?i)\bghu_[A-Za-z0-9]{36}\b"),
    re.compile(r"(?i)\bghr_[A-Za-z0-9]{36}\b"),
    re.compile(r"(?i)\bghs_[A-Za-z0-9]{36}\b"),
    re.compile(r"(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\bglpat-[A-Za-z0-9\-_]{20,}\b"),
    re.compile(r"(?i)\bglrt-[A-Za-z0-9\-_]{20,}\b"),
    re.compile(r"(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"(?i)hooks\.slack\.com/services/[A-Za-z0-9/_+-]{20,}"),
    re.compile(r"(?i)discord(?:app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b"),  # Telegram bot
    re.compile(r"(?i)\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"(?i)\bdapi[a-f0-9]{32}\b"),
    re.compile(r"(?i)\bhvs\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)\bNRAK-[A-Z0-9]{27}\b"),
    re.compile(r"(?i)\blin_api_[A-Za-z0-9]{40,}\b"),
    re.compile(r"(?i)\bpscale_tkn_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\bsq0[a-z]{3}-[0-9A-Za-z\-_]{20,}\b"),
    re.compile(r"(?i)\bsecret_[a-zA-Z0-9]{43}\b"),
    re.compile(
        r"(?i)\b(?:aws_?)?secret_?access_?key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"
    ),
    re.compile(r"(?i)\"type\"\s*:\s*\"service_account\""),
    re.compile(
        r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[^;\s]+"
    ),
    re.compile(
        r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss?|amqp):\/\/"
        r"[^:\s\/]+:[^@\s\/]+@[^\s]+"
    ),
    re.compile(
        r"(?i)\b(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid)\s*[:=]\s*"
        r"[A-Za-z0-9._-]{8,}"
    ),
    re.compile(r"(?i)\\n-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----"),
    # Labeled credentials: key=val AND natural language "key is …" / "password is …"
    # Also match punctuation-folded surfaces ("key: val" → "key val")
    re.compile(
        r"(?i)\b(?:password|passwd|pwd|passphrase|api[_ -]?keys?|secret[_ -]?keys?|client[_ -]?secrets?|"
        r"access[_ -]?tokens?|auth[_ -]?tokens?)\b\s*(?:(?:is|was|are|=|:)\s*)?"
        r"['\"]?(?:sk-|gsk_|hf_|ghp_|xai-|glpat-|xox[baprs]-)?[a-z0-9][a-z0-9$%_.!@#*-]{2,}"
    ),
    re.compile(
        r"(?i)\b(?:openai|anthropic|huggingface|cohere|mistral|groq|gemini|azure[_ -]?openai|"
        r"aws|github|gitlab|slack|stripe|twilio)[_ -]?(?:api[_ -]?)?keys?\b\s*(?:(?:is|was|are|=|:)\s*)?"
        r"['\"]?(?:sk-|gsk_|hf_|ghp_|xai-|glpat-|xox[baprs]-)?[a-z0-9][a-z0-9$%_.-]{2,}"
    ),
    re.compile(
        r"(?i)\b(?:my|our|the)\s+(?:(?:openai|anthropic|huggingface|cohere|mistral|groq|gemini|"
        r"azure|aws|github|gitlab|slack|stripe|twilio)\s+)?(?:api\s+)?keys?\b\s*(?:(?:is|was|are|=|:)\s*)?"
        r"['\"]?(?:sk-|gsk_|hf_|ghp_|xai-|glpat-|xox[baprs]-)?[a-z0-9][a-z0-9$%_.-]{2,}"
    ),
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*"),
    re.compile(r"(?i)\bemp[\s\-_]?\d{3,}\b"),
    re.compile(r"(?i)\b(?:ctr|contractor)[\s\-_]?\d{3,}\b"),
    re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN (dashed)
    # Dashless 9-digit SSN only when labeled (avoids random phone/order IDs)
    re.compile(
        r"(?i)\b(?:ssn|social\s*security(?:\s*number)?)\b\s*[:=]?\s*\d{3}-?\d{2}-?\d{4}\b"
    ),
    re.compile(
        r"(?i)\b(?:ssn|social\s*security(?:\s*number)?)\b\s*[:=]?\s*\d{9}\b"
    ),
    re.compile(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"
    ),
    re.compile(r"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    # People / badge IDs — never send to external AI
    re.compile(r"(?i)\bEMP[-_]?\d{3,}\b"),
    re.compile(r"(?i)\b(?:CTR|contractor)[-_]?\d{3,}\b"),
    # Contact PII — never Safe egress
    re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    # Modern SaaS secrets (2025–2026)
    re.compile(r"(?i)\bsk_live_[0-9a-zA-Z]{16,}\b"),
    re.compile(r"(?i)\bsk_test_[0-9a-zA-Z]{16,}\b"),
    re.compile(r"(?i)\bwhsec_[A-Za-z0-9]+\b"),
    re.compile(r"(?i)\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"(?i)\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    re.compile(r"(?i)\bshpat_[a-fA-F0-9]{32}\b"),
    # Labeled PHI / payment instruments
    re.compile(r"(?i)\b(?:NPI|national provider(?: identifier)?)\b\s*[:=]?\s*\d{10}\b"),
    re.compile(r"(?i)\b(?:MRN|medical record number)\b\s*[:=]?\s*[A-Z0-9-]{4,}\b"),
    re.compile(r"(?i)\b(?:cvv|cvc2?)\b\s*[:=]?\s*\d{3,4}\b"),
    re.compile(r"(?i)\b(?:iban)\b\s*[:=]?\s*[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
]

# Soft business sensitivity can stay moderate (sanitize → external)
# HIGH people/health/security/credentials — basic-knowledge cues + hide spans
HIGH_FORCE_DEPARTMENTS = {"healthcare", "pii"}
# If the detector hid a span in these areas, treat as HIGH (risk → private)
# Expanded 2026: any people / identity / credential / health / finance-instrument hide
HIGH_HIDE_DEPARTMENTS = {
    "healthcare",
    "pii",
    "engineering",
    "security",
    "hr",
}
SAFE_MAX_SCORE = 25
MODERATE_MAX_SCORE = 65

# ---------------------------------------------------------------------------
# HIGH-risk catalog (2025–2026 enterprise DLP / GenAI egress — max fail-closed)
# Anything matching these language cues → private AI only (never Safe egress).
# ---------------------------------------------------------------------------
HIGH_RISK_CATALOG: list[dict[str, str]] = [
    {"category": "Identity / PII", "examples": "username, user name, login, full name, employee/customer/patient name, DOB, address, email, phone, national ID, passport, Aadhaar, PAN, SSN"},
    {"category": "Authentication", "examples": "password, passphrase, OTP, MFA/2FA codes, security questions, session/cookie IDs, bearer tokens, PHPSESSID/JSESSIONID"},
    {"category": "API & cloud secrets", "examples": "API keys (OpenAI/Groq/AWS/GCP/Azure/GitHub/GitLab/Slack/Stripe/Twilio…), JWTs, private keys, .env, connection strings, Vault hvs., npm_/dapi tokens"},
    {"category": "Webhook / exfil channels", "examples": "Slack hooks.slack.com/services/…, Discord webhook URLs, Telegram bot tokens"},
    {"category": "Cloud credential blobs", "examples": "GCP service_account JSON, Azure DefaultEndpointsProtocol+AccountKey, AWS secret_access_key=…"},
    {"category": "HR / people", "examples": "EMP/CTR IDs, salary, compensation, severance, PIP, performance, background check"},
    {"category": "PHI / health", "examples": "patient, diagnosis, prescription, MRN, NPI, medical record, insurance member ID, lab results"},
    {"category": "PCI / payments", "examples": "credit/debit card, PAN, CVV, IBAN, SWIFT, routing number, bank account"},
    {"category": "Biometric / device", "examples": "fingerprint, face ID, voice print, IMEI, IMSI, IDFA, GAID, device ID"},
    {"category": "Location / network", "examples": "GPS/geolocation, home address, IP address, MAC address"},
    {"category": "Special category (GDPR)", "examples": "religion, political opinion, sexual orientation, trade union, children’s data / COPPA"},
    {"category": "Security incidents", "examples": "incident ID, breach, vulnerability, exploit, ransomware, zero-day"},
    {"category": "Source / infra", "examples": "source code dump, kubeconfig, terraform state, vault path, prod cluster secrets, credentialed DB URIs"},
    {
        "category": "Dynamic basic-knowledge (not only a fixed list)",
        "examples": (
            "Structural inference across identity, auth, health, PCI, HR, biometrics, "
            "location, incidents — topic+value co-occurrence, labeled assignments, "
            "enterprise login shapes; not a phrase allowlist alone"
        ),
    },
]

# Words that look like "* id" but are usually not identity secrets in prose
_ID_LABEL_STOPWORDS = frozenset(
    {
        "this",
        "that",
        "an",
        "the",
        "a",
        "any",
        "some",
        "no",
        "valid",
        "unique",
        "same",
        "other",
        "each",
        "every",
        "new",
        "old",
        "first",
        "last",
        "next",
        "prior",
        "slide",
        "page",
        "line",
        "row",
        "column",
        "chapter",
        "section",
        "step",
        "item",
        "ticket",
        "case",
        "request",
        "message",
        "post",
        "comment",
        "thread",
        "build",
        "commit",
        "run",
        "job",
        "task",
        "game",
        "match",
        "team",
        "player",
        "place",  # "3rd place" style
        # CRM / commercial IDs — Medium hide, not identity HIGH
        "opportunity",
        "opp",
        "deal",
        "quote",
        "pipeline",
        "order",
        "invoice",
        "po",
        "sku",
        "campaign",
        "lead",
        "prospect",
    }
)

# Enterprise systems where "login" / "id" is almost always credential/identity
_ENTERPRISE_AUTH_SYSTEMS = (
    r"sap|erp|oracle|workday|okta|salesforce|servicenow|successfactors|concur|"
    r"azure\s+ad|active\s+directory|ldap|sso|vpn|citrix|jira|confluence|"
    r"github|gitlab|aws|azure|gcp|office\s*365|o365|teams|slack"
)

# Basic-knowledge HIGH cues (case/punct insensitive via normalize_for_match).
# Fail closed to private AI — do not require exact punctuation or a hide span.
BASIC_HIGH_RISK_CUES = [
    # --- Identity / usernames / people names (the Safe leak that must not slip) ---
    re.compile(
        r"\b(?:user\s*names?|usernames?|user\s*ids?|userids?|login\s*names?|login\s*ids?|"
        r"display\s*names?|account\s*names?|account\s*ids?|screen\s*names?|handle\s*names?|"
        r"session\s*ids?|sessionids?|cookie\s*ids?)\b"
    ),
    re.compile(
        r"\b(?:full\s*names?|legal\s*names?|given\s*names?|family\s*names?|surnames?|"
        r"maiden\s*names?|employee\s*names?|customer\s*names?|client\s*names?|"
        r"patient\s*names?|vendor\s*names?|contractor\s*names?)\b"
    ),
    re.compile(r"\b(?:my|our|their|his|her|the)\s+names?\s+(?:is|was|are|equals?)\b"),
    re.compile(
        r"\b(?:user|employee|customer|client|patient|vendor|contractor|full|legal|"
        r"display|account|login)\s+names?\s*(?:is|was|are|=|:)\b"
    ),
    re.compile(r"\b(?:date of birth|dob|place of birth|mother s maiden)\b"),
    re.compile(r"\b(?:home|mailing|residential|billing|shipping)\s+address\b"),
    re.compile(
        r"\b(?:personal\s+email|personal\s+phone|email\s+address|phone\s+number|"
        r"mobile\s+number|cell\s+number|home\s+phone)\b"
    ),
    re.compile(
        r"\b(?:email|e-mail|phone|mobile|cell)\s*(?:is|was|are|=|:)\s*\S+"
    ),
    re.compile(r"\b(?:passport|driver s? license|national id|aadhaar|pan card|voter id|nin|nric)\b"),
    re.compile(r"\b(?:ssn|social security|tax id|itin)\b"),
    # --- Auth / credentials ---
    re.compile(r"\b(?:api|secret|access|private|auth|encryption|master|app|sdk|server)\s+keys?\b"),
    re.compile(
        r"\b(?:groq|openai|anthropic|huggingface|aws|github|gitlab|slack|stripe|twilio|"
        r"azure|gcp|google|cohere|mistral|gemini|datadog|sentry|sendgrid|shopify)\s+(?:api\s+)?keys?\b"
    ),
    re.compile(
        r"\b(?:password|passwd|pwd|passphrase|credentials?|client\s+secret|"
        r"shared\s+secret|signing\s+secret|webhook\s+secret)\b"
    ),
    re.compile(
        r"\b(?:bearer|private\s+key|secret\s+token|access\s+token|refresh\s+token|"
        r"id\s+token|session\s+token|auth\s+token|oauth|otp|one time password|"
        r"mfa|2fa|verification\s+code|security\s+question)\b"
    ),
    re.compile(r"\b(?:\.env|env file|kubeconfig|terraform state|vault path|connection string)\b"),
    re.compile(r"\b(?:slack webhook|discord webhook|webhook url|hooks\.slack)\b"),
    re.compile(r"\b(?:vault token|hashicorp vault|service account json|accountkey)\b"),
    re.compile(r"\b(?:session cookie|jsessionid|phpsessid|connect\.sid)\b"),
    # --- HR ---
    re.compile(r"\b(?:ssn|social\s+security|emp\s*\d+|employee\s+id|badge\s+id|contractor\s+id)\b"),
    re.compile(
        r"\b(?:salary|compensation|severance|base\s+pay|bonus|equity grant|stock options?|"
        r"performance\s+improvement|pip\b|background\s+check)\b"
    ),
    # --- Health / PHI ---
    re.compile(
        r"\b(?:patient|phi|ephi|medical\s+record|mrn|npi|diagnosis|prescription|lab\s+result|"
        r"health\s+insurance|hipaa|clinical\s+notes?|member\s+id|subscriber\s+id)\b"
    ),
    # --- Payments / PCI ---
    re.compile(
        r"\b(?:credit\s+card|debit\s+card|card\s+number|cvv|cvc|iban|swift|routing\s+number|"
        r"bank\s+account|account\s+number|pan\b|pci)\b"
    ),
    # --- Biometric / device / network ---
    re.compile(r"\b(?:biometric|fingerprint|face\s+id|retina|voice\s+print|facial\s+recognition)\b"),
    re.compile(r"\b(?:imei|imsi|idfa|gaid|android\s+id|device\s+id|mac\s+address|ip\s+address)\b"),
    re.compile(r"\b(?:geolocation|gps\s+coordinates|latitude|longitude)\b"),
    # --- Special category / minors ---
    re.compile(
        r"\b(?:religion|political\s+opinion|sexual\s+orientation|trade\s+union|"
        r"children s?\s+data|under\s+13|under\s+16|coppa)\b"
    ),
    # --- Security / IP ---
    re.compile(
        r"\b(?:security\s+incident|data\s+breach|zero[- ]day|ransomware|exploit|"
        r"vulnerability|cve-\d+|incident\s+id)\b"
    ),
    re.compile(r"\b(?:source\s+code|heap\s+dump|core\s+dump|stack\s+trace|proprietary\s+algorithm)\b"),
    re.compile(r"\b(?:confidential|internal only|do not (?:share|distribute|forward)|restricted|pii|spi)\b"),
]

# High-entropy blobs that look like secrets even without a vendor prefix
_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=]{28,}")
# Triggers DuckDuckGo snippets before Groq — Groq itself has no live KB.
_LIVE_KNOWLEDGE_RE = re.compile(
    r"(?i)\b("
    r"who\s+won|who\s+is|who\s+are|who\s+was|what\s+happened|what\s+is|what\s+are|"
    r"when\s+(?:is|was|did|does|will)|where\s+(?:is|was|are)|which\s+"
    r"|how\s+(?:many|much|old|long|did|does|is|are)|why\s+"
    r"|latest|today|tonight|yesterday|this\s+(?:morning|afternoon|evening|week|month|year)|"
    r"current|recent|breaking|update(?:s|d)?|\bnow\b|live\s+(?:score|results?)|"
    r"202[4-9]|20[3-9]\d|score|result|results|election|match|fixture|"
    r"ballon|fifa|world\s*cup|olympics|premier\s+league|ipl|nba|nfl|cricket|football|"
    r"weather|forecast|stock|share\s+price|market|news|headline|"
    r"ceo\s+of|prime\s+minister|president\s+of|released|launched|"
    r"happening|trending|standings|winner|champion|"
    # Commodities / bullion / FX — always need live rates
    r"gold\s+rate|silver\s+rate|platinum\s+rate|gold\s+price|silver\s+price|"
    r"bullion|carat|\d+\s*k\s+gold|per\s+gram|per\s+ounce|spot\s+price|"
    r"crude\s+oil|petrol\s+price|diesel\s+price|fuel\s+price|"
    r"usd\s+to|inr\s+to|exchange\s+rate|forex|currency\s+rate"
    r")\b"
)
# Commodity / rate asks even without "today" / "what is"
_LIVE_RATE_RE = re.compile(
    r"(?i)\b("
    r"(?:gold|silver|platinum|bullion).{0,24}(?:rate|price|cost)|"
    r"(?:rate|price|cost).{0,24}(?:gold|silver|platinum|bullion)|"
    r"(?:22k|24k|18k|22\s*carat|24\s*carat).{0,16}(?:gold|rate|price)|"
    r"per\s+gram|per\s+ounce|spot\s+price|"
    r"(?:petrol|diesel|fuel|crude).{0,16}(?:price|rate)|"
    r"exchange\s+rate|forex|"
    r"(?:usd|inr|eur|gbp|jpy|cny|aud|cad|chf|sgd|hkd|aed)\s*(?:to|/)\s*"
    r"(?:usd|inr|eur|gbp|jpy|cny|aud|cad|chf|sgd|hkd|aed)|"
    # Equities / indices / share market (global)
    r"share\s+price|stock\s+price|share\s+market|stock\s+market|"
    r"nifty(?:\s*50)?|sensex|nasdaq|dow\s+jones|s&p\s*500|"
    r"ftse|nikkei|hang\s+seng|dax|cac\s*40|asx|kospi|shanghai\s+composite|"
    r"\b(?:nse|bse|mcx|nyse|lse|tsx|hkex)\b|"
    r"(?:open|high|low|close|ltp|cmp|market\s+cap).{0,12}(?:price|today)|"
    r"(?:price|quote|trading\s+at).{0,20}(?:share|stock)|"
    r"\b[A-Z]{1,5}(?:\.[A-Z]{1,3})?\b.{0,12}(?:share|stock)\s+price|"
    r"(?:tcs|infosys|reliance|hdfc|icici|wipro|apple|microsoft|tesla|amazon|"
    r"toyota|samsung|sony|shell|bp|toyota|alibaba|tencent)\b.{0,20}(?:share|stock|price)"
    r")"
)

# Yahoo Finance symbol aliases — global indices, FX, mega-caps (search covers the rest)
_YAHOO_SYMBOL_RULES: list[tuple[re.Pattern[str], str, str]] = [
    # Indices — India / US / Europe / Asia
    (re.compile(r"(?i)\bnifty(?:\s*50)?\b|\bnsei\b"), "^NSEI", "Nifty 50"),
    (re.compile(r"(?i)\bsensex\b|\bbse\s*sensex\b"), "^BSESN", "Sensex"),
    (re.compile(r"(?i)\bnasdaq\b"), "^IXIC", "NASDAQ Composite"),
    (re.compile(r"(?i)\bdow\s+jones\b|\bdjia\b"), "^DJI", "Dow Jones"),
    (re.compile(r"(?i)\bs&p\s*500\b|\bspx\b"), "^GSPC", "S&P 500"),
    (re.compile(r"(?i)\bftse\s*100\b|\buk\s+100\b"), "^FTSE", "FTSE 100"),
    (re.compile(r"(?i)\bnikkei\b"), "^N225", "Nikkei 225"),
    (re.compile(r"(?i)\bhang\s+seng\b|\bhsi\b"), "^HSI", "Hang Seng"),
    (re.compile(r"(?i)\bdax\b"), "^GDAXI", "DAX"),
    (re.compile(r"(?i)\bcac\s*40\b"), "^FCHI", "CAC 40"),
    (re.compile(r"(?i)\basx\s*200\b"), "^AXJO", "ASX 200"),
    (re.compile(r"(?i)\bkospi\b"), "^KS11", "KOSPI"),
    # India mega-caps
    (re.compile(r"(?i)\btcs\b|tata\s+consultancy"), "TCS.NS", "TCS"),
    (re.compile(r"(?i)\binfosys\b|\binfy\b"), "INFY.NS", "Infosys"),
    (re.compile(r"(?i)\breliance\b"), "RELIANCE.NS", "Reliance Industries"),
    (re.compile(r"(?i)\bhdfc\s*bank\b"), "HDFCBANK.NS", "HDFC Bank"),
    (re.compile(r"(?i)\bicici\s*bank\b"), "ICICIBANK.NS", "ICICI Bank"),
    (re.compile(r"(?i)\bwipro\b"), "WIPRO.NS", "Wipro"),
    (re.compile(r"(?i)\bsbi\b|state\s+bank\s+of\s+india"), "SBIN.NS", "SBI"),
    # US mega-caps
    (re.compile(r"(?i)\bapple\b|\baapl\b"), "AAPL", "Apple"),
    (re.compile(r"(?i)\bmicrosoft\b|\bmsft\b"), "MSFT", "Microsoft"),
    (re.compile(r"(?i)\bgoogle\b|\balphabet\b|\bgoogl\b"), "GOOGL", "Alphabet"),
    (re.compile(r"(?i)\bamazon\b|\bamzn\b"), "AMZN", "Amazon"),
    (re.compile(r"(?i)\btesla\b|\btsla\b"), "TSLA", "Tesla"),
    (re.compile(r"(?i)\bmeta\b|\bfacebook\b"), "META", "Meta"),
    (re.compile(r"(?i)\bnvidia\b|\bnvda\b"), "NVDA", "NVIDIA"),
    # Global names
    (re.compile(r"(?i)\btoyota\b"), "TM", "Toyota"),
    (re.compile(r"(?i)\bsamsung\b"), "005930.KS", "Samsung Electronics"),
    (re.compile(r"(?i)\bsony\b"), "SONY", "Sony"),
    (re.compile(r"(?i)\balibaba\b|\bbaba\b"), "BABA", "Alibaba"),
    (re.compile(r"(?i)\btencent\b"), "0700.HK", "Tencent"),
    (re.compile(r"(?i)\bshell\b"), "SHEL", "Shell"),
    (re.compile(r"(?i)\bbp\b(?!\w)"), "BP", "BP"),
    # FX majors
    (re.compile(r"(?i)\busd\s*(?:to|/)?\s*inr\b|\bdollar\s+to\s+rupee\b"), "USDINR=X", "USD/INR"),
    (re.compile(r"(?i)\beur\s*(?:to|/)?\s*inr\b"), "EURINR=X", "EUR/INR"),
    (re.compile(r"(?i)\bgbp\s*(?:to|/)?\s*inr\b"), "GBPINR=X", "GBP/INR"),
    (re.compile(r"(?i)\busd\s*(?:to|/)?\s*eur\b|\beur\s*(?:to|/)?\s*usd\b"), "EURUSD=X", "EUR/USD"),
    (re.compile(r"(?i)\busd\s*(?:to|/)?\s*jpy\b|\bjpy\s*(?:to|/)?\s*usd\b"), "USDJPY=X", "USD/JPY"),
    (re.compile(r"(?i)\bgbp\s*(?:to|/)?\s*usd\b|\busd\s*(?:to|/)?\s*gbp\b"), "GBPUSD=X", "GBP/USD"),
    (re.compile(r"(?i)\busd\s*(?:to|/)?\s*cny\b|\byuan\b"), "USDCNY=X", "USD/CNY"),
    (re.compile(r"(?i)\baud\s*(?:to|/)?\s*usd\b"), "AUDUSD=X", "AUD/USD"),
    # Commodities / crypto
    (re.compile(r"(?i)\bgold\b"), "GC=F", "Gold futures"),
    (re.compile(r"(?i)\bsilver\b"), "SI=F", "Silver futures"),
    (re.compile(r"(?i)\bcrude\b|\bwti\b"), "CL=F", "Crude oil WTI"),
    (re.compile(r"(?i)\brent\b"), "BZ=F", "Brent crude"),
    (re.compile(r"(?i)\bbitcoin\b|\bbtc\b"), "BTC-USD", "Bitcoin"),
    (re.compile(r"(?i)\bethereum\b|\beth\b"), "ETH-USD", "Ethereum"),
]
# Pure drafting — skip live search (no public-fact lookup needed).
_LIVE_SKIP_RE = re.compile(
    r"(?i)^\s*(summarize|rewrite|rephrase|translate|polish|format|bullet(?:ize)?|"
    r"make this|turn this into|convert this)\b"
)
# Creative / generative prompts — skip live unless they also ask a fact.
_LIVE_CREATIVE_RE = re.compile(
    r"(?i)^\s*(write|compose|draft|brainstorm|invent|create|generate|poem|story|"
    r"song|joke|email|letter|essay|blog|linkedin|tweet|caption)\b"
)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
# Groq retired Llama 3.3 70B / 3.1 8B on 2026-08-16. Current defaults:
DEFAULT_EXTERNAL_AI_MODEL = "openai/gpt-oss-120b"
DEFAULT_EXTERNAL_AI_FALLBACK_MODEL = "openai/gpt-oss-20b"
_RETIRED_GROQ_MODELS = {
    "llama-3.3-70b-versatile": DEFAULT_EXTERNAL_AI_MODEL,
    "llama-3.1-8b-instant": DEFAULT_EXTERNAL_AI_FALLBACK_MODEL,
    "llama3-70b-8192": DEFAULT_EXTERNAL_AI_MODEL,
    "llama3-8b-8192": DEFAULT_EXTERNAL_AI_FALLBACK_MODEL,
    "llama-3.1-70b-versatile": DEFAULT_EXTERNAL_AI_MODEL,
    "qwen/qwen3-32b": DEFAULT_EXTERNAL_AI_MODEL,
    "meta-llama/llama-4-scout-17b-16e-instruct": DEFAULT_EXTERNAL_AI_MODEL,
}

# Defaults — prefer live_external_config() at call time so bat/env reloads apply.
EXTERNAL_AI_BASE_URL = os.getenv("EXTERNAL_AI_BASE_URL", "").rstrip("/")
EXTERNAL_AI_API_KEY = os.getenv("EXTERNAL_AI_API_KEY", "")
EXTERNAL_AI_MODEL = os.getenv("EXTERNAL_AI_MODEL", DEFAULT_EXTERNAL_AI_MODEL)
EXTERNAL_AI_MODE = os.getenv("EXTERNAL_AI_MODE", "simulate").lower()
EXTERNAL_AI_LIVE_SEARCH = os.getenv("EXTERNAL_AI_LIVE_SEARCH", "1").lower() not in {
    "0",
    "false",
    "no",
    "off",
}
EXTERNAL_AI_FALLBACK_MODEL = os.getenv(
    "EXTERNAL_AI_FALLBACK_MODEL", DEFAULT_EXTERNAL_AI_FALLBACK_MODEL
)
# Extra emergency fallback if primary + configured fallback both fail
_EXTERNAL_AI_LAST_RESORT_MODEL = DEFAULT_EXTERNAL_AI_FALLBACK_MODEL
_PROBE_CACHE: dict[str, Any] = {"t": 0.0, "result": None}
# Soft (AV/proxy) failures stay short-lived; hard failures (bad key) stick longer.
_LIVE_RUNTIME: dict[str, Any] = {
    "degraded": False,
    "soft": False,
    "live_ok": False,
    "reason": "",
}
_SOFT_DEGRADE_SEC = 8.0
_HARD_DEGRADE_SEC = 45.0
_LIVE_WEB_CACHE: dict[str, Any] = {"t": 0.0, "result": None}


def _canonical_groq_model(model_id: str | None, *, default: str) -> str:
    mid = (model_id or "").strip()
    if not mid:
        return default
    return _RETIRED_GROQ_MODELS.get(mid, mid)


def refresh_external_ai_config() -> dict[str, Any]:
    """Re-read EXTERNAL_AI_* from the process environment (after bat/key load)."""
    global EXTERNAL_AI_BASE_URL, EXTERNAL_AI_API_KEY, EXTERNAL_AI_MODEL
    global EXTERNAL_AI_MODE, EXTERNAL_AI_LIVE_SEARCH, EXTERNAL_AI_FALLBACK_MODEL
    EXTERNAL_AI_BASE_URL = (os.getenv("EXTERNAL_AI_BASE_URL") or "").rstrip("/")
    EXTERNAL_AI_API_KEY = os.getenv("EXTERNAL_AI_API_KEY") or ""
    EXTERNAL_AI_MODEL = _canonical_groq_model(
        os.getenv("EXTERNAL_AI_MODEL"), default=DEFAULT_EXTERNAL_AI_MODEL
    )
    EXTERNAL_AI_MODE = (os.getenv("EXTERNAL_AI_MODE") or "simulate").lower()
    EXTERNAL_AI_LIVE_SEARCH = (os.getenv("EXTERNAL_AI_LIVE_SEARCH") or "1").lower() not in {
        "0",
        "false",
        "no",
        "off",
    }
    EXTERNAL_AI_FALLBACK_MODEL = _canonical_groq_model(
        os.getenv("EXTERNAL_AI_FALLBACK_MODEL"),
        default=DEFAULT_EXTERNAL_AI_FALLBACK_MODEL,
    )
    return {
        "mode": EXTERNAL_AI_MODE,
        "base_url": EXTERNAL_AI_BASE_URL,
        "model": EXTERNAL_AI_MODEL,
        "fallback_model": EXTERNAL_AI_FALLBACK_MODEL,
        "live_search": EXTERNAL_AI_LIVE_SEARCH,
        "api_key": EXTERNAL_AI_API_KEY,
        "has_key": bool(EXTERNAL_AI_API_KEY) and len(EXTERNAL_AI_API_KEY) >= 20,
    }


def live_external_config() -> dict[str, Any]:
    """Fresh config for each outbound call (never trust stale import-time values alone)."""
    return refresh_external_ai_config()


def _is_av_or_local_block(err: str | None) -> bool:
    """Avast/AVG (aswMonFlt), WinError 5, and similar local blocks of Python HTTPS."""
    e = (err or "").lower()
    return any(
        token in e
        for token in (
            "aswmonflt",
            "permission denied",
            "errno 13",
            "winerror 5",
            "access is denied",
            "antivirus",
            "avast",
            "avg ",
        )
    )


def mark_external_degraded(reason: str) -> None:
    """Mark Groq unreachable. Soft (AV/proxy) blocks expire quickly and still retry live."""
    reason_s = (reason or "unreachable")[:180]
    soft = _is_av_or_local_block(reason_s) or _is_transport_error(reason_s)
    _LIVE_RUNTIME["degraded"] = True
    _LIVE_RUNTIME["soft"] = soft
    _LIVE_RUNTIME["live_ok"] = False
    _LIVE_RUNTIME["reason"] = reason_s
    _PROBE_CACHE["t"] = 0.0
    _PROBE_CACHE["result"] = None
    kind = "soft" if soft else "hard"
    print(f"[ExhaustShield] Groq unavailable ({kind}) → backup ({reason_s})")


def mark_external_live_ok() -> None:
    _LIVE_RUNTIME["degraded"] = False
    _LIVE_RUNTIME["soft"] = False
    _LIVE_RUNTIME["live_ok"] = True
    _LIVE_RUNTIME["reason"] = "ok"


def external_runtime_status() -> dict[str, Any]:
    cfg = live_external_config()
    degraded = bool(_LIVE_RUNTIME.get("degraded"))
    soft = bool(_LIVE_RUNTIME.get("soft"))
    live_ok = bool(_LIVE_RUNTIME.get("live_ok")) and not degraded
    wanted = cfg.get("mode") or "simulate"
    if wanted != "live":
        effective = "simulate"
    elif live_ok:
        effective = "live"
    else:
        effective = "backup"
    return {
        "wanted_mode": wanted,
        "effective_mode": effective,
        "degraded": degraded,
        "soft": soft,
        "live_ok": live_ok,
        "reason": _LIVE_RUNTIME.get("reason") or "",
        "demo_ready": True,
    }


def probe_external_ai(*, force: bool = False, timeout: float = 6.0) -> dict[str, Any]:
    """Groq reachability. Soft AV blocks expire fast; curl fallback recovers live."""
    try:
        return _probe_external_ai_inner(force=force, timeout=timeout)
    except Exception as exc:
        reason = f"probe_error:{exc}"[:180]
        mark_external_degraded(reason)
        return {
            "mode": (os.getenv("EXTERNAL_AI_MODE") or "simulate").lower(),
            "configured": True,
            "reachable": False,
            "model": os.getenv("EXTERNAL_AI_MODEL") or DEFAULT_EXTERNAL_AI_MODEL,
            "fallback_model": os.getenv("EXTERNAL_AI_FALLBACK_MODEL")
            or DEFAULT_EXTERNAL_AI_FALLBACK_MODEL,
            "model_available": None,
            "reason": reason,
            "demo_ready": True,
            "degraded": True,
            "soft": _is_av_or_local_block(reason) or _is_transport_error(reason),
            "effective_mode": "backup",
        }


def _probe_external_ai_inner(*, force: bool = False, timeout: float = 6.0) -> dict[str, Any]:
    cfg = live_external_config()
    now = time.time()
    runtime = external_runtime_status()
    result: dict[str, Any] = {
        "mode": cfg["mode"],
        "configured": cfg["mode"] == "live",
        "reachable": False,
        "model": cfg["model"],
        "fallback_model": cfg["fallback_model"],
        "model_available": None,
        "reason": "",
        "demo_ready": True,
        "degraded": runtime["degraded"],
        "soft": runtime.get("soft", False),
        "effective_mode": runtime["effective_mode"],
    }
    # Soft AV/proxy: short cool-down. Hard failures: longer. Then retry live.
    if runtime["degraded"] and not force:
        last = float(_PROBE_CACHE.get("t") or 0)
        cool = _SOFT_DEGRADE_SEC if runtime.get("soft") else _HARD_DEGRADE_SEC
        if now - last < cool:
            result["reason"] = runtime["reason"] or "backup"
            return result
        mark_external_live_ok()
        runtime = external_runtime_status()
        result["degraded"] = False
        result["soft"] = False
        result["effective_mode"] = runtime["effective_mode"]
    cached = _PROBE_CACHE.get("result")
    if (
        not force
        and isinstance(cached, dict)
        and now - float(_PROBE_CACHE.get("t") or 0) < 20
        and cached.get("reachable")
    ):
        return cached

    if cfg["mode"] != "live":
        result["reason"] = "simulate"
        result["effective_mode"] = "simulate"
        _PROBE_CACHE["t"] = now
        _PROBE_CACHE["result"] = result
        return result
    if not cfg["has_key"]:
        result["reason"] = "missing_key"
        mark_external_degraded("missing_key")
        result["degraded"] = True
        result["soft"] = False
        result["effective_mode"] = "backup"
        _PROBE_CACHE["t"] = now
        _PROBE_CACHE["result"] = result
        return result
    if not cfg["base_url"]:
        result["reason"] = "missing_base_url"
        mark_external_degraded("missing_base_url")
        result["degraded"] = True
        result["soft"] = False
        result["effective_mode"] = "backup"
        _PROBE_CACHE["t"] = now
        _PROBE_CACHE["result"] = result
        return result

    url = f"{cfg['base_url'].rstrip('/')}/models"
    headers = {"Authorization": f"Bearer {cfg['api_key']}"}
    payload, err = _http_json("GET", url, headers=headers, timeout=timeout)
    if err or not isinstance(payload, dict):
        reason = err or "empty_probe"
        mark_external_degraded(reason)
        result["reason"] = reason[:180]
        result["degraded"] = True
        result["soft"] = bool(_LIVE_RUNTIME.get("soft"))
        result["effective_mode"] = "backup"
    else:
        ids = {
            str(item.get("id") or "")
            for item in (payload.get("data") or [])
            if isinstance(item, dict)
        }
        result["reachable"] = True
        result["model_available"] = (cfg["model"] in ids) if ids else None
        if ids and cfg["model"] not in ids:
            result["reason"] = f"model_not_listed:{cfg['model']}"
        else:
            result["reason"] = "ok"
        mark_external_live_ok()
        result["effective_mode"] = "live"
        result["degraded"] = False
        result["soft"] = False

    _PROBE_CACHE["t"] = now
    _PROBE_CACHE["result"] = result
    return result


def _is_transport_error(err: str | None) -> bool:
    e = (err or "").lower()
    return any(
        token in e
        for token in (
            "network:",
            "permission",
            "timeout",
            "connection aborted",
            "connecttimeout",
            "nameresolution",
            "urllib:",
            "failed to establish",
            "10061",
            "10054",
            "aswmonflt",
            "curl:",
        )
    )


def _external_http_session() -> requests.Session:
    """Ignore broken Windows/corporate proxies. Never set proxy values to None."""
    session = requests.Session()
    session.trust_env = False
    session.proxies = {}
    return session


def _http_json_urllib(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict | None,
    timeout: float,
) -> tuple[dict | None, str | None]:
    merged = {
        "User-Agent": _GROQ_UA,
        "Accept": "application/json",
        **(headers or {}),
    }
    data = None if json_body is None else json.dumps(json_body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=merged, method=method)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=_groq_ssl_context()),
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            if resp.status != 200:
                return None, f"HTTP {resp.status}: {raw[:160]}"
            return json.loads(raw) if raw else {}, None
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")[:160]
        except Exception:
            body = ""
        return None, f"HTTP {exc.code}: {body}"
    except Exception as exc:
        return None, f"urllib: {exc}"


def _http_json_curl(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict | None,
    timeout: float,
) -> tuple[dict | None, str | None]:
    """Windows curl.exe + Schannel — bypasses Avast hooks that break Python HTTPS."""
    curl = shutil.which("curl") or shutil.which("curl.exe")
    if not curl:
        return None, "curl: not found"
    merged = {
        "User-Agent": _GROQ_UA,
        "Accept": "application/json",
        **(headers or {}),
    }
    cmd = [
        curl,
        "-sS",
        "-X",
        method.upper(),
        "--noproxy",
        "*",
        "--max-time",
        str(max(3, int(timeout))),
        "-H",
        "Content-Type: application/json",
    ]
    for k, v in merged.items():
        cmd.extend(["-H", f"{k}: {v}"])
    body_file = None
    try:
        if json_body is not None:
            body_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            )
            json.dump(json_body, body_file)
            body_file.close()
            cmd.extend(["--data-binary", f"@{body_file.name}"])
        cmd.extend(["-w", "\n%{http_code}", url])
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(4.0, float(timeout) + 2.0),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = completed.stdout or ""
        err = (completed.stderr or "").strip()
        if completed.returncode != 0 and not out.strip():
            return None, f"curl: {err or completed.returncode}"[:180]
        # Split trailing HTTP code line
        if "\n" in out:
            body, code_s = out.rsplit("\n", 1)
        else:
            body, code_s = out, "0"
        try:
            code = int(code_s.strip() or "0")
        except ValueError:
            body, code = out, 0
        if code != 200:
            return None, f"curl HTTP {code}: {(body or err)[:160]}"
        return (json.loads(body) if body.strip() else {}), None
    except Exception as exc:
        return None, f"curl: {exc}"[:180]
    finally:
        if body_file is not None:
            try:
                os.unlink(body_file.name)
            except Exception:
                pass


def _http_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict | None = None,
    timeout: float = 8.0,
) -> tuple[dict | None, str | None]:
    """urllib → requests → curl.exe. Curl recovers when Avast blocks Python SSL."""
    errors: list[str] = []
    payload, err = _http_json_urllib(
        method, url, headers=headers, json_body=json_body, timeout=timeout
    )
    if not err:
        return payload, None
    errors.append(err)

    try:
        merged = {
            "User-Agent": _GROQ_UA,
            "Accept": "application/json",
            **(headers or {}),
        }
        with _external_http_session() as session:
            if method.upper() == "GET":
                response = session.get(url, headers=merged, timeout=timeout)
            else:
                response = session.post(
                    url, headers=merged, json=json_body, timeout=timeout, verify=True
                )
        if response.status_code == 200:
            return (response.json() if response.content else {}), None
        errors.append(f"HTTP {response.status_code}: {response.text[:160]}")
    except Exception as exc:
        errors.append(f"network: {exc}")

    # Always try curl last — recovers when Avast/AVG hooks break Python HTTPS.
    payload, err = _http_json_curl(
        method, url, headers=headers, json_body=json_body, timeout=timeout
    )
    if not err:
        return payload, None
    errors.append(err)

    return None, " | ".join(errors)[:280]

def _backup_external_reply(
    prompt: str,
    *,
    sanitized: bool,
    snippets: list[dict[str, str]] | None = None,
) -> str:
    """Always-usable outside-AI answer so a presentation never dies on Groq."""
    snippets = snippets or []
    if snippets:
        lines = ["Here is what public sources currently say:", ""]
        for sn in snippets[:4]:
            title = sn.get("title") or "Source"
            body = sn.get("body") or ""
            lines.append(f"• {title}: {body}" if body else f"• {title}")
        lines.append("")
        lines.append("I only used the approved outbound text plus those public snippets.")
        return "\n".join(lines)
    shown = (prompt or "").strip()
    if len(shown) > 360:
        shown = shown[:360] + "…"
    if sanitized:
        return (
            "Understood. I can work from the approved outbound text only.\n\n"
            "Labeled stand-ins (company, employee, customer) are treated as ordinary "
            "references — I will not guess the hidden names or figures. "
            "Tell me what you want next using the same approved wording.\n\n"
            f"What I received:\n{shown}"
        )
    return (
        "Understood. Here is a concise take based only on what you sent.\n\n"
        "I can help with the general request. I do not see your private vault from "
        "this external side — only the text that was approved to leave the device.\n\n"
        f"What I received:\n{shown}"
    )


def _intentional_simulate_reply(prompt: str, *, sanitized: bool, model: str) -> str:
    lane_note = (
        "SANITIZED prompt forwarded to external platform"
        if sanitized
        else "CLEAR prompt forwarded to external platform (safe lane)"
    )
    preview = prompt[:500] + ("…" if len(prompt) > 500 else "")
    return (
        f"[EXTERNAL AI PLATFORM · simulated]\n"
        f"Route: {lane_note}\n"
        f"Model: {model}\n\n"
        f"Acknowledged request (as received by external AI):\n{preview}\n\n"
        f"Demo reply: External model answered from the {'tokenized' if sanitized else 'original'} "
        f"prompt only. The gate still ran; this path does not need a live vendor."
    )


def _normalize_chat_history(raw: Any, *, limit: int = 24) -> list[dict[str, str]]:
    """Keep recent user/assistant turns for multi-turn Groq / chat continuity."""
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip().lower()
        if role in {"assistant", "es", "exhaustshield", "bot"}:
            role = "assistant"
        elif role in {"user", "human", "you"}:
            role = "user"
        else:
            continue
        content = str(
            item.get("content")
            or item.get("text")
            or item.get("message")
            or ""
        ).strip()
        if not content or content == "—":
            continue
        # Drop thinking placeholders / groq-off banners from memory payload
        if content.startswith("⚠ **Groq is OFF"):
            # keep the substance after the banner if present
            parts = content.split("\n\n", 1)
            content = parts[1].strip() if len(parts) > 1 else content
        if len(content) > 4000:
            content = content[:4000] + "…"
        out.append({"role": role, "content": content})
    if len(out) > limit:
        out = out[-limit:]
    return out


def _post_chat_completions(
    *,
    base_url: str,
    api_key: str,
    model_id: str,
    system: str,
    user_content: str,
    timeout: int = 25,
    history: list[dict[str, str]] | None = None,
) -> tuple[str | None, str | None, dict]:
    """One Groq chat attempt. gpt-oss uses reasoning tokens — leave budget for the answer."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    url = f"{base_url.rstrip('/')}/chat/completions"
    messages: list[dict[str, str]] = [{"role": "system", "content": system}]
    for turn in _normalize_chat_history(history or [], limit=24):
        messages.append({"role": turn["role"], "content": turn["content"]})
    messages.append({"role": "user", "content": user_content})
    body: dict[str, Any] = {
        "model": model_id,
        "messages": messages,
        "temperature": 0.35,
        "max_tokens": 3072,
    }
    if "gpt-oss" in (model_id or "").lower():
        body["reasoning_effort"] = "low"
    payload, err = _http_json(
        "POST", url, headers=headers, json_body=body, timeout=timeout
    )
    if err:
        return None, err, {}
    choice = ((payload or {}).get("choices") or [{}])[0] or {}
    choice_msg = choice.get("message") or {}
    text = (choice_msg.get("content") or "").strip()
    extra: dict[str, Any] = {"history_turns": max(0, len(messages) - 2)}
    if choice_msg.get("executed_tools"):
        extra["executed_tools"] = True
    if not text:
        return None, "empty_content", extra
    return text, None, extra


def call_external_ai(
    model: str | None,
    prompt: str,
    *,
    sanitized: bool,
    history: list[dict[str, str]] | None = None,
) -> tuple[str, dict]:
    """External platform. Live Groq when it works; backup answer if it does not.

    Never returns an error as the user-visible reply. A presentation must finish.
    """
    cfg = live_external_config()
    use_model = _canonical_groq_model(model or cfg["model"], default=cfg["model"])
    prior = _normalize_chat_history(history or [], limit=24)
    meta: dict[str, Any] = {
        "provider": "external",
        "model": use_model,
        "sanitized": sanitized,
        "mode": cfg["mode"],
        "ok": True,
        "live_web_search": False,
        "history_turns": len(prior),
    }
    runtime = external_runtime_status()
    # Soft AV/proxy degrade must never skip live — always force a fresh attempt.
    if cfg["mode"] == "live" and cfg["has_key"] and cfg["base_url"]:
        if runtime["degraded"]:
            if runtime.get("soft") or _is_av_or_local_block(runtime.get("reason")):
                mark_external_live_ok()
                runtime = external_runtime_status()
            else:
                probe = probe_external_ai(force=False)
                runtime = external_runtime_status()
                if probe.get("reachable"):
                    runtime = {**runtime, "degraded": False, "live_ok": True, "soft": False}
    want_live = (
        cfg["mode"] == "live"
        and cfg["base_url"]
        and cfg["has_key"]
        and (not runtime["degraded"] or bool(runtime.get("soft")))
    )

    snippets: list[dict[str, str]] = []
    wanted_live_web = False
    # Groq has no live knowledge base — ExhaustShield injects scrubbed web snippets.
    if want_live and cfg["live_search"] and needs_live_knowledge(prompt):
        wanted_live_web = True
        try:
            search_q = scrub_query_for_web_search(prompt)
            snippets = fetch_web_snippets(search_q, max_results=6) if search_q else []
            # Second pass: shorter / alternate wording if first came up empty or thin
            if search_q and len(snippets) < 2:
                simple = re.sub(r"[^\w\s\-']", " ", search_q)
                simple = " ".join(simple.split()[:12]).strip()
                if simple and simple.lower() != search_q.lower():
                    extra = fetch_web_snippets(simple, max_results=6)
                    if extra:
                        # merge unique
                        seen = {(s.get("title") or "")[:80].lower() for s in snippets}
                        for row in extra:
                            key = (row.get("title") or "")[:80].lower()
                            if key and key not in seen:
                                snippets.append(row)
                                seen.add(key)
            if search_q and len(snippets) < 2:
                # Third pass: append "today" for time-sensitive short asks
                if not re.search(r"(?i)\btoday\b", search_q):
                    extra2 = fetch_web_snippets(f"{search_q} today", max_results=6)
                    seen = {(s.get("title") or "")[:80].lower() for s in snippets}
                    for row in extra2:
                        key = (row.get("title") or "")[:80].lower()
                        if key and key not in seen:
                            snippets.append(row)
                            seen.add(key)
            meta["web_search_query_scrubbed"] = bool(
                search_q and search_q != prompt[:280]
            )
            meta["web_search_query"] = (search_q or "")[:120]
        except Exception as exc:
            meta["web_search_error"] = str(exc)[:160]
            snippets = []
        meta["live_web_search"] = bool(snippets)
        meta["live_web_wanted"] = True
        meta["web_snippet_count"] = len(snippets)
        meta["web_search_policy"] = "dynamic_live_knowledge_v3"
        if not snippets:
            meta["live_web_lagging"] = True
            meta["web_search_error"] = meta.get("web_search_error") or "no_snippets"
        else:
            # Fresh success — refresh health cache so UI clears the lag banner.
            _LIVE_WEB_CACHE["t"] = time.time()
            _LIVE_WEB_CACHE["result"] = {
                "enabled": True,
                "ok": True,
                "snippet_count": len(snippets),
                "reason": "ok",
                "sample": (snippets[0].get("title") or "")[:80],
            }

    if want_live:
        # Always inject date + lag notice when live web was wanted (even if empty).
        outbound_prompt = (
            _with_live_context(prompt, snippets) if wanted_live_web else prompt
        )
        system = (
            "You are a sharp, helpful enterprise assistant on the ExhaustShield outbound path.\n"
            "The user message may contain placeholders such as <SALES_1> that stand for redacted words, "
            "and may include LIVE WEB SNIPPETS for current facts.\n"
            "Rules:\n"
            "1. UNDERSTAND THE QUESTION FIRST: Identify exactly what is being asked "
            "(who/what/when/where/how many/how much/price/rate). Answer that ask directly "
            "in the first sentence — for EVERY topic and EVERY country/region "
            "(markets, sports, science, history, geography, people, places, weather, news, definitions). "
            "Do not pivot to a related topic, do not limit yourself to one country, and do not refuse "
            "a normal public fact ask.\n"
            "2. Answer in clear, natural English. Be useful and concrete — not vague or apologetic.\n"
            "3. For general how-to, writing, brainstorming, summaries, and process questions: "
            "answer fully. Do NOT say you lack information unless a specific private fact is missing.\n"
            "4. When LIVE WEB SNIPPETS or LIVE MARKET QUOTE lines are present, treat them as the "
            "source of truth for any current / factual ask (news, sports, weather, markets, "
            "share prices, indices, FX, gold/silver rates, people, places). "
            "Lead with the concrete answer (name, number+unit, date, place). "
            "For stocks/indices/FX, quote the LIVE MARKET QUOTE number first. "
            "Never invent placeholders for public facts, never say 'check a website' when snippets "
            "already contain the figure or name, and never refuse with a knowledge-cutoff excuse "
            "when snippets cover the ask. If snippets conflict, prefer the LIVE MARKET QUOTE or "
            "the snippet that directly answers the user's exact question.\n"
            "5. Only reuse placeholders that already appear in the user message — copy them exactly "
            "(including Org_1 / Person_1 / Email_1 and any dollar amounts like $4.69Mn). "
            "Do not round, rescale, or replace those figures with ranges.\n"
            "6. Never invent new placeholders (e.g. do not create <FINANCE_1>).\n"
            "7. Never invent deal amounts, salaries, employee IDs, or other secrets. "
            "If a specific figure or name was redacted or not given, say exactly what you can still "
            "help with (e.g. the email structure) and note that the private value was not provided — "
            "do not use a blanket 'I don't have that information' for the whole request.\n"
            "8. Do not wrap ordinary words in <TAGS>.\n"
            "9. Never claim you can see the company vault or local policy files — you only see this message.\n"
            "10. MULTI-TURN MEMORY (critical): Prior user/assistant messages are this chat's memory. "
            "Follow-ups like \"what about…\", \"and then?\", \"explain that\", \"the other one\", "
            "\"more detail\", or pronouns (it/they/that) refer to earlier turns. "
            "Continue the same thread — do not restart with a generic standalone answer. "
            "Briefly connect to what was already said, then deepen the answer.\n"
            "11. Write at ChatGPT quality: clear structure, short paragraphs, concrete details, "
            "and useful next steps when relevant. Avoid vague one-liners and robotic refusals."
        )

        models_to_try: list[str] = []
        for mid in (use_model, cfg["fallback_model"], _EXTERNAL_AI_LAST_RESORT_MODEL):
            mid = _canonical_groq_model(mid, default="")
            if mid and mid not in models_to_try:
                models_to_try.append(mid)

        errors: list[str] = []
        text: str | None = None
        extra: dict = {}
        for mid in models_to_try:
            text, err, extra = _post_chat_completions(
                base_url=cfg["base_url"],
                api_key=cfg["api_key"],
                model_id=mid,
                system=system,
                user_content=outbound_prompt,
                history=prior,
            )
            if err:
                errors.append(f"{mid}: {err}")
                if _is_transport_error(err):
                    break
                continue
            use_model = mid
            meta["model"] = mid
            if mid != models_to_try[0]:
                meta["fell_back_model"] = True
            break

        if isinstance(text, str) and text.strip():
            mark_external_live_ok()
            meta["ok"] = True
            meta["provider"] = "external_live"
            meta["model"] = use_model
            meta.update(extra)
            return text, meta

        mark_external_degraded(" | ".join(errors)[:180] or "groq_failed")
        meta["error"] = " | ".join(errors)[:400]
        meta["attempts"] = errors
        meta["provider"] = "external_backup"
        meta["live_degraded"] = True
        return (
            _backup_external_reply(prompt, sanitized=sanitized, snippets=snippets),
            meta,
        )

    if cfg["mode"] == "live":
        if not runtime["degraded"]:
            mark_external_degraded("missing_key" if not cfg["has_key"] else "not_live")
        meta["provider"] = "external_backup"
        meta["live_degraded"] = True
        meta["error"] = runtime["reason"] or "live unavailable"
        return (
            _backup_external_reply(prompt, sanitized=sanitized, snippets=snippets),
            meta,
        )

    meta["provider"] = "external_simulated"
    return _intentional_simulate_reply(prompt, sanitized=sanitized, model=use_model), meta


def resolve_ollama_url() -> str:
    """Always hit local Ollama on :11434 unless OLLAMA_URL is a sane explicit override.

    Protects against bad env (e.g. proxy leftovers resolving to port 9) that
    make High-lane look 'broken' when Ollama is actually healthy.
    """
    default = "http://127.0.0.1:11434/api/generate"
    raw = (os.getenv("OLLAMA_URL") or OLLAMA_URL or "").strip()
    if not raw:
        return default
    m = re.search(r":(\d+)", raw)
    port = m.group(1) if m else ""
    # Only trust explicit Ollama ports (default 11434) or localhost without a weird port
    if port and port != "11434":
        return default
    if "/api/generate" not in raw:
        return raw.rstrip("/") + "/api/generate"
    return raw


def _norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def _hide_forces_high(item: dict) -> bool:
    """True when a concrete hide span must never leave for external AI.

    Basic rule: if we already decided to HIDE something in a high-risk department,
    treat it as HIGH — do not require brittle secondary regex on the exact spelling.
    """
    dept = (item.get("department") or item.get("type") or "").lower()
    val = str(item.get("value") or "")
    if dept in HIGH_HIDE_DEPARTMENTS:
        return True
    if dept == "finance" and re.search(
        r"(?i)IBAN|SWIFT|BIC|routing\s*number|CVV|CVC|card number|account number|PAN\b|"
        r"credit\s*card|debit\s*card|"
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}|"
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
        val,
    ):
        return True
    if dept == "legal" and re.search(
        r"(?i)source code dump|proprietary source code|proprietary algorithm",
        val,
    ):
        return True
    return False


def _basic_risk_forces_high(text: str) -> bool:
    """Fail-closed on common risk language — case and punctuation do not matter."""
    folded = normalize_for_match(text or "")
    if not folded:
        return False
    return any(p.search(folded) for p in BASIC_HIGH_RISK_CUES)


def dynamic_high_signals(text: str) -> list[str]:
    """Infer High risk from structure / basic knowledge — not only a fixed phrase list.

    Uses families of meaning + evidence (values, money, assignments, co-occurrence)
    so novel phrasings still fail closed when they look like regulated/secret data.
    """
    # Hard cap — avoids ReDoS / UI freezes on huge pastes
    folded = normalize_for_match((text or "")[:2500])
    if not folded:
        return []
    hits: list[str] = []

    has_money = bool(
        re.search(r"[$€£₹]|\busd\b|\beur\b|\bgbp\b|\binr\b|\bmillion\b|\bbillion\b", folded)
        or re.search(r"\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b", folded)
    )
    has_digits = bool(re.search(r"\d{3,}", folded))

    # ------------------------------------------------------------------
    # A) Identity / session / enterprise login (structural)
    # ------------------------------------------------------------------
    for m in re.finditer(
        r"\b([a-z][a-z0-9]{1,24})\s+ids?\s+(?:is|was|are|=|:)?\s*([a-z0-9._@+-]{2,64})\b",
        folded,
    ):
        label = m.group(1)
        if label in _ID_LABEL_STOPWORDS:
            continue
        hits.append(f"identity structure: {label} id + value")

    if re.search(
        r"\b(?:user|session|account|member|customer|employee|badge|device|tenant|"
        r"client|vendor|login)ids?\s*(?:is|was|are|=|:)?\s*[a-z0-9._@+-]{2,}\b",
        folded,
    ):
        hits.append("identity structure: compact *id + value")

    if re.search(
        rf"\b(?:{_ENTERPRISE_AUTH_SYSTEMS})\b.{{0,48}}\b(?:logins?|users?|passwords?|credentials?|ids?|pins?)\b",
        folded,
    ) or re.search(
        rf"\b(?:logins?|users?|passwords?|credentials?)\b.{{0,48}}\b(?:{_ENTERPRISE_AUTH_SYSTEMS})\b",
        folded,
    ):
        hits.append("enterprise auth/login structure")

    if re.search(
        r"\b(?:logins?|sign\s*ins?|signons?|logons?)\b\s*(?:id|user|name|for)?\s*"
        r"(?:is|was|are|=|:)?\s*[a-z0-9._@+-]{2,64}\b",
        folded,
    ):
        hits.append("login/sign-in + identifier")

    if re.search(
        r"\b(?:my|our|their|his|her)\s+"
        r"(?:session|user|account|login|badge|employee|customer|password|pin|otp)\b",
        folded,
    ):
        hits.append("possessive identity/credential language")

    # ------------------------------------------------------------------
    # B) Labeled sensitive assignment — stem field = value (bounded, no nested spam)
    # ------------------------------------------------------------------
    sens_field = (
        r"(?:api[ _-]?keys?|secret[ _-]?keys?|access[ _-]?tokens?|private[ _-]?keys?|"
        r"passwords?|passphrases?|pins?|otps?|credentials?|ssns?|salary|compensation|"
        r"severance|bonuses?|diagnosis|prescriptions?|mrns?|patients?|dob|passport|"
        r"aadhaar|iban|swift|cvv|cvc|routing|imei|imsi|biometric|fingerprint|"
        r"geolocation|webhook|bearer|cookies?|session(?:ids?)?|userids?|usernames?|"
        r"logins?|account[ _-]?numbers?|bank[ _-]?accounts?|keys?|secrets?|tokens?)"
    )
    if re.search(
        rf"\b{sens_field}\b\s*(?:is|was|are|=|:)\s*[a-z0-9$€£₹._@%+/-]{{2,80}}\b",
        folded,
    ):
        hits.append("sensitive field assignment")

    # ------------------------------------------------------------------
    # C) Topic family hits (basic-knowledge categories)
    # ------------------------------------------------------------------
    families: list[tuple[str, str]] = [
        (
            "credentials/secrets",
            r"\b(?:password|passwd|passphrase|api\s*keys?|secret\s*keys?|access\s*tokens?|"
            r"private\s*keys?|credentials?|client\s*secret|bearer|webhook\s*secret|"
            r"encryption\s*keys?|\.env|connection\s*string|kubeconfig)\b",
        ),
        (
            "health/PHI",
            r"\b(?:patient|phi|ephi|hipaa|diagnosis|prescription|medical\s*record|mrn|"
            r"lab\s*result|clinical\s*notes?|health\s*insurance)\b",
        ),
        (
            "payments/PCI",
            r"\b(?:credit\s*cards?|debit\s*cards?|card\s*numbers?|cvv|cvc|iban|swift|"
            r"routing\s*numbers?|bank\s*accounts?|pci\s*dss)\b",
        ),
        (
            "HR/compensation",
            r"\b(?:salary|compensation|severance|base\s*pay|pay\s*band|stock\s*options?|"
            r"equity\s*grant|background\s*check|performance\s*improvement|\bpip\b)\b",
        ),
        (
            "people identifiers",
            r"\b(?:ssn|social\s*security|employee\s*ids?|badge\s*ids?|passport|aadhaar|"
            r"national\s*ids?|driver\s*s?\s*license|date\s*of\s*birth|\bdob\b)\b",
        ),
        (
            "biometric/device",
            r"\b(?:biometric|fingerprint|face\s*id|retina|voice\s*print|imei|imsi|"
            r"idfa|gaid|device\s*ids?)\b",
        ),
        (
            "precise location",
            r"\b(?:home\s*address|mailing\s*address|gps|geolocation|latitude|longitude)\b",
        ),
        (
            "security incident",
            r"\b(?:data\s*breach|zero\s*day|ransomware|exploit|vulnerability|"
            r"security\s*incident|cve-\d+)\b",
        ),
        (
            "source/infra secret",
            r"\b(?:heap\s*dump|core\s*dump|terraform\s*state|vault\s*path|"
            r"private\s*source\s*code|prod(?:uction)?\s*secrets?|"
            r"service\s*account|accountkey|connection\s*string)\b",
        ),
        (
            "webhook/exfil channel",
            r"\b(?:slack\s*webhook|discord\s*webhook|hooks\.slack|telegram\s*bot|"
            r"webhook\s*url)\b",
        ),
    ]
    for name, topic_re in families:
        if re.search(topic_re, folded):
            hits.append(f"topic family: {name}")

    if has_money and re.search(
        r"\b(?:salary|compensation|bonus|severance|wage|payroll|emp|employee|"
        r"contractor|colleague|manager)\b",
        folded,
    ):
        hits.append("money + people/HR context")

    if re.search(r"\b(?:patient|diagnosis|prescription|mrn|phi)\b", folded) and has_digits:
        hits.append("health topic + number evidence")

    if re.search(r"\b(?:card|cvv|iban|visa|mastercard|amex|pci)\b", folded) and has_digits:
        hits.append("payment language + digit evidence")

    if re.search(
        r"\b(?:leak|leaked|paste|dumped?|exfiltrat|do not share|keep this secret|confidentially)\b",
        folded,
    ) and re.search(rf"\b{sens_field}\b", folded):
        hits.append("secrecy/leak intent + sensitive topic")

    if re.search(
        rf"\b{sens_field}\b.{{0,20}}(?:[a-z0-9._@+/-]{{4,64}}|\d{{3,}})",
        folded,
    ):
        hits.append("sensitive stem near value-like token")

    seen: set[str] = set()
    out: list[str] = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _dynamic_high_forces(text: str) -> bool:
    return bool(dynamic_high_signals(text))


def scrub_query_for_web_search(query: str, detector: ExhaustDetector | None = None) -> str:
    """Protection layer: never send raw secrets/hide spans to DDGS / live search.

    Uses detector redaction + strips hard-secret shaped tokens. Returns empty
    string when nothing safe remains to search.
    """
    raw = (query or "").strip()
    if not raw:
        return ""
    det = detector or ExhaustDetector()
    try:
        analysis = det.analyze_prompt(raw)
        scrubbed = (analysis.get("redacted_text") or raw).strip()
    except Exception:
        scrubbed = raw
    # Blank hard-secret / high-entropy looking tokens left behind
    for variant_pat in HARD_SECRET_PATTERNS[:12]:
        scrubbed = variant_pat.sub(" ", scrubbed)
    scrubbed = re.sub(r"\s+", " ", scrubbed).strip()
    # Drop leftover placeholder noise for a cleaner search
    scrubbed = re.sub(r"<[A-Z]+_\d+>", " ", scrubbed)
    scrubbed = re.sub(r"\s+", " ", scrubbed).strip()
    if len(scrubbed) < 3:
        return ""
    return scrubbed[:280]


def _curl_get_text(url: str, *, timeout: float = 8.0, accept: str = "*/*") -> str | None:
    """Raw GET via curl.exe (Avast-safe). Returns body text or None."""
    curl = shutil.which("curl") or shutil.which("curl.exe")
    if not curl:
        return None
    try:
        completed = subprocess.run(
            [
                curl,
                "-sS",
                "-L",
                "--noproxy",
                "*",
                "--max-time",
                str(max(3, int(timeout))),
                "-A",
                _GROQ_UA,
                "-H",
                f"Accept: {accept}",
                url,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(4.0, float(timeout) + 2.0),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0:
            return None
        return completed.stdout or ""
    except Exception:
        return None


def _strip_html(text: str) -> str:
    """Decode entities first (Google News RSS uses &lt;a href=…&gt;), then strip tags."""
    t = html_lib.unescape(text or "")
    t = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", t)
    t = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", t)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = html_lib.unescape(t)  # nested entities inside attribute text
    return re.sub(r"\s+", " ", t).strip()


def _is_junk_snippet_body(body: str) -> bool:
    b = (body or "").strip()
    if len(b) < 28:
        return True
    if re.search(r"(?i)^https?://", b):
        return True
    if "news.google.com/rss/articles" in b.lower():
        return True
    # Mostly a URL / tracking blob
    if b.count("/") >= 4 and len(re.findall(r"[A-Za-z]{4,}", b)) < 6:
        return True
    return False


def _parse_rss_items(xml: str, *, max_results: int = 5) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for block in re.findall(r"(?is)<item\b[^>]*>(.*?)</item>", xml or "")[: max_results * 3]:
        title_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", block)
        desc_m = re.search(r"(?is)<description[^>]*>(.*?)</description>", block)
        link_m = re.search(r"(?is)<link[^>]*>(.*?)</link>", block)
        pub_m = re.search(r"(?is)<pubDate[^>]*>(.*?)</pubDate>", block)
        title = _strip_html(title_m.group(1) if title_m else "")
        body = _strip_html(desc_m.group(1) if desc_m else "")
        href = _strip_html(link_m.group(1) if link_m else "")
        published = _strip_html(pub_m.group(1) if pub_m else "")
        if _is_junk_snippet_body(body):
            # Google News often has no real description — fall back to title text.
            body = title
        if not (title or body):
            continue
        row = {"title": title[:200], "body": body[:520], "url": href[:300]}
        if published:
            row["published"] = published[:80]
        out.append(row)
        if len(out) >= max_results:
            break
    return out


def _parse_ddg_html(html: str, *, max_results: int = 5) -> list[dict[str, str]]:
    """Parse DuckDuckGo lite / html result rows (best-effort; often empty when blocked)."""
    out: list[dict[str, str]] = []
    patterns = [
        r'(?is)<a[^>]+rel="nofollow"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
        r'(?is)<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    ]
    for pat in patterns:
        for m in re.finditer(pat, html or ""):
            href = m.group(1).strip()
            title = _strip_html(m.group(2))
            if not title or len(title) < 3:
                continue
            if href.startswith("//duckduckgo.com/l/?") or "duckduckgo.com/l/?" in href:
                um = re.search(r"[?&]uddg=([^&]+)", href)
                if um:
                    href = urllib.parse.unquote(um.group(1))
            window = (html or "")[m.end() : m.end() + 700]
            snip_m = re.search(
                r'(?is)class="[^"]*(?:result-snippet|result__snippet)[^"]*"[^>]*>(.*?)</(?:td|div|span|a)>',
                window,
            )
            body = _strip_html(snip_m.group(1) if snip_m else "")
            out.append({"title": title[:200], "body": (body or title)[:520], "url": href[:300]})
            if len(out) >= max_results:
                return out
    return out


def _build_web_search_query(query: str) -> tuple[str, bool]:
    """Tighten public search query. Returns (query, year_was_auto_injected)."""
    q = (query or "").strip()
    if not q:
        return "", False
    q = re.sub(r"[?!.]+$", "", q).strip()
    # Drop filler that dilutes search ("basic", "please tell me", …)
    q = re.sub(
        r"(?i)^\s*(please\s+)?(tell\s+me|give\s+me|what(?:'s|\s+is)|whats)\s+",
        "",
        q,
    ).strip()
    q = re.sub(r"(?i)\b(basic|simple|exact|approx(?:imate)?|roughly)\b", " ", q)
    q = re.sub(r"\s+", " ", q).strip()

    if re.search(r"(?i)\bwho\s+won\b", q) and not re.search(r"(?i)\b(winner|crowned|result)\b", q):
        q = f"{q} winner"

    # Bullion — region-aware: India → ₹/g retail; otherwise global spot (USD/oz)
    if re.search(r"(?i)\bgold\b", q) and re.search(r"(?i)\b(rate|price|per\s+gram|carat|\d+\s*k)\b", q):
        if re.search(r"(?i)\b(india|mumbai|delhi|chennai|bangalore|bengaluru|hyderabad|kolkata|₹|rs\.?|inr|22k|24k|carat|per\s+gram)\b", query or q):
            city = ""
            cm = re.search(
                r"(?i)\bin\s+(mumbai|delhi|chennai|bangalore|bengaluru|hyderabad|kolkata|pune|ahmedabad|jaipur)",
                query or "",
            )
            if cm:
                city = cm.group(1)
            return f"gold rate today India {city} 24K 22K per gram".strip(), False
        return "gold price today per ounce USD", False
    if re.search(r"(?i)\bsilver\b", q) and re.search(r"(?i)\b(rate|price|per\s+gram|per\s+kg|per\s+ounce)\b", q):
        if re.search(r"(?i)\b(india|₹|rs\.?|inr|per\s+gram|per\s+kg)\b", query or q):
            return "silver rate today India per gram per kg", False
        return "silver price today per ounce USD", False
    if re.search(r"(?i)\bplatinum\b", q) and re.search(r"(?i)\b(rate|price|per\s+gram)\b", q):
        if re.search(r"(?i)\b(india|₹|rs\.?|inr)\b", query or q):
            return "platinum rate today India per gram", False
        return "platinum price today per ounce USD", False

    # Other commodity / FX rates — force “today”, skip year append (hurts rate RSS)
    if _LIVE_RATE_RE.search(q):
        if not re.search(r"(?i)\b(today|latest|current|now)\b", q):
            q = f"{q} today"
        return q, False

    if re.search(r"\b(20\d{2})\b", q):
        return q, False
    year = str(date.today().year)
    timey = bool(
        re.search(
            r"(?i)\b(latest|today|tonight|yesterday|news|won|winner|score|election|"
            r"price|rate|current|live|stock|weather|forecast|"
            r"prime\s+minister|president\s+of|ceo\s+of)\b",
            q,
        )
    )
    # Evergreen / definitional asks must NOT get a year glued on
    # ("capital of France 2026" → useless private-capital news).
    evergreen = bool(
        re.search(
            r"(?i)\b(capital\s+of|population\s+of|definition\s+of|meaning\s+of|"
            r"who\s+invented|who\s+discovered|formula\s+for|distance\s+between|"
            r"largest|smallest|tallest|longest|currency\s+of|official\s+language)\b",
            q,
        )
    )
    if evergreen:
        return q, False
    if timey and not re.search(r"(?i)\bweather|forecast|temperature\b", q):
        return f"{q} {year}", True
    return q, False


def _yahoo_chart_quote(symbol: str) -> dict[str, Any] | None:
    """One live Yahoo Finance chart quote."""
    sym = (symbol or "").strip()
    if not sym:
        return None
    raw = _curl_get_text(
        f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(sym, safe='^=.')}"
        f"?interval=1d&range=5d",
        timeout=8.0,
        accept="application/json",
    )
    if not raw:
        return None
    try:
        data = json.loads(raw)
        result = ((data.get("chart") or {}).get("result") or [None])[0]
        if not result:
            return None
        meta = result.get("meta") or {}
        price = meta.get("regularMarketPrice")
        if price is None:
            # fall back to last close in indicators
            closes = (((result.get("indicators") or {}).get("quote") or [{}])[0].get("close") or [])
            closes = [c for c in closes if c is not None]
            price = closes[-1] if closes else meta.get("previousClose")
        if price is None:
            return None
        prev = meta.get("chartPreviousClose") or meta.get("previousClose")
        change = None
        pct = None
        try:
            if prev not in (None, 0):
                change = float(price) - float(prev)
                pct = (change / float(prev)) * 100.0
        except Exception:
            pass
        return {
            "symbol": str(meta.get("symbol") or sym),
            "name": str(meta.get("shortName") or meta.get("longName") or sym),
            "price": float(price),
            "currency": str(meta.get("currency") or ""),
            "exchange": str(meta.get("exchangeName") or meta.get("fullExchangeName") or ""),
            "previous_close": float(prev) if prev is not None else None,
            "change": change,
            "change_pct": pct,
        }
    except Exception:
        return None


def _yahoo_finance_search(query: str, *, limit: int = 4) -> list[tuple[str, str]]:
    """Dynamic symbol lookup — any company / index / FX / crypto without a fixed list."""
    q = (query or "").strip()
    if not q or len(q) < 2:
        return []
    q2 = re.sub(
        r"(?i)\b(share\s+price|stock\s+price|price\s+today|live\s+price|quote|ltp|cmp|"
        r"today|current|latest|what\s+is|tell\s+me|basic|rate)\b",
        " ",
        q,
    )
    q2 = re.sub(r"\s+", " ", q2).strip() or q
    url = (
        "https://query1.finance.yahoo.com/v1/finance/search?"
        + urllib.parse.urlencode({"q": q2[:80], "quotesCount": str(limit), "newsCount": "0"})
    )
    raw = _curl_get_text(url, timeout=8.0, accept="application/json")
    if not raw:
        return []
    out: list[tuple[str, str]] = []
    try:
        data = json.loads(raw)
        for row in (data.get("quotes") or [])[:limit]:
            if not isinstance(row, dict):
                continue
            sym = str(row.get("symbol") or "").strip()
            if not sym:
                continue
            qtype = str(row.get("quoteType") or "").upper()
            if qtype and qtype not in {
                "EQUITY", "INDEX", "CURRENCY", "CRYPTOCURRENCY", "ETF", "FUTURE", "OPTION",
            }:
                continue
            name = str(row.get("shortname") or row.get("longname") or sym)
            out.append((sym, name[:80]))
    except Exception:
        return []
    return out


def _market_region_hint(query: str) -> str:
    """Detect preferred listing region from the ask (empty = global / any)."""
    q = query or ""
    if re.search(r"(?i)\b(india|nse|bse|sensex|nifty|rupee|₹|inr)\b", q) or re.search(
        r"(?i)\b(tata|infosys|reliance|hdfc|icici|wipro|sbi)\b", q
    ):
        return "IN"
    if re.search(r"(?i)\b(uk|london|lse|ftse|gbp|britain|british)\b", q):
        return "UK"
    if re.search(r"(?i)\b(japan|tokyo|nikkei|jpy|yen)\b", q):
        return "JP"
    if re.search(r"(?i)\b(hong\s*kong|hang\s+seng|hkex|hkd)\b", q):
        return "HK"
    if re.search(r"(?i)\b(germany|frankfurt|dax|eur)\b", q) and re.search(
        r"(?i)\b(stock|share|index|dax|market)\b", q
    ):
        return "DE"
    if re.search(r"(?i)\b(australia|asx|aud)\b", q):
        return "AU"
    if re.search(r"(?i)\b(canada|tsx|toronto|cad)\b", q):
        return "CA"
    if re.search(r"(?i)\b(usa|u\.s\.|nyse|nasdaq|wall\s+street|dollar)\b", q):
        return "US"
    return ""


def _symbol_region_score(symbol: str, region: str) -> int:
    """Higher = better match for the requested region. Global asks accept all."""
    s = symbol or ""
    if not region:
        # Prefer primary/liquid listings when no region: US bare tickers, then major indices
        if s.startswith("^"):
            return 3
        if s.endswith("=X") or "-USD" in s:
            return 3
        if "." not in s:
            return 4  # US listings usually bare
        if s.endswith((".NS", ".BO", ".L", ".T", ".HK", ".AX", ".DE", ".PA", ".TO", ".KS")):
            return 2
        return 1
    pref = {
        "IN": (".NS", ".BO"),
        "UK": (".L",),
        "JP": (".T",),
        "HK": (".HK",),
        "DE": (".DE",),
        "AU": (".AX",),
        "CA": (".TO",),
        "US": (),  # bare ticker
    }.get(region, ())
    if region == "US":
        return 5 if "." not in s or s.startswith("^") else 1
    if any(s.endswith(p) for p in pref) or s.startswith("^"):
        return 5
    return 0


def _parse_fx_pair(query: str) -> tuple[str, str] | None:
    """USD to JPY / EUR/GBP → Yahoo FX symbol."""
    m = re.search(
        r"(?i)\b(usd|inr|eur|gbp|jpy|cny|aud|cad|chf|sgd|hkd|aed)\s*(?:to|/)\s*"
        r"(usd|inr|eur|gbp|jpy|cny|aud|cad|chf|sgd|hkd|aed)\b",
        query or "",
    )
    if not m:
        return None
    a, b = m.group(1).upper(), m.group(2).upper()
    if a == b:
        return None
    return f"{a}{b}=X", f"{a}/{b}"


def _resolve_yahoo_symbols(query: str) -> list[tuple[str, str]]:
    """Map a natural-language market ask to Yahoo symbols — global by default."""
    q = query or ""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    region = _market_region_hint(q)

    def _add(symbol: str, label: str) -> None:
        if not symbol or symbol in seen:
            return
        root = symbol.split(".")[0].upper().lstrip("^")
        # Allow same root on different exchanges only when region-hunting;
        # otherwise keep first (usually best) hit.
        if any(s.split(".")[0].upper().lstrip("^") == root and s != symbol for s in seen):
            if "." not in symbol and any("." in s for s in seen):
                return
            if region and _symbol_region_score(symbol, region) <= max(
                (_symbol_region_score(s, region) for s in seen if s.split(".")[0].upper().lstrip("^") == root),
                default=0,
            ):
                return
        found.append((symbol, label))
        seen.add(symbol)

    fx = _parse_fx_pair(q)
    if fx:
        _add(fx[0], fx[1])

    for pat, symbol, label in _YAHOO_SYMBOL_RULES:
        if pat.search(q):
            if symbol in {"GC=F", "SI=F"} and re.search(r"(?i)\bper\s+gram\b|\b22k\b|\b24k\b", q):
                continue
            _add(symbol, label)

    # Explicit tickers with global suffixes: AAPL, VOD.L, 7203.T, 0700.HK
    for m in re.finditer(r"\b([A-Z]{1,5}|\d{3,5})(?:\.([A-Z]{1,3}))?\b", q):
        raw, suf = m.group(1), m.group(2)
        if raw in {"USD", "INR", "EUR", "GBP", "JPY", "CNY", "AUD", "CAD", "CHF", "CEO", "PDF", "API", "HTTP", "JSON", "HTML", "NSE", "BSE", "MCX", "NYSE", "LSE"}:
            continue
        if not re.search(r"(?i)\b(share|stock|price|quote|index|market|trading|crypto|bitcoin|ticker)\b", q):
            continue
        symbol = f"{raw}.{suf}" if suf else raw
        if any(s.startswith(raw) for s in seen):
            continue
        _add(symbol, symbol)

    # Dynamic Yahoo search — global listings (no India-only filter)
    if len(found) < 2 and re.search(
        r"(?i)\b(share|stock|price|quote|nifty|sensex|index|forex|usd|inr|crypto|bitcoin|"
        r"ethereum|market|trading|ltp|cmp|rate|nasdaq|ftse|nikkei|dow|dax)\b",
        q,
    ):
        ranked: list[tuple[int, str, str]] = []
        for sym, name in _yahoo_finance_search(q, limit=8):
            if sym in {"GC=F", "SI=F"} and re.search(r"(?i)\bper\s+gram\b|\b22k\b|\b24k\b", q):
                continue
            score = _symbol_region_score(sym, region)
            if region and score == 0:
                continue  # wrong exchange for an explicit region ask
            ranked.append((score, sym, name))
        ranked.sort(key=lambda x: x[0], reverse=True)
        for _, sym, name in ranked:
            _add(sym, name)
            if len(found) >= 3:
                break

    # Generic “stock market today” with no name → major GLOBAL indices (not India-only)
    if not found and re.search(r"(?i)\b(share\s+market|stock\s+market|markets?\s+today|global\s+markets?)\b", q):
        if region == "IN":
            _add("^NSEI", "Nifty 50")
            _add("^BSESN", "Sensex")
        elif region == "UK":
            _add("^FTSE", "FTSE 100")
        elif region == "JP":
            _add("^N225", "Nikkei 225")
        elif region == "HK":
            _add("^HSI", "Hang Seng")
        elif region == "DE":
            _add("^GDAXI", "DAX")
        else:
            _add("^GSPC", "S&P 500")
            _add("^DJI", "Dow Jones")
            _add("^IXIC", "NASDAQ Composite")
            if not region:
                _add("^FTSE", "FTSE 100")
                _add("^N225", "Nikkei 225")

    if not found and re.search(r"(?i)\b(nifty|sensex)\b", q):
        _add("^NSEI", "Nifty 50")
        _add("^BSESN", "Sensex")
    return found[:4]


def _fetch_market_quotes(query: str) -> list[dict[str, str]]:
    """Live stocks / indices / FX / crypto / commodity quotes via Yahoo Finance."""
    q = (query or "").strip()
    if not q:
        return []
    if not (
        _LIVE_RATE_RE.search(q)
        or re.search(
            r"(?i)\b(share|stock|nifty|sensex|nasdaq|forex|usd|inr|gold|silver|crude|market|"
            r"crypto|bitcoin|ethereum|price|rate|quote|ltp|cmp|index|trading)\b",
            q,
        )
    ):
        return []
    symbols = _resolve_yahoo_symbols(q)
    out: list[dict[str, str]] = []
    for symbol, label in symbols:
        quote = _yahoo_chart_quote(symbol)
        if not quote:
            continue
        price = quote["price"]
        cur = quote["currency"] or ""
        name = quote["name"] or label
        unit = ""
        sym_u = str(quote.get("symbol") or symbol)
        if sym_u.endswith("=X") or "USD/INR" in name.upper() or "/INR" in name.upper():
            unit = " (FX rate)"
        elif symbol in {"GC=F", "SI=F", "CL=F"}:
            unit = " (futures)"
            if symbol in {"GC=F", "SI=F"} and re.search(r"(?i)\bper\s+gram\b", q):
                unit += " — India jewellery Rs/g differs; prefer INR retail news for per-gram"
        elif "-USD" in sym_u:
            unit = " (crypto)"
        change_bit = ""
        if quote.get("change") is not None and quote.get("change_pct") is not None:
            sign = "+" if quote["change"] >= 0 else ""
            change_bit = f", change {sign}{quote['change']:.2f} ({sign}{quote['change_pct']:.2f}%)"
        price_fmt = f"{price:,.4f}" if price < 1 else f"{price:,.2f}"
        body = (
            f"LIVE MARKET QUOTE ({date.today().isoformat()}): {name} ({quote['symbol']}) "
            f"last {price_fmt} {cur}{unit}{change_bit}"
            f"{(' on ' + quote['exchange']) if quote.get('exchange') else ''}. "
            f"Answer the user's price/rate/index question with this figure first."
        )
        out.append(
            {
                "title": f"Live quote · {label} ({quote['symbol']})",
                "body": body[:520],
                "url": f"https://finance.yahoo.com/quote/{urllib.parse.quote(symbol, safe='^=.-')}",
                "source": "yahoo_quote",
            }
        )
    return out


def _fetch_yahoo_spot(query: str) -> list[dict[str, str]]:
    """Backward-compatible alias → full market quote fetcher."""
    return _fetch_market_quotes(query)


def _query_years(text: str) -> set[str]:
    return set(re.findall(r"\b(20\d{2})\b", text or ""))


def _user_named_years(original_query: str) -> set[str]:
    """Years the user typed — never the auto-injected search year."""
    return _query_years(original_query or "")


def _score_snippet(
    query: str,
    row: dict[str, str],
    *,
    original_query: str = "",
    year_injected: bool = False,
) -> float:
    """Rank snippets so factual answers beat odds/contender fluff."""
    title = (row.get("title") or "").lower()
    body = (row.get("body") or "").lower()
    blob = f"{title} {body}"
    q = (original_query or query or "").lower()
    score = 0.0
    src = (row.get("source") or "").lower()

    # Live weather sensor always wins weather asks
    if src == "wttr" and re.search(r"(?i)\b(weather|forecast|temperature|temp\b)\b", q):
        return 100.0

    # Structured Yahoo quotes win for stocks / indices / FX / futures
    if src in {"yahoo_quote", "yahoo_spot"}:
        if re.search(r"(?i)\b(share|stock|nifty|sensex|nasdaq|forex|usd|inr|price|quote|index)\b", q):
            if re.search(r"(?i)\bper\s+gram\b|\b22k\b|\b24k\b", q) and "futures" in blob:
                score += 2.0
            else:
                return 95.0
        elif re.search(r"(?i)\b(gold|silver|crude|rate)\b", q):
            score += 12.0

    q_tokens = [
        t
        for t in re.findall(r"[a-z0-9']{3,}", q)
        if t
        not in {
            "the", "and", "for", "who", "what", "when", "where", "which", "how", "why",
            "did", "does", "are", "was", "were", "with", "from", "that", "this", "latest",
            "today", "tonight", "please", "tell",
        }
    ]
    for tok in q_tokens:
        if tok in blob:
            score += 2.2
        elif tok in title:
            score += 1.4

    # Only enforce year match for years the USER typed (not auto-injected).
    q_years = _user_named_years(original_query) if original_query else (
        set() if year_injected else _query_years(query)
    )
    blob_years = _query_years(blob)
    if q_years:
        if q_years & blob_years:
            score += 8.0
        elif blob_years and not (q_years & blob_years):
            score -= 8.0  # wrong year — demote hard

    if re.search(r"(?i)\b(who\s+won|winner|crowned|champion|result|final)\b", q):
        if re.search(r"(?i)\b(won|winner|crowned|champion|beats?|defeated|result)\b", blob):
            score += 6.0
        if re.search(
            r"(?i)\b(odds|favorites?|favourites?|contenders?|short\s*lists?|power\s*rankings?|to\s+win|deserves?\s+to\s+win)\b",
            blob,
        ):
            score -= 7.0
        if re.search(r"(?i)\bwhen\s+will\b|\bannounced\b.*\bhorizon\b", blob):
            score -= 3.0

    if re.search(r"(?i)\b(current|who\s+is|prime\s+minister|president|ceo|mayor)\b", q):
        if re.search(r"(?i)\b(current|new\s+prime|becomes?|named|sworn|incumbent|says\s+he\s+will)\b", blob):
            score += 5.0
        if re.search(r"(?i)\bcomplete\s+list\b|\bfrom\s+1721\b|\bhistory\b|\ball[- ]time\b", blob):
            score -= 5.0

    if re.search(r"(?i)\b(weather|forecast)\b", q):
        if re.search(r"(?i)\bmarathon|championships?|tournament|fixture\b", blob):
            score -= 6.0
        # Prefer snippets that mention today's calendar date-ish wording
        today = date.today()
        if re.search(rf"(?i)\b{today.strftime('%B')}\s+{today.day}\b", blob) or "today" in blob:
            score += 3.0

    if _LIVE_RATE_RE.search(q) or re.search(r"(?i)\b(gold|silver|platinum).{0,20}(rate|price)\b", q):
        if re.search(r"(?i)\b(per\s+gram|per\s+ounce|/g\b|/oz\b|22k|24k|18k|carat|₹|rs\.?|inr|usd)\b", blob):
            score += 6.0
        if re.search(r"(?i)\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b|\b\d{3,6}(?:\.\d+)?\b", blob):
            score += 4.0
        # Prefer India ₹ retail figures for generic “per gram” asks
        if re.search(r"(?i)\b(₹|rs\.?|inr|india|mumbai|delhi|chennai|bangalore|hyderabad)\b", blob):
            score += 5.0
        # Demote wrong-country retail (e.g. Indonesian Rp) unless user asked for it
        if re.search(r"(?i)\b(antam|rupiah|jakarta|rp\d)", blob) and not re.search(
            r"(?i)\b(indonesia|jakarta|rupiah|antam)\b", q
        ):
            score -= 8.0
        if re.search(r"(?i)\b(jewellery\s+design|history\s+of\s+gold|how\s+to\s+invest)\b", blob):
            score -= 5.0
        # Fed / technical chart pieces without a per-gram number
        if re.search(r"(?i)\b(fed\s+rate|dot\s+plot|support\s+at\s+\$|resistance\s+at)\b", blob) and not re.search(
            r"(?i)\b(per\s+gram|22k|24k|₹|rs\.?)\b", blob
        ):
            score -= 6.0

    if not _is_junk_snippet_body(body) and len(body) >= 60:
        score += 3.0
    if len(body) >= 120:
        score += 1.5

    if src in {"bing_news", "wikipedia", "wttr", "ddg_instant", "yahoo_spot", "yahoo_quote"}:
        score += 2.5
    if src == "google_news":
        score -= 0.5  # titles often useful, bodies often empty

    # Capital-of-X: prefer the country capital extract, not other "capital of …" pages
    cap = re.search(r"(?i)\bcapital\s+of\s+([a-z][a-z\s]+)$", q.strip())
    if cap:
        country = cap.group(1).strip()
        if country and country in blob and re.search(r"(?i)\bcapital\b", blob):
            score += 10.0
        if re.search(r"(?i)\b(french\s+guiana|polynesia|prince\s+edward)\b", blob):
            score -= 12.0

    return score


def _question_focus(prompt: str) -> str:
    """Dynamic focus — mirrors the user's ask so the model cannot wander."""
    p = (prompt or "").strip()
    if not p:
        return "Answer the user's question directly."
    compact = re.sub(r"\s+", " ", p)
    preview = compact if len(compact) <= 160 else compact[:157] + "…"

    if re.search(r"(?i)\bweather|forecast|temperature\b", p):
        return (
            "FOCUS: Report the current weather for the place named "
            "(temperature + conditions). Ignore unrelated event forecasts."
        )
    if _LIVE_RATE_RE.search(p) or re.search(
        r"(?i)\b(gold|silver|platinum|share|stock|nifty|sensex|forex|usd|inr).{0,20}(rate|price|quote)?\b",
        p,
    ):
        return (
            "FOCUS: Give the live number the user asked for (price/rate/index/FX) with "
            "unit/currency from LIVE MARKET QUOTE or rate snippets. "
            "Lead with the figure — do not refuse or say to check another website."
        )
    if re.search(r"(?i)\bwho\s+won\b|\bwinner\b", p):
        years = ", ".join(sorted(_user_named_years(p))) or "the year asked"
        return (
            f"FOCUS: Name who won (or the result) for {years}. "
            "Do not discuss odds, contenders, or a different year's race."
        )
    if re.search(r"(?i)\b(current|who\s+is\s+the)\b.*\b(prime\s+minister|president|ceo|mayor|chancellor)\b", p) or re.search(
        r"(?i)\b(prime\s+minister|president|ceo|mayor)\b.*\b(current|now|today)\b", p
    ):
        return (
            "FOCUS: Name the current office-holder. "
            "Do not dump a historical list unless asked."
        )
    if re.search(r"(?i)^\s*how\s+much\b|\b(price|cost|rate|fee)\b", p):
        return (
            f'FOCUS: The user asked “{preview}”. Lead with the number + unit/currency '
            "from the snippets."
        )
    if re.search(r"(?i)^\s*who\b", p):
        return f'FOCUS: The user asked “{preview}”. Name the person/entity in the first sentence.'
    if re.search(r"(?i)^\s*when\b", p):
        return f'FOCUS: The user asked “{preview}”. Lead with the date/time.'
    if re.search(r"(?i)^\s*where\b", p):
        return f'FOCUS: The user asked “{preview}”. Lead with the place/location.'
    if re.search(r"(?i)^\s*how\s+many\b|\b(how\s+much|score)\b", p):
        return f'FOCUS: The user asked “{preview}”. Lead with the specific number/score.'
    return (
        f'FOCUS: The user asked “{preview}”. '
        "Understand that exact ask. Answer it in the first sentence with the concrete fact "
        "supported by the snippets. Do not pivot to a related but different topic."
    )


def _fetch_bing_news(q_search: str, *, max_results: int) -> list[dict[str, str]]:
    url = "https://www.bing.com/news/search?q=" + urllib.parse.quote(q_search) + "&format=rss"
    xml = _curl_get_text(
        url, timeout=9.0, accept="application/rss+xml,application/xml,text/xml,*/*"
    )
    rows = _parse_rss_items(xml or "", max_results=max_results)
    for r in rows:
        r["source"] = "bing_news"
    return rows


def _fetch_google_news(q_search: str, *, max_results: int) -> list[dict[str, str]]:
    url = (
        "https://news.google.com/rss/search?"
        + urllib.parse.urlencode({"q": q_search, "hl": "en-US", "gl": "US", "ceid": "US:en"})
    )
    xml = _curl_get_text(
        url, timeout=9.0, accept="application/rss+xml,application/xml,text/xml,*/*"
    )
    rows = _parse_rss_items(xml or "", max_results=max_results)
    for r in rows:
        r["source"] = "google_news"
    return rows


def _fetch_wikipedia_extracts(query: str, *, max_results: int = 3) -> list[dict[str, str]]:
    """OpenSearch → plain-text extracts (far better than empty news descriptions)."""
    q = (query or "").strip()[:80]
    if not q:
        return []
    open_url = (
        "https://en.wikipedia.org/w/api.php?"
        + urllib.parse.urlencode(
            {
                "action": "opensearch",
                "search": q,
                "limit": str(max(3, max_results)),
                "namespace": "0",
                "format": "json",
            }
        )
    )
    raw = _curl_get_text(open_url, timeout=8.0, accept="application/json")
    titles: list[str] = []
    urls: list[str] = []
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, list) and len(data) >= 4:
                titles = [str(t) for t in (data[1] or [])[:max_results]]
                urls = [str(u) for u in (data[3] or [])[:max_results]]
        except Exception:
            titles = []
    if not titles:
        return []
    extract_url = (
        "https://en.wikipedia.org/w/api.php?"
        + urllib.parse.urlencode(
            {
                "action": "query",
                "prop": "extracts",
                "exintro": "1",
                "explaintext": "1",
                "redirects": "1",
                "titles": "|".join(titles),
                "format": "json",
            }
        )
    )
    eraw = _curl_get_text(extract_url, timeout=10.0, accept="application/json")
    out: list[dict[str, str]] = []
    if not eraw:
        return out
    try:
        pages = json.loads(eraw).get("query", {}).get("pages", {})
        # Redirects rename titles — do not require the original opensearch title key.
        url_by_title = {str(t): (urls[i] if i < len(urls) else "") for i, t in enumerate(titles)}
        for page in pages.values():
            if not isinstance(page, dict) or page.get("missing") is not None:
                continue
            title = str(page.get("title") or "").strip()
            extract = str(page.get("extract") or "").strip()
            if not extract or not title:
                continue
            out.append(
                {
                    "title": f"Wikipedia: {title}"[:200],
                    "body": extract[:700],
                    "url": (url_by_title.get(title) or f"https://en.wikipedia.org/wiki/{urllib.parse.quote(title.replace(' ', '_'))}")[:300],
                    "source": "wikipedia",
                }
            )
            if len(out) >= max_results:
                break
    except Exception:
        return out
    return out


def _fetch_ddg_instant(q_search: str) -> list[dict[str, str]]:
    api = (
        "https://api.duckduckgo.com/?"
        + urllib.parse.urlencode(
            {"q": q_search, "format": "json", "no_html": "1", "skip_disambig": "1"}
        )
    )
    payload, err = _http_json_curl(
        "GET", api, headers={"Accept": "application/json"}, json_body=None, timeout=8.0
    )
    out: list[dict[str, str]] = []
    if err or not isinstance(payload, dict):
        return out
    abstract = str(payload.get("AbstractText") or "").strip()
    if abstract:
        out.append(
            {
                "title": str(payload.get("Heading") or payload.get("AbstractSource") or "DuckDuckGo"),
                "body": abstract[:700],
                "url": str(payload.get("AbstractURL") or "")[:300],
                "source": "ddg_instant",
            }
        )
    answer = str(payload.get("Answer") or "").strip()
    if answer and answer.lower() not in {abstract.lower()}:
        out.append(
            {
                "title": "Instant answer",
                "body": answer[:520],
                "url": "",
                "source": "ddg_instant",
            }
        )
    return out


def _fetch_weather_snippet(query: str) -> list[dict[str, str]]:
    if not re.search(r"(?i)\b(weather|forecast|temperature|temp\b|rain|humidity)\b", query or ""):
        return []
    place = ""
    m = re.search(
        r"(?i)\b(?:weather|forecast|temperature)\s+(?:in|for|at|of)\s+([A-Za-z][A-Za-z\s\-']{1,40})",
        query or "",
    )
    if not m:
        m = re.search(
            r"(?i)\bin\s+([A-Za-z][A-Za-z\s\-']{1,40}?)(?:\s+(?:today|tonight|tomorrow|now|please))?[\s?!.]*$",
            (query or "").strip(),
        )
    if m:
        place = m.group(1).strip(" ?.!,")
    # Strip trailing time / filler words so "London today" → "London"
    place = re.sub(
        r"(?i)\b(today|tonight|tomorrow|yesterday|now|currently|please|this\s+week|this\s+morning|202\d)\b.*$",
        "",
        place or "",
    ).strip(" ?.!,")
    place = re.sub(r"\s+", " ", place).strip()
    if not place or len(place) < 2:
        return []
    place = " ".join(place.split()[:4])
    raw = _curl_get_text(
        f"https://wttr.in/{urllib.parse.quote(place)}?format=j1",
        timeout=8.0,
        accept="application/json",
    )
    if not raw:
        return []
    try:
        data = json.loads(raw)

        def _area_field(block: dict, key: str) -> str:
            arr = block.get(key) or []
            if isinstance(arr, list) and arr and isinstance(arr[0], dict):
                return str(arr[0].get("value") or "")
            return ""

        nearest = (data.get("nearest_area") or [{}])[0] if isinstance(data.get("nearest_area"), list) else {}
        cur = (data.get("current_condition") or [{}])[0] if isinstance(data.get("current_condition"), list) else {}
        area = _area_field(nearest, "areaName") or place
        region = _area_field(nearest, "region")
        country = _area_field(nearest, "country")
        desc = ""
        wdesc = cur.get("weatherDesc") or []
        if isinstance(wdesc, list) and wdesc and isinstance(wdesc[0], dict):
            desc = str(wdesc[0].get("value") or "").strip()
        body = (
            f"Current weather for {area}"
            f"{(', ' + region) if region else ''}"
            f"{(', ' + country) if country else ''}: "
            f"{cur.get('temp_C', '?')}°C "
            f"(feels like {cur.get('FeelsLikeC', '?')}°C), {desc or 'n/a'}. "
            f"Humidity {cur.get('humidity', '?')}%, wind {cur.get('windspeedKmph', '?')} km/h. "
            f"(Observed live via wttr.in on {date.today().isoformat()})"
        )
        return [
            {
                "title": f"Live weather · {area}",
                "body": body[:520],
                "url": f"https://wttr.in/{urllib.parse.quote(place)}",
                "source": "wttr",
            }
        ]
    except Exception:
        return []


def fetch_web_snippets(query: str, *, max_results: int = 6) -> list[dict[str, str]]:
    """Live public snippets — Bing+Wikipedia first (Google News titles are weak alone)."""
    q = scrub_query_for_web_search(query)
    if not q:
        return []
    q_search, year_injected = _build_web_search_query(q)
    want = max(3, min(int(max_results or 6), 8))
    is_weather = bool(re.search(r"(?i)\b(weather|forecast|temperature|temp\b)\b", q))
    is_rate = bool(
        _LIVE_RATE_RE.search(q)
        or re.search(
            r"(?i)\b(gold|silver|platinum|share|stock|nifty|sensex|nasdaq|forex|usd|inr).{0,24}(rate|price|quote)?\b",
            q,
        )
    )
    is_evergreen = bool(
        re.search(
            r"(?i)\b(capital\s+of|population\s+of|definition\s+of|meaning\s+of|"
            r"who\s+invented|who\s+discovered|formula\s+for|distance\s+between|"
            r"largest|smallest|tallest|longest|currency\s+of|official\s+language)\b",
            q,
        )
    )

    collected: list[dict[str, str]] = []

    def _jobs() -> list[tuple[str, Any]]:
        # Wikipedia uses the raw ask (no year injection) so evergreen facts resolve
        wiki_q = q if (is_evergreen or not year_injected) else q_search
        jobs: list[tuple[str, Any]] = [
            ("bing", lambda: _fetch_bing_news(q_search, max_results=want)),
            ("wiki", lambda: _fetch_wikipedia_extracts(wiki_q, max_results=3)),
            ("gnews", lambda: _fetch_google_news(q_search, max_results=1 if is_evergreen else (2 if (is_weather or is_rate) else 3))),
            ("ddg", lambda: _fetch_ddg_instant(q if is_evergreen else q_search)),
            ("weather", lambda: _fetch_weather_snippet(q)),
            ("yahoo", lambda: _fetch_yahoo_spot(q)),
        ]
        return jobs

    # Parallel curl fetches — bounded wait; keep whatever finished
    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = [pool.submit(fn) for _, fn in _jobs()]
        try:
            for fut in as_completed(futs, timeout=12):
                try:
                    rows = fut.result()
                    if rows:
                        collected.extend(rows)
                except Exception:
                    continue
        except TimeoutError:
            for fut in futs:
                if fut.done():
                    try:
                        rows = fut.result(timeout=0)
                        if rows:
                            collected.extend(rows)
                    except Exception:
                        pass

    # Optional ddgs package boost when still thin (skip for weather — wttr is enough)
    if len(collected) < 3 and not is_weather:
        try:
            from ddgs import DDGS
        except Exception:
            try:
                from duckduckgo_search import DDGS  # type: ignore
            except Exception:
                DDGS = None  # type: ignore
        if DDGS is not None:
            try:
                def _ddg_news() -> list:
                    return list(DDGS().news(q_search, max_results=want))

                with ThreadPoolExecutor(max_workers=1) as pool:
                    for row in pool.submit(_ddg_news).result(timeout=5.0) or []:
                        if isinstance(row, dict):
                            collected.append(
                                {
                                    "title": str(row.get("title") or "")[:200],
                                    "body": str(row.get("body") or row.get("snippet") or "")[:520],
                                    "url": str(row.get("url") or row.get("link") or "")[:300],
                                    "source": "ddgs_news",
                                }
                            )
            except Exception:
                pass

    # Dedupe + rank against the ORIGINAL user ask (not year-injected search string)
    seen: set[str] = set()
    ranked: list[tuple[float, dict[str, str]]] = []
    for row in collected:
        if not isinstance(row, dict):
            continue
        title = str(row.get("title") or "").strip()
        body = str(row.get("body") or row.get("snippet") or row.get("text") or "").strip()
        href = str(row.get("href") or row.get("link") or row.get("url") or "").strip()
        if _is_junk_snippet_body(body):
            body = title
        key = re.sub(r"\s+", " ", (title or body)[:140].lower()).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        cleaned = {
            "title": title[:200],
            "body": body[:520],
            "url": href[:300],
            "source": str(row.get("source") or "")[:40],
        }
        if row.get("published"):
            cleaned["published"] = str(row.get("published"))[:80]
        ranked.append(
            (
                _score_snippet(
                    q_search,
                    cleaned,
                    original_query=q,
                    year_injected=year_injected,
                ),
                cleaned,
            )
        )

    ranked.sort(key=lambda x: x[0], reverse=True)

    # Weather asks: keep live sensor first, at most 2 news backups
    if is_weather:
        live = [r for s, r in ranked if (r.get("source") or "") == "wttr"]
        others = [r for s, r in ranked if (r.get("source") or "") != "wttr" and s >= 1.0]
        return (live + others)[: max(2, min(want, 4))]

    # Rate / market asks: prefer structured quotes + strong numbered snippets
    if is_rate:
        quotes = [r for s, r in ranked if (r.get("source") or "") in {"yahoo_quote", "yahoo_spot"}]
        strong_rates = [r for s, r in ranked if s >= 6.0 and (r.get("source") or "") not in {"yahoo_quote", "yahoo_spot"}]
        merged = quotes + strong_rates
        if merged:
            return merged[:want]
        return [r for _, r in ranked[:want]]

    # Evergreen: Wikipedia / instant answers first
    if is_evergreen:
        wikiish = [r for s, r in ranked if (r.get("source") or "") in {"wikipedia", "ddg_instant"} and s >= 1.0]
        others = [r for s, r in ranked if (r.get("source") or "") not in {"wikipedia", "ddg_instant"}]
        merged = wikiish + others
        if merged:
            return merged[:want]

    strong = [r for s, r in ranked if s >= 2.0]
    if strong:
        return strong[:want]
    return [r for _, r in ranked[:want]]


def _with_live_context(prompt: str, snippets: list[dict[str, str]]) -> str:
    today = date.today().isoformat()
    focus = _question_focus(prompt)
    if not snippets:
        return (
            f"TODAY'S DATE: {today}\n"
            f"{focus}\n"
            "LIVE WEB LOOKUP: no public snippets were retrieved for this ask. "
            "Do not invent breaking news, scores, winners, or live weather. "
            "Say clearly that the live lookup failed and answer only what you can "
            "without guessing current facts.\n\n"
            f"USER REQUEST:\n{prompt}"
        )
    lines = [
        f"TODAY'S DATE: {today}",
        focus,
        "LIVE WEB SNIPPETS (ground truth for current facts — do NOT override with training memory):",
    ]
    for i, sn in enumerate(snippets, 1):
        src = sn.get("source") or "web"
        bit = f"{i}. [{src}] {sn.get('title') or 'Source'}"
        if sn.get("published"):
            bit += f" ({sn['published']})"
        if sn.get("body"):
            bit += f" — {sn['body']}"
        if sn.get("url"):
            bit += f" ({sn['url']})"
        lines.append(bit)
    lines.append("")
    lines.append(
        "Instructions:\n"
        "- Answer ANY factual question the user asks (science, history, geography, sports, "
        "markets, weather, people, tech, culture, math) — global scope, not one country only.\n"
        "- First understand what the USER REQUEST is asking. Answer that — nothing else.\n"
        "- Open with a direct answer in the first sentence (name, number, yes/no, or fact).\n"
        "- For TIME-SENSITIVE facts (prices, rates, scores, weather, elections, current office-holders, "
        "breaking news): use LIVE MARKET QUOTE / LIVE WEB SNIPPETS as primary evidence.\n"
        "- For STABLE encyclopedic facts (capitals, definitions, historical dates, math, science basics): "
        "prefer Wikipedia/instant-answer snippets; if snippets are off-topic, you MAY answer from "
        "well-established general knowledge — do not refuse a capital/definition just because news RSS "
        "was noisy.\n"
        "- If the user named a year or place, match that year/place; ignore unrelated nearby news.\n"
        "- If snippets conflict, prefer the LIVE MARKET QUOTE or the snippet that directly answers the ask.\n"
        "- For time-sensitive asks only: if snippets do not answer the ask, say you could not verify "
        "from live sources — do not invent a live price or live score.\n"
        "- Do not dump unrelated background, lists, or nearby news."
    )
    lines.append("")
    lines.append("USER REQUEST:")
    lines.append(prompt)
    return "\n".join(lines)


def probe_live_web(*, force: bool = False) -> dict[str, Any]:
    """Reachability of live web snippets (separate from Groq). Cached ~30s."""
    now = time.time()
    cached = _LIVE_WEB_CACHE.get("result")
    if (
        not force
        and isinstance(cached, dict)
        and now - float(_LIVE_WEB_CACHE.get("t") or 0) < 30
    ):
        return cached
    enabled = bool(live_external_config().get("live_search"))
    result: dict[str, Any] = {
        "enabled": enabled,
        "ok": False,
        "snippet_count": 0,
        "reason": "",
    }
    if not enabled:
        result["reason"] = "EXTERNAL_AI_LIVE_SEARCH=off"
        _LIVE_WEB_CACHE["t"] = now
        _LIVE_WEB_CACHE["result"] = result
        return result
    try:
        snippets = fetch_web_snippets("latest world news today", max_results=3)
        result["snippet_count"] = len(snippets)
        if snippets:
            result["ok"] = True
            result["reason"] = "ok"
            result["sample"] = (snippets[0].get("title") or "")[:80]
        else:
            result["reason"] = "no_snippets"
    except Exception as exc:
        result["reason"] = f"error:{exc}"[:160]
    _LIVE_WEB_CACHE["t"] = now
    _LIVE_WEB_CACHE["result"] = result
    return result


def needs_live_knowledge(text: str) -> bool:
    """Live web is DEFAULT for outbound Q&A — any topic, any country.

    Groq has no live KB. Opt out only for clear drafting/creative jobs.
    No topic allow-list — coverage is A–Z by default.
    """
    t = (text or "").strip()
    if not t:
        return False
    if _LIVE_SKIP_RE.search(t) and "?" not in t and not _LIVE_RATE_RE.search(t):
        return False
    if (
        _LIVE_CREATIVE_RE.search(t)
        and "?" not in t
        and not _LIVE_KNOWLEDGE_RE.search(t)
        and not _LIVE_RATE_RE.search(t)
    ):
        return False
    # Default ON for normal-length asks (global facts, markets, sports, science, …)
    if len(t) <= 800:
        return True
    if "?" in t or _LIVE_RATE_RE.search(t) or _LIVE_KNOWLEDGE_RE.search(t):
        return True
    if re.match(
        r"(?i)^\s*(who|what|when|where|which|how|why|is|are|was|were|did|does|do|can|will|should)\b",
        t,
    ):
        return True
    return False


def is_current_event_query(text: str) -> bool:
    """Backward-compatible alias — prefer needs_live_knowledge()."""
    return needs_live_knowledge(text)


def _has_hard_secret(text: str) -> bool:
    """Match hard secrets on raw text plus spaced-compact and base64-decoded surfaces."""
    for variant in text_variants_for_secret_scan(text or ""):
        if any(p.search(variant) for p in HARD_SECRET_PATTERNS):
            return True
    return False


_EMAIL_ONLY_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)


def _has_hard_secret_excluding_analysis_emails(text: str) -> bool:
    """Like _has_hard_secret but ignore bare emails (scrubbed as Email_N on analysis lane)."""
    stripped = _EMAIL_ONLY_RE.sub("Email_X", text or "")
    return _has_hard_secret(stripped)


def _is_analysis_scrubbable_hide(item: dict) -> bool:
    """Business contact / logo / table-cell hides that synthetic scrub replaces — not private-only."""
    dept = (item.get("department") or item.get("type") or "").lower()
    val = str(item.get("value") or "")
    if dept == "pii" and _EMAIL_ONLY_RE.fullmatch(val.strip()):
        return True
    if dept in {"sales", "finance", "pii", "hr"} and (
        ExhaustDetector._is_name_like_span(val)
        or bool(re.search(r"(?i)\$|USD|million|billion|\d", val))
        or _EMAIL_ONLY_RE.fullmatch(val.strip())
        or bool(re.match(r"(?i)^[A-Z]{2,5}[-_]\d{3,}$", val.strip()))
    ):
        return True
    return False


def _token_entropy(token: str) -> float:
    if not token:
        return 0.0
    freq: dict[str, int] = {}
    for ch in token:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(token)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


def _has_suspicious_entropy(text: str) -> bool:
    """True when a long high-entropy blob looks like a key/token (strict Safe fail-up)."""
    for tok in _ENTROPY_TOKEN_RE.findall(text or ""):
        if tok.isdigit():
            continue
        if re.fullmatch(r"[A-Za-z]+", tok):
            continue  # long English-ish word
        classes = sum(
            [
                any(c.islower() for c in tok),
                any(c.isupper() for c in tok),
                any(c.isdigit() for c in tok),
                any(c in "_-+/=" for c in tok),
            ]
        )
        if classes >= 3 and _token_entropy(tok) >= 3.2:
            return True
        if classes >= 2 and len(tok) >= 40 and _token_entropy(tok) >= 3.5:
            return True
    return False


def last_mile_classify(text: str, detector: ExhaustDetector | None = None) -> dict[str, Any]:
    """Re-run detect + classify on outbound text (strict Safe / Medium confirm)."""
    det = detector or ExhaustDetector()
    analysis = det.analyze_prompt(text or "")
    decision = classify_route(analysis, text or "")
    return {"analysis": analysis, "decision": decision}


def classify_route(analysis: dict, raw_prompt: str) -> dict[str, Any]:
    """Decide SAFE / MODERATE / HIGH from detector analysis + hard-secret scan.

    HIGH  = credentials, regulated people/health data, hard IDs, or unretractable hide
    MODERATE = commercial specifics that can be generalized then sent outside
    SAFE = strictly clean — nothing concrete AND no suspicious entropy
    """
    score = int(analysis.get("risk_score") or 0)
    flagged = analysis.get("flagged_items") or []
    hide_items = [
        f for f in flagged if (f.get("action") or "hide") == "hide"
    ]
    analysis_mode = ExhaustDetector.is_ratio_analysis_prompt(
        raw_prompt or ""
    ) or ExhaustDetector.looks_like_dataset(raw_prompt or "")
    hard = (
        _has_hard_secret_excluding_analysis_emails(raw_prompt)
        if analysis_mode
        else _has_hard_secret(raw_prompt)
    )
    basic_high = _basic_risk_forces_high(raw_prompt)
    # Analysis lane: bare business emails are scrubbed — don't force High via "email" cue alone
    if analysis_mode and basic_high:
        folded_no_email = normalize_for_match(
            _EMAIL_ONLY_RE.sub(" ", raw_prompt or "")
        )
        basic_high = any(p.search(folded_no_email) for p in BASIC_HIGH_RISK_CUES)
    dyn_hits = dynamic_high_signals(raw_prompt)
    dynamic_high = bool(dyn_hits)
    entropy_hit = _has_suspicious_entropy(raw_prompt)
    high_hides = [f for f in hide_items if _hide_forces_high(f)]
    if analysis_mode:
        high_hides = [f for f in high_hides if not _is_analysis_scrubbable_hide(f)]
        # CSV/markdown datasets: cell DLP noise (e.g. "emp_id,revenue") is rewritten by
        # table_synthetic — only true credential/health hides stay High.
        if ExhaustDetector.looks_like_dataset(raw_prompt or ""):
            high_hides = [
                f
                for f in high_hides
                if (f.get("department") or f.get("type") or "").lower()
                in {"engineering", "security", "healthcare"}
            ]
    # Healthcare / PII hide spans
    high_dept_hit = any(
        (f.get("department") or f.get("type") or "").lower() in HIGH_FORCE_DEPARTMENTS
        for f in hide_items
        if not (analysis_mode and _is_analysis_scrubbable_hide(f))
    )
    if analysis_mode and ExhaustDetector.looks_like_dataset(raw_prompt or ""):
        high_dept_hit = any(
            (f.get("department") or f.get("type") or "").lower() == "healthcare"
            and (f.get("action") or "") == "hide"
            for f in hide_items
        )

    reasons: list[str] = []
    if hard:
        reasons.append("Hard secret / credential / regulated ID shape detected")
    if basic_high:
        reasons.append("Basic risk language detected (keys, credentials, people/health data) — private AI only")
    if dynamic_high:
        reasons.append(
            "Dynamic basic-knowledge High signal — "
            + "; ".join(dyn_hits[:3])
            + ("…" if len(dyn_hits) > 3 else "")
            + " — private AI only"
        )
    if entropy_hit:
        reasons.append("High-entropy token looks like a secret — fail-closed (strict Safe)")
    if high_hides:
        depts = sorted(
            {
                (f.get("department") or f.get("type") or "?")
                for f in high_hides
            }
        )
        reasons.append(
            f"High-sensitivity concrete span(s) must stay private: {', '.join(depts)}"
        )
    if high_dept_hit and not high_hides:
        reasons.append("Healthcare / regulated personal detail detected")

    if hard or basic_high or dynamic_high or entropy_hit or high_hides or high_dept_hit:
        level = "high"
        destination = "private"
        sanitize = False  # private boundary may see cleartext
        if not reasons:
            reasons.append("Classified high — private AI only (never external)")
    elif hide_items:
        # Moderate only when there is something concrete to hide/sanitize.
        redacted = (analysis.get("redacted_text") or raw_prompt or "").strip()
        if _norm_text(redacted) == _norm_text(raw_prompt):
            # Strict Safe: unretractable hide → HIGH (never downgrade to Safe)
            level = "high"
            destination = "private"
            sanitize = False
            reasons.append(
                "Hide spans detected but redaction did not change text — "
                "fail-closed to private (strict Safe)"
            )
        else:
            level = "moderate"
            destination = "external"
            sanitize = True
            reasons.append(
                f"Medium — {len(hide_items)} business detail(s) will be hidden/rewritten "
                f"before external AI (score {score})"
            )
            if score >= MODERATE_MAX_SCORE and not hard:
                reasons.append(
                    "Elevated score without hard secret — sanitize→external (not private)"
                )
    else:
        level = "safe"
        destination = "external"
        sanitize = False
        keep_n = sum(1 for f in flagged if (f.get("action") or "") == "keep")
        if keep_n:
            reasons.append(
                f"Topic word(s) noted ({keep_n}) but nothing concrete to hide — "
                "Safe · send external as-is"
            )
        else:
            reasons.append(
                "No sensitive spans and low risk — Safe · send external as-is"
            )

    lane = {
        "safe": "external_safe",
        "moderate": "external_sanitized",
        "high": "private_high",
    }[level]
    badge = {
        "safe": "SAFE · OUTSIDE AI",
        "moderate": "MEDIUM · HIDE THEN OUTSIDE",
        "high": "HIGH · PRIVATE AI ONLY",
    }[level]

    return {
        "risk_level": level,
        "destination": destination,
        "sanitize": sanitize,
        "lane": lane,
        "lane_badge": badge,
        "reasons": reasons,
        "thresholds": {
            "safe_max_score": SAFE_MAX_SCORE,
            "moderate_max_score": MODERATE_MAX_SCORE,
            "high_force_departments": sorted(HIGH_FORCE_DEPARTMENTS),
            "high_requires": "hard_secret_or_people_health_credential_span",
            "strict_safe": True,
            "high_risk_catalog": HIGH_RISK_CATALOG,
            "lane_contract": {
                "safe": "Strictly clean — external as-is (no confirm)",
                "moderate": "Business specifics — hide/rewrite, then external",
                "high": "Identity / credentials / people / health / unretracted hide — private AI only",
            },
        },
        "hard_secret_detected": hard,
        "suspicious_entropy": entropy_hit,
        "dynamic_high_signals": dyn_hits,
        "external_mode": EXTERNAL_AI_MODE if destination == "external" else "n/a",
    }


PRIVATE_LLM_SYSTEM = (
    "You are an internal assistant running only on this machine. "
    "Always answer the user's question. Do not skip it. Do not refuse the whole request.\n"
    "Rules:\n"
    "1. Never repeat API keys, passwords, tokens, SSNs, or other raw secrets.\n"
    "2. Labels like company 01, employee 01, customer 01, credential 01 are already-safe stand-ins — answer as if they were the original names/values.\n"
    "3. Give practical next steps: rotate/revoke credentials, follow HR/policy process, draft talking points, checklists.\n"
    "4. If the ask is about a leaked key or password, explain rotation and containment — do not use the secret.\n"
    "5. Keep the same intent as the question. Write a complete, useful answer in clear English.\n"
    "6. After the answer, add one short line asking the user to resend using the safer wording if they want more detail."
)

_REFUSAL_RE = re.compile(
    r"(?i)\b("
    r"i\s+(?:can't|cannot|won't|will not|am unable to)|"
    r"i(?:['’]m| am) unable|"
    r"as an ai|"
    r"against my (?:guidelines|programming|policies)|"
    r"i must (?:not|decline)|"
    r"cannot (?:assist|help|provide|share)|"
    r"i('m| am) not (?:able|allowed) to|"
    r"sorry,? i can(?:not|'t) help"
    r")\b"
)


def _looks_like_refusal_or_empty(text: str) -> bool:
    t = (text or "").strip()
    if len(t) < 12:
        return True
    if t.startswith("PRIVATE LLM UNAVAILABLE"):
        return True
    return bool(_REFUSAL_RE.search(t))


def _scrub_hard_secrets(text: str, catalog: dict | None = None) -> str:
    """Replace remaining key/token shapes with credential 01, credential 02, …"""
    out = text or ""
    store = catalog if catalog is not None else {}
    for pat in HARD_SECRET_PATTERNS:
        def _repl(m: re.Match[str], _store: dict = store) -> str:
            return ExhaustDetector.labeled_entity("credential", m.group(0), _store)

        out = pat.sub(_repl, out)
    return out


def prepare_high_private_prompt(raw_prompt: str, analysis: dict) -> tuple[str, dict]:
    """Safer wording for High: rewrite + strip leftover secret shapes. Never send raw keys."""
    rewrite_info = suggest_rewrite(raw_prompt, analysis)
    rewritten = (rewrite_info.get("rewrite_suggestion") or "").strip()
    redacted = ((analysis or {}).get("redacted_text") or raw_prompt or "").strip()
    catalog: dict[str, dict[str, str]] = {}
    if rewritten and _norm_text(rewritten) != _norm_text(raw_prompt):
        sent = rewritten
    elif redacted and _norm_text(redacted) != _norm_text(raw_prompt):
        sent = redacted
    else:
        sent = raw_prompt or ""
    sent = _scrub_hard_secrets(sent, catalog)
    if _norm_text(sent) == _norm_text(raw_prompt or ""):
        sent = _scrub_hard_secrets(raw_prompt or "", catalog)
    return sent, rewrite_info


def _high_playbook_answer(safe_ask: str) -> str:
    ask = (safe_ask or "").strip() or "(same question, with secrets replaced by labels like credential 01)"
    return (
        "This stayed on this machine — nothing was sent to an outside AI.\n\n"
        "Here is a safe answer on the cleaned version of your question:\n"
        "- If this involved an access credential: rotate and revoke it, treat it as exposed on this device, "
        "store the new value in a vault, and never paste live secrets into chat.\n"
        "- If this involved people, pay, or health identifiers: follow HR/policy process; discuss the situation, "
        "not the raw values.\n"
        "- I can help with checklists, rotation steps, and how to word the ask — not with using the original secret.\n\n"
        "Please resend it like this so I can answer it properly:\n"
        f"{ask}"
    )


def _with_resend_nudge(answer: str, safe_ask: str) -> str:
    body = (answer or "").strip()
    ask = (safe_ask or "").strip()
    if not ask:
        return body
    if re.search(r"(?i)please resend", body):
        return body
    return (
        f"{body}\n\n"
        "Please resend it like this so I can answer it properly "
        "(same question, without the original secrets):\n"
        f"{ask}"
    )


def call_private_llm(
    model: str, prompt: str, *, system: str | None = None
) -> tuple[str, dict]:
    """Private / on-prem model (Ollama). Fail-closed on error — never fall back to external."""
    url = resolve_ollama_url()
    meta = {
        "provider": "private_ollama",
        "model": model,
        "ok": False,
        "fail_closed": True,
        "ollama_url": url,
    }
    payload: dict[str, Any] = {"model": model, "prompt": prompt, "stream": False}
    if system:
        payload["system"] = system
    try:
        # trust_env=False: ignore HTTP(S)_PROXY so High never routes via a dead local proxy
        with requests.Session() as session:
            session.trust_env = False
            session.proxies = {}
            response = session.post(
                url,
                json=payload,
                timeout=20,
            )
        if response.status_code != 200:
            meta["error"] = f"HTTP {response.status_code}"
            return (
                "PRIVATE LLM UNAVAILABLE — fail-closed. "
                "High-risk prompt was NOT sent to any external AI platform. "
                f"Details: HTTP {response.status_code}. "
                f"Is Ollama running with model '{model}'? Tried {url}",
                meta,
            )
        data = response.json()
        text = data.get("response") or ""
        meta["ok"] = True
        return text, meta
    except Exception as exc:
        meta["error"] = str(exc)
        return (
            "PRIVATE LLM UNAVAILABLE — fail-closed. "
            "High-risk prompt was NOT sent to any external AI platform. "
            f"Details: {exc}. "
            f"Is Ollama running with model '{model}'? Tried {url}",
            meta,
        )


def answer_high_private(
    model: str, raw_prompt: str, analysis: dict
) -> tuple[str, dict, str, dict]:
    """Always return a useful High answer: scrub → Ollama with system prompt → playbook if it still skips."""
    sent, rewrite_info = prepare_high_private_prompt(raw_prompt, analysis)
    ai_raw, meta = call_private_llm(model, sent, system=PRIVATE_LLM_SYSTEM)
    if _looks_like_refusal_or_empty(ai_raw) or not meta.get("ok"):
        text = _high_playbook_answer(sent)
        meta = {**meta, "used_playbook": True, "answered": True}
        return text, meta, sent, rewrite_info
    text = _with_resend_nudge(ai_raw, sent)
    meta = {**meta, "used_playbook": False, "answered": True, "scrubbed_for_private": True}
    return text, meta, sent, rewrite_info


def suggest_rewrite(raw_prompt: str, analysis: dict) -> dict[str, Any]:
    """Build a generalized rewrite that MUST differ when hide spans exist.

    Strategy (meaning-preserving):
    0a) Full table/dataset → synthetic peers (scaled numbers, fictional names,
        format-preserved keys) with restore_map back to originals.
    0b) Ratio/analysis prompts → session-scaled finance + Org/Person/Email/ID labels
       so multiples and YoY% stay mathematically valid for the external model.
    1) Else replace each HIDE span with its generalization hint — numbered labels for
       companies/people (company 01, employee 02) and nearby figures for money/%.
    2) Longest-first substitution so nested spans don't leak leftovers.
    3) If still identical to the original, rebuild from redacted_text by swapping
       <DEPT_N> tokens for hints — so the recommended panel is never a no-op copy.
    4) Soft synonym pass + light grammar cleanup so the ask stays coherent.
    """
    redacted = (analysis or {}).get("redacted_text") or (raw_prompt or "")
    flagged = list((analysis or {}).get("flagged_items") or [])
    hide_items = [
        it for it in flagged if (it.get("action") or "hide") == "hide"
    ]

    def _apply_scrub_result(scrub: dict, *, scale_flag: str) -> dict[str, Any] | None:
        if not scrub.get("applicable") or not scrub.get("scrubbed"):
            return None
        restore_map = dict(scrub.get("restore_map") or {})
        merged_map = dict((analysis or {}).get("token_map") or {})
        merged_map.update(restore_map)
        if isinstance(analysis, dict):
            analysis["token_map"] = merged_map
            analysis["analysis_scrub"] = {
                "factor": scrub.get("factor"),
                "mode": scrub.get("mode"),
                "counts": scrub.get("counts"),
                "restore_map": restore_map,
                "column_kinds": scrub.get("column_kinds"),
            }
            analysis["redacted_text"] = scrub["scrubbed"]
        return {
            "redacted_prompt": scrub["scrubbed"],
            "rewrite_suggestion": scrub["scrubbed"],
            "differs_from_original": True,
            "placeholders_differ": True,
            scale_flag: True,
            "analysis_scale": scrub.get("mode") in {"analysis_scale", "table_synthetic"},
            "analysis_factor": scrub.get("factor"),
            "analysis_restore_map": restore_map,
            "hints_applied": [
                {
                    "value": orig,
                    "token": standin,
                    "generalization_hint": standin,
                    "department": (
                        "finance"
                        if standin[:1] in "$€£₹"
                        or re.match(r"(?i)(?:USD|EUR|GBP|₹)", standin)
                        or re.match(r"^[-+]?\d", standin)
                        else "pii"
                        if "@" in standin or standin.startswith(("Person_", "person"))
                        or " " in standin and standin[:1].isupper()
                        else "operations"
                    ),
                }
                for standin, orig in restore_map.items()
            ],
        }

    # --- Table / dataset lane (full grid) — only when company-private ---
    if ExhaustDetector.looks_like_dataset(raw_prompt or ""):
        try:
            from public_knowledge import assess_enterprise_sensitivity

            privacy = assess_enterprise_sensitivity(raw_prompt or "", allow_network=True)
        except Exception:
            privacy = {"scrub_enterprise": True, "reasons": ["privacy assess unavailable"]}
        if privacy.get("scrub_enterprise"):
            applied = _apply_scrub_result(
                ExhaustDetector.build_table_scrub(raw_prompt or ""),
                scale_flag="table_synthetic",
            )
            if applied:
                applied["privacy"] = privacy
                return applied
        # Public-only dataset → fall through without synthetic rewrite

    # --- Analysis lane: scale money only for non-public / enterprise-private asks ---
    if ExhaustDetector.is_ratio_analysis_prompt(raw_prompt or ""):
        try:
            from public_knowledge import assess_enterprise_sensitivity

            privacy = assess_enterprise_sensitivity(raw_prompt or "", allow_network=True)
        except Exception:
            privacy = {"scrub_enterprise": True, "reasons": ["privacy assess unavailable"]}
        if privacy.get("scrub_enterprise"):
            applied = _apply_scrub_result(
                ExhaustDetector.build_analysis_scrub(raw_prompt or ""),
                scale_flag="analysis_scale",
            )
            if applied:
                applied["privacy"] = privacy
                return applied
        # Public-company analysis (e.g. Microsoft revenue) — leave figures clear

    rewrite = raw_prompt or ""
    catalog: dict[str, dict[str, str]] = {}

    def _hint_for(it: dict) -> str:
        value = str(it.get("value") or "")
        hint = ExhaustDetector.sanitize_rewrite_hint(
            str(it.get("generalization_hint") or "").strip() or None,
            value,
            catalog,
        )
        if hint:
            return hint
        dept = (it.get("department") or it.get("type") or "detail").lower()
        if re.fullmatch(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}", value.strip()):
            kind = ExhaustDetector._person_kind(dept, (raw_prompt or "").lower())
            return ExhaustDetector.labeled_entity(kind, value, catalog)
        if re.search(
            r"(?i)\b(?:Inc|Corp|Corporation|Ltd|LLC|Company|GmbH|PLC|"
            r"Solutions|Technologies|Technology|Systems|Software|Labs|Group|"
            r"Partners|Ventures|Industries|Holdings|Networks|Dynamics|"
            r"Analytics|Consulting|Services)\b",
            value,
        ):
            return ExhaustDetector.labeled_entity("company", value, catalog)
        defaults = {
            "finance": "a financial figure",
            "sales": ExhaustDetector.labeled_entity("company", value or "company", catalog),
            "hr": ExhaustDetector.labeled_entity("employee", value or "employee", catalog),
            "engineering": "an access credential",
            "security": "a security detail",
            "pii": ExhaustDetector.labeled_entity("employee", value or "employee", catalog),
            "healthcare": "a clinical matter",
            "legal": "an internal legal matter",
        }
        out = defaults.get(dept, "a non-specific detail")
        return ExhaustDetector.sanitize_rewrite_hint(out, value, catalog) or out

    # Longest hide values first
    items = sorted(
        hide_items,
        key=lambda it: len(str(it.get("value") or "")),
        reverse=True,
    )

    for item in items:
        value = str(item.get("value") or "").strip()
        hint = _hint_for(item)
        if not value or value not in rewrite:
            continue

        # "salary of $145,000" / "salary is $145,000" → mid-level compensation phrasing
        if re.search(r"(?i)compensation|salary|pay", hint):
            wider = re.compile(
                rf"(?i)\b(?:a\s+)?(?:salary|compensation|pay)\s+(?:of|is)\s+{re.escape(value)}\b"
            )
            if wider.search(rewrite):
                rewrite = wider.sub(hint, rewrite, count=1)
                continue

        # Prefer preposition-aware swaps for money magnitudes
        if re.search(
            r"(?i)(?:tens|hundreds) of millions|billions|hundreds of thousands|"
            r"tens of thousands|substantial sum|pricing|dollars|range|compensation|"
            r"six-figure|few million|several million|lakh|crore|"
            r"confidential amount|rupee|"
            r"\$\d|\d%\s+to\s+\d",
            hint,
        ):
            patterned = re.compile(
                rf"(?i)(?:\bvalued\s+at\s+|\b(?:for|of|at|worth)\s+){re.escape(value)}\b"
            )

            def _money_sub(m: re.Match[str], _hint: str = hint, _value: str = value) -> str:
                lead = m.group(0)[: -len(_value)].strip().lower()
                h = _hint
                if lead.startswith("for"):
                    return f"for {h}"
                if lead.startswith("valued"):
                    return f"valued at {h}"
                if lead.startswith("worth"):
                    return f"worth {h}"
                if lead.startswith("of") or lead.startswith("at"):
                    return f"{lead.split()[0]} {h}"
                return h

            if patterned.search(rewrite):
                rewrite = patterned.sub(_money_sub, rewrite, count=1)
                continue

        # Avoid "the a recent…" by absorbing a preceding article when hint has one
        if re.match(r"(?i)a\s+", hint):
            article_pat = re.compile(
                rf"(?i)\b(the|a|an)\s+{re.escape(value)}\b"
            )
            if article_pat.search(rewrite):
                rewrite = article_pat.sub(hint, rewrite, count=1)
                continue

        rewrite = rewrite.replace(value, hint, 1)

    # Fallback: build from placeholders so rewrite can never equal the original
    # when redaction actually changed the outbound text.
    if hide_items and _norm_text(rewrite) == _norm_text(raw_prompt):
        rewrite = redacted
        for item in sorted(
            hide_items,
            key=lambda it: len(str(it.get("token") or "")),
            reverse=True,
        ):
            token = str(item.get("token") or "").strip()
            if token and token in rewrite:
                rewrite = rewrite.replace(token, _hint_for(item))

    # Soft synonym pass: remaining sensitive jargon → plain equivalent words
    rewrite = ExhaustDetector.apply_meaning_safe_synonyms(rewrite)

    # Defense-in-depth: never leave generic company stand-ins in the suggested rewrite
    company_seeds = [
        str(it.get("value") or "")
        for it in items
        if re.search(
            r"(?i)\b(?:Inc|Corp|Corporation|Ltd|LLC|Company|Solutions|Technologies|"
            r"Labs|Group|Partners|Systems|Software|Analytics|Consulting)\b",
            str(it.get("value") or ""),
        )
        or (it.get("department") or it.get("type") or "").lower() == "sales"
    ]
    rewrite = ExhaustDetector.scrub_banned_company_standins(
        rewrite,
        seed_values=company_seeds or [str(it.get("value") or "company") for it in items],
        catalog=catalog,
    )

    # Grammar / fluency cleanup after substitutions
    rewrite = re.sub(r"(?i)\babout\s+about\b", "about", rewrite)
    rewrite = re.sub(r"(?i)\b(a|an)\s+around\b", "around", rewrite)
    rewrite = re.sub(r"(?i)\b(a|an)\s+about\b", "about", rewrite)
    rewrite = re.sub(r"\bthe\s+(a|an)\b", r"\1", rewrite, flags=re.I)
    rewrite = re.sub(r"\b(a|an)\s+\1\b", r"\1", rewrite, flags=re.I)
    rewrite = re.sub(r"\b(a|an)\s+an\b", "an", rewrite, flags=re.I)
    rewrite = re.sub(r"(?i)\bthis\s+(a\s+recent\s+(?:quarter|fiscal year))\b", r"\1", rewrite)
    rewrite = re.sub(r"(?i)\babout\s+(a\s+substantial\s+sum)\b", r"\1", rewrite)
    rewrite = re.sub(
        r"(?i)\b(by\s+\d+(?:\.\d+)?\s*%)\s+(a\s+recent\s+(?:quarter|fiscal year))\b",
        r"\1 in \2",
        rewrite,
    )
    # "operating costs a modest percentage decline" → "a modest percentage decline in operating costs"
    rewrite = re.sub(
        r"(?i)\b(operating costs|capital spending|profit and loss|recurring revenue)\s+"
        r"(a\s+(?:small|modest|sizable|large)\s+percentage\s+(?:decline|increase|change))\b",
        r"\2 in \1",
        rewrite,
    )
    rewrite = re.sub(r"(?i)\bthe\s+(a\s+modest\s+percentage)", r"\1", rewrite)
    rewrite = re.sub(r"(?i)\bthe\s+(a\s+(?:small|sizable|large)\s+percentage)", r"\1", rewrite)
    # "valued at about tens of millions" → "valued at about tens of millions of dollars" readability
    rewrite = re.sub(
        r"(?i)\b(valued at about|worth about|of about)\s+"
        r"((?:tens|hundreds)\s+of\s+(?:thousands|millions)|billions)\b",
        r"\1 \2",
        rewrite,
    )
    # "a dip of a … decline" → "a … decline"
    rewrite = re.sub(
        r"(?i)\b(?:a\s+)?(?:dip|drop|decline|decrease|increase|growth)\s+of\s+"
        r"(a\s+[^.]{0,80}?\s+(?:decline|increase|change))\b",
        r"\1",
        rewrite,
    )
    # "Their a sizable percentage decline in profit" → readable framing
    rewrite = re.sub(
        r"(?i)\b(their|its)\s+(a\s+(?:small|modest|sizable|large)\s+percentage\s+"
        r"(?:decline|increase|change)(?:\s+in\s+[A-Za-z][\w]*(?:\s+[A-Za-z][\w]*)?)?)\b",
        r"\1 figures show \2",
        rewrite,
    )
    # "profit a sizable percentage decline" (metric kept beside hint)
    rewrite = re.sub(
        r"(?i)\b(profit|revenue|earnings|valuation|margin|opex|capex|costs?)\s+"
        r"(a\s+(?:small|modest|sizable|large)\s+percentage\s+(?:decline|increase|change))\b",
        r"\1 that saw \2",
        rewrite,
    )
    # "cutting operating costs by a sizable percentage" — already fine; fix "costs by by"
    rewrite = re.sub(r"(?i)\bby\s+by\b", "by", rewrite)
    # "worth a substantial sum million" cleanup
    rewrite = re.sub(
        r"(?i)\b(worth|valued at|of)\s+(a\s+substantial\s+sum)\s*(?:million|billion|dollars)?\b",
        r"\1 \2",
        rewrite,
    )
    rewrite = re.sub(
        r"(?i)\b(?:employee|salary|compensation|pay)\s+is\s+"
        r"((?:entry|early-career|mid|senior|executive)-level compensation)\b",
        r"\1",
        rewrite,
    )
    rewrite = re.sub(
        r"(?i)\b(?:a\s+)?(?:salary|compensation(?:\s+details)?)\s+of\s+"
        r"((?:entry|early-career|mid|senior|executive)-level compensation)\b",
        r"\1",
        rewrite,
    )
    # "a recent commercial deal deal" / "acquisition acquisition"
    rewrite = re.sub(
        r"(?i)\b(deal|acquisition|customer|employee|company)\s+\1\b",
        r"\1",
        rewrite,
    )
    rewrite = re.sub(r"\s{2,}", " ", rewrite).strip()
    rewrite = re.sub(r"\s+([,.!?])", r"\1", rewrite)

    differs = _norm_text(rewrite) != _norm_text(raw_prompt)
    placeholders_differ = _norm_text(redacted) != _norm_text(raw_prompt)

    return {
        "redacted_prompt": redacted,
        "rewrite_suggestion": rewrite,
        "differs_from_original": differs,
        "placeholders_differ": placeholders_differ,
        "hints_applied": [
            {
                "value": it.get("value"),
                "token": it.get("token"),
                "generalization_hint": _hint_for(it),
                "department": it.get("department") or it.get("type"),
            }
            for it in items
        ],
    }


def route_inference(
    *,
    raw_prompt: str,
    analysis: dict,
    private_model: str,
    external_model: str | None = None,
    history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Run classify → optional sanitize → destination call → optional restore fields."""
    decision = classify_route(analysis, raw_prompt)
    token_map = analysis.get("token_map") or {}
    redacted = analysis.get("redacted_text") or raw_prompt

    if decision["destination"] == "private":
        # Always answer High: scrub secrets, Ollama with a "don't skip" system prompt,
        # playbook + "please resend like this" if the model still refuses.
        ai_raw, call_meta, sent, rewrite_info = answer_high_private(
            private_model, raw_prompt, analysis
        )
        restored = ai_raw
        destination_label = (
            "Private LLM (Ollama · playbook)"
            if call_meta.get("used_playbook")
            else "Private LLM (Ollama · safe High answer)"
        )
        call_meta = {
            **call_meta,
            "scrubbed_for_private": True,
            "rewrite_suggestion": (rewrite_info or {}).get("rewrite_suggestion"),
        }
    else:
        sent = redacted if decision["sanitize"] else raw_prompt
        ai_raw, call_meta = call_external_ai(
            external_model,
            sent,
            sanitized=decision["sanitize"],
            history=history,
        )
        restored = ai_raw
        if decision["sanitize"]:
            # Always run restore helper: maps known tokens + analysis-scale reverse
            scrub = (analysis or {}).get("analysis_scrub") or {}
            restore_map = dict(token_map or {})
            restore_map.update(scrub.get("restore_map") or {})
            restored = ExhaustDetector().restore_text(
                ai_raw, restore_map, analysis_scrub=scrub or None
            )
        destination_label = (
            "External AI (sanitized)" if decision["sanitize"] else "External AI (as-is)"
        )

    return {
        "decision": decision,
        "prompt_sent": sent,
        "llm_raw_response": ai_raw,
        "restored_response": restored,
        "call_meta": call_meta,
        "destination_label": destination_label,
    }
