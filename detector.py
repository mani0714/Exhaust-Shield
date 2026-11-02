from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

# Spaced/dashed secret evasion: "A K I A …" / "AKIA-ABCD-…" → compact before pattern scan.
_SPACED_SECRET_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z0-9](?:[\s\-]+[A-Za-z0-9]){9,})(?![A-Za-z0-9])"
)
# Token-like base64 blobs long enough to hide an access key / credential.
_BASE64_SECRET_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])"
)


def normalize_for_match(text: str) -> str:
    """Case- and punctuation-insensitive surface for risk matching.

    Letters/digits/$/% kept; hyphens/underscores kept inside tokens.
    Other punctuation becomes a space.
    """
    if not text:
        return ""
    out: list[str] = []
    prev_space = True
    n = len(text)
    for i, ch in enumerate(text):
        if ch.isalnum() or ch in "$%":
            out.append(ch.lower())
            prev_space = False
        elif (
            ch in "-_"
            and not prev_space
            and i + 1 < n
            and text[i + 1].isalnum()
        ):
            out.append(ch)
            prev_space = False
        else:
            if not prev_space:
                out.append(" ")
                prev_space = True
    return "".join(out).strip()


def build_match_surface(text: str) -> tuple[str, list[int]]:
    """Normalized scan string + map from each norm index → original index."""
    if not text:
        return "", []
    chars: list[str] = []
    index_map: list[int] = []
    prev_space = True
    n = len(text)
    for i, ch in enumerate(text):
        if ch.isalnum() or ch in "$%":
            chars.append(ch.lower())
            index_map.append(i)
            prev_space = False
        elif (
            ch in "-_"
            and not prev_space
            and i + 1 < n
            and text[i + 1].isalnum()
        ):
            chars.append(ch)
            index_map.append(i)
            prev_space = False
        else:
            if not prev_space:
                chars.append(" ")
                index_map.append(i)
                prev_space = True
    while chars and chars[-1] == " ":
        chars.pop()
        index_map.pop()
    return "".join(chars), index_map


def compact_spaced_secret_candidates(text: str) -> str:
    """Strip internal spaces/dashes from spaced-out token runs only (not whole prose)."""
    if not text:
        return text

    def _compact(match: re.Match[str]) -> str:
        return re.sub(r"[\s\-]+", "", match.group(0))

    return _SPACED_SECRET_CANDIDATE.sub(_compact, text)


def iter_base64_decoded_fragments(text: str) -> list[str]:
    """Decode clean base64 token-like substrings for a second-pass secret scan."""
    if not text:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for match in _BASE64_SECRET_CANDIDATE.finditer(text):
        token = match.group(0)
        pad = (-len(token)) % 4
        try:
            raw = base64.b64decode(token + ("=" * pad), validate=False)
        except Exception:
            continue
        if not raw:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not decoded or not all(ch.isprintable() or ch in "\n\r\t" for ch in decoded):
            continue
        if decoded in seen:
            continue
        seen.add(decoded)
        out.append(decoded)
    return out


def text_variants_for_secret_scan(text: str) -> list[str]:
    """Original + normalized + spaced-compacted + base64-decoded surfaces."""
    if not text:
        return []
    variants: list[str] = [text]
    folded = normalize_for_match(text)
    if folded and folded not in variants:
        variants.append(folded)
    compacted = compact_spaced_secret_candidates(text)
    if compacted != text:
        variants.append(compacted)
    for frag in iter_base64_decoded_fragments(text):
        variants.append(frag)
        frag_fold = normalize_for_match(frag)
        if frag_fold and frag_fold not in variants:
            variants.append(frag_fold)
        frag_compact = compact_spaced_secret_candidates(frag)
        if frag_compact != frag:
            variants.append(frag_compact)
    return variants


class ExhaustDetector:
    """Department-scoped sensitive-data patterns for prompt redaction.

    Coverage goal for the pilot: common enterprise secret / PII / confidential
    spans across major departments (~80–90% of typical demo & boardroom cases).
    Novel shapes are partially caught via labeled assignments and high-entropy
    token heuristics; true unknowns should fail closed upstream (human vault).
    """

    PATTERNS = {
        # ------------------------------------------------------------------
        # Engineering / DevOps / cloud / SaaS secrets
        # ------------------------------------------------------------------
        "engineering": [
            # OpenAI / Anthropic / LLM providers
            r"sk-[a-zA-Z0-9]{20,}",
            r"sk-proj-[a-zA-Z0-9_-]+",
            r"sk-ant-[a-zA-Z0-9_-]{20,}",
            r"(?i)\bgsk_[A-Za-z0-9]{20,}\b",  # Groq
            r"(?i)\bxai-[A-Za-z0-9]{20,}\b",  # xAI
            r"(?i)\b(?:openai|anthropic|huggingface|cohere|mistral|groq|gemini|azure[_ -]?openai)[_ -]?(?:api[_ -]?)?keys?\b\s*(?:(?:is|was|are|=|:)\s*)?['\"]?(?:sk-|gsk_|hf_|ghp_|xai-|glpat-|xox[baprs]-)?[a-z0-9][a-z0-9$%_.-]{2,}",
            # "My Groq key is …" / "our api key is …" / "groq key: …" (punct ignored on scan surface)
            r"(?i)\b(?:my|our|the)\s+(?:(?:openai|anthropic|huggingface|cohere|mistral|groq|gemini|azure|aws|github|gitlab|slack|stripe|twilio)\s+)?(?:api\s+)?keys?\b\s*(?:(?:is|was|are|=|:)\s*)?['\"]?(?:sk-|gsk_|hf_|ghp_|xai-|glpat-|xox[baprs]-)?[a-z0-9][a-z0-9$%_.-]{2,}",
            r"(?i)\bhf_[A-Za-z0-9]{20,}\b",
            r"(?i)\b(?:sbp|supabase)_[A-Za-z0-9]{20,}\b",
            r"(?i)\bvercel[_-]?token\b\s*[:=]\s*\S+",
            # Bearer / JWT
            r"(?i)bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*",
            r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            # AWS
            r"(?i)\b(?:aws_?access_?key_?id|aws_?secret_?access_?key|aws_?session_?token)\b\s*[:=]\s*\S+",
            r"(?i)\bAKIA[0-9A-Z]{16}\b",
            r"(?i)\bASIA[0-9A-Z]{16}\b",
            r"(?i)\bAIDA[0-9A-Z]{16}\b",
            r"(?i)\bAROA[0-9A-Z]{16}\b",
            # GitHub / GitLab / Bitbucket
            r"(?i)\bghp_[A-Za-z0-9]{36}\b",
            r"(?i)\bgho_[A-Za-z0-9]{36}\b",
            r"(?i)\bghu_[A-Za-z0-9]{36}\b",
            r"(?i)\bghr_[A-Za-z0-9]{36}\b",
            r"(?i)\bghs_[A-Za-z0-9]{36}\b",
            r"(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b",
            r"(?i)\bglpat-[A-Za-z0-9\-_]{20,}\b",
            r"(?i)\bglrt-[A-Za-z0-9\-_]{20,}\b",
            r"(?i)\bATBB[A-Za-z0-9]{20,}\b",
            # Slack / Discord / Teams
            r"(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
            r"(?i)\bxapp-[A-Za-z0-9-]{10,}\b",
            r"(?i)\bdiscord(?:[_-]?bot)?[_-]?token\b\s*[:=]\s*\S+",
            r"(?i)\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b",
            # Google / Azure / GCP
            r"(?i)\bAIza[0-9A-Za-z\-_]{35}\b",
            r"(?i)\bya29\.[0-9A-Za-z\-_]+",
            r"(?i)\bGOOG[0-9A-Za-z\-_]{20,}\b",
            r"(?i)\bAZURE[_-]?(?:CLIENT|TENANT|SUBSCRIPTION)[_-]?(?:ID|SECRET|KEY)?\b\s*[:=]\s*\S+",
            r"(?i)\b(?:DefaultEndpointsProtocol|AccountKey|SharedAccessSignature)=[^\s;]+",
            r"(?i)\b(?:storage|blob)\.core\.windows\.net\b",
            # Package registries / CI
            r"(?i)\b(?:npm[_-]?token|NODE_AUTH_TOKEN|NPM_TOKEN)\b\s*[:=]\s*\S+",
            r"(?i)\bpypi-[A-Za-z0-9_\-]{20,}\b",
            r"(?i)\b(?:GHCR_PAT|DOCKER_PASSWORD|DOCKERHUB_TOKEN|ARTIFACTORY_TOKEN)\b\s*[:=]\s*\S+",
            r"(?i)\b(?:circle[_-]?token|travis[_-]?token|sonar[_-]?token|codecov[_-]?token)\b\s*[:=]\s*\S+",
            # Commerce / messaging / monitoring SaaS
            r"(?i)\bshpat_[a-fA-F0-9]{32}\b",
            r"(?i)\bshpca_[a-fA-F0-9]{32}\b",
            r"(?i)\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
            r"(?i)\bsk_live_[0-9a-zA-Z]{16,}\b",
            r"(?i)\bsk_test_[0-9a-zA-Z]{16,}\b",
            r"(?i)\bpk_live_[0-9a-zA-Z]{16,}\b",
            r"(?i)\bpk_test_[0-9a-zA-Z]{16,}\b",
            r"(?i)\brk_live_[0-9a-zA-Z]{16,}\b",
            r"(?i)\bwhsec_[A-Za-z0-9]+",
            r"(?i)\bAC[a-f0-9]{32}\b",
            r"(?i)\bSK[a-f0-9]{32}\b",
            r"(?i)\b(?:twilio|datadog|newrelic|sentry|pagerduty|opsgenie)[_-]?(?:api[_-]?)?(?:key|token|secret)\b\s*[:=]\s*\S+",
            r"(?i)\b(?:DD|NR|SENTRY)[_-]?(?:API[_-]?)?(?:KEY|TOKEN)\b\s*[:=]\s*\S+",
            r"(?i)\bxoxe\.xoxp-[0-9-]{10,}",
            # Generic labeled secrets — key=val, "key is val", or "key val" after punct fold
            r"(?i)\b(?:api[_ -]?keys?|secret[_ -]?keys?|access[_ -]?tokens?|refresh[_ -]?tokens?|client[_ -]?secrets?|private[_ -]?keys?|auth[_ -]?tokens?|session[_ -]?tokens?|id[_ -]?tokens?|bearer[_ -]?tokens?|webhook[_ -]?secrets?|signing[_ -]?secrets?|encryption[_ -]?keys?|master[_ -]?keys?|app[_ -]?secrets?)\b\s*(?:(?:is|was|are|=|:)\s*)?['\"]?(?:sk-|gsk_|hf_|ghp_|xai-|glpat-|xox[baprs]-)?[a-z0-9][a-z0-9$%_.-]{2,}",
            r"(?i)\b(?:password|passwd|pwd|passphrase|db[_ -]?password|db[_ -]?pass|root[_ -]?password|admin[_ -]?password|mysql[_ -]?pwd)\b\s*(?:(?:is|was|are|=|:)\s*)?['\"]?[a-z0-9][a-z0-9$%_.!@#*-]{2,}",
            # Short / demo-shaped tokens when clearly labeled as a key/secret
            r"(?i)\b(?:api[_ -]?keys?|secret[_ -]?keys?|access[_ -]?tokens?|auth[_ -]?tokens?)\b(?:\s+\w+){0,4}\s+(?:sk-|gsk_|hf_|ghp_|[a-z0-9]*\d)[a-z0-9$%_.-]{2,}",
            r"(?i)\b(?:connection[_-]?string|conn[_-]?str|jdbc:|odbc:)\S+",
            # Connection URIs / keys / infra
            r"(?i)\b(?:mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis|amqp|kafka|couchdb|elasticsearch|neo4j|mssql):\/\/\S+",
            r"(?i)\b(?:ssh-rsa|ssh-ed25519|ssh-dss|BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY)\b",
            r"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
            r"(?i)\.(?:pem|key|p12|pfx|jks|keystore)\b",
            r"(?i)\b(?:kubectl|kubeconfig|docker\.sock|helm chart|terraform state|pulumi stack|ansible vault)\b",
            r"(?i)\b(?:prod(?:uction)?|staging|uat|dr)[_-]?(?:cluster|namespace|kube|eks|aks|gke)\b",
            r"(?i)\b(?:source code|codebase|repo(?:sitory)?|pull request|commit(?: hash)?|git diff|stack trace|core dump|heap dump)\b",
            r"(?i)\b(?:env file|\.env(?:\.\w+)?|config\.ya?ml|secrets?\.(?:ya?ml|json|toml)|vault path|hashicorp vault)\b",
            r"(?i)\b(?:CI[_/]?CD|jenkins|github actions|gitlab ci|build pipeline|deploy key|runner token)\b",
            r"(?i)\b(?:internal api|staging url|localhost:\d{2,5}|svc\.cluster\.local|internal\.corp)\b",
            r"(?i)\b(?:feature flag|launchdarkly|split\.io|unleash)\s+(?:key|sdk|server)\b",
            # ------------------------------------------------------------------
            # 2024–2026 high-signal secrets (OWASP LLM07 / GitHub secret scanning /
            # CISA AI data security — concrete shapes only, not vague English)
            # ------------------------------------------------------------------
            # Slack / Discord webhooks (credential + common exfil channel)
            r"(?i)hooks\.slack\.com/services/[A-Za-z0-9/_+-]{20,}",
            r"(?i)discord(?:app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9_-]{20,}",
            # Telegram bot tokens
            r"(?i)\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b",
            # npm / Databricks / Vault / New Relic / Linear / PlanetScale / Square
            r"(?i)\bnpm_[A-Za-z0-9]{36}\b",
            r"(?i)\bdapi[a-f0-9]{32}\b",
            r"(?i)\bhvs\.[A-Za-z0-9_-]{20,}\b",
            r"(?i)\bNRAK-[A-Z0-9]{27}\b",
            r"(?i)\bNRII-[A-Z0-9]{27}\b",
            r"(?i)\blin_api_[A-Za-z0-9]{40,}\b",
            r"(?i)\bpscale_tkn_[A-Za-z0-9_]{20,}\b",
            r"(?i)\bsq0[a-z]{3}-[0-9A-Za-z\-_]{20,}\b",
            # Notion integration secrets (fixed length after secret_)
            r"(?i)\bsecret_[a-zA-Z0-9]{43}\b",
            # AWS secret access key when clearly labeled (40-char)
            r"(?i)\b(?:aws_?)?secret_?access_?key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
            # GCP service-account JSON markers (prompt paste of credentials file)
            r"(?i)\"type\"\s*:\s*\"service_account\"",
            r"(?i)\"private_key\"\s*:\s*\"-----BEGIN",
            # Azure storage connection strings
            r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[^;\s]+",
            # Credentialed DB / broker URIs (user:pass@host) — never cleartext external
            r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss?|amqp):\/\/[^:\s\/]+:[^@\s\/]+@[^\s]+",
            # Named session cookies with values
            r"(?i)\b(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid)\s*[:=]\s*[A-Za-z0-9._-]{8,}",
            # PEM private keys pasted with escaped newlines (.env / JSON)
            r"(?i)\\n-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----",
            # Okta / Auth0 / Cloudflare labeled tokens
            r"(?i)\b(?:okta|auth0)[_-]?(?:api[_-]?)?(?:token|key|secret)\b\s*[:=]\s*\S+",
            r"(?i)\bcloudflare[_-]?(?:api[_-]?)?(?:token|key)\b\s*[:=]\s*\S+",
            # Amazon MWS auth tokens
            r"(?i)\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            # High-entropy assignment heuristic (novel token shapes)
            r"(?i)\b[a-z][a-z0-9_.-]{2,40}\b\s*[:=]\s*['\"]?[A-Za-z0-9+\/_-]{28,}={0,2}['\"]?",
        ],
        # ------------------------------------------------------------------
        # HR / employment / people ops
        # ------------------------------------------------------------------
        "hr": [
            r"(?i)\b(?:ssn|social\s*security(?:\s*number)?)\b\s*[:=]?\s*\d{3}-?\d{2}-?\d{4}\b",
            r"(?i)\b(?:ssn|social\s*security(?:\s*number)?)\b\s*[:=]?\s*\d{9}\b",
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"(?i)\b(?:employee(?: id| number)?|badge(?: id)?|staff id|emp[_ -]?id|associate id|worker id)\b\s*(?:is|was|are|=|:)?\s*[A-Z0-9\-]{3,}",
            r"(?i)\bEMP[\s\-_]?\d{3,}\b",
            r"(?i)\b(?:CTR|contractor)[\s\-_]?\d{3,}\b",
            r"(?i)\b(?:salary|compensation|bonus|severance|stock options?|RSUs?|equity grant|pay band|base pay|OTC|overtime pay|total cash|OTE|on[- ]target earnings)\b",
            r"(?i)\b(?:performance review|PIP|performance improvement plan|termination|fired|laid off|layoff|furlough|resignation|exit interview)\b",
            r"(?i)\b(?:background check|drug test|disciplinary action|write[- ]up|hr complaint|grievance|warning letter)\b",
            r"(?i)\b(?:resume|CV|curriculum vitae|offer letter|employment contract|appointment letter|relieving letter)\b",
            r"(?i)\b(?:date of birth|DOB|date of joining|DOJ|hire date|last working day|LWD|notice period)\b",
            r"(?i)\b(?:manager|direct report|org chart|reporting line|span of control|skip[- ]level)\b",
            r"(?i)\b(?:HR|human resources)\s+(?:only|confidential|file|record|case|ticket|investigation)s?\b",
            r"(?i)\b(?:payroll|payslip|pay stub|W-?2|W-?4|Form 16|PF number|UAN|ESI|gratuity)\b",
            r"(?i)\b(?:benefits enrollment|health insurance plan|dependent coverage|401\(?k\)?|provident fund|HSA|FSA|ESOP)\b",
            r"(?i)\b(?:interview feedback|candidate score|rejection reason|attrition|headcount|hiring plan|backfill)\b",
            r"(?i)\b(?:work authorization|visa status|H-?1B|L-?1|O-?1|green card|I-?9|EAD|work permit)\b",
            r"(?i)\b(?:emergency contact|next of kin|marital status|gender identity|disability status|veteran status)\b",
            r"(?i)\b(?:promotion|demotion|level(?:ing)?|job grade|pay raise|merit increase|calibration)\b",
            r"(?i)\b(?:PTO|paid time off|sick leave|parental leave|bereavement|leave of absence|LOA)\b",
            r"(?i)\b(?:union|collective bargaining|works council|labor relations)\b",
            r"(?i)\b(?:harassment|discrimination|EEOC|POSH|workplace investigation)\b",
        ],
        # ------------------------------------------------------------------
        # Finance / accounting / PCI / tax / banking
        # ------------------------------------------------------------------
        "finance": [
            r"\$\s?\d+(?:,\d{3})*(?:\.\d+)?\s?(?:[BbMmKk]n?|[Bb]illion|[Mm]illion|[Tt]rillion)?\b",
            # Price / amount ranges as one span ("$5 to $15")
            r"\$\s?\d+(?:,\d{3})*(?:\.\d+)?\s+(?:to|-|–|—)\s+\$?\s?\d+(?:,\d{3})*(?:\.\d+)?",
            # Bare magnitude amounts ("42 million", "2.5Bn") — deal values without $
            r"(?i)\b\d[\d,]*(?:\.\d+)?\s*(?:million|billion|thousand|trillion|mn|bn|mm|lakh|crore)\b",
            r"(?i)\b(?:USD|EUR|GBP|INR|JPY|CAD|AUD)\s?\d+(?:,\d{3})*(?:\.\d+)?\b",
            r"(?i)\b₹\s?\d+(?:,\d{2,3})*(?:\.\d+)?\b",
            r"(?i)\b(?:revenue|ARR|MRR|ACV|TCV|EBITDA|P&L|profit(?: margin)?|gross margin|net income|burn rate|runway|gross merchandise)\b",
            r"(?i)\b(?:market share|operating expenses?|expenses?|quarterly performance|financial(?:s)? performance)\b",
            r"(?i)\bQ[1-4]\s*(?:FY\s*)?20\d{2}\b",
            r"(?i)\b(?:FY|fiscal year)\s*20\d{2}\b",
            # Concrete % moves — hide these; bare topic words like OPEX stay keep
            r"(?i)\b(?:dip|drop|decline|decrease|increase|growth|uptick|downturn|variance)\s+(?:of\s+|by\s+)?\d+(?:\.\d+)?\s*%(?:\s+(?:in|of|on)\s+(?:OPEX|CAPEX|OpEx|CapEx|revenue|ARR|MRR|EBITDA|gross margin|net income|costs?|sales|profit|budget|forecast))?",
            r"(?i)\b\d+(?:\.\d+)?\s*%\s+(?:in|of|on)\s+(?:OPEX|CAPEX|OpEx|CapEx|revenue|ARR|MRR|EBITDA|gross margin|net income|costs?|sales|profit|budget|forecast)",
            r"(?i)\b(?:OPEX|CAPEX|OpEx|CapEx|revenue|ARR|MRR|EBITDA)\s+(?:down|up|at|of|was|is|by)?\s*\d+(?:\.\d+)?\s*%",
            # "profit down by 30%", "margin of 45%", "cutting … by 12%"
            r"(?i)\b(?:down|up|off)\s+by\s+\d+(?:\.\d+)?\s*%",
            r"(?i)\b(?:profit|revenue|earnings|valuation|margin|gross margin|net income|costs?|sales|budget|forecast)\s+(?:down|up|of|at|was|is|by)\s+\d+(?:\.\d+)?\s*%",
            r"(?i)\b(?:profit|revenue|earnings|valuation|margin|gross margin|net income)\s+(?:down|up)\s+by\s+\d+(?:\.\d+)?\s*%",
            r"(?i)\b(?:gross\s+)?margin\s+of\s+\d+(?:\.\d+)?\s*%",
            r"(?i)\bby\s+\d+(?:\.\d+)?\s*%",
            r"(?i)\b(?:invoice|purchase order|PO[#\s-]?\d+|bank account|routing number|IBAN|SWIFT|BIC)\b",
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
            r"(?i)\brouting\s*(?:number|#)?\s*[:=]?\s*\d{9}\b",
            r"(?i)\b(?:credit card|debit card|card number|CVV|CVC|expiry|expiration date|PAN|cardholder)\b",
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011|65\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b",
            r"\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b",
            r"(?i)\b(?:budget|forecast|quota|pipeline value|deal size|capex|opex|variance|accrual)\b",
            r"(?i)\b(?:tax id|EIN|VAT(?: number)?|GSTIN|TIN|ITIN|W-?9|1099|Form 1040|TAN|GST)\b",
            r"\b\d{2}-\d{7}\b",
            r"(?i)\b(?:wire transfer|ACH|NEFT|RTGS|IMPS|UPI|payment terms|accounts payable|accounts receivable|AP aging|AR aging)\b",
            r"(?i)\b(?:fiscal year|FY\d{2,4}|quarterly earnings|10-?K|10-?Q|8-?K|audit findings?|material weakness)\b",
            r"(?i)\b(?:cost center|GL code|chart of accounts|journal entry|ledger|reconciliation|trial balance)\b",
            r"(?i)\b(?:IFSC|MICR|account number|a/?c(?:ct)?\s*(?:no|number|#)?)\b\s*[:=]?\s*[A-Z0-9]{6,}",
            r"(?i)\b(?:stripe|paypal|razorpay|adyen|braintree|payment gateway)\s+(?:key|secret|settlement|merchant)\b",
            r"(?i)\b(?:valuation|term sheet|cap table|SAFE note|series [A-E] funding|pre[- ]money|post[- ]money)\b",
            r"(?i)\b(?:DSO|DPO|working capital|liquidity|covenant|debt facility|credit line)\b",
            r"(?i)\b(?:expense report|T&E|reimbursement|corporate card|P-?card)\b",
            r"(?i)\b(?:fx rate|hedge|derivative|treasury|cash position)\b",
            r"(?i)\b(?:internal financials|board pack|management accounts|flash report)\b",
            # High-signal payment instruments (PCI / banking — concrete values)
            r"(?i)\b(?:iban)\b\s*[:=]?\s*[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",
            r"(?i)\b(?:cvv|cvc2?|cid)\b\s*[:=]?\s*\d{3,4}\b",
            r"(?i)\b(?:swift|bic)\b\s*(?:code)?\s*[:=]?\s*[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
            r"(?i)\b(?:routing)\s*(?:number|#)?\b\s*[:=]?\s*\d{9}\b",
            r"(?i)\b(?:account)\s*(?:number|#|no\.?)\b\s*[:=]?\s*\d{6,17}\b",
        ],
        # ------------------------------------------------------------------
        # Legal / compliance / IP / privacy
        # ------------------------------------------------------------------
        "legal": [
            r"(?i)\b(?:attorney[- ]client|legal hold|privilege(?:d)?(?: communication)?|work product|under NDA)\b",
            r"(?i)\b(?:NDA|non[- ]disclosure(?: agreement)?|MSA|SOW|SLA|DPA|BAA|terms of service|EULA|MOU)\b",
            r"(?i)\b(?:lawsuit|litigation|subpoena|settlement|indemnif(?:y|ication)|class action|arbitration|mediation)\b",
            r"(?i)\b(?:patent|trademark|copyright|trade secret|IP assignment|invention disclosure|prior art)\b",
            r"(?i)\b(?:GDPR|CCPA|CPRA|HIPAA|SOC\s?2|ISO\s?27001|PCI[- ]DSS|SOX|GLBA|FERPA|ITAR|EAR|DPDP|LGPD)\b",
            r"(?i)\b(?:contract|clause|liability|jurisdiction|governing law|force majeure|non[- ]compete|non[- ]solicit)\b",
            r"(?i)\b(?:cease and desist|regulatory filing|compliance breach|consent order|fine|penalty|enforcement action)\b",
            r"(?i)\b(?:board resolution|shareholder agreement|bylaws|articles of incorporation|proxy statement)\b",
            r"(?i)\b(?:outside counsel|legal opinion|discovery|deposition|privilege log|in[- ]house counsel)\b",
            r"(?i)\b(?:data processing agreement|right to be forgotten|DSAR|subject access request|data subject)\b",
            r"(?i)\b(?:export control|sanctions|OFAC|restricted party|denied party|embargo)\b",
            r"(?i)\b(?:whistleblower|ethics hotline|internal investigation|code of conduct breach)\b",
            r"(?i)\b(?:privacy notice|cookie consent|legitimate interest|data retention|records retention)\b",
            r"(?i)\b(?:material contract|change of control|assignment clause|audit rights)\b",
            # Named NDA / IP disclosure — hide counterparty specifics before external
            r"(?i)\b(?:under NDA with|NDA with)\s+[A-Z][A-Za-z0-9&.\- ]{2,40}",
            r"(?i)\b(?:source code dump|proprietary source code|proprietary algorithm)\b",
        ],
        # ------------------------------------------------------------------
        # Sales / GTM / M&A / CRM
        # ------------------------------------------------------------------
        "sales": [
            r"(?i)\b(?:acquisition(?:s)?|acquirer|acquiree)\b",
            r"(?i)\b(?:we|company|our team)\s+acquired\b",
            r"(?i)\b(?:merger|M&A|divestiture|due diligence|letter of intent|LOI|definitive agreement|SPA|APA)\b",
            r"(?i)\b(?:deal of|closed[- ]won|closed[- ]lost|sales pipeline|opportunity stage|win rate|commit forecast)\b",
            r"(?i)\b(?:customer|client|prospect|account)\s+(?:named|list|roster|logo|reference|expansion)\b",
            # Legal-suffix companies — max 4 name tokens (avoids swallowing sentence prefixes
            # like "How did Amazon Inc" / "Draft … with Flipkart Inc" on folded surfaces)
            r"(?i)\b(?:[a-z][a-z0-9]*\s+){0,3}[a-z][a-z0-9]*\s+"
            r"(?:inc|corp|corporation|ltd|llc|company|gmbh|plc|pvt\s*ltd)\b",
            # Brand + corporate noun without Inc (OrionTech Solutions, northwind analytics)
            r"(?i)\b(?:[a-z][a-z0-9]*\s+){0,3}[a-z][a-z0-9]*\s+"
            r"(?:solutions|technologies|technology|systems|software|labs|group|partners|"
            r"ventures|industries|holdings|networks|dynamics|analytics|consulting|services)\b",
            # CamelCase product/company brands (OrionTech) — also match folded form via Analytics pattern
            r"\b[A-Z][a-z]+[A-Z][A-Za-z0-9]*\b",
            # Person names next to outreach / deal verbs (Medium hide → fictional rewrite)
            r"(?i)\b(?:email|ping|ask|tell|cc|bcc|contact|call|message|brief|notify|"
            r"talking points for|draft(?:\s+\w+)?\s+for|points for)\s+"
            r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b",
            r"(?i)\b(?:for|with|to)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b(?=.*\b(?:Inc|Corp|Ltd|LLC|deal|pricing|RFP|contract)\b)",
            r"(?i)\b(?:CEO|CFO|CTO|COO|CMO|CRO|CISO|VP|SVP|EVP|Director|Managing Director)\s+[A-Za-z][a-z]+(?:\s+[A-Za-z][a-z]+)+",
            r"(?i)\b(?:pricing|discount|quote|proposal|RFP|RFI|RFQ|rate card|list price|ASP|floor price)\b",
            r"(?i)\b(?:churn|upsell|cross[- ]sell|ARR expansion|NRR|GRR|logo retention|net retention)\b",
            r"(?i)\b(?:account executive|opportunity owner|CRM|Salesforce|HubSpot|lead score|MEDDIC|BANT)\b",
            r"(?i)\b(?:go[- ]to[- ]market|GTM|competitive intel(?:ligence)?|battle card|win[/ ]loss)\b",
            r"(?i)\b(?:enterprise agreement|MSA negotiation|renewal|upsell motion|land and expand)\b",
            r"(?i)\b(?:TAM|SAM|SOM|ICP|ideal customer profile|buyer persona)\b",
            r"(?i)\b(?:partner channel|reseller|distributor|commission|SPIFF|partner margin)\b",
            r"(?i)\b(?:roadmap preview|unannounced product|beta customer|design partner|early access)\b",
            r"(?i)\b(?:strategic account|named account|top[- ]\d+ account|whale account)\b",
            r"(?i)\b(?:contract value|ACV|TCV|multi[- ]year deal|preferred pricing)\b",
            # CRM deal specifics — hide/scrub before external (typically Medium lane)
            r"(?i)\b(?:opportunity|opp|deal)\s*(?:id|#)\b\s*[:=]?\s*[A-Z0-9-]{5,}\b",
            r"(?i)\b(?:salesforce|hubspot)\s+(?:opportunity|deal|account)\s*(?:id)?\s*[:=#]?\s*[A-Z0-9-]{5,}\b",
        ],
        # ------------------------------------------------------------------
        # Healthcare / PHI
        # ------------------------------------------------------------------
        "healthcare": [
            r"(?i)\b(?:patient|diagnosis|prescription|medical record|PHI|ePHI|health record|protected health)\b",
            r"(?i)\b(?:MRN|medical record number|patient id|patient #)\b\s*[:=]?\s*[A-Z0-9\-]{3,}",
            r"(?i)\b(?:ICD-?10|CPT(?: code)?|SNOMED|RxNorm|HIPAA|clinical trial|protocol number)\b",
            r"(?i)\b(?:blood type|allerg(?:y|ies)|medication|dosage|contraindication|adverse event)\b",
            r"(?i)\b(?:insurance(?: policy)?|member id|group number|subscriber id|claim id|NPI|payer id)\b",
            r"(?i)\b(?:hospital|clinic|physician|doctor|nurse practitioner|attending|discharge summary)\b",
            r"(?i)\b(?:lab results?|imaging|MRI|CT scan|X-?ray|biopsy|pathology|vital signs)\b",
            r"(?i)\b(?:treatment plan|prognosis|therapy|surgery|procedure|anesthesia)\b",
            r"(?i)\b(?:mental health|psychiatric|substance abuse|HIV|STD|genetic test|reproductive health)\b",
            r"(?i)\b(?:EHR|EMR|Epic|Cerner|HL7|FHIR|OpenEMR)\b",
            r"(?i)\b(?:prior authorization|referral|encounter|admission|discharge date)\b",
            r"(?i)\b(?:NDC|DEA number|controlled substance|formulary)\b",
            r"(?i)\b(?:immunization|vaccination record|COVID[- ]?19 result|test result)\b",
            r"(?i)\b(?:telehealth|clinical notes|progress notes|SOAP note)\b",
            # High-signal PHI identifiers (NIST AI RMF / HIPAA — labeled values)
            r"(?i)\b(?:NPI|national provider(?: identifier)?)\b\s*[:=]?\s*\d{10}\b",
            r"(?i)\b(?:DEA)\s*(?:number|#|no\.?)?\b\s*[:=]?\s*[A-Z]{2}\d{7}\b",
            r"(?i)\b(?:member|subscriber)\s*(?:id|#|number)\b\s*[:=]?\s*[A-Z0-9-]{6,}\b",
            r"(?i)\b(?:claim)\s*(?:id|#|number)\b\s*[:=]?\s*[A-Z0-9-]{6,}\b",
        ],
        # ------------------------------------------------------------------
        # Security / SOC / GRC
        # ------------------------------------------------------------------
        "security": [
            r"(?i)\b(?:vpn|zero[- ]trust|firewall|ids|ips|siem|soar|edr|xdr|waf|casb|dlp)\b",
            r"(?i)\b(?:vulnerability|CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]{4,}|zero[- ]day|exploit|penetration test|pentest|red team exercise)\b",
            r"(?i)\b(?:incident response|security breach|data breach|ransomware|phishing campaign|IOC|indicator of compromise)\b",
            r"(?i)\b(?:MFA|2FA|OTP|TOTP|one[- ]time password|security question|passkey|hardware token|recovery code)\b",
            r"(?i)\b(?:admin(?:istrator)?(?: account| password| access)|root access|privileged access|break[- ]glass|PAM|JIT access)\b",
            r"(?i)\b(?:audit log|access log|threat intel(?:ligence)?|SIEM alert|detection rule|sigma rule)\b",
            r"(?i)\b(?:encryption key|keystore|certificate|TLS|SSL|HSM|KMS|secrets manager|key rotation)\b",
            r"(?i)\b(?:SOC|security operations|blue team|red team|purple team|threat hunt)\b",
            r"(?i)\b(?:malware|trojan|backdoor|C2|command and control|lateral movement|exfiltration)\b",
            r"(?i)\b(?:allowlist|denylist|blocklist|firewall rule|security group|IAM policy|conditional access)\b",
            r"(?i)\b(?:security clearance|need[- ]to[- ]know|classified|top secret|secret clearance|CUI)\b",
            r"(?i)\b(?:bug bounty|responsible disclosure|security advisory|CVSS)\b",
            r"(?i)\b(?:insider threat|impossible travel|compromised account|credential stuffing)\b",
            r"(?i)\b(?:security questionnaire|SIG|CAIQ|penetration test report)\b",
        ],
        # ------------------------------------------------------------------
        # Operations / supply chain / vendors / facilities
        # ------------------------------------------------------------------
        "operations": [
            r"(?i)\b(?:vendor|supplier|procurement|purchase requisition|RFQ|sourcing event)\b",
            r"(?i)\b(?:supply chain|bill of materials|BOM|inventory level|safety stock|SKU)\b",
            r"(?i)\b(?:warehouse|fulfillment|logistics|freight|shipping label|tracking number)\b",
            r"(?i)\b(?:facility|badge access|door code|alarm code|CCTV|physical security)\b",
            r"(?i)\b(?:data center|colo(?:cation)?|rack location|cabinet key|NOC)\b",
            r"(?i)\b(?:vendor contract|MSA with vendor|preferred supplier|sole source)\b",
            r"(?i)\b(?:business continuity|disaster recovery|BCP|DR plan|RTO|RPO)\b",
            r"(?i)\b(?:on[- ]call roster|runbook|escalation matrix|pager duty schedule)\b",
            r"(?i)\b(?:office floor plan|badge photo|visitor log|contractor badge)\b",
            r"(?i)\b(?:capacity plan|headcount plan|site expansion|lease agreement)\b",
        ],
        # ------------------------------------------------------------------
        # Marketing / brand / unreleased
        # ------------------------------------------------------------------
        "marketing": [
            r"(?i)\b(?:unannounced|embargo(?:ed)?|under embargo|press embargo|leak embargo)\b",
            r"(?i)\b(?:product launch|launch date|go[- ]live date|GA date|public announcement)\b",
            r"(?i)\b(?:campaign budget|ad spend|media buy|CAC|LTV|ROAS|attribution)\b",
            r"(?i)\b(?:customer list for campaign|email list|subscriber list|segment export)\b",
            r"(?i)\b(?:brand guidelines?|trademark usage|logo lockup|style guide)\b",
            r"(?i)\b(?:influencer contract|creator fee|sponsorship deal|affiliate payout)\b",
            r"(?i)\b(?:A\/B test results?|conversion rate|funnel metrics|growth experiment)\b",
            r"(?i)\b(?:competitive teardown|win[/ ]loss marketing|positioning doc)\b",
            r"(?i)\b(?:pre[- ]brief|analyst briefing|Gartner|Forrester|magic quadrant)\b",
            r"(?i)\b(?:unpublished|draft press release|holding statement)\b",
        ],
        # ------------------------------------------------------------------
        # General PII / identity / classification
        # ------------------------------------------------------------------
        "pii": [
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            # Require separators so CVE-2024-12345 is not mistaken for a phone number
            r"(?<![\w-])(?:\+?1[-.\s])?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b",
            r"(?<![\w-])(?:\+91[-.\s]?|0)?[6-9]\d{9}\b",
            r"(?<![\w-])(?:\+44[-.\s])?\d{4}[-.\s]\d{6}\b",
            r"(?i)\b(?:home address|mailing address|residential address|billing address|shipping address)\b",
            # Street addresses — require a separate street-type token (avoids "2026 3rd" → Rd)
            r"(?i)\b\d{1,5}\s+(?:[A-Za-z0-9.'-]+\s+){1,6}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct)\.?\b",
            r"(?i)\b(?:passport|driver(?:'?s)? license|national id|aadhaar|pan card|voter id|national insurance|NIN|NRIC)\b",
            r"\b[A-Z]{5}\d{4}[A-Z]\b",  # PAN (India)
            r"\b\d{4}\s?\d{4}\s?\d{4}\b",  # Aadhaar-like
            # Labeled government IDs with values (high-signal; avoids bare digit spam)
            r"(?i)\b(?:aadhaar|uidai)\b\s*[:=]?\s*\d{4}\s?\d{4}\s?\d{4}\b",
            r"(?i)\b(?:passport)\s*(?:no|number|#)?\b\s*[:=]?\s*[A-Z0-9]{6,9}\b",
            r"(?i)\b(?:driver(?:'?s)?\s*license|dl)\s*(?:no|number|#)?\b\s*[:=]?\s*[A-Z0-9-]{6,}\b",
            # Usernames / identity labels (must not slip to Safe / external)
            r"(?i)\b(?:user\s*names?|usernames?|user\s*ids?|userids?|login\s*names?|login\s*ids?|display\s*names?|account\s*names?|account\s*ids?|screen\s*names?)\b",
            r"(?i)\b(?:user\s*names?|usernames?|user\s*ids?|login\s*names?|login\s*ids?|display\s*names?|account\s*names?|account\s*ids?|session\s*ids?)\b\s*(?:(?:is|was|are|=|:)\s*)?['\"]?[A-Za-z0-9._@+-]{2,}",
            r"(?i)\b(?:sap|erp|oracle|workday|okta)\s+(?:login|user|id|password)\b\s*(?:(?:is|was|are|=|:)\s*)?['\"]?[A-Za-z0-9._@+-]{0,64}",
            r"(?i)\b(?:full name|legal name|given name|family name|employee name|customer name|client name|patient name|vendor name)\b",
            r"(?i)\b(?:full name|employee name|customer name|patient name|my name|user name)\b\s*(?:(?:is|was|are|=|:)\s*)[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}",
            r"(?i)\b(?:date of birth|mother'?s maiden name|place of birth|maiden name)\b",
            r"(?i)\b(?:IP address|MAC address)\b\s*[:=]?\s*(?:\d{1,3}\.){3}\d{1,3}",
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            r"(?i)\b(?:MAC(?: address)?)\b\s*[:=]?\s*(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
            r"(?i)\bconfidential\b",
            r"(?i)\binternal only\b",
            r"(?i)\b(?:do not (?:share|distribute|forward)|restricted|proprietary|personal data|PII|SPI|sensitive personal)\b",
            r"(?i)\b(?:biometric|fingerprint|face id|retina|voice print|facial recognition)\b",
            r"(?i)\b(?:geolocation|GPS coordinates|lat(?:itude)?[/,\s]+long(?:itude)?)\b",
            r"(?i)\b(?:cookie|session id|sessionid|device id|IMEI|IMSI|IDFA|GAID|android[_-]?id)\b",
            r"(?i)\b(?:cookie|session id|sessionid|device id)\b\s*(?:(?:is|was|are|=|:)\s*)?['\"]?[A-Za-z0-9._@+-]{2,}",
            r"(?i)\b(?:bank account details|personal email|personal phone|home phone|email address|phone number)\b",
            r"(?i)\b(?:minor|under 13|under 16|children'?s data|COPPA)\b",
            r"(?i)\b(?:religion|political opinion|sexual orientation|trade union membership)\b",
        ],
    }

    DEPARTMENT_WEIGHTS = {
        "engineering": 30,
        "hr": 30,
        "finance": 25,
        "legal": 25,
        "sales": 20,
        "healthcare": 35,
        "security": 30,
        "operations": 22,
        "marketing": 18,
        "pii": 20,
    }

    # What ExhaustShield hides vs keeps — current enterprise AI / SaaS trends
    PLACEHOLDER_POLICY = [
        {
            "action": "hide",
            "label": "AI / LLM API keys",
            "examples": "sk-…, sk-proj-…, gsk_…, hf_…, Anthropic keys",
            "why": "Cloud model credentials — highest egress risk (OWASP LLM07)",
        },
        {
            "action": "hide",
            "label": "Cloud & DevOps secrets",
            "examples": "AKIA…, GitHub/GitLab PATs, Slack xox-/webhooks, JWTs, Vault hvs., connection URIs",
            "why": "Infrastructure takeover if leaked to an outside model",
        },
        {
            "action": "hide",
            "label": "Session / identity tokens",
            "examples": "Bearer JWTs, PHPSESSID, JSESSIONID, refresh/access tokens",
            "why": "Account takeover — must not leave cleartext (CISA AI data security)",
        },
        {
            "action": "hide",
            "label": "People & HR identifiers",
            "examples": "Usernames, user names, employee IDs, names+IDs, SSN, salary figures",
            "why": "Identity / regulated personal — never needed in cleartext externally",
        },
        {
            "action": "hide",
            "label": "PHI / health record IDs",
            "examples": "MRN, NPI, member/subscriber IDs, diagnosis+record numbers",
            "why": "HIPAA-class health data — private AI only when concrete",
        },
        {
            "action": "hide",
            "label": "PCI / banking instruments",
            "examples": "Card PANs, CVV, IBAN, SWIFT, routing + account numbers",
            "why": "Payment credentials — never cleartext external",
        },
        {
            "action": "hide",
            "label": "Deal & finance specifics",
            "examples": "Name + $42 million, 10% OPEX dip, CRM opportunity IDs (not the name alone)",
            "why": "Concrete commercial data — hide/scrub before outside AI",
        },
        {
            "action": "hide",
            "label": "Analysis-scale finance (ratio asks)",
            "examples": "$45M→$77.85M with session factor; Org_1 / Person_1 / Email_1; format-preserved deal IDs",
            "why": "Keeps multiples/YoY math valid for the model without sending exact dollars or contacts",
        },
        {
            "action": "hide",
            "label": "Table / dataset synthetic peers",
            "examples": "CSV/markdown grids → scaled numbers, fictional names, format-preserved keys; restored on reply",
            "why": "Full tables stay useful for analysis without leaking real cell values externally",
        },
        {
            "action": "keep",
            "label": "Open-web / public-market facts",
            "examples": "Microsoft revenue, Apple CEO, published filings — left clear when not company-private",
            "why": "Enterprise gate only scrubs non-public / internal details",
        },
        {
            "action": "hide",
            "label": "Security incident IDs",
            "examples": "CVE-2024-…, GHSA-…, zero-day labels tied to an asset",
            "why": "Attackers can weaponize exact IDs",
        },
        {
            "action": "hide",
            "label": "Customer / partner logos with sensitive context",
            "examples": "Contoso Ltd next to deal value / % / confidential — not 'tell me about Contoso'",
            "why": "Names alone are Safe; names + deal/confidential depth are competitive intel",
        },
        {
            "action": "keep",
            "label": "Topic / process words",
            "examples": "pricing, discount, RFP, revenue, salary, acquisition, confidential",
            "why": "Marks sensitivity for scoring but must stay so the question still makes sense",
        },
        {
            "action": "keep",
            "label": "Generic role / process labels",
            "examples": "manager, forecast, pipeline, NDA, contract (as words)",
            "why": "Context for the ask — not a concrete secret value",
        },
    ]

    # Corp nouns used for name-shape detection (mirrors sales company patterns)
    _NAME_CORP_SUFFIX = (
        r"(?:Inc|Corp|Corporation|Ltd|LLC|Company|GmbH|PLC|Pvt\.?\s*Ltd|"
        r"Solutions|Technologies|Technology|Systems|Software|Labs|Group|Partners|"
        r"Ventures|Industries|Holdings|Networks|Dynamics|Analytics|Consulting|Services)"
    )

    # Deal values / confidential depth — required before a bare name becomes Medium
    _SENSITIVE_NAME_CONTEXT_RE = re.compile(
        r"(?i)(?:"
        r"\$\s*[\d,]+(?:\.\d+)?|"
        r"(?:USD|EUR|GBP|INR|₹)\s*[\d,]+|"
        r"\d[\d,]*(?:\.\d+)?\s*(?:million|billion|thousand|trillion|mn|bn|mm|lakh|crore)\b|"
        r"\d+(?:\.\d+)?\s*%|"
        r"\b(?:ACV|TCV|ARR|MRR|NRR|GRR)\b\s*[:=]?\s*\$?\d|"
        r"\b(?:deal|contract|opportunity)\s+(?:value|amount|size|worth)\b|"
        r"\b(?:worth|valued\s+at|closed\s+at|priced\s+at|closed[- ]won)\b.{0,48}\d|"
        r"\b(?:under\s+NDA|confidential|proprietary|internal\s+only|"
        r"do\s+not\s+(?:share|forward|distribute)|trade\s+secret)\b|"
        r"\b(?:term\s+sheet|letter\s+of\s+intent|\bLOI\b|definitive\s+agreement|"
        r"due\s+diligence)\b|"
        r"\b(?:acquisition|acquired|acquirer|acquiree|merger|M&A|divestiture)\b|"
        r"\b(?:opportunity|opp|deal)\s*(?:id|#)\b|"
        r"\bEMP[-_]?\d{3,}|"
        r"\b(?:salary|compensation|base\s+pay|total\s+comp|OTE)\b.{0,40}\$?\d|"
        r"\b(?:discount|margin|markup)\b.{0,24}\d+(?:\.\d+)?\s*%|"
        r"\b(?:pricing|quote|rate\s+card|floor\s+price).{0,48}\$?\d"
        r")"
    )

    @staticmethod
    def _is_concrete_secret(value: str) -> bool:
        v = value or ""
        # Intentionally excludes bare company/person names — those need prompt context
        # (see _has_sensitive_name_context) before they count as hide/Medium.
        return bool(
            re.search(
                r"(?i)(?:sk-|sk-proj-|sk-ant-|gsk_|xai-|hf_|ghp_|gho_|glpat-|AKIA|ASIA|"
                r"xox[baprs]-|eyJ[A-Za-z0-9_-]+\.|bearer\s+|"
                r"hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|"
                r"npm_|dapi[a-f0-9]{32}|hvs\.|NRAK-|NRII-|lin_api_|pscale_tkn_|sq0[a-z]{3}-|"
                r"secret_[a-zA-Z0-9]{43}\b|amzn\.mws\.|"
                r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^:]+:[^@]+@|"
                r"DefaultEndpointsProtocol|service_account|"
                r"PHPSESSID|JSESSIONID|connect\.sid|"
                r"(?:api[_ -]?key|secret[_ -]?key|password|passwd|pwd|passphrase)\s*(?:is|was|are|=|:)|"
                r"(?:groq|openai|anthropic|aws|github)\s+(?:api\s+)?keys?\s*(?:is|was|are|=|:)|"
                r"CVE-\d{4}-\d+|EMP[-_]?\d{3,}|"
                r"\$\s?\d|USD\s?\d|\d{3}-\d{2}-\d{4}|"
                r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b|"
                r"\b(?:cvv|cvc2?|cid)\b\s*[:=]?\s*\d{3,4}\b|"
                r"\b(?:iban)\b\s*[:=]?\s*[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b|"
                r"\d+(?:\.\d+)?\s*%|"
                r"\d[\d,]*(?:\.\d+)?\s*(?:million|billion|thousand|trillion|mn|bn|mm|lakh|crore)\b)",
                v,
            )
        )

    @classmethod
    def _is_name_like_span(cls, value: str) -> bool:
        """True for company logos / person names — not dollar amounts or credential shapes."""
        v = (value or "").strip()
        if not v or len(v) > 80:
            return False
        # Money / % / IDs are concrete secrets, not "names"
        if re.search(
            r"(?i)\$\s*\d|\d+(?:\.\d+)?\s*%|EMP[-_]?\d|sk-|gsk_|password\s*[:=]",
            v,
        ):
            return False
        # Finance shorthand / periods — not logos
        if re.fullmatch(
            r"(?i)(?:YoY|QoQ|MoM|EBITDA|EPS|ARR|MRR|ACV|TCV|OPEX|CAPEX|KPI|ROI|"
            r"Q[1-4]|FY\d{2,4}|CEO|CFO|CTO|COO)",
            v,
        ):
            return False
        if re.fullmatch(rf"(?i){cls._NAME_CORP_SUFFIX}", v):
            return False
        if re.search(
            rf"(?i)\b[A-Za-z][A-Za-z0-9&.\-]*(?:\s+[A-Za-z][A-Za-z0-9&.\-]*){{0,3}}\s+{cls._NAME_CORP_SUFFIX}\b",
            v,
        ):
            return True
        if re.fullmatch(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}", v):
            return True
        if re.fullmatch(r"[A-Z][a-z]+[A-Z][A-Za-z0-9]*", v):
            return True
        return False

    @classmethod
    def _has_sensitive_name_context(cls, prompt: str, value: str = "") -> bool:
        """Deal values, confidential markers, or deep commercial detail near/after a name."""
        blob = f"{prompt or ''} {value or ''}".strip()
        if not blob:
            return False
        return bool(cls._SENSITIVE_NAME_CONTEXT_RE.search(blob))

    @classmethod
    def span_action(
        cls,
        category: str,
        value: str,
        hint: str | None,
        prompt: str = "",
    ) -> tuple[str, str]:
        """Return (hide|keep, reason) for UI + redaction policy."""
        vl = (value or "").strip().lower()
        # Identity / auth labels are never "topic keep" — always hide before egress
        if re.search(
            r"(?i)\b(?:user\s*id|userid|user\s*name|username|session\s*id|sessionid|"
            r"login\s*id|account\s*id|sap\s+login|cookie|badge\s*id)\b",
            vl,
        ) or (
            (category or "").lower() in {"pii", "hr", "security", "engineering"}
            and re.search(r"(?i)\b(?:login|password|session|userid)\b", vl)
            and re.search(r"[A-Za-z0-9]{2,}", vl)
        ):
            return "hide", "Identity / auth detail — hide before egress"
        # HR document/process labels alone are topic words — keep unless a concrete secret is in the span
        if (category or "").lower() == "hr" and re.fullmatch(
            r"(?i)(?:resume|cv|curriculum vitae|offer letter|employment contract|"
            r"appointment letter|relieving letter|performance review|pip|"
            r"performance improvement plan|background check|payroll|payslip|"
            r"pay stub|compensation|salary|bonus|severance|headcount|hiring plan)",
            (value or "").strip(),
        ):
            return (
                "keep",
                "HR topic word — left clear so the ask stays understandable",
            )
        # Bare company/person names stay clear unless the prompt has deal/confidential depth
        if cls._is_name_like_span(value):
            try:
                from public_knowledge import (
                    assess_enterprise_sensitivity,
                    has_private_enterprise_markers,
                    is_public_org_span,
                )

                assessment = assess_enterprise_sensitivity(prompt or "", allow_network=True)
                if is_public_org_span(value, assessment):
                    return (
                        "keep",
                        "Open-web known entity — left clear (not company-private)",
                    )
                # Non-public name: only hide with enterprise-private context
                if assessment.get("scrub_enterprise") and (
                    cls._has_sensitive_name_context(prompt, value)
                    or assessment.get("has_private_markers")
                    or value in (assessment.get("private_orgs") or [])
                ):
                    return (
                        "hide",
                        "Company-specific / not on open web — hide before egress",
                    )
                if not assessment.get("scrub_enterprise"):
                    return (
                        "keep",
                        "Open-web / generic ask — left clear",
                    )
            except Exception:
                if cls._has_sensitive_name_context(prompt, value):
                    return (
                        "hide",
                        "Named account with deal values or confidential detail — hide before egress",
                    )
            return (
                "keep",
                "Name alone — no company-private detail nearby (left clear)",
            )
        # Open-web / public-market figures: do not scrub when no enterprise-private markers
        try:
            from public_knowledge import assess_enterprise_sensitivity

            assessment = assess_enterprise_sensitivity(prompt or "", allow_network=True)
            cat = (category or "").lower()
            if (
                not assessment.get("scrub_enterprise")
                and cat in {"finance", "sales", "marketing"}
                and not re.search(
                    r"(?i)password|api[_ -]?key|secret|token|ssn|iban|cvv",
                    value or "",
                )
            ):
                return (
                    "keep",
                    "Open-web / generic topic — figures left clear (not company-private)",
                )
        except Exception:
            pass
        if hint or cls._is_concrete_secret(value):
            reasons = {
                "engineering": "Credential / technical secret — hide before egress",
                "hr": "People / compensation detail — hide before egress",
                "finance": "Concrete financial figure — hide before egress",
                "sales": "Named account or deal detail — hide before egress",
                "security": "Security identifier — hide before egress",
                "pii": "Personal data — hide before egress",
                "legal": "Sensitive legal detail — hide before egress",
                "healthcare": "Health-related detail — hide before egress",
                "operations": "Internal ops detail — hide before egress",
                "marketing": "Unreleased marketing detail — hide before egress",
            }
            return "hide", reasons.get(
                (category or "").lower(),
                "Concrete sensitive value — hide before egress",
            )
        return (
            "keep",
            "Topic word — left in the prompt so meaning stays clear (still counted for risk)",
        )

    @classmethod
    def placeholder_policy(cls) -> list[dict]:
        return list(cls.PLACEHOLDER_POLICY)

    def __init__(self):
        # Compile once — broader pattern packs stay fast in the pilot UI.
        self._compiled = {
            dept: [re.compile(p) for p in patterns]
            for dept, patterns in self.PATTERNS.items()
        }

    @staticmethod
    def _parse_money_amount(value: str) -> float | None:
        """Best-effort parse of $145,000 / $42 million / $45M / 2.5Bn into a USD-ish float."""
        if not value:
            return None
        cleaned = value.strip()
        # Compact suffix forms first: $45M, $9.5bn, $270MM
        compact = re.search(
            r"(?i)(?:\$|USD|EUR|GBP|INR|₹)?\s*([\d,]+(?:\.\d+)?)\s*"
            r"(million|billion|thousand|trillion|mn|mm|bn|lakh|crore|[mbk])\b",
            cleaned,
        )
        m = compact or re.search(
            r"(?i)(?:\$|USD|EUR|GBP|INR|₹)?\s*([\d,]+(?:\.\d+)?)\s*"
            r"(billion|million|thousand|trillion|bn|mn|mm|lakh|crore|"
            r"\b(?:k|b|m|t)\b)?",
            cleaned,
        )
        if not m:
            return None
        try:
            num = float(m.group(1).replace(",", ""))
        except ValueError:
            return None
        unit = (m.group(2) or "").lower()
        mult = {
            "k": 1_000,
            "thousand": 1_000,
            "lakh": 100_000,
            "m": 1_000_000,
            "mn": 1_000_000,
            "mm": 1_000_000,
            "million": 1_000_000,
            "crore": 10_000_000,
            "b": 1_000_000_000,
            "bn": 1_000_000_000,
            "billion": 1_000_000_000,
            "t": 1_000_000_000_000,
            "trillion": 1_000_000_000_000,
        }.get(unit, 1)
        return num * mult

    @classmethod
    def _iter_money_amounts(cls, value: str) -> list[float]:
        """All currency magnitudes in a span (for ranges like $5 to $15)."""
        amounts: list[float] = []
        for m in re.finditer(
            r"(?i)(?:\$|USD|EUR|GBP|INR|₹)\s*([\d,]+(?:\.\d+)?)\s*"
            r"(billion|million|thousand|trillion|bn|mn|mm|"
            r"\b(?:k|b|m|t)\b)?",
            value or "",
        ):
            parsed = cls._parse_money_amount(m.group(0))
            if parsed is not None:
                amounts.append(parsed)
        if amounts:
            return amounts
        # Fallback: bare number + unit (e.g. "42 Mn") without a $ sign
        parsed = cls._parse_money_amount(value or "")
        return [parsed] if parsed is not None else []

    @classmethod
    def _money_band_label(cls, amount: float) -> str:
        """Plain-language magnitude — preserves scale without the exact figure."""
        if amount < 10:
            return "low single-digit pricing"
        if amount < 100:
            return "low double-digit pricing"
        if amount < 1_000:
            return "hundreds of dollars"
        if amount < 10_000:
            return "thousands of dollars"
        if amount < 100_000:
            return "tens of thousands"
        if amount < 1_000_000:
            return "a substantial sum"
        if amount < 100_000_000:
            return "tens of millions"
        if amount < 1_000_000_000:
            return "hundreds of millions"
        return "billions"

    @classmethod
    def _money_range_hint(cls, value: str, *, salary_context: bool = False) -> str:
        # Prefer multi-amount ranges as one phrase ("$5 to $15")
        amounts = cls._iter_money_amounts(value)
        if len(amounts) >= 2 and not salary_context:
            a, b = amounts[0], amounts[1]
            low_l = cls._money_band_label(min(a, b))
            high_l = cls._money_band_label(max(a, b))
            if low_l == high_l:
                return f"a {low_l} range" if not low_l.startswith("a ") else f"{low_l} range"
            return f"a {low_l} to {high_l} range"

        amount = amounts[0] if amounts else cls._parse_money_amount(value)
        if amount is None:
            return "a confidential amount"
        if salary_context:
            # Meaning preserved (compensation ask) without repeating a tight dollar band
            if amount < 80_000:
                return "entry-level compensation"
            if amount < 120_000:
                return "early-career compensation"
            if amount < 180_000:
                return "mid-level compensation"
            if amount < 250_000:
                return "senior-level compensation"
            return "executive-level compensation"
        label = cls._money_band_label(amount)
        if label in {
            "tens of millions",
            "hundreds of millions",
            "billions",
            "hundreds of thousands",
            "tens of thousands",
        }:
            return label
        if label.startswith("a "):
            return label
        return f"about {label}"

    @staticmethod
    def _person_kind(category: str, prompt_l: str) -> str:
        if category in {"sales", "marketing"} or re.search(
            r"(?i)\b(?:customer|client|account|prospect|buyer|vendor|partner)\b",
            prompt_l,
        ):
            return "customer"
        return "employee"

    @classmethod
    def _percent_band_phrase(cls, n: float) -> str:
        """Wide % band — original figure is not guessable from the midpoint."""
        if n < 6:
            return "1% to 10%"
        if n < 18:
            return "5% to 25%"
        if n < 35:
            return "10% to 50%"
        if n < 55:
            return "25% to 75%"
        if n < 75:
            return "40% to 90%"
        return "60% to 95%"

    @classmethod
    def _salary_wide_range(cls, amount: float, *, inr: bool = False) -> str:
        """Wide pay band so an exact salary cannot be reverse-read."""
        if inr:
            if amount < 600_000:
                return "₹3 lakh to ₹10 lakh"
            if amount < 1_500_000:
                return "₹8 lakh to ₹22 lakh"
            if amount < 3_000_000:
                return "₹12 lakh to ₹35 lakh"
            if amount < 6_000_000:
                return "₹20 lakh to ₹55 lakh"
            return "₹40 lakh to ₹1.2 crore"
        if amount < 70_000:
            return "$30,000 to $90,000"
        if amount < 110_000:
            return "$50,000 to $150,000"
        if amount < 160_000:
            return "$80,000 to $200,000"
        if amount < 230_000:
            return "$120,000 to $280,000"
        if amount < 350_000:
            return "$180,000 to $420,000"
        return "$250,000 to $700,000"

    @classmethod
    def _deal_wide_range(cls, amount: float, *, inr: bool = False) -> str:
        """Wide commercial/P&L money band — not a tight estimate of the true figure."""
        if inr:
            if amount < 200_000:
                return "₹50,000 to ₹3 lakh"
            if amount < 1_000_000:
                return "₹2 lakh to ₹12 lakh"
            if amount < 10_000_000:
                return "₹15 lakh to ₹1 crore"
            if amount < 80_000_000:
                return "₹2 crore to ₹12 crore"
            return "₹8 crore to ₹40 crore"
        if amount < 8_000:
            return "$1,000 to $12,000"
        if amount < 80_000:
            return "$15,000 to $90,000"
        if amount < 800_000:
            return "$150,000 to $800,000"
        if amount < 8_000_000:
            return "$2 million to $12 million"
        if amount < 80_000_000:
            return "$15 million to $90 million"
        if amount < 400_000_000:
            return "$80 million to $400 million"
        return "$250 million to $1 billion"

    @classmethod
    def _money_word_band(cls, amount: float, *, original: str = "", salary_context: bool = False) -> str:
        """Wide numeric band (or rupee band) — never the exact figure."""
        raw = original or ""
        inr = bool(re.search(r"₹|INR|\brupees?\b|\blakh\b|\bcrore\b", raw, re.I))
        if salary_context:
            return cls._salary_wide_range(amount, inr=inr)
        return cls._deal_wide_range(amount, inr=inr)

    @classmethod
    def _nearby_money_phrase(cls, value: str, *, salary_context: bool = False) -> str:
        amounts = cls._iter_money_amounts(value)
        if len(amounts) >= 2 and not salary_context:
            lo, hi = min(amounts[0], amounts[1]), max(amounts[0], amounts[1])
            span = cls._deal_wide_range(hi, inr=bool(re.search(r"₹|INR|lakh|crore", value or "", re.I)))
            return span
        amount = amounts[0] if amounts else cls._parse_money_amount(value)
        if amount is None:
            return "a confidential amount"
        return cls._money_word_band(amount, original=value, salary_context=salary_context)

    @classmethod
    def labeled_entity(cls, kind: str, value: str, catalog: dict | None = None) -> str:
        """company 01 / employee 02 / customer 01 — numbered category, not the real name."""
        kind_key = re.sub(r"[^a-z]", "", (kind or "item").lower()) or "item"
        if kind_key in {"person", "colleague", "name"}:
            kind_key = "employee"
        if kind_key in {"logo", "brand", "org", "organization"}:
            kind_key = "company"
        key = re.sub(r"\s+", " ", (value or "").strip().lower()) or kind_key
        store = catalog if catalog is not None else {}
        bucket = store.setdefault(kind_key, {})
        if key in bucket:
            return bucket[key]
        n = len(bucket) + 1
        label = f"{kind_key} {n:02d}"
        bucket[key] = label
        return label

    # Soft synonym swaps for the recommended rewrite — plain language, same intent.
    # Applied after concrete hide→hint substitutions. Does not change placeholders.
    MEANING_SAFE_SYNONYMS: list[tuple[str, str]] = [
        (r"(?i)\bOPEX\b", "operating costs"),
        (r"(?i)\bCAPEX\b", "capital spending"),
        (r"(?i)\bP&L\b", "profit and loss"),
        (r"(?i)\bEBITDA\b", "operating earnings"),
        (r"(?i)\bARR\b", "recurring revenue"),
        (r"(?i)\bMRR\b", "monthly recurring revenue"),
        (r"(?i)\bACV\b", "annual contract value"),
        (r"(?i)\bTCV\b", "total contract value"),
        (r"(?i)\bSSN\b", "government ID"),
        (r"(?i)\bsocial security numbers?\b", "government ID"),
        # EMP IDs are swapped in generalization_hint (fictional badge) — do not
        # re-scrub those placeholders here.
        (r"(?i)\bapi[_ -]?keys?\b", "access credentials"),
        (r"(?i)\bsecret[_ -]?keys?\b", "access credentials"),
        (r"(?i)\bpasswords?\b", "sign-in credentials"),
        (r"(?i)\bconfidential\b", "internal"),
        (r"(?i)\bproprietary\b", "company-internal"),
        (r"(?i)\binternal only\b", "for internal use"),
        (r"(?i)\bdo not (?:share|distribute|forward)\b", "keep internal"),
        (r"(?i)\btrade secrets?\b", "protected know-how"),
        (r"(?i)\bPII\b", "personal details"),
        (r"(?i)\bPHI\b", "health details"),
        (r"(?i)\bpatient (?:id|identifier|record)s?\b", "a clinical record reference"),
        (r"(?i)\bmarket share\b", "competitive position"),
        (r"(?i)\bheadcount\b", "team size"),
        (r"(?i)\battrition\b", "turnover"),
        (r"(?i)\bPIP\b", "performance plan"),
        (r"(?i)\bseverance\b", "exit package"),
        (r"(?i)\bcompensation review\b", "pay review"),
        (r"(?i)\bsalary is\b", "pay is"),
        (r"(?i)\bbase pay\b", "base pay level"),
        (r"(?i)\bQ[1-4]\s*(?:FY\s*)?20\d{2}\b", "a recent quarter"),
        (r"(?i)\b(?:FY|fiscal year)\s*20\d{2}\b", "a recent fiscal year"),
        (r"(?i)\bthis\s+(?:morning|afternoon|evening|week|month|quarter|year)\b", "recently"),
        (r"(?i)\blast\s+(?:Monday|Tuesday|Wednesday|Thursday|Friday|week|month|quarter)\b", "recently"),
        (r"(?i)\bcodenamed?\s+[A-Z][A-Za-z0-9_-]+\b", "an internal project name"),
        (r"(?i)\bproject\s+[A-Z][A-Za-z0-9_-]{2,}\b", "an internal project"),
    ]

    # Never emit these as company-name replacements in rewrite suggestions
    BANNED_COMPANY_STANDINS: frozenset[str] = frozenset(
        {
            "our company",
            "a company",
            "the company",
            "your company",
            "our organization",
            "the organization",
            "an organization",
            "a recent commercial deal",
            "a commercial deal",
            "the commercial deal",
            "a recent acquisition",
        }
    )
    _BANNED_COMPANY_STANDIN_RE = re.compile(
        r"(?i)\b(?:"
        r"our company|a company|the company|your company|"
        r"our organization|the organization|an organization|"
        r"a recent commercial deal|a commercial deal|the commercial deal|"
        r"a recent acquisition"
        r")\b"
    )

    @classmethod
    def apply_meaning_safe_synonyms(cls, text: str) -> str:
        """Replace leftover jargon and exact figures; keep the ask answerable."""
        out = text or ""
        for pattern, repl in cls.MEANING_SAFE_SYNONYMS:
            out = re.sub(pattern, repl, out)

        held: list[str] = []

        def _hold_band(m: re.Match[str]) -> str:
            held.append(m.group(0))
            return f"[[BAND{len(held) - 1}]]"

        out = re.sub(
            r"(?i)(?:\$|USD|EUR|GBP|₹)\s*[\d,]+(?:\.\d+)?(?:\s*(?:million|billion|thousand|lakh|crore))?"
            r"\s+to\s+"
            r"(?:\$|USD|EUR|GBP|₹)\s*[\d,]+(?:\.\d+)?(?:\s*(?:million|billion|thousand|lakh|crore))?",
            _hold_band,
            out,
        )
        out = re.sub(
            r"(?i)\d+(?:\.\d+)?\s*%\s+to\s+\d+(?:\.\d+)?\s*%",
            _hold_band,
            out,
        )

        salaryish_doc = bool(
            re.search(
                r"(?i)\b(?:salary|compensation|bonus|base pay|pay band|earns|earning)\b",
                out,
            )
        )

        def _pct_leftover(m: re.Match[str]) -> str:
            lead = m.group(1) or ""
            try:
                n = float(m.group(2))
            except (ValueError, IndexError):
                n = 10.0
            return f"{lead}{cls._percent_band_phrase(n)}"

        out = re.sub(
            r"(?i)\b((?:down|up|off|by|of|at)\s+)(\d+(?:\.\d+)?)\s*%(?!\s+to\s+\d)",
            _pct_leftover,
            out,
        )
        out = re.sub(
            r"(?i)(?<!to )(?<![\d.])(\d+(?:\.\d+)?)\s*%(?!\s+to\s+\d)",
            lambda m: cls._percent_band_phrase(float(m.group(1))),
            out,
        )
        out = re.sub(
            r"(?i)(?<![\d.])(\d+(?:\.\d+)?)\s+percent\b",
            lambda m: cls._percent_band_phrase(float(m.group(1))),
            out,
        )

        def _money_leftover(m: re.Match[str]) -> str:
            return cls._nearby_money_phrase(
                m.group(0), salary_context=salaryish_doc
            )

        out = re.sub(
            r"(?i)(?<!to )(?:\$|USD|EUR|GBP|INR|₹)\s*\d[\d,]*(?:\.\d+)?\s*"
            r"(?:billion|million|thousand|trillion|bn|mn|lakh|crore)?"
            r"(?!\s+to\s+[\$₹])",
            _money_leftover,
            out,
        )
        for i, band in enumerate(held):
            out = out.replace(f"[[BAND{i}]]", band)
        out = re.sub(r"\s{2,}", " ", out).strip()
        out = re.sub(r"(?i)\b(a|an)\s+around\b", "around", out)
        out = re.sub(r"(?i)\b(a|an)\s+about\b", "about", out)
        out = re.sub(r"(?i)\babout\s+about\b", "about", out)
        return out

    # Structural words we redacted for risk scoring but should stay readable in the rewrite.
    _REWRITE_KEEP = frozenset(
        {
            "pricing",
            "discount",
            "quote",
            "proposal",
            "rfp",
            "rfi",
            "rfq",
            "revenue",
            "earnings",
            "arr",
            "mrr",
            "ebitda",
            "salary",
            "compensation",
            "bonus",
            "acquisition",
            "acquisitions",
            "merger",
            "m&a",
            "deal",
            "pipeline",
            "forecast",
            "budget",
            "confidential",
            "internal only",
            "nda",
            "contract",
            "customer",
            "client",
            "prospect",
        }
    )

    @classmethod
    def generalization_hint(
        cls, category: str, value: str, *, prompt: str = "", catalog: dict | None = None
    ) -> str | None:
        """Category-level substitute that keeps meaning without leaking the specific.

        Returns None when the span should stay as-is in the suggested rewrite
        (generic policy keywords that only mark sensitivity, not a concrete secret).
        """
        v = (value or "").strip()
        if not v:
            return None
        vl = v.lower()
        compact = re.sub(r"\s+", " ", vl)
        cat = (category or "").lower()
        prompt_l = (prompt or "").lower()

        # Keep bare structural words so the rewrite still reads like the user's ask
        if compact in cls._REWRITE_KEEP or re.fullmatch(
            r"(?i)(?:pricing|discount|quote|proposal|rfp|rfi|rfq|revenue|salary|"
            r"compensation|bonus|acquisition|merger|confidential|nda|contract|"
            r"opex|capex|budget|forecast|pipeline|margin)",
            v.strip(),
        ):
            return None

        # Concrete percentages — keep the metric (P&L, revenue, OPEX); never emit digits.
        pct_m = re.search(r"(?i)(\d+(?:\.\d+)?)\s*%", v)
        if pct_m and (
            cat == "finance"
            or re.search(
                r"(?i)opex|capex|revenue|arr|mrr|ebitda|margin|budget|forecast|"
                r"p&l|profit|valuation|earnings|costs?|"
                r"dip|drop|decline|decrease|increase|growth|variance|"
                r"down|up|off",
                v + " " + prompt_l,
            )
        ):
            try:
                n = float(pct_m.group(1))
            except ValueError:
                n = 0.0
            band = cls._percent_band_phrase(n)
            down_in_value = bool(
                re.search(
                    r"(?i)\b(?:dip|drop|decline|decrease|down|downturn|off)\b",
                    v,
                )
            )
            up_in_value = bool(
                re.search(r"(?i)\b(?:increase|growth|uptick|up)\b", v)
            )
            down = down_in_value or bool(
                re.search(
                    r"(?i)\b(?:dip|drop|decline|decrease|down|downturn|off|cutting|cut)\b",
                    prompt_l,
                )
            )
            up = up_in_value or bool(
                re.search(r"(?i)\b(?:increase|growth|uptick|up)\b", prompt_l)
            )
            metric_m = re.search(
                r"(?i)\b(OPEX|CAPEX|OpEx|CapEx|P&L|revenue|ARR|MRR|EBITDA|profit|"
                r"gross margin|net income|valuation|earnings|budget|forecast|costs?|sales)\b",
                v,
            )
            metric = metric_m.group(1) if metric_m else None
            if re.search(r"(?i)\bby\s+\d+(?:\.\d+)?\s*%", v) and not down_in_value and not up_in_value:
                if metric:
                    return f"{metric} by {band}"
                return band
            if metric and down_in_value:
                return f"{band} decline in {metric}"
            if metric and up_in_value:
                return f"{band} increase in {metric}"
            if metric and re.search(r"(?i)\b(?:of|at|was|is)\b", v):
                return f"{metric} of {band}"
            if down_in_value or (down and not metric):
                return f"{band} decline"
            if up_in_value or (up and not metric):
                return f"{band} increase"
            return band

        if re.search(r"(?i)CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]{4,}|zero[- ]day", v):
            return "a recent critical vulnerability"
        if cat == "security" and re.search(
            r"(?i)\b(?:CVE-|GHSA-|zero[- ]day|vulnerabilit(?:y|ies)|incident|breach)\b", v
        ):
            return "a recent critical vulnerability"

        # Employee / badge IDs (and name+ID spans) → fictional person + fake badge
        if re.search(
            r"(?i)\bEMP[-_]?\d{3,}\b|\b(?:CTR|contractor)[-_]?\d{3,}\b|"
            r"\b(?:employee(?: id| number)?|badge(?: id)?|staff id|emp[_ -]?id|"
            r"associate id|worker id)\b",
            v,
        ):
            person = cls._PERSON_CORE_RE.search(v)
            if person:
                return (
                    f"{cls.labeled_entity('employee', person.group(1), catalog)} "
                    f"({cls.labeled_entity('employee', v, catalog)})"
                )
            return cls.labeled_entity("employee", v, catalog)
        # Period + metric as a unit
        if re.search(
            r"(?i)\b(?:Q[1-4]|FY\d{2,4}|H[12])\b.*\b(?:revenue|earnings|sales|ARR|MRR)\b",
            v,
        ) or (
            re.search(r"(?i)\b(?:Q[1-4]|FY\d{2,4}|H[12])\b", v) and "revenue" in vl
        ):
            return "quarterly revenue"
        # Bare quarter labels with a year (Q2 2026) — generalize; keep the ask answerable
        if re.fullmatch(r"(?i)Q[1-4]\s*(?:FY\s*)?20\d{2}", v.strip()):
            return "a recent quarter"
        if re.fullmatch(r"(?i)(?:FY|fiscal year)\s*20\d{2}", v.strip()):
            return "a recent fiscal year"
        if re.fullmatch(
            r"(?i)(?:january|february|march|april|may|june|july|august|september|"
            r"october|november|december)\s+\d{1,2},?\s+20\d{2}",
            v.strip(),
        ):
            return "recently"

        # Company / deal naming — use prompt context so we don't call every logo an acquisition
        _CORP_NOUN = (
            r"Inc|Corp|Corporation|Ltd|LLC|Company|GmbH|PLC|Pvt\.?\s*Ltd|"
            r"Solutions|Technologies|Technology|Systems|Software|Labs|Group|Partners|"
            r"Ventures|Industries|Holdings|Networks|Dynamics|Analytics|Consulting|Services"
        )
        camel_brand = bool(re.fullmatch(r"[A-Z][a-z]+[A-Z][A-Za-z0-9]*", v))
        companyish = bool(
            re.search(
                rf"\b[A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+)*\s+(?:{_CORP_NOUN})\b",
                v,
            )
            or re.search(
                r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b",
                v,
            )
            or camel_brand
            or re.search(
                rf"(?i)\b(?:{_CORP_NOUN})\b",
                v,
            )
        )
        # Common CamelCase tech words — not company logos
        if camel_brand and compact in {
            "javascript",
            "typescript",
            "powerpoint",
            "chatgpt",
            "openai",
            "youtube",
            "linkedin",
            "github",
            "gitlab",
            "mongodb",
            "postgresql",
            "graphql",
            "kubernetes",
            "jenkins",
            "bitbucket",
            "salesforce",
            "hubspot",
            "wordpress",
            "sharepoint",
        }:
            return None

        acq_in_value = bool(re.search(r"(?i)acquisition|acquirer|acquiree|merger|M&A|acquire", v))
        acq_in_prompt = bool(
            re.search(r"(?i)\b(?:acquisition|acquired|acquirer|merger|M&A)\b", prompt_l)
        )
        deal_in_prompt = bool(
            re.search(r"(?i)\b(?:deal|closed[- ]won|opportunity|term sheet)\b", prompt_l)
        )
        productish = bool(
            re.search(
                r"(?i)\b(?:codename|code[- ]name|project|product|release|roadmap)\b",
                prompt_l + " " + vl,
            )
            and camel_brand
        )
        if productish and not re.search(rf"(?i)\b(?:{_CORP_NOUN})\b", v):
            return cls.labeled_entity("product", v, catalog)

        # Named companies → company 01 only when prompt has deal/confidential depth.
        # Bare "What about Northwind Analytics?" stays clear (Safe) — no rewrite hint.
        has_corp_suffix = bool(re.search(rf"(?i)\b(?:{_CORP_NOUN})\b", v))
        person_only = bool(re.fullmatch(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}", v.strip()))
        person_kind = cls._person_kind(cat, prompt_l)
        name_sensitive = cls._has_sensitive_name_context(prompt_l, v)
        if has_corp_suffix and not re.fullmatch(
            rf"(?i)(?:{_CORP_NOUN})", v.strip()
        ):
            return cls.labeled_entity("company", v, catalog) if name_sensitive else None
        if acq_in_value or (companyish and acq_in_prompt and cat == "sales"):
            if not name_sensitive and not acq_in_value and not acq_in_prompt:
                return None
            if has_corp_suffix or (companyish and not person_only):
                return cls.labeled_entity("company", v, catalog)
            if person_only:
                return cls.labeled_entity(person_kind, v, catalog)
            return cls.labeled_entity("company", v or "acquisition", catalog)
        if companyish and cat in {"sales", "finance", "legal", "marketing", "operations"}:
            if not name_sensitive:
                return None
            if has_corp_suffix:
                return cls.labeled_entity("company", v, catalog)
            if person_only:
                return cls.labeled_entity(person_kind, v, catalog)
            if camel_brand and cat == "sales":
                return cls.labeled_entity("company", v, catalog)
            if camel_brand:
                return None
            return cls.labeled_entity("company", v, catalog)

        # Person-like "First Last" — only rewrite when sensitive context is present
        if person_only and cat in {
            "hr",
            "pii",
            "sales",
        }:
            return (
                cls.labeled_entity(person_kind, v, catalog) if name_sensitive else None
            )
        salaryish = bool(
            re.search(
                r"(?i)salary|compensation|bonus|base pay|OTE|total cash|pay band|severance",
                v,
            )
        ) or bool(
            re.search(
                r"(?i)\b(?:salary|compensation|bonus|base pay|pay band|earns|earning)\b",
                prompt_l,
            )
            and re.search(r"[\d,$]", v)
        )

        currencyish = bool(
            re.search(
                r"(?i)\$|USD|EUR|GBP|INR|₹|million|billion|thousand|\d{1,3}(?:,\d{3})+",
                v,
            )
        )
        if currencyish and (cat in {"finance", "hr", "sales"} or salaryish):
            amount = cls._parse_money_amount(v)
            treat_as_salary = salaryish or (
                cat == "hr"
                or (
                    amount is not None
                    and 20_000 <= amount < 500_000
                    and not re.search(r"(?i)million|billion|bn|mn|mm\b", v)
                    and re.search(r"(?i)\b(?:salary|compensation|pay|bonus|earns|earning)\b", prompt_l)
                )
            )
            # Deal / acquisition dollars read better as magnitude phrases
            if not treat_as_salary and (
                acq_in_prompt or deal_in_prompt or re.search(r"(?i)million|billion|lakh|crore", v)
            ):
                return cls._nearby_money_phrase(v, salary_context=False)
            return cls._nearby_money_phrase(v, salary_context=treat_as_salary)

        if cat == "hr" and re.search(r"[A-Z]", v):
            # Bare employee names stay clear unless compensation / ID context exists
            if not cls._has_sensitive_name_context(prompt_l, v):
                return None
            if re.fullmatch(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}", v):
                return cls.labeled_entity("employee", v, catalog)
            return cls.labeled_entity("employee", v, catalog)

        if cat == "engineering":
            if re.search(r"(?i)key|token|secret|password|credential|bearer|AKIA|sk-", v):
                return "an access credential"
            return None  # keep generic eng wording
        if cat == "legal":
            return None if compact in cls._REWRITE_KEEP else "an internal legal matter"
        if cat == "healthcare":
            return "a clinical matter"
        if cat == "operations":
            if re.search(r"(?i)incident|outage|severity", v):
                return "an internal operations issue"
            return None
        if cat == "marketing":
            if re.search(r"(?i)unannounced|roadmap|launch", v):
                return "an upcoming product plan"
            return None
        if cat == "pii":
            if "@" in v:
                return "a colleague's contact"
            if re.search(r"\d", v):
                return "personal contact details"
            if re.fullmatch(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+", v):
                return cls.labeled_entity("employee", v, catalog)
            return None
        if cat == "finance":
            if re.search(r"(?i)invoice|PO[#\s-]|purchase order", v):
                return "a purchase reference"
            if re.search(r"(?i)bank|IBAN|routing|account", v):
                return "a payment account reference"
            if re.search(
                r"(?i)\b(?:cvv|cvc|cid)\b|\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[ -]?\d{4}",
                v,
            ):
                return "a payment card reference"
            return None  # keep words like revenue/forecast; amounts handled above
        if cat == "sales":
            if re.search(r"(?i)pipeline|opportunity|quota", v):
                return "a sales opportunity"
            return None
        if cat == "security":
            if re.search(r"(?i)password|credential|key", v):
                return "an access credential"
            return None
        return None

    @staticmethod
    def _expand_span(text: str, start: int, end: int, category: str, value: str) -> tuple[int, int]:
        """Widen matches so deal/period/name phrasing generalizes as a unit."""
        vl = (value or "").lower()
        # "Northwind Analytics acquisition" — pull in preceding Proper Case words
        if category == "sales" and re.search(r"(?i)acquisition|merger|acquire", vl):
            m = re.search(r"((?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+)$", text[:start])
            if m:
                start = start - len(m.group(1))
        # "$5 to $15" / "$3-$8" — keep the range as one finance span
        if category == "finance" and re.search(r"\$|\d", value or ""):
            m = re.match(
                r"\s*(?:to|-|–|—)\s*\$?\s?\d+(?:,\d{3})*(?:\.\d+)?",
                text[end:],
            )
            if m and not re.search(r"(?i)\b(?:to|-|–|—)\b", value or ""):
                end = end + len(m.group(0))
        # "OrionTech" → "OrionTech Solutions"
        if category == "sales" and re.fullmatch(
            r"[A-Z][a-z]+[A-Z][A-Za-z0-9]*", value or ""
        ):
            m = re.match(
                r"\s+(?:Solutions|Technologies|Technology|Systems|Software|Labs|Group|"
                r"Partners|Ventures|Industries|Holdings|Networks|Dynamics|Analytics|"
                r"Consulting|Services)",
                text[end:],
            )
            if m:
                end = end + len(m.group(0))
        # "Q4 revenue" — pull in quarter/FY prefix
        if category == "finance" and re.search(r"(?i)revenue|earnings|ARR|MRR|sales", vl):
            m = re.search(r"((?:Q[1-4]|FY\d{2,4}|H[12])\s+)$", text[:start], re.I)
            if m:
                start = start - len(m.group(1))
        # "Jane Doe EMP-10422" — pull in preceding person name
        if category == "hr" and re.search(r"(?i)\bEMP[-_]?\d{3,}\b", vl):
            m = re.search(r"((?:[A-Z][a-z]+\s+){1,3})$", text[:start])
            if m:
                start = start - len(m.group(1))
        return start, end

    # Corporate nouns used to locate a company core inside an over-wide match
    _CORP_SUFFIX_RE = (
        r"(?:Inc|Corp|Corporation|Ltd|LLC|Company|GmbH|PLC|Pvt\.?\s*Ltd|"
        r"Solutions|Technologies|Technology|Systems|Software|Labs|Group|Partners|"
        r"Ventures|Industries|Holdings|Networks|Dynamics|Analytics|Consulting|Services)"
    )
    _COMPANY_CORE_RE = re.compile(
        # Prefer Proper-Case name tokens so "Sarah Chen about Contoso Ltd" → Contoso Ltd
        rf"\b((?:[A-Z][A-Za-z0-9]*\s+){{0,2}}[A-Z][A-Za-z0-9]*\s+{_CORP_SUFFIX_RE})\b"
    )
    _PERSON_CORE_RE = re.compile(
        r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"
    )
    # Leading junk words that greedy Inc/Ltd matches often swallow on folded surfaces
    _ENTITY_LEAD_STOP = frozenset(
        {
            "how", "did", "does", "do", "what", "when", "where", "why", "who", "whom",
            "summarize", "draft", "write", "email", "ping", "ask", "tell", "please",
            "can", "could", "would", "should", "about", "regarding", "concerning",
            "for", "with", "from", "into", "onto", "the", "a", "an", "our", "my",
            "your", "their", "its", "this", "that", "and", "or", "but", "to", "of",
            "in", "on", "at", "by", "as", "is", "was", "are", "were", "be", "been",
            "talking", "points", "year", "long", "contract", "deal", "message",
            "brief", "notify", "contact", "call", "cc", "bcc",
        }
    )

    @classmethod
    def _trim_leading_stopwords(cls, span: str) -> tuple[int, str]:
        """Return (offset into span, trimmed text) after dropping lead stopwords."""
        tokens = re.split(r"(\s+)", span)
        i = 0
        offset = 0
        # tokens alternate word, whitespace, word, ...
        while i < len(tokens):
            tok = tokens[i]
            if not tok.strip():
                offset += len(tok)
                i += 1
                continue
            if tok.lower().strip(".,;:?!") in cls._ENTITY_LEAD_STOP:
                offset += len(tok)
                i += 1
                continue
            break
        trimmed = span[offset:]
        return offset, trimmed

    @classmethod
    def _trim_trailing_stopwords(cls, span: str) -> str:
        tokens = re.split(r"(\s+)", span or "")
        while tokens:
            tok = tokens[-1]
            if not tok.strip():
                tokens.pop()
                continue
            if tok.lower().strip(".,;:?!") in cls._ENTITY_LEAD_STOP:
                tokens.pop()
                continue
            break
        return "".join(tokens).strip()

    @classmethod
    def _clean_person_name(cls, name: str) -> str | None:
        """Drop lead/trail stopwords; require First Last shape."""
        if not name:
            return None
        parts = name.split()
        while parts and parts[0].lower().strip(".,;:?!") in cls._ENTITY_LEAD_STOP:
            parts.pop(0)
        while parts and parts[-1].lower().strip(".,;:?!") in cls._ENTITY_LEAD_STOP:
            parts.pop()
        if len(parts) < 2:
            return None
        cleaned = " ".join(parts)
        if not re.fullmatch(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}", cleaned):
            return None
        if re.search(rf"(?i)\b{cls._CORP_SUFFIX_RE}\b", cleaned):
            return None
        return cleaned

    @classmethod
    def _iter_entity_cores(
        cls, text: str, start: int, end: int, category: str, value: str
    ) -> list[tuple[int, int, str]]:
        """Shrink over-wide sales spans to company / person cores so rewrites stay grammatical.

        Returns one or more (start, end, category) cores. Non-sales categories pass through.
        """
        if category != "sales":
            return [(start, end, category)]
        span = text[start:end]
        cores: list[tuple[int, int, str]] = []
        occupied: list[tuple[int, int]] = []

        def _add(a: int, b: int, cat: str) -> None:
            if b <= a:
                return
            if any(not (b <= s or a >= e) for s, e in occupied):
                return
            occupied.append((a, b))
            cores.append((a, b, cat))

        # Prefer company-shaped substring(s) first (rightmost logos)
        for m in cls._COMPANY_CORE_RE.finditer(span):
            raw = m.group(1)
            off, trimmed = cls._trim_leading_stopwords(raw)
            trimmed = cls._trim_trailing_stopwords(trimmed)
            if not trimmed or len(trimmed) < 3:
                continue
            rel = raw.find(trimmed)
            if rel < 0:
                rel = off
            a = start + m.start(1) + rel
            b = a + len(trimmed)
            _add(a, b, "sales")

        # Person names (First Last) — never keep lead verbs like "Email"
        for m in cls._PERSON_CORE_RE.finditer(span):
            cleaned = cls._clean_person_name(m.group(1))
            if not cleaned:
                continue
            rel = span.find(cleaned, m.start(1), m.end(1) + 1)
            if rel < 0:
                rel = span.find(cleaned)
            if rel < 0:
                continue
            a, b = start + rel, start + rel + len(cleaned)
            _add(a, b, "sales")

        # Outreach verb + name: "Email Sarah Chen" → keep only the name
        outreach = re.search(
            r"(?i)\b(?:email|ping|ask|tell|cc|bcc|contact|call|message|brief|notify)\s+"
            r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b",
            span,
        )
        if outreach:
            cleaned = cls._clean_person_name(outreach.group(1)) or outreach.group(1)
            rel = span.find(cleaned)
            if rel >= 0:
                _add(start + rel, start + rel + len(cleaned), "sales")

        if cores:
            return cores

        # Fallback: single trimmed entity only when it still looks like one name/logo
        off, trimmed = cls._trim_leading_stopwords(span)
        trimmed = cls._trim_trailing_stopwords(trimmed)
        if not trimmed:
            return [(start, end, category)]
        m = cls._COMPANY_CORE_RE.search(trimmed)
        if m:
            rel = trimmed.find(m.group(1))
            a = start + off + max(rel, 0)
            b = a + len(m.group(1))
            return [(a, b, category)]
        person = cls._clean_person_name(trimmed)
        if person:
            rel = trimmed.find(person)
            a = start + off + max(rel, 0)
            return [(a, a + len(person), category)]
        # Avoid returning stopword-tainted leftovers like "Sarah Chen about"
        if trimmed != span and re.search(rf"(?i)\b{cls._CORP_SUFFIX_RE}\b", trimmed):
            return [(start + off, start + off + len(trimmed), category)]
        return [(start, end, category)]

    # Fictional but plausible stand-ins — rewrite path must read like natural language
    FICTIONAL_COMPANIES: tuple[str, ...] = (
        "Meridian Softworks",
        "Cedar Peak Labs",
        "Bright Harbor Systems",
        "Northvale Dynamics",
        "Silverpine Analytics",
        "Oakridge Ventures",
        "Horizon Bridge Group",
        "Bluefinch Technologies",
        "Ironwood Consulting",
        "Lumenfield Partners",
        "Coral Bay Industries",
        "Stonebrook Holdings",
        "Fairwind Networks",
        "Maplecrest Solutions",
        "Redfern Software",
        "Ashford Analytics",
    )
    FICTIONAL_PEOPLE: tuple[str, ...] = (
        "Jordan Hale",
        "Casey Morgan",
        "Riley Quinn",
        "Alex Rivera",
        "Sam Ortiz",
        "Taylor Brooks",
        "Morgan Ellis",
        "Blake Avery",
        "Jamie Weston",
        "Cameron Shaw",
        "Drew Sullivan",
        "Avery Nolan",
        "Reese Dalton",
        "Parker Quinn",
        "Hayden Brooks",
        "Rowan Ellis",
    )
    FICTIONAL_PRODUCTS: tuple[str, ...] = (
        "the flagship platform",
        "the internal toolkit",
        "the upcoming release",
        "the core product line",
        "the customer portal",
        "the analytics suite",
    )

    @classmethod
    def _stable_pick(cls, value: str, pool: tuple[str, ...]) -> str:
        """Deterministic placeholder from the original value (stable within a session)."""
        if not pool:
            return "a placeholder"
        digest = hashlib.sha256((value or "").strip().lower().encode("utf-8")).hexdigest()
        return pool[int(digest[:8], 16) % len(pool)]

    @classmethod
    def fictional_company_name(cls, value: str, catalog: dict | None = None) -> str:
        """Numbered company label — company 01, company 02 — never the real name."""
        return cls.labeled_entity("company", value, catalog)

    @classmethod
    def is_banned_company_standin(cls, text: str | None) -> bool:
        t = (text or "").strip().lower()
        if not t:
            return False
        if t in cls.BANNED_COMPANY_STANDINS:
            return True
        return bool(cls._BANNED_COMPANY_STANDIN_RE.fullmatch(t))

    @classmethod
    def scrub_banned_company_standins(
        cls, text: str, *, seed_values: list[str] | None = None, catalog: dict | None = None
    ) -> str:
        """Replace generic company stand-ins with company 01 / company 02."""
        out = text or ""
        seeds = [s for s in (seed_values or []) if s and str(s).strip()]
        store = catalog if catalog is not None else {}
        seed_i = 0

        def _repl(_m: re.Match[str]) -> str:
            nonlocal seed_i
            seed = seeds[seed_i] if seed_i < len(seeds) else (seeds[0] if seeds else "company")
            seed_i = min(seed_i + 1, max(len(seeds) - 1, 0))
            return cls.labeled_entity("company", seed, store)

        return cls._BANNED_COMPANY_STANDIN_RE.sub(_repl, out)

    @classmethod
    def sanitize_rewrite_hint(
        cls, hint: str | None, value: str = "", catalog: dict | None = None
    ) -> str | None:
        """Reject banned company stand-ins; coerce to a numbered company label."""
        if hint is None:
            return None
        h = str(hint).strip()
        if not h:
            return None
        if cls.is_banned_company_standin(h):
            return cls.labeled_entity("company", value or h, catalog)
        return h

    @classmethod
    def fictional_person_name(
        cls, value: str, catalog: dict | None = None, *, kind: str = "employee"
    ) -> str:
        return cls.labeled_entity(kind, value, catalog)

    @classmethod
    def fictional_employee_id(cls, value: str, catalog: dict | None = None) -> str:
        return cls.labeled_entity("employee", value, catalog)

    @classmethod
    def fictional_product_term(cls, value: str, catalog: dict | None = None) -> str:
        return cls.labeled_entity("product", value, catalog)

    def analyze_prompt(self, text: str):
        candidates = []
        surface, idx_map = build_match_surface(text)

        def _map_span(start_s: int, end_s: int) -> tuple[int, int] | None:
            if not idx_map or start_s < 0 or end_s <= start_s:
                return None
            if start_s >= len(idx_map) or (end_s - 1) >= len(idx_map):
                return None
            return idx_map[start_s], idx_map[end_s - 1] + 1

        # Primary pass: case- and punctuation-folded surface (basic knowledge matching)
        if surface:
            for category, patterns in self._compiled.items():
                for pattern in patterns:
                    for match in pattern.finditer(surface):
                        mapped = _map_span(match.start(), match.end())
                        if not mapped:
                            continue
                        start, end = self._expand_span(
                            text, mapped[0], mapped[1], category, text[mapped[0]:mapped[1]]
                        )
                        for c_start, c_end, c_cat in self._iter_entity_cores(
                            text, start, end, category, text[start:end]
                        ):
                            candidates.append({
                                "type": c_cat,
                                "value": text[c_start:c_end],
                                "start": c_start,
                                "end": c_end,
                            })

        # Secondary pass: original text (CamelCase brands, exact punctuation forms)
        for category, patterns in self._compiled.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    start, end = self._expand_span(
                        text, match.start(), match.end(), category, match.group(0)
                    )
                    for c_start, c_end, c_cat in self._iter_entity_cores(
                        text, start, end, category, text[start:end]
                    ):
                        candidates.append({
                            "type": c_cat,
                            "value": text[c_start:c_end],
                            "start": c_start,
                            "end": c_end,
                        })

        # Evasion pass: spaced/dashed token runs → compact, then re-check secret patterns
        # against the compacted value while redacting the original spaced span.
        for spaced in _SPACED_SECRET_CANDIDATE.finditer(text):
            compact = re.sub(r"[\s\-]+", "", spaced.group(0))
            for category, patterns in self._compiled.items():
                if category not in {"engineering", "hr", "finance", "security", "pii"}:
                    continue
                for pattern in patterns:
                    if pattern.search(compact) or pattern.search(normalize_for_match(compact)):
                        candidates.append({
                            "type": category,
                            "value": spaced.group(0),
                            "start": spaced.start(),
                            "end": spaced.end(),
                        })
                        break
                else:
                    continue
                break

        # Evasion pass: base64-decode token-like blobs and flag if a secret is inside
        for b64 in _BASE64_SECRET_CANDIDATE.finditer(text):
            token = b64.group(0)
            pad = (-len(token)) % 4
            try:
                raw = base64.b64decode(token + ("=" * pad), validate=False)
                decoded = raw.decode("utf-8")
            except Exception:
                continue
            if not decoded or not all(ch.isprintable() or ch in "\n\r\t" for ch in decoded):
                continue
            scan_surfaces = [
                decoded,
                compact_spaced_secret_candidates(decoded),
                normalize_for_match(decoded),
            ]
            hit_category = None
            for category, patterns in self._compiled.items():
                if category not in {"engineering", "hr", "finance", "security", "pii"}:
                    continue
                for pattern in patterns:
                    if any(pattern.search(surface) for surface in scan_surfaces if surface):
                        hit_category = category
                        break
                if hit_category:
                    break
            if hit_category:
                candidates.append({
                    "type": hit_category,
                    "value": token,
                    "start": b64.start(),
                    "end": b64.end(),
                })

        # Prefer longer matches; drop overlaps
        candidates.sort(key=lambda c: (c["end"] - c["start"], -c["start"]), reverse=True)
        selected = []
        occupied = []
        for cand in candidates:
            if any(not (cand["end"] <= s or cand["start"] >= e) for s, e in occupied):
                continue
            occupied.append((cand["start"], cand["end"]))
            selected.append(cand)

        selected.sort(key=lambda c: c["start"])

        flagged = []
        token_map = {}
        redacted_text = text
        token_counter = 1
        catalog: dict[str, dict[str, str]] = {}
        hint_by_span: dict[tuple[int, int], str | None] = {}
        for item in selected:
            value = (item["value"] or "").strip()
            hint_by_span[(item["start"], item["end"])] = self.sanitize_rewrite_hint(
                self.generalization_hint(
                    item["type"], value, prompt=text, catalog=catalog
                ),
                value,
                catalog,
            )

        # Replace from the end so earlier offsets stay valid — only HIDE spans become tokens
        for item in sorted(selected, key=lambda c: c["start"], reverse=True):
            value = (item["value"] or "").strip()
            hint = hint_by_span.get((item["start"], item["end"]))
            action, reason = self.span_action(item["type"], value, hint, text)
            # Force hide when a generalization exists or shape is concrete
            if action == "hide":
                token = f"<{item['type'].upper()}_{token_counter}>"
                token_counter += 1
                token_map[token] = value
                redacted_text = (
                    redacted_text[: item["start"]]
                    + token
                    + redacted_text[item["end"] :]
                )
            else:
                token = ""  # kept in cleartext for meaning
            flagged.append({
                "type": item["type"],
                "value": value,
                "token": token,
                "department": item["type"],
                "generalization_hint": hint,
                "action": action,
                "reason": reason,
                "start": item["start"],
                "end": item["end"],
            })

        flagged.reverse()

        score = 0
        hide_seen_by_dept: dict[str, int] = {}
        for item in flagged:
            w = self.DEPARTMENT_WEIGHTS.get(item["type"], 20)
            if item.get("action") == "hide":
                # Diminishing returns so four $ prices don't slam the meter to 100%
                n = hide_seen_by_dept.get(item["type"], 0)
                hide_seen_by_dept[item["type"]] = n + 1
                score += max(6, int(w / (2 ** n)))
            else:
                # Topic "keep" words still raise awareness, but weigh less than concrete secrets
                score += max(8, w // 3)
        score = min(100, score)

        by_department = {}
        for item in flagged:
            by_department[item["type"]] = by_department.get(item["type"], 0) + 1

        department_risk = {
            dept: 0 for dept in self.PATTERNS.keys()
        }
        for dept, count in by_department.items():
            department_risk[dept] = min(100, count * self.DEPARTMENT_WEIGHTS.get(dept, 20))

        placeholders = [
            {
                "token": item["token"] or "—",
                "original": item["value"],
                "department": item["type"],
                "generalization_hint": item.get("generalization_hint"),
                "action": item.get("action") or "hide",
                "reason": item.get("reason") or "",
                "rewrite_as": item.get("generalization_hint") or item["value"],
            }
            for item in flagged
        ]

        hidden_n = sum(1 for it in flagged if it.get("action") == "hide")
        kept_n = sum(1 for it in flagged if it.get("action") == "keep")

        if flagged:
            bits = []
            if hidden_n:
                bits.append(
                    f"hid {hidden_n} concrete secret(s) as placeholders "
                    f"({', '.join(token_map.keys()) or 'none'})"
                )
            if kept_n:
                bits.append(
                    f"kept {kept_n} topic word(s) in cleartext so the ask still makes sense"
                )
            prevention_summary = (
                "ExhaustShield reviewed sensitive spans before the LLM call: "
                + "; ".join(bits)
                + ". Hidden values are restored only on-gateway after the model replies."
            )
        else:
            prevention_summary = (
                "No department policy matches were found. The prompt was forwarded "
                "to the LLM unchanged."
            )

        return {
            "risk_score": score,
            "flagged_items": flagged,
            "redacted_text": redacted_text,
            "token_map": token_map,
            "by_department": by_department,
            "department_risk": department_risk,
            "placeholders": placeholders,
            "placeholder_policy": self.placeholder_policy(),
            "prevention": {
                "secrets_blocked": hidden_n,
                "topic_words_kept": kept_n,
                "departments_involved": list(by_department.keys()),
                "llm_exposed_secrets": 0 if hidden_n else "n/a",
                "summary": prevention_summary,
            },
        }

    # ------------------------------------------------------------------
    # Table / dataset scrub: synthetic numbers (same magnitude), fictional
    # names, format-preserved keys — restore_map reverses on the way back
    # ------------------------------------------------------------------
    _TABLE_FIRST_NAMES = (
        "Alex", "Jordan", "Casey", "Riley", "Morgan", "Quinn", "Avery", "Cameron",
        "Drew", "Jamie", "Taylor", "Sage", "Reese", "Skyler", "Parker", "Rowan",
    )
    _TABLE_LAST_NAMES = (
        "Rivera", "Nguyen", "Patel", "Brooks", "Keller", "Hayes", "Ortiz", "Bennett",
        "Singh", "Coleman", "Walsh", "Fujimoto", "Ibrahim", "Kowalski", "Dubois", "Okafor",
    )

    @classmethod
    def looks_like_dataset(cls, text: str) -> bool:
        """True for CSV / TSV / markdown tables with a header + several data rows."""
        t = (text or "").strip()
        if not t or len(t) < 20:
            return False
        parsed = cls._parse_table(t)
        if not parsed:
            return False
        headers, rows = parsed
        return len(headers) >= 2 and len(rows) >= 2

    @classmethod
    def _parse_table(cls, text: str) -> tuple[list[str], list[list[str]]] | None:
        """Best-effort parse of CSV, TSV, or markdown pipe tables embedded in a prompt."""
        raw = text or ""
        # Prefer fenced / contiguous table block if the prompt has prose around it
        block = raw
        fence = re.search(r"```(?:csv|tsv|text)?\s*([\s\S]*?)```", raw, re.I)
        if fence:
            block = fence.group(1).strip()
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        if len(lines) < 3:
            # Maybe whole prompt is the table with a short ask on first/last line
            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if len(lines) < 3:
            return None

        # Markdown pipe table
        if sum(1 for ln in lines[:8] if ln.count("|") >= 2) >= 3:
            md_lines = [ln for ln in lines if ln.count("|") >= 2]
            md_lines = [
                ln for ln in md_lines
                if not re.match(r"^\|?\s*:?-{3,}", ln.replace("|", " ").strip() or "x")
                and not re.match(r"^[\|\s:\-]+$", ln)
            ]
            if len(md_lines) >= 3:
                def _split_md(ln: str) -> list[str]:
                    parts = [p.strip() for p in ln.strip().strip("|").split("|")]
                    return parts
                headers = _split_md(md_lines[0])
                rows = [_split_md(ln) for ln in md_lines[1:]]
                rows = [r for r in rows if len(r) == len(headers)]
                if len(headers) >= 2 and len(rows) >= 2:
                    return headers, rows

        # CSV / TSV — find a contiguous block with consistent delimiter counts
        for delim in [",", "\t", ";"]:
            best: tuple[list[str], list[list[str]]] | None = None
            i = 0
            while i < len(lines):
                # Skip until a line looks like a header (2+ fields)
                if lines[i].count(delim) < 1:
                    i += 1
                    continue
                header_count = lines[i].count(delim)
                headers = [c.strip().strip('"') for c in lines[i].split(delim)]
                if len(headers) < 2:
                    i += 1
                    continue
                rows: list[list[str]] = []
                j = i + 1
                while j < len(lines) and lines[j].count(delim) == header_count:
                    cells = [c.strip().strip('"') for c in lines[j].split(delim)]
                    if len(cells) == len(headers):
                        rows.append(cells)
                    j += 1
                if len(rows) >= 2:
                    best = (headers, rows)
                    break
                i += 1
            if best:
                return best
        return None

    @classmethod
    def _classify_table_column(cls, header: str, values: list[str]) -> str:
        h = (header or "").strip().lower()
        nonempty = [v for v in values if str(v).strip()]
        if re.search(r"(?i)\b(?:email|e-mail)\b", h) or any(
            "@" in v for v in nonempty[:20]
        ):
            return "email"
        if re.search(
            r"(?i)\b(?:revenue|amount|price|cost|salary|ebitda|profit|value|usd|qty|quantity|units|count|total|fee)\b",
            h,
        ):
            return "number"
        if re.search(
            r"(?i)\b(?:name|employee|customer|contact|person|owner|rep|manager)\b",
            h,
        ) or (
            nonempty
            and sum(
                1
                for v in nonempty[:20]
                if re.fullmatch(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}", v.strip())
            )
            >= max(2, len(nonempty[:20]) // 2)
        ):
            return "name"
        if re.search(
            r"(?i)\b(?:id|key|ref|uuid|ssn|badge|emp|account\s*#|deal\s*ref|oppty)\b",
            h,
        ) or (
            nonempty
            and sum(
                1
                for v in nonempty[:20]
                if re.match(r"(?i)^[A-Z]{2,5}[-_]\d{3,}$", v.strip())
                or (
                    re.match(r"(?i)^[A-F0-9\-]{8,}$", v.strip())
                    and re.search(r"[A-Fa-f]", v)
                    and not v.strip().isdigit()
                )
            )
            >= max(2, len(nonempty[:20]) // 2)
        ):
            return "key"
        # Value-shape fallback
        numish = 0
        for v in nonempty[:20]:
            if cls._parse_money_amount(v) is not None or re.fullmatch(
                r"[-+]?\d[\d,]*(?:\.\d+)?%?", v.strip()
            ):
                numish += 1
        if nonempty and numish >= max(2, len(nonempty[:20]) // 2):
            return "number"
        return "text"

    @classmethod
    def _synth_table_number(cls, value: str, factor: float) -> str:
        raw = (value or "").strip()
        if re.fullmatch(r"[-+]?\d+(?:\.\d+)?\s*%", raw):
            return raw  # keep ratios
        amount = cls._parse_money_amount(raw)
        if amount is not None and amount != 0:
            return cls._format_scaled_money(raw, abs(amount) * factor * (1 if amount > 0 else -1))
        m = re.fullmatch(r"([-+]?)(\d[\d,]*(?:\.\d+)?)", raw)
        if not m:
            return raw
        try:
            num = float(m.group(2).replace(",", ""))
        except ValueError:
            return raw
        scaled = num * factor
        if abs(scaled - round(scaled)) < 1e-9:
            body = f"{int(round(scaled)):,}"
        else:
            body = f"{scaled:.2f}".rstrip("0").rstrip(".")
            if "," in m.group(2):
                # keep simple decimal form
                pass
        return f"{m.group(1)}{body}"

    @classmethod
    def _synth_table_name(cls, value: str, catalog: dict) -> str:
        """Fictional First Last — stable per original within this table scrub."""
        key = re.sub(r"\s+", " ", (value or "").strip().lower()) or "person"
        bucket = catalog.setdefault("table_person", {})
        if key in bucket:
            return bucket[key]
        first = cls._stable_pick(key + "|f", cls._TABLE_FIRST_NAMES)
        last = cls._stable_pick(key + "|l", cls._TABLE_LAST_NAMES)
        label = f"{first} {last}"
        # Avoid accidental identity
        if label.lower() == (value or "").strip().lower():
            label = f"{cls._stable_pick(key + '|f2', cls._TABLE_FIRST_NAMES)} {cls._stable_pick(key + '|l2', cls._TABLE_LAST_NAMES)}"
        bucket[key] = label
        return label

    @classmethod
    def _synth_table_email(cls, value: str, catalog: dict) -> str:
        key = (value or "").strip().lower()
        bucket = catalog.setdefault("table_email", {})
        if key in bucket:
            return bucket[key]
        n = len(bucket) + 1
        label = f"person{n:02d}@example.com"
        bucket[key] = label
        return label

    @classmethod
    def build_table_scrub(
        cls, text: str, *, factor: float | None = None
    ) -> dict[str, Any]:
        """Replace a full table/dataset with synthetic peers; build restore_map."""
        import secrets

        raw = text or ""
        parsed = cls._parse_table(raw)
        if not parsed:
            return {
                "applicable": False,
                "scrubbed": raw,
                "restore_map": {},
                "factor": None,
                "mode": "table_synthetic",
            }
        headers, rows = parsed
        kinds = [
            cls._classify_table_column(h, [r[i] for r in rows if i < len(r)])
            for i, h in enumerate(headers)
        ]
        rng = secrets.SystemRandom()
        use_factor = float(factor) if factor and factor > 1.01 else rng.uniform(1.55, 1.95)
        use_factor = round(use_factor, 4)
        salt = int(use_factor * 10_000) % 997
        catalog: dict[str, dict[str, str]] = {}
        restore_map: dict[str, str] = {}

        def _remember(new: str, old: str) -> str:
            if not new or new == old:
                return old
            # Unique synthetic surface if collision
            out = new
            n = 2
            while out in restore_map and restore_map[out] != old:
                out = f"{new}#{n}"
                n += 1
            restore_map[out] = old
            return out

        new_rows: list[list[str]] = []
        for row in rows:
            new_row = []
            for i, cell in enumerate(row):
                old = cell
                kind = kinds[i] if i < len(kinds) else "text"
                if not str(old).strip():
                    new_row.append(old)
                    continue
                if kind == "number":
                    synth = cls._synth_table_number(old, use_factor)
                elif kind == "name":
                    synth = cls._synth_table_name(old, catalog)
                elif kind == "email":
                    synth = cls._synth_table_email(old, catalog)
                elif kind == "key":
                    synth = cls._format_preserve_id(old, salt=salt + i)
                else:
                    # Generic sensitive-looking tokens → stable fictional label
                    if re.fullmatch(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}", old.strip()):
                        synth = cls._synth_table_name(old, catalog)
                    elif "@" in old:
                        synth = cls._synth_table_email(old, catalog)
                    elif cls._parse_money_amount(old) is not None:
                        synth = cls._synth_table_number(old, use_factor)
                    else:
                        synth = old
                new_row.append(_remember(synth, old) if synth != old else old)
            new_rows.append(new_row)

        # Rebuild table in the same family as the source
        if re.search(r"\|.+\|", raw) and raw.count("|") >= 6:
            def _md(row: list[str]) -> str:
                return "| " + " | ".join(row) + " |"
            table_out = "\n".join(
                [_md(headers), "| " + " | ".join("---" for _ in headers) + " |"]
                + [_md(r) for r in new_rows]
            )
        else:
            delim = "\t" if raw.count("\t") >= raw.count(",") else ","
            def _csv(row: list[str]) -> str:
                out_cells = []
                for c in row:
                    if delim in c or "," in c or '"' in c:
                        out_cells.append('"' + c.replace('"', '""') + '"')
                    else:
                        out_cells.append(c)
                return delim.join(out_cells)
            table_out = "\n".join([_csv(headers)] + [_csv(r) for r in new_rows])

        # Splice back into prompt if table was only a portion
        scrubbed = raw
        # Replace first occurrence of original serialized table region
        orig_block_lines = []
        # Reconstruct original table text from parsed rows for replacement
        if "\t" in raw and raw.count("\t") >= raw.count(","):
            od = "\t"
        elif raw.count("|") >= 6:
            od = "|"
        else:
            od = ","
        if od == "|":
            orig_serialized = "\n".join(
                ["| " + " | ".join(headers) + " |"]
                + [
                    ln
                    for ln in raw.splitlines()
                    if re.match(r"^\|?\s*:?-{3,}", (ln or "").replace("|", " "))
                ][:1]
                + ["| " + " | ".join(r) + " |" for r in rows]
            )
            # Simpler: replace line-by-line where data rows match
            scrubbed = raw
            for old_row, new_row in zip(rows, new_rows):
                for variant in (
                    ",".join(old_row),
                    "\t".join(old_row),
                    "| " + " | ".join(old_row) + " |",
                    "|" + "|".join(old_row) + "|",
                ):
                    if variant in scrubbed:
                        repl = (
                            "| " + " | ".join(new_row) + " |"
                            if "|" in variant
                            else (",".join(new_row) if "," in variant else "\t".join(new_row))
                        )
                        scrubbed = scrubbed.replace(variant, repl, 1)
                        break
        else:
            for old_row, new_row in zip(rows, new_rows):
                for variant in (",".join(old_row), "\t".join(old_row)):
                    if variant in scrubbed:
                        scrubbed = scrubbed.replace(
                            variant,
                            (",".join(new_row) if "," in variant else "\t".join(new_row)),
                            1,
                        )
                        break
            # Header stays (column names are schema, not secrets) unless they look like names
            pass

        if scrubbed == raw and restore_map:
            # Fallback: use rebuilt table only + keep any non-table prefix/suffix ask
            prefix = ""
            suffix = ""
            # If prompt starts with ask then table, try to keep first line
            first_lines = raw.splitlines()
            if first_lines and not (
                "," in first_lines[0] or "\t" in first_lines[0] or first_lines[0].count("|") >= 2
            ):
                prefix = first_lines[0] + "\n"
            scrubbed = (prefix + table_out).strip()

        applicable = bool(restore_map) and scrubbed != raw
        return {
            "applicable": applicable,
            "scrubbed": scrubbed if applicable else raw,
            "restore_map": restore_map if applicable else {},
            "factor": use_factor if applicable else None,
            "mode": "table_synthetic",
            "column_kinds": dict(zip(headers, kinds)),
            "counts": {
                "rows": len(rows),
                "cols": len(headers),
                "cells_rewritten": len(restore_map),
            },
        }

    # ------------------------------------------------------------------
    # Analysis-lane scrub: session-scaled finance + typed entity labels
    # (ratios / multiples stay valid; exact dollars never leave cleartext)
    # ------------------------------------------------------------------
    _ANALYSIS_CUE_RE = re.compile(
        r"(?i)\b(?:"
        r"EBITDA|EV/EBITDA|P/E|multiple|fair\s+multiple|valuation|"
        r"YoY|year[- ]over[- ]year|acquired|acquisition|acquirer|"
        r"revenue|ARR|MRR|gross\s+margin|operating\s+margin|"
        r"is\s+\d+(?:\.\d+)?\s*x\b|given\s+\d+(?:\.\d+)?\s*%"
        r")\b"
    )
    _ANALYSIS_MONEY_RE = re.compile(
        r"(?i)(?:(?:\$|USD|EUR|GBP|INR|₹)\s*[\d,]+(?:\.\d+)?\s*"
        r"(?:billion|million|thousand|trillion|bn|mn|mm|lakh|crore|[BbMmKk])?\b|"
        r"\$\s*[\d,]+(?:\.\d+)?[BbMmKk]\b)"
    )
    _ANALYSIS_EMAIL_RE = re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    )
    _ANALYSIS_PERSON_RE = re.compile(
        r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"
    )
    _ANALYSIS_ORG_RE = re.compile(
        r"\b((?:[A-Z][A-Za-z0-9&.\-]*(?:\s+[A-Z][A-Za-z0-9&.\-]*){0,3})\s+"
        r"(?:Inc|Corp|Corporation|Ltd|LLC|Company|GmbH|PLC|Holdings|Partners|"
        r"Ventures|Industries|Group|Systems|Solutions|Technologies|Analytics|"
        r"Consulting|Services|Labs|Networks|Dynamics))\b"
    )
    # Single Proper / CamelCase brand next to finance language (Mindsprint, OrionTech)
    _ANALYSIS_BRAND_RE = re.compile(
        r"\b([A-Z][a-z]+(?:[A-Z][A-Za-z0-9]+)+|[A-Z][a-z]{3,})\b"
    )
    _ANALYSIS_BRAND_BLOCKLIST = frozenset(
        {
            "EBITDA", "Revenue", "Profit", "Margin", "Quarter", "Growth", "Decline",
            "Jump", "Dip", "Net", "Gross", "Operating", "Focus", "How", "What",
            "When", "Where", "Why", "With", "From", "Last", "Next", "Still",
            "Things", "Consider", "Recorded", "YoY", "USD", "EUR", "GBP",
        }
    )
    _ANALYSIS_DEAL_ID_RE = re.compile(
        r"\b((?:AC|OPP|DEAL|REF|CRM)[-_ ]?[A-Z0-9]{4,})\b",
        re.I,
    )
    _ANALYSIS_PERSON_BLOCKLIST = frozenset(
        {
            "our", "the", "and", "for", "with", "from", "into", "is", "are",
            "was", "were", "been", "being", "had", "have", "has", "this",
            "that", "these", "those", "ebitda", "yoy", "usd", "eur", "gbp",
            "arr", "mrr", "acv", "tcv", "gaap", "ifrs",
        }
    )

    @classmethod
    def is_ratio_analysis_prompt(cls, text: str) -> bool:
        """True when the ask needs ratio/multiple/performance math on financial figures.

        Triggers when there are several currency amounts, OR one amount plus
        financial % / EBITDA-style cues (e.g. \"$3Mn … jump of 15% … EBITDA of 12%\").
        """
        t = text or ""
        if not cls._ANALYSIS_CUE_RE.search(t):
            return False
        money_hits = list(cls._ANALYSIS_MONEY_RE.finditer(t))
        if len(money_hits) >= 2:
            return True
        if len(money_hits) >= 1 and re.search(
            r"(?i)\d+(?:\.\d+)?\s*%|"
            r"\b(?:EBITDA|YoY|year[- ]over[- ]year|gross\s+margin|net\s+profit|"
            r"operating\s+margin|jump|dip|growth|decline)\b",
            t,
        ):
            return True
        return False

    @classmethod
    def _format_scaled_money(cls, original: str, scaled_amount: float) -> str:
        """Render scaled dollars in a shape close to the original ($45M → $77.85M)."""
        raw = (original or "").strip()
        currency = "$"
        if re.match(r"(?i)USD", raw):
            currency = "USD "
        elif re.match(r"(?i)EUR", raw):
            currency = "EUR "
        elif re.match(r"(?i)GBP", raw):
            currency = "GBP "
        elif "₹" in raw or re.match(r"(?i)INR", raw):
            currency = "₹"

        compact = re.search(
            r"(?i)([\d,]+(?:\.\d+)?)\s*([BbMmKk]|million|billion|thousand|bn|mn|mm)\b",
            raw,
        )
        unit_token = (compact.group(2) if compact else "") or ""
        unit_l = unit_token.lower()

        def _num(n: float, decimals: int = 2) -> str:
            if abs(n - round(n)) < 1e-9:
                return str(int(round(n)))
            return f"{n:.{decimals}f}".rstrip("0").rstrip(".")

        if unit_l in {"m", "mm", "mn", "million"} or (
            unit_l == "" and scaled_amount >= 1_000_000 and re.search(r"(?i)\$\s*[\d.]+[Mm]\b", raw)
        ):
            # Prefer compact $77.85M / $5.19Mn when original used $45M / $3Mn
            if re.search(r"(?i)\$\s*[\d,]+(?:\.\d+)?Mn\b", raw):
                return f"{currency}{_num(scaled_amount / 1_000_000)}Mn"
            if re.search(r"(?i)\$\s*[\d,]+(?:\.\d+)?[Mm]\b", raw) and not re.search(
                r"(?i)million", raw
            ):
                return f"{currency}{_num(scaled_amount / 1_000_000)}M"
            return f"{currency}{_num(scaled_amount / 1_000_000)} million"
        if unit_l in {"b", "bn", "billion"}:
            if re.search(r"(?i)\$\s*[\d,]+(?:\.\d+)?[Bb]\b", raw) and not re.search(
                r"(?i)billion", raw
            ):
                return f"{currency}{_num(scaled_amount / 1_000_000_000)}B"
            return f"{currency}{_num(scaled_amount / 1_000_000_000)} billion"
        if unit_l in {"k", "thousand"}:
            return f"{currency}{_num(scaled_amount / 1_000)}K"
        if scaled_amount >= 1_000_000:
            return f"{currency}{_num(scaled_amount / 1_000_000)}M"
        if scaled_amount >= 1_000:
            return f"{currency}{scaled_amount:,.0f}"
        return f"{currency}{_num(scaled_amount)}"

    @classmethod
    def _format_preserve_id(cls, value: str, *, salt: int) -> str:
        """Keep prefix/separators; remap digits so shape stays, value does not."""
        out = []
        digit_i = 0
        for ch in value:
            if ch.isdigit():
                # Deterministic digit remap from salt (not identity)
                out.append(str((int(ch) * 7 + salt + digit_i * 3) % 10))
                digit_i += 1
            else:
                out.append(ch)
        fake = "".join(out)
        if fake == value:
            # Guarantee difference when all zeros etc.
            chars = list(fake)
            for i, ch in enumerate(chars):
                if ch.isdigit():
                    chars[i] = str((int(ch) + 1) % 10)
                    break
            fake = "".join(chars)
        return fake

    @classmethod
    def build_analysis_scrub(
        cls, text: str, *, factor: float | None = None
    ) -> dict[str, Any]:
        """Session-scale money + Org/Person/Email/ID labels for ratio analysis.

        Percentages and Nx multiples are left untouched so fairness math still works.
        Returns scrubbed text and a restore_map (scrubbed_surface → original).
        """
        import secrets

        raw = text or ""
        if not raw.strip():
            return {
                "applicable": False,
                "scrubbed": raw,
                "restore_map": {},
                "factor": None,
                "mode": "analysis_scale",
            }

        rng = secrets.SystemRandom()
        # Tight-ish distortion: enough to hide exact dollars, ratios unchanged
        use_factor = float(factor) if factor and factor > 1.01 else rng.uniform(1.55, 1.95)
        use_factor = round(use_factor, 4)
        salt = int(use_factor * 10_000) % 997

        scrubbed = raw
        restore_map: dict[str, str] = {}
        replacements: list[tuple[int, int, str, str]] = []  # start, end, new, old

        def _queue(start: int, end: int, new: str, old: str) -> None:
            if start < 0 or end <= start or not new or new == old:
                return
            # Skip overlaps with already queued spans
            if any(not (end <= s or start >= e) for s, e, _, _ in replacements):
                return
            replacements.append((start, end, new, old))

        # Money — scale together with the same session factor
        for m in cls._ANALYSIS_MONEY_RE.finditer(raw):
            old = m.group(0)
            amount = cls._parse_money_amount(old)
            if amount is None or amount <= 0:
                continue
            scaled = amount * use_factor
            new = cls._format_scaled_money(old, scaled)
            # Avoid colliding surfaces
            if new in restore_map and restore_map[new] != old:
                new = cls._format_scaled_money(old, scaled * 1.001)
            _queue(m.start(), m.end(), new, old)

        # Emails
        email_i = 0
        for m in cls._ANALYSIS_EMAIL_RE.finditer(raw):
            email_i += 1
            old = m.group(0)
            new = f"Email_{email_i}"
            _queue(m.start(), m.end(), new, old)

        # Orgs before persons (multi-word Holdings etc.)
        org_i = 0
        for m in cls._ANALYSIS_ORG_RE.finditer(raw):
            old = m.group(1)
            # Skip generic "Our Company" style if somehow matched without Proper Case
            if old.lower() in {"our company", "the company", "a company"}:
                continue
            org_i += 1
            new = f"Org_{org_i}"
            _queue(m.start(1), m.end(1), new, old)

        # Single-token brands (Mindsprint) when finance context is present
        for m in cls._ANALYSIS_BRAND_RE.finditer(raw):
            old = m.group(1)
            if old in cls._ANALYSIS_BRAND_BLOCKLIST or old.upper() in {
                x.upper() for x in cls._ANALYSIS_BRAND_BLOCKLIST
            }:
                continue
            if old.lower() in cls._ANALYSIS_PERSON_BLOCKLIST:
                continue
            # Require nearby finance cue so random Proper nouns aren't labeled
            window = raw[max(0, m.start() - 40) : m.end() + 80]
            if not re.search(
                r"(?i)\b(?:revenue|EBITDA|profit|margin|acquired|quarter|\$|USD)\b",
                window,
            ):
                continue
            org_i += 1
            new = f"Org_{org_i}"
            _queue(m.start(1), m.end(1), new, old)

        # People — First Last, not blocked words, not inside email spans
        person_i = 0
        email_spans = [(m.start(), m.end()) for m in cls._ANALYSIS_EMAIL_RE.finditer(raw)]
        for m in cls._ANALYSIS_PERSON_RE.finditer(raw):
            old = m.group(1)
            if any(not (m.end() <= s or m.start() >= e) for s, e in email_spans):
                continue
            parts = old.split()
            if any(p.lower() in cls._ANALYSIS_PERSON_BLOCKLIST for p in parts):
                continue
            # Skip org cores already queued
            if any(
                old in orig or orig in old
                for _, _, _, orig in replacements
            ):
                # only skip if overlapping an org replacement span
                if any(
                    not (m.end() <= s or m.start() >= e)
                    for s, e, _, _ in replacements
                ):
                    continue
            person_i += 1
            new = f"Person_{person_i}"
            _queue(m.start(1), m.end(1), new, old)

        # Deal / CRM style IDs — format-preserving
        for m in cls._ANALYSIS_DEAL_ID_RE.finditer(raw):
            old = m.group(1)
            new = cls._format_preserve_id(old, salt=salt)
            _queue(m.start(1), m.end(1), new, old)

        # Apply right-to-left
        for start, end, new, old in sorted(replacements, key=lambda x: x[0], reverse=True):
            scrubbed = scrubbed[:start] + new + scrubbed[end:]
            restore_map[new] = old

        applicable = bool(restore_map) and scrubbed != raw
        return {
            "applicable": applicable,
            "scrubbed": scrubbed,
            "restore_map": restore_map,
            "factor": use_factor if applicable else None,
            "mode": "analysis_scale",
            "counts": {
                "money": sum(1 for k in restore_map if k[:1] in "$€£₹" or re.match(r"(?i)USD|EUR|GBP", k)),
                "org": sum(1 for k in restore_map if k.startswith("Org_")),
                "person": sum(1 for k in restore_map if k.startswith("Person_")),
                "email": sum(1 for k in restore_map if k.startswith("Email_")),
                "id": sum(
                    1
                    for k, v in restore_map.items()
                    if re.match(r"(?i)(?:AC|OPP|DEAL|REF|CRM)", v or "")
                ),
            },
        }

    def restore_text(
        self,
        text: str,
        token_map: dict | None = None,
        analysis_scrub: dict | None = None,
    ):
        """Put real values back after external AI.

        1) Exact replace of stand-ins / tokens (Org_1, $4.69Mn, <FINANCE_1>, …)
        2) Analysis-scale: reverse any paraphrased money via session factor
        3) Strip invented <DEPT_N> tags the model may have added
        """
        restored = text or ""
        scrub = analysis_scrub or {}
        merged: dict[str, str] = {}
        merged.update(token_map or {})
        merged.update(scrub.get("restore_map") or {})

        # Longer stand-ins first (avoid partial collisions)
        for token, original in sorted(merged.items(), key=lambda kv: len(kv[0]), reverse=True):
            if token and original is not None and token in restored:
                restored = restored.replace(token, str(original))

        # Reverse-scale money the model slightly rewrote ($4.69Mn → $4.7Mn)
        factor = scrub.get("factor")
        restore_map = scrub.get("restore_map") or {}
        if factor and float(factor) > 1.01 and restore_map:
            restored = self._restore_scaled_money_spans(
                restored, factor=float(factor), restore_map=restore_map
            )

        orphan = re.compile(r"<([A-Z][A-Z0-9]*)_\d+>")
        if orphan.search(restored):
            restored = orphan.sub("(not provided in your message)", restored)
            restored = re.sub(r"\s{2,}", " ", restored).strip()
        return restored

    @classmethod
    def _restore_scaled_money_spans(
        cls, text: str, *, factor: float, restore_map: dict[str, str]
    ) -> str:
        """Map scaled / near-scaled dollar spans back to originals using the session factor."""
        pairs: list[tuple[float, float, str]] = []  # scaled_amt, orig_amt, orig_str
        for standin, orig in (restore_map or {}).items():
            sa = cls._parse_money_amount(str(standin))
            oa = cls._parse_money_amount(str(orig))
            if sa and oa and sa > 0 and oa > 0:
                pairs.append((sa, oa, str(orig)))
        if not pairs:
            return text or ""

        def _repl(m: re.Match[str]) -> str:
            span = m.group(0)
            amt = cls._parse_money_amount(span)
            if amt is None or amt <= 0:
                return span
            # Exact / near match to a known scaled surface
            for sa, _oa, orig in pairs:
                if abs(amt - sa) / sa <= 0.03:
                    return orig
            # Divide by session factor → nearest original
            approx = amt / factor
            best = None
            best_err = 1.0
            for _sa, oa, orig in pairs:
                err = abs(approx - oa) / oa
                if err < best_err:
                    best_err = err
                    best = orig
            if best is not None and best_err <= 0.05:
                return best
            return span

        return cls._ANALYSIS_MONEY_RE.sub(_repl, text or "")
