"""
ai_explainer.py — Two things, both strictly advisory, never authoritative:

  1. explain_finding_sync(finding)
     Explains WHY a finding passed or failed, using only the evidence the
     deterministic check already produced. Also assesses whether the
     verdict might be a FALSE POSITIVE due to context the check couldn't
     see — e.g. "the CA policy check failed, but MFA might actually be
     enforced via Security Defaults or per-user legacy MFA, which this
     specific check doesn't query." This assessment is recorded as
     ai_false_positive_likelihood ("none"/"possible"/"likely") and
     ai_false_positive_reason — it NEVER changes `status`, `score`, or
     `severity`. A human still makes the final call; the AI just flags
     where its confidence in the deterministic verdict is lower.

  2. summarise_scan_sync(findings, checks_total, checks_passed, checks_failed)
     Writes one short narrative for the whole scan run, from the aggregate
     results only — not called per-check, called once after the loop ends.

HARD BOUNDARY, unchanged from earlier: nothing in this module can write to
`status`, `score`, or `severity`. Every field it produces is visually and
structurally separate (different DB columns, different UI treatment) from
the deterministic fields so a reader can never confuse "the check found this"
with "the AI thinks this."

── Provider support ──────────────────────────────────────────────────────────
AI_EXPLAIN_PROVIDER: "anthropic" | "openai" | "groq" | "ollama"
See .env.example for full setup instructions per provider.

── Cost/latency control ───────────────────────────────────────────────────────
AI_EXPLAIN_MAX_PER_SCAN caps how many findings get explained per scan run
(default 30). All checks are eligible — this is not an allowlist by check ID
anymore, it's a per-scan budget. When the cap is hit, findings are
prioritised in this order:
  1. Conditional Access checks (AZURE-CA-*, AZURE-CA-MFA-ALL, AZURE-CA-LEGACY*)
     — always included first, per explicit product priority.
  2. Remaining FAILED findings, ordered by severity (Critical > High > Medium
     > Low) then score, descending.
  3. PASSED findings only fill remaining budget after all failed findings
     are covered — a pass rarely needs deep reasoning, but if budget allows,
     explaining a handful of passes helps confirm they're not falsely
     reassuring.
"""

import os
import json
import logging

log = logging.getLogger(__name__)

AI_EXPLAIN_ENABLED = os.getenv("AI_EXPLAIN_ENABLED", "false").lower() == "true"
AI_EXPLAIN_PROVIDER = os.getenv("AI_EXPLAIN_PROVIDER", "anthropic").strip().lower()
AI_EXPLAIN_MAX_PER_SCAN = int(os.getenv("AI_EXPLAIN_MAX_PER_SCAN", "30"))

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
# `or` (not a bare os.getenv default) — docker-compose.yml passes these
# through as ${VAR:-} which sets the key to an EMPTY STRING when unset in
# .env, not an absent key. os.getenv()'s default argument only applies when
# the key is truly missing, so an empty string silently survives as "" and
# gets sent to the provider as an invalid empty model name (this is exactly
# what caused Groq to 404 on every single explanation call — "model": ""
# is not a real model). `x or default` correctly treats both an absent key
# AND an empty-string value as "use the default".
ANTHROPIC_MODEL = os.getenv("AI_EXPLAIN_MODEL_ANTHROPIC", "") or os.getenv("AI_EXPLAIN_MODEL", "") or "claude-sonnet-4-6"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("AI_EXPLAIN_MODEL_OPENAI", "") or "gpt-4o-mini"
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "") or "https://api.openai.com/v1"

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("AI_EXPLAIN_MODEL_GROQ", "") or "llama-3.1-8b-instant"
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "") or "https://api.groq.com/openai/v1"

OLLAMA_MODEL = os.getenv("AI_EXPLAIN_MODEL_OLLAMA", "") or "llama3.1"
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "") or "http://host.docker.internal:11434/v1"

_CA_PREFIXES = ("AZURE-CA-", "AZURE-RISK-")  # Conditional Access + risk-based CA policies
_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_VALID_FP_LEVELS = {"none", "possible", "likely"}


# ─── Provider transport (unchanged mechanics, four vendors) ───────────────────

def _call_anthropic(prompt: str, max_tokens: int = 350) -> str:
    import httpx
    with httpx.Client(timeout=20) as client:
        resp = client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={"model": ANTHROPIC_MODEL, "max_tokens": max_tokens,
                  "messages": [{"role": "user", "content": prompt}]},
        )
        resp.raise_for_status()
        data = resp.json()
    text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
    return " ".join(text_blocks).strip()


def _call_openai_compatible(prompt: str, base_url: str, api_key: str, model: str,
                             timeout: int = 20, max_tokens: int = 350) -> str:
    import httpx
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json={"model": model, "max_tokens": max_tokens,
                  "messages": [{"role": "user", "content": prompt}]},
        )
        resp.raise_for_status()
        data = resp.json()
    choices = data.get("choices", [])
    if not choices:
        return ""
    return (choices[0].get("message", {}).get("content") or "").strip()


def _call_openai(prompt: str, max_tokens: int = 350) -> str:
    return _call_openai_compatible(prompt, OPENAI_BASE_URL, OPENAI_API_KEY, OPENAI_MODEL, max_tokens=max_tokens)

def _call_groq(prompt: str, max_tokens: int = 350) -> str:
    return _call_openai_compatible(prompt, GROQ_BASE_URL, GROQ_API_KEY, GROQ_MODEL, max_tokens=max_tokens)

def _call_ollama(prompt: str, max_tokens: int = 350) -> str:
    return _call_openai_compatible(prompt, OLLAMA_BASE_URL, "", OLLAMA_MODEL, timeout=60, max_tokens=max_tokens)


_PROVIDERS = {
    "anthropic": {"key": lambda: ANTHROPIC_API_KEY, "call": _call_anthropic},
    "openai":    {"key": lambda: OPENAI_API_KEY,    "call": _call_openai},
    "groq":      {"key": lambda: GROQ_API_KEY,      "call": _call_groq},
    "ollama":    {"key": lambda: True,              "call": _call_ollama},
}


def _get_provider():
    """Returns the configured provider dict, or None if disabled/misconfigured.
    Centralised so every caller (per-finding and per-scan) applies identical
    on/off logic rather than duplicating the same three checks."""
    if not AI_EXPLAIN_ENABLED:
        return None
    provider = _PROVIDERS.get(AI_EXPLAIN_PROVIDER)
    if not provider:
        log.warning(f"AI_EXPLAIN_PROVIDER={AI_EXPLAIN_PROVIDER!r} not recognised "
                     f"(expected anthropic/openai/groq/ollama) — AI features skipped.")
        return None
    if not provider["key"]():
        return None
    return provider


# ─── Per-finding: explanation + false-positive judgment ───────────────────────

_PII_KEYS = {"upn", "userprincipalname", "email", "mail", "user", "displayname",
             "name", "owner", "member", "otheremails", "proxyaddresses"}


def _redact_affected_resources(affected, max_items: int = 8) -> list:
    """Prepares affected_resources for inclusion in an AI prompt.

    affected_resources is the field that actually carries identifiable data
    (UPNs, display names, emails) — unlike `evidence`, which across this
    codebase is almost entirely counts and booleans. Sending it raw would
    materially change this tool's privacy posture, so identifying values are
    replaced with a type marker while non-identifying context (setting names,
    issue descriptions, scenario labels, domains) is preserved, because that
    context is exactly what makes the AI's explanation more specific and
    useful than reasoning from a bare count alone.

    Also caps list length — some checks return dozens of affected items, and
    the AI needs a representative sample, not an exhaustive dump that bloats
    the prompt and re-creates the cost problem we deliberately avoided."""
    if not isinstance(affected, list):
        return []

    redacted = []
    for item in affected[:max_items]:
        if not isinstance(item, dict):
            continue
        clean = {}
        for k, v in item.items():
            if k.lower() in _PII_KEYS:
                clean[k] = f"<redacted {k}>"
            else:
                clean[k] = v
        redacted.append(clean)

    if len(affected) > max_items:
        redacted.append({"_note": f"...and {len(affected) - max_items} more (truncated for prompt size)"})
    return redacted


def _build_finding_prompt(check_id: str, status: str, severity: str, evidence: dict,
                           affected_resources=None) -> str:
    affected_block = ""
    if affected_resources:
        redacted = _redact_affected_resources(affected_resources)
        if redacted:
            affected_block = (
                f"\nAffected resources (identifying values redacted, sample): "
                f"{json.dumps(redacted, default=str, indent=2)}\n"
            )

    return (
        "You are a senior Entra ID / Azure AD identity security engineer reviewing "
        "one automated security check result. The status below was already decided "
        "by deterministic code that queried Microsoft Graph — you are NOT deciding "
        "pass/fail, you are reviewing whether that verdict is trustworthy and "
        "explaining it clearly.\n\n"
        f"Check ID: {check_id}\n"
        f"Severity: {severity}\n"
        f"Status: {status}\n"
        f"Evidence collected by the check: {json.dumps(evidence, default=str, indent=2)}\n"
        f"{affected_block}"
        "\nRespond with EXACTLY this structure, three lines, nothing else:\n\n"
        "EXPLANATION: <2-3 sentences. Add information the evidence numbers alone don't "
        "already convey to a reader — do NOT just restate '{count} is 0/low so this "
        "failed' in different words, that adds nothing the status/score didn't already "
        "say. Instead, either (a) explain the concrete attacker-relevant consequence of "
        "this specific gap, or (b) note what additional context would change the "
        "picture. If the evidence is too sparse to say anything beyond restating the "
        "numbers, say so directly: 'The evidence here is a bare count with no further "
        "detail — no additional analysis beyond the check's own verdict is possible "
        "from this alone.' A short honest answer is better than padded restatement.>\n"
        "FALSE_POSITIVE: <one word: none, possible, or likely>\n"
        "FALSE_POSITIVE_REASON: <if FALSE_POSITIVE is not 'none', explain in one "
        "sentence what OTHER tenant setting or control (not visible in the evidence "
        "above) could independently satisfy this control and make the 'failed' "
        "verdict a false positive — e.g. MFA enforced via Security Defaults, "
        "per-user legacy MFA, or a differently-shaped Conditional Access policy the "
        "check's query pattern wouldn't match. Be as specific as the evidence allows — "
        "a vague 'some other setting might cover this' is weaker than naming the "
        "actual control category you suspect (Security Defaults, per-user MFA, a "
        "broader-scoped CA policy, etc). If FALSE_POSITIVE is 'none', write "
        "'N/A'. Only say 'likely' if the evidence itself hints at a gap in what was "
        "actually queried (e.g. a policy count of 0 when broader coverage is "
        "plausible) — do not say 'likely' just because false positives are "
        "theoretically possible for any check.>"
    )


def _parse_finding_response(raw: str) -> dict:
    """Extracts the three labelled fields from the model's response. Falls
    back gracefully — if parsing fails, the explanation text is still kept
    (better degraded output than none), but false-positive fields stay None
    rather than guessing."""
    out = {"ai_explanation": None, "ai_false_positive_likelihood": None, "ai_false_positive_reason": None}
    if not raw:
        return out

    explanation_lines, fp_level, fp_reason = [], None, None
    mode = None
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("EXPLANATION:"):
            mode = "explanation"
            explanation_lines.append(stripped.split(":", 1)[1].strip())
        elif stripped.upper().startswith("FALSE_POSITIVE_REASON:"):
            mode = "fp_reason"
            fp_reason = stripped.split(":", 1)[1].strip()
        elif stripped.upper().startswith("FALSE_POSITIVE:"):
            mode = "fp_level"
            val = stripped.split(":", 1)[1].strip().lower()
            fp_level = val if val in _VALID_FP_LEVELS else None
        elif mode == "explanation" and stripped:
            explanation_lines.append(stripped)
        elif mode == "fp_reason" and stripped:
            fp_reason = f"{fp_reason} {stripped}".strip()

    out["ai_explanation"] = " ".join(explanation_lines).strip() or None
    out["ai_false_positive_likelihood"] = fp_level
    # Only keep the reason if we have a VALID level to attach it to — a reason
    # without a valid likelihood is meaningless (the UI gates display on
    # likelihood being set), and storing it anyway would leave an orphaned
    # value that never surfaces but silently occupies the column.
    if fp_level and fp_reason and fp_reason.upper() != "N/A":
        out["ai_false_positive_reason"] = fp_reason
    return out


def _is_conditional_access_check(check_id: str) -> bool:
    return check_id.startswith(_CA_PREFIXES)


def select_findings_to_explain(findings: list, max_per_scan: int = None) -> list:
    """Given ALL findings from a completed scan, returns the subset (up to
    the cap) that should get AI explanation, in priority order:
      1. Conditional Access checks (always included first)
      2. Remaining FAILED findings, by severity then score descending
      3. PASSED findings, only if budget remains
    Does not mutate the input list or any finding dict."""
    cap = max_per_scan if max_per_scan is not None else AI_EXPLAIN_MAX_PER_SCAN
    if cap <= 0:
        return []

    ca_checks = [f for f in findings if _is_conditional_access_check(f.get("check_id", ""))]
    ca_ids = {f.get("check_id") for f in ca_checks}

    remaining = [f for f in findings if f.get("check_id") not in ca_ids]
    failed = sorted(
        [f for f in remaining if f.get("status") == "failed"],
        key=lambda f: (_SEVERITY_ORDER.get(f.get("severity"), 4), -(f.get("score") or 0)),
    )
    passed = [f for f in remaining if f.get("status") == "passed"]

    selected = ca_checks[:cap]
    budget = cap - len(selected)
    if budget > 0:
        selected += failed[:budget]
        budget = cap - len(selected)
    if budget > 0:
        selected += passed[:budget]

    return selected


def explain_finding_sync(finding: dict) -> dict:
    """Adds ai_explanation, ai_false_positive_likelihood, and
    ai_false_positive_reason. Never mutates status/score/severity/evidence.
    Caller is responsible for applying the per-scan cap via
    select_findings_to_explain — this function itself has no allowlist,
    it will attempt any finding it's given."""
    provider = _get_provider()
    if not provider:
        return finding

    check_id = finding.get("check_id", "")
    try:
        prompt = _build_finding_prompt(
            check_id, finding.get("status", ""), finding.get("severity", ""),
            finding.get("evidence", {}), finding.get("affected_resources"),
        )
        raw = provider["call"](prompt)
        parsed = _parse_finding_response(raw)
        for k, v in parsed.items():
            if v is not None:
                finding[k] = v
    except Exception as e:
        log.warning(f"AI explanation failed for {check_id} via {AI_EXPLAIN_PROVIDER} "
                     f"(non-critical, scan continues): {e}")

    return finding


# ─── Per-scan: aggregate summary ───────────────────────────────────────────────

def _build_summary_prompt(stats: dict, top_findings: list, fp_flagged: list) -> str:
    top_lines = "\n".join(
        f"- [{f.get('severity')}] {f.get('check_id')} (score {f.get('score')})"
        for f in top_findings
    ) or "(none)"
    fp_lines = "\n".join(
        f"- {f.get('check_id')}: {f.get('ai_false_positive_reason', '')}"
        for f in fp_flagged
    ) or "(none flagged)"

    return (
        "You are a senior Entra ID security engineer writing a short executive "
        "summary of a completed automated security scan. Use ONLY the aggregate "
        "data below — do not invent findings not listed here.\n\n"
        f"Checks run: {stats.get('checks_total')}\n"
        f"Passed: {stats.get('checks_passed')}\n"
        f"Failed: {stats.get('checks_failed')}\n"
        f"Skipped/errored: {stats.get('checks_skipped')}\n\n"
        f"Highest-priority failing findings:\n{top_lines}\n\n"
        f"Findings flagged as possible/likely false positives (worth manual review "
        f"before treating as confirmed gaps):\n{fp_lines}\n\n"
        "Write 3-4 sentences: what the overall posture looks like, the single most "
        "urgent thing to fix first and why, and whether the false-positive flags "
        "(if any) change what should be prioritised. Plain language, no bullet "
        "points, no restating the raw numbers verbatim."
    )


def summarise_scan_sync(findings: list, checks_total: int, checks_passed: int,
                         checks_failed: int, checks_skipped: int) -> str:
    """Writes one short narrative for a completed scan run. Called once,
    after the check loop ends — never per-check. Returns None (not an
    empty string) when disabled/unconfigured so callers can distinguish
    'no summary attempted' from 'summary attempted but empty'."""
    provider = _get_provider()
    if not provider:
        return None

    try:
        failed = sorted(
            [f for f in findings if f.get("status") == "failed"],
            key=lambda f: (_SEVERITY_ORDER.get(f.get("severity"), 4), -(f.get("score") or 0)),
        )
        top_findings = failed[:8]
        fp_flagged = [f for f in findings if f.get("ai_false_positive_likelihood") in ("possible", "likely")]

        stats = {
            "checks_total": checks_total, "checks_passed": checks_passed,
            "checks_failed": checks_failed, "checks_skipped": checks_skipped,
        }
        prompt = _build_summary_prompt(stats, top_findings, fp_flagged)
        # Single retry on rate-limit (429) specifically — this call runs once
        # per scan, after up to AI_EXPLAIN_MAX_PER_SCAN per-finding calls have
        # already fired, so it's the most likely single call to land on a
        # free-tier rate limit window. A short wait-and-retry costs little
        # (one scan, one summary) and meaningfully improves reliability versus
        # just giving up on the first 429.
        try:
            summary = provider["call"](prompt)
        except Exception as first_err:
            if "429" in str(first_err):
                import time as _time
                log.info("AI scan summary hit a rate limit, waiting 5s and retrying once...")
                _time.sleep(5)
                summary = provider["call"](prompt)
            else:
                raise
        return summary or None
    except Exception as e:
        log.warning(f"AI scan summary failed via {AI_EXPLAIN_PROVIDER} (non-critical): {e}")
        return None
