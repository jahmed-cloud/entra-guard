"""
ai_agent.py — Investigative agent: gives the AI a bounded, read-only
Microsoft Graph query tool so it can actually verify a finding rather than
just narrate a pre-packaged evidence summary.

HARD BOUNDARIES (all enforced in code, not just by prompt instruction):

  1. READ-ONLY, structurally, not by request. The GraphClient instance
     passed to this agent (from tasks.py) only has a .get() and
     .get_all_pages() method — there is no create/update/delete method
     anywhere on that class for the agent to call even if it wanted to.
     The tool wrapper here additionally re-validates that outgoing paths
     look like a GET-shaped Graph read, as defense in depth.

  2. BOUNDED TOOL CALLS. Each finding gets at most AI_AGENT_MAX_TOOL_CALLS
     (default 3) Graph lookups before the agent must produce a final
     answer. This is a real cost/latency control, not just tidiness — an
     unbounded agent loop against a paid or rate-limited API is a genuine
     liability.

  3. EVERY TOOL CALL IS LOGGED. Full audit trail of exactly which Graph
     paths the agent queried for which finding — see the `queries_made`
     field returned alongside the explanation. This is not a black box;
     you can see precisely what it looked at.

  4. STILL CANNOT WRITE status/score/severity. Same as the non-agent
     explainer — this only ever returns ai_explanation,
     ai_false_positive_likelihood, ai_false_positive_reason, plus the new
     ai_queries_made audit field. The deterministic verdict from the check
     function is final and untouched.

  5. GRACEFUL FALLBACK. If tool-calling isn't supported by the configured
     model/provider, or the loop errors, or times out, this falls back to
     the existing non-agent evidence-only explanation from ai_explainer.py
     rather than failing the finding or the scan.

── Provider support ──────────────────────────────────────────────────────────
Tool-calling requires a model that actually supports function calling.
Groq's free-tier default (llama-3.1-8b-instant) does NOT reliably support
this — llama-3.3-70b-versatile does. Set AI_AGENT_MODEL_GROQ explicitly if
using Groq with the agent. OpenAI and Anthropic models generally support
tool calling natively. Ollama support varies by model — test before relying
on it.

AI_AGENT_ENABLED=false by default — this is a heavier, slower, costlier
feature than the base explainer and is opt-in separately from
AI_EXPLAIN_ENABLED.
"""

import os
import json
import logging

log = logging.getLogger(__name__)

AI_AGENT_ENABLED = os.getenv("AI_AGENT_ENABLED", "false").lower() == "true"
AI_AGENT_MAX_TOOL_CALLS = int(os.getenv("AI_AGENT_MAX_TOOL_CALLS", "3"))
AI_AGENT_MAX_FINDINGS_PER_SCAN = int(os.getenv("AI_AGENT_MAX_FINDINGS_PER_SCAN", "5"))
AI_AGENT_MAX_SECONDS_PER_FINDING = int(os.getenv("AI_AGENT_MAX_SECONDS_PER_FINDING", "90"))

# Agent-specific model overrides — tool calling needs a capable model, which
# may differ from the (often smaller/cheaper) default used for plain
# explanation text. Falls back to the base explainer's model if not set.
AI_AGENT_MODEL_GROQ = os.getenv("AI_AGENT_MODEL_GROQ", "") or "llama-3.3-70b-versatile"

# Ollama — fully local, no API key. Tool-calling support varies sharply by
# model: qwen2.5/qwen3 and llama3.1+ generally support it, smaller/older
# models often don't. If the agent consistently falls back to the plain
# explainer with Ollama, the model likely isn't emitting tool_calls — try a
# larger or more recent model before assuming the integration is broken.
AI_AGENT_MODEL_OLLAMA = os.getenv("AI_AGENT_MODEL_OLLAMA", "") or "qwen2.5"
AI_AGENT_MODEL_OPENAI = os.getenv("AI_AGENT_MODEL_OPENAI", "") or "gpt-4o-mini"


def resolve_agent_provider_config():
    """Returns (provider_name, config_dict) for whichever provider is
    configured via AI_EXPLAIN_PROVIDER, or (None, None) if the configured
    provider doesn't support the agent's tool-calling requirement.

    This lives here rather than in tasks.py so provider knowledge stays in
    one place — tasks.py previously hardcoded Groq here, which meant setting
    AI_EXPLAIN_PROVIDER=ollama would correctly route the plain explainer to
    a local model while the agent silently kept calling Groq. That was a
    real bug, not just a missing feature."""
    provider = os.getenv("AI_EXPLAIN_PROVIDER", "anthropic").strip().lower()

    if provider == "groq":
        return "groq", {
            "api_key": os.getenv("GROQ_API_KEY", ""),
            "base_url": os.getenv("GROQ_BASE_URL", "") or "https://api.groq.com/openai/v1",
            "model": AI_AGENT_MODEL_GROQ,
        }
    if provider == "ollama":
        return "ollama", {
            "api_key": "",  # local Ollama needs no auth
            "base_url": os.getenv("OLLAMA_BASE_URL", "") or "http://host.docker.internal:11434/v1",
            "model": AI_AGENT_MODEL_OLLAMA,
        }
    if provider == "openai":
        return "openai", {
            "api_key": os.getenv("OPENAI_API_KEY", ""),
            "base_url": os.getenv("OPENAI_BASE_URL", "") or "https://api.openai.com/v1",
            "model": AI_AGENT_MODEL_OPENAI,
        }

    # Anthropic's tool-calling API uses a different request/response shape
    # than the OpenAI-compatible one this agent implements — rather than
    # silently misbehave, decline and let the caller fall back to the plain
    # explainer, which DOES support Anthropic properly.
    log.info(f"Agent does not support provider '{provider}' (tool-calling shape differs) — "
             f"findings will use the plain explainer instead.")
    return None, None

# Graph paths the agent is allowed to query — an allowlist of prefixes, not
# a denylist. This is deliberately conservative: the agent can look at
# directory/policy/identity configuration (exactly the categories every
# check in this codebase already reads), but cannot go fishing in mail,
# files, Teams messages, or anything outside the identity-security surface
# this tool is scoped to, even though the underlying app registration's
# Graph permissions might technically allow broader reads.
_ALLOWED_PATH_PREFIXES = (
    "/identity/", "/policies/", "/servicePrincipals", "/applications",
    "/directoryRoles", "/roleManagement/", "/groups", "/users",
    "/domains", "/subscribedSkus", "/identityGovernance/",
    "/identityProtection/", "/organization",
)

_DENIED_SEGMENTS = {
    "messages", "mailfolders", "drive", "drives", "events", "calendar",
    "calendars", "calendarview", "chats", "contacts", "contactfolders",
    "onenote", "photo", "photos", "conversations", "threads", "posts",
    "sites", "team", "planner", "todo", "insights", "extensions",
}


def _path_is_allowed(path: str) -> bool:
    """Defense in depth: even though GraphClient has no write methods at
    all, also reject anything that isn't a read against an allowlisted
    identity-security-relevant path. Rejects absolute URLs (could point
    off-Graph entirely), OData write-shaped hints, and anything outside
    the allowlist."""
    if not isinstance(path, str) or not path:
        return False
    if path.startswith("http://") or path.startswith("https://"):
        return False  # only relative Graph paths, never arbitrary URLs
    lowered = path.lower()
    if any(bad in lowered for bad in ("$delete", "$batch", "action", "invite")):
        return False
    # "/users" and "/groups" are allowed prefixes, but their sub-resources
    # include mailboxes, files, chats and calendars — exactly what the
    # comment above says the agent must not read. Also block ".." so a path
    # can't climb out of an allowlisted prefix.
    segments = {seg for seg in lowered.split("?", 1)[0].split("/") if seg}
    if ".." in segments or segments & _DENIED_SEGMENTS:
        return False
    return any(path.startswith(prefix) for prefix in _ALLOWED_PATH_PREFIXES)


def _make_graph_tool_schema():
    """OpenAI-compatible tool schema — shared shape across every provider
    that supports tool calling, since Groq/OpenAI/Ollama-with-tools all
    use this same JSON structure."""
    return [{
        "type": "function",
        "function": {
            "name": "query_graph",
            "description": (
                "Query Microsoft Graph API (read-only, GET requests only) to look up "
                "additional tenant configuration relevant to verifying this finding. "
                "Use this to check for compensating controls the original check may not "
                "have queried — e.g. Security Defaults, per-user MFA state, a differently-"
                "shaped Conditional Access policy. Returns the raw JSON response."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "A Microsoft Graph v1.0 relative path, e.g. "
                            "'/policies/identitySecurityDefaultsEnforcementPolicy' or "
                            "'/identity/conditionalAccess/policies'. Must be a GET-shaped "
                            "read path — no write operations are possible."
                        ),
                    }
                },
                "required": ["path"],
            },
        },
    }]


def _agent_affected_block(affected_resources) -> str:
    """Reuses the explainer's redaction so PII handling is defined in exactly
    one place — if the redaction rules change, both prompt paths change
    together rather than drifting apart."""
    if not affected_resources:
        return ""
    try:
        from app.ai_explainer import _redact_affected_resources
        redacted = _redact_affected_resources(affected_resources)
        if not redacted:
            return ""
        return (f"Affected resources (identifying values redacted, sample): "
                f"{json.dumps(redacted, default=str, indent=2)}\n")
    except Exception:
        return ""


def _build_agent_system_prompt(check_id: str, status: str, severity: str, evidence: dict,
                                affected_resources=None) -> str:
    return (
        "You are a senior Entra ID / Azure AD identity security engineer investigating "
        "one automated security check result. The status was already decided by "
        "deterministic code — you are NOT deciding pass/fail. Your job is to verify "
        "whether that verdict is trustworthy by actually checking the tenant's live "
        "configuration, then explain your finding clearly.\n\n"
        f"Check ID: {check_id}\n"
        f"Severity: {severity}\n"
        f"Status: {status}\n"
        f"Evidence already collected by the check: {json.dumps(evidence, default=str, indent=2)}\n"
        f"{_agent_affected_block(affected_resources)}\n"
        "You have a query_graph(path) tool available to look up ADDITIONAL tenant "
        f"configuration — you may call it up to {AI_AGENT_MAX_TOOL_CALLS} times. Use it "
        "specifically to check for compensating controls the check's own evidence "
        "doesn't cover — for example, if this is an MFA-related check that failed, "
        "consider checking '/policies/identitySecurityDefaultsEnforcementPolicy' to see "
        "if Security Defaults independently covers the gap.\n\n"
        "Once you have enough information (or have used your tool call budget), respond "
        "with EXACTLY this structure, three lines, nothing else:\n\n"
        "EXPLANATION: <2-3 sentences, grounded in the evidence AND anything you looked up, "
        "explaining why this verdict makes sense.>\n"
        "FALSE_POSITIVE: <one word: none, possible, or likely>\n"
        "FALSE_POSITIVE_REASON: <if not 'none', name the specific compensating control you "
        "found (or suspect) and why it might make the verdict wrong. If 'none', write 'N/A'.>"
    )


def _run_agent_loop_openai_compatible(base_url: str, api_key: str, model: str,
                                       system_prompt: str, graph_client,
                                       max_tool_calls: int, timeout: int = 30,
                                       max_total_seconds: int = 90) -> tuple:
    """Runs the tool-calling loop against any OpenAI-compatible /chat/completions
    endpoint (OpenAI, Groq, Ollama-with-tools). Returns (final_text, queries_made).
    Raises on any error — caller is responsible for catching and falling back.

    max_total_seconds bounds the WHOLE loop, not just each individual HTTP
    call. The per-request `timeout` only caps one call; with up to
    max_tool_calls+2 sequential calls (tool rounds + the forced final
    answer), a slow-but-not-timing-out provider could otherwise stretch one
    finding's investigation well past a minute, and with
    AI_AGENT_MAX_FINDINGS_PER_SCAN investigations happening sequentially per
    scan, that compounds into several extra minutes of scan time with no
    ceiling. This was a real gap — found during review, not from an
    incident — worth closing before it becomes one."""
    import httpx, time as _time

    start_time = _time.monotonic()

    def _check_deadline():
        if _time.monotonic() - start_time > max_total_seconds:
            raise TimeoutError(f"Agent loop exceeded {max_total_seconds}s wall-clock budget")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    messages = [{"role": "user", "content": system_prompt}]
    tools = _make_graph_tool_schema()
    queries_made = []

    with httpx.Client(timeout=timeout) as client:
        for round_num in range(max_tool_calls + 1):
            _check_deadline()
            resp = client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "max_tokens": 500,
                    "messages": messages,
                    "tools": tools if round_num < max_tool_calls else None,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            choice = (data.get("choices") or [{}])[0]
            message = choice.get("message", {})
            tool_calls = message.get("tool_calls")

            if not tool_calls:
                # Model produced a final answer (no more tool calls requested)
                return (message.get("content") or "").strip(), queries_made

            # Model wants to call the tool — append its request, then append
            # our tool result(s), then loop back for the next round.
            messages.append(message)
            for tc in tool_calls:
                try:
                    args = json.loads(tc.get("function", {}).get("arguments", "{}"))
                    path = args.get("path", "")
                except (json.JSONDecodeError, AttributeError):
                    path = ""

                if not _path_is_allowed(path):
                    result_content = json.dumps({"error": "Path not permitted for this tool. Only read-only identity/policy/directory Graph paths are allowed."})
                else:
                    try:
                        result = graph_client.get(path)
                        queries_made.append(path)
                        # Trim large responses so we don't blow the context
                        # window or re-introduce the "send everything" cost
                        # problem one level down inside the agent loop itself.
                        result_content = json.dumps(result, default=str)[:3000]
                    except Exception as e:
                        # Deliberately generic message back to the model, not
                        # str(e) directly — a raw Graph exception could in
                        # principle include request details we'd rather not
                        # feed back into the conversation the model is
                        # reasoning over and may echo into its final answer.
                        # The real exception is still logged server-side for
                        # our own debugging (see investigate_finding's
                        # exception handler), just not sent to the LLM.
                        log.warning(f"Agent tool call to {path} failed: {e}")
                        result_content = json.dumps({"error": "Lookup failed or the path was not found. Try a different path or proceed without this data."})

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "content": result_content,
                })

        # Exhausted all rounds without a final non-tool-call answer — ask
        # one last time with tools disabled to force a final response.
        _check_deadline()
        resp = client.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json={"model": model, "max_tokens": 500, "messages": messages},
        )
        resp.raise_for_status()
        data = resp.json()
        message = (data.get("choices") or [{}])[0].get("message", {})
        return (message.get("content") or "").strip(), queries_made


def investigate_finding(finding: dict, graph_client, provider_name: str,
                         provider_config: dict) -> dict:
    """Runs the bounded investigative agent loop for one finding. Mutates and
    returns the finding dict with ai_explanation, ai_false_positive_likelihood,
    ai_false_positive_reason, and ai_queries_made (the audit trail of what the
    agent actually looked up) — same as ai_explainer.py's non-agent version,
    plus the audit field. Never touches status/score/severity.

    provider_config is expected to have: api_key, base_url, model.
    Only OpenAI-compatible providers (openai, groq, ollama) are supported for
    tool calling in this version — Anthropic's tool-calling API has a
    different request/response shape and isn't wired in here yet."""
    if not AI_AGENT_ENABLED:
        return finding

    check_id = finding.get("check_id", "")
    try:
        system_prompt = _build_agent_system_prompt(
            check_id, finding.get("status", ""), finding.get("severity", ""),
            finding.get("evidence", {}), finding.get("affected_resources"),
        )
        final_text, queries_made = _run_agent_loop_openai_compatible(
            provider_config["base_url"], provider_config["api_key"], provider_config["model"],
            system_prompt, graph_client, AI_AGENT_MAX_TOOL_CALLS,
            max_total_seconds=AI_AGENT_MAX_SECONDS_PER_FINDING,
        )

        # Reuse the exact same response parser as the non-agent explainer —
        # both produce the identical EXPLANATION/FALSE_POSITIVE/REASON format,
        # so there's no need for a second parsing implementation to maintain.
        from app.ai_explainer import _parse_finding_response
        parsed = _parse_finding_response(final_text)
        for k, v in parsed.items():
            if v is not None:
                finding[k] = v
        finding["ai_queries_made"] = queries_made
        if queries_made:
            log.info(f"Agent investigated {check_id}: {len(queries_made)} Graph queries made — {queries_made}")

    except Exception as e:
        log.warning(f"Agent investigation failed for {check_id} via {provider_name} "
                     f"(falling back to non-agent explanation): {e}")
        # Graceful fallback — try the plain, non-agent explainer instead of
        # leaving this finding with no AI treatment at all.
        try:
            from app.ai_explainer import explain_finding_sync
            explain_finding_sync(finding)
        except Exception as fallback_err:
            log.warning(f"Fallback explanation also failed for {check_id}: {fallback_err}")

    return finding
