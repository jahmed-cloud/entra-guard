import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import tasks  # noqa: E402
from app.ai_agent import _path_is_allowed  # noqa: E402

VALID_STATUSES = {"passed", "failed", "error", "skipped", "manual", "warning", "info", "not_applicable"}


class EmptyGraph:
    """A tenant with nothing in it — every list is empty, every object {}."""
    def __init__(self):
        self.calls = []

    def get(self, path, headers=None, **kwargs):
        self.calls.append((path, headers))
        return {"value": []}

    def get_all_pages(self, path, headers=None):
        self.calls.append((path, headers))
        return []

    def __getattr__(self, name):
        if name.startswith("get_"):
            return lambda *a, **k: []
        raise AttributeError(name)


def _run_all(graph):
    results = []
    for fn in tasks.ALL_CHECKS:
        try:
            results.append((fn, fn(graph, {})))
        except Exception as e:  # the runner tolerates this; record it
            results.append((fn, e))
    return results


def test_registry_has_no_duplicate_functions():
    names = Counter(fn.__name__ for fn in tasks.ALL_CHECKS)
    assert [n for n, c in names.items() if c > 1] == []


def test_check_ids_are_unique_and_results_well_formed():
    ids = []
    for fn, res in _run_all(EmptyGraph()):
        if isinstance(res, Exception):
            continue
        assert isinstance(res, dict), fn.__name__
        assert res.get("check_id"), fn.__name__
        assert res.get("status") in VALID_STATUSES, (fn.__name__, res.get("status"))
        float(res.get("score", 0))  # must be numeric for the INSERT
        # Every shipped check must already satisfy normalize_result, so the
        # coercion there is a safety net and never changes a real result.
        clean = tasks.normalize_result(res, fn.__name__)
        assert clean is not None, fn.__name__
        for key in ("status", "severity", "score", "affected_resources", "evidence"):
            assert clean[key] == res[key], (fn.__name__, key, res[key])
        ids.append(res["check_id"])
    dupes = [i for i, c in Counter(ids).items() if c > 1]
    assert dupes == [], dupes


def test_lockout_check_can_fail():
    class G(EmptyGraph):
        def get(self, path, headers=None, **kwargs):
            assert path.startswith("/auditLogs/signIns") and "50053" in path
            return {"value": [{"userPrincipalName": "a@x.com"}] * 3 + [{"userPrincipalName": "b@x.com"}]}
    res = tasks.check_users_lockout_count(G(), {})
    assert res["status"] == "failed"
    assert res["affected_resources"] == [{"upn": "a@x.com", "lockout_events": 3}]


def test_empty_groups_check_sends_consistency_level():
    class G(EmptyGraph):
        def get_all_pages(self, path, headers=None):
            assert headers == {"ConsistencyLevel": "eventual"}
            return [{"id": "g1", "displayName": "Empty"}, {"id": "g2", "displayName": "Full"}]

        def get(self, path, headers=None, **kwargs):
            assert headers == {"ConsistencyLevel": "eventual"}
            return 0 if "g1" in path else 4
    res = tasks.check_delete_empty_groups(G(), {})
    assert res["status"] == "failed"
    assert res["affected_resources"] == [{"group": "Empty", "id": "g1"}]


def test_graph_client_merges_headers_without_dropping_auth():
    seen = {}

    class FakeHttp:
        def get(self, url, headers=None, **kwargs):
            seen.update(headers)
            return type("R", (), {"status_code": 200, "headers": {}, "raise_for_status": lambda s: None,
                                  "json": lambda s: {"value": []}})()

    g = tasks.GraphClient.__new__(tasks.GraphClient)
    g._token, g._http = "tok", FakeHttp()
    g._ensure_token = lambda: None
    g.get("/groups", headers={"ConsistencyLevel": "eventual"})
    assert seen == {"ConsistencyLevel": "eventual", "Authorization": "Bearer tok"}


def test_agent_path_allowlist():
    assert _path_is_allowed("/policies/identitySecurityDefaultsEnforcementPolicy")
    assert _path_is_allowed("/users?$select=id,userPrincipalName")
    assert _path_is_allowed("/groups/abc/members")
    for bad in ("/users/abc/messages", "/users/abc/mailFolders/inbox", "/users/abc/drive/root",
                "/groups/abc/conversations", "/policies/../users/x/messages", "/policies/../me",
                "https://evil.example/x", "/me", "/users/abc/calendar/events", ""):
        assert not _path_is_allowed(bad), bad


# ── Result validation ─────────────────────────────────────────────────────────

GOOD = {"check_id": "AZURE-X-001", "severity": "High", "status": "failed", "score": 7.5,
        "affected_resources": [{"upn": "a@x.com"}], "evidence": {"n": 1},
        "risk_description": "r", "remediation_steps": "s", "estimated_effort": "Moderate"}


def test_normalize_keeps_a_valid_result_unchanged():
    assert tasks.normalize_result(dict(GOOD), "check_x") == GOOD


def test_normalize_drops_results_it_cannot_identify():
    assert tasks.normalize_result(("AZURE-X-001", "failed"), "check_x") is None
    assert tasks.normalize_result(None, "check_x") is None
    assert tasks.normalize_result({**GOOD, "check_id": ""}, "check_x") is None
    assert tasks.normalize_result({**GOOD, "check_id": 42}, "check_x") is None
    assert tasks.normalize_result({k: v for k, v in GOOD.items() if k != "check_id"}, "check_x") is None


def test_normalize_coerces_bad_values():
    out = tasks.normalize_result({**GOOD, "status": "pass", "severity": "critical", "score": None,
                                  "affected_resources": "everyone", "evidence": ["x"],
                                  "estimated_effort": "weeks", "risk_description": None}, "check_x")
    assert out["status"] == "error"          # unknown status is never counted as passed
    assert out["severity"] == "Medium"
    assert out["score"] == 0.0
    assert out["affected_resources"] == [] and out["evidence"] == {}
    assert out["estimated_effort"] == "Low" and out["risk_description"] == ""


def test_normalize_clamps_score_to_the_column_range():
    for raw, expected in ((99, 10.0), (-3, 0.0), (float("nan"), 0.0), (float("inf"), 0.0), ("7.26", 7.3), (True, 0.0)):
        assert tasks.normalize_result({**GOOD, "score": raw}, "check_x")["score"] == expected, raw


def test_normalize_caps_affected_resources_but_keeps_the_total():
    out = tasks.normalize_result({**GOOD, "affected_resources": [{"i": i} for i in range(1200)]}, "check_x")
    assert len(out["affected_resources"]) == tasks.MAX_AFFECTED_RESOURCES
    assert out["evidence"]["affected_total"] == 1200 and out["evidence"]["affected_truncated"] is True


def test_normalize_truncates_long_text():
    out = tasks.normalize_result({**GOOD, "risk_description": "x" * 10_000}, "check_x")
    assert len(out["risk_description"]) == tasks.MAX_TEXT_LENGTH


# ── Graph client hardening ────────────────────────────────────────────────────

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _client(responses):
    """GraphClient whose HTTP layer replays `responses` and records URLs."""
    calls = []

    class FakeHttp:
        def get(self, url, headers=None, **kwargs):
            calls.append(url)
            status, body, hdrs = responses[min(len(calls), len(responses)) - 1]

            def raise_for_status(self_):
                if status >= 400:
                    raise RuntimeError(f"HTTP {status}")
            return type("R", (), {"status_code": status, "headers": hdrs,
                                  "raise_for_status": raise_for_status, "json": lambda s: body})()

    g = tasks.GraphClient.__new__(tasks.GraphClient)
    g._token, g._http = "tok", FakeHttp()
    g._ensure_token = lambda: None
    return g, calls


def test_graph_client_validates_tenant_and_client_ids():
    tasks.GraphClient(TENANT, CLIENT, "secret")
    tasks.GraphClient("contoso.onmicrosoft.com", CLIENT, "secret")
    for tenant, client in (("contoso.com/../evil", CLIENT), ("", CLIENT), (TENANT, "not-a-guid"), (TENANT, None)):
        try:
            tasks.GraphClient(tenant, client, "secret")
        except ValueError:
            continue
        raise AssertionError(f"accepted tenant={tenant!r} client={client!r}")


def test_graph_token_is_never_sent_off_graph():
    g, calls = _client([(200, {"value": []}, {})])
    for url in ("https://evil.example/v1.0/users", "http://graph.microsoft.com/v1.0/users",
                "https://graph.microsoft.com.evil.example/v1.0/users"):
        try:
            g.get(url)
        except ValueError:
            continue
        raise AssertionError(f"followed {url}")
    assert calls == []
    g.get("https://graph.microsoft.com/v1.0/users?$skiptoken=abc")  # a real nextLink still works
    assert len(calls) == 1


def test_graph_client_retries_when_throttled(monkeypatch):
    slept = []
    monkeypatch.setattr(tasks.time, "sleep", slept.append)
    g, calls = _client([(429, {}, {"Retry-After": "7"}), (503, {}, {}), (200, {"value": [1]}, {})])
    assert g.get("/users") == {"value": [1]}
    assert len(calls) == 3
    assert slept == [7.0, 2]  # honours Retry-After, otherwise backs off


def test_graph_client_gives_up_after_max_retries(monkeypatch):
    monkeypatch.setattr(tasks.time, "sleep", lambda s: None)
    g, calls = _client([(429, {}, {"Retry-After": "9999"})])
    try:
        g.get("/users")
    except RuntimeError as e:
        assert "429" in str(e)
    else:
        raise AssertionError("expected the 429 to surface")
    assert len(calls) == tasks.GraphClient.MAX_RETRIES + 1
    assert g._retry_delay(type("R", (), {"headers": {"Retry-After": "9999"}})(), 0) == tasks.GraphClient.MAX_RETRY_DELAY


def test_graph_client_does_not_retry_permission_errors(monkeypatch):
    monkeypatch.setattr(tasks.time, "sleep", lambda s: None)
    g, calls = _client([(403, {}, {})])
    try:
        g.get("/users")
    except RuntimeError:
        pass
    assert len(calls) == 1
