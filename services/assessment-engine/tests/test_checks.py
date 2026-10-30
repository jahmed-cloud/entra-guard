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
            return type("R", (), {"raise_for_status": lambda s: None, "json": lambda s: {"value": []}})()

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
