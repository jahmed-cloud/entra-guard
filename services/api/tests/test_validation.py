import uuid

import pytest

from conftest import FakeSession, bearer, use_db

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


# ── Target config ─────────────────────────────────────────────────────────────

def test_target_config_accepts_guid_and_domain_tenants():
    from app.routers.targets import validate_target_config
    validate_target_config({"tenant_id": TENANT, "client_id": CLIENT, "break_glass_group_id": CLIENT})
    validate_target_config({"tenant_id": "contoso.onmicrosoft.com"})
    validate_target_config({})


@pytest.mark.parametrize("config", [
    {"tenant_id": "contoso.com/../evil"},        # would end up in the Microsoft login URL
    {"tenant_id": "not a tenant"},
    {"tenant_id": 12345},
    {"client_id": "not-a-guid"},
    {"break_glass_group_id": "group name"},
    {"client_secret": "s3cr3t"},                 # config is readable by every signed-in user
    {"api_key": "abc"},
    {"Bad-Key": "x"},
    {"notes": "x" * 257},
    {"nested": {"a": 1}},
    {f"k{i}": i for i in range(21)},
])
def test_target_config_rejects_bad_input(config):
    from app.routers.targets import validate_target_config
    with pytest.raises(ValueError):
        validate_target_config(config)


def test_create_target_validates_before_touching_the_database(client):
    admin = bearer()
    ok = {"name": "Prod", "config": {"tenant_id": TENANT, "client_id": CLIENT}}
    bad_bodies = [
        {**ok, "config": {"client_secret": "s3cr3t"}},
        {**ok, "name": ""},
        {**ok, "name": "x" * 101},
        {**ok, "type": "aws_account"},
        {**ok, "credential_ref": "file:///etc/passwd"},
        {**ok, "id": str(uuid.uuid4())},
    ]
    for body in bad_bodies:
        assert client.post("/api/v1/targets", headers=admin, json=body).status_code == 422, body

    session = FakeSession()
    use_db(session)
    r = client.post("/api/v1/targets", headers=admin, json=ok)
    assert r.status_code == 200, r.text
    assert session.added[0].config == ok["config"]


# ── Query parameters ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("query", [
    "page=0", "page_size=0", "page_size=5000", "status=bogus", "status=failed'--",
    "target_id=abc", "scan_run_id=1%20OR%201=1",
])
def test_findings_rejects_bad_query(client, query):
    assert client.get(f"/api/v1/findings?{query}", headers=bearer(role="viewer")).status_code == 422


def test_impact_rejects_bad_query(client):
    h = bearer(role="viewer")
    assert client.get("/api/v1/findings/impact?top=0", headers=h).status_code == 422
    assert client.get("/api/v1/findings/impact?top=500", headers=h).status_code == 422


# ── Starting scans ────────────────────────────────────────────────────────────

class _FakeCelery:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def send_task(self, name, args):
        if self.fail:
            raise RuntimeError("redis://redis:6379/1 connection refused (internal detail)")
        self.sent.append((name, args))


def _target():
    from app.models.models import Target
    return Target(id=uuid.uuid4(), name="Prod", is_active=True)


def test_run_rejects_bad_body(client):
    admin = bearer()
    assert client.post("/api/v1/assessments/run", headers=admin, json={"target_id": "abc"}).status_code == 422
    assert client.post("/api/v1/assessments/run", headers=admin, json={"force": True}).status_code == 422


def test_run_queues_a_scan(client, monkeypatch):
    from app.routers import assessments
    celery = _FakeCelery()
    monkeypatch.setattr(assessments, "get_celery", lambda: celery)
    target = _target()
    use_db(FakeSession(target, None))  # target lookup, then "no scan in progress"
    r = client.post("/api/v1/assessments/run", headers=bearer(), json={"target_id": str(target.id)})
    assert r.status_code == 200, r.text
    assert celery.sent == [("app.tasks.run_assessment_task", [r.json()["id"], str(target.id)])]


def test_run_refuses_a_second_scan_for_the_same_target(client, monkeypatch):
    from app.routers import assessments
    celery = _FakeCelery()
    monkeypatch.setattr(assessments, "get_celery", lambda: celery)
    use_db(FakeSession(_target(), uuid.uuid4()))  # a pending/running run exists
    r = client.post("/api/v1/assessments/run", headers=bearer(), json={})
    assert r.status_code == 409
    assert celery.sent == []


def test_queue_failure_does_not_leak_internals(client, monkeypatch):
    from app.routers import assessments
    monkeypatch.setattr(assessments, "get_celery", lambda: _FakeCelery(fail=True))
    session = FakeSession(_target(), None)
    use_db(session)
    r = client.post("/api/v1/assessments/run", headers=bearer(), json={})
    assert r.status_code == 503
    assert "redis://" not in r.text and "internal detail" not in r.text
    assert session.added[0].status == "failed"  # the run is not left pending
