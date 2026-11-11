import json
import logging
import os

from conftest import bearer

LOGIN = "/api/v1/auth/login/extended"


def _store():
    from app.routers.users import load_users, save_users
    return load_users, save_users


# ── Response hardening ────────────────────────────────────────────────────────

def test_security_headers_on_api_responses(client):
    r = client.get("/api/v1/auth/config")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_rate_limited_response_also_has_security_headers(client):
    for _ in range(6):
        r = client.post(LOGIN, json={"username": "admin", "password": "nope"})
    assert r.status_code == 429
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["retry-after"] == "300"


def test_oversized_request_body_is_rejected(client):
    r = client.post(LOGIN, content=b"x" * (1024 * 1024 + 1), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_api_docs_are_off_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


# ── Sessions follow the user store ────────────────────────────────────────────

def test_disabled_user_loses_access_immediately(client):
    load_users, save_users = _store()
    h = bearer(role="viewer", sub="carol")
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200
    users = load_users()
    users["carol"]["active"] = False
    save_users(users)
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_deleted_user_loses_access_immediately(client):
    load_users, save_users = _store()
    h = bearer(role="admin", sub="dave")
    users = load_users()
    del users["dave"]
    save_users(users)
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_role_comes_from_store_not_token(client):
    load_users, save_users = _store()
    h = bearer(role="admin", sub="erin")  # token says admin
    assert client.get("/api/v1/users", headers=h).status_code == 200
    users = load_users()
    users["erin"]["role"] = "viewer"
    save_users(users)
    assert client.get("/api/v1/auth/me", headers=h).json()["role"] == "viewer"
    assert client.get("/api/v1/users", headers=h).status_code == 403


def test_token_for_unknown_account_is_rejected(client):
    from app.auth.router import create_token
    token = create_token({"sub": "ghost", "role": "admin", "auth_type": "local"})
    assert client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"}).status_code == 401


# ── Login ─────────────────────────────────────────────────────────────────────

def test_login_failures_are_indistinguishable(client):
    load_users, save_users = _store()
    admin = bearer()
    r = client.post("/api/v1/users", headers=admin,
                    json={"username": "frank", "password": "frank-is-not-here-42".replace("frank", "f"), "name": "Frank"})
    assert r.status_code == 200, r.text
    password = "f-is-not-here-42"
    users = load_users()
    users["frank"]["active"] = False
    save_users(users)

    disabled = client.post(LOGIN, json={"username": "frank", "password": password})
    wrong = client.post(LOGIN, json={"username": "frank", "password": "wrong-password-1"})
    unknown = client.post(LOGIN, json={"username": "nobody", "password": password})
    assert disabled.status_code == wrong.status_code == unknown.status_code == 401
    assert disabled.json() == wrong.json() == unknown.json()


def test_users_file_cannot_shadow_builtin_admin(client):
    from app.routers.users import hash_password, load_users
    with open(os.environ["USERS_FILE"], "w") as f:
        json.dump({"admin": {"username": "admin", "role": "admin", "active": True,
                             "password_hash": hash_password("planted-password-1")}}, f)
    assert load_users()["admin"]["builtin"] is True
    r = client.post(LOGIN, json={"username": "admin", "password": "planted-password-1"})
    assert r.status_code == 401


def test_failed_login_cannot_forge_log_lines(client, caplog):
    with caplog.at_level(logging.INFO, logger="entraguard.audit"):
        client.post(LOGIN, json={"username": "x\n2026-01-01 INFO entraguard.audit: action=login actor='admin'",
                                 "password": "whatever-1234"})
    lines = [r.getMessage() for r in caplog.records if r.name == "entraguard.audit"]
    assert len(lines) == 1 and "\n" not in lines[0]
    assert lines[0].startswith("action=login_failed")


# ── Rate limiter backends ─────────────────────────────────────────────────────

class _FakeRedis:
    def __init__(self, fail=False):
        self.counts, self.fail, self.ttl = {}, fail, None

    async def eval(self, script, numkeys, key, ttl):
        if self.fail:
            raise ConnectionError("redis down")
        self.counts[key] = self.counts.get(key, 0) + 1
        self.ttl = ttl
        return self.counts[key]


def test_rate_limit_counts_in_redis_when_available(client, monkeypatch):
    from app import main
    fake = _FakeRedis()
    monkeypatch.setattr(main, "_RATE_LIMIT_REDIS_URL", "redis://fake")
    monkeypatch.setattr(main, "_redis_client", fake)
    monkeypatch.setattr(main, "_redis_retry_at", 0.0)
    codes = [client.post(LOGIN, json={"username": "admin", "password": "nope"}).status_code for _ in range(6)]
    assert codes == [401] * 5 + [429]
    assert list(fake.counts.values()) == [6] and fake.ttl == 300
    assert main._login_attempts == {}  # the in-memory fallback was not used


def test_rate_limit_falls_back_to_memory_when_redis_is_down(client, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "_RATE_LIMIT_REDIS_URL", "redis://fake")
    monkeypatch.setattr(main, "_redis_client", _FakeRedis(fail=True))
    monkeypatch.setattr(main, "_redis_retry_at", 0.0)
    codes = [client.post(LOGIN, json={"username": "admin", "password": "nope"}).status_code for _ in range(6)]
    assert codes == [401] * 5 + [429]  # still enforced, never fails open


# ── User management ───────────────────────────────────────────────────────────

def test_password_policy(client):
    admin = bearer()
    def create(username, password):
        return client.post("/api/v1/users", headers=admin, json={"username": username, "password": password, "name": "N"})
    assert create("gina", "short-1").status_code == 400                 # under 12 characters
    assert create("gina", "x-GINA-x-12345").status_code == 400          # contains the username
    assert create("gina", "aaaaaaaaaaaaaa").status_code == 400          # one repeated character
    assert create("gina", "p" * 129).status_code == 422                 # over the hard cap
    assert create("gina", "tangerine-otter-91").status_code == 200


def test_user_input_validation(client):
    admin = bearer()
    base = {"password": "tangerine-otter-91", "name": "N"}
    for bad in ("ab", "has space", "semi;colon", "../etc", "x" * 65, "<script>"):
        r = client.post("/api/v1/users", headers=admin, json={**base, "username": bad})
        assert r.status_code == 422, bad
    assert client.post("/api/v1/users", headers=admin, json={**base, "username": "henry", "role": "owner"}).status_code == 422
    assert client.post("/api/v1/users", headers=admin, json={**base, "username": "henry", "builtin": True}).status_code == 422
    assert client.post("/api/v1/users", headers=admin, json={**base, "username": "henry", "name": "   "}).status_code == 422


def test_admin_cannot_lock_themselves_out(client):
    h = bearer(role="admin", sub="ivan")
    assert client.put("/api/v1/users/ivan", headers=h, json={"role": "viewer"}).status_code == 400
    assert client.put("/api/v1/users/ivan", headers=h, json={"active": False}).status_code == 400
    assert client.delete("/api/v1/users/ivan", headers=h).status_code == 400
    assert client.put("/api/v1/users/ivan", headers=h, json={"name": "Ivan I."}).status_code == 200


def test_builtin_admin_cannot_be_edited(client):
    assert client.put("/api/v1/users/admin", headers=bearer(), json={"active": False}).status_code == 400


def test_users_file_is_written_atomically(client):
    client.post("/api/v1/users", headers=bearer(),
                json={"username": "judy", "password": "tangerine-otter-91", "name": "Judy"})
    path = os.environ["USERS_FILE"]
    assert "judy" in json.load(open(path))
    assert not os.path.exists(path + ".tmp")
