import hashlib
import json
import os

import pytest

from conftest import bearer


def test_extended_login_env_admin(client):
    r = client.post("/api/v1/auth/login/extended", json={"username": "admin", "password": "correct-horse-battery"})
    assert r.status_code == 200
    assert r.json()["user"]["role"] == "admin"


def test_login_non_ascii_password_is_401_not_500(client):
    for path in ("/api/v1/auth/login", "/api/v1/auth/login/extended"):
        r = client.post(path, json={"username": "admin", "password": "pässwörd"})
        assert r.status_code == 401, path


def test_extended_login_rejects_malformed_body(client):
    r = client.post("/api/v1/auth/login/extended", json={"username": ["admin"], "password": 1})
    assert r.status_code == 422


def test_rate_limit_keys_on_forwarded_ip_from_proxy(client):
    # TestClient's peer is "testclient" (not an IP) so X-Real-IP is ignored and
    # every request shares one bucket — the 6th attempt is throttled.
    for _ in range(5):
        client.post("/api/v1/auth/login/extended", json={"username": "admin", "password": "nope"})
    r = client.post("/api/v1/auth/login/extended", json={"username": "admin", "password": "nope"})
    assert r.status_code == 429


def test_client_ip_trusts_header_only_from_private_peer():
    from app.main import _client_ip

    class Req:
        def __init__(self, peer, header):
            self.client = type("C", (), {"host": peer})()
            self.headers = {"x-real-ip": header} if header else {}

    assert _client_ip(Req("172.18.0.5", "203.0.113.9")) == "203.0.113.9"
    assert _client_ip(Req("8.8.8.8", "203.0.113.9")) == "8.8.8.8"
    assert _client_ip(Req("172.18.0.5", "not-an-ip")) == "172.18.0.5"


def test_password_hash_is_pbkdf2_and_verifies():
    from app.routers.users import hash_password, verify_password, is_legacy_hash
    h = hash_password("s3cret-pass")
    assert h.startswith("pbkdf2_sha256$") and not is_legacy_hash(h)
    assert verify_password("s3cret-pass", h)
    assert not verify_password("wrong", h)


def test_legacy_hash_still_logs_in_and_is_upgraded(client):
    salt = "abcd"
    legacy = f"{salt}:{hashlib.sha256(f'{salt}:old-password'.encode()).hexdigest()}"
    with open(os.environ["USERS_FILE"], "w") as f:
        json.dump({"alice": {"username": "alice", "name": "Alice", "role": "viewer",
                             "password_hash": legacy, "active": True}}, f)
    r = client.post("/api/v1/auth/login/extended", json={"username": "alice", "password": "old-password"})
    assert r.status_code == 200
    with open(os.environ["USERS_FILE"]) as f:
        assert json.load(f)["alice"]["password_hash"].startswith("pbkdf2_sha256$")


def test_viewer_cannot_mutate(client):
    h = bearer(role="viewer")
    assert client.post("/api/v1/targets", json={"name": "x"}, headers=h).status_code == 403
    assert client.put("/api/v1/targets/abc", json={"name": "x"}, headers=h).status_code == 403
    assert client.delete("/api/v1/targets/abc", headers=h).status_code == 403
    assert client.post("/api/v1/assessments/run", json={}, headers=h).status_code == 403
    assert client.get("/api/v1/users", headers=h).status_code == 403


def test_target_update_rejects_unknown_fields(client):
    r = client.put("/api/v1/targets/abc", json={"id": "evil", "created_at": "x"}, headers=bearer())
    assert r.status_code == 400


def test_malformed_ids_are_404(client):
    assert client.put("/api/v1/targets/not-a-uuid", json={"name": "x"}, headers=bearer()).status_code == 404
    assert client.delete("/api/v1/targets/not-a-uuid", headers=bearer()).status_code == 404


def test_unauthenticated_request_is_401(client):
    assert client.get("/api/v1/targets").status_code == 401


def test_msal_login_sets_state_cookie(client):
    r = client.get("/api/v1/auth/msal/login", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert "eg_oauth_state" in r.cookies
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A3000" in r.headers["location"]


def test_msal_callback_rejects_missing_or_wrong_state(client):
    r = client.get("/api/v1/auth/callback?code=abc&state=forged", follow_redirects=False)
    assert "error=invalid_state" in r.headers["location"]
    client.cookies.set("eg_oauth_state", "expected")
    r = client.get("/api/v1/auth/callback?code=abc&state=forged", follow_redirects=False)
    assert "error=invalid_state" in r.headers["location"]


def test_msal_error_param_is_encoded(client):
    r = client.get("/api/v1/auth/callback?error=x%26next%3Devil", follow_redirects=False)
    assert r.headers["location"].endswith("error=x%26next%3Devil")


def test_msal_roles_come_from_store(client):
    from app.auth.router import _resolve_msal_role
    from app.routers.users import load_users, save_users
    assert _resolve_msal_role("Boss@Contoso.com", "Boss") == "admin"
    assert _resolve_msal_role("new@contoso.com", "New") == "viewer"
    users = load_users()
    assert users["msal:new@contoso.com"]["role"] == "viewer"
    users["msal:new@contoso.com"]["role"] = "admin"
    save_users(users)
    assert _resolve_msal_role("new@contoso.com", "New") == "admin"


def test_msal_users_cannot_get_local_passwords(client):
    from app.auth.router import _resolve_msal_role
    _resolve_msal_role("someone@contoso.com", "Someone")
    r = client.put("/api/v1/users/msal:someone@contoso.com", json={"password": "longenough1"}, headers=bearer())
    assert r.status_code == 400
    r = client.post("/api/v1/users", json={"username": "msal:x@y.com", "password": "longenough1", "name": "x"},
                    headers=bearer())
    assert r.status_code == 400


def test_health_does_not_derive_id_from_secret(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["instance_id"] != hashlib.sha256(os.environ["SECRET_KEY"].encode()).hexdigest()[:16]


def test_default_secret_key_refused_when_auth_enabled(monkeypatch):
    import importlib
    import app.auth.router as router_mod
    monkeypatch.setenv("SECRET_KEY", "CHANGE_ME_run_openssl_rand_hex_32")
    with pytest.raises(RuntimeError):
        importlib.reload(router_mod)
    monkeypatch.setenv("SECRET_KEY", "x" * 64)
    importlib.reload(router_mod)
