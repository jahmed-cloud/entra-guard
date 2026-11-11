"""End-to-end smoke test against a running EntraGuard stack (see docs/RELEASING.md).

Usage: python scripts/smoke_test.py <ui-base-url> <env-file>
  e.g. python scripts/smoke_test.py http://localhost:3000 .env

Needs AUTH_ENABLED=true and LOCAL_ADMIN_PASSWORD in the env file. It creates and
disables a user called "smoke-viewer", queues one scan, and finishes by tripping
the login rate limit, so this client IP cannot log in again for the limit window.
Run it against a test stack, not production. Standard library only.
"""
import json
import sys
import urllib.error
import urllib.request

BASE, ENV = sys.argv[1].rstrip("/"), sys.argv[2]
ADMIN_PW = next(l.split("=", 1)[1].strip() for l in open(ENV) if l.startswith("LOCAL_ADMIN_PASSWORD="))
results = []


def call(method, path, body=None, token=None, headers=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode()


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


def login(user, pw):
    status, _, body = call("POST", "/api/v1/auth/login/extended", {"username": user, "password": pw})
    return status, (json.loads(body).get("access_token") if status == 200 else None)


# Dashboard headers
status, h, _ = call("GET", "/")
check("dashboard loads", status == 200)
csp = h.get("content-security-policy", "")
check("dashboard CSP restricts scripts to self", "script-src 'self'" in csp and "frame-ancestors 'none'" in csp, csp)
check("dashboard X-Frame-Options", h.get("x-frame-options") == "DENY")
check("nginx version hidden", "/" not in h.get("server", ""), h.get("server"))

# API headers, auth
status, h, _ = call("GET", "/api/v1/auth/config")
check("api no-store + nosniff", h.get("cache-control") == "no-store" and h.get("x-content-type-options") == "nosniff", str(h))
check("api security headers not duplicated by nginx", "," not in h.get("x-frame-options", ""), h.get("x-frame-options"))
check("unauthenticated request is 401", call("GET", "/api/v1/targets")[0] == 401)
check("api docs not exposed", call("GET", "/api/v1/../docs")[0] in (400, 404))

status, admin = login("admin", ADMIN_PW)
check("admin login", status == 200)

# Validation
check("bad target config rejected (secret)", call("POST", "/api/v1/targets", {"name": "x", "config": {"client_secret": "s"}}, admin)[0] == 422)
check("bad tenant id rejected", call("POST", "/api/v1/targets", {"name": "x", "config": {"tenant_id": "a/../b"}}, admin)[0] == 422)
check("bad findings query rejected", call("GET", "/api/v1/findings?status=bogus", token=admin)[0] == 422)
check("oversized body rejected", call("POST", "/api/v1/targets", {"name": "x" * (1024 * 1024 + 10)}, admin)[0] == 413)

# Users, policy, live session re-check
check("weak password rejected", call("POST", "/api/v1/users", {"username": "smoke-viewer", "password": "short", "name": "V"}, admin)[0] == 400)
pw = "tangerine-otter-91"
check("user created", call("POST", "/api/v1/users", {"username": "smoke-viewer", "password": pw, "name": "V"}, admin)[0] == 200)
status, viewer = login("smoke-viewer", pw)
check("viewer login", status == 200)
check("viewer can read findings", call("GET", "/api/v1/findings", token=viewer)[0] == 200)
check("viewer cannot start scan", call("POST", "/api/v1/assessments/run", {}, viewer)[0] == 403)
check("viewer cannot list users", call("GET", "/api/v1/users", token=viewer)[0] == 403)
check("promote viewer", call("PUT", "/api/v1/users/smoke-viewer", {"role": "admin"}, admin)[0] == 200)
check("promotion applies to existing token", call("GET", "/api/v1/users", token=viewer)[0] == 200)
check("disable user", call("PUT", "/api/v1/users/smoke-viewer", {"active": False}, admin)[0] == 200)
check("disabled user's token is rejected at once", call("GET", "/api/v1/findings", token=viewer)[0] == 401)

# Scans
status, _, body = call("POST", "/api/v1/assessments/run", {}, admin)
check("scan queued", status == 200, body)
status2, _, body2 = call("POST", "/api/v1/assessments/run", {}, admin)
check("second scan while one is pending/running is 409 (or the first already finished)", status2 in (409, 200), body2)

# Impact endpoint
status, _, body = call("GET", "/api/v1/findings/impact", token=admin)
check("impact endpoint responds", status == 200 and "weighted_score" in body, body[:200])

# Rate limit last (it locks this IP out of logins for the window)
codes = [login("admin", "wrong-password-xx")[0] for _ in range(8)]
check("login rate limit holds across both API workers", 429 in codes and codes.count(401) <= 5, str(codes))

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
