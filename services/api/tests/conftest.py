import os
import sys
import tempfile

# Config is read at import time, so it must be in place before `app` loads.
_tmp = tempfile.mkdtemp(prefix="entraguard-test-")
os.environ.update({
    "AUTH_ENABLED": "true",
    "SECRET_KEY": "x" * 64,
    "LOCAL_ADMIN_USERNAME": "admin",
    "LOCAL_ADMIN_PASSWORD": "correct-horse-battery",
    "USERS_FILE": os.path.join(_tmp, "users.json"),
    "INSTANCE_ID_FILE": os.path.join(_tmp, "instance_id"),
    "MSAL_ADMIN_USERS": "boss@contoso.com",
    "AZURE_TENANT_ID": "tenant",
    "AZURE_CLIENT_ID": "client",
    "TELEMETRY_ENABLED": "false",
    # No Redis in unit tests: the login limiter uses its in-memory fallback.
    "LOGIN_RATE_LIMIT_REDIS_URL": "",
})
os.environ.pop("ENABLE_API_DOCS", None)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from app import main
    main._login_attempts.clear()
    main.app.dependency_overrides.clear()
    if os.path.exists(os.environ["USERS_FILE"]):
        os.remove(os.environ["USERS_FILE"])
    # Not used as a context manager, so lifespan (DB create_all) doesn't run.
    return TestClient(main.app)


def bearer(role="admin", sub=None):
    """Auth header for a real account. Every request re-checks the account
    against the user store, so a token for a user that isn't in it is
    rejected: the default admin is the built-in one, anyone else is written
    to the store first. Call after the `client` fixture (it resets the store)."""
    from app.auth.router import create_token
    from app.routers.users import load_users, save_users
    if sub is None and role == "admin":
        sub = "admin"
    else:
        sub = sub or "viewer1"
        users = load_users()
        users[sub] = {"username": sub, "name": sub, "role": role, "active": True}
        save_users(users)
    return {"Authorization": f"Bearer {create_token({'sub': sub, 'role': role, 'auth_type': 'local'})}"}


class FakeResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.value or []


class FakeSession:
    """Stands in for the async DB session: each execute() returns the next
    queued value. Lets endpoint logic be tested without Postgres."""
    def __init__(self, *results):
        self.results = list(results)
        self.added = []

    async def execute(self, query):
        return FakeResult(self.results.pop(0))

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass


def use_db(session):
    from app import main
    from app.core.database import get_db
    main.app.dependency_overrides[get_db] = lambda: session
