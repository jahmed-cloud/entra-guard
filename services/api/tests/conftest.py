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
})
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from app import main
    main._login_attempts.clear()
    if os.path.exists(os.environ["USERS_FILE"]):
        os.remove(os.environ["USERS_FILE"])
    # Not used as a context manager, so lifespan (DB create_all) doesn't run.
    return TestClient(main.app)


def bearer(role="admin", sub="tester"):
    from app.auth.router import create_token
    return {"Authorization": f"Bearer {create_token({'sub': sub, 'role': role, 'auth_type': 'local'})}"}
