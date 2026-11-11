import os
import secrets
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from app.auth.router import AUTH_ENABLED, require_admin, create_token, constant_time_equals
from app.auth.models import LoginRequest
from app.core.audit import audit

log = logging.getLogger(__name__)
router = APIRouter()

# Simple JSON-file based user store
# For production, use a proper DB table — this is sufficient for small teams
USERS_FILE = os.getenv("USERS_FILE", "/app/data/users.json")

# Applies to passwords set from now on; existing hashes keep working.
PASSWORD_MIN_LENGTH = max(8, int(os.getenv("PASSWORD_MIN_LENGTH", "12")))
PASSWORD_MAX_LENGTH = 128  # bounds the PBKDF2 input

Username = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{2,63}$")]
DisplayName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
Role = Literal["admin", "viewer"]

class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: Username
    password: str = Field(max_length=PASSWORD_MAX_LENGTH)
    name: DisplayName
    role: Role = "viewer"

class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[DisplayName] = None
    password: Optional[str] = Field(default=None, max_length=PASSWORD_MAX_LENGTH)
    role: Optional[Role] = None
    active: Optional[bool] = None

def validate_password(password: str, username: str) -> None:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise HTTPException(400, f"Password must be at least {PASSWORD_MIN_LENGTH} characters")
    if username.lower() in password.lower():
        raise HTTPException(400, "Password must not contain the username")
    if len(set(password)) < 5:
        raise HTTPException(400, "Password is too repetitive")

# PBKDF2-HMAC-SHA256 — stdlib only, so no new dependency. Hashes created
# before this change were a single salted SHA-256 ("salt:hex"), which is
# GPU-crackable; verify_password still accepts them and extended_login
# transparently re-hashes on the next successful sign-in.
_PBKDF2_ITERATIONS = 600_000

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS).hex()
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${h}"

def is_legacy_hash(stored: str) -> bool:
    return not stored.startswith("pbkdf2_sha256$")

def verify_password(password: str, stored: str) -> bool:
    try:
        if not is_legacy_hash(stored):
            _, iterations, salt, h = stored.split("$", 3)
            candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations)).hex()
        else:
            salt, h = stored.split(":", 1)
            candidate = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
        return secrets.compare_digest(candidate, h)
    except Exception:
        return False

_dummy_hash = None

def _burn_password_check(password: str) -> None:
    """Spends the same time as a real password check. Without it, a login
    for an unknown username returned instantly while a known one took a full
    PBKDF2 round, which let an attacker tell which usernames exist."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_hex(16))
    verify_password(password, _dummy_hash)

def msal_store_key(upn: str) -> str:
    # Prefixed so an MSAL identity can never collide with a local username.
    return f"msal:{upn.lower()}"

def load_users() -> dict:
    users = {}
    try:
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE) as f:
                stored = json.load(f)
            if isinstance(stored, dict):
                users = {k: v for k, v in stored.items() if isinstance(v, dict)}
            else:
                log.warning("Users file is not a JSON object; ignoring it")
    except Exception as e:
        log.warning(f"Could not load users file: {e}")
    # The local admin from env is always present and is applied last, so an
    # entry in the file can never replace or shadow it.
    admin_user = os.getenv("LOCAL_ADMIN_USERNAME", "admin")
    users[admin_user] = {
        "username": admin_user,
        "name": "Local Administrator",
        "role": "admin",
        "active": True,
        "builtin": True,
        "created_at": "builtin",
    }
    return users

def save_users(users: dict):
    # Never save the builtin admin to the file
    to_save = {k: v for k, v in users.items() if not v.get("builtin")}
    tmp = f"{USERS_FILE}.tmp"
    try:
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        # Write to a temp file and rename, so a crash mid-write can't leave a
        # truncated users.json (which would silently drop every account).
        # 0600: the file holds password hashes.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(to_save, f, indent=2)
        os.replace(tmp, USERS_FILE)
    except Exception as e:
        log.error(f"Could not save users file: {e}")
        raise HTTPException(500, "Could not save user data")

def _is_self(username: str, user: dict) -> bool:
    if username == user.get("sub"):
        return True
    return bool(user.get("email")) and username == msal_store_key(user["email"])

@router.get("/users")
async def list_users(user=Depends(require_admin)):
    users = load_users()
    return {"items": [
        {
            "username": u.get("username", key),
            "name": u.get("name", key),
            "role": u.get("role", "viewer"),
            "active": u.get("active", True),
            "builtin": u.get("builtin", False),
            "created_at": u.get("created_at"),
        }
        for key, u in users.items()
    ]}

@router.post("/users")
async def create_user(req: UserCreate, user=Depends(require_admin)):
    users = load_users()
    if req.username in users:
        raise HTTPException(409, f"User '{req.username}' already exists")
    validate_password(req.password, req.username)

    users[req.username] = {
        "username": req.username,
        "name": req.name,
        "role": req.role,
        "password_hash": hash_password(req.password),
        "active": True,
        "builtin": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    save_users(users)
    audit("user_created", user, username=req.username, role=req.role)
    return {"username": req.username, "name": req.name, "role": req.role}

@router.put("/users/{username}")
async def update_user(username: str, req: UserUpdate, user=Depends(require_admin)):
    users = load_users()
    if username not in users:
        raise HTTPException(404, "User not found")
    u = users[username]
    if u.get("builtin"):
        # It is never written to the users file, so an edit would look like
        # it worked and then vanish.
        raise HTTPException(400, "The built-in admin is configured through LOCAL_ADMIN_USERNAME / LOCAL_ADMIN_PASSWORD, not here")
    if _is_self(username, user) and (req.active is False or (req.role is not None and req.role != u.get("role"))):
        raise HTTPException(400, "You can't disable your own account or change your own role")

    changed = []
    if req.name is not None:
        u["name"] = req.name
        changed.append("name")
    if req.password is not None:
        if u.get("auth_type") == "msal":
            raise HTTPException(400, "Microsoft sign-in accounts don't have a local password")
        validate_password(req.password, username)
        u["password_hash"] = hash_password(req.password)
        changed.append("password")
    if req.role is not None:
        u["role"] = req.role
        changed.append(f"role={req.role}")
    if req.active is not None:
        u["active"] = req.active
        changed.append(f"active={req.active}")

    users[username] = u
    save_users(users)
    audit("user_updated", user, username=username, changed=",".join(changed) or "nothing")
    return {"username": username, "name": u.get("name", username), "role": u.get("role", "viewer"),
            "active": u.get("active", True)}

@router.delete("/users/{username}")
async def delete_user(username: str, user=Depends(require_admin)):
    users = load_users()
    if username not in users:
        raise HTTPException(404, "User not found")
    if users[username].get("builtin"):
        raise HTTPException(400, "Cannot delete built-in admin user")
    if _is_self(username, user):
        raise HTTPException(400, "Cannot delete your own account")
    del users[username]
    save_users(users)
    audit("user_deleted", user, username=username)
    return {"deleted": True}

# Login endpoint that checks the users file too
@router.post("/auth/login/extended")
async def extended_login(req: LoginRequest):
    """Login that checks both env admin and users file"""
    if not AUTH_ENABLED:
        raise HTTPException(400, "Authentication is not enabled")
    username = req.username.strip()
    password = req.password

    # Check env admin first
    env_admin = os.getenv("LOCAL_ADMIN_USERNAME", "admin")
    env_pass = os.getenv("LOCAL_ADMIN_PASSWORD", "")
    if env_pass and constant_time_equals(username, env_admin) and constant_time_equals(password, env_pass):
        user_info = {"sub": username, "name": "Local Administrator", "auth_type": "local", "role": "admin"}
        audit("login", user_info, method="local")
        return {"access_token": create_token(user_info), "token_type": "bearer", "user": user_info}

    # Check users file. Every failure path below costs one password check and
    # returns the same message, so a caller can't tell an unknown username
    # from a wrong password or a disabled account.
    users = load_users()
    u = users.get(username) or {}
    pw_hash = "" if u.get("builtin") else u.get("password_hash", "")
    if not pw_hash:
        _burn_password_check(password)
    elif verify_password(password, pw_hash) and u.get("active", True):
        if is_legacy_hash(pw_hash):
            u["password_hash"] = hash_password(password)
            save_users(users)
            log.info(f"Upgraded legacy password hash for {username!r}")
        user_info = {"sub": username, "name": u.get("name", username),
                    "auth_type": "local", "role": u.get("role", "viewer")}
        audit("login", user_info, method="local")
        return {"access_token": create_token(user_info), "token_type": "bearer", "user": user_info}

    audit("login_failed", username, method="local")
    raise HTTPException(401, "Invalid username or password")
