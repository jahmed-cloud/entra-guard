import os
import secrets
import hashlib
import json
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from app.auth.router import require_auth, create_token

log = logging.getLogger(__name__)
router = APIRouter()

# Simple JSON-file based user store
# For production, use a proper DB table — this is sufficient for small teams
USERS_FILE = os.getenv("USERS_FILE", "/app/data/users.json")

class UserCreate(BaseModel):
    username: str
    password: str
    name: str
    role: str = "viewer"  # admin | viewer

class UserUpdate(BaseModel):
    name: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"{salt}:{h}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        return secrets.compare_digest(
            hashlib.sha256(f"{salt}:{password}".encode()).hexdigest(), h
        )
    except Exception:
        return False

def load_users() -> dict:
    # Always include the local admin from env as a built-in user
    admin_user = os.getenv("LOCAL_ADMIN_USERNAME", "admin")
    users = {
        admin_user: {
            "username": admin_user,
            "name": "Local Administrator",
            "role": "admin",
            "active": True,
            "builtin": True,
            "created_at": "builtin",
        }
    }
    try:
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE) as f:
                stored = json.load(f)
                users.update(stored)
    except Exception as e:
        log.warning(f"Could not load users file: {e}")
    return users

def save_users(users: dict):
    # Never save the builtin admin to the file
    to_save = {k: v for k, v in users.items() if not v.get("builtin")}
    try:
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        with open(USERS_FILE, "w") as f:
            json.dump(to_save, f, indent=2)
    except Exception as e:
        log.error(f"Could not save users file: {e}")
        raise HTTPException(500, "Could not save user data")

def require_admin(user=Depends(require_auth)):
    if user.get("role") not in ["admin"] and user.get("auth_type") not in ["local", "msal"]:
        raise HTTPException(403, "Admin access required")
    return user

@router.get("/users")
async def list_users(user=Depends(require_admin)):
    users = load_users()
    return {"items": [
        {
            "username": u["username"],
            "name": u.get("name", u["username"]),
            "role": u.get("role", "viewer"),
            "active": u.get("active", True),
            "builtin": u.get("builtin", False),
            "created_at": u.get("created_at"),
        }
        for u in users.values()
    ]}

@router.post("/users")
async def create_user(req: UserCreate, user=Depends(require_admin)):
    users = load_users()
    if req.username in users:
        raise HTTPException(409, f"User '{req.username}' already exists")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if req.role not in ["admin", "viewer"]:
        raise HTTPException(400, "Role must be 'admin' or 'viewer'")

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
    log.info(f"User created: {req.username} by {user.get('sub')}")
    return {"username": req.username, "name": req.name, "role": req.role}

@router.put("/users/{username}")
async def update_user(username: str, req: UserUpdate, user=Depends(require_admin)):
    users = load_users()
    if username not in users:
        raise HTTPException(404, "User not found")
    u = users[username]
    if u.get("builtin") and req.role:
        raise HTTPException(400, "Cannot change role of built-in admin")

    if req.name is not None:
        u["name"] = req.name
    if req.password is not None:
        if len(req.password) < 8:
            raise HTTPException(400, "Password must be at least 8 characters")
        u["password_hash"] = hash_password(req.password)
    if req.role is not None and not u.get("builtin"):
        if req.role not in ["admin", "viewer"]:
            raise HTTPException(400, "Role must be 'admin' or 'viewer'")
        u["role"] = req.role
    if req.active is not None:
        u["active"] = req.active

    users[username] = u
    save_users(users)
    log.info(f"User updated: {username} by {user.get('sub')}")
    return {"username": username, "name": u["name"], "role": u["role"], "active": u["active"]}

@router.delete("/users/{username}")
async def delete_user(username: str, user=Depends(require_admin)):
    users = load_users()
    if username not in users:
        raise HTTPException(404, "User not found")
    if users[username].get("builtin"):
        raise HTTPException(400, "Cannot delete built-in admin user")
    if username == user.get("sub"):
        raise HTTPException(400, "Cannot delete your own account")
    del users[username]
    save_users(users)
    log.info(f"User deleted: {username} by {user.get('sub')}")
    return {"deleted": True}

# Login endpoint that checks the users file too
@router.post("/auth/login/extended")
async def extended_login(req: dict):
    """Login that checks both env admin and users file"""
    username = req.get("username", "")
    password = req.get("password", "")

    # Check env admin first
    env_admin = os.getenv("LOCAL_ADMIN_USERNAME", "admin")
    env_pass = os.getenv("LOCAL_ADMIN_PASSWORD", "")
    if secrets.compare_digest(username, env_admin) and secrets.compare_digest(password, env_pass) and env_pass:
        token = create_token({"sub": username, "name": "Local Administrator", "auth_type": "local", "role": "admin"})
        return {"access_token": token, "token_type": "bearer",
                "user": {"sub": username, "name": "Local Administrator", "auth_type": "local", "role": "admin"}}

    # Check users file
    users = load_users()
    if username in users:
        u = users[username]
        if not u.get("active", True):
            raise HTTPException(401, "Account is disabled")
        if u.get("builtin"):
            raise HTTPException(401, "Invalid credentials")
        pw_hash = u.get("password_hash", "")
        if pw_hash and verify_password(password, pw_hash):
            user_info = {"sub": username, "name": u.get("name", username),
                        "auth_type": "local", "role": u.get("role", "viewer")}
            token = create_token(user_info)
            return {"access_token": token, "token_type": "bearer", "user": user_info}

    raise HTTPException(401, "Invalid username or password")
