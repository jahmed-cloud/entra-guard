import os, jwt, httpx, secrets, logging
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, quote
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from app.auth.models import LoginRequest, TokenResponse

log = logging.getLogger(__name__)
router = APIRouter()

AUTH_ENABLED       = os.getenv("AUTH_ENABLED", "false").lower() == "true"
SECRET_KEY         = os.getenv("SECRET_KEY", "changeme")

# SECURITY: every JWT is HS256-signed with SECRET_KEY. With the shipped
# default ("changeme") anyone can mint an admin token offline, so refuse to
# start rather than run "authenticated" with a publicly known signing key.
if AUTH_ENABLED and (SECRET_KEY.lower().startswith("change") or len(SECRET_KEY) < 32):
    raise RuntimeError(
        "AUTH_ENABLED=true requires SECRET_KEY to be set to a random value of at "
        "least 32 characters (e.g. `openssl rand -hex 32`)."
    )
JWT_EXPIRE_HOURS   = int(os.getenv("JWT_EXPIRE_HOURS", "8"))
LOCAL_ADMIN_USER   = os.getenv("LOCAL_ADMIN_USERNAME", "admin")
LOCAL_ADMIN_PASS   = os.getenv("LOCAL_ADMIN_PASSWORD", "")
AZURE_TENANT_ID    = os.getenv("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID    = os.getenv("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET= os.getenv("AZURE_CLIENT_SECRET", "")
APP_BASE_URL       = os.getenv("APP_BASE_URL", "http://localhost:3000")

MSAL_REDIRECT_URI  = f"{APP_BASE_URL}/api/v1/auth/callback"
MSAL_AUTH_URL      = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/authorize"
MSAL_TOKEN_URL     = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"
MSAL_SCOPES        = "openid profile email User.Read"
# Comma-separated UPNs that get role=admin on Microsoft sign-in. Every other
# MSAL user starts as viewer and can be promoted from the Users page.
MSAL_ADMIN_USERS   = {u.strip().lower() for u in os.getenv("MSAL_ADMIN_USERS", "").split(",") if u.strip()}
MSAL_STATE_COOKIE  = "eg_oauth_state"


def constant_time_equals(a: str, b: str) -> bool:
    # compare_digest raises TypeError on non-ASCII str, which turned any
    # login with e.g. "é" in the password into a 500 — compare bytes instead.
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def create_token(payload: dict, expires_hours: int = JWT_EXPIRE_HOURS) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
    return jwt.encode({**payload, "exp": exp, "iat": datetime.now(timezone.utc)},
                      SECRET_KEY, algorithm="HS256")


def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


def get_token_from_request(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    token = request.cookies.get("eg_token")
    if token:
        return token
    raise HTTPException(401, "Not authenticated")


def require_auth(request: Request):
    """Dependency — skip if AUTH_ENABLED is false"""
    if not AUTH_ENABLED:
        return {"sub": "anonymous", "name": "Anonymous", "auth_type": "disabled", "role": "admin"}
    token = get_token_from_request(request)
    return verify_token(token)


def require_admin(user=Depends(require_auth)):
    """Dependency for every state-changing endpoint. Role-only check — see
    the history note in UPGRADE-NOTES.md about the old De Morgan bug."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    return user


def _login_error_redirect(code: str) -> RedirectResponse:
    return RedirectResponse(f"{APP_BASE_URL}/login?error={quote(code, safe='')}")


def _resolve_msal_role(upn: str, display_name: str) -> str:
    """Looks the MSAL user up in the shared JSON user store (creating a
    viewer record on first sign-in) so admins can manage MSAL roles from the
    Users page like local accounts. Imported lazily because routers/users.py
    imports this module."""
    from app.routers.users import load_users, save_users, msal_store_key
    upn = (upn or "").lower()
    if upn in MSAL_ADMIN_USERS:
        return "admin"
    users = load_users()
    key = msal_store_key(upn)
    record = users.get(key)
    if record is None:
        record = {
            "username": key, "name": display_name or upn, "role": "viewer",
            "active": True, "builtin": False, "auth_type": "msal",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        users[key] = record
        save_users(users)
        log.info(f"Registered new MSAL user as viewer: {upn}")
    if not record.get("active", True):
        raise HTTPException(403, "Account is disabled")
    return record.get("role", "viewer")


@router.get("/auth/config")
async def auth_config():
    """Returns auth configuration for the frontend to know what to show"""
    return {
        "auth_enabled": AUTH_ENABLED,
        "msal_enabled": bool(AZURE_TENANT_ID and AZURE_CLIENT_ID),
        "local_admin_enabled": bool(LOCAL_ADMIN_PASS),
        "tenant_id": AZURE_TENANT_ID if AUTH_ENABLED else None,
        "client_id": AZURE_CLIENT_ID if AUTH_ENABLED else None,
    }


@router.post("/auth/login", response_model=TokenResponse)
async def local_login(req: LoginRequest):
    if not AUTH_ENABLED:
        raise HTTPException(400, "Authentication is not enabled")
    if not LOCAL_ADMIN_PASS:
        raise HTTPException(400, "Local admin account not configured. Set LOCAL_ADMIN_PASSWORD in .env")

    user_match = constant_time_equals(req.username.strip(), LOCAL_ADMIN_USER)
    pass_match = constant_time_equals(req.password, LOCAL_ADMIN_PASS)

    if not (user_match and pass_match):
        log.warning(f"Failed local login attempt for user: {req.username}")
        raise HTTPException(401, "Invalid username or password")

    user = {"sub": LOCAL_ADMIN_USER, "name": "Local Administrator", "auth_type": "local", "role": "admin"}
    token = create_token(user)
    log.info(f"Local admin login successful: {req.username}")
    return TokenResponse(access_token=token, user=user)


# Note: POST /auth/login/extended is defined in app/routers/users.py, not here —
# that version checks both the env admin AND the JSON file-based user store
# users.py manages. Keeping only one definition avoids FastAPI route shadowing.


@router.get("/auth/msal/login")
async def msal_login():
    """Redirect user to Microsoft Entra ID login page"""
    if not AUTH_ENABLED:
        raise HTTPException(400, "Authentication is not enabled")
    if not AZURE_TENANT_ID or not AZURE_CLIENT_ID:
        raise HTTPException(400, "MSAL not configured. Set AZURE_TENANT_ID and AZURE_CLIENT_ID in .env")

    state = secrets.token_urlsafe(32)
    params = {
        "client_id": AZURE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": MSAL_REDIRECT_URI,
        "response_mode": "query",
        "scope": MSAL_SCOPES,
        "state": state,
        "prompt": "select_account",
    }
    response = RedirectResponse(f"{MSAL_AUTH_URL}?{urlencode(params)}")
    # SECURITY: the state was previously generated but never checked, so the
    # callback would accept any attacker-initiated code (login CSRF). Bind
    # it to this browser and verify it in msal_callback.
    response.set_cookie(MSAL_STATE_COOKIE, state, httponly=True, samesite="lax",
                        max_age=600, secure=APP_BASE_URL.startswith("https://"))
    return response


@router.get("/auth/callback")
async def msal_callback(request: Request, code: str = None, state: str = None, error: str = None):
    """Handle Microsoft Entra ID OAuth callback"""
    if error:
        log.error(f"MSAL auth error: {error}")
        return _login_error_redirect(error)

    if not code:
        return _login_error_redirect("no_code")

    expected_state = request.cookies.get(MSAL_STATE_COOKIE)
    if not state or not expected_state or not secrets.compare_digest(state, expected_state):
        log.warning("MSAL callback rejected: missing or mismatched state")
        return _login_error_redirect("invalid_state")

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(MSAL_TOKEN_URL, data={
                "client_id": AZURE_CLIENT_ID,
                "client_secret": AZURE_CLIENT_SECRET,
                "code": code,
                "redirect_uri": MSAL_REDIRECT_URI,
                "grant_type": "authorization_code",
                "scope": MSAL_SCOPES,
            }, timeout=15)
            resp.raise_for_status()
            token_data = resp.json()

        access_token = token_data.get("access_token")
        async with httpx.AsyncClient() as client:
            me = await client.get("https://graph.microsoft.com/v1.0/me",
                                  headers={"Authorization": f"Bearer {access_token}"}, timeout=10)
            me.raise_for_status()
            profile = me.json()

        # Role comes from MSAL_ADMIN_USERS or the shared user store — new
        # MSAL users are viewers until an admin promotes them.
        upn = profile.get("userPrincipalName")
        user = {
            "sub": profile.get("id"),
            "name": profile.get("displayName"),
            "email": upn,
            "auth_type": "msal",
            "role": _resolve_msal_role(upn, profile.get("displayName")),
        }

        eg_token = create_token(user)
        log.info(f"MSAL login successful: {user.get('email')} role={user['role']}")

        response = RedirectResponse(f"{APP_BASE_URL}/")
        response.set_cookie("eg_token", eg_token, httponly=True, samesite="lax",
                            max_age=JWT_EXPIRE_HOURS * 3600,
                            secure=APP_BASE_URL.startswith("https://"))
        response.delete_cookie(MSAL_STATE_COOKIE)
        return response

    except HTTPException as e:
        log.warning(f"MSAL login refused: {e.detail}")
        return _login_error_redirect("account_disabled")
    except Exception as e:
        log.error(f"MSAL callback error: {e}")
        return _login_error_redirect("auth_failed")


@router.post("/auth/logout")
async def logout():
    response = JSONResponse({"message": "Logged out"})
    response.delete_cookie("eg_token")
    return response


@router.get("/auth/me")
async def me(user=Depends(require_auth)):
    return user
