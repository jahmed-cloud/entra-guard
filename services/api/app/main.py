import os, uuid, asyncio, logging, ipaddress, time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

# Without this, uvicorn only shows its own access log: the app's INFO lines
# (including the audit trail in app/core/audit.py) were silently dropped.
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

from app.core.database import engine, Base
from app.routers import targets, assessments, findings, users as users_router
from app.auth.router import router as auth_router
from app.auth.tracker import heartbeat_loop, get_instance_info, APP_VERSION

log = logging.getLogger(__name__)

_STARTUP_LOCK_KEY = 0x45477264  # arbitrary constant shared by all API workers

@asynccontextmanager
async def lifespan(app: FastAPI):
    from sqlalchemy import select, text
    from app.models.models import Target

    # uvicorn starts several worker processes and each one runs this. On a
    # new database they raced: both tried to create the tables, one died
    # with a UniqueViolation and was never restarted (leaving the API on a
    # single worker), and both could seed a target. The advisory lock makes
    # the second worker wait until the first has committed.
    async with engine.begin() as conn:
        await conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _STARTUP_LOCK_KEY})
        await conn.run_sync(Base.metadata.create_all)

        # Auto-create target from env vars if none exists
        existing = await conn.execute(select(Target.id).limit(1))
        if not existing.first():
            tenant_id = os.getenv("AZURE_TENANT_ID") or os.getenv("ENTRA_TENANT_ID")
            client_id = os.getenv("AZURE_CLIENT_ID") or os.getenv("ENTRA_CLIENT_ID")
            if tenant_id and client_id:
                name = os.getenv("TARGET_NAME", "My Azure Tenant")
                await conn.execute(Target.__table__.insert().values(
                    id=uuid.uuid4(),
                    name=name,
                    type="azure_tenant",
                    config={"tenant_id": tenant_id, "client_id": client_id},
                    credential_ref="env://AZURE",
                ))
                log.info(f"Auto-created target: {name}")

    # Start telemetry heartbeat in background
    asyncio.create_task(heartbeat_loop())

    yield

# The interactive docs describe every endpoint to anyone who can reach the
# API port, and load scripts from a CDN. Off unless explicitly enabled.
_docs_enabled = os.getenv("ENABLE_API_DOCS", "false").lower() == "true"

app = FastAPI(
    title="EntraGuard API", version=APP_VERSION, lifespan=lifespan,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# SECURITY: allow_origins=["*"] combined with allow_credentials=True was
# previously set here. That combination allows any website on the internet
# to make authenticated (cookie/credentialed) requests to this API from a
# victim's browser — a real CSRF-adjacent exposure, not a style issue.
# Locked to APP_BASE_URL (the one origin this app is actually served from)
# plus optional comma-separated extras via CORS_EXTRA_ORIGINS for local dev.
_app_base_url = os.getenv("APP_BASE_URL", "http://localhost:3000").rstrip("/")
_extra_origins = [o.strip() for o in os.getenv("CORS_EXTRA_ORIGINS", "").split(",") if o.strip()]
_allowed_origins = list({_app_base_url, *_extra_origins})

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Rate limiting on authentication endpoints ─────────────────────────────────
# SECURITY: /auth/login and /auth/login/extended previously had no throttling
# at all — an internet-facing login form with zero rate limit is brute-forceable
# regardless of how strong the password comparison itself is.
#
# Attempts are counted in Redis, so the limit holds across uvicorn workers,
# API replicas and restarts. If Redis is unreachable (or no REDIS_URL is set,
# as in the unit tests) it falls back to a per-process in-memory counter
# rather than failing open or blocking logins.
_login_attempts: dict[str, list[float]] = {}
_LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_RATE_LIMIT_ATTEMPTS", "5"))
_LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "300"))  # 5 minutes
_RATE_LIMIT_REDIS_URL = os.getenv("LOGIN_RATE_LIMIT_REDIS_URL", os.getenv("REDIS_URL", ""))
_REDIS_RETRY_SECONDS = 30
_redis_client = None
_redis_retry_at = 0.0

# INCR and EXPIRE in one step: if they were two calls and the API died between
# them, the key would never expire and that IP would be locked out for good.
_INCR_WITH_TTL = """
local count = redis.call('INCR', KEYS[1])
if count == 1 or redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""

def _client_ip(request: Request) -> str:
    """Every browser request arrives via the web-ui nginx container, so the
    socket peer is always nginx's Docker IP — keying on it meant 5 bad
    attempts from anyone locked out every user. nginx sets X-Real-IP; trust
    it only when the peer is itself on a private network (i.e. our proxy),
    so a client hitting the published :8000 port directly can't spoof it."""
    peer = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-real-ip", "").strip()
    try:
        if forwarded and ipaddress.ip_address(peer).is_private:
            ipaddress.ip_address(forwarded)  # reject garbage header values
            return forwarded
    except ValueError:
        pass
    return peer

async def _redis_attempt_count(client_ip: str):
    """Records the attempt in Redis and returns the count for this window,
    or None when Redis can't be used right now."""
    global _redis_client, _redis_retry_at
    if not _RATE_LIMIT_REDIS_URL or time.time() < _redis_retry_at:
        return None
    try:
        if _redis_client is None:
            import redis.asyncio as aioredis
            # Short timeouts: a slow Redis must not make logins hang.
            _redis_client = aioredis.from_url(_RATE_LIMIT_REDIS_URL, socket_connect_timeout=0.5, socket_timeout=0.5)
        return int(await _redis_client.eval(_INCR_WITH_TTL, 1, f"eg:login:{client_ip}", _LOGIN_WINDOW_SECONDS))
    except Exception as e:
        log.warning("Login rate limiter: Redis unavailable (%s); using the in-memory counter for %ss",
                    e, _REDIS_RETRY_SECONDS)
        _redis_retry_at = time.time() + _REDIS_RETRY_SECONDS
        return None

def _memory_attempt_count(client_ip: str) -> int:
    now = time.time()
    # Prune expired IPs so the dict can't grow without bound.
    for ip in [ip for ip, ts in _login_attempts.items() if not ts or now - ts[-1] >= _LOGIN_WINDOW_SECONDS]:
        del _login_attempts[ip]
    attempts = [t for t in _login_attempts.get(client_ip, []) if now - t < _LOGIN_WINDOW_SECONDS]
    # Blocked attempts aren't recorded, so the window runs from the last
    # attempt that was actually let through.
    if len(attempts) < _LOGIN_MAX_ATTEMPTS:
        attempts.append(now)
        _login_attempts[client_ip] = attempts
        return len(attempts)
    return _LOGIN_MAX_ATTEMPTS + 1

@app.middleware("http")
async def login_rate_limit(request: Request, call_next):
    if request.url.path in ("/api/v1/auth/login", "/api/v1/auth/login/extended") and request.method == "POST":
        client_ip = _client_ip(request)
        count = await _redis_attempt_count(client_ip)
        if count is None:
            count = _memory_attempt_count(client_ip)
        if count > _LOGIN_MAX_ATTEMPTS:
            log.warning("Login rate limit exceeded for %r", client_ip)
            return JSONResponse(
                status_code=429,
                content={"detail": f"Too many login attempts. Try again in {_LOGIN_WINDOW_SECONDS // 60} minutes."},
                headers={"Retry-After": str(_LOGIN_WINDOW_SECONDS)},
            )
    return await call_next(request)

# ── Response hardening ────────────────────────────────────────────────────────
# The dashboard's own headers are set by nginx (docker/nginx.conf). These
# cover API responses, including when the API port is reached directly.
# Registered after the rate limiter on purpose: the last middleware added
# is the outermost, so 429 responses get these headers too.
_MAX_BODY_BYTES = int(os.getenv("MAX_REQUEST_BODY_BYTES", str(1024 * 1024)))

@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Every legitimate request body here is a few hundred bytes of JSON.
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > _MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request body too large"})

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/"):
        # Findings and user lists must not sit in a browser or proxy cache.
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    if _app_base_url.startswith("https://"):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response

app.include_router(auth_router,    prefix="/api/v1")
app.include_router(targets.router, prefix="/api/v1")
app.include_router(assessments.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(users_router.router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok", **get_instance_info()}
