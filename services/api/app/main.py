import os, uuid, asyncio, logging, ipaddress
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from app.core.database import engine, Base, AsyncSessionLocal
from app.routers import targets, assessments, findings, users as users_router
from app.auth.router import router as auth_router
from app.auth.tracker import heartbeat_loop, get_instance_info

log = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Auto-create target from env vars if none exists
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        from app.models.models import Target
        result = await db.execute(select(Target).limit(1))
        if not result.scalar_one_or_none():
            tenant_id = os.getenv("AZURE_TENANT_ID") or os.getenv("ENTRA_TENANT_ID")
            client_id = os.getenv("AZURE_CLIENT_ID") or os.getenv("ENTRA_CLIENT_ID")
            if tenant_id and client_id:
                t = Target(
                    id=uuid.uuid4(),
                    name=os.getenv("TARGET_NAME", "My Azure Tenant"),
                    type="azure_tenant",
                    config={"tenant_id": tenant_id, "client_id": client_id},
                    credential_ref="env://AZURE",
                )
                db.add(t)
                await db.commit()
                log.info(f"Auto-created target: {t.name}")

    # Start telemetry heartbeat in background
    asyncio.create_task(heartbeat_loop())

    yield

app = FastAPI(title="EntraGuard API", version="2.0.0", lifespan=lifespan)

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
# regardless of how strong the password comparison itself is. This is a minimal
# in-memory limiter (per-process, resets on restart) — sufficient for a
# single-instance deployment. For multi-replica deployments, replace with a
# Redis-backed limiter keyed the same way.
_login_attempts: dict[str, list[float]] = {}
_LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_RATE_LIMIT_ATTEMPTS", "5"))
_LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "300"))  # 5 minutes

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

@app.middleware("http")
async def login_rate_limit(request: Request, call_next):
    import time
    if request.url.path in ("/api/v1/auth/login", "/api/v1/auth/login/extended") and request.method == "POST":
        client_ip = _client_ip(request)
        now = time.time()
        # Prune expired IPs so the dict can't grow without bound.
        for ip in [ip for ip, ts in _login_attempts.items() if not ts or now - ts[-1] >= _LOGIN_WINDOW_SECONDS]:
            del _login_attempts[ip]
        attempts = _login_attempts.get(client_ip, [])
        attempts = [t for t in attempts if now - t < _LOGIN_WINDOW_SECONDS]
        if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
            log.warning(f"Login rate limit exceeded for {client_ip}")
            return JSONResponse(
                status_code=429,
                content={"detail": f"Too many login attempts. Try again in {_LOGIN_WINDOW_SECONDS // 60} minutes."},
            )
        attempts.append(now)
        _login_attempts[client_ip] = attempts
    return await call_next(request)

app.include_router(auth_router,    prefix="/api/v1")
app.include_router(targets.router, prefix="/api/v1")
app.include_router(assessments.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(users_router.router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok", **get_instance_info()}
