# EntraGuard — context

What the project is, how the pieces fit, and where to look. Read this first when picking the project up after a break. Decisions and gotchas are in [MEMORY.md](MEMORY.md), open work in [TASKS.md](TASKS.md), the release procedure in [RELEASING.md](RELEASING.md).

## What it is

A free, open-source, self-hosted security posture scanner for Microsoft Entra ID (Azure AD). It reads a tenant's configuration through Microsoft Graph with **read-only** application permissions, runs 122 checks (Conditional Access, MFA, privileged roles/PIM, app registrations and consent, guests, break-glass accounts), and shows findings with remediation steps in a web dashboard. Tenant data stays on the operator's own server.

- Repo: https://github.com/jahmed-cloud/entra-guard (default branch `main`)
- Images: `jahmed22/entra-guard-{api,worker,scheduler,ui}` on Docker Hub
- Author: Junaid Ahmed — https://jahmed.cloud

## Architecture

```
browser ──► ui (nginx :80, published on ${PORT:-3000})
              ├─ /        static React bundle + security headers (CSP etc.)
              └─ /api/ ──► api (FastAPI :8000)  ──► postgres   (targets, scan_runs, findings)
                              │                 ──► /app/data  (users.json, instance_id — volume)
                              │                 ──► redis db0  (login rate-limit counters)
                              └─ send_task ───► redis db1 (Celery broker)
                                                   │
                           worker (Celery) ◄───────┘ ──► Microsoft Graph (read-only)
                              └─ writes findings ──► postgres
                           scheduler (Celery beat) ──► queues the daily scan
```

| Service | Code | Image / Dockerfile | Notes |
|---|---|---|---|
| `api` | `services/api/app` | `Dockerfile.api` | FastAPI + async SQLAlchemy (asyncpg), 2 uvicorn workers |
| `worker` (`assessment-engine` in the source compose) | `services/assessment-engine/app` | `Dockerfile.engine` | Celery worker, sync SQLAlchemy (psycopg2), runs as uid 10001 |
| `scheduler` | same code as worker | `Dockerfile.scheduler` | Celery beat only |
| `ui` (`web-ui`) | `services/web-ui/src/App.tsx` | `Dockerfile.web` | Single-file React + Vite, served by nginx (`docker/nginx.conf`) |
| `postgres`, `redis` | — | official images | On the `internal` network only (no outbound access) |

Two compose files: `docker-compose.yml` builds from source; `docker-compose.example.yml` runs the published images and is what the README Quick Start downloads.

## API layout (`services/api/app`)

| File | Responsibility |
|---|---|
| `main.py` | App setup, CORS, login rate limiter (Redis with in-memory fallback), security headers, body-size limit, `/health` |
| `auth/router.py` | JWT create/verify, `require_auth`, `require_admin`, local admin login, Microsoft (MSAL) sign-in |
| `auth/tracker.py` | `APP_VERSION`, opt-in telemetry heartbeat, instance id |
| `routers/users.py` | JSON-file user store, password hashing and policy, `/users` CRUD, `/auth/login/extended` |
| `routers/targets.py` | `/targets` CRUD and target-config validation |
| `routers/assessments.py` | Start a scan (`/assessments/run`), run history |
| `routers/findings.py` | `/findings` and `/findings/impact` |
| `services/impact.py` | Severity-weighted score and "fix first" ranking (pure functions) |
| `core/audit.py` | `audit()` — one log line per security-relevant action |
| `core/database.py`, `models/models.py` | Engine/session, ORM models |

## Auth model

- `AUTH_ENABLED=false` (default): every endpoint is open; `require_auth` returns an anonymous admin. A warning is logged at startup.
- `AUTH_ENABLED=true`: HS256 JWT signed with `SECRET_KEY` (the API refuses to start if it is a placeholder or under 32 characters). Token in `localStorage` for local login, `eg_token` cookie for Microsoft sign-in.
- Two roles: **admin** and **viewer**. Reads need `require_auth`; every state change needs `require_admin`.
- Accounts: the built-in admin from `LOCAL_ADMIN_USERNAME`/`LOCAL_ADMIN_PASSWORD` (never stored), local users in `users.json` (PBKDF2-SHA256, 600k iterations), and Microsoft users stored as `msal:<upn>` (viewer by default; `MSAL_ADMIN_USERS` lists admins).
- **Every request re-checks the account against the store** (`_current_account`): the role comes from the store, and a disabled or deleted user is rejected at once even though their token is still within its lifetime.

## Scan lifecycle

1. `POST /api/v1/assessments/run` (admin) → validates the target, refuses if a scan for it is already pending/running (409; ignored after `SCAN_STALE_MINUTES`), inserts a `scan_runs` row, sends `app.tasks.run_assessment_task` to Celery.
2. Worker: builds a `GraphClient` (validates tenant/client IDs; only ever sends the token to `graph.microsoft.com`; retries 429/503/504), runs every function in `ALL_CHECKS`.
3. Each result goes through `normalize_result` (valid status/severity/effort, score clamped to 0–10, lists capped) before it is counted.
4. Optional AI phase (`ai_explainer.py`, `ai_agent.py`): adds explanation text and a false-positive hint. Advisory only — never changes status, score or severity.
5. Findings are inserted; the run is marked `completed` with totals.
6. The scheduler queues the same task once a day.

## Check contract (`services/assessment-engine/app/tasks.py`)

`def check_xxx(graph, target_config) -> dict` returning `check_id`, `severity` (Critical/High/Medium/Low), `status` (passed/failed/error), `score` (0–10), `affected_resources` (list), `evidence` (dict), `risk_description`, `remediation_steps`, `estimated_effort` (Low/Moderate/High). A check catches its own Graph errors. `check_id`s are unique. `tests/test_checks.py` runs all checks against an empty fake tenant and enforces this.

Known quirk: most checks report a Graph **403** (missing permission) as `status: "failed"` with the error in `evidence.error`. The impact model treats those as *unverified*, not as real failures.

## Impact model (`services/api/app/services/impact.py`)

Each verified check weighs Critical 10 / High 7 / Medium 4 / Low 1. `weighted_score` = passing weight ÷ total weight. A failed check's `points` = how far fixing it alone raises that score. "Fix first" ranks by weight, then cheaper effort, then the engine's risk score. `quick_win` = Low effort and Critical/High. The dashboard's "Fix first — biggest impact" card renders `/findings/impact`.

## Data

- Postgres tables: `targets`, `scan_runs`, `findings`, `assessment_definitions` (unused by the engine). Created by `Base.metadata.create_all` — **no migrations**; a new column needs a manual `ALTER TABLE` (UPGRADE-NOTES §1).
- `/app/data` volume (`users_data`): `users.json`, `instance_id`.
- Browser `localStorage`: token, exceptions and "fixed" markers (not shared between users yet).

## Configuration

All settings are environment variables, documented in `.env.example`. The source compose file lists each variable explicitly under `environment:`; the example compose uses `env_file: .env`. A new variable must be added to `.env.example`, the `api`/`worker` block of `docker-compose.yml`, and the README table.

## Tests and CI

- `services/api/tests` — auth, security, validation, impact (no database: `FakeSession` in `conftest.py`).
- `services/assessment-engine/tests` — check registry, result validation, Graph client.
- Both suites and the UI type-check/build run in `.github/workflows/ci.yml` on every push and PR.
