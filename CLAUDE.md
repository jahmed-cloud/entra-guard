# EntraGuard — project context

Self-hosted Entra ID (Azure AD) security posture scanner. Docker Compose stack:

| Service | Path | Notes |
|---|---|---|
| `api` | `services/api/app` | FastAPI + async SQLAlchemy (asyncpg). Auth, targets, runs, findings, users. |
| `assessment-engine` / `scheduler` | `services/assessment-engine/app` | Celery worker + beat. `tasks.py` holds every check (~150) and `ALL_CHECKS`; `ai_explainer.py` / `ai_agent.py` are optional LLM narration (advisory only, never change status/score). |
| `web-ui` | `services/web-ui/src/App.tsx` | Single-file React + Vite app served by nginx (`docker/nginx.conf`), which proxies `/api/` to the API and sets `X-Real-IP`. |
| `postgres`, `redis` | — | Schema is created by `Base.metadata.create_all` — no Alembic migrations; new columns need a manual `ALTER TABLE` (see UPGRADE-NOTES.md §1). |

## Conventions that matter

- Both Python services use a top-level package named `app` — run their tests separately (`cd services/<svc> && python -m pytest tests`).
- Auth: `require_auth` (any signed-in user) and `require_admin` (role == admin) live in `services/api/app/auth/router.py`. Every state-changing endpoint uses `require_admin`.
- Users are a JSON file (`USERS_FILE`, default `/app/data/users.json`); the env admin is a built-in that's never saved. MSAL users are stored as `msal:<upn>`.
- Each check returns `{check_id, severity, status, score, affected_resources, evidence, risk_description, remediation_steps, estimated_effort}` and must catch its own Graph errors. `check_id`s must be unique — `tests/test_checks.py` enforces it.
- Graph advanced queries (`$count`, `NOT` filters) need `headers={"ConsistencyLevel": "eventual"}` on `GraphClient.get`/`get_all_pages`.
- User-facing release notes go in `UPGRADE-NOTES.md`; breaking changes get a "what you might notice" row.

## Verifying changes

```bash
(cd services/api && python -m pytest tests)
(cd services/assessment-engine && python -m pytest tests)
(cd services/web-ui && npm ci && npx tsc --noEmit -p . && npm run build)
```

CI runs the same in `.github/workflows/ci.yml`. A full stack check needs Docker Desktop running: `docker compose up -d --build`.

## Open work (plan)

1. Redis-backed login rate limiter (current one is per-process; API runs 2 workers).
2. Drop the `8000:8000` API port mapping from the production compose file, or make it opt-in.
3. Move UI exceptions / "fixed" markers from `localStorage` to the database so they're shared.
4. Replace `create_all` with Alembic migrations.
5. Add a `LICENSE` file (README says MIT).
6. Split `tasks.py` (~4.7k lines) into per-domain modules.
