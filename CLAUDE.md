# EntraGuard — project context

Self-hosted Entra ID (Azure AD) security posture scanner. Docker Compose stack:

| Service | Path | Notes |
|---|---|---|
| `api` | `services/api/app` | FastAPI + async SQLAlchemy (asyncpg). Auth, targets, runs, findings, users. |
| `assessment-engine` / `scheduler` | `services/assessment-engine/app` | Celery worker + beat. `tasks.py` holds every check (122) and `ALL_CHECKS`; `ai_explainer.py` / `ai_agent.py` are optional LLM narration (advisory only, never change status/score). |
| `web-ui` | `services/web-ui/src/App.tsx` | Single-file React + Vite app served by nginx (`docker/nginx.conf`), which proxies `/api/` to the API and sets `X-Real-IP`. |
| `postgres`, `redis` | — | Schema is created by `Base.metadata.create_all` — no Alembic migrations; new columns need a manual `ALTER TABLE` (see UPGRADE-NOTES.md §1). |

## Conventions that matter

- Both Python services use a top-level package named `app` — run their tests separately (`cd services/<svc> && python -m pytest tests`).
- Auth: `require_auth` (any signed-in user) and `require_admin` (role == admin) live in `services/api/app/auth/router.py`. Every state-changing endpoint uses `require_admin`. `require_auth` re-checks the account against the user store on every request, so tests must use `bearer()` from `tests/conftest.py` (it creates the account).
- Every request body is a Pydantic model with `extra="forbid"`; query parameters use `Query(...)` bounds. Don't accept a raw `dict`.
- Security-relevant actions call `audit()` from `app/core/audit.py`. Never put user-supplied text into a log line without `!r`.
- Check results pass through `normalize_result` in `tasks.py`; the valid statuses, severities and efforts are the constants above it.
- Users are a JSON file (`USERS_FILE`, default `/app/data/users.json`); the env admin is a built-in that's never saved. MSAL users are stored as `msal:<upn>`.
- Each check returns `{check_id, severity, status, score, affected_resources, evidence, risk_description, remediation_steps, estimated_effort}` and must catch its own Graph errors. `check_id`s must be unique — `tests/test_checks.py` enforces it.
- Graph advanced queries (`$count`, `NOT` filters) need `headers={"ConsistencyLevel": "eventual"}` on `GraphClient.get`/`get_all_pages`.
- User-facing release notes go in `UPGRADE-NOTES.md`; breaking changes get a "what you might notice" row.
- Maintainer links (website, GitHub, email) and the donate link live in the `AUTHOR` / `DONATE_URL` constants near the top of `App.tsx` — the About page, sidebar Sponsor button and footer all read from them. `.github/FUNDING.yml` drives the repo's Sponsor button.
- The mobile sidebar wrapper (`.eg-sidebar`) must keep `width:232` to match `Nav`, or the slide-out transform moves 0px and the menu never hides.

## Verifying changes

```bash
(cd services/api && python -m pytest tests)
(cd services/assessment-engine && python -m pytest tests)
(cd services/web-ui && npm ci && npx tsc --noEmit -p . && npm run build)
```

CI runs the same in `.github/workflows/ci.yml`. A full stack check needs Docker Desktop running: `docker compose up -d --build`.

## Releasing images

Four images on Docker Hub (`jahmed22/entra-guard-{api,worker,scheduler,ui}`), one Dockerfile each: `Dockerfile.api`, `Dockerfile.engine` (worker), `Dockerfile.scheduler` (Celery beat — never build the scheduler from the worker Dockerfile), `Dockerfile.web`. Build multi-arch (`linux/amd64,linux/arm64`) with `docker buildx` and tag both the version and `latest`; the exact loop is in README → Multi-arch build. `docker-compose.yml` builds from source; `docker-compose.example.yml` runs the published images and is what the README Quick Start downloads. Before pushing, smoke-test the example compose with locally built images (`EG_VERSION=<tag>`).

## Project documents

Read these before starting work, and keep them current as part of the change:

- [`docs/CONTEXT.md`](docs/CONTEXT.md) — architecture, file map, auth model, scan lifecycle, impact model.
- [`docs/MEMORY.md`](docs/MEMORY.md) — decisions and their reasons, gotchas, dev-machine notes, release history. Add an entry when something non-obvious is learned.
- [`docs/TASKS.md`](docs/TASKS.md) — the roadmap: next up, backlog, done. Move items to Done when they ship.
- [`docs/RELEASING.md`](docs/RELEASING.md) — version bump locations, smoke test, image build and verification.
- `UPGRADE-NOTES.md` — user-facing release notes.
