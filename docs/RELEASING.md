# Releasing EntraGuard

A release is: a version bump, a merged PR with green CI, four multi-arch images on Docker Hub, and a check that the README Quick Start works with them. Do the steps in order; each one catches a different class of mistake.

## 1. Bump the version

The version appears in these places — change all of them together (`X.Y.Z`):

| Where | What |
|---|---|
| `services/api/app/auth/tracker.py` | `APP_VERSION = "X.Y.Z"` (also the FastAPI version and `/health`) |
| `services/web-ui/src/App.tsx` | `const APP_VERSION = "X.Y.Z"` (sidebar, login page, footer) |
| `README.md` | image table tags, `EG_VERSION=vX.Y.Z` example, `VERSION=vX.Y.Z` in the build loop |
| `.env.example` | the `EG_VERSION` comment |
| `docker-compose.example.yml` | the `EG_VERSION` comment at the top |
| `UPGRADE-NOTES.md` | a new section; breaking changes get a "what you might notice" row |
| `docs/TASKS.md`, `docs/MEMORY.md` | move shipped items to Done; add a History row |

## 2. Test

```bash
(cd services/api && python -m pytest tests)
(cd services/assessment-engine && python -m pytest tests)
(cd services/web-ui && npm ci && npx tsc --noEmit -p . && npm run build)
```

## 3. Smoke-test the stack locally

Build from source and run it with a throwaway `.env` (random `SECRET_KEY`, `AUTH_ENABLED=true`, a `LOCAL_ADMIN_PASSWORD`, spare ports):

```bash
docker compose -p egtest --env-file /path/to/test.env up -d --build
```

Run the scripted checks (27 of them: headers, auth, validation, live session re-check, scan queueing, rate limit):

```bash
python scripts/smoke_test.py http://localhost:<PORT> /path/to/test.env
```

It finishes by tripping the login rate limit, so clear it before logging in from the browser: `docker compose -p egtest exec redis redis-cli -n 0 --scan --pattern 'eg:login:*'` then `del` the key.

What it covers, plus what to check by hand:

- `GET /api/v1/auth/config` responds; an unauthenticated `GET /api/v1/targets` is 401
- login works; a sixth bad login in a row is 429
- `POST /api/v1/assessments/run` queues a run and the worker picks it up (with no real tenant it fails with a credentials error — that is the expected result); a second request straight away is 409 while the first is pending
- `docker compose logs scheduler` shows `beat: Starting`
- the dashboard loads with **no Content-Security-Policy errors** in the browser console
- `docker compose ps` shows the API as `healthy`; worker and scheduler run as uid 10001 (`docker compose exec assessment-engine id`)

Then `docker compose -p egtest down -v`.

## 4. Merge

Branch, commit, open a PR, wait for CI (Python tests + web UI build), squash-merge. Commits are single-author with no co-author trailers.

## 5. Build and push the images

From `main` at the merged commit, with Docker logged in as `jahmed22`:

```bash
VERSION=vX.Y.Z
for pair in api:Dockerfile.api worker:Dockerfile.engine scheduler:Dockerfile.scheduler ui:Dockerfile.web; do
  name=${pair%%:*}; file=${pair#*:}
  docker buildx build --platform linux/amd64,linux/arm64 -f "$file" \
    -t "jahmed22/entra-guard-$name:$VERSION" -t "jahmed22/entra-guard-$name:latest" --push .
done
```

- Push one image at a time and confirm each before the next; a Docker Desktop restart mid-push leaves nothing published.
- The scheduler **must** be built from `Dockerfile.scheduler`.
- The arm64 half is built under emulation and is slow the first time.

## 6. Verify what was published

```bash
for n in api worker scheduler ui; do
  docker buildx imagetools inspect "jahmed22/entra-guard-$n:vX.Y.Z" | grep -E "Name|Platform"
done
```

Each must list `linux/amd64` and `linux/arm64`, and `latest` must have the same digest as the version tag. Then run the README Quick Start exactly as a new user would (download `docker-compose.example.yml` and `.env.example` from GitHub, `docker compose pull`, `up -d`) and repeat the smoke checks from step 3.

## 7. After the release

- Update the Docker Hub repository descriptions if the feature list changed.
- If the release has breaking changes, say so wherever it is announced and link UPGRADE-NOTES.
