# EntraGuard — project memory

Decisions that were made, why, and mistakes worth not repeating. Add an entry when something non-obvious is learned; delete entries that stop being true. Architecture is in [CONTEXT.md](CONTEXT.md), open work in [TASKS.md](TASKS.md).

## Decisions and why

| Decision | Why |
|---|---|
| Users live in a JSON file, not Postgres | Small teams; no migration tooling yet. Written atomically (temp file + rename, mode 0600). Moving to a table is in TASKS. |
| The role is read from the user store on every request, not from the JWT | A demoted or disabled user otherwise kept their old access for up to `JWT_EXPIRE_HOURS`. |
| Microsoft sign-in users default to viewer | Previously every tenant user who signed in became admin. Admins are listed in `MSAL_ADMIN_USERS` or promoted on the Users page. |
| API refuses to start with a default/short `SECRET_KEY` when auth is on | A known signing key means anyone can mint an admin token. Failing loudly beats running insecurely. |
| Login limiter counts in Redis, falls back to memory | The API runs 2 workers, so a per-process counter doubled the real limit. Fallback so a Redis outage neither blocks logins nor removes the limit. |
| All login failures return the same message and cost one password check | Different messages/timing revealed which usernames exist. |
| Password minimum is 12 (`PASSWORD_MIN_LENGTH`), no composition rules | Length beats complexity rules; existing shorter passwords keep working until changed. |
| Target config rejects secret-looking keys | The config is returned to every signed-in user by `GET /targets`. Secrets belong in environment variables. |
| One scan per target at a time (409) | Each scan is several hundred Graph calls; stacked scans get the app registration throttled. Stale after `SCAN_STALE_MINUTES` so a crashed worker can't block scans forever. |
| `normalize_result` coerces instead of rejecting | One bad check must not lose the other 121 results. Unknown status becomes `error`, never `passed`. |
| Graph token only ever goes to `https://graph.microsoft.com/` | `@odata.nextLink` is followed blindly otherwise; a bad link would leak the tenant token. |
| Impact is computed in the API, not the UI | Testable in pytest and reusable by scripts; the UI only renders it. |
| 403 from Graph counts as *unverified* in the impact score | The engine stores it as `failed`, but it is a coverage gap, not a confirmed weakness. |
| Worker/scheduler run as uid 10001, read-only root filesystem | They handle tenant credentials and parse remote data. The **API still runs as root**: existing `users_data` volumes are root-owned and a non-root API could not write them (see TASKS). |
| API port bound to `127.0.0.1` in both compose files | Published on all interfaces it bypassed nginx, and the limiter trusts `X-Real-IP` from private peers. |
| CSP allows `style-src 'unsafe-inline'` | The UI uses React inline styles throughout. Scripts are `'self'` only. |
| AI explanation is advisory only | It must never change a finding's status, score or severity. |
| Telemetry is opt-in | Off in code and compose; the instance id is random, not derived from `SECRET_KEY`. |
| `kombu==5.4.2` is pinned | `celery==5.4.0` allows kombu 5.7, which rejects `redis==5.0.4`; fresh builds crash-looped. `tests/test_dependencies.py` guards it. |
| Scheduler has its own Dockerfile | Images up to v2.3.1 built it from the worker Dockerfile, so beat never ran and daily scans never fired. |

## Gotchas

- **Both Python services have a top-level package named `app`.** Run their tests separately, from each service directory.
- **Config is read at import time** in the API. Tests set environment variables in `conftest.py` *before* importing `app`. One test reloads `app.auth.router`; it must stay last in its file.
- **Tests need real accounts.** A token for a user that isn't in the store is rejected. Use `bearer()` from `conftest.py` (it writes the user to the store); call it after the `client` fixture.
- **Middleware order:** the last `@app.middleware` registered is the outermost. Security headers are registered after the rate limiter so 429 responses carry them.
- **nginx `add_header` is not inherited** into a `location` that has its own `add_header`. Dashboard headers are set in `location /`; `/api/` has none on purpose (the API sets its own).
- **A new env var needs three places:** `.env.example`, the `environment:` block in `docker-compose.yml`, the README table. (The example compose uses `env_file` and needs nothing.)
- **No migrations.** A new model column does not appear in existing databases; document the `ALTER TABLE` in UPGRADE-NOTES.
- **`tasks.py` builds `ALL_CHECKS` in three steps** (`ALL_CHECKS`, `EXTRA_CHECKS`, `WORKSHEET_CHECKS`). A function defined after the lists but never added is dead code.
- **Graph advanced queries** (`$count`, `NOT` filters) need `headers={"ConsistencyLevel": "eventual"}` or they return 400.
- **The mobile sidebar wrapper must keep `width:232`** or the slide-out transform moves 0px.
- **A check's docstring is its title.** The first docstring line must be `AZURE-XXX-001 — Title`. `scripts/gen_check_titles.py` turns those into `services/web-ui/src/checkTitles.json` (dashboard titles) and `docs/CHECKS.md`; an engine test fails if they are stale. Run the script after adding or renaming a check.
- **README screenshots** are produced by `scripts/screenshots/` (seed sample data, then drive headless Chrome). Retake them after a visible UI change; look at every image before committing, because the first attempt exposed four real UI bugs.
- **Version lives in several places** — see [RELEASING.md](RELEASING.md).
- **Breaking changes** go in UPGRADE-NOTES with a "what you might notice" row; pushing `latest` delivers them to everyone who runs `docker compose pull`.

## Working on this repo (Windows dev machine)

- `python` is not on PATH; use `py`. Tests run from a venv built with `py -3.12 -m venv`.
- Git has `core.autocrlf=true`: working files are CRLF, the repo is LF. Scripts that patch files should normalise line endings first.
- In Bash heredocs, backslashes in Python/sed snippets get mangled (`\a` became a bell character once). For anything with backslashes, write a script file and run it.
- Docker Desktop stops on its own between sessions and has died mid-push. Check `docker info` first; push images one at a time; verify tags afterwards with `docker buildx imagetools inspect`.
- GitHub occasionally returns a transient 500 on push or PR creation. Check whether it landed before retrying.
- Commit convention: single author (the maintainer), no co-author trailers or "generated with" footers. Squash-merge PRs with an explicit subject and body.

## History

| Date | Release | What |
|---|---|---|
| 2026-06 | v2.0 – v2.3.1 | Initial public releases |
| 2026-10-30 | (PR #1) | Security review: OAuth state check, MSAL roles, admin-only writes, PBKDF2, rate-limiter keying, tests and CI |
| 2026-11-09 | (PR #2) | About page, Sponsor button, mobile menu fix |
| 2026-11-10 | v2.4.0 (PR #3) | Example compose file, scheduler image fix, kombu pin, multi-arch images |
| 2026-11-15 | v2.5.1 | Titles for all 122 checks, coverage ring totals, login margin, phone top bar; README screenshots and generated check catalogue |
| 2026-11 | v2.5.0 | Hardening: session re-validation, Redis rate limiter, input validation, result validation, Graph client hardening, impact score, security headers, container hardening |
