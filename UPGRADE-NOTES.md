# Upgrade Notes — Security Hardening Release

This release fixes real security gaps in the application itself (not just
detection coverage) and adds new threat-informed checks. Read this before
deploying over an existing installation.

---

## 1. Database migration required (existing deployments only)

A new column was added to the `findings` table: `ai_explanation` (nullable
text). `Base.metadata.create_all()` in `main.py` only creates tables that
don't exist yet — it does **not** alter existing tables. On a fresh
deployment (new Postgres volume) this is automatic. On an existing
deployment, run this once before starting the new containers:

```bash
docker compose exec postgres psql -U ${POSTGRES_USER:-cspm_user} -d ${POSTGRES_DB:-cspm} \
  -c 'ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_explanation TEXT;
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_false_positive_likelihood TEXT;
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_false_positive_reason TEXT;
      ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS ai_summary TEXT;
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_queries_made TEXT;'
```

If you skip this on an existing deployment, the API will throw a column-not-found
error on the first insert after the new code is deployed.

---

## 2. Breaking change: `AUTH_ENABLED=true` now actually protects your data

**Before this release**, `AUTH_ENABLED=true` only gated the login page and
`/auth/me`. Every other endpoint — `/findings`, `/assessments/run`,
`/targets` — had no authentication check at all, regardless of this setting.

**After this release**, those endpoints genuinely require a valid session
when `AUTH_ENABLED=true`.

If you were already running with `AUTH_ENABLED=true` believing your data was
protected, it was not — this is now fixed, but it also means:

- Any existing frontend sessions will need to re-authenticate if their token
  expired or was never truly validated server-side before.
- If you have anything (scripts, integrations, monitoring) calling the API
  directly without a token, those calls will now start returning `401` once
  `AUTH_ENABLED=true` is set. If you rely on unauthenticated API access
  internally, either keep `AUTH_ENABLED=false` (network-perimeter security
  model) or update those callers to authenticate.

If you run with `AUTH_ENABLED=false`, nothing changes in observed behaviour —
`require_auth` returns an anonymous pass-through user in that mode, exactly
as before.

---

## 3. CORS is now locked to `APP_BASE_URL`

**Before:** `allow_origins=["*"]` with `allow_credentials=True` — any origin
could make credentialed requests to the API.

**After:** only `APP_BASE_URL` (plus anything you list in the new
`CORS_EXTRA_ORIGINS` env var, comma-separated) is allowed.

**Action required:** set `APP_BASE_URL` in `.env` to the exact URL your
frontend is actually served from, including scheme and port
(e.g. `http://10.0.0.5:3000`, not just `10.0.0.5`). If this is wrong, the
frontend will appear to work for unauthenticated GETs proxied through nginx
but browser-direct API calls or any credentialed request may be silently
blocked by CORS — check the browser console for CORS errors if something
that used to work now fails.

If you run a local dev frontend on a different port (e.g. Vite dev server on
`:5173` while the API runs on `:8000`), add that origin to
`CORS_EXTRA_ORIGINS`.

---

## 4. Login rate limiting is new

`POST /auth/login` and `/auth/login/extended` are now limited to 5 attempts
per IP per 5-minute window by default (`LOGIN_RATE_LIMIT_ATTEMPTS`,
`LOGIN_RATE_LIMIT_WINDOW_SECONDS`). This is in-memory and per-process — it
resets on container restart and does not share state across multiple API
replicas. If you scale the API service beyond one replica, this limiter
becomes easy to bypass by hitting different replicas; replace it with a
Redis-backed limiter keyed the same way (client IP + endpoint) if that
matters for your deployment.

If legitimate automated testing or CI hits the login endpoint repeatedly,
raise `LOGIN_RATE_LIMIT_ATTEMPTS` or exclude that source IP at your reverse
proxy layer instead of disabling the limiter entirely.

---

## 5. New environment variables

Add these to your `.env` (see `.env.example` for the full annotated list):

```bash
# CORS — usually just leave blank, APP_BASE_URL alone is correct
CORS_EXTRA_ORIGINS=

# Login rate limiting
LOGIN_RATE_LIMIT_ATTEMPTS=5
LOGIN_RATE_LIMIT_WINDOW_SECONDS=300

# AI explanation layer — optional, OFF by default
AI_EXPLAIN_ENABLED=false
ANTHROPIC_API_KEY=
AI_EXPLAIN_MODEL=claude-sonnet-4-6
AI_EXPLAIN_CHECK_IDS=
```

---

## 6. New checks — validate before trusting fully

Six new checks were added, targeting attack techniques not previously
covered: `AZURE-FED-001`, `AZURE-FED-002`, `AZURE-RISK-LICENSE`,
`AZURE-CBA-001`, `AZURE-CONSENT-002`, `AZURE-BG-SIGNIN-FREQ`.

Two additive "effective coverage" checks were also added:
`AZURE-MFA-002-V2` and `AZURE-CA-LEGACY-V2`. These run **alongside** the
original `AZURE-MFA-002` and `AZURE-CA-LEGACY` (both still present) rather
than replacing them.

**Recommendation:** run 2-3 scan cycles and compare:

```sql
SELECT check_id, status, score
FROM findings
WHERE check_id IN ('AZURE-MFA-002', 'AZURE-MFA-002-V2', 'AZURE-CA-LEGACY', 'AZURE-CA-LEGACY-V2')
ORDER BY check_id;
```

If `-V2` passes while the original fails for the same scan, that's a
confirmed false positive in the original check — the tenant is actually
covered by a compensating control (most likely Security Defaults) the
original check didn't know to look for. At that point you can safely remove
the original from `ALL_CHECKS` if you want to avoid the duplicate finding.

`AZURE-CBA-001` deliberately cannot fully self-verify via the Graph API —
if Certificate-Based Authentication is enabled at all, it flags for manual
review rather than guessing pass/fail, because the trusted CA list's
adequacy is a judgment call the API alone can't resolve.

---

## 7. AI explainer — still off by default, here's how to turn it on

```bash
AI_EXPLAIN_ENABLED=true
ANTHROPIC_API_KEY=sk-ant-...
```

This adds one new outbound network dependency from the worker container to
`api.anthropic.com`, on a small allowlist of checks (`AI_EXPLAIN_CHECK_IDS`,
defaults to the two `-V2` checks plus the four new hardening checks). It
narrates evidence already collected — it cannot and does not change any
finding's status, score, or severity. See `ai_explainer.py`'s module
docstring for the full boundary documentation.

If you enable this, note it changes your "no tenant data leaves your
infrastructure" posture narrowly: evidence dicts (policy names, scenario
labels, licence booleans) are sent to Anthropic's API for the explained
checks only. Update your own documentation/README if that matters for your
users.

---

## 8. Fixed: MSAL users no longer get unconditional admin

Previously every "Sign in with Microsoft" user was assigned `role: "admin"`.
Now `msal_callback` looks the user up in the same JSON user store the Users
page manages (as `msal:<upn>`):

- UPNs listed in the new `MSAL_ADMIN_USERS` env var (comma-separated) are admin.
- Everyone else is created as a **viewer** on first sign-in; an admin can
  promote them from the Users page. Disabling them there blocks sign-in.

**Action required if you use MSAL:** set `MSAL_ADMIN_USERS` to your admins'
UPNs *before* upgrading, or make sure you can still log in with the local
admin, otherwise every MSAL user will land as a viewer.

`require_admin` (role-only check, the De Morgan fix from the previous
release) now lives in `auth/router.py` and is shared by every router.

---

## 9. Security review fixes (this release)

**Possibly breaking — read first:**

| Change | What you might notice |
|---|---|
| API refuses to start when `AUTH_ENABLED=true` and `SECRET_KEY` is the default/placeholder or under 32 chars | `RuntimeError` in `docker compose logs api`. Fix: `SECRET_KEY=$(openssl rand -hex 32)` in `.env`. Existing sessions are invalidated when the key changes. |
| Starting scans and creating/editing/deleting targets now require the **admin** role | Viewers get `403` (UI shows "Only admins can start a scan."). |
| `PUT /targets/{id}` only accepts `name`, `type`, `config`, `credential_ref`, `is_active` | Any other key returns `400` (previously any column, including `id`, could be overwritten). |
| Telemetry code default is now `false` (matches docker-compose) and the instance ID is random | `/health` shows a new `instance_id`, persisted at `/app/data/instance_id`. |

**Fixed without behaviour change for normal use:**

- **OAuth login CSRF** — the MSAL `state` was generated but never verified. It's now bound to a short-lived cookie and checked on callback; query parameters and the error redirect are URL-encoded.
- **Login rate limiter locked out everyone** — it keyed on the socket peer, which is always the nginx container, so 5 bad attempts from anyone throttled all users. It now uses nginx's `X-Real-IP` when the peer is a private address, and prunes expired entries.
- **Password hashing** — local users were hashed with a single salted SHA-256. New hashes use PBKDF2-HMAC-SHA256 (600k iterations, stdlib). Old hashes still verify and are upgraded automatically on the user's next login.
- **Non-ASCII passwords returned 500** (`secrets.compare_digest` on `str`); `/auth/login/extended` now also validates its body and honours `AUTH_ENABLED`.
- **Malformed UUIDs returned 500** on run/target/finding endpoints; now `404`. `page_size` on `/findings` is clamped to 1–1000.
- **Celery result backend** in the API was derived as `redis://redis:6379/1_backend`; it now uses `CELERY_RESULT_BACKEND`.
- **`/health` leaked a hash of `SECRET_KEY`** (offline oracle for a weak key → forged JWTs). Replaced with a random ID.
- **Agent Graph allowlist** — `/users` and `/groups` prefixes let the AI agent read mailboxes, drives, chats, calendars etc., and `..` could escape a prefix. Those sub-resources and `..` are now rejected.
- **`AZURE-MONITORING-LOCKOUT` could never fail** — it queried `directoryAudits` with `$top=1`. It now reads the last 7 days of sign-ins with error 50053 (needs `AuditLog.Read.All`, already required by other checks).
- **`AZURE-GROUP-EMPTY` errored or found nothing** — its `NOT` filter and `/$count` are Graph advanced queries that require `ConsistencyLevel: eventual`. `GraphClient.get`/`get_all_pages` now accept extra headers.
- Removed a dead duplicate `check_ca_block_guest_admin_portals` (`AZURE-CA-GUESTADMIN`) that was defined after the registry was built and never ran. `AZURE-CA-014` remains the registered check.

**New:** unit tests in `services/api/tests` and `services/assessment-engine/tests`, run in GitHub Actions (`.github/workflows/ci.yml`). See CONTRIBUTING.md → Running the tests.

**Known, still open:**

- The login rate limiter is per-process and the API runs `--workers 2`, so the effective limit is up to 2× the configured value. Use a Redis-backed limiter for a hard limit.
- `docker-compose.yml` publishes the API on `:8000` directly, bypassing nginx. If clients reach it through Docker's userland proxy, their peer address is a private gateway IP and `X-Real-IP` would be trusted. Remove the `8000:8000` mapping in production if you don't need direct API access.
- Exceptions and "fixed" markers in the UI are stored in browser `localStorage` only, not shared between users.
- README links to a `LICENSE` file that isn't in the repository.

---

## 10. Docker Hub images v2.4.0 and `docker-compose.example.yml`

The images on Docker Hub (`jahmed22/entra-guard-{api,worker,scheduler,ui}`) are now published as `v2.4.0` and `latest`, built for `linux/amd64` and `linux/arm64`. They include everything in §8–9 above, so read the breaking-change table in §9 before pulling `latest`. In particular, set a real `SECRET_KEY` if `AUTH_ENABLED=true`.

**Fixed: scheduled scans never ran from Docker Hub images.** Up to `v2.3.1`, the scheduler image was built from the worker Dockerfile, so the `scheduler` container ran a second Celery worker instead of Celery beat, and the daily scan was never triggered. It now has its own `Dockerfile.scheduler`.

**Fixed: fresh builds couldn't run scans.** `celery==5.4.0` only bounds `kombu` to `<6`, so a build today pulls kombu 5.7.0, which refuses to work with the pinned `redis==5.0.4`. The worker crash-looped and the API returned `Failed to queue scan`. `kombu==5.4.2` is now pinned in both services, and a test (`tests/test_dependencies.py`) fails CI if the pair ever becomes incompatible again. If you build from source, rebuild with `docker compose build --no-cache`.

**New `docker-compose.example.yml`** for running from the published images (the README's Quick Start downloads it). Compared with the compose file previously shown in the README:

| Change | What you might notice |
|---|---|
| No `platform: linux/amd64` lines | ARM hosts (Raspberry Pi, Apple Silicon) now get native images instead of emulated amd64 ones. |
| Scheduler has an explicit `beat` command | Daily scans start running, even if you stay on an older image tag. |
| API port bound to `127.0.0.1` | `curl localhost:8000` on the server still works; other machines can no longer reach the API directly (the dashboard is unaffected). Change the port mapping if you relied on remote API access. |
| New `users_data` volume on the API | Local users created on the Users page now survive container recreation. If you were using the old README compose, users you created there were only in the container and will need to be recreated once. |
| `EG_VERSION` in `.env` | Pin a release (e.g. `EG_VERSION=v2.4.0`) instead of tracking `latest`. |

---

## 11. v2.5.0 — hardening, validation and impact scoring

**Possibly breaking — read first:**

| Change | What you might notice |
|---|---|
| New passwords need at least 12 characters (`PASSWORD_MIN_LENGTH`) and must not contain the username | Creating a user or changing a password with a shorter one returns `400`. Existing passwords keep working. |
| Usernames are limited to letters, digits and `. _ @ -` (3–64 characters) | Creating a user with spaces or other characters returns `422`. Existing users are unaffected. |
| Request bodies are validated; unknown fields are rejected | `POST/PUT /targets`, `/users` and `/assessments/run` return `422` for unknown or malformed fields (`PUT /targets` used to return `400`). Malformed IDs and paging values in `/findings` queries return `422`. |
| Target `config` is validated | `tenant_id` must be a GUID or a domain, `client_id` and `break_glass_group_id` must be GUIDs, and keys that look like secrets are refused. A scan for an existing target with an invalid tenant or client ID now fails immediately with a clear message. |
| One scan per tenant at a time | Starting a scan while one is pending or running returns `409`. A scan stuck for more than `SCAN_STALE_MINUTES` (default 60) stops blocking. |
| Sessions are re-checked on every request | A disabled, deleted or demoted user loses access (or admin rights) at once instead of when their token expires. |
| Disabled accounts get the generic "Invalid username or password" | Previously the login said "Account is disabled". |
| The built-in admin can't be edited on the Users page; admins can't disable or demote themselves | `400` with an explanation. Change the built-in admin through `LOCAL_ADMIN_*` in `.env`. |
| `docker-compose.yml` binds the API to `127.0.0.1:8000` | Other machines can no longer reach the API port directly; the dashboard is unaffected. (The example compose already did this.) |
| Interactive API docs are off | `/docs` and `/openapi.json` return `404` unless `ENABLE_API_DOCS=true`. |
| Worker and scheduler run as a non-root user with a read-only filesystem | Nothing, unless you mounted files into those containers that only root can read. `docker cp` into the worker (the old "deploy without rebuilding" tip) no longer works; rebuild the image instead. |
| Queue failures return `503` with a generic message | The detail is in the API log and in Scan History, not in the HTTP response. |

**New:**

- **Impact scoring.** `GET /api/v1/findings/impact` and the dashboard's "Fix first — biggest impact" card: a severity-weighted score, the points each fix would add, quick wins, and the score you would reach. Checks that could not be verified are excluded.
- **Audit trail** on the `entraguard.audit` logger: logins, failed logins, user and target changes, scan starts. The API now logs at `LOG_LEVEL` (default `INFO`).
- **Redis-backed login rate limit**, shared by all API workers and replicas, with an in-memory fallback. This closes the "limit is per process" item from §9.
- **Security headers**: a Content-Security-Policy, `X-Frame-Options`, `nosniff` and `Referrer-Policy` on the dashboard; `no-store` and a deny-all CSP on API responses; HSTS when `APP_BASE_URL` is HTTPS. Request bodies over 1 MB are refused.
- **Container hardening** in both compose files: `no-new-privileges` everywhere, all capabilities dropped for the API, worker and scheduler, an API healthcheck.
- **Scanner**: results are validated before they are stored (bad values are coerced and logged instead of failing the insert); Graph throttling (429/503/504) is retried with backoff; the Graph token is never sent to a non-Graph URL.
- New settings: `PASSWORD_MIN_LENGTH`, `SCAN_STALE_MINUTES`, `ENABLE_API_DOCS`, `LOG_LEVEL` (see `.env.example`). No database changes.

**Fixed:**

- On a brand-new database the API's two worker processes raced to create the tables; one crashed at startup and was not restarted, leaving the API on a single worker until the next restart. Startup is now serialised with a Postgres advisory lock.
- Login timing and messages revealed which usernames exist.
- A user entry in `users.json` with the built-in admin's name could shadow the built-in admin.
- `users.json` is now written atomically with mode `0600`; a crash mid-write could previously truncate it.
- A username containing a newline could forge log lines.
- Validation errors showed as `[object Object]` on the Users page.

**Known, still open** (tracked in `docs/TASKS.md`): the API container still runs as root; users are still a JSON file; exceptions and "fixed" markers are still per-browser; there are no database migrations.
