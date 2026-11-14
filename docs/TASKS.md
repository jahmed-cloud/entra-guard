# EntraGuard — tasks

The single list of what's next. Move an item to **Done** with its release when it ships; keep reasons with the items so priorities can be re-judged later. Context is in [CONTEXT.md](CONTEXT.md), past decisions in [MEMORY.md](MEMORY.md).

## Next up

1. **Run the API container as non-root.** Worker and scheduler already do. Blocker: existing `users_data` volumes are root-owned. Needs an entrypoint that fixes ownership once and then drops privileges, tested against both a fresh and an existing volume.
2. **Alembic migrations** in place of `Base.metadata.create_all`. Every schema change currently needs a hand-written `ALTER TABLE` in UPGRADE-NOTES.
3. **Move users into Postgres** (after 2). Removes the JSON file, gives proper uniqueness and an `updated_at`, and lets API replicas share users.
4. **Server-side exceptions and "fixed" markers.** They live in each browser's `localStorage`, so two admins see different exception lists and nothing is audited.
5. **Report permission errors as their own status.** Checks return `failed` for a Graph 403. The impact model already treats these as unverified; the engine, counts and UI should too (`status: "unverified"` or reuse `error`).
6. **Add a `LICENSE` file.** The README says MIT but the file is missing.

## Backlog

- Split `tasks.py` (~4.8k lines) into one module per domain (CA, MFA, PIM, apps, guests…), keeping `ALL_CHECKS` as the registry.
- Trend for the weighted score: store `weighted_score` on `scan_runs` so the dashboard can chart it.
- Per-finding "impact" on the Findings and Remediation pages (the points are already in `/findings/impact`).
- Session revocation list / shorter tokens with refresh, so logout invalidates a token server-side.
- Move the token from `localStorage` to an HttpOnly cookie for local logins too (needs CSRF protection on writes).
- Account lockout per username, in addition to the per-IP rate limit.
- Optional Redis password and Postgres TLS for deployments where the internal network isn't trusted.
- **README documents things the code doesn't do:** email/Teams/Slack notifications, `SCAN_SCHEDULE_CRON` and `CELERY_CONCURRENCY` (the schedule is a fixed 24 h and concurrency is fixed at 2). Either build them or remove them from the README.
- Export findings (CSV/PDF) from the UI.
- Support national clouds (`graph.microsoft.us`, `microsoftgraph.chinacloudapi.cn`) — `GraphClient.GRAPH_ORIGIN` is currently fixed.
- Image scanning (Trivy) and Dependabot in CI; pin base images by digest.
- End-to-end test in CI: bring the example stack up and run the smoke test from RELEASING.md.
- Company-sponsor section in the README once there are sponsors.
- Only 20 checks have a full hand-written remediation guide in the UI (`REM` in `App.tsx`); the other 102 fall back to the engine's one-paragraph remediation text. Write guides for the Critical and High ones first.

## Done

### v2.5.1
- Titles for all 122 checks in the dashboard (generated from the engine); generated `docs/CHECKS.md`
- Coverage ring totals, login page margin, phone top bar overlap
- README screenshots (`docs/images`, regenerate with `scripts/screenshots`)

### v2.5.0
- Accounts are re-checked against the user store on every request (disable/demote/delete is immediate)
- Redis-backed login rate limiter with in-memory fallback
- Uniform login failures (no username enumeration); password policy; atomic user-file writes
- Request validation on every write endpoint and on findings queries; target config validation
- One scan per target at a time; queue failures no longer leak internals
- Audit log (`entraguard.audit`) for logins, user/target changes and scan starts
- Security headers on API and dashboard (CSP, frame, nosniff, referrer, HSTS behind HTTPS); API docs off by default; 1 MB body limit
- Engine: result validation, Graph token pinned to Graph, retry on throttling, tenant/client ID validation
- Impact: severity-weighted score and "Fix first" card
- Containers: worker/scheduler non-root and read-only, `no-new-privileges`, dropped capabilities, API healthcheck, API port on localhost
- Project docs: CONTEXT, MEMORY, TASKS, RELEASING

### v2.4.0
- `docker-compose.example.yml`; `Dockerfile.scheduler` (daily scans now run); `kombu` pin; multi-arch images

### Earlier (PRs #1, #2)
- Security review fixes, test suites, CI
- About page, Sponsor button, mobile menu fix
