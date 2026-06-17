# EntraGuard — Azure Identity Security Posture Management

> **Continuously assess, monitor, and harden your Microsoft Entra ID tenant against 115 security checks — with step-by-step remediation, compliance mapping, and real-time dashboards.**

[![Docker Pulls](https://img.shields.io/docker/pulls/jahmed22/entra-guard-api?label=API+Pulls&logo=docker)](https://hub.docker.com/r/jahmed22/entra-guard-api)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-lightgrey)](https://hub.docker.com/r/jahmed22/entra-guard-api)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Configuration & Environment Variables](#configuration--environment-variables)
- [Azure App Registration Setup](#azure-app-registration-setup)
- [Automated SPN Setup (PowerShell)](#automated-spn-setup-powershell)
- [Authentication](#authentication)
- [Check Catalogue](#check-catalogue)
- [Adding Custom Checks](#adding-custom-checks)
- [Finding Inventory & Management](#finding-inventory--management)
- [Notifications & Integrations](#notifications--integrations)
- [Compliance Framework Mappings](#compliance-framework-mappings)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

EntraGuard is a production-grade, containerised **Azure Identity Security Posture Management (ISPM)** platform. It continuously assesses your Microsoft Entra ID (Azure AD) tenant against a catalogue of 115+ checks covering:

- Conditional Access policies
- MFA & authentication methods
- Privileged Identity Management (PIM)
- Identity hygiene and lifecycle
- Application & service principal security
- Guest access and collaboration
- Break glass and emergency access
- Groups, devices, and directory settings

Every finding includes a **plain-English risk description**, **numbered step-by-step remediation**, **affected resource list**, and **Microsoft documentation links** — so engineers can fix issues without leaving the dashboard.

---

## Features

### Assessment Engine
- **115 automated checks** across 12 security domains
- Real-time assessment against a live Microsoft Entra ID tenant via Microsoft Graph API
- Celery-based async execution — scans complete in under 5 minutes
- Scheduled daily scans (06:00 UTC by default, configurable via cron)
- Graceful error handling — one failing check never blocks others

### Dashboard
- Security posture score with trend charts
- Severity breakdown — Critical, High, Medium, Low
- Domain-level failure heat map
- Top-5 highest risk score findings
- Line chart trends (failing checks over time, pass rate over time)
- Mini compliance coverage rings per category

### Findings
- Advanced filtering by severity, status, and text search
- Expandable detail panel per finding:
  - **Why this matters** — business impact
  - **How to fix it** — numbered step-by-step guide
  - **Affected resources** — exact users, apps, or policies affected
  - **Evidence** — raw API data that triggered the finding
  - **Microsoft documentation links**
- CSV export of all findings
- Mark as Fixed tracking

### Exceptions Management
- Acknowledge findings with status: Fixed, Risk Accepted, False Positive, In Progress
- Add free-text notes for audit trail
- Edit and revoke acknowledgements
- Summary counts by status

### Compliance
- Findings mapped to NIST CSF, CIS Azure v2, and ISO 27001
- Per-domain coverage percentage with visual progress bars
- Control-level pass/fail status

### Remediation
- Grouped by effort: Quick Wins (<1 hr), Short Term (1–7 days), Project (multi-week)
- Risk description and step-by-step fix instructions per finding
- Sorted by risk score within each effort group

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      EntraGuard Stack                        │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐   ┌────────────────┐  │
│  │   Web UI     │───▶│  FastAPI     │──▶│ Assessment     │  │
│  │  React +     │    │  REST API    │   │ Engine         │  │
│  │  Nginx       │    │  Port 8000   │   │ (Celery Worker)│  │
│  │  Port 3000   │    └──────┬───────┘   └───────┬────────┘  │
│  └──────────────┘           │                   │           │
│                             ▼                   ▼           │
│                    ┌──────────────┐   ┌──────────────────┐  │
│                    │  PostgreSQL  │   │      Redis       │  │
│                    │  Port 5432   │   │  Celery broker   │  │
│                    └──────────────┘   └──────────────────┘  │
│                                                              │
│                    ┌──────────────────────────────────────┐  │
│                    │  Celery Beat (Scheduler)             │  │
│                    │  Triggers daily scans automatically  │  │
│                    └──────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
               ┌──────────────────────────────┐
               │  Microsoft Entra ID           │
               │  (Microsoft Graph API)        │
               │  Read-only — never modifies   │
               └──────────────────────────────┘
```

| Service | Image | Purpose |
|---------|-------|---------|
| `web-ui` | `jahmed22/entra-guard-ui` | React dashboard served by Nginx |
| `api` | `jahmed22/entra-guard-api` | FastAPI REST API and data layer |
| `worker` | `jahmed22/entra-guard-worker` | Celery worker running Graph API checks |
| `scheduler` | `jahmed22/entra-guard-scheduler` | Celery Beat for scheduled scans |
| `postgres` | `postgres:16-alpine` | Persistent store for findings and runs |
| `redis` | `redis:7-alpine` | Message broker for Celery |

---

## Quick Start

### Prerequisites

- Docker Engine 24+ and Docker Compose v2
- A Microsoft Entra ID (Azure AD) tenant
- An Azure App Registration with required Graph API permissions (see [setup guide](#azure-app-registration-setup) or use the [automated PowerShell script](#automated-spn-setup-powershell))

### 1. Create your folder

```bash
mkdir entra-guard && cd entra-guard
```

### 2. Create `docker-compose.yml`

```yaml
services:
  postgres:
    image: postgres:16-alpine
    container_name: entra-guard-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-cspm}
      POSTGRES_USER: ${POSTGRES_USER:-cspm_user}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-cspm_user}"]
      interval: 5s
      retries: 10
    networks: [internal]

  redis:
    image: redis:7-alpine
    container_name: entra-guard-redis
    restart: unless-stopped
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      retries: 10
    networks: [internal]

  api:
    image: jahmed22/entra-guard-api:latest
    platform: linux/amd64
    container_name: entra-guard-api
    restart: unless-stopped
    ports:
      - "${API_PORT:-8000}:8000"
    env_file: .env
    environment:
      DATABASE_URL: postgresql+asyncpg://${POSTGRES_USER:-cspm_user}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-cspm}
      REDIS_URL: redis://redis:6379/0
      CELERY_BROKER_URL: redis://redis:6379/1
      CELERY_RESULT_BACKEND: redis://redis:6379/2
      # Auth settings — must be declared here explicitly to be visible in container
      AUTH_ENABLED: ${AUTH_ENABLED:-true}
      LOCAL_ADMIN_USERNAME: ${LOCAL_ADMIN_USERNAME}
      LOCAL_ADMIN_PASSWORD: ${LOCAL_ADMIN_PASSWORD}
      JWT_EXPIRE_HOURS: ${JWT_EXPIRE_HOURS:-8}
      APP_BASE_URL: ${APP_BASE_URL:-http://localhost:3000}
      # Notifications
      SMTP_HOST: ${SMTP_HOST}
      SMTP_PORT: ${SMTP_PORT}
      SMTP_USER: ${SMTP_USER}
      SMTP_PASSWORD: ${SMTP_PASSWORD}
      ALERT_EMAIL: ${ALERT_EMAIL}
      TEAMS_WEBHOOK_URL: ${TEAMS_WEBHOOK_URL}
      SLACK_WEBHOOK_URL: ${SLACK_WEBHOOK_URL}
      # Break glass
      BREAK_GLASS_GROUP_ID: ${BREAK_GLASS_GROUP_ID}
    depends_on:
      postgres: { condition: service_healthy }
      redis:    { condition: service_healthy }
    networks: [internal, external]

  worker:
    image: jahmed22/entra-guard-worker:latest
    platform: linux/amd64
    container_name: entra-guard-worker
    restart: unless-stopped
    env_file: .env
    environment:
      DATABASE_URL: postgresql+psycopg2://${POSTGRES_USER:-cspm_user}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-cspm}
      REDIS_URL: redis://redis:6379/0
      CELERY_BROKER_URL: redis://redis:6379/1
      CELERY_RESULT_BACKEND: redis://redis:6379/2
      BREAK_GLASS_GROUP_ID: ${BREAK_GLASS_GROUP_ID}
    depends_on:
      postgres: { condition: service_healthy }
      redis:    { condition: service_healthy }
    networks: [internal, external]

  scheduler:
    image: jahmed22/entra-guard-scheduler:latest
    platform: linux/amd64
    container_name: entra-guard-scheduler
    restart: unless-stopped
    env_file: .env
    environment:
      DATABASE_URL: postgresql+psycopg2://${POSTGRES_USER:-cspm_user}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-cspm}
      CELERY_BROKER_URL: redis://redis:6379/1
      CELERY_RESULT_BACKEND: redis://redis:6379/2
    depends_on:
      postgres: { condition: service_healthy }
      redis:    { condition: service_healthy }
    networks: [internal, external]

  ui:
    image: jahmed22/entra-guard-ui:latest
    platform: linux/amd64
    container_name: entra-guard-ui
    restart: unless-stopped
    ports:
      - "${PORT:-3000}:80"
    depends_on: [api]
    networks: [internal, external]

networks:
  internal:
    driver: bridge
    internal: true
  external:
    driver: bridge

volumes:
  postgres_data:
  redis_data:
```

> **Important:** Environment variables from `.env` are **not** automatically visible inside containers. Any variable the API needs at runtime must be explicitly declared in the `environment:` block of its service, as shown above. This is a common source of auth and notification failures.

### 3. Create `.env`

```bash
# ── Required ──────────────────────────────────────────────────
POSTGRES_PASSWORD=your_strong_password_here
SECRET_KEY=your_secret_key_here          # openssl rand -hex 32

# ── Azure / Entra ID credentials ──────────────────────────────
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# ── Display ───────────────────────────────────────────────────
TARGET_NAME=My Azure Tenant
PORT=3000
API_PORT=8000

# ── Database ──────────────────────────────────────────────────
POSTGRES_DB=cspm
POSTGRES_USER=cspm_user

# ── Authentication ────────────────────────────────────────────
AUTH_ENABLED=true
LOCAL_ADMIN_USERNAME=admin
LOCAL_ADMIN_PASSWORD=your_admin_password
JWT_EXPIRE_HOURS=8
APP_BASE_URL=http://your-server-ip:3000  # Used for SSO redirect URIs

# ── Email alerts (optional) ───────────────────────────────────
# SMTP_HOST=mail.yourdomain.com
# SMTP_PORT=587
# SMTP_USER=alerts@yourdomain.com
# SMTP_PASSWORD=your_smtp_password
# ALERT_EMAIL=security@yourdomain.com

# ── Slack / Teams notifications (optional) ────────────────────
# TEAMS_WEBHOOK_URL=https://...
# SLACK_WEBHOOK_URL=https://hooks.slack.com/...

# ── Break glass monitoring (optional) ────────────────────────
# BREAK_GLASS_GROUP_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### 4. Pull and start

```bash
docker compose pull
docker compose up -d
docker compose ps
```

### 5. Open the dashboard

Navigate to **http://localhost:3000**, log in with your `LOCAL_ADMIN_USERNAME` / `LOCAL_ADMIN_PASSWORD`, and click **▶ Scan** to run your first assessment.

---

## Docker Deployment

### Images on Docker Hub

| Image | Tags | Size |
|-------|------|------|
| `jahmed22/entra-guard-api` | `latest`, `v2.1` | ~600 MB |
| `jahmed22/entra-guard-ui` | `latest`, `v2.1` | ~50 MB |
| `jahmed22/entra-guard-worker` | `latest`, `v2.1` | ~530 MB |
| `jahmed22/entra-guard-scheduler` | `latest`, `v2.1` | ~530 MB |

All images are multi-arch: **linux/amd64** and **linux/arm64** (Raspberry Pi 4/5, Apple Silicon, DietPi).

### Running multiple tenants on one server

Run a second stack on different ports with different container names and its own `.env`:

```bash
mkdir entra-guard-tenant2 && cd entra-guard-tenant2
# Same docker-compose.yml — change ports in .env:
PORT=3001
API_PORT=8001
```

### Updating to a new version

```bash
docker compose pull
docker compose up -d
```

### Building from source

```bash
git clone https://github.com/jahmed-cloud/entra-guard.git
cd entra-guard
docker compose build --no-cache
docker compose up -d
```

### Multi-arch build (for maintainers)

Images are built from an ARM64 host (DietPi) using `docker buildx` to produce manifests for both `linux/amd64` and `linux/arm64`:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t jahmed22/entra-guard-api:latest --push .
```

If you deploy to an AMD64 server and see platform mismatch warnings, add `platform: linux/amd64` under each service in `docker-compose.yml`.

---

## Configuration & Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `SECRET_KEY` | FastAPI JWT signing key — run `openssl rand -hex 32` |
| `AZURE_TENANT_ID` | Your Entra ID tenant ID |
| `AZURE_CLIENT_ID` | App Registration client ID |
| `AZURE_CLIENT_SECRET` | App Registration client secret |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_ENABLED` | `true` | Enable login wall. Set `false` only for local dev. |
| `LOCAL_ADMIN_USERNAME` | — | Username for the built-in local admin account |
| `LOCAL_ADMIN_PASSWORD` | — | Password for the built-in local admin account |
| `JWT_EXPIRE_HOURS` | `8` | Session token lifetime in hours |
| `APP_BASE_URL` | `http://localhost:3000` | Public URL of the dashboard (used for SSO redirect URIs) |

> **Note on Microsoft SSO:** Microsoft Entra ID SSO login requires HTTPS redirect URIs — Azure Portal rejects plain HTTP for any non-localhost origin. SSO is a pending feature pending TLS/HTTPS setup. Local admin login works fully over HTTP today.

### Display

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_NAME` | `My Azure Tenant` | Tenant display name shown in the dashboard header |
| `PORT` | `3000` | UI port |
| `API_PORT` | `8000` | API port |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | `cspm` | Database name |
| `POSTGRES_USER` | `cspm_user` | Database user |

### Email Alerts

| Variable | Description |
|----------|-------------|
| `SMTP_HOST` | SMTP server hostname (e.g. `mail.yourdomain.com`) |
| `SMTP_PORT` | SMTP port (`587` for STARTTLS, `465` for SSL) |
| `SMTP_USER` | SMTP username / From address |
| `SMTP_PASSWORD` | SMTP password |
| `ALERT_EMAIL` | Recipient address for Critical finding alerts |

### Notifications

| Variable | Description |
|----------|-------------|
| `TEAMS_WEBHOOK_URL` | Microsoft Teams incoming webhook URL |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `PAGERDUTY_ROUTING_KEY` | PagerDuty Events API v2 routing key |

### Break Glass

| Variable | Description |
|----------|-------------|
| `BREAK_GLASS_GROUP_ID` | Object ID of the Entra ID group containing break glass accounts |

### Advanced

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_SCHEDULE_CRON` | `0 6 * * *` | Cron expression for scheduled scans (default: 6 AM UTC daily) |
| `CELERY_CONCURRENCY` | `2` | Number of parallel Celery workers |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warning`, `error` |

> **Environment variable visibility:** Variables defined in `.env` are **not** automatically passed into containers — they must be explicitly listed in the `environment:` block of each service in `docker-compose.yml`. Missing declarations are the most common cause of auth failures and missing notifications.

---

## Azure App Registration Setup

You can configure the App Registration manually (steps below) or use the [automated PowerShell script](#automated-spn-setup-powershell) which handles everything in one run.

### Step 1 — Create App Registration

1. Go to **Entra ID → App Registrations → New registration**
2. Name: `EntraGuard-CSPM`
3. Supported account types: **Accounts in this organisational directory only**
4. Click **Register**

### Step 2 — Create Client Secret

1. Go to **Certificates & secrets → New client secret**
2. Description: `EntraGuard`; Expiry: **12 months** (set a calendar reminder to rotate)
3. Copy the **Value** immediately — this is your `AZURE_CLIENT_SECRET`

### Step 3 — Grant API Permissions

Go to **API permissions → Add a permission → Microsoft Graph → Application permissions** and add all of the following:

| Permission | Purpose |
|-----------|---------|
| `AuditLog.Read.All` | Sign-in logs, audit events |
| `Directory.Read.All` | Users, groups, roles, directory objects |
| `Policy.Read.All` | Conditional Access, authorization policies |
| `PrivilegedAccess.Read.AzureAD` | PIM role assignments and settings |
| `IdentityRiskyUser.Read.All` | Identity Protection risky users |
| `AccessReview.Read.All` | Access review configurations |
| `SecurityEvents.Read.All` | Security alerts and events |
| `User.Read.All` | User profiles and authentication methods |
| `UserAuthenticationMethod.Read.All` | MFA registration details |
| `Application.Read.All` | App registrations and service principals |
| `Group.Read.All` | Group memberships and settings |
| `RoleManagement.Read.Directory` | Directory role assignments |
| `Reports.Read.All` | MFA registration reports, usage data |

Click **Grant admin consent for [your tenant]** after adding all permissions.

### Step 4 — Record your credentials

From the App Registration **Overview** page, copy:

- **Directory (tenant) ID** → `AZURE_TENANT_ID`
- **Application (client) ID** → `AZURE_CLIENT_ID`
- Client secret value → `AZURE_CLIENT_SECRET`

---

## Automated SPN Setup (PowerShell)

A PowerShell script is provided that automates the complete App Registration and permissions setup. It requires the **Microsoft Graph PowerShell SDK**.

**Download:** [`Setup-EntraGuardSPN.ps1`](scripts/Setup-EntraGuardSPN.ps1)

```powershell
# Run from PowerShell 7+ with admin rights
.\Setup-EntraGuardSPN.ps1
```

The script will:

1. Connect to Microsoft Graph (browser login prompt)
2. Create the `EntraGuard-CSPM` App Registration
3. Add all 13 required Graph API application permissions
4. Grant admin consent for all permissions
5. Create a client secret valid for 12 months
6. Output the `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` values ready to paste into your `.env`

See the [script documentation](scripts/Setup-EntraGuardSPN.ps1) for prerequisites and options.

---

## Authentication

### Local Admin Login

EntraGuard ships with a built-in local admin account controlled by:

```
LOCAL_ADMIN_USERNAME=admin
LOCAL_ADMIN_PASSWORD=your_password
```

These must be set in `.env` **and** explicitly declared in the `api` service's `environment:` block in `docker-compose.yml` — otherwise the API container cannot read them.

Login issues checklist:

```bash
# Verify the env vars are visible inside the container
docker exec entra-guard-api env | grep -E "AUTH_ENABLED|LOCAL_ADMIN"

# Check API logs for auth errors
docker compose logs api --tail=50 | grep -i auth
```

### Microsoft SSO (Pending HTTPS)

Microsoft Entra ID SSO is implemented in the codebase but requires an HTTPS redirect URI. Azure Portal rejects HTTP redirect URIs for any non-localhost origin. To enable SSO:

1. Set up TLS/HTTPS (via reverse proxy such as Caddy, Nginx + Let's Encrypt, or Cloudflare Tunnel)
2. Update `APP_BASE_URL` to your HTTPS URL (e.g. `https://entra-guard.yourdomain.com`)
3. Add the HTTPS redirect URI to your App Registration in Azure Portal under **Authentication**

---

## Check Catalogue

EntraGuard runs 115 checks across 12 domains. Full details in [`docs/CHECKS.md`](docs/CHECKS.md).

### Summary by domain

| Domain | Checks | Key Controls |
|--------|--------|-------------|
| Conditional Access | 22 | Break glass exclusion, MFA for all users, legacy auth block, risk-based policies |
| MFA & Authentication | 11 | Admin MFA, number matching, phishing-resistant MFA, fraud alert |
| Privileged Identity (PIM) | 8 | No permanent assignments, JIT activation, approval requirements |
| Privileged Accounts | 7 | Cloud-only admins, max GA count, role separation |
| Identity Hygiene | 10 | SSPR, stale accounts, security defaults, cross-tenant policy |
| Applications | 14 | Credential expiry, consent controls, assignment required, redirect URIs |
| Guests | 6 | Pending invitations, stale guests, invite restrictions |
| Groups | 7 | Expiration policy, empty groups, dynamic membership |
| Monitoring & Risk | 8 | Risky users, sign-in logs, legacy auth sign-ins, lockout events |
| Break Glass | 3 | Account existence, CA exclusion, password rotation |
| Governance | 4 | Access reviews, entitlement management |
| Directory | 15 | Sync accounts, group creation, app registration restrictions |

### Severity distribution

| Severity | Count | Response SLA |
|----------|-------|--------------|
| Critical | ~10 | Immediate (same day) |
| High | ~55 | This week |
| Medium | ~35 | This month |
| Low | ~15 | Next quarter |

---

## Adding Custom Checks

### Where checks live

All checks are Python functions in `services/assessment-engine/app/tasks.py`.

### Check function signature

```python
def check_my_custom_control(graph, target_config):
    """AZURE-CUSTOM-001 — Description of what this checks"""
    try:
        # Call Microsoft Graph API
        data = graph.pages("/some/graph/endpoint")
        
        issue_found = len(data) == 0
        
        return {
            "check_id": "AZURE-CUSTOM-001",
            "severity": "High",           # Critical / High / Medium / Low
            "status": "failed" if issue_found else "passed",
            "score": 6.0 if issue_found else 0.0,  # 0.0–10.0
            "affected_resources": [{"item": d.get("displayName")} for d in data],
            "evidence": {"count": len(data)},
            "risk_description": "Plain-English explanation of why this matters.",
            "remediation_steps": "Step-by-step instructions to fix this.",
            "estimated_effort": "Low",    # Low / Moderate / High
        }
    except Exception as e:
        return {
            "check_id": "AZURE-CUSTOM-001", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Check failed to run.",
            "remediation_steps": "Ensure required Graph API permissions are granted.",
            "estimated_effort": "Low",
        }
```

### Register your check

Add it to the `ALL_CHECKS` list at the bottom of `tasks.py`:

```python
ALL_CHECKS = [
    # ... existing checks ...
    check_my_custom_control,   # ← add here
]
```

### Add rich remediation text

Add an entry to the `REM` dictionary in `App.tsx`:

```javascript
"AZURE-CUSTOM-001": {
    title: "Short title for the finding card",
    risk: "Why this matters to the business — one clear paragraph.",
    steps: [
        "Go to Entra ID → ...",
        "Click ...",
        "Set ... to ...",
    ],
    ref: "https://learn.microsoft.com/en-us/...",
},
```

### Deploy without rebuilding

```bash
# Copy updated tasks.py into the running containers
docker cp services/assessment-engine/app/tasks.py entra-guard-worker:/app/app/tasks.py
docker cp services/assessment-engine/app/tasks.py entra-guard-scheduler:/app/app/tasks.py
docker restart entra-guard-worker entra-guard-scheduler
```

---

## Finding Inventory & Management

### Where findings are stored

All findings are stored in PostgreSQL in the `findings` table. The API always returns only the **latest completed scan's** results to prevent accumulation across runs.

```sql
SELECT check_id, status, severity, score, affected_resources
FROM findings
WHERE scan_run_id = (
    SELECT id FROM scan_runs
    WHERE status = 'completed'
    ORDER BY completed_at DESC
    LIMIT 1
)
ORDER BY score DESC;
```

### Querying via API

```bash
# All findings from latest scan
GET /api/v1/findings?page_size=500

# Filter by severity
GET /api/v1/findings?severity=critical&page_size=200

# Findings from a specific scan run
GET /api/v1/findings?scan_run_id=<uuid>

# All scan runs
GET /api/v1/assessments/runs

# Trigger a new scan
POST /api/v1/assessments/run
{ "target_id": "<uuid>" }
```

### Exporting findings

**From the UI:** Findings tab → Export button → downloads CSV with check ID, title, severity, score, risk description, and remediation steps.

**Direct database export:**

```bash
docker exec entra-guard-db psql -U cspm_user -d cspm -c "\COPY (
    SELECT check_id, status, severity, score, risk_description, remediation_steps, estimated_effort
    FROM findings
    WHERE scan_run_id = (SELECT id FROM scan_runs WHERE status='completed' ORDER BY completed_at DESC LIMIT 1)
    ORDER BY score DESC
) TO STDOUT WITH CSV HEADER" > findings-export.csv
```

### Bulk operations

```bash
# Remove all findings from failed/incomplete scans
docker exec entra-guard-db psql -U cspm_user -d cspm -c "
DELETE FROM findings
WHERE scan_run_id IN (
    SELECT id FROM scan_runs WHERE status != 'completed'
);"

# Keep only the last 10 completed scans
docker exec entra-guard-db psql -U cspm_user -d cspm -c "
DELETE FROM findings
WHERE scan_run_id NOT IN (
    SELECT id FROM scan_runs
    WHERE status = 'completed'
    ORDER BY completed_at DESC
    LIMIT 10
);"
```

---

## Notifications & Integrations

### Email alerts

Set `SMTP_*` and `ALERT_EMAIL` in `.env` and ensure they are declared in the `api` service environment block. Alerts fire when a completed scan finds new Critical findings.

### Microsoft Teams

1. In Teams, go to a channel → **Manage channel → Connectors → Incoming Webhook**
2. Copy the webhook URL
3. Set `TEAMS_WEBHOOK_URL=<url>` in `.env`

EntraGuard posts a summary card after each scan with critical and high finding counts and a link to the dashboard.

### Slack

1. Go to https://api.slack.com/apps → **Create app → Incoming Webhooks → Add New Webhook**
2. Copy the webhook URL
3. Set `SLACK_WEBHOOK_URL=<url>` in `.env`

### Webhook payload format

```json
{
  "scan_id": "uuid",
  "completed_at": "2026-06-14T10:00:00Z",
  "tenant": "My Azure Tenant",
  "checks_total": 115,
  "checks_failed": 43,
  "critical": 6,
  "high": 28,
  "medium": 7,
  "low": 2,
  "score": 62,
  "dashboard_url": "http://your-server:3000"
}
```

---

## Compliance Framework Mappings

| Framework | Domains Covered |
|-----------|----------------|
| NIST CSF 2.0 | Identify, Protect, Detect, Respond, Recover |
| CIS Azure v2 | IAM, Conditional Access, Applications, Monitoring, Governance |
| ISO 27001:2022 | A.9 Access Control, A.12 Operations, A.14 Development, A.16 Incidents |

Mappings are visible in the **Compliance** tab. Each check ID is colour-coded: green (pass), red (fail), grey (not yet scanned).

---

## Troubleshooting

### Dashboard shows OFFLINE

The UI cannot reach the API. Check:

```bash
docker compose ps                          # Are all containers Up?
docker compose logs api --tail=30          # Any Python errors?
curl http://localhost:8000/health          # Does the API respond?
```

### Cannot log in / auth errors

The most common cause is missing environment variable declarations in `docker-compose.yml`. Verify:

```bash
# Check what the container actually sees
docker exec entra-guard-api env | grep -E "AUTH_ENABLED|LOCAL_ADMIN"
```

If the variables are blank, add them to the `environment:` block of the `api` service and restart:

```bash
docker compose up -d api
```

### White screen on load

A JavaScript error is crashing the React app. Open browser DevTools → Console tab. Common causes:

- Stale cached JS in Nginx — force rebuild: `docker compose build --no-cache ui && docker compose up -d ui`
- A JSX object spread bug (CSS variable string used as `{...OBJECT}` spread) — check the console for `Objects are not valid as a React child`

### Worker shows "Name resolution failed"

The worker or scheduler container cannot reach `graph.microsoft.com`. The containers need access to both the internal network (for Redis/Postgres) and the external network (for Graph API calls).

**Immediate fix:**

```bash
docker network connect <project>_external entra-guard-worker
docker network connect <project>_external entra-guard-scheduler
```

**Permanent fix** — ensure both `networks: [internal, external]` are listed under the `worker` and `scheduler` services in `docker-compose.yml`, then:

```bash
docker compose down && docker compose up -d
```

### Checks showing "error" status

```bash
# See which checks errored and why
curl -s "http://localhost:8000/api/v1/findings?page_size=500" | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for f in d['items']:
    if f['status'] == 'error':
        print(f['check_id'], '-', f['evidence'].get('error', '?')[:80])
" | head -20
```

Most errors are caused by missing Graph API permissions. Grant the missing permission in the Azure Portal and click **Grant admin consent**.

### Duplicate findings / inflated counts

The findings endpoint filters to the latest completed scan — if you see duplicates it may be caused by querying without this filter, or leftover data from failed runs.

```bash
# Clean up failed/incomplete scan data and keep only the last 5 completed scans
docker exec entra-guard-db psql -U cspm_user -d cspm -c "
DELETE FROM findings WHERE scan_run_id NOT IN (
    SELECT id FROM scan_runs
    WHERE status='completed'
    ORDER BY completed_at DESC
    LIMIT 5
);
DELETE FROM scan_runs WHERE status != 'completed';"
```

### Platform mismatch warnings on AMD64 servers

Add `platform: linux/amd64` under every `jahmed22/entra-guard-*` service in `docker-compose.yml`, then:

```bash
docker compose down
docker compose pull
docker compose up -d
```

---

## FAQ

**Does EntraGuard modify my Azure tenant?**
No. It is entirely read-only. Only GET Microsoft Graph API requests are made. It never modifies your configuration.

**What licences are required in Azure?**
Most checks work with any Entra ID licence (Free or P1). Checks for PIM, Identity Protection risk-based policies, and access reviews require **Entra ID P2** or **Microsoft Entra ID Governance**.

**Can I run it against multiple tenants?**
Yes. Create separate `docker-compose.yml` stacks on different ports, each with their own `.env` pointing to a different tenant's App Registration credentials.

**How often does it scan?**
Manual scans via the dashboard Scan button. Automatic daily scans run at 06:00 UTC via Celery Beat (configurable with `SCAN_SCHEDULE_CRON`).

**Is my Azure data sent anywhere?**
No. EntraGuard runs entirely on your own infrastructure. All findings and scan data stay in your local PostgreSQL container.

**How do I back up my findings data?**

```bash
docker exec entra-guard-db pg_dump -U cspm_user cspm > backup-$(date +%Y%m%d).sql
```

**Why aren't my SMTP/Teams/Slack settings working?**
They must be declared in the `environment:` block of the `api` service in `docker-compose.yml` — not just in `.env`. Refer to the full `docker-compose.yml` in the Quick Start section.

**Can I disable authentication for local dev?**
Yes. Set `AUTH_ENABLED=false` in `.env` (and declare it in the `api` environment block). Do not do this in production.

---

## Roadmap

| Version | Planned Features |
|---------|----------------|
| v2.1 | PDF/Excel report export, email alert on new Critical findings ✅ |
| v2.2 | Microsoft Teams and Slack scan summary notifications ✅ |
| v2.3 | Multi-tenant comparison dashboard |
| v2.4 | Trend-based alerting (score drops >10 points) |
| v3.0 | AWS IAM and GCP IAM check modules |
| v3.1 | Microsoft SSO / Entra ID authentication (requires HTTPS) |
| v3.2 | AI-powered risk narrative and remediation suggestions |
| v3.3 | Remediation workflow with Jira/ServiceNow ticket creation |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

Quick summary:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-check`
3. Add your check function to `tasks.py` and register it in `ALL_CHECKS`
4. Add remediation text to `App.tsx` under `REM`
5. Test against a real or demo tenant
6. Open a pull request describing what the check tests and why it matters

---

## License

EntraGuard is released under the [MIT License](LICENSE).

Built by **Junaid Ahmed** — [iam@jahmed.cloud](mailto:iam@jahmed.cloud)
