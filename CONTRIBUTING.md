# Contributing to EntraGuard

Thank you for considering a contribution to EntraGuard! This document explains how to get involved — from reporting a bug to adding a new security check.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Adding a New Security Check](#adding-a-new-security-check)
- [Improving Remediation Content](#improving-remediation-content)
- [UI Contributions](#ui-contributions)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)

---

## Code of Conduct

Be respectful, constructive, and inclusive. We welcome contributors of all backgrounds and experience levels. Offensive behaviour, harassment, or dismissiveness will result in removal from the project.

---

## Ways to Contribute

| Type | Examples |
|------|---------|
| New security checks | Add a check from the Microsoft Secure Score, CIS Benchmark, or your own experience |
| Improved remediation | Add more detailed steps, screenshots, or links to official Microsoft docs |
| Bug fixes | Fix an API call that returns 400, improve error handling, fix a UI bug |
| UI improvements | Dashboard widgets, chart types, mobile layout |
| Documentation | Fix typos, add examples, translate to other languages |
| Compliance mappings | Map existing checks to SOC 2, PCI DSS, NIST 800-53 |
| Tests | Add automated tests for check functions |

---

## Development Setup

### Prerequisites

- Docker Engine 24+
- Python 3.11+
- Node 20+
- A Microsoft Entra ID tenant with an App Registration (can be a free developer tenant)

### 1. Clone the repository

```bash
git clone https://github.com/jahmed-cloud/entra-guard.git
cd entra-guard
```

### 2. Create your environment file

```bash
cp .env.example .env
# Fill in your Azure credentials
nano .env
```

### 3. Start the full stack

```bash
docker compose up -d
docker compose logs -f
```

### 4. Hot-reload for backend changes

The assessment engine reads `tasks.py` on each task execution. After editing:

```bash
docker cp services/assessment-engine/app/tasks.py entra-guard-worker:/app/app/tasks.py
docker restart entra-guard-worker
```

### 5. Hot-reload for frontend changes (source builds only)

If running from source with Vite dev server:

```bash
cd services/web-ui
npm install
npm run dev   # runs on http://localhost:5173
```

---

## Adding a New Security Check

This is the most impactful contribution you can make.

### Step 1: Choose what to check

Good candidates:
- Controls from the CIS Microsoft Azure Foundations Benchmark
- Controls from your organisation's internal security standard
- Microsoft Secure Score recommendations
- Any Conditional Access, identity, or app governance control not yet covered

### Step 2: Write the check function

Add your function to `services/assessment-engine/app/tasks.py`. Follow this exact pattern:

```python
def check_my_new_control(graph, target_config):
    """AZURE-CATEGORY-NNN — Short description of what is being checked"""
    try:
        # 1. Call the Graph API
        results = graph.pages("/some/graph/v1.0/endpoint?$select=id,displayName")

        # 2. Evaluate results
        bad_items = [
            {"name": r.get("displayName"), "id": r.get("id")}
            for r in results
            if r.get("someProperty") is False
        ]

        # 3. Return standardised finding dict
        return {
            "check_id": "AZURE-CATEGORY-NNN",
            "severity": "High",              # Critical / High / Medium / Low
            "status": "failed" if bad_items else "passed",
            "score": 6.5 if bad_items else 0.0,   # 0.0–10.0, 0.0 when passing
            "affected_resources": bad_items[:20],  # Cap at 20 for display
            "evidence": {
                "total_checked": len(results),
                "failed_count": len(bad_items),
            },
            "risk_description": (
                "Clear, business-focused explanation of why this matters. "
                "What can an attacker do if this control is missing?"
            ),
            "remediation_steps": (
                "Step-by-step fix. Use numbered steps if multiple actions are needed. "
                "Reference the Azure portal path (Entra ID → Security → ...)."
            ),
            "estimated_effort": "Low",   # Low (<1 hr) / Moderate (1-7 days) / High (weeks)
        }

    except Exception as e:
        return {
            "check_id": "AZURE-CATEGORY-NNN",
            "severity": "High",
            "status": "error",
            "score": 0.0,
            "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Check failed to run.",
            "remediation_steps": "Ensure [PermissionName].Read.All is granted in the App Registration.",
            "estimated_effort": "Low",
        }
```

### Step 3: Register the check

Add your function to the `ALL_CHECKS` list at the bottom of `tasks.py`:

```python
ALL_CHECKS = [
    # ... existing checks ...
    check_my_new_control,   # ← add here, grouped by category
]
```

### Step 4: Add remediation content to the UI

In `services/web-ui/src/App.tsx`, find the `REM` dictionary and add an entry:

```javascript
"AZURE-CATEGORY-NNN": {
    title: "Short title shown in the findings list",
    risk: "Why this matters — business impact in plain English. One paragraph.",
    steps: [
        "Go to Entra ID → Security → Conditional Access.",
        "Click + New policy.",
        "Under Name, enter 'My Policy'.",
        "Configure Users → All users, Cloud apps → All cloud apps.",
        "Grant → Require multifactor authentication. Enable → On.",
    ],
    ref: "https://learn.microsoft.com/en-us/entra/identity/...",
},
```

### Step 5: Test your check

```bash
# Deploy and test
docker cp services/assessment-engine/app/tasks.py entra-guard-worker:/app/app/tasks.py
docker restart entra-guard-worker

# Trigger a scan and watch logs
curl -X POST http://localhost:8000/api/v1/assessments/run \
  -H "Content-Type: application/json" \
  -d '{"target_id": "your-target-uuid"}'

docker logs entra-guard-worker -f | grep "AZURE-CATEGORY-NNN"
```

### Check ID naming convention

```
AZURE-{DOMAIN}-{NUMBER}

Domains:
  CA          Conditional Access
  MFA         MFA & Authentication
  PIM         Privileged Identity Management
  PRIV        Privileged Accounts
  IDENTITY    Identity Hygiene
  APP         Applications & Service Principals
  GUEST       Guest Users
  GROUP       Groups
  MONITORING  Monitoring & Risk
  BG          Break Glass
  GOVERNANCE  Governance & Lifecycle
  RISK        Risk Detections
```

### Score guidelines

| Score | Meaning |
|-------|---------|
| 9.0–10.0 | Critical — direct path to full tenant compromise |
| 7.0–8.9 | High — significant security gap |
| 5.0–6.9 | High — important control missing |
| 3.0–4.9 | Medium — meaningful risk reduction opportunity |
| 1.0–2.9 | Low — hygiene / best practice |
| 0.0 | Check passes — no risk |

---

## Improving Remediation Content

The `REM` dictionary in `App.tsx` holds rich remediation text. If a check shows generic text, add a proper entry:

1. Find or add the check ID in `REM` in `App.tsx`
2. Write a clear `risk` paragraph (why this matters)
3. Write numbered `steps` (exact portal paths)
4. Add a Microsoft Learn `ref` link

Good remediation steps:
- Start with the exact portal path: `Go to Entra ID → Security → ...`
- Say exactly what to click, select, or type
- Include what to exclude (e.g., break glass group)
- Mention testing in Report-only mode before enabling
- Note any licence requirements (P1, P2)

---

## UI Contributions

The frontend is a single-file React app at `services/web-ui/src/App.tsx`. It uses:
- React with hooks
- Inline styles (no CSS framework)
- Pure SVG for charts
- No external component libraries

When contributing UI changes:
- Test at 1280px and 768px (mobile breakpoint)
- Keep the dark theme consistent with the existing palette
- Use the existing colour tokens (`#1e293b` for cards, `#f87171` for critical, etc.)
- Avoid adding npm dependencies where possible

---

## Pull Request Process

1. Fork the repo and create a branch: `git checkout -b feature/azure-ca-new-check`
2. Make your changes with clear, focused commits
3. Test against a real tenant (or a development/demo tenant)
4. Ensure no existing checks are broken
5. Open a pull request with:
   - **What**: what check or feature you added
   - **Why**: what security risk it addresses
   - **Test**: how you verified it works (include a screenshot of the finding if possible)
   - **References**: link to Microsoft documentation for the control

### PR checklist

- [ ] Check function follows the standard return format
- [ ] Check ID follows naming convention (`AZURE-DOMAIN-NNN`)
- [ ] Check is registered in `ALL_CHECKS`
- [ ] `REM` entry added in `App.tsx` with title, risk, steps, and ref
- [ ] Error handling returns `status: "error"` not an exception
- [ ] Tested against a real or demo Entra ID tenant
- [ ] No `print()` statements left in code (use `log.info()`)

---

## Coding Standards

### Python (assessment engine)

- Python 3.11+
- Follow PEP 8 style
- Use `graph.pages()` for paginated Graph API calls
- Use `graph.get()` for single-object calls
- Always handle exceptions at the check level — a single check failing must not crash the entire scan
- Use `log.error()` not `print()` for error logging
- Keep each check function focused on a single control

### JavaScript / React

- Functional components with hooks only
- No class components
- Inline styles only (no external CSS files or frameworks)
- No TypeScript strict mode — the file uses `// @ts-nocheck` at the top
- Avoid adding new npm dependencies

### Git commit messages

```
feat: add AZURE-CA-018 check for authentication strength on admin roles
fix: handle 403 from riskyUsers endpoint when P2 licence not present
docs: add remediation steps for AZURE-APP-010 redirect URI check
refactor: extract GraphClient helper methods into separate class
```

---

## Reporting Bugs

Please open a GitHub issue with:

1. **What you expected** to happen
2. **What actually happened**
3. **Steps to reproduce** (which check, what tenant config)
4. **Logs** from `docker compose logs assessment-engine --tail=50`
5. **Browser console errors** if it's a UI issue (F12 → Console)
6. **Environment**: OS, Docker version, DietPi/Ubuntu/other

Sensitive tenant details (tenant IDs, client secrets) must never be included in issues.

---

## Requesting Features

Open a GitHub issue with the label `enhancement` describing:

- The security control or feature you want
- Why it matters (what risk it addresses or what workflow it improves)
- Any Microsoft documentation or framework reference
- Whether you're willing to implement it yourself

---

## Recognition

All contributors are listed in [CONTRIBUTORS.md](CONTRIBUTORS.md). Meaningful contributions (new checks, UI improvements, documentation) will be credited in release notes.

---

*Questions? Open an issue or email [iam@jahmed.cloud](mailto:iam@jahmed.cloud)*
