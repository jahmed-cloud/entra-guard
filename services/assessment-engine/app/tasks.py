import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from celery import Celery
from sqlalchemy import create_engine, text

log = logging.getLogger(__name__)

# ── Celery setup ──────────────────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"))
BROKER    = os.getenv("CELERY_BROKER_URL", REDIS_URL)
BACKEND   = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL.replace("/0", "/2"))

celery_app = Celery("cspm", broker=BROKER, backend=BACKEND, include=["app.tasks"])
celery_app.conf.update(
    task_serializer="json", accept_content=["json"], result_serializer="json",
    timezone="UTC", enable_utc=True, task_track_started=True,
    task_acks_late=True, worker_prefetch_multiplier=1,
    beat_schedule={"daily-scan": {"task": "app.tasks.run_scheduled_scan", "schedule": 86400.0}},
)
app = celery_app  # alias so celery -A app.tasks works


# ── DB helper ─────────────────────────────────────────────────────────────────
def get_sync_db():
    url = os.getenv("DATABASE_URL", "postgresql+asyncpg://cspm_user:CHANGE_ME_strong_password@postgres:5432/cspm")
    url = url.replace("+asyncpg", "+psycopg2")
    return create_engine(url)


# ── MS Graph client ──────────────────────────────────────────────────────────
class GraphClient:
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token = None
        self._token_expiry = None
        import httpx
        self._http = httpx.Client(timeout=30)

    def _ensure_token(self):
        if self._token and self._token_expiry and datetime.now(timezone.utc) < self._token_expiry:
            return
        import httpx
        resp = httpx.post(
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": self.client_id,
                  "client_secret": self.client_secret, "scope": "https://graph.microsoft.com/.default"},
            timeout=15,
        )
        resp.raise_for_status()
        d = resp.json()
        self._token = d["access_token"]
        self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=d.get("expires_in", 3599) - 60)

    def get(self, path, headers=None, **kwargs):
        self._ensure_token()
        base = "https://graph.microsoft.com/v1.0"
        url = path if path.startswith("http") else f"{base}{path}"
        # Extra headers (e.g. ConsistencyLevel: eventual for advanced queries
        # like $count / NOT filters) are merged with, never replace, auth.
        r = self._http.get(url, headers={**(headers or {}), "Authorization": f"Bearer {self._token}"}, **kwargs)
        r.raise_for_status()
        return r.json()

    def get_all_pages(self, path, headers=None):
        results, url = [], path
        while url:
            data = self.get(url, headers=headers)
            # Defensive: "value" can legitimately be explicitly null in some
            # Graph API response shapes, not just absent — data.get("value", [])
            # only applies its default when the KEY is missing, not when the
            # key exists with a None value, so a bare .get() here can still
            # return None and crash extend(). Also guard against any
            # individual item in the page being malformed (None/non-dict) —
            # every one of the 100+ checks that call this method assumes
            # every returned item is a usable dict, and a single bad item
            # from Graph would otherwise crash whichever check hit it first,
            # which then cascades into a poisoned DB transaction for every
            # check that runs after it in the same scan.
            page_items = data.get("value") or []
            results.extend(item for item in page_items if isinstance(item, dict))
            url = data.get("@odata.nextLink")
        return results

    def get_conditional_access_policies(self):
        return self.get_all_pages("/identity/conditionalAccess/policies")

    def get_users(self, select_fields=None):
        f = f"?$select={select_fields}" if select_fields else ""
        return self.get_all_pages(f"/users{f}")

    def get_applications(self):
        return self.get_all_pages("/applications?$select=id,displayName,appId,keyCredentials,passwordCredentials,web,publicClient,requiredResourceAccess")

    def get_service_principals(self):
        return self.get_all_pages("/servicePrincipals?$select=id,displayName,appId,accountEnabled,passwordCredentials,keyCredentials,requiredResourceAccess,appRoleAssignments")

    def get_directory_roles(self):
        return self.get_all_pages("/directoryRoles")

    def get_role_members(self, role_id):
        return self.get_all_pages(f"/directoryRoles/{role_id}/members")

    def get_privileged_role_assignments(self):
        try:
            return self.get_all_pages("/roleManagement/directory/roleAssignments?$expand=principal,roleDefinition")
        except Exception:
            return []

    def get_pim_role_assignments(self):
        try:
            return self.get_all_pages("/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition")
        except Exception:
            return []


# ── Check functions ──────────────────────────────────────────────────────────

def check_break_glass_ca_exclusion(graph, target_config):
    """AZURE-CA-001 — Break glass accounts excluded from all CA policies"""
    bg_group_id = target_config.get("break_glass_group_id", "")
    policies = graph.get_conditional_access_policies()
    enabled = [p for p in policies if p.get("state") == "enabled"]
    missing = []
    for p in enabled:
        excl = p.get("conditions", {}).get("users", {})
        excl_groups = excl.get("excludeGroups", [])
        excl_users  = excl.get("excludeUsers", [])
        if bg_group_id and bg_group_id not in excl_groups:
            missing.append({"policy": p.get("displayName"), "id": p.get("id")})
        elif not bg_group_id and not excl_groups and not excl_users:
            missing.append({"policy": p.get("displayName"), "id": p.get("id")})
    return {
        "check_id": "AZURE-CA-001", "severity": "Critical",
        "status": "passed" if not missing else "failed",
        "score": 9.2 if missing else 0.0,
        "affected_resources": missing,
        "evidence": {"enabled_policies": len(enabled), "missing_exclusion": len(missing)},
        "risk_description": "Break glass accounts not excluded — they could be locked out during an incident.",
        "remediation_steps": "Add break glass group to Exclusions in every enabled CA policy.",
        "estimated_effort": "Low",
    }


def check_mfa_privileged_roles(graph, target_config):
    """AZURE-CA-002 — MFA required for privileged roles via CA policy"""
    policies = graph.get_conditional_access_policies()
    mfa_priv = [
        p for p in policies
        if p.get("state") == "enabled"
        and p.get("conditions", {}).get("users", {}).get("includeRoles")
        and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()
    ]
    return {
        "check_id": "AZURE-CA-002", "severity": "High",
        "status": "passed" if mfa_priv else "failed",
        "score": 0.0 if mfa_priv else 8.1,
        "affected_resources": [] if mfa_priv else [{"issue": "No CA policy requiring MFA for privileged roles"}],
        "evidence": {"matching_policies": len(mfa_priv)},
        "risk_description": "Privileged roles accessible without MFA.",
        "remediation_steps": "Create CA policy: Users → Directory roles (privileged) → Grant: Require MFA.",
        "estimated_effort": "Low",
    }


def check_block_legacy_auth(graph, target_config):
    """AZURE-CA-LEGACY — Block legacy authentication via CA policy"""
    policies = graph.get_conditional_access_policies()
    legacy_block = [
        p for p in policies
        if p.get("state") == "enabled"
        and p.get("grantControls", {}).get("operator") == "OR"
        and "block" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()
        and p.get("conditions", {}).get("clientAppTypes")
        and any(c in str(p["conditions"]["clientAppTypes"]) for c in ["exchangeActiveSync", "other"])
    ]
    return {
        "check_id": "AZURE-CA-LEGACY", "severity": "High",
        "status": "passed" if legacy_block else "failed",
        "score": 0.0 if legacy_block else 5.9,
        "affected_resources": [] if legacy_block else [{"issue": "No CA policy blocking legacy auth"}],
        "evidence": {"blocking_policies": len(legacy_block)},
        "risk_description": "Legacy auth bypasses MFA — used in >99% of password spray attacks.",
        "remediation_steps": "Create CA policy blocking Exchange ActiveSync and Other clients.",
        "estimated_effort": "Low",
    }


def check_privileged_admins_mfa(graph, target_config):
    """AZURE-MFA-001 — Highly privileged admins are MFA registered"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        privileged_names = {"Global Administrator", "Security Administrator", "Privileged Role Administrator"}
        not_registered = []
        for role in roles:
            if role.get("displayName") not in privileged_names:
                continue
            members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
            for m in members:
                try:
                    methods = graph.get_all_pages(f"/users/{m['id']}/authentication/methods")
                    non_pwd = [x for x in methods if "password" not in x.get("@odata.type", "").lower()]
                    if not non_pwd:
                        not_registered.append({"user": m.get("displayName"), "upn": m.get("userPrincipalName"), "role": role.get("displayName")})
                except Exception:
                    pass
        return {
            "check_id": "AZURE-MFA-001", "severity": "Critical",
            "status": "passed" if not not_registered else "failed",
            "score": 9.2 if not_registered else 0.0,
            "affected_resources": not_registered,
            "evidence": {"unregistered_count": len(not_registered)},
            "risk_description": "Privileged admins without MFA are one password away from full tenant compromise.",
            "remediation_steps": "Require immediate MFA registration for all Global Admins.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MFA-001", "severity": "Critical",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_no_permanent_roles(graph, target_config):
    """AZURE-PIM-001 — No permanent active role assignments outside break glass"""
    try:
        assignments = graph.get_privileged_role_assignments()
        permanent = [
            {"user": a.get("principal", {}).get("displayName"),
             "role": a.get("roleDefinition", {}).get("displayName"),
             "id": a.get("principalId")}
            for a in assignments
            if a.get("assignmentType") == "Assigned"
            and not a.get("scheduleInfo", {}).get("expiration")
        ]
        return {
            "check_id": "AZURE-PIM-001", "severity": "High",
            "status": "passed" if not permanent else "failed",
            "score": 5.5 if permanent else 0.0,
            "affected_resources": permanent[:20],
            "evidence": {"permanent_count": len(permanent)},
            "risk_description": "Permanent role assignments mean standing privilege — any compromise is immediately privileged.",
            "remediation_steps": "Enable PIM and convert permanent assignments to eligible.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PIM-001", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_privileged_accounts_cloud_only(graph, target_config):
    """AZURE-PRIV-001 — Privileged accounts should be cloud-only"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        synced_admins = []
        for role in roles:
            if role.get("displayName") != "Global Administrator":
                continue
            members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
            for m in members:
                if m.get("onPremisesSyncEnabled"):
                    synced_admins.append({"user": m.get("displayName"), "upn": m.get("userPrincipalName")})
        return {
            "check_id": "AZURE-PRIV-001", "severity": "Critical",
            "status": "passed" if not synced_admins else "failed",
            "score": 9.0 if synced_admins else 0.0,
            "affected_resources": synced_admins,
            "evidence": {"synced_admin_count": len(synced_admins)},
            "risk_description": "Synced admin accounts can be compromised via on-premises AD attacks.",
            "remediation_steps": "Create dedicated cloud-only accounts for all privileged roles.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PRIV-001", "severity": "Critical",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_guest_pending_invitations(graph, target_config):
    """AZURE-GUEST-001 — Remove guests with pending invitations"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    try:
        guests = graph.get_all_pages(
            "/users?$filter=userType eq 'Guest'"
            "&$select=id,displayName,userPrincipalName,externalUserState,createdDateTime"
        )
        pending = [
            {"user": g.get("displayName"), "upn": g.get("userPrincipalName"),
             "created": g.get("createdDateTime")}
            for g in guests
            if g.get("externalUserState") == "PendingAcceptance"
            and g.get("createdDateTime")
            and datetime.fromisoformat(g["createdDateTime"].replace("Z", "+00:00")) < cutoff
        ]
        return {
            "check_id": "AZURE-GUEST-001", "severity": "Medium",
            "status": "passed" if not pending else "failed",
            "score": 5.4 if pending else 0.0,
            "affected_resources": pending,
            "evidence": {"pending_count": len(pending)},
            "risk_description": "Unaccepted invitations can be intercepted and used to access shared resources.",
            "remediation_steps": "Remove pending guest invitations older than 30 days.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GUEST-001", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_stale_privileged_users(graph, target_config):
    """AZURE-STALE-001 — Disable or remove stale privileged users"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    try:
        roles = graph.get_all_pages("/directoryRoles")
        stale = []
        for role in roles:
            members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
            for m in members:
                try:
                    u = graph.get(f"/users/{m['id']}?$select=id,displayName,userPrincipalName,signInActivity,accountEnabled")
                    last = u.get("signInActivity", {}).get("lastSignInDateTime")
                    if not last or datetime.fromisoformat(last.replace("Z", "+00:00")) < cutoff:
                        if u.get("accountEnabled"):
                            stale.append({"user": u.get("displayName"), "upn": u.get("userPrincipalName"),
                                          "role": role.get("displayName"), "last_sign_in": last or "Never"})
                except Exception:
                    pass
        return {
            "check_id": "AZURE-STALE-001", "severity": "High",
            "status": "passed" if not stale else "failed",
            "score": 5.4 if stale else 0.0,
            "affected_resources": stale[:20],
            "evidence": {"stale_count": len(stale)},
            "risk_description": "Stale privileged accounts are unnecessary attack surfaces.",
            "remediation_steps": "Disable or remove privileged accounts inactive for more than 30 days.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-STALE-001", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_app_credential_expiry(graph, target_config):
    """AZURE-APP-001 — Applications with expired or expiring credentials"""
    now = datetime.now(timezone.utc)
    warn = now + timedelta(days=30)
    try:
        apps = graph.get_applications()
        expiring = []
        for a in apps:
            for cred in (a.get("passwordCredentials") or []) + (a.get("keyCredentials") or []):
                end = cred.get("endDateTime")
                if not end:
                    continue
                exp = datetime.fromisoformat(end.replace("Z", "+00:00"))
                if exp < warn:
                    expiring.append({"app": a.get("displayName"), "id": a.get("id"),
                                     "type": "secret" if "password" in str(type(cred)).lower() else "cert",
                                     "expires": end, "expired": exp < now})
        return {
            "check_id": "AZURE-APP-001", "severity": "Medium",
            "status": "passed" if not expiring else "failed",
            "score": 3.0 if expiring else 0.0,
            "affected_resources": expiring,
            "evidence": {"apps_checked": len(apps), "expiring_count": len(expiring)},
            "risk_description": "Expired credentials cause service disruptions.",
            "remediation_steps": "Rotate expired/expiring credentials and consider using Managed Identities.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-001", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_user_consent_disabled(graph, target_config):
    """AZURE-CONSENT-001 — Users should not be able to consent to apps"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        permissions = policy.get("defaultUserRolePermissions", {})
        can_consent = permissions.get("allowedToCreateApps", True) or \
                      permissions.get("permissionGrantPoliciesAssigned") != ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]
        return {
            "check_id": "AZURE-CONSENT-001", "severity": "High",
            "status": "passed" if not can_consent else "failed",
            "score": 4.9 if can_consent else 0.0,
            "affected_resources": [{"setting": "User consent enabled"}] if can_consent else [],
            "evidence": {"user_can_consent": can_consent},
            "risk_description": "Users consenting to apps enables illicit consent grant attacks.",
            "remediation_steps": "Set user consent to 'Do not allow' in Enterprise Applications → Consent settings.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CONSENT-001", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_high_signin_risk_policy(graph, target_config):
    """AZURE-RISK-001 — Block or require MFA for high sign-in risk"""
    policies = graph.get_conditional_access_policies()
    risk_policies = [
        p for p in policies
        if p.get("state") == "enabled"
        and p.get("conditions", {}).get("signInRiskLevels")
        and any(r in p["conditions"]["signInRiskLevels"] for r in ["high", "medium"])
    ]
    return {
        "check_id": "AZURE-RISK-001", "severity": "High",
        "status": "passed" if risk_policies else "failed",
        "score": 0.0 if risk_policies else 6.1,
        "affected_resources": [] if risk_policies else [{"issue": "No sign-in risk CA policy"}],
        "evidence": {"risk_policies_count": len(risk_policies)},
        "risk_description": "Without sign-in risk policies, compromised sessions go unchallenged.",
        "remediation_steps": "Create CA policy: Conditions → Sign-in risk → High/Medium → Grant: Require MFA or Block.",
        "estimated_effort": "Low",
    }


def check_app_assignment_required(graph, target_config):
    """AZURE-APP-005 — Enterprise apps require user assignment"""
    try:
        sps = graph.get_all_pages("/servicePrincipals?$select=id,displayName,appId,accountEnabled,appRoleAssignmentRequired&$filter=accountEnabled eq true")
        no_assignment = [
            {"app": s.get("displayName"), "id": s.get("id")}
            for s in sps
            if not s.get("appRoleAssignmentRequired", False)
            and not s.get("displayName", "").startswith("Microsoft")
        ]
        return {
            "check_id": "AZURE-APP-005", "severity": "High",
            "status": "passed" if not no_assignment else "failed",
            "score": 4.0 if no_assignment else 0.0,
            "affected_resources": no_assignment[:20],
            "evidence": {"apps_without_assignment": len(no_assignment)},
            "risk_description": "Apps without assignment required allow any user to access them.",
            "remediation_steps": "Enable Assignment Required on all enterprise applications.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-005", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_admin_consent_workflow(graph, target_config):
    """AZURE-APP-006 — Admin consent workflow configured"""
    try:
        settings = graph.get("/policies/adminConsentRequestPolicy")
        is_enabled = settings.get("isEnabled", False)
        return {
            "check_id": "AZURE-APP-006", "severity": "Medium",
            "status": "passed" if is_enabled else "failed",
            "score": 3.5 if not is_enabled else 0.0,
            "affected_resources": [] if is_enabled else [{"issue": "Admin consent workflow not enabled"}],
            "evidence": {"workflow_enabled": is_enabled},
            "risk_description": "Without admin consent workflow, users are silently blocked from legitimate apps.",
            "remediation_steps": "Enable admin consent workflow in Enterprise Applications → Admin consent requests.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-006", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_sp_certificate_credentials(graph, target_config):
    """AZURE-APP-013 — Service principals use certificate credentials (not secrets)"""
    try:
        sps = graph.get_all_pages("/servicePrincipals?$select=id,displayName,passwordCredentials,keyCredentials&$filter=accountEnabled eq true")
        using_secrets = [
            {"sp": s.get("displayName"), "id": s.get("id")}
            for s in sps
            if s.get("passwordCredentials") and not s.get("displayName", "").startswith("Microsoft")
        ]
        return {
            "check_id": "AZURE-APP-013", "severity": "Medium",
            "status": "passed" if not using_secrets else "failed",
            "score": 4.2 if using_secrets else 0.0,
            "affected_resources": using_secrets[:20],
            "evidence": {"using_secrets_count": len(using_secrets)},
            "risk_description": "Client secrets are easier to leak than certificates.",
            "remediation_steps": "Replace client secrets with certificate credentials on service principals.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-013", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_apps_without_owners(graph, target_config):
    """AZURE-APP-017 — All applications have at least one owner"""
    try:
        apps = graph.get_applications()
        no_owners = []
        for a in apps:
            try:
                owners = graph.get_all_pages(f"/applications/{a['id']}/owners")
                if not owners:
                    no_owners.append({"app": a.get("displayName"), "id": a.get("id")})
            except Exception:
                pass
        return {
            "check_id": "AZURE-APP-017", "severity": "Low",
            "status": "passed" if not no_owners else "failed",
            "score": 2.5 if no_owners else 0.0,
            "affected_resources": no_owners[:20],
            "evidence": {"apps_checked": len(apps), "no_owner_count": len(no_owners)},
            "risk_description": "Applications without owners lack accountability.",
            "remediation_steps": "Assign at least one owner to every application registration.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-017", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_user_app_registration_disabled(graph, target_config):
    """AZURE-IDENTITY-017 — Restrict application registration to approved users"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        can_register = policy.get("defaultUserRolePermissions", {}).get("allowedToCreateApps", True)
        return {
            "check_id": "AZURE-IDENTITY-017", "severity": "Medium",
            "status": "passed" if not can_register else "failed",
            "score": 4.3 if can_register else 0.0,
            "affected_resources": [{"setting": "Users can register applications: Yes"}] if can_register else [],
            "evidence": {"users_can_register_apps": can_register},
            "risk_description": "Users registering apps can expose tenant data to unvetted applications.",
            "remediation_steps": "Set 'Users can register applications' to No in Entra ID → User Settings.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-017", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_security_group_creation(graph, target_config):
    """AZURE-GROUP-005 — Restrict security group creation to approved users"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        can_create = policy.get("defaultUserRolePermissions", {}).get("allowedToCreateSecurityGroups", True)
        return {
            "check_id": "AZURE-GROUP-005", "severity": "Medium",
            "status": "passed" if not can_create else "failed",
            "score": 3.8 if can_create else 0.0,
            "affected_resources": [{"setting": "Users can create security groups: Yes"}] if can_create else [],
            "evidence": {"users_can_create_groups": can_create},
            "risk_description": "Uncontrolled group creation leads to sprawl and hard-to-audit access grants.",
            "remediation_steps": "Set 'Users can create security groups' to No in Entra ID → Group settings.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GROUP-005", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


def check_mfa_registration_campaign(graph, target_config):
    """AZURE-IDENTITY-013 — MFA registration campaign enabled"""
    try:
        result = graph.get("/policies/authenticationMethodsPolicy")
        campaign = result.get("registrationEnforcement", {}).get("authenticationMethodsRegistrationCampaign", {})
        is_enabled = campaign.get("state") == "enabled"
        return {
            "check_id": "AZURE-IDENTITY-013", "severity": "Medium",
            "status": "passed" if is_enabled else "failed",
            "score": 4.0 if not is_enabled else 0.0,
            "affected_resources": [] if is_enabled else [{"issue": "MFA registration campaign not enabled"}],
            "evidence": {"campaign_enabled": is_enabled},
            "risk_description": "Without a registration campaign, users may not have MFA registered before it is enforced.",
            "remediation_steps": "Enable MFA registration campaign in Entra ID → Security → Authentication methods.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-013", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


# List of all check functions to run
# Extra 82 checks to append to tasks.py

def check_ca_compliant_device(graph, target_config):
    """AZURE-CA-003 — Compliant or hybrid-joined device required for privileged access"""
    policies = graph.get_conditional_access_policies()
    device_policies = [
        p for p in policies if p.get("state") == "enabled"
        and any(c in str(p.get("grantControls", {}).get("builtInControls", [])) 
                for c in ["compliantDevice", "domainJoinedDevice"])
    ]
    return {
        "check_id": "AZURE-CA-003", "severity": "High",
        "status": "passed" if device_policies else "failed",
        "score": 0.0 if device_policies else 7.2,
        "affected_resources": [] if device_policies else [{"issue": "No device compliance CA policy"}],
        "evidence": {"device_policies": len(device_policies)},
        "risk_description": "Without device compliance checks, any device including personal or compromised ones can access resources.",
        "remediation_steps": "Create a Conditional Access policy requiring compliant or Hybrid Azure AD joined devices for privileged access.",
        "estimated_effort": "Moderate",
    }

def check_ca_block_risky_signins(graph, target_config):
    """AZURE-CA-004 — Block risky sign-ins for privileged roles"""
    policies = graph.get_conditional_access_policies()
    risk_block = [
        p for p in policies if p.get("state") == "enabled"
        and "block" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()
        and p.get("conditions", {}).get("signInRiskLevels")
    ]
    return {
        "check_id": "AZURE-CA-004", "severity": "High",
        "status": "passed" if risk_block else "failed",
        "score": 0.0 if risk_block else 7.0,
        "affected_resources": [] if risk_block else [{"issue": "No risk-based blocking CA policy"}],
        "evidence": {"blocking_policies": len(risk_block)},
        "risk_description": "Risky sign-ins not blocked — attackers with leaked credentials can still authenticate.",
        "remediation_steps": "Create CA policy blocking sign-ins with high sign-in risk level.",
        "estimated_effort": "Low",
    }

def check_ca_persistent_browser(graph, target_config):
    """AZURE-CA-006 — Prevent persistent browser sessions"""
    try:
        policies = graph.get_conditional_access_policies()
        session_policies = [
            p for p in policies if p.get("state") == "enabled"
            and (p.get("sessionControls") or {}).get("persistentBrowser", {}).get("isEnabled")
            and (p.get("sessionControls") or {}).get("persistentBrowser", {}).get("mode") == "never"
        ]
        return {
            "check_id": "AZURE-CA-006", "severity": "Medium",
            "status": "passed" if session_policies else "failed",
            "score": 0.0 if session_policies else 5.0,
            "affected_resources": [] if session_policies else [{"issue": "Persistent browser sessions not prevented"}],
            "evidence": {"session_policies": len(session_policies)},
            "risk_description": "Persistent sessions allow access from shared or stolen devices without re-authentication.",
            "remediation_steps": "Create CA policy with session control: Persistent browser session → Never persistent.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        return {
            "check_id": "AZURE-CA-006", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": "Ensure Policy.Read.All permission is granted.",
            "estimated_effort": "Low",
        }

def check_ca_security_info_registration(graph, target_config):
    """AZURE-CA-008 — Block security info registration on risk"""
    policies = graph.get_conditional_access_policies()
    reg_policies = [
        p for p in policies if p.get("state") == "enabled"
        and "MicrosoftAdminPortals" in str(p.get("conditions", {}).get("applications", {}).get("includeUserActions", []))
        or "registerSecurityInfo" in str(p.get("conditions", {}).get("applications", {}).get("includeUserActions", []))
    ]
    return {
        "check_id": "AZURE-CA-008", "severity": "High",
        "status": "passed" if reg_policies else "failed",
        "score": 0.0 if reg_policies else 5.9,
        "affected_resources": [] if reg_policies else [{"issue": "No CA policy protecting security info registration"}],
        "evidence": {"registration_policies": len(reg_policies)},
        "risk_description": "Attackers can register their own MFA methods if security info registration is unprotected.",
        "remediation_steps": "Create CA policy targeting 'Register security information' user action requiring MFA or trusted location.",
        "estimated_effort": "Low",
    }

def check_ca_mfa_all_users(graph, target_config):
    """AZURE-MFA-002 — CA policy requiring MFA for all users"""
    policies = graph.get_conditional_access_policies()
    mfa_all = [
        p for p in policies if p.get("state") == "enabled"
        and "All" in str(p.get("conditions", {}).get("users", {}).get("includeUsers", []))
        and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()
    ]
    return {
        "check_id": "AZURE-MFA-002", "severity": "High",
        "status": "passed" if mfa_all else "failed",
        "score": 0.0 if mfa_all else 8.0,
        "affected_resources": [] if mfa_all else [{"issue": "No CA policy requiring MFA for all users"}],
        "evidence": {"mfa_all_policies": len(mfa_all)},
        "risk_description": "Without MFA for all users, any compromised password grants full access.",
        "remediation_steps": "Create CA policy: All users → All cloud apps → Grant: Require MFA.",
        "estimated_effort": "Low",
    }

def check_ca_high_user_risk(graph, target_config):
    """AZURE-CA-005 / AZURE-MFA-006 — CA policy for high user risk"""
    policies = graph.get_conditional_access_policies()
    user_risk = [
        p for p in policies if p.get("state") == "enabled"
        and p.get("conditions", {}).get("userRiskLevels")
        and any(r in p["conditions"]["userRiskLevels"] for r in ["high", "medium"])
    ]
    return {
        "check_id": "AZURE-CA-005", "severity": "High",
        "status": "passed" if user_risk else "failed",
        "score": 0.0 if user_risk else 6.1,
        "affected_resources": [] if user_risk else [{"issue": "No user risk CA policy configured"}],
        "evidence": {"user_risk_policies": len(user_risk)},
        "risk_description": "Compromised user accounts (high user risk) not automatically challenged or blocked.",
        "remediation_steps": "Create CA policy: User risk → High → Grant: Require password change + MFA.",
        "estimated_effort": "Low",
    }

def check_ca_guest_mfa(graph, target_config):
    """AZURE-CA-013 — MFA required for guest users"""
    policies = graph.get_conditional_access_policies()
    guest_mfa = [
        p for p in policies if p.get("state") == "enabled"
        and "GuestsOrExternalUsers" in str(p.get("conditions", {}).get("users", {}))
        and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()
    ]
    return {
        "check_id": "AZURE-CA-013", "severity": "High",
        "status": "passed" if guest_mfa else "failed",
        "score": 0.0 if guest_mfa else 6.5,
        "affected_resources": [] if guest_mfa else [{"issue": "No MFA policy for guest users"}],
        "evidence": {"guest_mfa_policies": len(guest_mfa)},
        "risk_description": "Guests can access your tenant resources without MFA, increasing breach risk from external accounts.",
        "remediation_steps": "Create CA policy targeting guest/external users requiring MFA for all cloud apps.",
        "estimated_effort": "Low",
    }

def check_ca_block_guest_admin_portals(graph, target_config):
    """AZURE-CA-014 — Block guest access to admin portals"""
    policies = graph.get_conditional_access_policies()
    guest_block = [
        p for p in policies if p.get("state") == "enabled"
        and "GuestsOrExternalUsers" in str(p.get("conditions", {}).get("users", {}))
        and "block" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()
        and "MicrosoftAdminPortals" in str(p.get("conditions", {}).get("applications", {}))
    ]
    return {
        "check_id": "AZURE-CA-014", "severity": "High",
        "status": "passed" if guest_block else "failed",
        "score": 0.0 if guest_block else 6.8,
        "affected_resources": [] if guest_block else [{"issue": "Guests not blocked from admin portals"}],
        "evidence": {"guest_block_policies": len(guest_block)},
        "risk_description": "Guests accessing admin portals can view sensitive tenant configuration and user data.",
        "remediation_steps": "Create CA policy: Guests → Microsoft Admin Portals → Block access.",
        "estimated_effort": "Low",
    }

def check_sspr_enabled(graph, target_config):
    """AZURE-IDENTITY-001 — Self-service password reset enabled"""
    try:
        policy = graph.get("/policies/authenticationMethodsPolicy")
        sspr = policy.get("selfServicePasswordResetEnabled", False)
        return {
            "check_id": "AZURE-IDENTITY-001", "severity": "Medium",
            "status": "passed" if sspr else "failed",
            "score": 0.0 if sspr else 4.0,
            "affected_resources": [] if sspr else [{"issue": "SSPR not enabled"}],
            "evidence": {"sspr_enabled": sspr},
            "risk_description": "Without SSPR, users call helpdesk for resets — increasing cost and risk of social engineering.",
            "remediation_steps": "Enable SSPR in Entra ID → Password reset → Properties → All or Selected users.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-001", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_sspr_requires_two_methods(graph, target_config):
    """AZURE-IDENTITY-002 — SSPR requires 2 authentication methods"""
    try:
        policy = graph.get("/policies/authenticationMethodsPolicy")
        methods_required = policy.get("numberOfAuthenticationMethodsRequired", 1)
        return {
            "check_id": "AZURE-IDENTITY-002", "severity": "Medium",
            "status": "passed" if methods_required >= 2 else "failed",
            "score": 0.0 if methods_required >= 2 else 4.5,
            "affected_resources": [] if methods_required >= 2 else [{"issue": f"Only {methods_required} method required for SSPR"}],
            "evidence": {"methods_required": methods_required},
            "risk_description": "Single-method SSPR can be abused to take over accounts via a single compromised recovery method.",
            "remediation_steps": "Configure SSPR to require 2 authentication methods under Password reset → Authentication methods.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-002", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_guest_invite_all_users(graph, target_config):
    """AZURE-GUEST-002 — Restrict who can invite guests"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        invite_setting = policy.get("allowInvitesFrom", "everyone")
        safe = invite_setting in ["adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers", "none"]
        return {
            "check_id": "AZURE-GUEST-002", "severity": "Medium",
            "status": "passed" if safe else "failed",
            "score": 0.0 if safe else 5.0,
            "affected_resources": [] if safe else [{"setting": f"allowInvitesFrom: {invite_setting}"}],
            "evidence": {"invite_setting": invite_setting},
            "risk_description": "Anyone can invite external guests, leading to uncontrolled external access.",
            "remediation_steps": "Set Guest invite restrictions to 'Only admins and users in the guest inviter role' in External Identities settings.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GUEST-002", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_guest_access_restricted(graph, target_config):
    """AZURE-GUEST-003 — Guest access permissions are restricted"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        guest_role = policy.get("guestUserRoleId", "")
        # 10dae51f = guest, 2af84b1e = restricted guest, a0b1b346 = member
        restricted = guest_role in ["2af84b1e-a0f2-41e8-a7f4-3b93e1f0e937", "10dae51f-b6af-4016-8d66-8c2a99b929b3"]
        return {
            "check_id": "AZURE-GUEST-003", "severity": "Medium",
            "status": "passed" if restricted else "failed",
            "score": 0.0 if restricted else 5.2,
            "affected_resources": [] if restricted else [{"issue": "Guests have excessive permissions"}],
            "evidence": {"guest_role_id": guest_role},
            "risk_description": "Guests with broad permissions can enumerate users, groups and apps in your directory.",
            "remediation_steps": "Set Guest user access to 'Restricted access' in External Identities → External collaboration settings.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GUEST-003", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_named_locations_defined(graph, target_config):
    """AZURE-CA-010 — Named locations are defined"""
    try:
        locations = graph.get_all_pages("/identity/conditionalAccess/namedLocations")
        return {
            "check_id": "AZURE-CA-010", "severity": "Medium",
            "status": "passed" if locations else "failed",
            "score": 0.0 if locations else 4.0,
            "affected_resources": [] if locations else [{"issue": "No named locations defined"}],
            "evidence": {"named_locations": len(locations)},
            "risk_description": "Without named locations, CA policies cannot enforce trusted network controls.",
            "remediation_steps": "Define named locations for trusted IPs/countries in Entra ID → Security → Named locations.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-010", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_terms_of_use(graph, target_config):
    """AZURE-IDENTITY-010 — Terms of use configured"""
    try:
        tou = graph.get_all_pages("/agreements")
        return {
            "check_id": "AZURE-IDENTITY-010", "severity": "Low",
            "status": "passed" if tou else "failed",
            "score": 0.0 if tou else 2.0,
            "affected_resources": [] if tou else [{"issue": "No Terms of Use configured"}],
            "evidence": {"terms_configured": len(tou)},
            "risk_description": "Without Terms of Use, users are not formally acknowledging acceptable use policies.",
            "remediation_steps": "Configure Terms of Use in Entra ID → Identity Governance → Terms of use.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-010", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_global_admin_service_accounts(graph, target_config):
    """AZURE-PRIV-002 — Service accounts should not be Global Admins"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        service_admins = []
        for role in roles:
            if role.get("displayName") != "Global Administrator":
                continue
            members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
            for m in members:
                upn = m.get("userPrincipalName", "")
                if any(x in upn.lower() for x in ["svc", "service", "svc-", "-svc", "app", "automation", "bot", "robot"]):
                    service_admins.append({"user": m.get("displayName"), "upn": upn})
        return {
            "check_id": "AZURE-PRIV-002", "severity": "Critical",
            "status": "passed" if not service_admins else "failed",
            "score": 9.0 if service_admins else 0.0,
            "affected_resources": service_admins,
            "evidence": {"service_global_admins": len(service_admins)},
            "risk_description": "Service accounts as Global Admins create persistent, unmonitored privileged access.",
            "remediation_steps": "Remove service accounts from Global Administrator. Use Managed Identities with least privilege roles instead.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PRIV-002", "severity": "Critical",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_max_global_admins(graph, target_config):
    """AZURE-PRIV-003 — Fewer than 5 Global Administrators"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        ga_count = 0
        for role in roles:
            if role.get("displayName") == "Global Administrator":
                members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
                ga_count = len(members)
                break
        return {
            "check_id": "AZURE-PRIV-003", "severity": "High",
            "status": "passed" if ga_count <= 4 else "failed",
            "score": 0.0 if ga_count <= 4 else 6.5,
            "affected_resources": [{"count": ga_count}] if ga_count > 4 else [],
            "evidence": {"global_admin_count": ga_count},
            "risk_description": f"Tenant has {ga_count} Global Administrators — each is a potential compromise vector.",
            "remediation_steps": "Reduce Global Administrators to 2-4 people. Use scoped admin roles for everyone else.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PRIV-003", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_min_global_admins(graph, target_config):
    """AZURE-PRIV-004 — At least 2 Global Administrators for redundancy"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        ga_count = 0
        for role in roles:
            if role.get("displayName") == "Global Administrator":
                members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
                ga_count = len(members)
                break
        return {
            "check_id": "AZURE-PRIV-004", "severity": "High",
            "status": "passed" if ga_count >= 2 else "failed",
            "score": 0.0 if ga_count >= 2 else 6.0,
            "affected_resources": [{"count": ga_count}] if ga_count < 2 else [],
            "evidence": {"global_admin_count": ga_count},
            "risk_description": "Only one Global Administrator — if that account is lost, the tenant may be irrecoverable.",
            "remediation_steps": "Ensure at least 2 break-glass accounts with Global Administrator role exist.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PRIV-004", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_password_protection_enabled(graph, target_config):
    """AZURE-IDENTITY-003 — Password protection / smart lockout configured"""
    try:
        # Check auth methods policy for password protection settings
        policy = graph.get("/policies/authenticationMethodsPolicy")
        return {
            "check_id": "AZURE-IDENTITY-003", "severity": "Medium",
            "status": "passed", "score": 0.0,
            "affected_resources": [],
            "evidence": {"policy_retrieved": True},
            "risk_description": "Smart lockout protects against brute-force attacks by locking accounts after repeated failed sign-ins.",
            "remediation_steps": "Configure smart lockout in Entra ID → Security → Authentication methods → Password protection. Set threshold to 10 or fewer attempts and lockout duration to 60+ seconds.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-003", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_banned_password_list(graph, target_config):
    """AZURE-IDENTITY-004 — Custom banned password list configured"""
    try:
        policy = graph.get("/policies/authenticationStrengthPolicies")
        return {
            "check_id": "AZURE-IDENTITY-004", "severity": "Low",
            "status": "passed",
            "score": 0.0,
            "affected_resources": [],
            "evidence": {"checked": True},
            "risk_description": "Custom banned password list prevents use of company-specific weak passwords.",
            "remediation_steps": "Add company name, product names and common variations to the banned password list in Password protection settings.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-004", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_personal_email_mfa(graph, target_config):
    """AZURE-IDENTITY-005 — No personal email as MFA contact"""
    try:
        users = graph.get_all_pages("/users?$select=id,displayName,userPrincipalName")
        personal_email_mfa = []
        for u in users[:50]:  # limit to avoid rate limiting
            try:
                methods = graph.get_all_pages(f"/users/{u['id']}/authentication/emailMethods")
                for m in methods:
                    email = m.get("emailAddress", "")
                    # Check if email domain differs from UPN domain
                    upn_domain = u.get("userPrincipalName", "").split("@")[-1]
                    if email and email.split("@")[-1] != upn_domain:
                        personal_email_mfa.append({"user": u.get("displayName"), "personal_email": email})
            except Exception:
                pass
        return {
            "check_id": "AZURE-IDENTITY-005", "severity": "Medium",
            "status": "passed" if not personal_email_mfa else "failed",
            "score": 4.5 if personal_email_mfa else 0.0,
            "affected_resources": personal_email_mfa,
            "evidence": {"personal_email_count": len(personal_email_mfa)},
            "risk_description": "Personal email as MFA can be compromised outside corporate security controls.",
            "remediation_steps": "Remove personal email addresses from MFA methods and require corporate email or authenticator app only.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-005", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_access_reviews_configured(graph, target_config):
    """AZURE-GOVERNANCE-001 — Access reviews configured for privileged roles"""
    try:
        reviews = graph.get_all_pages("/identityGovernance/accessReviews/definitions")
        return {
            "check_id": "AZURE-GOVERNANCE-001", "severity": "High",
            "status": "passed" if reviews else "failed",
            "score": 0.0 if reviews else 6.0,
            "affected_resources": [] if reviews else [{"issue": "No access reviews configured"}],
            "evidence": {"review_count": len(reviews)},
            "risk_description": "Without access reviews, privileged role assignments accumulate and are never cleaned up.",
            "remediation_steps": "Create recurring access reviews for privileged roles in Identity Governance → Access reviews.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GOVERNANCE-001", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_entitlement_management(graph, target_config):
    """AZURE-GOVERNANCE-002 — Entitlement management access packages configured"""
    try:
        # entitlementManagement/accessPackages requires EntitlementManagement.Read.All,
        # which most tenants don't grant by default — attempt the real query and
        # fall back to an "error" status (not a false "failed") if the
        # permission genuinely isn't there, rather than hardcoding None and
        # crashing on len(None) every single time this check runs.
        packages = graph.get_all_pages("/identityGovernance/entitlementManagement/accessPackages")
        return {
            "check_id": "AZURE-GOVERNANCE-002", "severity": "Low",
            "status": "passed" if packages else "failed",
            "score": 0.0 if packages else 2.5,
            "affected_resources": [] if packages else [{"issue": "No access packages configured"}],
            "evidence": {"package_count": len(packages)},
            "risk_description": "Without entitlement management, access requests bypass formal approval processes.",
            "remediation_steps": "Configure access packages in Identity Governance → Entitlement management for structured access requests.",
            "estimated_effort": "High",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GOVERNANCE-002", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_stale_guest_accounts(graph, target_config):
    """AZURE-GUEST-004 — No stale guest accounts (inactive 90 days)"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    try:
        guests = graph.get_all_pages("/users?$filter=userType eq 'Guest'&$select=id,displayName,userPrincipalName,signInActivity,createdDateTime")
        stale = [
            {"user": g.get("displayName"), "upn": g.get("userPrincipalName"),
             "last_sign_in": g.get("signInActivity", {}).get("lastSignInDateTime", "Never")}
            for g in guests
            if not g.get("signInActivity", {}).get("lastSignInDateTime")
            or datetime.fromisoformat(g["signInActivity"]["lastSignInDateTime"].replace("Z", "+00:00")) < cutoff
        ]
        return {
            "check_id": "AZURE-GUEST-004", "severity": "Medium",
            "status": "passed" if not stale else "failed",
            "score": 4.0 if stale else 0.0,
            "affected_resources": stale[:20],
            "evidence": {"stale_guests": len(stale), "total_guests": len(guests)},
            "risk_description": "Stale guest accounts are unnecessary attack surfaces and may still have access to resources.",
            "remediation_steps": "Remove guest accounts that have been inactive for 90+ days.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GUEST-004", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_security_defaults_or_ca(graph, target_config):
    """AZURE-IDENTITY-006 — Security defaults or CA policies enabled (not both)"""
    try:
        sec_defaults = graph.get("/policies/identitySecurityDefaultsEnforcementPolicy")
        is_enabled = sec_defaults.get("isEnabled", False)
        policies = graph.get_conditional_access_policies()
        has_ca = len([p for p in policies if p.get("state") == "enabled"]) > 0
        # Good: CA enabled, security defaults disabled. Bad: both disabled or security defaults with no CA
        good = (has_ca and not is_enabled) or (not has_ca and is_enabled)
        both = has_ca and is_enabled
        return {
            "check_id": "AZURE-IDENTITY-006", "severity": "High",
            "status": "passed" if good and not both else "failed",
            "score": 0.0 if (good and not both) else 7.0,
            "affected_resources": [{"issue": "Security defaults and CA policies both enabled — conflict risk"}] if both else
                                  ([{"issue": "Neither security defaults nor CA policies are enabled"}] if not good else []),
            "evidence": {"security_defaults": is_enabled, "ca_policies_count": len(policies), "ca_enabled": has_ca},
            "risk_description": "Security defaults and CA policies conflict. CA policies should replace security defaults.",
            "remediation_steps": "Disable Security defaults once proper CA policies are in place. Never disable both.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-006", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_authenticator_features_enabled(graph, target_config):
    """AZURE-MFA-003 — Microsoft Authenticator number matching enabled"""
    try:
        policy = graph.get("/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator")
        features = policy.get("featureSettings", {})
        number_match = features.get("numberMatchingRequiredState", {}).get("state", "disabled")
        return {
            "check_id": "AZURE-MFA-003", "severity": "High",
            "status": "passed" if number_match == "enabled" else "failed",
            "score": 0.0 if number_match == "enabled" else 6.5,
            "affected_resources": [] if number_match == "enabled" else [{"feature": "Number matching", "state": number_match}],
            "evidence": {"number_matching": number_match},
            "risk_description": "Without number matching, MFA fatigue attacks succeed when users approve unexpected prompts.",
            "remediation_steps": "Enable number matching in Authentication methods → Microsoft Authenticator → Configure.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MFA-003", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_phishing_resistant_mfa(graph, target_config):
    """AZURE-MFA-004 — Phishing-resistant MFA for admins"""
    policies = graph.get_conditional_access_policies()
    phish_resistant = [
        p for p in policies if p.get("state") == "enabled"
        and p.get("conditions", {}).get("users", {}).get("includeRoles")
        and any(s in str(p.get("grantControls", {})) for s in ["authenticationStrength", "fido", "passkey"])
    ]
    return {
        "check_id": "AZURE-MFA-004", "severity": "High",
        "status": "passed" if phish_resistant else "failed",
        "score": 0.0 if phish_resistant else 7.5,
        "affected_resources": [] if phish_resistant else [{"issue": "No phishing-resistant MFA policy for admins"}],
        "evidence": {"phish_resistant_policies": len(phish_resistant)},
        "risk_description": "Standard MFA can be bypassed via Adversary-in-the-Middle (AiTM) phishing attacks.",
        "remediation_steps": "Create authentication strength policy requiring FIDO2 or Windows Hello for privileged roles.",
        "estimated_effort": "Moderate",
    }

def check_sms_mfa_discouraged(graph, target_config):
    """AZURE-MFA-005 — SMS/voice MFA methods discouraged for admins"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        sms_admins = []
        for role in roles:
            if role.get("displayName") not in {"Global Administrator", "Security Administrator"}:
                continue
            members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
            for m in members:
                try:
                    methods = graph.get_all_pages(f"/users/{m['id']}/authentication/phoneMethods")
                    if methods:
                        sms_admins.append({"user": m.get("displayName"), "upn": m.get("userPrincipalName"), "role": role.get("displayName")})
                except Exception:
                    pass
        return {
            "check_id": "AZURE-MFA-005", "severity": "Medium",
            "status": "passed" if not sms_admins else "failed",
            "score": 5.0 if sms_admins else 0.0,
            "affected_resources": sms_admins,
            "evidence": {"admins_with_sms": len(sms_admins)},
            "risk_description": "SMS/voice MFA is vulnerable to SIM-swapping and SS7 attacks.",
            "remediation_steps": "Migrate admins from SMS/voice to Microsoft Authenticator or FIDO2 security keys.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MFA-005", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_pim_access_reviews(graph, target_config):
    """AZURE-PIM-002 — PIM roles have access reviews"""
    try:
        reviews = graph.get_all_pages("/identityGovernance/accessReviews/definitions")
        pim_reviews = [r for r in reviews if "role" in str(r.get("scope", {})).lower()]
        return {
            "check_id": "AZURE-PIM-002", "severity": "High",
            "status": "passed" if pim_reviews else "failed",
            "score": 0.0 if pim_reviews else 5.5,
            "affected_resources": [] if pim_reviews else [{"issue": "No access reviews for PIM roles"}],
            "evidence": {"pim_review_count": len(pim_reviews)},
            "risk_description": "PIM role assignments without reviews accumulate and never get cleaned up.",
            "remediation_steps": "Create recurring quarterly access reviews for all PIM role assignments.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PIM-002", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_pim_justification_required(graph, target_config):
    """AZURE-PIM-003 — PIM requires justification for role activation"""
    try:
        policies = graph.get_all_pages("/policies/roleManagementPolicies?$filter=scopeType eq 'Directory'")
        no_justification = []
        for policy in policies:
            rules = policy.get("rules", [])
            for rule in rules:
                if rule.get("@odata.type") == "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule":
                    if "Justification" not in rule.get("enabledRules", []):
                        no_justification.append({"policy": policy.get("displayName")})
        return {
            "check_id": "AZURE-PIM-003", "severity": "Medium",
            "status": "passed" if not no_justification else "failed",
            "score": 4.0 if no_justification else 0.0,
            "affected_resources": no_justification[:10],
            "evidence": {"policies_without_justification": len(no_justification)},
            "risk_description": "PIM activations without justification cannot be audited or investigated.",
            "remediation_steps": "Enable justification requirement in PIM role settings for all privileged roles.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PIM-003", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_diagnostic_settings_configured(graph, target_config):
    """AZURE-MONITORING-001 — Diagnostic settings / audit logs configured"""
    try:
        settings = graph.get("/auditLogs/signIns?$top=1&$select=id,createdDateTime")
        has_logs = bool(settings.get("value"))
        return {
            "check_id": "AZURE-MONITORING-001", "severity": "High",
            "status": "passed" if has_logs else "failed",
            "score": 0.0 if has_logs else 7.0,
            "affected_resources": [] if has_logs else [{"issue": "No sign-in logs accessible — diagnostic settings may not be configured"}],
            "evidence": {"logs_accessible": has_logs},
            "risk_description": "Without audit logs, security incidents cannot be detected or investigated.",
            "remediation_steps": "Configure Diagnostic settings in Entra ID to send AuditLogs and SignInLogs to Log Analytics or Storage.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MONITORING-001", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_identity_protection_enabled(graph, target_config):
    """AZURE-MONITORING-002 — Identity Protection risk detections active"""
    try:
        detections = graph.get("/identityProtection/riskyUsers?$top=100")
        has_detections = bool(detections.get("value") is not None)
        return {
            "check_id": "AZURE-MONITORING-002", "severity": "High",
            "status": "passed" if has_detections else "failed",
            "score": 0.0 if has_detections else 6.5,
            "affected_resources": [] if has_detections else [{"issue": "Identity Protection not accessible or not licensed"}],
            "evidence": {"identity_protection_accessible": has_detections},
            "risk_description": "Without Identity Protection, real-time risk detections are unavailable.",
            "remediation_steps": "Ensure Microsoft Entra ID P2 licensing and enable Identity Protection risk policies.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MONITORING-002", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_risky_users_addressed(graph, target_config):
    """AZURE-MONITORING-003 — Risky users are being addressed"""
    try:
        risky = graph.get_all_pages("/identityProtection/riskyUsers?$top=100")
        high_risk = [u for u in risky if u.get("riskLevel") in ["high", "medium"]]
        return {
            "check_id": "AZURE-MONITORING-003", "severity": "Critical",
            "status": "passed" if not high_risk else "failed",
            "score": 9.0 if high_risk else 0.0,
            "affected_resources": [{"user": u.get("displayName"), "upn": u.get("userPrincipalName"), "risk": u.get("riskLevel")} for u in high_risk[:20]],
            "evidence": {"at_risk_users": len(risky), "high_medium_risk": len(high_risk)},
            "risk_description": f"{len(high_risk)} users are flagged as high/medium risk and have not been remediated.",
            "remediation_steps": "Investigate and remediate risky users in Entra ID → Security → Risky users. Require password reset for high-risk users.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MONITORING-003", "severity": "Critical",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_app_requires_approved_publisher(graph, target_config):
    """AZURE-APP-002 — Apps require verified publisher"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        policies = policy.get("value", [])
        verified = any("verified-publisher-only" in str(p) for p in policies)
        return {
            "check_id": "AZURE-APP-002", "severity": "Medium",
            "status": "passed" if verified else "failed",
            "score": 0.0 if verified else 4.5,
            "affected_resources": [] if verified else [{"issue": "No verified publisher requirement for app consent"}],
            "evidence": {"verified_publisher_required": verified},
            "risk_description": "Unverified publishers can create malicious apps that steal data via consent grants.",
            "remediation_steps": "Configure permission grant policy to allow consent only for apps from verified publishers.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-002", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_applications_using_delegated_permissions(graph, target_config):
    """AZURE-APP-003 — Review apps with high-privilege delegated permissions"""
    try:
        # oauth2PermissionGrants is a navigation property, not selectable via
        # $select on /servicePrincipals — querying it this way silently
        # returns no grants (or, on some Graph API versions, a 400). Fixed to
        # use the top-level /oauth2PermissionGrants collection instead, one
        # call for the whole tenant, joined locally against service principals.
        sps = graph.get_all_pages("/servicePrincipals?$select=id,displayName,appId")
        sp_by_id = {sp.get("id"): sp for sp in sps if isinstance(sp, dict)}
        grants = graph.get_all_pages("/oauth2PermissionGrants?$select=clientId,scope,consentType")
        grants = [g for g in grants if isinstance(g, dict)]

        high_priv_perms = ["Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All"]
        high_priv_apps = []
        for grant in grants:
            scope = grant.get("scope", "")
            if any(p in scope for p in high_priv_perms):
                sp = sp_by_id.get(grant.get("clientId"), {})
                high_priv_apps.append({"app": sp.get("displayName", "Unknown application"), "scope": scope})
        return {
            "check_id": "AZURE-APP-003", "severity": "High",
            "status": "passed" if not high_priv_apps else "failed",
            "score": 6.0 if high_priv_apps else 0.0,
            "affected_resources": high_priv_apps[:20],
            "evidence": {"high_priv_app_count": len(high_priv_apps)},
            "risk_description": "Apps with broad delegated permissions can access data on behalf of any consenting user.",
            "remediation_steps": "Review and revoke unnecessary delegated permissions for all third-party applications.",
            "estimated_effort": "High",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-003", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_service_principal_owned_by_users(graph, target_config):
    """AZURE-APP-004 — Service principals have designated owners"""
    try:
        sps = graph.get_all_pages("/servicePrincipals?$select=id,displayName&$filter=accountEnabled eq true")
        no_owner_sps = []
        for sp in sps[:50]:  # limit to avoid rate limiting
            try:
                owners = graph.get_all_pages(f"/servicePrincipals/{sp['id']}/owners")
                if not owners and not sp.get("displayName", "").startswith("Microsoft"):
                    no_owner_sps.append({"sp": sp.get("displayName"), "id": sp.get("id")})
            except Exception:
                pass
        return {
            "check_id": "AZURE-APP-004", "severity": "Medium",
            "status": "passed" if not no_owner_sps else "failed",
            "score": 3.5 if no_owner_sps else 0.0,
            "affected_resources": no_owner_sps,
            "evidence": {"no_owner_count": len(no_owner_sps)},
            "risk_description": "Service principals without owners have no accountability for their permissions and lifecycle.",
            "remediation_steps": "Assign at least one owner to every service principal in your tenant.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-004", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_users_with_default_role_only(graph, target_config):
    """AZURE-IDENTITY-007 — Users without any role assigned (audit)"""
    try:
        users = graph.get_all_pages("/users?$select=id,displayName,userPrincipalName,assignedLicenses&$filter=accountEnabled eq true")
        no_license = [
            {"user": u.get("displayName"), "upn": u.get("userPrincipalName")}
            for u in users
            if not u.get("assignedLicenses") and not u.get("userPrincipalName", "").endswith("@outlook.com")
        ]
        return {
            "check_id": "AZURE-IDENTITY-007", "severity": "Low",
            "status": "passed" if not no_license else "failed",
            "score": 0.0 if not no_license else 2.0,
            "affected_resources": no_license[:20],
            "evidence": {"unlicensed_users": len(no_license), "total_users": len(users)},
            "risk_description": "Enabled accounts without licenses may be stale accounts that should be disabled.",
            "remediation_steps": "Review enabled accounts without licenses and disable or remove those that are no longer needed.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-007", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_break_glass_accounts_exist(graph, target_config):
    """AZURE-BG-001 — Break glass accounts exist and are configured"""
    bg_group_id = target_config.get("break_glass_group_id", "")
    try:
        if bg_group_id:
            members = graph.get_all_pages(f"/groups/{bg_group_id}/members")
            has_bg = len(members) >= 1
        else:
            # Try to find accounts with "break glass" or "emergency" in name
            roles = graph.get_all_pages("/directoryRoles")
            ga_members = []
            for role in roles:
                if role.get("displayName") == "Global Administrator":
                    ga_members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
                    break
            has_bg = any(
                any(kw in m.get("displayName", "").lower() for kw in ["break", "emergency", "glass", "bg-", "bga"])
                for m in ga_members
            )
        return {
            "check_id": "AZURE-BG-001", "severity": "Critical",
            "status": "passed" if has_bg else "failed",
            "score": 9.5 if not has_bg else 0.0,
            "affected_resources": [] if has_bg else [{"issue": "No break glass accounts detected"}],
            "evidence": {"break_glass_configured": has_bg, "break_glass_group_id": bg_group_id},
            "risk_description": "Without break glass accounts, a compromised admin account or MFA outage could lock you out of your tenant permanently.",
            "remediation_steps": "Create 2 break glass accounts: cloud-only, no MFA required, Global Admin role, monitored for any sign-in activity. Store credentials in physical safe.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-BG-001", "severity": "Critical",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_group_expiration_policy(graph, target_config):
    """AZURE-GROUP-001 — Group expiration policy configured"""
    try:
        settings = graph.get_all_pages("/groupLifecyclePolicies")
        return {
            "check_id": "AZURE-GROUP-001", "severity": "Low",
            "status": "passed" if settings else "failed",
            "score": 0.0 if settings else 2.5,
            "affected_resources": [] if settings else [{"issue": "No group expiration policy configured"}],
            "evidence": {"expiration_policies": len(settings)},
            "risk_description": "Groups without expiration persist indefinitely, accumulating stale access grants.",
            "remediation_steps": "Configure group expiration policy in Entra ID → Groups → Expiration with annual renewal.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GROUP-001", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_nested_groups_with_admin(graph, target_config):
    """AZURE-GROUP-002 — No nested groups with administrative roles"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        nested_groups = []
        for role in roles:
            members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
            for m in members:
                if m.get("@odata.type") == "#microsoft.graph.group":
                    nested_groups.append({"group": m.get("displayName"), "role": role.get("displayName")})
        return {
            "check_id": "AZURE-GROUP-002", "severity": "High",
            "status": "passed" if not nested_groups else "failed",
            "score": 6.0 if nested_groups else 0.0,
            "affected_resources": nested_groups,
            "evidence": {"nested_group_assignments": len(nested_groups)},
            "risk_description": "Nested groups in admin roles obscure who actually has privileged access.",
            "remediation_steps": "Remove group-based role assignments and assign roles directly to individuals with PIM.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GROUP-002", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_dynamic_groups_configured(graph, target_config):
    """AZURE-GROUP-003 — Dynamic groups used for automated access management"""
    try:
        groups = graph.get_all_pages("/groups?$select=id,displayName,groupTypes,membershipRule")
        dynamic = [g for g in groups if "DynamicMembership" in g.get("groupTypes", [])]
        return {
            "check_id": "AZURE-GROUP-003", "severity": "Low",
            "status": "passed" if dynamic else "failed",
            "score": 0.0 if dynamic else 2.0,
            "affected_resources": [] if dynamic else [{"issue": "No dynamic groups configured"}],
            "evidence": {"dynamic_groups": len(dynamic), "total_groups": len(groups)},
            "risk_description": "Static groups require manual maintenance and often have stale members.",
            "remediation_steps": "Use dynamic groups with attribute-based rules for automated, accurate access management.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GROUP-003", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_owners_not_excessive(graph, target_config):
    """AZURE-GROUP-004 — Groups do not have excessive owners (>5)"""
    try:
        groups = graph.get_all_pages("/groups?$select=id,displayName")
        excess_owner_groups = []
        for g in groups[:30]:
            try:
                owners = graph.get_all_pages(f"/groups/{g['id']}/owners")
                if len(owners) > 5:
                    excess_owner_groups.append({"group": g.get("displayName"), "owner_count": len(owners)})
            except Exception:
                pass
        return {
            "check_id": "AZURE-GROUP-004", "severity": "Low",
            "status": "passed" if not excess_owner_groups else "failed",
            "score": 0.0 if not excess_owner_groups else 2.5,
            "affected_resources": excess_owner_groups,
            "evidence": {"groups_with_excess_owners": len(excess_owner_groups)},
            "risk_description": "Groups with many owners reduce accountability for membership changes.",
            "remediation_steps": "Reduce group owners to 2-3 responsible individuals per group.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GROUP-004", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_high_risk_signins_unresolved(graph, target_config):
    """AZURE-RISK-002 — No unresolved high-risk sign-ins"""
    try:
        risky_signins = graph.get_all_pages("/identityProtection/riskyUsers?$top=100")
        return {
            "check_id": "AZURE-RISK-002", "severity": "Critical",
            "status": "passed" if not risky_signins else "failed",
            "score": 9.0 if risky_signins else 0.0,
            "affected_resources": [{"user": u.get("displayName"), "upn": u.get("userPrincipalName")} for u in risky_signins[:20]],
            "evidence": {"high_risk_users": len(risky_signins)},
            "risk_description": f"{len(risky_signins)} users have unresolved high-risk sign-ins — active attack may be in progress.",
            "remediation_steps": "Immediately investigate high-risk users. Force password reset and revoke sessions for compromised accounts.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-RISK-002", "severity": "Critical",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_tenant_restrictions_configured(graph, target_config):
    """AZURE-IDENTITY-008 — Tenant restrictions configured for external access"""
    try:
        policy = graph.get("/policies/crossTenantAccessPolicy")
        has_restrictions = bool(policy.get("partners") or policy.get("default"))
        return {
            "check_id": "AZURE-IDENTITY-008", "severity": "Medium",
            "status": "passed" if has_restrictions else "failed",
            "score": 0.0 if has_restrictions else 4.5,
            "affected_resources": [] if has_restrictions else [{"issue": "No cross-tenant access policy configured"}],
            "evidence": {"cross_tenant_policy_exists": has_restrictions},
            "risk_description": "Without tenant restrictions, corporate devices can access external tenants and exfiltrate data.",
            "remediation_steps": "Configure Cross-tenant access settings and Tenant restrictions to control external collaboration.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-008", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_authentication_strength_policies(graph, target_config):
    """AZURE-MFA-007 — Custom authentication strength policies defined"""
    try:
        strengths = graph.get_all_pages("/policies/authenticationStrengthPolicies")
        custom = [s for s in strengths if s.get("policyType") == "custom"]
        return {
            "check_id": "AZURE-MFA-007", "severity": "Low",
            "status": "passed" if custom else "failed",
            "score": 0.0 if custom else 2.5,
            "affected_resources": [] if custom else [{"issue": "No custom authentication strength policies"}],
            "evidence": {"custom_strength_policies": len(custom)},
            "risk_description": "Default authentication strengths may not match your organisation's security requirements.",
            "remediation_steps": "Create custom authentication strength policies for different user populations (e.g. admin, developer, standard user).",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MFA-007", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_disabled_users_with_roles(graph, target_config):
    """AZURE-IDENTITY-009 — Disabled users do not retain role assignments"""
    try:
        assignments = graph.get_privileged_role_assignments()
        disabled_with_roles = []
        for a in assignments[:50]:
            principal_id = a.get("principalId")
            if principal_id:
                try:
                    user = graph.get(f"/users/{principal_id}?$select=displayName,userPrincipalName,accountEnabled")
                    if not user.get("accountEnabled"):
                        disabled_with_roles.append({"user": user.get("displayName"), "upn": user.get("userPrincipalName"),
                                                    "role": a.get("roleDefinition", {}).get("displayName")})
                except Exception:
                    pass
        return {
            "check_id": "AZURE-IDENTITY-009", "severity": "High",
            "status": "passed" if not disabled_with_roles else "failed",
            "score": 6.5 if disabled_with_roles else 0.0,
            "affected_resources": disabled_with_roles,
            "evidence": {"disabled_users_with_roles": len(disabled_with_roles)},
            "risk_description": "Disabled accounts retaining role assignments can be re-enabled by an attacker to regain privileged access.",
            "remediation_steps": "Remove all role assignments before or immediately upon disabling accounts.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-009", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_app_with_all_permissions(graph, target_config):
    """AZURE-APP-007 — No apps with .All permissions without justification"""
    try:
        sps = graph.get_all_pages("/servicePrincipals?$select=id,displayName,appRoles,requiredResourceAccess")
        dangerous_apps = []
        dangerous_perms = ["User.ReadWrite.All", "Directory.ReadWrite.All", "Mail.ReadWrite", "Files.ReadWrite.All", "Group.ReadWrite.All"]
        for sp in sps:
            for resource in (sp.get("requiredResourceAccess") or []):
                for access in resource.get("resourceAccess", []):
                    if any(p in str(access) for p in dangerous_perms):
                        if not sp.get("displayName", "").startswith("Microsoft"):
                            dangerous_apps.append({"app": sp.get("displayName"), "id": sp.get("id")})
                            break
        return {
            "check_id": "AZURE-APP-007", "severity": "High",
            "status": "passed" if not dangerous_apps else "failed",
            "score": 7.0 if dangerous_apps else 0.0,
            "affected_resources": dangerous_apps[:20],
            "evidence": {"apps_with_all_perms": len(dangerous_apps)},
            "risk_description": "Applications with broad .All permissions can read or modify all data in your tenant.",
            "remediation_steps": "Review and revoke unnecessary .All permissions. Replace with scoped permissions where possible.",
            "estimated_effort": "High",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-007", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_conditional_access_coverage(graph, target_config):
    """AZURE-CA-011 — CA policies cover all cloud apps"""
    policies = graph.get_conditional_access_policies()
    all_apps_covered = any(
        p.get("state") == "enabled"
        and "All" in str(p.get("conditions", {}).get("applications", {}).get("includeApplications", []))
        for p in policies
    )
    return {
        "check_id": "AZURE-CA-011", "severity": "High",
        "status": "passed" if all_apps_covered else "failed",
        "score": 0.0 if all_apps_covered else 6.0,
        "affected_resources": [] if all_apps_covered else [{"issue": "No CA policy covers All cloud apps"}],
        "evidence": {"all_apps_policy_exists": all_apps_covered, "total_policies": len(policies)},
        "risk_description": "CA policies that don't cover all apps leave gaps that attackers can exploit.",
        "remediation_steps": "Ensure at least one CA policy targets All cloud apps for your baseline controls.",
        "estimated_effort": "Low",
    }

def check_ca_report_only_not_primary(graph, target_config):
    """AZURE-CA-012 — CA policies are not all in report-only mode"""
    policies = graph.get_conditional_access_policies()
    enabled = [p for p in policies if p.get("state") == "enabled"]
    report_only = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]
    only_report = not enabled and bool(report_only)
    return {
        "check_id": "AZURE-CA-012", "severity": "High",
        "status": "passed" if not only_report else "failed",
        "score": 8.0 if only_report else 0.0,
        "affected_resources": [{"issue": f"{len(report_only)} CA policies in report-only mode, none enforced"}] if only_report else [],
        "evidence": {"enabled_policies": len(enabled), "report_only_policies": len(report_only)},
        "risk_description": "Report-only CA policies are not enforced — they provide no security protection.",
        "remediation_steps": "Review report-only policies and enable them after validating they won't block legitimate access.",
        "estimated_effort": "Low",
    }

def check_no_accounts_with_no_mfa_registered(graph, target_config):
    """AZURE-MFA-008 — All enabled users have MFA registered"""
    try:
        report = graph.get("/reports/authenticationMethods/userRegistrationDetails")
        mfa_capable = report.get("userRegistrationFeatureSummary", {})
        total = mfa_capable.get("totalUserCount", 0)
        mfa_count = mfa_capable.get("mfaCapableUserCount", 0)
        not_registered = total - mfa_count
        pct = (mfa_count / total * 100) if total > 0 else 100
        return {
            "check_id": "AZURE-MFA-008", "severity": "High",
            "status": "passed" if pct >= 95 else "failed",
            "score": 0.0 if pct >= 95 else max(3.0, 8.0 * (1 - pct/100)),
            "affected_resources": [{"issue": f"{not_registered} users not MFA registered ({100-pct:.1f}%)"}] if pct < 95 else [],
            "evidence": {"total_users": total, "mfa_registered": mfa_count, "mfa_pct": round(pct, 1)},
            "risk_description": f"Only {pct:.1f}% of users have MFA registered — {not_registered} accounts are one password away from compromise.",
            "remediation_steps": "Enable MFA registration campaign and enforce MFA via CA policy for all users.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MFA-008", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_passwordless_adoption(graph, target_config):
    """AZURE-MFA-009 — Passwordless authentication adoption"""
    try:
        report = graph.get("/reports/authenticationMethods/userRegistrationDetails")
        summary = report.get("userRegistrationFeatureSummary", {})
        total = summary.get("totalUserCount", 1)
        passwordless = summary.get("passwordlessCapableUserCount", 0)
        pct = (passwordless / total * 100) if total > 0 else 0
        return {
            "check_id": "AZURE-MFA-009", "severity": "Low",
            "status": "passed" if pct >= 10 else "failed",
            "score": 0.0 if pct >= 10 else 3.0,
            "affected_resources": [] if pct >= 10 else [{"issue": f"Only {pct:.1f}% of users have passwordless capable auth"}],
            "evidence": {"passwordless_users": passwordless, "total_users": total, "pct": round(pct, 1)},
            "risk_description": "Low passwordless adoption means most users rely on passwords which can be phished.",
            "remediation_steps": "Drive Microsoft Authenticator passwordless phone sign-in or FIDO2 key adoption.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MFA-009", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


# ═══════════════════════════════════════════════════════════════════════════
# Effective Coverage Engine
# ─────────────────────────────────────────────────────────────────────────────
# Problem: a check like "does a CA policy require MFA for all users" produces
# false positives whenever the org achieves that outcome a DIFFERENT way —
# e.g. two narrower policies that together cover everyone, or Security
# Defaults instead of Conditional Access. This engine simulates a small set
# of representative access scenarios against the UNION of all controls that
# could apply (enabled CA policies + Security Defaults), rather than
# pattern-matching a single policy shape.
#
# Used by: check_ca_mfa_all_users_v2 (AZURE-MFA-002-V2)
#          check_block_legacy_auth_v2 (AZURE-CA-LEGACY-V2)
#
# These are ADDITIVE — the original AZURE-MFA-002 and AZURE-CA-LEGACY checks
# still run unchanged. Compare both for a few scan cycles: if the -V2 check
# passes while the original fails, that confirms the original was a false
# positive caught by a compensating control (most likely Security Defaults).
# Once confirmed, remove the -V1 entries from ALL_CHECKS below.
# ═══════════════════════════════════════════════════════════════════════════

_COVERAGE_SCENARIOS = [
    {"id": "member-office365",    "user_type": "member", "app": "Office365",              "role": "user"},
    {"id": "member-azure-portal", "user_type": "member", "app": "MicrosoftAdminPortals",   "role": "user"},
    {"id": "guest-office365",     "user_type": "guest",  "app": "Office365",               "role": "user"},
    {"id": "member-admin-role",   "user_type": "member", "app": "All",                     "role": "admin"},
]


def _policy_targets_scenario(policy: dict, scenario: dict) -> bool:
    """Conservative match: if we can't determine exclusion, assume the policy
    applies — better to over-count coverage than silently miss a real gap."""
    if policy.get("state") != "enabled":
        return False
    conditions = policy.get("conditions", {})
    users = conditions.get("users", {})
    apps = conditions.get("applications", {})

    include_users = str(users.get("includeUsers", []))
    include_roles = users.get("includeRoles", [])
    include_guests = "GuestsOrExternalUsers" in str(users)

    if scenario["role"] == "admin" and not include_roles and "All" not in include_users:
        return False
    if scenario["user_type"] == "guest" and not (include_guests or "All" in include_users):
        return False
    if scenario["user_type"] == "member" and include_guests and "All" not in include_users:
        return False

    include_apps = str(apps.get("includeApplications", []))
    if scenario["app"] != "All" and scenario["app"] not in include_apps and "All" not in include_apps:
        return False
    return True


def _policy_grants_mfa(policy: dict) -> bool:
    return "mfa" in str(policy.get("grantControls", {}).get("builtInControls", [])).lower()


def _policy_blocks_legacy_auth(policy: dict) -> bool:
    conditions = policy.get("conditions", {})
    client_apps = str(conditions.get("clientAppTypes", [])).lower()
    controls = str(policy.get("grantControls", {}).get("builtInControls", [])).lower()
    return ("other" in client_apps or "exchangeactivesync" in client_apps) and "block" in controls


def _security_defaults_enabled(graph) -> bool:
    try:
        sd = graph.get("/policies/identitySecurityDefaultsEnforcementPolicy")
        return bool(sd.get("isEnabled", False))
    except Exception as e:
        log.warning(f"Could not read security defaults: {e}")
        return False


def check_ca_mfa_all_users_v2(graph, target_config):
    """AZURE-MFA-002-V2 — Effective MFA coverage across representative scenarios,
    accounting for Security Defaults as a compensating control."""
    try:
        policies = graph.get_conditional_access_policies()
        enabled = [p for p in policies if p.get("state") == "enabled"]
        sec_defaults = _security_defaults_enabled(graph)

        covered, gaps = [], []
        for scenario in _COVERAGE_SCENARIOS:
            applicable = [p for p in enabled if _policy_targets_scenario(p, scenario)]
            mfa_via_ca = any(_policy_grants_mfa(p) for p in applicable)
            if mfa_via_ca:
                covered.append({**scenario, "covered_by": "conditional_access"})
            elif sec_defaults:
                covered.append({**scenario, "covered_by": "security_defaults"})
            else:
                gaps.append(scenario)

        ok = len(gaps) == 0
        return {
            "check_id": "AZURE-MFA-002-V2", "severity": "High",
            "status": "passed" if ok else "failed",
            "score": 0.0 if ok else 8.0,
            "affected_resources": [{"gap_scenario": g["id"], "user_type": g["user_type"], "app": g["app"]} for g in gaps],
            "evidence": {
                "scenarios_evaluated": len(_COVERAGE_SCENARIOS),
                "scenarios_covered": len(covered),
                "scenarios_with_gaps": len(gaps),
                "security_defaults_enabled": sec_defaults,
                "coverage_detail": covered,
            },
            "risk_description": (
                f"{len(gaps)} of {len(_COVERAGE_SCENARIOS)} representative access scenarios have no MFA "
                "requirement from any control (Conditional Access or Security Defaults)."
            ),
            "remediation_steps": (
                "For each uncovered scenario, extend an existing CA policy's scope or create a new one "
                "requiring MFA. If relying on Security Defaults, confirm it is actually enabled — it is "
                "silently disabled the moment any Conditional Access policy is created."
            ),
            "estimated_effort": "Low",
        }
    except Exception as e:
        return {"check_id": "AZURE-MFA-002-V2", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not evaluate effective MFA coverage.",
                "remediation_steps": "Ensure Policy.Read.All is granted.", "estimated_effort": "Low"}


def check_block_legacy_auth_v2(graph, target_config):
    """AZURE-CA-LEGACY-V2 — Effective legacy auth block, accounting for Security Defaults
    (which implicitly disables legacy auth)."""
    try:
        policies = graph.get_conditional_access_policies()
        enabled = [p for p in policies if p.get("state") == "enabled"]
        blocked_via_ca = any(_policy_blocks_legacy_auth(p) for p in enabled)
        sec_defaults = _security_defaults_enabled(graph)
        ok = blocked_via_ca or sec_defaults

        return {
            "check_id": "AZURE-CA-LEGACY-V2", "severity": "High",
            "status": "passed" if ok else "failed",
            "score": 0.0 if ok else 5.9,
            "affected_resources": [] if ok else [{"issue": "No CA policy or Security Defaults blocking legacy auth"}],
            "evidence": {
                "covered_by": "conditional_access" if blocked_via_ca else ("security_defaults" if sec_defaults else None),
                "security_defaults_enabled": sec_defaults,
            },
            "risk_description": (
                "Legacy authentication bypasses MFA and is the dominant vector for password spray "
                "attacks. Neither a Conditional Access block policy nor Security Defaults covers it."
            ),
            "remediation_steps": (
                "Enable Security Defaults if no CA policies are in use, OR create a CA policy blocking "
                "legacy client app types. Do not enable both — they conflict."
            ),
            "estimated_effort": "Low",
        }
    except Exception as e:
        return {"check_id": "AZURE-CA-LEGACY-V2", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not evaluate effective legacy auth coverage.",
                "remediation_steps": "Ensure Policy.Read.All is granted.", "estimated_effort": "Low"}


# ═══════════════════════════════════════════════════════════════════════════
# Advanced Threat-Informed Hardening Checks
# ─────────────────────────────────────────────────────────────────────────────
# These checks target attack techniques with real breach precedent that were
# not covered by the existing 117 checks:
#   - Federation/domain trust abuse (Golden SAML-equivalent token forgery)
#   - Custom domain verification gaps (phishing/subdomain-takeover infra)
#   - Identity Protection licensing blind spot (P1-only tenants show "0 risky
#     users" not because they're safe, but because detection never ran)
#   - Certificate-based auth trust anchor abuse
#   - Actual dangerous OAuth grant AUDIT (not just app registration scope
#     review — grants that already exist and are active in the tenant today)
#
# All checks are read-only, use only the existing GraphClient interface, and
# report evidence + remediation — none of them contain or enable exploitation
# steps. Sourced from documented Microsoft incident guidance and MITRE
# ATT&CK for Azure AD (federated credential abuse: T1606.002; consent grant
# abuse: T1528; valid accounts via cloud identity: T1078.004).
# ═══════════════════════════════════════════════════════════════════════════

def check_federated_domain_trust(graph, target_config):
    """AZURE-FED-001 — No unexpected federated domain trust configured
    Federated domains delegate authentication to an external IdP (e.g. ADFS).
    A federated domain added by a compromised admin account, or a legitimate
    one with a compromised token-signing certificate, allows an attacker to
    forge SAML tokens for ANY user in that domain — bypassing MFA and
    Conditional Access entirely, since the token is trusted at face value.
    This is the core mechanic behind Golden SAML-style attacks."""
    try:
        domains = graph.get_all_pages("/domains")
        federated = [d for d in domains if d.get("authenticationType") == "Federated"]
        return {
            "check_id": "AZURE-FED-001", "severity": "Critical",
            "status": "passed" if not federated else "failed",
            "score": 0.0 if not federated else 8.7,
            "affected_resources": [{"domain": d.get("id")} for d in federated],
            "evidence": {"federated_domain_count": len(federated), "total_domains": len(domains)},
            "risk_description": (
                "Federated domains delegate authentication trust to an external identity provider. "
                "If that provider or its signing certificate is compromised, an attacker can forge "
                "valid tokens for any user in the domain, bypassing Conditional Access and MFA entirely."
            ),
            "remediation_steps": (
                "If federation is not intentionally in use, this is unexpected and requires immediate "
                "investigation — check Entra ID → Custom domain names for the federated domain's "
                "configuration history and admin activity around when it was set. If federation is "
                "intentional (hybrid AD FS), verify the token-signing certificate rotation schedule and "
                "monitor sign-in logs for anomalous federated sign-ins. Consider migrating to Entra "
                "Connect cloud sync with Seamless SSO to eliminate the federation trust dependency."
            ),
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        return {"check_id": "AZURE-FED-001", "severity": "Critical", "status": _status,
                "score": 0.0, "affected_resources": [], "evidence": {"error": _err},
                "risk_description": "Could not check domain federation configuration.",
                "remediation_steps": "Ensure Domain.Read.All permission is granted.",
                "estimated_effort": "Low"}


def check_unverified_domains(graph, target_config):
    """AZURE-FED-002 — No unverified custom domains registered
    Unverified domains left in a tenant (e.g. from an abandoned pilot, or
    added by a since-departed admin) can potentially be claimed and verified
    by anyone who can prove DNS control — including a former employee who
    still controls the DNS zone, or via a lapsed domain registration. A
    newly verified domain can then be used to create convincing phishing
    infrastructure or, in some tenant configurations, influence email
    routing and identity claims."""
    try:
        domains = graph.get_all_pages("/domains")
        unverified = [d for d in domains if not d.get("isVerified", True)]
        return {
            "check_id": "AZURE-FED-002", "severity": "Medium",
            "status": "passed" if not unverified else "failed",
            "score": 0.0 if not unverified else 3.8,
            "affected_resources": [{"domain": d.get("id")} for d in unverified],
            "evidence": {"unverified_count": len(unverified)},
            "risk_description": (
                "Unverified domains sitting in the tenant are stale configuration that serves no "
                "purpose but does represent a small future attack surface if DNS control changes hands."
            ),
            "remediation_steps": "Remove unverified domains that are no longer needed: Entra ID → Custom domain names → select domain → Delete.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        return {"check_id": "AZURE-FED-002", "severity": "Medium", "status": _status,
                "score": 0.0, "affected_resources": [], "evidence": {"error": _err},
                "risk_description": "Could not check domain verification status.",
                "remediation_steps": "Ensure Domain.Read.All permission is granted.",
                "estimated_effort": "Low"}


def check_identity_protection_licensed(graph, target_config):
    """AZURE-RISK-LICENSE — Identity Protection is actually licensed and active
    AZURE-RISK-001/002 report on risky users via the Identity Protection API.
    A tenant WITHOUT Entra ID P2 will show zero risky users — not because no
    risk exists, but because the detection engine that generates those
    signals never ran. This is a genuine blind spot: passing risky-user
    checks on an unlicensed tenant is a false sense of security, not a
    real security posture."""
    try:
        skus = graph.get("/subscribedSkus")
        sku_list = skus.get("value", [])
        p2_names = ("AAD_PREMIUM_P2", "SPE_E5", "ENTERPRISEPREMIUM", "IDENTITY_THREAT_PROTECTION")
        has_p2 = any(
            s.get("skuPartNumber", "") in p2_names or "P2" in s.get("skuPartNumber", "")
            for s in sku_list
        )
        return {
            "check_id": "AZURE-RISK-LICENSE", "severity": "High",
            "status": "passed" if has_p2 else "failed",
            "score": 0.0 if has_p2 else 6.5,
            "affected_resources": [] if has_p2 else [{"issue": "No Entra ID P2 (or equivalent) licence detected in tenant"}],
            "evidence": {"p2_or_equivalent_licensed": has_p2, "skus_checked": len(sku_list)},
            "risk_description": (
                "Without Entra ID P2, Identity Protection's risk detection engine does not run. Any "
                "'0 risky users' result elsewhere in this report reflects absence of licensing, not "
                "absence of risk. Sign-in risk and user risk Conditional Access policies also silently "
                "do nothing without this licence, even if the policy exists and is enabled."
            ),
            "remediation_steps": (
                "Licence Entra ID P2 for at least your privileged/admin population if full-tenant "
                "licensing is not feasible. Re-run this scan after licensing changes — risky-user "
                "findings elsewhere in this report only become meaningful once this passes."
            ),
            "estimated_effort": "High",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        return {"check_id": "AZURE-RISK-LICENSE", "severity": "High", "status": _status,
                "score": 0.0, "affected_resources": [], "evidence": {"error": _err},
                "risk_description": "Could not check tenant licensing.",
                "remediation_steps": "Ensure Organization.Read.All or Directory.Read.All permission is granted.",
                "estimated_effort": "Low"}


def check_certificate_based_auth_trust(graph, target_config):
    """AZURE-CBA-001 — Certificate-based auth trust anchors are scoped and reviewed
    If Certificate-Based Authentication is enabled, ANY certificate issued by
    a trusted CA in the trust list can authenticate as a user (matched by
    UPN/SAN mapping). An overly broad or unreviewed trusted-CA list allows
    an attacker who compromises (or operates) any trusted CA to mint a
    valid client certificate and authenticate as any user — including
    admins — completely bypassing password and MFA prompts."""
    try:
        cba_policy = graph.get("/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/X509Certificate")
        state = cba_policy.get("state", "disabled")
        if state != "enabled":
            return {
                "check_id": "AZURE-CBA-001", "severity": "Low",
                "status": "passed", "score": 0.0,
                "affected_resources": [], "evidence": {"cba_enabled": False},
                "risk_description": "Certificate-based authentication is not enabled — no trust-anchor risk applies.",
                "remediation_steps": "N/A", "estimated_effort": "Low",
            }
        # CBA is enabled — this requires manual review of the trusted CA list,
        # which is not fully exposed via a simple Graph read in v1.0 for all
        # tenant configurations. Flag for manual verification rather than
        # guess at a pass/fail the API can't fully confirm.
        return {
            "check_id": "AZURE-CBA-001", "severity": "High",
            "status": "failed", "score": 5.0,
            "affected_resources": [{"issue": "Certificate-based authentication is enabled — trust anchor list requires manual review"}],
            "evidence": {"cba_enabled": True},
            "risk_description": (
                "Certificate-based authentication is enabled. Any certificate issued by a CA in the "
                "trusted list can be used to authenticate, bypassing password and MFA. This is only as "
                "secure as your trusted CA list and username-binding configuration."
            ),
            "remediation_steps": (
                "Review Entra ID → Security → Certificate-based authentication → Certificate authorities. "
                "Confirm every listed CA is one your organisation directly controls or a trusted third "
                "party with strong issuance controls. Verify username binding is configured on the "
                "strictest available field (e.g. PrincipalName) rather than a broadly-matched field. "
                "Remove any CA no longer in active use."
            ),
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        return {"check_id": "AZURE-CBA-001", "severity": "High", "status": _status,
                "score": 0.0, "affected_resources": [], "evidence": {"error": _err},
                "risk_description": "Could not check certificate-based auth configuration.",
                "remediation_steps": "Ensure Policy.Read.All permission is granted.",
                "estimated_effort": "Low"}


def check_active_oauth_grants_dangerous_scopes(graph, target_config):
    """AZURE-CONSENT-002 — Audit ACTIVE OAuth consent grants for dangerous scopes
    already in effect (not just app registration review). This is distinct
    from AZURE-APP-007: that check reviews what permissions an app REQUESTS;
    this checks what has ALREADY BEEN GRANTED and is live right now. A grant
    made months ago by illicit consent phishing (T1528) remains active and
    exploitable until explicitly revoked, even if the app's registration
    looks unremarkable today."""
    try:
        DANGEROUS_SCOPES = {
            "Mail.ReadWrite", "Mail.Send", "Mail.ReadWrite.Shared",
            "Files.ReadWrite.All", "Directory.ReadWrite.All", "Directory.AccessAsUser.All",
            "User.ReadWrite.All", "Group.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
            "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
        }
        # oauth2PermissionGrants is a navigation property on servicePrincipal —
        # it is NOT selectable via $select (that either returns nothing or, on
        # some tenant/API versions, a 400) and querying it per-service-principal
        # would mean one Graph call per SP, which is slow at scale. The correct
        # approach is one call against the top-level /oauth2PermissionGrants
        # collection, which returns every active grant tenant-wide directly,
        # then join against servicePrincipals locally for display names.
        sps = graph.get_all_pages("/servicePrincipals?$select=id,displayName,appId")
        # Defensive: Graph API pagination can occasionally surface a null/
        # malformed entry for certain tenant configurations. Filtering here
        # rather than trusting every item is a dict avoids a single bad
        # entry crashing the whole check with 'NoneType' object has no
        # attribute 'get' — which then cascades into a poisoned DB
        # transaction for every check that runs after this one.
        sp_by_id = {sp.get("id"): sp for sp in sps if isinstance(sp, dict)}

        grants = graph.get_all_pages("/oauth2PermissionGrants?$select=clientId,scope,consentType")
        grants = [g for g in grants if isinstance(g, dict)]

        risky_grants = []
        for grant in grants:
            scopes = set((grant.get("scope") or "").split())
            hit = scopes & DANGEROUS_SCOPES
            if hit and grant.get("consentType") == "AllPrincipals":
                # AllPrincipals = org-wide consent, not scoped to one user —
                # the highest-impact grant shape
                sp = sp_by_id.get(grant.get("clientId"), {})
                risky_grants.append({
                    "app": sp.get("displayName", "Unknown application"),
                    "app_id": sp.get("appId", grant.get("clientId")),
                    "scopes": sorted(hit),
                    "consent_type": "org-wide",
                })
        return {
            "check_id": "AZURE-CONSENT-002", "severity": "Critical",
            "status": "passed" if not risky_grants else "failed",
            "score": 0.0 if not risky_grants else 8.2,
            "affected_resources": risky_grants[:20],
            "evidence": {"active_dangerous_grants": len(risky_grants)},
            "risk_description": (
                "These OAuth consent grants are ACTIVE RIGHT NOW with organisation-wide scope, meaning "
                "the app can act on this data for every user without further consent. This is the exact "
                "mechanic used in illicit consent grant phishing attacks — the malicious app looks "
                "unremarkable, but the grant persists silently until revoked."
            ),
            "remediation_steps": (
                "For each listed app: verify with the business owner whether this access is still "
                "needed and was granted deliberately. If not, revoke immediately: Entra ID → Enterprise "
                "applications → select app → Permissions → Revoke. Then review sign-in and audit logs "
                "for that service principal's activity history."
            ),
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        return {"check_id": "AZURE-CONSENT-002", "severity": "Critical", "status": _status,
                "score": 0.0, "affected_resources": [], "evidence": {"error": _err},
                "risk_description": "Could not audit active OAuth grants.",
                "remediation_steps": "Ensure Application.Read.All permission is granted.",
                "estimated_effort": "Low"}


def check_break_glass_signin_frequency(graph, target_config):
    """AZURE-BG-SIGNIN-FREQ — Break glass accounts have NOT signed in recently
    (inverse logic vs AZURE-BG-001 which checks existence). A break-glass
    account that IS signing in regularly is either being used for daily
    operations (defeats its purpose as an emergency-only credential and
    expands its exposure window) or is a signal of compromise if no
    legitimate emergency has occurred. Either finding warrants investigation."""
    try:
        bg_group_id = (target_config or {}).get("break_glass_group_id", "")
        if not bg_group_id:
            return {
                "check_id": "AZURE-BG-SIGNIN-FREQ", "severity": "Medium",
                "status": "error", "score": 0.0,
                "affected_resources": [], "evidence": {"configured": False},
                "risk_description": "Break glass group not configured in target settings — cannot verify sign-in frequency.",
                "remediation_steps": "Configure break_glass_group_id in target settings to enable this check.",
                "estimated_effort": "Low",
            }
        members = graph.get_all_pages(f"/groups/{bg_group_id}/members")
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        recent_signins = []
        for m in members:
            try:
                u = graph.get(f"/users/{m['id']}?$select=displayName,userPrincipalName,signInActivity")
                last = u.get("signInActivity", {}).get("lastSignInDateTime")
                if last:
                    last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                    if last_dt > cutoff:
                        recent_signins.append({"user": u.get("displayName"), "last_signin": last})
            except Exception:
                pass
        return {
            "check_id": "AZURE-BG-SIGNIN-FREQ", "severity": "Medium",
            "status": "passed" if not recent_signins else "failed",
            "score": 0.0 if not recent_signins else 5.5,
            "affected_resources": recent_signins,
            "evidence": {"recent_signin_count": len(recent_signins)},
            "risk_description": (
                "Break glass accounts have signed in within the last 30 days. If no emergency occurred "
                "requiring their use, this is a strong indicator of either unauthorised access or "
                "process drift where the account is being used for routine work — both defeat the "
                "purpose of a break-glass credential."
            ),
            "remediation_steps": (
                "Investigate each recent sign-in immediately: confirm with your security team whether "
                "it corresponds to a known, authorised emergency. If not confirmed, treat as a potential "
                "compromise — rotate the account's credentials immediately and review all activity from "
                "that session in the audit log."
            ),
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        return {"check_id": "AZURE-BG-SIGNIN-FREQ", "severity": "Medium", "status": _status,
                "score": 0.0, "affected_resources": [], "evidence": {"error": _err},
                "risk_description": "Could not check break glass sign-in activity.",
                "remediation_steps": "Ensure AuditLog.Read.All permission is granted.",
                "estimated_effort": "Low"}


ALL_CHECKS = [
    # ── Threat-informed hardening (federation trust, licence blind spots,
    #    CBA trust anchors, active dangerous OAuth grants) ────────────────
    check_federated_domain_trust,
    check_unverified_domains,
    check_identity_protection_licensed,
    check_certificate_based_auth_trust,
    check_active_oauth_grants_dangerous_scopes,
    check_break_glass_signin_frequency,
    # ── Conditional Access ─────────────────────────────────────────────────
    check_break_glass_ca_exclusion,
    check_mfa_privileged_roles,
    check_block_legacy_auth,
    check_block_legacy_auth_v2,   # effective-coverage version, see coverage engine above
    check_high_signin_risk_policy,
    check_ca_compliant_device,
    check_ca_block_risky_signins,
    check_ca_persistent_browser,
    check_ca_security_info_registration,
    check_ca_mfa_all_users,
    check_ca_mfa_all_users_v2,    # effective-coverage version, see coverage engine above
    check_ca_high_user_risk,
    check_ca_guest_mfa,
    check_ca_block_guest_admin_portals,
    check_named_locations_defined,
    check_conditional_access_coverage,
    check_ca_report_only_not_primary,
    # ── MFA ────────────────────────────────────────────────────────────────
    check_privileged_admins_mfa,
    check_mfa_registration_campaign,
    check_authenticator_features_enabled,
    check_phishing_resistant_mfa,
    check_sms_mfa_discouraged,
    check_authentication_strength_policies,
    check_no_accounts_with_no_mfa_registered,
    check_passwordless_adoption,
    # ── PIM ────────────────────────────────────────────────────────────────
    check_no_permanent_roles,
    check_pim_access_reviews,
    check_pim_justification_required,
    # ── Privileged Identity ────────────────────────────────────────────────
    check_privileged_accounts_cloud_only,
    check_no_global_admin_service_accounts,
    check_max_global_admins,
    check_min_global_admins,
    check_no_disabled_users_with_roles,
    # ── Break Glass ────────────────────────────────────────────────────────
    check_break_glass_accounts_exist,
    # ── Identity ───────────────────────────────────────────────────────────
    check_user_consent_disabled,
    check_user_app_registration_disabled,
    check_security_group_creation,
    check_sspr_enabled,
    check_sspr_requires_two_methods,
    check_password_protection_enabled,
    check_banned_password_list,
    check_no_personal_email_mfa,
    check_security_defaults_or_ca,
    check_tenant_restrictions_configured,
    check_terms_of_use,
    check_no_users_with_default_role_only,
    # ── Applications ───────────────────────────────────────────────────────
    check_app_credential_expiry,
    check_app_assignment_required,
    check_admin_consent_workflow,
    check_sp_certificate_credentials,
    check_apps_without_owners,
    check_no_app_with_all_permissions,
    check_app_requires_approved_publisher,
    check_applications_using_delegated_permissions,
    check_service_principal_owned_by_users,
    # ── Guests ─────────────────────────────────────────────────────────────
    check_guest_pending_invitations,
    check_no_guest_invite_all_users,
    check_guest_access_restricted,
    check_no_stale_guest_accounts,
    # ── Groups ─────────────────────────────────────────────────────────────
    check_group_expiration_policy,
    check_no_nested_groups_with_admin,
    check_dynamic_groups_configured,
    check_owners_not_excessive,
    # ── Monitoring & Risk ──────────────────────────────────────────────────
    check_stale_privileged_users,
    check_diagnostic_settings_configured,
    check_identity_protection_enabled,
    check_risky_users_addressed,
    check_no_high_risk_signins_unresolved,
    # ── Governance ─────────────────────────────────────────────────────────
    check_access_reviews_configured,
    check_entitlement_management,
]


# ── Celery tasks ──────────────────────────────────────────────────────────────

@celery_app.task(name="app.tasks.run_assessment_task")
def run_assessment_task(run_id: str, target_id: str):
    engine = get_sync_db()
    with engine.connect() as conn:
        # Mark as running
        conn.execute(text("""
            UPDATE scan_runs SET status='running', started_at=now() WHERE id=:id
        """), {"id": run_id})
        conn.commit()

        # Get target config
        row = conn.execute(text("SELECT config FROM targets WHERE id=:id"), {"id": target_id}).fetchone()
        if not row:
            conn.execute(text("UPDATE scan_runs SET status='failed', error_message='Target not found' WHERE id=:id"), {"id": run_id})
            conn.commit()
            return

        config = row[0] or {}
        tenant_id     = config.get("tenant_id") or os.getenv("AZURE_TENANT_ID") or os.getenv("ENTRA_TENANT_ID")
        client_id     = config.get("client_id") or os.getenv("AZURE_CLIENT_ID") or os.getenv("ENTRA_CLIENT_ID")
        client_secret = os.getenv("AZURE_CLIENT_SECRET") or os.getenv("ENTRA_CLIENT_SECRET")

        if not all([tenant_id, client_id, client_secret]):
            conn.execute(text("UPDATE scan_runs SET status='failed', error_message='Missing Azure credentials' WHERE id=:id"), {"id": run_id})
            conn.commit()
            return

        graph = GraphClient(tenant_id, client_id, client_secret)
        passed = failed = skipped = 0

        # ── Phase 1: run every check, hold results in memory ────────────────
        # AI explanation/false-positive analysis needs to see ALL results
        # before it can apply the priority order (Conditional Access first,
        # then failed-by-severity, then passed) within the per-scan cap — so
        # this can no longer happen inline per-check as findings are produced.
        all_results = []
        for check_fn in ALL_CHECKS:
            try:
                result = check_fn(graph, config)
                status = result.get("status", "error")
                if status == "passed":
                    passed += 1
                elif status == "failed":
                    failed += 1
                else:
                    skipped += 1
                all_results.append(result)
            except Exception as e:
                # Full traceback, not just the exception message — a bare
                # "'tuple' object has no attribute 'get'" gives no clue which
                # line inside the check (or inside a shared helper it calls)
                # actually produced a tuple where a dict was expected. This
                # has cost real debugging time twice already this session for
                # checks that DO have their own try/except but still failed
                # here, meaning the error originates in a shared call path
                # (get_all_pages, get_conditional_access_policies, etc.)
                # rather than inside the check function's own try block.
                import traceback
                log.error(f"Check {check_fn.__name__} failed: {e}\n{traceback.format_exc()}")
                skipped += 1

        # ── Phase 2: AI explanation + false-positive analysis, capped ───────
        # Fully optional — no-ops entirely unless AI_EXPLAIN_ENABLED=true and
        # a provider is configured. See ai_explainer.py for the full boundary
        # documentation. Selection order: Conditional Access checks first,
        # then remaining FAILED findings by severity/score, then PASSED
        # findings if budget remains — up to AI_EXPLAIN_MAX_PER_SCAN total.
        ai_summary_text = None
        try:
            # Import as app.ai_explainer, not bare ai_explainer — Celery starts
            # this worker as `celery -A app.tasks` with WORKDIR=/app, so the
            # module is addressed as app.ai_explainer at runtime, matching how
            # app.tasks itself is addressed. A bare `from ai_explainer import`
            # only works if /app/app is directly on sys.path, which it isn't
            # in this container's actual runtime — this was silently failing
            # every scan with "No module named 'ai_explainer'" despite the
            # file being present on disk in the correct location.
            from app.ai_explainer import select_findings_to_explain, explain_finding_sync, summarise_scan_sync

            to_explain = select_findings_to_explain(all_results)

            # Investigative agent — opt-in, separate from the base explainer.
            # Runs on a SMALLER subset (AI_AGENT_MAX_FINDINGS_PER_SCAN,
            # default 5) since each agent investigation costs multiple LLM
            # calls (up to AI_AGENT_MAX_TOOL_CALLS+1) versus one call for the
            # plain explainer. Findings selected for agent investigation are
            # excluded from the plain explainer loop below, so no finding
            # gets both (wasteful) or neither.
            agent_ids = set()
            try:
                from app.ai_agent import (AI_AGENT_ENABLED, AI_AGENT_MAX_FINDINGS_PER_SCAN,
                                           investigate_finding, resolve_agent_provider_config)
                if AI_AGENT_ENABLED:
                    agent_provider, provider_cfg = resolve_agent_provider_config()
                    if agent_provider:
                        to_investigate = to_explain[:AI_AGENT_MAX_FINDINGS_PER_SCAN]
                        agent_ids = {id(f) for f in to_investigate}
                        for result in to_investigate:
                            investigate_finding(result, graph, agent_provider, provider_cfg)
                            import time as _time
                            _time.sleep(0.5)
                        if to_investigate:
                            log.info(f"Agent-investigated {len(to_investigate)}/{len(all_results)} "
                                      f"findings for scan {run_id} via {agent_provider}")
            except Exception as _agent_err:
                log.warning(f"Agent investigation phase skipped for scan {run_id}: {_agent_err}")

            for result in to_explain:
                if id(result) in agent_ids:
                    continue  # already handled by the agent above
                explain_finding_sync(result)  # mutates result in place, adds ai_* keys only
                # Small pacing delay between calls — free-tier providers (Groq
                # in particular) enforce requests-per-minute limits, and firing
                # 15-30 calls in a couple of seconds reliably trips a 429 on
                # the LAST call in the batch (which was always the summary
                # call, since it runs after every per-finding call) even
                # though the individual explanation calls themselves succeed.
                # This keeps total added time modest (well under a minute for
                # the default cap of 30) while giving rate limiters real
                # breathing room.
                import time as _time
                _time.sleep(0.5)

            if to_explain:
                log.info(f"AI-explained {len(to_explain)}/{len(all_results)} findings for scan {run_id}")

            ai_summary_text = summarise_scan_sync(all_results, len(all_results), passed, failed, skipped)
        except Exception as _ai_err:
            log.warning(f"AI explanation phase skipped for scan {run_id}: {_ai_err}")

        # ── Phase 3: persist every finding ───────────────────────────────────
        for result in all_results:
            try:
                conn.execute(text("""
                    INSERT INTO findings (id, scan_run_id, target_id, check_id, status, severity, score,
                        affected_resources, evidence, risk_description, remediation_steps,
                        estimated_effort, ai_explanation, ai_false_positive_likelihood,
                        ai_false_positive_reason, ai_queries_made, first_seen_at, last_seen_at, created_at, updated_at)
                    VALUES (:id, :run_id, :target_id, :check_id, :status, :severity, :score,
                        cast(:affected as jsonb), cast(:evidence as jsonb),
                        :risk, :remediation, :effort, :ai_explanation, :ai_fp_likelihood,
                        :ai_fp_reason, :ai_queries, now(), now(), now(), now())
                    ON CONFLICT DO NOTHING
                """), {
                    "id": str(uuid.uuid4()), "run_id": run_id, "target_id": target_id,
                    "check_id": result["check_id"], "status": result["status"],
                    "severity": result.get("severity", "Medium"),
                    "score": result.get("score", 0.0),
                    "affected": __import__("json").dumps(result.get("affected_resources", []), default=str),
                    "evidence": __import__("json").dumps(result.get("evidence", {}), default=str),
                    "risk": result.get("risk_description", ""),
                    "remediation": result.get("remediation_steps", ""),
                    "effort": result.get("estimated_effort", "Low"),
                    "ai_explanation": result.get("ai_explanation"),
                    "ai_fp_likelihood": result.get("ai_false_positive_likelihood"),
                    "ai_fp_reason": result.get("ai_false_positive_reason"),
                    "ai_queries": __import__("json").dumps(result.get("ai_queries_made")) if result.get("ai_queries_made") else None,
                })
                conn.commit()
            except Exception as insert_err:
                # Log the SPECIFIC check_id and error that caused the INSERT to
                # fail, before rolling back — otherwise this information is lost
                # and every subsequent failure looks identical, masking which
                # finding actually caused the original problem.
                log.error(
                    f"INSERT failed for check_id={result.get('check_id')} "
                    f"status={result.get('status')} score={result.get('score')!r} "
                    f"score_type={type(result.get('score')).__name__}: {insert_err}"
                )
                # CRITICAL: without this rollback, a single failed INSERT poisons
                # the connection for the rest of the scan — every subsequent
                # statement (remaining inserts, the completion UPDATE) fails
                # with InFailedSqlTransaction, and the run gets stuck at
                # status='running' forever. Rolling back lets the connection
                # recover and the loop continue normally.
                try:
                    conn.rollback()
                except Exception as rollback_err:
                    log.error(f"Rollback also failed after check_id={result.get('check_id')}: {rollback_err}")
                skipped += 1

        total = passed + failed + skipped
        try:
            conn.execute(text("""
                UPDATE scan_runs
                SET status='completed', completed_at=now(),
                    checks_total=:total, checks_passed=:passed,
                    checks_failed=:failed, checks_skipped=:skipped,
                    ai_summary=:ai_summary
                WHERE id=:id
            """), {"id": run_id, "total": total, "passed": passed, "failed": failed,
                   "skipped": skipped, "ai_summary": ai_summary_text})
            conn.commit()
        except Exception as e:
            # Last resort: if even the completion update fails (e.g. connection
            # still broken for some other reason), roll back and try to at
            # least mark the run as failed rather than leaving it stuck at
            # 'running' indefinitely with no way for the UI to know it's dead.
            log.error(f"Failed to mark scan {run_id} as completed: {e}")
            try:
                conn.rollback()
                conn.execute(text("""
                    UPDATE scan_runs SET status='failed', completed_at=now(),
                        error_message=:err, checks_total=:total, checks_passed=:passed,
                        checks_failed=:failed, checks_skipped=:skipped
                    WHERE id=:id
                """), {"id": run_id, "err": str(e)[:500], "total": total,
                       "passed": passed, "failed": failed, "skipped": skipped})
                conn.commit()
            except Exception as e2:
                log.error(f"Could not even mark scan {run_id} as failed: {e2}")

    log.info(f"Scan {run_id} complete: {passed} passed, {failed} failed, {skipped} skipped")


@celery_app.task(name="app.tasks.run_scheduled_scan")
def run_scheduled_scan():
    engine = get_sync_db()
    with engine.connect() as conn:
        row = conn.execute(text("SELECT id FROM targets WHERE is_active=true LIMIT 1")).fetchone()
        if row:
            run_id = str(uuid.uuid4())
            conn.execute(text("""
                INSERT INTO scan_runs (id, target_id, status, triggered_by, created_at, updated_at)
                VALUES (:id, :tid, 'pending', 'scheduler', now(), now())
            """), {"id": run_id, "tid": str(row[0])})
            conn.commit()
            run_assessment_task.delay(run_id, str(row[0]))

# ── Additional checks ─────────────────────────────────────────────────────────

def check_pim_notification_alerts(graph, target_config):
    """AZURE-PIM-004 — PIM sends alerts for role activation"""
    try:
        alerts = graph.get_all_pages("/privilegedAccess/aadroles/settings")
        return {
            "check_id": "AZURE-PIM-004", "severity": "Medium",
            "status": "passed", "score": 0.0, "affected_resources": [],
            "evidence": {"checked": True},
            "risk_description": "PIM role activation without notifications means security teams cannot monitor privileged access in real-time.",
            "remediation_steps": "In PIM → Settings for each role → enable notifications to role assignees and security team on activation.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PIM-004", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_guest_global_admin(graph, target_config):
    """AZURE-GUEST-005 — No guest users assigned privileged roles"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        priv = {"Global Administrator","Security Administrator","Privileged Role Administrator","Exchange Administrator"}
        guest_admins = []
        for role in roles:
            if role.get("displayName") not in priv: continue
            for m in graph.get_all_pages(f"/directoryRoles/{role['id']}/members"):
                if m.get("userType") == "Guest":
                    guest_admins.append({"user": m.get("displayName"), "upn": m.get("userPrincipalName"), "role": role.get("displayName")})
        return {
            "check_id": "AZURE-GUEST-005", "severity": "Critical",
            "status": "passed" if not guest_admins else "failed",
            "score": 9.5 if guest_admins else 0.0,
            "affected_resources": guest_admins,
            "evidence": {"guest_admins": len(guest_admins)},
            "risk_description": "Guest users with privileged roles are external accounts with administrative control — an extreme security risk.",
            "remediation_steps": "Immediately remove all guest accounts from privileged roles. Create internal cloud-only accounts for any legitimate admin needs.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GUEST-005", "severity": "Critical",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_shared_accounts(graph, target_config):
    """AZURE-IDENTITY-011 — No shared/generic accounts in privileged roles"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        shared_keywords = ["shared", "generic", "admin", "service", "system", "team", "helpdesk", "support"]
        shared_admins = []
        for role in roles:
            for m in graph.get_all_pages(f"/directoryRoles/{role['id']}/members"):
                upn = m.get("userPrincipalName", "").lower()
                name = m.get("displayName", "").lower()
                if any(k in upn or k in name for k in shared_keywords):
                    shared_admins.append({"user": m.get("displayName"), "upn": m.get("userPrincipalName"), "role": role.get("displayName")})
        return {
            "check_id": "AZURE-IDENTITY-011", "severity": "High",
            "status": "passed" if not shared_admins else "failed",
            "score": 7.0 if shared_admins else 0.0,
            "affected_resources": shared_admins[:20],
            "evidence": {"potential_shared": len(shared_admins)},
            "risk_description": "Shared or generic accounts cannot be attributed to a specific individual, making audit trails meaningless and preventing accountability.",
            "remediation_steps": "Replace shared accounts with individual named accounts. Each admin must have their own dedicated identity for all privileged actions.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-011", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_privileged_role_count(graph, target_config):
    """AZURE-PRIV-005 — Total privileged role assignments are minimised"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        priv_roles = {"Global Administrator","Privileged Role Administrator","Security Administrator",
                      "Exchange Administrator","SharePoint Administrator","Teams Administrator",
                      "Application Administrator","Cloud Application Administrator","Conditional Access Administrator"}
        total_assignments = []
        for role in roles:
            if role.get("displayName") not in priv_roles: continue
            members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
            total_assignments.extend([{"user": m.get("displayName"), "role": role.get("displayName")} for m in members])
        excessive = len(total_assignments) > 20
        return {
            "check_id": "AZURE-PRIV-005", "severity": "Medium",
            "status": "passed" if not excessive else "failed",
            "score": 0.0 if not excessive else 5.0,
            "affected_resources": total_assignments[:10] if excessive else [],
            "evidence": {"total_privileged_assignments": len(total_assignments)},
            "risk_description": f"Tenant has {len(total_assignments)} privileged role assignments — each is a potential attack vector. Minimise standing privilege.",
            "remediation_steps": "Review all privileged role assignments. Remove unnecessary assignments and convert remaining to PIM eligible-only.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PRIV-005", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_app_multitenant_disabled(graph, target_config):
    """AZURE-APP-008 — Applications are not unnecessarily multi-tenant"""
    try:
        apps = graph.get_all_pages("/applications?$select=id,displayName,signInAudience,web")
        multitenant = [
            {"app": a.get("displayName"), "id": a.get("id"), "audience": a.get("signInAudience")}
            for a in apps
            if a.get("signInAudience") in ["AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount", "PersonalMicrosoftAccount"]
        ]
        return {
            "check_id": "AZURE-APP-008", "severity": "High",
            "status": "passed" if not multitenant else "failed",
            "score": 6.5 if multitenant else 0.0,
            "affected_resources": multitenant[:20],
            "evidence": {"multitenant_apps": len(multitenant), "total_apps": len(apps)},
            "risk_description": "Multi-tenant apps accept authentication from ANY Azure AD tenant or Microsoft account, not just your organisation. This dramatically expands the attack surface.",
            "remediation_steps": "Change sign-in audience to 'AzureADMyOrg' for all internal applications. Only keep multi-tenant if the app genuinely needs external users.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-008", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_app_implicit_flow_disabled(graph, target_config):
    """AZURE-APP-009 — Applications do not use implicit grant flow"""
    try:
        apps = graph.get_all_pages("/applications?$select=id,displayName,web,spa")
        implicit_apps = []
        for a in apps:
            web = a.get("web", {}) or {}
            spa = a.get("spa", {}) or {}
            if web.get("implicitGrantSettings", {}).get("enableAccessTokenIssuance") or \
               web.get("implicitGrantSettings", {}).get("enableIdTokenIssuance"):
                implicit_apps.append({"app": a.get("displayName"), "id": a.get("id")})
        return {
            "check_id": "AZURE-APP-009", "severity": "Medium",
            "status": "passed" if not implicit_apps else "failed",
            "score": 4.5 if implicit_apps else 0.0,
            "affected_resources": implicit_apps[:20],
            "evidence": {"implicit_flow_apps": len(implicit_apps)},
            "risk_description": "Implicit flow passes tokens in URL fragments which can be logged, cached, or intercepted. Modern apps should use PKCE-based auth code flow instead.",
            "remediation_steps": "Disable implicit grant flow in app registrations → Authentication → uncheck 'Access tokens' and 'ID tokens'. Migrate to authorization code flow with PKCE.",
            "estimated_effort": "High",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-009", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_reply_url_wildcards(graph, target_config):
    """AZURE-APP-010 — No wildcard redirect URIs in app registrations"""
    try:
        apps = graph.get_all_pages("/applications?$select=id,displayName,web,spa,publicClient")
        wildcard_apps = []
        for a in apps:
            all_uris = []
            for section in ["web", "spa", "publicClient"]:
                s = a.get(section, {}) or {}
                all_uris.extend(s.get("redirectUris", []))
            wildcards = [u for u in all_uris if "*" in u or u == "https://localhost" or "localhost" in u.lower()]
            if wildcards:
                wildcard_apps.append({"app": a.get("displayName"), "uris": wildcards[:3]})
        return {
            "check_id": "AZURE-APP-010", "severity": "High",
            "status": "passed" if not wildcard_apps else "failed",
            "score": 6.0 if wildcard_apps else 0.0,
            "affected_resources": wildcard_apps[:20],
            "evidence": {"apps_with_wildcards": len(wildcard_apps)},
            "risk_description": "Wildcard redirect URIs allow tokens to be redirected to any subdomain, enabling open redirector attacks where attackers steal auth codes.",
            "remediation_steps": "Remove all wildcard redirect URIs. Use exact, specific URIs only. Remove localhost URIs from production app registrations.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-010", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_conditional_access_policy_count(graph, target_config):
    """AZURE-CA-015 — Sufficient CA policies are configured"""
    try:
        policies = graph.get_all_pages("/identity/conditionalAccess/policies")
        enabled = [p for p in policies if p.get("state") == "enabled"]
        sufficient = len(enabled) >= 5
        return {
            "check_id": "AZURE-CA-015", "severity": "High",
            "status": "passed" if sufficient else "failed",
            "score": 0.0 if sufficient else 6.0,
            "affected_resources": [] if sufficient else [{"issue": f"Only {len(enabled)} enabled CA policies — minimum 5 recommended"}],
            "evidence": {"total_policies": len(policies), "enabled_policies": len(enabled)},
            "risk_description": f"Only {len(enabled)} CA policies are enabled. A complete security baseline requires at minimum: block legacy auth, require MFA all users, require MFA admins, block high risk sign-ins, require compliant device.",
            "remediation_steps": "Implement the Microsoft CA policy baseline: Block legacy auth, Require MFA for all users, Require MFA for admins, Block high sign-in risk, Require compliant device for sensitive apps.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-015", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_directory_role_assignments_reviewed(graph, target_config):
    """AZURE-PRIV-006 — All directory role assignments are documented"""
    try:
        assignments = graph.get_all_pages("/roleManagement/directory/roleAssignments?$expand=principal,roleDefinition")
        undocumented = [
            {"user": a.get("principal", {}).get("displayName"), "role": a.get("roleDefinition", {}).get("displayName")}
            for a in assignments
            if not a.get("roleDefinition", {}).get("description")
        ]
        return {
            "check_id": "AZURE-PRIV-006", "severity": "Low",
            "status": "passed", "score": 0.0,
            "affected_resources": [],
            "evidence": {"total_role_assignments": len(assignments)},
            "risk_description": "Undocumented role assignments create accountability gaps and make it harder to audit who has access to what.",
            "remediation_steps": "Maintain a register of all privileged role assignments with business justification, assigned date, and review date. Use PIM to enforce justification on activation.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PRIV-006", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_sign_in_logs_retained(graph, target_config):
    """AZURE-MONITORING-005 — Sign-in logs are being generated and accessible"""
    try:
        logs = graph.get("/auditLogs/signIns?$top=5&$select=id,createdDateTime,userDisplayName,status")
        recent = logs.get("value", [])
        has_recent = len(recent) > 0
        if has_recent:
            latest = recent[0].get("createdDateTime", "")
            from datetime import datetime, timezone, timedelta
            if latest:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(latest.replace("Z", "+00:00"))
                has_recent = age < timedelta(hours=48)
        return {
            "check_id": "AZURE-MONITORING-005", "severity": "High",
            "status": "passed" if has_recent else "failed",
            "score": 0.0 if has_recent else 7.0,
            "affected_resources": [] if has_recent else [{"issue": "No recent sign-in logs found"}],
            "evidence": {"recent_logs_found": len(recent), "logs_accessible": len(recent) > 0},
            "risk_description": "Without accessible sign-in logs, security incidents cannot be detected or investigated. Logs may not be configured to a SIEM or storage account.",
            "remediation_steps": "Configure Diagnostic settings in Entra ID → send SignInLogs and AuditLogs to Log Analytics workspace, Storage Account, or Event Hub. Ensure retention is set to 90+ days.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MONITORING-005", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_emergency_access_monitored(graph, target_config):
    """AZURE-MONITORING-004 — Break glass account sign-ins are alerted"""
    bg_group_id = target_config.get("break_glass_group_id", "")
    try:
        if not bg_group_id:
            return {
                "check_id": "AZURE-MONITORING-004", "severity": "Critical",
                "status": "failed", "score": 8.0,
                "affected_resources": [{"issue": "Break glass group ID not configured in target settings"}],
                "evidence": {"bg_group_configured": False},
                "risk_description": "Break glass account sign-ins must trigger immediate alerts to the security team. Any use of these accounts indicates either an emergency or a breach.",
                "remediation_steps": "1. Configure the break glass group ID in target settings. 2. Create a Log Analytics alert rule triggered by any sign-in from break glass accounts. 3. Route alert to security team via email and SMS immediately.",
                "estimated_effort": "Low",
            }
        members = graph.get_all_pages(f"/groups/{bg_group_id}/members?$select=id,displayName,userPrincipalName")
        return {
            "check_id": "AZURE-MONITORING-004", "severity": "Critical",
            "status": "passed" if members else "failed",
            "score": 0.0 if members else 9.0,
            "affected_resources": [],
            "evidence": {"bg_accounts_found": len(members)},
            "risk_description": "Break glass account sign-ins must trigger immediate security team alerts.",
            "remediation_steps": "Create a Log Analytics alert for any sign-in from break glass accounts. Route to security team immediately via email and SMS.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MONITORING-004", "severity": "Critical",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_admin_mfa_methods_strong(graph, target_config):
    """AZURE-MFA-010 — Admins use strong MFA methods (not just SMS)"""
    try:
        priv = {"Global Administrator", "Security Administrator", "Privileged Role Administrator"}
        weak_mfa_admins = []
        for role in graph.get_all_pages("/directoryRoles"):
            if role.get("displayName") not in priv: continue
            for m in graph.get_all_pages(f"/directoryRoles/{role['id']}/members"):
                try:
                    methods = graph.get_all_pages(f"/users/{m['id']}/authentication/methods")
                    method_types = [x.get("@odata.type", "").lower() for x in methods]
                    has_strong = any(t for t in method_types if "fido2" in t or "windowshello" in t or "softwareoath" in t or "microsoftauthenticator" in t)
                    has_sms_only = any("phone" in t for t in method_types) and not has_strong
                    if has_sms_only:
                        weak_mfa_admins.append({"user": m.get("displayName"), "upn": m.get("userPrincipalName")})
                except Exception:
                    pass
        return {
            "check_id": "AZURE-MFA-010", "severity": "High",
            "status": "passed" if not weak_mfa_admins else "failed",
            "score": 6.5 if weak_mfa_admins else 0.0,
            "affected_resources": weak_mfa_admins,
            "evidence": {"weak_mfa_admins": len(weak_mfa_admins)},
            "risk_description": "Admins using only SMS for MFA are vulnerable to SIM-swapping attacks which can bypass this control in minutes.",
            "remediation_steps": "Migrate all admin accounts from SMS-based MFA to Microsoft Authenticator with number matching, or FIDO2 security keys.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MFA-010", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_license_p2_available(graph, target_config):
    """AZURE-IDENTITY-012 — Entra ID P2 licences available for security features"""
    try:
        subs = graph.get("/subscribedSkus?$select=skuPartNumber,capabilityStatus,consumedUnits,prepaidUnits")
        p2_skus = ["AAD_PREMIUM_P2", "EMSPREMIUM", "M365EDU_A5", "SPE_E5", "M365_E5"]
        has_p2 = any(
            s.get("skuPartNumber") in p2_skus and s.get("capabilityStatus") == "Enabled"
            for s in subs.get("value", [])
        )
        return {
            "check_id": "AZURE-IDENTITY-012", "severity": "High",
            "status": "passed" if has_p2 else "failed",
            "score": 0.0 if has_p2 else 7.0,
            "affected_resources": [] if has_p2 else [{"issue": "No Entra ID P2 licence detected"}],
            "evidence": {"p2_licensed": has_p2},
            "risk_description": "Entra ID P2 is required for Identity Protection (risk-based CA), PIM, access reviews, and privileged identity management — the core of a mature security posture.",
            "remediation_steps": "Licence Entra ID P2 (or Microsoft 365 E5/EMS E5) for all users who need security features. At minimum, licence all privileged users and security team members.",
            "estimated_effort": "High",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-012", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_legacy_auth_successful(graph, target_config):
    """AZURE-MONITORING-006 — No successful legacy auth sign-ins in last 30 days"""
    try:
        from datetime import datetime, timezone, timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs = graph.get(f"/auditLogs/signIns?$filter=clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients' and createdDateTime gt {cutoff} and status/errorCode eq 0&$top=10&$select=userDisplayName,clientAppUsed,createdDateTime")
        legacy_signins = logs.get("value", [])
        return {
            "check_id": "AZURE-MONITORING-006", "severity": "High",
            "status": "passed" if not legacy_signins else "failed",
            "score": 7.0 if legacy_signins else 0.0,
            "affected_resources": [{"user": s.get("userDisplayName"), "method": s.get("clientAppUsed"), "date": s.get("createdDateTime")} for s in legacy_signins[:10]],
            "evidence": {"legacy_auth_count": len(legacy_signins)},
            "risk_description": f"{len(legacy_signins)} successful legacy authentication sign-ins in the last 30 days — these bypass MFA entirely.",
            "remediation_steps": "Identify and update applications using legacy auth before blocking. Check Sign-in logs filtered by client app type to find the source, then enable the legacy auth block CA policy.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MONITORING-006", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_token_lifetime_policy(graph, target_config):
    """AZURE-CA-016 — Token lifetime policies configured"""
    try:
        policies = graph.get_all_pages("/policies/tokenLifetimePolicies")
        return {
            "check_id": "AZURE-CA-016", "severity": "Low",
            "status": "passed" if policies else "failed",
            "score": 0.0 if policies else 2.5,
            "affected_resources": [] if policies else [{"issue": "No token lifetime policies configured"}],
            "evidence": {"policies": len(policies)},
            "risk_description": "Default token lifetimes may be too long for sensitive scenarios. Short-lived tokens limit the window of opportunity if a token is stolen.",
            "remediation_steps": "Create token lifetime policies for sensitive applications to reduce access token lifetime. Use Continuous Access Evaluation (CAE) as the primary control for session management.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-016", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_continuous_access_evaluation(graph, target_config):
    """AZURE-CA-017 — Continuous Access Evaluation enabled"""
    try:
        policies = graph.get_all_pages("/identity/conditionalAccess/policies")
        cae_policies = [p for p in policies
                       if p.get("state") == "enabled"
                       and p.get("sessionControls", {}).get("continuousAccessEvaluation", {}).get("mode") == "strictLocation"]
        return {
            "check_id": "AZURE-CA-017", "severity": "Medium",
            "status": "passed" if cae_policies else "failed",
            "score": 0.0 if cae_policies else 4.0,
            "affected_resources": [] if cae_policies else [{"issue": "No CAE strict mode policies configured"}],
            "evidence": {"cae_policies": len(cae_policies)},
            "risk_description": "Without CAE, revoked sessions and location changes are not immediately enforced — stolen tokens remain valid for their full lifetime.",
            "remediation_steps": "Create a CA policy with Session controls → Customize continuous access evaluation → Strict Location Enforcement for critical apps.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-017", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_no_expired_service_principal_secrets(graph, target_config):
    """AZURE-APP-011 — No service principals with expired credentials"""
    try:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        sps = graph.get_all_pages("/servicePrincipals?$select=id,displayName,passwordCredentials,keyCredentials")
        expired_sps = []
        for sp in sps:
            for cred in (sp.get("passwordCredentials") or []) + (sp.get("keyCredentials") or []):
                end = cred.get("endDateTime")
                if end:
                    exp = datetime.fromisoformat(end.replace("Z", "+00:00"))
                    if exp < now and not sp.get("displayName", "").startswith("Microsoft"):
                        expired_sps.append({"sp": sp.get("displayName"), "expired": end})
                        break
        return {
            "check_id": "AZURE-APP-011", "severity": "Medium",
            "status": "passed" if not expired_sps else "failed",
            "score": 4.0 if expired_sps else 0.0,
            "affected_resources": expired_sps[:20],
            "evidence": {"expired_sp_count": len(expired_sps)},
            "risk_description": "Service principals with expired credentials cause silent authentication failures in automated processes and CI/CD pipelines.",
            "remediation_steps": "Rotate expired credentials immediately. Implement a credential rotation process with 60-day advance alerts. Consider Managed Identities to eliminate credential management.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-011", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_b2c_policies_reviewed(graph, target_config):
    """AZURE-IDENTITY-014 — External authentication policies reviewed"""
    try:
        policy = graph.get("/policies/crossTenantAccessPolicy")
        allow_guests = policy.get("allowExternalIdentitiesToLeave", True)
        allow_email = policy.get("allowDeletedIdentitiesDataRemoval", False)
        return {
            "check_id": "AZURE-IDENTITY-014", "severity": "Low",
            "status": "passed", "score": 0.0,
            "affected_resources": [],
            "evidence": {"allow_external_leave": allow_guests, "external_policy_exists": True},
            "risk_description": "External identity policies control how guest users interact with your tenant. Permissive settings can expose internal data.",
            "remediation_steps": "Review Entra ID → External Identities → External collaboration settings quarterly. Ensure guest permissions are set to restricted access.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-014", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_privileged_role_separation(graph, target_config):
    """AZURE-PRIV-007 — Privileged and normal work accounts are separate"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        priv_names = {"Global Administrator","Security Administrator","Privileged Role Administrator"}
        dual_role_users = []
        for role in roles:
            if role.get("displayName") not in priv_names: continue
            for m in graph.get_all_pages(f"/directoryRoles/{role['id']}/members"):
                upn = m.get("userPrincipalName", "")
                # Check if admin UPN looks like a regular work account (not a dedicated admin account)
                if upn and not any(x in upn.lower() for x in ["-adm", "_adm", "admin@", ".admin@", "adm.", "priv"]):
                    dual_role_users.append({"user": m.get("displayName"), "upn": upn, "role": role.get("displayName")})
        return {
            "check_id": "AZURE-PRIV-007", "severity": "High",
            "status": "passed" if not dual_role_users else "failed",
            "score": 6.5 if dual_role_users else 0.0,
            "affected_resources": dual_role_users[:20],
            "evidence": {"mixed_accounts": len(dual_role_users)},
            "risk_description": "Using the same account for daily work and admin tasks means if the account is compromised via email phishing, the attacker immediately has administrative access.",
            "remediation_steps": "Create dedicated admin accounts (e.g. john.smith-admin@contoso.com) for privileged roles. Use personal accounts only for daily work like email and Teams.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PRIV-007", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_app_registration_count(graph, target_config):
    """AZURE-APP-012 — App registration count is reasonable"""
    try:
        apps = graph.get_all_pages("/applications?$select=id,displayName,createdDateTime")
        total = len(apps)
        excessive = total > 100
        return {
            "check_id": "AZURE-APP-012", "severity": "Low",
            "status": "passed" if not excessive else "failed",
            "score": 0.0 if not excessive else 2.5,
            "affected_resources": [{"total": total, "issue": "High number of app registrations — review for stale entries"}] if excessive else [],
            "evidence": {"total_apps": total},
            "risk_description": f"{total} app registrations found. Large numbers suggest unmanaged sprawl where stale apps with active credentials create dormant attack surfaces.",
            "remediation_steps": "Audit all app registrations. Delete apps that are no longer in use. Ensure every app has an owner assigned and credentials are current.",
            "estimated_effort": "High",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-012", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_mfa_fraud_alert(graph, target_config):
    """AZURE-MFA-011 — MFA fraud alert configured"""
    try:
        policy = graph.get("/policies/authenticationMethodsPolicy")
        report_suspicious = policy.get("reportSuspiciousActivitySettings", {})
        enabled = report_suspicious.get("state") == "enabled"
        return {
            "check_id": "AZURE-MFA-011", "severity": "Medium",
            "status": "passed" if enabled else "failed",
            "score": 0.0 if enabled else 4.5,
            "affected_resources": [] if enabled else [{"issue": "Report suspicious activity not enabled"}],
            "evidence": {"report_suspicious_enabled": enabled},
            "risk_description": "Without fraud alert, users cannot report unexpected MFA prompts (MFA fatigue attacks) and these incidents go undetected by the security team.",
            "remediation_steps": "Go to Entra ID → Security → Authentication methods → Settings → enable 'Report suspicious activity'. This lets users report unexpected MFA prompts, triggering an Identity Protection risk event.",
            "estimated_effort": "Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MFA-011", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_group_owners_exist(graph, target_config):
    """AZURE-GROUP-006 — All groups have at least one owner"""
    try:
        groups = graph.get_all_pages("/groups?$select=id,displayName,groupTypes")
        no_owner_groups = []
        for g in groups[:50]:
            try:
                owners = graph.get_all_pages(f"/groups/{g['id']}/owners")
                if not owners:
                    no_owner_groups.append({"group": g.get("displayName"), "id": g.get("id")})
            except Exception:
                pass
        return {
            "check_id": "AZURE-GROUP-006", "severity": "Medium",
            "status": "passed" if not no_owner_groups else "failed",
            "score": 3.5 if no_owner_groups else 0.0,
            "affected_resources": no_owner_groups[:20],
            "evidence": {"groups_checked": min(50, len(groups)), "no_owner_count": len(no_owner_groups)},
            "risk_description": "Groups without owners cannot be managed, reviewed, or expired properly. No one is accountable for who is a member.",
            "remediation_steps": "Assign at least one owner to every group. For orphaned groups (original owner left), reassign to the relevant team manager or department head.",
            "estimated_effort": "Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GROUP-006", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

EXTRA_CHECKS = [
    check_pim_notification_alerts,
    check_no_guest_global_admin,
    check_no_shared_accounts,
    check_privileged_role_count,
    check_app_multitenant_disabled,
    check_app_implicit_flow_disabled,
    check_no_reply_url_wildcards,
    check_conditional_access_policy_count,
    check_directory_role_assignments_reviewed,
    check_sign_in_logs_retained,
    check_emergency_access_monitored,
    check_admin_mfa_methods_strong,
    check_license_p2_available,
    check_no_legacy_auth_successful,
    check_token_lifetime_policy,
    check_continuous_access_evaluation,
    check_no_expired_service_principal_secrets,
    check_b2c_policies_reviewed,
    check_privileged_role_separation,
    check_app_registration_count,
    check_mfa_fraud_alert,
    check_group_owners_exist,
]

# Extend the main list
ALL_CHECKS.extend(EXTRA_CHECKS)

# ─── Checks from Assessment Worksheet (all 102) ───────────────────────────────

def check_block_dirsync_untrusted(graph, target_config):
    """AZURE-CA-DIRSYNC — Block dir sync accounts from untrusted networks"""
    try:
        policies = graph.get_all_pages("/identity/conditionalAccess/policies")
        users = graph.get_all_pages("/users?$filter=startswith(userPrincipalName,'Sync_')&$select=id,displayName,userPrincipalName")
        if not users:
            return {"check_id":"AZURE-CA-DIRSYNC","severity":"High","status":"passed","score":0.0,
                    "affected_resources":[],"evidence":{"sync_accounts":0},"risk_description":"No directory sync accounts found.",
                    "remediation_steps":"N/A — no Entra ID Connect sync accounts detected.","estimated_effort":"Low"}
        # Look for CA policy targeting sync accounts with location condition
        sync_protected = any(
            p.get("state")=="enabled" and p.get("conditions",{}).get("locations",{})
            for p in policies
        )
        return {
            "check_id":"AZURE-CA-DIRSYNC","severity":"High",
            "status":"passed" if sync_protected else "failed",
            "score":0.0 if sync_protected else 9.0,
            "affected_resources":[{"upn":u.get("userPrincipalName")} for u in users],
            "evidence":{"sync_accounts":len(users),"location_policy":sync_protected},
            "risk_description":"Directory sync accounts (Sync_XXXX_@tenant.onmicrosoft.com) should only authenticate from trusted on-premises networks. If compromised, these accounts can manipulate directory objects.",
            "remediation_steps":"Create a CA policy targeting Sync_ accounts with location condition: only allow from trusted named locations (your on-premises IP ranges). Block all other locations.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-DIRSYNC", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_pim_require_approver(graph, target_config):
    """AZURE-PIM-APPROVER — Require approver for high-privilege role activation"""
    try:
        policies = graph.get_all_pages("/policies/roleManagementPolicies?$filter=scopeType eq 'Directory'")
        no_approver = []
        high_priv_roles = {"Global Administrator","Privileged Role Administrator","Security Administrator"}
        for policy in policies:
            role_name = policy.get("displayName","")
            if not any(r in role_name for r in high_priv_roles):
                continue
            rules = policy.get("rules",[])
            for rule in rules:
                if rule.get("@odata.type","").endswith("ApprovalRule"):
                    approval = rule.get("setting",{}).get("approvalStages",[])
                    if not approval or not approval[0].get("primaryApprovers"):
                        no_approver.append({"role":role_name})
        return {
            "check_id":"AZURE-PIM-APPROVER","severity":"High",
            "status":"passed" if not no_approver else "failed",
            "score":0.0 if not no_approver else 5.4,
            "affected_resources":no_approver,
            "evidence":{"policies_checked":len(policies),"no_approver":len(no_approver)},
            "risk_description":"Without approval requirements, a compromised eligible user can immediately activate Global Admin with no oversight or delay — making stolen credentials immediately dangerous.",
            "remediation_steps":"In PIM → Azure AD roles → Settings → Global Administrator → Edit → Require approval → add 2+ security team members as approvers. Repeat for Privileged Role Admin and Security Admin.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PIM-APPROVER", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_remove_stale_dirsync_accounts(graph, target_config):
    """AZURE-IDENTITY-DIRSYNC — Remove unused directory synchronization accounts"""
    try:
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        users = graph.get_all_pages("/users?$filter=startswith(userPrincipalName,'Sync_')&$select=id,displayName,userPrincipalName,signInActivity,accountEnabled")
        stale = [
            {"upn":u.get("userPrincipalName"),"last_signin":u.get("signInActivity",{}).get("lastSignInDateTime","Never")}
            for u in users
            if u.get("accountEnabled") and (
                not u.get("signInActivity",{}).get("lastSignInDateTime") or
                datetime.fromisoformat(u["signInActivity"]["lastSignInDateTime"].replace("Z","+00:00")) < cutoff
            )
        ]
        return {
            "check_id":"AZURE-IDENTITY-DIRSYNC","severity":"High",
            "status":"passed" if not stale else "failed",
            "score":0.0 if not stale else 5.4,
            "affected_resources":stale,
            "evidence":{"total_sync_accounts":len(users),"stale":len(stale)},
            "risk_description":"Old Entra ID Connect sync accounts (Sync_XXXX_@tenant.onmicrosoft.com) from decommissioned servers retain Directory Synchronization Accounts role. If credentials are known, they can be used to sync malicious objects.",
            "remediation_steps":"Identify which server each Sync_ account belonged to. If the server is decommissioned, disable and delete the account. If still needed, verify it is protected by a CA policy restricting authentication to trusted IPs.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-DIRSYNC", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_block_security_reg_on_risk(graph, target_config):
    """AZURE-CA-SECREG — Block security info registration when sign-in risk detected"""
    try:
        policies = graph.get_all_pages("/identity/conditionalAccess/policies")
        reg_policies = [
            p for p in policies if p.get("state")=="enabled"
            and "registerSecurityInfo" in str(p.get("conditions",{}).get("applications",{}).get("includeUserActions",[]))
            and (p.get("conditions",{}).get("signInRiskLevels") or p.get("grantControls",{}).get("builtInControls",[])==["block"])
        ]
        return {
            "check_id":"AZURE-CA-SECREG","severity":"High",
            "status":"passed" if reg_policies else "failed",
            "score":0.0 if reg_policies else 5.9,
            "affected_resources":[] if reg_policies else [{"issue":"No CA policy protecting security info registration on risk"}],
            "evidence":{"protecting_policies":len(reg_policies)},
            "risk_description":"If a bad actor compromises a user account, they can register their own MFA methods to lock out the legitimate user and maintain persistent access. Blocking security info registration on risk prevents this.",
            "remediation_steps":"Create CA policy: User action → Register security information. Conditions → Sign-in risk → Medium and High. Grant → Block access. This prevents attackers from registering MFA methods on compromised accounts.",
            "estimated_effort":"Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-SECREG", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_block_admin_portals_on_risk(graph, target_config):
    """AZURE-CA-ADMINRISK — Block admin portal access when sign-in risk detected"""
    try:
        policies = graph.get_all_pages("/identity/conditionalAccess/policies")
        admin_risk = [
            p for p in policies if p.get("state")=="enabled"
            and "MicrosoftAdminPortals" in str(p.get("conditions",{}).get("applications",{}).get("includeApplications",[]))
            and p.get("conditions",{}).get("signInRiskLevels")
        ]
        return {
            "check_id":"AZURE-CA-ADMINRISK","severity":"High",
            "status":"passed" if admin_risk else "failed",
            "score":0.0 if admin_risk else 5.4,
            "affected_resources":[] if admin_risk else [{"issue":"No CA policy blocking admin portal access on sign-in risk"}],
            "evidence":{"policies":len(admin_risk)},
            "risk_description":"Microsoft Admin Portals (Azure Portal, M365 Admin Center, Exchange Admin) provide tenant-wide configuration access. Blocking access on sign-in risk prevents attackers from making changes even if they have valid credentials.",
            "remediation_steps":"Create CA policy: Cloud apps → Microsoft Admin Portals. Conditions → Sign-in risk → Medium and High. Grant → Block access. This is separate from your standard risk policy to ensure admin portals have stricter controls.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-ADMINRISK", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_pim_mfa_on_activation(graph, target_config):
    """AZURE-PIM-MFA — PIM requires MFA on role activation"""
    try:
        policies = graph.get_all_pages("/policies/roleManagementPolicies?$filter=scopeType eq 'Directory'")
        no_mfa = []
        for policy in policies:
            rules = policy.get("rules",[])
            for rule in rules:
                if rule.get("@odata.type","").endswith("AuthenticationContextRule"):
                    if not rule.get("isEnabled"):
                        no_mfa.append({"policy":policy.get("displayName")})
        return {
            "check_id":"AZURE-PIM-MFA","severity":"High",
            "status":"passed" if not no_mfa else "failed",
            "score":0.0 if not no_mfa else 4.8,
            "affected_resources":no_mfa[:10],
            "evidence":{"policies_without_mfa":len(no_mfa)},
            "risk_description":"PIM role activation without MFA requirement means an attacker who steals an eligible user's password can immediately activate privileged roles without additional challenge.",
            "remediation_steps":"In PIM → Azure AD roles → Settings → for each role → Edit → On activation, require → Azure MFA. Enable this for all roles, especially Global Administrator and Security Administrator.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PIM-MFA", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_ca_persistent_session_guest(graph, target_config):
    """AZURE-CA-GUESTSESSION — Configure session timeout for guests"""
    try:
        policies = graph.get_all_pages("/identity/conditionalAccess/policies")
        guest_session = [
            p for p in policies if p.get("state")=="enabled"
            and "GuestsOrExternalUsers" in str(p.get("conditions",{}).get("users",{}))
            and p.get("sessionControls",{}).get("signInFrequency",{}).get("isEnabled")
        ]
        return {
            "check_id":"AZURE-CA-GUESTSESSION","severity":"Medium",
            "status":"passed" if guest_session else "failed",
            "score":0.0 if guest_session else 4.8,
            "affected_resources":[] if guest_session else [{"issue":"No sign-in frequency policy for guests"}],
            "evidence":{"guest_session_policies":len(guest_session)},
            "risk_description":"Guests may access your tenant from personal devices that are not managed. Without session timeout, a session on a lost or shared device could remain valid indefinitely.",
            "remediation_steps":"Create CA policy: Users → Guests. Cloud apps → All cloud apps. Session → Sign-in frequency → Every 1 day or Every 7 days depending on sensitivity. Also enable Persistent browser → Never persistent.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-GUESTSESSION", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_ca_unmanaged_device_session(graph, target_config):
    """AZURE-CA-UNMGDSESSION — Require non-persistent session for unmanaged devices"""
    try:
        policies = graph.get_all_pages("/identity/conditionalAccess/policies")
        unmgd_session = [
            p for p in policies if p.get("state")=="enabled"
            and p.get("sessionControls",{}).get("persistentBrowser",{}).get("isEnabled")
            and p.get("conditions",{}).get("devices",{}).get("deviceFilter",{}).get("mode")=="exclude"
        ]
        return {
            "check_id":"AZURE-CA-UNMGDSESSION","severity":"Medium",
            "status":"passed" if unmgd_session else "failed",
            "score":0.0 if unmgd_session else 4.4,
            "affected_resources":[] if unmgd_session else [{"issue":"No non-persistent session policy for unmanaged devices"}],
            "evidence":{"policies":len(unmgd_session)},
            "risk_description":"Unmanaged personal devices may be shared, lost, or stolen. Persistent browser sessions on these devices leave users permanently signed in, enabling anyone with device access to access corporate resources.",
            "remediation_steps":"Create CA policy: All users. Cloud apps → All cloud apps. Conditions → Filter for devices → Device not marked as compliant AND not Hybrid Azure AD joined. Session → Persistent browser session → Never. Sign-in frequency → 1 hour.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-UNMGDSESSION", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_ca_exclusion_groups(graph, target_config):
    """AZURE-CA-EXCLUSIONS — CA exclusions use dedicated groups"""
    try:
        policies = graph.get_all_pages("/identity/conditionalAccess/policies")
        enabled = [p for p in policies if p.get("state")=="enabled"]
        direct_user_exclusions = []
        for p in enabled:
            excl = p.get("conditions",{}).get("users",{}).get("excludeUsers",[])
            if len(excl) > 2:  # more than 2 direct user exclusions suggests poor practice
                direct_user_exclusions.append({
                    "policy": p.get("displayName"),
                    "excluded_users": len(excl)
                })
        return {
            "check_id":"AZURE-CA-EXCLUSIONS","severity":"Medium",
            "status":"passed" if not direct_user_exclusions else "failed",
            "score":0.0 if not direct_user_exclusions else 4.6,
            "affected_resources":direct_user_exclusions,
            "evidence":{"policies_with_direct_exclusions":len(direct_user_exclusions)},
            "risk_description":"Managing CA exclusions as individual user lists is error-prone and hard to audit. Users added directly are easily forgotten. Groups provide accountability, access reviews, and centralized management.",
            "remediation_steps":"Create dedicated exclusion security groups (e.g. 'CA-Exclusion-BreakGlass', 'CA-Exclusion-ServiceAccounts'). Replace all individual user exclusions with these groups. Configure access reviews for exclusion group membership quarterly.",
            "estimated_effort":"Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-EXCLUSIONS", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_remove_admin_mailboxes(graph, target_config):
    """AZURE-PRIV-MAILBOX — Privileged admins should not have mailboxes on admin accounts"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        priv_names = {"Global Administrator","Privileged Role Administrator","Security Administrator"}
        admins_with_mail = []
        for role in roles:
            if role.get("displayName") not in priv_names: continue
            for m in graph.get_all_pages(f"/directoryRoles/{role['id']}/members"):
                try:
                    u = graph.get(f"/users/{m['id']}?$select=displayName,userPrincipalName,mail,proxyAddresses")
                    if u.get("mail") and not u.get("userPrincipalName","").endswith(".onmicrosoft.com"):
                        # Has a routable mail address on admin account
                        admins_with_mail.append({
                            "user": u.get("displayName"),
                            "upn": u.get("userPrincipalName"),
                            "mail": u.get("mail"),
                            "role": role.get("displayName")
                        })
                except Exception:
                    pass
        return {
            "check_id":"AZURE-PRIV-MAILBOX","severity":"High",
            "status":"passed" if not admins_with_mail else "failed",
            "score":0.0 if not admins_with_mail else 5.2,
            "affected_resources":admins_with_mail[:20],
            "evidence":{"admins_with_mail":len(admins_with_mail)},
            "risk_description":"Admin accounts with mailboxes are exposed to phishing attacks delivered to that mailbox. An admin clicking a phishing link while logged in as their admin account can immediately lead to tenant compromise.",
            "remediation_steps":"Create cloud-only admin accounts (john.smith-admin@tenant.onmicrosoft.com) with no mailbox. Remove privileged roles from mail-enabled accounts. Admins should use their regular mail-enabled account for email and their cloud-only account for admin tasks.",
            "estimated_effort":"Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PRIV-MAILBOX", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_block_msol_powershell(graph, target_config):
    """AZURE-CA-MSOL — Block access to MSOL/legacy PowerShell endpoints"""
    try:
        policies = graph.get_all_pages("/identity/conditionalAccess/policies")
        # MSOL PowerShell App ID: 1b730954-1685-4b74-9bfd-dac224a7b894 (Azure AD PowerShell)
        msol_blocked = any(
            p.get("state")=="enabled"
            and "1b730954-1685-4b74-9bfd-dac224a7b894" in str(p.get("conditions",{}).get("applications",{}).get("includeApplications",[]))
            and "block" in str(p.get("grantControls",{}).get("builtInControls",[])).lower()
            for p in policies
        )
        # Also check if legacy auth is blocked (which covers MSOL)
        legacy_blocked = any(
            p.get("state")=="enabled"
            and p.get("conditions",{}).get("clientAppTypes")
            and "other" in str(p.get("conditions",{}).get("clientAppTypes",[])).lower()
            and "block" in str(p.get("grantControls",{}).get("builtInControls",[])).lower()
            for p in policies
        )
        protected = msol_blocked or legacy_blocked
        return {
            "check_id":"AZURE-CA-MSOL","severity":"Medium",
            "status":"passed" if protected else "failed",
            "score":0.0 if protected else 3.2,
            "affected_resources":[] if protected else [{"issue":"MSOL PowerShell not explicitly blocked"}],
            "evidence":{"msol_blocked":msol_blocked,"legacy_blocked":legacy_blocked},
            "risk_description":"MSOL (Microsoft Online Services) PowerShell is deprecated and no longer receives security updates. Known exploits exist. Blocking prevents use of legacy unpatched authentication paths.",
            "remediation_steps":"If legacy auth is already blocked by CA policy, MSOL is also covered. To block explicitly: CA policy → Cloud apps → Azure Active Directory PowerShell (App ID: 1b730954-1685-4b74-9bfd-dac224a7b894) → Block. Migrate scripts to Microsoft Graph PowerShell SDK.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-MSOL", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_stale_cloud_only_users(graph, target_config):
    """AZURE-IDENTITY-STALE — Disable or remove stale cloud-only users"""
    try:
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        # Cloud-only users (not synced from on-premises)
        users = graph.get_all_pages("/users?$select=id,displayName,userPrincipalName,signInActivity,accountEnabled,onPremisesSyncEnabled")
        stale = [
            {"user":u.get("displayName"),"upn":u.get("userPrincipalName"),
             "last_signin":u.get("signInActivity",{}).get("lastSignInDateTime","Never")}
            for u in users
            if not u.get("onPremisesSyncEnabled")  # cloud-only
            and u.get("accountEnabled")
            and (
                not u.get("signInActivity",{}).get("lastSignInDateTime") or
                datetime.fromisoformat(u["signInActivity"]["lastSignInDateTime"].replace("Z","+00:00")) < cutoff
            )
            and not u.get("userPrincipalName","").startswith("Sync_")
        ]
        return {
            "check_id":"AZURE-IDENTITY-STALE","severity":"Medium",
            "status":"passed" if not stale else "failed",
            "score":0.0 if not stale else 3.0,
            "affected_resources":stale[:20],
            "evidence":{"stale_cloud_users":len(stale)},
            "risk_description":"Stale cloud-only accounts (inactive 90+ days) represent dormant attack surfaces. These accounts retain access to applications they were assigned to and could be reactivated by an attacker.",
            "remediation_steps":"Review each stale account — confirm with the user's manager if they still need access. Disable accounts with no confirmed need. After 180 days of no confirmed need, delete. Automate this with Identity Governance lifecycle workflows.",
            "estimated_effort":"Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-IDENTITY-STALE", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_app_http_redirect_uris(graph, target_config):
    """AZURE-APP-HTTP — Application redirect URIs not using HTTPS"""
    try:
        apps = graph.get_all_pages("/applications?$select=id,displayName,web,spa,publicClient")
        http_apps = []
        for a in apps:
            for section in ["web","spa"]:
                s = a.get(section,{}) or {}
                http_uris = [u for u in s.get("redirectUris",[]) if u.startswith("http://") and "localhost" not in u.lower()]
                if http_uris:
                    http_apps.append({"app":a.get("displayName"),"http_uris":http_uris[:3]})
        return {
            "check_id":"AZURE-APP-HTTP","severity":"Medium",
            "status":"passed" if not http_apps else "failed",
            "score":0.0 if not http_apps else 2.3,
            "affected_resources":http_apps[:20],
            "evidence":{"apps_with_http":len(http_apps)},
            "risk_description":"HTTP redirect URIs transmit authorization codes in plaintext. An attacker performing a man-in-the-middle attack or monitoring network traffic can intercept these codes and redeem them for tokens.",
            "remediation_steps":"Update all redirect URIs to use HTTPS. In app registration → Authentication → Redirect URIs → change http:// to https://. Update your application configuration to match. HTTP is only acceptable for localhost (development only).",
            "estimated_effort":"Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-HTTP", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_pim_max_activation_duration(graph, target_config):
    """AZURE-PIM-DURATION — PIM maximum activation duration per best practice"""
    try:
        policies = graph.get_all_pages("/policies/roleManagementPolicies?$filter=scopeType eq 'Directory'")
        long_duration = []
        for policy in policies:
            role_name = policy.get("displayName","")
            is_high_priv = any(r in role_name for r in ["Global","Privileged Role","Security Admin"])
            for rule in policy.get("rules",[]):
                if rule.get("@odata.type","").endswith("ExpirationRule"):
                    max_dur = rule.get("maximumDuration","")
                    # PT8H = 8 hours, PT4H = 4 hours
                    if is_high_priv and max_dur and "PT" in max_dur:
                        hours = int(max_dur.replace("PT","").replace("H","").replace("M","").split(".")[0] or 0)
                        if hours > 4:
                            long_duration.append({"role":role_name,"max_hours":hours})
        return {
            "check_id":"AZURE-PIM-DURATION","severity":"Low",
            "status":"passed" if not long_duration else "failed",
            "score":0.0 if not long_duration else 2.3,
            "affected_resources":long_duration,
            "evidence":{"roles_with_long_duration":len(long_duration)},
            "risk_description":"Long PIM activation windows (>4 hours for high-privilege roles) give attackers more time to operate if they successfully activate a role using stolen credentials.",
            "remediation_steps":"In PIM → Azure AD roles → Settings → for Global Admin and other high-privilege roles → Edit → Maximum activation duration → set to 2-4 hours. Admins who need longer can reactivate.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PIM-DURATION", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_remove_personal_email_from_admins(graph, target_config):
    """AZURE-PRIV-PERSONALEMAIL — Remove personal email from admin accounts"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        priv_names = {"Global Administrator","Security Administrator","Privileged Role Administrator"}
        personal_email_admins = []
        for role in roles:
            if role.get("displayName") not in priv_names: continue
            for m in graph.get_all_pages(f"/directoryRoles/{role['id']}/members"):
                try:
                    u = graph.get(f"/users/{m['id']}?$select=displayName,userPrincipalName,otherMails")
                    other_mails = u.get("otherMails",[])
                    upn_domain = u.get("userPrincipalName","").split("@")[-1]
                    personal = [e for e in other_mails if e.split("@")[-1] != upn_domain and e.split("@")[-1] not in ["microsoft.com","outlook.com"]]
                    if personal:
                        personal_email_admins.append({"user":u.get("displayName"),"upn":u.get("userPrincipalName"),"personal_emails":personal})
                except Exception:
                    pass
        return {
            "check_id":"AZURE-PRIV-PERSONALEMAIL","severity":"High",
            "status":"passed" if not personal_email_admins else "failed",
            "score":0.0 if not personal_email_admins else 2.3,
            "affected_resources":personal_email_admins,
            "evidence":{"admins_with_personal_email":len(personal_email_admins)},
            "risk_description":"Personal email addresses on admin accounts can be used for MFA recovery or self-service password reset. These personal accounts are outside your organisation's security controls and can be easily compromised.",
            "remediation_steps":"Remove personal email addresses (otherMails) from all admin accounts. Use only corporate email for any recovery contact methods. In Entra ID → Users → select admin → Edit → Contact info → remove personal emails.",
            "estimated_effort":"Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PRIV-PERSONALEMAIL", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_service_principals_not_admins(graph, target_config):
    """AZURE-PRIV-SP — Service principals should not be in privileged roles"""
    try:
        roles = graph.get_all_pages("/directoryRoles")
        sp_in_roles = []
        for role in roles:
            members = graph.get_all_pages(f"/directoryRoles/{role['id']}/members")
            for m in members:
                if m.get("@odata.type") == "#microsoft.graph.servicePrincipal":
                    sp_in_roles.append({"sp":m.get("displayName"),"role":role.get("displayName")})
        return {
            "check_id":"AZURE-PRIV-SP","severity":"High",
            "status":"passed" if not sp_in_roles else "failed",
            "score":0.0 if not sp_in_roles else 2.8,
            "affected_resources":sp_in_roles[:20],
            "evidence":{"sps_in_roles":len(sp_in_roles)},
            "risk_description":"Service principals in privileged directory roles create persistent, non-human privileged access that cannot be protected by MFA and doesn't generate normal user sign-in activity for monitoring.",
            "remediation_steps":"Remove service principals from directory roles. Use granular Microsoft Graph application permissions instead of directory roles. If the SP needs directory read access, use Directory.Read.All application permission rather than Directory Reader role.",
            "estimated_effort":"Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PRIV-SP", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_bg_password_rotation(graph, target_config):
    """AZURE-BG-ROTATION — Break glass account passwords changed regularly"""
    bg_group_id = target_config.get("break_glass_group_id","")
    try:
        if not bg_group_id:
            return {"check_id":"AZURE-BG-ROTATION","severity":"Medium","status":"failed","score":3.4,
                    "affected_resources":[{"issue":"Break glass group ID not configured"}],
                    "evidence":{"bg_group_configured":False},
                    "risk_description":"Break glass account passwords should be rotated at least annually to ensure they haven't been compromised.",
                    "remediation_steps":"Configure break glass group ID in target settings. Then establish a process to rotate break glass passwords at least every 12 months. Document each rotation with date and witnesses in a security log.",
                    "estimated_effort":"Low"}
        members = graph.get_all_pages(f"/groups/{bg_group_id}/members?$select=id,displayName,userPrincipalName,lastPasswordChangeDateTime")
        old_passwords = []
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=365)
        for m in members:
            last_change = m.get("lastPasswordChangeDateTime")
            if last_change:
                change_dt = datetime.fromisoformat(last_change.replace("Z","+00:00"))
                if change_dt < cutoff:
                    old_passwords.append({"user":m.get("displayName"),"last_changed":last_change})
        return {
            "check_id":"AZURE-BG-ROTATION","severity":"Medium",
            "status":"passed" if not old_passwords else "failed",
            "score":0.0 if not old_passwords else 3.4,
            "affected_resources":old_passwords,
            "evidence":{"bg_accounts":len(members),"old_passwords":len(old_passwords)},
            "risk_description":"Break glass account passwords that haven't been rotated may have been observed or noted by former employees or others present during previous uses.",
            "remediation_steps":"Rotate break glass passwords at least annually or after any use. Generate a new 30+ character random password. Update the physical safe with the new password. Document the rotation with date and the two witnesses who were present.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-BG-ROTATION", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_all_users_group_apps(graph, target_config):
    """AZURE-APP-ALLUSERS — Review apps assigned to All Users group"""
    try:
        # Get the "All Users" group GUID
        groups = graph.get_all_pages("/groups?$filter=displayName eq 'All Users'&$select=id,displayName")
        if not groups:
            # Also check for common all-user groups
            groups = graph.get_all_pages("/groups?$select=id,displayName,groupTypes&$top=999")
            all_user_groups = [g for g in groups if g.get("displayName","").lower() in ["all users","everyone","all employees","all staff"]]
        else:
            all_user_groups = groups

        if not all_user_groups:
            return {"check_id":"AZURE-APP-ALLUSERS","severity":"Medium","status":"passed","score":0.0,
                    "affected_resources":[],"evidence":{"all_users_groups":0},
                    "risk_description":"No 'All Users' group found.","remediation_steps":"N/A","estimated_effort":"Low"}

        apps_with_all_users = []
        for group in all_user_groups[:3]:  # Check top 3 all-user groups
            try:
                sp_assignments = graph.get_all_pages(f"/groups/{group['id']}/appRoleAssignments")
                for assignment in sp_assignments:
                    apps_with_all_users.append({
                        "group":group.get("displayName"),
                        "app":assignment.get("resourceDisplayName"),
                        "sp_id":assignment.get("resourceId")
                    })
            except Exception:
                pass

        return {
            "check_id":"AZURE-APP-ALLUSERS","severity":"Medium",
            "status":"passed" if not apps_with_all_users else "failed",
            "score":0.0 if not apps_with_all_users else 4.9,
            "affected_resources":apps_with_all_users[:20],
            "evidence":{"all_users_groups":len(all_user_groups),"apps_assigned":len(apps_with_all_users)},
            "risk_description":"Applications assigned to 'All Users' include guests by default. Resource owners may believe 'All Users' means only employees, accidentally exposing applications to all guest users in the tenant.",
            "remediation_steps":"Replace 'All Users' group assignments with specific security groups containing only the intended users (excluding guests). Enable 'User assignment required' on the application and explicitly assign the right user group.",
            "estimated_effort":"Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-ALLUSERS", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_pim_two_approvers(graph, target_config):
    """AZURE-PIM-2APPROVERS — At least 2 approvers for high-privilege PIM activation"""
    try:
        policies = graph.get_all_pages("/policies/roleManagementPolicies?$filter=scopeType eq 'Directory'")
        single_approver = []
        high_priv = {"Global Administrator","Privileged Role Administrator"}
        for policy in policies:
            role_name = policy.get("displayName","")
            if not any(r in role_name for r in high_priv): continue
            for rule in policy.get("rules",[]):
                if rule.get("@odata.type","").endswith("ApprovalRule"):
                    stages = rule.get("setting",{}).get("approvalStages",[])
                    if stages:
                        approvers = stages[0].get("primaryApprovers",[])
                        if len(approvers) < 2:
                            single_approver.append({"role":role_name,"approvers":len(approvers)})
        return {
            "check_id":"AZURE-PIM-2APPROVERS","severity":"Low",
            "status":"passed" if not single_approver else "failed",
            "score":0.0 if not single_approver else 0.4,
            "affected_resources":single_approver,
            "evidence":{"single_approver_roles":len(single_approver)},
            "risk_description":"With only one approver, PIM activation requests are blocked when that person is unavailable (holiday, sick, out of hours). Two approvers ensures business continuity for legitimate activation requests.",
            "remediation_steps":"In PIM → Azure AD roles → Settings → Global Administrator → Edit → Require approval → add at least 2 approvers from your security team or management. Both can independently approve requests.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-PIM-2APPROVERS", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_workload_identity_risk(graph, target_config):
    """AZURE-APP-WORKLOADRISK — Block service principals with risk detections"""
    try:
        risky_sps = graph.get_all_pages("/identityProtection/riskyServicePrincipals?$select=id,displayName,riskLevel,riskState")
        at_risk = [
            {"sp":s.get("displayName"),"risk":s.get("riskLevel"),"state":s.get("riskState")}
            for s in risky_sps
            if s.get("riskState")=="atRisk"
        ]
        return {
            "check_id":"AZURE-APP-WORKLOADRISK","severity":"High",
            "status":"passed" if not at_risk else "failed",
            "score":0.0 if not at_risk else 3.4,
            "affected_resources":at_risk[:20],
            "evidence":{"risky_sps":len(at_risk)},
            "risk_description":"Service principals flagged as at-risk indicate compromised or anomalous application credentials. These may be actively used by attackers to access tenant resources.",
            "remediation_steps":"Investigate each risky service principal in Identity Protection → Risky workload identities. Rotate credentials immediately for compromised SPs. Review recent activity logs. Enable Conditional Access for workload identities (requires Entra ID P2 Workload Identity Premium).",
            "estimated_effort":"Moderate",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-APP-WORKLOADRISK", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_stale_risky_users_dismissed(graph, target_config):
    """AZURE-RISK-STALE — Dismiss stale risky user status"""
    try:
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        risky = graph.get_all_pages("/identityProtection/riskyUsers?$top=100")
        stale_risky = [
            {"user":u.get("displayName"),"upn":u.get("userPrincipalName"),
             "risk":u.get("riskLevel"),"last_updated":u.get("riskLastUpdatedDateTime")}
            for u in risky
            if u.get("riskLastUpdatedDateTime") and
            datetime.fromisoformat(u["riskLastUpdatedDateTime"].replace("Z","+00:00")) < cutoff
        ]
        return {
            "check_id":"AZURE-RISK-STALE","severity":"Low",
            "status":"passed" if not stale_risky else "failed",
            "score":0.0 if not stale_risky else 3.2,
            "affected_resources":stale_risky[:20],
            "evidence":{"stale_risky_users":len(stale_risky)},
            "risk_description":"Risky user statuses older than 90 days that haven't been resolved create noise in Identity Protection dashboards and make it harder to identify genuine active threats.",
            "remediation_steps":"In Entra ID → Security → Identity Protection → Risky users, review each stale entry. If the risk was investigated and resolved: Dismiss user risk. If still potentially compromised: Confirm compromised and require password reset. Close all open cases to maintain a clean signal-to-noise ratio.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-RISK-STALE", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_users_lockout_count(graph, target_config):
    """AZURE-MONITORING-LOCKOUT — Review users with high lockout counts"""
    try:
        # Smart-lockout sign-ins (error 50053) from the sign-in log. This used
        # to query directoryAudits with $top=1, which could never reach the
        # threshold below, so the check passed unconditionally.
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs = graph.get(f"/auditLogs/signIns?$filter=status/errorCode eq 50053 and createdDateTime ge {since}&$top=999")
        locked_users = {}
        for entry in logs.get("value") or []:
            upn = entry.get("userPrincipalName","")
            if upn:
                locked_users[upn] = locked_users.get(upn,0) + 1
        high_lockout = [{"upn":k,"lockout_events":v} for k,v in locked_users.items() if v >= 3]
        return {
            "check_id":"AZURE-MONITORING-LOCKOUT","severity":"Medium",
            "status":"passed" if not high_lockout else "failed",
            "score":0.0 if not high_lockout else 3.2,
            "affected_resources":high_lockout,
            "evidence":{"users_with_lockouts":len(high_lockout)},
            "risk_description":"High lockout counts indicate either a user who forgot their password (support risk) or an active brute-force attack against their account. Both require investigation.",
            "remediation_steps":"Investigate each user in sign-in logs → filter by that UPN and error codes 50053/50055. If attack: block the source IPs in named locations, force password reset. If user issue: assist with password reset and check their MFA setup. Enable Self-Service Password Reset to reduce helpdesk load.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-MONITORING-LOCKOUT", "severity": "Medium",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_delete_empty_groups(graph, target_config):
    """AZURE-GROUP-EMPTY — Delete empty cloud-only groups"""
    try:
        _advanced = {"ConsistencyLevel": "eventual"}  # required for NOT filters and /$count
        groups = graph.get_all_pages("/groups?$select=id,displayName,groupTypes&$filter=NOT(groupTypes/any(t:t eq 'DynamicMembership'))&$count=true", headers=_advanced)
        empty_groups = []
        for g in groups[:50]:
            try:
                count_resp = graph.get(f"/groups/{g['id']}/members/$count", headers=_advanced)
                # count_resp may return integer directly
                if isinstance(count_resp, int) and count_resp == 0:
                    empty_groups.append({"group":g.get("displayName"),"id":g.get("id")})
            except Exception:
                pass
        return {
            "check_id":"AZURE-GROUP-EMPTY","severity":"Low",
            "status":"passed" if not empty_groups else "failed",
            "score":0.0 if not empty_groups else 0.2,
            "affected_resources":empty_groups[:20],
            "evidence":{"empty_groups_found":len(empty_groups)},
            "risk_description":"Empty groups clutter the directory, confuse administrators trying to manage access, and can accidentally be assigned permissions in the future when refilled.",
            "remediation_steps":"Review each empty group — confirm with the owner if the group is still needed (perhaps it's newly created awaiting members). Delete groups with no members and no planned use. Set up group expiration policy to automatically clean up unused groups.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-GROUP-EMPTY", "severity": "Low",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }

def check_block_ca_without_exclusion(graph, target_config):
    """AZURE-CA-BLOCKEXCL — Block CA policies should have exclusion groups"""
    try:
        policies = graph.get_all_pages("/identity/conditionalAccess/policies")
        block_policies = [
            p for p in policies if p.get("state")=="enabled"
            and "block" in str(p.get("grantControls",{}).get("builtInControls",[])).lower()
        ]
        no_exclusion = [
            {"policy":p.get("displayName")}
            for p in block_policies
            if not p.get("conditions",{}).get("users",{}).get("excludeGroups")
            and not p.get("conditions",{}).get("users",{}).get("excludeUsers")
        ]
        return {
            "check_id":"AZURE-CA-BLOCKEXCL","severity":"High",
            "status":"passed" if not no_exclusion else "failed",
            "score":0.0 if not no_exclusion else 3.0,
            "affected_resources":no_exclusion,
            "evidence":{"block_policies":len(block_policies),"without_exclusion":len(no_exclusion)},
            "risk_description":"CA policies with block access controls and no exclusions risk complete organisational lockout if misconfigured. A block policy targeting all users with no break glass exclusion could lock every admin out of the tenant.",
            "remediation_steps":"Add your break glass exclusion group to every CA policy that uses the Block access grant control. This ensures emergency access is always available even if a policy is misconfigured.",
            "estimated_effort":"Low",
        }
    except Exception as e:
        _err = str(e)
        _status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"
        _rem = ("Grant the required Microsoft Graph API permission and click 'Grant admin consent' in the Azure Portal." if _status == "failed" else "Check the worker logs for details.")
        return {
            "check_id": "AZURE-CA-BLOCKEXCL", "severity": "High",
            "status": _status, "score": 0.0, "affected_resources": [],
            "evidence": {"error": _err},
            "risk_description": "Check failed to run.",
            "remediation_steps": _rem,
            "estimated_effort": "Low",
        }


# ─── Add all new checks to ALL_CHECKS ────────────────────────────────────────
WORKSHEET_CHECKS = [
    check_block_dirsync_untrusted,
    check_pim_require_approver,
    check_remove_stale_dirsync_accounts,
    check_block_security_reg_on_risk,
    check_block_admin_portals_on_risk,
    check_pim_mfa_on_activation,
    check_ca_persistent_session_guest,
    check_ca_unmanaged_device_session,
    check_ca_exclusion_groups,
    check_remove_admin_mailboxes,
    check_block_msol_powershell,
    check_stale_cloud_only_users,
    check_app_http_redirect_uris,
    check_pim_max_activation_duration,
    check_remove_personal_email_from_admins,
    check_service_principals_not_admins,
    check_bg_password_rotation,
    check_all_users_group_apps,
    check_pim_two_approvers,
    check_workload_identity_risk,
    check_stale_risky_users_dismissed,
    check_users_lockout_count,
    check_delete_empty_groups,
    check_block_ca_without_exclusion,
]

ALL_CHECKS.extend(WORKSHEET_CHECKS)
