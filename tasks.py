from app.celery_app import celery_app
from app.connectors.ms_graph import MSGraphClient
import os, json, logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

DB_URL  = os.getenv("DATABASE_URL", "").replace("+asyncpg", "+psycopg2")
engine  = create_engine(DB_URL, pool_pre_ping=True)
Session = sessionmaker(bind=engine)

def get_credentials():
    return {
        "tenant_id":     os.getenv("ENTRA_TENANT_ID", ""),
        "client_id":     os.getenv("ENTRA_CLIENT_ID", ""),
        "client_secret": os.getenv("ENTRA_CLIENT_SECRET", ""),
    }

def update_run(_, run_id: str, **kwargs):
    with engine.connect() as conn:
        sets = ", ".join(f"{k}=:{k}" for k in kwargs)
        conn.execute(text(f"UPDATE scan_runs SET {sets} WHERE id=:run_id"),
                     {**kwargs, "run_id": run_id})
        conn.commit()

def save_finding(run_id: str, target_id: str, result: dict):
    now       = datetime.now(timezone.utc)
    resources = json.dumps(result.get("affected_resources", []))
    evidence  = json.dumps(result.get("evidence", {}))
    with engine.connect() as conn:
        existing = conn.execute(
            text("SELECT id FROM findings WHERE target_id=:tid AND check_id=:cid"),
            {"tid": target_id, "cid": result["check_id"]}
        ).fetchone()
        if existing:
            conn.execute(text("""
                UPDATE findings SET
                    status=:status, score=:score,
                    affected_resources=cast(:resources as jsonb),
                    evidence=cast(:evidence as jsonb),
                    last_seen_at=:now, updated_at=:now, scan_run_id=:run_id,
                    resolved_at=CASE WHEN :status='passed' THEN :now ELSE NULL END
                WHERE id=:fid
            """), {
                "status": result["status"], "score": result["score"],
                "resources": resources, "evidence": evidence,
                "now": now, "run_id": run_id, "fid": str(existing[0]),
            })
        else:
            conn.execute(text("""
                INSERT INTO findings (
                    id, scan_run_id, target_id, check_id, status, severity, score,
                    affected_resources, evidence, risk_description, remediation_steps,
                    estimated_effort, first_seen_at, last_seen_at, created_at, updated_at
                ) VALUES (
                    gen_random_uuid(), :run_id, :target_id, :check_id, :status,
                    :severity, :score,
                    cast(:resources as jsonb), cast(:evidence as jsonb),
                    :risk_desc, :remediation, :effort,
                    :now, :now, :now, :now
                )
            """), {
                "run_id": run_id, "target_id": target_id,
                "check_id": result["check_id"], "status": result["status"],
                "severity": result.get("severity", "Medium"), "score": result["score"],
                "resources": resources, "evidence": evidence,
                "risk_desc":   result.get("risk_description", ""),
                "remediation": result.get("remediation_steps", ""),
                "effort":      result.get("estimated_effort", "Low"),
                "now": now,
            })
        conn.commit()

# ─── Helper ───────────────────────────────────────────────────────────────────
def _ca_policies(graph):
    return graph.get_conditional_access_policies()

def _priv_role_members(graph, role_ids):
    seen, members = set(), []
    for rid in role_ids:
        for m in graph.get_directory_role_members(rid):
            if m.get("id") not in seen:
                seen.add(m["id"])
                members.append(m)
    return members

GLOBAL_ADMIN   = "62e90394-69f5-4237-9190-012177145e10"
SEC_ADMIN      = "194ae4cb-b126-40b2-bd5b-6091b380977d"
PRIV_ROLE_ADMIN= "e8611ab8-c189-46e8-94e1-60213ab1f814"
EXCHANGE_ADMIN = "29232cdf-9323-42fd-abe3-de7cc08a02fe"
SP_ADMIN       = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
HELPDESK_ADMIN = "729827e3-9c14-49f7-bb1b-9608f156bbb8"

ALL_PRIV_ROLES = [GLOBAL_ADMIN, SEC_ADMIN, PRIV_ROLE_ADMIN,
                  EXCHANGE_ADMIN, SP_ADMIN, HELPDESK_ADMIN]

# ─── CONDITIONAL ACCESS (9 checks) ───────────────────────────────────────────

def check_break_glass_ca(graph, target_config):
    """AZURE-CA-001"""
    bg_group = target_config.get("break_glass_group_id")
    policies  = _ca_policies(graph)
    failing   = []
    if bg_group:
        try:
            bg_ids = {m["id"] for m in graph.get_group_members(bg_group)}
        except Exception:
            bg_ids = set()
        for p in policies:
            if p.get("state") == "disabled":
                continue
            u = p.get("conditions", {}).get("users", {})
            excl_u = set(u.get("excludeUsers", []))
            excl_g = set(u.get("excludeGroups", []))
            if not (bg_ids & excl_u) and bg_group not in excl_g:
                failing.append({"id": p["id"], "name": p.get("displayName")})
    return {
        "check_id": "AZURE-CA-001", "severity": "Critical",
        "status": "passed" if not failing else "failed",
        "score":  9.2 if failing else 0.0,
        "affected_resources": failing,
        "evidence": {"total_policies": len(policies), "failing": len(failing)},
        "risk_description": "Break glass accounts could be locked out during emergencies if not excluded from CA policies.",
        "remediation_steps": "1. In Entra ID > Security > Conditional Access, open each failing policy.\n2. Under Assignments > Users > Exclude, add your break glass group.\n3. Save the policy.\n4. Test break glass access to confirm it works.",
        "estimated_effort": "Low",
    }

def check_legacy_auth_blocked(graph, target_config):
    """AZURE-CA-LEGACY"""
    policies = _ca_policies(graph)
    blocking = [
        p for p in policies
        if p.get("state") == "enabled"
        and ("exchangeActiveSync" in p.get("conditions", {}).get("clientAppTypes", [])
             or "other" in p.get("conditions", {}).get("clientAppTypes", []))
        and p.get("grantControls", {}).get("builtInControls", []) == ["block"]
    ]
    has_block = len(blocking) > 0
    return {
        "check_id": "AZURE-CA-LEGACY", "severity": "High",
        "status": "passed" if has_block else "failed",
        "score":  5.9 if not has_block else 0.0,
        "affected_resources": [] if has_block else [{"issue": "No CA policy blocking legacy auth found"}],
        "evidence": {"blocking_policies": len(blocking)},
        "risk_description": "Legacy authentication bypasses MFA entirely. Over 99% of password spray attacks use legacy auth.",
        "remediation_steps": "1. In Entra ID > Security > Conditional Access, create a new policy.\n2. Users: All users. Exclude break glass group.\n3. Cloud apps: All cloud apps.\n4. Conditions > Client apps: Enable, tick Exchange ActiveSync and Other clients.\n5. Grant: Block access.\n6. Test in Report-only first, then enable.",
        "estimated_effort": "Low",
    }

def check_risky_signins_blocked(graph, target_config):
    """AZURE-RISK-001"""
    policies = _ca_policies(graph)
    risk_policies = [
        p for p in policies
        if p.get("state") == "enabled"
        and "high" in p.get("conditions", {}).get("signInRiskLevels", [])
    ]
    has_policy = len(risk_policies) > 0
    return {
        "check_id": "AZURE-RISK-001", "severity": "High",
        "status": "passed" if has_policy else "failed",
        "score":  6.1 if not has_policy else 0.0,
        "affected_resources": [] if has_policy else [{"issue": "No CA policy targeting high sign-in risk"}],
        "evidence": {"risk_policies": len(risk_policies)},
        "risk_description": "High-risk sign-ins without a blocking policy allow compromised credentials to succeed undetected.",
        "remediation_steps": "1. Create a CA policy: Conditions > Sign-in risk > High and Medium.\n2. Grant: Block access (or require MFA + password change).\n3. Exclude break glass accounts.\n4. Enable policy.",
        "estimated_effort": "Low",
    }

def check_mfa_all_users(graph, target_config):
    """AZURE-MFA-002"""
    policies = _ca_policies(graph)
    mfa_all = [
        p for p in policies
        if p.get("state") == "enabled"
        and p.get("conditions", {}).get("users", {}).get("includeUsers") == ["All"]
        and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()
    ]
    has_policy = len(mfa_all) > 0
    return {
        "check_id": "AZURE-MFA-002", "severity": "High",
        "status": "passed" if has_policy else "failed",
        "score":  4.9 if not has_policy else 0.0,
        "affected_resources": [] if has_policy else [{"issue": "No CA policy requiring MFA for all users"}],
        "evidence": {"mfa_all_user_policies": len(mfa_all)},
        "risk_description": "Without MFA for all users, any compromised password grants full access to corporate resources.",
        "remediation_steps": "1. Create a CA policy targeting All Users.\n2. Exclude break glass group.\n3. Cloud apps: All cloud apps.\n4. Grant: Require multifactor authentication.\n5. Run in Report-only mode for 1 week first to identify impact.\n6. Enable.",
        "estimated_effort": "Moderate",
    }

def check_ca_report_only(graph, target_config):
    """AZURE-CA-023"""
    policies = _ca_policies(graph)
    report_only = [
        {"id": p["id"], "name": p.get("displayName")}
        for p in policies
        if p.get("state") == "enabledForReportingButNotEnforced"
    ]
    return {
        "check_id": "AZURE-CA-023", "severity": "Medium",
        "status": "passed" if not report_only else "failed",
        "score":  2.5 if report_only else 0.0,
        "affected_resources": report_only,
        "evidence": {"report_only_count": len(report_only), "total_policies": len(policies)},
        "risk_description": "Policies in report-only mode are not enforced. They provide visibility but zero protection.",
        "remediation_steps": "1. For each report-only policy, review the sign-in log impact.\n2. Resolve any users or services that would be blocked.\n3. Change State from Report-only to On.\n4. Monitor for unexpected blocks.",
        "estimated_effort": "Low",
    }

def check_ca_sync_restriction(graph, target_config):
    """AZURE-SYNC-001"""
    policies = _ca_policies(graph)
    try:
        users = graph.get_all_pages(
            "/users?$filter=startswith(userPrincipalName,'Sync_')"
            "&$select=id,displayName,userPrincipalName"
        )
        sync_accounts = [u for u in users if u.get("userPrincipalName", "").startswith("Sync_")]
    except Exception:
        sync_accounts = []

    if not sync_accounts:
        return {
            "check_id": "AZURE-SYNC-001", "severity": "Critical",
            "status": "passed", "score": 0.0, "affected_resources": [],
            "evidence": {"sync_accounts_found": 0},
            "risk_description": "No directory sync accounts found.",
            "remediation_steps": "No action required.",
            "estimated_effort": "Low",
        }

    # Check if any CA policy restricts the sync account
    sync_ids = {u["id"] for u in sync_accounts}
    protected = []
    for p in policies:
        if p.get("state") != "enabled":
            continue
        u = p.get("conditions", {}).get("users", {})
        included = set(u.get("includeUsers", []))
        if sync_ids & included:
            protected.append(p["id"])

    unprotected = [u for u in sync_accounts
                   if not any(u["id"] in p for p in protected)]

    return {
        "check_id": "AZURE-SYNC-001", "severity": "Critical",
        "status": "passed" if not unprotected else "failed",
        "score":  9.0 if unprotected else 0.0,
        "affected_resources": [{"name": u.get("userPrincipalName"), "id": u.get("id")}
                                for u in unprotected],
        "evidence": {"sync_accounts": len(sync_accounts), "unprotected": len(unprotected)},
        "risk_description": "The Entra ID Connect sync account has directory write access. If accessible from the internet, it can be used to manipulate directory objects.",
        "remediation_steps": "1. Create a named location with your on-premises public IP.\n2. Create a CA policy targeting the Sync_ account.\n3. Conditions > Locations: Any location, Exclude on-premises named location.\n4. Grant: Block access.\n5. Test that Entra ID Connect still syncs successfully.",
        "estimated_effort": "Low",
    }

def check_guest_admin_portal_blocked(graph, target_config):
    """AZURE-CA-014"""
    policies = _ca_policies(graph)
    guest_block = [
        p for p in policies
        if p.get("state") == "enabled"
        and p.get("conditions", {}).get("users", {}).get("includeGuestsOrExternalUsers")
        and p.get("grantControls", {}).get("builtInControls", []) == ["block"]
    ]
    has_block = len(guest_block) > 0
    return {
        "check_id": "AZURE-CA-014", "severity": "High",
        "status": "passed" if has_block else "failed",
        "score":  3.2 if not has_block else 0.0,
        "affected_resources": [] if has_block else [{"issue": "No CA policy blocking guest access to admin portals"}],
        "evidence": {"blocking_policies": len(guest_block)},
        "risk_description": "Guest accounts should never access Azure or M365 admin portals. Exposure can lead to information leakage about tenant configuration.",
        "remediation_steps": "1. Create a CA policy.\n2. Users: All guest and external users.\n3. Cloud apps: Microsoft Admin Portals.\n4. Grant: Block access.\n5. Enable.",
        "estimated_effort": "Low",
    }

def check_ca_exclusion_groups(graph, target_config):
    """AZURE-CA-018"""
    policies = _ca_policies(graph)
    individual_exclusions = []
    for p in policies:
        if p.get("state") == "disabled":
            continue
        u = p.get("conditions", {}).get("users", {})
        excl_users = u.get("excludeUsers", [])
        # More than 1 individual user exclusion (excluding None/All values)
        real_excl = [uid for uid in excl_users
                     if uid not in ("None", "GuestsOrExternalUsers")
                     and len(uid) == 36]  # GUID length
        if len(real_excl) > 0:
            individual_exclusions.append({
                "policy": p.get("displayName"),
                "id": p["id"],
                "individual_exclusions": len(real_excl)
            })
    return {
        "check_id": "AZURE-CA-018", "severity": "Medium",
        "status": "passed" if not individual_exclusions else "failed",
        "score":  0.9 if individual_exclusions else 0.0,
        "affected_resources": individual_exclusions,
        "evidence": {"policies_with_individual_exclusions": len(individual_exclusions)},
        "risk_description": "Individual user exclusions in CA policies are invisible to access reviews and grow silently over time.",
        "remediation_steps": "1. For each policy with individual exclusions, create a named exclusion group.\n2. Add the excluded users to the group.\n3. Replace the individual exclusions with the group.\n4. Configure a quarterly access review for the exclusion group.",
        "estimated_effort": "Low",
    }

def check_user_risk_policy(graph, target_config):
    """AZURE-MFA-006"""
    policies = _ca_policies(graph)
    user_risk_policies = [
        p for p in policies
        if p.get("state") == "enabled"
        and "high" in p.get("conditions", {}).get("userRiskLevels", [])
    ]
    has_policy = len(user_risk_policies) > 0
    return {
        "check_id": "AZURE-MFA-006", "severity": "High",
        "status": "passed" if has_policy else "failed",
        "score":  6.1 if not has_policy else 0.0,
        "affected_resources": [] if has_policy else [{"issue": "No CA policy for high user risk"}],
        "evidence": {"user_risk_policies": len(user_risk_policies)},
        "risk_description": "High user risk indicates credentials may be leaked. Without a policy, compromised accounts go undetected.",
        "remediation_steps": "1. Create a CA policy: Conditions > User risk > High.\n2. Grant: Require password change.\n3. Enable SSPR so users can self-remediate.\n4. Exclude break glass accounts.\n5. Enable.",
        "estimated_effort": "Low",
    }

# ─── MFA & AUTHENTICATION (4 checks) ─────────────────────────────────────────

def check_privileged_mfa(graph, target_config):
    """AZURE-MFA-001"""
    members = graph.get_directory_role_members(GLOBAL_ADMIN)
    no_mfa  = []
    for m in members:
        try:
            methods = graph.get(f"/users/{m['id']}/authentication/methods")
            types   = [x.get("@odata.type", "") for x in methods.get("value", [])]
            if not any("microsoftAuthenticator" in t or "phone" in t or "fido2" in t
                       for t in types):
                no_mfa.append({"id": m["id"], "name": m.get("displayName"),
                               "upn": m.get("userPrincipalName")})
        except Exception as e:
            logger.warning(f"MFA check failed for {m.get('displayName')}: {e}")
    return {
        "check_id": "AZURE-MFA-001", "severity": "Critical",
        "status": "passed" if not no_mfa else "failed",
        "score":  9.2 if no_mfa else 0.0,
        "affected_resources": no_mfa,
        "evidence": {"admin_count": len(members), "no_mfa": len(no_mfa)},
        "risk_description": "Global Admins without MFA are a single password theft away from full tenant compromise.",
        "remediation_steps": "1. Go to https://mysecurityinfo.microsoft.com and register MFA for each listed admin.\n2. Create a CA policy requiring MFA for the Global Administrator role.\n3. Verify all admins can complete MFA before enforcing.",
        "estimated_effort": "Low",
    }

def check_sspr_enabled(graph, target_config):
    """AZURE-IDENTITY-013"""
    try:
        result = graph.get("/policies/authenticationMethodsPolicy")
        campaign = result.get("registrationEnforcement", {}).get(
            "authenticationMethodsRegistrationCampaign", {})
        is_enabled = campaign.get("state") == "enabled"
    except Exception:
        is_enabled = False
    return {
        "check_id": "AZURE-IDENTITY-013", "severity": "High",
        "status": "passed" if is_enabled else "failed",
        "score":  3.2 if not is_enabled else 0.0,
        "affected_resources": [] if is_enabled else [{"issue": "MFA registration campaign not enabled"}],
        "evidence": {"registration_campaign_enabled": is_enabled},
        "risk_description": "Without SSPR, users must call the helpdesk to reset passwords, blocking risk remediation flows.",
        "remediation_steps": "1. In Entra ID > Security > Authentication methods > Registration campaign.\n2. Set State to Enabled.\n3. Set snoozeable days to 7.\n4. Include all users.\n5. Monitor completion in Authentication Methods Activity report.",
        "estimated_effort": "Low",
    }

def check_user_app_registration(graph, target_config):
    """AZURE-IDENTITY-017"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        can_register = policy.get("defaultUserRolePermissions", {}).get(
            "allowedToCreateApps", True)
    except Exception:
        can_register = True
    return {
        "check_id": "AZURE-IDENTITY-017", "severity": "Medium",
        "status": "passed" if not can_register else "failed",
        "score":  2.8 if can_register else 0.0,
        "affected_resources": [{"setting": "allowedToCreateApps", "value": "true"}] if can_register else [],
        "evidence": {"users_can_register_apps": can_register},
        "risk_description": "Users registering unvetted apps can expose tenant data to malicious applications.",
        "remediation_steps": "1. In Entra ID > Users > User settings.\n2. Set 'Users can register applications' to No.\n3. Create a process for developers to request app registration via the Application Developer role.",
        "estimated_effort": "Low",
    }

def check_combined_registration(graph, target_config):
    """AZURE-IDENTITY-019"""
    try:
        policy = graph.get("/policies/authenticationMethodsPolicy")
        migration = policy.get("authenticationMethodConfigurations", [])
        # Combined registration is default-on for newer tenants
        # Check if policies exist as a proxy for tenant age/config
        is_configured = len(migration) > 0
    except Exception:
        is_configured = False
    return {
        "check_id": "AZURE-IDENTITY-019", "severity": "Medium",
        "status": "passed" if is_configured else "failed",
        "score":  2.0 if not is_configured else 0.0,
        "affected_resources": [] if is_configured else [{"issue": "Authentication methods policy not configured"}],
        "evidence": {"methods_configured": len(migration) if is_configured else 0},
        "risk_description": "Without combined registration, users register MFA and SSPR separately, reducing completion rates.",
        "remediation_steps": "1. In Entra ID > Security > Authentication methods.\n2. Enable Microsoft Authenticator for all users.\n3. Enable the Registration campaign.\n4. Users register at https://aka.ms/setupsecurityinfo.",
        "estimated_effort": "Low",
    }

# ─── PIM (4 checks) ───────────────────────────────────────────────────────────

def check_pim_permanent_members(graph, target_config):
    """AZURE-PIM-001"""
    try:
        assignments = graph.get_all_pages(
            "/roleManagement/directory/roleAssignments?$expand=principal"
        )
        permanent = [
            {"id": a.get("id"),
             "principal": a.get("principal", {}).get("displayName"),
             "upn": a.get("principal", {}).get("userPrincipalName"),
             "role": a.get("roleDefinitionId")}
            for a in assignments
            if a.get("directoryScopeId") == "/"
            and a.get("principal", {}).get("@odata.type") == "#microsoft.graph.user"
        ]
    except Exception as e:
        return {
            "check_id": "AZURE-PIM-001", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not evaluate PIM assignments.",
            "remediation_steps": "Ensure RoleManagement.Read.Directory permission is granted.",
            "estimated_effort": "Low",
        }
    return {
        "check_id": "AZURE-PIM-001", "severity": "High",
        "status": "passed" if not permanent else "failed",
        "score":  5.5 if permanent else 0.0,
        "affected_resources": permanent,
        "evidence": {"permanent_assignments": len(permanent)},
        "risk_description": "Permanent role assignments mean standing privilege 24/7. Any session compromise is a privileged compromise.",
        "remediation_steps": "1. In Entra ID > Identity Governance > PIM > Entra ID Roles > Assignments.\n2. For each permanent assignment, add the user as Eligible instead.\n3. Remove the permanent Active assignment.\n4. Configure: MFA required, justification required, approval required for Global Admin.",
        "estimated_effort": "Low",
    }

def check_pim_mfa_activation(graph, target_config):
    """AZURE-MFA-003"""
    try:
        policies = graph.get_all_pages(
            "/policies/roleManagementPolicies?$filter=scopeType eq 'DirectoryRole'"
        )
        no_mfa = []
        for policy in policies[:15]:  # limit to avoid rate limiting
            try:
                rules = graph.get_all_pages(
                    f"/policies/roleManagementPolicies/{policy['id']}/rules"
                )
                mfa_rule = next(
                    (r for r in rules
                     if r.get("@odata.type") == "#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule"
                     or "authentication" in str(r.get("@odata.type", "")).lower()),
                    None
                )
                if not mfa_rule:
                    no_mfa.append({"policy": policy.get("displayName", policy["id"])})
            except Exception:
                pass
    except Exception as e:
        return {
            "check_id": "AZURE-MFA-003", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check PIM MFA settings.",
            "remediation_steps": "Ensure PrivilegedAccess.Read.AzureAD permission is granted.",
            "estimated_effort": "Low",
        }
    return {
        "check_id": "AZURE-MFA-003", "severity": "High",
        "status": "passed" if not no_mfa else "failed",
        "score":  4.8 if no_mfa else 0.0,
        "affected_resources": no_mfa,
        "evidence": {"policies_checked": len(policies) if 'policies' in dir() else 0},
        "risk_description": "Without MFA at PIM activation, a stolen password allows immediate privilege escalation.",
        "remediation_steps": "1. In PIM > Entra ID Roles > Settings, select each privileged role.\n2. Under Activation, enable 'Require multi-factor authentication on activation'.\n3. Save and repeat for all privileged roles.",
        "estimated_effort": "Low",
    }

def check_pim_access_reviews(graph, target_config):
    """AZURE-PIM-005"""
    try:
        reviews = graph.get_all_pages("/identityGovernance/accessReviews/definitions")
        pim_reviews = [
            r for r in reviews
            if "role" in str(r.get("scope", {})).lower()
            and r.get("status") in ("Active", "NotStarted")
        ]
        has_reviews = len(pim_reviews) > 0
    except Exception as e:
        return {
            "check_id": "AZURE-PIM-005", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check access reviews.",
            "remediation_steps": "Ensure AccessReview.Read.All permission is granted.",
            "estimated_effort": "Low",
        }
    return {
        "check_id": "AZURE-PIM-005", "severity": "High",
        "status": "passed" if has_reviews else "failed",
        "score":  3.0 if not has_reviews else 0.0,
        "affected_resources": [] if has_reviews else [{"issue": "No active PIM access reviews found"}],
        "evidence": {"pim_access_reviews": len(pim_reviews)},
        "risk_description": "Without access reviews, stale privileged role assignments accumulate unchecked.",
        "remediation_steps": "1. In Entra ID > Identity Governance > Access Reviews > New.\n2. Review scope: Privileged Identity Management roles.\n3. Select all privileged roles.\n4. Reviewers: Managers of members.\n5. Recurrence: Monthly for high-priv roles, quarterly for others.\n6. Upon completion: Remove access for denied/non-reviewed.",
        "estimated_effort": "Moderate",
    }

def check_pim_justification(graph, target_config):
    """AZURE-PIM-008"""
    try:
        policies = graph.get_all_pages(
            "/policies/roleManagementPolicies?$filter=scopeType eq 'DirectoryRole'"
        )
        no_justification = []
        for policy in policies[:10]:
            try:
                rules = graph.get_all_pages(
                    f"/policies/roleManagementPolicies/{policy['id']}/rules"
                )
                justification_rule = next(
                    (r for r in rules
                     if "enabledRule" in str(r.get("@odata.type", ""))
                     or "justification" in str(r).lower()),
                    None
                )
                if not justification_rule:
                    no_justification.append({"policy": policy.get("displayName", policy["id"])})
            except Exception:
                pass
        has_justification = len(no_justification) == 0
    except Exception as e:
        return {
            "check_id": "AZURE-PIM-008", "severity": "Medium",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check PIM justification settings.",
            "remediation_steps": "Ensure PrivilegedAccess.Read.AzureAD permission is granted.",
            "estimated_effort": "Low",
        }
    return {
        "check_id": "AZURE-PIM-008", "severity": "Medium",
        "status": "passed" if has_justification else "failed",
        "score":  2.0 if not has_justification else 0.0,
        "affected_resources": no_justification,
        "evidence": {"policies_without_justification": len(no_justification)},
        "risk_description": "Without justification requirements, PIM activations lack an audit trail for security reviews.",
        "remediation_steps": "1. In PIM > Entra ID Roles > Settings, select each privileged role.\n2. Under Activation, enable 'Require justification on activation'.\n3. Save changes.",
        "estimated_effort": "Low",
    }

# ─── IDENTITY HYGIENE (6 checks) ─────────────────────────────────────────────

def check_privileged_cloud_only(graph, target_config):
    """AZURE-PRIV-001"""
    synced, seen = [], set()
    for m in _priv_role_members(graph, ALL_PRIV_ROLES):
        uid = m.get("id")
        if uid in seen:
            continue
        seen.add(uid)
        if m.get("onPremisesSyncEnabled"):
            synced.append({"id": uid, "name": m.get("displayName"),
                           "upn": m.get("userPrincipalName")})
    return {
        "check_id": "AZURE-PRIV-001", "severity": "Critical",
        "status": "passed" if not synced else "failed",
        "score":  9.0 if synced else 0.0,
        "affected_resources": synced,
        "evidence": {"checked": len(seen), "synced": len(synced)},
        "risk_description": "Synced privileged accounts inherit on-premises compromise risks, negating cloud security controls.",
        "remediation_steps": "1. Create dedicated cloud-only admin accounts (e.g., jadmin@contoso.com).\n2. Assign privileged roles to the new accounts.\n3. Register MFA on the new accounts.\n4. Remove privileged roles from synced accounts.\n5. Do not add mailboxes or Skype to admin accounts.",
        "estimated_effort": "Low",
    }

def check_stale_privileged_users(graph, target_config):
    """AZURE-STALE-001"""
    cutoff  = datetime.now(timezone.utc) - timedelta(days=30)
    members = graph.get_directory_role_members(GLOBAL_ADMIN)
    stale   = []
    for m in members:
        try:
            data = graph.get(f"/users/{m['id']}?$select=id,displayName,signInActivity")
            last = data.get("signInActivity", {}).get("lastSignInDateTime")
            if not last:
                stale.append({"id": m["id"], "name": m.get("displayName"), "last_sign_in": "Never"})
            elif datetime.fromisoformat(last.replace("Z", "+00:00")) < cutoff:
                stale.append({"id": m["id"], "name": m.get("displayName"), "last_sign_in": last})
        except Exception as e:
            logger.warning(f"Sign-in check failed for {m.get('displayName')}: {e}")
    return {
        "check_id": "AZURE-STALE-001", "severity": "High",
        "status": "passed" if not stale else "failed",
        "score":  5.4 if stale else 0.0,
        "affected_resources": stale,
        "evidence": {"checked": len(members), "stale": len(stale)},
        "risk_description": "Stale privileged accounts are attack surfaces that may belong to departed employees.",
        "remediation_steps": "1. For each listed account, verify with manager whether still needed.\n2. If departures: disable immediately, then delete after 30 days.\n3. If role no longer needed: remove role assignment, convert to PIM eligible.\n4. Configure monthly access reviews in PIM.",
        "estimated_effort": "Low",
    }

def check_stale_guests(graph, target_config):
    """AZURE-GUEST-001"""
    guests = graph.get_all_pages(
        "/users?$filter=userType eq 'Guest'"
        "&$select=id,displayName,userPrincipalName,externalUserState,createdDateTime"
    )
    pending = [
        {"id": g["id"], "name": g.get("displayName"),
         "upn": g.get("userPrincipalName"), "created": g.get("createdDateTime")}
        for g in guests
        if g.get("externalUserState") == "PendingAcceptance"
    ]
    return {
        "check_id": "AZURE-GUEST-001", "severity": "Medium",
        "status": "passed" if not pending else "failed",
        "score":  5.4 if pending else 0.0,
        "affected_resources": pending,
        "evidence": {"total_guests": len(guests), "pending": len(pending)},
        "risk_description": "Unaccepted guest invitations can be intercepted. The link may be forwarded to attackers.",
        "remediation_steps": "1. In Entra ID > Users, filter by Guest + External User State = Pending.\n2. Remove any pending invitations older than 30 days.\n3. Re-send if the collaboration is still needed.",
        "estimated_effort": "Low",
    }

def check_stale_cloud_users(graph, target_config):
    """AZURE-IDENTITY-033"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    try:
        users = graph.get_all_pages(
            "/users?$filter=userType eq 'Member'"
            "&$select=id,displayName,userPrincipalName,accountEnabled,"
            "onPremisesSyncEnabled,signInActivity"
        )
        stale = []
        for u in users:
            if u.get("onPremisesSyncEnabled"):
                continue  # skip synced users
            if not u.get("accountEnabled"):
                continue  # skip already disabled
            last = u.get("signInActivity", {}).get("lastSignInDateTime")
            if not last:
                stale.append({"id": u["id"], "name": u.get("displayName"),
                              "upn": u.get("userPrincipalName"), "last_sign_in": "Never"})
            else:
                try:
                    if datetime.fromisoformat(last.replace("Z", "+00:00")) < cutoff:
                        stale.append({"id": u["id"], "name": u.get("displayName"),
                                      "upn": u.get("userPrincipalName"), "last_sign_in": last})
                except Exception:
                    pass
    except Exception as e:
        return {
            "check_id": "AZURE-IDENTITY-033", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check stale cloud users.",
            "remediation_steps": "Ensure AuditLog.Read.All permission is granted.",
            "estimated_effort": "Low",
        }
    return {
        "check_id": "AZURE-IDENTITY-033", "severity": "High",
        "status": "passed" if not stale else "failed",
        "score":  3.0 if stale else 0.0,
        "affected_resources": stale[:20],
        "evidence": {"stale_count": len(stale), "cutoff_days": 30},
        "risk_description": "Stale cloud-only accounts are attack surfaces. They may belong to departed contractors or forgotten service accounts.",
        "remediation_steps": "1. For each account, verify with HR whether the user is still active.\n2. Disable accounts with no legitimate owner.\n3. Implement HR-triggered lifecycle workflows for automatic deprovisioning.",
        "estimated_effort": "Moderate",
    }

def check_personal_emails(graph, target_config):
    """AZURE-IDENTITY-005"""
    PERSONAL_DOMAINS = {"gmail.com", "hotmail.com", "yahoo.com", "outlook.com",
                        "live.com", "icloud.com", "me.com", "protonmail.com"}
    try:
        users = graph.get_all_pages(
            "/users?$select=id,displayName,userPrincipalName,otherMails"
        )
        with_personal = [
            {"id": u["id"], "name": u.get("displayName"),
             "upn": u.get("userPrincipalName"),
             "personal_email": next((m for m in (u.get("otherMails") or [])
                                     if m.split("@")[-1].lower() in PERSONAL_DOMAINS), "")}
            for u in users
            if any(m.split("@")[-1].lower() in PERSONAL_DOMAINS
                   for m in (u.get("otherMails") or []))
        ]
    except Exception as e:
        return {
            "check_id": "AZURE-IDENTITY-005", "severity": "Medium",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check personal email addresses.",
            "remediation_steps": "Ensure User.Read.All permission is granted.",
            "estimated_effort": "Moderate",
        }
    return {
        "check_id": "AZURE-IDENTITY-005", "severity": "Medium",
        "status": "passed" if not with_personal else "failed",
        "score":  2.3 if with_personal else 0.0,
        "affected_resources": with_personal[:20],
        "evidence": {"users_checked": len(users), "with_personal_email": len(with_personal)},
        "risk_description": "Personal email addresses as MFA/SSPR contacts allow attackers who compromise a personal mailbox to reset corporate credentials.",
        "remediation_steps": "1. Remove personal email addresses from user profiles via Microsoft Graph.\n2. Disable external email as an SSPR authentication method.\n3. Communicate to users to only use corporate email addresses.",
        "estimated_effort": "Moderate",
    }

def check_risky_users(graph, target_config):
    """AZURE-IDENTITY-015"""
    try:
        risky = graph.get_all_pages(
            "/identityProtection/riskyUsers?$filter=riskLevel eq 'high' and riskState eq 'atRisk'"
            "&$select=id,userDisplayName,userPrincipalName,riskLevel,riskState,riskLastUpdatedDateTime"
        )
    except Exception as e:
        return {
            "check_id": "AZURE-IDENTITY-015", "severity": "Critical",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check risky users.",
            "remediation_steps": "Ensure IdentityRiskEvent.Read.All permission is granted.",
            "estimated_effort": "Low",
        }
    affected = [
        {"id": u.get("id"), "name": u.get("userDisplayName"),
         "upn": u.get("userPrincipalName"), "risk_level": u.get("riskLevel"),
         "last_updated": u.get("riskLastUpdatedDateTime")}
        for u in risky
    ]
    return {
        "check_id": "AZURE-IDENTITY-015", "severity": "Critical",
        "status": "passed" if not affected else "failed",
        "score":  8.5 if affected else 0.0,
        "affected_resources": affected,
        "evidence": {"high_risk_users": len(affected)},
        "risk_description": "Users with high risk status have likely had credentials compromised. Immediate action is required.",
        "remediation_steps": "1. In Entra ID > Security > Identity Protection > Risky Users.\n2. For each high-risk user: review the risk detections.\n3. Force a password reset.\n4. Revoke all sessions.\n5. Review recent sign-in and activity logs for data exfiltration.\n6. Dismiss risk once remediated.",
        "estimated_effort": "Low",
    }

# ─── APPLICATIONS (7 checks) ─────────────────────────────────────────────────

def check_app_credentials_expiry(graph, target_config):
    """AZURE-APP-001"""
    apps    = graph.get_applications()
    warning = datetime.now(timezone.utc) + timedelta(days=30)
    now     = datetime.now(timezone.utc)
    at_risk = []
    for app in apps:
        for cred in (app.get("passwordCredentials") or []) + (app.get("keyCredentials") or []):
            end = cred.get("endDateTime")
            if not end:
                continue
            try:
                end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                state  = "EXPIRED" if end_dt < now else ("EXPIRING_SOON" if end_dt < warning else None)
                if state:
                    at_risk.append({"app": app.get("displayName"), "id": app.get("id"),
                                    "expires": end, "state": state})
            except Exception:
                pass
    return {
        "check_id": "AZURE-APP-001", "severity": "Medium",
        "status": "passed" if not at_risk else "failed",
        "score":  3.0 if at_risk else 0.0,
        "affected_resources": at_risk,
        "evidence": {"apps_checked": len(apps), "at_risk": len(at_risk)},
        "risk_description": "Expired app credentials cause service outages. Expiring ones need rotation before they break.",
        "remediation_steps": "1. For each listed app, open it in Entra ID > App Registrations.\n2. Under Certificates & secrets, remove the old credential.\n3. Generate a new certificate (preferred) or client secret.\n4. Update the application configuration.\n5. Test the application before deleting the old credential.",
        "estimated_effort": "Low",
    }

def check_user_consent_enabled(graph, target_config):
    """AZURE-CONSENT-001"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        grants = policy.get("defaultUserRolePermissions", {}).get(
            "permissionGrantPoliciesAssigned", [])
        can_consent = any("ManagePermissionGrantsForSelf" in g for g in grants)
    except Exception as e:
        logger.warning(f"Consent policy check failed: {e}")
        can_consent = False
    return {
        "check_id": "AZURE-CONSENT-001", "severity": "High",
        "status": "passed" if not can_consent else "failed",
        "score":  4.9 if can_consent else 0.0,
        "affected_resources": [{"setting": "userConsentForApps", "value": "enabled"}] if can_consent else [],
        "evidence": {"user_consent_enabled": can_consent},
        "risk_description": "User consent enables illicit consent grant attacks where phishing tricks users into granting app access to their data.",
        "remediation_steps": "1. In Entra ID > Enterprise Applications > Consent and permissions.\n2. Set 'User consent for apps' to 'Do not allow user consent'.\n3. Enable the admin consent workflow so users can request access.\n4. Add at least 2 reviewers to the workflow.",
        "estimated_effort": "Low",
    }

def check_app_http_uris(graph, target_config):
    """AZURE-APP-015"""
    apps = graph.get_applications()
    insecure = []
    for app in apps:
        for uri in (app.get("web", {}) or {}).get("redirectUris", []):
            if uri.startswith("http://") and "localhost" not in uri:
                insecure.append({"app": app.get("displayName"), "id": app.get("id"), "uri": uri})
    return {
        "check_id": "AZURE-APP-015", "severity": "Medium",
        "status": "passed" if not insecure else "failed",
        "score":  2.3 if insecure else 0.0,
        "affected_resources": insecure,
        "evidence": {"apps_checked": len(apps), "insecure_uris": len(insecure)},
        "risk_description": "HTTP redirect URIs allow OAuth tokens to be intercepted in transit via man-in-the-middle attacks.",
        "remediation_steps": "1. For each listed app, open it in Entra ID > App Registrations > Authentication.\n2. Update the HTTP redirect URI to HTTPS.\n3. Ensure the destination endpoint has a valid TLS certificate.\n4. Test the authentication flow.",
        "estimated_effort": "Moderate",
    }

def check_apps_without_owners(graph, target_config):
    """AZURE-APP-017"""
    apps = graph.get_applications()
    no_owners = []
    for app in apps:
        try:
            owners = graph.get_all_pages(f"/applications/{app['id']}/owners")
            if not owners:
                no_owners.append({"app": app.get("displayName"), "id": app.get("id")})
        except Exception:
            pass
    return {
        "check_id": "AZURE-APP-017", "severity": "Low",
        "status": "passed" if not no_owners else "failed",
        "score":  0.5 if no_owners else 0.0,
        "affected_resources": no_owners,
        "evidence": {"apps_checked": len(apps), "no_owner_count": len(no_owners)},
        "risk_description": "Apps without owners have no accountable party for credential rotation, permission review, or security incidents.",
        "remediation_steps": "1. For each listed app, identify the business or technical owner.\n2. In Entra ID > App Registrations > {app} > Owners, add at least one owner.\n3. For unknown apps: assess whether they are still needed. Delete if not.",
        "estimated_effort": "Low",
    }

def check_app_assignment_required(graph, target_config):
    """AZURE-APP-005"""
    try:
        sps = graph.get_all_pages(
            "/servicePrincipals?$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
            "&$select=id,displayName,appRoleAssignmentRequired"
        )
        no_assignment = [
            {"app": sp.get("displayName"), "id": sp.get("id")}
            for sp in sps
            if not sp.get("appRoleAssignmentRequired")
        ]
    except Exception as e:
        return {
            "check_id": "AZURE-APP-005", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check app assignment settings.",
            "remediation_steps": "Ensure Application.Read.All permission is granted.",
            "estimated_effort": "Moderate",
        }
    return {
        "check_id": "AZURE-APP-005", "severity": "High",
        "status": "passed" if not no_assignment else "failed",
        "score":  4.9 if no_assignment else 0.0,
        "affected_resources": no_assignment[:20],
        "evidence": {"apps_checked": len(sps), "no_assignment_required": len(no_assignment)},
        "risk_description": "Apps without assignment required are accessible to every user in the tenant, including guests.",
        "remediation_steps": "1. For each sensitive enterprise application, go to Entra ID > Enterprise Applications > {app} > Properties.\n2. Set 'Assignment required' to Yes.\n3. Under Users and groups, add the appropriate groups.\n4. Test that unassigned users are blocked.",
        "estimated_effort": "Moderate",
    }

def check_sp_password_credentials(graph, target_config):
    """AZURE-APP-013"""
    try:
        sps = graph.get_all_pages(
            "/servicePrincipals?$select=id,displayName,passwordCredentials"
        )
        using_passwords = [
            {"app": sp.get("displayName"), "id": sp.get("id"),
             "credential_count": len(sp.get("passwordCredentials", []))}
            for sp in sps
            if sp.get("passwordCredentials")
        ]
    except Exception as e:
        return {
            "check_id": "AZURE-APP-013", "severity": "Medium",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check service principal credentials.",
            "remediation_steps": "Ensure Application.Read.All permission is granted.",
            "estimated_effort": "Low",
        }
    return {
        "check_id": "AZURE-APP-013", "severity": "Medium",
        "status": "passed" if not using_passwords else "failed",
        "score":  1.8 if using_passwords else 0.0,
        "affected_resources": using_passwords[:20],
        "evidence": {"sps_checked": len(sps), "using_passwords": len(using_passwords)},
        "risk_description": "Password credentials on service principals can be logged, leaked via config files, or stolen from developer machines.",
        "remediation_steps": "1. For each listed service principal, generate a certificate credential.\n2. Update the application to use the certificate.\n3. Delete the password credential.\n4. Consider Managed Identities for Azure-hosted workloads to eliminate credentials entirely.",
        "estimated_effort": "Low",
    }

def check_aad_graph_usage(graph, target_config):
    """AZURE-APP-008"""
    try:
        sps = graph.get_all_pages("/servicePrincipals?$select=id,displayName,appId")
        # Azure AD Graph service principal app ID
        AAD_GRAPH_APP_ID = "00000002-0000-0000-c000-000000000000"
        aad_graph_sp = next((sp for sp in sps if sp.get("appId") == AAD_GRAPH_APP_ID), None)

        if not aad_graph_sp:
            return {
                "check_id": "AZURE-APP-008", "severity": "High",
                "status": "passed", "score": 0.0, "affected_resources": [],
                "evidence": {"aad_graph_sp_found": False},
                "risk_description": "Azure AD Graph API is deprecated and will be retired.",
                "remediation_steps": "No Azure AD Graph usage detected.",
                "estimated_effort": "High",
            }

        # Check which apps have permissions on AAD Graph
        grants = graph.get_all_pages(
            f"/servicePrincipals/{aad_graph_sp['id']}/appRoleAssignedTo"
        )
        apps_using = [
            {"app": g.get("principalDisplayName"), "id": g.get("principalId")}
            for g in grants
            if g.get("principalType") in ("Application", "ServicePrincipal")
        ]
    except Exception as e:
        return {
            "check_id": "AZURE-APP-008", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check Azure AD Graph usage.",
            "remediation_steps": "Ensure Application.Read.All permission is granted.",
            "estimated_effort": "High",
        }
    return {
        "check_id": "AZURE-APP-008", "severity": "High",
        "status": "passed" if not apps_using else "failed",
        "score":  3.6 if apps_using else 0.0,
        "affected_resources": apps_using,
        "evidence": {"apps_using_aad_graph": len(apps_using)},
        "risk_description": "Azure AD Graph API is deprecated and will be retired. Apps using it will break when the API is shut down.",
        "remediation_steps": "1. For each listed application, contact the owner or development team.\n2. Migrate from graph.windows.net endpoints to graph.microsoft.com.\n3. Update permissions to use Microsoft Graph equivalents.\n4. Remove Azure AD Graph permissions after migration.",
        "estimated_effort": "High",
    }

# ─── GUEST USERS (3 checks) ───────────────────────────────────────────────────

def check_guest_permissions(graph, target_config):
    """AZURE-GUEST-003"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        guest_perms = policy.get("guestUserRoleId", "")
        # 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Restricted (most restrictive)
        # 2af84b1e-32c8-42b7-82bc-daa82404023b = Member (least restrictive)
        # bf6952be-ea29-4fd2-a3ca-09c2e5aa7cec = Limited (default)
        is_restrictive = guest_perms == "10dae51f-b6af-4016-8d66-8c2a99b929b3"
    except Exception as e:
        return {
            "check_id": "AZURE-GUEST-003", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check guest access permissions.",
            "remediation_steps": "Ensure Policy.Read.All permission is granted.",
            "estimated_effort": "Moderate",
        }
    return {
        "check_id": "AZURE-GUEST-003", "severity": "High",
        "status": "passed" if is_restrictive else "failed",
        "score":  5.2 if not is_restrictive else 0.0,
        "affected_resources": [] if is_restrictive else [{"setting": "guestUserRoleId", "value": guest_perms}],
        "evidence": {"guest_role_id": guest_perms, "is_most_restrictive": is_restrictive},
        "risk_description": "Unrestricted guest access allows guests to enumerate users, groups, and service principals — useful for attackers doing reconnaissance.",
        "remediation_steps": "1. In Entra ID > External Identities > External collaboration settings.\n2. Set Guest user access to 'Guest users have restricted access to properties and memberships'.\n3. Save settings.",
        "estimated_effort": "Moderate",
    }

def check_guest_access_reviews(graph, target_config):
    """AZURE-GUEST-006"""
    try:
        reviews = graph.get_all_pages("/identityGovernance/accessReviews/definitions")
        guest_reviews = [
            r for r in reviews
            if "guest" in str(r.get("scope", {})).lower()
            and r.get("status") in ("Active", "NotStarted")
        ]
        has_reviews = len(guest_reviews) > 0
    except Exception as e:
        return {
            "check_id": "AZURE-GUEST-006", "severity": "Medium",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check guest access reviews.",
            "remediation_steps": "Ensure AccessReview.Read.All permission is granted.",
            "estimated_effort": "Moderate",
        }
    return {
        "check_id": "AZURE-GUEST-006", "severity": "Medium",
        "status": "passed" if has_reviews else "failed",
        "score":  2.2 if not has_reviews else 0.0,
        "affected_resources": [] if has_reviews else [{"issue": "No active access reviews for guest users"}],
        "evidence": {"guest_access_reviews": len(guest_reviews)},
        "risk_description": "Without access reviews, stale guest accounts accumulate and retain access to shared resources indefinitely.",
        "remediation_steps": "1. In Entra ID > Identity Governance > Access Reviews > New access review.\n2. Review scope: Guest users in Microsoft 365 groups.\n3. Reviewers: Group owners.\n4. Recurrence: Monthly.\n5. Upon completion: Remove uncertified access automatically.",
        "estimated_effort": "Moderate",
    }

def check_stale_guest_accounts(graph, target_config):
    """AZURE-GUEST-002"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    try:
        guests = graph.get_all_pages(
            "/users?$filter=userType eq 'Guest'"
            "&$select=id,displayName,userPrincipalName,signInActivity,createdDateTime"
        )
        stale = []
        for g in guests:
            last = g.get("signInActivity", {}).get("lastSignInDateTime")
            if not last:
                # Never signed in — check creation date
                created = g.get("createdDateTime")
                if created:
                    try:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        if created_dt < cutoff:
                            stale.append({"id": g["id"], "name": g.get("displayName"),
                                          "upn": g.get("userPrincipalName"),
                                          "last_sign_in": "Never"})
                    except Exception:
                        pass
            else:
                try:
                    if datetime.fromisoformat(last.replace("Z", "+00:00")) < cutoff:
                        stale.append({"id": g["id"], "name": g.get("displayName"),
                                      "upn": g.get("userPrincipalName"),
                                      "last_sign_in": last})
                except Exception:
                    pass
    except Exception as e:
        return {
            "check_id": "AZURE-GUEST-002", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check stale guest accounts.",
            "remediation_steps": "Ensure AuditLog.Read.All permission is granted.",
            "estimated_effort": "Moderate",
        }
    return {
        "check_id": "AZURE-GUEST-002", "severity": "High",
        "status": "passed" if not stale else "failed",
        "score":  3.0 if stale else 0.0,
        "affected_resources": stale[:20],
        "evidence": {"total_guests": len(guests), "stale_90d": len(stale)},
        "risk_description": "Stale guest accounts represent unnecessary access that may belong to people who no longer work with your organisation.",
        "remediation_steps": "1. For each listed guest, verify with the inviting team whether access is still needed.\n2. If no longer needed: delete the guest account.\n3. Implement monthly access reviews for all guest users.",
        "estimated_effort": "Moderate",
    }

# ─── GROUPS (3 checks) ────────────────────────────────────────────────────────

def check_groups_without_owners(graph, target_config):
    """AZURE-GROUP-002"""
    try:
        groups = graph.get_all_pages(
            "/groups?$filter=groupTypes/any(c:c eq 'Unified') or securityEnabled eq true"
            "&$select=id,displayName,groupTypes,onPremisesSyncEnabled"
        )
        cloud_groups = [g for g in groups if not g.get("onPremisesSyncEnabled")]
        no_owners = []
        for group in cloud_groups[:50]:  # limit to avoid rate limiting
            try:
                owners = graph.get_all_pages(f"/groups/{group['id']}/owners")
                if not owners:
                    no_owners.append({"id": group["id"], "name": group.get("displayName")})
            except Exception:
                pass
    except Exception as e:
        return {
            "check_id": "AZURE-GROUP-002", "severity": "Low",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check group owners.",
            "remediation_steps": "Ensure Group.Read.All permission is granted.",
            "estimated_effort": "Low",
        }
    return {
        "check_id": "AZURE-GROUP-002", "severity": "Low",
        "status": "passed" if not no_owners else "failed",
        "score":  0.5 if no_owners else 0.0,
        "affected_resources": no_owners,
        "evidence": {"cloud_groups_checked": len(cloud_groups), "no_owners": len(no_owners)},
        "risk_description": "Groups without owners have no accountable party for membership management or access reviews.",
        "remediation_steps": "1. For each listed group, identify an appropriate owner.\n2. In Entra ID > Groups > {group} > Owners, add them.\n3. For unknown groups: review membership and delete if empty and unused.",
        "estimated_effort": "Low",
    }

def check_empty_groups(graph, target_config):
    """AZURE-GROUP-003"""
    try:
        groups = graph.get_all_pages(
            "/groups?$filter=securityEnabled eq true"
            "&$select=id,displayName,onPremisesSyncEnabled"
        )
        cloud_groups = [g for g in groups if not g.get("onPremisesSyncEnabled")]
        empty = []
        for group in cloud_groups[:50]:
            try:
                members = graph.get_all_pages(f"/groups/{group['id']}/members")
                if not members:
                    empty.append({"id": group["id"], "name": group.get("displayName")})
            except Exception:
                pass
    except Exception as e:
        return {
            "check_id": "AZURE-GROUP-003", "severity": "Low",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check empty groups.",
            "remediation_steps": "Ensure Group.Read.All permission is granted.",
            "estimated_effort": "Low",
        }
    return {
        "check_id": "AZURE-GROUP-003", "severity": "Low",
        "status": "passed" if not empty else "failed",
        "score":  0.2 if empty else 0.0,
        "affected_resources": empty,
        "evidence": {"checked": len(cloud_groups), "empty": len(empty)},
        "risk_description": "Empty groups add noise to the directory and complicate auditing of access policies.",
        "remediation_steps": "1. Review each empty group to determine if it is still needed.\n2. Delete groups that are unused and have no application assignments.\n3. Configure group expiration policies to automate cleanup.",
        "estimated_effort": "Low",
    }

def check_sg_creation_restricted(graph, target_config):
    """AZURE-GROUP-005"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        can_create = policy.get("defaultUserRolePermissions", {}).get(
            "allowedToCreateSecurityGroups", True)
    except Exception:
        can_create = True
    return {
        "check_id": "AZURE-GROUP-005", "severity": "Medium",
        "status": "passed" if not can_create else "failed",
        "score":  1.1 if can_create else 0.0,
        "affected_resources": [{"setting": "allowedToCreateSecurityGroups", "value": "true"}] if can_create else [],
        "evidence": {"users_can_create_security_groups": can_create},
        "risk_description": "Unrestricted security group creation leads to unmanaged groups used for ad-hoc access without security governance.",
        "remediation_steps": "1. In Entra ID > Groups > General.\n2. Set 'Users can create security groups in Azure portals, API, or PowerShell' to No.\n3. Provide a request process for users who need groups.",
        "estimated_effort": "Moderate",
    }

# ─── MONITORING (3 checks) ────────────────────────────────────────────────────

def check_secure_score(graph, target_config):
    """AZURE-BG-002"""
    try:
        scores = graph.get_all_pages(
            "/security/secureScores?$top=1&$select=currentScore,maxScore,createdDateTime"
        )
        if scores:
            latest = scores[0]
            current = latest.get("currentScore", 0)
            maximum = latest.get("maxScore", 100)
            pct = round((current / maximum * 100) if maximum else 0, 1)
        else:
            pct = 0
            current = 0
            maximum = 0
    except Exception as e:
        return {
            "check_id": "AZURE-BG-002", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not retrieve Microsoft Secure Score.",
            "remediation_steps": "Ensure SecurityEvents.Read.All permission is granted.",
            "estimated_effort": "High",
        }
    threshold = 70
    return {
        "check_id": "AZURE-BG-002", "severity": "High",
        "status": "passed" if pct >= threshold else "failed",
        "score":  3.6 * (1 - pct / 100) if pct < threshold else 0.0,
        "affected_resources": [] if pct >= threshold else [
            {"metric": "Identity Secure Score", "current": f"{pct}%",
             "target": f"{threshold}%", "gap": f"{threshold - pct:.1f}%"}
        ],
        "evidence": {"current_score": current, "max_score": maximum, "percentage": pct},
        "risk_description": f"Identity Secure Score is {pct}% — below the recommended 70% threshold. Microsoft has identified unimplemented security controls.",
        "remediation_steps": "1. Navigate to security.microsoft.com > Secure Score.\n2. Filter Improvement actions by Category = Identity.\n3. Sort by Score impact descending.\n4. Work through each action.\n5. Target: 80%+ Identity Secure Score.",
        "estimated_effort": "High",
    }

def check_sync_unused_accounts(graph, target_config):
    """AZURE-SYNC-002"""
    try:
        users = graph.get_all_pages(
            "/users?$select=id,displayName,userPrincipalName,accountEnabled,signInActivity"
        )
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        stale_sync = []
        for u in users:
            upn = u.get("userPrincipalName", "")
            if not upn.startswith("Sync_"):
                continue
            last = u.get("signInActivity", {}).get("lastSignInDateTime")
            if not last or datetime.fromisoformat(last.replace("Z", "+00:00")) < cutoff:
                stale_sync.append({"id": u["id"], "name": u.get("displayName"),
                                   "upn": upn, "enabled": u.get("accountEnabled")})
    except Exception as e:
        return {
            "check_id": "AZURE-SYNC-002", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check sync accounts.",
            "remediation_steps": "Ensure User.Read.All and AuditLog.Read.All permissions are granted.",
            "estimated_effort": "Low",
        }
    return {
        "check_id": "AZURE-SYNC-002", "severity": "High",
        "status": "passed" if not stale_sync else "failed",
        "score":  5.4 if stale_sync else 0.0,
        "affected_resources": stale_sync,
        "evidence": {"stale_sync_accounts": len(stale_sync)},
        "risk_description": "Orphaned Entra ID Connect service accounts retain Directory Synchronisation Accounts role with directory write access.",
        "remediation_steps": "1. Identify which server each Sync_ account belongs to.\n2. Check if that server is still running Entra ID Connect.\n3. For decommissioned servers: disable the Sync_ account.\n4. Verify active sync is still working after disabling.\n5. Delete after 14-day observation period.",
        "estimated_effort": "Low",
    }

def check_admin_consent_workflow(graph, target_config):
    """AZURE-APP-006"""
    try:
        settings = graph.get("/policies/adminConsentRequestPolicy")
        is_enabled = settings.get("isEnabled", False)
        reviewers = settings.get("reviewers", [])
    except Exception as e:
        return {
            "check_id": "AZURE-APP-006", "severity": "High",
            "status": "error", "score": 0.0, "affected_resources": [],
            "evidence": {"error": str(e)},
            "risk_description": "Could not check admin consent workflow.",
            "remediation_steps": "Ensure Policy.Read.All permission is granted.",
            "estimated_effort": "Moderate",
        }
    issues = []
    if not is_enabled:
        issues.append({"issue": "Admin consent request workflow is disabled"})
    if is_enabled and len(reviewers) < 2:
        issues.append({"issue": f"Only {len(reviewers)} reviewer(s) configured — recommend at least 2"})
    return {
        "check_id": "AZURE-APP-006", "severity": "High",
        "status": "passed" if not issues else "failed",
        "score":  4.4 if not is_enabled else (1.0 if issues else 0.0),
        "affected_resources": issues,
        "evidence": {"workflow_enabled": is_enabled, "reviewer_count": len(reviewers)},
        "risk_description": "Without the admin consent workflow, users blocked from apps have no legitimate path to request access and may resort to workarounds.",
        "remediation_steps": "1. In Entra ID > Enterprise Applications > Admin consent requests.\n2. Set 'Users can request admin consent' to Yes.\n3. Add at least 2 reviewers.\n4. Set reminder email frequency.\n5. Save.",
        "estimated_effort": "Moderate",
    }




# ─── EXTRA CHECKS — 71 additional functions ──────────────────────────────────

# ── Conditional Access ────────────────────────────────────────────────────────

def check_ca_mfa_privileged(graph, target_config):
    """AZURE-CA-002"""
    policies = _ca_policies(graph)
    priv_mfa = [p for p in policies if p.get("state") == "enabled"
                and p.get("conditions", {}).get("users", {}).get("includeRoles")
                and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()]
    has_policy = len(priv_mfa) > 0
    return {"check_id": "AZURE-CA-002", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 8.1 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy requiring MFA for privileged roles"}],
            "evidence": {"mfa_priv_role_policies": len(priv_mfa)},
            "risk_description": "Privileged role members without MFA enforcement are one stolen password away from full tenant compromise.",
            "remediation_steps": "1. Create a CA policy targeting Directory roles (Global Admin, Security Admin, etc.).\n2. Grant: Require MFA.\n3. Exclude break glass group.\n4. Enable.", "estimated_effort": "Low"}

def check_ca_compliant_device(graph, target_config):
    """AZURE-CA-003"""
    policies = _ca_policies(graph)
    compliant = [p for p in policies if p.get("state") == "enabled"
                 and any(c in p.get("grantControls", {}).get("builtInControls", [])
                         for c in ["compliantDevice", "domainJoinedDevice"])]
    has_policy = len(compliant) > 0
    return {"check_id": "AZURE-CA-003", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 7.2 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy requiring compliant or domain-joined device"}],
            "evidence": {"device_compliance_policies": len(compliant)},
            "risk_description": "Without device compliance requirements, corporate data can be accessed from unmanaged personal devices.",
            "remediation_steps": "1. Enrol devices in Intune and configure compliance policies.\n2. Create a CA policy requiring compliant or hybrid joined device.\n3. Start in Report-only mode for 2-4 weeks.\n4. Enforce once compliance rate is above 95%.", "estimated_effort": "High"}

def check_ca_block_risky_privileged(graph, target_config):
    """AZURE-CA-004"""
    policies = _ca_policies(graph)
    block_priv_risk = [p for p in policies if p.get("state") == "enabled"
                       and p.get("conditions", {}).get("users", {}).get("includeRoles")
                       and p.get("conditions", {}).get("signInRiskLevels")
                       and "block" in p.get("grantControls", {}).get("builtInControls", [])]
    has_policy = len(block_priv_risk) > 0
    return {"check_id": "AZURE-CA-004", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 6.1 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy blocking risky sign-ins for privileged roles"}],
            "evidence": {"block_risky_priv_policies": len(block_priv_risk)},
            "risk_description": "Even a low sign-in risk signal for privileged accounts warrants blocking.",
            "remediation_steps": "1. Create a CA policy targeting Directory roles.\n2. Conditions: Sign-in risk = Low, Medium, High.\n3. Grant: Block access.\n4. Exclude break glass.\n5. Enable.", "estimated_effort": "Low"}

def check_ca_block_high_signin_risk(graph, target_config):
    """AZURE-CA-005"""
    policies = _ca_policies(graph)
    mfa_risk = [p for p in policies if p.get("state") == "enabled"
                and "high" in p.get("conditions", {}).get("signInRiskLevels", [])
                and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()]
    has_policy = len(mfa_risk) > 0
    return {"check_id": "AZURE-CA-005", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 6.1 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy requiring MFA for high sign-in risk"}],
            "evidence": {"mfa_on_risk_policies": len(mfa_risk)},
            "risk_description": "High-risk sign-ins without MFA enforcement allow attackers to succeed undetected.",
            "remediation_steps": "1. Create CA policy: Conditions > Sign-in risk > High and Medium.\n2. Grant: Require MFA.\n3. Enable.", "estimated_effort": "Low"}

def check_ca_no_persistent_session(graph, target_config):
    """AZURE-CA-006"""
    policies = _ca_policies(graph)
    session_policies = [p for p in policies if p.get("state") == "enabled"
                        and p.get("sessionControls", {}).get("persistentBrowser", {}).get("mode") == "never"]
    has_policy = len(session_policies) > 0
    return {"check_id": "AZURE-CA-006", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 4.4 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy preventing persistent browser sessions"}],
            "evidence": {"no_persistent_session_policies": len(session_policies)},
            "risk_description": "Persistent browser sessions on unmanaged devices allow session hijacking if device is lost or shared.",
            "remediation_steps": "1. Create a CA policy for unmanaged devices.\n2. Session > Persistent browser session: Never persistent.\n3. Session > Sign-in frequency: 1 hour.\n4. Enable.", "estimated_effort": "Moderate"}

def check_ca_block_admin_portals_risk(graph, target_config):
    """AZURE-CA-007"""
    policies = _ca_policies(graph)
    block_on_risk = [p for p in policies if p.get("state") == "enabled"
                     and p.get("conditions", {}).get("signInRiskLevels")
                     and "block" in p.get("grantControls", {}).get("builtInControls", [])]
    has_policy = len(block_on_risk) > 0
    return {"check_id": "AZURE-CA-007", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 5.4 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy blocking access on sign-in risk"}],
            "evidence": {"block_on_risk_policies": len(block_on_risk)},
            "risk_description": "Admin portal access during a risky sign-in can lead to irreversible tenant configuration changes.",
            "remediation_steps": "1. Create CA policy targeting Microsoft Admin Portals.\n2. Conditions: Sign-in risk > Low, Medium, High.\n3. Grant: Block access.\n4. Enable.", "estimated_effort": "Low"}

def check_ca_block_security_registration(graph, target_config):
    """AZURE-CA-008"""
    policies = _ca_policies(graph)
    risk_reg_block = [p for p in policies if p.get("state") == "enabled"
                      and "registerSecurityInfo" in str(p.get("conditions", {}).get("applications", {}).get("includeUserActions", []))
                      and p.get("conditions", {}).get("signInRiskLevels")]
    has_policy = len(risk_reg_block) > 0
    return {"check_id": "AZURE-CA-008", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 5.9 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy blocking security info registration on sign-in risk"}],
            "evidence": {"block_registration_on_risk_policies": len(risk_reg_block)},
            "risk_description": "After MFA fatigue attacks, attackers register their own authenticator to maintain persistent access.",
            "remediation_steps": "1. Create CA policy targeting User Actions > Register security information.\n2. Conditions: Sign-in risk > Low, Medium, High.\n3. Grant: Block access.\n4. Enable.", "estimated_effort": "Moderate"}

def check_ca_mfa_guests(graph, target_config):
    """AZURE-CA-013"""
    policies = _ca_policies(graph)
    guest_mfa = [p for p in policies if p.get("state") == "enabled"
                 and p.get("conditions", {}).get("users", {}).get("includeGuestsOrExternalUsers")
                 and "mfa" in str(p.get("grantControls", {}).get("builtInControls", [])).lower()]
    has_policy = len(guest_mfa) > 0
    return {"check_id": "AZURE-CA-013", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 4.9 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy requiring MFA for guest users"}],
            "evidence": {"mfa_guest_policies": len(guest_mfa)},
            "risk_description": "Guest users authenticate with external identities that may have weaker security controls.",
            "remediation_steps": "1. Create a CA policy targeting All guest and external users.\n2. Grant: Require MFA.\n3. Enable.", "estimated_effort": "Moderate"}

def check_ca_guest_session_timeout(graph, target_config):
    """AZURE-CA-015"""
    policies = _ca_policies(graph)
    guest_session = [p for p in policies if p.get("state") == "enabled"
                     and p.get("conditions", {}).get("users", {}).get("includeGuestsOrExternalUsers")
                     and p.get("sessionControls", {}).get("signInFrequency")]
    has_policy = len(guest_session) > 0
    return {"check_id": "AZURE-CA-015", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 4.8 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No session timeout policy for guests"}],
            "evidence": {"guest_session_policies": len(guest_session)},
            "risk_description": "Guest sessions without timeout allow persistent access from unmanaged devices indefinitely.",
            "remediation_steps": "1. Create CA policy for guests.\n2. Session > Sign-in frequency: 1 hour.\n3. Session > Persistent browser: Never.\n4. Enable.", "estimated_effort": "Low"}

def check_ca_priv_compliant_device(graph, target_config):
    """AZURE-CA-010"""
    policies = _ca_policies(graph)
    priv_device = [p for p in policies if p.get("state") == "enabled"
                   and p.get("conditions", {}).get("users", {}).get("includeRoles")
                   and any(c in p.get("grantControls", {}).get("builtInControls", [])
                           for c in ["compliantDevice", "domainJoinedDevice"])]
    has_policy = len(priv_device) > 0
    return {"check_id": "AZURE-CA-010", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 5.6 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy requiring compliant device for privileged roles"}],
            "evidence": {"priv_device_policies": len(priv_device)},
            "risk_description": "Admins working from unmanaged devices are exposed to keyloggers and browser-based credential theft.",
            "remediation_steps": "1. Create CA policy targeting Directory roles.\n2. Grant: Require compliant device.\n3. Ensure admins have enrolled corporate devices in Intune.\n4. Enable.", "estimated_effort": "Moderate"}

def check_ca_block_msol(graph, target_config):
    """AZURE-CA-017"""
    policies = _ca_policies(graph)
    block_other = [p for p in policies if p.get("state") == "enabled"
                   and "block" in p.get("grantControls", {}).get("builtInControls", [])
                   and "other" in p.get("conditions", {}).get("clientAppTypes", [])]
    has_policy = len(block_other) > 0
    return {"check_id": "AZURE-CA-017", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 3.2 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy blocking MSOL/legacy PowerShell"}],
            "evidence": {"block_legacy_ps_policies": len(block_other)},
            "risk_description": "MSOL PowerShell is deprecated. Attackers use it to bypass modern authentication controls.",
            "remediation_steps": "1. Migrate MSOL scripts to Microsoft Graph PowerShell.\n2. Create a CA policy blocking Other clients.\n3. Exclude approved automation accounts.\n4. Enable.", "estimated_effort": "High"}

def check_ca_workload_risk(graph, target_config):
    """AZURE-CA-022"""
    policies = _ca_policies(graph)
    workload_risk = [p for p in policies if p.get("state") == "enabled"
                     and p.get("conditions", {}).get("servicePrincipalRiskLevels")]
    has_policy = len(workload_risk) > 0
    return {"check_id": "AZURE-CA-022", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 3.4 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy for workload identity risk"}],
            "evidence": {"workload_risk_policies": len(workload_risk)},
            "risk_description": "Compromised service principals can perform lateral movement without triggering user-based risk policies.",
            "remediation_steps": "1. Enable Workload Identity Premium licences.\n2. Create CA policy for workload identities with high risk.\n3. Grant: Block.\n4. Enable.", "estimated_effort": "Moderate"}

def check_ca_cae(graph, target_config):
    """AZURE-CA-024"""
    policies = _ca_policies(graph)
    cae_policies = [p for p in policies if p.get("state") == "enabled"
                    and p.get("sessionControls", {}).get("continuousAccessEvaluation", {}).get("mode") == "strictEnforcement"]
    has_policy = len(cae_policies) > 0
    return {"check_id": "AZURE-CA-024", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 4.2 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy with Continuous Access Evaluation (strict enforcement)"}],
            "evidence": {"cae_strict_policies": len(cae_policies)},
            "risk_description": "Without CAE strict enforcement, stolen access tokens remain valid until expiry, providing an attack window.",
            "remediation_steps": "1. In CA policy session controls, enable Continuous Access Evaluation.\n2. Set mode to Strict enforcement.\n3. Enable for policies covering critical apps.", "estimated_effort": "Low"}

# ── MFA ───────────────────────────────────────────────────────────────────────

def check_mfa_registration_campaign(graph, target_config):
    """AZURE-MFA-004"""
    try:
        policy = graph.get("/policies/authenticationMethodsPolicy")
        campaign = policy.get("registrationEnforcement", {}).get("authenticationMethodsRegistrationCampaign", {})
        is_enabled = campaign.get("state") == "enabled"
        snoozeable = campaign.get("snoozeDurationInDays", 99)
        issues = []
        if not is_enabled:
            issues.append({"issue": "Registration campaign disabled"})
        elif snoozeable > 7:
            issues.append({"issue": f"Snoozeable days too high: {snoozeable} (recommend ≤7)"})
    except Exception as e:
        return {"check_id": "AZURE-MFA-004", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check MFA registration campaign.",
                "remediation_steps": "Ensure Policy.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-MFA-004", "severity": "High",
            "status": "passed" if not issues else "failed",
            "score": 4.4 if issues else 0.0,
            "affected_resources": issues,
            "evidence": {"campaign_enabled": is_enabled, "snoozeable_days": snoozeable},
            "risk_description": "Without a registration campaign, users never register MFA and CA MFA policies will block them.",
            "remediation_steps": "1. In Entra ID > Security > Authentication methods > Registration campaign.\n2. Set State to Enabled.\n3. Set snoozeable days to 7.\n4. Include all users.", "estimated_effort": "Moderate"}

def check_sspr_all_users(graph, target_config):
    """AZURE-MFA-005"""
    try:
        policy = graph.get("/policies/authenticationMethodsPolicy")
        methods = policy.get("authenticationMethodConfigurations", [])
        has_email = any(m.get("id") == "Email" and m.get("state") == "enabled" for m in methods)
        has_phone = any(m.get("id") in ("Sms", "Voice") and m.get("state") == "enabled" for m in methods)
        is_configured = has_email or has_phone
    except Exception as e:
        return {"check_id": "AZURE-MFA-005", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check SSPR configuration.",
                "remediation_steps": "Ensure Policy.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-MFA-005", "severity": "High",
            "status": "passed" if is_configured else "failed",
            "score": 4.9 if not is_configured else 0.0,
            "affected_resources": [] if is_configured else [{"issue": "SSPR authentication methods not configured"}],
            "evidence": {"email_enabled": has_email, "phone_enabled": has_phone},
            "risk_description": "Without SSPR methods, users cannot reset passwords during Identity Protection risk remediation flows.",
            "remediation_steps": "1. In Entra ID > Security > Authentication methods.\n2. Enable Microsoft Authenticator for all users.\n3. Enable SMS or Email as fallback.\n4. Save.", "estimated_effort": "Moderate"}

def check_admin_sspr_registered(graph, target_config):
    """AZURE-MFA-007"""
    members = _priv_role_members(graph, [GLOBAL_ADMIN, SEC_ADMIN])
    not_registered = []
    for m in members:
        try:
            methods = graph.get(f"/users/{m['id']}/authentication/methods")
            types = [x.get("@odata.type", "").lower() for x in methods.get("value", [])]
            if not any("email" in t or "phone" in t for t in types):
                not_registered.append({"id": m["id"], "name": m.get("displayName"), "upn": m.get("userPrincipalName")})
        except Exception as e:
            logger.warning(f"SSPR admin check failed for {m.get('displayName')}: {e}")
    return {"check_id": "AZURE-MFA-007", "severity": "Medium",
            "status": "passed" if not not_registered else "failed",
            "score": 0.9 if not_registered else 0.0,
            "affected_resources": not_registered,
            "evidence": {"admins_checked": len(members), "not_registered": len(not_registered)},
            "risk_description": "Admins without SSPR cannot self-remediate high user risk events.",
            "remediation_steps": "1. Direct each admin to https://mysecurityinfo.microsoft.com.\n2. Register at least one SSPR method.\n3. Verify via Authentication Methods Activity report.", "estimated_effort": "Low"}

def check_banned_password_onprem(graph, target_config):
    """AZURE-MFA-008"""
    try:
        domains = graph.get("/domains")
        has_onprem = any(d.get("isVerified") and not d.get("isDefault")
                         for d in domains.get("value", []))
    except Exception:
        has_onprem = False
    if not has_onprem:
        return {"check_id": "AZURE-MFA-008", "severity": "High", "status": "passed",
                "score": 0.0, "affected_resources": [], "evidence": {"onprem_domains": False},
                "risk_description": "No on-premises domains — cloud-only tenant.",
                "remediation_steps": "No action required for cloud-only tenants.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-MFA-008", "severity": "High", "status": "failed",
            "score": 5.4,
            "affected_resources": [{"issue": "On-premises domains detected — verify Entra ID Password Protection is installed on DCs"}],
            "evidence": {"onprem_domains_detected": True},
            "risk_description": "Without Password Protection on DCs, users can set banned weak passwords that cloud policy would reject.",
            "remediation_steps": "1. Download Azure AD Password Protection DC agent.\n2. Install on every domain controller.\n3. Install Proxy service on member server.\n4. Register with Entra ID.\n5. Start in Audit mode, then Enforced.", "estimated_effort": "Low"}

# ── PIM ───────────────────────────────────────────────────────────────────────

def check_pim_two_approvers(graph, target_config):
    """AZURE-PIM-003"""
    try:
        policies = graph.get_all_pages("/policies/roleManagementPolicies?$filter=scopeType eq 'DirectoryRole'")
        single_approver = []
        for policy in policies[:10]:
            try:
                rules = graph.get_all_pages(f"/policies/roleManagementPolicies/{policy['id']}/rules")
                for rule in rules:
                    s = rule.get("setting", {}) if isinstance(rule.get("setting"), dict) else {}
                    if s.get("isApprovalRequired") and len(s.get("approvers", [])) < 2:
                        single_approver.append({"policy": policy.get("displayName", policy["id"])})
                        break
            except Exception:
                pass
    except Exception as e:
        return {"check_id": "AZURE-PIM-003", "severity": "Medium", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check PIM approvers.",
                "remediation_steps": "Ensure PrivilegedAccess.Read.AzureAD permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-PIM-003", "severity": "Medium",
            "status": "passed" if not single_approver else "failed",
            "score": 0.4 if single_approver else 0.0,
            "affected_resources": single_approver,
            "evidence": {"roles_with_single_approver": len(single_approver)},
            "risk_description": "A single approver creates a single point of failure for PIM activations.",
            "remediation_steps": "1. In PIM > Entra ID Roles > Settings, select each role.\n2. Add at least 2 approvers in different timezones.\n3. Save.", "estimated_effort": "Low"}

def check_pim_activation_duration(graph, target_config):
    """AZURE-PIM-004"""
    try:
        policies = graph.get_all_pages("/policies/roleManagementPolicies?$filter=scopeType eq 'DirectoryRole'")
        long_duration = []
        for policy in policies[:10]:
            try:
                rules = graph.get_all_pages(f"/policies/roleManagementPolicies/{policy['id']}/rules")
                for rule in rules:
                    s = rule.get("setting", {}) if isinstance(rule.get("setting"), dict) else {}
                    max_d = s.get("maximumDuration", "")
                    if "PT" in max_d and "H" in max_d:
                        hours = int(max_d.replace("PT", "").replace("H", "").replace("M", "0"))
                        if hours > 8:
                            long_duration.append({"policy": policy.get("displayName", policy["id"]), "max_hours": hours})
                            break
            except Exception:
                pass
    except Exception as e:
        return {"check_id": "AZURE-PIM-004", "severity": "Medium", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check PIM activation duration.",
                "remediation_steps": "Ensure PrivilegedAccess.Read.AzureAD permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-PIM-004", "severity": "Medium",
            "status": "passed" if not long_duration else "failed",
            "score": 2.3 if long_duration else 0.0,
            "affected_resources": long_duration,
            "evidence": {"roles_with_long_duration": len(long_duration)},
            "risk_description": "Long activation durations mean standing privilege for extended periods after activation.",
            "remediation_steps": "1. In PIM > Settings, set Global Admin/Security Admin max to 2 hours.\n2. Set other roles to 8 hours maximum.", "estimated_effort": "Moderate"}

def check_pim_cloud_only_privileged(graph, target_config):
    """AZURE-PIM-006"""
    try:
        assignments = graph.get_all_pages("/roleManagement/directory/roleEligibilitySchedules?$expand=principal")
        synced_eligible = [{"principal": a.get("principal", {}).get("displayName"),
                            "upn": a.get("principal", {}).get("userPrincipalName")}
                           for a in assignments if a.get("principal", {}).get("onPremisesSyncEnabled")]
    except Exception as e:
        return {"check_id": "AZURE-PIM-006", "severity": "Critical", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check PIM eligible assignments.",
                "remediation_steps": "Ensure RoleManagement.Read.Directory permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-PIM-006", "severity": "Critical",
            "status": "passed" if not synced_eligible else "failed",
            "score": 9.0 if synced_eligible else 0.0,
            "affected_resources": synced_eligible,
            "evidence": {"synced_eligible": len(synced_eligible)},
            "risk_description": "PIM eligible assignments on synced accounts allow on-premises compromise to escalate to cloud privilege.",
            "remediation_steps": "1. Create cloud-only accounts for each synced eligible user.\n2. Move PIM eligible assignments to cloud-only accounts.\n3. Remove eligible assignments from synced accounts.", "estimated_effort": "Low"}

def check_pim_alerts(graph, target_config):
    """AZURE-PIM-007"""
    try:
        alerts = graph.get_all_pages("/privilegedAccess/aadRoles/resources/tenant/alerts")
        critical = [{"alert": a.get("alertDefinitionId"), "count": a.get("numberOfAffectedItems")}
                    for a in alerts if a.get("isActive") and
                    ("permanent" in str(a.get("alertDefinitionId", "")).lower() or
                     "outside" in str(a.get("alertDefinitionId", "")).lower())]
    except Exception as e:
        return {"check_id": "AZURE-PIM-007", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check PIM security alerts.",
                "remediation_steps": "Ensure PrivilegedAccess.Read.AzureAD permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-PIM-007", "severity": "High",
            "status": "passed" if not critical else "failed",
            "score": 4.8 if critical else 0.0,
            "affected_resources": critical,
            "evidence": {"critical_pim_alerts": len(critical)},
            "risk_description": "Active PIM security alerts indicate governance issues like permanent assignments made outside PIM.",
            "remediation_steps": "1. In PIM > Entra ID Roles > Alerts, review all active alerts.\n2. Resolve each following the recommendation.\n3. Enable email notifications for new PIM alerts.", "estimated_effort": "Low"}

# ── Identity ──────────────────────────────────────────────────────────────────

def check_identity_secure_score_001(graph, target_config):
    """AZURE-IDENTITY-001"""
    try:
        scores = graph.get_all_pages("/security/secureScores?$top=1&$select=currentScore,maxScore")
        if scores:
            current = scores[0].get("currentScore", 0)
            maximum = scores[0].get("maxScore", 100)
            pct = round((current / maximum * 100) if maximum else 0)
        else:
            pct = 0
        is_good = pct >= 60
    except Exception as e:
        return {"check_id": "AZURE-IDENTITY-001", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check Identity Secure Score.",
                "remediation_steps": "Ensure SecurityEvents.Read.All permission is granted.", "estimated_effort": "High"}
    return {"check_id": "AZURE-IDENTITY-001", "severity": "High",
            "status": "passed" if is_good else "failed",
            "score": 3.6 * (1 - pct / 100) if not is_good else 0.0,
            "affected_resources": [] if is_good else [{"metric": "Secure Score", "pct": pct, "target": 60}],
            "evidence": {"secure_score_pct": pct},
            "risk_description": f"Identity Secure Score is {pct}% — below 60% threshold.",
            "remediation_steps": "1. In Entra ID > Security > Identity Secure Score.\n2. Review each improvement action.\n3. Start with highest-impact items.\n4. Target 80%+ score.", "estimated_effort": "High"}

def check_stale_cloud_users_002(graph, target_config):
    """AZURE-IDENTITY-002"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    try:
        users = graph.get_all_pages(
            "/users?$filter=userType eq 'Member' and accountEnabled eq true"
            "&$select=id,displayName,userPrincipalName,onPremisesSyncEnabled,signInActivity,createdDateTime")
        stale = []
        for u in users:
            if u.get("onPremisesSyncEnabled"):
                continue
            last = u.get("signInActivity", {}).get("lastSignInDateTime")
            created = u.get("createdDateTime", "")
            try:
                if not last and created and datetime.fromisoformat(created.replace("Z", "+00:00")) < cutoff:
                    stale.append({"id": u["id"], "name": u.get("displayName"), "upn": u.get("userPrincipalName"), "last_sign_in": "Never"})
                elif last and datetime.fromisoformat(last.replace("Z", "+00:00")) < cutoff:
                    stale.append({"id": u["id"], "name": u.get("displayName"), "upn": u.get("userPrincipalName"), "last_sign_in": last})
            except Exception:
                pass
    except Exception as e:
        return {"check_id": "AZURE-IDENTITY-002", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check stale cloud users.",
                "remediation_steps": "Ensure AuditLog.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-IDENTITY-002", "severity": "High",
            "status": "passed" if not stale else "failed",
            "score": 3.0 if stale else 0.0,
            "affected_resources": stale[:20],
            "evidence": {"stale_count": len(stale)},
            "risk_description": "Stale cloud accounts may belong to departed employees retaining access.",
            "remediation_steps": "1. Cross-reference with HR records.\n2. Disable accounts with no legitimate owner.\n3. Delete after 30-day grace period.\n4. Implement HR lifecycle workflows.", "estimated_effort": "Moderate"}

def check_admin_no_mailbox(graph, target_config):
    """AZURE-IDENTITY-003"""
    members = _priv_role_members(graph, [GLOBAL_ADMIN, SEC_ADMIN])
    with_mailbox = []
    for m in members:
        try:
            user = graph.get(f"/users/{m['id']}?$select=id,displayName,userPrincipalName,mail")
            mail = user.get("mail", "")
            if mail and ".onmicrosoft.com" not in mail and "admin" not in mail.lower():
                with_mailbox.append({"id": m["id"], "name": m.get("displayName"), "upn": m.get("userPrincipalName"), "mail": mail})
        except Exception:
            pass
    return {"check_id": "AZURE-IDENTITY-003", "severity": "High",
            "status": "passed" if not with_mailbox else "failed",
            "score": 5.2 if with_mailbox else 0.0,
            "affected_resources": with_mailbox,
            "evidence": {"admins_checked": len(members), "with_mailbox": len(with_mailbox)},
            "risk_description": "Admin accounts with mailboxes can receive phishing emails, directly exposing privileged access.",
            "remediation_steps": "1. Create cloud-only admin accounts without mailboxes.\n2. Move privileged roles to new accounts.\n3. Remove Exchange licences from admin accounts.", "estimated_effort": "Moderate"}

def check_admin_no_skype(graph, target_config):
    """AZURE-IDENTITY-004"""
    members = _priv_role_members(graph, [GLOBAL_ADMIN, SEC_ADMIN])
    with_skype = []
    for m in members:
        try:
            user = graph.get(f"/users/{m['id']}?$select=id,displayName,userPrincipalName,imAddresses")
            if user.get("imAddresses"):
                with_skype.append({"id": m["id"], "name": m.get("displayName"), "upn": m.get("userPrincipalName")})
        except Exception:
            pass
    return {"check_id": "AZURE-IDENTITY-004", "severity": "High",
            "status": "passed" if not with_skype else "failed",
            "score": 5.2 if with_skype else 0.0,
            "affected_resources": with_skype,
            "evidence": {"admins_checked": len(members), "with_skype": len(with_skype)},
            "risk_description": "Skype/Teams on admin accounts allows social engineering targeting privileged accounts.",
            "remediation_steps": "1. Remove Skype addresses from admin profiles.\n2. Remove Teams and Exchange licences from admin accounts.", "estimated_effort": "Moderate"}

def check_stale_sync_id006(graph, target_config):
    """AZURE-IDENTITY-006"""
    try:
        users = graph.get_all_pages("/users?$select=id,displayName,userPrincipalName,accountEnabled")
        sync_accounts = [u for u in users if u.get("userPrincipalName", "").startswith("Sync_")]
        issues = [{"name": u.get("userPrincipalName"), "enabled": u.get("accountEnabled")}
                  for u in sync_accounts[1:]] if len(sync_accounts) > 1 else []
    except Exception as e:
        return {"check_id": "AZURE-IDENTITY-006", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check sync accounts.",
                "remediation_steps": "Ensure User.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-IDENTITY-006", "severity": "High",
            "status": "passed" if not issues else "failed",
            "score": 5.4 if issues else 0.0,
            "affected_resources": issues,
            "evidence": {"sync_accounts_found": len(sync_accounts)},
            "risk_description": "Multiple Sync_ accounts suggest decommissioned Entra ID Connect servers never cleaned up.",
            "remediation_steps": "1. Identify active Entra ID Connect server's Sync_ account.\n2. Disable and delete all other Sync_ accounts.\n3. Verify sync still works.", "estimated_effort": "Low"}

def check_old_synced_passwords(graph, target_config):
    """AZURE-IDENTITY-007"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=365)
    try:
        users = graph.get_all_pages(
            "/users?$filter=onPremisesSyncEnabled eq true"
            "&$select=id,displayName,userPrincipalName,lastPasswordChangeDateTime")
        old_pw = []
        for u in users:
            lc = u.get("lastPasswordChangeDateTime")
            if lc:
                try:
                    if datetime.fromisoformat(lc.replace("Z", "+00:00")) < cutoff:
                        old_pw.append({"id": u["id"], "name": u.get("displayName"), "upn": u.get("userPrincipalName"), "last_changed": lc})
                except Exception:
                    pass
    except Exception as e:
        return {"check_id": "AZURE-IDENTITY-007", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check password ages.",
                "remediation_steps": "Ensure User.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-IDENTITY-007", "severity": "High",
            "status": "passed" if not old_pw else "failed",
            "score": 1.0 if old_pw else 0.0,
            "affected_resources": old_pw[:20],
            "evidence": {"synced_users": len(users), "old_passwords": len(old_pw)},
            "risk_description": "Passwords over 365 days old have had a longer exposure window through breaches and phishing.",
            "remediation_steps": "1. Configure AD max password age of 365 days.\n2. Force reset for listed accounts.\n3. Enable Entra ID Password Protection on DCs.", "estimated_effort": "Low"}

def check_pwdlastset_sync(graph, target_config):
    """AZURE-IDENTITY-008"""
    try:
        users = graph.get_all_pages(
            "/users?$filter=onPremisesSyncEnabled eq true"
            "&$select=id,userPrincipalName,lastPasswordChangeDateTime&$top=20")
        missing = [u for u in users if not u.get("lastPasswordChangeDateTime")]
        pct = len(missing) / len(users) * 100 if users else 0
        is_syncing = pct < 10
    except Exception as e:
        return {"check_id": "AZURE-IDENTITY-008", "severity": "Medium", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check pwdLastSet sync.",
                "remediation_steps": "Ensure User.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-IDENTITY-008", "severity": "Medium",
            "status": "passed" if is_syncing else "failed",
            "score": 1.2 if not is_syncing else 0.0,
            "affected_resources": [] if is_syncing else [{"issue": f"{pct:.0f}% of synced users missing lastPasswordChangeDateTime"}],
            "evidence": {"sample_size": len(users), "missing_pct": round(pct)},
            "risk_description": "Without pwdLastSet sync, tokens remain valid up to 12 hours after an on-premises password change.",
            "remediation_steps": "1. In Entra ID Connect, verify passwordLastSet is in sync rules.\n2. Run delta sync.\n3. Verify lastPasswordChangeDateTime is populated.", "estimated_effort": "Low"}

def check_account_takeover_protection(graph, target_config):
    """AZURE-IDENTITY-009"""
    try:
        org = graph.get("/organization?$select=onPremisesSyncEnabled")
        sync_enabled = any(o.get("onPremisesSyncEnabled") for o in org.get("value", []))
    except Exception:
        sync_enabled = False
    if not sync_enabled:
        return {"check_id": "AZURE-IDENTITY-009", "severity": "High", "status": "passed",
                "score": 0.0, "affected_resources": [], "evidence": {"sync_enabled": False},
                "risk_description": "No on-premises sync — cloud-only tenant.",
                "remediation_steps": "No action required.", "estimated_effort": "High"}
    return {"check_id": "AZURE-IDENTITY-009", "severity": "High", "status": "failed",
            "score": 1.4,
            "affected_resources": [{"issue": "Verify soft matching is disabled in Entra ID Connect"}],
            "evidence": {"sync_enabled": True},
            "risk_description": "Soft matching allows on-premises AD to claim cloud-only admin accounts.",
            "remediation_steps": "1. Open Entra ID Connect configuration.\n2. Disable soft match.\n3. Run: Set-MsolDirSyncFeature -Feature SoftMatchOnUpn -Enable $false", "estimated_effort": "High"}

def check_admin_email_id010(graph, target_config):
    """AZURE-IDENTITY-010"""
    members = _priv_role_members(graph, [GLOBAL_ADMIN])
    with_email = []
    for m in members:
        try:
            user = graph.get(f"/users/{m['id']}?$select=id,displayName,userPrincipalName,mail")
            mail = user.get("mail", "")
            if mail and "admin" not in mail.lower() and ".onmicrosoft.com" not in mail:
                with_email.append({"id": m["id"], "name": m.get("displayName"), "upn": m.get("userPrincipalName"), "mail": mail})
        except Exception:
            pass
    return {"check_id": "AZURE-IDENTITY-010", "severity": "High",
            "status": "passed" if not with_email else "failed",
            "score": 5.2 if with_email else 0.0,
            "affected_resources": with_email,
            "evidence": {"global_admins": len(members), "with_email": len(with_email)},
            "risk_description": "Admin accounts with email addresses can receive phishing directly targeting privileged access.",
            "remediation_steps": "1. Create cloud-only admin accounts (admin@) without mailboxes.\n2. Remove email/Exchange licences from existing admin accounts.", "estimated_effort": "Moderate"}

def check_sspr_admin_id012(graph, target_config):
    """AZURE-IDENTITY-012"""
    members = _priv_role_members(graph, [GLOBAL_ADMIN, SEC_ADMIN])
    not_registered = []
    for m in members:
        try:
            methods = graph.get(f"/users/{m['id']}/authentication/methods")
            types = [x.get("@odata.type", "").lower() for x in methods.get("value", [])]
            if not any("email" in t or "phone" in t or "authenticator" in t for t in types):
                not_registered.append({"id": m["id"], "name": m.get("displayName"), "upn": m.get("userPrincipalName")})
        except Exception:
            pass
    return {"check_id": "AZURE-IDENTITY-012", "severity": "Medium",
            "status": "passed" if not not_registered else "failed",
            "score": 0.9 if not_registered else 0.0,
            "affected_resources": not_registered,
            "evidence": {"admins_checked": len(members), "not_registered": len(not_registered)},
            "risk_description": "Admins without SSPR cannot self-remediate risk events.",
            "remediation_steps": "1. Direct admins to https://mysecurityinfo.microsoft.com.\n2. Register MFA and SSPR methods.\n3. Verify via Authentication Methods Activity report.", "estimated_effort": "Low"}

def check_admin_sspr_id014(graph, target_config):
    """AZURE-IDENTITY-014"""
    members = _priv_role_members(graph, ALL_PRIV_ROLES)
    not_registered = []
    for m in members[:20]:
        try:
            methods = graph.get(f"/users/{m['id']}/authentication/methods")
            types = methods.get("value", [])
            if len(types) <= 1:
                not_registered.append({"id": m["id"], "name": m.get("displayName"), "upn": m.get("userPrincipalName")})
        except Exception:
            pass
    return {"check_id": "AZURE-IDENTITY-014", "severity": "Medium",
            "status": "passed" if not not_registered else "failed",
            "score": 0.9 if not_registered else 0.0,
            "affected_resources": not_registered,
            "evidence": {"admins_checked": min(len(members), 20), "no_method": len(not_registered)},
            "risk_description": "Admin role members with no authentication method cannot be protected by MFA or SSPR policies.",
            "remediation_steps": "1. Require all admins to register at https://mysecurityinfo.microsoft.com.\n2. Track completion via Authentication Methods Activity report.", "estimated_effort": "Low"}

def check_m365_group_creation(graph, target_config):
    """AZURE-IDENTITY-016"""
    try:
        policy = graph.get("/policies/authorizationPolicy")
        can_create = policy.get("defaultUserRolePermissions", {}).get("allowedToCreateGroups", True)
    except Exception:
        can_create = True
    return {"check_id": "AZURE-IDENTITY-016", "severity": "Low",
            "status": "passed" if not can_create else "failed",
            "score": 0.8 if can_create else 0.0,
            "affected_resources": [{"setting": "allowedToCreateGroups", "value": "true"}] if can_create else [],
            "evidence": {"users_can_create_groups": can_create},
            "risk_description": "Unrestricted M365 group creation leads to ungoverned Teams, SharePoint sites, and mailboxes.",
            "remediation_steps": "1. Configure M365 group naming policy in Entra ID.\n2. Restrict creation to approved users.\n3. Enable group expiration policy.", "estimated_effort": "Moderate"}

def check_smart_lockout(graph, target_config):
    """AZURE-IDENTITY-018"""
    try:
        policy = graph.get("/policies/authenticationMethodsPolicy")
        has_policy = policy.get("id") is not None
    except Exception:
        has_policy = False
    return {"check_id": "AZURE-IDENTITY-018", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 4.5 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "Could not verify smart lockout configuration"}],
            "evidence": {"policy_accessible": has_policy},
            "risk_description": "Smart lockout protects against brute force attacks. Threshold and duration should match your environment.",
            "remediation_steps": "1. In Entra ID > Security > Authentication methods > Password protection.\n2. Set lockout threshold to 5-10.\n3. Set lockout duration to 120+ seconds.", "estimated_effort": "Low"}

def check_secure_score_id020(graph, target_config):
    """AZURE-IDENTITY-020"""
    try:
        improvements = graph.get_all_pages(
            "/security/secureScoreControlProfiles?$filter=controlCategory eq 'Identity'&$select=id,title,maxScore,implementationStatus")
        not_impl = [{"control": i.get("title"), "max_score": i.get("maxScore")}
                    for i in improvements if i.get("implementationStatus") in ("notImplemented", "thirdParty")]
        total_missed = sum(i.get("maxScore", 0) for i in not_impl)
    except Exception as e:
        return {"check_id": "AZURE-IDENTITY-020", "severity": "Medium", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check Secure Score recommendations.",
                "remediation_steps": "Ensure SecurityEvents.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-IDENTITY-020", "severity": "Medium",
            "status": "passed" if not not_impl else "failed",
            "score": min(2.5, total_missed * 0.05) if not_impl else 0.0,
            "affected_resources": not_impl[:10],
            "evidence": {"unimplemented": len(not_impl), "points_missed": total_missed},
            "risk_description": "Unimplemented Secure Score identity controls represent known gaps identified by Microsoft.",
            "remediation_steps": "1. Go to security.microsoft.com > Secure Score > Improvement actions.\n2. Filter by Identity.\n3. Work through highest-impact items.\n4. Target 80%+ score.", "estimated_effort": "Moderate"}

# ── Applications ──────────────────────────────────────────────────────────────

def check_app_mailbox_perms(graph, target_config):
    """AZURE-APP-002"""
    try:
        grants = graph.get_all_pages("/oauth2PermissionGrants")
        affected = [{"app_id": g.get("clientId"), "scope": g.get("scope")}
                    for g in grants if any(s in g.get("scope", "") for s in ["Mail.Read", "Mail.ReadWrite", "Mail.Send"])]
    except Exception as e:
        return {"check_id": "AZURE-APP-002", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check mailbox permission grants.",
                "remediation_steps": "Ensure DelegatedPermissionGrant.ReadWrite.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-APP-002", "severity": "High",
            "status": "passed" if not affected else "failed",
            "score": 5.6 if affected else 0.0,
            "affected_resources": affected[:10],
            "evidence": {"mail_grants_found": len(affected)},
            "risk_description": "Apps with Mail.Read/ReadWrite can exfiltrate entire mailboxes when a user is compromised.",
            "remediation_steps": "1. Review each listed app and verify it is approved.\n2. Revoke consent for unknown apps.\n3. Enable app assignment to limit scope.", "estimated_effort": "Moderate"}

def check_app_sharepoint_perms(graph, target_config):
    """AZURE-APP-003"""
    try:
        grants = graph.get_all_pages("/oauth2PermissionGrants")
        affected = [{"app_id": g.get("clientId"), "scope": g.get("scope")}
                    for g in grants if any(s in g.get("scope", "") for s in ["Files.ReadWrite", "Sites.ReadWrite.All", "Sites.FullControl.All"])]
    except Exception as e:
        return {"check_id": "AZURE-APP-003", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check SharePoint permission grants.",
                "remediation_steps": "Ensure DelegatedPermissionGrant.ReadWrite.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-APP-003", "severity": "High",
            "status": "passed" if not affected else "failed",
            "score": 5.6 if affected else 0.0,
            "affected_resources": affected[:10],
            "evidence": {"sharepoint_grants": len(affected)},
            "risk_description": "Apps with SharePoint write permissions can modify or exfiltrate document repositories.",
            "remediation_steps": "1. Review each app and confirm write access is necessary.\n2. Downgrade to read-only where possible.\n3. Revoke consent for unknown apps.", "estimated_effort": "Moderate"}

def check_app_sp_assigned_perms(graph, target_config):
    """AZURE-APP-004"""
    try:
        sp_apps = graph.get_all_pages("/servicePrincipals?$filter=appId eq '00000003-0000-0ff1-ce00-000000000000'&$select=id")
        risky = []
        if sp_apps:
            assignments = graph.get_all_pages(f"/servicePrincipals/{sp_apps[0]['id']}/appRoleAssignedTo")
            risky = [{"app": a.get("principalDisplayName"), "id": a.get("principalId")}
                     for a in assignments if a.get("principalType") in ("Application", "ServicePrincipal")]
    except Exception as e:
        return {"check_id": "AZURE-APP-004", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check SharePoint application permissions.",
                "remediation_steps": "Ensure Application.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-APP-004", "severity": "High",
            "status": "passed" if not risky else "failed",
            "score": 5.6 if risky else 0.0,
            "affected_resources": risky[:10],
            "evidence": {"apps_with_sp_permissions": len(risky)},
            "risk_description": "Application-level SharePoint permissions allow access to all SharePoint data without user consent.",
            "remediation_steps": "1. Review each app.\n2. Revoke unnecessary permissions.\n3. Prefer delegated over application permissions.", "estimated_effort": "Moderate"}

def check_recent_admin_consents(graph, target_config):
    """AZURE-APP-007"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    try:
        sps = graph.get_all_pages("/servicePrincipals?$select=id,displayName,createdDateTime,tags")
        recent_30d = []
        for sp in sps:
            if "WindowsAzureActiveDirectoryIntegratedApp" not in (sp.get("tags") or []):
                continue
            created = sp.get("createdDateTime")
            if created:
                try:
                    if datetime.fromisoformat(created.replace("Z", "+00:00")) > cutoff:
                        recent_30d.append({"app": sp.get("displayName"), "id": sp.get("id"), "created": created})
                except Exception:
                    pass
    except Exception as e:
        return {"check_id": "AZURE-APP-007", "severity": "Low", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check recent app consents.",
                "remediation_steps": "Ensure Application.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-APP-007", "severity": "Low",
            "status": "passed" if not recent_30d else "failed",
            "score": 0.5 if recent_30d else 0.0,
            "affected_resources": recent_30d[:10],
            "evidence": {"new_apps_30d": len(recent_30d)},
            "risk_description": "Recently consented apps should be reviewed to ensure they went through the governance process.",
            "remediation_steps": "1. Review each new application.\n2. Verify approved through admin consent workflow.\n3. Revoke consent for any unrecognised apps.", "estimated_effort": "Moderate"}

def check_app_signin_audience(graph, target_config):
    """AZURE-APP-009"""
    try:
        sps = graph.get_all_pages("/servicePrincipals?$select=id,displayName,signInAudience&$top=50")
        broad = [{"app": sp.get("displayName"), "id": sp.get("id"), "audience": sp.get("signInAudience")}
                 for sp in sps if sp.get("signInAudience") in ("AzureADandPersonalMicrosoftAccount", "PersonalMicrosoftAccount")]
    except Exception as e:
        return {"check_id": "AZURE-APP-009", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check application sign-in audience.",
                "remediation_steps": "Ensure Application.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-APP-009", "severity": "High",
            "status": "passed" if not broad else "failed",
            "score": 2.6 if broad else 0.0,
            "affected_resources": broad[:10],
            "evidence": {"broad_audience_apps": len(broad)},
            "risk_description": "Apps with broad sign-in audience expand the attack surface beyond your organisation.",
            "remediation_steps": "1. Change sign-in audience to AzureADMyOrg for each listed app.\n2. Test the application after changing.\n3. This restricts authentication to your tenant only.", "estimated_effort": "Moderate"}

def check_app_credential_rotation(graph, target_config):
    """AZURE-APP-011"""
    apps = graph.get_applications()
    old_creds = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=365)
    for app in apps:
        for cred in (app.get("passwordCredentials") or []) + (app.get("keyCredentials") or []):
            start = cred.get("startDateTime")
            if start:
                try:
                    start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    if start_dt < cutoff:
                        old_creds.append({"app": app.get("displayName"), "id": app.get("id"),
                                          "created": start, "age_days": (datetime.now(timezone.utc) - start_dt).days})
                except Exception:
                    pass
    return {"check_id": "AZURE-APP-011", "severity": "High",
            "status": "passed" if not old_creds else "failed",
            "score": 2.7 if old_creds else 0.0,
            "affected_resources": old_creds[:15],
            "evidence": {"apps_checked": len(apps), "old_credentials": len(old_creds)},
            "risk_description": "Credentials older than 12 months have had a longer exposure window.",
            "remediation_steps": "1. Generate new credentials for each listed app.\n2. Update application configuration.\n3. Test application.\n4. Delete old credentials.\n5. Consider Azure Key Vault for automated rotation.", "estimated_effort": "Moderate"}

def check_default_app_creds(graph, target_config):
    """AZURE-APP-012"""
    try:
        first_party = graph.get_all_pages(
            "/servicePrincipals?$filter=tags/any(t:t eq 'MicrosoftFirstParty')&$select=id,displayName,passwordCredentials,keyCredentials")
        with_creds = [{"app": sp.get("displayName"), "id": sp.get("id")}
                      for sp in first_party if sp.get("passwordCredentials") or sp.get("keyCredentials")]
    except Exception as e:
        return {"check_id": "AZURE-APP-012", "severity": "Medium", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check default Microsoft application credentials.",
                "remediation_steps": "Ensure Application.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-APP-012", "severity": "Medium",
            "status": "passed" if not with_creds else "failed",
            "score": 2.3 if with_creds else 0.0,
            "affected_resources": with_creds[:10],
            "evidence": {"first_party_apps": len(first_party), "with_unexpected_creds": len(with_creds)},
            "risk_description": "Credentials on Microsoft first-party service principals are unusual and may indicate tampering.",
            "remediation_steps": "1. Investigate why credentials were added to each listed app.\n2. Remove unauthorised credentials.\n3. Review audit logs for credential creation events.", "estimated_effort": "Moderate"}

def check_app_risky_oauth(graph, target_config):
    """AZURE-APP-014"""
    RISKY = {"RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"}
    try:
        grants = graph.get_all_pages("/oauth2PermissionGrants")
        risky = [{"app_id": g.get("clientId"), "scope": g.get("scope")}
                 for g in grants if any(p in (g.get("scope") or "") for p in RISKY)]
    except Exception as e:
        return {"check_id": "AZURE-APP-014", "severity": "Medium", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check risky OAuth permissions.",
                "remediation_steps": "Ensure DelegatedPermissionGrant.ReadWrite.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-APP-014", "severity": "Medium",
            "status": "passed" if not risky else "failed",
            "score": 2.8 if risky else 0.0,
            "affected_resources": risky[:10],
            "evidence": {"risky_grants": len(risky)},
            "risk_description": "High-privilege OAuth grants allow apps to modify directory roles or grant themselves additional permissions.",
            "remediation_steps": "1. Review each listed app and permission.\n2. Revoke unnecessary high-privilege grants.\n3. Enable admin consent workflow.", "estimated_effort": "Low"}

# ── Guests ────────────────────────────────────────────────────────────────────

def check_guest_email_otp(graph, target_config):
    """AZURE-GUEST-005"""
    try:
        collab = graph.get("/policies/externalIdentitiesPolicy")
        otp_enabled = collab.get("isEmailPasswordAuthenticationEnabled", False)
    except Exception as e:
        return {"check_id": "AZURE-GUEST-005", "severity": "Low", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check guest OTP settings.",
                "remediation_steps": "Ensure Policy.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-GUEST-005", "severity": "Low",
            "status": "passed" if otp_enabled else "failed",
            "score": 1.6 if not otp_enabled else 0.0,
            "affected_resources": [] if otp_enabled else [{"issue": "Email one-time passcode not enabled for guests"}],
            "evidence": {"email_otp_enabled": otp_enabled},
            "risk_description": "Without email OTP, guests without Microsoft or Google accounts have no authentication path.",
            "remediation_steps": "1. In Entra ID > External Identities > External collaboration settings.\n2. Enable Email one-time passcode.\n3. Save.", "estimated_effort": "Low"}

def check_guest_block_admin_ca(graph, target_config):
    """AZURE-GUEST-004"""
    policies = _ca_policies(graph)
    guest_block = [p for p in policies if p.get("state") == "enabled"
                   and p.get("conditions", {}).get("users", {}).get("includeGuestsOrExternalUsers")
                   and "block" in p.get("grantControls", {}).get("builtInControls", [])]
    has_policy = len(guest_block) > 0
    return {"check_id": "AZURE-GUEST-004", "severity": "High",
            "status": "passed" if has_policy else "failed",
            "score": 3.2 if not has_policy else 0.0,
            "affected_resources": [] if has_policy else [{"issue": "No CA policy blocking guest access"}],
            "evidence": {"guest_block_policies": len(guest_block)},
            "risk_description": "Guest accounts accessing admin portals can perform reconnaissance on tenant configuration.",
            "remediation_steps": "1. Create CA policy for All guest and external users.\n2. Cloud apps: Microsoft Admin Portals.\n3. Grant: Block access.\n4. Enable.", "estimated_effort": "Low"}

# ── Groups ────────────────────────────────────────────────────────────────────

def check_group_no_owners_001(graph, target_config):
    """AZURE-GROUP-001"""
    try:
        groups = graph.get_all_pages(
            "/groups?$filter=securityEnabled eq true&$select=id,displayName,onPremisesSyncEnabled")
        cloud = [g for g in groups if not g.get("onPremisesSyncEnabled")]
        no_owners = []
        for g in cloud[:40]:
            try:
                owners = graph.get_all_pages(f"/groups/{g['id']}/owners")
                if not owners:
                    no_owners.append({"id": g["id"], "name": g.get("displayName")})
            except Exception:
                pass
    except Exception as e:
        return {"check_id": "AZURE-GROUP-001", "severity": "Low", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check security group owners.",
                "remediation_steps": "Ensure Group.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-GROUP-001", "severity": "Low",
            "status": "passed" if not no_owners else "failed",
            "score": 0.5 if no_owners else 0.0,
            "affected_resources": no_owners,
            "evidence": {"groups_checked": len(cloud), "no_owners": len(no_owners)},
            "risk_description": "Security groups without owners have no accountable party for membership management.",
            "remediation_steps": "1. Identify an appropriate owner for each group.\n2. Assign in Entra ID > Groups > {group} > Owners.\n3. Delete groups with no clear purpose.", "estimated_effort": "Low"}

def check_group_expiration(graph, target_config):
    """AZURE-GROUP-004"""
    try:
        policies = graph.get_all_pages("/groupLifecyclePolicies")
        covers_all = any(p.get("managedGroupTypes") == "All" for p in policies)
    except Exception as e:
        return {"check_id": "AZURE-GROUP-004", "severity": "Low", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check group expiration policy.",
                "remediation_steps": "Ensure Directory.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-GROUP-004", "severity": "Low",
            "status": "passed" if covers_all else "failed",
            "score": 0.5 if not covers_all else 0.0,
            "affected_resources": [] if covers_all else [{"issue": "No M365 group expiration policy for all groups"}],
            "evidence": {"expiration_policy_covers_all": covers_all},
            "risk_description": "Without group expiration, unused M365 groups accumulate with SharePoint sites and mailboxes.",
            "remediation_steps": "1. In Entra ID > Groups > Expiration.\n2. Set Group lifetime to 180 days.\n3. Enable for All groups.\n4. Save.", "estimated_effort": "Low"}

def check_duplicate_groups(graph, target_config):
    """AZURE-GROUP-006"""
    try:
        groups = graph.get_all_pages("/groups?$select=id,displayName,onPremisesSyncEnabled")
        cloud = [g for g in groups if not g.get("onPremisesSyncEnabled")]
        seen, duplicates = set(), []
        for g in cloud:
            name = g.get("displayName", "").lower()
            if name in seen:
                duplicates.append({"name": g.get("displayName"), "id": g["id"]})
            seen.add(name)
    except Exception as e:
        return {"check_id": "AZURE-GROUP-006", "severity": "Low", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check for duplicate group names.",
                "remediation_steps": "Ensure Group.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-GROUP-006", "severity": "Low",
            "status": "passed" if not duplicates else "failed",
            "score": 0.0,
            "affected_resources": duplicates[:10],
            "evidence": {"cloud_groups": len(cloud), "duplicates": len(duplicates)},
            "risk_description": "Duplicate group names cause confusion in access reviews and app assignments.",
            "remediation_steps": "1. Identify the purpose of each duplicate group.\n2. Merge or rename.\n3. Update access packages and CA policies referencing renamed groups.", "estimated_effort": "Low"}

# ── Directory ─────────────────────────────────────────────────────────────────

def check_msa_upn_conflict(graph, target_config):
    """AZURE-DIR-001"""
    return {"check_id": "AZURE-DIR-001", "severity": "Low",
            "status": "passed", "score": 0.0, "affected_resources": [],
            "evidence": {"note": "Manual verification recommended for MSA UPN conflicts"},
            "risk_description": "Personal Microsoft accounts matching corporate UPNs create authentication confusion and bypass corporate security controls.",
            "remediation_steps": "1. Identify users with both corporate Entra ID and personal Microsoft accounts at same email.\n2. Ask users to rename their personal account.\n3. Consider blocking personal Microsoft account authentication for your domain.",
            "estimated_effort": "Low"}

def check_sync_orphaned(graph, target_config):
    """AZURE-DIR-002"""
    try:
        users = graph.get_all_pages(
            "/users?$filter=onPremisesSyncEnabled eq true"
            "&$select=id,displayName,userPrincipalName,onPremisesLastSyncDateTime&$top=50")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=6)
        orphaned = []
        for u in users:
            last_sync = u.get("onPremisesLastSyncDateTime")
            if last_sync:
                try:
                    if datetime.fromisoformat(last_sync.replace("Z", "+00:00")) < cutoff:
                        orphaned.append({"id": u["id"], "name": u.get("displayName"), "upn": u.get("userPrincipalName"), "last_sync": last_sync})
                except Exception:
                    pass
    except Exception as e:
        return {"check_id": "AZURE-DIR-002", "severity": "Low", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check sync orphaned users.",
                "remediation_steps": "Ensure User.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-DIR-002", "severity": "Low",
            "status": "passed" if not orphaned else "failed",
            "score": 0.6 if orphaned else 0.0,
            "affected_resources": orphaned[:10],
            "evidence": {"synced_users_sampled": len(users), "out_of_sync": len(orphaned)},
            "risk_description": "Users no longer syncing may have stale attributes or retain cloud access after on-premises deletion.",
            "remediation_steps": "1. Check Entra ID Connect Health for sync errors.\n2. Resolve attribute conflicts or OU filter issues.\n3. For removed on-premises accounts, decide to keep or delete the cloud object.", "estimated_effort": "Moderate"}

def check_dir_reader_writer(graph, target_config):
    """AZURE-DIR-003"""
    DIR_READER = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
    DIR_WRITER = "9360feb5-f418-4baa-8175-e2a00bac4301"
    members = _priv_role_members(graph, [DIR_READER, DIR_WRITER])
    users_in_roles = [{"id": m["id"], "name": m.get("displayName"), "upn": m.get("userPrincipalName")}
                      for m in members if "#microsoft.graph.user" in m.get("@odata.type", "#microsoft.graph.user")]
    return {"check_id": "AZURE-DIR-003", "severity": "Low",
            "status": "passed" if not users_in_roles else "failed",
            "score": 0.7 if users_in_roles else 0.0,
            "affected_resources": users_in_roles,
            "evidence": {"users_in_dir_roles": len(users_in_roles)},
            "risk_description": "Directory Reader/Writer roles should only be assigned to applications, not individual users.",
            "remediation_steps": "1. For each user, identify why they need the permission.\n2. Move permission to service principal using Graph API permissions instead.\n3. Remove user from the role.", "estimated_effort": "Moderate"}

def check_usage_location(graph, target_config):
    """AZURE-DIR-004"""
    try:
        users = graph.get_all_pages(
            "/users?$filter=usageLocation eq null and accountEnabled eq true"
            "&$select=id,displayName,userPrincipalName&$top=50")
        no_loc = [{"id": u["id"], "name": u.get("displayName"), "upn": u.get("userPrincipalName")} for u in users]
    except Exception as e:
        return {"check_id": "AZURE-DIR-004", "severity": "Low", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check usage location.",
                "remediation_steps": "Ensure User.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-DIR-004", "severity": "Low",
            "status": "passed" if not no_loc else "failed",
            "score": 0.4 if no_loc else 0.0,
            "affected_resources": no_loc[:10],
            "evidence": {"users_without_location": len(no_loc)},
            "risk_description": "Users without usage location cannot be assigned licences, blocking SSPR registration.",
            "remediation_steps": "1. Set Usage Location for each user in Entra ID > Users > Profile.\n2. Update provisioning process to always set this field.", "estimated_effort": "Low"}

def check_orphaned_claim_policies(graph, target_config):
    """AZURE-DIR-005"""
    try:
        policies = graph.get_all_pages("/policies/claimsMappingPolicies")
        orphaned = []
        for policy in policies:
            try:
                assigned = graph.get_all_pages(f"/policies/claimsMappingPolicies/{policy['id']}/appliesTo")
                if not assigned:
                    orphaned.append({"id": policy["id"], "name": policy.get("displayName")})
            except Exception:
                pass
    except Exception as e:
        return {"check_id": "AZURE-DIR-005", "severity": "Low", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check orphaned claim mapping policies.",
                "remediation_steps": "Ensure Policy.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-DIR-005", "severity": "Low",
            "status": "passed" if not orphaned else "failed",
            "score": 0.1 if orphaned else 0.0,
            "affected_resources": orphaned,
            "evidence": {"total_policies": len(policies), "orphaned": len(orphaned)},
            "risk_description": "Orphaned claim mapping policies add complexity and may be accidentally applied to new applications.",
            "remediation_steps": "1. Confirm each orphaned policy is no longer needed.\n2. Delete via: DELETE /policies/claimsMappingPolicies/{id}", "estimated_effort": "Low"}

def check_dynamic_group_paused(graph, target_config):
    """AZURE-DIR-006"""
    try:
        groups = graph.get_all_pages(
            "/groups?$filter=groupTypes/any(c:c eq 'DynamicMembership')&$select=id,displayName,membershipRuleProcessingState")
        paused = [{"id": g["id"], "name": g.get("displayName")}
                  for g in groups if g.get("membershipRuleProcessingState") == "Paused"]
    except Exception as e:
        return {"check_id": "AZURE-DIR-006", "severity": "Low", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check dynamic group state.",
                "remediation_steps": "Ensure Group.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-DIR-006", "severity": "Low",
            "status": "passed" if not paused else "failed",
            "score": 0.0,
            "affected_resources": paused,
            "evidence": {"dynamic_groups": len(groups), "paused": len(paused)},
            "risk_description": "Paused dynamic groups do not reflect current membership, causing CA policies to apply to wrong users.",
            "remediation_steps": "1. Investigate why each group was paused.\n2. Re-enable if pause was temporary.\n3. Verify membership after re-enabling.", "estimated_effort": "Low"}

# ── Compliance ────────────────────────────────────────────────────────────────

def check_entra_recommendations(graph, target_config):
    """AZURE-COMP-001"""
    try:
        recs = graph.get_all_pages(
            "/directory/recommendations?$filter=status eq 'active'&$select=id,displayName,priority,status")
        high_priority = [{"id": r.get("id"), "name": r.get("displayName")}
                         for r in recs if r.get("priority") in ("high", "medium")]
    except Exception as e:
        return {"check_id": "AZURE-COMP-001", "severity": "Medium", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check Entra ID recommendations.",
                "remediation_steps": "Ensure DirectoryRecommendations.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-COMP-001", "severity": "Medium",
            "status": "passed" if not high_priority else "failed",
            "score": min(3.0, 0.4 * len(high_priority)) if high_priority else 0.0,
            "affected_resources": high_priority[:10],
            "evidence": {"active_recs": len(recs), "high_medium": len(high_priority)},
            "risk_description": "Entra ID built-in recommendations identify configuration issues specific to your tenant.",
            "remediation_steps": "1. In Entra ID > Overview > Recommendations.\n2. Review all active items.\n3. Implement, Risk accept, or mark as Third party.\n4. Resolve all High and Medium priority items.", "estimated_effort": "Moderate"}

def check_ca_exclusion_reviews(graph, target_config):
    """AZURE-COMP-002"""
    try:
        reviews = graph.get_all_pages("/identityGovernance/accessReviews/definitions")
        excl_reviews = [r for r in reviews if "exclusion" in str(r.get("displayName", "")).lower()
                        or "ca" in str(r.get("displayName", "")).lower()]
        has_reviews = len(excl_reviews) > 0
    except Exception as e:
        return {"check_id": "AZURE-COMP-002", "severity": "Medium", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check CA exclusion access reviews.",
                "remediation_steps": "Ensure AccessReview.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-COMP-002", "severity": "Medium",
            "status": "passed" if has_reviews else "failed",
            "score": 0.4 if not has_reviews else 0.0,
            "affected_resources": [] if has_reviews else [{"issue": "No access reviews for CA exclusion groups"}],
            "evidence": {"ca_exclusion_reviews": len(excl_reviews)},
            "risk_description": "CA exclusions grow unchecked without access reviews, eroding security policy intent.",
            "remediation_steps": "1. Identify groups used as CA policy exclusions.\n2. Create quarterly access reviews for each.\n3. Upon completion: remove uncertified members.", "estimated_effort": "Moderate"}

# ── Monitoring ────────────────────────────────────────────────────────────────

def check_audit_log_retention(graph, target_config):
    """AZURE-MONITORING-001"""
    try:
        result = graph.get("/auditLogs/signIns?$top=1&$select=id")
        has_logs = len(result.get("value", [])) > 0
    except Exception as e:
        return {"check_id": "AZURE-MONITORING-001", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not verify audit log access.",
                "remediation_steps": "Ensure AuditLog.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-MONITORING-001", "severity": "High",
            "status": "passed" if has_logs else "failed",
            "score": 5.0 if not has_logs else 0.0,
            "affected_resources": [] if has_logs else [{"issue": "Sign-in logs not accessible"}],
            "evidence": {"logs_accessible": has_logs},
            "risk_description": "Default log retention is 30 days. Security investigations often begin weeks after an incident.",
            "remediation_steps": "1. Create an Azure Log Analytics workspace.\n2. In Entra ID > Monitoring > Diagnostic settings, route logs to Log Analytics.\n3. Set retention to 90 days minimum.", "estimated_effort": "Moderate"}

def check_security_alerts_configured(graph, target_config):
    """AZURE-MONITORING-002"""
    try:
        graph.get("/security/alerts_v2?$top=1&$select=id")
        configured = True
    except Exception:
        configured = False
    return {"check_id": "AZURE-MONITORING-002", "severity": "High",
            "status": "passed" if configured else "failed",
            "score": 5.2 if not configured else 0.0,
            "affected_resources": [] if configured else [{"issue": "Security alerts API not accessible"}],
            "evidence": {"alerts_api_accessible": configured},
            "risk_description": "Without security alerts, critical events like admin sign-ins from unusual locations go undetected.",
            "remediation_steps": "1. Configure Log Analytics to receive Entra ID logs.\n2. Create alert rules for critical events.\n3. Route to SOC Teams/email/PagerDuty.\n4. Test each alert.", "estimated_effort": "Moderate"}

def check_defender_for_identity(graph, target_config):
    """AZURE-MONITORING-003"""
    try:
        org = graph.get("/organization?$select=verifiedDomains")
        has_onprem = any(not d.get("isDefault") and d.get("isVerified")
                         for o in org.get("value", []) for d in o.get("verifiedDomains", []))
    except Exception:
        has_onprem = False
    if not has_onprem:
        return {"check_id": "AZURE-MONITORING-003", "severity": "High", "status": "passed",
                "score": 0.0, "affected_resources": [], "evidence": {"onprem_detected": False},
                "risk_description": "No on-premises environment detected.",
                "remediation_steps": "No action required for cloud-only tenants.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-MONITORING-003", "severity": "High", "status": "failed",
            "score": 6.5,
            "affected_resources": [{"issue": "On-premises AD detected — verify Defender for Identity is deployed on all DCs"}],
            "evidence": {"onprem_detected": True},
            "risk_description": "Without Defender for Identity, on-premises attacks like Pass-the-Hash and Golden Ticket are invisible.",
            "remediation_steps": "1. Download MDI sensor from security.microsoft.com.\n2. Install on every domain controller.\n3. Configure event collection.\n4. Wait 24h for baseline.", "estimated_effort": "Moderate"}

def check_break_glass_alerting(graph, target_config):
    """AZURE-MONITORING-004"""
    bg_group = target_config.get("break_glass_group_id")
    if not bg_group:
        return {"check_id": "AZURE-MONITORING-004", "severity": "Critical", "status": "failed",
                "score": 9.0,
                "affected_resources": [{"issue": "Break glass group ID not configured in target settings"}],
                "evidence": {"break_glass_configured": False},
                "risk_description": "Break glass sign-in alerting requires the break glass group to be configured.",
                "remediation_steps": "1. Configure break glass group ID in target settings.\n2. Set up Log Analytics alert for break glass sign-ins.\n3. Route to P1 escalation channel.\n4. Test annually.", "estimated_effort": "Low"}
    try:
        members = graph.get_group_members(bg_group)
        bg_count = len(members)
        ok = bg_count >= 2
    except Exception:
        ok = False
        bg_count = 0
    return {"check_id": "AZURE-MONITORING-004", "severity": "Critical",
            "status": "passed" if ok else "failed",
            "score": 9.0 if not ok else 0.0,
            "affected_resources": [] if ok else [{"issue": f"Break glass group has {bg_count} account(s) — need at least 2"}],
            "evidence": {"break_glass_accounts": bg_count},
            "risk_description": "Any break glass sign-in is either an emergency or a compromise — neither should go undetected.",
            "remediation_steps": "1. Ensure at least 2 break glass accounts.\n2. Create Log Analytics alert on their sign-ins.\n3. Route to P1 phone escalation.", "estimated_effort": "Low"}

# ── Sync ──────────────────────────────────────────────────────────────────────

def check_sync_credential_rotation(graph, target_config):
    """AZURE-SYNC-003"""
    try:
        users = graph.get_all_pages("/users?$select=id,displayName,userPrincipalName,lastPasswordChangeDateTime")
        sync_accounts = [u for u in users if u.get("userPrincipalName", "").startswith("Sync_")]
        if not sync_accounts:
            return {"check_id": "AZURE-SYNC-003", "severity": "High", "status": "passed",
                    "score": 0.0, "affected_resources": [], "evidence": {"sync_accounts": 0},
                    "risk_description": "No sync accounts found.",
                    "remediation_steps": "No action required.", "estimated_effort": "Moderate"}
        cutoff = datetime.now(timezone.utc) - timedelta(days=365)
        stale = []
        for u in sync_accounts:
            lc = u.get("lastPasswordChangeDateTime")
            if lc:
                try:
                    if datetime.fromisoformat(lc.replace("Z", "+00:00")) < cutoff:
                        stale.append({"name": u.get("userPrincipalName"), "last_changed": lc})
                except Exception:
                    pass
            else:
                stale.append({"name": u.get("userPrincipalName"), "last_changed": "Unknown"})
    except Exception as e:
        return {"check_id": "AZURE-SYNC-003", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check sync credential age.",
                "remediation_steps": "Ensure User.Read.All permission is granted.", "estimated_effort": "Moderate"}
    return {"check_id": "AZURE-SYNC-003", "severity": "High",
            "status": "passed" if not stale else "failed",
            "score": 2.2 if stale else 0.0,
            "affected_resources": stale,
            "evidence": {"sync_accounts": len(sync_accounts), "stale_creds": len(stale)},
            "risk_description": "Sync credentials older than 12 months have had an extended exposure window.",
            "remediation_steps": "1. Open Entra ID Connect on sync server.\n2. Generate new strong password (20+ chars).\n3. Update in both Entra ID Connect and Entra ID account.\n4. Restart sync service and verify.", "estimated_effort": "Moderate"}

def check_bg_password_rotation(graph, target_config):
    """AZURE-BG-001"""
    bg_group = target_config.get("break_glass_group_id")
    if not bg_group:
        return {"check_id": "AZURE-BG-001", "severity": "High", "status": "failed",
                "score": 3.4,
                "affected_resources": [{"issue": "Break glass group not configured in target settings"}],
                "evidence": {"configured": False},
                "risk_description": "Break glass password rotation cannot be verified without group configuration.",
                "remediation_steps": "1. Configure break glass group ID in target settings.\n2. Rotate passwords annually.\n3. Store in physical safe.", "estimated_effort": "Low"}
    try:
        members = graph.get_group_members(bg_group)
        cutoff = datetime.now(timezone.utc) - timedelta(days=365)
        stale = []
        for m in members:
            try:
                user = graph.get(f"/users/{m['id']}?$select=id,displayName,lastPasswordChangeDateTime")
                lc = user.get("lastPasswordChangeDateTime")
                if lc:
                    change_dt = datetime.fromisoformat(lc.replace("Z", "+00:00"))
                    if change_dt < cutoff:
                        stale.append({"id": m["id"], "name": m.get("displayName"), "last_changed": lc,
                                      "age_days": (datetime.now(timezone.utc) - change_dt).days})
                else:
                    stale.append({"id": m["id"], "name": m.get("displayName"), "last_changed": "Never recorded"})
            except Exception:
                pass
    except Exception as e:
        return {"check_id": "AZURE-BG-001", "severity": "High", "status": "error",
                "score": 0.0, "affected_resources": [], "evidence": {"error": str(e)},
                "risk_description": "Could not check break glass password age.",
                "remediation_steps": "Ensure User.Read.All permission is granted.", "estimated_effort": "Low"}
    return {"check_id": "AZURE-BG-001", "severity": "High",
            "status": "passed" if not stale else "failed",
            "score": 3.4 if stale else 0.0,
            "affected_resources": stale,
            "evidence": {"bg_accounts": len(members), "stale": len(stale)},
            "risk_description": "Break glass passwords older than 1 year may have been exposed. A compromised account could take over the entire tenant.",
            "remediation_steps": "1. Generate a new 20+ character random password.\n2. Update in Entra ID.\n3. Print and store in physical safe.\n4. Document rotation date.", "estimated_effort": "Low"}


# ─── EXTRA_CHECKS list ────────────────────────────────────────────────────────
EXTRA_CHECKS = [
    check_ca_mfa_privileged, check_ca_compliant_device, check_ca_block_risky_privileged,
    check_ca_block_high_signin_risk, check_ca_no_persistent_session, check_ca_block_admin_portals_risk,
    check_ca_block_security_registration, check_ca_mfa_guests, check_ca_guest_session_timeout,
    check_ca_priv_compliant_device, check_ca_block_msol, check_ca_workload_risk, check_ca_cae,
    check_mfa_registration_campaign, check_sspr_all_users, check_admin_sspr_registered, check_banned_password_onprem,
    check_pim_two_approvers, check_pim_activation_duration, check_pim_cloud_only_privileged, check_pim_alerts,
    check_identity_secure_score_001, check_stale_cloud_users_002, check_admin_no_mailbox, check_admin_no_skype,
    check_stale_sync_id006, check_old_synced_passwords, check_pwdlastset_sync, check_account_takeover_protection,
    check_admin_email_id010, check_sspr_admin_id012, check_admin_sspr_id014, check_m365_group_creation,
    check_smart_lockout, check_secure_score_id020,
    check_app_mailbox_perms, check_app_sharepoint_perms, check_app_sp_assigned_perms,
    check_recent_admin_consents, check_app_signin_audience, check_app_credential_rotation,
    check_default_app_creds, check_app_risky_oauth,
    check_guest_email_otp, check_guest_block_admin_ca,
    check_group_no_owners_001, check_group_expiration, check_duplicate_groups,
    check_msa_upn_conflict, check_sync_orphaned, check_dir_reader_writer, check_usage_location,
    check_orphaned_claim_policies, check_dynamic_group_paused,
    check_entra_recommendations, check_ca_exclusion_reviews,
    check_audit_log_retention, check_security_alerts_configured,
    check_defender_for_identity, check_break_glass_alerting,
    check_sync_credential_rotation, check_bg_password_rotation,
]


# ─── ALL CHECKS ───────────────────────────────────────────────────────────────
ALL_CHECKS = [
    # Conditional Access (9)
    check_break_glass_ca,
    check_legacy_auth_blocked,
    check_risky_signins_blocked,
    check_mfa_all_users,
    check_ca_report_only,
    check_ca_sync_restriction,
    check_guest_admin_portal_blocked,
    check_ca_exclusion_groups,
    check_user_risk_policy,
    # MFA & Auth (4)
    check_privileged_mfa,
    check_sspr_enabled,
    check_user_app_registration,
    check_combined_registration,
    # PIM (4)
    check_pim_permanent_members,
    check_pim_mfa_activation,
    check_pim_access_reviews,
    check_pim_justification,
    # Identity (6)
    check_privileged_cloud_only,
    check_stale_privileged_users,
    check_stale_guests,
    check_stale_cloud_users,
    check_personal_emails,
    check_risky_users,
    # Applications (7)
    check_app_credentials_expiry,
    check_user_consent_enabled,
    check_app_http_uris,
    check_apps_without_owners,
    check_app_assignment_required,
    check_sp_password_credentials,
    check_aad_graph_usage,
    # Guests (3)
    check_guest_permissions,
    check_guest_access_reviews,
    check_stale_guest_accounts,
    # Groups (3)
    check_groups_without_owners,
    check_empty_groups,
    check_sg_creation_restricted,
    # Monitoring (3)
    check_secure_score,
    check_sync_unused_accounts,
    check_admin_consent_workflow,
]
# Total: 39 base checks
ALL_CHECKS.extend(EXTRA_CHECKS)  # adds 62 more = 101 total


# ─── Email alert ──────────────────────────────────────────────────────────────
def send_critical_alert(critical_findings, target_name):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASSWORD")
    smtp_to   = os.getenv("ALERT_EMAIL", smtp_user)
    if not all([smtp_host, smtp_user, smtp_pass, smtp_to]):
        logger.warning("Email not configured — skipping alert")
        return
    rows = "".join(
        f"<tr><td>{f['check_id']}</td><td>{f.get('risk_description','')[:100]}</td>"
        f"<td>{len(f.get('affected_resources',[]))}</td>"
        f"<td>{f.get('remediation_steps','')[:150]}</td></tr>"
        for f in critical_findings
    )
    html = f"""<h2>&#9888;&#65039; {len(critical_findings)} Critical Findings &#8212; {target_name}</h2>
    <p>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
    <table border="1" cellpadding="6" style="border-collapse:collapse">
      <tr><th>Check</th><th>Risk</th><th>Affected</th><th>Fix</th></tr>{rows}
    </table>"""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"SecurePosture: {len(critical_findings)} Critical — {target_name}"
    msg["From"] = smtp_user
    msg["To"]   = smtp_to
    msg.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.sendmail(smtp_user, smtp_to, msg.as_string())
        logger.info(f"Alert sent to {smtp_to}")
    except Exception as e:
        logger.error(f"Email failed: {e}")


# ─── Main scan task ───────────────────────────────────────────────────────────
@celery_app.task(name="app.tasks.run_scan", bind=True)
def run_scan(self, scan_run_id, target_id, check_ids=None):
    logger.info(f"Starting scan {scan_run_id} for target {target_id}")
    update_run(None, scan_run_id, status="running",
               started_at=datetime.now(timezone.utc),
               checks_total=len(ALL_CHECKS))
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT name, config FROM targets WHERE id=:id"),
                {"id": target_id}
            ).fetchone()
        target_name   = row[0] if row else target_id
        target_config = dict(row[1]) if row and row[1] else {}

        creds = get_credentials()
        graph = MSGraphClient(creds["tenant_id"], creds["client_id"], creds["client_secret"])

        passed = failed = skipped = 0
        critical_findings = []
        checks_to_run = ALL_CHECKS if not check_ids else [
            c for c in ALL_CHECKS
            if any(cid in (c.__doc__ or c.__name__) for cid in check_ids)
        ]

        for check_fn in checks_to_run:
            try:
                result = check_fn(graph, target_config)
                save_finding(scan_run_id, target_id, result)
                if result["status"] == "passed":
                    passed += 1
                elif result["status"] == "failed":
                    failed += 1
                    if result.get("severity") == "Critical":
                        critical_findings.append(result)
                else:
                    skipped += 1
                logger.info(
                    f"  {result['check_id']}: {result['status']} "
                    f"score={result['score']} affected={len(result.get('affected_resources', []))}"
                )
            except Exception as e:
                logger.error(f"  {check_fn.__name__} error: {e}", exc_info=True)
                skipped += 1

        update_run(None, scan_run_id,
                   status="completed",
                   completed_at=datetime.now(timezone.utc),
                   checks_passed=passed,
                   checks_failed=failed,
                   checks_skipped=skipped)

        if critical_findings:
            send_critical_alert(critical_findings, target_name)

        logger.info(f"Scan done — passed={passed} failed={failed} skipped={skipped}")

    except Exception as e:
        logger.error(f"Scan crashed: {e}", exc_info=True)
        update_run(None, scan_run_id,
                   status="failed",
                   error_message=str(e)[:500],
                   completed_at=datetime.now(timezone.utc))
        raise


# ─── Scheduled task ───────────────────────────────────────────────────────────
@celery_app.task(name="app.tasks.run_scheduled_scan")
def run_scheduled_scan():
    with engine.connect() as conn:
        targets = conn.execute(
            text("SELECT id FROM targets WHERE is_active=true")
        ).fetchall()
    for row in targets:
        target_id = str(row[0])
        with engine.connect() as conn:
            result = conn.execute(text("""
                INSERT INTO scan_runs (id, target_id, triggered_by, status, created_at)
                VALUES (gen_random_uuid(), :tid, 'schedule', 'pending', now())
                RETURNING id
            """), {"tid": target_id})
            conn.commit()
            run_id = str(result.fetchone()[0])
        run_scan.delay(run_id, target_id)
        logger.info(f"Scheduled scan: run={run_id} target={target_id}")
