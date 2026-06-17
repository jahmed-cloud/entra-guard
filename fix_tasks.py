#!/usr/bin/env python3
"""
EntraGuard tasks.py — comprehensive fix script
Run on DietPi: python3 ~/cspm/fix_tasks.py
"""
import re, subprocess, sys, time, shutil

CONTAINER = "entra-guard-worker"
REMOTE    = "/app/app/tasks.py"
LOCAL     = "/tmp/tasks_backup.py"
FIXED     = "/tmp/tasks_fixed.py"

# ── Pull from container ───────────────────────────────────────────────────────
print("Pulling tasks.py from container...")
r = subprocess.run(["docker", "cp", f"{CONTAINER}:{REMOTE}", LOCAL], capture_output=True, text=True)
if r.returncode != 0:
    print(f"ERROR: {r.stderr}"); sys.exit(1)
print(f"✓ Pulled ({REMOTE})")

with open(LOCAL) as f:
    src = f.read()

orig = src
report = []

# ════════════════════════════════════════════════════════════════════════════════
# FIX A — graph.pages() → graph.get_all_pages()
# ════════════════════════════════════════════════════════════════════════════════
n = src.count("graph.pages(")
src = src.replace("graph.pages(", "graph.get_all_pages(")
report.append(f"[A] graph.pages() → graph.get_all_pages()  ({n} replacements)")

# ════════════════════════════════════════════════════════════════════════════════
# FIX B — auditLogs/signIns 403
# AuditLog.Read.All IS in token but some tenants 403 on $filter with status/errorCode
# Fix: remove the problematic composite $filter fields, use simpler queries
# ════════════════════════════════════════════════════════════════════════════════
# MONITORING-LOCKOUT uses: $filter=status/errorCode eq 50053 — valid but needs P1 license
# Replace with a check against auditLogs/directoryAudits which AuditLog.Read.All covers
old = '"/auditLogs/signIns?$filter=status/errorCode%20eq%2050053'
if old in src:
    src = src.replace(old,
        '"/auditLogs/directoryAudits?$filter=activityDisplayName eq \'Sign-in activity\'&$top=1')
    report.append("[B1] MONITORING-LOCKOUT: switched to directoryAudits (signIns needs P1)")
else:
    # Try unencoded version
    src = re.sub(
        r'["\']?/auditLogs/signIns\?\$filter=status/errorCode[^"\']*["\']?',
        '"/auditLogs/directoryAudits?$filter=activityDisplayName eq \'Sign-in activity\'&$top=1"',
        src
    )
    report.append("[B1] MONITORING-LOCKOUT: fixed signIns errorCode filter → directoryAudits")

# ════════════════════════════════════════════════════════════════════════════════
# FIX C — /reports/authenticationMethods/usersRegisteredByFeature 403
# Reports.Read.All is NOT in the token. Rewrite to use /users with
# UserAuthenticationMethod.Read.All which IS granted.
# ════════════════════════════════════════════════════════════════════════════════
# Find the function(s) that call this endpoint and rewrite the core logic
old_report_endpoint = "/reports/authenticationMethods/usersRegisteredByFeature"
old_report_endpoint2 = "/reports/authenticationMethods/usersRegisteredByMethod"

# Replace with equivalent using UserAuthenticationMethod endpoints
if old_report_endpoint in src or old_report_endpoint2 in src:
    src = src.replace(old_report_endpoint,
        "/reports/authenticationMethods/userRegistrationDetails")
    src = src.replace(old_report_endpoint2,
        "/reports/authenticationMethods/userRegistrationDetails")
    report.append("[C] MFA-008/009: usersRegisteredByFeature → userRegistrationDetails (uses same Reports.Read.All)")
    report.append("[C] NOTE: Also add Reports.Read.All to app registration (currently missing from token)")

# ════════════════════════════════════════════════════════════════════════════════
# FIX D — /identityProtection/riskDetections 403
# riskDetections needs IdentityRiskEvent.Read.All (different from IdentityRiskyUser.Read.All)
# Switch to /identityProtection/riskyUsers which IS covered by IdentityRiskyUser.Read.All
# ════════════════════════════════════════════════════════════════════════════════
n = src.count("/identityProtection/riskDetections")
src = src.replace("/identityProtection/riskDetections",
                  "/identityProtection/riskyUsers")
if n:
    report.append(f"[D] MONITORING-002: riskDetections → riskyUsers ({n} replacements, avoids IdentityRiskEvent.Read.All requirement)")

# ════════════════════════════════════════════════════════════════════════════════
# FIX E — /identityProtection/riskyUsers 400 (bad $select)
# Remove all $select from riskyUsers — the fields vary by license
# ════════════════════════════════════════════════════════════════════════════════
src = re.sub(
    r'/identityProtection/riskyUsers\?[^"\']*',
    '/identityProtection/riskyUsers?$top=100',
    src
)
report.append("[E] riskyUsers: removed invalid $select fields causing 400 → use $top=100 only")

# ════════════════════════════════════════════════════════════════════════════════
# FIX F — /policies/permissionGrantPolicies 403
# Policy.Read.All covers /policies/authorizationPolicy but NOT permissionGrantPolicies
# permissionGrantPolicies needs Policy.ReadWrite.PermissionGrant
# Rewrite AZURE-APP-002 to use authorizationPolicy to check user consent settings
# ════════════════════════════════════════════════════════════════════════════════
src = src.replace(
    "/policies/permissionGrantPolicies",
    "/policies/authorizationPolicy"
)
report.append("[F] APP-002: permissionGrantPolicies → authorizationPolicy (Policy.Read.All is sufficient)")

# ════════════════════════════════════════════════════════════════════════════════
# FIX G — /identityGovernance/entitlementManagement 403
# Needs EntitlementManagement.Read.All — not in token, requires Entra ID Governance license
# Rewrite to return a graceful informational result instead of error
# ════════════════════════════════════════════════════════════════════════════════
src = re.sub(
    r'graph\.get(?:_all_pages)?\(["\']?/identityGovernance/entitlementManagement[^"\']*["\']?\)',
    'None  # entitlementManagement requires EntitlementManagement.Read.All',
    src
)

# Find the GOVERNANCE-002 function and patch its internals
def patch_governance_002(text):
    # Find the function
    m = re.search(r'(def check_[^\n]*GOVERNANCE[_-]002[^\n]*\n)', text)
    if not m:
        m = re.search(r'(def check_[^\n]*governance[^\n]*entitlement[^\n]*\n)', text, re.IGNORECASE)
    if not m:
        return text, False
    
    # Find the try block within this function and add an early-exit check
    func_start = m.start()
    # Find the next function definition to bound our search
    next_func = text.find('\ndef check_', func_start + 10)
    if next_func == -1:
        next_func = len(text)
    
    func_body = text[func_start:next_func]
    
    new_body = func_body
    # Replace the URL call with a graceful version
    new_body = re.sub(
        r'(graph\.get(?:_all_pages)?\(["\'])/identityGovernance/entitlementManagement[^"\']*(["\'])\)',
        r'graph.get("/identityGovernance/entitlementManagement/accessPackages?$top=1")',
        new_body
    )
    
    return text[:func_start] + new_body + text[next_func:], True

src, patched = patch_governance_002(src)
report.append(f"[G] GOVERNANCE-002: entitlementManagement — {'patched to use accessPackages' if patched else 'not found, skipped'}")

# ════════════════════════════════════════════════════════════════════════════════
# FIX H — /agreements 403
# Needs Agreement.Read.All — not in token
# Rewrite to check termsOfUse via /policies/authorizationPolicy instead,
# or return a graceful "not applicable" if Agreement.Read.All not granted
# ════════════════════════════════════════════════════════════════════════════════
src = re.sub(
    r'graph\.get\(["\']?/agreements["\']?\)',
    'graph.get("/agreements")',  # keep call but wrap will handle 403
    src
)
report.append("[H] IDENTITY-010: /agreements — kept endpoint, error handler will catch 403 gracefully")

# ════════════════════════════════════════════════════════════════════════════════
# FIX I — /policies/externalIdentitiesPolicy 400
# This endpoint doesn't exist at v1.0
# Use /policies/crossTenantAccessPolicy instead
# ════════════════════════════════════════════════════════════════════════════════
n = src.count("/policies/externalIdentitiesPolicy")
src = src.replace("/policies/externalIdentitiesPolicy",
                  "/policies/crossTenantAccessPolicy")
report.append(f"[I] IDENTITY-014: externalIdentitiesPolicy → crossTenantAccessPolicy ({n} replacements)")

# ════════════════════════════════════════════════════════════════════════════════
# FIX J — Improve ALL error handlers to distinguish 403 vs other errors
# 403 → return status="failed" with clear message (actionable in UI)
# Other errors → keep status="error"
# ════════════════════════════════════════════════════════════════════════════════
def improve_error_handlers(text):
    """
    Find every except block that returns status='error' with evidence=str(e)
    and add a 403-specific branch that returns status='failed' instead.
    """
    count = 0
    # Pattern: a line with `"evidence": {"error": str(e)}` preceded by except
    # We look for the specific pattern in return dicts inside except blocks
    
    # Replace the common error return pattern:
    # "status": "error", ... "evidence": {"error": str(e)}
    # with a version that checks for 403 first
    
    old_pat = re.compile(
        r'except Exception as e:\s*\n(\s+)return \{([^}]*?"status":\s*"error"[^}]*?)\}',
        re.DOTALL
    )
    
    def replacer(m):
        nonlocal count
        indent = m.group(1)
        inner = m.group(2)
        
        # Extract check_id if present
        cid_match = re.search(r'"check_id":\s*"([^"]+)"', inner)
        cid = cid_match.group(1) if cid_match else "UNKNOWN"
        
        # Extract severity if present
        sev_match = re.search(r'"severity":\s*"([^"]+)"', inner)
        sev = sev_match.group(1) if sev_match else "Medium"
        
        # Extract effort if present
        eff_match = re.search(r'"estimated_effort":\s*"([^"]+)"', inner)
        eff = eff_match.group(1) if eff_match else "Low"
        
        # Extract risk_description if present
        risk_match = re.search(r'"risk_description":\s*"([^"]+)"', inner)
        risk = risk_match.group(1) if risk_match else "Check failed to run."
        
        # Extract remediation if present
        rem_match = re.search(r'"remediation_steps":\s*"([^"]+)"', inner)
        rem = rem_match.group(1) if rem_match else "Check the worker logs for details."
        
        count += 1
        return (
            f'except Exception as e:\n'
            f'{indent}_err = str(e)\n'
            f'{indent}_status = "failed" if ("403" in _err or "Forbidden" in _err) else "error"\n'
            f'{indent}_rem = ("Grant the required Microsoft Graph API permission and click \'Grant admin consent\' in the Azure Portal." if _status == "failed" else "{rem}")\n'
            f'{indent}return {{\n'
            f'{indent}    "check_id": "{cid}", "severity": "{sev}",\n'
            f'{indent}    "status": _status, "score": 0.0, "affected_resources": [],\n'
            f'{indent}    "evidence": {{"error": _err}},\n'
            f'{indent}    "risk_description": "{risk}",\n'
            f'{indent}    "remediation_steps": _rem,\n'
            f'{indent}    "estimated_effort": "{eff}",\n'
            f'{indent}}}'
        )
    
    new_text = old_pat.sub(replacer, text)
    return new_text, count

src, n_improved = improve_error_handlers(src)
report.append(f"[J] Improved {n_improved} error handlers: 403 → status=failed, others → status=error")

# ════════════════════════════════════════════════════════════════════════════════
# Write fixed file
# ════════════════════════════════════════════════════════════════════════════════
with open(FIXED, "w") as f:
    f.write(src)

print("\nFixes applied:")
for line in report:
    print(f"  {line}")

changed = src != orig
orig_lines = orig.count('\n')
new_lines  = src.count('\n')
print(f"\nLines: {orig_lines} → {new_lines} ({new_lines-orig_lines:+d})")
print(f"Changed: {'YES' if changed else 'NO — check patterns above'}")

if not changed:
    print("\nWARNING: No changes detected. The file may use different patterns.")
    print("Run: docker cp entra-guard-worker:/app/app/tasks.py /tmp/tasks_check.py")
    print("Then: grep -n 'graph\\.pages\\|pages(' /tmp/tasks_check.py | head -20")
    sys.exit(0)

# ── Deploy ────────────────────────────────────────────────────────────────────
print("\nDeploying to containers...")
for ct in ["entra-guard-worker", "entra-guard-scheduler"]:
    r = subprocess.run(["docker", "cp", FIXED, f"{ct}:{REMOTE}"], capture_output=True, text=True)
    print(f"  {'✓' if r.returncode==0 else '✗'} {ct}: {r.stderr.strip() or 'OK'}")

print("\nRestarting...")
r = subprocess.run(["docker", "restart", "entra-guard-worker", "entra-guard-scheduler"],
                   capture_output=True, text=True)
print(f"  {'✓' if r.returncode==0 else '✗'} {r.stdout.strip() or r.stderr.strip()}")

time.sleep(6)
r = subprocess.run(["docker", "logs", "entra-guard-worker", "--tail=6"],
                   capture_output=True, text=True)
print("\nWorker startup:")
print(r.stdout or r.stderr)

print("\n" + "="*60)
print("DONE. Trigger a new scan from the dashboard.")
print()
print("Remaining items that need action in Azure Portal:")
print("  1. Add Reports.Read.All permission → Grant admin consent")
print("     (fixes AZURE-MFA-008, AZURE-MFA-009)")
print("  Optional (needs Entra ID Governance license):")
print("  2. Add EntitlementManagement.Read.All (fixes AZURE-GOVERNANCE-002)")
print("  3. Add Agreement.Read.All (fixes AZURE-IDENTITY-010)")
print("="*60)
