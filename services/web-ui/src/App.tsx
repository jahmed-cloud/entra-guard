// @ts-nocheck
import React, { useState, useEffect, useCallback, useRef } from "react";

// ─── API ──────────────────────────────────────────────────────────────────────
const API = "/api/v1";
// Both apiFetch and apiPost now attach the stored Bearer token via
// getStoredToken() (declared below — safe to reference here since function
// declarations are hoisted). Previously these sent no Authorization header
// at all, so every call through them (findings, targets, runs, scan trigger)
// was silently unauthenticated — harmless while those endpoints had no auth
// check, but a real bug once AUTH_ENABLED=true genuinely enforces it.
const apiFetch = async (p) => {
  const token = getStoredToken();
  const headers = token ? { "Authorization": `Bearer ${token}` } : {};
  const r = await fetch(API+p, { headers });
  if (r.status === 401) { clearStoredToken(); window.location.href = "/"; }
  if(!r.ok) throw new Error(r.status);
  return r.json();
};
const apiPost = async (p, b={}) => {
  const token = getStoredToken();
  const headers = { "Content-Type":"application/json", ...(token ? { "Authorization": `Bearer ${token}` } : {}) };
  const r = await fetch(API+p, {method:"POST", headers, body:JSON.stringify(b)});
  if (r.status === 401) { clearStoredToken(); window.location.href = "/"; }
  if(!r.ok) throw new Error(r.status);
  return r.json();
};

// ─── Material Design 3 tokens ─────────────────────────────────────────────────
// Dark theme, tonal surface system. Elevation communicates hierarchy of
// attention (critical findings sit visually "closer" to the viewer);
// severity colors are MD3-desaturated so they read as part of the surface
// system rather than fighting it.
const MD = {
  // Surface roles — each step lighter = higher elevation
  surfaceDim:    "#0E1116",
  surface:       "#121417",
  surfaceLow:    "#191C20",
  surfaceCont:   "#1D2024",
  surfaceHigh:   "#282A2F",
  surfaceHighest:"#33353A",
  outline:       "#8B9198",
  outlineVar:    "#42474E",
  // Primary — confident blue-violet, MD3's "vivid but not neon" register
  primary:       "#AEC6FF",
  primaryDim:    "#5B8DFF",
  primaryContainer: "#1E3A78",
  onPrimaryContainer: "#DCE2FF",
  // Text
  onSurface:     "#E3E2E6",
  onSurfaceVar:  "#C4C6D0",
  // Shape
  radiusSm: 8,
  radiusMd: 12,
  radiusLg: 16,
  radiusXl: 28,
};

// MD3 elevation via layered shadow (dp1–dp5). Applied as a style fragment.
const elevation = (dp) => {
  const shadows = {
    0: "none",
    1: "0 1px 2px rgba(0,0,0,0.30), 0 1px 3px 1px rgba(0,0,0,0.15)",
    2: "0 1px 2px rgba(0,0,0,0.30), 0 2px 6px 2px rgba(0,0,0,0.15)",
    3: "0 1px 3px rgba(0,0,0,0.30), 0 4px 8px 3px rgba(0,0,0,0.15)",
    4: "0 2px 3px rgba(0,0,0,0.30), 0 6px 10px 4px rgba(0,0,0,0.15)",
    5: "0 4px 4px rgba(0,0,0,0.30), 0 8px 12px 6px rgba(0,0,0,0.15)",
  };
  return shadows[dp] ?? shadows[1];
};

// State-layer overlay — MD3's signature interaction affordance. A hover or
// press isn't a color swap, it's a translucent wash over the resting surface.
const stateLayer = (baseColor, opacity) => {
  // baseColor expected as hex; opacity 0.08 hover / 0.12 press per MD3 spec
  return `${baseColor}${Math.round(opacity * 255).toString(16).padStart(2, "0")}`;
};

// ─── Type scale (MD3-derived: Display/Headline/Title/Body/Label) ─────────────
const TYPE = {
  titleLg:   { fontSize: 20, fontWeight: 600, letterSpacing: "-0.01em", lineHeight: 1.3 },
  titleMd:   { fontSize: 15, fontWeight: 600, letterSpacing: "0", lineHeight: 1.4 },
  titleSm:   { fontSize: 13, fontWeight: 600, letterSpacing: "0.005em", lineHeight: 1.4 },
  bodyLg:    { fontSize: 14, fontWeight: 400, letterSpacing: "0.01em", lineHeight: 1.6 },
  bodyMd:    { fontSize: 13, fontWeight: 400, letterSpacing: "0.015em", lineHeight: 1.55 },
  bodySm:    { fontSize: 12, fontWeight: 400, letterSpacing: "0.02em", lineHeight: 1.5 },
  labelLg:   { fontSize: 12, fontWeight: 600, letterSpacing: "0.04em", lineHeight: 1.3 },
  labelMd:   { fontSize: 10.5, fontWeight: 700, letterSpacing: "0.06em", lineHeight: 1.3 },
  labelSm:   { fontSize: 9.5, fontWeight: 700, letterSpacing: "0.08em", lineHeight: 1.3, textTransform: "uppercase" },
};

// ─── Severity ─────────────────────────────────────────────────────────────────
// MD3-desaturated tonal severity palette — sits in the surface system rather
// than screaming against it. Each pairs a "tone" (for accents/text) with a
// "container" (for filled badge backgrounds) per MD3 role-color convention.
const SC = { Critical:"#FFB4AB", High:"#FFB77C", Medium:"#F5D67C", Low:"#8DD9A8", Info:"#A8C8FF" };
const SC_CONTAINER = { Critical:"#5C1A15", High:"#5C3A15", Medium:"#4A3F10", Low:"#1B4A2C", Info:"#1E3A5F" };
const SO = { Critical:0, High:1, Medium:2, Low:3 };

function sev(f) { return SC[f.severity] || SC.Info; }
function sevContainer(f) { return SC_CONTAINER[f.severity] || SC_CONTAINER.Info; }
// Severity badge — resolves both tone + container from the finding/severity so
// call sites don't need to know about SC_CONTAINER individually.
const SeverityBadge = ({ severity, small }) => (
  <Badge label={severity} color={SC[severity]||SC.Info} container={SC_CONTAINER[severity]||SC_CONTAINER.Info} small={small}/>
);
function focus(id) {
  if(id.startsWith("AZURE-CA-")||id.startsWith("AZURE-RISK-")) return "Conditional Access";
  if(id.startsWith("AZURE-MFA-")) return "MFA";
  if(id.startsWith("AZURE-PIM-")||id.startsWith("AZURE-PRIV-")||id.startsWith("AZURE-BG-")) return "Privileged Identity";
  if(id.startsWith("AZURE-APP-")||id.startsWith("AZURE-CONSENT-")) return "Applications";
  if(id.startsWith("AZURE-GUEST-")) return "Guests";
  if(id.startsWith("AZURE-GROUP-")) return "Groups";
  if(id.startsWith("AZURE-MONITORING-")) return "Monitoring";
  if(id.startsWith("AZURE-GOVERNANCE-")) return "Governance";
  return "Identity";
}

// ─── Remediation ─────────────────────────────────────────────────────────────
const REM = {
  "AZURE-CA-001":{title:"Break glass accounts excluded from all CA policies",risk:"If break glass accounts are subject to CA policies, admins can be permanently locked out during an MFA outage or CA misconfiguration — with no way back in.",steps:["Create a dedicated security group: 'Break Glass — CA Exclusion'. Add both break glass accounts.","Open every enabled CA policy → Assignments → Users → Exclude → add the break glass group.","Verify: sign in as a break glass account and confirm no CA policies apply in the sign-in logs."],ref:"https://learn.microsoft.com/en-us/entra/identity/roles/security-emergency-access"},
  "AZURE-CA-002":{title:"MFA required for privileged roles",risk:"A single phished password grants full tenant admin access without MFA on privileged roles.",steps:["New CA policy → 'Require MFA — Privileged Roles'.","Include: Global Admin, Security Admin, Privileged Role Admin, Exchange Admin.","Grant: Require multifactor authentication. Exclude break glass group. Enable On."],ref:"https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa"},
  "AZURE-CA-LEGACY":{title:"Block legacy authentication",risk:"Legacy protocols (POP3, IMAP, SMTP Auth) cannot enforce MFA. 99%+ of password spray attacks use legacy auth.",steps:["New CA policy → 'Block Legacy Authentication'.","All users, All cloud apps.","Conditions → Client apps → Exchange ActiveSync clients + Other clients.","Grant → Block access. Enable On after monitoring in Report-only for 30 days."],ref:"https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication"},
  "AZURE-CA-MFA-ALL":{title:"MFA required for all users",risk:"Without universal MFA, any compromised password gives full access. This single control prevents ~99.9% of account compromise attacks.",steps:["New CA policy → 'Require MFA — All Users'.","All users (exclude break glass), All cloud apps.","Grant → Require multifactor authentication.","Enable Report-only first for 2 weeks, then switch to On."],ref:"https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa"},
  "AZURE-RISK-001":{title:"Block/challenge high sign-in risk",risk:"Without risk-based policies, flagged sign-ins (impossible travel, anonymous IP, leaked credentials) proceed unchallenged.",steps:["New CA policy → 'Block High Sign-in Risk'.","All users, All cloud apps.","Conditions → Sign-in risk → High.","Grant → Block access (High) or Require MFA (Medium). Enable On. Requires P2."],ref:"https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies"},
  "AZURE-CA-005":{title:"Require password change for high user risk",risk:"Compromised accounts (leaked credentials, malware) retain access indefinitely without a user risk policy.",steps:["New CA policy → 'High User Risk — Require Password Change'.","All users, All cloud apps.","Conditions → User risk → High.","Grant → Require MFA AND Require password change. Enable On. Requires P2."],ref:"https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies"},
  "AZURE-MFA-001":{title:"All privileged admins registered for MFA",risk:"An admin without MFA is one password away from full tenant compromise — including the ability to add new admins, disable security controls, and access all data.",steps:["Go to Entra ID → Security → Authentication methods → Registration campaign → Enable.","Set deadline to 7 days for all administrators.","Verify each Global Admin has MFA registered: Users → select admin → Authentication methods.","Block sign-in for any admin who doesn't register within the deadline."],ref:"https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates"},
  "AZURE-MFA-003":{title:"Number matching enabled in Authenticator",risk:"MFA push fatigue attacks send repeated notifications until users approve blindly. Number matching requires entering a code visible on the sign-in screen.",steps:["Entra ID → Security → Authentication methods → Microsoft Authenticator → Configure.","Set 'Require number matching' to Enabled.","Also enable 'Show application name' and 'Show geographic location'.","Takes effect within 15 minutes."],ref:"https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match"},
  "AZURE-MFA-004":{title:"Phishing-resistant MFA for admins",risk:"Standard MFA (push/OTP) is bypassed by AiTM (Adversary-in-the-Middle) phishing proxies that relay tokens in real-time. FIDO2/Windows Hello are cryptographically bound to the site URL.",steps:["Enable FIDO2: Authentication methods → FIDO2 security key → Enable.","Create authentication strength: Conditional Access → Authentication strengths → New → select FIDO2 + Windows Hello.","Create CA policy targeting privileged roles requiring this strength.","Procure YubiKeys or similar for all admins."],ref:"https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths"},
  "AZURE-PIM-001":{title:"No permanent active role assignments",risk:"Standing privilege means every moment of every day, those accounts can be abused. PIM enforces Just-in-Time with time limits, justification, and approval workflow.",steps:["Entra ID → Identity Governance → PIM → Azure AD roles → Assignments.","For each permanent active assignment (except break glass): Remove the active assignment.","Add the same user as Eligible instead.","Configure role settings: max activation 4-8 hours, require justification, require MFA, optional approval."],ref:"https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-getting-started"},
  "AZURE-PIM-002":{title:"PIM roles have access reviews",risk:"Role assignments accumulate as staff change roles or leave. Without reviews, stale assignments persist forever.",steps:["Entra ID → Identity Governance → Access reviews → New access review.","Select Azure AD roles → include all privileged roles.","Frequency: Quarterly. Reviewers: managers. Auto-apply: Yes.","If no response: Remove access. Enable email notifications. Start."],ref:"https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-create-azure-ad-roles-and-resource-roles-review"},
  "AZURE-PRIV-001":{title:"Privileged accounts must be cloud-only",risk:"Synced admin accounts can be compromised via on-prem attacks (Pass-the-Hash, DCSync). Cloud-only accounts are isolated from on-premises attack paths.",steps:["Create dedicated cloud-only accounts: john.smith-admin@contoso.onmicrosoft.com.","Assign all privileged roles exclusively to these cloud-only accounts.","Remove privileged roles from all on-premises synced accounts.","Enable PIM for cloud-only admin accounts."],ref:"https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices"},
  "AZURE-PRIV-003":{title:"Fewer than 5 Global Administrators",risk:"Every Global Admin is a potential attack vector. Microsoft recommends 2-4 — enough for redundancy without excessive attack surface.",steps:["Entra ID → Roles → Global Administrator → review each member.","Identify who can use a scoped role instead (Exchange Admin, SharePoint Admin, etc.).","Remove Global Admin from those who don't need it.","Convert remaining to PIM eligible assignments."],ref:"https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices"},
  "AZURE-BG-001":{title:"Break glass accounts exist",risk:"Without break glass accounts, a CA misconfiguration, MFA outage, or compromised admin account can permanently lock everyone out of the tenant.",steps:["Create 2 cloud-only accounts: breakglass1@contoso.onmicrosoft.com, breakglass2@contoso.onmicrosoft.com.","Assign Global Administrator permanently (not via PIM). No MFA registration.","Generate 30+ character passwords. Store in physical safe at two locations.","Exclude from ALL Conditional Access policies.","Set up Log Analytics alerts for any sign-in from these accounts.","Test quarterly — attempt sign-in without completing any actions."],ref:"https://learn.microsoft.com/en-us/entra/identity/roles/security-emergency-access"},
  "AZURE-APP-001":{title:"No expired or expiring app credentials",risk:"Expired credentials cause immediate service outages. Near-expiry credentials need urgent rotation before production services break.",steps:["Entra ID → App registrations → each app → Certificates & secrets.","For expired/expiring: create new credential first, update app config, verify, then delete old.","Set Azure Monitor alerts for credential expiry 60 days in advance.","Consider Managed Identities for Azure-hosted services to eliminate credential management."],ref:"https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tutorial-manage-certificates-for-federated-single-sign-on"},
  "AZURE-CONSENT-001":{title:"Users cannot consent to apps",risk:"Illicit consent grant attacks trick users into consenting to malicious OAuth apps that steal mailbox and file data. One phishing email grants persistent access to all user data.",steps:["Entra ID → Enterprise apps → Consent and permissions → User consent settings.","Set to: 'Do not allow user consent'.","Enable admin consent workflow: Admin consent requests → Toggle Yes → add security team as reviewers.","Save. Users now see 'Request approval' instead of consenting directly."],ref:"https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent"},
  "AZURE-APP-005":{title:"Enterprise apps require user assignment",risk:"Without assignment required, any tenant user (including guests) can access any app that hasn't been locked down.",steps:["Entra ID → Enterprise applications → select each app → Properties.","Set Assignment required to Yes.","Users and groups → Add the appropriate users and groups who should have access.","Repeat for all business-critical and externally-accessible apps."],ref:"https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal"},
  "AZURE-GUEST-001":{title:"Remove unaccepted guest invitations",risk:"Pending invitations older than 30 days may have been intercepted or sent to wrong addresses. An intercepted invitation grants immediate tenant access.",steps:["Entra ID → Users → filter: User type = Guest, Invitation accepted = No.","Contact the inviting manager to confirm if still needed.","Delete invitations older than 30 days with no valid reason.","Re-invite if still needed with the correct email address."],ref:"https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b"},
  "AZURE-GOVERNANCE-001":{title:"Access reviews for privileged roles",risk:"Without reviews, role assignments accumulate as people change roles or leave. Required by ISO 27001, SOC 2, and most security frameworks.",steps:["Entra ID → Identity Governance → Access reviews → New access review.","Select all privileged Azure AD roles.","Frequency: Quarterly. Reviewers: managers or security team.","Auto-apply: Yes. If no response: Remove access. Start."],ref:"https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview"},
  "AZURE-MONITORING-003":{title:"High-risk users must be remediated",risk:"Identity Protection flags active compromises. High-risk users represent real breaches or very high-probability compromises requiring immediate action.",steps:["Entra ID → Security → Identity Protection → Risky users → filter: High risk.","For each: review Risk detections to understand why they're flagged.","If compromised: Confirm user compromised → Reset password → Revoke all sessions.","If false positive: Dismiss with justification.","Configure CA policy for user risk to automate future responses."],ref:"https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk"},
  "AZURE-STALE-001":{title:"Disable stale privileged accounts",risk:"Privileged accounts inactive for 30+ days are unnecessary attack surfaces that the legitimate owner may not notice if abused.",steps:["Entra ID → Users → filter by privileged roles → check last sign-in.","For accounts inactive 30+ days: confirm with owner if access still needed.","If no longer needed: Block sign-in → remove all role assignments.","After 90 days without need confirmed: delete the account."],ref:"https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details"},
};

const EXS = {
  fixed:          {l:"Fixed",          c:SC.Low,     cc:SC_CONTAINER.Low,     i:"✓"},
  risk_accepted:  {l:"Risk accepted",  c:SC.Medium,  cc:SC_CONTAINER.Medium,  i:"⚠"},
  false_positive: {l:"False positive", c:SC.Info,    cc:SC_CONTAINER.Info,    i:"⊘"},
  in_progress:    {l:"In progress",    c:SC.High,    cc:SC_CONTAINER.High,    i:"◷"},
};

const FW = {
  "NIST CSF":{
    "Identify":["AZURE-IDENTITY-001","AZURE-IDENTITY-006","AZURE-IDENTITY-008","AZURE-IDENTITY-009","AZURE-IDENTITY-012","AZURE-IDENTITY-017"],
    "Protect":["AZURE-CA-001","AZURE-CA-002","AZURE-CA-MFA-ALL","AZURE-CA-LEGACY","AZURE-MFA-001","AZURE-MFA-003","AZURE-MFA-004","AZURE-PRIV-001","AZURE-PRIV-003","AZURE-PIM-001","AZURE-BG-001"],
    "Detect":["AZURE-MONITORING-003","AZURE-MONITORING-005","AZURE-MONITORING-006","AZURE-RISK-001","AZURE-CA-005"],
    "Respond":["AZURE-BG-001","AZURE-MONITORING-004"],
    "Recover":["AZURE-BG-001","AZURE-PRIV-004"],
  },
  "CIS Azure v2":{
    "IAM":["AZURE-MFA-001","AZURE-CA-MFA-ALL","AZURE-CA-001","AZURE-CA-002","AZURE-CA-LEGACY","AZURE-PRIV-001","AZURE-IDENTITY-017","AZURE-GROUP-005","AZURE-IDENTITY-012"],
    "Conditional Access":["AZURE-CA-003","AZURE-CA-005","AZURE-CA-006","AZURE-CA-010","AZURE-CA-012","AZURE-CA-013","AZURE-RISK-001","AZURE-CA-015","AZURE-CA-017"],
    "Applications":["AZURE-APP-001","AZURE-APP-005","AZURE-APP-006","AZURE-APP-008","AZURE-APP-010","AZURE-APP-013","AZURE-CONSENT-001"],
    "Monitoring":["AZURE-MONITORING-003","AZURE-MONITORING-004","AZURE-MONITORING-005","AZURE-MONITORING-006"],
    "Governance":["AZURE-PIM-001","AZURE-PIM-002","AZURE-GOVERNANCE-001"],
  },
  "ISO 27001":{
    "A.9 Access Control":["AZURE-CA-001","AZURE-CA-002","AZURE-MFA-001","AZURE-PRIV-001","AZURE-PIM-001","AZURE-IDENTITY-006","AZURE-BG-001"],
    "A.12 Operations":["AZURE-MONITORING-003","AZURE-MONITORING-005","AZURE-APP-001","AZURE-STALE-001"],
    "A.14 Development":["AZURE-APP-005","AZURE-APP-006","AZURE-APP-008","AZURE-APP-013","AZURE-CONSENT-001"],
    "A.16 Incidents":["AZURE-MONITORING-003","AZURE-MONITORING-004","AZURE-RISK-001","AZURE-BG-001"],
  },
};

// ─── Tiny components ──────────────────────────────────────────────────────────
// MD3 "tonal" badge — filled with the color's own dark container tone rather
// than a translucent wash over the page background. Text uses the light tone
// from the same role, so contrast holds regardless of what surface it sits on.
const Badge = ({label, color, container, small}) => (
  <span style={{display:"inline-flex",alignItems:"center",
    padding:small?"2px 8px":"3px 10px",
    borderRadius:999,...(small?TYPE.labelMd:TYPE.labelLg),
    background:container||color+"26",color}}>{label}</span>
);

const ScoreBar = ({score, max=10}) => {
  const c = score>7?SC.Critical:score>4?SC.High:score>0?SC.Medium:SC.Low;
  return (
    <div style={{display:"flex",alignItems:"center",gap:8}}>
      <div style={{flex:1,height:4,background:MD.surfaceHigh,borderRadius:2,overflow:"hidden"}}>
        <div style={{height:"100%",borderRadius:2,background:c,
          width:`${(score/max)*100}%`,transition:"width 0.5s cubic-bezier(0.2,0,0,1)"}}/>
      </div>
      <span style={{fontFamily:"'Roboto Mono',ui-monospace,monospace",fontSize:11,fontWeight:600,
        color:c,minWidth:28,textAlign:"right"}}>{score.toFixed(1)}</span>
    </div>
  );
};

// ─── Sidebar ──────────────────────────────────────────────────────────────────
const NAVS = [
  {id:"dashboard",  icon:"◈", l:"Dashboard"},
  {id:"findings",   icon:"⚡",l:"Findings"},
  {id:"compliance", icon:"✓", l:"Compliance"},
  {id:"remediation",icon:"⚙", l:"Remediation"},
  {id:"history",    icon:"◷", l:"Scan History"},
  {id:"exceptions", icon:"⊘", l:"Exceptions"},
  {id:"users",      icon:"👤", l:"Users", adminOnly:true},
];

// ─── Auth ────────────────────────────────────────────────────────────────────
const AUTH_CONFIG_URL = "/api/v1/auth/config";
const AUTH_LOGIN_URL  = "/api/v1/auth/login/extended";
const AUTH_ME_URL     = "/api/v1/auth/me";
const AUTH_LOGOUT_URL = "/api/v1/auth/logout";
const MSAL_LOGIN_URL  = "/api/v1/auth/msal/login";

function getStoredToken() {
  try { return localStorage.getItem("eg_token") || ""; } catch { return ""; }
}
function setStoredToken(t) {
  try { localStorage.setItem("eg_token", t); } catch {}
}
function clearStoredToken() {
  try { localStorage.removeItem("eg_token"); } catch {}
}

async function authFetch(url, opts={}) {
  const token = getStoredToken();
  const headers = { "Content-Type":"application/json", ...(opts.headers||{}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const r = await fetch(url, { ...opts, headers });
  if (r.status === 401) { clearStoredToken(); window.location.href = "/"; }
  return r;
}

// ─── Login Page ───────────────────────────────────────────────────────────────
function LoginPage({ onLogin, config }) {
  const [user, setUser] = React.useState("");
  const [pass, setPass] = React.useState("");
  const [err, setErr]   = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [tab, setTab] = React.useState(config.msal_enabled ? "msal" : "local");
  const [focusField, setFocusField] = React.useState(null);

  const localLogin = async () => {
    if (!user || !pass) { setErr("Enter username and password"); return; }
    setLoading(true); setErr("");
    try {
      const r = await fetch(AUTH_LOGIN_URL, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({username:user, password:pass}),
      });
      const d = await r.json();
      if (!r.ok) { setErr(d.detail || "Invalid credentials"); return; }
      setStoredToken(d.access_token);
      onLogin(d.user);
    } catch(e) { setErr("Connection failed"); }
    finally { setLoading(false); }
  };

  const msalLogin = () => { window.location.href = MSAL_LOGIN_URL; };

  const fieldStyle = (name) => ({
    width:"100%",padding:"12px 14px",background:MD.surfaceDim,
    border:`1px solid ${focusField===name?MD.primary:MD.outlineVar}`,
    borderRadius:MD.radiusMd,color:MD.onSurface,
    ...TYPE.bodyLg,outline:"none",boxSizing:"border-box",
    transition:"border-color 0.15s",
  });

  return (
    <div style={{minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",
      background:MD.surfaceDim,fontFamily:"'Inter',system-ui,sans-serif",padding:16}}>
      <div style={{width:"100%",maxWidth:420}}>
        {/* Logo */}
        <div style={{textAlign:"center",marginBottom:36}}>
          <div style={{width:56,height:56,borderRadius:MD.radiusLg,
            background:MD.primaryContainer,
            display:"flex",alignItems:"center",justifyContent:"center",
            margin:"0 auto 18px",fontSize:22,fontWeight:700,color:MD.onPrimaryContainer,
            boxShadow:elevation(2)}}>EG</div>
          <div style={{...TYPE.titleLg,fontSize:26,color:MD.onSurface}}>EntraGuard</div>
          <div style={{...TYPE.bodySm,color:MD.outline,marginTop:5}}>Azure identity security posture management</div>
        </div>

        <div style={{background:MD.surfaceCont,borderRadius:MD.radiusXl,padding:30,boxShadow:elevation(3)}}>
          {/* Tab switcher — MD3 segmented button */}
          {config.msal_enabled && config.local_admin_enabled && (
            <div style={{display:"flex",background:MD.surfaceDim,borderRadius:MD.radiusXl,padding:4,marginBottom:26,gap:4}}>
              {[["msal","Sign in with Microsoft"],["local","Local admin"]].map(([t,l])=>(
                <button key={t} onClick={()=>setTab(t)} style={{
                  flex:1,padding:"8px 12px",borderRadius:MD.radiusXl,border:"none",cursor:"pointer",
                  background:tab===t?MD.surfaceHigh:"transparent",
                  color:tab===t?MD.onSurface:MD.outline,
                  ...TYPE.labelLg,fontWeight:tab===t?700:500,transition:"all 0.15s"
                }}>{l}</button>
              ))}
            </div>
          )}

          {/* MSAL button */}
          {(tab === "msal" || (!config.local_admin_enabled && config.msal_enabled)) && (
            <div>
              <button onClick={msalLogin} style={{
                width:"100%",padding:"13px 18px",borderRadius:MD.radiusXl,border:"none",cursor:"pointer",
                background:MD.primaryDim,color:MD.surfaceDim,...TYPE.bodyLg,fontWeight:700,
                display:"flex",alignItems:"center",justifyContent:"center",gap:11,
                boxShadow:elevation(1),transition:"background 0.2s",
              }}>
                <svg width="18" height="18" viewBox="0 0 21 21" fill="currentColor">
                  <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
                  <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
                  <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
                  <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
                </svg>
                Sign in with Microsoft
              </button>
              <div style={{marginTop:10,padding:"10px 14px",background:SC_CONTAINER.Medium,
                borderRadius:MD.radiusMd,...TYPE.bodySm,color:SC.Medium,lineHeight:1.6}}>
                Requires HTTPS. Add <code style={{fontFamily:"'Roboto Mono',ui-monospace,monospace",fontSize:10.5}}>
                {window.location.origin}/api/v1/auth/callback</code> as a redirect URI in
                Azure Portal → App registration → Authentication, and set up HTTPS for your app.
              </div>
            </div>
          )}

          {/* Local admin form — MD3 outlined text fields */}
          {tab === "local" && config.local_admin_enabled && (
            <div style={{display:"flex",flexDirection:"column",gap:16}}>
              <div>
                <div style={{...TYPE.labelMd,color:MD.outline,marginBottom:7}}>Username</div>
                <input value={user} onChange={e=>setUser(e.target.value)}
                  onFocus={()=>setFocusField("user")} onBlur={()=>setFocusField(null)}
                  onKeyDown={e=>e.key==="Enter"&&localLogin()}
                  placeholder="admin"
                  style={fieldStyle("user")}/>
              </div>
              <div>
                <div style={{...TYPE.labelMd,color:MD.outline,marginBottom:7}}>Password</div>
                <input type="password" value={pass} onChange={e=>setPass(e.target.value)}
                  onFocus={()=>setFocusField("pass")} onBlur={()=>setFocusField(null)}
                  onKeyDown={e=>e.key==="Enter"&&localLogin()}
                  placeholder="••••••••"
                  style={fieldStyle("pass")}/>
              </div>
              {err && <div style={{...TYPE.bodySm,color:SC.Critical,padding:"10px 14px",
                background:SC_CONTAINER.Critical,borderRadius:MD.radiusMd}}>{err}</div>}
              <button onClick={localLogin} disabled={loading}
                style={{padding:"13px 18px",borderRadius:MD.radiusXl,border:"none",cursor:"pointer",
                  background:loading?MD.surfaceHigh:MD.primaryDim,
                  color:loading?MD.outline:MD.surfaceDim,...TYPE.bodyLg,fontWeight:700,marginTop:6,
                  boxShadow:loading?"none":elevation(1),transition:"all 0.2s"}}>
                {loading?"Signing in…":"Sign in"}
              </button>
            </div>
          )}

          {!config.msal_enabled && !config.local_admin_enabled && (
            <div style={{textAlign:"center",color:MD.outline,...TYPE.bodyMd,lineHeight:1.7}}>
              Authentication is enabled but no login method is configured.<br/>
              Set LOCAL_ADMIN_PASSWORD or configure AZURE credentials in .env.
            </div>
          )}
        </div>

        <div style={{textAlign:"center",marginTop:18,...TYPE.labelMd,color:MD.outlineVar}}>
          EntraGuard v2.0 · Read-only · Your data stays on your server
        </div>
      </div>
    </div>
  );
}

function Nav({view, setView, fails, user, onLogout}) {
  const [hoverId, setHoverId] = React.useState(null);
  return (
    <aside style={{position:"fixed",top:0,left:0,bottom:0,width:232,
      background:MD.surfaceLow,borderRight:`1px solid ${MD.outlineVar}`,
      display:"flex",flexDirection:"column",zIndex:100,
      fontFamily:"'Inter',system-ui,sans-serif"}}>
      {/* Logo */}
      <div style={{padding:"20px 20px 18px"}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:38,height:38,borderRadius:MD.radiusMd,
            background:MD.primaryContainer,
            display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
            <svg width="20" height="20" fill="none" stroke={MD.onPrimaryContainer} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
            </svg>
          </div>
          <div>
            <div style={{...TYPE.titleSm,color:MD.onSurface}}>EntraGuard</div>
            <div style={{...TYPE.labelSm,color:MD.outline,marginTop:1}}>Azure CSPM · v2.0</div>
          </div>
        </div>
      </div>

      {/* Nav — MD3 navigation-rail pattern: pill active-indicator behind
          icon+label, state-layer wash on hover, no borders */}
      <nav style={{flex:1,padding:"4px 12px",overflowY:"auto"}}>
        {NAVS.map(n=>{
          const active = view===n.id;
          const hovered = hoverId===n.id;
          return (
            <button key={n.id} onClick={()=>setView(n.id)}
              onMouseEnter={()=>setHoverId(n.id)} onMouseLeave={()=>setHoverId(null)}
              style={{
                width:"100%",display:"flex",alignItems:"center",gap:12,
                padding:"10px 14px",marginBottom:4,borderRadius:MD.radiusXl,
                background: active ? MD.primaryContainer : hovered ? stateLayer(MD.onSurface, 0.06) : "transparent",
                border:"none",
                color: active ? MD.onPrimaryContainer : MD.onSurfaceVar,
                ...TYPE.labelLg, fontWeight: active?700:500, letterSpacing:"0.01em",
                cursor:"pointer",transition:"background 0.15s cubic-bezier(0.2,0,0,1)",textAlign:"left"}}>
              <span style={{fontSize:15,opacity:active?1:0.85,width:18,textAlign:"center"}}>{n.icon}</span>
              <span style={{flex:1}}>{n.l}</span>
              {n.id==="findings"&&fails>0&&(
                <span style={{background:SC_CONTAINER.Critical,color:SC.Critical,
                  ...TYPE.labelMd,padding:"1px 7px",borderRadius:999}}>{fails}</span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div style={{padding:"16px 20px",borderTop:`1px solid ${MD.outlineVar}`}}>
        {user && user.auth_type !== "disabled" ? (<>
          <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:6}}>Signed in as</div>
          <div style={{...TYPE.bodyMd,color:MD.onSurface,fontWeight:600,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{user.name||"User"}</div>
          {user.email&&<div style={{...TYPE.bodySm,color:MD.outline,marginTop:1,overflow:"hidden",textOverflow:"ellipsis"}}>{user.email}</div>}
          <div style={{...TYPE.labelSm,color:MD.outline,marginTop:4}}>{user.auth_type==="msal"?"Microsoft SSO":"Local admin"}</div>
          <button onClick={onLogout} style={{marginTop:12,width:"100%",padding:"8px",
            background:"transparent",border:`1px solid ${MD.outlineVar}`,borderRadius:MD.radiusSm,
            color:MD.onSurfaceVar,...TYPE.labelLg,fontWeight:600,cursor:"pointer",
            transition:"background 0.15s"}}
            onMouseEnter={e=>e.currentTarget.style.background=stateLayer(MD.onSurface,0.06)}
            onMouseLeave={e=>e.currentTarget.style.background="transparent"}>Sign out</button>
        </>) : (<>
          <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:5}}>Operator</div>
          <div style={{...TYPE.bodyMd,color:MD.onSurfaceVar,fontWeight:600}}>Junaid Ahmed</div>
          <div style={{...TYPE.bodySm,color:MD.outline}}>iam@jahmed.cloud</div>
          <div style={{display:"flex",gap:8,marginTop:10}}>
            {[["GH","https://github.com/jahmed-cloud/entra-guard"],["DH","https://hub.docker.com/r/jahmed22/entra-guard"]].map(([l,u])=>(
              <a key={l} href={u} target="_blank" style={{...TYPE.labelMd,color:MD.outline,
                textDecoration:"none",padding:"3px 8px",border:`1px solid ${MD.outlineVar}`,borderRadius:MD.radiusSm}}>{l}</a>
            ))}
          </div>
        </>)}
      </div>
    </aside>
  );
}

// ─── Topbar ───────────────────────────────────────────────────────────────────
// ─── Topbar ───────────────────────────────────────────────────────────────────
function Top({target, scanning, onScan, online, lastScan, crits}) {
  const [hover, setHover] = React.useState(false);
  return (
    <header className="eg-top-header" style={{position:"fixed",top:0,left:232,right:0,height:64,
      background:MD.surfaceLow,borderBottom:`1px solid ${MD.outlineVar}`,
      display:"flex",alignItems:"center",padding:"0 24px",gap:16,zIndex:90,
      fontFamily:"'Inter',system-ui,sans-serif"}}>
      <div style={{display:"flex",alignItems:"center",gap:10,flex:1,minWidth:0}}>
        <span style={{width:8,height:8,borderRadius:"50%",
          background:online?SC.Low:SC.Critical,
          boxShadow:`0 0 0 3px ${online?SC.Low:SC.Critical}22`,flexShrink:0}}/>
        <span style={{...TYPE.labelMd,color:MD.outline}}>{online?"Online":"Offline"}</span>
        {target&&<>
          <span style={{color:MD.outlineVar,fontSize:15}}>/</span>
          <span style={{...TYPE.bodyMd,color:MD.onSurfaceVar,fontWeight:600,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{target.name}</span>
        </>}
        {lastScan&&<span style={{...TYPE.labelMd,color:MD.outline,marginLeft:6,flexShrink:0,fontWeight:500}}>
          Last scan {new Date(lastScan).toLocaleString()}
        </span>}
      </div>

      {crits>0&&(
        <div style={{display:"flex",alignItems:"center",gap:7,padding:"6px 14px",
          background:SC_CONTAINER.Critical,borderRadius:MD.radiusXl,boxShadow:elevation(1)}}>
          <span style={{width:6,height:6,borderRadius:"50%",background:SC.Critical,
            animation:"blink 1.4s ease infinite"}}/>
          <span style={{...TYPE.labelLg,color:SC.Critical}}>{crits} critical</span>
        </div>
      )}

      {/* MD3 filled button — solid tonal fill, state-layer on hover, no gradient */}
      <button onClick={onScan} disabled={scanning}
        onMouseEnter={()=>setHover(true)} onMouseLeave={()=>setHover(false)}
        style={{padding:"10px 22px",borderRadius:MD.radiusXl,border:"none",cursor:scanning?"default":"pointer",
          background:scanning?MD.surfaceHigh:(hover?MD.primary:MD.primaryDim),
          color:scanning?MD.outline:MD.surfaceDim,
          boxShadow:scanning?"none":elevation(hover?2:1),
          ...TYPE.labelLg,letterSpacing:"0.03em",
          display:"flex",alignItems:"center",gap:8,
          transition:"background 0.15s cubic-bezier(0.2,0,0,1), box-shadow 0.15s"}}>
        {scanning
          ?<><div style={{width:14,height:14,border:`2px solid ${MD.outline}`,borderTopColor:"transparent",
              borderRadius:"50%",animation:"spin 0.7s linear infinite"}}/>Scanning…</>
          :<>▶ Run scan</>}
      </button>
    </header>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
function Dashboard({findings, runs}) {
  const fail=findings.filter(f=>f.status==="failed");
  const pass=findings.filter(f=>f.status==="passed");
  const err=findings.filter(f=>f.status==="error");
  const score=findings.length?Math.round(pass.length/findings.length*100):null;
  const bySev={Critical:0,High:0,Medium:0,Low:0};
  fail.forEach(f=>{if(bySev[f.severity]!==undefined)bySev[f.severity]++;});
  const byDomain={};
  fail.forEach(f=>{const d=focus(f.check_id);byDomain[d]=(byDomain[d]||0)+1;});
  const aiExplainedCount=findings.filter(f=>f.ai_explanation).length;
  const aiFlaggedCount=findings.filter(f=>f.ai_false_positive_likelihood&&f.ai_false_positive_likelihood!=="none").length;
  const top5=[...fail].sort((a,b)=>b.score-a.score).slice(0,5);
  const trendData=runs.slice(0,12).reverse();

  const W=480,H=88,PAD=8;
  const vals=trendData.map(r=>r.checks_failed||0);
  const maxV=Math.max(...vals,1);
  const pts=vals.map((v,i)=>{
    const x=PAD+(i/(Math.max(vals.length-1,1)))*(W-PAD*2);
    const y=H-PAD-(v/maxV)*(H-PAD*2);
    return [Math.round(x),Math.round(y)];
  });
  const linePath=pts.map((p,i)=>i===0?`M${p[0]},${p[1]}`:`L${p[0]},${p[1]}`).join(" ");
  const areaPath=pts.length>0?`${linePath} L${pts[pts.length-1][0]},${H-PAD} L${pts[0][0]},${H-PAD} Z`:"";

  const passVals=trendData.map(r=>r.checks_total>0?Math.round((r.checks_passed||0)/r.checks_total*100):0);
  const maxP=100;
  const passPts=passVals.map((v,i)=>{
    const x=PAD+(i/(Math.max(passVals.length-1,1)))*(W-PAD*2);
    const y=H-PAD-(v/maxP)*(H-PAD*2);
    return [Math.round(x),Math.round(y)];
  });
  const passPath=passPts.map((p,i)=>i===0?`M${p[0]},${p[1]}`:`L${p[0]},${p[1]}`).join(" ");
  const passArea=passPts.length>0?`${passPath} L${passPts[passPts.length-1][0]},${H-PAD} L${passPts[0][0]},${H-PAD} Z`:"";

  const domainEntries=Object.entries(byDomain).sort((a,b)=>b[1]-a[1]);
  const maxDomain=Math.max(...domainEntries.map(e=>e[1]),1);

  // MD3 elevated surface card — one shared shape/elevation, dp1 resting state
  const CARD={background:MD.surfaceCont,borderRadius:MD.radiusLg,padding:18,boxShadow:elevation(1)};
  const scoreColor = score===null?MD.outline:score>=80?SC.Low:score>=60?SC.Medium:SC.Critical;
  // Category palette drawn from the shared MD3 ramp set, not ad-hoc hex —
  // used for domain bars where more than one hue is needed to distinguish rows
  const CAT = [SC.Critical, SC.High, SC.Medium, SC.Low, MD.primary, "#C9A6FF"];

  return (
    <div style={{animation:"fadeIn 0.25s cubic-bezier(0.2,0,0,1)"}}>
      {/* Critical banner — elevated above the rest of the page (dp2) since it
          demands the most immediate attention: elevation as priority signal */}
      {bySev.Critical>0&&(
        <div style={{marginBottom:16,padding:"14px 18px",borderRadius:MD.radiusLg,
          background:SC_CONTAINER.Critical,boxShadow:elevation(2),
          display:"flex",alignItems:"center",gap:14}}>
          <div style={{width:38,height:38,borderRadius:MD.radiusMd,background:"rgba(0,0,0,0.18)",
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,flexShrink:0,color:SC.Critical}}>⚠</div>
          <div>
            <div style={{...TYPE.titleSm,color:SC.Critical}}>
              {bySev.Critical} critical issue{bySev.Critical!==1?"s":""} require immediate action
            </div>
            <div style={{...TYPE.bodySm,color:"#E8B4AE",marginTop:3}}>
              {bySev.High} high · {bySev.Medium} medium · {bySev.Low} low severity findings detected.
              Open Findings for step-by-step remediation guides.
            </div>
          </div>
        </div>
      )}

      {/* AI scan summary — prominent, unmistakably AI-labeled card. Sits
          below the deterministic critical banner (never replacing it), but
          is now visually substantial enough that a first-time user notices
          the feature is active, not just a small aside easy to miss. */}
      {runs[0]?.ai_summary&&(
        <div style={{marginBottom:16,borderRadius:MD.radiusLg,overflow:"hidden",
          background:`linear-gradient(135deg, ${MD.primaryContainer}45, ${MD.primaryContainer}15)`,
          border:`1px solid ${MD.primary}30`,boxShadow:elevation(2)}}>
          <div style={{padding:"16px 20px"}}>
            <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:10}}>
              <div style={{width:32,height:32,borderRadius:"50%",background:MD.primaryContainer,
                display:"flex",alignItems:"center",justifyContent:"center",fontSize:16,flexShrink:0}}>✨</div>
              <div style={{...TYPE.labelLg,color:MD.primary,fontWeight:700,letterSpacing:"0.02em"}}>
                AI SCAN SUMMARY
              </div>
              <span style={{...TYPE.labelSm,color:MD.onPrimaryContainer,background:MD.primaryContainer,
                padding:"2px 8px",borderRadius:MD.radiusXl,fontWeight:600}}>
                AI-generated
              </span>
              <div style={{flex:1}}/>
              {aiExplainedCount>0&&(
                <span style={{...TYPE.labelSm,color:MD.outline}}>
                  {aiExplainedCount} finding{aiExplainedCount!==1?"s":""} AI-reviewed
                  {aiFlaggedCount>0&&<> · <span style={{color:SC.Medium,fontWeight:600}}>{aiFlaggedCount} flagged as possible false positive{aiFlaggedCount!==1?"s":""}</span></>}
                </span>
              )}
            </div>
            <p style={{...TYPE.bodyLg,color:MD.onSurface,lineHeight:1.75,margin:0}}>
              {runs[0].ai_summary}
            </p>
          </div>
          <div style={{padding:"8px 20px",background:MD.surfaceDim+"40",borderTop:`1px solid ${MD.primary}20`}}>
            <span style={{...TYPE.labelSm,color:MD.outlineVar}}>
              Generated from this scan's aggregate results — see individual findings below for per-check AI reasoning and false-positive flags.
            </span>
          </div>
        </div>
      )}

      {/* Row 1 — Score + KPIs */}
      <div style={{display:"grid",gridTemplateColumns:"150px 1fr",gap:12,marginBottom:12}} className="eg-chart-row">
        <div style={{...CARD,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:10}}>
          <div style={{...TYPE.labelSm,color:MD.outline}}>Posture</div>
          <div style={{position:"relative",width:88,height:88}}>
            <svg width="88" height="88" viewBox="0 0 88 88" style={{transform:"rotate(-90deg)"}}>
              <circle cx="44" cy="44" r="36" fill="none" stroke={MD.surfaceHigh} strokeWidth="9"/>
              {score!==null&&<circle cx="44" cy="44" r="36" fill="none"
                stroke={scoreColor} strokeWidth="9" strokeLinecap="round"
                strokeDasharray={`${2*Math.PI*36*score/100} ${2*Math.PI*36}`}
                style={{transition:"stroke-dasharray 1.2s cubic-bezier(0.2,0,0,1)"}}/>}
            </svg>
            <div style={{position:"absolute",inset:0,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center"}}>
              <div style={{fontSize:score===null?15:26,fontWeight:700,lineHeight:1,color:scoreColor}}>
                {score===null?"—":score}
              </div>
              {score!==null&&<div style={{...TYPE.labelMd,color:MD.outline,marginTop:2}}>/100</div>}
            </div>
          </div>
          <div style={{...TYPE.labelMd,color:scoreColor,textAlign:"center"}}>
            {score===null?"No data":score>=80?"Good":score>=60?"Moderate":"At risk"}
          </div>
        </div>

        <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:10}} className="eg-kpi-grid">
          {[
            {l:"Checks",v:findings.length,c:MD.onSurfaceVar},
            {l:"Failing",v:fail.length,c:fail.length>0?SC.Critical:SC.Low,s:`${findings.length?Math.round(fail.length/findings.length*100):0}%`},
            {l:"Critical",v:bySev.Critical,c:bySev.Critical>0?SC.Critical:MD.outlineVar},
            {l:"High",v:bySev.High,c:bySev.High>0?SC.High:MD.outlineVar},
            {l:"Passing",v:pass.length,c:SC.Low},
            {l:"Errors",v:err.length,c:err.length>0?SC.High:MD.outlineVar,s:"fix perms"},
          ].map(k=>(
            <div key={k.l} style={{background:MD.surfaceCont,borderRadius:MD.radiusMd,padding:"14px 14px",boxShadow:elevation(1)}}>
              <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:6}}>{k.l}</div>
              <div style={{fontSize:28,fontWeight:700,color:k.c,lineHeight:1}}>{k.v}</div>
              {k.s&&<div style={{...TYPE.labelMd,color:MD.outline,marginTop:5}}>{k.s}</div>}
            </div>
          ))}
        </div>
      </div>

      {/* Row 2 — Severity + Domain */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}} className="eg-sev-domain">
        <div style={{...CARD}}>
          <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:16}}>Findings by severity</div>
          {Object.entries(bySev).map(([s,n])=>(
            <div key={s} style={{display:"flex",alignItems:"center",gap:12,marginBottom:12}}>
              <Badge label={s} color={SC[s]} container={SC_CONTAINER[s]} small/>
              <div style={{flex:1,height:8,background:MD.surfaceDim,borderRadius:4,overflow:"hidden"}}>
                <div style={{height:"100%",borderRadius:4,background:SC[s],
                  width:fail.length?`${Math.max(2,(n/fail.length)*100)}%`:"0%",
                  transition:"width 0.9s cubic-bezier(0.2,0,0,1)"}}/>
              </div>
              <span style={{fontSize:13,fontWeight:700,color:SC[s],minWidth:22,textAlign:"right"}}>{n}</span>
            </div>
          ))}
        </div>

        <div style={{...CARD}}>
          <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:16}}>Failures by domain</div>
          {domainEntries.length===0
            ?<div style={{color:SC.Low,...TYPE.bodyMd,textAlign:"center",paddingTop:24}}>All clear</div>
            :domainEntries.slice(0,6).map(([d,n],i)=>{
              const pct=Math.max(3,(n/maxDomain)*100);
              const c=CAT[i%CAT.length];
              return (
                <div key={d} style={{display:"flex",alignItems:"center",gap:10,marginBottom:11}}>
                  <div style={{...TYPE.bodySm,color:MD.onSurfaceVar,minWidth:118,flexShrink:0}}>{d}</div>
                  <div style={{flex:1,height:8,background:MD.surfaceDim,borderRadius:4,overflow:"hidden"}}>
                    <div style={{height:"100%",borderRadius:4,background:c,width:`${pct}%`,transition:"width 0.9s cubic-bezier(0.2,0,0,1)"}}/>
                  </div>
                  <span style={{fontSize:12,fontWeight:700,color:c,minWidth:20,textAlign:"right"}}>{n}</span>
                </div>
              );
            })
          }
        </div>
      </div>

      {/* Row 3 — Trend charts */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}} className="eg-chart-row">
        <div style={{...CARD}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:12}}>
            <div style={{...TYPE.labelSm,color:MD.outline}}>Failing checks — trend</div>
            {trendData.length>0&&<span style={{...TYPE.labelMd,color:SC.Critical}}>
              {trendData[trendData.length-1]?.checks_failed||vals[vals.length-1]||0} current
            </span>}
          </div>
          <svg width="100%" height={H} viewBox={"0 0 "+W+" "+H} preserveAspectRatio="none" style={{display:"block"}}>
            <defs>
              <linearGradient id="failGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={SC.Critical} stopOpacity="0.28"/>
                <stop offset="100%" stopColor={SC.Critical} stopOpacity="0.02"/>
              </linearGradient>
            </defs>
            {[0.25,0.5,0.75].map(p=>(
              <line key={p} x1={PAD} y1={H-PAD-(p*(H-PAD*2))} x2={W-PAD} y2={H-PAD-(p*(H-PAD*2))}
                stroke={MD.outlineVar} strokeWidth="0.5" strokeDasharray="3,3"/>
            ))}
            {areaPath&&<path d={areaPath} fill="url(#failGrad)"/>}
            {linePath&&<path d={linePath} fill="none" stroke={SC.Critical} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>}
            {pts.map((p,i)=>(
              <circle key={i} cx={p[0]} cy={p[1]} r="3.5" fill={SC.Critical} stroke={MD.surfaceCont} strokeWidth="2"/>
            ))}
            {trendData.map((_,i)=>(
              <text key={i} x={pts[i]?.[0]||0} y={H-1} textAnchor="middle"
                fontSize="8" fill={MD.outlineVar}>{i+1}</text>
            ))}
          </svg>
        </div>

        <div style={{...CARD}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:12}}>
            <div style={{...TYPE.labelSm,color:MD.outline}}>Pass rate — trend</div>
            {passVals.length>0&&<span style={{...TYPE.labelMd,color:SC.Low}}>
              {passVals[passVals.length-1]}% current
            </span>}
          </div>
          <svg width="100%" height={H} viewBox={"0 0 "+W+" "+H} preserveAspectRatio="none" style={{display:"block"}}>
            <defs>
              <linearGradient id="passGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={SC.Low} stopOpacity="0.24"/>
                <stop offset="100%" stopColor={SC.Low} stopOpacity="0.02"/>
              </linearGradient>
            </defs>
            {[0.25,0.5,0.75].map(p=>(
              <line key={p} x1={PAD} y1={H-PAD-(p*(H-PAD*2))} x2={W-PAD} y2={H-PAD-(p*(H-PAD*2))}
                stroke={MD.outlineVar} strokeWidth="0.5" strokeDasharray="3,3"/>
            ))}
            {passArea&&<path d={passArea} fill="url(#passGrad)"/>}
            {passPath&&<path d={passPath} fill="none" stroke={SC.Low} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>}
            {passPts.map((p,i)=>(
              <circle key={i} cx={p[0]} cy={p[1]} r="3.5" fill={SC.Low} stroke={MD.surfaceCont} strokeWidth="2"/>
            ))}
            {trendData.map((_,i)=>(
              <text key={i} x={passPts[i]?.[0]||0} y={H-1} textAnchor="middle"
                fontSize="8" fill={MD.outlineVar}>{i+1}</text>
            ))}
          </svg>
        </div>
      </div>

      {/* Row 4 — Top findings + Coverage rings */}
      <div style={{display:"grid",gridTemplateColumns:"1fr auto",gap:12,marginBottom:12}} className="eg-top5-grid">
        {top5.length>0&&(
          <div style={{...CARD}}>
            <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:16}}>Top 5 — highest risk score</div>
            {top5.map((f,i)=>{
              const r=REM[f.check_id];const sc=sev(f);
              return (
                <div key={f.check_id} style={{display:"grid",gridTemplateColumns:"22px 3px 1fr auto 76px",
                  alignItems:"center",gap:12,padding:"10px 0",
                  borderBottom:i<4?`1px solid ${MD.outlineVar}`:"none"}}>
                  <div style={{width:22,height:22,borderRadius:MD.radiusSm,background:MD.surfaceHigh,
                    display:"flex",alignItems:"center",justifyContent:"center",
                    fontSize:10,fontWeight:700,color:MD.outline}}>{i+1}</div>
                  <div style={{height:30,background:sc,borderRadius:2}}/>
                  <div style={{minWidth:0}}>
                    <div style={{...TYPE.labelMd,color:MD.outline,marginBottom:1}}>{f.check_id}</div>
                    <div style={{...TYPE.bodyMd,color:MD.onSurfaceVar,fontWeight:500,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{r?.title||f.check_id}</div>
                  </div>
                  <Badge label={f.severity} color={sc} container={sevContainer(f)} small/>
                  <ScoreBar score={f.score}/>
                </div>
              );
            })}
          </div>
        )}

        <div style={{...CARD,display:"flex",flexDirection:"column",gap:14,minWidth:172}}>
          <div style={{...TYPE.labelSm,color:MD.outline}}>Coverage</div>
          {[
            {l:"CA policies",total:15,pass:Object.values(findings.filter(f=>f.check_id.startsWith("AZURE-CA-")).reduce((a,f)=>{a[f.check_id]=f;return a},{})).filter(f=>f.status==="passed").length},
            {l:"MFA",total:9,pass:Object.values(findings.filter(f=>f.check_id.startsWith("AZURE-MFA-")).reduce((a,f)=>{a[f.check_id]=f;return a},{})).filter(f=>f.status==="passed").length},
            {l:"Identity",total:12,pass:Object.values(findings.filter(f=>f.check_id.startsWith("AZURE-IDENTITY-")).reduce((a,f)=>{a[f.check_id]=f;return a},{})).filter(f=>f.status==="passed").length},
            {l:"Apps",total:12,pass:Object.values(findings.filter(f=>f.check_id.startsWith("AZURE-APP-")||f.check_id.startsWith("AZURE-CONSENT-")).reduce((a,f)=>{a[f.check_id]=f;return a},{})).filter(f=>f.status==="passed").length},
          ].map(({l,total,pass})=>{
            const pct=total>0?Math.round((pass/total)*100):0;
            const c=pct>=80?SC.Low:pct>=60?SC.Medium:SC.Critical;
            const r=21,circ=2*Math.PI*r;
            return (
              <div key={l} style={{display:"flex",alignItems:"center",gap:12}}>
                <svg width="48" height="48" viewBox="0 0 48 48">
                  <circle cx="24" cy="24" r={r} fill="none" stroke={MD.surfaceHigh} strokeWidth="4.5"/>
                  <circle cx="24" cy="24" r={r} fill="none" stroke={c} strokeWidth="4.5"
                    strokeLinecap="round" strokeDasharray={`${circ*pct/100} ${circ}`}
                    transform="rotate(-90 24 24)"
                    style={{transition:"stroke-dasharray 0.8s cubic-bezier(0.2,0,0,1)"}}/>
                  <text x="24" y="28" textAnchor="middle" fontSize="10" fontWeight="700" fill={c}>{pct}%</text>
                </svg>
                <div>
                  <div style={{...TYPE.bodyMd,color:MD.onSurfaceVar,fontWeight:600}}>{l}</div>
                  <div style={{...TYPE.labelMd,color:MD.outline,marginTop:1}}>{pass}/{total} pass</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function Findings({findings}) {
  const [q,setQ]=useState(""); const [sf,setSf]=useState("All"); const [st,setSt]=useState("failed");
  const [page,setPage]=useState(1); const [open,setOpen]=useState(null); const PAGE=20;
  const [fixed,setFixed]=useState(()=>{try{return new Set(JSON.parse(localStorage.getItem("eg-fixed")||"[]"))}catch{return new Set()}});
  const tog=(id)=>{const n=new Set(fixed);n.has(id)?n.delete(id):n.add(id);setFixed(n);localStorage.setItem("eg-fixed",JSON.stringify([...n]));};

  const list=findings.filter(f=>{
    const r=REM[f.check_id];const t=r?.title||f.check_id;
    return(sf==="All"||f.severity===sf)&&(st==="All"||f.status===st)
      &&(!q||f.check_id.toLowerCase().includes(q.toLowerCase())||t.toLowerCase().includes(q.toLowerCase()));
  }).sort((a,b)=>b.score-a.score||(SO[a.severity]||4)-(SO[b.severity]||4));

  const pages=Math.ceil(list.length/PAGE);
  const shown=list.slice((page-1)*PAGE,page*PAGE);

  const STATUS_COLOR = { passed: SC.Low, failed: SC.Critical, error: SC.High };
  const STATUS_CONTAINER = { passed: SC_CONTAINER.Low, failed: SC_CONTAINER.Critical, error: SC_CONTAINER.High };

  const csv=()=>{
    const h=["Check ID","Title","Severity","Score","Status","Risk","Steps","Effort"];
    const rows=list.map(f=>{const r=REM[f.check_id];return[f.check_id,r?.title||"",f.severity,f.score,f.status,r?.risk||f.risk_description||"",r?.steps?.join(" | ")||f.remediation_steps||"",f.estimated_effort||""];});
    const c=[h,...rows].map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(",")).join("\n");
    const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([c],{type:"text/csv"}));a.download="findings.csv";a.click();
  };

  return (
    <div style={{animation:"fadeIn 0.25s cubic-bezier(0.2,0,0,1)"}}>
      {/* Toolbar */}
      <div className="eg-findings-toolbar" style={{display:"flex",gap:8,marginBottom:14,flexWrap:"wrap",alignItems:"center"}}>
        <input value={q} onChange={e=>{setQ(e.target.value);setPage(1);}}
          placeholder="Search check ID or title…"
          style={{padding:"9px 14px",background:MD.surfaceHigh,border:`1px solid ${MD.outlineVar}`,
            color:MD.onSurface,borderRadius:MD.radiusXl,...TYPE.bodyMd,width:260,fontFamily:"inherit"}}/>
        {/* MD3 filter chips — outlined resting state, filled tonal when active */}
        {["All","Critical","High","Medium","Low"].map(s=>{
          const active = sf===s;
          const c = SC[s]||MD.primary;
          const cc = SC_CONTAINER[s]||MD.primaryContainer;
          return (
            <button key={s} onClick={()=>{setSf(s);setPage(1);}}
              style={{padding:"7px 14px",borderRadius:MD.radiusXl,...TYPE.labelLg,fontWeight:600,
                background:active?cc:"transparent",
                border:`1px solid ${active?cc:MD.outlineVar}`,
                color:active?c:MD.onSurfaceVar,cursor:"pointer",transition:"all 0.15s"}}>{s}</button>
          );
        })}
        <select value={st} onChange={e=>{setSt(e.target.value);setPage(1);}}
          style={{padding:"8px 12px",background:MD.surfaceHigh,border:`1px solid ${MD.outlineVar}`,
            color:MD.onSurfaceVar,borderRadius:MD.radiusMd,...TYPE.labelLg,fontFamily:"inherit"}}>
          {["failed","All","passed","error"].map(s=><option key={s}>{s}</option>)}
        </select>
        <div style={{flex:1}}/>
        <span style={{...TYPE.labelMd,color:MD.outline}}>{shown.length}/{list.length}</span>
        <button onClick={csv} style={{padding:"8px 16px",background:MD.surfaceHigh,
          border:`1px solid ${MD.outlineVar}`,color:MD.onSurfaceVar,borderRadius:MD.radiusXl,
          ...TYPE.labelLg,fontWeight:600,cursor:"pointer"}}>↓ CSV</button>
      </div>

      {/* List */}
      <div style={{display:"flex",flexDirection:"column",gap:6}}>
        {shown.length===0&&<div style={{textAlign:"center",padding:56,color:MD.outline,...TYPE.bodyMd}}>No findings match filter</div>}
        {shown.map(f=>{
          const r=REM[f.check_id];const isO=open===f.check_id;const isFx=fixed.has(f.check_id);
          const sc=sev(f);
          const stColor=STATUS_COLOR[f.status]||MD.outline;
          const stContainer=STATUS_CONTAINER[f.status]||MD.surfaceHigh;
          return (
            <div key={f.check_id} style={{borderRadius:MD.radiusMd,overflow:"hidden",
              background:MD.surfaceCont,boxShadow:elevation(isO?2:1),
              transition:"box-shadow 0.15s cubic-bezier(0.2,0,0,1)"}}>
              <div onClick={()=>setOpen(isO?null:f.check_id)}
                style={{display:"grid",gridTemplateColumns:"4px 168px 1fr auto auto auto auto",
                  alignItems:"center",gap:12,padding:"12px 16px",cursor:"pointer"}}>
                <div style={{height:"100%",minHeight:30,background:sc,borderRadius:2}}/>
                <span style={{...TYPE.labelMd,color:MD.outline,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{f.check_id}</span>
                <span style={{...TYPE.bodyMd,color:isFx?MD.outlineVar:MD.onSurface,fontWeight:500,
                  overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",
                  textDecoration:isFx?"line-through":"none"}}>
                  {r?.title||f.check_id}
                  {f.ai_false_positive_likelihood&&f.ai_false_positive_likelihood!=="none"&&(
                    <span title={`AI flagged this as a ${f.ai_false_positive_likelihood} false positive`}
                      style={{marginLeft:8,fontSize:11,color:SC.Medium}}>⚠ AI flag</span>
                  )}
                </span>
                <Badge label={f.severity} color={sc} container={sevContainer(f)} small/>
                <Badge label={f.status==="passed"?"✓ "+f.status:f.status} color={stColor} container={stContainer} small/>
                <div style={{width:76}}><ScoreBar score={f.score}/></div>
                <div style={{display:"flex",gap:6,alignItems:"center"}}>
                  <button onClick={e=>{e.stopPropagation();tog(f.check_id);}}
                    style={{padding:"4px 10px",background:isFx?SC_CONTAINER.Low:"transparent",
                      border:`1px solid ${isFx?SC_CONTAINER.Low:MD.outlineVar}`,
                      color:isFx?SC.Low:MD.outline,borderRadius:MD.radiusSm,...TYPE.labelMd,cursor:"pointer"}}>
                    {isFx?"✓ Fixed":"Mark fixed"}
                  </button>
                  <span style={{color:MD.outline,fontSize:11,transform:isO?"rotate(180deg)":"none",transition:"transform 0.2s"}}>▼</span>
                </div>
              </div>

              {isO&&(
                <div style={{borderTop:`1px solid ${MD.outlineVar}`,padding:"18px 18px 18px 30px",
                  background:MD.surfaceDim}}>
                  {r?(
                    <>
                      <div style={{marginBottom:16}}>
                        <div style={{...TYPE.labelSm,color:SC.Medium,marginBottom:8}}>Why this matters</div>
                        <p style={{...TYPE.bodyMd,color:MD.onSurfaceVar,lineHeight:1.8,margin:0}}>{r.risk}</p>
                      </div>
                      <div style={{marginBottom:14}}>
                        <div style={{...TYPE.labelSm,color:SC.Low,marginBottom:10}}>How to fix — step by step</div>
                        <div style={{display:"flex",flexDirection:"column",gap:9}}>
                          {r.steps.map((s,i)=>(
                            <div key={i} style={{display:"flex",gap:11}}>
                              <div style={{width:22,height:22,borderRadius:"50%",
                                background:MD.primaryContainer,
                                display:"flex",alignItems:"center",justifyContent:"center",
                                fontSize:10,fontWeight:700,color:MD.onPrimaryContainer,flexShrink:0}}>{i+1}</div>
                              <p style={{...TYPE.bodyMd,color:MD.onSurfaceVar,lineHeight:1.7,margin:0,paddingTop:2}}>{s}</p>
                            </div>
                          ))}
                        </div>
                        {r.ref&&<a href={r.ref} target="_blank"
                          style={{display:"inline-flex",alignItems:"center",gap:5,
                            marginTop:14,...TYPE.labelLg,color:MD.primary,textDecoration:"none",
                            padding:"6px 14px",border:`1px solid ${MD.primaryContainer}`,borderRadius:MD.radiusXl}}>
                          ↗ Microsoft documentation
                        </a>}
                      </div>
                    </>
                  ):(
                    <>
                      {f.risk_description&&<div style={{marginBottom:14}}>
                        <div style={{...TYPE.labelSm,color:SC.Medium,marginBottom:8}}>Risk</div>
                        <p style={{...TYPE.bodyMd,color:MD.onSurfaceVar,lineHeight:1.7,margin:0}}>{f.risk_description}</p>
                      </div>}
                      {f.remediation_steps&&<div style={{marginBottom:14}}>
                        <div style={{...TYPE.labelSm,color:SC.Low,marginBottom:8}}>Remediation</div>
                        <p style={{...TYPE.bodyMd,color:MD.onSurfaceVar,lineHeight:1.7,margin:0}}>{f.remediation_steps}</p>
                      </div>}

                    </>
                  )}
                  {(f.ai_explanation||f.ai_false_positive_likelihood)&&(() => {
                    const fp = f.ai_false_positive_likelihood;
                    const flagged = fp && fp !== "none";
                    // Confidence in the DETERMINISTIC verdict, inverted from
                    // the AI's false-positive likelihood: "likely FP" means
                    // low confidence the failed verdict is real.
                    const conf = fp === "likely" ? 25 : fp === "possible" ? 60 : 92;
                    const confColor = conf >= 80 ? SC.Low : conf >= 50 ? SC.Medium : SC.Critical;
                    const queries = (() => {
                      try { return f.ai_queries_made ? JSON.parse(f.ai_queries_made) : []; }
                      catch { return []; }
                    })();
                    const R=26, C=2*Math.PI*R;
                    return (
                      <div style={{marginBottom:14,borderRadius:MD.radiusLg,overflow:"hidden",
                        background:`linear-gradient(135deg, ${MD.primaryContainer}40, ${MD.primaryContainer}12)`,
                        border:`1px solid ${flagged?SC.Medium+"55":MD.primary+"30"}`}}>

                        <div style={{display:"flex",alignItems:"center",gap:10,padding:"10px 16px",
                          borderBottom:`1px solid ${MD.primary}20`}}>
                          <span style={{fontSize:15}}>✨</span>
                          <span style={{...TYPE.labelLg,color:MD.primary,fontWeight:700,letterSpacing:"0.03em"}}>
                            AI ANALYSIS
                          </span>
                          {queries.length>0&&(
                            <span style={{...TYPE.labelSm,color:MD.onPrimaryContainer,
                              background:MD.primaryContainer,padding:"2px 8px",borderRadius:MD.radiusXl}}>
                              🔎 AGENT — {queries.length} live check{queries.length!==1?"s":""}
                            </span>
                          )}
                          <div style={{flex:1}}/>
                          <span style={{...TYPE.labelSm,color:MD.outlineVar}}>advisory only</span>
                        </div>

                        <div style={{display:"flex",gap:16,padding:"14px 16px",alignItems:"flex-start"}}>
                          {/* Confidence gauge — infographic, not decoration:
                              encodes how much the AI trusts the deterministic
                              verdict, at a glance, before reading any text. */}
                          <div style={{flexShrink:0,textAlign:"center",width:76}}>
                            <svg width="68" height="68" viewBox="0 0 68 68">
                              <circle cx="34" cy="34" r={R} fill="none" stroke={MD.surfaceHigh} strokeWidth="6"/>
                              <circle cx="34" cy="34" r={R} fill="none" stroke={confColor} strokeWidth="6"
                                strokeLinecap="round" strokeDasharray={`${C*conf/100} ${C}`}
                                transform="rotate(-90 34 34)"
                                style={{transition:"stroke-dasharray 0.9s cubic-bezier(0.2,0,0,1)"}}/>
                              <text x="34" y="31" textAnchor="middle" fontSize="15" fontWeight="700" fill={confColor}>{conf}%</text>
                              <text x="34" y="43" textAnchor="middle" fontSize="7" fill={MD.outline}>CONFIDENCE</text>
                            </svg>
                            <div style={{...TYPE.labelSm,color:confColor,marginTop:2}}>
                              {conf>=80?"Verdict solid":conf>=50?"Verify this":"Likely wrong"}
                            </div>
                          </div>

                          <div style={{flex:1,minWidth:0}}>
                            {f.ai_explanation&&(
                              <p style={{...TYPE.bodyMd,color:MD.onSurface,lineHeight:1.7,margin:"0 0 10px"}}>
                                {f.ai_explanation}
                              </p>
                            )}

                            {flagged&&(
                              <div style={{padding:"10px 12px",borderRadius:MD.radiusMd,
                                background:SC_CONTAINER.Medium+"55",borderLeft:`3px solid ${SC.Medium}`}}>
                                <div style={{...TYPE.labelSm,color:SC.Medium,marginBottom:5}}>
                                  ⚠ RECOMMENDED ACTION — {fp==="likely"?"likely":"possible"} false positive
                                </div>
                                <p style={{...TYPE.bodyMd,color:MD.onSurfaceVar,lineHeight:1.65,margin:0}}>
                                  {f.ai_false_positive_reason || "Flagged as uncertain, but no specific reason was given."}
                                </p>
                                <p style={{...TYPE.labelMd,color:MD.outline,margin:"8px 0 0"}}>
                                  Verify manually before treating as resolved — the stored verdict is unchanged.
                                </p>
                              </div>
                            )}

                            {queries.length>0&&(
                              <div style={{marginTop:10}}>
                                <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:5}}>
                                  Live tenant lookups performed
                                </div>
                                <div style={{display:"flex",flexWrap:"wrap",gap:5}}>
                                  {queries.map((q,i)=>(
                                    <code key={i} style={{...TYPE.labelMd,color:MD.onPrimaryContainer,
                                      background:MD.primaryContainer+"70",padding:"3px 8px",
                                      borderRadius:MD.radiusSm,fontFamily:"'Roboto Mono',monospace"}}>{q}</code>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })()}
                  {f.affected_resources?.length>0&&(
                    <div>
                      <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:8}}>
                        Affected [{f.affected_resources.length}]
                      </div>
                      <div style={{background:MD.surfaceCont,borderRadius:MD.radiusSm,
                        padding:"10px 12px",maxHeight:110,overflowY:"auto"}}>
                        {f.affected_resources.slice(0,8).map((r,i)=>(
                          <div key={i} style={{...TYPE.bodySm,color:MD.outline,marginBottom:3,fontFamily:"'Roboto Mono',ui-monospace,monospace"}}>
                            {typeof r==="string"?r:Object.entries(r).map(([k,v])=>`${k}: ${v}`).join("  ·  ")}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {f.evidence&&Object.keys(f.evidence).filter(k=>k!=="error").length>0&&(
                    <div style={{marginTop:12}}>
                      <div style={{...TYPE.labelSm,color:MD.outlineVar,marginBottom:6}}>Evidence</div>
                      <div style={{fontFamily:"'Roboto Mono',ui-monospace,monospace",fontSize:10.5,color:MD.outlineVar,lineHeight:1.6}}>
                        {JSON.stringify(f.evidence,null,2).split("\n").slice(0,5).join("\n")}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
      {pages>1&&(
        <div style={{display:"flex",gap:6,justifyContent:"center",marginTop:16}}>
          {Array.from({length:pages},(_,i)=>(
            <button key={i} onClick={()=>setPage(i+1)}
              style={{padding:"6px 12px",borderRadius:MD.radiusXl,...TYPE.labelLg,
                background:page===i+1?MD.primaryContainer:"transparent",
                border:`1px solid ${page===i+1?MD.primaryContainer:MD.outlineVar}`,
                color:page===i+1?MD.onPrimaryContainer:MD.outline,cursor:"pointer"}}>{i+1}</button>
          ))}
        </div>
      )}
    </div>
  );
}

function Compliance({findings}) {
  const [fw,setFw]=useState("NIST CSF");
  const sm=Object.fromEntries(findings.map(f=>[f.check_id,f.status]));
  return (
    <div style={{animation:"fadeIn 0.25s cubic-bezier(0.2,0,0,1)"}}>
      <div className="eg-compliance-tabs" style={{display:"flex",gap:8,marginBottom:18}}>
        {Object.keys(FW).map(f=>{
          const active = fw===f;
          return (
            <button key={f} onClick={()=>setFw(f)}
              style={{padding:"8px 16px",borderRadius:MD.radiusXl,...TYPE.labelLg,fontWeight:600,
                background:active?MD.primaryContainer:"transparent",
                border:`1px solid ${active?MD.primaryContainer:MD.outlineVar}`,
                color:active?MD.onPrimaryContainer:MD.outline,cursor:"pointer",transition:"all 0.15s"}}>{f}
            </button>
          );
        })}
      </div>
      {Object.entries(FW[fw]).map(([domain,ids])=>{
        const tot=ids.length;
        const pas=ids.filter(id=>sm[id]==="passed").length;
        const pct=tot?Math.round((pas/tot)*100):0;
        const c=pct>=80?SC.Low:pct>=60?SC.Medium:SC.Critical;
        return (
          <div key={domain} style={{background:MD.surfaceCont,boxShadow:elevation(1),
            borderRadius:MD.radiusLg,padding:18,marginBottom:10}}>
            <div style={{display:"flex",alignItems:"center",gap:14,marginBottom:10}}>
              <div style={{flex:1,...TYPE.titleSm,color:MD.onSurface}}>{domain}</div>
              <span style={{...TYPE.labelMd,color:MD.outline}}>{pas}/{tot} controls</span>
              <span style={{fontSize:16,fontWeight:700,color:c}}>{pct}%</span>
            </div>
            <div style={{height:6,background:MD.surfaceDim,borderRadius:3,marginBottom:12,overflow:"hidden"}}>
              <div style={{height:"100%",borderRadius:3,background:c,width:`${pct}%`,
                transition:"width 0.8s cubic-bezier(0.2,0,0,1)"}}/>
            </div>
            <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
              {ids.map(id=>{
                const s=sm[id];
                const co=s==="passed"?SC.Low:s==="failed"?SC.Critical:MD.outlineVar;
                const cco=s==="passed"?SC_CONTAINER.Low:s==="failed"?SC_CONTAINER.Critical:MD.surfaceHigh;
                return <span key={id} style={{fontFamily:"'Roboto Mono',ui-monospace,monospace",fontSize:9.5,
                  padding:"3px 8px",borderRadius:MD.radiusSm,background:cco,color:co,fontWeight:600}}>{id}</span>;
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Remediation({findings}) {
  const fail = findings.filter(f=>f.status==="failed");
  const [expanded, setExpanded] = React.useState(null);
  const [effortFilter, setEffortFilter] = React.useState("All");
  const [hoverKey, setHoverKey] = React.useState(null);

  const groups = {
    Low:      {label:"Quick wins",   color:SC.Low,    icon:"⚡", desc:"Under 1 hour"},
    Moderate: {label:"This week",    color:SC.Medium, icon:"📅", desc:"1–7 days"},
    High:     {label:"Project work", color:SC.Critical,icon:"🏗", desc:"Multi-week"},
  };

  fail.forEach(f => {
    const e = f.estimated_effort||"Moderate";
    if(groups[e]) groups[e].items = [...(groups[e].items||[]), f];
  });
  Object.values(groups).forEach(g => {
    g.items = (g.items||[]).sort((a,b)=>b.score-a.score);
  });

  const shown = effortFilter==="All" ? [...fail].sort((a,b)=>b.score-a.score)
    : (groups[effortFilter]?.items||[]);

  if (fail.length === 0) return (
    <div style={{textAlign:"center",padding:96,animation:"fadeIn 0.3s cubic-bezier(0.2,0,0,1)"}}>
      <div style={{fontSize:48,marginBottom:18}}>🎉</div>
      <div style={{...TYPE.titleMd,color:SC.Low}}>All checks passing</div>
    </div>
  );

  return (
    <div style={{animation:"fadeIn 0.3s cubic-bezier(0.2,0,0,1)"}}>
      {/* Summary cards — MD3 elevation lifts on hover, a real interaction
          affordance rather than a static border swap */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10,marginBottom:18}} className="eg-chart-row">
        {Object.entries(groups).map(([key,g])=>{
          const count = g.items?.length||0;
          const pct = fail.length ? Math.round((count/fail.length)*100) : 0;
          const r=17, circ=2*Math.PI*r;
          const active = effortFilter===key;
          const hovered = hoverKey===key;
          return (
            <button key={key}
              onClick={()=>setEffortFilter(active?"All":key)}
              onMouseEnter={()=>setHoverKey(key)} onMouseLeave={()=>setHoverKey(null)}
              style={{background:active?g.color+"14":MD.surfaceCont,
                border:`1px solid ${active?g.color:"transparent"}`,
                boxShadow:elevation(hovered||active?2:1),
                borderRadius:MD.radiusLg,padding:"16px 18px",cursor:"pointer",textAlign:"left",
                transition:"box-shadow 0.15s cubic-bezier(0.2,0,0,1), background 0.15s"}}>
              <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:10}}>
                <span style={{fontSize:20}}>{g.icon}</span>
                <div style={{flex:1}}>
                  <div style={{...TYPE.titleSm,color:active?g.color:MD.onSurface}}>{g.label}</div>
                  <div style={{...TYPE.labelMd,color:MD.outline,marginTop:1}}>{g.desc}</div>
                </div>
                <svg width="42" height="42" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r={r} fill="none" stroke={MD.surfaceHigh} strokeWidth="4"/>
                  <circle cx="21" cy="21" r={r} fill="none" stroke={g.color} strokeWidth="4"
                    strokeLinecap="round" strokeDasharray={`${circ*pct/100} ${circ}`}
                    transform="rotate(-90 21 21)" style={{transition:"stroke-dasharray 0.8s cubic-bezier(0.2,0,0,1)"}}/>
                  <text x="21" y="25" textAnchor="middle" fontSize="9.5" fontWeight="700" fill={g.color}>{pct}%</text>
                </svg>
              </div>
              <div style={{fontSize:26,fontWeight:700,color:g.color}}>{count}
                <span style={{...TYPE.labelMd,color:MD.outline,fontWeight:500,marginLeft:8}}>
                  finding{count!==1?"s":""}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Filter bar */}
      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:16,flexWrap:"wrap"}}>
        <span style={{...TYPE.labelMd,color:MD.outline}}>Filter</span>
        {["All",...Object.keys(groups)].map(k=>{
          const active = effortFilter===k;
          const c = k==="All"?MD.primary:groups[k]?.color;
          return (
            <button key={k} onClick={()=>setEffortFilter(k)}
              style={{padding:"6px 14px",borderRadius:MD.radiusXl,border:"none",cursor:"pointer",
                ...TYPE.labelLg,fontWeight:active?700:500,
                background:active?c+"20":"transparent",
                color:active?c:MD.outline}}>
              {k==="All"?`All (${fail.length})`:groups[k]?.label+` (${groups[k]?.items?.length||0})`}
            </button>
          );
        })}
        <div style={{flex:1}}/>
        <span style={{...TYPE.labelMd,color:MD.outlineVar}}>
          {shown.length} items · click to expand
        </span>
      </div>

      {/* Collapsed list */}
      <div style={{display:"flex",flexDirection:"column",gap:5}}>
        {shown.map((f)=>{
          const r = REM[f.check_id];
          const sc = sev(f);
          const effort = f.estimated_effort||"Moderate";
          const g = groups[effort]||groups.Moderate;
          const isOpen = expanded===f.check_id;
          const hasContent = r?.steps?.length>0 || f.remediation_steps;

          return (
            <div key={f.check_id} style={{background:MD.surfaceCont,
              borderRadius:MD.radiusMd,overflow:"hidden",boxShadow:elevation(isOpen?2:1),
              borderLeft:`3px solid ${sc}`,transition:"box-shadow 0.15s cubic-bezier(0.2,0,0,1)"}}>
              <button onClick={()=>setExpanded(isOpen?null:f.check_id)}
                style={{width:"100%",background:"none",border:"none",cursor:"pointer",
                  padding:"13px 18px",textAlign:"left",
                  display:"flex",alignItems:"center",gap:12}}>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}>
                    <span style={{...TYPE.labelMd,color:MD.outlineVar}}>{f.check_id}</span>
                    <Badge label={f.severity} color={sc} container={sevContainer(f)} small/>
                    <span style={{...TYPE.labelMd,fontWeight:600,padding:"2px 8px",borderRadius:MD.radiusSm,
                      background:g.color+"14",color:g.color}}>
                      {g.icon} {g.label}
                    </span>
                    {!hasContent&&<span style={{...TYPE.labelMd,color:MD.outlineVar}}>· no steps available</span>}
                  </div>
                  <div style={{...TYPE.bodyLg,color:MD.onSurface,fontWeight:600,overflow:"hidden",
                    textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                    {r?.title||f.check_id}
                  </div>
                </div>
                <div style={{width:80,flexShrink:0}}><ScoreBar score={f.score}/></div>
                <span style={{color:MD.outline,fontSize:12,flexShrink:0,
                  transform:isOpen?"rotate(180deg)":"none",transition:"transform 0.2s"}}>▼</span>
              </button>

              {isOpen&&(
                <div style={{borderTop:`1px solid ${MD.outlineVar}`,padding:"14px 18px 16px",
                  background:MD.surfaceDim}}>
                  {hasContent ? (
                    <>
                      {(r?.risk||f.risk_description)&&(
                        <div style={{marginBottom:14}}>
                          <div style={{...TYPE.labelSm,color:SC.Medium,marginBottom:7}}>Why this matters</div>
                          <p style={{...TYPE.bodyMd,color:MD.onSurfaceVar,lineHeight:1.7,margin:0}}>
                            {r?.risk||f.risk_description}
                          </p>
                        </div>
                      )}
                      <div style={{background:MD.surfaceCont,borderRadius:MD.radiusMd,padding:"12px 16px"}}>
                        <div style={{...TYPE.labelSm,color:SC.Low,marginBottom:11}}>Action required</div>
                        {r?.steps ? (
                          <div style={{display:"flex",flexDirection:"column",gap:7}}>
                            {r.steps.map((s,i)=>(
                              <div key={i} style={{display:"flex",gap:9,alignItems:"flex-start"}}>
                                <div style={{width:20,height:20,borderRadius:"50%",
                                  background:MD.primaryContainer,
                                  display:"flex",alignItems:"center",justifyContent:"center",
                                  fontSize:9.5,fontWeight:700,color:MD.onPrimaryContainer,flexShrink:0}}>{i+1}</div>
                                <span style={{...TYPE.bodyMd,color:MD.onSurfaceVar,lineHeight:1.65,paddingTop:1}}>{s}</span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p style={{...TYPE.bodyMd,color:MD.onSurfaceVar,lineHeight:1.65,margin:0}}>
                            {f.remediation_steps}
                          </p>
                        )}
                        {r?.ref&&(
                          <a href={r.ref} target="_blank"
                            style={{display:"inline-block",marginTop:12,...TYPE.labelMd,
                              color:MD.primary,textDecoration:"none"}}>
                            ↗ Microsoft documentation
                          </a>
                        )}
                      </div>
                      {f.affected_resources?.length>0&&(
                        <div style={{marginTop:10,...TYPE.labelMd,color:MD.outlineVar}}>
                          ⚠ {f.affected_resources.length} affected resource{f.affected_resources.length!==1?"s":""}
                          {f.affected_resources[0]&&typeof f.affected_resources[0]==="object"&&
                            ` — ${Object.values(f.affected_resources[0])[0]}`}
                        </div>
                      )}
                    </>
                  ) : (
                    <div style={{padding:"4px 0"}}>
                      <div style={{...TYPE.labelSm,color:MD.outlineVar,marginBottom:9}}>Remediation</div>
                      <p style={{...TYPE.bodyMd,color:MD.outline,lineHeight:1.65,margin:0}}>
                        Review this control in the Microsoft Entra ID portal. Check the Findings tab
                        for the raw evidence, then consult{" "}
                        <a href="https://learn.microsoft.com/en-us/entra/identity/" target="_blank"
                          style={{color:MD.primary}}>Microsoft documentation</a>
                        {" "}for remediation steps specific to{" "}
                        <code style={{fontFamily:"'Roboto Mono',ui-monospace,monospace",fontSize:11.5,
                          color:MD.onSurfaceVar}}>{f.check_id}</code>.
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Users({authUser}) {
  const [users, setUsers] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [showForm, setShowForm] = React.useState(false);
  const [editUser, setEditUser] = React.useState(null);
  const [form, setForm] = React.useState({username:"",name:"",password:"",role:"viewer"});
  const [saving, setSaving] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [msg, setMsg] = React.useState("");

  const isAdmin = authUser?.role==="admin" || authUser?.auth_type==="local";

  const load = async () => {
    try {
      const r = await authFetch("/api/v1/users");
      if (!r.ok) { const txt = await r.text(); throw new Error(txt); }
      const data = await r.json();
      setUsers(data.items || []);
    } catch (e) {
      console.error("Load users failed:", e);
      setErr("Could not load users. Admin access required.");
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(()=>{ load(); },[]);

  const openCreate = () => {
    setForm({username:"",name:"",password:"",role:"viewer"});
    setEditUser(null); setErr(""); setShowForm(true);
  };

  const openEdit = (u) => {
    setForm({username:u.username,name:u.name,password:"",role:u.role});
    setEditUser(u); setErr(""); setShowForm(true);
  };

  const save = async () => {
    setSaving(true); setErr("");
    try {
      const token = getStoredToken();
      const headers = {"Content-Type":"application/json",...(token?{"Authorization":"Bearer "+token}:{})};
      if (editUser) {
        const body = {};
        if(form.name!==editUser.name) body.name=form.name;
        if(form.password) body.password=form.password;
        if(form.role!==editUser.role) body.role=form.role;
        const r = await fetch(`/api/v1/users/${editUser.username}`,{method:"PUT",headers,body:JSON.stringify(body)});
        if(!r.ok){const d=await r.json();throw new Error(d.detail||"Update failed");}
      } else {
        if(!form.username||!form.name||!form.password) throw new Error("All fields required");
        const r = await fetch("/api/v1/users",{method:"POST",headers,body:JSON.stringify(form)});
        if(!r.ok){const d=await r.json();throw new Error(d.detail||"Create failed");}
      }
      setShowForm(false); setMsg(editUser?"User updated":"User created"); load();
      setTimeout(()=>setMsg(""),3000);
    } catch(e) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const deleteUser = async (username) => {
    if(!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    try {
      const token = getStoredToken();
      const r = await fetch(`/api/v1/users/${username}`,{
        method:"DELETE",headers:token?{"Authorization":"Bearer "+token}:{}
      });
      if(!r.ok){const d=await r.json();throw new Error(d.detail||"Delete failed");}
      setMsg("User deleted"); load(); setTimeout(()=>setMsg(""),3000);
    } catch(e) { setErr(e.message); }
  };

  const toggleActive = async (u) => {
    try {
      const token = getStoredToken();
      const r = await fetch(`/api/v1/users/${u.username}`,{
        method:"PUT",
        headers:{"Content-Type":"application/json",...(token?{"Authorization":"Bearer "+token}:{})},
        body:JSON.stringify({active:!u.active})
      });
      if(!r.ok){const d=await r.json();throw new Error(d.detail||"Update failed");}
      load();
    } catch(e) { setErr(e.message); }
  };

  // Role color kept distinct from severity semantics — admin isn't "danger",
  // it's a role tier, so it takes the primary hue rather than SC.Critical
  const ROLE_COLOR = {admin:MD.primary, viewer:SC.Info};
  const ROLE_CONTAINER = {admin:MD.primaryContainer, viewer:SC_CONTAINER.Info};

  return (
    <div style={{animation:"fadeIn 0.3s cubic-bezier(0.2,0,0,1)"}}>
      {/* Header */}
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:22}}>
        <div>
          <div style={{...TYPE.titleLg,color:MD.onSurface}}>User management</div>
          <div style={{...TYPE.bodySm,color:MD.outline,marginTop:3}}>
            Manage who can access this EntraGuard instance. Auth must be enabled in .env.
          </div>
        </div>
        <div style={{flex:1}}/>
        {isAdmin&&(
          <button onClick={openCreate}
            style={{padding:"10px 20px",background:MD.primaryDim,
              border:"none",borderRadius:MD.radiusXl,color:MD.surfaceDim,...TYPE.labelLg,fontWeight:700,
              cursor:"pointer",boxShadow:elevation(1)}}>
            + Add user
          </button>
        )}
      </div>

      {/* Notices */}
      {msg&&<div style={{marginBottom:14,padding:"10px 16px",background:SC_CONTAINER.Low,
        borderRadius:MD.radiusMd,...TYPE.bodyMd,color:SC.Low}}>{msg}</div>}
      {err&&<div style={{marginBottom:14,padding:"10px 16px",background:SC_CONTAINER.Critical,
        borderRadius:MD.radiusMd,...TYPE.bodyMd,color:SC.Critical}}>{err}</div>}

      {/* Info banner */}
      <div style={{marginBottom:18,padding:"12px 16px",background:SC_CONTAINER.Medium,
        borderRadius:MD.radiusMd,...TYPE.bodySm,color:SC.Medium,lineHeight:1.6}}>
        Users added here can sign in when <code style={{fontFamily:"'Roboto Mono',ui-monospace,monospace"}}>AUTH_ENABLED=true</code> is set in .env.
        The built-in admin from <code style={{fontFamily:"'Roboto Mono',ui-monospace,monospace"}}>LOCAL_ADMIN_USERNAME/PASSWORD</code> always has access.
      </div>

      {/* User list */}
      {loading ? (
        <div style={{textAlign:"center",padding:48,color:MD.outline}}>Loading users…</div>
      ) : (
        <div style={{display:"flex",flexDirection:"column",gap:5}}>
          {users.map(u=>(
            <div key={u.username} style={{background:MD.surfaceCont,boxShadow:elevation(1),
              borderRadius:MD.radiusMd,padding:"14px 18px",display:"flex",alignItems:"center",gap:14,
              opacity:u.active?1:0.55}}>
              {/* Avatar — MD3 tonal circle, no gradient */}
              <div style={{width:40,height:40,borderRadius:"50%",
                background:ROLE_CONTAINER[u.role]||MD.surfaceHigh,
                display:"flex",alignItems:"center",justifyContent:"center",
                fontSize:14,fontWeight:700,color:ROLE_COLOR[u.role]||MD.outline,flexShrink:0}}>
                {(u.name||u.username).slice(0,1).toUpperCase()}
              </div>
              <div style={{flex:1,minWidth:0}}>
                <div style={{...TYPE.bodyLg,color:MD.onSurface,fontWeight:600}}>{u.name}</div>
                <div style={{display:"flex",alignItems:"center",gap:9,marginTop:3}}>
                  <span style={{...TYPE.labelMd,color:MD.outline}}>{u.username}</span>
                  <Badge label={u.role} color={ROLE_COLOR[u.role]} container={ROLE_CONTAINER[u.role]} small/>
                  {u.builtin&&<span style={{...TYPE.labelMd,color:MD.outlineVar}}>Built-in</span>}
                  {!u.active&&<span style={{...TYPE.labelMd,color:SC.Critical}}>Disabled</span>}
                </div>
              </div>
              {isAdmin&&!u.builtin&&(
                <div style={{display:"flex",gap:7,flexShrink:0}}>
                  <button onClick={()=>toggleActive(u)}
                    style={{padding:"6px 14px",background:"transparent",
                      border:`1px solid ${u.active?MD.outlineVar:SC_CONTAINER.Low}`,
                      color:u.active?MD.outlineVar:SC.Low,borderRadius:MD.radiusXl,...TYPE.labelMd,fontWeight:600,cursor:"pointer"}}>
                    {u.active?"Disable":"Enable"}
                  </button>
                  <button onClick={()=>openEdit(u)}
                    style={{padding:"6px 14px",background:"transparent",
                      border:`1px solid ${MD.outlineVar}`,color:MD.onSurfaceVar,borderRadius:MD.radiusXl,...TYPE.labelMd,fontWeight:600,cursor:"pointer"}}>
                    Edit
                  </button>
                  <button onClick={()=>deleteUser(u.username)}
                    style={{padding:"6px 14px",background:"transparent",
                      border:`1px solid ${SC_CONTAINER.Critical}`,color:SC.Critical,borderRadius:MD.radiusXl,...TYPE.labelMd,fontWeight:600,cursor:"pointer"}}>
                    Delete
                  </button>
                </div>
              )}
            </div>
          ))}
          {users.length===0&&(
            <div style={{textAlign:"center",padding:48,color:MD.outlineVar,...TYPE.bodyMd}}>
              No additional users. Click "Add user" to create one.
            </div>
          )}
        </div>
      )}

      {/* Create/edit dialog — MD3 scrim + elevated dp5 surface */}
      {showForm&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.5)",display:"flex",
          alignItems:"center",justifyContent:"center",zIndex:999}}
          onClick={()=>setShowForm(false)}>
          <div onClick={e=>e.stopPropagation()}
            style={{background:MD.surfaceHigh,borderRadius:MD.radiusXl,boxShadow:elevation(5),
              width:"min(460px,95vw)",padding:28}}>
            <div style={{...TYPE.titleMd,color:MD.onSurface,marginBottom:22}}>
              {editUser?"Edit user":"Add new user"}
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:16}}>
              {!editUser&&(
                <div>
                  <div style={{...TYPE.labelMd,color:MD.outline,marginBottom:7}}>Username</div>
                  <input value={form.username} onChange={e=>setForm({...form,username:e.target.value})}
                    placeholder="john.smith"
                    style={{width:"100%",padding:"11px 14px",background:MD.surfaceDim,
                      border:`1px solid ${MD.outlineVar}`,borderRadius:MD.radiusMd,color:MD.onSurface,...TYPE.bodyMd,
                      boxSizing:"border-box"}}/>
                </div>
              )}
              <div>
                <div style={{...TYPE.labelMd,color:MD.outline,marginBottom:7}}>Display name</div>
                <input value={form.name} onChange={e=>setForm({...form,name:e.target.value})}
                  placeholder="John Smith"
                  style={{width:"100%",padding:"11px 14px",background:MD.surfaceDim,
                    border:`1px solid ${MD.outlineVar}`,borderRadius:MD.radiusMd,color:MD.onSurface,...TYPE.bodyMd,
                    boxSizing:"border-box"}}/>
              </div>
              <div>
                <div style={{...TYPE.labelMd,color:MD.outline,marginBottom:7}}>
                  {editUser?"New password (leave blank to keep current)":"Password"}
                </div>
                <input type="password" value={form.password}
                  onChange={e=>setForm({...form,password:e.target.value})}
                  placeholder={editUser?"Unchanged":"Minimum 8 characters"}
                  style={{width:"100%",padding:"11px 14px",background:MD.surfaceDim,
                    border:`1px solid ${MD.outlineVar}`,borderRadius:MD.radiusMd,color:MD.onSurface,...TYPE.bodyMd,
                    boxSizing:"border-box"}}/>
              </div>
              <div>
                <div style={{...TYPE.labelMd,color:MD.outline,marginBottom:9}}>Role</div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
                  {[["admin","Admin","Full access — can scan, manage users, and view all findings"],
                    ["viewer","Viewer","Read-only — can view findings and reports but cannot scan or manage users"]
                  ].map(([val,label,desc])=>{
                    const active = form.role===val;
                    const c = ROLE_COLOR[val];
                    return (
                      <button key={val} onClick={()=>setForm({...form,role:val})}
                        style={{padding:"12px 14px",textAlign:"left",borderRadius:MD.radiusMd,cursor:"pointer",
                          background:active?c+"16":MD.surfaceDim,
                          border:`1px solid ${active?c:MD.outlineVar}`,
                          color:active?c:MD.outline,transition:"all 0.15s"}}>
                        <div style={{fontWeight:700,fontSize:13}}>{label}</div>
                        <div style={{...TYPE.labelMd,marginTop:4,lineHeight:1.5,
                          color:active?c+"cc":MD.outlineVar}}>{desc}</div>
                      </button>
                    );
                  })}
                </div>
              </div>
              {err&&<div style={{...TYPE.bodySm,color:SC.Critical,padding:"10px 14px",
                background:SC_CONTAINER.Critical,borderRadius:MD.radiusMd}}>{err}</div>}
              <div style={{display:"flex",gap:10,justifyContent:"flex-end",marginTop:6}}>
                <button onClick={()=>setShowForm(false)}
                  style={{padding:"9px 18px",background:"transparent",border:"none",
                    color:MD.onSurfaceVar,borderRadius:MD.radiusXl,...TYPE.labelLg,fontWeight:600,cursor:"pointer"}}>Cancel</button>
                <button onClick={save} disabled={saving}
                  style={{padding:"9px 22px",background:saving?MD.surfaceHigh:MD.primaryDim,
                    border:"none",color:saving?MD.outline:MD.surfaceDim,borderRadius:MD.radiusXl,...TYPE.labelLg,fontWeight:700,
                    cursor:saving?"not-allowed":"pointer",boxShadow:saving?"none":elevation(1)}}>
                  {saving?"Saving…":editUser?"Save changes":"Create user"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function History({runs}) {
  return (
    <div style={{animation:"fadeIn 0.25s cubic-bezier(0.2,0,0,1)",display:"flex",flexDirection:"column",gap:6}}>
      {runs.length===0&&<div style={{textAlign:"center",padding:56,color:MD.outlineVar,...TYPE.bodyMd}}>No scan history — run first scan</div>}
      {runs.map((r,i)=>{
        const sc=r.status==="completed"?SC.Low:r.status==="running"?SC.Medium:SC.Critical;
        const cc=r.status==="completed"?SC_CONTAINER.Low:r.status==="running"?SC_CONTAINER.Medium:SC_CONTAINER.Critical;
        return (
          <div key={r.id} style={{background:MD.surfaceCont,boxShadow:elevation(1),borderRadius:MD.radiusMd,padding:"13px 16px"}}>
            <div style={{display:"flex",alignItems:"center",gap:12}}>
              <span style={{...TYPE.labelMd,color:MD.outlineVar,minWidth:26}}>#{runs.length-i}</span>
              <span style={{width:8,height:8,borderRadius:"50%",background:sc,flexShrink:0}}/>
              <Badge label={r.status.toUpperCase()} color={sc} container={cc} small/>
              <span style={{...TYPE.bodySm,color:MD.outline}}>
                {r.created_at?new Date(r.created_at).toLocaleString():"—"}
              </span>
              {r.status==="completed"&&<>
                <div style={{flex:1,height:1,background:MD.outlineVar}}/>
                <span style={{...TYPE.labelMd,color:SC.Low,fontWeight:700}}>{r.checks_passed}P</span>
                <span style={{...TYPE.labelMd,color:SC.Critical,fontWeight:700}}>{r.checks_failed}F</span>
                <span style={{...TYPE.labelMd,color:MD.outline}}>{r.checks_skipped}S</span>
                <span style={{...TYPE.labelMd,color:MD.outlineVar}}>{r.checks_total} total</span>
              </>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Exceptions({findings}) {
  const [exs, setExs] = useState(() => {
    try { return JSON.parse(localStorage.getItem("eg-exceptions") || "{}"); } catch { return {}; }
  });
  const [form, setForm] = useState(null);
  const [fSt, setFSt] = useState("fixed");
  const [fNote, setFNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [q, setQ] = useState("");

  const save = (exs) => { setExs(exs); localStorage.setItem("eg-exceptions", JSON.stringify(exs)); };

  const saveEx = (id) => {
    setSaving(true);
    try {
      const now = new Date().toISOString();
      const ex = exs[id];
      const upd = { ...exs, [id]: { id: ex?.id||Math.random().toString(36).slice(2), check_id:id, status:fSt, note:fNote, created_at:ex?.created_at||now, updated_at:now } };
      save(upd);
      setSaved(true); setTimeout(()=>setSaved(false),2500);
      setForm(null); setFNote("");
    } finally { setSaving(false); }
  };

  const acts = findings.filter(f=>f.status==="failed"||f.status==="error");
  const filt = acts.filter(f=>{const t=REM[f.check_id]?.title||f.check_id;return !q||f.check_id.toLowerCase().includes(q.toLowerCase())||t.toLowerCase().includes(q.toLowerCase());});
  const ackd = Object.values(exs);

  return (
    <div style={{animation:"fadeIn 0.25s cubic-bezier(0.2,0,0,1)"}}>
      {/* Summary */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:18}}>
        {Object.entries(EXS).map(([k,m])=>(
          <div key={k} style={{background:MD.surfaceCont,boxShadow:elevation(1),borderRadius:MD.radiusMd,padding:"14px 16px"}}>
            <div style={{...TYPE.labelSm,color:m.c}}>{m.l}</div>
            <div style={{fontSize:28,fontWeight:700,color:m.c,marginTop:6}}>{ackd.filter(e=>e.status===k).length}</div>
          </div>
        ))}
      </div>

      {/* Acknowledged */}
      {ackd.length>0&&(
        <div style={{marginBottom:22}}>
          <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:10}}>Acknowledged ({ackd.length})</div>
          <div style={{display:"flex",flexDirection:"column",gap:5}}>
            {ackd.map(ex=>{const m=EXS[ex.status]||EXS.fixed;const t=REM[ex.check_id]?.title||ex.check_id;
              return (
                <div key={ex.check_id} style={{background:MD.surfaceCont,boxShadow:elevation(1),borderRadius:MD.radiusMd,padding:"10px 14px"}}>
                  <div style={{display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
                    <span style={{...TYPE.labelMd,color:MD.outline,minWidth:130,flexShrink:0}}>{ex.check_id}</span>
                    <span style={{flex:1,...TYPE.bodySm,color:MD.onSurfaceVar,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{t}</span>
                    <Badge label={`${m.i} ${m.l}`} color={m.c} container={m.cc} small/>
                    {ex.note&&<span style={{...TYPE.bodySm,color:MD.outlineVar,fontStyle:"italic",maxWidth:170,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>"{ex.note}"</span>}
                    <button onClick={()=>{setForm(ex.check_id);setFSt(ex.status);setFNote(ex.note||"");}}
                      style={{padding:"4px 12px",background:"transparent",border:`1px solid ${MD.outlineVar}`,
                        color:MD.outline,borderRadius:MD.radiusXl,...TYPE.labelMd,cursor:"pointer"}}>Edit</button>
                    <button onClick={()=>{const u={...exs};delete u[ex.check_id];save(u);}}
                      style={{padding:"4px 12px",background:"transparent",border:`1px solid ${SC_CONTAINER.Critical}`,
                        color:SC.Critical,borderRadius:MD.radiusXl,...TYPE.labelMd,cursor:"pointer"}}>Revoke</button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Active findings */}
      <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:10}}>
        Active findings — click to acknowledge ({filt.length})
      </div>
      <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Filter by check ID or title…"
        style={{width:"100%",padding:"10px 14px",background:MD.surfaceHigh,border:`1px solid ${MD.outlineVar}`,
          color:MD.onSurface,borderRadius:MD.radiusXl,...TYPE.bodyMd,marginBottom:10,fontFamily:"inherit",
          boxSizing:"border-box"}}/>
      <div style={{display:"flex",flexDirection:"column",gap:4}}>
        {filt.map(f=>{
          const ex=exs[f.check_id];const m=ex?EXS[ex.status]:null;const t=REM[f.check_id]?.title||f.check_id;
          return (
            <div key={f.check_id} style={{background:MD.surfaceCont,boxShadow:elevation(1),borderRadius:MD.radiusMd}}>
              <div style={{display:"flex",alignItems:"center",gap:10,padding:"10px 14px",flexWrap:"wrap"}}>
                <div style={{width:3,background:sev(f),alignSelf:"stretch",borderRadius:2,flexShrink:0}}/>
                <span style={{...TYPE.labelMd,color:MD.outline,minWidth:130,flexShrink:0}}>{f.check_id}</span>
                <span style={{flex:1,...TYPE.bodySm,color:MD.onSurfaceVar,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{t}</span>
                <Badge label={f.severity} color={sev(f)} container={sevContainer(f)} small/>
                {ex?(
                  <Badge label={`${m.i} ${m.l}`} color={m.c} container={m.cc} small/>
                ):(
                  <button onClick={()=>{setForm(f.check_id);setFSt("fixed");setFNote("");}}
                    style={{padding:"6px 16px",background:MD.primaryContainer,
                      border:"none",color:MD.onPrimaryContainer,
                      borderRadius:MD.radiusXl,...TYPE.labelLg,fontWeight:700,cursor:"pointer",
                      flexShrink:0}}>+ Acknowledge</button>
                )}
              </div>
            </div>
          );
        })}
        {filt.length===0&&<div style={{textAlign:"center",padding:28,color:MD.outlineVar,...TYPE.bodyMd}}>No active findings</div>}
      </div>

      {/* Modal */}
      {form&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.55)",display:"flex",
          alignItems:"center",justifyContent:"center",zIndex:9999}}
          onClick={()=>setForm(null)}>
          <div onClick={e=>e.stopPropagation()}
            style={{background:MD.surfaceHigh,borderRadius:MD.radiusXl,
              width:"min(480px,95vw)",padding:28,boxShadow:elevation(5)}}>
            <div style={{...TYPE.labelSm,color:MD.primary,marginBottom:6}}>Acknowledge finding</div>
            <div style={{...TYPE.labelMd,color:MD.outline,marginBottom:5}}>{form}</div>
            <div style={{...TYPE.titleMd,color:MD.onSurface,marginBottom:22,lineHeight:1.4}}>
              {REM[form]?.title||form}
            </div>

            <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:11}}>Status</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:20}}>
              {Object.entries(EXS).map(([k,m])=>{
                const active = fSt===k;
                return (
                  <button key={k} onClick={()=>setFSt(k)}
                    style={{padding:"11px 14px",textAlign:"left",borderRadius:MD.radiusMd,
                      background:active?m.c+"18":MD.surfaceDim,
                      border:`1px solid ${active?m.c:MD.outlineVar}`,
                      color:active?m.c:MD.outline,
                      ...TYPE.bodyMd,fontWeight:active?700:500,cursor:"pointer",
                      display:"flex",alignItems:"center",gap:9,transition:"all 0.15s"}}>
                    <span style={{fontSize:17}}>{m.i}</span>{m.l}
                  </button>
                );
              })}
            </div>

            <div style={{...TYPE.labelSm,color:MD.outline,marginBottom:8}}>Notes</div>
            <textarea value={fNote} onChange={e=>setFNote(e.target.value)}
              placeholder="e.g. Compensating control in place — SIEM alert active. Review Q3 2026."
              style={{width:"100%",height:80,padding:"11px 14px",background:MD.surfaceDim,
                border:`1px solid ${MD.outlineVar}`,color:MD.onSurfaceVar,borderRadius:MD.radiusMd,
                ...TYPE.bodyMd,resize:"vertical",marginBottom:18,fontFamily:"inherit",
                boxSizing:"border-box"}}/>

            <div style={{display:"flex",gap:10,justifyContent:"flex-end"}}>
              <button onClick={()=>setForm(null)}
                style={{padding:"9px 18px",background:"transparent",border:"none",
                  color:MD.onSurfaceVar,borderRadius:MD.radiusXl,...TYPE.labelLg,fontWeight:600,cursor:"pointer"}}>Cancel</button>
              <button onClick={()=>saveEx(form)} disabled={saving}
                style={{padding:"9px 24px",minWidth:180,justifyContent:"center",
                  background:saved?SC.Low:saving?MD.surfaceHigh:MD.primaryDim,
                  color:saved?MD.surfaceDim:saving?MD.outline:MD.surfaceDim,
                  borderRadius:MD.radiusXl,...TYPE.labelLg,fontWeight:700,
                  border:"none",cursor:saving?"not-allowed":"pointer",
                  display:"flex",alignItems:"center",gap:9,
                  boxShadow:saving?"none":elevation(1),transition:"background 0.2s"}}>
                {saving?<><div style={{width:12,height:12,border:`2px solid ${MD.outline}`,
                  borderTopColor:"transparent",borderRadius:"50%",
                  animation:"spin 0.7s linear infinite"}}/>Saving…</>
                  :saved?"✓ Saved":"Save acknowledgement"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Root ─────────────────────────────────────────────────────────────────────
export default function App() {
  const [view, setView]     = React.useState("dashboard");
  const [findings, setFindings] = React.useState([]);
  const [runs, setRuns]     = React.useState([]);
  const [targets, setTargets] = React.useState([]);
  const [scanning, setScanning] = React.useState(false);
  const [online, setOnline] = React.useState(false);
  const [mobileOpen, setMobileOpen] = React.useState(false);

  // Auth state
  const [authConfig, setAuthConfig] = React.useState(null);
  const [authUser, setAuthUser]     = React.useState(null);
  const [authLoading, setAuthLoading] = React.useState(true);

  const poll = React.useRef(null);

  // Load auth config and check existing token
  React.useEffect(() => {
    (async () => {
      try {
        const cfg = await fetch(AUTH_CONFIG_URL).then(r=>r.json());
        setAuthConfig(cfg);
        if (!cfg.auth_enabled) {
          setAuthUser({name:"Anonymous", auth_type:"disabled"});
          setAuthLoading(false);
          return;
        }
        // Check if we have a valid token
        const token = getStoredToken();
        if (token) {
          const me = await authFetch(AUTH_ME_URL);
          if (me.ok) {
            const u = await me.json();
            setAuthUser(u);
          } else {
            clearStoredToken();
          }
        }
        // Check for MSAL cookie-based auth (set by /auth/callback)
        if (!getStoredToken()) {
          const me = await fetch(AUTH_ME_URL, {credentials:"include"});
          if (me.ok) setAuthUser(await me.json());
        }
      } catch(e) {
        console.error("Auth config failed:", e);
        setAuthConfig({auth_enabled:false});
        setAuthUser({name:"Anonymous", auth_type:"disabled"});
      } finally {
        setAuthLoading(false);
      }
    })();
  }, []);

  const handleLogin = (user) => setAuthUser(user);

  const handleLogout = async () => {
    clearStoredToken();
    await fetch(AUTH_LOGOUT_URL, {method:"POST", credentials:"include"});
    setAuthUser(null);
  };

  const load = React.useCallback(async () => {
    try {
      const [f,r,t] = await Promise.all([
        apiFetch("/findings?page_size=500").catch(()=>({items:[]})),
        apiFetch("/assessments/runs").catch(()=>({items:[]})),
        apiFetch("/targets").catch(()=>({items:[]})),
      ]);
      setFindings(f.items||[]);
      setRuns(r.items||[]); setTargets(t.items||[]); setOnline(true);
      if(!(r.items||[]).find(x=>x.status==="running"||x.status==="pending")) {
        setScanning(false);
        if(poll.current){clearInterval(poll.current);poll.current=null;}
      }
    } catch{setOnline(false);}
  }, []);

  React.useEffect(()=>{
    if (!authUser) return;
    load();
    const iv=setInterval(load,15000);
    return()=>{clearInterval(iv);if(poll.current)clearInterval(poll.current);};
  },[load, authUser]);

  const scan=async()=>{
    try{
      const t=await apiFetch("/targets");const list=t.items||[];
      if(!list.length){alert("No target configured — check Azure credentials in .env");return;}
      setScanning(true);
      await apiPost("/assessments/run",{target_id:list[0].id});
      if(poll.current)clearInterval(poll.current);
      poll.current=setInterval(load,3000);
    }catch(e){alert(e?.message==="403"?"Only admins can start a scan.":"Scan failed: "+e);setScanning(false);}
  };

  const fail=findings.filter(f=>f.status==="failed");
  const crit=fail.filter(f=>f.severity==="Critical").length;
  const last=runs.find(r=>r.status==="completed")?.completed_at;

  const VIEWS={
    dashboard:<Dashboard findings={findings} runs={runs}/>,
    findings:<Findings findings={findings}/>,
    compliance:<Compliance findings={findings}/>,
    remediation:<Remediation findings={findings}/>,
    history:<History runs={runs}/>,
    exceptions:<Exceptions findings={findings}/>,
    users:<Users authUser={authUser}/>,
  };

  // Loading
  if (authLoading) return (
    <div style={{minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",background:MD.surfaceDim}}>
      <div style={{textAlign:"center"}}>
        <div style={{width:40,height:40,border:`3px solid ${MD.surfaceHigh}`,borderTopColor:MD.primaryDim,
          borderRadius:"50%",animation:"spin 0.8s linear infinite",margin:"0 auto 16px"}}/>
        <div style={{color:MD.outline,...TYPE.labelLg}}>Loading…</div>
      </div>
    </div>
  );

  // Login wall
  if (authConfig?.auth_enabled && !authUser) {
    return <LoginPage onLogin={handleLogin} config={authConfig}/>;
  }

  return (
    <>
      <style>{`
        *{box-sizing:border-box;margin:0;padding:0;}
        body{background:${MD.surfaceDim};color:${MD.onSurface};font-family:'Inter',system-ui,sans-serif;
          font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased;}
        ::-webkit-scrollbar{width:5px;height:5px;}
        ::-webkit-scrollbar-track{background:${MD.surfaceLow};}
        ::-webkit-scrollbar-thumb{background:${MD.outlineVar};border-radius:3px;}
        ::-webkit-scrollbar-thumb:hover{background:${MD.outline};}
        input,textarea,select{font-family:inherit;outline:none;}
        button{font-family:inherit;}
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
        @keyframes blink{0%,100%{opacity:1}50%{opacity:0.35}}
        /* ── Mobile ── */
        @media(max-width:768px){
          .eg-sidebar{
            transform:translateX(-100%);
            transition:transform 0.2s cubic-bezier(0.2,0,0,1);
            z-index:200!important;
          }
          .eg-sidebar.open{transform:translateX(0)!important;}
          .eg-overlay{
            display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:199;
          }
          .eg-overlay.open{display:block;}
          .eg-main{margin-left:0!important;padding:16px!important;}
          .eg-topbar{left:0!important;}
          .eg-top-header{padding-left:56px!important;}
          .eg-hamburger{display:flex!important;}
          .eg-kpi-grid{grid-template-columns:repeat(2,1fr)!important;}
          .eg-chart-row{grid-template-columns:1fr!important;}
          .eg-top5-grid{grid-template-columns:1fr!important;}
          .eg-sev-domain{grid-template-columns:1fr!important;}
          .eg-findings-toolbar{flex-wrap:wrap!important;}
          .eg-findings-toolbar select{width:100%!important;}
          .eg-compliance-tabs{flex-wrap:wrap!important;}
        }
        @media(min-width:769px){
          .eg-hamburger{display:none!important;}
        }
      `}</style>

      {/* Mobile overlay */}
      <div className={`eg-overlay${mobileOpen?" open":""}`} onClick={()=>setMobileOpen(false)}/>

      {/* Sidebar — Nav renders its own full-height <aside>; this wrapper only
          carries the mobile slide-in class + z-index, no duplicate styling */}
      <div className={`eg-sidebar${mobileOpen?" open":""}`}
        style={{position:"fixed",top:0,left:0,bottom:0,zIndex:100}}>
        <Nav view={view} setView={(v)=>{setView(v);setMobileOpen(false);}} fails={fail.length}
          user={authUser} onLogout={handleLogout}/>
      </div>

      {/* Topbar — single source of truth (Top component), with hamburger
          injected for mobile via a small wrapper so Top itself stays
          desktop/mobile agnostic */}
      <div className="eg-topbar" style={{position:"fixed",top:0,left:232,right:0,zIndex:90}}>
        <div style={{position:"relative"}}>
          <button className="eg-hamburger" onClick={()=>setMobileOpen(o=>!o)}
            style={{position:"absolute",left:16,top:0,bottom:0,margin:"auto 0",height:32,
              background:"none",border:"none",color:MD.onSurfaceVar,cursor:"pointer",
              padding:"6px",display:"none",flexDirection:"column",justifyContent:"center",gap:4,zIndex:1}}>
            <div style={{width:18,height:2,background:"currentColor",borderRadius:1}}/>
            <div style={{width:18,height:2,background:"currentColor",borderRadius:1}}/>
            <div style={{width:18,height:2,background:"currentColor",borderRadius:1}}/>
          </button>
          <Top target={targets[0]} scanning={scanning} onScan={scan} online={online} lastScan={last} crits={crit}/>
        </div>
      </div>

      {/* Main content */}
      <main className="eg-main" style={{marginLeft:232,marginTop:64,padding:24,
        minHeight:"calc(100vh - 64px)",display:"flex",flexDirection:"column"}}>
        <div style={{flex:1}}>{VIEWS[view]||VIEWS.dashboard}</div>
        {/* Footer */}
        <footer style={{marginTop:48,paddingTop:24,borderTop:`1px solid ${MD.outlineVar}`,
          display:"flex",alignItems:"center",justifyContent:"space-between",
          flexWrap:"wrap",gap:14}}>
          <div style={{display:"flex",alignItems:"center",gap:16}}>
            <div style={{display:"flex",alignItems:"center",gap:9}}>
              <div style={{width:24,height:24,borderRadius:MD.radiusSm,
                background:MD.primaryContainer,
                display:"flex",alignItems:"center",justifyContent:"center",
                ...TYPE.labelMd,color:MD.onPrimaryContainer}}>EG</div>
              <span style={{...TYPE.labelLg,color:MD.outline,fontWeight:600}}>EntraGuard v2.0</span>
            </div>
            <span style={{color:MD.outlineVar}}>|</span>
            <span style={{...TYPE.bodySm,color:MD.outline}}>Azure Identity Security Posture Management</span>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:18,flexWrap:"wrap"}}>
            {[
              ["GitHub","https://github.com/jahmed-cloud/entra-guard"],
              ["Docker Hub","https://hub.docker.com/r/jahmed22/entra-guard-api"],
              ["Docs","https://github.com/jahmed-cloud/entra-guard#readme"],
              ["Report issue","https://github.com/jahmed-cloud/entra-guard/issues"],
              ["Microsoft Graph","https://learn.microsoft.com/en-us/graph/overview"],
            ].map(([l,u])=>(
              <a key={l} href={u} target="_blank" style={{...TYPE.bodySm,color:MD.outline,
                textDecoration:"none",transition:"color 0.15s"}}
                onMouseOver={e=>e.target.style.color=MD.primary}
                onMouseOut={e=>e.target.style.color=MD.outline}>{l}</a>
            ))}
          </div>
          <div style={{display:"flex",alignItems:"center",gap:7}}>
            <span style={{...TYPE.bodySm,color:MD.outlineVar}}>Built by</span>
            <a href="mailto:iam@jahmed.cloud"
              style={{...TYPE.bodySm,color:MD.outline,textDecoration:"none"}}
              onMouseOver={e=>e.target.style.color=MD.primary}
              onMouseOut={e=>e.target.style.color=MD.outline}>Junaid Ahmed</a>
            <span style={{color:MD.outlineVar}}>·</span>
            <span style={{...TYPE.bodySm,color:MD.outlineVar}}>MIT License</span>
          </div>
        </footer>
      </main>
    </>
  );
}
