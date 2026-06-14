// @ts-nocheck
import React, { useState, useEffect, useCallback, useRef } from "react";

// ─── API ──────────────────────────────────────────────────────────────────────
const API = "/api/v1";
const apiFetch = async (p) => { const r = await fetch(API+p); if(!r.ok) throw new Error(r.status); return r.json(); };
const apiPost  = async (p, b={}) => { const r = await fetch(API+p, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)}); if(!r.ok) throw new Error(r.status); return r.json(); };

// ─── Severity ─────────────────────────────────────────────────────────────────
const SC = { Critical:"#f87171", High:"#fb923c", Medium:"#fcd34d", Low:"#34d399", Info:"#60a5fa" };
const SO = { Critical:0, High:1, Medium:2, Low:3 };

function sev(f) { return SC[f.severity] || SC.Info; }
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
  fixed:          {l:"Fixed",          c:"#34d399", i:"✓"},
  risk_accepted:  {l:"Risk Accepted",  c:"#fcd34d", i:"⚠"},
  false_positive: {l:"False Positive", c:"#60a5fa", i:"⊘"},
  in_progress:    {l:"In Progress",    c:"#fb923c", i:"◷"},
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
const Badge = ({label, color, small}) => (
  <span style={{display:"inline-flex",alignItems:"center",padding:small?"1px 6px":"2px 9px",
    borderRadius:3,fontSize:small?9:10,fontWeight:700,letterSpacing:"0.05em",
    background:color+"18",color,border:`1px solid ${color}35`}}>{label}</span>
);

const ScoreBar = ({score, max=10}) => (
  <div style={{display:"flex",alignItems:"center",gap:8}}>
    <div style={{flex:1,height:4,background:"#2d3748",borderRadius:2}}>
      <div style={{height:"100%",borderRadius:2,
        background:score>7?"#f87171":score>4?"#fb923c":"#fcd34d",
        width:`${(score/max)*100}%`,transition:"width 0.6s ease"}}/>
    </div>
    <span style={{fontFamily:"monospace",fontSize:11,fontWeight:700,
      color:score>7?"#f87171":score>4?"#fb923c":score>0?"#fcd34d":"#34d399",
      minWidth:28,textAlign:"right"}}>{score.toFixed(1)}</span>
  </div>
);

// ─── Sidebar ──────────────────────────────────────────────────────────────────
const NAVS = [
  {id:"dashboard",  icon:"◈", l:"Dashboard"},
  {id:"findings",   icon:"⚡",l:"Findings"},
  {id:"compliance", icon:"✓", l:"Compliance"},
  {id:"remediation",icon:"⚙", l:"Remediation"},
  {id:"history",    icon:"◷", l:"Scan History"},
  {id:"exceptions", icon:"⊘", l:"Exceptions"},
];

function Nav({view, setView, fails}) {
  return (
    <aside style={{position:"fixed",top:0,left:0,bottom:0,width:216,
      background:"#1a2332",borderRight:"1px solid #2d3748",
      display:"flex",flexDirection:"column",zIndex:100,
      fontFamily:"'JetBrains Mono','Fira Code','Consolas',monospace"}}>
      {/* Logo */}
      <div style={{padding:"22px 18px 18px",borderBottom:"1px solid #2d3748"}}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{width:36,height:36,borderRadius:8,
            background:"linear-gradient(135deg,#38bdf8,#818cf8)",
            display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
            <svg width="20" height="20" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round">
              <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
            </svg>
          </div>
          <div>
            <div style={{fontWeight:700,color:"#d1d9e6",fontSize:14,letterSpacing:"0.02em"}}>EntraGuard</div>
            <div style={{fontSize:9,color:"#4a5568",letterSpacing:"0.08em",marginTop:1}}>AZURE CSPM · v2.0</div>
          </div>
        </div>
      </div>
      {/* Nav */}
      <nav style={{flex:1,padding:"10px 10px",overflowY:"auto"}}>
        {NAVS.map(n=>(
          <button key={n.id} onClick={()=>setView(n.id)} style={{
            width:"100%",display:"flex",alignItems:"center",gap:10,
            padding:"9px 10px",marginBottom:2,borderRadius:6,
            background:view===n.id?"#0f2744":"transparent",
            border:`1px solid ${view===n.id?"#2d5986":"transparent"}`,
            color:view===n.id?"#38bdf8":"#5a6a7e",
            fontSize:11,fontWeight:view===n.id?700:400,
            cursor:"pointer",transition:"all 0.12s",textAlign:"left"}}>
            <span style={{fontSize:13,opacity:0.9}}>{n.icon}</span>
            {n.l}
            {n.id==="findings"&&fails>0&&(
              <span style={{marginLeft:"auto",background:"#f87171",color:"#fff",
                fontSize:9,padding:"1px 5px",borderRadius:9,fontWeight:700}}>{fails}</span>
            )}
          </button>
        ))}
      </nav>
      {/* Footer */}
      <div style={{padding:"14px 18px",borderTop:"1px solid #2d3748"}}>
        <div style={{fontSize:9,color:"#374458",letterSpacing:"0.08em",marginBottom:4}}>OPERATOR</div>
        <div style={{fontSize:12,color:"#8896aa",fontWeight:500}}>Junaid Ahmed</div>
        <div style={{fontSize:9,color:"#374458",marginTop:1}}>iam@jahmed.cloud</div>
        <div style={{display:"flex",gap:10,marginTop:10}}>
          {[["GH","https://github.com/jahmed-cloud/entra-guard"],["DH","https://hub.docker.com/r/jahmed22/entra-guard"]].map(([l,u])=>(
            <a key={l} href={u} target="_blank" style={{fontSize:9,color:"#374458",
              textDecoration:"none",padding:"2px 6px",border:"1px solid #2d3748",borderRadius:3}}>{l}</a>
          ))}
        </div>
      </div>
    </aside>
  );
}

// ─── Topbar ───────────────────────────────────────────────────────────────────
function Top({target, scanning, onScan, online, lastScan, crits}) {
  return (
    <header style={{position:"fixed",top:0,left:216,right:0,height:52,
      background:"#1a2332",borderBottom:"1px solid #2d3748",
      display:"flex",alignItems:"center",padding:"0 22px",gap:14,zIndex:90,
      fontFamily:"'JetBrains Mono','Fira Code','Consolas',monospace"}}>
      <div style={{display:"flex",alignItems:"center",gap:8,flex:1,minWidth:0}}>
        <span style={{width:7,height:7,borderRadius:"50%",
          background:online?"#34d399":"#f87171",
          boxShadow:`0 0 8px ${online?"#34d399":"#f87171"}`,flexShrink:0}}/>
        <span style={{fontSize:10,color:"#4a5568"}}>{online?"ONLINE":"OFFLINE"}</span>
        {target&&<>
          <span style={{color:"#2d3748",fontSize:14}}>/</span>
          <span style={{fontSize:11,color:"#8896aa",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{target.name}</span>
        </>}
        {lastScan&&<span style={{fontSize:9,color:"#374458",marginLeft:4,flexShrink:0}}>
          LAST {new Date(lastScan).toLocaleString()}
        </span>}
      </div>
      {crits>0&&(
        <div style={{display:"flex",alignItems:"center",gap:6,padding:"4px 10px",
          background:"#f8717115",border:"1px solid #f8717140",borderRadius:4}}>
          <span style={{width:5,height:5,borderRadius:"50%",background:"#f87171",
            animation:"blink 1.2s ease infinite"}}/>
          <span style={{fontSize:9,color:"#f87171",fontWeight:700,letterSpacing:"0.06em"}}>{crits} CRITICAL</span>
        </div>
      )}
      <button onClick={onScan} disabled={scanning}
        style={{padding:"7px 16px",borderRadius:4,border:"none",cursor:"pointer",
          background:scanning?"transparent":"linear-gradient(135deg,#38bdf8,#818cf8)",
          color:scanning?"#38bdf8":"#fff",
          outline:scanning?"1px solid #38bdf8":"none",
          fontSize:10,fontWeight:700,letterSpacing:"0.08em",
          display:"flex",alignItems:"center",gap:7,transition:"all 0.2s"}}>
        {scanning
          ?<><div style={{width:10,height:10,border:"2px solid #38bdf8",borderTopColor:"transparent",
              borderRadius:"50%",animation:"spin 0.7s linear infinite"}}/>SCANNING</>
          :"▶ SCAN"}
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
  const top5=[...fail].sort((a,b)=>b.score-a.score).slice(0,5);
  const trendData=runs.slice(0,12).reverse();

  // SVG Line Chart helpers
  const W=480,H=80,PAD=8;
  const vals=trendData.map(r=>r.checks_failed||0);
  const maxV=Math.max(...vals,1);
  const pts=vals.map((v,i)=>{
    const x=PAD+(i/(Math.max(vals.length-1,1)))*(W-PAD*2);
    const y=H-PAD-(v/maxV)*(H-PAD*2);
    return [Math.round(x),Math.round(y)];
  });
  const linePath=pts.map((p,i)=>i===0?`M${p[0]},${p[1]}`:`L${p[0]},${p[1]}`).join(" ");
  const areaPath=pts.length>0?`${linePath} L${pts[pts.length-1][0]},${H-PAD} L${pts[0][0]},${H-PAD} Z`:"";

  // Pass rate trend
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

  const CARD={background:"#1e293b",border:"1px solid #2d3748",borderRadius:10,padding:16};

  return (
    <div style={{animation:"fadeIn 0.25s ease"}}>
      {/* Critical Banner */}
      {bySev.Critical>0&&(
        <div style={{marginBottom:16,padding:"12px 16px",borderRadius:8,
          background:"rgba(248,113,113,0.08)",border:"1px solid rgba(248,113,113,0.25)",
          display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:36,height:36,borderRadius:8,background:"rgba(248,113,113,0.12)",
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,flexShrink:0}}>⚠</div>
          <div>
            <div style={{fontWeight:700,color:"#f87171",fontSize:13}}>
              {bySev.Critical} critical issue{bySev.Critical!==1?"s":""} require immediate action
            </div>
            <div style={{fontSize:11,color:"#5a6a7e",marginTop:2}}>
              {bySev.High} high · {bySev.Medium} medium · {bySev.Low} low severity findings detected.
              Open Findings for step-by-step remediation guides.
            </div>
          </div>
        </div>
      )}

      {/* Row 1: Score + KPIs */}
      <div style={{display:"grid",gridTemplateColumns:"130px 1fr",gap:10,marginBottom:10}}>
        {/* Score ring */}
        <div style={{...CARD,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:8}}>
          <div style={{fontSize:9,color:"#5a6a7e",letterSpacing:"0.1em",fontFamily:"monospace"}}>POSTURE</div>
          <div style={{position:"relative",width:80,height:80}}>
            <svg width="80" height="80" viewBox="0 0 80 80" style={{transform:"rotate(-90deg)"}}>
              <circle cx="40" cy="40" r="32" fill="none" stroke="#2d3748" strokeWidth="8"/>
              {score!==null&&<circle cx="40" cy="40" r="32" fill="none"
                stroke={score>=80?"#34d399":score>=60?"#fcd34d":"#f87171"}
                strokeWidth="8" strokeLinecap="round"
                strokeDasharray={`${2*Math.PI*32*score/100} ${2*Math.PI*32}`}
                style={{transition:"stroke-dasharray 1.2s ease"}}/>}
            </svg>
            <div style={{position:"absolute",inset:0,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center"}}>
              <div style={{fontSize:score===null?14:22,fontWeight:800,lineHeight:1,
                color:score===null?"#374458":score>=80?"#34d399":score>=60?"#fcd34d":"#f87171"}}>
                {score===null?"—":score}
              </div>
              {score!==null&&<div style={{fontSize:8,color:"#5a6a7e",marginTop:1}}>/100</div>}
            </div>
          </div>
          <div style={{fontSize:9,color:score===null?"#374458":score>=80?"#34d399":score>=60?"#fcd34d":"#f87171",
            fontFamily:"monospace",textAlign:"center",letterSpacing:"0.06em"}}>
            {score===null?"NO DATA":score>=80?"GOOD":score>=60?"MODERATE":"AT RISK"}
          </div>
        </div>

        {/* KPI grid */}
        <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:8}}>
          {[
            {l:"Checks",v:findings.length,c:"#8896aa"},
            {l:"Failing",v:fail.length,c:fail.length>0?"#f87171":"#34d399",s:`${findings.length?Math.round(fail.length/findings.length*100):0}%`},
            {l:"Critical",v:bySev.Critical,c:bySev.Critical>0?"#f87171":"#374458"},
            {l:"High",v:bySev.High,c:bySev.High>0?"#fb923c":"#374458"},
            {l:"Passing",v:pass.length,c:"#34d399"},
            {l:"Errors",v:err.length,c:err.length>0?"#fb923c":"#374458",s:"fix perms"},
          ].map(k=>(
            <div key={k.l} style={{background:"#1e293b",border:"1px solid #2d3748",borderRadius:8,padding:"11px 12px"}}>
              <div style={{fontSize:9,color:"#4a5568",fontWeight:600,letterSpacing:"0.08em",marginBottom:5,fontFamily:"monospace"}}>{k.l.toUpperCase()}</div>
              <div style={{fontSize:26,fontWeight:800,color:k.c,lineHeight:1}}>{k.v}</div>
              {k.s&&<div style={{fontSize:9,color:"#4a5568",marginTop:3,fontFamily:"monospace"}}>{k.s}</div>}
            </div>
          ))}
        </div>
      </div>

      {/* Row 2: Severity bars + Domain bars */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
        {/* Severity */}
        <div style={{...CARD}}>
          <div style={{fontSize:9,color:"#4a5568",fontWeight:600,letterSpacing:"0.1em",marginBottom:14,fontFamily:"monospace"}}>FINDINGS BY SEVERITY</div>
          {Object.entries(bySev).map(([s,n])=>(
            <div key={s} style={{display:"flex",alignItems:"center",gap:10,marginBottom:10}}>
              <span style={{fontSize:10,padding:"2px 7px",borderRadius:4,
                background:SC[s]+"18",color:SC[s],
                border:`1px solid ${SC[s]}35`,fontWeight:700,minWidth:60,textAlign:"center"}}>{s}</span>
              <div style={{flex:1,height:6,background:"#111827",borderRadius:3,overflow:"hidden"}}>
                <div style={{height:"100%",borderRadius:3,background:SC[s],
                  width:fail.length?`${Math.max(2,(n/fail.length)*100)}%`:"0%",
                  transition:"width 0.9s ease"}}/>
              </div>
              <span style={{fontSize:12,fontWeight:700,color:SC[s],minWidth:24,textAlign:"right",fontFamily:"monospace"}}>{n}</span>
            </div>
          ))}
        </div>

        {/* Domain horizontal bars */}
        <div style={{...CARD}}>
          <div style={{fontSize:9,color:"#4a5568",fontWeight:600,letterSpacing:"0.1em",marginBottom:14,fontFamily:"monospace"}}>FAILURES BY DOMAIN</div>
          {domainEntries.length===0
            ?<div style={{color:"#34d399",fontSize:12,textAlign:"center",paddingTop:20}}>✓ All clear</div>
            :domainEntries.slice(0,6).map(([d,n],i)=>{
              const pct=Math.max(3,(n/maxDomain)*100);
              const colors=["#f87171","#fb923c","#fcd34d","#34d399","#38bdf8","#818cf8"];
              const c=colors[i%colors.length];
              return (
                <div key={d} style={{display:"flex",alignItems:"center",gap:8,marginBottom:9}}>
                  <div style={{fontSize:9,color:"#8896aa",minWidth:110,flexShrink:0,fontFamily:"monospace"}}>{d.toUpperCase().slice(0,12)}</div>
                  <div style={{flex:1,height:6,background:"#111827",borderRadius:3,overflow:"hidden"}}>
                    <div style={{height:"100%",borderRadius:3,background:c,width:`${pct}%`,transition:"width 0.9s ease"}}/>
                  </div>
                  <span style={{fontSize:11,fontWeight:700,color:c,minWidth:20,textAlign:"right",fontFamily:"monospace"}}>{n}</span>
                </div>
              );
            })
          }
        </div>
      </div>

      {/* Row 3: Dual Line Charts */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
        {/* Failing trend line chart */}
        <div style={{...CARD}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
            <div style={{fontSize:9,color:"#4a5568",fontWeight:600,letterSpacing:"0.1em",fontFamily:"monospace"}}>FAILING CHECKS — TREND</div>
            {trendData.length>0&&<span style={{fontSize:9,color:"#f87171",fontFamily:"monospace"}}>
              {trendData[trendData.length-1]?.checks_failed||vals[vals.length-1]||0} CURRENT
            </span>}
          </div>
          <svg width="100%" height={H} viewBox={"0 0 "+W+" "+H} preserveAspectRatio="none" style={{display:"block"}}>
            <defs>
              <linearGradient id="failGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f87171" stopOpacity="0.25"/>
                <stop offset="100%" stopColor="#f87171" stopOpacity="0.02"/>
              </linearGradient>
            </defs>
            {/* Grid lines */}
            {[0.25,0.5,0.75].map(p=>(
              <line key={p} x1={PAD} y1={H-PAD-(p*(H-PAD*2))} x2={W-PAD} y2={H-PAD-(p*(H-PAD*2))}
                stroke="#2d3748" strokeWidth="0.5" strokeDasharray="3,3"/>
            ))}
            {/* Area fill */}
            {areaPath&&<path d={areaPath} fill="url(#failGrad)"/>}
            {/* Line */}
            {linePath&&<path d={linePath} fill="none" stroke="#f87171" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>}
            {/* Data points */}
            {pts.map((p,i)=>(
              <circle key={i} cx={p[0]} cy={p[1]} r="3" fill="#f87171" stroke="#1e293b" strokeWidth="1.5"/>
            ))}
            {/* X labels */}
            {trendData.map((_,i)=>(
              <text key={i} x={pts[i]?.[0]||0} y={H-1} textAnchor="middle"
                fontSize="7" fill="#374458" fontFamily="monospace">#{i+1}</text>
            ))}
          </svg>
        </div>

        {/* Pass rate trend */}
        <div style={{...CARD}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
            <div style={{fontSize:9,color:"#4a5568",fontWeight:600,letterSpacing:"0.1em",fontFamily:"monospace"}}>PASS RATE — TREND</div>
            {passVals.length>0&&<span style={{fontSize:9,color:"#34d399",fontFamily:"monospace"}}>
              {passVals[passVals.length-1]}% CURRENT
            </span>}
          </div>
          <svg width="100%" height={H} viewBox={"0 0 "+W+" "+H} preserveAspectRatio="none" style={{display:"block"}}>
            <defs>
              <linearGradient id="passGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#34d399" stopOpacity="0.2"/>
                <stop offset="100%" stopColor="#34d399" stopOpacity="0.02"/>
              </linearGradient>
            </defs>
            {[0.25,0.5,0.75].map(p=>(
              <line key={p} x1={PAD} y1={H-PAD-(p*(H-PAD*2))} x2={W-PAD} y2={H-PAD-(p*(H-PAD*2))}
                stroke="#2d3748" strokeWidth="0.5" strokeDasharray="3,3"/>
            ))}
            {passArea&&<path d={passArea} fill="url(#passGrad)"/>}
            {passPath&&<path d={passPath} fill="none" stroke="#34d399" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>}
            {passPts.map((p,i)=>(
              <circle key={i} cx={p[0]} cy={p[1]} r="3" fill="#34d399" stroke="#1e293b" strokeWidth="1.5"/>
            ))}
            {trendData.map((_,i)=>(
              <text key={i} x={passPts[i]?.[0]||0} y={H-1} textAnchor="middle"
                fontSize="7" fill="#374458" fontFamily="monospace">#{i+1}</text>
            ))}
          </svg>
        </div>
      </div>

      {/* Row 4: Top findings + Compliance ring grid */}
      <div style={{display:"grid",gridTemplateColumns:"1fr auto",gap:10,marginBottom:10}}>
        {/* Top findings */}
        {top5.length>0&&(
          <div style={{...CARD}}>
            <div style={{fontSize:9,color:"#4a5568",fontWeight:600,letterSpacing:"0.1em",marginBottom:14,fontFamily:"monospace"}}>TOP 5 — HIGHEST RISK SCORE</div>
            {top5.map((f,i)=>{
              const r=REM[f.check_id];const sc=sev(f);
              return (
                <div key={f.check_id} style={{display:"grid",gridTemplateColumns:"20px 3px 1fr auto 72px",
                  alignItems:"center",gap:10,padding:"8px 0",
                  borderBottom:i<4?"1px solid #2d3748":"none"}}>
                  <div style={{width:20,height:20,borderRadius:4,background:"#2d3748",
                    display:"flex",alignItems:"center",justifyContent:"center",
                    fontSize:9,fontWeight:700,color:"#5a6a7e",fontFamily:"monospace"}}>{i+1}</div>
                  <div style={{height:28,background:sc,borderRadius:2}}/>
                  <div style={{minWidth:0}}>
                    <div style={{fontSize:9,color:"#4a5568",fontFamily:"monospace"}}>{f.check_id}</div>
                    <div style={{fontSize:12,fontWeight:500,color:"#c0cad8",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{r?.title||f.check_id}</div>
                  </div>
                  <span style={{fontSize:9,padding:"2px 7px",borderRadius:4,
                    background:sc+"18",color:sc,border:`1px solid ${sc}35`,fontWeight:700,flexShrink:0}}>{f.severity}</span>
                  <div style={{display:"flex",alignItems:"center",gap:6}}>
                    <div style={{flex:1,height:4,background:"#111827",borderRadius:2}}>
                      <div style={{height:"100%",borderRadius:2,background:sc,width:`${(f.score/10)*100}%`}}/>
                    </div>
                    <span style={{fontSize:11,fontWeight:700,color:sc,minWidth:24,textAlign:"right",fontFamily:"monospace"}}>{f.score.toFixed(1)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Mini compliance rings */}
        <div style={{...CARD,display:"flex",flexDirection:"column",gap:12,minWidth:160}}>
          <div style={{fontSize:9,color:"#4a5568",fontWeight:600,letterSpacing:"0.1em",fontFamily:"monospace"}}>COVERAGE</div>
          {[
            {l:"CA Policies",total:15,pass:Object.values(findings.filter(f=>f.check_id.startsWith("AZURE-CA-")).reduce((a,f)=>{a[f.check_id]=f;return a},{})).filter(f=>f.status==="passed").length},
            {l:"MFA",total:9,pass:Object.values(findings.filter(f=>f.check_id.startsWith("AZURE-MFA-")).reduce((a,f)=>{a[f.check_id]=f;return a},{})).filter(f=>f.status==="passed").length},
            {l:"Identity",total:12,pass:Object.values(findings.filter(f=>f.check_id.startsWith("AZURE-IDENTITY-")).reduce((a,f)=>{a[f.check_id]=f;return a},{})).filter(f=>f.status==="passed").length},
            {l:"Apps",total:12,pass:Object.values(findings.filter(f=>f.check_id.startsWith("AZURE-APP-")||f.check_id.startsWith("AZURE-CONSENT-")).reduce((a,f)=>{a[f.check_id]=f;return a},{})).filter(f=>f.status==="passed").length},
          ].map(({l,total,pass})=>{
            const pct=total>0?Math.round((pass/total)*100):0;
            const c=pct>=80?"#34d399":pct>=60?"#fcd34d":"#f87171";
            const r=20,circ=2*Math.PI*r;
            return (
              <div key={l} style={{display:"flex",alignItems:"center",gap:10}}>
                <svg width="44" height="44" viewBox="0 0 44 44">
                  <circle cx="22" cy="22" r={r} fill="none" stroke="#2d3748" strokeWidth="4"/>
                  <circle cx="22" cy="22" r={r} fill="none" stroke={c} strokeWidth="4"
                    strokeLinecap="round" strokeDasharray={`${circ*pct/100} ${circ}`}
                    transform="rotate(-90 22 22)"
                    style={{transition:"stroke-dasharray 0.8s ease"}}/>
                  <text x="22" y="26" textAnchor="middle" fontSize="9" fontWeight="700" fill={c} fontFamily="monospace">{pct}%</text>
                </svg>
                <div>
                  <div style={{fontSize:11,color:"#8896aa",fontWeight:500}}>{l}</div>
                  <div style={{fontSize:9,color:"#374458",fontFamily:"monospace"}}>{pass}/{total} pass</div>
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

  const csv=()=>{
    const h=["Check ID","Title","Severity","Score","Status","Risk","Steps","Effort"];
    const rows=list.map(f=>{const r=REM[f.check_id];return[f.check_id,r?.title||"",f.severity,f.score,f.status,r?.risk||f.risk_description||"",r?.steps?.join(" | ")||f.remediation_steps||"",f.estimated_effort||""];});
    const c=[h,...rows].map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(",")).join("\n");
    const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([c],{type:"text/csv"}));a.download="findings.csv";a.click();
  };

  return (
    <div style={{animation:"fadeIn 0.25s ease"}}>
      {/* Toolbar */}
      <div style={{display:"flex",gap:6,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
        <input value={q} onChange={e=>{setQ(e.target.value);setPage(1);}}
          placeholder="Search check ID or title…"
          style={{padding:"6px 11px",background:"#1e293b",border:"1px solid #2d3748",
            color:"#8896aa",borderRadius:5,fontSize:11,width:240,fontFamily:"inherit"}}/>
        {["All","Critical","High","Medium","Low"].map(s=>(
          <button key={s} onClick={()=>{setSf(s);setPage(1);}}
            style={{padding:"5px 11px",borderRadius:4,fontSize:10,fontWeight:600,
              background:sf===s?(SC[s]||"#38bdf8")+"18":"#1e293b",
              border:`1px solid ${sf===s?(SC[s]||"#38bdf8")+"60":"#2d3748"}`,
              color:sf===s?(SC[s]||"#38bdf8"):"#4a5568",cursor:"pointer"}}>{s}</button>
        ))}
        <select value={st} onChange={e=>{setSt(e.target.value);setPage(1);}}
          style={{padding:"5px 10px",background:"#1e293b",border:"1px solid #2d3748",
            color:"#5a6a7e",borderRadius:5,fontSize:10,fontFamily:"inherit"}}>
          {["failed","All","passed","error"].map(s=><option key={s}>{s}</option>)}
        </select>
        <div style={{flex:1}}/>
        <span style={{fontSize:9,color:"#374458",fontFamily:"monospace"}}>{shown.length}/{list.length}</span>
        <button onClick={csv} style={{padding:"5px 12px",background:"#1e293b",
          border:"1px solid #2d3748",color:"#4a5568",borderRadius:4,fontSize:10,cursor:"pointer"}}>↓ CSV</button>
      </div>

      {/* List */}
      <div style={{display:"flex",flexDirection:"column",gap:2}}>
        {shown.length===0&&<div style={{textAlign:"center",padding:48,color:"#374458",fontSize:12,fontFamily:"monospace"}}>NO FINDINGS MATCH FILTER</div>}
        {shown.map(f=>{
          const r=REM[f.check_id];const isO=open===f.check_id;const isFx=fixed.has(f.check_id);
          const sc=sev(f);
          return (
            <div key={f.check_id} style={{border:`1px solid ${isO?"#2d5986":"#2d3748"}`,
              background:"#1e293b",borderRadius:6,overflow:"hidden"}}>
              <div onClick={()=>setOpen(isO?null:f.check_id)}
                style={{display:"grid",gridTemplateColumns:"4px 140px 1fr auto auto auto auto",
                  alignItems:"center",gap:10,padding:"9px 12px",cursor:"pointer"}}>
                <div style={{height:"100%",minHeight:28,background:sc,borderRadius:2}}/>
                <span style={{fontFamily:"monospace",fontSize:9,color:"#4a5568",overflow:"hidden",textOverflow:"ellipsis"}}>{f.check_id}</span>
                <span style={{fontSize:12,color:isFx?"#374458":"#c0cad8",fontWeight:500,
                  overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",
                  textDecoration:isFx?"line-through":"none"}}>{r?.title||f.check_id}</span>
                <Badge label={f.severity} color={sc} small/>
                <span style={{fontSize:9,padding:"2px 7px",borderRadius:3,fontWeight:700,
                  background:f.status==="passed"?"#34d39920":f.status==="failed"?"#f8717118":"#fb923c18",
                  color:f.status==="passed"?"#34d399":f.status==="failed"?"#f87171":"#fb923c",
                  border:`1px solid ${f.status==="passed"?"#34d39940":f.status==="failed"?"#f8717130":"#fb923c30"}`}}>
                  {f.status==="passed"?"✓ "+f.status:f.status}
                </span>
                <div style={{width:70}}><ScoreBar score={f.score}/></div>
                <div style={{display:"flex",gap:5,alignItems:"center"}}>
                  <button onClick={e=>{e.stopPropagation();tog(f.check_id);}}
                    style={{padding:"2px 8px",background:"transparent",
                      border:`1px solid ${isFx?"#34d39950":"#2d3748"}`,
                      color:isFx?"#34d399":"#374458",borderRadius:3,fontSize:9,cursor:"pointer",
                      fontFamily:"monospace"}}>{isFx?"✓ FIXED":"MARK FIXED"}</button>
                  <span style={{color:"#374458",fontSize:10}}>{isO?"▲":"▼"}</span>
                </div>
              </div>

              {isO&&(
                <div style={{borderTop:"1px solid #2d3748",padding:"16px 16px 16px 26px",
                  background:"#111827"}}>
                  {r?(
                    <>
                      <div style={{marginBottom:14}}>
                        <div style={{fontSize:9,color:"#f59e0b",fontWeight:700,letterSpacing:"0.1em",
                          fontFamily:"monospace",marginBottom:8}}>WHY THIS MATTERS</div>
                        <p style={{fontSize:12,color:"#8896aa",lineHeight:1.8,margin:0}}>{r.risk}</p>
                      </div>
                      <div style={{marginBottom:14}}>
                        <div style={{fontSize:9,color:"#34d399",fontWeight:700,letterSpacing:"0.1em",
                          fontFamily:"monospace",marginBottom:10}}>HOW TO FIX — STEP BY STEP</div>
                        <div style={{display:"flex",flexDirection:"column",gap:8}}>
                          {r.steps.map((s,i)=>(
                            <div key={i} style={{display:"flex",gap:10}}>
                              <div style={{width:20,height:20,borderRadius:"50%",
                                background:"#38bdf820",border:"1px solid #38bdf840",
                                display:"flex",alignItems:"center",justifyContent:"center",
                                fontSize:9,fontWeight:700,color:"#38bdf8",flexShrink:0,fontFamily:"monospace"}}>{i+1}</div>
                              <p style={{fontSize:12,color:"#8896aa",lineHeight:1.7,margin:0,paddingTop:1}}>{s}</p>
                            </div>
                          ))}
                        </div>
                        {r.ref&&<a href={r.ref} target="_blank"
                          style={{display:"inline-flex",alignItems:"center",gap:4,
                            marginTop:12,fontSize:10,color:"#38bdf8",textDecoration:"none",
                            padding:"3px 10px",border:"1px solid #1e4a7a",borderRadius:4}}>
                          ↗ Microsoft Documentation
                        </a>}
                      </div>
                    </>
                  ):(
                    <>
                      {f.risk_description&&<div style={{marginBottom:12}}>
                        <div style={{fontSize:9,color:"#f59e0b",fontWeight:700,letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:6}}>RISK</div>
                        <p style={{fontSize:12,color:"#8896aa",lineHeight:1.7,margin:0}}>{f.risk_description}</p>
                      </div>}
                      {f.remediation_steps&&<div style={{marginBottom:12}}>
                        <div style={{fontSize:9,color:"#34d399",fontWeight:700,letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:6}}>REMEDIATION</div>
                        <p style={{fontSize:12,color:"#8896aa",lineHeight:1.7,margin:0}}>{f.remediation_steps}</p>
                      </div>}
                    </>
                  )}
                  {f.affected_resources?.length>0&&(
                    <div>
                      <div style={{fontSize:9,color:"#4a5568",fontWeight:700,letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:6}}>
                        AFFECTED [{f.affected_resources.length}]
                      </div>
                      <div style={{background:"#1a2332",border:"1px solid #2d3748",borderRadius:4,
                        padding:"8px 10px",maxHeight:100,overflowY:"auto"}}>
                        {f.affected_resources.slice(0,8).map((r,i)=>(
                          <div key={i} style={{fontFamily:"monospace",fontSize:10,color:"#5a6a7e",marginBottom:2}}>
                            {typeof r==="string"?r:Object.entries(r).map(([k,v])=>`${k}: ${v}`).join("  ·  ")}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {f.evidence&&Object.keys(f.evidence).filter(k=>k!=="error").length>0&&(
                    <div style={{marginTop:10}}>
                      <div style={{fontSize:9,color:"#374458",fontWeight:700,letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:4}}>EVIDENCE</div>
                      <div style={{fontFamily:"monospace",fontSize:9,color:"#374458",lineHeight:1.6}}>
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
        <div style={{display:"flex",gap:4,justifyContent:"center",marginTop:12}}>
          {Array.from({length:pages},(_,i)=>(
            <button key={i} onClick={()=>setPage(i+1)}
              style={{padding:"4px 9px",borderRadius:3,fontSize:10,
                background:page===i+1?"#38bdf8":"#1e293b",
                border:"1px solid #2d3748",color:page===i+1?"#fff":"#4a5568",cursor:"pointer"}}>{i+1}</button>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Compliance ───────────────────────────────────────────────────────────────
function Compliance({findings}) {
  const [fw,setFw]=useState("NIST CSF");
  const sm=Object.fromEntries(findings.map(f=>[f.check_id,f.status]));
  return (
    <div style={{animation:"fadeIn 0.25s ease"}}>
      <div style={{display:"flex",gap:6,marginBottom:16}}>
        {Object.keys(FW).map(f=>(
          <button key={f} onClick={()=>setFw(f)}
            style={{padding:"6px 14px",borderRadius:4,fontSize:10,fontWeight:600,
              background:fw===f?"#38bdf818":"#1e293b",
              border:`1px solid ${fw===f?"#38bdf860":"#2d3748"}`,
              color:fw===f?"#38bdf8":"#4a5568",cursor:"pointer",fontFamily:"monospace"}}>{f}
          </button>
        ))}
      </div>
      {Object.entries(FW[fw]).map(([domain,ids])=>{
        const tot=ids.length;
        const pas=ids.filter(id=>sm[id]==="passed").length;
        const pct=tot?Math.round((pas/tot)*100):0;
        const c=pct>=80?"#34d399":pct>=60?"#fcd34d":"#f87171";
        return (
          <div key={domain} style={{background:"#1e293b",border:"1px solid #2d3748",
            borderRadius:8,padding:16,marginBottom:8}}>
            <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:8}}>
              <div style={{flex:1,fontSize:12,fontWeight:600,color:"#c0cad8"}}>{domain}</div>
              <span style={{fontSize:10,color:"#4a5568",fontFamily:"monospace"}}>{pas}/{tot} controls</span>
              <span style={{fontSize:14,fontWeight:800,color:c,fontFamily:"monospace"}}>{pct}%</span>
            </div>
            <div style={{height:4,background:"#2d3748",borderRadius:2,marginBottom:10}}>
              <div style={{height:"100%",borderRadius:2,background:c,width:`${pct}%`,transition:"width 0.8s"}}/>
            </div>
            <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
              {ids.map(id=>{const s=sm[id];const co=s==="passed"?"#34d399":s==="failed"?"#f87171":"#374458";
                return <span key={id} style={{fontFamily:"monospace",fontSize:8,
                  padding:"2px 5px",borderRadius:3,background:`${co}12`,color:co,border:`1px solid ${co}25`}}>{id}</span>;
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Remediation ──────────────────────────────────────────────────────────────
function Remediation({findings}) {
  const fail=findings.filter(f=>f.status==="failed");
  const byE={Low:[],Moderate:[],High:[]};
  fail.forEach(f=>{const e=f.estimated_effort||"Moderate";(byE[e]=byE[e]||[]).push(f);});
  const EM={Low:{l:"Quick Wins",c:"#34d399",d:"<1 hr"},Moderate:{l:"This Week",c:"#fcd34d",d:"1-7 days"},High:{l:"Project",c:"#fb923c",d:"Multi-week"}};
  return (
    <div style={{animation:"fadeIn 0.25s ease"}}>
      <p style={{fontSize:12,color:"#4a5568",marginBottom:16,lineHeight:1.6}}>
        Remediation tasks ordered by implementation effort — start with Quick Wins for maximum immediate risk reduction.
      </p>
      {["Low","Moderate","High"].map(e=>{
        const items=(byE[e]||[]).sort((a,b)=>b.score-a.score); if(!items.length)return null;
        const m=EM[e];
        return (
          <div key={e} style={{marginBottom:24}}>
            <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:10,
              padding:"8px 12px",background:"#1e293b",border:"1px solid #2d3748",borderRadius:5,
              borderLeft:`3px solid ${m.c}`}}>
              <span style={{fontWeight:700,color:m.c,fontSize:12,fontFamily:"monospace"}}>{m.l.toUpperCase()}</span>
              <span style={{fontSize:10,color:"#4a5568"}}>{m.d}</span>
              <span style={{marginLeft:"auto",fontSize:10,color:"#4a5568",fontFamily:"monospace"}}>{items.length} item{items.length!==1?"s":""}</span>
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {items.map(f=>{
                const r=REM[f.check_id];const sc=sev(f);
                return (
                  <div key={f.check_id} style={{background:"#1e293b",border:"1px solid #2d3748",
                    borderRadius:6,padding:"14px 16px",borderLeft:`3px solid ${sc}`}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6,flexWrap:"wrap"}}>
                      <span style={{fontFamily:"monospace",fontSize:9,color:"#4a5568"}}>{f.check_id}</span>
                      <Badge label={f.severity} color={sc} small/>
                      <div style={{width:70,marginLeft:"auto"}}><ScoreBar score={f.score}/></div>
                    </div>
                    <div style={{fontSize:13,fontWeight:600,color:"#d1d9e6",marginBottom:6}}>{r?.title||f.check_id}</div>
                    {r?.risk&&<p style={{fontSize:11,color:"#5a6a7e",lineHeight:1.65,margin:"0 0 10px"}}>{r.risk}</p>}
                    {r?.steps&&(
                      <div style={{background:"#111827",border:"1px solid #2d3748",borderRadius:4,padding:"10px 12px"}}>
                        <div style={{fontSize:9,color:"#34d399",fontWeight:700,letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:8}}>HOW TO FIX</div>
                        <div style={{display:"flex",flexDirection:"column",gap:5}}>
                          {r.steps.map((s,i)=>(
                            <div key={i} style={{display:"flex",gap:8,fontSize:11,color:"#5a6a7e",lineHeight:1.65}}>
                              <span style={{color:"#38bdf8",fontWeight:700,flexShrink:0,fontFamily:"monospace"}}>{i+1}.</span>
                              <span>{s}</span>
                            </div>
                          ))}
                        </div>
                        {r.ref&&<a href={r.ref} target="_blank"
                          style={{display:"inline-block",marginTop:8,fontSize:9,color:"#38bdf8",textDecoration:"none",fontFamily:"monospace"}}>
                          ↗ learn.microsoft.com
                        </a>}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
      {fail.length===0&&<div style={{textAlign:"center",padding:60}}>
        <div style={{fontSize:36,marginBottom:12}}>🎉</div>
        <div style={{color:"#34d399",fontSize:14,fontWeight:700}}>All checks passing — no remediation required</div>
      </div>}
    </div>
  );
}

// ─── History ──────────────────────────────────────────────────────────────────
function History({runs}) {
  return (
    <div style={{animation:"fadeIn 0.25s ease",display:"flex",flexDirection:"column",gap:4}}>
      {runs.length===0&&<div style={{textAlign:"center",padding:48,color:"#374458",fontSize:11,fontFamily:"monospace"}}>NO SCAN HISTORY — RUN FIRST SCAN</div>}
      {runs.map((r,i)=>{
        const sc=r.status==="completed"?"#34d399":r.status==="running"?"#fcd34d":"#f87171";
        return (
          <div key={r.id} style={{background:"#1e293b",border:"1px solid #2d3748",borderRadius:6,padding:"11px 14px"}}>
            <div style={{display:"flex",alignItems:"center",gap:10}}>
              <span style={{fontSize:9,color:"#374458",minWidth:24,fontFamily:"monospace"}}>#{runs.length-i}</span>
              <span style={{width:7,height:7,borderRadius:"50%",background:sc,flexShrink:0}}/>
              <Badge label={r.status.toUpperCase()} color={sc} small/>
              <span style={{fontSize:11,color:"#5a6a7e",fontFamily:"monospace"}}>
                {r.created_at?new Date(r.created_at).toLocaleString():"—"}
              </span>
              {r.status==="completed"&&<>
                <div style={{flex:1,height:1,background:"#2d3748"}}/>
                <span style={{fontSize:10,color:"#34d399",fontFamily:"monospace"}}>{r.checks_passed}P</span>
                <span style={{fontSize:10,color:"#f87171",fontFamily:"monospace"}}>{r.checks_failed}F</span>
                <span style={{fontSize:10,color:"#4a5568",fontFamily:"monospace"}}>{r.checks_skipped}S</span>
                <span style={{fontSize:9,color:"#374458",fontFamily:"monospace"}}>{r.checks_total} total</span>
              </>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Exceptions ───────────────────────────────────────────────────────────────
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
    <div style={{animation:"fadeIn 0.25s ease"}}>
      {/* Summary */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8,marginBottom:16}}>
        {Object.entries(EXS).map(([k,m])=>(
          <div key={k} style={{background:"#1e293b",border:`1px solid ${m.c}25`,borderRadius:8,padding:"12px 14px"}}>
            <div style={{fontSize:9,color:m.c,fontWeight:700,letterSpacing:"0.08em",fontFamily:"monospace"}}>{m.l.toUpperCase()}</div>
            <div style={{fontSize:26,fontWeight:800,color:m.c,marginTop:4,fontFamily:"monospace"}}>{ackd.filter(e=>e.status===k).length}</div>
          </div>
        ))}
      </div>

      {/* Acknowledged */}
      {ackd.length>0&&(
        <div style={{marginBottom:20}}>
          <div style={{fontSize:9,color:"#4a5568",fontWeight:700,letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:8}}>ACKNOWLEDGED ({ackd.length})</div>
          <div style={{display:"flex",flexDirection:"column",gap:3}}>
            {ackd.map(ex=>{const m=EXS[ex.status]||EXS.fixed;const t=REM[ex.check_id]?.title||ex.check_id;
              return (
                <div key={ex.check_id} style={{background:"#1e293b",border:`1px solid ${m.c}35`,borderRadius:5,padding:"9px 12px"}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                    <span style={{fontFamily:"monospace",fontSize:9,color:"#4a5568",minWidth:120,flexShrink:0}}>{ex.check_id}</span>
                    <span style={{flex:1,fontSize:11,color:"#8896aa",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{t}</span>
                    <Badge label={`${m.i} ${m.l}`} color={m.c} small/>
                    {ex.note&&<span style={{fontSize:10,color:"#4a5568",fontStyle:"italic",maxWidth:160,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>"{ex.note}"</span>}
                    <button onClick={()=>{setForm(ex.check_id);setFSt(ex.status);setFNote(ex.note||"");}}
                      style={{padding:"2px 8px",background:"transparent",border:"1px solid #2d3748",
                        color:"#4a5568",borderRadius:3,fontSize:9,cursor:"pointer",fontFamily:"monospace"}}>EDIT</button>
                    <button onClick={()=>{const u={...exs};delete u[ex.check_id];save(u);}}
                      style={{padding:"2px 8px",background:"transparent",border:"1px solid #f8717130",
                        color:"#f87171",borderRadius:3,fontSize:9,cursor:"pointer",fontFamily:"monospace"}}>REVOKE</button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Active findings */}
      <div style={{fontSize:9,color:"#4a5568",fontWeight:700,letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:8}}>
        ACTIVE FINDINGS — CLICK TO ACKNOWLEDGE ({filt.length})
      </div>
      <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Filter by check ID or title…"
        style={{width:"100%",padding:"7px 11px",background:"#1e293b",border:"1px solid #2d3748",
          color:"#8896aa",borderRadius:5,fontSize:11,marginBottom:8,fontFamily:"inherit"}}/>
      <div style={{display:"flex",flexDirection:"column",gap:2}}>
        {filt.map(f=>{
          const ex=exs[f.check_id];const m=ex?EXS[ex.status]:null;const t=REM[f.check_id]?.title||f.check_id;
          return (
            <div key={f.check_id} style={{background:"#1e293b",
              border:`1px solid ${ex?EXS[ex.status].c+"45":"#2d3748"}`,borderRadius:5}}>
              <div style={{display:"flex",alignItems:"center",gap:8,padding:"9px 12px",flexWrap:"wrap"}}>
                <div style={{width:3,background:sev(f),alignSelf:"stretch",borderRadius:2,flexShrink:0}}/>
                <span style={{fontFamily:"monospace",fontSize:9,color:"#4a5568",minWidth:120,flexShrink:0}}>{f.check_id}</span>
                <span style={{flex:1,fontSize:11,color:"#8896aa",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{t}</span>
                <Badge label={f.severity} color={sev(f)} small/>
                {ex?(
                  <Badge label={`${m.i} ${m.l}`} color={m.c} small/>
                ):(
                  <button onClick={()=>{setForm(f.check_id);setFSt("fixed");setFNote("");}}
                    style={{padding:"5px 14px",background:"#38bdf818",
                      border:"1px solid #38bdf840",color:"#38bdf8",
                      borderRadius:4,fontSize:10,fontWeight:700,cursor:"pointer",
                      fontFamily:"monospace",flexShrink:0,letterSpacing:"0.05em"}}>+ ACK</button>
                )}
              </div>
            </div>
          );
        })}
        {filt.length===0&&<div style={{textAlign:"center",padding:24,color:"#374458",fontSize:11,fontFamily:"monospace"}}>NO ACTIVE FINDINGS</div>}
      </div>

      {/* Modal */}
      {form&&(
        <div style={{position:"fixed",inset:0,background:"#00000095",display:"flex",
          alignItems:"center",justifyContent:"center",zIndex:9999}}
          onClick={()=>setForm(null)}>
          <div onClick={e=>e.stopPropagation()}
            style={{background:"#1e293b",border:"1px solid #1e4a7a",borderRadius:10,
              width:"min(480px,95vw)",padding:24,
              boxShadow:"0 40px 80px #000c,0 0 0 1px #2d3748"}}>
            <div style={{fontSize:9,color:"#38bdf8",fontWeight:700,letterSpacing:"0.12em",
              fontFamily:"monospace",marginBottom:4}}>ACKNOWLEDGE FINDING</div>
            <div style={{fontFamily:"monospace",fontSize:10,color:"#4a5568",marginBottom:4}}>{form}</div>
            <div style={{fontSize:14,fontWeight:600,color:"#d1d9e6",marginBottom:20,lineHeight:1.4}}>
              {REM[form]?.title||form}
            </div>

            <div style={{fontSize:9,color:"#4a5568",fontWeight:700,letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:10}}>STATUS</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginBottom:18}}>
              {Object.entries(EXS).map(([k,m])=>(
                <button key={k} onClick={()=>setFSt(k)}
                  style={{padding:"10px 12px",textAlign:"left",borderRadius:6,
                    background:fSt===k?m.c+"22":"#111827",
                    border:`2px solid ${fSt===k?m.c:"#2d3748"}`,
                    color:fSt===k?m.c:"#4a5568",
                    fontSize:11,fontWeight:fSt===k?700:400,cursor:"pointer",
                    display:"flex",alignItems:"center",gap:8,transition:"all 0.12s"}}>
                  <span style={{fontSize:17}}>{m.i}</span>{m.l}
                </button>
              ))}
            </div>

            <div style={{fontSize:9,color:"#4a5568",fontWeight:700,letterSpacing:"0.1em",fontFamily:"monospace",marginBottom:6}}>NOTES</div>
            <textarea value={fNote} onChange={e=>setFNote(e.target.value)}
              placeholder="e.g. Compensating control in place — SIEM alert active. Review Q3 2026."
              style={{width:"100%",height:76,padding:"8px 11px",background:"#111827",
                border:"1px solid #2d3748",color:"#8896aa",borderRadius:5,
                fontSize:11,resize:"vertical",marginBottom:16,fontFamily:"inherit",
                lineHeight:1.6}}/>

            <div style={{display:"flex",gap:8,justifyContent:"flex-end"}}>
              <button onClick={()=>setForm(null)}
                style={{padding:"8px 16px",background:"transparent",border:"1px solid #2d3748",
                  color:"#4a5568",borderRadius:5,fontSize:11,cursor:"pointer"}}>Cancel</button>
              <button onClick={()=>saveEx(form)} disabled={saving}
                style={{padding:"8px 22px",minWidth:170,justifyContent:"center",
                  background:saved?"#34d399":saving?"#38bdf860":"linear-gradient(135deg,#38bdf8,#818cf8)",
                  color:"#fff",borderRadius:5,fontSize:11,fontWeight:700,
                  border:"none",cursor:saving?"not-allowed":"pointer",
                  display:"flex",alignItems:"center",gap:8,transition:"background 0.2s"}}>
                {saving?<><div style={{width:11,height:11,border:"2px solid #fff",
                  borderTopColor:"transparent",borderRadius:"50%",
                  animation:"spin 0.7s linear infinite"}}/>Saving…</>
                  :saved?"✓ Saved!":"Save Acknowledgement"}
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
  const [view, setView] = useState("dashboard");
  const [findings, setFindings] = useState([]);
  const [runs, setRuns] = useState([]);
  const [targets, setTargets] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [online, setOnline] = useState(false);
  const poll = useRef(null);

  const load = useCallback(async () => {
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
        if(poll.current) { clearInterval(poll.current); poll.current=null; }
      }
    } catch { setOnline(false); }
  }, []);

  useEffect(() => {
    load();
    const iv = setInterval(load, 15000);
    return () => { clearInterval(iv); if(poll.current) clearInterval(poll.current); };
  }, [load]);

  const scan = async () => {
    try {
      const t = await apiFetch("/targets"); const list = t.items||[];
      if(!list.length) { alert("No target configured — check Azure credentials in .env"); return; }
      setScanning(true);
      await apiPost("/assessments/run", {target_id:list[0].id});
      if(poll.current) clearInterval(poll.current);
      poll.current = setInterval(load, 3000);
    } catch(e) { alert("Scan failed: "+e); setScanning(false); }
  };

  const fail = findings.filter(f=>f.status==="failed");
  const crit = fail.filter(f=>f.severity==="Critical").length;
  const last = runs.find(r=>r.status==="completed")?.completed_at;

  const VIEWS = {
    dashboard:   <Dashboard findings={findings} runs={runs}/>,
    findings:    <Findings findings={findings}/>,
    compliance:  <Compliance findings={findings}/>,
    remediation: <Remediation findings={findings}/>,
    history:     <History runs={runs}/>,
    exceptions:  <Exceptions findings={findings}/>,
  };

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700;800&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;}
        body{
          background:#111827;
          color:#d1d9e6;
          font-family:'Inter',system-ui,sans-serif;
          font-size:14px;
          line-height:1.6;
          -webkit-font-smoothing:antialiased;
          text-rendering:optimizeLegibility;
        }
        ::-webkit-scrollbar-thumb:hover{background:#4a5568;}
        a{color:#38bdf8;}
        ::-webkit-scrollbar{width:4px;height:4px;}
        ::-webkit-scrollbar-track{background:#1a2332;}
        ::-webkit-scrollbar-thumb{background:#2d3748;border-radius:2px;}
        input,textarea,select{outline:none;font-family:inherit;}
        button{font-family:inherit;}
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
        @keyframes blink{0%,100%{opacity:1}50%{opacity:0.3}}
        @media(max-width:768px){
          .nav-aside{display:none!important;}
          .main-wrap{margin-left:0!important;}
          .top-header{left:0!important;}
        }
      `}</style>
      <Nav view={view} setView={setView} fails={fail.length}/>
      <Top target={targets[0]} scanning={scanning} onScan={scan} online={online} lastScan={last} crits={crit}/>
      <main className="main-wrap" style={{marginLeft:216,marginTop:52,padding:22,minHeight:"calc(100vh - 52px)"}}>
        {VIEWS[view]||VIEWS.dashboard}
      </main>
    </>
  );
}
