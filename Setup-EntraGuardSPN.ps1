<#
.SYNOPSIS
    Creates the EntraGuard-CSPM App Registration in Microsoft Entra ID and assigns
    all required Microsoft Graph API permissions with admin consent.

.DESCRIPTION
    This script automates the full Azure App Registration setup for EntraGuard.
    It will:
      1. Connect to Microsoft Graph (interactive browser login)
      2. Create the EntraGuard-CSPM App Registration
      3. Create a Service Principal for the app
      4. Add all 13 required Graph API application permissions
      5. Grant admin consent for all permissions
      6. Create a client secret (12-month expiry)
      7. Output the .env values ready to paste into your EntraGuard .env file

.PREREQUISITES
    - PowerShell 7.0 or later  (winget install Microsoft.PowerShell)
    - Microsoft.Graph PowerShell SDK:
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    - You must be a Global Administrator or Privileged Role Administrator
      in the target Entra ID tenant to grant admin consent.

.USAGE
    .\Setup-EntraGuardSPN.ps1

    Optional parameters:
      -AppName        Override the default app name  (default: EntraGuard-CSPM)
      -SecretMonths   Client secret validity in months (default: 12, max: 24)
      -TenantId       Specify tenant ID to skip interactive tenant picker

.EXAMPLE
    .\Setup-EntraGuardSPN.ps1
    .\Setup-EntraGuardSPN.ps1 -AppName "EntraGuard-Prod" -SecretMonths 24
    .\Setup-EntraGuardSPN.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.NOTES
    Author : Junaid Ahmed <iam@jahmed.cloud>
    Version: 1.0
    Project: https://github.com/jahmed-cloud/entra-guard
#>

[CmdletBinding()]
param (
    [string] $AppName     = "EntraGuard-CSPM",
    [int]    $SecretMonths = 12,
    [string] $TenantId    = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─── Colour helpers ──────────────────────────────────────────────────────────
function Write-Step   { param($msg) Write-Host "`n▶  $msg" -ForegroundColor Cyan }
function Write-OK     { param($msg) Write-Host "   ✓  $msg" -ForegroundColor Green }
function Write-Warn   { param($msg) Write-Host "   ⚠  $msg" -ForegroundColor Yellow }
function Write-Fail   { param($msg) Write-Host "   ✗  $msg" -ForegroundColor Red }

# ─── Banner ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "║          EntraGuard — SPN Setup Script  v1.0                ║" -ForegroundColor Blue
Write-Host "║          github.com/jahmed-cloud/entra-guard                ║" -ForegroundColor Blue
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Blue
Write-Host ""

# ─── Step 0: Check prerequisites ─────────────────────────────────────────────
Write-Step "Checking prerequisites..."

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Fail "PowerShell 7+ is required. Current version: $($PSVersionTable.PSVersion)"
    Write-Host "   Install via: winget install Microsoft.PowerShell" -ForegroundColor Yellow
    exit 1
}
Write-OK "PowerShell $($PSVersionTable.PSVersion)"

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Warn "Microsoft.Graph module not found. Installing..."
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
    Write-OK "Microsoft.Graph installed"
} else {
    Write-OK "Microsoft.Graph module found"
}

# ─── Step 1: Connect to Microsoft Graph ──────────────────────────────────────
Write-Step "Connecting to Microsoft Graph..."

$connectParams = @{
    Scopes = @(
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "Directory.ReadWrite.All"
    )
}
if ($TenantId -ne "") {
    $connectParams["TenantId"] = $TenantId
}

try {
    Connect-MgGraph @connectParams -NoWelcome
    $context   = Get-MgContext
    $TenantId  = $context.TenantId
    Write-OK "Connected to tenant: $TenantId"
    Write-OK "Signed in as: $($context.Account)"
} catch {
    Write-Fail "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# ─── Step 2: Check for existing App Registration ──────────────────────────────
Write-Step "Checking for existing App Registration named '$AppName'..."

$existingApp = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue |
               Select-Object -First 1

if ($existingApp) {
    Write-Warn "App Registration '$AppName' already exists (ID: $($existingApp.Id))"
    $choice = Read-Host "   Do you want to update the existing app? [y/N]"
    if ($choice -notmatch "^[Yy]$") {
        Write-Host "`n   Exiting. No changes made." -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        exit 0
    }
    $app = $existingApp
    Write-OK "Will update existing app registration"
} else {
    $app = $null
    Write-OK "No existing app found — will create a new one"
}

# ─── Step 3: Define required permissions ──────────────────────────────────────
Write-Step "Resolving Microsoft Graph API permission IDs..."

# Microsoft Graph Service Principal App ID (constant across all tenants)
$graphAppId = "00000003-0000-0000-c000-000000000000"

$requiredPermissions = @(
    "AuditLog.Read.All",
    "Directory.Read.All",
    "Policy.Read.All",
    "PrivilegedAccess.Read.AzureAD",
    "IdentityRiskyUser.Read.All",
    "AccessReview.Read.All",
    "SecurityEvents.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Application.Read.All",
    "Group.Read.All",
    "RoleManagement.Read.Directory",
    "Reports.Read.All"
)

# Fetch the Graph SP to resolve permission GUIDs
$graphSP = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
if (-not $graphSP) {
    Write-Fail "Could not find Microsoft Graph service principal in this tenant."
    exit 1
}

$resolvedRoles = @()
$notFound      = @()

foreach ($permName in $requiredPermissions) {
    $role = $graphSP.AppRoles | Where-Object { $_.Value -eq $permName -and $_.AllowedMemberTypes -contains "Application" }
    if ($role) {
        $resolvedRoles += $role
        Write-OK "$permName  ($($role.Id))"
    } else {
        $notFound += $permName
        Write-Warn "$permName — NOT FOUND (permission may have been renamed)"
    }
}

if ($notFound.Count -gt 0) {
    Write-Warn "$($notFound.Count) permission(s) could not be resolved. Proceeding with the rest."
}

# Build the requiredResourceAccess object
$resourceAccess = $resolvedRoles | ForEach-Object {
    @{ id = $_.Id; type = "Role" }
}

$requiredResourceAccessBody = @(
    @{
        resourceAppId  = $graphAppId
        resourceAccess = $resourceAccess
    }
)

# ─── Step 4: Create or update the App Registration ───────────────────────────
Write-Step "Creating / updating App Registration..."

if ($null -eq $app) {
    $appBody = @{
        displayName            = $AppName
        signInAudience         = "AzureADMyOrg"
        requiredResourceAccess = $requiredResourceAccessBody
        notes                  = "EntraGuard CSPM — Azure Identity Security Posture Management. See https://github.com/jahmed-cloud/entra-guard"
    }
    $app = New-MgApplication -BodyParameter $appBody
    Write-OK "App Registration created: $($app.DisplayName)  (Object ID: $($app.Id))"
    Write-OK "Application (client) ID:  $($app.AppId)"
} else {
    Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $requiredResourceAccessBody
    Write-OK "App Registration updated with latest permissions"
}

$clientId = $app.AppId

# ─── Step 5: Create or find the Service Principal ────────────────────────────
Write-Step "Ensuring Service Principal exists..."

$sp = Get-MgServicePrincipal -Filter "appId eq '$clientId'" -ErrorAction SilentlyContinue |
      Select-Object -First 1

if (-not $sp) {
    $sp = New-MgServicePrincipal -AppId $clientId
    Write-OK "Service Principal created: $($sp.Id)"
} else {
    Write-OK "Service Principal already exists: $($sp.Id)"
}

# ─── Step 6: Grant admin consent ─────────────────────────────────────────────
Write-Step "Granting admin consent for all permissions..."

# Get the Graph SP to use as the resource
$graphSpId = $graphSP.Id
$granted   = 0
$skipped   = 0

foreach ($role in $resolvedRoles) {
    # Check if assignment already exists
    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue |
                Where-Object { $_.AppRoleId -eq $role.Id -and $_.ResourceId -eq $graphSpId }

    if ($existing) {
        $skipped++
        continue
    }

    try {
        $assignBody = @{
            principalId = $sp.Id
            resourceId  = $graphSpId
            appRoleId   = $role.Id
        }
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -BodyParameter $assignBody | Out-Null
        Write-OK "Consented: $($role.Value)"
        $granted++
    } catch {
        Write-Warn "Could not grant consent for $($role.Value): $_"
    }
}

Write-OK "$granted permission(s) consented; $skipped already had consent"

# ─── Step 7: Create client secret ────────────────────────────────────────────
Write-Step "Creating client secret (valid for $SecretMonths months)..."

$secretExpiry = (Get-Date).AddMonths($SecretMonths).ToString("yyyy-MM-ddTHH:mm:ssZ")

$secretBody = @{
    passwordCredential = @{
        displayName = "EntraGuard-Secret-$(Get-Date -Format 'yyyy-MM-dd')"
        endDateTime = $secretExpiry
    }
}

try {
    $secret = Add-MgApplicationPassword -ApplicationId $app.Id -BodyParameter $secretBody
    $clientSecret = $secret.SecretText
    Write-OK "Client secret created (expires: $secretExpiry)"
    Write-Warn "IMPORTANT: Copy the secret value now — it will NOT be shown again."
} catch {
    Write-Fail "Failed to create client secret: $_"
    Write-Host "   You can create one manually in the Azure Portal under:" -ForegroundColor Yellow
    Write-Host "   Entra ID → App Registrations → $AppName → Certificates & secrets" -ForegroundColor Yellow
    $clientSecret = "<CREATE_MANUALLY_IN_AZURE_PORTAL>"
}

# ─── Step 8: Output .env values ──────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              Setup Complete — Copy to your .env             ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "# Azure / Entra ID credentials — paste into your .env file"    -ForegroundColor DarkGray
Write-Host "AZURE_TENANT_ID=$TenantId"     -ForegroundColor White
Write-Host "AZURE_CLIENT_ID=$clientId"     -ForegroundColor White
Write-Host "AZURE_CLIENT_SECRET=$clientSecret" -ForegroundColor Yellow
Write-Host ""

# ─── Step 9: Verify consent in portal (informational) ────────────────────────
$portalUrl = "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$clientId"
Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host " Verify permissions in Azure Portal:" -ForegroundColor DarkGray
Write-Host " $portalUrl" -ForegroundColor DarkGray
Write-Host " (API permissions → should show all 13 permissions as 'Granted')" -ForegroundColor DarkGray
Write-Host "─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# ─── Step 10: Reminder about secret rotation ──────────────────────────────────
$expiryDate = (Get-Date).AddMonths($SecretMonths).ToString("dd MMMM yyyy")
Write-Warn "Set a calendar reminder to rotate the client secret before: $expiryDate"
Write-Host ""

# ─── Disconnect ───────────────────────────────────────────────────────────────
Disconnect-MgGraph | Out-Null
Write-OK "Disconnected from Microsoft Graph"
Write-Host ""
Write-Host "EntraGuard SPN setup complete. You are ready to deploy." -ForegroundColor Cyan
Write-Host ""
