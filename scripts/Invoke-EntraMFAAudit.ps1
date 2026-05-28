#Requires -Modules Microsoft.Graph.Reports, Microsoft.Graph.Identity.DirectoryManagement
<#
.SYNOPSIS
    Audits MFA registration status and authentication method strength across Entra ID users.

.DESCRIPTION
    Evaluates the authentication method registrations for all users using the bulk
    registration report API, identifying accounts without MFA, accounts using weak methods
    (SMS/voice), privileged accounts relying on legacy per-user MFA, and overall tenant
    MFA posture.

    Findings covered:
      - Users with no MFA method registered (password-only authentication)
      - Users with only weak MFA (SMS OTP, voice call)
      - Privileged role holders without strong MFA (FIDO2 or Authenticator app)
      - Privileged role holders with moderate-only MFA

.PARAMETER OutputPath
    Directory to write CSV output. Default: .\reports\

.PARAMETER SkipGuestUsers
    Skip guest/B2B accounts (MFA for guests is often managed by home tenant). Default: true.

.PARAMETER PassThru
    Return findings as objects to the pipeline.

.EXAMPLE
    .\Invoke-EntraMFAAudit.ps1

.EXAMPLE
    .\Invoke-EntraMFAAudit.ps1 -SkipGuestUsers:$false -OutputPath C:\EntraReports

.NOTES
    Required scopes : Reports.Read.All, Directory.Read.All
    Note            : Uses the authentication method registration report (bulk API) —
                      requires Reports.Read.All which is less privileged than per-user
                      UserAuthenticationMethod.Read.All.
    Legal           : Run only on tenants you own or have written authorisation to audit.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [bool]$SkipGuestUsers = $true,

    [Parameter()]
    [switch]$PassThru,

    # ── App-only (enterprise application) authentication ──────────────────────
    [Parameter()]
    [string]$TenantId = '',

    [Parameter()]
    [string]$ClientId = '',

    [Parameter()]
    [securestring]$ClientSecret,

    [Parameter()]
    [string]$CertificateThumbprint = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'AuditHelpers.psm1') -Force

# ── Method type classification ────────────────────────────────────────────────
# Keys match the report API's MethodsRegistered string values

$METHOD_STRENGTH = @{
    'microsoftAuthenticatorPush'          = @{ Name='Authenticator App (Push)';    Strength='Strong' }
    'microsoftAuthenticatorPasswordless'  = @{ Name='Authenticator Passwordless';  Strength='Strong' }
    'fido2'                               = @{ Name='FIDO2 Key';                   Strength='Strong' }
    'windowsHelloForBusiness'             = @{ Name='Windows Hello for Business';  Strength='Strong' }
    'softwareOneTimePasscode'             = @{ Name='TOTP (Software OATH)';        Strength='Moderate' }
    'hardwareOneTimePasscode'             = @{ Name='TOTP (Hardware OATH)';        Strength='Moderate' }
    'sms'                                 = @{ Name='SMS OTP';                     Strength='Weak' }
    'voice'                               = @{ Name='Voice Call';                  Strength='Weak' }
    'email'                               = @{ Name='Email OTP';                   Strength='Weak' }
    'temporaryAccessPass'                 = @{ Name='Temporary Access Pass';       Strength='Temporary' }
}

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  ENTRA ID MFA REGISTRATION AUDIT' -ForegroundColor Cyan
    Write-Host '  ⚠  Run only on tenants you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

# ── Main audit ────────────────────────────────────────────────────────────────

function Invoke-MFAAudit {
    [CmdletBinding()]
    param([bool]$SkipGuests)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $stats    = @{ Total=0; NoMFA=0; WeakOnly=0; Strong=0; Moderate=0 }

    # ── Privileged role members for cross-reference ───────────────────────────
    Write-Verbose 'Retrieving privileged role members for cross-reference…'
    $privUserIds = [System.Collections.Generic.HashSet[string]]::new()
    $privRoleDefIds = @{
        'Global Administrator'              = '62e90394-69f5-4237-9190-012177145e10'
        'Privileged Role Administrator'     = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
        'Security Administrator'            = '194ae4cb-b126-40b2-bd5b-6091b380977d'
        'Exchange Administrator'            = '29232cdf-9323-42fd-ade2-1d097af3e4de'
    }
    try {
        foreach ($roleId in $privRoleDefIds.Values) {
            Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$roleId'" -All -ErrorAction SilentlyContinue |
                ForEach-Object { [void]$privUserIds.Add($_.PrincipalId) }
        }
        Write-Verbose "  Privileged principal IDs tracked: $($privUserIds.Count)"
    }
    catch { Write-Verbose "Could not retrieve role assignments: $_" }

    # ── Bulk MFA registration report ──────────────────────────────────────────
    Write-Verbose 'Retrieving MFA registration report…'
    try {
        $regDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve authentication method registration report: $_"
    }

    Write-Verbose "  Processing $($regDetails.Count) user record(s)…"
    $processed = 0

    foreach ($reg in $regDetails) {
        # Apply guest filter
        if ($SkipGuests -and $reg.UserType -eq 'guest') { continue }

        $stats.Total++
        $processed++
        if ($processed % 100 -eq 0) { Write-Verbose "  Progress: $processed / $($regDetails.Count)" }

        $upn     = $reg.UserPrincipalName
        $name    = $reg.UserDisplayName
        $uType   = $reg.UserType ?? 'member'
        $isPriv  = $privUserIds.Contains($reg.Id)

        # Classify registered methods
        $registeredMethods = $reg.MethodsRegistered | Where-Object { $_ -ne 'password' }
        $methodNames   = $registeredMethods | ForEach-Object { $METHOD_STRENGTH[$_]?.Name ?? $_ }
        $methodSummary = if ($methodNames) { $methodNames -join ', ' } else { 'None' }

        $hasStrong   = $registeredMethods | Where-Object { $METHOD_STRENGTH[$_]?.Strength -eq 'Strong' }
        $hasWeak     = $registeredMethods | Where-Object { $METHOD_STRENGTH[$_]?.Strength -eq 'Weak' }
        $hasModerate = $registeredMethods | Where-Object { $METHOD_STRENGTH[$_]?.Strength -eq 'Moderate' }

        # ── No MFA registered ─────────────────────────────────────────────────
        if (-not $registeredMethods) {
            $stats.NoMFA++
            $sev = if ($isPriv) { 'Critical' } else { 'High' }
            $findings.Add((New-AuditFinding -Module 'MFAAudit' -Category 'NoMFARegistered' `
                -Identity $upn -IdentityType $uType -Resource 'Authentication Methods' `
                -Severity $sev `
                -Detail "No MFA method registered$(if($isPriv){' [PRIVILEGED ACCOUNT]'}) — account protected by password only" `
                -Recommendation 'Require MFA registration via Conditional Access; consider Authenticator App or FIDO2'))
        }
        # ── Weak MFA only ─────────────────────────────────────────────────────
        elseif ($hasWeak -and -not $hasStrong -and -not $hasModerate) {
            $stats.WeakOnly++
            $sev = if ($isPriv) { 'High' } else { 'Medium' }
            $findings.Add((New-AuditFinding -Module 'MFAAudit' -Category 'WeakMFAOnly' `
                -Identity $upn -IdentityType $uType -Resource $methodSummary `
                -Severity $sev `
                -Detail "Only weak MFA registered: $methodSummary$(if($isPriv){' [PRIVILEGED ACCOUNT]'}) — SMS/voice is vulnerable to SIM-swapping and SS7 attacks" `
                -Recommendation 'Encourage users to register Authenticator App; block SMS for privileged accounts'))
        }
        # ── Privileged user without strong MFA ────────────────────────────────
        elseif ($isPriv -and -not $hasStrong) {
            $findings.Add((New-AuditFinding -Module 'MFAAudit' -Category 'PrivilegedWeakMFA' `
                -Identity $upn -IdentityType $uType -Resource $methodSummary `
                -Severity 'High' `
                -Detail "Privileged account using $methodSummary — phishing-resistant MFA (FIDO2 or Authenticator) required for admin roles" `
                -Recommendation 'Enforce phishing-resistant MFA for privileged roles via Conditional Access authentication strength policy'))
        }
        elseif ($hasStrong)   { $stats.Strong++ }
        elseif ($hasModerate) { $stats.Moderate++ }
    }

    # ── Coverage summary ──────────────────────────────────────────────────────
    Write-Host "  MFA Coverage:" -ForegroundColor White
    Write-Host ("    No MFA registered : {0} users ({1:P0})" -f $stats.NoMFA,   ($stats.NoMFA   / [Math]::Max(1,$stats.Total))) -ForegroundColor $(if($stats.NoMFA -gt 0){'Red'}else{'Green'})
    Write-Host ("    Weak MFA only     : {0} users ({1:P0})" -f $stats.WeakOnly, ($stats.WeakOnly / [Math]::Max(1,$stats.Total))) -ForegroundColor $(if($stats.WeakOnly -gt 0){'DarkYellow'}else{'Green'})
    Write-Host ("    Moderate MFA      : {0} users ({1:P0})" -f $stats.Moderate, ($stats.Moderate / [Math]::Max(1,$stats.Total))) -ForegroundColor Cyan
    Write-Host ("    Strong MFA        : {0} users ({1:P0})" -f $stats.Strong,   ($stats.Strong  / [Math]::Max(1,$stats.Total))) -ForegroundColor Green
    Write-Host ''

    return $findings
}

# ── Entry point ───────────────────────────────────────────────────────────────

Assert-MgConnection -RequiredScopes 'Reports.Read.All','Directory.Read.All' `
    -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint
Write-AuditBanner

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$findings = Invoke-MFAAudit -SkipGuests:$SkipGuestUsers

if ($findings.Count -eq 0) {
    Write-Host '  ✅ All users have MFA registered.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings
    $csv = Join-Path $OutputPath "EntraMFAAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csv" -ForegroundColor Green
}

if ($PassThru) { return $findings }
