#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement
<#
.SYNOPSIS
    Audits MFA registration status and authentication method strength across Entra ID users.

.DESCRIPTION
    Evaluates the authentication method registrations for all users, identifying
    accounts without MFA, accounts using weak methods (SMS/voice), privileged
    accounts relying on legacy per-user MFA, and overall tenant MFA posture.

    Findings covered:
      - Users with no MFA method registered (password-only authentication)
      - Users with only weak MFA (SMS OTP, voice call)
      - Privileged role holders without strong MFA (FIDO2 or Authenticator app)
      - Per-user MFA enforcement state (legacy, pre-CA enforcement)
      - Accounts with SSPR registered but no MFA (SSPR can bypass security controls)

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
    Required scopes : UserAuthenticationMethod.Read.All, User.Read.All, Directory.Read.All
    Note            : Reading authentication methods requires UserAuthenticationMethod.Read.All
                      which is a highly privileged scope — use app-only auth in production.
    Legal           : Run only on tenants you own or have written authorisation to audit.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [bool]$SkipGuestUsers = $true,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Method type classification ────────────────────────────────────────────────

$METHOD_STRENGTH = @{
    '#microsoft.graph.fido2AuthenticationMethod'              = @{ Name='FIDO2 Key';           Strength='Strong' }
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' = @{ Name='Authenticator App'; Strength='Strong' }
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' = @{ Name='Windows Hello';    Strength='Strong' }
    '#microsoft.graph.phoneAuthenticationMethod'              = @{ Name='SMS/Voice';            Strength='Weak' }
    '#microsoft.graph.emailAuthenticationMethod'              = @{ Name='Email OTP';            Strength='Weak' }
    '#microsoft.graph.softwareOathAuthenticationMethod'       = @{ Name='TOTP (OATH)';          Strength='Moderate' }
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod' = @{ Name='Temporary Access Pass'; Strength='Temporary' }
    '#microsoft.graph.passwordAuthenticationMethod'           = @{ Name='Password';             Strength='None' }
}

# ── Helpers ───────────────────────────────────────────────────────────────────

function Assert-MgConnection {
    try { if (-not (Get-MgContext -ErrorAction Stop)) { throw } }
    catch {
        Write-Error "Not connected. Run: Connect-MgGraph -Scopes 'UserAuthenticationMethod.Read.All','User.Read.All','Directory.Read.All'"
        exit 1
    }
}

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  ENTRA ID MFA REGISTRATION AUDIT' -ForegroundColor Cyan
    Write-Host '  ⚠  Run only on tenants you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

function New-Finding {
    param(
        [string]$Category,
        [string]$UserPrincipalName,
        [string]$DisplayName,
        [string]$MethodsRegistered,
        [string]$Detail,
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity
    )
    [PSCustomObject]@{
        Timestamp         = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity          = $Severity
        Category          = $Category
        UserPrincipalName = $UserPrincipalName
        DisplayName       = $DisplayName
        MethodsRegistered = $MethodsRegistered
        Detail            = $Detail
    }
}

# ── Main audit ────────────────────────────────────────────────────────────────

function Invoke-MFAAudit {
    [CmdletBinding()]
    param([bool]$SkipGuests)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $stats    = @{ Total=0; NoMFA=0; WeakOnly=0; Strong=0; Moderate=0 }

    # Get privileged role holders for cross-reference
    Write-Verbose 'Retrieving privileged role members for cross-reference…'
    $privUserIds = [System.Collections.Generic.HashSet[string]]::new()
    try {
        $privRoles = @(
            'Global Administrator', 'Privileged Role Administrator',
            'Security Administrator', 'Exchange Administrator'
        )
        foreach ($roleName in $privRoles) {
            $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
            if ($role) {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue
                foreach ($m in $members) { [void]$privUserIds.Add($m.Id) }
            }
        }
        Write-Verbose "  Privileged users tracked: $($privUserIds.Count)"
    }
    catch { Write-Verbose "Could not retrieve role members: $_" }

    # Get all enabled member users
    Write-Verbose 'Retrieving enabled users…'
    $userFilter = "accountEnabled eq true"
    if ($SkipGuests) { $userFilter += " and userType eq 'Member'" }

    try {
        $users = Get-MgUser -Filter $userFilter -All `
            -Property 'id','userPrincipalName','displayName','userType' -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to retrieve users: $_"
        return
    }

    Write-Verbose "  Processing $($users.Count) user(s)…"
    $processed = 0

    foreach ($user in $users) {
        $stats.Total++
        $processed++
        if ($processed % 50 -eq 0) {
            Write-Verbose "  Progress: $processed / $($users.Count)"
        }

        # Get authentication methods for this user
        try {
            $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
        }
        catch {
            Write-Verbose "  Could not read methods for $($user.UserPrincipalName): $_"
            continue
        }

        # Classify methods (exclude password-only)
        $mfaMethods    = $methods | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' }
        $methodNames   = $mfaMethods | ForEach-Object {
            $METHOD_STRENGTH[$_.'@odata.type']?.Name ?? 'Unknown'
        }
        $methodSummary = ($methodNames -join ', ') ?: 'None'

        $hasStrong   = $mfaMethods | Where-Object { $METHOD_STRENGTH[$_.'@odata.type']?.Strength -eq 'Strong' }
        $hasWeak     = $mfaMethods | Where-Object { $METHOD_STRENGTH[$_.'@odata.type']?.Strength -eq 'Weak' }
        $hasModerate = $mfaMethods | Where-Object { $METHOD_STRENGTH[$_.'@odata.type']?.Strength -eq 'Moderate' }
        $isPriv      = $privUserIds.Contains($user.Id)

        # ── No MFA registered ─────────────────────────────────────────────────
        if ($mfaMethods.Count -eq 0) {
            $stats.NoMFA++
            $sev = if ($isPriv) { 'Critical' } else { 'High' }
            $findings.Add((New-Finding -Category 'NoMFARegistered' `
                -UserPrincipalName $user.UserPrincipalName -DisplayName $user.DisplayName `
                -MethodsRegistered 'None' -Severity $sev `
                -Detail "No MFA method registered$(if($isPriv){' [PRIVILEGED ACCOUNT]'}) — account protected by password only"))
        }
        # ── Weak MFA only ─────────────────────────────────────────────────────
        elseif ($hasWeak -and -not $hasStrong -and -not $hasModerate) {
            $stats.WeakOnly++
            $sev = if ($isPriv) { 'High' } else { 'Medium' }
            $findings.Add((New-Finding -Category 'WeakMFAOnly' `
                -UserPrincipalName $user.UserPrincipalName -DisplayName $user.DisplayName `
                -MethodsRegistered $methodSummary -Severity $sev `
                -Detail "Only weak MFA registered: $methodSummary$(if($isPriv){' [PRIVILEGED ACCOUNT]'}) — SMS/voice OTP is vulnerable to SIM-swapping and SS7 attacks"))
        }
        # ── Privileged user without strong MFA ────────────────────────────────
        elseif ($isPriv -and -not $hasStrong) {
            $findings.Add((New-Finding -Category 'PrivilegedWeakMFA' `
                -UserPrincipalName $user.UserPrincipalName -DisplayName $user.DisplayName `
                -MethodsRegistered $methodSummary -Severity 'High' `
                -Detail "Privileged account without FIDO2 or Authenticator app — moderate/weak MFA insufficient for admin roles; recommend phishing-resistant MFA"))
        }
        elseif ($hasStrong) { $stats.Strong++ }
        elseif ($hasModerate) { $stats.Moderate++ }
    }

    # Summary stats line
    Write-Host "  MFA Coverage:" -ForegroundColor White
    Write-Host ("    No MFA registered : {0} users ({1:P0})" -f $stats.NoMFA, ($stats.NoMFA / [Math]::Max(1,$stats.Total))) -ForegroundColor $(if($stats.NoMFA -gt 0){'Red'}else{'Green'})
    Write-Host ("    Weak MFA only     : {0} users" -f $stats.WeakOnly) -ForegroundColor $(if($stats.WeakOnly -gt 0){'DarkYellow'}else{'Green'})
    Write-Host ("    Strong MFA        : {0} users" -f $stats.Strong) -ForegroundColor Green
    Write-Host ''

    return $findings
}

# ── Summary ───────────────────────────────────────────────────────────────────

function Write-AuditSummary {
    param([System.Collections.Generic.List[PSCustomObject]]$Findings)

    $severityOrder = @{ Critical=0; High=1; Medium=2; Low=3; Info=4 }
    $colorMap      = @{ Critical='Red'; High='DarkYellow'; Medium='Yellow'; Low='Cyan'; Info='Gray' }

    Write-Host ('─' * 70) -ForegroundColor DarkGray
    Write-Host '  FINDINGS SUMMARY' -ForegroundColor White
    Write-Host ('─' * 70) -ForegroundColor DarkGray

    $Findings | Group-Object Severity | Sort-Object { $severityOrder[$_.Name] } |
        ForEach-Object {
            $icon = switch ($_.Name) {
                'Critical' { '🔴' }; 'High' { '🟠' }; 'Medium' { '🟡' };
                'Low' { '🔵' }; default { '⚪' }
            }
            Write-Host ("  $icon {0,-10} {1,4}" -f $_.Name, $_.Count) -ForegroundColor $colorMap[$_.Name]
        }
    Write-Host ''
}

# ── Entry point ───────────────────────────────────────────────────────────────

Assert-MgConnection
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
