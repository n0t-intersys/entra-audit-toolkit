#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Reports
<#
.SYNOPSIS
    Audits Entra ID user accounts for stale identities, guest exposure, and licensing waste.

.DESCRIPTION
    Connects to Microsoft Graph and evaluates all user objects for:
      - Stale accounts (no interactive sign-in beyond threshold)
      - Guest/B2B users with elevated exposure
      - Disabled accounts still consuming licenses
      - Accounts that have never signed in
      - Users with no manager set (orphaned identities)
      - Accounts created but never activated

    Sign-in activity requires AuditLog.Read.All permission.

.PARAMETER StaleThresholdDays
    Days since last interactive sign-in before flagging as stale. Default: 90.

.PARAMETER OutputPath
    Directory to write CSV output. Default: .\reports\

.PARAMETER IncludeGuests
    Include guest/B2B accounts in stale analysis (default: flagged separately).

.PARAMETER PassThru
    Return findings as objects to the pipeline.

.EXAMPLE
    .\Invoke-EntraUserAudit.ps1

.EXAMPLE
    .\Invoke-EntraUserAudit.ps1 -StaleThresholdDays 60 -OutputPath C:\EntraReports

.NOTES
    Required scopes : User.Read.All, AuditLog.Read.All, Directory.Read.All
    Connect first   : Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","Directory.Read.All"
    Legal           : Run only on tenants you own or have written authorisation to audit.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleThresholdDays = 90,

    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [switch]$IncludeGuests,

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

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-AuditBanner {
    $tenant = (Get-MgContext).TenantId
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  ENTRA ID USER ACCOUNT AUDIT' -ForegroundColor Cyan
    Write-Host "  Tenant: $tenant" -ForegroundColor DarkGray
    Write-Host '  ⚠  Run only on tenants you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

# ── Main audit ────────────────────────────────────────────────────────────────

function Invoke-UserAudit {
    [CmdletBinding()]
    param([int]$StaleThresholdDays, [bool]$IncludeGuests)

    $findings   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $staleDate  = (Get-Date).AddDays(-$StaleThresholdDays)

    $properties = @(
        'id', 'userPrincipalName', 'displayName', 'userType', 'accountEnabled',
        'createdDateTime', 'assignedLicenses', 'manager', 'mail',
        'signInActivity', 'onPremisesSyncEnabled', 'userState'
    )

    Write-Verbose 'Retrieving all Entra ID users…'
    try {
        $users = Get-MgUser -All -Property $properties -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to retrieve users from Graph: $_"
        return
    }
    Write-Verbose "  Retrieved $($users.Count) user object(s)"

    $memberCount = 0
    $guestCount  = 0

    foreach ($user in $users) {
        $upn      = $user.UserPrincipalName
        $name     = $user.DisplayName
        $uType    = $user.UserType ?? 'Member'
        $isGuest  = $uType -eq 'Guest'
        $isCloud  = -not $user.OnPremisesSyncEnabled

        if ($isGuest) { $guestCount++ } else { $memberCount++ }

        # ── Never signed in ───────────────────────────────────────────────────
        $lastSignIn = $user.SignInActivity?.LastSignInDateTime
        if ($user.AccountEnabled -and -not $lastSignIn) {
            $ageDays = [int]((Get-Date) - [datetime]$user.CreatedDateTime).TotalDays
            $findings.Add((New-AuditFinding -Module 'UserAudit' -Category 'NeverSignedIn' `
                -Identity $upn -IdentityType $uType -Resource '' `
                -Severity 'Medium' `
                -Detail "Account enabled but never signed in — created $ageDays days ago" `
                -Recommendation 'Verify the account is still needed; disable or delete if unused'))
        }

        # ── Stale sign-in ─────────────────────────────────────────────────────
        if ($user.AccountEnabled -and $lastSignIn) {
            $lastSignInDt = [datetime]$lastSignIn
            if ($lastSignInDt -lt $staleDate) {
                $daysStale = [int]((Get-Date) - $lastSignInDt).TotalDays
                $sev       = if ($daysStale -gt 180) { 'High' } else { 'Medium' }
                if ($isGuest -and -not $IncludeGuests) {
                    # Guests flagged separately below
                }
                else {
                    $findings.Add((New-AuditFinding -Module 'UserAudit' -Category 'StaleAccount' `
                        -Identity $upn -IdentityType $uType -Resource '' `
                        -Severity $sev `
                        -Detail "No sign-in for $daysStale days (threshold: $StaleThresholdDays)" `
                        -Recommendation 'Verify account is still required; consider disabling or deleting after manager review'))
                }
            }
        }

        # ── Disabled account with licenses ────────────────────────────────────
        if (-not $user.AccountEnabled -and $user.AssignedLicenses.Count -gt 0) {
            $findings.Add((New-AuditFinding -Module 'UserAudit' -Category 'DisabledWithLicense' `
                -Identity $upn -IdentityType $uType -Resource '' `
                -Severity 'Medium' `
                -Detail "Disabled account holds $($user.AssignedLicenses.Count) license(s) — licensing cost with no security value" `
                -Recommendation 'Remove licenses from disabled accounts to reclaim spend; automate via lifecycle workflow'))
        }

        # ── Guest user checks ─────────────────────────────────────────────────
        if ($isGuest) {
            $findings.Add((New-AuditFinding -Module 'UserAudit' -Category 'GuestUser' `
                -Identity $upn -IdentityType 'Guest' -Resource '' `
                -Severity 'Info' `
                -Detail "External/B2B guest account — verify access is still required and scoped appropriately" `
                -Recommendation 'Implement guest access reviews; enforce Entitlement Management access packages with expiry'))

            # Stale guest (separate from member stale)
            if ($lastSignIn -and [datetime]$lastSignIn -lt $staleDate) {
                $daysStale = [int]((Get-Date) - [datetime]$lastSignIn).TotalDays
                $findings.Add((New-AuditFinding -Module 'UserAudit' -Category 'StaleGuest' `
                    -Identity $upn -IdentityType 'Guest' -Resource '' `
                    -Severity 'High' `
                    -Detail "Guest account with no sign-in for $daysStale days — external access should be time-limited" `
                    -Recommendation 'Remove or expire guest account; use access package expiry to automate time-limited external access'))
            }
        }

        # ── No manager (cloud-only accounts) ─────────────────────────────────
        if ($user.AccountEnabled -and $isCloud -and -not $isGuest -and -not $user.Manager) {
            $findings.Add((New-AuditFinding -Module 'UserAudit' -Category 'NoManager' `
                -Identity $upn -IdentityType $uType -Resource '' `
                -Severity 'Low' `
                -Detail 'No manager attribute set — orphaned accounts evade access certification' `
                -Recommendation 'Set manager attribute; use access reviews requiring manager approval to surface unmanaged accounts'))
        }
    }

    Write-Verbose "  Members: $memberCount | Guests: $guestCount"
    return $findings
}

# ── Entry point ───────────────────────────────────────────────────────────────

Assert-MgConnection -RequiredScopes 'User.Read.All','AuditLog.Read.All','Directory.Read.All' `
    -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint
Write-AuditBanner

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$findings = Invoke-UserAudit -StaleThresholdDays $StaleThresholdDays -IncludeGuests:$IncludeGuests.IsPresent

if ($findings.Count -eq 0) {
    Write-Host '  ✅ No user account findings.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings -ShowCategoryBreakdown
    $csv = Join-Path $OutputPath "EntraUserAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csv" -ForegroundColor Green
}

if ($PassThru) { return $findings }
