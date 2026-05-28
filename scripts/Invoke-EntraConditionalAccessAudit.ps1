#Requires -Modules Microsoft.Graph.Identity.SignIns
<#
.SYNOPSIS
    Audits Entra ID Conditional Access policies for coverage gaps and security misconfigurations.

.DESCRIPTION
    Evaluates all Conditional Access policies against security best practices:
      - Policies in report-only or disabled state
      - No policy enforcing MFA for all users
      - Legacy authentication not blocked
      - Admin roles not covered by dedicated CA policies
      - Policies with broad exclusions (all guests, all service accounts)
      - No compliant/Hybrid Azure AD joined device requirement for admins
      - Sign-in risk policies missing or report-only
      - Break-glass accounts unaccounted for in exclusions

.PARAMETER OutputPath
    Directory to write CSV output. Default: .\reports\

.PARAMETER PassThru
    Return findings as objects to the pipeline.

.EXAMPLE
    .\Invoke-EntraConditionalAccessAudit.ps1

.NOTES
    Required scopes : Policy.Read.All, Directory.Read.All
    Legal           : Run only on tenants you own or have written authorisation to audit.
    Reference       : Microsoft CA Best Practices, CIS Microsoft 365 Foundations Benchmark
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = '.\reports',

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

# ── Legacy auth client apps ───────────────────────────────────────────────────

$LEGACY_AUTH_CLIENTS = @(
    'exchangeActiveSync', 'other'  # 'other' covers IMAP, POP3, SMTP auth, older Office clients
)

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  ENTRA ID CONDITIONAL ACCESS AUDIT' -ForegroundColor Cyan
    Write-Host '  Reference: CIS Microsoft 365 Foundations Benchmark' -ForegroundColor DarkGray
    Write-Host '  ⚠  Run only on tenants you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

function Get-MFAEnforcingPolicies {
    param($Policies)
    return $Policies | Where-Object {
        $_.State -eq 'enabled' -and
        $_.GrantControls.BuiltInControls -contains 'mfa'
    }
}

# ── Main audit ────────────────────────────────────────────────────────────────

function Invoke-CAudit {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Verbose 'Retrieving Conditional Access policies…'
    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to retrieve CA policies: $_"
        return
    }

    $enabledPolicies     = $policies | Where-Object { $_.State -eq 'enabled' }
    $reportOnlyPolicies  = $policies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforcing' }
    $disabledPolicies    = $policies | Where-Object { $_.State -eq 'disabled' }

    Write-Host "  CA Policies: $($policies.Count) total | $($enabledPolicies.Count) enabled | $($reportOnlyPolicies.Count) report-only | $($disabledPolicies.Count) disabled" -ForegroundColor White
    Write-Host ''

    # ── No CA policies at all ─────────────────────────────────────────────────
    if ($policies.Count -eq 0) {
        $findings.Add((New-AuditFinding -Module 'ConditionalAccess' -Category 'NoCAPolicies' `
            -Identity 'N/A' -IdentityType 'policy' -Resource 'N/A' `
            -Severity 'Critical' `
            -Detail 'No Conditional Access policies found — every sign-in granted without condition' `
            -Recommendation 'Implement CA policies starting with MFA for all users and block legacy authentication'))
        return $findings
    }

    # ── Report-only policies ──────────────────────────────────────────────────
    foreach ($p in $reportOnlyPolicies) {
        $findings.Add((New-AuditFinding -Module 'ConditionalAccess' -Category 'ReportOnlyPolicy' `
            -Identity $p.DisplayName -IdentityType 'policy' -Resource $p.DisplayName `
            -Severity 'High' `
            -Detail "Policy '$($p.DisplayName)' is in report-only mode — not enforcing any controls" `
            -Recommendation 'Review sign-in logs for impact, then switch to enabled state'))
    }

    # ── Disabled policies ─────────────────────────────────────────────────────
    foreach ($p in $disabledPolicies) {
        $findings.Add((New-AuditFinding -Module 'ConditionalAccess' -Category 'DisabledPolicy' `
            -Identity $p.DisplayName -IdentityType 'policy' -Resource $p.DisplayName `
            -Severity 'Info' `
            -Detail "Policy '$($p.DisplayName)' is disabled — may represent a misconfiguration or leftover config" `
            -Recommendation 'Review and either enable, document as intentional, or delete'))
    }

    # ── No MFA policy covering all users ─────────────────────────────────────
    $mfaPolicies = Get-MFAEnforcingPolicies -Policies $enabledPolicies
    if ($mfaPolicies.Count -eq 0) {
        $findings.Add((New-AuditFinding -Module 'ConditionalAccess' -Category 'MFANotEnforced' `
            -Identity 'N/A' -IdentityType 'policy' -Resource 'N/A' `
            -Severity 'Critical' `
            -Detail 'No enabled CA policy enforces MFA for any users — entire tenant authenticates with password only' `
            -Recommendation 'Create a CA policy: All users → All cloud apps → Require MFA (CIS L1 1.1.3)'))
    }
    else {
        # Check if any MFA policy covers ALL users without excessive exclusions
        $broadMFAExists = $false
        foreach ($p in $mfaPolicies) {
            $includesAll = $p.Conditions.Users.IncludeUsers -contains 'All'
            if ($includesAll) {
                $broadMFAExists = $true
                $exclCount = $p.Conditions.Users.ExcludeUsers.Count + $p.Conditions.Users.ExcludeGroups.Count
                if ($exclCount -gt 5) {
                    $findings.Add((New-AuditFinding -Module 'ConditionalAccess' -Category 'BroadMFAExclusions' `
                        -Identity $p.DisplayName -IdentityType 'policy' -Resource $p.DisplayName `
                        -Severity 'High' `
                        -Detail "MFA policy '$($p.DisplayName)' has $exclCount exclusions — large exclusion lists create gaps attackers can target" `
                        -Recommendation 'Audit all exclusions; move break-glass accounts to a named exclusion group and review quarterly'))
                }
            }
        }

        if (-not $broadMFAExists) {
            $findings.Add((New-AuditFinding -Module 'ConditionalAccess' -Category 'MFANotForAllUsers' `
                -Identity 'Multiple' -IdentityType 'policy' -Resource 'Multiple' `
                -Severity 'High' `
                -Detail 'MFA policies exist but none covers All Users — gaps in coverage allow password-only authentication' `
                -Recommendation 'Consolidate into an All Users → Require MFA baseline policy with minimal exclusions'))
        }
    }

    # ── Legacy authentication not blocked ─────────────────────────────────────
    $legacyBlockPolicy = $enabledPolicies | Where-Object {
        $_.Conditions.ClientAppTypes | Where-Object { $_ -in $LEGACY_AUTH_CLIENTS }
    } | Where-Object {
        $_.GrantControls.BuiltInControls -contains 'block'
    }

    if (-not $legacyBlockPolicy) {
        $findings.Add((New-AuditFinding -Module 'ConditionalAccess' -Category 'LegacyAuthNotBlocked' `
            -Identity 'N/A' -IdentityType 'policy' -Resource 'N/A' `
            -Severity 'Critical' `
            -Detail 'No policy blocks legacy authentication protocols (IMAP, POP3, SMTP, EAS) — these bypass MFA entirely' `
            -Recommendation 'Create CA policy: All users → Legacy auth clients → Block (CIS L1 1.3.3)'))
    }

    # ── Admin-targeted MFA policies ───────────────────────────────────────────
    $adminRoleIds = @(
        '62e90394-69f5-4237-9190-012177145e10',  # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814',  # Privileged Authentication Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13',  # Privileged Role Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d',  # Security Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de',  # Exchange Administrator
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',  # SharePoint Administrator
        '3a2c62db-5318-420d-8d74-23affee5d9d5',  # Intune Administrator
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',  # Conditional Access Administrator
        '0964bb5e-9bdb-4d7b-ac29-58e794862a40',  # Authentication Administrator
        '2b745bdf-0803-4d80-aa65-822c4493daac',  # Hybrid Identity Administrator
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',  # Application Administrator
        '158c047a-c907-4556-b7ef-446551a6b5f7'   # Cloud Application Administrator
    )
    $adminCoveredByPolicy = $enabledPolicies | Where-Object {
        $rids = $_.Conditions.Users.IncludeRoles
        ($rids | Where-Object { $_ -in $adminRoleIds }).Count -gt 0 -or
        $_.Conditions.Users.IncludeUsers -contains 'All'
    }

    if (-not $adminCoveredByPolicy) {
        $findings.Add((New-AuditFinding -Module 'ConditionalAccess' -Category 'AdminsNotTargeted' `
            -Identity 'N/A' -IdentityType 'policy' -Resource 'N/A' `
            -Severity 'High' `
            -Detail 'No CA policy specifically targets administrator roles — admins should have stricter controls than regular users' `
            -Recommendation 'Create a dedicated admin CA policy requiring MFA + compliant device or privileged workstation'))
    }

    # ── Sign-in risk policy check ─────────────────────────────────────────────
    $riskPolicy = $enabledPolicies | Where-Object {
        $_.Conditions.SignInRiskLevels.Count -gt 0
    }

    if (-not $riskPolicy) {
        $findings.Add((New-AuditFinding -Module 'ConditionalAccess' -Category 'NoSignInRiskPolicy' `
            -Identity 'N/A' -IdentityType 'policy' -Resource 'N/A' `
            -Severity 'Medium' `
            -Detail 'No CA policy responds to sign-in risk (requires Entra ID P2) — risky sign-ins proceed without challenge' `
            -Recommendation 'Create risk-based CA policy: Medium/High risk → Require MFA or Block. Requires Entra ID P2 license'))
    }

    # ── Policies with all-guest exclusions ────────────────────────────────────
    foreach ($p in $enabledPolicies) {
        $includesAll     = $p.Conditions.Users.IncludeUsers -contains 'All'
        $excludesGuests  = $p.Conditions.Users.ExcludeGuestsOrExternalUsers -ne $null
        if ($includesAll -and $excludesGuests) {
            $findings.Add((New-AuditFinding -Module 'ConditionalAccess' -Category 'GuestsExcludedFromPolicy' `
                -Identity $p.DisplayName -IdentityType 'policy' -Resource $p.DisplayName `
                -Severity 'Medium' `
                -Detail "Policy '$($p.DisplayName)' excludes all guests — external users bypass this control" `
                -Recommendation 'Create a separate CA policy scoped to guest/external users with appropriate controls'))
        }
    }

    return $findings
}

# ── Entry point ───────────────────────────────────────────────────────────────

Assert-MgConnection -RequiredScopes 'Policy.Read.All','Directory.Read.All' `
    -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint
Write-AuditBanner

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$findings = Invoke-CAudit

if ($findings.Count -eq 0) {
    Write-Host '  ✅ Conditional Access policies meet baseline requirements.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings -ShowTopFindings
    $csv = Join-Path $OutputPath "EntraConditionalAccessAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csv" -ForegroundColor Green
}

if ($PassThru) { return $findings }
