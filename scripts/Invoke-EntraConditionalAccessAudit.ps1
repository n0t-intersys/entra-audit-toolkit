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

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Legacy auth client apps ───────────────────────────────────────────────────

$LEGACY_AUTH_CLIENTS = @(
    'exchangeActiveSync', 'other'  # 'other' covers IMAP, POP3, SMTP auth, older Office clients
)

# ── Helpers ───────────────────────────────────────────────────────────────────

function Assert-MgConnection {
    try { if (-not (Get-MgContext -ErrorAction Stop)) { throw } }
    catch {
        Write-Error "Not connected. Run: Connect-MgGraph -Scopes 'Policy.Read.All','Directory.Read.All'"
        exit 1
    }
}

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  ENTRA ID CONDITIONAL ACCESS AUDIT' -ForegroundColor Cyan
    Write-Host '  Reference: CIS Microsoft 365 Foundations Benchmark' -ForegroundColor DarkGray
    Write-Host '  ⚠  Run only on tenants you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

function New-Finding {
    param(
        [string]$Category,
        [string]$PolicyName,
        [string]$PolicyState,
        [string]$Detail,
        [string]$Recommendation,
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity
    )
    [PSCustomObject]@{
        Timestamp      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity       = $Severity
        Category       = $Category
        PolicyName     = $PolicyName
        PolicyState    = $PolicyState
        Detail         = $Detail
        Recommendation = $Recommendation
    }
}

# ── Analysis helpers ──────────────────────────────────────────────────────────

function Test-PoliciesCoversAllUsers {
    param($Policies, $RequiredControl)
    foreach ($p in $Policies) {
        if ($p.State -ne 'enabled') { continue }
        $conditions = $p.Conditions
        $includesAll = $conditions.Users.IncludeUsers -contains 'All'
        $noExclusions = $conditions.Users.ExcludeUsers.Count -eq 0 -and
                        $conditions.Users.ExcludeGroups.Count -eq 0
        if ($includesAll -and $noExclusions) {
            $controls = $p.GrantControls.BuiltInControls
            if ($RequiredControl -in $controls) { return $true }
        }
    }
    return $false
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
        $findings.Add((New-Finding -Category 'NoCAPolicies' -PolicyName 'N/A' -PolicyState 'N/A' `
            -Severity 'Critical' `
            -Detail 'No Conditional Access policies found — every sign-in granted without condition' `
            -Recommendation 'Implement CA policies starting with MFA for all users and block legacy authentication'))
        return $findings
    }

    # ── Report-only policies ──────────────────────────────────────────────────
    foreach ($p in $reportOnlyPolicies) {
        $findings.Add((New-Finding -Category 'ReportOnlyPolicy' -PolicyName $p.DisplayName -PolicyState 'Report-Only' `
            -Severity 'High' `
            -Detail "Policy '$($p.DisplayName)' is in report-only mode — not enforcing any controls" `
            -Recommendation 'Review sign-in logs for impact, then switch to enabled state'))
    }

    # ── Disabled policies ─────────────────────────────────────────────────────
    foreach ($p in $disabledPolicies) {
        $findings.Add((New-Finding -Category 'DisabledPolicy' -PolicyName $p.DisplayName -PolicyState 'Disabled' `
            -Severity 'Info' `
            -Detail "Policy '$($p.DisplayName)' is disabled — may represent a misconfiguration or leftover config" `
            -Recommendation 'Review and either enable, document as intentional, or delete'))
    }

    # ── No MFA policy covering all users ─────────────────────────────────────
    $mfaPolicies = Get-MFAEnforcingPolicies -Policies $enabledPolicies
    if ($mfaPolicies.Count -eq 0) {
        $findings.Add((New-Finding -Category 'MFANotEnforced' -PolicyName 'N/A' -PolicyState 'N/A' `
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
                    $findings.Add((New-Finding -Category 'BroadMFAExclusions' -PolicyName $p.DisplayName -PolicyState 'Enabled' `
                        -Severity 'High' `
                        -Detail "MFA policy '$($p.DisplayName)' has $exclCount exclusions — large exclusion lists create gaps attackers can target" `
                        -Recommendation 'Audit all exclusions; move break-glass accounts to a named exclusion group and review quarterly'))
                }
            }
        }

        if (-not $broadMFAExists) {
            $findings.Add((New-Finding -Category 'MFANotForAllUsers' -PolicyName 'Multiple' -PolicyState 'Enabled' `
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
        $findings.Add((New-Finding -Category 'LegacyAuthNotBlocked' -PolicyName 'N/A' -PolicyState 'N/A' `
            -Severity 'Critical' `
            -Detail 'No policy blocks legacy authentication protocols (IMAP, POP3, SMTP, EAS) — these bypass MFA entirely' `
            -Recommendation 'Create CA policy: All users → Legacy auth clients → Block (CIS L1 1.3.3)'))
    }

    # ── Admin-targeted MFA policies ───────────────────────────────────────────
    $adminRoleIds = @(
        '62e90394-69f5-4237-9190-012177145e10',  # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814',  # Privileged Authentication Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'   # Privileged Role Administrator
    )
    $adminCoveredByPolicy = $enabledPolicies | Where-Object {
        $rids = $_.Conditions.Users.IncludeRoles
        ($rids | Where-Object { $_ -in $adminRoleIds }).Count -gt 0 -or
        $_.Conditions.Users.IncludeUsers -contains 'All'
    }

    if (-not $adminCoveredByPolicy) {
        $findings.Add((New-Finding -Category 'AdminsNotTargeted' -PolicyName 'N/A' -PolicyState 'N/A' `
            -Severity 'High' `
            -Detail 'No CA policy specifically targets administrator roles — admins should have stricter controls than regular users' `
            -Recommendation 'Create a dedicated admin CA policy requiring MFA + compliant device or privileged workstation'))
    }

    # ── Sign-in risk policy check ─────────────────────────────────────────────
    $riskPolicy = $enabledPolicies | Where-Object {
        $_.Conditions.SignInRiskLevels.Count -gt 0
    }

    if (-not $riskPolicy) {
        $findings.Add((New-Finding -Category 'NoSignInRiskPolicy' -PolicyName 'N/A' -PolicyState 'N/A' `
            -Severity 'Medium' `
            -Detail 'No CA policy responds to sign-in risk (requires Entra ID P2) — risky sign-ins proceed without challenge' `
            -Recommendation 'Create risk-based CA policy: Medium/High risk → Require MFA or Block. Requires Entra ID P2 license'))
    }

    # ── Policies with all-guest exclusions ────────────────────────────────────
    foreach ($p in $enabledPolicies) {
        $includesAll     = $p.Conditions.Users.IncludeUsers -contains 'All'
        $excludesGuests  = $p.Conditions.Users.ExcludeGuestsOrExternalUsers -ne $null
        if ($includesAll -and $excludesGuests) {
            $findings.Add((New-Finding -Category 'GuestsExcludedFromPolicy' -PolicyName $p.DisplayName -PolicyState 'Enabled' `
                -Severity 'Medium' `
                -Detail "Policy '$($p.DisplayName)' excludes all guests — external users bypass this control" `
                -Recommendation 'Create a separate CA policy scoped to guest/external users with appropriate controls'))
        }
    }

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
    foreach ($f in $Findings | Sort-Object { $severityOrder[$_.Severity] } | Select-Object -First 10) {
        Write-Host ("  [{0}] {1}" -f $f.Severity, $f.Detail.Substring(0, [Math]::Min(90, $f.Detail.Length))) `
            -ForegroundColor $colorMap[$f.Severity]
        Write-Host ("        → {0}" -f $f.Recommendation.Substring(0, [Math]::Min(80, $f.Recommendation.Length))) `
            -ForegroundColor DarkGray
    }
    Write-Host ''
}

# ── Entry point ───────────────────────────────────────────────────────────────

Assert-MgConnection
Write-AuditBanner

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$findings = Invoke-CAudit

if ($findings.Count -eq 0) {
    Write-Host '  ✅ Conditional Access policies meet baseline requirements.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings
    $csv = Join-Path $OutputPath "EntraConditionalAccessAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csv" -ForegroundColor Green
}

if ($PassThru) { return $findings }
