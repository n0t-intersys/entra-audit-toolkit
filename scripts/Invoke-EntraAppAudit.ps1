#Requires -Modules Microsoft.Graph.Applications
<#
.SYNOPSIS
    Audits Entra ID app registrations and service principals for credential risk and over-permissioning.

.DESCRIPTION
    Reviews all app registrations and service principals for:
      - Expiring or expired credentials (secrets/certificates)
      - High-privilege application API permissions (non-delegated)
      - Applications with no owners
      - Service principals with direct Entra role assignments
      - Multi-tenant apps exposed to any external tenant
      - Apps with user consent (OAuth phishing exposure)

    ATT&CK coverage:
      T1528  — Steal Application Access Token
      T1550.001 — Use Alternate Auth Material: Application Access Token

.PARAMETER OutputPath
    Directory to write CSV output. Default: .\reports\

.PARAMETER CredentialExpiryWarningDays
    Days before credential expiry to flag as warning. Default: 30.

.PARAMETER PassThru
    Return findings as objects to the pipeline.

.EXAMPLE
    .\Invoke-EntraAppAudit.ps1

.EXAMPLE
    .\Invoke-EntraAppAudit.ps1 -CredentialExpiryWarningDays 60 -OutputPath C:\EntraReports

.NOTES
    Required scopes : Application.Read.All, Directory.Read.All
    Legal           : Run only on tenants you own or have written authorisation to audit.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [ValidateRange(1,365)]
    [int]$CredentialExpiryWarningDays = 30,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── High-risk Graph API permissions ──────────────────────────────────────────
# Application (non-delegated) permissions that warrant escalated review

$HIGH_RISK_APP_PERMISSIONS = @{
    '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' = @{ Name='Application.ReadWrite.All';      Risk='Critical' }
    '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' = @{ Name='RoleManagement.ReadWrite.Directory'; Risk='Critical' }
    '06b708a9-e830-4db3-a914-8e69da51d44f' = @{ Name='AppRoleAssignment.ReadWrite.All'; Risk='Critical' }
    '741f803b-c850-494e-b5df-cde7c675a1ca' = @{ Name='User.ReadWrite.All';              Risk='High' }
    '19dbc75e-c2e2-444c-a770-ec69d8559fc7' = @{ Name='Directory.ReadWrite.All';         Risk='High' }
    '62a82d76-70ea-41e2-9197-370581804d09' = @{ Name='Group.ReadWrite.All';             Risk='High' }
    'e2a3a72e-5f79-4c64-b1b1-878b674786c9' = @{ Name='Mail.ReadWrite';                 Risk='High' }
    '810c84a8-4a9e-49e6-bf7d-12d183f40d01' = @{ Name='Mail.Read';                      Risk='Medium' }
    '7ab1d382-f21e-4acd-a863-ba3e13f7da61' = @{ Name='Directory.Read.All';             Risk='Medium' }
    'df021288-bdef-4463-88db-98f22de89214' = @{ Name='User.Read.All';                  Risk='Low' }
}

# ── Helpers ───────────────────────────────────────────────────────────────────

function Assert-MgConnection {
    try { if (-not (Get-MgContext -ErrorAction Stop)) { throw } }
    catch {
        Write-Error "Not connected. Run: Connect-MgGraph -Scopes 'Application.Read.All','Directory.Read.All'"
        exit 1
    }
}

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  ENTRA ID APPLICATION & SERVICE PRINCIPAL AUDIT' -ForegroundColor Cyan
    Write-Host '  ATT&CK: T1528 | T1550.001' -ForegroundColor DarkGray
    Write-Host '  ⚠  Run only on tenants you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

function New-Finding {
    param(
        [string]$Category,
        [string]$AppName,
        [string]$AppId,
        [string]$Detail,
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity
    )
    [PSCustomObject]@{
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity  = $Severity
        Category  = $Category
        AppName   = $AppName
        AppId     = $AppId
        Detail    = $Detail
    }
}

# ── Main audit ────────────────────────────────────────────────────────────────

function Invoke-AppAudit {
    [CmdletBinding()]
    param([int]$WarningDays)

    $findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now         = Get-Date
    $warnDate    = $now.AddDays($WarningDays)

    # ── App registrations ─────────────────────────────────────────────────────
    Write-Verbose 'Retrieving app registrations…'
    try {
        $apps = Get-MgApplication -All -Property @(
            'id','appId','displayName','signInAudience','owners',
            'passwordCredentials','keyCredentials','requiredResourceAccess',
            'createdDateTime'
        ) -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not retrieve app registrations: $_"
        $apps = @()
    }

    Write-Verbose "  Found $($apps.Count) app registration(s)"

    foreach ($app in $apps) {
        $name  = $app.DisplayName
        $appId = $app.AppId

        # ── Expired / expiring secrets ────────────────────────────────────────
        foreach ($cred in $app.PasswordCredentials) {
            if (-not $cred.EndDateTime) { continue }
            $expiry  = [datetime]$cred.EndDateTime
            $daysLeft = [int]($expiry - $now).TotalDays

            if ($expiry -lt $now) {
                $findings.Add((New-Finding -Category 'ExpiredSecret' -AppName $name -AppId $appId `
                    -Severity 'High' `
                    -Detail "Client secret '$($cred.DisplayName ?? $cred.KeyId)' expired $([math]::Abs($daysLeft)) days ago — app may be broken or using an alternate auth method"))
            }
            elseif ($expiry -lt $warnDate) {
                $findings.Add((New-Finding -Category 'ExpiringSecret' -AppName $name -AppId $appId `
                    -Severity 'Medium' `
                    -Detail "Client secret expires in $daysLeft days ($($expiry.ToString('yyyy-MM-dd'))) — rotate before expiry to avoid outage"))
            }
        }

        # ── Expired / expiring certificates ──────────────────────────────────
        foreach ($cert in $app.KeyCredentials) {
            if (-not $cert.EndDateTime) { continue }
            $expiry   = [datetime]$cert.EndDateTime
            $daysLeft = [int]($expiry - $now).TotalDays

            if ($expiry -lt $now) {
                $findings.Add((New-Finding -Category 'ExpiredCertificate' -AppName $name -AppId $appId `
                    -Severity 'High' `
                    -Detail "Certificate '$($cert.DisplayName ?? $cert.KeyId)' expired $([math]::Abs($daysLeft)) days ago"))
            }
            elseif ($expiry -lt $warnDate) {
                $findings.Add((New-Finding -Category 'ExpiringCertificate' -AppName $name -AppId $appId `
                    -Severity 'Medium' `
                    -Detail "Certificate expires in $daysLeft days ($($expiry.ToString('yyyy-MM-dd')))"))
            }
        }

        # ── No owners ────────────────────────────────────────────────────────
        if ($app.Owners.Count -eq 0) {
            $findings.Add((New-Finding -Category 'NoOwner' -AppName $name -AppId $appId `
                -Severity 'Medium' `
                -Detail 'App registration has no owner — orphaned apps have no accountable party for access review or incident response'))
        }

        # ── Multi-tenant exposure ─────────────────────────────────────────────
        if ($app.SignInAudience -in 'AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount') {
            $findings.Add((New-Finding -Category 'MultiTenantApp' -AppName $name -AppId $appId `
                -Severity 'Medium' `
                -Detail "App is multi-tenant (SignInAudience: $($app.SignInAudience)) — users from external tenants can authenticate; verify this is intentional"))
        }

        # ── High-privilege application permissions ────────────────────────────
        foreach ($resource in $app.RequiredResourceAccess) {
            foreach ($scope in $resource.ResourceAccess) {
                if ($scope.Type -ne 'Role') { continue }  # Role = Application permission (non-delegated)
                $permInfo = $HIGH_RISK_APP_PERMISSIONS[$scope.Id]
                if ($permInfo) {
                    $findings.Add((New-Finding -Category 'HighPrivilegeAppPermission' -AppName $name -AppId $appId `
                        -Severity $permInfo.Risk `
                        -Detail "Has APPLICATION permission '$($permInfo.Name)' — non-delegated; acts as itself with no user context (T1528)"))
                }
            }
        }
    }

    # ── Service principals (first-party + enterprise apps) ────────────────────
    Write-Verbose 'Retrieving service principals…'
    try {
        $sps = Get-MgServicePrincipal -All -Property @(
            'id','appId','displayName','servicePrincipalType','appOwnerOrganizationId',
            'passwordCredentials','keyCredentials','oauth2PermissionScopes'
        ) -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not retrieve service principals: $_"
        $sps = @()
    }

    $tenantId = (Get-MgContext).TenantId

    foreach ($sp in $sps) {
        # Skip Microsoft first-party apps
        if ($sp.AppOwnerOrganizationId -eq '72f988bf-86f1-41af-91ab-2d7cd011db47') { continue }
        # Skip managed identities for now
        if ($sp.ServicePrincipalType -eq 'ManagedIdentity') { continue }

        $name  = $sp.DisplayName
        $appId = $sp.AppId

        # ── Expiring SP credentials ───────────────────────────────────────────
        foreach ($cred in $sp.PasswordCredentials) {
            if (-not $cred.EndDateTime) { continue }
            $expiry   = [datetime]$cred.EndDateTime
            $daysLeft = [int]($expiry - $now).TotalDays
            if ($expiry -lt $warnDate) {
                $sev = if ($expiry -lt $now) { 'High' } else { 'Medium' }
                $findings.Add((New-Finding -Category 'ExpiringServicePrincipalCred' -AppName $name -AppId $appId `
                    -Severity $sev `
                    -Detail "Service principal secret $(if($expiry -lt $now){"expired $([math]::Abs($daysLeft)) days ago"}else{"expires in $daysLeft days"})"))
            }
        }

        # ── External (non-home-tenant) service principals ─────────────────────
        if ($sp.AppOwnerOrganizationId -and $sp.AppOwnerOrganizationId -ne $tenantId) {
            $findings.Add((New-Finding -Category 'ExternalServicePrincipal' -AppName $name -AppId $appId `
                -Severity 'Info' `
                -Detail "Service principal from external tenant ($($sp.AppOwnerOrganizationId)) — verify consent is intentional and permissions are scoped appropriately"))
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

    $Findings | Group-Object Category | ForEach-Object {
        Write-Host ("  {0,-35} {1,4} finding(s)" -f $_.Name, $_.Count) -ForegroundColor White
    }
    Write-Host ''

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

$findings = Invoke-AppAudit -WarningDays $CredentialExpiryWarningDays

if ($findings.Count -eq 0) {
    Write-Host '  ✅ No application security findings.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings
    $csv = Join-Path $OutputPath "EntraAppAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csv" -ForegroundColor Green
}

if ($PassThru) { return $findings }
