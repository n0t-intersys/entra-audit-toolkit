#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Applications, Microsoft.Graph.Identity.Governance
<#
.SYNOPSIS
    Master orchestrator — runs all Entra ID audit modules and produces a consolidated HTML report.

.DESCRIPTION
    Invokes each of the five audit modules in sequence:
      1. User Accounts       (stale, never signed in, disabled with licenses, guests)
      2. Privileged Access   (GA count, permanent assignments, SP roles, PIM)
      3. Conditional Access  (coverage gaps, legacy auth, MFA enforcement)
      4. Applications        (expiring creds, over-permissioned apps, orphaned SPs)
      5. MFA Registration    (no MFA, weak MFA, privileged without strong MFA)

    Aggregates all findings, renders a dark-themed HTML dashboard, and saves per-module CSVs.

.PARAMETER OutputPath
    Directory to write HTML report and CSV files. Default: .\reports\

.PARAMETER StaleThresholdDays
    Days without sign-in before an account is considered stale. Default: 90.

.PARAMETER SkipGuestUsers
    Exclude guests from MFA audit (typically managed by home tenant). Default: $true.

.PARAMETER CredentialExpiryWarningDays
    Days before app credential expiry to flag as warning. Default: 30.

.PARAMETER OpenReport
    Open the HTML report in the default browser when complete.

.EXAMPLE
    .\Invoke-EntraAuditSuite.ps1

.EXAMPLE
    .\Invoke-EntraAuditSuite.ps1 -StaleThresholdDays 60 -OpenReport -Verbose

.NOTES
    Required scopes:
      UserAuthenticationMethod.Read.All, User.Read.All, AuditLog.Read.All,
      Directory.Read.All, Policy.Read.All, Application.Read.All,
      RoleManagement.Read.Directory, PrivilegedAccess.Read.AzureAD

    Connect first:
      Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All","User.Read.All",
        "AuditLog.Read.All","Directory.Read.All","Policy.Read.All",
        "Application.Read.All","RoleManagement.Read.Directory"

    Legal: Run only on tenants you own or have written authorisation to audit.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleThresholdDays = 90,

    [Parameter()]
    [bool]$SkipGuestUsers = $true,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$CredentialExpiryWarningDays = 30,

    [Parameter()]
    [switch]$OpenReport,

    # ── App-only (enterprise application) authentication ──────────────────────
    # The suite connects once; all sub-modules reuse the same session.
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

# ── Banner ────────────────────────────────────────────────────────────────────

function Write-SuiteBanner {
    $ctx    = Get-MgContext
    $tenant = $ctx.TenantId ?? 'Unknown'
    $account = $ctx.Account ?? 'App-only'
    Write-Host ''
    Write-Host ('═' * 72) -ForegroundColor DarkCyan
    Write-Host '  ENTRA ID SECURITY AUDIT SUITE' -ForegroundColor Cyan
    Write-Host "  Tenant  : $tenant" -ForegroundColor DarkGray
    Write-Host "  Identity: $account" -ForegroundColor DarkGray
    Write-Host "  Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host '  ⚠  Run only on tenants you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 72) -ForegroundColor DarkCyan
    Write-Host ''
}

# ── Module runner ─────────────────────────────────────────────────────────────

function Invoke-Module {
    param(
        [string]$Name,
        [string]$ScriptPath,
        [hashtable]$Arguments
    )

    Write-Host "  ▶ $Name" -ForegroundColor Cyan -NoNewline

    if (-not (Test-Path $ScriptPath)) {
        Write-Host ' [SKIP — script not found]' -ForegroundColor DarkYellow
        return @()
    }

    try {
        $findings = & $ScriptPath @Arguments -PassThru -ErrorAction Stop
        $count = if ($null -eq $findings) { 0 } else { @($findings).Count }
        Write-Host " → $count finding(s)" -ForegroundColor $(if ($count -gt 0) { 'Yellow' } else { 'Green' })
        return @($findings)
    }
    catch {
        Write-Host " [ERROR: $_]" -ForegroundColor Red
        return @()
    }
}

# ── HTML report ───────────────────────────────────────────────────────────────

function ConvertTo-HtmlReport {
    param(
        [object[]]$AllFindings,
        [string]$TenantId,
        [datetime]$RunTime
    )

    Add-Type -AssemblyName System.Web

    $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $severityColor = @{
        Critical = '#ff4444'
        High     = '#ff8800'
        Medium   = '#ffcc00'
        Low      = '#44aaff'
        Info     = '#888888'
    }
    $severityBg = @{
        Critical = 'rgba(255,68,68,0.12)'
        High     = 'rgba(255,136,0,0.12)'
        Medium   = 'rgba(255,204,0,0.12)'
        Low      = 'rgba(68,170,255,0.12)'
        Info     = 'rgba(136,136,136,0.08)'
    }

    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in $AllFindings) { $counts[$f.Severity]++ }

    # Build summary cards
    $cards = ''
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low', 'Info') {
        $cards += @"
    <div class="card" style="border-color:$($severityColor[$sev])">
      <div class="card-count" style="color:$($severityColor[$sev])">$($counts[$sev])</div>
      <div class="card-label">$sev</div>
    </div>
"@
    }

    # Build findings rows
    $rows = ''
    foreach ($f in ($AllFindings | Sort-Object { $severityOrder[$_.Severity] })) {
        $col    = $severityColor[$f.Severity]
        $bg     = $severityBg[$f.Severity]
        $detail = [System.Web.HttpUtility]::HtmlEncode($f.Detail ?? '')
        $cat    = [System.Web.HttpUtility]::HtmlEncode($f.Category ?? '')
        $mod    = [System.Web.HttpUtility]::HtmlEncode($f.Module ?? '')
        $rec    = [System.Web.HttpUtility]::HtmlEncode($f.Recommendation ?? '')

        # Unified identity field
        $identity = [System.Web.HttpUtility]::HtmlEncode($f.Identity ?? '—')

        $rows += @"
    <tr style="background:$bg">
      <td><span class="badge" style="color:$col;border-color:$col">$($f.Severity)</span></td>
      <td style="font-size:0.85em;color:#8b949e">$mod</td>
      <td>$cat</td>
      <td style="font-family:monospace;font-size:0.85em">$identity</td>
      <td>$detail</td>
      <td style="font-size:0.85em;color:#8b949e">$rec</td>
    </tr>
"@
    }

    # Category breakdown
    $catRows = ''
    $AllFindings | Group-Object Category | Sort-Object Count -Descending | Select-Object -First 20 |
        ForEach-Object {
            $catRows += "<tr><td>$($_.Name)</td><td style='text-align:right;font-weight:600'>$($_.Count)</td></tr>"
        }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Entra ID Audit Report — $($RunTime.ToString('yyyy-MM-dd'))</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
    a { color: #58a6ff; }
    header { background: #161b22; border-bottom: 1px solid #30363d; padding: 24px 32px; }
    header h1 { color: #00ff9d; font-size: 1.4em; letter-spacing: 0.05em; text-transform: uppercase; }
    header p  { color: #8b949e; margin-top: 4px; font-size: 0.9em; }
    main { padding: 24px 32px; max-width: 1600px; margin: 0 auto; }
    h2 { color: #00ff9d; font-size: 1em; text-transform: uppercase; letter-spacing: 0.08em;
         margin: 28px 0 12px; border-bottom: 1px solid #21262d; padding-bottom: 6px; }
    .cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 8px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 20px 28px; min-width: 120px; text-align: center; border-top-width: 3px; }
    .card-count { font-size: 2.4em; font-weight: 700; line-height: 1; }
    .card-label { font-size: 0.78em; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.06em; }
    table { width: 100%; border-collapse: collapse; background: #161b22;
            border-radius: 8px; overflow: hidden; }
    th { background: #21262d; color: #8b949e; text-align: left; padding: 10px 14px;
         font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.06em; }
    td { padding: 10px 14px; border-bottom: 1px solid #21262d; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,0.03); }
    .badge { border: 1px solid; border-radius: 4px; padding: 2px 8px;
             font-size: 0.75em; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }
    .meta { color: #8b949e; font-size: 0.8em; margin-top: 4px; }
    footer { text-align: center; padding: 32px; color: #8b949e; font-size: 0.8em; border-top: 1px solid #21262d; margin-top: 40px; }
  </style>
</head>
<body>
<header>
  <h1>⬡ Entra ID Security Audit</h1>
  <p>Tenant: <code>$TenantId</code> &nbsp;|&nbsp; Generated: $($RunTime.ToString('yyyy-MM-dd HH:mm:ss UTC'))</p>
</header>
<main>
  <h2>Summary</h2>
  <div class="cards">
$cards  </div>
  <p class="meta">Total findings: $($AllFindings.Count) across $($AllFindings | Select-Object -ExpandProperty Category -Unique | Measure-Object | Select-Object -ExpandProperty Count) categories</p>

  <h2>Findings by Category</h2>
  <table>
    <tr><th>Category</th><th>Count</th></tr>
    $catRows
  </table>

  <h2>All Findings</h2>
  <table>
    <tr>
      <th>Severity</th>
      <th>Module</th>
      <th>Category</th>
      <th>Principal / Resource</th>
      <th>Detail</th>
      <th>Recommendation</th>
    </tr>
$rows
  </table>
</main>
<footer>
  Entra ID Audit Suite &nbsp;|&nbsp; Run only on tenants you own or have written authorisation to audit.
</footer>
</body>
</html>
"@
    return $html
}

# ── Entry point ───────────────────────────────────────────────────────────────

Assert-MgConnection -RequiredScopes 'User.Read.All','AuditLog.Read.All','Directory.Read.All','Policy.Read.All','Application.Read.All','RoleManagement.Read.Directory','PrivilegedAccess.Read.AzureAD','Reports.Read.All' `
    -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint
Write-SuiteBanner

$ctx     = Get-MgContext
$tenant  = $ctx.TenantId ?? 'unknown'
$runTime = Get-Date

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$scriptRoot = $PSScriptRoot

Write-Host ('─' * 72) -ForegroundColor DarkGray
Write-Host '  Running audit modules…' -ForegroundColor White
Write-Host ('─' * 72) -ForegroundColor DarkGray

$all = [System.Collections.Generic.List[PSCustomObject]]::new()

# Module 1 — Users
$r = Invoke-Module -Name 'User Accounts' `
    -ScriptPath (Join-Path $scriptRoot 'Invoke-EntraUserAudit.ps1') `
    -Arguments @{ OutputPath = $OutputPath; StaleThresholdDays = $StaleThresholdDays }
foreach ($f in $r) { $all.Add($f) }

# Module 2 — Privileged Access
$r = Invoke-Module -Name 'Privileged Access' `
    -ScriptPath (Join-Path $scriptRoot 'Invoke-EntraPrivilegedAudit.ps1') `
    -Arguments @{ OutputPath = $OutputPath }
foreach ($f in $r) { $all.Add($f) }

# Module 3 — Conditional Access
$r = Invoke-Module -Name 'Conditional Access' `
    -ScriptPath (Join-Path $scriptRoot 'Invoke-EntraConditionalAccessAudit.ps1') `
    -Arguments @{ OutputPath = $OutputPath }
foreach ($f in $r) { $all.Add($f) }

# Module 4 — Applications
$r = Invoke-Module -Name 'App Registrations & SPs' `
    -ScriptPath (Join-Path $scriptRoot 'Invoke-EntraAppAudit.ps1') `
    -Arguments @{ OutputPath = $OutputPath; CredentialExpiryWarningDays = $CredentialExpiryWarningDays }
foreach ($f in $r) { $all.Add($f) }

# Module 5 — MFA
$r = Invoke-Module -Name 'MFA Registration' `
    -ScriptPath (Join-Path $scriptRoot 'Invoke-EntraMFAAudit.ps1') `
    -Arguments @{ OutputPath = $OutputPath; SkipGuestUsers = $SkipGuestUsers }
foreach ($f in $r) { $all.Add($f) }

Write-Host ''

# ── Aggregate CSV ─────────────────────────────────────────────────────────────

if ($all.Count -gt 0) {
    $aggCsv = Join-Path $OutputPath "EntraAuditSuite_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $all | Export-Csv -Path $aggCsv -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Aggregate CSV : $aggCsv" -ForegroundColor Green
}

# ── HTML report ───────────────────────────────────────────────────────────────

try {
    $html     = ConvertTo-HtmlReport -AllFindings $all -TenantId $tenant -RunTime $runTime
    $htmlPath = Join-Path $OutputPath "EntraAuditReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "  🌐 HTML report   : $htmlPath" -ForegroundColor Green

    if ($OpenReport) {
        Start-Process $htmlPath
    }
}
catch {
    Write-Warning "HTML generation failed: $_"
}

# ── Console summary ───────────────────────────────────────────────────────────

Write-Host ''
Write-AuditSummary -Findings $all -ShowCategoryBreakdown

if ($all.Count -eq 0) {
    Write-Host '  ✅ No findings across all modules.' -ForegroundColor Green
}
Write-Host ('═' * 72) -ForegroundColor DarkCyan
Write-Host ''
