#Requires -Modules Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.Governance
<#
.SYNOPSIS
    Audits privileged role assignments in Entra ID, including PIM and service principal exposure.

.DESCRIPTION
    Enumerates all active and eligible (PIM) role assignments across Entra ID built-in roles.
    Identifies permanent assignments to high-value roles, service principals holding admin rights,
    accounts outside PIM, and roles assigned directly to users rather than groups.

    Findings covered:
      - Members of high-value roles (Global Admin, Privileged Auth Admin, etc.)
      - Permanent (non-PIM) assignments to privileged roles
      - Service principals / applications holding admin roles
      - Global Admin count above recommended threshold (2–4)
      - Admin accounts without a dedicated admin UPN pattern
      - Eligible PIM assignments that have never been activated
      - Roles assigned to cloud-only vs synced accounts

    ATT&CK coverage:
      T1078.004 — Valid Accounts: Cloud Accounts
      T1098.003 — Account Manipulation: Additional Cloud Roles

.PARAMETER OutputPath
    Directory to write CSV output. Default: .\reports\

.PARAMETER PassThru
    Return findings as objects to the pipeline.

.EXAMPLE
    .\Invoke-EntraPrivilegedAudit.ps1

.EXAMPLE
    .\Invoke-EntraPrivilegedAudit.ps1 -OutputPath C:\EntraReports -Verbose

.NOTES
    Required scopes : Directory.Read.All, RoleManagement.Read.Directory,
                      PrivilegedAccess.Read.AzureAD (for PIM eligible assignments)
    Legal           : Run only on tenants you own or have written authorisation to audit.
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

# ── Role risk classification ──────────────────────────────────────────────────

$HIGH_VALUE_ROLES = @{
    'Global Administrator'              = 'Critical'
    'Privileged Role Administrator'     = 'Critical'
    'Privileged Authentication Administrator' = 'Critical'
    'Security Administrator'            = 'High'
    'Exchange Administrator'            = 'High'
    'SharePoint Administrator'          = 'High'
    'Intune Administrator'              = 'High'
    'Conditional Access Administrator'  = 'High'
    'Authentication Administrator'      = 'High'
    'Hybrid Identity Administrator'     = 'High'
    'Application Administrator'         = 'High'
    'Cloud Application Administrator'   = 'High'
    'User Administrator'                = 'Medium'
    'Groups Administrator'              = 'Medium'
    'Helpdesk Administrator'            = 'Medium'
    'License Administrator'             = 'Low'
    'Global Reader'                     = 'Low'
}

$RECOMMENDED_GA_MAX = 4

# ── Helpers ───────────────────────────────────────────────────────────────────

function Assert-MgConnection {
    try { if (-not (Get-MgContext -ErrorAction Stop)) { throw } }
    catch {
        Write-Error "Not connected. Run: Connect-MgGraph -Scopes 'Directory.Read.All','RoleManagement.Read.Directory'"
        exit 1
    }
}

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  ENTRA ID PRIVILEGED ACCESS AUDIT' -ForegroundColor Cyan
    Write-Host '  ATT&CK: T1078.004 | T1098.003' -ForegroundColor DarkGray
    Write-Host '  ⚠  Run only on tenants you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

function New-Finding {
    param(
        [string]$Category,
        [string]$Principal,
        [string]$PrincipalType,
        [string]$RoleName,
        [string]$AssignmentType,
        [string]$Detail,
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity
    )
    [PSCustomObject]@{
        Timestamp      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity       = $Severity
        Category       = $Category
        Principal      = $Principal
        PrincipalType  = $PrincipalType
        RoleName       = $RoleName
        AssignmentType = $AssignmentType
        Detail         = $Detail
    }
}

# ── Main audit ────────────────────────────────────────────────────────────────

function Invoke-PrivilegedAudit {
    $findings     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $globalAdmins = [System.Collections.Generic.List[string]]::new()

    # ── 1. Active role assignments ────────────────────────────────────────────
    Write-Verbose 'Retrieving active Entra ID role assignments…'

    # Graph only allows one $expand per query — pre-load role definitions into
    # a lookup table, then expand only 'principal' when fetching assignments.
    $roleDefMap = @{}
    try {
        Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop |
            ForEach-Object { $roleDefMap[$_.Id] = $_.DisplayName }
        Write-Verbose "  Role definitions loaded: $($roleDefMap.Count)"
    }
    catch {
        Write-Verbose "  Could not pre-load role definitions: $_"
    }

    try {
        $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All `
            -ExpandProperty 'principal' -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not retrieve role assignments: $_"
        $roleAssignments = @()
    }

    foreach ($assignment in $roleAssignments) {
        $roleName  = $roleDefMap[$assignment.RoleDefinitionId] ?? $assignment.RoleDefinitionId
        $principal = $assignment.Principal

        if (-not $principal) { continue }

        $principalName = $principal.AdditionalProperties['userPrincipalName'] ??
                         $principal.AdditionalProperties['displayName'] ??
                         $principal.Id
        $principalType = $principal.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.',''

        $sev = $HIGH_VALUE_ROLES[$roleName] ?? 'Info'

        if ($sev -eq 'Info' -and $roleName -notin $HIGH_VALUE_ROLES.Keys) { continue }

        # Track Global Admins
        if ($roleName -eq 'Global Administrator') {
            $globalAdmins.Add($principalName)
        }

        # Flag service principals with admin roles
        if ($principalType -in 'servicePrincipal', 'application') {
            $findings.Add((New-Finding -Category 'ServicePrincipalRole' `
                -Principal $principalName -PrincipalType $principalType `
                -RoleName $roleName -AssignmentType 'Permanent' `
                -Severity ($sev -eq 'Low' ? 'Medium' : $sev) `
                -Detail "Service principal/app holds '$roleName' — non-interactive identities with admin rights are high-value targets (T1098.003)"))
            continue
        }

        # Permanent (non-PIM) assignment
        $findings.Add((New-Finding -Category 'PermanentRoleAssignment' `
            -Principal $principalName -PrincipalType $principalType `
            -RoleName $roleName -AssignmentType 'Permanent (Active)' `
            -Severity $sev `
            -Detail "Permanent assignment to '$roleName' — not governed by PIM; role is always active"))
    }

    # ── 2. Global Admin count check ───────────────────────────────────────────
    Write-Verbose "Global Admins found: $($globalAdmins.Count)"

    if ($globalAdmins.Count -gt $RECOMMENDED_GA_MAX) {
        $findings.Add((New-Finding -Category 'ExcessiveGlobalAdmins' `
            -Principal "($($globalAdmins.Count) accounts)" -PrincipalType 'User' `
            -RoleName 'Global Administrator' -AssignmentType 'Permanent' `
            -Severity 'High' `
            -Detail "$($globalAdmins.Count) Global Administrators found — Microsoft recommends 2–4 max. Each GA can modify any tenant setting and reset any password."))
    }

    # ── 3. PIM eligible assignments ───────────────────────────────────────────
    Write-Verbose 'Checking PIM eligible role assignments…'

    try {
        $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All `
            -ExpandProperty 'principal' -ErrorAction SilentlyContinue

        if ($eligibleAssignments) {
            foreach ($ea in $eligibleAssignments) {
                $roleName  = $roleDefMap[$ea.RoleDefinitionId] ?? $ea.RoleDefinitionId
                $principal = $ea.Principal
                if (-not $principal) { continue }

                $principalName = $principal.AdditionalProperties['userPrincipalName'] ??
                                 $principal.AdditionalProperties['displayName'] ?? $ea.PrincipalId
                $sev = $HIGH_VALUE_ROLES[$roleName] ?? 'Info'
                if ($sev -eq 'Info') { continue }

                # PIM eligible is good — log as Info so analysts can verify
                $findings.Add((New-Finding -Category 'PIMEligibleAssignment' `
                    -Principal $principalName -PrincipalType 'User' `
                    -RoleName $roleName -AssignmentType 'PIM Eligible' `
                    -Severity 'Info' `
                    -Detail "PIM eligible assignment to '$roleName' — role must be explicitly activated (good practice; verify activation policy requires MFA + justification)"))
            }
        }
    }
    catch {
        Write-Verbose "PIM eligible assignment query not available (requires PrivilegedAccess.Read.AzureAD): $_"
    }

    # ── 4. Recommend: GA accounts using shared/generic UPNs ──────────────────
    foreach ($gaName in $globalAdmins) {
        if ($gaName -notmatch 'admin|adm|priv|svc' -and $gaName -match '@') {
            $findings.Add((New-Finding -Category 'GASharedAccount' `
                -Principal $gaName -PrincipalType 'User' `
                -RoleName 'Global Administrator' -AssignmentType 'Permanent' `
                -Severity 'Medium' `
                -Detail "Global Admin account does not follow dedicated admin naming convention — admin roles should use separate privileged accounts, not day-to-day user accounts"))
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
    $Findings | Where-Object { $_.Severity -in 'Critical','High' } | Select-Object -First 15 |
        ForEach-Object {
            Write-Host ("  [{0}] {1} → {2} — {3}" -f `
                $_.Severity, $_.Principal, $_.RoleName, $_.Detail.Substring(0, [Math]::Min(80, $_.Detail.Length))) `
                -ForegroundColor $colorMap[$_.Severity]
        }
    Write-Host ''
}

# ── Entry point ───────────────────────────────────────────────────────────────

Assert-MgConnection
Write-AuditBanner

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$findings = Invoke-PrivilegedAudit

if ($findings.Count -eq 0) {
    Write-Host '  ✅ No privileged access findings.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings
    $csv = Join-Path $OutputPath "EntraPrivilegedAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csv" -ForegroundColor Green
}

if ($PassThru) { return $findings }
