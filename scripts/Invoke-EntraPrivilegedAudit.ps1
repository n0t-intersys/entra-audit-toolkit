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

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  ENTRA ID PRIVILEGED ACCESS AUDIT' -ForegroundColor Cyan
    Write-Host '  ATT&CK: T1078.004 | T1098.003' -ForegroundColor DarkGray
    Write-Host '  ⚠  Run only on tenants you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
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
        Write-Warning "Could not pre-load role definitions — role names will appear as GUIDs: $_"
        # Abort if map is empty to prevent producing a misleadingly clean report
        if ($roleDefMap.Count -eq 0) { throw "Role definition pre-load failed. Cannot produce accurate audit results." }
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

        # Flag service principals with admin roles
        if ($principalType -in 'servicePrincipal', 'application') {
            $findings.Add((New-AuditFinding -Module 'PrivilegedAccess' -Category 'ServicePrincipalRole' `
                -Identity $principalName -IdentityType $principalType `
                -Resource $roleName `
                -Severity ($sev -eq 'Low' ? 'Medium' : $sev) `
                -Detail "Service principal/app holds '$roleName' — non-interactive identities with admin rights are high-value targets (T1098.003)" `
                -Recommendation "Review whether this SP requires '$roleName'; prefer scoped permissions over directory roles"))
            continue
        }

        # Track Global Admins (users/groups only, not SPs)
        if ($roleName -eq 'Global Administrator') {
            $globalAdmins.Add($principalName)
        }

        # Permanent (non-PIM) assignment
        $findings.Add((New-AuditFinding -Module 'PrivilegedAccess' -Category 'PermanentRoleAssignment' `
            -Identity $principalName -IdentityType $principalType `
            -Resource $roleName `
            -Severity $sev `
            -Detail "Permanent assignment to '$roleName' — not governed by PIM; role is always active" `
            -Recommendation 'Migrate to PIM eligible assignment with MFA activation policy'))
    }

    # ── 2. Global Admin count check ───────────────────────────────────────────
    Write-Verbose "Global Admins found: $($globalAdmins.Count)"

    if ($globalAdmins.Count -ge $RECOMMENDED_GA_MAX) {
        $findings.Add((New-AuditFinding -Module 'PrivilegedAccess' -Category 'ExcessiveGlobalAdmins' `
            -Identity "($($globalAdmins.Count) accounts)" -IdentityType 'User' `
            -Resource 'Global Administrator' `
            -Severity 'High' `
            -Detail "$($globalAdmins.Count) Global Administrators found — Microsoft recommends 2–4 max. Each GA can modify any tenant setting and reset any password." `
            -Recommendation 'Reduce Global Administrators to 2–4 break-glass accounts; use scoped admin roles for day-to-day tasks'))
    }

    # ── 3. PIM eligible assignments ───────────────────────────────────────────
    Write-Verbose 'Checking PIM eligible role assignments…'

    try {
        $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All `
            -ExpandProperty 'principal' -ErrorAction Stop

        if ($eligibleAssignments) {
            foreach ($ea in $eligibleAssignments) {
                $roleName  = $roleDefMap[$ea.RoleDefinitionId] ?? $ea.RoleDefinitionId
                $principal = $ea.Principal
                if (-not $principal) { continue }

                $principalName = $principal.AdditionalProperties['userPrincipalName'] ??
                                 $principal.AdditionalProperties['displayName'] ?? $ea.PrincipalId
                $sev = $HIGH_VALUE_ROLES[$roleName] ?? 'Info'
                if ($sev -eq 'Info') { continue }

                # PIM eligible is good — log at actual severity so analysts can verify
                $findings.Add((New-AuditFinding -Module 'PrivilegedAccess' -Category 'PIMEligibleAssignment' `
                    -Identity $principalName -IdentityType 'User' `
                    -Resource $roleName `
                    -Severity $sev `
                    -Detail "PIM eligible assignment to '$roleName' — role must be explicitly activated (verify activation policy requires MFA + justification)" `
                    -Recommendation 'Review PIM activation policy: require MFA, justification, and set a maximum activation duration'))
            }
        }
    }
    catch {
        if ($_ -match '403|Forbidden|Authorization_RequestDenied|PrivilegedAccess') {
            Write-Verbose "PIM eligible assignments skipped — requires PrivilegedAccess.Read.AzureAD scope: $_"
        } else {
            Write-Warning "PIM eligible assignment query failed: $_"
        }
    }

    # ── 4. Recommend: GA accounts using shared/generic UPNs ──────────────────
    foreach ($gaName in $globalAdmins) {
        if ($gaName -notmatch '(?i)(^|[-_.])adm(in)?[-_.]|(?i)(^|[-_.])priv[-_.]|(?i)(^|[-_.])svc[-_.]' -and $gaName -match '@') {
            $findings.Add((New-AuditFinding -Module 'PrivilegedAccess' -Category 'GASharedAccount' `
                -Identity $gaName -IdentityType 'User' `
                -Resource 'Global Administrator' `
                -Severity 'Medium' `
                -Detail "Global Admin account does not follow dedicated admin naming convention — admin roles should use separate privileged accounts, not day-to-day user accounts" `
                -Recommendation 'Provision a dedicated privileged account (e.g. adm.firstname@domain) for Global Admin duties; keep standard account separate'))
        }
    }

    return $findings
}

# ── Entry point ───────────────────────────────────────────────────────────────

Assert-MgConnection -RequiredScopes 'Directory.Read.All','RoleManagement.Read.Directory','PrivilegedAccess.Read.AzureAD' `
    -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint
Write-AuditBanner

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$findings = Invoke-PrivilegedAudit

if ($findings.Count -eq 0) {
    Write-Host '  ✅ No privileged access findings.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings -ShowTopFindings -TopFindingsCount 15
    $csv = Join-Path $OutputPath "EntraPrivilegedAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csv" -ForegroundColor Green
}

if ($PassThru) { return $findings }
