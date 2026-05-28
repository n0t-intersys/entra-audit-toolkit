# AuditHelpers.psm1
# Shared helper functions for all Entra ID audit scripts.

function Assert-MgConnection {
    param(
        [string[]]$RequiredScopes        = @(),
        [string]  $TenantId              = '',
        [string]  $ClientId              = '',
        [securestring]$ClientSecret      = $null,
        [string]  $CertificateThumbprint = ''
    )

    # Check for an existing connection before attempting to create one
    $ctx = $null
    try { $ctx = Get-MgContext -ErrorAction Stop } catch {}

    # Connect with app-only credentials if provided and not already connected
    if ($ClientId -and $TenantId -and -not $ctx) {
        Write-Verbose 'Connecting to Microsoft Graph using app-only authentication…'
        try {
            if ($ClientSecret) {
                $cred = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -NoWelcome -ErrorAction Stop
            } elseif ($CertificateThumbprint) {
                Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
                    -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
            } else {
                throw 'Provide either -ClientSecret or -CertificateThumbprint for app-only authentication.'
            }
            $ctx = Get-MgContext
        }
        catch { throw "Failed to connect to Microsoft Graph: $_" }
    }

    if (-not $ctx) {
        $scopeHint = if ($RequiredScopes) { " -Scopes '$($RequiredScopes -join "','")'" } else { '' }
        throw "Not connected to Microsoft Graph. Run: Connect-MgGraph$scopeHint"
    }

    # Scope validation only applies to delegated (user) auth — app-only permissions
    # are granted in the Azure portal and are not reflected in Get-MgContext.Scopes
    $isAppOnly = $ctx.AuthType -eq 'AppOnly'
    if (-not $isAppOnly -and $RequiredScopes.Count -gt 0) {
        $missing = $RequiredScopes | Where-Object { $_ -notin $ctx.Scopes }
        if ($missing) {
            throw "Connected but missing required scope(s): $($missing -join ', '). Reconnect with all required scopes."
        }
    }

    $identity = if ($isAppOnly) { "App: $($ctx.ClientId)" } else { $ctx.Account }
    Write-Verbose "Connected | $($ctx.AuthType) | $identity | Tenant: $($ctx.TenantId)"
}

function New-AuditFinding {
    param(
        [string]$Category,
        [string]$Identity,         # UPN, app name, policy name, principal display name
        [string]$IdentityType,     # user, servicePrincipal, application, group, policy
        [string]$Resource,         # role name, app ID, permission name — what the identity has access to
        [string]$Detail,
        [string]$Recommendation = '',
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        [string]$Module = ''       # which audit script produced this
    )
    [PSCustomObject]@{
        Timestamp      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity       = $Severity
        Module         = $Module
        Category       = $Category
        Identity       = $Identity
        IdentityType   = $IdentityType
        Resource       = $Resource
        Detail         = $Detail
        Recommendation = $Recommendation
    }
}

function Write-AuditSummary {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$Findings,
        [switch]$ShowCategoryBreakdown,
        [switch]$ShowTopFindings,
        [int]$TopFindingsCount = 10
    )

    $severityOrder = @{ Critical=0; High=1; Medium=2; Low=3; Info=4 }
    $colorMap      = @{ Critical='Red'; High='DarkYellow'; Medium='Yellow'; Low='Cyan'; Info='Gray' }

    Write-Host ('─' * 70) -ForegroundColor DarkGray
    Write-Host '  FINDINGS SUMMARY' -ForegroundColor White
    Write-Host ('─' * 70) -ForegroundColor DarkGray

    if ($ShowCategoryBreakdown) {
        $Findings | Group-Object Category | Sort-Object Count -Descending |
            ForEach-Object {
                Write-Host ("  {0,-35} {1,4} finding(s)" -f $_.Name, $_.Count) -ForegroundColor White
            }
        Write-Host ''
    }

    $Findings | Group-Object Severity | Sort-Object { $severityOrder[$_.Name] } |
        ForEach-Object {
            $icon = switch ($_.Name) {
                'Critical' { '🔴' }; 'High' { '🟠' }; 'Medium' { '🟡' };
                'Low'  { '🔵' }; default { '⚪' }
            }
            Write-Host ("  $icon {0,-10} {1,4}" -f $_.Name, $_.Count) -ForegroundColor $colorMap[$_.Name]
        }

    if ($ShowTopFindings -and $Findings.Count -gt 0) {
        Write-Host ''
        $Findings | Sort-Object { $severityOrder[$_.Severity] } | Select-Object -First $TopFindingsCount |
            ForEach-Object {
                Write-Host ("  [{0}] {1}" -f $_.Severity, $_.Detail.Substring(0, [Math]::Min(90, $_.Detail.Length))) `
                    -ForegroundColor $colorMap[$_.Severity]
                if ($_.Recommendation) {
                    Write-Host ("        → {0}" -f $_.Recommendation.Substring(0, [Math]::Min(80, $_.Recommendation.Length))) `
                        -ForegroundColor DarkGray
                }
            }
    }

    Write-Host ''
}

Export-ModuleMember -Function Assert-MgConnection, New-AuditFinding, Write-AuditSummary
