# Entra ID Security Auditor

Five PowerShell modules covering the Entra ID attack surface I audit most often — MFA gaps, over-permissioned apps, Conditional Access blindspots, stale identities, and permanent privileged role assignments. Run individually or as a single suite that produces a dark-themed HTML dashboard.

![PSScriptAnalyzer](https://github.com/n0t-intersys/entra-audit-toolkit/actions/workflows/ci.yml/badge.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-7.2%2B-5391FE?logo=powershell&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-SDK-00BCF2?logo=microsoft&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## What it checks

| Module | Key findings |
|---|---|
| **User Accounts** | Stale sign-ins, never-logged-in, disabled with licenses, stale guests, no manager |
| **Privileged Access** | GA count, permanent (non-PIM) assignments, service principals with admin roles, PIM eligible |
| **Conditional Access** | No MFA policy, legacy auth not blocked, broad exclusions, no sign-in risk policy |
| **App Registrations** | Expiring secrets/certs, no owner, multi-tenant exposure, high-privilege app permissions |
| **MFA Registration** | No MFA registered, SMS/voice only, privileged accounts without phishing-resistant MFA |

MITRE ATT&CK coverage: T1078.004 · T1098.003 · T1528 · T1550.001

---

## Requirements

- PowerShell 7.2+
- Microsoft Graph PowerShell SDK modules:

```powershell
Install-Module Microsoft.Graph.Users,
              Microsoft.Graph.Identity.DirectoryManagement,
              Microsoft.Graph.Identity.SignIns,
              Microsoft.Graph.Applications,
              Microsoft.Graph.Identity.Governance -Scope CurrentUser
```

---

## Quick start

Connect with the required scopes, then run the suite:

```powershell
Connect-MgGraph -Scopes `
  "UserAuthenticationMethod.Read.All", `
  "User.Read.All", `
  "AuditLog.Read.All", `
  "Directory.Read.All", `
  "Policy.Read.All", `
  "Application.Read.All", `
  "RoleManagement.Read.Directory"

.\scripts\Invoke-EntraAuditSuite.ps1 -OpenReport
```

An HTML report and per-module CSVs land in `.\reports\`.

---

## Running modules individually

Each script is self-contained and accepts `-PassThru` to return findings as objects:

```powershell
# MFA audit — skip guests (default), verbose progress
.\scripts\Invoke-EntraMFAAudit.ps1 -Verbose

# Privileged access audit — pipe findings to Where-Object
$critical = .\scripts\Invoke-EntraPrivilegedAudit.ps1 -PassThru |
    Where-Object Severity -eq 'Critical'

# CA audit with custom output path
.\scripts\Invoke-EntraConditionalAccessAudit.ps1 -OutputPath C:\AuditReports

# App audit — warn sooner about expiring credentials
.\scripts\Invoke-EntraAppAudit.ps1 -CredentialExpiryWarningDays 60

# User audit — tighter stale threshold
.\scripts\Invoke-EntraUserAudit.ps1 -StaleThresholdDays 60
```

---

## Suite parameters

| Parameter | Default | Description |
|---|---|---|
| `-OutputPath` | `.\reports` | Directory for CSV and HTML output |
| `-StaleThresholdDays` | `90` | Days without sign-in before flagging |
| `-SkipGuestUsers` | `$true` | Exclude guests from MFA module |
| `-CredentialExpiryWarningDays` | `30` | Days before credential expiry to warn |
| `-OpenReport` | — | Open HTML in browser when done |

---

## Finding severity model

| Level | Meaning |
|---|---|
| 🔴 Critical | Immediate risk — direct path to tenant compromise |
| 🟠 High | Significant exposure, remediate within days |
| 🟡 Medium | Increases attack surface, remediate within weeks |
| 🔵 Low | Hygiene issue or policy gap |
| ⚪ Info | Informational — verify intent |

---

## Required Graph scopes

| Scope | Used by |
|---|---|
| `UserAuthenticationMethod.Read.All` | MFA module |
| `User.Read.All` | Users, MFA |
| `AuditLog.Read.All` | Users (sign-in activity) |
| `Directory.Read.All` | All modules |
| `Policy.Read.All` | CA module |
| `Application.Read.All` | Apps module |
| `RoleManagement.Read.Directory` | Privileged module |

`UserAuthenticationMethod.Read.All` is highly privileged. Use app-only authentication with a service principal in automated/scheduled runs rather than delegated credentials.

---

## Legal

Run only on tenants you own or have explicit written authorisation to audit. See [LEGAL.md](LEGAL.md).

Output files contain personal data — handle under your organisation's data classification policy. Do not commit reports to version control.
