# Legal Notice

## Authorised Use Only

These scripts query Microsoft Graph API on your behalf. They read user accounts, authentication methods, role assignments, Conditional Access policies, and application registrations.

**You must have explicit written authorisation from the tenant owner before running these scripts.** Unauthorised access to computer systems is a criminal offence in most jurisdictions, including (but not limited to):

- United States: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- United Kingdom: Computer Misuse Act 1990
- European Union: Directive 2013/40/EU on attacks against information systems
- Australia: Criminal Code Act 1995 (Part 10.7)

## Data Handling

- Output files (CSV, HTML) contain personal data (user names, sign-in timestamps, email addresses) — handle under your organisation's data classification policy and applicable privacy law (GDPR, CCPA, etc.).
- Do not store output in public repositories.
- Delete reports when no longer needed for remediation tracking.

## Scope of API Permissions

The suite requests the following Graph scopes:

| Scope | Purpose |
|---|---|
| `UserAuthenticationMethod.Read.All` | Read MFA registration status |
| `User.Read.All` | Enumerate user accounts |
| `AuditLog.Read.All` | Read sign-in activity timestamps |
| `Directory.Read.All` | Read roles, groups, and directory objects |
| `Policy.Read.All` | Read Conditional Access policies |
| `Application.Read.All` | Read app registrations and service principals |
| `RoleManagement.Read.Directory` | Read role assignments |

These are **read-only** scopes. The scripts do not write, modify, or delete any data.

## No Warranty

This software is provided "as is" without warranty of any kind. The author accepts no liability for damages arising from the use or misuse of these scripts.
