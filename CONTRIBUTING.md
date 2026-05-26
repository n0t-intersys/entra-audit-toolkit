# Contributing

Contributions are welcome. A few ground rules:

## What's in scope

- New audit checks within existing modules (add a clearly commented block inside the relevant `Invoke-*` function)
- New audit modules following the existing pattern (parameter block, `New-Finding` factory, `PassThru` support, CSV export)
- Bug fixes and PowerShell compatibility improvements
- Documentation improvements

## What to check before opening a PR

1. **PSScriptAnalyzer** — run `Invoke-ScriptAnalyzer -Path scripts/ -Recurse` and fix any warnings
2. **Comment-based help** — every parameter should have a `.PARAMETER` block
3. **Legal note** — every script that touches user data must include the `⚠ Run only on tenants you own or have written authorisation to audit` line in its banner
4. **No hardcoded credentials** — the scripts must not embed tenant IDs, client secrets, or user names

## Style conventions

- Use `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'`
- Wrap Graph calls in `try/catch` with `-ErrorAction Stop` so errors surface cleanly
- Use `Write-Verbose` for progress; `Write-Host` only for user-facing status lines
- Findings go through the `New-Finding` helper — do not construct `[PSCustomObject]` directly in audit logic
- Severity levels: `Critical` / `High` / `Medium` / `Low` / `Info`

## Submitting

1. Fork the repo and create a feature branch
2. Make your changes and test against a non-production tenant
3. Open a pull request with a brief description of what the new check catches and why it matters
