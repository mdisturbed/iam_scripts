# Changelog

All notable changes to these scripts are recorded here. Each script also carries its own `$ScriptVersion`, which is written to every run manifest.

## 1.0.0 - 2026-10-20

Initial release.

### Added
- `01-Get-MfaCoverage.ps1` - Conditional Access policies and exclusions, excluded-group members, MFA registration, successful single-factor and legacy-auth sign-ins.
- `02-Get-PrivilegedAccess.ps1` - active and eligible Entra role assignments, role-holding group members, role-assignable groups, per-user privileged hygiene. Falls back when PIM is not licensed.
- `03-Get-AppsAndConsents.ps1` - consent settings, app registrations and credentials, service principals, application and delegated permissions, per-app "data movers" summary.
- `04-Get-ADPrivilegedAndServiceAccounts.ps1` - protected-group membership with nesting paths, privileged-account hygiene, service-account candidates, adminCount leftovers.
- `05-Get-ADGroupNesting.ps1` - full group graph with nesting depth, circular-nesting detection and hygiene flags.
- `06-Compare-JmlTiming.ps1` - joiner and leaver lag against an HR export, terminated-but-enabled, activity after termination, orphan candidates; optional Entra sign-in check.
- `tools/Test-ReadOnly.ps1` - static AST check that the scripts contain no state-changing commands and that every Graph call is GET.
- Evidence output for every run: timestamped folder, UTC ISO 8601 dates, `run-manifest.json`, `dataset-status.csv` with SHA-256 per file, `run.log`.
- `docs/permissions.md` and `docs/outputs.md`.
