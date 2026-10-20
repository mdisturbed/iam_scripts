# Changelog

All notable changes to these scripts are recorded here. Each script also carries its own `$ScriptVersion`, which is written to every run manifest, so evidence can always be tied to the exact code that produced it.

## 1.1.0 - 2026-10-20

### Added
- `07-Get-RoleMiningCandidates.ps1` (1.0.0): role mining by department / job code, with attribute quality and spelling-variant detection, birthright and role candidates, and outliers.
- `08-Get-ExtensionAttributeInventory.ps1` (1.0.0): usage and format of AD extension and custom attributes, Entra cloud-only extension attributes, directory (schema) extensions and custom security attribute definitions.
- `09-Get-MailForwardingAndSharing.ps1` (1.0.0): mailbox forwarding, forwarding / hiding inbox rules, transport rules, remote domain and outbound spam forwarding settings, SharePoint tenant and site sharing.
- `10-Get-GuestAccess.ps1` (1.0.0): external collaboration settings, per-guest activity / access / sponsors, guests by home domain.
- `11-Get-AzureRbac.ps1` (1.0.0): Azure role assignments across management groups and subscriptions, PIM eligibility, custom roles, classic administrators.
- `12-Get-StaleAccounts.ps1` (1.0.0): combined AD + Entra activity per identity, activity buckets, optional stale computers.
- `13-Get-HybridSyncScope.ps1` (1.0.0): sync status, inferred OU scope, unsynced users, orphaned synced objects, cloud-only duplicates, provisioning errors, optional groups.
- `14-Compare-IgaToDirectory.ps1` (1.0.0): reconciliation of IGA account and assignment exports against AD.
- `15-Test-RuleManagedAccess.ps1` (1.0.0): drift between applied roles, HR-expected roles and actual rule-managed group membership.
- `examples/`: placeholder input templates for scripts 06, 14 and 15.
- `docs/pilot-runbook.md`: per-script known-answer checks, tuning guide, problem reporting and sign-off table for moving scripts from mock-tested to pilot-verified.
- `tools/Test-ReadOnly.ps1` 1.1.0: also fails on `Invoke-AzRestMethod` without `-Method GET`.

### Fixed (scripts 01-06 -> 1.0.1)
- **02, 03: owner counts were always 1.** Wrapping the paged Graph helper's result in `@()` produced a one-element array, so `OwnerCount` on role-assignable groups (02) and service principals without an app registration (03) was wrong, and the `NoOwner` flag never fired for those service principals.
- All Graph and AD scripts: the run manifest can now record extra connection details (used by 09 and 11). Identical helper change in every script, so all are bumped to 1.0.1.

### Changed
- README rewritten to cover all 15 scripts, with per-script parameters, a goal-to-script map and an expanded troubleshooting table.
- `docs/permissions.md`: per-script summary, every scope used, Exchange and Azure sections.
- `docs/outputs.md`: output reference for scripts 07-15.
- `.gitignore`: allows only `examples/*.example.csv`; all other CSV, JSON and log files stay blocked.

## 1.0.0 - 2026-10-20

Initial release.

### Added
- `01-Get-MfaCoverage.ps1`: Conditional Access policies and exclusions, excluded-group members, MFA registration, successful single-factor and legacy-auth sign-ins.
- `02-Get-PrivilegedAccess.ps1`: active and eligible Entra role assignments, role-holding group members, role-assignable groups, per-user privileged hygiene. Falls back when PIM is not licensed.
- `03-Get-AppsAndConsents.ps1`: consent settings, app registrations and credentials, service principals, application and delegated permissions, per-app "data movers" summary.
- `04-Get-ADPrivilegedAndServiceAccounts.ps1`: protected-group membership with nesting paths, privileged-account hygiene, service-account candidates, adminCount leftovers.
- `05-Get-ADGroupNesting.ps1`: full group graph with nesting depth, circular-nesting detection and hygiene flags.
- `06-Compare-JmlTiming.ps1`: joiner and leaver lag against an HR export, terminated-but-enabled, activity after termination, orphan candidates; optional Entra sign-in check.
- `tools/Test-ReadOnly.ps1`: static AST check that the scripts contain no state-changing commands and that every Graph call is GET.
- Evidence output for every run: timestamped folder, UTC ISO 8601 dates, `run-manifest.json`, `dataset-status.csv` with SHA-256 per file, `run.log`.
- `docs/permissions.md` and `docs/outputs.md`.
