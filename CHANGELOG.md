# Changelog

All notable changes to these scripts are recorded here. Each script also carries its own `$ScriptVersion`, which is written to every run manifest, so evidence can always be tied to the exact code that produced it.

## 1.5.1 - 2026-10-21

### Changed
- `23-Get-ADAttributePopulation.ps1` 1.0.1: attribute syntax codes are built from a prefix and number instead of written out in full, so the source no longer trips the guardrail's IP address rule. No change in behavior or output.

## 1.5.0 - 2026-10-21

### Added
- `23-Get-ADAttributePopulation.ps1` (1.0.0): every attribute the schema allows on users (and optionally groups and computers), resolved through superclasses and auxiliary classes, with populated count and %, total and distinct values, longest value, syntax, single/multi-valued, mandatory, defining class, global catalog, link type, system-only and confidential. Binary attributes counted by presence only; constructed, base-only and security-descriptor attributes reported as not counted; confidential zeros marked as possibly unreadable. No values written unless `-SampleValueCount` is set. Flag values from [MS-ADTS] 2.2.9 and 2.2.10.
- Catalog entry for the launcher and report (shows as Check first: heavy read), script page, permissions, pilot check, tuning and sign-off rows.

## 1.4.0 - 2026-10-21

Launcher and report; no discovery-script changes.

### Added
- `tools/Start-Discovery.ps1` (1.0.0): readiness check for every script on this machine (AD module and DC, Graph / Exchange / Azure / AWS modules, input files), pick list (Out-GridView or console), runs the picks with `-Server` and `-OutputRoot`, asks for required input files and for SOC confirmation before 18, then a run summary (Completed / Partial / Failed / Skipped with the run folder). Unattended with `-Select` and `-ScriptParameters`.
- `tools/New-DiscoveryReport.ps1` (1.0.0): one self-contained HTML page from the evidence folder: headline tiles, coverage of all 22 scripts with pilot status, summary metrics with change since the previous run, dataset statuses. Built from summaries only (counts, no names); run details only with `-IncludeRunDetails`.
- `tools/discovery-catalog.psd1`: script list and what each needs, shared by the two tools.
- Docs: launcher and report section and an Entra-joined devices section in `docs/getting-started.md`; troubleshooting rows.

### Changed
- `tools/Test-ReadOnly.ps1` 1.3.0: `Read` added to the read-only verbs (`Read-Host` reads keyboard input).

## 1.3.1 - 2026-10-20

Repository guardrail; no script changes.

### Added
- `tools/guardrail/`: scanner (`Invoke-Guardrail.ps1`), rules (`rules.psd1`), Microsoft-published ID allowlist (`known-public-ids.txt`), private denylist template, one-time setup (`Install-Guardrail.ps1`) and a self-test (`Test-Guardrail.ps1`) that proves every rule fires and the placeholders pass.
- `.githooks/pre-commit` and `.githooks/commit-msg`: scan staged files and the commit message; fail closed.
- `.github/workflows/guardrail.yml`: self-test, full tree + commit message / author scan with the `GUARDRAIL_DENYLIST` secret, and gitleaks over the full history on every push and pull request.
- `docs/guardrail.md` and `CONTRIBUTING.md`.

### Changed
- `.gitignore`: also ignores the private denylist, `*.local.psd1`, `.env`, credential XML and more data / archive types.

## 1.3.0 - 2026-10-20

Documentation restructure; no script changes.

### Changed
- README is now a short front door: script table, quick start, read-only guarantee, using the results, and a documentation index.
- `docs/scripts/`: one page per script (collects, parameters, output files, permissions, pilot check, troubleshooting), with an index and previous / next links.
- `docs/getting-started.md`: prerequisites, authentication, common parameters, every script with typical parameters, locked-down environments.
- `docs/outputs.md`: now covers the run folder, dataset statuses and handling the output; per-script output tables moved to the script pages.
- `docs/troubleshooting.md` and `docs/design-and-testing.md`: moved out of the README.

## 1.2.1 - 2026-10-20

### Added
- `LICENSE` (MIT) and an Author section in the README.
- `tools/New-FindingEvidence.ps1` 1.0.0: reads a run folder and prints the finding's Scope count, Evidence (with SHA-256) and Closure criteria (exact rerun command and metric), to console, file or clipboard.
- `docs/jira-finding-template.md`: Jira issue fields, description template, severity guide with examples from the scripts, worked example and evidence rules.

## 1.2.0 - 2026-10-20

Fills the gaps found when mapping the discovery access matrix against the scripts.

### Added
- `16-Get-DevicePosture.ps1` (1.0.0): Entra device join / management / compliance, Intune compliance and check-in, compliance policy assignment and the no-policy setting, CA policies that rely on device state.
- `17-Get-AwsIamPosture.ps1` (1.0.0): AWS root MFA and keys, IAM users and access keys, role trusts (cross-account, wildcard, SAML), Access Analyzer external-access findings, IAM Identity Center permission sets and assignments; multi-account through a read-only role.
- `18-Get-ADDelegation.ps1` (1.0.0): dangerous ACL rights on the domain root, AdminSDHolder, DC OU, OUs and protected groups held by non-default trustees (incl. DCSync, reset password, write members, shadow credentials, RBCD, LAPS read), non-default owners, per-trustee view.
- `19-Get-DcAuthProtocolUsage.ps1` (1.0.0): NTLM v1 / v2 logons, NTLM validations and RC4 / DES Kerberos tickets from DC Security logs, with the window each DC's log actually covers.
- `20-Get-GovernanceCoverage.ps1` (1.0.0): access review definitions and decision statistics, coverage of apps / groups / Tier 0 roles, optional in-scope application list, access packages.
- `21-Get-IdentityRisk.ps1` (1.0.0): risky users (admins first), risk detections, risky service principals, CA risk policies.
- `22-Get-PimRoleSettings.ps1` (1.0.0): PIM activation requirements and permanent-assignment settings per directory role, with Tier 0 flags.
- Docs: README sections, permissions (AWS and event log sections), outputs, pilot runbook checks and sign-off rows for 16-22.

### Changed
- `tools/Test-ReadOnly.ps1` 1.2.0: `Use-STSRole` added to the allowlist (returns temporary credentials for a read-only AWS role; changes nothing).

### Found and fixed during testing (before release)
- 18: schema and extended-right GUID lookups were shared, but some GUIDs are identical (`member` / Self-Membership, `servicePrincipalName` / Validated-SPN), which would have mislabeled write-members rights. Now kept separate.
- 18: builtin operator groups were reported as unresolved trustees.
- 19: covered window is now taken from where each DC's Security log starts, not from the oldest matching event.
- 20: decision apply failures with "Failure" in the result were not counted.

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
