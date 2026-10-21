# Pilot runbook

Every script in this repository has been tested against **mocked** Graph, Active Directory, Exchange Online, SharePoint and Azure Resource Manager responses. That shows the logic is correct and nothing writes to the directory. It cannot show how a script behaves against a real tenant: real property shapes, real data volumes, throttling, permission edge cases, and whether the default thresholds and name patterns suit the environment.

This runbook is how a script moves from **mock-tested** to **pilot-verified**, so it can be handed to other people to run. Do the pilot yourself, with your own read access, before anyone else runs a script.

## Status levels

| Status | Meaning | Who may run it |
|--------|---------|----------------|
| Mock-tested | Passed parse, lint, `Test-ReadOnly.ps1`, and end-to-end runs against mocks | The engineer running the pilot |
| Pilot-verified | Run once in the target environment and checked against known answers (below) | Anyone with the documented permissions |
| Baseline | Pilot-verified and its output filed as the evidence baseline | Anyone; rerun with the same parameters to measure change |

Every script starts at **Mock-tested**. Record progress in the sign-off table at the end.

## Before the first run

1. Run `.\tools\Test-ReadOnly.ps1` and keep the output; it's the reviewer's evidence that nothing writes to the directory.
2. Confirm the permissions in [permissions.md](permissions.md) are granted, and note any that aren't. Missing permissions show up as `Blocked` datasets, not failures.
3. Choose the evidence location. Use `-OutputRoot` to point there so nothing lands next to the scripts.
4. Run outside business-critical windows for the AD scripts that read every object (05, 07, 08, 12, 13, 18, 23), and for 19, which queries every DC's Security log.
5. Before running 18 or 19, tell the SOC. ACL enumeration and remote event log reads can look like reconnaissance to EDR / identity threat detection.

## Order

Start with the scripts that need the least setup and give the clearest known answers:

1. **02** Entra privileged access, **01** MFA coverage
2. **04** AD privileged accounts, **05** AD group nesting
3. **03** apps and consents, **10** guests, **12** stale accounts, **13** sync scope
4. **07** role mining, **08** extension attributes, **23** attribute population
5. **16** device posture, **21** identity risk, **22** PIM settings, **20** governance coverage
6. **18** AD delegation, **19** DC authentication protocols (needs Event Log Readers)
7. **09** mail and sharing (needs Exchange access), **11** Azure RBAC (needs Azure Reader), **17** AWS (needs the read-only role in each account)
8. **06** JML timing, **14** IGA reconciliation, **15** rule-managed access (need input files)

## What to check for every run

- [ ] Script finished without a `Fatal` line in `run.log`.
- [ ] `dataset-status.csv`: every `Blocked` or `EvidenceUnavailable` row is explained (permission not yet granted, licence not present).
- [ ] `run-manifest.json`: `ScopesInToken` contains only read scopes and matches what was approved.
- [ ] Row counts are plausible against what you know about the environment, roughly within 10%.
- [ ] No column is blank in every row when it shouldn't be. An all-blank column usually means a property name differs from what the script expects; report it.
- [ ] The known-answer checks below match.

## Known-answer checks

Pick one or two facts per script that you can confirm independently in the portal, ADUC or the admin center, and compare.

| Script | Check against |
|--------|---------------|
| 01 MFA coverage | Number of CA policies and their states in the Entra portal; one known exclusion group appears in `ca-exclusions.csv` |
| 02 Privileged access | Global Administrator count in Entra > Roles; one known PIM-eligible admin appears as eligible |
| 03 Apps and consents | One known app registration's secret expiry date; one third-party app's granted permissions in Enterprise apps > Permissions |
| 04 AD privileged | Domain Admins membership in ADUC, including a nested group if one exists |
| 05 Group nesting | Total group count (`(Get-ADGroup -Filter *).Count`); one known nested group's `DepthDown` |
| 06 JML timing | One recent leaver: termination date in HR vs account disable date in AD |
| 07 Role mining | Size of one department population vs an HR headcount; one group you know every member of that department has |
| 08 Extension attributes | One attribute you know is in use shows `InUse`, with a plausible count |
| 09 Mail and sharing | One known forwarding mailbox or inbox rule (if any); tenant sharing level in the SharePoint admin center |
| 10 Guests | Total guest count in Entra > Users (filter: Guest) |
| 11 Azure RBAC | Owner assignments on one subscription in the portal (Access control (IAM)) |
| 12 Stale accounts | One account you know is active on both sides shows `0-30`; one disabled leaver shows as stale or disabled |
| 13 Sync scope | Last sync time in Entra Connect Health or the portal; one OU you know is excluded shows `OutOfScope` |
| 14 IGA reconciliation | `iga-input-profile.csv` systems and status values look right; one account you know was created outside the IGA appears |
| 15 Rule-managed access | `role-definition-check.csv` has no unexpected issues; one user you know moved shows `RoleDrift` (once the attribute is in use) |
| 16 Device posture | Device counts by join type vs Entra > Devices; one known non-compliant device in Intune |
| 17 AWS IAM | Root MFA status in one account's IAM dashboard; one known cross-account role's trust policy |
| 18 AD delegation | One delegation you know exists (e.g. helpdesk reset-password on a user OU) appears with the right OU and trustee |
| 19 DC auth protocols | `LogStartsUtc` matches the oldest event in Event Viewer on one DC; one known NTLM application server appears |
| 20 Governance coverage | Number of access reviews in Identity Governance; one app you know is reviewed shows `Covered` |
| 21 Identity risk | Risky user count in Entra ID Protection > Risky users |
| 22 PIM role settings | Global Administrator settings in PIM > Entra roles > Settings |
| 23 AD attribute population | `user objects scanned` matches `(Get-ADUser -Filter *).Count`; `sAMAccountName` shows 100% |

## Tuning on first run

Expect to adjust these on the first run and record the values used. They're written to the manifest automatically.

| Script | Usually tuned |
|--------|---------------|
| 04, 06, 07, 14, 15 | Service / admin account name patterns (`-ServiceNamePatterns`, `-ExcludeNamePatterns`) |
| 05 | `-NamingConventionRegex` once a convention is agreed |
| 06 | HR column names, `-HrDateFormat`, `-TerminatedStatusValues`, `-AdMatchAttribute` |
| 07 | `-GroupingAttributes` (add the job-code attribute), `-MinPopulation`, thresholds |
| 08 | `-AdditionalAttributes`, `-SampleValueCount 0` if values are sensitive |
| 12, 13 | `-AnchorAttribute` if Entra Connect uses `mS-DS-ConsistencyGuid` |
| 17 | `-Region`, `-IdentityCenterRegion`, `-AssumeRoleName` |
| 19 | `-Hours` to fit how much Security log the DCs hold |
| 20 | `-InScopeAppsCsv` once the certification scope list exists |
| 22 | `-MaxActivationHours` to match the agreed standard |
| 23 | `-ObjectClass`, `-EnabledOnly`, `-SearchBase` to limit load |
| 14 | Column names, `-SystemName`, status value lists |

## Reporting a problem

Send only what's needed to reproduce it, with identifiers replaced by placeholders (User1, Group1, contoso.local):

- the script name and version from `run-manifest.json`
- the `ERROR` or `WARN` lines from `run.log`
- the dataset name from `dataset-status.csv`, and the column that looks wrong
- the parameters used

Never send raw CSV output.

## Handover

When a script is pilot-verified, hand it over with:

1. the `Test-ReadOnly.ps1` output
2. the pilot run's `run-manifest.json` and `dataset-status.csv` (no data files)
3. the tuned parameters, as a ready-to-run command line
4. the permissions the runner needs, from [permissions.md](permissions.md)

## Sign-off

| Script | Version | Pilot date | Run by | Known-answer checks passed | Tuned parameters | Status |
|--------|---------|-----------|--------|----------------------------|------------------|--------|
| 01 MFA coverage | 1.0.1 | | | | | Mock-tested |
| 02 Privileged access | 1.0.1 | | | | | Mock-tested |
| 03 Apps and consents | 1.0.1 | | | | | Mock-tested |
| 04 AD privileged / service accounts | 1.0.1 | | | | | Mock-tested |
| 05 AD group nesting | 1.0.1 | | | | | Mock-tested |
| 06 JML timing | 1.0.1 | | | | | Mock-tested |
| 07 Role mining | 1.0.0 | | | | | Mock-tested |
| 08 Extension attributes | 1.0.0 | | | | | Mock-tested |
| 09 Mail and sharing | 1.0.0 | | | | | Mock-tested |
| 10 Guests | 1.0.0 | | | | | Mock-tested |
| 11 Azure RBAC | 1.0.0 | | | | | Mock-tested |
| 12 Stale accounts | 1.0.0 | | | | | Mock-tested |
| 13 Hybrid sync scope | 1.0.0 | | | | | Mock-tested |
| 14 IGA reconciliation | 1.0.0 | | | | | Mock-tested |
| 15 Rule-managed access | 1.0.0 | | | | | Mock-tested |
| 16 Device posture | 1.0.0 | | | | | Mock-tested |
| 17 AWS IAM posture | 1.0.0 | | | | | Mock-tested |
| 18 AD delegation | 1.0.0 | | | | | Mock-tested |
| 19 DC auth protocols | 1.0.0 | | | | | Mock-tested |
| 20 Governance coverage | 1.0.0 | | | | | Mock-tested |
| 21 Identity risk | 1.0.0 | | | | | Mock-tested |
| 22 PIM role settings | 1.0.0 | | | | | Mock-tested |
| 23 AD attribute population | 1.0.0 | | | | | Mock-tested |
