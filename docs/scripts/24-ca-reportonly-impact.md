# 24 - CA report-only impact

**Script:** [`24-Get-CaReportOnlyImpact.ps1`](../../scripts/24-Get-CaReportOnlyImpact.ps1) · **Version:** 1.1.1 · **Source:** Entra sign-in logs

> What does each Conditional Access policy do to real sign-ins, who would a report-only policy block or challenge if it were switched on, and which successful sign-ins does no enforced policy cover?

Staged enforcement means running a policy in report-only mode first. Entra records, on every sign-in, what every policy did or *would* have done; this script turns that into a per-policy impact list so a policy can be switched on knowing exactly who it affects, and lists the sign-ins that only report-only policies touched.

**Collects:** every Conditional Access policy and its state; for a lookback window of sign-ins, per policy: sign-ins evaluated and the count of every result (`success`, `failure`, `notApplied`, `reportOnlySuccess`, `reportOnlyFailure` = would block, `reportOnlyInterrupted` = would need an extra step such as MFA, `reportOnlyNotApplied`), distinct users that would be blocked or interrupted, top apps involved; one row per policy, user and app for every would-block / would-interrupt (and every enforced block), with whether the user is privileged or Tier 0; and one row per user and app for successful sign-ins where no enforced policy applied. Policies seen in sign-ins but no longer present are reported as *deleted or not readable*.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SignInLookbackDays` | `14` | Days of sign-ins (1-30); 14-30 is usual before enforcing |
| `-MaxSignInRecords` | `100000` | Safety cap per sign-in type, counted across all slices; output marked TRUNCATED, with the window actually covered, if reached |
| `-SignInSliceHours` | `24` | Hours of sign-ins read per Graph query (1-168). Use a smaller slice if a large tenant still times out |
| `-ReportOnlyPoliciesOnly` | off | Keep results for report-only policies only |
| `-IncludeNonInteractive` | off | Add non-interactive sign-ins (beta endpoint; much larger) |
| `-IncludeServicePrincipal` | off | Add service principal sign-ins (beta endpoint), so workload identity policies show impact |
| `-SkipPrivilegeJoin` | off | Do not read directory role holders; `IsPrivileged` / `IsTier0` are left blank |
| `-TopAppCount` | `5` | Apps listed per policy |

**Open first:** `ca-policy-results.csv` filtered on `Flags` = `ReportOnlyWouldImpactUsers`, then `ca-reportonly-impact.csv` for that policy: the people and apps to deal with (exclusion, registration, device fix) before enforcing. Then `no-enforced-policy-signins.csv`, sorted with Tier 0 and privileged users first.

Common parameters (`-OutputRoot`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ca-policy-results.csv` | Policy | `State`, `SignInsEvaluated`, one column per result, `UsersWouldBeBlocked`, `UsersWouldBeInterrupted`, `UsersBlocked`, `TopAppsAffected`, `Flags` (ReportOnlyWouldImpactUsers, ReportOnlyNoSignInsEvaluated, EnforcedBlocking, PolicyNotInCurrentList, SignInsTruncated, SignInSlicesNotRead) |
| `ca-reportonly-impact.csv` | Policy + user + app + result | `Result`, `Meaning`, `UserPrincipalName`, `AppDisplayName`, `ClientAppUsed`, `SignInType`, `SignIns`, `FirstSeenUtc`, `LastSeenUtc`, `PrincipalType`, `PrincipalId`, `IsPrivileged`, `IsTier0` |
| `no-enforced-policy-signins.csv` | User (or service principal) + app | `SignIns`, `NoPolicyEvaluated`, `ReportOnlyWouldBlock`, `ReportOnlyWouldInterrupt`, `ClientApps`, `SignInTypes`, `FirstSeenUtc`, `LastSeenUtc`, `IsPrivileged`, `IsTier0` |

**Reading it:**
- Report-only results only come back when the request asks for them (`Prefer: include-unknown-enum-members`); the script always does.
- If *Sign-ins carrying Conditional Access results* is 0 while sign-ins were read, the run account can't read Conditional Access: results are left out of the logs for it, and the impact and gap files are marked Blocked rather than empty.
- *ReportOnlyNoSignInsEvaluated* means the policy's conditions never matched in the window. Widen the window before concluding it's safe.
- **Slices:** sign-ins are read one slice at a time (`-SignInSliceHours`), newest slice first. If a slice still fails after retries, the other slices are kept, the datasets are marked Partial, `Flags` shows `SignInSlicesNotRead` and the notes and the *Sign-in slices not read* summary row list the missing windows (UTC). If every slice fails, the datasets are Blocked as before.
- **Truncation:** Graph returns the newest sign-ins first, and slices are read newest first. When a read stops at `-MaxSignInRecords`, the summary rows *Earliest sign-in read* and *Sign-in window covered (days)* and the dataset notes give the window actually covered; the datasets are marked Partial.
- `no-enforced-policy-signins.csv` counts successful sign-ins (error code 0) where every policy result was not applied, disabled or report-only. `NoPolicyEvaluated` counts sign-ins that carried no policy result at all. A privileged user here signs in with no enforced control.
- For service principal sign-ins, `UserPrincipalName` holds the service principal name and `AppDisplayName` the resource it called.
- Sign-ins are reduced to the fields used here as each page is read (the sign-in list API does not document `$select`).

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader or Security Reader | Policy.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, Directory.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup | | Graph Auth |

Sign-in logs need Entra ID P1; eligible roles and PIM for Groups need Entra ID P2. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: one report-only policy's results match **Entra > Conditional Access > Insights and reporting** (or a sign-in's **Report-only** tab) for the same user and day.

Usually tuned on first run: `-SignInLookbackDays`, `-MaxSignInRecords`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 24: `ca-reportonly-impact` EvidenceUnavailable | No Entra ID P1, or no sign-in log access | Record as a finding, or use a Reports Reader / Global Reader account |
| Script 24: no Conditional Access results in sign-ins | Account can't read Conditional Access | Global Reader / Security Reader, or `Policy.Read.All` |
| Script 24: TRUNCATED | Hit `-MaxSignInRecords` | Shorter lookback or a higher cap; read *Sign-in window covered (days)* |
| Script 24: Partial, `SignInSlicesNotRead` | Graph kept timing out for those windows after 6 retries | Rerun, or use a smaller `-SignInSliceHours` |
| Script 24: `IsPrivileged` blank | Role assignments not readable | RoleManagement.Read.Directory, or `-SkipPrivilegeJoin` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 23 AD attribute population](23-ad-attribute-population.md) · [All scripts](README.md) · [25 Purview classification and DLP →](25-purview-classification.md)
