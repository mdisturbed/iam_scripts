# 24 - CA report-only impact

**Script:** [`24-Get-CaReportOnlyImpact.ps1`](../../scripts/24-Get-CaReportOnlyImpact.ps1) · **Version:** 1.0.0 · **Source:** Entra sign-in logs

> What does each Conditional Access policy do to real sign-ins, and who would a report-only policy block or challenge if it were switched on?

Staged enforcement means running a policy in report-only mode first. Entra records, on every sign-in, what every policy did or *would* have done; this script turns that into a per-policy impact list so a policy can be switched on knowing exactly who it affects.

**Collects:** every Conditional Access policy and its state; for a lookback window of sign-ins, per policy: sign-ins evaluated and the count of every result (`success`, `failure`, `notApplied`, `reportOnlySuccess`, `reportOnlyFailure` = would block, `reportOnlyInterrupted` = would need an extra step such as MFA, `reportOnlyNotApplied`), distinct users that would be blocked or interrupted, top apps involved; and one row per policy, user and app for every would-block / would-interrupt (and every enforced block). Policies seen in sign-ins but no longer present are reported as *deleted or not readable*.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SignInLookbackDays` | `14` | Days of sign-ins (1-30); 14-30 is usual before enforcing |
| `-MaxSignInRecords` | `100000` | Safety cap per query; output marked TRUNCATED if reached |
| `-ReportOnlyPoliciesOnly` | off | Keep results for report-only policies only |
| `-IncludeNonInteractive` | off | Add non-interactive sign-ins (beta endpoint; much larger) |
| `-TopAppCount` | `5` | Apps listed per policy |

**Open first:** `ca-policy-results.csv` filtered on `Flags` = `ReportOnlyWouldImpactUsers`, then `ca-reportonly-impact.csv` for that policy: the people and apps to deal with (exclusion, registration, device fix) before enforcing.

Common parameters (`-OutputRoot`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ca-policy-results.csv` | Policy | `State`, `SignInsEvaluated`, one column per result, `UsersWouldBeBlocked`, `UsersWouldBeInterrupted`, `UsersBlocked`, `TopAppsAffected`, `Flags` (ReportOnlyWouldImpactUsers, ReportOnlyNoSignInsEvaluated, EnforcedBlocking, PolicyNotInCurrentList) |
| `ca-reportonly-impact.csv` | Policy + user + app + result | `Result`, `Meaning`, `UserPrincipalName`, `AppDisplayName`, `ClientAppUsed`, `SignInType`, `SignIns`, `FirstSeenUtc`, `LastSeenUtc` |

**Reading it:**
- Report-only results only come back when the request asks for them (`Prefer: include-unknown-enum-members`); the script always does.
- If *Sign-ins carrying Conditional Access results* is 0 while sign-ins were read, the run account can't read Conditional Access: results are left out of the logs for it.
- *ReportOnlyNoSignInsEvaluated* means the policy's conditions never matched in the window. Widen the window before concluding it's safe.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader or Security Reader | Policy.Read.All, AuditLog.Read.All | | Graph Auth |

Sign-in logs need Entra ID P1. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: one report-only policy's results match **Entra > Conditional Access > Insights and reporting** (or a sign-in's **Report-only** tab) for the same user and day.

Usually tuned on first run: `-SignInLookbackDays`, `-MaxSignInRecords`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 24: `ca-reportonly-impact` EvidenceUnavailable | No Entra ID P1, or no sign-in log access | Record as a finding, or use a Reports Reader / Global Reader account |
| Script 24: no Conditional Access results in sign-ins | Account can't read Conditional Access | Global Reader / Security Reader, or `Policy.Read.All` |
| Script 24: TRUNCATED | Hit `-MaxSignInRecords` | Shorter lookback or a higher cap |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 23 AD attribute population](23-ad-attribute-population.md) · [All scripts](README.md) · [25 Purview classification and DLP →](25-purview-classification.md)
