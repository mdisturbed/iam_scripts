# 06 - JML timing

**Script:** [`06-Compare-JmlTiming.ps1`](../../scripts/06-Compare-JmlTiming.ps1) · **Version:** 1.0.1 · **Source:** AD + HR file (+ Entra)

> How quickly are joiners provisioned and leavers disabled, compared with HR?

Compares HR lifecycle dates with account state to show how well joiners and leavers are processed.

**Collects:** joiner lag (account created vs hire date); leaver lag (disabled vs termination date); terminated-but-enabled; logon or sign-in after termination; active HR records with no account; enabled accounts with no HR match; median, 90th percentile and maximum lags.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-HrCsvPath` | required | HR export ([template](../../examples/hr.example.csv)) |
| `-HrIdColumn`, `-HrStatusColumn`, `-HrHireDateColumn`, `-HrTermDateColumn` | `EmployeeId`, `EmploymentStatus`, `HireDate`, `TerminationDate` | Map the export's column names |
| `-HrDateFormat` | invariant parse | e.g. `'MM/dd/yyyy'` |
| `-TerminatedStatusValues` | `Terminated`, `Inactive` | Status values that mean "left" |
| `-AdMatchAttribute` | `employeeID` | AD attribute holding the HR id |
| `-LeaverSlaDays` | `1` | Allowed days between termination and disable |
| `-IncludeEntraSignIn` | off | Add Entra sign-in after termination |

**Open first:** `summary.csv`, then `jml-terminated-still-enabled.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `jml-matched.csv` | AD account matched to an HR record | `CreateLagDays`, `DisableLagDays`, `ADLastLogonUtc`, `EntraLastSignInUtc`, `Flags` |
| `jml-terminated-still-enabled.csv` | Terminated person with an enabled account | |
| `jml-activity-after-termination.csv` | Logon or sign-in more than a day after termination | |
| `jml-hr-active-no-account.csv` | Active HR record with no AD account | |
| `jml-ad-orphan-candidates.csv` | Enabled AD account with no HR match | `Reason` |

**Caveats:** disable time is approximated from the last change to `userAccountControl`, so it can be later than the real disable. `lastLogonTimestamp` replicates on a 9-14 day cycle, so AD logon-after-termination is indicative; the Entra sign-in check is more precise.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| (Global Reader with `-IncludeEntraSignIn`) | (User.Read.All, AuditLog.Read.All) | Domain read; read of replication metadata | RSAT AD (+ Graph Auth) |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One recent leaver: termination date in HR vs account disable date in AD.

Usually tuned on first run: Service / admin account name patterns (`-ServiceNamePatterns`, `-ExcludeNamePatterns`); HR column names, `-HrDateFormat`, `-TerminatedStatusValues`, `-AdMatchAttribute`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 06: `HR file has no column ...` | Column names differ | Map with `-HrIdColumn` and so on |
| Script 06: date values failed to parse | Date format not recognized | Set `-HrDateFormat` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 05 AD group nesting](05-ad-group-nesting.md) · [All scripts](README.md) · [07 Role mining →](07-role-mining.md)
