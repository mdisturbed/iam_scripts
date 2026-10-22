# 06 - JML timing

**Script:** [`06-Compare-JmlTiming.ps1`](../../scripts/06-Compare-JmlTiming.ps1) · **Version:** 1.1.0 · **Source:** AD + HR file (+ Entra)

> How quickly are joiners provisioned and leavers disabled, and which leavers and their admin accounts still hold access?

Compares HR lifecycle dates with account state to show how well joiners, movers and leavers are processed, down to the leaver's secondary (admin / service / test) accounts, group memberships and licences.

**Collects:** joiner lag (account created vs hire date); leaver lag (disabled vs termination date); terminated-but-enabled; terminated, disabled but still in groups; terminated and still licensed (Entra); logon or sign-in after termination; rehires (hire date after termination date, treated as active); active HR records with no account; enabled accounts with no HR match; admin / service / test accounts linked to their owner, with enabled accounts whose owner has left; optional mover mismatches (department, title, manager); optional cloud-only Entra member users with no HR record; median, 90th percentile and maximum lags.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-HrCsvPath` | required | HR export ([template](../../examples/hr.example.csv)) |
| `-HrIdColumn`, `-HrStatusColumn`, `-HrHireDateColumn`, `-HrTermDateColumn` | `EmployeeId`, `EmploymentStatus`, `HireDate`, `TerminationDate` | Map the export's column names |
| `-HrUpnColumn`, `-HrMailColumn` | `UserPrincipalName`, `Email` | HR columns used for fallback matching; ignored if the file doesn't have them |
| `-HrDepartmentColumn`, `-HrTitleColumn`, `-HrManagerColumn` | (none) | Turn on the mover check. The manager column can hold the manager's HR id, UPN, mail or sAMAccountName |
| `-HrDateFormat` | invariant parse | e.g. `'MM/dd/yyyy'` |
| `-TerminatedStatusValues` | `Terminated`, `Inactive` | Status values that mean "left" |
| `-AdMatchAttribute` | `employeeID` | AD attribute holding the HR id |
| `-FallbackMatch` | `userPrincipalName`, `mail` | AD attributes matched against the HR UPN / mail when `-AdMatchAttribute` is blank on the account; `@()` turns it off |
| `-ExcludeNamePatterns` | `svc*`, `sa-*`, `sa_*`, `adm*`, `*admin*`, `test*` | Secondary accounts: kept out of the orphan list and reported in `secondary-accounts.csv` instead |
| `-OwnerLinkAttribute` | (none) | AD attribute on secondary accounts that names the owner (HR id, sAMAccountName, UPN or DN), e.g. `extensionAttribute7` |
| `-AnchorAttribute` | `objectGUID` | Entra Connect source anchor for the Entra join; `mS-DS-ConsistencyGuid` falls back to `objectGUID` when empty, as Entra Connect does |
| `-LeaverSlaDays` | `1` | Allowed days between termination and disable |
| `-SkipDisableTimestamp` | off | Skip the per-account replication metadata read (faster; no leaver lag) |
| `-IncludeEntraSignIn` | off | Add Entra sign-in after termination, licences, session revocation time and cloud-only users |

**Open first:** `summary.csv`, then `jml-terminated-still-enabled.csv` and `secondary-accounts.csv` filtered on `OwnerTerminatedSecondaryEnabled`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `jml-matched.csv` | AD account matched to an HR record | `CreateLagDays`, `DisableLagDays`, `ADLastLogonUtc`, `EntraLastSignInUtc`, `Flags`, `HrRehire`, `MatchMethod`, `MemberOfCount`, `AdminCount`, `AssignedLicenseCount`, `SignInSessionsValidFromUtc`, `LastNonInteractiveSignInUtc` |
| `jml-terminated-still-enabled.csv` | Terminated person with an enabled account | |
| `jml-activity-after-termination.csv` | Logon or sign-in more than a day after termination | |
| `jml-hr-active-no-account.csv` | Active HR record with no AD account | |
| `jml-ad-orphan-candidates.csv` | Enabled AD account with no HR match | `Reason` |
| `secondary-accounts.csv` | Account matching `-ExcludeNamePatterns` | `MatchedPattern`, `LinkedOwner` (HR id), `OwnerSamAccountName`, `LinkMethod`, `OwnerHrStatus`, `OwnerTerminated`, `LastLogonUtc`, `Flags` (OwnerTerminatedSecondaryEnabled, NoOwnerLink, AdminCount) |
| `mover-mismatches.csv` | HR vs AD difference for an active person (mover columns set) | `Attribute` (Department / Title / Manager), `HrValue`, `AdValue` |
| `cloud-only-users-not-in-hr.csv` | Entra member user not synced from AD and not in HR (`-IncludeEntraSignIn`) | `EmployeeId`, `AccountEnabled`, `LastSignInUtc`, `AssignedLicenseCount` |

`jml-matched.csv` flags: `TerminatedButEnabled`, `ADLogonAfterTermination`, `EntraSignInAfterTermination`, `DisabledAfterSLA(nd)`, `ActiveInHrButDisabled`, `MultipleAccountsSameHrId`, `DisabledButStillInGroups`, `TerminatedStillLicensed`, `HrRehire`.

**Reading it:**
- A person counts as terminated when the status is in `-TerminatedStatusValues`, or the termination date has passed and no later hire date follows it. A rehire (hire date after termination date) is active.
- `MatchMethod` is `employeeID` (or your `-AdMatchAttribute`) or `Fallback:<attribute>` when the account had no HR id and matched on UPN / mail. Fallback matches are worth a look: the HR id should be populated.
- Secondary accounts are linked to an owner in this order: the account's own HR id, `-OwnerLinkAttribute`, the name stem (`adm-jsmith` → `jsmith`), then `manager`. A `manager` link is the weakest: it is often the line manager, not the owner.
- `DisabledButStillInGroups` and `TerminatedStillLicensed` matter because re-enabling the account restores the access, and licences keep mailbox and OneDrive data reachable.
- `EntraLastSignInUtc` uses the last successful sign-in when Entra reports it; otherwise the newer of interactive and non-interactive. Entra's `lastSignInDateTime` alone also counts failed attempts.

**Caveats:** disable time is approximated from the last change to `userAccountControl`, so it can be later than the real disable. When the replication metadata can't be read, the count of affected accounts is in the summary and the `jml-matched` note, and their `DisableLagDays` is blank. `lastLogonTimestamp` replicates on a 9-14 day cycle, so AD logon-after-termination is indicative; the Entra sign-in check is more precise.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| (Global Reader with `-IncludeEntraSignIn`) | (User.Read.All, AuditLog.Read.All) | Domain read; read of replication metadata | RSAT AD (+ Graph Auth) |

Brackets mean only with the matching optional switch. `signInActivity` needs Entra ID P1; without it licences, session revocation time and cloud-only users are still reported and `entra-signin-check` shows `EvidenceUnavailable`. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One recent leaver: termination date in HR vs account disable date in AD, and that leaver's admin account (if any) appears in `secondary-accounts.csv` linked to them.

Usually tuned on first run: Service / admin account name patterns (`-ExcludeNamePatterns`), `-OwnerLinkAttribute`; HR column names, `-HrDateFormat`, `-TerminatedStatusValues`, `-AdMatchAttribute`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 06: `HR file has no column ...` | Column names differ (including the mover columns you passed) | Map with `-HrIdColumn`, `-HrDepartmentColumn` and so on |
| Script 06: date values failed to parse | Date format not recognized | Set `-HrDateFormat` |
| Script 06: `fallback matching ... is off` in run.log | The HR file has no UPN or mail column | Map them with `-HrUpnColumn` / `-HrMailColumn`, or ignore |
| Script 06: `Replication metadata unreadable` | No rights to read replication metadata, or a DC not reachable | Run with domain read on a reachable DC; the affected count is in the summary |
| Script 06: `entra-signin-check` is `EvidenceUnavailable` | No Entra ID P1 or AuditLog.Read.All | Sign-in after termination can't be checked; the rest of the Entra columns are still filled |
| Script 06: many `NoOwnerLink` secondary accounts | No naming convention or owner attribute | Set `-OwnerLinkAttribute`, or adjust `-ExcludeNamePatterns` so the name stem works |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 05 AD group nesting](05-ad-group-nesting.md) · [All scripts](README.md) · [07 Role mining →](07-role-mining.md)
