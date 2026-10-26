# 29 - Pilot outcome

**Script:** [`29-Test-PilotOutcome.ps1`](../../scripts/29-Test-PilotOutcome.ps1) · **Version:** 1.0.0 · **Source:** Entra sign-in logs + test-case file

> Did each pilot test case (expected and adverse) produce the result it should, and is there sign-in evidence to prove it?

Pilot test evidence and rollback validation for MFA and Conditional Access changes. Each test case says who signs in, to which app, which policy should do what, and whether the sign-in should succeed. The script finds the real sign-in and records Pass or Fail with the sign-in's correlation ID and request ID as proof. Run it once the test users have done their sign-ins, and again after a rollback with the post-rollback cases.

**Collects:** for each test user, their sign-ins since the earliest `NotBeforeUtc` of their cases (or the `-LookbackHours` window). For each test case: the matching sign-ins, the policy's result and the sign-in outcome on the one evaluated, and Pass / Fail / NoEvidence / Blocked. Also every sign-in used as evidence (no IP address, location or device details). Optionally: each test user's pilot group membership checked against the file, and users outside the pilot group on whom a pilot policy was enforced.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-TestCaseCsv` | required | The test cases ([template](../../examples/pilot-test-cases.example.csv)) |
| `-LookbackHours` | `72` | Window start for cases with no `NotBeforeUtc`, and for `-CheckScopeLeak` (1-720) |
| `-MaxSignInsPerUser` | `5000` | Safety cap per test user; the case `Note` says TRUNCATED if reached |
| `-IncludeNonInteractive` | off | Add the test users' non-interactive sign-ins (beta endpoint) |
| `-EvaluateAll` | off | Pass only if every matching sign-in meets the expectation (default: the latest one) |
| `-PilotGroupId` | none | Pilot group object ID; adds `pilot-scope-check.csv` |
| `-PolicyIds` | the `PolicyId` values in the file | Policies checked by `-CheckScopeLeak` |
| `-CheckScopeLeak` | off | Read every interactive sign-in in the window and list users outside the pilot group on whom a listed policy was enforced. Needs `-PilotGroupId` |
| `-MaxSignInRecords` | `100000` | Safety cap for the `-CheckScopeLeak` read; marked TRUNCATED if reached |

**Open first:** `summary.csv` (*All test cases passed*), then `pilot-test-results.csv` filtered on `Outcome` not `Pass`: the `Note` says what was expected and what happened. Then `pilot-scope-leak.csv`, if run. Anyone listed there is outside the pilot but already affected.

Common parameters (`-OutputRoot`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Test-case file

| Column | Values | Meaning |
|--------|--------|---------|
| `TestId` | unique text | Case ID used in every output |
| `CaseType` | `Expected` / `Adverse` | Expected: the change should do this. Adverse: the change must not do this, or must block this |
| `Description` | text | What the tester does |
| `UserPrincipalName` | UPN | Test user |
| `App` | app display name, appId, or `*` | Matched case-insensitively; `*` or blank = any app |
| `PolicyId`, `PolicyName` | policy ID and/or name | The policy whose result is checked; looked up by `PolicyId` when given, else by `PolicyName` |
| `ExpectedPolicyResult` | `success`, `failure`, `notApplied`, `notEnabled`, `reportOnlySuccess`, `reportOnlyFailure`, `reportOnlyInterrupted`, `reportOnlyNotApplied`, or blank | The policy's result on the sign-in. Blank = only the sign-in outcome is checked |
| `ExpectedSignIn` | `Success` / `Failure` / `Any` | Success = error code 0; Failure = any other error code; blank = Any |
| `NotBeforeUtc` | ISO 8601 UTC, or blank | Only sign-ins at or after this time count. Blank = `-LookbackHours` before the run. For rollback cases, set it to the rollback time |
| `InPilotExpected` | `True` / `False` / blank (optional column) | Whether the user should be in the pilot group; checked only with `-PilotGroupId` |

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `pilot-test-results.csv` | Test case | `TestId`, `CaseType`, `Description`, `UserPrincipalName`, `App`, `Policy`, `ExpectedPolicyResult`, `ObservedPolicyResult`, `ExpectedSignIn`, `ObservedSignIn`, `Outcome` (Pass / Fail / NoEvidence / Blocked), `SignInsMatched`, `EvidenceSignInTimeUtc`, `CorrelationId`, `RequestId`, `ErrorCode`, `FailureReason`, `Note` |
| `pilot-signin-evidence.csv` | Sign-in evaluated for a case | `TestId`, `CaseType`, `CreatedUtc`, `UserPrincipalName`, `AppDisplayName`, `AppId`, `ClientAppUsed`, `SignInType`, `ErrorCode`, `FailureReason`, `ConditionalAccessStatus`, `PolicyResult`, `AuthenticationRequirement`, `MetExpectation`, `CorrelationId`, `RequestId` |
| `pilot-scope-check.csv` | Test case | `TestId`, `CaseType`, `Description`, `UserPrincipalName`, `InPilotGroup`, `InPilotExpected`, `Check` (Match / Mismatch / NotChecked), `Flags` |
| `pilot-scope-leak.csv` | User outside the pilot + policy | `UserPrincipalName`, `PolicyName`, `PolicyState`, `Results`, `SignIns`, `Apps`, `FirstSeenUtc`, `LastSeenUtc`, `UserId`, `PolicyId` |

Flags: `CaseTypeConflict` (the test user's pilot group membership differs from `InPilotExpected`. For example, an Expected case user who isn't in the pilot group, or an "outside the pilot" Adverse case user who is).

**Reading it:**
- **Which sign-in counts.** Only sign-ins by the same user, to the matching app, at or after `NotBeforeUtc` are considered. By default the **latest** of these is evaluated, because that reflects the configuration in force now. With `-EvaluateAll`, a case passes only if every matching sign-in meets the expectation. The row then shows the first one that didn't, and the `Note` gives the count.
- **Outcome.** `Pass`: the evaluated sign-in meets both the policy result and the sign-in expectation. `Fail`: it doesn't, and the `Note` says which. `NoEvidence`: no matching sign-in in the window, so the test hasn't been done yet, or the app name or time is wrong. `Blocked`: the evidence couldn't be read (sign-ins 403 or licence, or no Conditional Access results), or the test case itself is invalid. A Blocked case is never counted as failed.
- **notInSignIn.** If the policy isn't listed in the sign-in's Conditional Access results, the observed result is `notInSignIn`. It counts as `notApplied` when the case expects `notApplied`, and as a mismatch for any other expectation.
- **No Conditional Access results.** These are only returned to accounts that can read Conditional Access. If none of the sign-ins read carry them, every case with an `ExpectedPolicyResult` is Blocked, not Fail. Cases that check only the sign-in outcome are still evaluated.
- **Report-only results** (`reportOnly*`) are only returned with `Prefer: include-unknown-enum-members`; the script always sends it. A report-only pilot is tested by expecting `reportOnlySuccess`, `reportOnlyInterrupted` (would prompt) or `reportOnlyFailure` (would block).
- **Evidence IDs.** `RequestId` is the sign-in's `id` (the Request ID shown in the Entra sign-in log) and `CorrelationId` is the client's correlation ID. Either one finds the sign-in in the portal.
- **Personal data.** Only what the proof needs is kept: no IP address, location or device names.
- **All test cases passed** is `True` only when every case passed, `False` when any case failed, and blank when no case failed but some have no evidence or are blocked.
- **Rollback validation.** Write the post-rollback cases with `NotBeforeUtc` set to the rollback time (for example, a pilot user expecting `notApplied`), have the testers sign in again, then run the script. Pair it with a [28 CA policy snapshot](28-ca-policy-snapshot.md) compared with the pre-change baseline.
- **Scope leak** reads every interactive sign-in in the window, so it can be large. A user listed there isn't in the pilot group (transitive membership), yet a pilot policy had an enforced result (`success` or `failure`) on their sign-in. The usual cause is a policy scoped wider than the pilot group.
- A UPN with an apostrophe is escaped (`''`) in the sign-in filter.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader or Security Reader (Reports Reader for sign-ins) | AuditLog.Read.All, Policy.Read.All, Directory.Read.All; GroupMember.Read.All for `-PilotGroupId` | The test-case file | Graph Auth |

Sign-in logs need Entra ID P1. Without it, results are EvidenceUnavailable. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm one Pass case: its `RequestId` should open the same sign-in in **Entra > Sign-in logs**, and the policy result there should match `ObservedPolicyResult`.

Usually tuned on first run: `App` values (use the app name as it appears in the sign-in log, or the appId), `NotBeforeUtc`, `-LookbackHours`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 29: `Test-case file is missing column(s)` | Header differs from the template | Use the [template](../../examples/pilot-test-cases.example.csv) headers |
| Script 29: case Blocked, *Invalid test case* | A value isn't one of the allowed values | Fix the value named in `Note` |
| Script 29: NoEvidence | The tester hasn't signed in yet, the app name differs, or `NotBeforeUtc` is too late | Check the sign-in log for the user; use the appId in `App` |
| Script 29: Blocked, *No Conditional Access results* | Account can't read Conditional Access | Global Reader / Security Reader, or `Policy.Read.All` |
| Script 29: results EvidenceUnavailable | No Entra ID P1 | Record as a finding |
| Script 29: `pilot-scope-leak` Blocked | No `-PilotGroupId`, or pilot group not readable | Pass `-PilotGroupId`; add GroupMember.Read.All |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 28 CA policy snapshot](28-ca-policy-snapshot.md) · [All scripts](README.md) · [30 Access review evidence →](30-access-review-evidence.md)
