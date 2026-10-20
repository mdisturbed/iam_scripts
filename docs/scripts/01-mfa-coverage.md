# 01 - MFA coverage

**Script:** [`01-Get-MfaCoverage.ps1`](../../scripts/01-Get-MfaCoverage.ps1) · **Version:** 1.0.1 · **Source:** Entra

> Is MFA actually enforced everywhere, or only registered?

Measures whether MFA is actually enforced, not just registered.

**Collects:** every Conditional Access policy flattened with names resolved; one row per exclusion and the transitive members of excluded groups; MFA registration for every user (registered vs capable, SMS/voice, phone-only); successful single-factor sign-ins over a lookback window, with legacy authentication flagged.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SignInLookbackDays` | `7` | Days of sign-in logs to read (1-30) |
| `-MaxSignInRecords` | `50000` | Safety cap; output marked TRUNCATED if reached |
| `-SkipSignIns` | off | Skip the sign-in query |
| `-SkipExcludedGroupMembers` | off | Skip expanding excluded groups |

**Open first:** `summary.csv`, then `ca-exclusions.csv` and `signins-singlefactor-success.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ca-policies.csv` | CA policy | `State`, `RequiresMfa`, `BlocksLegacyAuth`, include/exclude scope resolved to names, `ClientAppTypes`, `SessionControls` |
| `ca-exclusions.csv` | Exclusion on a policy | `PolicyName`, `ExclusionType` (User/Group/Role/GuestOrExternal), `DisplayName` |
| `ca-excluded-group-members.csv` | Member of an excluded group (transitive) | `GroupName`, `ExcludedFromPolicies`, `MemberUPN`, `AccountEnabled` |
| `mfa-registration.csv` | User | `IsMfaRegistered`, `IsMfaCapable`, `MethodsRegistered`, `HasSmsOrVoice`, `HasPhoneMethodOnly`, `IsAdmin` |
| `signins-singlefactor-success.csv` | User + app + client | `IsLegacyAuth`, `SignInCount`, first/last seen, `CaStatuses` |

**Reading it:** registered is not the same as enforced. A user can be registered and still sign in with a password if no enabled policy requires MFA for that sign-in; the single-factor file shows where that actually happened.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | Policy.Read.All, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Number of CA policies and their states in the Entra portal; one known exclusion group appears in `ca-exclusions.csv`.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 01 note says TRUNCATED | Hit `-MaxSignInRecords` | Shorter lookback or higher cap |

General issues: [troubleshooting](../troubleshooting.md).

---

[All scripts](README.md) · [02 Entra privileged access →](02-entra-privileged-access.md)
