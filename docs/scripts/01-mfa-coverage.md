# 01 - MFA coverage

**Script:** [`01-Get-MfaCoverage.ps1`](../../scripts/01-Get-MfaCoverage.ps1) · **Version:** 1.1.2 · **Source:** Entra

> Is MFA actually enforced everywhere, how strong is it, and who is left out?

Measures whether MFA is actually enforced, not just registered, how strong the registered methods are, and which real accounts fall outside Conditional Access.

**Collects:**
- Every Conditional Access policy flattened, with users, groups, roles, apps, named locations, authentication strength combinations, authentication flows and device filters resolved.
- One row per exclusion, the transitive members of excluded groups, and the accounts that hold excluded roles (from the effective privileged set: direct, group, eligible, PIM for Groups, group owners).
- MFA registration for every user (registered vs capable, method strength, phishing-resistant, SMS/voice, phone-only, email-only), joined to account enabled / synced state and to privilege (`IsPrivileged`, `IsTier0`).
- The authentication methods policy (which methods are on and for whom), the registration campaign, policy migration state and security defaults.
- Successful single-factor sign-ins over a lookback window, with legacy authentication flagged (read from the beta sign-in endpoint, because `authenticationRequirement` exists only there); optionally non-interactive single-factor sign-ins.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SignInLookbackDays` | `7` | Days of sign-in logs to read (1-30) |
| `-MaxSignInRecords` | `50000` | Safety cap per sign-in query, counted across all slices; output marked TRUNCATED if reached |
| `-SignInSliceHours` | `24` | Hours of sign-ins read per Graph query (1-168). Use a smaller slice if a large tenant still times out |
| `-SkipSignIns` | off | Skip the interactive sign-in query |
| `-SkipExcludedGroupMembers` | off | Skip expanding excluded groups |
| `-SkipPrivilegeJoin` | off | Skip building the privileged set (no `IsPrivileged` / `IsTier0`, no excluded role holders) |
| `-IncludeNonInteractive` | off | Also read non-interactive single-factor sign-ins (beta endpoint; high volume, keep the lookback short) |

**Open first:** `summary.csv`, then `ca-exclusions.csv`, `ca-excluded-role-holders.csv` and `signins-singlefactor-success.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ca-policies.csv` | CA policy | `State`, `RequiresMfa`, `BlocksLegacyAuth`, include/exclude scope resolved to names, `ClientAppTypes`, `SessionControls`, `IncludeLocationNames`, `ExcludeLocationNames`, `AuthenticationFlows`, `DeviceFilter`, `AuthStrengthCombinations`, `AuthContexts` |
| `ca-exclusions.csv` | Exclusion on a policy | `PolicyName`, `ExclusionType` (User/Group/Role/GuestOrExternal), `DisplayName` |
| `ca-excluded-group-members.csv` | Member of an excluded group (transitive) | `GroupName`, `ExcludedFromPolicies`, `MemberUPN`, `AccountEnabled` |
| `ca-excluded-role-holders.csv` | Holder of a role excluded from a policy | `PolicyName`, `RoleName`, `Upn`, `AssignmentState`, `Via`, `ViaGroup`, `EffectiveForCa` |
| `mfa-registration.csv` | User | `IsMfaRegistered`, `IsMfaCapable`, `MethodsRegistered`, `HasSmsOrVoice`, `HasPhoneMethodOnly`, `IsAdmin`, `PhishResistant`, `MethodStrength`, `IsPrivileged`, `IsTier0`, `AccountEnabled`, `OnPremisesSynced` |
| `auth-methods-policy.csv` | Method configuration, campaign, migration state, security defaults | `Section`, `Id`, `State`, `IncludeTargets`, `ExcludeTargets`, `Flags` |
| `signins-singlefactor-success.csv` | User + app + client | `IsLegacyAuth`, `SignInCount`, first/last seen, `CaStatuses` |
| `signins-noninteractive-singlefactor.csv` | User + app + resource + client (only with `-IncludeNonInteractive`) | `SignInCount`, first/last seen, `IsPrivileged` |

**Reading it:**
- Registered is not the same as enforced. A user can be registered and still sign in with a password if no enabled policy requires MFA for that sign-in; the single-factor files show where that actually happened.
- `MethodStrength` is the strongest registered method: `PhishResistant` (FIDO2, passkey, Windows Hello, certificate), `Authenticator` (app or OTP), `PhoneOnly` (SMS/voice), `EmailOnly`, `None`. `HasPhoneMethodOnly` is true only when SMS/voice is the strongest method; email-only users are counted separately.
- Filter `mfa-registration.csv` on `AccountEnabled` to leave disabled accounts out of coverage percentages.
- In `ca-excluded-role-holders.csv`, `EffectiveForCa` is true for active or activated holders (direct or through a role-assignable group). Eligible holders become excluded when they activate; group owners are listed because they can add themselves.
- Sign-ins are read one slice at a time (`-SignInSliceHours`), newest first, so no single query spans the whole lookback. If a slice still fails after retries, the other slices are kept and the dataset is `Partial`; the note lists the missing windows (UTC). If every slice fails, the dataset is `Blocked` as before.
- `auth-methods-policy.csv` flags `SmsEnabled`, `VoiceEnabled`, `SmsSignInEnabled`, `LegacyMethodSettingsStillApply` and `RegistrationCampaignOff`.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | Policy.Read.All, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup (not with `-SkipPrivilegeJoin`) | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Number of CA policies and their states in the Entra portal; one known exclusion group appears in `ca-exclusions.csv`; the SMS and Authenticator states in Entra > Authentication methods > Policies match `auth-methods-policy.csv`.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 01 note says TRUNCATED | Hit `-MaxSignInRecords` | Shorter lookback or higher cap |
| Sign-in dataset `Partial`, note lists slices not read | Graph kept timing out for those windows after 6 retries | Rerun, or use a smaller `-SignInSliceHours` |
| `ca-excluded-group-members` / `ca-excluded-role-holders` `Blocked` | CA policies could not be read, so exclusions are unknown (not "none") | Grant Policy.Read.All |
| `mfa-registration` `Partial` | Privileged set or user list incomplete; the note names the source | Blank `IsPrivileged` / `AccountEnabled` cells are unknown, not false |
| `auth-methods-policy` `Partial` or `Blocked` | Methods policy or security defaults not readable | Grant Policy.Read.All |

General issues: [troubleshooting](../troubleshooting.md).

---

[All scripts](README.md) · [02 Entra privileged access →](02-entra-privileged-access.md)
