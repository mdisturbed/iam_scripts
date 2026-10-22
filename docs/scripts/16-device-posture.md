# 16 - Device posture

**Script:** [`16-Get-DevicePosture.ps1`](../../scripts/16-Get-DevicePosture.ps1) · **Version:** 1.1.0 · **Source:** Entra + Intune

> Are devices joined, managed, compliant and backed up (LAPS / BitLocker), who can join them, and which accounts does device-based Conditional Access actually exempt?

Zero Trust device controls only work if devices are registered, managed and evaluated, and only for the accounts they are not excluded from.

**Collects:**
- **Entra device objects:** join type (Entra joined, hybrid joined, registered), ownership, management and enrollment type, managed, compliant and last sign-in, with flags for stale, unmanaged, non-compliant, personal and duplicate-name devices; with `-IncludeDeviceOwners`, registered owners and users.
- **Device registration policy:** who can join and register devices, MFA to join, the per-user device quota, whether the joining user becomes local admin, and whether Windows LAPS is switched on.
- **LAPS and BitLocker backup coverage:** how many enabled Entra-joined and hybrid-joined Windows devices have a backed-up LAPS password and a BitLocker recovery key in Entra. Metadata only: no password or key is ever requested.
- **Intune managed devices:** compliance state, last check-in, encryption, jailbreak status, ownership, serial number and model, enrollment type, reported threat state, and whether each has a matching Entra object.
- **Compliance policies:** each policy with its include and exclude assignments (exclusions do not count as assigned), the grace period before a device is marked non-compliant, plus the tenant setting that decides whether a device with *no* policy counts as compliant.
- **Enrollment restrictions and app protection:** platform and personal-device enrollment blocks, device limits, and app protection (MAM) policies with whether they are assigned.
- **Conditional Access policies that depend on devices or apps:** those requiring a compliant or hybrid-joined device or an approved / app-protected client app, using device filters, or targeting platforms, and every account their user, group (transitive) and role exclusions exempt.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-StaleDays` | `90` | Entra devices with no sign-in in this window are flagged |
| `-CheckInStaleDays` | `30` | Intune devices not checked in for this long are flagged |
| `-SkipIntune` | off | Entra devices, registration policy, backup coverage and CA only |
| `-IncludeDeviceOwners` | off | Read registered owners and users per device (two calls per device) |
| `-SkipLapsBitLocker` | off | Skip the LAPS / BitLocker backup counts |
| `-SkipCaExclusionExpansion` | off | Don't resolve CA exclusions to accounts |

**Open first:** `summary.csv`. The "devices with no policy treated as compliant" line matters: if it's True, an unassigned device passes a require-compliant-device control. Then `device-ca-exclusions.csv`: everyone listed there is not bound by the device requirement.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `entra-devices.csv` | Entra device object | `JoinType`, `IsManaged`, `IsCompliant`, `LastSignInUtc`, `Flags` (adds PersonalDevice, DuplicateName), `DeviceOwnership`, `ProfileType`, `ManagementType`, `EnrollmentType`, `EnrollmentProfile`, `ObjectsWithSameName`, `RegisteredOwners`, `RegisteredUsers`, `HasLapsBackup`, `HasBitLockerKey` |
| `device-registration-policy.csv` | Registration setting | `Setting`, `Value`, `Note` |
| `laps-bitlocker-coverage.csv` | Backup control (LAPS, BitLocker) | `Status`, `WindowsDevices`, `DevicesWithBackup`, `CoveragePct` |
| `intune-devices.csv` | Intune managed device | `ComplianceState`, `LastCheckInUtc`, `IsEncrypted`, `HasEntraObject`, `Flags`, `SerialNumber`, `Model`, `Manufacturer`, `EnrollmentType`, `EnrollmentProfile`, `ThreatState`, `GraceExpiresUtc`, `AzureADDeviceId` |
| `compliance-policies.csv` | Compliance policy | `Platform`, `AssignmentCount` (include targets only), `Unassigned` (True / False / Unknown), `ExclusionCount`, `TargetNames`, `BlockGraceHours`, `Actions`, `AssignmentRead` |
| `enrollment-restrictions.csv` | Platform restriction or device limit | `Platform`, `PlatformBlocked`, `PersonalDeviceEnrollmentBlocked`, `OsMinimumVersion`, `DeviceLimit` |
| `app-protection-policies.csv` | App protection / app configuration policy | `PolicyType`, `Platform`, `IsAssigned`, `DeployedAppCount` |
| `ca-device-requirements.csv` | CA policy that uses device or app state | `RequiresCompliantDevice`, `RequiresHybridJoined`, `DeviceFilterRule`, `IncludePlatforms`, `State`, `RequiresApprovedApp`, `RequiresAppProtection`, `ExcludeUsers`, `ExcludeGroups`, `ExcludeRoleCount`, `ExcludePlatforms`, `ExcludedAccounts` |
| `device-ca-exclusions.csv` | Account exempted from a device / app CA policy | `Policy`, `ExclusionType` (User / Group / Role), `ExcludedObject`, `UserPrincipalName`, `AccountEnabled`, `Via`, `ResolveStatus` |

**Reading it:** a require-compliant-device policy only protects as far as devices are enrolled and evaluated. Unmanaged enabled devices can't pass it, an unassigned device passes it if the tenant treats devices with no policy as compliant, and every account in `device-ca-exclusions.csv` is outside it. `ResolveStatus` = `NotFound (deleted)` is an exclusion that points at a deleted user; `Group not expanded` or `Role holders not readable` means the exemption could not be measured (the dataset is then `Partial`).

`Unassigned` = `Unknown` on a compliance policy means its assignments could not be read; it is not reported as unassigned. A policy assigned only to exclusion groups is unassigned. `BlockGraceHours` is how long a failing device keeps passing before it is marked non-compliant.

`RegisteringUserIsLocalAdmin` = `All` in the registration policy means every user who joins a device is its local administrator. LAPS / BitLocker coverage below 100% means devices whose local admin password or recovery key is not held in Entra.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader (or Intune Read Only Operator + Global Reader) | Device.Read.All, Policy.Read.All (registration policy; Policy.Read.DeviceConfiguration also works), Directory.Read.All (CA exclusion expansion), DeviceLocalCredential.ReadBasic.All, BitlockerKey.ReadBasic.All (backup counts), DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All (Intune) | - | Graph Auth |

Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Device counts by join type vs Entra > Devices; one known non-compliant device in Intune.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 16: Intune datasets `Blocked` | No Intune read role / scope | Intune Read Only Operator, `DeviceManagementManagedDevices.Read.All` |
| `laps-bitlocker-coverage` row `EvidenceUnavailable` | Token lacks `DeviceLocalCredential.ReadBasic.All` or `BitlockerKey.ReadBasic.All` | Consent the scope (the ReadBasic scopes never expose passwords or keys) or run with `-SkipLapsBitLocker` |
| `enrollment-restrictions` / `app-protection-policies` `EvidenceUnavailable` | Token lacks `DeviceManagementServiceConfig.Read.All` / `DeviceManagementApps.Read.All` | Consent the scope |
| `compliance-policies` `Partial` | Some policy assignments unreadable | See run.log; `Unassigned` shows `Unknown` for those policies |
| `device-ca-exclusions` `Partial` | An excluded group or role could not be expanded | See `ResolveStatus`; needs Directory.Read.All |
| Run slow with `-IncludeDeviceOwners` | Two calls per device | Leave it off for large tenants |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 15 Rule-managed access](15-rule-managed-access.md) · [All scripts](README.md) · [17 AWS IAM posture →](17-aws-iam-posture.md)
