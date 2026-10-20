# 16 - Device posture

**Script:** [`16-Get-DevicePosture.ps1`](../../scripts/16-Get-DevicePosture.ps1) · **Version:** 1.0.0 · **Source:** Entra + Intune

> Are devices joined, managed and compliant, and does Conditional Access rely on it?

Zero Trust device controls only work if devices are registered, managed and evaluated.

**Collects:**
- **Entra device objects:** join type (Entra joined, hybrid joined, registered), managed, compliant and last sign-in, with flags for stale, unmanaged and non-compliant devices.
- **Intune managed devices:** compliance state, last check-in, encryption, jailbreak status, and whether each has a matching Entra object.
- **Compliance policies:** each policy and its assignments, plus the tenant setting that decides whether a device with *no* policy counts as compliant.
- **Conditional Access policies that depend on devices:** those requiring a compliant or hybrid-joined device, using device filters, or targeting platforms.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-StaleDays` | `90` | Entra devices with no sign-in in this window are flagged |
| `-CheckInStaleDays` | `30` | Intune devices not checked in for this long are flagged |
| `-SkipIntune` | off | Entra devices and CA only |

**Open first:** `summary.csv`. The "devices with no policy treated as compliant" line matters: if it's True, an unassigned device passes a require-compliant-device control.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `entra-devices.csv` | Entra device object | `JoinType`, `IsManaged`, `IsCompliant`, `LastSignInUtc`, `Flags` |
| `intune-devices.csv` | Intune managed device | `ComplianceState`, `LastCheckInUtc`, `IsEncrypted`, `HasEntraObject`, `Flags` |
| `compliance-policies.csv` | Compliance policy | `Platform`, `AssignmentCount`, `Unassigned` |
| `ca-device-requirements.csv` | CA policy that uses device state | `RequiresCompliantDevice`, `RequiresHybridJoined`, `DeviceFilterRule`, `IncludePlatforms`, `State` |

**Reading it:** a require-compliant-device policy only protects as far as devices are enrolled and evaluated. Unmanaged enabled devices can't pass it, and an unassigned device passes it if the tenant treats devices with no policy as compliant.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader (or Intune Read Only Operator + Global Reader) | Device.Read.All, Policy.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Device counts by join type vs Entra > Devices; one known non-compliant device in Intune.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 16: Intune datasets `Blocked` | No Intune read role / scope | Intune Read Only Operator, `DeviceManagementManagedDevices.Read.All` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 15 Rule-managed access](15-rule-managed-access.md) · [All scripts](README.md) · [17 AWS IAM posture →](17-aws-iam-posture.md)
