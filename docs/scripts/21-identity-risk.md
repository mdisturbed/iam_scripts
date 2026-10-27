# 21 - Identity risk

**Script:** [`21-Get-IdentityRisk.ps1`](../../scripts/21-Get-IdentityRisk.ps1) · **Version:** 1.1.1 · **Source:** Entra ID Protection

> Who is at risk right now, and does Conditional Access act on risk - for everyone?

**Collects:**
- **Users currently at risk:** with their effective privilege (direct, group, eligible, PIM for Groups and group-owner paths) and MFA registration. Flagged when they hold a directory role, hold a Tier 0 role, are not MFA registered (they cannot self-remediate), or their risk has been left open longer than `-RiskStaleDays`.
- **Risk detections:** over a lookback window, with an aggregate by detection type.
- **Risky service principals and service principal risk detections:** marked `EvidenceUnavailable` without Workload Identities Premium.
- **Conditional Access policies that act on user, sign-in or workload risk.**
- **Who those risk policies skip:** excluded users, transitive members of excluded groups, holders of excluded roles, guest types and service principals.
- **Risk history (optional):** for dismissed or remediated users, who closed the risk and how.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-DetectionLookbackDays` | `30` | Days of detections (1-90) |
| `-RiskStaleDays` | `30` | At-risk users not updated for longer are flagged `RiskLeftOpen<n>d` |
| `-IncludeRemediated` | off | Include remediated / dismissed users |
| `-IncludeRiskHistory` | off | Read the risk history of dismissed / remediated users |
| `-MaxHistoryUsers` | `500` | Cap on users whose history is read |
| `-SkipServicePrincipals` | off | Skip workload identity risk |
| `-SkipPrivilegeJoin` | off | Use direct active role assignments only for the admin flag |

**Open first:** `summary.csv`, then `risky-users.csv`, where risky admins are listed first, then `risk-policy-exclusions.csv`. Legacy Identity Protection risk policies (outside CA) aren't exposed by Graph; check the portal if CA shows none.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `risky-users.csv` | Risky user | `RiskLevel`, `RiskState`, `DaysSinceUpdate`, `DirectoryRoles`, `Flags`, `UserId`, `IsPrivileged`, `IsTier0`, `PrivilegePaths`, `IsMfaRegistered`, `RiskyNotMfaRegistered` |
| `risk-detections.csv` | Detection | `RiskEventType`, `RiskLevel`, `DetectionTiming`, `IpAddress`, `IsAdmin` |
| `risk-detections-by-type.csv` | Type + level | `Detections`, `DistinctUsers`, `AdminUsers` |
| `risky-service-principals.csv` | Risky service principal | `RiskLevel`, `HoldsDirectoryRole`, `IsTier0`, `DirectoryRoles` |
| `service-principal-risk-detections.csv` | Workload identity detection | `RiskEventType`, `RiskLevel`, `HoldsDirectoryRole`, `IsTier0` |
| `ca-risk-policies.csv` | CA policy using risk | `State`, `UserRiskLevels`, `SignInRiskLevels`, `GrantControls` |
| `risk-policy-exclusions.csv` | Account excluded from a risk policy | `PolicyName`, `RiskTypes`, `ExclusionType`, `ExcludedVia`, `Upn`, `IsPrivileged`, `CurrentlyAtRisk`, `EffectiveForCa`, `Status` |
| `risky-user-history.csv` | History event of a dismissed / remediated user (only with `-IncludeRiskHistory`) | `EventRiskState`, `RiskDetail`, `InitiatedByName`, `UpdatedUtc`, `Flags` |

**Reading it:**
- `IsAdmin` / `RiskyAdmin` use the effective privileged set, so a user who is only eligible, only in a role-holding group, or only PIM-for-Groups eligible is still an admin here.
- `RiskyNotMfaRegistered`: the user is at risk and has no MFA method, so a user-risk policy cannot let them self-remediate.
- In `risk-policy-exclusions.csv`, `EffectiveForCa` is false for eligible-only role holders (they are excluded once they activate) and for empty groups. `CurrentlyAtRisk` shows excluded accounts that are at risk right now.
- `risky-user-history.csv` flags `AdminDismissed` events: an admin closed the risk instead of the user remediating it.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Security Reader or Global Reader | IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All, Policy.Read.All, RoleManagement.Read.Directory, Directory.Read.All, AuditLog.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup (+ IdentityRiskyServicePrincipal.Read.All) | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Risky user count in Entra ID Protection > Risky users; one excluded group of the user-risk policy appears in `risk-policy-exclusions.csv` with its members.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scripts 20-22: datasets `EvidenceUnavailable` | No Entra ID P2 / ID Governance | Record as a finding |
| Service principal datasets `EvidenceUnavailable` | No Workload Identities Premium | Record as a finding |
| `risky-users` `Partial` with "direct active assignments only" | Privileged set not readable (or `-SkipPrivilegeJoin`) | Eligible and group-based admins are not flagged; grant RoleManagement.Read.Directory / PrivilegedEligibilitySchedule.Read.AzureADGroup |
| MFA columns blank, note says registration details Blocked | AuditLog.Read.All not granted | Grant it; blank means unknown, not "not registered" |
| `risk-policy-exclusions` rows with `Unresolved` status | Group members or role names not readable | Grant Directory.Read.All |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 20 Governance coverage](20-governance-coverage.md) · [All scripts](README.md) · [22 PIM role settings →](22-pim-role-settings.md)
