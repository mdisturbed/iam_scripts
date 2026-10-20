# 21 - Identity risk

**Script:** [`21-Get-IdentityRisk.ps1`](../../scripts/21-Get-IdentityRisk.ps1) · **Version:** 1.0.0 · **Source:** Entra ID Protection

> Who is at risk right now, and does Conditional Access act on risk?

**Collects:**
- **Users currently at risk:** flagged when they hold a directory role or when their risk has been left open for 30+ days.
- **Risk detections:** over a lookback window, with an aggregate by detection type.
- **Risky service principals:** marked `EvidenceUnavailable` without Workload Identities Premium.
- **Conditional Access policies that act on user or sign-in risk.**

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-DetectionLookbackDays` | `30` | Days of detections (1-90) |
| `-IncludeRemediated` | off | Include remediated / dismissed users |
| `-SkipServicePrincipals` | off | Skip workload identity risk |

**Open first:** `summary.csv`, then `risky-users.csv`, where risky admins are listed first. Legacy Identity Protection risk policies (outside CA) aren't exposed by Graph; check the portal if CA shows none.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `risky-users.csv` | Risky user | `RiskLevel`, `RiskState`, `DaysSinceUpdate`, `DirectoryRoles`, `Flags` |
| `risk-detections.csv` | Detection | `RiskEventType`, `RiskLevel`, `DetectionTiming`, `IpAddress`, `IsAdmin` |
| `risk-detections-by-type.csv` | Type + level | `Detections`, `DistinctUsers`, `AdminUsers` |
| `risky-service-principals.csv` | Risky service principal | `RiskLevel`, `HoldsDirectoryRole` |
| `ca-risk-policies.csv` | CA policy using risk | `State`, `UserRiskLevels`, `SignInRiskLevels`, `GrantControls` |

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Security Reader or Global Reader | IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All, Policy.Read.All, RoleManagement.Read.Directory (+ IdentityRiskyServicePrincipal.Read.All) | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Risky user count in Entra ID Protection > Risky users.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scripts 20-22: datasets `EvidenceUnavailable` | No Entra ID P2 / ID Governance | Record as a finding |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 20 Governance coverage](20-governance-coverage.md) · [All scripts](README.md) · [22 PIM role settings →](22-pim-role-settings.md)
