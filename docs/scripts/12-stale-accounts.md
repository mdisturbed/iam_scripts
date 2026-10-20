# 12 - Stale accounts

**Script:** [`12-Get-StaleAccounts.ps1`](../../scripts/12-Get-StaleAccounts.ps1) · **Version:** 1.0.0 · **Source:** AD + Entra

> Which identities are really unused once AD and Entra activity are combined?

A user can look stale in AD while signing in to Microsoft 365 every day, or the reverse. This joins AD and Entra and uses the newest activity from either side.

**Collects:** one row per identity (Hybrid, ADOnly, CloudOnly) with enabled state on each side, AD last logon, Entra interactive / non-interactive / successful sign-in, newest activity, activity bucket (0-30 … 365+, Never) and flags (`NeverUsed`, `Stale`, `EnabledMismatch`, `CreatedButNeverUsed`, `PasswordNeverExpires`, `Guest`); optionally stale computer accounts.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AnchorAttribute` | `objectGUID` | Use `mS-DS-ConsistencyGuid` if Entra Connect anchors on it |
| `-StaleDays` | `90` | Threshold for `Stale` |
| `-NewAccountGraceDays` | `30` | New accounts aren't flagged as never used until this old |
| `-EnabledOnly` | off | Only identities enabled on at least one side |
| `-IncludeComputers` | off | Add stale AD computer accounts |

**Open first:** `summary.csv`; the "Stale in AD but active in Entra" line shows how many accounts an AD-only check would have wrongly flagged.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `identity-activity.csv` | Identity (AD and/or Entra) | `Source` (Hybrid / ADOnly / CloudOnly), `ADEnabled`, `EntraEnabled`, `ADLastLogonUtc`, `EntraLast*Utc`, `NewestActivityUtc`, `NewestActivitySource`, `ActivityBucket`, `Flags` |
| `ad-computers.csv` | Computer account (`-IncludeComputers`) | `LastLogonUtc`, `PasswordLastSetUtc`, `Stale` |

**Reading it:** `NewestActivityUtc` is the newer of AD and Entra. `EnabledMismatch` means disabled on one side and enabled on the other, often a leaver disabled on-prem whose cloud object hasn't synced yet, or the reverse.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | User.Read.All, AuditLog.Read.All | Domain read | RSAT AD, Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One account you know is active on both sides shows `0-30`; one disabled leaver shows as stale or disabled.

Usually tuned on first run: `-AnchorAttribute` if Entra Connect uses `mS-DS-ConsistencyGuid`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scripts 12 / 13: few AD users matched to Entra | Entra Connect anchors on a different attribute | `-AnchorAttribute 'mS-DS-ConsistencyGuid'` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 11 Azure RBAC](11-azure-rbac.md) · [All scripts](README.md) · [13 Hybrid sync scope →](13-hybrid-sync-scope.md)
