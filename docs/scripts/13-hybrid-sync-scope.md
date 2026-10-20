# 13 - Hybrid sync scope

**Script:** [`13-Get-HybridSyncScope.ps1`](../../scripts/13-Get-HybridSyncScope.ps1) · **Version:** 1.0.0 · **Source:** AD + Entra

> What actually syncs from AD to Entra, and where do they disagree?

Any provisioning design that writes to AD depends on knowing what reaches Entra.

**Collects:** tenant sync status (on/off, last sync, last password-hash sync, optional feature flags); per-OU coverage with inferred scope (`InScope`, `OutOfScope`, `Partial - investigate`); enabled AD users not in Entra; synced Entra users with no AD match (orphaned, or from another domain); cloud-only users that look like duplicates of AD users; provisioning errors; optionally the same for groups (matched on SID).

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AnchorAttribute` | `objectGUID` | As in script 12 |
| `-IncludeGroups` | off | Add group coverage and orphans |
| `-IncludeSyncFeatures` | off | Read sync feature flags (`OnPremDirectorySynchronization.Read.All`) |
| `-SyncStaleHours` | `24` | Warn if the last sync is older |

**Open first:** `summary.csv`, then `sync-ou-coverage-users.csv` rows marked Partial. Scope is inferred from results, not read from the Entra Connect configuration. Run once per domain in a multi-domain forest.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `sync-tenant-status.csv` | Setting | last sync, last password-hash sync, feature flags |
| `sync-ou-coverage-users.csv` | OU holding users | `Users`, `SyncedUsers`, `SyncedPct`, `InferredScope` |
| `ad-users-not-in-entra.csv` | Enabled AD user with no Entra twin | `ParentOU`, `Note` |
| `entra-synced-without-ad-match.csv` | Synced Entra user with no AD match here | `Classification` (OtherDomain / OrphanedSyncedObject / NoMatchInThisDomain) |
| `cloud-only-possible-duplicates.csv` | Cloud-only user resembling an AD user | `MatchesADAccounts`, `MatchStrength` (Strong / NameOnly) |
| `user-provisioning-errors.csv` | Provisioning error | `Category`, `PropertyCausingError`, `Value` |
| `sync-ou-coverage-groups.csv` | OU holding groups (`-IncludeGroups`) | as for users |
| `entra-synced-groups-without-ad-match.csv` | Synced Entra group with no AD match here | `Classification` |

**Reading it:** scope is inferred from results. An OU at 100% is in scope, 0% is out of scope, and anything in between has an explanation to find: an attribute filter, sync errors, or objects created after the last sync.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | User.Read.All, Group.Read.All, Organization.Read.All (+ OnPremDirectorySynchronization.Read.All) | Domain read | RSAT AD, Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Last sync time in Entra Connect Health or the portal; one OU you know is excluded shows `OutOfScope`.

Usually tuned on first run: `-AnchorAttribute` if Entra Connect uses `mS-DS-ConsistencyGuid`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scripts 12 / 13: few AD users matched to Entra | Entra Connect anchors on a different attribute | `-AnchorAttribute 'mS-DS-ConsistencyGuid'` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 12 Stale accounts](12-stale-accounts.md) · [All scripts](README.md) · [14 IGA reconciliation →](14-iga-reconciliation.md)
