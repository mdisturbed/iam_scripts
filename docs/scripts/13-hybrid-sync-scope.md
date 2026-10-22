# 13 - Hybrid sync scope

**Script:** [`13-Get-HybridSyncScope.ps1`](../../scripts/13-Get-HybridSyncScope.ps1) · **Version:** 1.1.0 · **Source:** AD + Entra

> What actually syncs from AD to Entra, where do they disagree, and which on-prem admins reach the cloud?

Any provisioning design that writes to AD depends on knowing what reaches Entra. The same join also shows the classic hybrid risk: on-prem privileged accounts that are synced to Entra, and some that hold Entra admin roles as well.

**Collects:** tenant sync status (on/off, last sync, last password-hash sync, optional feature flags); per-OU coverage with inferred scope (`InScope`, `OutOfScope`, `Partial - investigate`); AD users not in Entra (enabled and disabled); synced Entra users with no AD match (orphaned, duplicate anchor, or from another domain); Entra users sharing one source anchor; matched pairs that disagree (UPN, enabled state, optionally display name); cloud-only users that look like duplicates of AD users; provisioning errors; privileged AD accounts synced to Entra and whether they hold an Entra role; Entra Connect / Cloud Sync service accounts and the Seamless SSO computer account; AD computers vs hybrid-joined Entra devices per OU; optionally group coverage, orphans and group provisioning errors (matched on SID).

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AnchorAttribute` | `objectGUID` | As in script 12; an empty `mS-DS-ConsistencyGuid` falls back to `objectGUID` |
| `-IncludeGroups` | off | Add group coverage, orphans and group provisioning errors |
| `-IncludeSyncFeatures` | off | Read sync feature flags (`OnPremDirectorySynchronization.Read.All`) |
| `-SyncStaleHours` | `24` | Warn if the last sync is older |
| `-OrphanDays` | `7` | A synced Entra user not updated for this many days is `OrphanedSyncedObject` |
| `-SkipDevices` | off | Leave out the device coverage check |
| `-SkipEntraRoles` | off | Don't read Entra role assignments (`SyncedAdminHoldsEntraRole` isn't evaluated) |
| `-IncludeDisplayNameMismatch` | off | Add display-name differences to `matched-pair-mismatches.csv` |

**Open first:** `summary.csv`, then `privileged-ad-accounts-synced.csv` rows with `SyncedAdminHoldsEntraRole`, then `matched-pair-mismatches.csv` rows with Severity High, then `sync-ou-coverage-users.csv` rows marked Partial. Scope is inferred from results, not read from the Entra Connect configuration. Run once per domain in a multi-domain forest.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `sync-tenant-status.csv` | Setting | last sync, last password-hash sync, feature flags |
| `sync-ou-coverage-users.csv` | OU holding users | `Users`, `SyncedUsers`, `SyncedPct`, `InferredScope` |
| `ad-users-not-in-entra.csv` | AD user with no Entra twin | `ParentOU`, `Note`, `Enabled` |
| `entra-synced-without-ad-match.csv` | Synced Entra user with no AD match here | `Classification` (OtherDomain / DuplicateAnchor / OrphanedSyncedObject / NoMatchInThisDomain) |
| `duplicate-anchors.csv` | Entra user sharing an `onPremisesImmutableId` | `OnPremisesImmutableId`, `UserPrincipalName`, `UsedForMatch`, `SharedBy` |
| `matched-pair-mismatches.csv` | Difference on a matched AD / Entra pair | `Check` (UPN / Enabled / DisplayName), `AdValue`, `EntraValue`, `Severity`, `Note` |
| `cloud-only-possible-duplicates.csv` | Cloud-only user resembling an AD user | `MatchesADAccounts`, `MatchStrength` (Strong / NameOnly) |
| `user-provisioning-errors.csv` | Provisioning error | `Category`, `PropertyCausingError`, `Value` |
| `privileged-ad-accounts-synced.csv` | Privileged AD account with an Entra twin | `PrivilegedVia`, `AdminCount`, `EntraUserPrincipalName`, `HoldsEntraRole`, `EntraRoles`, `Severity`, `Flags` (SyncedPrivilegedAccount, SyncedAdminHoldsEntraRole, AdminCountOnly, EnabledMismatch) |
| `sync-service-accounts.csv` | `MSOL_*`, `Sync_*`, `AAD_*`, `ADSyncMSA*` account or `AZUREADSSOACC` | `Kind`, `Enabled`, `PwdLastSetUtc`, `PasswordAgeDays`, `LastLogonUtc`, `Flags` (SsoKeyNotRolled, PasswordNeverExpires, NoRecentLogon, MultipleConnectorAccounts) |
| `device-sync-coverage.csv` | OU holding computers | `Computers`, `HybridJoined`, `InEntraOtherTrustType`, `NotInEntra`, `HybridJoinedPct` |
| `sync-ou-coverage-groups.csv` | OU holding groups (`-IncludeGroups`) | as for users |
| `entra-synced-groups-without-ad-match.csv` | Synced Entra group with no AD match here | `Classification` |
| `group-provisioning-errors.csv` | Group provisioning error (`-IncludeGroups`) | `DisplayName`, `Category`, `PropertyCausingError`, `Value` |

**Reading it:**
- Scope is inferred from results. An OU at 100% is in scope, 0% is out of scope, and anything in between has an explanation to find: an attribute filter, sync errors, or objects created after the last sync.
- Privileged means `adminCount = 1` or a nested member of Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators or Backup Operators. A privileged on-prem account that is synced can be taken over from the cloud side (password reset, sign-in), and one that also holds an Entra role links the two tiers: `SyncedAdminHoldsEntraRole` is the finding to fix first. `AdminCountOnly` means adminCount is still set but no current membership was found (often a leftover).
- `HoldsEntraRole` is `True`, `False`, `Unknown (Partial)` or `EvidenceUnavailable`; only `False` means no role was found. The summary count is blank when roles couldn't be read.
- Enabled mismatch: AD disabled but Entra enabled is High (cloud sign-in still works until the next sync, or forever if the object is filtered out); Entra-only blocks are Medium.
- `AZUREADSSOACC` with `SsoKeyNotRolled(>30d)`: the Seamless SSO Kerberos key should be rolled regularly. The `MSOL_` account has directory replication rights and belongs in Tier 0.
- Devices match on `onPremisesSecurityIdentifier`, then `deviceId` = AD `objectGUID`. Servers and domain controllers are usually not hybrid joined by design; `InEntraOtherTrustType` means the device is only registered or Entra joined.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | User.Read.All, Group.Read.All, Organization.Read.All, RoleManagement.Read.Directory, GroupMember.Read.All, Device.Read.All (+ OnPremDirectorySynchronization.Read.All) | Domain read | RSAT AD, Graph Auth |

Brackets mean only with the matching optional switch. RoleManagement.Read.Directory and GroupMember.Read.All aren't needed with `-SkipEntraRoles`, Device.Read.All isn't needed with `-SkipDevices`; eligible (PIM) role assignments need Entra ID P2. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Last sync time in Entra Connect Health or the portal; one OU you know is excluded shows `OutOfScope`; one on-prem admin account you know is synced appears in `privileged-ad-accounts-synced.csv`.

Usually tuned on first run: `-AnchorAttribute` if Entra Connect uses `mS-DS-ConsistencyGuid`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scripts 12 / 13: few AD users matched to Entra | Entra Connect anchors on a different attribute | `-AnchorAttribute 'mS-DS-ConsistencyGuid'` |
| Script 13: `sync-tenant-status` Blocked | Organization.Read.All not consented | Consent it; the rest of the run is unaffected |
| Script 13: `privileged-ad-accounts-synced` note says PARTIAL | A built-in group couldn't be read (e.g. Enterprise Admins from a child domain) | Run in the forest root as well, or with rights there |
| Script 13: `HoldsEntraRole` is `EvidenceUnavailable` / `Unknown (Partial)` | RoleManagement.Read.Directory missing, or no Entra ID P2 for eligible roles | See the dataset note; the AD side is still complete |
| Script 13: `device-sync-coverage` Blocked | Device.Read.All not consented | Consent it, or run with `-SkipDevices` |
| Script 13: `sync-service-accounts` Blocked | AD query refused | Check the run.log error; domain read is enough |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 12 Stale accounts](12-stale-accounts.md) · [All scripts](README.md) · [14 IGA reconciliation →](14-iga-reconciliation.md)
