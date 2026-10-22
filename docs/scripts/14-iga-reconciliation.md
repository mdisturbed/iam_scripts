# 14 - IGA reconciliation

**Script:** [`14-Compare-IgaToDirectory.ps1`](../../scripts/14-Compare-IgaToDirectory.ps1) · **Version:** 1.1.0 · **Source:** AD + IGA export

> Where does the IGA platform's view of accounts and group access differ from AD, including access granted through nested groups and leavers who still hold groups?

Shows where the IGA platform's view differs from AD. Run it before JML moves to a new platform, to document what the current IGA does and doesn't control. Inputs are CSV exports you supply; nothing connects to the IGA.

**Collects:**
- an input profile (rows, systems and status values seen) to confirm the column mapping
- AD accounts the IGA doesn't know, with service/admin patterns marked separately, and `adminCount`, group count, manager, SPN and admin-name flags so privileged unmanaged accounts stand out
- IGA accounts missing from AD
- status mismatches, where `IgaInactive_ADEnabled` is the highest risk
- leavers still holding access: inactive in the IGA, disabled in AD, still in groups
- duplicate or blank match keys on either side, which would otherwise hide accounts or groups

With an assignments export it also collects:
- governed groups, with counts of members in both, AD-only and IGA-only, plus nested users and non-user members
- memberships granted outside the IGA (direct)
- nested memberships: users who reach a governed group through another group, resolved transitively, with the group they come through and the nesting path
- non-user members of governed groups: groups, computers, foreign security principals and users outside `-SearchBase`
- IGA assignments not present in AD
- AD security groups the IGA never assigns, counting users who are only reached through nesting (so Administrators-style groups that hold only groups appear)

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AccountsCsv` | required | One row per account per system ([template](../../examples/iga-accounts.example.csv)) |
| `-AssignmentsCsv` | none | One row per account per group ([template](../../examples/iga-assignments.example.csv)) |
| `-SystemName` | `Active Directory` | Value identifying AD rows; wildcards allowed |
| `-Acct*Column`, `-Asg*Column` | see templates | Map the export's column names |
| `-ActiveStatusValues` / `-InactiveStatusValues` | `Active`, `Enabled` / `Disabled`, `Inactive`, `Terminated`, `Deleted`, `Expired`, `Removed`, `Revoked` | Status mapping. A blank status is `Unknown`, never `Active` |
| `-AdAccountKey` | `sAMAccountName` | Or `userPrincipalName`. AD users with a blank key are skipped and listed in `duplicate-keys.csv` |
| `-AdGroupKey` | `sAMAccountName` | Or `Name`, `DistinguishedName`. The default changed from `Name` because group names are not unique; pass `-AdGroupKey Name` if the IGA exports the group's CN |
| `-ServiceNamePatterns` | service/admin patterns | Marked separately in the unmanaged list |
| `-AdminNamePatterns` | `adm*`, `*adm`, `*-adm*`, `*_adm*`, `a-*`, `a_*`, `da-*`, `*admin*` | Sets `IsAdminNamed` on unmanaged accounts |
| `-SkipNestedExpansion` | off | Skip the transitive member lookup (one LDAP query per governed group) |
| `-GroupSearchBase` | whole domain | Limit the group scope |

**Open first:** `iga-input-profile.csv` (check the mapping) and `duplicate-keys.csv`, then `summary.csv`, `account-status-mismatch.csv` and `inactive-but-still-member.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `iga-input-profile.csv` | Input fact | rows read, SHA-256, systems seen, status values and how each was mapped |
| `accounts-ad-not-in-iga.csv` | AD account the IGA doesn't know | `Enabled`, `Classification` (UnmanagedEnabled / UnmanagedDisabled / ServiceOrAdminPattern), `AdminCount`, `MemberOfCount`, `Manager`, `HasSpn`, `IsAdminNamed` |
| `accounts-iga-not-in-ad.csv` | IGA account with no AD account | `IgaStatus`, `IgaStatusClass` |
| `account-status-mismatch.csv` | Account whose status differs | `MismatchType` (IgaInactive_ADEnabled / IgaActive_ADDisabled / UnmappedIgaStatus) |
| `inactive-but-still-member.csv` | Account inactive in the IGA and disabled in AD that is still in groups | `MemberOfCount`, `Groups`, `GovernedGroups` |
| `duplicate-keys.csv` | Duplicate or blank match key | `Source` (AD account / IGA account / AD group), `Issue` (DuplicateKey / BlankKey), `Objects`, `Handling` |
| `governed-groups.csv` | Group referenced by an IGA assignment | `IgaAssignments`, `ADUserMembers`, `InBoth`, `ADOnly`, `IgaOnly`, `NestedUserMembers`, `NestedNotInIga`, `NonUserMembers`, `ExpansionStatus` |
| `memberships-outside-iga.csv` | Direct AD membership with no IGA assignment | `GroupDistinguishedName` |
| `nested-memberships-outside-iga.csv` | User reaching a governed group through another group | `Account`, `Group`, `ViaGroup`, `Enabled`, `InIga`, `NestingPath` |
| `governed-group-nonuser-members.csv` | Non-user member of a governed group | `MemberType` (Group / Computer / ForeignSecurityPrincipal / UserOutsideSearchBase / ManagedServiceAccount / Unresolved) |
| `assignments-not-in-ad.csv` | IGA assignment not present as direct membership | `Finding` (NotProvisioned / ProvisionedViaNesting / AccountMissingInAD / GroupMissingInAD) |
| `ungoverned-groups.csv` | Security group with users that no IGA assignment references | `UserMembers` (direct), `TransitiveUserMembers` |

**Reading it:** check `iga-input-profile.csv` first. If a status value maps to `Unknown` (including blank), extend the status lists and rerun before trusting mismatches. Rows in `duplicate-keys.csv` mean some accounts or groups were not reconciled; fix the key choice before trusting counts. In `nested-memberships-outside-iga.csv`, `InIga = False` is access the IGA doesn't grant and won't remove; `InIga = True` is an IGA assignment fulfilled through nesting, which also appears as `ProvisionedViaNesting` in `assignments-not-in-ad.csv`. `inactive-but-still-member.csv` lists leavers whose access comes straight back if the account is re-enabled.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read; IGA exports supplied by the IGA owner | RSAT AD |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: `iga-input-profile.csv` systems and status values look right; `duplicate-keys.csv` is empty or explained; one account you know was created outside the IGA appears; one group you know is nested inside a governed group shows in `nested-memberships-outside-iga.csv`.

Usually tuned on first run: Service / admin account name patterns (`-ServiceNamePatterns`, `-ExcludeNamePatterns`); Column names, `-SystemName`, status value lists, `-AdGroupKey`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 14: `No account rows match System` | `-SystemName` doesn't match the export | Check "Systems seen" in `iga-input-profile.csv` |
| Script 14: many `UnmappedIgaStatus` rows | Status values not in the lists, or a blank status column | Extend `-ActiveStatusValues` / `-InactiveStatusValues`; check the status column mapping |
| Script 14: most governed groups `ExistsInAD = False` | The IGA exports group names, not sAMAccountNames | Rerun with `-AdGroupKey Name` and check `duplicate-keys.csv` for ambiguous names |
| Script 14: `ExpansionStatus` starts with `Failed` | The transitive lookup for that group was refused | The nested dataset is marked `Partial`; nested users of that group may appear as `NotProvisioned`. Rerun with read access, or use `-SkipNestedExpansion` |
| Script 14: `ViaGroup` shows `(group outside -GroupSearchBase)` | The intermediate group was not read | Widen `-GroupSearchBase` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 13 Hybrid sync scope](13-hybrid-sync-scope.md) · [All scripts](README.md) · [15 Rule-managed access →](15-rule-managed-access.md)
