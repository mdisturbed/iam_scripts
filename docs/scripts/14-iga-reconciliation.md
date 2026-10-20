# 14 - IGA reconciliation

**Script:** [`14-Compare-IgaToDirectory.ps1`](../../scripts/14-Compare-IgaToDirectory.ps1) · **Version:** 1.0.0 · **Source:** AD + IGA export

> Where does the IGA platform's view of accounts and group access differ from AD?

Shows where the IGA platform's view differs from AD. Run it before JML moves to a new platform, to document what the current IGA does and doesn't control. Inputs are CSV exports you supply; nothing connects to the IGA.

**Collects:**
- an input profile (rows, systems and status values seen) to confirm the column mapping
- AD accounts the IGA doesn't know, with service/admin patterns marked separately
- IGA accounts missing from AD
- status mismatches, where `IgaInactive_ADEnabled` is the highest risk

With an assignments export it also collects:
- governed groups, with counts of members in both, AD-only and IGA-only
- memberships granted outside the IGA
- IGA assignments not present in AD
- AD security groups the IGA never assigns

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AccountsCsv` | required | One row per account per system ([template](../../examples/iga-accounts.example.csv)) |
| `-AssignmentsCsv` | none | One row per account per group ([template](../../examples/iga-assignments.example.csv)) |
| `-SystemName` | `Active Directory` | Value identifying AD rows; wildcards allowed |
| `-Acct*Column`, `-Asg*Column` | see templates | Map the export's column names |
| `-ActiveStatusValues` / `-InactiveStatusValues` | `Active`, `Enabled` / `Disabled`, `Inactive`, `Terminated`, `Deleted`, `Expired`, `Removed`, `Revoked` | Status mapping |
| `-AdAccountKey` | `sAMAccountName` | Or `userPrincipalName` |
| `-AdGroupKey` | `Name` | Or `sAMAccountName`, `DistinguishedName` |
| `-ServiceNamePatterns` | service/admin patterns | Marked separately in the unmanaged list |
| `-GroupSearchBase` | whole domain | Limit the group scope |

**Open first:** `iga-input-profile.csv` (check the mapping), then `summary.csv` and `account-status-mismatch.csv`. Compares direct membership; access the IGA grants through nesting appears as "not in AD" for the parent group.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `iga-input-profile.csv` | Input fact | rows read, SHA-256, systems seen, status values and how each was mapped |
| `accounts-ad-not-in-iga.csv` | AD account the IGA doesn't know | `Enabled`, `Classification` (UnmanagedEnabled / UnmanagedDisabled / ServiceOrAdminPattern) |
| `accounts-iga-not-in-ad.csv` | IGA account with no AD account | `IgaStatus`, `IgaStatusClass` |
| `account-status-mismatch.csv` | Account whose status differs | `MismatchType` (IgaInactive_ADEnabled / IgaActive_ADDisabled / UnmappedIgaStatus) |
| `governed-groups.csv` | Group referenced by an IGA assignment | `IgaAssignments`, `ADUserMembers`, `InBoth`, `ADOnly`, `IgaOnly` |
| `memberships-outside-iga.csv` | AD membership with no IGA assignment | |
| `assignments-not-in-ad.csv` | IGA assignment not present in AD | `Finding` (NotProvisioned / AccountMissingInAD / GroupMissingInAD) |
| `ungoverned-groups.csv` | Security group with users that no IGA assignment references | `UserMembers` |

**Reading it:** check `iga-input-profile.csv` first. If a status value maps to `Unknown`, extend the status lists and rerun before trusting mismatches.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read; IGA exports supplied by the IGA owner | RSAT AD |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: `iga-input-profile.csv` systems and status values look right; one account you know was created outside the IGA appears.

Usually tuned on first run: Service / admin account name patterns (`-ServiceNamePatterns`, `-ExcludeNamePatterns`); Column names, `-SystemName`, status value lists. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 14: `No account rows match System` | `-SystemName` doesn't match the export | Check "Systems seen" in `iga-input-profile.csv` |
| Script 14: many `UnmappedIgaStatus` rows | Status values not in the lists | Extend `-ActiveStatusValues` / `-InactiveStatusValues` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 13 Hybrid sync scope](13-hybrid-sync-scope.md) · [All scripts](README.md) · [15 Rule-managed access →](15-rule-managed-access.md)
