# 11 - Azure RBAC

**Script:** [`11-Get-AzureRbac.ps1`](../../scripts/11-Get-AzureRbac.ps1) · **Version:** 1.0.0 · **Source:** Azure + Entra

> Who has access to Azure resources, at what scope, and to deleted principals?

Entra roles control the tenant; Azure RBAC controls the resources.

**Collects:** visible management groups and subscriptions; every role assignment at management group, subscription, resource group and resource scope (de-duplicated, principal resolved via Graph); eligible PIM assignments where licensed; custom roles flagged when they contain `*` or authorization-write actions; classic administrators. Assignment flags: `DirectUserAssignment`, `GuestPrincipal`, `OrphanedPrincipal`, `PrivilegedAtBroadScope`, `ServicePrincipalPrivileged`, `CustomRoleRisky`.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SubscriptionId` | all visible | Limit to listed subscriptions |
| `-SkipManagementGroups` | off | Skip management-group scopes |
| `-SkipEligible` | off | Skip PIM eligibility |
| `-SkipPrincipalResolution` | off | Don't call Graph; principals show as IDs |

**Open first:** `summary.csv`, then `azure-role-assignments.csv` filtered on `OrphanedPrincipal` (safe clean-up) and `PrivilegedAtBroadScope`. Subscriptions you can't read are counted in the summary and logged; they are not silently skipped.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `azure-management-groups.csv` | Management group | |
| `azure-subscriptions.csv` | Subscription in scope | `State` |
| `azure-role-assignments.csv` | Role assignment | `Scope`, `ScopeLevel`, `RoleName`, `RoleType`, `IsPrivilegedRole`, `PrincipalType`, `PrincipalName`, `Flags` |
| `azure-eligible-assignments.csv` | PIM eligible assignment | `RoleName`, `PrincipalName`, `EndUtc` |
| `azure-custom-roles.csv` | Custom role | `Actions`, `Risky`, `AssignmentCount` |
| `azure-classic-administrators.csv` | Classic co-administrator | |

**Reading it:** `OrphanedPrincipal` rows point at deleted identities and are the safest clean-up. `PrivilegedAtBroadScope` rows are the highest-impact standing access. Check the summary's "Scopes that could not be read" before treating counts as complete.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | Directory.Read.All | Azure **Reader** at root management group (or each subscription) | Az.Accounts, Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Owner assignments on one subscription in the portal (Access control (IAM)).

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 11: "Scopes that could not be read" above 0 | No Reader on some subscriptions | Request Reader at the root management group |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 10 Guest access](10-guest-access.md) · [All scripts](README.md) · [12 Stale accounts →](12-stale-accounts.md)
