# 11 - Azure RBAC

**Script:** [`11-Get-AzureRbac.ps1`](../../scripts/11-Get-AzureRbac.ps1) · **Version:** 1.1.2 · **Source:** Azure + Entra

> Who actually holds access to Azure resources (groups expanded to people and workload identities), at what scope, permanently or just-in-time, and through which other paths (Key Vault access policies, Lighthouse, managed identities)?

Entra roles control the tenant; Azure RBAC controls the resources.

**Collects:** visible management groups (with parent) and subscriptions; every role assignment at management group, subscription, resource group and resource scope (de-duplicated, principal resolved via Graph, ABAC condition text, and whether it is permanent, time-bound or a PIM activation); eligible PIM assignments at management group and subscription scope where licensed; every active and eligible assignment resolved to users and service principals, with group assignments expanded to transitive members; custom roles defined at subscription or management group scope, flagged when their actions or data actions reach access control, secrets, keys, blob data or VM run command; classic administrators; Key Vaults (RBAC or legacy access-policy model) and their access policies; Azure Lighthouse delegations to other tenants; deny assignments; user-assigned managed identities with their role assignments.

Assignment flags: `DirectUserAssignment`, `GuestPrincipal`, `OrphanedPrincipal` (Graph returned 404), `PrincipalNotVerified` (Graph read failed for another reason), `PrivilegedAtBroadScope`, `ServicePrincipalPrivileged`, `CustomRoleRisky`, `RoleDefinitionUnresolved`.

Privileged roles: Owner, User Access Administrator, Role Based Access Control Administrator, Contributor, Key Vault Administrator, Key Vault Secrets Officer, Key Vault Data Access Administrator, Storage Blob Data Owner, Storage Account Contributor, Virtual Machine Administrator Login, Virtual Machine Contributor, Azure Kubernetes Service Cluster Admin Role, Azure Kubernetes Service RBAC Cluster Admin, Managed Identity Operator, any risky custom role, plus `-AdditionalPrivilegedRoles`.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SubscriptionId` | all visible | Limit to listed subscriptions |
| `-SkipManagementGroups` | off | Skip management-group scopes (assignments, eligibility, custom roles defined there) |
| `-SkipEligible` | off | Skip PIM eligibility |
| `-SkipPrincipalResolution` | off | Don't call Graph; principals show as IDs and `azure-effective-users` is `Deferred` |
| `-SkipGroupExpansion` | off | Don't expand group assignments to members (one Graph call per group) |
| `-SkipKeyVaults` | off | Skip the Key Vault and access-policy read |
| `-AdditionalPrivilegedRoles` | none | Extra role names to treat as privileged |

**Open first:** `summary.csv`, then `azure-effective-users.csv` filtered on `IsPrivilegedRole` = True, then `azure-role-assignments.csv` filtered on `OrphanedPrincipal` and `PrivilegedAtBroadScope`. Subscriptions you can't read are counted in the summary and logged; they are not silently skipped.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `azure-management-groups.csv` | Management group | `Parent`, `ParentDisplayName` |
| `azure-subscriptions.csv` | Subscription in scope | `State` |
| `azure-role-assignments.csv` | Role assignment | `Scope`, `ScopeLevel`, `RoleName`, `RoleType`, `IsPrivilegedRole`, `PrincipalType`, `PrincipalName`, `Flags`, `Condition`, `AssignmentType` (Permanent / TimeBound / Activated / Unknown) |
| `azure-eligible-assignments.csv` | PIM eligible assignment (management group or subscription scope) | `RoleName`, `PrincipalName`, `EndUtc`, `PrincipalId`, `RoleGuid` |
| `azure-effective-users.csv` | Principal holding a role, after group expansion | `SubscriptionName`, `Scope`, `RoleName`, `IsPrivilegedRole`, `PrincipalId`, `Upn`, `DisplayName`, `AssignmentState` (Active / Eligible), `Via` (Direct / Group member), `ViaGroup`, `PrincipalType`, `AssignmentType` |
| `azure-custom-roles.csv` | Custom role | `Actions`, `Risky`, `AssignmentCount`, `DataActions`, `NotDataActions`, `RiskReasons`, `DefinedAt` |
| `azure-classic-administrators.csv` | Classic co-administrator | |
| `keyvaults.csv` | Key Vault | `PermissionModel` (RBAC / AccessPolicy), `AccessPolicyCount`, `Flags` (LegacyAccessPolicyModel / PublicNetworkOpen) |
| `keyvault-access-policies.csv` | Access policy entry | `VaultName`, `PrincipalName`, `PrincipalType`, `SecretPermissions`, `KeyPermissions`, `CertificatePermissions`, `Flags` (CanReadSecrets / AllPermissions / IgnoredRbacModel / OrphanedPrincipal) |
| `lighthouse-delegations.csv` | Authorization granted to another tenant | `ManagedByTenantName`, `AuthorizationType` (Permanent / Eligible), `PrincipalDisplayName`, `RoleName`, `IsPrivilegedRole` |
| `azure-deny-assignments.csv` | Deny assignment | `Scope`, `IsSystemProtected`, `Principals`, `Actions` |
| `managed-identities.csv` | User-assigned managed identity | `PrincipalId`, `RoleAssignments`, `PrivilegedAssignments`, `Flags` |

**Reading it:** `azure-effective-users.csv` is the answer to "who can do what": one row per user or service principal per role and scope, with `Via` = `Group member` and `ViaGroup` showing access that arrives through a group. `PrivilegedAtBroadScope` rows in `azure-role-assignments.csv` are the highest-impact standing access; `AssignmentType` = `Permanent` on a privileged role is a PIM candidate.

`OrphanedPrincipal` means Graph returned 404 for the principal: it was deleted and the assignment is a clean-up candidate. `PrincipalNotVerified` means the Graph read failed for another reason (403, throttling); it is not evidence of deletion. A dataset marked `Partial` had at least one scope it could not read; the note says which part is missing. Check the summary's "Scopes that could not be read" before treating counts as complete.

Key Vaults on the legacy access-policy model grant data access outside Azure RBAC, so those principals do not appear in role assignments; read `keyvault-access-policies.csv` alongside. `lighthouse-delegations.csv` lists identities in another tenant that hold roles here.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | Directory.Read.All (resolve principals, expand groups) | Azure **Reader** at root management group (or each subscription); covers Key Vault, Lighthouse, deny assignment and managed identity reads | Az.Accounts, Graph Auth |

Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Owner assignments on one subscription in the portal (Access control (IAM)).

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 11: "Scopes that could not be read" above 0 | No Reader on some subscriptions | Request Reader at the root management group |
| Every dataset `Blocked` with "No subscriptions visible to the run account"; summary values blank | The account holds no Azure RBAC role. Azure returns an empty subscription list rather than an error, so before 1.1.2 this showed as Completed with 0 rows | Request Reader at the root management group (granting it may need a Global Administrator to elevate access first), or Reader on each in-scope subscription and run with `-SkipManagementGroups` |
| `azure-management-groups` is `Partial` | Tree not readable from the tenant root and some groups unreadable | Reader at the root management group |
| `PrincipalNotVerified` on many rows | Graph 403 or throttling on `directoryObjects` | Check the Graph consent for Directory.Read.All and re-run; do not treat these as deleted |
| `azure-effective-users` is `Partial` | Some groups could not be expanded | See the dataset note (group IDs) and run.log |
| `azure-effective-users` is `Deferred` | Graph not available or `-SkipPrincipalResolution` | Run with Graph access |
| `keyvaults` is `Partial` | No Reader on some subscriptions | Same fix as unreadable scopes |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 10 Guest access](10-guest-access.md) · [All scripts](README.md) · [12 Stale accounts →](12-stale-accounts.md)
