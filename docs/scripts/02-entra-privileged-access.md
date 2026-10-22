# 02 - Entra privileged access

**Script:** [`02-Get-PrivilegedAccess.ps1`](../../scripts/02-Get-PrivilegedAccess.ps1) · **Version:** 1.1.0 · **Source:** Entra

> Who really holds Entra admin roles - down to the account - and are those accounts well managed?

Shows who holds directory roles and how: directly, through a group (active or eligible), through PIM for Groups eligibility, or as owner of a role-holding group. Every path is resolved to the real user, service principal or managed identity, so the answer is a list of accounts, not a list of groups.

**Collects:**
- Active and eligible (PIM) role assignments, with administrative-unit scopes resolved to names.
- Members of role-holding groups; role-assignable groups and their owners.
- The effective privileged set: one row per principal, role and path.
- One row per privileged user with sync source, last sign-in, MFA and phishing-resistant MFA registration, Tier 0 role, break-glass status and flags.
- Service principals and managed identities that hold roles, with owners, credential counts, nearest expiry and last sign-in.
- Custom role definitions, with risky permissions flagged.
- Administrative units with member counts and scoped role members.
- PIM self-activations over a lookback window.

Falls back to plain role assignments if PIM isn't licensed.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-StaleDays` | `90` | Days without sign-in before a privileged user or service principal is flagged |
| `-BreakGlassUpns` | none | Break-glass account UPNs (for example `breakglass1@contoso.local`). Flagged in `privileged-users.csv` and checked against enforced CA policies |
| `-ActivationDays` | `30` | Days of PIM self-activations to export (1-365) |
| `-SkipServicePrincipalDetail` | off | Skip owners, credentials and sign-in of role-holding service principals |
| `-SkipAdministrativeUnits` | off | Skip the administrative unit inventory (AU scopes are still named one by one) |

**Open first:** `summary.csv`, then `privileged-users.csv` sorted by `Flags`. Tier 0 users come first.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `role-assignments-active.csv` | Active assignment | `RoleName`, `IsTier0Role`, `PrincipalType`, `AssignmentType`, `IsPermanent`, `MemberType`, `ScopeName` |
| `role-assignments-eligible.csv` | Eligible assignment | `IsPermanentlyEligible`, `ScopeName` |
| `role-group-members.csv` | Member of a role-holding group | `RolesGranted`, `MemberUPN` |
| `role-assignable-groups.csv` | Role-assignable group | `HoldsRoles`, `OwnerCount`, `SyncedFromOnPrem` |
| `privileged-principals-effective.csv` | Principal x role x path | `PrincipalId`, `PrincipalType`, `PrincipalName`, `Upn`, `AccountEnabled`, `UserType`, `Role`, `Tier0`, `BuiltInRole`, `AssignmentState`, `Via`, `ViaGroup`, `DirectoryScope`, `EndDateTime` |
| `privileged-users.csv` | Privileged user | `SyncedFromOnPrem`, `LastSignInUtc`, `IsMfaRegistered`, `HoldsTier0Role`, `Roles`, `Flags`, `Paths`, `ViaPimForGroups`, `IsGroupOwnerPath`, `PhishResistantMfa`, `IsBreakGlass`, `ExcludedFromAllCa`, `CaPoliciesApplying`, `Status` |
| `privileged-service-principals.csv` | Service principal / managed identity holding a role | `ServicePrincipalType`, `AppId`, `Roles`, `Owners`, `AppOwners`, `SpPasswordCredentials`, `NearestCredentialExpiryUtc`, `ExpiredCredentials`, `LastSignInUtc`, `Flags` |
| `custom-role-definitions.csv` | Custom role | `RiskyActions`, `AllowedResourceActions`, `AssignedPrincipals`, `AssignedTo`, `Flags` |
| `administrative-units.csv` | Administrative unit | `IsMemberManagementRestricted`, `MembershipType`, `MemberCount`, `ScopedRoleMembers`, `ScopedAssignmentsInSet` |
| `pim-activations.csv` | PIM self-activation | `CreatedUtc`, `Upn`, `RoleName`, `IsTier0Role`, `Justification`, `Duration`, `TicketNumber` |

**Reading it:**
- `privileged-principals-effective.csv` is the source of truth for "who is privileged". `Via` is `Direct`, `Group member`, `PIM for Groups eligible member` / `owner`, or `Owner of role-holding group` (an owner can add themselves to the group). Script 26 reads this file.
- `privileged-users.csv` includes users reached only through eligible group membership, PIM for Groups or group ownership. `Status` is `Unresolved (HTTP x)` when the account could not be read: the row is kept, it is not evidence of absence.
- Flags: `SyncedFromOnPrem`, `Disabled`, `NoSignIn<n>d` (only when sign-in activity was read for that user), `NotMfaRegistered`, `PermanentActive`, `Guest`, `Tier0WithoutPhishResistantMfa`, `BreakGlass`, `BreakGlassNotExcludedFromAllCa`.
- `ExcludedFromAllCa` is `True` when no enabled CA policy applies to the break-glass account (user, group and active role conditions are checked). `CaPoliciesApplying` lists the policies that still apply.
- Service principal flags: `Tier0ServicePrincipal`, `NoOwner`, `SecretOnServicePrincipal`, `ExpiredCredential`, `NoSignIn<n>d`, `Disabled`, `NoAppObjectInTenant` (multi-tenant or first-party app).
- Custom roles are flagged `RiskyPermissions` when they grant role assignment, role definition, app or service principal credential, password, authentication method, CA policy, group membership or `allProperties/allTasks` actions.
- Tier 0 roles are matched by role template ID (one list shared by the Entra scripts).

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | RoleManagement.Read.Directory, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup (+ Policy.Read.All with `-BreakGlassUpns`) | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md). Service principal sign-in activity uses the beta `reports/servicePrincipalSignInActivities` endpoint (AuditLog.Read.All, Entra ID P1).

## Pilot check

Before handing this script to others, confirm: Global Administrator count in Entra > Roles; one known PIM-eligible admin appears as eligible; one member of a role-holding group appears in `privileged-users.csv` with `Paths` naming the group.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `privileged-principals-effective` is `Partial` | One source (eligible, PIM for Groups, group owners, group members) was not readable; the note names it | Grant the missing scope (PIM for Groups needs PrivilegedEligibilitySchedule.Read.AzureADGroup) or record as a limit |
| `privileged-users` rows with `Status` `Unresolved (HTTP 403)` | The account could not be read with the granted scopes | Check Directory.Read.All consent; the role path is still listed |
| `Resolved (sign-in activity not readable)` | No Entra ID P1 (all users) or a per-user read failure | Staleness is not evaluated for those users; `NoSignIn` is never set without data |
| `pim-activations` `EvidenceUnavailable` | No Entra ID P2 / ID Governance | Record as a finding |
| `ExcludedFromAllCa` starts with `Unknown` | CA policies or the account's group membership not readable | Grant Policy.Read.All |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 01 MFA coverage](01-mfa-coverage.md) · [All scripts](README.md) · [03 Apps and consents →](03-apps-and-consents.md)
