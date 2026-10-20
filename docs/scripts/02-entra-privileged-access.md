# 02 - Entra privileged access

**Script:** [`02-Get-PrivilegedAccess.ps1`](../../scripts/02-Get-PrivilegedAccess.ps1) · **Version:** 1.0.1 · **Source:** Entra

> Who holds Entra admin roles, how, and are those accounts well managed?

Shows who holds directory roles, how (directly, through a group, permanently or just-in-time), and whether those accounts are well managed.

**Collects:** active and eligible (PIM) role assignments; members of role-holding groups; role-assignable groups and owners; one row per privileged user with sync source, last sign-in, MFA registration, Tier 0 role and flags. Falls back to plain role assignments if PIM isn't licensed.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-StaleDays` | `90` | Days without sign-in before a privileged user is flagged |

**Open first:** `summary.csv`, then `privileged-users.csv` sorted by `Flags`. The Tier 0 role list is at the top of the script.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `role-assignments-active.csv` | Active assignment | `RoleName`, `IsTier0Role`, `PrincipalType`, `AssignmentType`, `IsPermanent`, `MemberType` |
| `role-assignments-eligible.csv` | Eligible assignment | `IsPermanentlyEligible` |
| `role-group-members.csv` | Member of a role-holding group | `RolesGranted`, `MemberUPN` |
| `role-assignable-groups.csv` | Role-assignable group | `HoldsRoles`, `OwnerCount`, `SyncedFromOnPrem` |
| `privileged-users.csv` | Privileged user | `SyncedFromOnPrem`, `LastSignInUtc`, `IsMfaRegistered`, `HoldsTier0Role`, `Roles`, `Flags` |

Tier 0 roles are listed at the top of the script and can be extended.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | RoleManagement.Read.Directory, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Global Administrator count in Entra > Roles; one known PIM-eligible admin appears as eligible.

See the [pilot runbook](../pilot-runbook.md).

---

[← 01 MFA coverage](01-mfa-coverage.md) · [All scripts](README.md) · [03 Apps and consents →](03-apps-and-consents.md)
