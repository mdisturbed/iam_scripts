# 10 - Guest access

**Script:** [`10-Get-GuestAccess.ps1`](../../scripts/10-Get-GuestAccess.ps1) · **Version:** 1.1.1 · **Source:** Entra

> How many guests and external accounts are there, are they used, what can they reach, and which partner tenants do we trust?

Guests are often the largest pool of stale access. External members (B2B accounts with userType Member, for example from cross-tenant sync or converted guests) are included, because they get member-level directory access.

**Collects:**
- **External collaboration settings:** who can invite, guest permission level, invitation domain allow / block list, default cross-tenant access per direction (access type and targets), inbound trust, automatic redemption, partner policy count.
- **Partner tenants:** one row per partner-specific cross-tenant policy: inbound trust (MFA, compliant and hybrid-joined devices), automatic redemption, B2B collaboration and direct connect settings per direction, and whether cross-tenant sync into this tenant is allowed.
- **External accounts:** one row per guest and external member with home domain, invitation state, last sign-in, transitive group membership (including role-assignable groups), directory roles, app assignments by name, owned objects, sponsors, effective privilege (active, eligible, via a group or PIM for Groups) and flags: `PendingInvitation`, `PendingOverNd`, `NeverSignedIn`, `NoSignInNd`, `Disabled`, `HoldsDirectoryRole`, `Privileged`, `PrivilegedTier0`, `InRoleAssignableGroup`, `OwnsObjects`, `NoSponsor`, `ExternalMember`.
- **Every group, owned object and privileged role path** of each external account, as separate files.
- One row per home domain.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-StaleDays` | `90` | Days without sign-in before flagging |
| `-PendingDays` | `30` | Pending invitations older than this are flagged |
| `-SkipMemberships` | off | Fast pass: no per-account group, app or owned-object calls |
| `-SkipSponsors` | off | Do not read sponsors (read by default) |
| `-SkipExternalMembers` | off | Guests only: do not look for external members |
| `-SkipPrivilegeJoin` | off | Do not read directory role holders; `IsPrivileged` is left blank |
| `-IncludeSponsors` | - | Accepted for older command lines; sponsors are read by default |

**Open first:** `summary.csv`, then `privileged-guests.csv`, then `guests.csv` filtered on enabled accounts that are stale or never signed in.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `external-collaboration-settings.csv` | Setting | Who can invite, guest access level, invitation domain restriction, cross-tenant defaults and targets |
| `cross-tenant-partners.csv` | Partner tenant policy | `TrustExternalMfa`, `TrustCompliantDevice`, `AutoRedeemInbound`, `B2BCollaborationInbound`/`Outbound`, `B2BDirectConnectInbound`/`Outbound`, `IdentitySyncInbound`, `Flags` |
| `guests.csv` | Guest or external member | `HomeDomain`, `InvitationState`, `LastSignInUtc`, `GroupCount` (transitive), `DirectoryRoles`, `AppAssignments`, `Sponsors`, `Flags`, `ExternalType`, `UserPrincipalName`, `GroupCountTotal`, `RoleAssignableGroups`, `AppAssignmentNames`, `OwnedObjects`, `IsPrivileged`, `IsTier0`, `Roles`, `PrivilegePaths` |
| `guest-group-memberships.csv` | External account + group (transitive) | `GroupName`, `GroupType`, `IsAssignableToRole`, `Dynamic` |
| `guest-owned-objects.csv` | Object owned by an external account | `ObjectType` (application, servicePrincipal, group …), `ObjectName` |
| `privileged-guests.csv` | External account + role path | `Role`, `Tier0`, `AssignmentState`, `Via`, `ViaGroup`, `EndDateTime` |
| `guests-by-domain.csv` | Home domain | `Guests`, `PendingInvitation`, `NeverSignedIn`, `Stale`, `ExternalMembers`, `Privileged` |

**Reading it:**
- `Groups` lists the first 10 groups; the full list is in `guest-group-memberships.csv`.
- `privileged-guests.csv` includes eligible roles and roles reached through a group or PIM for Groups, which a plain membership check misses. Any Tier 0 row is a priority finding.
- A guest owning an application or service principal can add credentials to it.
- `IdentitySyncInbound = Allowed` means that partner tenant can create and update users here through cross-tenant sync. `TrustExternalMfa` means the partner's MFA satisfies your Conditional Access.
- The invitation domain list comes from an undocumented Graph beta endpoint (`legacy/policies`). Confirm it in Entra > External Identities > External collaboration settings.
- External members are found by `externalUserState` or an `#EXT#` user principal name; a member with neither is not detected.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | User.Read.All, Directory.Read.All, AuditLog.Read.All, Policy.Read.All, RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup | - | Graph Auth |

`signInActivity` needs Entra ID P1; eligible roles and PIM for Groups need Entra ID P2. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Total guest count in Entra > Users (filter: Guest); one guest you know holds a role appears in `privileged-guests.csv`.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `guests` note: signInActivity unavailable | No Entra ID P1, or AuditLog.Read.All missing | Record as a finding; staleness is not evaluated |
| `guests` Partial: External members unreadable | The run account cannot list members | Run as Global Reader, or use `-SkipExternalMembers` |
| `privileged-guests` Blocked | Role assignments not readable | Add RoleManagement.Read.Directory |
| `cross-tenant-partners` row `IdentitySyncInbound = unreadable` | 403 on identitySynchronization | Policy.Read.All; `Not configured` is a real answer (404) |
| Invitation domain restriction `unreadable` | The beta legacy endpoint refused the call | Check the setting in the portal |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 09 Mail forwarding and external sharing](09-mail-forwarding-and-external-sharing.md) · [All scripts](README.md) · [11 Azure RBAC →](11-azure-rbac.md)
