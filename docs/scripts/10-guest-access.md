# 10 - Guest access

**Script:** [`10-Get-GuestAccess.ps1`](../../scripts/10-Get-GuestAccess.ps1) · **Version:** 1.0.0 · **Source:** Entra

> How many guests are there, are they used, and what can they reach?

Guests are often the largest pool of stale access.

**Collects:** external collaboration settings (who can invite, guest permission level, default cross-tenant access, partner policy count); one row per guest with home domain, invitation state, last sign-in, group/role/app counts, sponsors and flags (`PendingInvitation`, `PendingOverNd`, `NeverSignedIn`, `NoSignInNd`, `Disabled`, `HoldsDirectoryRole`, `NoSponsor`); one row per home domain.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-StaleDays` | `90` | Days without sign-in before flagging |
| `-PendingDays` | `30` | Pending invitations older than this are flagged |
| `-SkipMemberships` | off | Fast pass: no per-guest group/app calls |
| `-IncludeSponsors` | off | Read each guest's sponsors |

**Open first:** `summary.csv`, then `guests.csv` filtered on enabled guests that are stale or never signed in.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `external-collaboration-settings.csv` | Setting | Who can invite, guest access level, cross-tenant defaults |
| `guests.csv` | Guest | `HomeDomain`, `InvitationState`, `LastSignInUtc`, `GroupCount`, `DirectoryRoles`, `AppAssignments`, `Sponsors`, `Flags` |
| `guests-by-domain.csv` | Home domain | `Guests`, `PendingInvitation`, `NeverSignedIn`, `Stale` |

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | User.Read.All, Directory.Read.All, AuditLog.Read.All, Policy.Read.All | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Total guest count in Entra > Users (filter: Guest).

See the [pilot runbook](../pilot-runbook.md).

---

[← 09 Mail forwarding and external sharing](09-mail-forwarding-and-external-sharing.md) · [All scripts](README.md) · [11 Azure RBAC →](11-azure-rbac.md)
