# 05 - AD group nesting

**Script:** [`05-Get-ADGroupNesting.ps1`](../../scripts/05-Get-ADGroupNesting.ps1) · **Version:** 1.1.0 · **Source:** AD

> How deep and messy is group nesting, which accounts does each group really reach, and how healthy are groups and their owners?

Builds the full group-in-group graph in memory and reports structure, effective membership and hygiene for every group.

**Collects:** one row per group with member counts, depth below (`DepthDown`) and above (`DepthUp`), owner status, and flags (empty, no owner, owner disabled or stale, all members disabled, mail-enabled security, deep or circular nesting, naming-convention miss); one row per circular loop; every nesting edge, including members that could not be followed; and per group, the accounts it reaches through nesting and whether it is nested into a privileged built-in group.

**How it works:**
- Groups are read once with their members. Groups with 1500 or more members are re-read with ranged retrieval (`member;range=...`), so lists over the 5000-value limit are complete; if that read fails the group is marked `MemberReadStatus = Partial` and flagged `MemberListTruncated`.
- Users, computers, contacts and foreign principals are read once, domain-wide, to classify members (enabled / disabled, last logon) and to add accounts that hold a group as their **primary group** (not listed in `member`).
- Members that are groups outside `-SearchBase`, or objects in another domain, are recorded in `ad-group-edges.csv` with `Status = OutOfScope` and counted; they are never dropped silently.
- Depth is computed with each circular loop collapsed to one node, so groups in a loop share their depth and groups next to a loop are not under-counted.
- Privileged reach: a group is nested into Domain / Enterprise / Schema Admins, Administrators, Account / Server / Backup / Print Operators, DnsAdmins, Group Policy Creator Owners, Key Admins or Enterprise Key Admins at any depth. Forest-root groups are read from the root domain.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-DeepNestingThreshold` | `3` | Groups nested at least this deep are flagged |
| `-NamingConventionRegex` | none | e.g. `'^(RB|APP)-'` |
| `-StaleDays` | `90` | Enabled owner with no logon for this many days = `OwnerStale` |
| `-SkipReach` | off | Skip effective membership and privileged reach (`ad-group-reach`) |

**Open first:** `summary.csv`, then `ad-group-reach.csv` filtered on `ReachesPrivilegedGroup` = `True` and `IsPrivilegedGroup` = `False`, then `ad-groups.csv` filtered on `Flags`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-groups.csv` | Group | `DirectMembers`, `DirectGroupMembers`, `DepthDown`, `DepthUp`, `CycleId`, `Flags`, then at the end `OutOfScopeMembers`, `PrimaryGroupMembers`, `MemberReadStatus`, `OwnerName`, `OwnerClass`, `OwnerEnabled`, `OwnerLastLogonUtc`, `OwnerStatus` (OK / NoOwner / OwnerDisabled / OwnerStale / OwnerIsGroup / OwnerIsContact / Unresolved), `AllMembersDisabled` |
| `ad-circular-nesting.csv` | Nesting loop | `Groups` |
| `ad-group-edges.csv` | Group-in-group edge, or member not followed | `ParentGroup`, `MemberName`, `MemberType`, `Status` (InScope / OutOfScope), `Reason` |
| `ad-group-reach.csv` | Group | `EffectiveUsers`, `EnabledUsers`, `DisabledUsers`, `Computers`, `EnabledComputers`, `ForeignPrincipals`, `Contacts`, `OutOfScopeMembers`, `NestedGroups`, `IsPrivilegedGroup`, `ReachesPrivilegedGroup`, `PrivilegedGroupsReached`, `PrivilegedPath`, `Status` |

**Flags:** `Empty` (no members and no primary-group members), `NoManagedBy`, `OwnerDisabled`, `OwnerStale`, `OwnerUnresolved`, `NoDescription`, `MailEnabledSecurity`, `DeepNesting(>=N)`, `CircularNesting`, `MemberListTruncated` (full list could not be read), `AllMembersDisabled`, `HasOutOfScopeMembers`, `NamingConventionMiss`.

**Reading it:**
- `DepthDown` counts levels of groups nested inside a group; `DepthUp` counts levels of groups it sits inside. Groups in the same loop share both values.
- `EffectiveUsers` counts distinct accounts through every level of nesting, including primary-group members. A `Status` of `Partial` means some members were out of scope or a member list was incomplete, so counts are a floor.
- `PrivilegedPath` shows the shortest chain, e.g. `Helpdesk > Server Admins > Administrators`. Per-group counts overlap; for the distinct list of privileged accounts use [04](04-ad-privileged-and-service-accounts.md).
- `AllMembersDisabled` = every account reached is disabled and nothing was out of scope: a clean-up candidate.
- `OwnerStale` / `OwnerDisabled`: nobody is really accountable for the group's membership.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read; forest root read for Enterprise / Schema Admins reach | RSAT AD |

Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Total group count (`(Get-ADGroup -Filter *).Count`); one known nested group's `DepthDown`; for one large group, `EffectiveUsers` against `(Get-ADGroupMember <group> -Recursive).Count` (primary-group members can make 05 slightly higher).

Usually tuned on first run: `-NamingConventionRegex` once a convention is agreed. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 05: `ranged member read failed` | A very large group could not be read in ranges | The group is `MemberReadStatus = Partial`; rerun against another DC with `-Server` |
| Script 05: `Member classification read failed` | The domain-wide user / computer read failed (timeout or permissions) | `ad-group-reach` is Blocked and owner checks are limited; rerun off-peak, or use `-SkipReach` |
| Script 05: many `OutOfScope` edges | `-SearchBase` excludes nested groups, or members are in another domain | Expected with `-SearchBase`; run without it for the full graph |
| Script 05: slow in a very large domain | Effective membership is computed for every group | Use `-SkipReach` for structure and hygiene only |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 04 AD privileged and service accounts](04-ad-privileged-and-service-accounts.md) · [All scripts](README.md) · [06 JML timing →](06-jml-timing.md)
