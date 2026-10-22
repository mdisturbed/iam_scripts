# 18 - AD delegation

**Script:** [`18-Get-ADDelegation.ps1`](../../scripts/18-Get-ADDelegation.ps1) · **Version:** 1.1.0 · **Source:** AD

> Who has dangerous rights through AD permissions (ACLs), not group membership, and which real accounts end up holding them?

Group membership (script 04) is only half of privileged access. Accounts and groups holding dangerous rights through **ACLs** are effectively admins too, and they're often forgotten.

**Looks at:**
- **Tier 0:** the domain root, AdminSDHolder, the Domain Controllers OU, the protected groups, protected accounts (`adminCount=1`), and GPOs linked to the domain or the DC OU
- **every OU** and **every other GPO** (edit rights on a GPO = control of everything it applies to)
- **individual accounts** (`-ObjectAclScope`): by default admin-like accounts, meaning protected ones, names matching `-AdminNamePatterns` and members of `-AdditionalPrivilegedGroups`; `All` checks every user, group and computer

**Reports** rights held by non-default trustees: full control, modify permissions, take ownership, write all properties, reset password, write members, write SPN, write key credential (shadow credentials), write RBCD, write GPO path or links, all extended rights, DCSync and read LAPS password. Each group trustee is then expanded through nested groups to the **user accounts** that actually hold the right, and accounts that don't look like admin accounts are flagged `RegularAccountWithElevatedRights`.

Trustees are labelled so product defaults can be filtered rather than hidden: `Exchange (product default)`, `Entra Connect (sync account)`, `Builtin operator`, `Custom`.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ObjectAclScope` | `Privileged` | Individual accounts to check: `Privileged`, `All` (slow in large domains), `None` |
| `-AdminNamePatterns` | `adm*`, `*adm`, `*-adm*`, `*_adm*`, `a-*`, `a_*`, `da-*`, `*admin*` | Admin naming standard: picks accounts to check and separates admin from regular accounts. Set to the organization's convention |
| `-AdditionalPrivilegedGroups` | none | Custom admin groups whose members are checked too |
| `-SkipGPOs` | off | Skip GPO permissions |
| `-SkipMemberExpansion` | off | Don't expand group trustees to users |
| `-SkipOUs` | off | Skip the per-OU review |
| `-AdditionalTargets` | none | Extra DNs to review |
| `-IncludeInherited` | off | Also report inherited ACEs (noisy) |
| `-IncludeLowSeverity` | off | Include create / delete child object rights |

**Open first:** `ad-delegation-effective-users.csv` filtered on `Flags` = `RegularAccountWithElevatedRights`, then `ad-delegations.csv` filtered on `TrusteeCategory` = `Custom` and sorted by severity.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-delegations.csv` | Risky right held by a non-default trustee on a target | `Target`, `TargetKind`, `Tier` (Tier0 / OU / GPO / PrivilegedAccount / Object), `Trustee`, `TrusteeType`, `TrusteeCategory`, `Right`, `AppliesTo`, `AppliesToObjects`, `Severity` |
| `ad-nondefault-owners.csv` | Target with a non-default owner | `Owner`, `OwnerType`, `Severity` |
| `ad-delegation-by-trustee.csv` | Trustee | `TrusteeType`, `TrusteeCategory`, `HighestSeverity`, `Rights`, `Tier0Targets`, `OUTargets`, `GPOTargets`, `AccountTargets`, `EffectiveUsers` |
| `ad-delegation-effective-users.csv` | User account holding a right (directly or through nested groups) | `SamAccountName`, `Enabled`, `LooksLikeAdminAccount`, `HighestSeverity`, `HoldsTier0Rights`, `Rights`, `Via`, `Flags` (RegularAccountWithElevatedRights, DirectGrant, Disabled, NoLogon90d) |

**Reading it:**
- Severity is Critical for any right on a Tier 0 object and for DCSync anywhere; High for the big rights elsewhere.
- `RegularAccountWithElevatedRights` = enabled, not named like an admin account, and holding a High or Critical right. Usually a day-to-day account in a helpdesk or admin group, which should use a separate admin account.
- On protected accounts, rights copied from AdminSDHolder are reported once (on AdminSDHolder), not on every account.
- `Exchange (product default)` rows are real escalation paths (e.g. Exchange Windows Permissions with modify permissions on the domain); `Entra Connect (sync account)` with DCSync is expected.
- Expansion follows nested groups (`memberOf` in-chain); primary-group membership and foreign-domain members are not included. GPO permissions are read from AD; SYSVOL file permissions are not.
- An object's owner can rewrite its permissions: accounts often show the helpdesk user who created them.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read (DACLs are readable by authenticated users on most objects) | RSAT AD |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: one delegation you know exists (e.g. helpdesk reset-password on a user OU) appears with the right OU and trustee, and one helpdesk member appears in `ad-delegation-effective-users.csv`.

Usually tuned on first run: `-AdminNamePatterns` to the admin naming standard, `-AdditionalPrivilegedGroups`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 18: many `(unresolved)` trustees | Deleted accounts or groups still in ACLs | These are clean-up items; confirm the SID is gone |
| Script 18: admin accounts flagged as regular | `-AdminNamePatterns` doesn't match the naming standard | Set it, e.g. `-AdminNamePatterns 'adm-*','*-a'` |
| Script 18: `Individual account review stopped early` | The account search failed (permissions or timeout) | The rest of the run is kept; rerun with `-ObjectAclScope Privileged` or narrower patterns |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 17 AWS IAM posture](17-aws-iam-posture.md) · [All scripts](README.md) · [19 DC authentication protocols →](19-dc-authentication-protocols.md)
