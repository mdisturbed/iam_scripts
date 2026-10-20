# 18 - AD delegation

**Script:** [`18-Get-ADDelegation.ps1`](../../scripts/18-Get-ADDelegation.ps1) · **Version:** 1.0.0 · **Source:** AD

> Who has dangerous rights through AD permissions (ACLs), not group membership?

Group membership (script 04) is only half of privileged access. Accounts and groups holding dangerous rights through **ACLs** are effectively admins too, and they're often forgotten.

**Collects:** explicit permissions on the domain root, AdminSDHolder, the Domain Controllers OU, every OU and the protected groups, held by **non-default** trustees. The rights reported are:
- full control, modify permissions, take ownership and write all properties
- reset password, write members, write SPN, write key credential (shadow credentials) and write RBCD
- all extended rights, DCSync and read LAPS password

Each row has a severity: Critical on Tier 0 objects or for DCSync. The script also lists objects with a non-default owner, and gives a per-trustee summary. GUIDs are resolved from this forest's schema, so forest-specific attributes like the LAPS password are named correctly.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SkipOUs` | off | Tier 0 targets only |
| `-AdditionalTargets` | none | Extra DNs to review |
| `-IncludeInherited` | off | Also report inherited ACEs (noisy) |
| `-IncludeLowSeverity` | off | Include create / delete child object rights |

**Open first:** `summary.csv`, then `ad-delegations.csv` sorted by severity. Expand group trustees with script 04 or 05 to see who actually holds the rights.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-delegations.csv` | Risky right held by a non-default trustee on a target | `Target`, `Tier`, `Trustee`, `Right`, `AppliesTo`, `AppliesToObjects`, `Severity` |
| `ad-nondefault-owners.csv` | Target with a non-default owner | `Owner`, `Severity` |
| `ad-delegation-by-trustee.csv` | Trustee | `HighestSeverity`, `Rights`, `Tier0Targets`, `OUTargets` |

**Reading it:** severity is Critical for any right on a Tier 0 object (domain root, AdminSDHolder, DC OU, protected groups) and for DCSync anywhere. `AppliesToObjects` shows which object class an OU-level right applies to (e.g. ResetPassword on `user`).

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read (DACLs are readable by authenticated users on most objects) | RSAT AD |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One delegation you know exists (e.g. helpdesk reset-password on a user OU) appears with the right OU and trustee.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 18: many `(unresolved)` trustees | Deleted accounts or groups still in ACLs | These are clean-up items; confirm the SID is gone |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 17 AWS IAM posture](17-aws-iam-posture.md) · [All scripts](README.md) · [19 DC authentication protocols →](19-dc-authentication-protocols.md)
