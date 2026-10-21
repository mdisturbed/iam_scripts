# 22 - PIM role settings

**Script:** [`22-Get-PimRoleSettings.ps1`](../../scripts/22-Get-PimRoleSettings.ps1) · **Version:** 1.0.0 · **Source:** Entra PIM

> What does it actually take to activate each admin role?

PIM only reduces risk if activation is hard enough. For every directory role this exports what activation requires:
- maximum duration
- MFA, justification and ticket number
- approval and the approvers
- authentication context

It also shows whether eligible or active assignments can be permanent, with assignment counts. Tier 0 roles are flagged when activation has no approval, has no MFA or authentication context, lasts longer than the threshold, or permanent assignment is allowed.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-MaxActivationHours` | `8` | Longer Tier 0 activation is flagged |
| `-OnlyAssignedRoles` | off | Skip roles nobody holds |

**Open first:** `pim-role-settings.csv`, with Tier 0 roles listed first. Covers directory roles only; PIM for Groups and Azure resource roles are configured per group or scope.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `pim-role-settings.csv` | Directory role | `MaxActivationHours`, `ActivationRequiresMfa`, `ActivationRequiresAuthContext`, `ApprovalRequired`, `Approvers`, `PermanentEligibleAllowed`, `PermanentActiveAllowed`, assignment counts, `Flags` |

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | RoleManagementPolicy.Read.Directory, RoleManagement.Read.Directory | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Global Administrator settings in PIM > Entra roles > Settings.

Usually tuned on first run: `-MaxActivationHours` to match the agreed standard. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scripts 20-22: datasets `EvidenceUnavailable` | No Entra ID P2 / ID Governance | Record as a finding |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 21 Identity risk](21-identity-risk.md) · [All scripts](README.md) · [23 AD attribute population →](23-ad-attribute-population.md)
