# 22 - PIM role settings

**Script:** [`22-Get-PimRoleSettings.ps1`](../../scripts/22-Get-PimRoleSettings.ps1) · **Version:** 1.1.1 · **Source:** Entra PIM

> What does it actually take to activate each admin role or privileged group, and who approves it?

PIM only reduces risk if activation is hard enough. For every directory role this exports what activation requires:
- maximum duration
- MFA, justification and ticket number
- approval, the approvers resolved to accounts (approver groups expanded), and whether an approver is also eligible for the role
- authentication context, and whether an enabled Conditional Access policy actually enforces it (with that policy's grant)
- which notifications go to admins, approvers and requestors on activation and assignment

It also shows whether eligible or active assignments can be permanent, with active, activated-now and eligible counts and the number of effective holders (direct, group, eligible, PIM for Groups, group owners). The same settings are exported for PIM for Groups (member and owner) on every group that holds a role, every role-assignable group and any group in `-PimGroupIds`. Open PIM alerts for directory roles are exported when readable.

Roles are flagged when activation has no approval, has no MFA or enforced authentication context, lasts longer than the threshold, raises no admin alert, allows permanent assignment, or has an approver who is also eligible. Tier 0 roles get `Tier0`-prefixed flags; every other role with holders gets the same flags without the prefix.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-MaxActivationHours` | `8` | Longer activation is flagged |
| `-OnlyAssignedRoles` | off | Skip roles nobody holds |
| `-PimGroupIds` | none | Extra group object IDs whose PIM for Groups settings to read |
| `-SkipPimGroups` | off | Skip PIM for Groups settings |
| `-SkipAlerts` | off | Skip PIM alerts |

**Open first:** `pim-role-settings.csv`, with Tier 0 roles listed first, then `pim-group-settings.csv`. Azure resource roles are configured per scope and are not covered.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `pim-role-settings.csv` | Directory role | `MaxActivationHours`, `ActivationRequiresMfa`, `ActivationRequiresAuthContext`, `ApprovalRequired`, `Approvers`, `PermanentEligibleAllowed`, `PermanentActiveAllowed`, `ActiveAssignments`, `ActivatedNow`, `EligibleAssignments`, `EffectivePrincipals`, `ApproverAccounts`, `ApproverAlsoEligible`, `ApproverConflicts`, `AuthContextName`, `AuthContextEnforcedByCa`, `AuthContextGrant`, `NotifyAdminOnActivation`, `Flags` |
| `pim-group-settings.csv` | Group x access (member / owner) | Same columns as `pim-role-settings.csv`, plus `GroupId`, `GroupName`, `AccessId`, `WhyIncluded` |
| `pim-alerts.csv` | PIM alert | `AlertName`, `Severity`, `IsActive`, `IncidentCount`, `LastScannedUtc` |

**Reading it:**
- `ActiveAssignments` counts standing (assigned) assignments only; `ActivatedNow` counts eligible assignments that are activated at the time of the run.
- An authentication context only protects activation when `AuthContextEnforcedByCa` is `True`. When no enabled CA policy targets the context, the role is flagged `AuthContextNotEnforcedByCa` and the context does not count as MFA.
- `ApproverAlsoEligible` means at least one approver also holds the role (any path) - they can approve a request that leads to their own access path.
- In `pim-group-settings.csv`, `EligibleAssignments` counts eligible accounts for that access (groups expanded); `ActiveAssignments` is not collected for groups.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | RoleManagementPolicy.Read.Directory, RoleManagement.Read.Directory, Directory.Read.All, Policy.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup (+ RoleManagementPolicy.Read.AzureADGroup, RoleManagementAlert.Read.Directory) | - | Graph Auth |

Brackets mean only with the matching optional switch (on by default; `-SkipPimGroups`, `-SkipAlerts` drop them). Full detail: [permissions](../permissions.md). PIM alerts use the beta endpoint.

## Pilot check

Before handing this script to others, confirm: Global Administrator settings in PIM > Entra roles > Settings; one role-holding group's settings in PIM > Groups match `pim-group-settings.csv`.

Usually tuned on first run: `-MaxActivationHours` to match the agreed standard. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scripts 20-22: datasets `EvidenceUnavailable` | No Entra ID P2 / ID Governance | Record as a finding |
| `pim-group-settings` `Blocked` | RoleManagementPolicy.Read.AzureADGroup not granted | Grant it, or run with `-SkipPimGroups` |
| `pim-alerts` `Blocked` | RoleManagementAlert.Read.Directory not granted | Grant it, or run with `-SkipAlerts` |
| `AuthContextEnforcedByCa` starts with `Unknown` | CA policies not readable | Grant Policy.Read.All |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 21 Identity risk](21-identity-risk.md) · [All scripts](README.md) · [23 AD attribute population →](23-ad-attribute-population.md)
