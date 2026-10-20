# 15 - Rule-managed access

**Script:** [`15-Test-RuleManagedAccess.ps1`](../../scripts/15-Test-RuleManagedAccess.ps1) · **Version:** 1.0.0 · **Source:** AD + role files

> Are applied roles, HR-expected roles and actual group membership in step?

A drift check for rule-based access once roles are in place. It assumes each role maps to groups (role definition file), the JML automation records applied roles on the user in an attribute, and rule-managed groups are identifiable.

**Collects:**
- **Role-definition check:** groups that don't exist, groups not tagged as rule-managed, tagged groups that no role uses, and roles in the rule map that aren't defined.
- **Per-user reconciliation:**
  - applied roles, and HR-expected roles if a rule map is supplied
  - `RolesToAdd` / `RolesToRemove`, which show a mover that wasn't processed
  - unknown role codes
  - `MissingGroups`: groups required by an applied role that the user isn't in
  - `ExtraRuleGroups`: rule-managed groups the user is in that no applied role justifies
- **Drift detail:** one row per difference.

Run it on a schedule after go-live and the output becomes ongoing evidence that rule-based access is working.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-RoleDefinitionCsv` | required | `RoleCode,GroupName` ([template](../../examples/role-definitions.example.csv)) |
| `-RuleMapCsv` | none | `Attribute,Value,RoleCode`; `*,*` for everyone ([template](../../examples/rule-map.example.csv)) |
| `-AppliedRolesAttribute` | `extensionAttribute10` | Attribute holding applied roles; pick one with script 08 |
| `-Separator` | `;` | Separator inside that attribute |
| `-RuleManagedGroupRegex` | none | Identify rule-managed groups by name, e.g. `'^RB-'` |
| `-GroupTagAttribute` / `-GroupTagValues` | none / `Birthright`, `Department`, `JobCode` | Or identify them by an attribute on the group |
| `-OnlyDrift` | off | Write only users with differences |
| `-IncludeDisabled`, `-ExcludeNamePatterns` | | |

If neither a regex nor a tag is given, the groups in the role definition file are treated as rule-managed.

**Open first:** `role-definition-check.csv` (fix any issues first), then `summary.csv` and `drift-detail.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `role-definition-check.csv` | Role-group mapping, untagged or unused rule group, or undefined rule-map role | `Issue` (GroupNotFound / GroupNotTaggedRuleManaged / TaggedButNotInAnyRole / RoleInMapNotDefined) |
| `user-reconciliation.csv` | User | `AppliedRoles`, `ExpectedRoles`, `RolesToAdd`, `RolesToRemove`, `UnknownRoles`, `MissingGroups`, `ExtraRuleGroups`, `Issues`, `Status` |
| `drift-detail.csv` | Difference | `Type` (MissingGroup / ExtraRuleGroup / RoleToAdd / RoleToRemove) |

**Reading it:** `RolesToAdd` / `RolesToRemove` mean the user's HR attributes changed but the applied roles didn't, which is a mover the automation didn't process. `ExtraRuleGroups` means someone was added to a rule-managed group by hand, or kept it from an old role.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read; role files | RSAT AD |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: `role-definition-check.csv` has no unexpected issues; one user you know moved shows `RoleDrift` (once the attribute is in use).

Usually tuned on first run: Service / admin account name patterns (`-ServiceNamePatterns`, `-ExcludeNamePatterns`). See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 15: everyone shows drift | Applied-roles attribute not yet populated, or wrong attribute | Check `-AppliedRolesAttribute` with script 08 |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 14 IGA reconciliation](14-iga-reconciliation.md) · [All scripts](README.md) · [16 Device posture →](16-device-posture.md)
