# 15 - Rule-managed access

**Script:** [`15-Test-RuleManagedAccess.ps1`](../../scripts/15-Test-RuleManagedAccess.ps1) · **Version:** 1.1.0 · **Source:** AD + role files

> Are applied roles, HR-expected roles and actual group membership in step, and who is in a rule-managed group who shouldn't be?

A drift check for rule-based access once roles are in place. It assumes each role maps to groups (role definition file), the JML automation records applied roles on the user in an attribute, and rule-managed groups are identifiable.

**Collects:**
- **Role-definition check:** groups that don't exist or whose name matches more than one group, groups not tagged as rule-managed, tagged groups that no role uses, roles in the rule map that aren't defined, and rule-map attributes that aren't in the AD schema.
- **Per-user reconciliation** (enabled and disabled users; disabled users are evaluated by default and shown with `Enabled = False`):
  - applied roles, and HR-expected roles if a rule map is supplied
  - `RolesToAdd` / `RolesToRemove`, which show a mover that wasn't processed
  - unknown role codes
  - `MissingGroups`: groups required by an applied role that the user isn't in
  - `ExtraRuleGroups`: rule-managed groups the user is in that no applied role justifies
  - `DisabledHoldsRuleGroups`: a disabled account, usually a leaver, still in rule-managed groups
- **Drift detail:** one row per difference.
- **Group side:** every member of every rule-managed group that isn't an evaluated, enabled user: disabled accounts, users outside `-SearchBase`, service/admin-named accounts, nested groups, computers and foreign security principals.

Groups are matched by distinguished name. A `GroupName` in the role definition file is resolved as a distinguished name, then `sAMAccountName`, then name; a name that matches several groups is flagged `AmbiguousGroupName`.

Run it on a schedule after go-live and the output becomes ongoing evidence that rule-based access is working.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-RoleDefinitionCsv` | required | `RoleCode,GroupName` ([template](../../examples/role-definitions.example.csv)). `GroupName` can be a DN, sAMAccountName or name |
| `-RuleMapCsv` | none | `Attribute,Value,RoleCode`; `*,*` for everyone ([template](../../examples/rule-map.example.csv)). One attribute per row; rows for the same role are alternatives (OR). Rules that need two attributes together (AND) aren't supported by this format |
| `-AppliedRolesAttribute` | `extensionAttribute10` | Attribute holding applied roles; pick one with script 08 |
| `-Separator` | `;` | Separator inside that attribute |
| `-RuleManagedGroupRegex` | none | Identify rule-managed groups by name, e.g. `'^RB-'` |
| `-GroupTagAttribute` / `-GroupTagValues` | none / `Birthright`, `Department`, `JobCode` | Or identify them by an attribute on the group |
| `-OnlyDrift` | off | Write only users with differences |
| `-EnabledOnly` | off | Evaluate enabled users only. Disabled users are evaluated by default (this changed: they used to need `-IncludeDisabled`) |
| `-IncludeDisabled` | | Deprecated and ignored; kept so existing command lines still run |
| `-ExcludeNamePatterns` | service/admin patterns | Accounts not evaluated; still listed on the group side |

If neither a regex nor a tag is given, the groups in the role definition file are treated as rule-managed.

**Open first:** `role-definition-check.csv` (fix any issues first), then `summary.csv`, `rule-group-unexpected-members.csv` and `drift-detail.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `role-definition-check.csv` | Role-group mapping, untagged or unused rule group, undefined rule-map role, or rule-map attribute missing from the schema | `Issue` (GroupNotFound / AmbiguousGroupName / GroupNotTaggedRuleManaged / TaggedButNotInAnyRole / RoleInMapNotDefined / AttributeNotInSchema) |
| `user-reconciliation.csv` | User | `Enabled`, `AppliedRoles`, `ExpectedRoles`, `RolesToAdd`, `RolesToRemove`, `UnknownRoles`, `MissingGroups`, `ExtraRuleGroups`, `Issues`, `Status` |
| `drift-detail.csv` | Difference | `Type` (MissingGroup / ExtraRuleGroup / RoleToAdd / RoleToRemove / DisabledHoldsRuleGroup) |
| `rule-group-unexpected-members.csv` | Member of a rule-managed group that isn't an evaluated, enabled user | `Group`, `RoleCodes`, `Member`, `Reason` (DisabledMember / OutOfScopeMember / ExcludedNameMember / NestedGroup / Computer / FSP / ManagedServiceAccount / Unresolved), `Enabled` |

**Reading it:** `RolesToAdd` / `RolesToRemove` mean the user's HR attributes changed but the applied roles didn't, which is a mover the automation didn't process. `ExtraRuleGroups` means someone was added to a rule-managed group by hand, or kept it from an old role. `DisabledHoldsRuleGroups` and `DisabledMember` rows are leavers whose access returns if the account is re-enabled. A `NestedGroup` row means everyone in that group inherits the rule-managed access without any rule granting it.

If a rule-map attribute isn't in the schema, its rules are skipped and role drift for the roles it grants isn't reported (see `role-definition-check.csv`); the rest of the run continues.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read (including the schema partition); role files | RSAT AD |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: `role-definition-check.csv` has no unexpected issues; one user you know moved shows `RoleDrift` (once the attribute is in use); one leaver you know of appears with `DisabledHoldsRuleGroups`.

Usually tuned on first run: Service / admin account name patterns (`-ServiceNamePatterns`, `-ExcludeNamePatterns`). See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 15: everyone shows drift | Applied-roles attribute not yet populated, or wrong attribute | Check `-AppliedRolesAttribute` with script 08 |
| Script 15: `Attribute '…' (-AppliedRolesAttribute) is not in the AD schema` | Typo or attribute not present in this forest | Pick an existing attribute with script 08 |
| Script 15: `AttributeNotInSchema` row | A rule-map attribute name is wrong | Fix the `Attribute` column; those rules are skipped until then |
| Script 15: `AmbiguousGroupName` row | Two groups share the name used in the role file | Use the sAMAccountName or DN in `GroupName` |
| Script 15: many `Unresolved` members | Member objects not readable, or deleted | Check the DNs; the note gives the lookup error |
| Script 15: log says the schema isn't readable | Schema partition read denied | Attributes are probed one at a time instead; results are the same |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 14 IGA reconciliation](14-iga-reconciliation.md) · [All scripts](README.md) · [16 Device posture →](16-device-posture.md)
