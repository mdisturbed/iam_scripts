# 07 - Role mining

**Script:** [`07-Get-RoleMiningCandidates.ps1`](../../scripts/07-Get-RoleMiningCandidates.ps1) · **Version:** 1.1.0 · **Source:** AD

> Which groups do people in the same department or job code share, who has far more access than their peers, and is the HR data clean enough to drive roles?

Supports the move to RBAC (birthright → department roles → job-code roles). For each value of each grouping attribute, it measures how many people in that population hold each group.

Membership is resolved down to the account: direct membership, the primary group (`primaryGroupID`, normally Domain Users) and access inherited through nested groups all count by default. Use `-DirectOnly` to count direct membership and the primary group only. Groups are keyed by distinguished name, so two groups with the same name in different OUs stay separate; their labels carry the parent container.

**Collects:**
- **Attribute quality:** blank %, distinct values, and values spelled more than one way (`IT` vs `I.T.`, `Finance` vs `finance`). Rule-based roles only work on clean attributes, and this shows whether the data can carry them.
- **Populations:** the size of each department or job-code group.
- **Birthright candidates:** groups held by almost everyone (default 90%+).
- **Role candidates:** groups held by most of one population (default 80%+), with lift against the overall rate.
- **Layered populations:** with `-LayeredAttributes department,title`, the combined key (`Dept1|Title1`) is mined the same way, so a group held by every analyst in Finance shows even when the department as a whole doesn't qualify.
- **Outliers:** people missing a group their peers have, and people holding a group that is rare in their population and overall. These are questions for managers, not findings.
- **Access load:** each person's group count against the median of their peer population (the first grouping attribute). People with more than `-AccessLoadRatio` times the peer median and more than `-AccessLoadMinGroups` groups are flagged `HighAccessForPeers`.
- **Excluded accounts:** accounts left out of the mining by `-ExcludeNamePatterns` (service, admin, test), listed with their groups so admin accounts are never invisible.
- **No-population users:** people with a blank grouping attribute, listed with their groups. They can't receive a role by rule.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-GroupingAttributes` | `department`, `title` | Attributes that define populations; add the job-code attribute. The first is also the peer population for access load |
| `-LayeredAttributes` | none | Two or more attributes mined as one combined key, e.g. `department,title` |
| `-MinPopulation` | `5` | Smaller populations are listed but not mined; access load falls back to all users |
| `-RoleThreshold` | `0.8` | Share of a population that makes a group a role candidate |
| `-CommonThreshold` | `0.5` | Minimum share to appear in `role-candidates.csv` |
| `-BirthrightThreshold` | `0.9` | Share of all users that makes a group a birthright candidate |
| `-OutlierThreshold` | `0.1` | "Rare" for uncommon-access outliers |
| `-AccessLoadRatio` | `2` | Multiple of the peer median that flags `HighAccessForPeers` |
| `-AccessLoadMinGroups` | `10` | Minimum group count before anyone is flagged |
| `-ExcludeNamePatterns` | service/admin patterns | Accounts left out of the mining math (listed in `excluded-accounts.csv`) |
| `-ExcludeGroupRegex` | none | Groups left out, e.g. `'^(All Staff|Everyone)'` |
| `-DirectOnly` | off | Count direct membership and the primary group only. Nested membership is counted by default |
| `-ExpandNested` | | Deprecated and ignored (nested is the default); kept so existing command lines still run |
| `-NormalizeValues` | off | Treat `IT` and `it ` as one population once variants are confirmed cosmetic |
| `-IncludeDisabled`, `-IncludeDistributionGroups`, `-SkipOutliers` | off | |

**Open first:** `attribute-quality.csv` and `attribute-value-variants.csv` (fix the data first), then `excluded-accounts.csv` and `access-load.csv`, then `birthright-candidates.csv` and `role-candidates.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `attribute-quality.csv` | Grouping attribute (and layered key) | `BlankPct`, `DistinctRawValues`, `DistinctNormalizedValues`, `ValuesWithSpellingVariants`, `PopulationsMeetingMin` |
| `attribute-value-variants.csv` | Normalised value | `VariantCount`, `Variants` (each raw spelling with its count) |
| `populations.csv` | Attribute value | `Users`, `MeetsMinPopulation` |
| `birthright-candidates.csv` | Group held by almost everyone | `Holders`, `PctOfAllUsers`, `NestedHolders`, `GroupDistinguishedName` |
| `role-candidates.csv` | Group held by at least `-CommonThreshold` of a population | `PctInPopulation`, `PctOfAllUsers`, `Lift`, `Classification` (BirthrightCandidate / RoleCandidate / Common), `NestedHolders`, `GroupDistinguishedName`. Layered rows have `Attribute` = `department|title` |
| `outliers.csv` | User + group | `Type` (MissingRoleCandidate / UncommonAccess), `MembershipSource` (Direct / Nested), `GroupDistinguishedName` |
| `access-load.csv` | In-scope user | `GroupCount`, `DirectGroupCount`, `NestedGroupCount`, `PeerPopulation`, `PeerMedian`, `Ratio`, `ZScore`, `Flag` (HighAccessForPeers) |
| `excluded-accounts.csv` | Account matching `-ExcludeNamePatterns` | `MatchedPattern`, `GroupCount`, `Groups` |
| `no-population-users.csv` | User with a blank grouping attribute | `BlankAttributes`, `GroupCount`, `Groups` |

`Groups` lists are sorted, mark nested-only memberships with `(nested)`, and stop at 50 with a `(+N more)` count. Group labels are the group name, with the parent container in brackets when another group has the same name.

**Reading it:** fix the attribute data before designing roles. A `VariantCount` above 1 means the same department or job code is spelled more than one way, which splits populations and breaks rule-based assignment. `Lift` near 1 means a group is common everywhere, not specific to that population, so it's more likely birthright than a department role. A high `NestedHolders` means the access comes through group nesting, so a role built on it should target the parent group. `HighAccessForPeers` rows and the admin rows in `excluded-accounts.csv` are the first places to look for access creep.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read | RSAT AD |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Size of one department population vs an HR headcount; one group you know every member of that department has; one admin account appears in `excluded-accounts.csv` with its groups.

Usually tuned on first run: Service / admin account name patterns (`-ServiceNamePatterns`, `-ExcludeNamePatterns`); `-GroupingAttributes` (add the job-code attribute), `-MinPopulation`, thresholds. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 07: almost no populations meet the minimum | Attribute values inconsistent or too granular | Read `attribute-value-variants.csv`; try `-NormalizeValues` or a lower `-MinPopulation` |
| Script 07: Domain Users (or another primary group) is a birthright candidate | The primary group is counted as direct membership | Expected; exclude it with `-ExcludeGroupRegex '^Domain Users$'` if it clutters the results |
| Script 07: role-candidate counts higher than a direct-membership view | Nested membership is counted by default | Compare `NestedHolders`; use `-DirectOnly` for the direct view |
| Script 07: log warns a primaryGroupID matched no group | The primary group is outside the groups read, or not a security group | Check the user's primary group; the rest of their membership is still counted |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 06 JML timing](06-jml-timing.md) · [All scripts](README.md) · [08 Extension attribute inventory →](08-extension-attribute-inventory.md)
