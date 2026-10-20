# 07 - Role mining

**Script:** [`07-Get-RoleMiningCandidates.ps1`](../../scripts/07-Get-RoleMiningCandidates.ps1) · **Version:** 1.0.0 · **Source:** AD

> Which groups do people in the same department or job code share, and is the HR data clean enough to drive roles?

Supports the move to RBAC (birthright → department roles → job-code roles). For each value of each grouping attribute, it measures how many people in that population hold each group.

**Collects:**
- **Attribute quality:** blank %, distinct values, and values spelled more than one way (`IT` vs `I.T.`, `Finance` vs `finance`). Rule-based roles only work on clean attributes, and this shows whether the data can carry them.
- **Populations:** the size of each department or job-code group.
- **Birthright candidates:** groups held by almost everyone (default 90%+).
- **Role candidates:** groups held by most of one population (default 80%+), with lift against the overall rate.
- **Outliers:** people missing a group their peers have, and people holding a group that is rare in their population and overall. These are questions for managers, not findings.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-GroupingAttributes` | `department`, `title` | Attributes that define populations; add the job-code attribute |
| `-MinPopulation` | `5` | Smaller populations are listed but not mined |
| `-RoleThreshold` | `0.8` | Share of a population that makes a group a role candidate |
| `-CommonThreshold` | `0.5` | Minimum share to appear in `role-candidates.csv` |
| `-BirthrightThreshold` | `0.9` | Share of all users that makes a group a birthright candidate |
| `-OutlierThreshold` | `0.1` | "Rare" for uncommon-access outliers |
| `-ExcludeNamePatterns` | service/admin patterns | Accounts left out of mining |
| `-ExcludeGroupRegex` | none | Groups left out, e.g. `'^(All Staff|Everyone)'` |
| `-ExpandNested` | off | Count access through nested groups too |
| `-NormalizeValues` | off | Treat `IT` and `it ` as one population once variants are confirmed cosmetic |
| `-IncludeDisabled`, `-IncludeDistributionGroups`, `-SkipOutliers` | off | |

**Open first:** `attribute-quality.csv` and `attribute-value-variants.csv` (fix the data first), then `birthright-candidates.csv` and `role-candidates.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `attribute-quality.csv` | Grouping attribute | `BlankPct`, `DistinctRawValues`, `DistinctNormalizedValues`, `ValuesWithSpellingVariants`, `PopulationsMeetingMin` |
| `attribute-value-variants.csv` | Normalised value | `VariantCount`, `Variants` (each raw spelling with its count) |
| `populations.csv` | Attribute value | `Users`, `MeetsMinPopulation` |
| `birthright-candidates.csv` | Group held by almost everyone | `Holders`, `PctOfAllUsers` |
| `role-candidates.csv` | Group held by at least `-CommonThreshold` of a population | `PctInPopulation`, `PctOfAllUsers`, `Lift`, `Classification` (BirthrightCandidate / RoleCandidate / Common) |
| `outliers.csv` | User + group | `Type` (MissingRoleCandidate / UncommonAccess) |

**Reading it:** fix the attribute data before designing roles. A `VariantCount` above 1 means the same department or job code is spelled more than one way, which splits populations and breaks rule-based assignment. `Lift` near 1 means a group is common everywhere, not specific to that population, so it's more likely birthright than a department role.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read | RSAT AD |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Size of one department population vs an HR headcount; one group you know every member of that department has.

Usually tuned on first run: Service / admin account name patterns (`-ServiceNamePatterns`, `-ExcludeNamePatterns`); `-GroupingAttributes` (add the job-code attribute), `-MinPopulation`, thresholds. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 07: almost no populations meet the minimum | Attribute values inconsistent or too granular | Read `attribute-value-variants.csv`; try `-NormalizeValues` or a lower `-MinPopulation` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 06 JML timing](06-jml-timing.md) · [All scripts](README.md) · [08 Extension attribute inventory →](08-extension-attribute-inventory.md)
