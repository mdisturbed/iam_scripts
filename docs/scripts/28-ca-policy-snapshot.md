# 28 - CA policy snapshot

**Script:** [`28-Export-CaPolicySnapshot.ps1`](../../scripts/28-Export-CaPolicySnapshot.ps1) · **Version:** 1.0.0 · **Source:** Entra Conditional Access and authentication policies

> What exactly is the Conditional Access configuration right now, and what changed since the last snapshot?

This is the frozen baseline before a change, the rollback artifact and the before/after proof. Take a snapshot before an approved Conditional Access or MFA change and another one after it, then compare the two. After a rollback, a snapshot compared with the pre-change baseline should show every policy as `Unchanged`.

**Collects:** every Conditional Access policy, named location and authentication strength (built-in and custom), the authentication methods policy with its method configurations, and the security defaults policy. Each is written as JSON exactly as read (IDs, not names), plus CSV files with one row per policy, location and strength. With `-BaselineRunFolder`, every item is compared by ID with an earlier snapshot: Added, Removed, Changed (with the paths that differ) or Unchanged.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-BaselineRunFolder` | none | An earlier run folder of this script (the one holding its `run-manifest.json`). Adds the drift files |
| `-ResolveNames` | `$true` | Show user, group, role, app and named location names instead of IDs in `ca-policies.csv`. `-ResolveNames $false` gives raw IDs and a faster run. The JSON always holds raw IDs |

**Open first:** `summary.csv` (*Configuration identical to baseline*, and policies added / removed / changed), then `ca-policy-drift.csv` filtered on `ChangeType` not `Unchanged`: `ChangedPaths` says exactly what moved. Without a baseline, `ca-policies.csv` is the readable copy of the configuration.

Common parameters (`-OutputRoot`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ca-policies.json` | Policy (raw array) | Graph `conditionalAccessPolicy` as read, sorted by `id` |
| `ca-policies.csv` | Policy | `PolicyId`, `DisplayName`, `State`, `CreatedUtc`, `ModifiedUtc`, `IncludeUsers`, `ExcludeUsers`, `IncludeGroups`, `ExcludeGroups`, `IncludeRoles`, `ExcludeRoles`, `IncludeGuestsOrExternal`, `ExcludeGuestsOrExternal`, `IncludeApplications`, `ExcludeApplications`, `UserActions`, `AuthContexts`, `ClientAppTypes`, `Platforms`, `Locations`, `SignInRisk`, `UserRisk`, `DeviceFilter`, `GrantOperator`, `BuiltInControls`, `AuthenticationStrength`, `TermsOfUse`, `SessionControls`, `PolicyHash` |
| `named-locations.json` / `.csv` | Named location | `LocationId`, `DisplayName`, `LocationType` (ipNamedLocation / countryNamedLocation), `IsTrusted`, `IpRanges`, `Countries`, `IncludeUnknownCountries`, `CountryLookupMethod`, `CreatedUtc`, `ModifiedUtc`, `UsedByPolicies`, `LocationHash` |
| `authentication-strengths.json` / `.csv` | Authentication strength | `StrengthId`, `DisplayName`, `PolicyType` (builtIn / custom), `RequirementsSatisfied`, `AllowedCombinations`, `Description`, `CreatedUtc`, `ModifiedUtc`, `UsedByPolicies`, `StrengthHash` |
| `authentication-methods-policy.json` | The policy (one object) | Method configurations, registration campaign, `policyMigrationState` |
| `security-defaults.json` | The policy (one object) | `isEnabled` |
| `ca-policy-drift.csv` | Policy in either snapshot | `PolicyId`, `PolicyName`, `ChangeType` (Added / Removed / Changed / Unchanged), `ChangedPaths`, `BaselineState`, `CurrentState`, `BaselineModifiedUtc`, `CurrentModifiedUtc` |
| `named-location-drift.csv` | Named location in either snapshot | `LocationId`, `LocationName`, `LocationType`, `ChangeType`, `ChangedPaths`, `BaselineIsTrusted`, `CurrentIsTrusted`, `BaselineModifiedUtc`, `CurrentModifiedUtc` |
| `authentication-strength-drift.csv` | Authentication strength in either snapshot | `StrengthId`, `StrengthName`, `PolicyType`, `ChangeType`, `ChangedPaths`, `BaselineModifiedUtc`, `CurrentModifiedUtc` |
| `auth-methods-drift.csv` | Methods policy, each method configuration, security defaults | `Item` (authenticationMethodsPolicy / method:&lt;id&gt; / securityDefaults), `ChangeType`, `ChangedPaths`, `BaselineState`, `CurrentState` |

The JSON files are listed in `dataset-status.csv` as `<name>-json` (for example `ca-policies-json`), with their SHA-256 like the CSV files. Without `-BaselineRunFolder` the drift datasets are `Deferred`.

**Reading it:**
- **Stable JSON.** Objects are sorted by `id`, properties by name, and dates are written as UTC ISO 8601. Two snapshots of an unchanged configuration give the same JSON, apart from the volatile fields below.
- **Volatile fields** change without a configuration change (an edit that was later reverted, or a service update). They stay in the JSON files but are left out of every hash and every drift comparison: `modifiedDateTime` on policies, named locations and authentication strengths; `createdDateTime` and `modifiedDateTime` of an authentication strength embedded in a policy's `grantControls`; and `lastModifiedDateTime` on the authentication methods policy. The file SHA-256 of two unchanged snapshots can still differ because of these fields. Compare `PolicyHash` or the drift files, not the file hash.
- **PolicyHash** (also `LocationHash` and `StrengthHash`) is the SHA-256 of a canonical JSON form of that one item. In that form, null and empty values are dropped, list order is ignored and volatile fields are left out. The same hash in two snapshots means the same configuration.
- **ChangedPaths** are dot paths to the values that differ, such as `conditions.users.excludeGroups` or `state`. A list is reported by its own path, not by item, and list order doesn't count as a change. A value that went from empty to set, or the other way round, is listed too.
- **Removed** means the policy is in the baseline but not in the current read. If the current policy read failed, the drift is Blocked rather than showing everything as Removed.
- **The baseline is checked before use.** It must be a run of this script, and each baseline JSON file must still match the SHA-256 recorded in that run's `dataset-status.csv`. A changed file, or a file that was Blocked in the baseline run, makes that drift dataset Blocked with the reason. The rest of the run still completes. The baseline folder, its `run-manifest.json` SHA-256 and the hash of each baseline file used are recorded under `Extra` in `run-manifest.json`.
- **Names are in the CSV only.** An ID that can't be resolved (deleted object, or no read access) shows as `<id> (unresolved)`, and `ca-policies.csv` is then Partial. The JSON always holds the raw IDs, so drift isn't affected by naming.
- **Rollback proof.** Take snapshot A before the change and snapshot B after the rollback. Run B with `-BaselineRunFolder` set to A. *Configuration identical to baseline* = `True` is the proof. Blank means that some part couldn't be compared (see `dataset-status.csv`).

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader or Security Reader | Policy.Read.All; Directory.Read.All and Application.Read.All for name resolution | Read access to the baseline run folder | Graph Auth |

Conditional Access needs Entra ID P1. Without it, the Conditional Access datasets are EvidenceUnavailable. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm two things. One policy's row in `ca-policies.csv` should match **Entra > Conditional Access > Policies** for that policy. And two runs a few minutes apart, with no change in between, should show *Configuration identical to baseline* = `True`.

Usually tuned on first run: nothing. Run it without a baseline first, then use that folder as the baseline. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 28: Conditional Access datasets EvidenceUnavailable | No Entra ID P1 | Record as a finding |
| Script 28: datasets Blocked (403) | Account can't read policies | Global Reader / Security Reader, or `Policy.Read.All` |
| Script 28: drift Blocked, *Baseline not usable* | Folder missing, not a run of this script, or no `run-manifest.json` | Point `-BaselineRunFolder` at the run folder itself (`...\28-CaPolicySnapshot\<yyyyMMdd-HHmmssZ>`) |
| Script 28: drift Blocked, *SHA-256 does not match* | A baseline JSON file was edited after its run | Use an untouched copy of the baseline run folder |
| Script 28: names show `(unresolved)` | Deleted object, or no Directory.Read.All / Application.Read.All | Expected for deleted objects; otherwise add the scope, or use `-ResolveNames $false` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 27 Identity population](27-identity-population.md) · [All scripts](README.md) · [29 Pilot outcome →](29-pilot-outcome.md)
