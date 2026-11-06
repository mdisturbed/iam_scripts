# 33 - CA policy analysis

**Script:** [`33-Get-CaPolicyAnalysis.ps1`](../../scripts/33-Get-CaPolicyAnalysis.ps1) · **Version:** 1.0.0 · **Source:** a script 28 snapshot (+ 27, 01)

> For every Conditional Access policy: what is its scope, control, exclusions, state and dependencies? And where are the gaps, overlaps and conflicts between policies?

Analyses a script 28 snapshot offline. It gives one inventory row per policy and one issue row per gap, overlap, conflict or hygiene problem, each with a severity and a recommendation. It doesn't change or test anything, and it connects to nothing.

**Collects:** from 28: every policy (raw JSON for comparison, names from the CSV), named locations, authentication strengths and security defaults. From 27 (optional): the break-glass accounts, so the script can check each policy excludes them. From 01 (optional): members of excluded groups, for group sizes and for break-glass exclusion through a group.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-EvidenceRoot` | `-OutputRoot` | Folder holding the earlier runs |
| `-SnapshotRunFolder` | latest 28 run | Pin the snapshot to analyse (for example the frozen pre-change baseline) |
| `-PopulationRunFolder`, `-MfaRunFolder` | latest run | Pin the 27 or 01 run |
| `-BreakGlassUpns` | (none) | Break-glass UPNs, in addition to 27's `BreakGlass` accounts |
| `-ReportOnlyMaxDays` | `30` | Report-only policies untouched for longer are `ReportOnlyStale` |
| `-DisabledMaxDays` | `90` | Disabled policies untouched for longer are `DisabledStale` |
| `-BroadExclusionThreshold` | `25` | Excluded groups with more members are `BroadExclusion` |
| `-AllowHashMismatch` | off | Use a source file that changed after its run |

**Open first:** `ca-policy-issues.csv` (sorted by severity), then `ca-coverage-checks.csv`, then `ca-policy-inventory.csv`.

```powershell
.\scripts\33-Get-CaPolicyAnalysis.ps1 -OutputRoot D:\Evidence
.\scripts\33-Get-CaPolicyAnalysis.ps1 -OutputRoot D:\Evidence -BreakGlassUpns bg1@contoso.com, bg2@contoso.com
```

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ca-policy-inventory.csv` | Policy | `PolicyId`, `PolicyName`, `State`, `ModifiedUtc`, `Purpose`, `ScopeUsers`, `ScopeApps`, `ScopeConditions`, `GrantControls`, `SessionControls`, `Exclusions`, `ExclusionCount`, `Dependencies`, `DeletedDependencies`, `IssueCount`, `Issues`, `HighestSeverity`, `PolicyHash` |
| `ca-policy-issues.csv` | Issue | `IssueId` (CA-001 …), `Category`, `Severity`, `Code`, `Policies`, `PolicyIds`, `PolicyStates`, `Detail`, `Recommendation`, `Reference` |
| `ca-policy-dependencies.csv` | Policy and referenced object | `PolicyName`, `PolicyState`, `Usage` (Include / Exclude / Grant), `ObjectType` (User / Group / Role / Application / NamedLocation / AuthenticationStrength / TermsOfUse / AuthenticationContext), `ObjectId`, `ObjectName`, `Resolved`, `Detail` |
| `ca-coverage-checks.csv` | Tenant baseline check | `Check`, `Reference`, `Result` (Pass / Gap / ReportOnlyOnly / Partial / NotAssessed), `SatisfiedBy`, `ReportOnlyCandidates`, `Note` |
| `source-runs.csv` | Source dataset read | `Script`, `Dataset`, `RunFolder`, `SourceStatus`, `HashCheck`, `UsedAs` |

Issue codes:

| Category | Code | Severity | Meaning |
|----------|------|----------|---------|
| Gap | `NoMfaForAllUsers`, `LegacyAuthNotBlocked`, `NoAdminMfa` | High | Tenant baseline missing (CISA MS.AAD.3.2, 1.1) |
| Gap | `NoPhishResistantAdminMfa`, `DeviceCodeFlowNotBlocked`, `NoUserRiskPolicy`, `NoSignInRiskPolicy`, `NoGuestMfa` | Medium | (CISA MS.AAD.3.6, 3.9, 2.1, 2.3) |
| Gap | `SecurityInfoRegistrationUnprotected` | Low | Register security info not protected (CISA MS.AAD.3.8) |
| Conflict | `BlockShadowsPolicy` | High | A block policy covers every sign-in another enabled policy covers, so that policy can never grant access |
| Conflict | `IncludeExcludeSameObject` | Medium | The same object is included and excluded (exclude wins) |
| Conflict | `SessionFrequencyConflict` | Low | Different sign-in frequencies for the same sign-ins |
| Overlap | `Duplicate`, `RedundantPolicy` | Low | Same configuration; or same controls for a subset of another policy's sign-ins |
| Overlap | `SameScopeDifferentControls`, `ReportOnlyCopy` | Info | Same scope, different controls (both apply); report-only copy of an enabled policy |
| Exclusion | `BreakGlassNotExcluded` | High | An enabled policy with a control applies to a break-glass account (Maester MT.1005) |
| Exclusion | `ExclusionNoFallback`, `BroadExclusion`, `TrustedLocationBypass` | Medium | Excluded object has no other MFA or block policy that covers the same sign-ins (MT.1036). Break-glass accounts, and groups whose only members are break-glass accounts, are skipped. Also: excluded group above the threshold; MFA skipped from trusted locations |
| Exclusion | `BaselineExcludesApps` | Low | The MFA baseline excludes apps |
| Hygiene | `DeletedReference` | Medium | Refers to a user, group or app that no longer exists (MT.1038) |
| Hygiene | `ReportOnlyStale`, `NoControls`, `SecurityDefaultsWithCa` | Low | |
| Hygiene | `DisabledStale` | Info | |

**Reading it:**
- **Comparison is exact, not a simulation.** Policy A *covers* policy B when every condition of A is unset or the same as B's, A's includes are a superset of B's and A's excludes a subset. A condition the script doesn't model (for example insider risk) must be identical in both, or A doesn't cover B. Policies that only partly overlap aren't reported. Script 24 (report-only impact) and the What If tool answer sign-in level questions.
- **Group membership isn't known** beyond the excluded groups that 01 expanded, so two policies that target different groups with the same people aren't seen as overlapping.
- **Break-glass** is checked only when the accounts are known (27 category `BreakGlass`, or `-BreakGlassUpns`). Every enabled policy with a control that targets All users, names the account, or targets groups or roles is checked. Group and role targeting shows as *Unverified*, because membership isn't known offline, and so does an exclusion through a group when 01 hasn't run. A `-BreakGlassUpns` account that no policy refers to is reported as not excluded from every All-users policy; check the UPN is spelled as in Entra.
- **`Resolved` = False** means the object no longer existed when 28 ran (or couldn't be read). A deleted excluded group is usually an old exception nobody cleaned up.
- **Pass on a check** means an enabled policy meets it as written. It doesn't mean nobody is excluded; see `ExclusionNoFallback` and script 32 for that.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| none | none | Read access to the evidence folder (a 28 run; 27 and 01 optional) | none |

## Pilot check

The policy count and states in `summary.csv` match **Entra > Conditional Access > Policies**. Pick one issue of each category and confirm it in the portal. For `BlockShadowsPolicy`, check the What If tool for one user in scope of both policies.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 33: `The CA policy snapshot ... is needed` | No usable 28 run | Run 28 into the same evidence folder |
| Script 33: names show as IDs | 28 ran with `-ResolveNames $false`, or its `ca-policies.csv` isn't usable | Rerun 28 with names |
| Script 33: break-glass check `NotAssessed` | No break-glass accounts known | Run 27 with `-BreakGlassUpns`, or pass `-BreakGlassUpns` here |
| Script 33: an expected overlap is missing | The policies differ in a condition, or only partly overlap | By design: only full coverage is reported |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 32 MFA effectiveness](32-mfa-effectiveness.md) · [All scripts](README.md) · [34 Privileged register →](34-privileged-register.md)
