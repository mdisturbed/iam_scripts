# 32 - MFA effectiveness

**Script:** [`32-Get-MfaEffectiveness.ps1`](../../scripts/32-Get-MfaEffectiveness.ps1) · **Version:** 1.3.0 · **Source:** earlier runs of 01 and 27 (+ exception register)

> Out of the agreed population, how many identities are actually protected by MFA, who is excluded and why, where did MFA fail in practice, and which evidence does each number come from?

Turns script 01's raw MFA data into measures with a defensible denominator. Each figure is reported as value, denominator and percent, with the definition, the source runs and a status. Connects to nothing: it reads earlier run folders and checks every file's SHA-256 against the hash its run recorded.

**Collects:** (01's `ca-included-scope-members` is also read when present, to resolve group- and role-targeted MFA policies.) For every identity in a population: MFA registration and method strength (01), whether a baseline MFA policy enforces MFA for it or it is excluded (by user, group, role or guest type), successful single-factor sign-ins, and the resulting state. The populations come from script 27: human workforce, admin accounts, guests and external members, and break-glass accounts. Enabled Entra role holders (01 `IsPrivileged`) are added as a fifth population. Also lists every exclusion, approved or not, every single-factor sign-in with its likely cause, and which policies count as baseline.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-EvidenceRoot` | `-OutputRoot` | Folder holding the earlier runs |
| `-MfaRunFolder`, `-PopulationRunFolder` | latest run | Pin the run of 01 or 27 to measure, instead of the latest |
| `-MfaPolicyNames` | detected | Exact names of the enabled policies that count as baseline MFA policies |
| `-ExceptionRegisterCsv` | (none) | Exception register ([template](../../examples/exception-register.example.csv)). Accepted or Approved, unexpired rows whose `Control` is about MFA and whose `Identity` or `Scope` names the user or the excluding group mark that exclusion as approved |
| `-MaxRunSpreadDays` | `7` | 01 and 27 runs further apart than this make the measures Partial |
| `-MfaPolicyNamesFile` | `<parent of EvidenceRoot>\config\mfa-baseline-policies.txt` | One baseline policy name per line (`#` comments). Read when `-MfaPolicyNames` is not given, so reruns keep the same baseline |
| `-SaveMfaPolicyNames` | off | Write the names given with `-MfaPolicyNames` to that file |
| `-TokenBrokerApps` | `Microsoft Authentication Broker`, `Windows Sign In` | Apps whose single-factor sign-ins are token-broker / Windows logon (PRT) events, not failures. `@()` counts every single-factor sign-in as a failure |
| `-AllowHashMismatch` | off | Use a source file that changed after its run (Partial). Off: the dataset is Blocked |

**Open first:** `mfa-effectiveness-measures.csv`, filtered on Population = `Human workforce enabled (Entra)`. That is the table to report. Then `mfa-exclusions.csv` and `mfa-failures.csv`.

```powershell
.\scripts\32-Get-MfaEffectiveness.ps1 -OutputRoot D:\Evidence
.\scripts\32-Get-MfaEffectiveness.ps1 -OutputRoot D:\Evidence -ExceptionRegisterCsv D:\Engagement\registers\exception-register.csv
```

Run 27 (with the HR file) and 01 first, ideally on the same day.

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `mfa-effectiveness-measures.csv` | Population and measure | `Population`, `Measure`, `Value`, `Denominator`, `Percent`, `Definition`, `Source` (script and run), `Status`, `Note` |
| `mfa-effectiveness.csv` | Identity in any population | `Upn`, `Category`, `Populations`, `MfaState`, `Enforcement`, `MfaRegistered`, `MethodStrength`, `PhishResistant`, `PhoneOnly`, `IsPrivileged`, `IsTier0`, `EnforcedBy`, `ExcludedFrom`, `ExclusionVia`, `ExclusionApproved`, `SingleFactorSignIns`, `TokenBrokerSignIns`, `SingleFactorSignInsExBroker`, `LegacyAuthSignIns`, `Flags` |
| `mfa-exclusions.csv` | Exclusion | `ExclusionKind` (Population / BaselineMfaPolicy), `Upn`, `Category`, `ExcludedFrom`, `Via`, `Reason`, `Approved`, `ApprovedBy`, `ExpiresUtc`, `Source` |
| `mfa-failures.csv` | Single-factor sign-in group (user, app, client) | `Upn`, `InScope`, `Category`, `SignInKind`, `AppDisplayName`, `ClientAppUsed`, `IsLegacyAuth`, `IsTokenBroker`, `SignInCount`, `LastSeenUtc`, `CaStatuses`, `Enforcement`, `LikelyCause` |
| `mfa-baseline-policies.csv` | MFA policy | `PolicyName`, `State`, `CountsAsBaseline`, `Reason`, `LeavesOut` |
| `source-runs.csv` | Source dataset read | `Script`, `Dataset`, `RunFolder`, `SourceStatus`, `Rows`, `RecordedSha256`, `Sha256`, `HashCheck` (Verified / Mismatch / NotRecorded / MissingFile), `UsedAs` |

Measures per population: population (denominator); protected (registered and enforced); protected with no single-factor sign-in; registered; phishing-resistant method; phone as the strongest method; enforced by a baseline policy; enforced only with conditions; excluded from every baseline policy; excluded from at least one; exclusions not in the exception register (with `-ExceptionRegisterCsv`); enforced but not registered; registered but not enforced; not in the registration report; with single-factor sign-ins (raw, token broker included); with single-factor sign-ins (failures, token broker left out); with token broker / Windows sign-in events only; protected with no single-factor sign-in excluding token broker; with legacy authentication sign-ins.

`MfaState`: `Protected` (registered and enforced), `EnforcedNotRegistered`, `RegisteredNotEnforced`, `Excluded`, `Unprotected`, `NoRegistrationData`, `Unknown` (CA policies not usable).

`Enforcement`: `Enforced`, `EnforcedWithConditions` (every covering baseline policy leaves out locations, apps or devices), `Excluded`, `NotCovered` (no baseline policy applies), `Unknown` (CA policies not usable, or the only baseline policies that might apply target groups or roles, whose membership isn't known offline).

Flags: `SingleFactorSignIn`, `LegacyAuthSignIn`, `PhoneOnly`, `PartiallyExcluded`, `EnforcedOnlyWithConditions`, `ExpectedExclusion(BreakGlass)`, `BreakGlassNotExcluded`, `ExclusionNotInExceptionRegister`, `Tier0WithoutPhishResistant`.

**Reading it:**
- **Denominator basis** (first line of `summary.csv`): `Agreed` means 27 ran with an HR file. `NamingRules` means 27 ran without one. `Fallback` means there's no usable 27 run, so the denominator is every enabled member account, including service and shared accounts. Anything other than `Agreed` makes the measures Partial, and the note says why.
- **A baseline MFA policy** is enabled, requires MFA (or an authentication strength), and targets All users, All cloud apps and every client app type, with no risk condition and no include-location or include-platform condition. Excluded locations, apps or a device filter still count, but enforcement then shows as `EnforcedWithConditions`. `mfa-baseline-policies.csv` gives every other MFA policy and why it doesn't count. When the tenant enforces MFA through several scoped policies instead, name them with `-MfaPolicyNames`. A named policy must be enabled. One that targets All users covers everyone it doesn't exclude. One that targets users, groups or roles covers the accounts in 01's `ca-included-scope-members` (01 1.2.0 and later expands them). With an older 01 run, group and role targeting can't be resolved and enforcement is `Unknown`, so rerun 01 first. A policy limited to some apps (for example Office 365 only) counts, but enforcement shows as `EnforcedWithConditions` and `LeavesOut` names the apps.
- **Exclusions** are resolved to accounts: users directly, excluded groups through 01's transitive members, and excluded roles through 01's active role holders. Only exclusions on enabled policies count. A guest-type exclusion applies to guests when it lists `b2bCollaborationGuest` or `internalGuest`, and to external members when it lists `b2bCollaborationMember`. If 01 couldn't expand a group, the exclusion datasets are Partial and say so.
- **Failures** are successful sign-ins that didn't need a second factor in 01's lookback window. Non-interactive sign-ins are included only when 01 ran with `-IncludeNonInteractive`; their legacy flag comes from the client app. `LikelyCause` is a pointer, not a verdict; check the sign-in in the Entra log.
- **Name the baseline once.** In tenants that enforce MFA per app or per group, detection finds no baseline policy and Protected and Enforced come out 0 (the run log warns, and the summary says so). Run once with `-MfaPolicyNames … -SaveMfaPolicyNames`; later runs read `config\mfa-baseline-policies.txt` next to the evidence folder. `examples/32-select-baseline-and-rerun.txt` picks the names with a stated rule: every enabled MFA policy except user-action, risk-based and authentication-context policies. The summary row *Baseline policy names from* records where the list came from.
- **Token broker and Windows Sign In are not failures.** Entra logs sign-ins by Microsoft Authentication Broker and Windows Sign In as single-factor with Conditional Access *Not Applied*. These are Primary Refresh Token events: CA is not evaluated when a PRT is issued or renewed (Windows renews it every 4 hours), and MFA was satisfied earlier in the session ([Microsoft Learn: Primary Refresh Token](https://learn.microsoft.com/entra/identity/devices/concept-primary-refresh-token)). In most tenants they are the bulk of single-factor rows. 32 keeps them in `mfa-failures.csv` with `IsTokenBroker = True` and reports the failure measure without them; the *(raw)* measure still includes them. Report the *(failures)* figure, and say the raw one was adjusted and why.
- **A blank value is not zero.** A measure whose sources are Blocked or not run has an empty `Value` and says why in `Note`.
- **Changed evidence is refused.** If a source CSV was opened and saved after its run, its SHA-256 no longer matches and that dataset is Blocked. Restore the original or rerun the source script.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| none | none | Read access to the evidence folder (earlier runs of 01 and 27); the exception register, if used | none |

## Pilot check

`Population (denominator)` for the human workforce matches `Human workforce enabled (Entra)` in 27's `population-denominators.csv`. One user you know is in an excluded group shows `Excluded` with that group in `ExclusionVia`. The baseline policy names match what you'd call the MFA baseline in **Entra > Conditional Access**.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 32: `MFA registration from script 01 is needed` | No usable 01 run in the evidence folder | Run 01, or point `-EvidenceRoot` at the folder that holds it |
| Script 32: Denominator basis `Fallback` | No 27 run, or its datasets aren't usable | Run 27; with the HR file for `Agreed` |
| Script 32: a source is Blocked with `SHA-256 mismatch` | The file was edited (often opened and saved in Excel) | Restore it from the original run, or rerun the source script. `-AllowHashMismatch` only for a known, harmless change |
| Script 32: `Baseline MFA policies` = 0 but MFA is enforced | MFA comes from scoped policies or user actions | Name the policies with `-MfaPolicyNames` |
| Script 32: measures Partial with *runs are N days apart* | 01 and 27 ran far apart | Rerun both close together, or raise `-MaxRunSpreadDays` and note it |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 31 Licence inventory](31-licence-inventory.md) · [All scripts](README.md) · [33 CA policy analysis →](33-ca-policy-analysis.md)
