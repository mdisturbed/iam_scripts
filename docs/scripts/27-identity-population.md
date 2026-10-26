# 27 - Identity population

**Script:** [`27-Get-IdentityPopulation.ps1`](../../scripts/27-Get-IdentityPopulation.ps1) · **Version:** 1.0.0 · **Source:** AD + Entra (+ HR file, exclusions file)

> Who exactly is in scope, how many of each kind are there, and who was excluded and why?

Gives you one agreed, reviewable in-scope identity population and the denominators every KPI divides by. A figure like "MFA coverage 94%" can then always point to a signed denominator. Every account is put in exactly one category. Every enabled account left out of the human workforce has a written reason.

**Collects:** AD users and Entra users, joined on the Entra Connect source anchor, plus active HR workers who have no account. For each identity: its category and the rule that set it, enabled state on each side, Entra user type, HR status and how HR was matched, whether it counts in each human-workforce population, its approved exclusion, and flags. Also: 14 standard denominators, each with a written Definition, Includes and Excludes; an HR vs AD vs Entra reconciliation; exclusion rows that matched nobody.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SkipAD`, `-SkipEntra` | off | Leave one directory out; its populations are listed as `Deferred`. You can't set both |
| `-AnchorAttribute` | `objectGUID` | Entra Connect source anchor. `mS-DS-ConsistencyGuid` falls back to `objectGUID` when it's empty, as Entra Connect does |
| `-HrCsvPath` | (none) | HR export ([template](../../examples/hr.example.csv)). Without it, HR populations are `Deferred` and every remaining enabled member account counts as workforce |
| `-HrIdColumn`, `-HrStatusColumn` | `EmployeeId`, `EmploymentStatus` | Map the export's column names |
| `-ActiveStatusValues` | `Active` | Status values that mean "currently working". Any other value isn't active |
| `-HrUpnColumn`, `-HrMailColumn` | `UserPrincipalName`, `Email` | HR columns used for fallback matching. Ignored if the file doesn't have them |
| `-AdEmployeeIdAttribute` | `employeeID` | AD attribute holding the HR id |
| `-AdminNamePatterns` | `adm*`, `*adm`, `*-adm*`, `*_adm*`, `a-*`, `a_*`, `da-*`, `*admin*` | Admin account names |
| `-ServiceNamePatterns` | `svc*`, `*-svc*`, `*_svc*`, `sa-*`, `sa_*` | Service account names. Directory sync names (`MSOL_*`, `Sync_*`, `AAD_*`, `ADSyncMSA*`) are always service accounts |
| `-TestNamePatterns` | `test*`, `*-test*`, `*_test*`, `tst-*`, `tst_*` | Test account names |
| `-ResourceNamePatterns` | `room-*`, `room_*`, `rm-*`, `conf-*`, `shared-*`, `shared_*`, `mbx-*`, `res-*`, `equip-*`, `noreply*`, `no-reply*` | Room, equipment and shared account names |
| `-BreakGlassUpns` | (none) | UPNs (or sAMAccountNames) of the emergency access accounts |
| `-ExclusionsCsv` | (none) | Approved exclusions ([template](../../examples/population-exclusions.example.csv)): `Identity`, `Reason`, `ApprovedBy`, `ApprovedOnUtc`, `ExpiresUtc` |

Name patterns use `-like` and are tested against the sAMAccountName and the UPN prefix (the part before `@`).

**Open first:** `population-denominators.csv` (this is what an approver signs), then `summary.csv` (`Unclassified` and the HR match rate), then `population-reconciliation.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Categories

Each identity gets the first rule that matches, in this order:

| Category | Rule (`ClassifiedBy`) |
|----------|-----------------------|
| `BreakGlass` | Listed in `-BreakGlassUpns` |
| `Guest` | Entra `userType` = Guest |
| `ExternalMember` | Entra `userType` = Member with `#EXT#` in the UPN |
| `AdminAccount` / `ServiceAccount` | AD built-in account: Administrator (RID 500) is admin. Guest, krbtgt and DefaultAccount (RID 501-503) are service |
| `ServiceAccount` | Directory sync account name |
| `AdminAccount` | `-AdminNamePatterns` (checked before service names, so `svc-admin` is admin) |
| `ServiceAccount` | `-ServiceNamePatterns` |
| `TestAccount` | `-TestNamePatterns` |
| `ResourceOrShared` | `-ResourceNamePatterns` |
| `ServiceAccount` | AD `servicePrincipalName` set and no HR match |
| `HumanWorkforce` | HR match. With no HR file: any remaining account |
| `Unclassified-NoHR` | HR file given, no HR match, no pattern (only used with `-HrCsvPath`) |

A mailbox type (shared, room, equipment) can't be read without Exchange. Shared and resource accounts are found by name only. Put the rest in `-ExclusionsCsv`.

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `population-denominators.csv` | Standard population | `Population`, `Count`, `Definition`, `Includes`, `Excludes`, `Source`, `Status` |
| `identity-population.csv` | Identity (AD and Entra joined; active HR workers with no account) | `Key`, `Upn`, `SamAccountName`, `DisplayName`, `Source` (AD+Entra / AD only / Entra only / HR only), `Category`, `ClassifiedBy`, `AdEnabled`, `EntraEnabled`, `UserType`, `HrStatus`, `HrMatchedBy`, `InHumanWorkforceEntra`, `InHumanWorkforceAD`, `Excluded`, `ExclusionReason`, `Flags`, `HrId`, `Mail`, `EmployeeType`, `CreationType`, `OnPremisesSyncEnabled`, `AdminCount`, `HasSpn`, `EntraObjectId`, `EntraCreatedUtc` |
| `population-exclusions.csv` | Enabled identity left out of a human-workforce population | `Key`, `Upn`, `SamAccountName`, `DisplayName`, `Source`, `Category`, `ExclusionType` (Category / ApprovedExclusion / NoHrMatch / HrNotActive), `ExclusionReason`, `ExcludedFrom`, `ApprovedBy`, `ApprovedOnUtc`, `ExpiresUtc` |
| `population-reconciliation.csv` | Identity per issue (`-HrCsvPath`) | `Issue`, `Key`, `HrId`, `HrStatus`, `Upn`, `SamAccountName`, `DisplayName`, `Category`, `AdEnabled`, `EntraEnabled`, `Note` |
| `unmatched-exclusions.csv` | Exclusion row that matched no identity (`-ExclusionsCsv`) | `Identity`, `Reason`, `ApprovedBy`, `ApprovedOnUtc`, `ExpiresUtc`, `RowState` (Applied / Expired / NotApproved / BadDate), `Note` |

Standard populations (the exact names other tools key on): `Entra users (all)`, `Entra members enabled`, `Entra guests`, `Human workforce enabled (Entra)`, `Human workforce enabled (AD)`, `AD users enabled`, `AD service accounts enabled`, `AD admin accounts enabled`, `Entra admin accounts enabled`, `Break-glass accounts`, `HR active workers`, `HR active with AD account`, `HR active with Entra account`, `Approved exclusions`.

Reconciliation issues: `HrActiveNoAdAccount`, `HrActiveNoEntraAccount`, `HrTerminatedAdEnabled`, `HrTerminatedEntraEnabled`, `AdEnabledHumanNotInHr`, `EntraEnabledHumanNotInHr`.

Flags: `NoHrMatch`, `HrTerminatedButEnabled`, `HrActiveButDisabled`, `MultipleAccountsSameHrId`, `AdminCountNotAdminNamed`, `PersonAccountWithSpn`, `EnabledMismatch`, `DuplicateAnchor`, `SyncedNoAdMatch`, `ExclusionExpired`, `ExclusionNotApproved`, `ExclusionBadDate`, `PatternAndExclusionConflict`.

**Reading it:**
- "Human workforce enabled" means all of these: enabled, a member (not a guest), category `HumanWorkforce` and not on an approved exclusion. With an HR file, the account must also match an HR record with an active status. Enabled accounts that fail the HR test aren't silently dropped: they're in `population-exclusions.csv` and `population-reconciliation.csv`. The `Definition` column states which rule was used in this run.
- A population that couldn't be computed is still listed, with a blank `Count` and `Status` = `Blocked`, `Deferred` or `EvidenceUnavailable`. The reason is at the end of `Definition`. Never read a blank as zero.
- A `Partial` population has a count, but one input wasn't complete. For example, `Break-glass accounts` is Partial when a listed UPN wasn't found. `Human workforce enabled (Entra)` is Partial when AD couldn't be read, because synced accounts were then classified on Entra data alone.
- HR matching: HR id to AD `-AdEmployeeIdAttribute` first, then to Entra `employeeId`. UPN or mail are used only when both ids are blank on the account. `HrMatchedBy` says which one matched. A fallback match is worth a look: the id should be populated.
- Guests and external members are never matched to HR.
- An admin or test account that shares the person's HR id isn't counted as the person's account. `HR active with AD account` counts `HumanWorkforce` accounts only.
- `Unclassified-NoHR` should trend to zero before anyone signs the denominators. Each one needs a name pattern, an HR record or an approved exclusion.
- Exclusions match on UPN or sAMAccountName (`CONTOSO\` is ignored). An expired row isn't applied: the account stays in the population and gets the `ExclusionExpired` flag. A row without `ApprovedBy` isn't applied either. A blank `ExpiresUtc` means no expiry.
- `PatternAndExclusionConflict`: the account was already left out by its category and is also on the exclusions list. That's harmless, but the list can probably be shortened.
- `DuplicateAnchor`: two Entra users share one source anchor. Only the first is joined to AD; the other shows up as `Entra only` with `SyncedNoAdMatch`.
- Admin counts are by name only. For group-based privilege and Entra role holders, use scripts 04, 18 and 02.
- Managed service accounts (gMSA / sMSA) aren't user objects, so they aren't in any population here. Script 12 lists them.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader (or Directory Readers) | User.Read.All (Directory.Read.All also works) | Domain read; the HR export and the exclusions list | RSAT AD, Graph Auth |

No licence beyond Entra ID Free. RSAT AD isn't needed with `-SkipAD`, and Graph isn't needed with `-SkipEntra`. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm three things. `Entra users (all)` matches the user count in the Entra admin centre. One person you know is `HumanWorkforce` and counted in both human-workforce populations. Your break-glass accounts show as `BreakGlass`.

Usually tuned on first run: the name patterns for your naming standard; `-ActiveStatusValues` (for example, add leave of absence if those people keep access); `-AnchorAttribute` if Entra Connect uses `mS-DS-ConsistencyGuid`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 27: Entra populations `Blocked` | User.Read.All not consented, or no directory reader role | Consent the scope; the reason is at the end of each `Definition` |
| Script 27: many `Unclassified-NoHR` | HR ids not populated on accounts, or naming not covered by the patterns | Check `HrMatchedBy` on matched rows; add `-HrUpnColumn` / `-HrMailColumn`; extend the name patterns |
| Script 27: few AD users show `AD+Entra` | Entra Connect anchors on a different attribute | `-AnchorAttribute 'mS-DS-ConsistencyGuid'` |
| Script 27: `HR file has no column ...` | Export headers differ | Map with `-HrIdColumn` and `-HrStatusColumn`; the error lists the columns |
| Script 27: an exclusion isn't applied | Expired, no `ApprovedBy`, or unreadable date | Check the flag on the identity, or `RowState` in `unmatched-exclusions.csv` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 26 PAM vault coverage](26-pam-vault-coverage.md) · [All scripts](README.md)
