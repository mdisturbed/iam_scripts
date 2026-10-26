# Evidence tools

**Tools:** [`Compare-RunFolders.ps1`](../tools/Compare-RunFolders.ps1), [`Get-KpiSummary.ps1`](../tools/Get-KpiSummary.ps1), [`New-EvidencePackage.ps1`](../tools/New-EvidencePackage.ps1) · **Version:** 1.0.0 · **Source:** run folders in the evidence folder

> What changed, what do the numbers say against an agreed population, and is each deliverable's evidence complete and untouched?

Three local tools that turn run folders into gate evidence for a staged identity programme: before / after evidence for an approved change, KPIs with validated denominators, and an intake log and package per deliverable. They read run folders only and connect to nothing. Each writes its own run folder, `<OutputRoot>\<ToolName>\<yyyyMMdd-HHmmssZ>\`, with `run-manifest.json`, `dataset-status.csv` (SHA-256 per output), `summary.csv` where it has one, and `run.log`, so the tool output is evidence in the same form as the script output ([run folder layout](outputs.md#run-folder)).

Every tool re-hashes the input files it reads and compares them with the SHA-256 recorded in the run's `dataset-status.csv`. A file changed after its run is never used silently: it is reported as `HashMismatch` / `Mismatch` with a warning.

## Compare-RunFolders

Before / after evidence for an approved change: two run folders of the same script, compared dataset by dataset and row by row.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-BeforeRunFolder` | required | The run before the change, e.g. `D:\Evidence\01-MfaCoverage\20261020-140501Z` |
| `-AfterRunFolder` | required | The run after the change, same script |
| `-Dataset` | every dataset `Completed` or `Partial` in both runs, except `summary` | Datasets to compare (name or file name) |
| `-KeyColumns` | auto | Key per dataset: `@{ 'ca-exclusions' = @('PolicyId', 'ExcludedType', 'ExcludedId') }` |
| `-IgnoreColumns` | last sign-in / logon / key-use times, `NewestActivity*`, `DaysSince*`, `*AgeDays`, `DaysToExpiry`, `NextExpiryDays`, `ActivityBucket` | Columns (wildcards allowed) left out of the comparison; `@()` compares every column |
| `-IncludeUnchanged` | off | Also list Unchanged rows in `run-diff-rows.csv` |
| `-Force` | off | Compare runs of different scripts (refused otherwise) |
| `-OutputRoot` | the evidence folder above `-AfterRunFolder` | Where `Compare-RunFolders\<timestamp>\` goes |

**Key:** `-KeyColumns` when given; otherwise the first of `Id`, `ObjectId`, `PrincipalId`, `PolicyId`, `UserPrincipalName`, `Upn`, `DistinguishedName`, `SamAccountName` that is in both files, never blank and unique on both sides; otherwise the whole row (so a row is Added, Removed or Unchanged, never Changed). JSON datasets (28) are compared per array element, top-level property by property; nested objects are compared as compact JSON.

**Open first:** `run-diff-summary.csv` (any `HashMismatch`?), then `run-diff-rows.csv` filtered on the dataset the change was meant to touch.

| File | One row per | Key columns |
|------|-------------|-------------|
| `run-diff-summary.csv` | Dataset | `Dataset`, `BeforeRows`, `AfterRows`, `Added`, `Removed`, `Changed`, `Unchanged`, `DuplicateKeys`, `KeyColumns`, `BeforeSha256`, `AfterSha256`, `BeforeStatus`, `AfterStatus`, `Status` (Compared / Partial / HashMismatch / NotComparable), `Note` |
| `run-diff-rows.csv` | Added, removed, changed or duplicate-key row | `Dataset`, `Key`, `ChangeType` (Added / Removed / Changed / DuplicateKey / Unchanged), `ChangedColumns`, `Before`, `After` (compact `col=val; col=val`; for Changed only the changed columns) |
| `metric-diff.csv` | `summary.csv` metric | `Metric`, `Before`, `After`, `Delta` (after - before, when both are numbers), `Change` (Same / Changed / OnlyBefore / OnlyAfter), `BeforeNote`, `AfterNote` |
| `input-verification.csv` | Input file | `Side`, `RunFolder`, `Dataset`, `File`, `RecordedSha256`, `ActualSha256`, `Result` (Verified / Mismatch / MissingFile) |

**Reading it:**
- `HashMismatch`: a file in one of the two runs no longer matches the SHA-256 recorded when the script wrote it. The comparison still runs so you can see what differs, but it is not evidence until the change to the file is explained.
- `NotComparable`: one side is `Blocked`, `Deferred`, `EvidenceUnavailable` or missing. It is never read as zero rows.
- `Partial`: a side was `Partial`, or keys repeat. Added and Removed can reflect the part that wasn't read rather than a real change.
- `DuplicateKey`: the key appears more than once on a side. Those rows are listed, not merged; give `-KeyColumns` for that dataset.
- A different script version on each side is logged as a warning; columns only on one side are named in the Note and not compared.

## Get-KpiSummary

KPIs computed from the latest runs (or the latest at or before a date), each value traced to the run, file and SHA-256 it came from.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-EvidenceRoot` | required | Folder holding the run folders |
| `-KpiDefinitionPath` | [`examples/kpi-definitions.example.psd1`](../examples/kpi-definitions.example.psd1) | KPI definitions |
| `-AsOf` | latest runs | Use the latest run of each script started at or before this UTC time, e.g. `2026-11-01T00:00:00Z` |
| `-MaxRunSpreadDays` | `7` | Numerator and denominator runs further apart are `Partial` |
| `-OutputRoot` | `-EvidenceRoot` | Where `Get-KpiSummary\<timestamp>\` goes |

**Definition file:** one hashtable per KPI with `Id`, `Name`, `Description`, `Direction` (`HigherIsBetter` / `LowerIsBetter`), optional `Target` (percent), and a `Numerator` and `Denominator` of one of these shapes:

| Shape | Example |
|-------|---------|
| Summary metric (a count) | `@{ Script = '26'; Metric = 'Entra privileged accounts vaulted' }` |
| Dataset rows | `@{ Script = '29'; Dataset = 'pilot-test-results'; FilterColumn = 'Outcome'; FilterValue = 'Pass'; FilterMode = 'Equals' }` |
| Dataset, several filters | `@{ Script = '01'; Dataset = 'mfa-registration'; Filters = @( @{ Column = 'UserType'; Value = 'member' }, @{ Column = 'IsMfaRegistered'; Value = 'True' } ) }` |
| Distinct values | add `CountDistinct = '<column>'` to a dataset shape |
| Population (27) | `@{ Population = 'Human workforce enabled (Entra)' }` |

`Script` is the run folder prefix (`'01'`) or full name (`'01-MfaCoverage'`). `FilterMode`: `Equals` (default, case-insensitive), `NotEquals`, `Like`, `Contains`, `Match` (regex). Population names are exact and come from `population-denominators.csv` of the latest 27 run. A malformed definition stops the tool, so a typo is never reported as missing evidence.

**Open first:** `kpi-summary.csv`, sorted on `Status`.

| File | One row per | Key columns |
|------|-------------|-------------|
| `kpi-summary.csv` | KPI | `KpiId`, `Name`, `Numerator`, `Denominator`, `Value` (%, 1 dp), `Target`, `MeetsTarget`, `Direction`, `NumeratorSource`, `NumeratorRunUtc`, `NumeratorSha256`, `DenominatorSource`, `DenominatorRunUtc`, `DenominatorSha256`, `Status`, `Note`, `Description` |

Summary metrics: KPIs defined, KPIs per status, KPIs meeting / missing target.

**Status rules** (the most serious wins):

| Status | When | Value |
|--------|------|-------|
| `NotRun` | The source script has no run (at or before `-AsOf`) | blank |
| `Blocked` | The source dataset is Blocked; a source file no longer matches its SHA-256; or the denominator is zero | blank |
| `EvidenceUnavailable` | The source is EvidenceUnavailable; the dataset, metric, population or a filter column is not there; a metric is blank or not a number | blank |
| `Deferred` | The source dataset or population is Deferred | blank |
| `Partial` | A source is Partial; runs more than `-MaxRunSpreadDays` apart; or the numerator is larger than the denominator | computed, with the reason in `Note` |
| `Completed` | Both sides Completed, verified and in the same window | computed |

**Reading it:**
- A value is never computed from a Blocked, EvidenceUnavailable, Deferred or missing source, or from a file that fails its hash check.
- `Source` names the run folder, file and filter, so anyone can recount the number by hand from the evidence.
- A numerator over the denominator usually means they count different things, e.g. `mfa-registration` includes shared and service accounts that 27 excludes from the human workforce. Fix the definition, or agree the exclusions.
- Use `-AsOf` with the gate date to rebuild the KPI table as it stood at that gate.

## New-EvidencePackage

The evidence intake log, every dataset re-verified, and a status per deliverable from a deliverable map; optionally a copied package.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-EvidenceRoot` | required | Folder holding the run folders (scripts and tools) |
| `-DeliverableMapPath` | [`examples/deliverable-map.example.psd1`](../examples/deliverable-map.example.psd1) | Which scripts and datasets each deliverable needs |
| `-IncludeAllRuns` | latest per script, plus pinned runs | List (and package) every run folder |
| `-CopyTo` | none | Build a package in this new or empty folder |
| `-OutputRoot` | `-EvidenceRoot` | Where `New-EvidencePackage\<timestamp>\` goes |

**Deliverable map:** one hashtable per deliverable with `Id`, `Deliverable`, `Gate`, optional `Description`, and `Requires = @( @{ Script = '01'; Datasets = @('mfa-registration', 'ca-policies'); Run = '20261020-140501Z' } )`. `Script` is a prefix (`'01'`) or a folder name (`'Compare-RunFolders'`, `'Get-KpiSummary'`). `Datasets` takes dataset names or file names with extension (use file names for the JSON files of 28); leave it out to require every dataset of the run. `Run` pins a frozen baseline; without it the latest run is used.

**Open first:** `evidence-index.md` (status per deliverable), then `evidence-intake-log.csv` filtered on `HashCheck` not `Verified`.

| File | One row per | Key columns |
|------|-------------|-------------|
| `evidence-intake-log.csv` | Run folder | `Script`, `ScriptVersion`, `RunFolder`, `StartedUtc`, `FinishedUtc`, `RunAs`, `Machine`, `TenantId`, `Domain`, `DatasetCount`, `Completed`, `Partial`, `Blocked`, `Deferred`, `EvidenceUnavailable`, `HashCheck` (Verified / Mismatch / MissingFile), `ManifestSha256`, `Latest`, `Note` |
| `evidence-datasets.csv` | Dataset of a listed run | `Script`, `RunFolder`, `Dataset`, `Status`, `Rows`, `File`, `RecordedSha256`, `ActualSha256`, `HashCheck` (Verified / Mismatch / MissingFile / NoFile), `Note` |
| `deliverable-status.csv` | Deliverable | `DeliverableId`, `Deliverable`, `Gate`, `RequiredScripts`, `RequiredDatasets`, `Present`, `Missing`, `Status`, `Note`, `Evidence` (run folders) |
| `evidence-index.md` | Deliverable (readable) | Status, notes, and per required dataset its status, rows, path and SHA-256 |
| `package-manifest.csv` (with `-CopyTo`) | Copied file | `RelativePath`, `Bytes`, `Sha256`, `CopyCheck` (Verified / Mismatch), `SourcePath` |

**Status rollup per deliverable** (the most serious wins): `HashMismatch` (a required file was altered after its run), `NotRun` (a required script has no run, or the pinned run is absent), `Blocked`, `EvidenceUnavailable` (also when the run didn't write a required dataset), `Deferred`, `Partial`, `Completed` (every required dataset Completed and verified). The Note names each dataset that holds the status back.

**Reading it:**
- `HashCheck` = `Mismatch` means a file differs from the SHA-256 in `dataset-status.csv`, or `dataset-status.csv` differs from `run-manifest.json`. Treat the run as altered until explained; rerun the script if in doubt.
- `NoFile` is normal for a Blocked, Deferred or EvidenceUnavailable dataset: nothing was written.
- With `-CopyTo` the package holds `<NN-Name>\<timestamp>\` copies of the selected runs and an `index\` folder with the four index files and `package-manifest.csv`. Each copy is re-hashed against its source. Copying uses `[System.IO.Directory]::CreateDirectory` and `[System.IO.File]::Copy` without overwrite, so the tool stays within the commands `Test-ReadOnly.ps1` allows.
- The tool skips its own earlier run folders when it builds the log.

## Typical flow per gate

| Gate | Run | Then |
|------|-----|------|
| G0 Readiness | The first run of each script you have access for | Pin those runs (`Run =`) in the map as the frozen baseline; `New-EvidencePackage.ps1` |
| G1 Baseline | 01-06, 10, 12, 13, 20, 22, then 27 with the signed exclusions | `Get-KpiSummary.ps1` for the baseline KPIs; `New-EvidencePackage.ps1` |
| G2 Design and pilot | 28 (snapshot), 24, 29 with the test cases; 02, 04, 26; 06, 14, 15 | `Get-KpiSummary.ps1` (CA pilot pass rate); package |
| G3 Change | Rerun the affected script after the change; 28 with `-BaselineRunFolder` after a rollback | `Compare-RunFolders.ps1` before vs after; package |
| G4 Operate | 20, 30 after the review period; 27 again | `Get-KpiSummary.ps1` (KPI draft); package |
| G5 Final | Latest of everything | `New-EvidencePackage.ps1 -CopyTo <new folder>` once every deliverable is Completed or its gap is accepted |

Run the numerator and denominator scripts of a KPI in the same window (within `-MaxRunSpreadDays`) so the KPI isn't Partial.

```powershell
.\tools\Compare-RunFolders.ps1 -BeforeRunFolder D:\Evidence\22-PimRoleSettings\20261020-140501Z -AfterRunFolder D:\Evidence\22-PimRoleSettings\20261103-091500Z
.\tools\Get-KpiSummary.ps1 -EvidenceRoot D:\Evidence -KpiDefinitionPath D:\Programme\kpi-definitions.psd1
.\tools\New-EvidencePackage.ps1 -EvidenceRoot D:\Evidence -DeliverableMapPath D:\Programme\deliverable-map.psd1 -CopyTo E:\Packages\G3-20261103
```

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Read access to the evidence folder; write access to `-OutputRoot` (and `-CopyTo`) | none |

The run folders hold identity data. Keep the tool output and packages in the approved evidence location, as for the script output ([handling the output](outputs.md#handling-the-output)).

---

[← Back to README](../README.md)
