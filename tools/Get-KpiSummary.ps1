<#
.SYNOPSIS
    Computes programme KPIs from discovery run folders, with every numerator and denominator traced to
    the run, file and SHA-256 it came from, and no value computed from evidence that is not there.

.DESCRIPTION
    Reads a KPI definition file (PowerShell data file) and, for each KPI, takes a numerator and a
    denominator from the latest runs in the evidence folder (or the latest at or before -AsOf):

      - a summary metric:   @{ Script = '26'; Metric = 'Entra privileged accounts vaulted' }
      - a dataset count:    @{ Script = '01'; Dataset = 'mfa-registration'; FilterColumn = 'IsMfaRegistered'; FilterValue = 'True' }
                            optional FilterMode (Equals, NotEquals, Like, Contains, Match; default Equals),
                            Filters = @( @{ Column; Value; Mode }, ... ) where every filter must match, and
                            CountDistinct = '<column>' to count distinct non-blank values instead of rows
      - a population:       @{ Population = 'Human workforce enabled (Entra)' }, read from
                            population-denominators.csv of the latest 27-IdentityPopulation run (usually the
                            denominator; also allowed as numerator, e.g. HR active with Entra account)

    Value = numerator / denominator x 100, one decimal. Status rules:
      - NotRun               the source script has no run (at or before -AsOf)
      - inherited            the source dataset, summary or population row is not Completed: its status
                             (Partial, Blocked, EvidenceUnavailable, Deferred) is carried with its note.
                             A population uses its own row's Status, so one population that could not
                             be computed does not mark every other population Partial
      - no value             from a Blocked, EvidenceUnavailable or Deferred source, a blank count or
                             metric, or a file that no longer matches its recorded SHA-256 (Blocked)
      - Blocked              denominator is zero
      - Partial              numerator and denominator runs more than -MaxRunSpreadDays apart, or the
                             numerator is larger than the denominator (the two count different things)
    When several apply, the most serious wins: NotRun, Blocked, EvidenceUnavailable, Deferred, Partial.

    Local only: reads run folders, writes only its own run folder. Connects to nothing.

    Output: <OutputRoot>\Get-KpiSummary\<yyyyMMdd-HHmmssZ>\kpi-summary.csv + run-manifest.json + run.log

.PARAMETER EvidenceRoot
    Folder holding the run folders (NN-Name\yyyyMMdd-HHmmssZ).

.PARAMETER KpiDefinitionPath
    KPI definition file. Default: examples\kpi-definitions.example.psd1 in the repository.

.PARAMETER AsOf
    Use the latest run of each script started at or before this UTC time (e.g. 2026-11-01T00:00:00Z),
    to rebuild the KPIs as they stood at a gate.

.PARAMETER MaxRunSpreadDays
    Numerator and denominator runs further apart than this are Partial. Default 7.

.PARAMETER OutputRoot
    Where the tool's own run folder goes. Default: -EvidenceRoot.

.EXAMPLE
    .\tools\Get-KpiSummary.ps1 -EvidenceRoot D:\Evidence
.EXAMPLE
    .\tools\Get-KpiSummary.ps1 -EvidenceRoot D:\Evidence -KpiDefinitionPath D:\Programme\kpi-definitions.psd1 -AsOf 2026-11-01T00:00:00Z

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x. Runs of the scripts the definitions name; 27 for Population denominators.
    Scopes  : none. Reads local files only.
    Licence : none
    Sources : run-manifest.json, dataset-status.csv, summary.csv and dataset files of the source runs.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [string]$KpiDefinitionPath = '',
    [string]$AsOf = '',
    [int]$MaxRunSpreadDays = 7,
    [string]$OutputRoot = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = 'Get-KpiSummary'
$ScriptVersion = '1.0.0'

if (-not (Test-Path -LiteralPath $EvidenceRoot)) { throw "Evidence folder not found: $EvidenceRoot" }
$EvidenceRoot = (Resolve-Path -LiteralPath $EvidenceRoot).Path
if (-not $KpiDefinitionPath) { $KpiDefinitionPath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'examples') 'kpi-definitions.example.psd1' }
if (-not (Test-Path -LiteralPath $KpiDefinitionPath)) { throw "KPI definition file not found: $KpiDefinitionPath" }
if (-not $OutputRoot) { $OutputRoot = $EvidenceRoot }

#region ---- Common helpers (identical in every evidence tool; self-contained by design) ----
if (-not $OutputRoot) { $OutputRoot = Join-Path $PSScriptRoot 'output' }
$script:RunStartUtc = (Get-Date).ToUniversalTime()
$script:RunFolder   = Join-Path (Join-Path $OutputRoot $ScriptName) ($script:RunStartUtc.ToString('yyyyMMdd-HHmmss') + 'Z')
New-Item -Path $script:RunFolder -ItemType Directory -Force | Out-Null
$script:LogFile  = Join-Path $script:RunFolder 'run.log'
$script:Datasets = [System.Collections.Generic.List[object]]::new()

function Write-RunLog {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Level, $Message
    $color = @{ INFO = 'Gray'; WARN = 'Yellow'; ERROR = 'Red' }[$Level]
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $script:LogFile -Value $line
}

function Export-Dataset {
    param([Parameter(Mandatory)][string]$Name, [object[]]$Rows, [string]$Status = 'Completed', [string]$Note = '')
    $file = Join-Path $script:RunFolder ("{0}.csv" -f $Name)
    $count = 0
    if ($Rows -and @($Rows).Count -gt 0) {
        # Normalise every DateTime to ISO 8601 UTC so CSVs are culture-independent.
        $Rows | ForEach-Object {
            $o = [ordered]@{}
            foreach ($pp in $_.PSObject.Properties) { $o[$pp.Name] = $(if ($pp.Value -is [datetime]) { $pp.Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $pp.Value }) }
            [pscustomobject]$o
        } | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
        $count = @($Rows).Count
    }
    else { Set-Content -Path $file -Value '' -Encoding UTF8 }
    $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
    $script:Datasets.Add([pscustomobject][ordered]@{ Dataset = $Name; Status = $Status; Rows = $count; File = (Split-Path $file -Leaf); Sha256 = $hash; Note = $Note })
    Write-RunLog ("{0}: {1} rows [{2}] {3}" -f $Name, $count, $Status, $Note)
}

function Set-DatasetStatus {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][ValidateSet('Blocked', 'Deferred', 'EvidenceUnavailable')][string]$Status, [string]$Note = '')
    $script:Datasets.Add([pscustomobject][ordered]@{ Dataset = $Name; Status = $Status; Rows = 0; File = ''; Sha256 = ''; Note = $Note })
    Write-RunLog ("{0}: [{1}] {2}" -f $Name, $Status, $Note) 'WARN'
}

function Write-RunManifest {
    param([hashtable]$Parameters)
    $manifest = [ordered]@{
        Script        = $ScriptName
        ScriptVersion = $ScriptVersion
        StartedUtc    = $script:RunStartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        FinishedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        RunAsWindows  = [Environment]::UserDomainName + '\' + [Environment]::UserName
        Machine       = [Environment]::MachineName
        PowerShell    = $PSVersionTable.PSVersion.ToString()
        Parameters    = $Parameters
        Datasets      = $script:Datasets.ToArray()
    }
    if ($script:ManifestExtra) { $manifest['Extra'] = $script:ManifestExtra }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $script:RunFolder 'run-manifest.json') -Encoding UTF8
    $script:Datasets | Export-Csv -Path (Join-Path $script:RunFolder 'dataset-status.csv') -NoTypeInformation -Encoding UTF8
}

function Join-Values { param($Values) if ($null -eq $Values) { return '' } return (@($Values) | Where-Object { $null -ne $_ -and "$_" -ne '' }) -join '; ' }
#endregion

# ---- Tool-specific helpers ----
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$script:Severity = @{ Completed = 0; Partial = 1; Deferred = 2; EvidenceUnavailable = 3; Blocked = 4; NotRun = 5 }
$script:NoValueStatus = @('Blocked', 'EvidenceUnavailable', 'Deferred', 'NotRun')
$script:PopulationScript = '27-IdentityPopulation'
$script:RunCache = @{}
$script:HashCache = @{}

function Read-CsvSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    if ((Get-Item -LiteralPath $Path).Length -lt 4) { return @() }
    return @(Import-Csv -LiteralPath $Path)
}

function ConvertTo-UtcDate {
    # Manifest times: a string in PowerShell 5.1, already a DateTime after ConvertFrom-Json in 7.
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse("$Value", $script:Inv, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
}

function ConvertFrom-RunName {
    param([string]$Name)
    return [datetime]::ParseExact($Name, "yyyyMMdd-HHmmss'Z'", $script:Inv, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
}

function Get-ScriptFolder {
    # Script folders matching a script reference: the exact folder name, or NN for NN-*.
    param([string]$Script)
    $all = @(Get-ChildItem -LiteralPath $EvidenceRoot -Directory -ErrorAction SilentlyContinue)
    $exact = @($all | Where-Object { $_.Name -eq $Script })
    if ($exact.Count) { return $exact }
    $nn = ($Script -split '-')[0]
    if ($nn -match '^\d\d$') { return @($all | Where-Object { $_.Name -like "$nn-*" }) }
    return @()
}

function Find-SourceRun {
    # Latest run folder (with run-manifest.json) of a script, at or before -AsOf. Cached.
    param([string]$Script)
    if ($script:RunCache.ContainsKey($Script)) { return $script:RunCache[$Script] }
    $runs = @(Get-ScriptFolder $Script | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
            Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'run-manifest.json')) })
    if ($script:AsOfUtc) { $runs = @($runs | Where-Object { (ConvertFrom-RunName $_.Name) -le $script:AsOfUtc }) }
    $run = $runs | Sort-Object Name | Select-Object -Last 1
    $result = $null
    if ($run) {
        $manifest = Get-Content -LiteralPath (Join-Path $run.FullName 'run-manifest.json') -Raw | ConvertFrom-Json
        $started = $(if ($manifest.StartedUtc) { ConvertTo-UtcDate $manifest.StartedUtc } else { ConvertFrom-RunName $run.Name })
        $result = [pscustomobject]@{
            Folder = $run.FullName; Label = ('{0}/{1}' -f (Split-Path $run.Parent.FullName -Leaf), $run.Name); Script = "$($manifest.Script)"
            StartedUtc = $started; Status = @(Read-CsvSafe (Join-Path $run.FullName 'dataset-status.csv'))
        }
    }
    $script:RunCache[$Script] = $result
    return $result
}

function Test-FileHash {
    # Re-hashes a run file and compares with dataset-status.csv. Returns Verified / Mismatch / MissingFile / NotRecorded.
    param($Run, $StatusRow)
    $path = Join-Path $Run.Folder $StatusRow.File
    if ($script:HashCache.ContainsKey($path)) { return $script:HashCache[$path] }
    $actual = $(if (Test-Path -LiteralPath $path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } else { '' })
    $r = $(if (-not $actual) { 'MissingFile' } elseif (-not $StatusRow.Sha256) { 'NotRecorded' } elseif ($actual -eq "$($StatusRow.Sha256)".ToUpperInvariant()) { 'Verified' } else { 'Mismatch' })
    $script:HashCache[$path] = [pscustomobject]@{ Result = $r; Actual = $actual }
    return $script:HashCache[$path]
}

function Test-RowFilter {
    param($Row, $Filters)
    foreach ($f in $Filters) {
        $v = "$($Row.($f.Column))"
        $ok = switch ($f.Mode) {
            'NotEquals' { -not [string]::Equals($v, "$($f.Value)", [StringComparison]::OrdinalIgnoreCase) }
            'Like' { $v -like "$($f.Value)" }
            'Contains' { $v.IndexOf("$($f.Value)", [StringComparison]::OrdinalIgnoreCase) -ge 0 }
            'Match' { $v -match "$($f.Value)" }
            default { [string]::Equals($v, "$($f.Value)", [StringComparison]::OrdinalIgnoreCase) }
        }
        if (-not $ok) { return $false }
    }
    return $true
}

function Get-FilterList {
    # Normalises FilterColumn / FilterValue / FilterMode and Filters into one list.
    param([hashtable]$Spec)
    $list = [System.Collections.Generic.List[object]]::new()
    if ($Spec.FilterColumn) { $list.Add([pscustomobject]@{ Column = [string]$Spec.FilterColumn; Value = [string]$Spec.FilterValue; Mode = $(if ($Spec.FilterMode) { [string]$Spec.FilterMode } else { 'Equals' }) }) }
    foreach ($f in @($Spec.Filters)) {
        if (-not $f) { continue }
        $list.Add([pscustomobject]@{ Column = [string]$f.Column; Value = [string]$f.Value; Mode = $(if ($f.Mode) { [string]$f.Mode } else { 'Equals' }) })
    }
    return $list.ToArray()
}

function ConvertTo-Number {
    param([string]$Value)
    $d = 0.0
    if ($Value -match '^\s*-?\d+(\.\d+)?\s*$' -and [double]::TryParse($Value, [Globalization.NumberStyles]::Float, $script:Inv, [ref]$d)) { return $d }
    return $null
}

function Resolve-Side {
    # Returns Count (or $null), Status, Note, Source, RunUtc, Sha256 for a numerator or denominator spec.
    param([hashtable]$Spec, [string]$Side)
    $out = [pscustomobject]@{ Count = $null; Status = 'Completed'; Note = ''; Source = ''; RunUtc = $null; Sha256 = ''; Kind = '' }
    $srcScript = $(if ($Spec.Population) { $script:PopulationScript } else { [string]$Spec.Script })
    $run = Find-SourceRun $srcScript
    if (-not $run) {
        $out.Status = 'NotRun'; $out.Source = $srcScript
        $out.Note = "$Side source $srcScript has no run" + $(if ($script:AsOfUtc) { ' at or before ' + $script:AsOfUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }) + " in $EvidenceRoot"
        return $out
    }
    $out.RunUtc = $run.StartedUtc

    if ($Spec.Population) {
        $out.Kind = 'Population'
        $st = @($run.Status | Where-Object { $_.Dataset -eq 'population-denominators' }) | Select-Object -First 1
        $out.Source = "$($run.Label)/population-denominators.csv [Population = $($Spec.Population)]"
        if (-not $st) { $out.Status = 'EvidenceUnavailable'; $out.Note = "$Side`: population-denominators not in dataset-status.csv of $($run.Label)"; return $out }
        $out.Sha256 = $st.Sha256
        if ($script:NoValueStatus -contains $st.Status) { $out.Status = $st.Status; $out.Note = "$Side`: population-denominators $($st.Status): $($st.Note)"; return $out }
        $h = Test-FileHash $run $st
        if ($h.Result -ne 'Verified') { $out.Status = 'Blocked'; $out.Note = "$Side`: EVIDENCE ALTERED OR MISSING: population-denominators.csv $($h.Result) against its recorded SHA-256"; return $out }
        $pop = @(Read-CsvSafe (Join-Path $run.Folder $st.File) | Where-Object { $_.Population -ceq [string]$Spec.Population }) | Select-Object -First 1
        if (-not $pop) { $out.Status = 'EvidenceUnavailable'; $out.Note = "$Side`: population '$($Spec.Population)' not in population-denominators.csv (names are exact; see the 27 contract)"; return $out }
        if ($pop.Status -and $pop.Status -ne 'Completed') { $out.Status = $(if ($script:Severity.ContainsKey($pop.Status)) { $pop.Status } else { 'EvidenceUnavailable' }); $out.Note = "$Side`: population '$($Spec.Population)' $($pop.Status)" + $(if ($pop.Definition) { " ($($pop.Definition))" } else { '' }) }
        elseif (-not ($pop.PSObject.Properties.Name -contains 'Status') -and $st.Status -eq 'Partial') { $out.Status = 'Partial'; $out.Note = "$Side`: population-denominators Partial: $($st.Note)" }
        $n = ConvertTo-Number ([string]$pop.Count)
        if ($null -eq $n) {
            if ($out.Status -eq 'Completed' -or $out.Status -eq 'Partial') { $out.Status = 'EvidenceUnavailable'; $out.Note = Join-Values @($out.Note, "$Side`: population '$($Spec.Population)' has no count") }
            return $out
        }
        if ($script:NoValueStatus -notcontains $out.Status) { $out.Count = $n }
        return $out
    }

    if ($Spec.Metric) {
        $out.Kind = 'Metric'
        $st = @($run.Status | Where-Object { $_.Dataset -eq 'summary' }) | Select-Object -First 1
        $out.Source = "$($run.Label)/summary.csv [Metric = $($Spec.Metric)]"
        if (-not $st) { $out.Status = 'EvidenceUnavailable'; $out.Note = "$Side`: no summary in dataset-status.csv of $($run.Label)"; return $out }
        $out.Sha256 = $st.Sha256
        $h = Test-FileHash $run $st
        if ($h.Result -ne 'Verified') { $out.Status = 'Blocked'; $out.Note = "$Side`: EVIDENCE ALTERED OR MISSING: summary.csv $($h.Result) against its recorded SHA-256"; return $out }
        $m = @(Read-CsvSafe (Join-Path $run.Folder $st.File) | Where-Object { $_.Metric -ceq [string]$Spec.Metric }) | Select-Object -First 1
        if (-not $m) { $out.Status = 'EvidenceUnavailable'; $out.Note = "$Side`: metric '$($Spec.Metric)' not in summary.csv of $($run.Label) (exact name; check the definition and script version)"; return $out }
        $n = ConvertTo-Number ([string]$m.Value)
        if ($null -eq $n) { $out.Status = 'EvidenceUnavailable'; $out.Note = "$Side`: metric '$($Spec.Metric)' is '$($m.Value)', not a number" + $(if ($m.Note) { " ($($m.Note))" } else { '' }); return $out }
        if ($m.Metric -match '\(%\)$') { $out.Note = "$Side`: metric is a percentage, not a count" }
        $out.Count = $n
        return $out
    }

    # Dataset count
    $out.Kind = 'Dataset'
    $ds = [IO.Path]::GetFileNameWithoutExtension([string]$Spec.Dataset)
    $filters = @(Get-FilterList $Spec)
    $ftext = Join-Values (@($filters | ForEach-Object { '{0} {1} {2}' -f $_.Column, $_.Mode, $_.Value }) + $(if ($Spec.CountDistinct) { "distinct $($Spec.CountDistinct)" }))
    $out.Source = "$($run.Label)/$ds.csv" + $(if ($ftext) { " [$ftext]" } else { ' [all rows]' })
    $st = @($run.Status | Where-Object { $_.Dataset -eq $ds }) | Select-Object -First 1
    if (-not $st) { $out.Status = 'EvidenceUnavailable'; $out.Note = "$Side`: dataset $ds not in dataset-status.csv of $($run.Label)"; return $out }
    $out.Sha256 = $st.Sha256
    if ($script:NoValueStatus -contains $st.Status) { $out.Status = $st.Status; $out.Note = "$Side`: $ds $($st.Status): $($st.Note)"; return $out }
    if ($st.Status -ne 'Completed') { $out.Status = $(if ($script:Severity.ContainsKey($st.Status)) { $st.Status } else { 'Partial' }); $out.Note = "$Side`: $ds $($st.Status): $($st.Note)" }
    $h = Test-FileHash $run $st
    if ($h.Result -ne 'Verified') { $out.Status = 'Blocked'; $out.Note = "$Side`: EVIDENCE ALTERED OR MISSING: $($st.File) $($h.Result) against its recorded SHA-256"; return $out }
    $rows = @(Read-CsvSafe (Join-Path $run.Folder $st.File))
    if ($rows.Count) {
        $cols = @($rows[0].PSObject.Properties.Name)
        $needed = @($filters | ForEach-Object { $_.Column }) + @($(if ($Spec.CountDistinct) { [string]$Spec.CountDistinct }))
        $missing = @($needed | Where-Object { $_ -and $cols -notcontains $_ })
        if ($missing.Count) { $out.Status = 'EvidenceUnavailable'; $out.Note = "$Side`: column(s) $($missing -join ', ') not in $ds.csv (check the definition and script version)"; return $out }
    }
    $hits = @($rows | Where-Object { Test-RowFilter $_ $filters })
    $out.Count = $(if ($Spec.CountDistinct) { @($hits | ForEach-Object { "$($_.($Spec.CountDistinct))".ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique).Count } else { $hits.Count })
    return $out
}

function Test-Definition {
    # Throws on a malformed KPI definition so a typo is never reported as missing evidence.
    param([hashtable]$Kpi, [System.Collections.Generic.HashSet[string]]$Seen)
    foreach ($k in 'Id', 'Name', 'Direction', 'Numerator', 'Denominator') { if (-not $Kpi.ContainsKey($k) -or $null -eq $Kpi[$k] -or "$($Kpi[$k])" -eq '') { throw "KPI '$($Kpi.Id)': '$k' is required." } }
    if (-not $Seen.Add([string]$Kpi.Id)) { throw "KPI Id '$($Kpi.Id)' is used twice." }
    if (@('HigherIsBetter', 'LowerIsBetter') -notcontains $Kpi.Direction) { throw "KPI '$($Kpi.Id)': Direction must be HigherIsBetter or LowerIsBetter." }
    if ($Kpi.ContainsKey('Target') -and "$($Kpi.Target)" -ne '' -and $null -eq (ConvertTo-Number ([string]$Kpi.Target))) { throw "KPI '$($Kpi.Id)': Target must be a number (percent)." }
    foreach ($side in 'Numerator', 'Denominator') {
        $s = $Kpi[$side]
        if ($s -isnot [hashtable]) { throw "KPI '$($Kpi.Id)': $side must be a hashtable." }
        $shapes = @(@('Population', 'Metric', 'Dataset') | Where-Object { $s.ContainsKey($_) -and "$($s[$_])" })
        if ($shapes.Count -ne 1) { throw "KPI '$($Kpi.Id)': $side needs exactly one of Population, Metric or Dataset." }
        if (-not $s.Population -and -not $s.Script) { throw "KPI '$($Kpi.Id)': $side needs Script (e.g. '01' or '01-MfaCoverage')." }
        foreach ($f in @(Get-FilterList $s)) {
            if (-not $f.Column) { throw "KPI '$($Kpi.Id)': $side has a filter without a column." }
            if (@('Equals', 'NotEquals', 'Like', 'Contains', 'Match') -notcontains $f.Mode) { throw "KPI '$($Kpi.Id)': filter mode '$($f.Mode)' is not Equals, NotEquals, Like, Contains or Match." }
        }
    }
}

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $script:AsOfUtc = $null
    if ($AsOf) {
        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParse($AsOf, $script:Inv, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed)) { throw "-AsOf '$AsOf' is not a date. Use UTC ISO 8601, e.g. 2026-11-01T00:00:00Z." }
        $script:AsOfUtc = $parsed
        Write-RunLog ("Using the latest runs at or before {0}" -f $parsed.ToString('yyyy-MM-ddTHH:mm:ssZ'))
    }
    $defHash = (Get-FileHash -LiteralPath $KpiDefinitionPath -Algorithm SHA256).Hash
    $defs = Import-PowerShellDataFile -Path $KpiDefinitionPath
    if (-not $defs.Kpis) { throw "No Kpis = @( ... ) in $KpiDefinitionPath" }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $defs.Kpis) { Test-Definition $k $seen }
    Write-RunLog ("{0} KPI definitions from {1} (SHA-256 {2})" -f @($defs.Kpis).Count, $KpiDefinitionPath, $defHash)

    $rows = foreach ($k in $defs.Kpis) {
        $num = Resolve-Side $k.Numerator 'Numerator'
        $den = Resolve-Side $k.Denominator 'Denominator'
        $notes = [System.Collections.Generic.List[string]]::new()
        foreach ($n in @($num.Note, $den.Note)) { if ($n) { $notes.Add($n) } }
        $status = @($num.Status, $den.Status) | Sort-Object { $script:Severity[$_] } -Descending | Select-Object -First 1
        $value = ''
        if ($script:NoValueStatus -notcontains $status -and $null -ne $num.Count -and $null -ne $den.Count) {
            if ($den.Count -eq 0) { $status = 'Blocked'; $notes.Add('denominator is zero') }
            else {
                $value = [math]::Round(100.0 * $num.Count / $den.Count, 1, [MidpointRounding]::AwayFromZero)
                if ($num.Count -gt $den.Count) {
                    if ($script:Severity[$status] -lt $script:Severity['Partial']) { $status = 'Partial' }
                    $notes.Add('numerator is larger than the denominator: they count different populations; check the definition')
                }
            }
        }
        if ($num.RunUtc -and $den.RunUtc) {
            $spread = [math]::Abs(($num.RunUtc - $den.RunUtc).TotalDays)
            if ($spread -gt $MaxRunSpreadDays) {
                if ($script:Severity[$status] -lt $script:Severity['Partial']) { $status = 'Partial' }
                $notes.Add(('numerator and denominator are {0} days apart (over {1}): they describe different points in time' -f [math]::Round($spread, 1), $MaxRunSpreadDays))
            }
        }
        $target = $(if ($k.ContainsKey('Target') -and "$($k.Target)" -ne '') { ConvertTo-Number ([string]$k.Target) } else { $null })
        $meets = ''
        if ($null -ne $target -and "$value" -ne '') { $meets = $(if ($k.Direction -eq 'HigherIsBetter') { $value -ge $target } else { $value -le $target }) }
        Write-RunLog ("{0}: {1} / {2} = {3} [{4}] {5}" -f $k.Id, $num.Count, $den.Count, $value, $status, ($notes -join '; ')) $(if ($status -eq 'Completed') { 'INFO' } else { 'WARN' })
        [pscustomobject][ordered]@{
            KpiId             = $k.Id
            Name              = $k.Name
            Numerator         = $(if ($null -ne $num.Count) { $num.Count } else { '' })
            Denominator       = $(if ($null -ne $den.Count) { $den.Count } else { '' })
            Value             = $value
            Target            = $(if ($null -ne $target) { $target } else { '' })
            MeetsTarget       = $meets
            Direction         = $k.Direction
            NumeratorSource   = $num.Source
            NumeratorRunUtc   = $(if ($num.RunUtc) { $num.RunUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            NumeratorSha256   = $num.Sha256
            DenominatorSource = $den.Source
            DenominatorRunUtc = $(if ($den.RunUtc) { $den.RunUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            DenominatorSha256 = $den.Sha256
            Status            = $status
            Note              = ($notes -join '; ')
            Description       = $(if ($k.Description) { [string]$k.Description } else { '' })
        }
    }
    $rows = @($rows)
    $notDone = @($rows | Where-Object Status -ne 'Completed').Count
    Export-Dataset -Name 'kpi-summary' -Rows $rows -Status 'Completed' -Note $(if ($notDone) { "$notDone of $($rows.Count) KPI(s) not Completed: see Status and Note" } else { 'Every KPI Completed' })

    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'KPIs defined' $rows.Count -Note (Split-Path $KpiDefinitionPath -Leaf)
    foreach ($s in 'Completed', 'Partial', 'Deferred', 'EvidenceUnavailable', 'Blocked', 'NotRun') { Add-Metric "KPIs $s" @($rows | Where-Object Status -eq $s).Count }
    Add-Metric 'KPIs meeting target' @($rows | Where-Object { $_.MeetsTarget -eq $true }).Count -Note 'Of KPIs with a target and a value'
    Add-Metric 'KPIs missing target' @($rows | Where-Object { $_.MeetsTarget -eq $false }).Count
    Export-Dataset -Name 'summary' -Rows $summary
    $script:ManifestExtra = @{ EvidenceRoot = $EvidenceRoot; KpiDefinitionFile = (Split-Path $KpiDefinitionPath -Leaf); KpiDefinitionSha256 = $defHash; AsOfUtc = $(if ($script:AsOfUtc) { $script:AsOfUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }) }
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Parameters @{ EvidenceRoot = $EvidenceRoot; KpiDefinitionPath = $KpiDefinitionPath; AsOf = $AsOf; MaxRunSpreadDays = $MaxRunSpreadDays }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
