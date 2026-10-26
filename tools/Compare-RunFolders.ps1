<#
.SYNOPSIS
    Before / after evidence for an approved change: compares two run folders of the same script,
    dataset by dataset and row by row, and records what was added, removed and changed.

.DESCRIPTION
    Reads two run folders of one discovery script (for example the run before a change window and the
    rerun after it) and writes:

      - run-diff-summary    one row per dataset: rows before and after, added, removed, changed,
                            unchanged, duplicate keys, the key used, both SHA-256 values and a status
      - run-diff-rows       one row per added, removed or changed row (and per duplicate key), with the
                            changed columns and their before and after values
      - metric-diff         every summary.csv metric side by side, with the delta when both are numbers
      - input-verification  every file listed in both input folders' dataset-status.csv, with the
                            recorded and the current SHA-256

    Input check first: every file in both run folders is hashed and compared with the SHA-256 recorded
    in its dataset-status.csv. A file that no longer matches was changed after the run; its dataset gets
    Status HashMismatch, a loud warning is logged, and the comparison is not evidence until explained.

    Rows are matched on a key. Give it per dataset with -KeyColumns, or let the tool pick the first of
    Id, ObjectId, PrincipalId, PolicyId, UserPrincipalName, Upn, DistinguishedName, SamAccountName that
    is present in both files, never blank and unique on both sides. With none of those, the whole row
    (without the ignored columns) is the key, so a row is either Unchanged, Added or Removed.
    A key that appears more than once on either side is reported as DuplicateKey and is not merged.

    Volatile columns (-IgnoreColumns) are left out of the comparison, so last sign-in times and age
    counters do not show every account as changed. They are still listed in the dataset Note. JSON datasets (for example from 28) are compared
    per array element, top-level property by property.

    Local only: reads the two run folders, writes only its own run folder. Connects to nothing.

    Output: <OutputRoot>\Compare-RunFolders\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER BeforeRunFolder
    The earlier run folder, e.g. D:\Evidence\22-PimRoleSettings\20261020-140501Z

.PARAMETER AfterRunFolder
    The later run folder of the same script.

.PARAMETER Dataset
    Datasets to compare (name or file name). Default: every dataset that is Completed or Partial in
    both runs, except summary (summary.csv is compared in metric-diff).

.PARAMETER KeyColumns
    Key columns per dataset, e.g. @{ 'ca-exclusions' = @('PolicyId', 'ExcludedType', 'ExcludedId') }

.PARAMETER IgnoreColumns
    Column names or wildcard patterns left out of the comparison. Default: values that move every day
    without anyone changing anything - last sign-in, logon and key-use times (*LastSignIn*, *LastLogon*,
    *LastInteractive*, *LastNonInteractive*, *LastSuccessful*, *LastUsedUtc, NewestActivity*), day and
    age counters (DaysSince*, *AgeDays, DaysToExpiry, NextExpiryDays) and ActivityBucket. Settings such
    as MaxActiveDays are compared. Pass @() to compare every column.

.PARAMETER IncludeUnchanged
    Also write Unchanged rows to run-diff-rows.csv.

.PARAMETER Force
    Compare run folders of different scripts. Without it the tool stops.

.PARAMETER OutputRoot
    Where the tool's own run folder goes. Default: the evidence root two levels above -AfterRunFolder.

.EXAMPLE
    .\tools\Compare-RunFolders.ps1 -BeforeRunFolder D:\Evidence\22-PimRoleSettings\20261020-140501Z -AfterRunFolder D:\Evidence\22-PimRoleSettings\20261103-091500Z
.EXAMPLE
    .\tools\Compare-RunFolders.ps1 -BeforeRunFolder D:\Evidence\01-MfaCoverage\20261020-140501Z -AfterRunFolder D:\Evidence\01-MfaCoverage\20261103-091500Z `
        -Dataset ca-exclusions, mfa-registration -KeyColumns @{ 'ca-exclusions' = @('PolicyId', 'ExcludedType', 'ExcludedId') }

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x. Two run folders of the same script.
    Scopes  : none. Reads local files only.
    Licence : none
    Sources : run-manifest.json, dataset-status.csv, summary.csv and the dataset files of both runs.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [Parameter(Mandatory)][string]$BeforeRunFolder,
    [Parameter(Mandatory)][string]$AfterRunFolder,
    [string[]]$Dataset = @(),
    [hashtable]$KeyColumns = @{},
    [string[]]$IgnoreColumns = @('*LastSignIn*', '*LastLogon*', '*LastInteractive*', '*LastNonInteractive*', '*LastSuccessful*', '*LastUsedUtc',
        'NewestActivity*', 'DaysSince*', 'ActivityBucket', '*AgeDays', 'DaysToExpiry', 'NextExpiryDays'),
    [switch]$IncludeUnchanged,
    [switch]$Force,
    [string]$OutputRoot = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = 'Compare-RunFolders'
$ScriptVersion = '1.0.0'

foreach ($f in @($BeforeRunFolder, $AfterRunFolder)) { if (-not (Test-Path -LiteralPath (Join-Path $f 'run-manifest.json'))) { throw "No run-manifest.json in $f - point at a single timestamped run folder." } }
$BeforeRunFolder = (Resolve-Path -LiteralPath $BeforeRunFolder).Path
$AfterRunFolder  = (Resolve-Path -LiteralPath $AfterRunFolder).Path
if ($BeforeRunFolder -eq $AfterRunFolder) { throw 'Before and after are the same run folder.' }
if (-not $OutputRoot) { $OutputRoot = Split-Path (Split-Path $AfterRunFolder -Parent) -Parent }

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
$script:AutoKeyOrder = @('Id', 'ObjectId', 'PrincipalId', 'PolicyId', 'UserPrincipalName', 'Upn', 'DistinguishedName', 'SamAccountName')
$script:MaxValueLength = 200

function Read-CsvSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    if ((Get-Item -LiteralPath $Path).Length -lt 4) { return @() }
    return @(Import-Csv -LiteralPath $Path)
}

function Read-RunInfo {
    # Manifest, dataset-status rows and summary rows of one run folder.
    param([string]$Folder)
    [pscustomobject]@{
        Folder   = $Folder
        Manifest = (Get-Content -LiteralPath (Join-Path $Folder 'run-manifest.json') -Raw | ConvertFrom-Json)
        Status   = @(Read-CsvSafe (Join-Path $Folder 'dataset-status.csv'))
        Summary  = @(Read-CsvSafe (Join-Path $Folder 'summary.csv'))
        Manifest256 = (Get-FileHash -LiteralPath (Join-Path $Folder 'run-manifest.json') -Algorithm SHA256).Hash
    }
}

function Test-RunFileHash {
    # One row per file listed in dataset-status.csv: Verified / Mismatch / MissingFile.
    param($Run, [string]$Side)
    if (-not (Test-Path -LiteralPath (Join-Path $Run.Folder 'dataset-status.csv'))) {
        return @([pscustomobject][ordered]@{ Side = $Side; RunFolder = $Run.Folder; Dataset = ''; File = 'dataset-status.csv'; RecordedSha256 = ''; ActualSha256 = ''; Result = 'MissingFile' })
    }
    foreach ($s in $Run.Status) {
        if (-not $s.File) { continue }
        $path = Join-Path $Run.Folder $s.File
        $actual = $(if (Test-Path -LiteralPath $path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } else { '' })
        $result = $(if (-not $actual) { 'MissingFile' } elseif ($actual -eq "$($s.Sha256)".ToUpperInvariant()) { 'Verified' } else { 'Mismatch' })
        [pscustomobject][ordered]@{ Side = $Side; RunFolder = $Run.Folder; Dataset = $s.Dataset; File = $s.File; RecordedSha256 = $s.Sha256; ActualSha256 = $actual; Result = $result }
    }
}

function Find-StatusRow {
    # Dataset-status row by dataset name, or by file name when the name has an extension.
    param($Run, [string]$Name)
    if ([IO.Path]::GetExtension($Name)) { return @($Run.Status | Where-Object { "$($_.File)" -eq $Name }) | Select-Object -First 1 }
    return @($Run.Status | Where-Object { "$($_.Dataset)" -eq $Name }) | Select-Object -First 1
}

function ConvertTo-CellText {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool] -or $Value -is [ValueType]) { return [string]::Format($script:Inv, '{0}', $Value) }
    return ($Value | ConvertTo-Json -Compress -Depth 20)
}

function Read-DatasetRows {
    # Rows of one dataset as ordered dictionaries of strings, plus the column list. CSV or JSON.
    param([string]$Path)
    $rows = [System.Collections.Generic.List[object]]::new()
    $cols = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Rows = $rows; Columns = $cols } }
    if ([IO.Path]::GetExtension($Path) -eq '.json') {
        $raw = Get-Content -LiteralPath $Path -Raw
        if ($raw -and $raw.Trim()) {
            $data = $raw | ConvertFrom-Json
            foreach ($item in @($data)) {
                $d = [ordered]@{}
                if ($item -is [System.Management.Automation.PSCustomObject]) {
                    foreach ($p in $item.PSObject.Properties) { $d[$p.Name] = ConvertTo-CellText $p.Value; if (-not $cols.Contains($p.Name)) { $cols.Add($p.Name) } }
                }
                else { $d['Value'] = ConvertTo-CellText $item; if (-not $cols.Contains('Value')) { $cols.Add('Value') } }
                $rows.Add($d)
            }
        }
    }
    else {
        foreach ($r in (Read-CsvSafe $Path)) {
            $d = [ordered]@{}
            foreach ($p in $r.PSObject.Properties) { $d[$p.Name] = [string]$p.Value; if (-not $cols.Contains($p.Name)) { $cols.Add($p.Name) } }
            $rows.Add($d)
        }
    }
    return [pscustomobject]@{ Rows = $rows; Columns = $cols }
}

function Test-IgnoredColumn {
    param([string]$Column)
    foreach ($p in $IgnoreColumns) { if ($Column -like $p) { return $true } }
    return $false
}

function Find-AutoKey {
    # First candidate column present in both, never blank and unique on both sides.
    param($Before, $After)
    foreach ($cand in $script:AutoKeyOrder) {
        $bc = @($Before.Columns | Where-Object { $_ -eq $cand }) | Select-Object -First 1
        $ac = @($After.Columns | Where-Object { $_ -eq $cand }) | Select-Object -First 1
        if (-not $bc -or -not $ac) { continue }
        $ok = $true
        foreach ($side in @(@{ Rows = $Before.Rows; Col = $bc }, @{ Rows = $After.Rows; Col = $ac })) {
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($r in $side.Rows) {
                $v = "$($r[$side.Col])"
                if (-not $v -or -not $seen.Add($v)) { $ok = $false; break }
            }
            if (-not $ok) { break }
        }
        if ($ok) { return @($bc) }
    }
    return @()
}

function Get-RowKey {
    param($Row, [string[]]$Keys, [string[]]$Compared)
    if ($Keys.Count) { return (($Keys | ForEach-Object { "$($Row[$_])" }) -join ' | ') }
    $text = ($Compared | ForEach-Object { '{0}={1}' -f $_, $Row[$_] }) -join [char]31
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return 'row:' + (([BitConverter]::ToString($bytes) -replace '-', '').Substring(0, 16))
}

function Format-Compact {
    # "col=val; col=val" for the given columns; long values cut to MaxValueLength.
    param($Row, [string[]]$Columns, [switch]$SkipBlank)
    $parts = foreach ($c in $Columns) {
        $v = "$($Row[$c])"
        if ($SkipBlank -and -not $v) { continue }
        if ($v.Length -gt $script:MaxValueLength) { $v = $v.Substring(0, $script:MaxValueLength) + '...' }
        '{0}={1}' -f $c, $v
    }
    return ($parts -join '; ')
}

function ConvertTo-UtcDate {
    # Manifest times: a string in PowerShell 5.1, already a DateTime after ConvertFrom-Json in 7.
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse("$Value", $script:Inv, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
}

function ConvertTo-Number {
    param([string]$Value)
    $d = 0.0
    if ($Value -match '^\s*-?\d+(\.\d+)?\s*$' -and [double]::TryParse($Value, [Globalization.NumberStyles]::Float, $script:Inv, [ref]$d)) { return $d }
    return $null
}

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $before = Read-RunInfo $BeforeRunFolder
    $after  = Read-RunInfo $AfterRunFolder
    Write-RunLog ("Before: {0} v{1} {2}" -f $before.Manifest.Script, $before.Manifest.ScriptVersion, $BeforeRunFolder)
    Write-RunLog ("After : {0} v{1} {2}" -f $after.Manifest.Script, $after.Manifest.ScriptVersion, $AfterRunFolder)
    if ("$($before.Manifest.Script)" -ne "$($after.Manifest.Script)") {
        if (-not $Force) { throw ("The run folders are from different scripts ({0} and {1}). Use -Force to compare anyway." -f $before.Manifest.Script, $after.Manifest.Script) }
        Write-RunLog ("Different scripts compared (-Force): {0} and {1}" -f $before.Manifest.Script, $after.Manifest.Script) 'WARN'
    }
    if ("$($before.Manifest.ScriptVersion)" -ne "$($after.Manifest.ScriptVersion)") { Write-RunLog ("Script versions differ ({0} and {1}): columns may differ" -f $before.Manifest.ScriptVersion, $after.Manifest.ScriptVersion) 'WARN' }
    $beforeTime = ConvertTo-UtcDate $before.Manifest.StartedUtc
    $afterTime  = ConvertTo-UtcDate $after.Manifest.StartedUtc
    if ($afterTime -lt $beforeTime) { Write-RunLog 'The after run is older than the before run. Check the order of the parameters.' 'WARN' }

    # ---- 1. Verify both input folders against their recorded SHA-256 ----
    $verify = @(Test-RunFileHash $before 'Before') + @(Test-RunFileHash $after 'After')
    $bad = @($verify | Where-Object { $_.Result -ne 'Verified' })
    foreach ($b in $bad) { Write-RunLog ("EVIDENCE ALTERED OR MISSING: {0} {1} -> {2} (recorded {3}, now {4})" -f $b.Side, $b.File, $b.Result, $b.RecordedSha256, $b.ActualSha256) 'ERROR' }
    if ($bad.Count) { Write-Warning ("{0} input file(s) do not match the SHA-256 recorded at run time. Those datasets are marked HashMismatch and are not evidence until explained." -f $bad.Count) }
    else { Write-RunLog ("Input check: {0} file(s) verified against dataset-status.csv" -f $verify.Count) }
    Export-Dataset -Name 'input-verification' -Rows $verify -Status $(if ($bad.Count) { 'Partial' } else { 'Completed' }) -Note $(if ($bad.Count) { "$($bad.Count) file(s) altered or missing since the run" } else { 'Every input file matches its recorded SHA-256' })
    $mismatch = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($b in $bad) { [void]$mismatch.Add("$($b.Side)|$($b.File)") }

    # ---- 2. Which datasets ----
    $okStatus = @('Completed', 'Partial')
    $names = [System.Collections.Generic.List[string]]::new()
    if ($Dataset.Count) { foreach ($d in $Dataset) { $names.Add($d) } }
    else {
        foreach ($s in $after.Status) {
            if ($s.Dataset -eq 'summary' -or -not $s.File -or $okStatus -notcontains $s.Status) { continue }
            $bs = Find-StatusRow $before $s.File
            if ($bs -and $okStatus -contains $bs.Status) { $names.Add([string]$s.File) }
        }
        foreach ($s in $before.Status) {
            if ($s.Dataset -eq 'summary') { continue }
            $as = $(if ($s.File) { Find-StatusRow $after $s.File } else { Find-StatusRow $after $s.Dataset })
            if ($names -notcontains $s.File -and (-not $as -or $okStatus -notcontains $as.Status -or $okStatus -notcontains $s.Status)) {
                Write-RunLog ("{0}: not compared (before {1}, after {2})" -f $s.Dataset, $s.Status, $(if ($as) { $as.Status } else { 'not in run' })) 'WARN'
            }
        }
    }

    # ---- 3. Compare each dataset ----
    $summaryRows = [System.Collections.Generic.List[object]]::new()
    $diffRows = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $names) {
        $bs = Find-StatusRow $before $name
        $as = Find-StatusRow $after $name
        $label = $(if ($as) { $as.Dataset } elseif ($bs) { $bs.Dataset } else { [IO.Path]::GetFileNameWithoutExtension($name) })
        $row = [ordered]@{ Dataset = $label; BeforeRows = ''; AfterRows = ''; Added = ''; Removed = ''; Changed = ''; Unchanged = ''; DuplicateKeys = ''
            KeyColumns = ''; BeforeSha256 = $(if ($bs) { $bs.Sha256 } else { '' }); AfterSha256 = $(if ($as) { $as.Sha256 } else { '' })
            BeforeStatus = $(if ($bs) { $bs.Status } else { 'NotInRun' }); AfterStatus = $(if ($as) { $as.Status } else { 'NotInRun' }); Status = ''; Note = '' }
        if (-not $bs -or -not $as -or $okStatus -notcontains $bs.Status -or $okStatus -notcontains $as.Status -or -not $bs.File -or -not $as.File) {
            $row.Status = 'NotComparable'
            $row.Note = Join-Values @($(if ($bs -and $bs.Note -and $okStatus -notcontains $bs.Status) { "before: $($bs.Note)" }), $(if ($as -and $as.Note -and $okStatus -notcontains $as.Status) { "after: $($as.Note)" }), 'Only Completed or Partial datasets are compared; a Blocked or missing dataset is never read as zero rows')
            $summaryRows.Add([pscustomobject]$row); Write-RunLog ("{0}: NotComparable (before {1}, after {2})" -f $label, $row.BeforeStatus, $row.AfterStatus) 'WARN'
            continue
        }
        $b = Read-DatasetRows (Join-Path $BeforeRunFolder $bs.File)
        $a = Read-DatasetRows (Join-Path $AfterRunFolder $as.File)
        $notes = [System.Collections.Generic.List[string]]::new()

        $common = @($a.Columns | Where-Object { $b.Columns -contains $_ })
        $onlyBefore = @($b.Columns | Where-Object { $a.Columns -notcontains $_ })
        $onlyAfter = @($a.Columns | Where-Object { $b.Columns -notcontains $_ })
        if ($onlyBefore.Count) { $notes.Add("columns only before (not compared): $($onlyBefore -join ', ')") }
        if ($onlyAfter.Count) { $notes.Add("columns only after (not compared): $($onlyAfter -join ', ')") }
        $ignored = @($common | Where-Object { Test-IgnoredColumn $_ })
        $compared = @($common | Where-Object { $ignored -notcontains $_ })
        if ($ignored.Count) { $notes.Add("ignored: $($ignored -join ', ')") }

        # Key
        $keys = @()
        $given = $null
        foreach ($k in @($KeyColumns.Keys)) { if ($k -eq $label -or $k -eq $name -or $k -eq $as.File) { $given = @($KeyColumns[$k]) } }
        if ($given) {
            $missingKey = @($given | Where-Object { $common -notcontains $_ })
            if ($missingKey.Count) { throw ("{0}: key column(s) {1} not in both files. Columns: {2}" -f $label, ($missingKey -join ', '), ($common -join ', ')) }
            $keys = $given; $keyText = $keys -join ' + '
        }
        else {
            $keys = @(Find-AutoKey $b $a)
            $keyText = $(if ($keys.Count) { $keys -join ' + ' } else { '(whole row)' })
        }
        $valueCols = @($compared | Where-Object { $keys -notcontains $_ })

        $bIndex = @{}; $aIndex = @{}
        foreach ($pair in @(@{ Src = $b.Rows; Idx = $bIndex }, @{ Src = $a.Rows; Idx = $aIndex })) {
            foreach ($r in $pair.Src) {
                $k = Get-RowKey -Row $r -Keys $keys -Compared $compared
                $kl = $k.ToLowerInvariant()
                if (-not $pair.Idx.ContainsKey($kl)) { $pair.Idx[$kl] = [System.Collections.Generic.List[object]]::new() }
                $pair.Idx[$kl].Add([pscustomobject]@{ Key = $k; Row = $r })
            }
        }
        $added = 0; $removed = 0; $changed = 0; $unchanged = 0; $dups = 0
        $allKeys = [System.Collections.Generic.List[string]]::new()
        foreach ($k in $bIndex.Keys) { $allKeys.Add($k) }
        foreach ($k in $aIndex.Keys) { if (-not $bIndex.ContainsKey($k)) { $allKeys.Add($k) } }
        foreach ($k in ($allKeys | Sort-Object)) {
            $bl = @(); if ($bIndex.ContainsKey($k)) { $bl = $bIndex[$k].ToArray() }
            $al = @(); if ($aIndex.ContainsKey($k)) { $al = $aIndex[$k].ToArray() }
            $shown = $(if ($al.Count) { $al[0].Key } else { $bl[0].Key })
            if ($bl.Count -gt 1 -or $al.Count -gt 1) {
                $dups++
                $diffRows.Add([pscustomobject][ordered]@{ Dataset = $label; Key = $shown; ChangeType = 'DuplicateKey'; ChangedColumns = ''
                        Before = $(if ($bl.Count) { "$($bl.Count) rows; first: " + (Format-Compact $bl[0].Row $compared -SkipBlank) } else { '0 rows' })
                        After = $(if ($al.Count) { "$($al.Count) rows; first: " + (Format-Compact $al[0].Row $compared -SkipBlank) } else { '0 rows' }) })
                continue
            }
            if (-not $bl.Count) {
                $added++
                $diffRows.Add([pscustomobject][ordered]@{ Dataset = $label; Key = $shown; ChangeType = 'Added'; ChangedColumns = ''; Before = ''; After = (Format-Compact $al[0].Row $compared -SkipBlank) })
                continue
            }
            if (-not $al.Count) {
                $removed++
                $diffRows.Add([pscustomobject][ordered]@{ Dataset = $label; Key = $shown; ChangeType = 'Removed'; ChangedColumns = ''; Before = (Format-Compact $bl[0].Row $compared -SkipBlank); After = '' })
                continue
            }
            $br = $bl[0].Row; $ar = $al[0].Row
            $diffCols = @($valueCols | Where-Object { -not [string]::Equals("$($br[$_])", "$($ar[$_])", [StringComparison]::Ordinal) })
            if ($diffCols.Count) {
                $changed++
                $diffRows.Add([pscustomobject][ordered]@{ Dataset = $label; Key = $shown; ChangeType = 'Changed'; ChangedColumns = ($diffCols -join ', '); Before = (Format-Compact $br $diffCols); After = (Format-Compact $ar $diffCols) })
            }
            else {
                $unchanged++
                if ($IncludeUnchanged) { $diffRows.Add([pscustomobject][ordered]@{ Dataset = $label; Key = $shown; ChangeType = 'Unchanged'; ChangedColumns = ''; Before = ''; After = '' }) }
            }
        }

        $row.BeforeRows = $b.Rows.Count; $row.AfterRows = $a.Rows.Count
        $row.Added = $added; $row.Removed = $removed; $row.Changed = $changed; $row.Unchanged = $unchanged; $row.DuplicateKeys = $dups
        $row.KeyColumns = $keyText
        if ("$($bs.Rows)" -ne '' -and [int]$bs.Rows -ne $b.Rows.Count) { $notes.Add("before: dataset-status says $($bs.Rows) rows, file has $($b.Rows.Count)") }
        if ("$($as.Rows)" -ne '' -and [int]$as.Rows -ne $a.Rows.Count) { $notes.Add("after: dataset-status says $($as.Rows) rows, file has $($a.Rows.Count)") }
        if ($dups) { $notes.Add("$dups key(s) occur more than once: listed as DuplicateKey, not compared. Give -KeyColumns for this dataset") }
        $altered = @(@("Before|$($bs.File)", "After|$($as.File)") | Where-Object { $mismatch.Contains($_) })
        if ($altered.Count) {
            $row.Status = 'HashMismatch'
            $notes.Insert(0, ("EVIDENCE ALTERED: {0} no longer match(es) the SHA-256 recorded at run time; do not use this comparison as evidence" -f (($altered | ForEach-Object { ($_ -split '\|')[0].ToLowerInvariant() + ' file' }) -join ' and ')))
        }
        elseif ($dups) { $row.Status = 'Partial' }
        elseif ($bs.Status -eq 'Partial' -or $as.Status -eq 'Partial') {
            $row.Status = 'Partial'
            $notes.Add('a side is Partial: part of the source was not read, so Added / Removed may reflect the gap, not a change')
        }
        else { $row.Status = 'Compared' }
        $row.Note = $notes -join '; '
        $summaryRows.Add([pscustomobject]$row)
        Write-RunLog ("{0}: {1} -> {2} rows; +{3} -{4} ~{5} ={6} dup {7} [{8}] key {9}" -f $label, $row.BeforeRows, $row.AfterRows, $added, $removed, $changed, $unchanged, $dups, $row.Status, $keyText) $(if ($row.Status -eq 'HashMismatch') { 'ERROR' } else { 'INFO' })
    }

    $altCount = @($summaryRows | Where-Object Status -eq 'HashMismatch').Count
    Export-Dataset -Name 'run-diff-summary' -Rows $summaryRows -Status $(if ($altCount) { 'Partial' } else { 'Completed' }) -Note $(if ($altCount) { "$altCount dataset(s) HashMismatch: input evidence altered" } else { "Key per dataset in KeyColumns; ignored columns in Note" })
    Export-Dataset -Name 'run-diff-rows' -Rows $diffRows -Status $(if ($altCount) { 'Partial' } else { 'Completed' }) -Note $(if ($IncludeUnchanged) { 'Added, Removed, Changed, DuplicateKey and Unchanged rows' } else { 'Added, Removed, Changed and DuplicateKey rows (Unchanged counted in run-diff-summary only)' })

    # ---- 4. summary.csv metrics side by side ----
    $bSum = @{}; foreach ($m in $before.Summary) { if (-not $bSum.ContainsKey($m.Metric)) { $bSum[$m.Metric] = $m } }
    $aSum = @{}; foreach ($m in $after.Summary) { if (-not $aSum.ContainsKey($m.Metric)) { $aSum[$m.Metric] = $m } }
    $order = [System.Collections.Generic.List[string]]::new()
    foreach ($m in $after.Summary) { if (-not $order.Contains($m.Metric)) { $order.Add($m.Metric) } }
    foreach ($m in $before.Summary) { if (-not $order.Contains($m.Metric)) { $order.Add($m.Metric) } }
    $metricRows = foreach ($name in $order) {
        $bm = $bSum[$name]; $am = $aSum[$name]
        $bv = $(if ($bm) { [string]$bm.Value } else { '' }); $av = $(if ($am) { [string]$am.Value } else { '' })
        $bn = ConvertTo-Number $bv; $an = ConvertTo-Number $av
        [pscustomobject][ordered]@{
            Metric     = $name
            Before     = $bv
            After      = $av
            Delta      = $(if ($null -ne $bn -and $null -ne $an) { ($an - $bn).ToString('0.##', $script:Inv) } else { '' })
            Change     = $(if (-not $bm) { 'OnlyAfter' } elseif (-not $am) { 'OnlyBefore' } elseif ($bv -ceq $av) { 'Same' } else { 'Changed' })
            BeforeNote = $(if ($bm) { $bm.Note } else { '' })
            AfterNote  = $(if ($am) { $am.Note } else { '' })
        }
    }
    $sumAltered = @($bad | Where-Object { $_.File -eq 'summary.csv' })
    if (-not $before.Summary.Count -and -not $after.Summary.Count) { Set-DatasetStatus -Name 'metric-diff' -Status 'EvidenceUnavailable' -Note 'Neither run folder has a summary.csv' }
    else {
        Export-Dataset -Name 'metric-diff' -Rows @($metricRows) -Status $(if ($sumAltered.Count) { 'Partial' } else { 'Completed' }) -Note $(if ($sumAltered.Count) { 'EVIDENCE ALTERED: summary.csv does not match its recorded SHA-256 (' + (($sumAltered | ForEach-Object { $_.Side }) -join ', ') + ')' } else { 'Delta = after - before, when both values are numbers' })
    }
    $script:ManifestExtra = @{
        BeforeRunFolder = $BeforeRunFolder; BeforeScript = $before.Manifest.Script; BeforeScriptVersion = $before.Manifest.ScriptVersion; BeforeStartedUtc = $beforeTime.ToString('yyyy-MM-ddTHH:mm:ssZ'); BeforeManifestSha256 = $before.Manifest256
        AfterRunFolder = $AfterRunFolder; AfterScript = $after.Manifest.Script; AfterScriptVersion = $after.Manifest.ScriptVersion; AfterStartedUtc = $afterTime.ToString('yyyy-MM-ddTHH:mm:ssZ'); AfterManifestSha256 = $after.Manifest256
        InputFilesAltered = $bad.Count
    }
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Parameters @{ BeforeRunFolder = $BeforeRunFolder; AfterRunFolder = $AfterRunFolder; Dataset = $Dataset; KeyColumns = $KeyColumns; IgnoreColumns = $IgnoreColumns; IncludeUnchanged = [bool]$IncludeUnchanged; Force = [bool]$Force }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
