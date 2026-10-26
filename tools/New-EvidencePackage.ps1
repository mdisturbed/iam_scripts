<#
.SYNOPSIS
    Evidence intake log and per-deliverable evidence index: which runs are in the evidence folder, whether
    their files still match the SHA-256 recorded at run time, and which deliverables they complete.

.DESCRIPTION
    Reads every run folder under -EvidenceRoot (NN-Name\yyyyMMdd-HHmmssZ, and the tool folders such as
    Compare-RunFolders and Get-KpiSummary), re-hashes every file listed in each dataset-status.csv, and
    checks the hashes against run-manifest.json as well. Then reads a deliverable map (which scripts and
    datasets each deliverable needs) and writes:

      - evidence-intake-log   one row per run folder: script, version, times, run account, machine, tenant
                              or domain, dataset counts per status, hash check, SHA-256 of the manifest
      - evidence-datasets     every dataset of the selected runs: status, rows, recorded and current SHA-256
      - deliverable-status    one row per deliverable: required scripts and datasets, present, missing,
                              status rollup and the run folders used as evidence
      - evidence-index.md     the same per deliverable, readable: status, evidence paths and hashes

    Status rollup per deliverable (most serious wins):
      HashMismatch          a required file no longer matches its recorded SHA-256 (evidence altered)
      NotRun                a required script has no run in the evidence folder (or the pinned run is absent)
      Blocked / EvidenceUnavailable / Deferred / Partial
                            carried from the required dataset(s), named in the Note; a required dataset the
                            run did not produce is EvidenceUnavailable
      Completed             every required dataset is Completed and verified

    Runs: by default the latest run of each script. A map entry can pin a run (Run = 'yyyyMMdd-HHmmssZ'),
    for example a frozen baseline. -IncludeAllRuns lists every run in the intake log and datasets file;
    deliverables still use the latest or pinned run.

    -CopyTo builds a package: the selected run folders (latest or pinned, or every run with
    -IncludeAllRuns) and the index files are copied into a new folder, each copy is re-hashed against its
    source, and package-manifest.csv lists every copied file with its SHA-256. Copying uses
    [System.IO.Directory]::CreateDirectory and [System.IO.File]::Copy (no overwrite) so the tool stays
    within the read-only command list checked by Test-ReadOnly.ps1. The target must be new or empty.

    Local only: reads the evidence folder, writes its own run folder (and -CopyTo). Connects to nothing.

    Output: <OutputRoot>\New-EvidencePackage\<yyyyMMdd-HHmmssZ>\*.csv, evidence-index.md + run-manifest.json + run.log

.PARAMETER EvidenceRoot
    Folder holding the run folders.

.PARAMETER DeliverableMapPath
    Deliverable map (PowerShell data file). Default: examples\deliverable-map.example.psd1 in the repository.

.PARAMETER IncludeAllRuns
    List every run folder in the intake log, the datasets file and the package, not only the latest per script.

.PARAMETER CopyTo
    Build an evidence package in this folder (new or empty).

.PARAMETER OutputRoot
    Where the tool's own run folder goes. Default: -EvidenceRoot.

.EXAMPLE
    .\tools\New-EvidencePackage.ps1 -EvidenceRoot D:\Evidence
.EXAMPLE
    .\tools\New-EvidencePackage.ps1 -EvidenceRoot D:\Evidence -DeliverableMapPath D:\Programme\deliverable-map.psd1 -CopyTo E:\Packages\G1-20261103

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x.
    Scopes  : none. Reads local files only.
    Licence : none
    Sources : run-manifest.json, dataset-status.csv and dataset files of every run under -EvidenceRoot.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [string]$DeliverableMapPath = '',
    [switch]$IncludeAllRuns,
    [string]$CopyTo = '',
    [string]$OutputRoot = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = 'New-EvidencePackage'
$ScriptVersion = '1.0.0'

if (-not (Test-Path -LiteralPath $EvidenceRoot)) { throw "Evidence folder not found: $EvidenceRoot" }
$EvidenceRoot = (Resolve-Path -LiteralPath $EvidenceRoot).Path
if (-not $DeliverableMapPath) { $DeliverableMapPath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'examples') 'deliverable-map.example.psd1' }
if (-not (Test-Path -LiteralPath $DeliverableMapPath)) { throw "Deliverable map not found: $DeliverableMapPath" }
if ($CopyTo) {
    $CopyTo = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CopyTo)
    if ((Test-Path -LiteralPath $CopyTo) -and @(Get-ChildItem -LiteralPath $CopyTo -Force).Count) { throw "-CopyTo folder is not empty: $CopyTo. Use a new folder so the package holds only this selection." }
}
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
$script:Severity = @{ Completed = 0; Partial = 1; Deferred = 2; EvidenceUnavailable = 3; Blocked = 4; NotRun = 5; HashMismatch = 6 }

function Read-CsvSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    if ((Get-Item -LiteralPath $Path).Length -lt 4) { return @() }
    return @(Import-Csv -LiteralPath $Path)
}

function Export-TextDataset {
    # Writes a text output (Markdown) to the run folder and records it with SHA-256 like a CSV dataset.
    param([string]$Name, [string]$FileName, [string]$Text, [string]$Note = '')
    $file = Join-Path $script:RunFolder $FileName
    Set-Content -Path $file -Value $Text -Encoding UTF8
    $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
    $script:Datasets.Add([pscustomobject][ordered]@{ Dataset = $Name; Status = 'Completed'; Rows = ''; File = $FileName; Sha256 = $hash; Note = $Note })
    Write-RunLog ("{0}: written [{1}]" -f $FileName, $hash)
}

function ConvertTo-UtcText {
    # Manifest times: a string in PowerShell 5.1, already a DateTime after ConvertFrom-Json in 7.
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return "$Value"
}

function Get-RelativePath {
    param([string]$Path)
    if ($Path.StartsWith($EvidenceRoot, [StringComparison]::OrdinalIgnoreCase)) { return $Path.Substring($EvidenceRoot.Length).TrimStart('\', '/') }
    return $Path
}

function Get-WorstStatus {
    param([string[]]$Statuses)
    $worst = 'Completed'
    foreach ($s in $Statuses) { if ($s -and $script:Severity.ContainsKey($s) -and $script:Severity[$s] -gt $script:Severity[$worst]) { $worst = $s } }
    return $worst
}

function Read-RunFolder {
    # Manifest, dataset-status rows re-hashed and cross-checked with the manifest's dataset list.
    param([System.IO.DirectoryInfo]$Dir)
    $manifestPath = Join-Path $Dir.FullName 'run-manifest.json'
    $manifest = $null; $manifestError = ''
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json } catch { $manifestError = $_.Exception.Message }
    $statusPath = Join-Path $Dir.FullName 'dataset-status.csv'
    $statusRows = @(Read-CsvSafe $statusPath)
    $mDatasets = @{}
    if ($manifest -and $manifest.Datasets) { foreach ($d in @($manifest.Datasets)) { if ($d.File) { $mDatasets["$($d.File)".ToLowerInvariant()] = "$($d.Sha256)".ToUpperInvariant() } } }
    $ds = foreach ($s in $statusRows) {
        $actual = ''; $check = 'NoFile'
        if ($s.File) {
            $path = Join-Path $Dir.FullName $s.File
            if (Test-Path -LiteralPath $path) {
                $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
                $recorded = "$($s.Sha256)".ToUpperInvariant()
                $inManifest = $(if ($mDatasets.ContainsKey("$($s.File)".ToLowerInvariant())) { $mDatasets["$($s.File)".ToLowerInvariant()] } else { $null })
                $check = $(if (-not $recorded) { 'NotRecorded' } elseif ($actual -ne $recorded) { 'Mismatch' } elseif ($null -ne $inManifest -and $inManifest -ne $recorded) { 'Mismatch' } else { 'Verified' })
            }
            else { $check = 'MissingFile' }
        }
        [pscustomobject]@{ Dataset = "$($s.Dataset)"; Status = "$($s.Status)"; Rows = "$($s.Rows)"; File = "$($s.File)"; RecordedSha256 = "$($s.Sha256)"; ActualSha256 = $actual; HashCheck = $check; Note = "$($s.Note)" }
    }
    $ds = @($ds)
    $checks = @($ds | ForEach-Object { $_.HashCheck })
    $hashCheck = $(if (-not (Test-Path -LiteralPath $statusPath)) { 'MissingFile' } elseif ($checks -contains 'Mismatch') { 'Mismatch' } elseif ($checks -contains 'MissingFile') { 'MissingFile' } else { 'Verified' })
    $counted = @($ds | Where-Object { $_.Dataset -ne 'summary' })
    [pscustomobject]@{
        Dir = $Dir; ScriptFolder = $Dir.Parent.Name; RunName = $Dir.Name; Folder = $Dir.FullName
        Manifest = $manifest; ManifestError = $manifestError
        ManifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
        Datasets = $ds; Counted = $counted; HashCheck = $hashCheck
    }
}

function Get-ScriptKey {
    # '01' for '01-MfaCoverage', otherwise the folder name (tool folders).
    param([string]$Folder)
    if ($Folder -match '^(\d\d)-') { return $Matches[1] }
    return $Folder
}

function Find-RunDataset {
    # Dataset row by dataset name, or by file name when the name has an extension.
    param($Run, [string]$Name)
    if ([IO.Path]::GetExtension($Name) -in @('.csv', '.json', '.md', '.txt', '.html')) { return @($Run.Datasets | Where-Object { $_.File -eq $Name }) | Select-Object -First 1 }
    $hit = @($Run.Datasets | Where-Object { $_.Dataset -eq $Name }) | Select-Object -First 1
    if ($hit) { return $hit }
    return @($Run.Datasets | Where-Object { $_.File -and [IO.Path]::GetFileNameWithoutExtension($_.File) -eq $Name }) | Select-Object -First 1
}

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $mapHash = (Get-FileHash -LiteralPath $DeliverableMapPath -Algorithm SHA256).Hash
    $map = Import-PowerShellDataFile -Path $DeliverableMapPath
    if (-not $map.Deliverables) { throw "No Deliverables = @( ... ) in $DeliverableMapPath" }
    $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $map.Deliverables) {
        if (-not $d.Id -or -not $d.Deliverable) { throw 'Every deliverable needs Id and Deliverable.' }
        if (-not $ids.Add([string]$d.Id)) { throw "Deliverable Id '$($d.Id)' is used twice." }
        if (-not $d.Requires -or -not @($d.Requires).Count) { throw "Deliverable '$($d.Id)': Requires is empty." }
        foreach ($r in @($d.Requires)) {
            if (-not $r.Script) { throw "Deliverable '$($d.Id)': every Requires entry needs Script." }
            if ($r.Run -and "$($r.Run)" -notmatch '^\d{8}-\d{6}Z$') { throw "Deliverable '$($d.Id)': Run '$($r.Run)' is not a run folder name (yyyyMMdd-HHmmssZ)." }
        }
    }
    Write-RunLog ("Deliverable map: {0} deliverables from {1} (SHA-256 {2})" -f @($map.Deliverables).Count, $DeliverableMapPath, $mapHash)

    # ---- 1. Every run folder ----
    $runDirs = @(Get-ChildItem -LiteralPath $EvidenceRoot -Directory | Where-Object { $_.Name -ne $ScriptName } |
            ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
            Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'run-manifest.json')) })
    $all = @($runDirs | Sort-Object { $_.Parent.Name }, Name | ForEach-Object { Read-RunFolder $_ })
    Write-RunLog ("{0} run folder(s) in {1} scripts / tools" -f $all.Count, @($all | Select-Object -ExpandProperty ScriptFolder -Unique).Count)
    $latest = @{}
    foreach ($r in $all) { $latest[$r.ScriptFolder] = $r }   # sorted by name, so the last one wins
    $byKey = @{}
    foreach ($f in $latest.Keys) { $k = Get-ScriptKey $f; if (-not $byKey.ContainsKey($k) -or $latest[$f].RunName -gt $byKey[$k].RunName) { $byKey[$k] = $latest[$f] } }

    # Runs used: latest per script, plus any pinned in the map
    $used = [System.Collections.Generic.List[object]]::new()
    foreach ($f in ($latest.Keys | Sort-Object)) { $used.Add($latest[$f]) }
    foreach ($d in $map.Deliverables) {
        foreach ($r in @($d.Requires)) {
            if (-not $r.Run) { continue }
            $k = Get-ScriptKey ([string]$r.Script)
            $pin = @($all | Where-Object { ((Get-ScriptKey $_.ScriptFolder) -eq $k -or $_.ScriptFolder -eq $r.Script) -and $_.RunName -eq $r.Run }) | Select-Object -First 1
            if ($pin -and -not $used.Contains($pin)) { $used.Add($pin) }
        }
    }
    $selected = $(if ($IncludeAllRuns) { $all } else { @($used | Sort-Object ScriptFolder, RunName) })

    # ---- 2. Intake log and datasets ----
    $intake = foreach ($r in $selected) {
        $m = $r.Manifest
        $runAs = $(if ($m) { @($m.GraphAccount, $(if ($m.Extra) { $m.Extra.AwsCallerArn }), $m.RunAsWindows) | Where-Object { $_ } | Select-Object -First 1 } else { '' })
        [pscustomobject][ordered]@{
            Script         = $(if ($m -and $m.Script) { $m.Script } else { $r.ScriptFolder })
            ScriptVersion  = $(if ($m) { $m.ScriptVersion } else { '' })
            RunFolder      = Get-RelativePath $r.Folder
            StartedUtc     = $(if ($m -and $m.StartedUtc) { ConvertTo-UtcText $m.StartedUtc } else { '' })
            FinishedUtc    = $(if ($m -and $m.FinishedUtc) { ConvertTo-UtcText $m.FinishedUtc } else { '' })
            RunAs          = $runAs
            Machine        = $(if ($m) { $m.Machine } else { '' })
            TenantId       = $(if ($m) { $m.TenantId } else { '' })
            Domain         = $(if ($m) { $m.Domain } else { '' })
            DatasetCount   = $r.Counted.Count
            Completed      = @($r.Counted | Where-Object Status -eq 'Completed').Count
            Partial        = @($r.Counted | Where-Object Status -eq 'Partial').Count
            Blocked        = @($r.Counted | Where-Object Status -eq 'Blocked').Count
            Deferred       = @($r.Counted | Where-Object Status -eq 'Deferred').Count
            EvidenceUnavailable = @($r.Counted | Where-Object Status -eq 'EvidenceUnavailable').Count
            HashCheck      = $r.HashCheck
            ManifestSha256 = $r.ManifestSha256
            Latest         = [bool]($latest[$r.ScriptFolder] -eq $r)
            Note           = Join-Values @($(if ($r.ManifestError) { "run-manifest.json unreadable: $($r.ManifestError)" }), $(if ($r.HashCheck -ne 'Verified') { 'EVIDENCE ALTERED OR INCOMPLETE: ' + (Join-Values ($r.Datasets | Where-Object { $_.HashCheck -in @('Mismatch', 'MissingFile') } | ForEach-Object { "$($_.File) $($_.HashCheck)" })) }))
        }
        if ($r.HashCheck -ne 'Verified') { Write-RunLog ("EVIDENCE ALTERED OR INCOMPLETE: {0} {1}" -f (Get-RelativePath $r.Folder), $r.HashCheck) 'ERROR' }
    }
    $intake = @($intake)
    $badRuns = @($intake | Where-Object HashCheck -ne 'Verified').Count
    if ($badRuns) { Write-Warning "$badRuns run folder(s) have files that no longer match the SHA-256 recorded at run time. See evidence-intake-log.csv." }
    Export-Dataset -Name 'evidence-intake-log' -Rows $intake -Note $(if ($IncludeAllRuns) { 'Every run folder' } else { 'Latest run per script plus pinned runs; -IncludeAllRuns for every run' })

    $dsRows = foreach ($r in $selected) {
        foreach ($d in $r.Datasets) {
            [pscustomobject][ordered]@{
                Script = $(if ($r.Manifest -and $r.Manifest.Script) { $r.Manifest.Script } else { $r.ScriptFolder }); RunFolder = Get-RelativePath $r.Folder
                Dataset = $d.Dataset; Status = $d.Status; Rows = $d.Rows; File = $d.File
                RecordedSha256 = $d.RecordedSha256; ActualSha256 = $d.ActualSha256; HashCheck = $d.HashCheck; Note = $d.Note
            }
        }
    }
    Export-Dataset -Name 'evidence-datasets' -Rows @($dsRows) -Note 'HashCheck: Verified / Mismatch (file or manifest differs) / MissingFile / NoFile (Blocked, Deferred or EvidenceUnavailable: nothing written)'

    # ---- 3. Deliverables ----
    $delRows = [System.Collections.Generic.List[object]]::new()
    $detail = @{}
    foreach ($d in $map.Deliverables) {
        $statuses = [System.Collections.Generic.List[string]]::new()
        $present = [System.Collections.Generic.List[string]]::new()
        $missing = [System.Collections.Generic.List[string]]::new()
        $notes = [System.Collections.Generic.List[string]]::new()
        $evidence = [System.Collections.Generic.List[string]]::new()
        $lines = [System.Collections.Generic.List[object]]::new()
        $reqScripts = [System.Collections.Generic.List[string]]::new()
        $reqDatasets = [System.Collections.Generic.List[string]]::new()
        foreach ($req in @($d.Requires)) {
            $scriptRef = [string]$req.Script
            $k = Get-ScriptKey $scriptRef
            $reqScripts.Add($scriptRef + $(if ($req.Run) { "@$($req.Run)" } else { '' }))
            $run = $null
            if ($req.Run) { $run = @($all | Where-Object { ((Get-ScriptKey $_.ScriptFolder) -eq $k -or $_.ScriptFolder -eq $scriptRef) -and $_.RunName -eq $req.Run }) | Select-Object -First 1 }
            elseif ($byKey.ContainsKey($k)) { $run = $byKey[$k] }
            elseif ($latest.ContainsKey($scriptRef)) { $run = $latest[$scriptRef] }
            $names = @($req.Datasets | Where-Object { $_ })
            if (-not $run) {
                $statuses.Add('NotRun')
                $what = $(if ($req.Run) { "pinned run $($req.Run) not found" } else { 'no run' })
                $notes.Add("$scriptRef`: $what")
                foreach ($n in $(if ($names.Count) { $names } else { @('(all datasets)') })) { $reqDatasets.Add("$k`:$n"); $missing.Add("$k`:$n (NotRun)"); $lines.Add([pscustomobject]@{ Script = $scriptRef; Dataset = $n; Status = 'NotRun'; Rows = ''; Path = ''; Sha256 = ''; HashCheck = ''; Note = $what }) }
                continue
            }
            $evidence.Add((Get-RelativePath $run.Folder))
            if (-not $names.Count) { $names = @($run.Datasets | Where-Object { $_.Dataset -ne 'summary' } | ForEach-Object { $_.Dataset }) }
            foreach ($n in $names) {
                $reqDatasets.Add("$k`:$n")
                $row = Find-RunDataset $run $n
                if (-not $row) {
                    $statuses.Add('EvidenceUnavailable'); $missing.Add("$k`:$n (not in run)")
                    $notes.Add("$k`:$n not produced by $(Get-RelativePath $run.Folder) (older version or switch not used)")
                    $lines.Add([pscustomobject]@{ Script = $scriptRef; Dataset = $n; Status = 'NotInRun'; Rows = ''; Path = (Get-RelativePath $run.Folder); Sha256 = ''; HashCheck = ''; Note = 'Not produced by this run' })
                    continue
                }
                $st = $(if ($row.HashCheck -in @('Mismatch', 'MissingFile')) { 'HashMismatch' } elseif ($script:Severity.ContainsKey($row.Status)) { $row.Status } else { 'Partial' })
                $statuses.Add($st)
                if ($st -in @('Completed', 'Partial')) { $present.Add("$k`:$n" + $(if ($st -eq 'Partial') { ' (Partial)' } else { '' })) } else { $missing.Add("$k`:$n ($st)") }
                if ($st -eq 'HashMismatch') { $notes.Add("$k`:$n EVIDENCE ALTERED: $($row.File) $($row.HashCheck) against its recorded SHA-256") }
                elseif ($st -ne 'Completed') { $notes.Add("$k`:$n $st" + $(if ($row.Note) { ": $($row.Note)" } else { '' })) }
                $lines.Add([pscustomobject]@{ Script = $scriptRef; Dataset = $n; Status = $st; Rows = $row.Rows; Path = $(if ($row.File) { Join-Path (Get-RelativePath $run.Folder) $row.File } else { Get-RelativePath $run.Folder }); Sha256 = $row.ActualSha256; HashCheck = $row.HashCheck; Note = $row.Note })
            }
        }
        $status = Get-WorstStatus $statuses
        $delRows.Add([pscustomobject][ordered]@{
                DeliverableId    = $d.Id
                Deliverable      = $d.Deliverable
                Gate             = $(if ($d.Gate) { $d.Gate } else { '' })
                RequiredScripts  = ($reqScripts -join '; ')
                RequiredDatasets = ($reqDatasets -join '; ')
                Present          = ($present -join '; ')
                Missing          = ($missing -join '; ')
                Status           = $status
                Note             = ($notes -join '; ')
                Evidence         = (($evidence | Select-Object -Unique) -join '; ')
            })
        $detail[[string]$d.Id] = [pscustomobject]@{ Lines = $lines; Description = $(if ($d.Description) { [string]$d.Description } else { '' }) }
        Write-RunLog ("{0} {1}: {2}" -f $d.Id, $d.Deliverable, $status) $(if ($status -eq 'Completed') { 'INFO' } else { 'WARN' })
    }
    Export-Dataset -Name 'deliverable-status' -Rows $delRows -Note 'Completed only when every required dataset is Completed and its file matches its recorded SHA-256'

    # ---- 4. Readable index ----
    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add('# Evidence index')
    $md.Add('')
    $md.Add("- Built: $($script:RunStartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')) by $ScriptName $ScriptVersion")
    $md.Add("- Evidence root: ``$EvidenceRoot`` (paths below are relative to it)")
    $md.Add("- Deliverable map: ``$(Split-Path $DeliverableMapPath -Leaf)`` SHA-256 ``$mapHash``")
    $md.Add("- Run folders: $($all.Count) found, $($selected.Count) listed; hash check failed for $badRuns")
    $md.Add('')
    $md.Add('| Deliverable | Gate | Status |')
    $md.Add('|-------------|------|--------|')
    foreach ($r in $delRows) { $md.Add(('| {0} {1} | {2} | {3} |' -f $r.DeliverableId, $r.Deliverable, $r.Gate, $r.Status)) }
    foreach ($r in $delRows) {
        $md.Add('')
        $md.Add(('## {0} {1}' -f $r.DeliverableId, $r.Deliverable))
        $md.Add('')
        $md.Add(('**Gate:** {0} · **Status:** {1}' -f $(if ($r.Gate) { $r.Gate } else { '-' }), $r.Status))
        if ($detail[$r.DeliverableId].Description) { $md.Add(''); $md.Add($detail[$r.DeliverableId].Description) }
        if ($r.Note) { $md.Add(''); foreach ($n in ($r.Note -split '; (?=[^;]*:)')) { $md.Add("- $n") } }
        $md.Add('')
        $md.Add('| Script | Dataset | Status | Rows | Evidence | SHA-256 |')
        $md.Add('|--------|---------|--------|------|----------|---------|')
        foreach ($l in $detail[$r.DeliverableId].Lines) {
            $md.Add(('| {0} | {1} | {2} | {3} | `{4}` | {5} |' -f $l.Script, $l.Dataset, $l.Status, $l.Rows, $l.Path, $(if ($l.Sha256) { '`' + $l.Sha256 + '`' } else { '' })))
        }
    }
    $md.Add('')
    $md.Add('Statuses: Completed = collected and verified; Partial = part of the source not read; Blocked = access denied or call failed;')
    $md.Add('EvidenceUnavailable = the tenant cannot produce it, or the run did not write it; Deferred = skipped on purpose;')
    $md.Add('NotRun = no run of the script; HashMismatch = the file no longer matches the SHA-256 recorded at run time.')
    Export-TextDataset -Name 'evidence-index' -FileName 'evidence-index.md' -Text ($md -join [Environment]::NewLine)

    # ---- 5. Package ----
    $packageRows = [System.Collections.Generic.List[object]]::new()
    if ($CopyTo) {
        [void][System.IO.Directory]::CreateDirectory($CopyTo)
        $copyFailures = 0
        $copyOne = {
            param([string]$Source, [string]$Relative)
            $target = Join-Path $CopyTo $Relative
            [void][System.IO.Directory]::CreateDirectory((Split-Path $target -Parent))
            [System.IO.File]::Copy($Source, $target, $false)
            $srcHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
            $dstHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
            $packageRows.Add([pscustomobject][ordered]@{ RelativePath = $Relative; Bytes = (Get-Item -LiteralPath $target).Length; Sha256 = $dstHash; CopyCheck = $(if ($srcHash -eq $dstHash) { 'Verified' } else { 'Mismatch' }); SourcePath = $Source })
            return [bool]($srcHash -eq $dstHash)
        }
        foreach ($r in $selected) {
            foreach ($f in @(Get-ChildItem -LiteralPath $r.Folder -File -Recurse)) {
                $rel = Join-Path (Join-Path $r.ScriptFolder $r.RunName) $f.FullName.Substring($r.Folder.Length).TrimStart('\', '/')
                if (-not (& $copyOne $f.FullName $rel)) { $copyFailures++ }
            }
        }
        foreach ($f in @('evidence-intake-log.csv', 'evidence-datasets.csv', 'deliverable-status.csv', 'evidence-index.md')) {
            if (-not (& $copyOne (Join-Path $script:RunFolder $f) (Join-Path 'index' $f))) { $copyFailures++ }
        }
        Export-Dataset -Name 'package-manifest' -Rows $packageRows -Status $(if ($copyFailures) { 'Partial' } else { 'Completed' }) -Note $(if ($copyFailures) { "$copyFailures file(s) differ after copy" } else { "Every copied file matches its source; package at $CopyTo" })
        [System.IO.File]::Copy((Join-Path $script:RunFolder 'package-manifest.csv'), (Join-Path (Join-Path $CopyTo 'index') 'package-manifest.csv'), $false)
        Write-RunLog ("Package: {0} file(s) copied to {1}" -f $packageRows.Count, $CopyTo) $(if ($copyFailures) { 'ERROR' } else { 'INFO' })
    }
    else { Set-DatasetStatus -Name 'package-manifest' -Status 'Deferred' -Note 'No -CopyTo: index only, nothing copied' }

    # ---- 6. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Run folders found' $all.Count
    Add-Metric 'Run folders listed' $selected.Count -Note $(if ($IncludeAllRuns) { 'All runs' } else { 'Latest per script plus pinned' })
    Add-Metric 'Run folders failing hash check' $badRuns -Note 'Files altered or missing since the run'
    Add-Metric 'Deliverables' $delRows.Count
    foreach ($s in 'Completed', 'Partial', 'Deferred', 'EvidenceUnavailable', 'Blocked', 'NotRun', 'HashMismatch') { Add-Metric "Deliverables $s" @($delRows | Where-Object Status -eq $s).Count }
    if ($CopyTo) { Add-Metric 'Files packaged' $packageRows.Count -Note $CopyTo }
    Export-Dataset -Name 'summary' -Rows $summary
    $script:ManifestExtra = @{ EvidenceRoot = $EvidenceRoot; DeliverableMapFile = (Split-Path $DeliverableMapPath -Leaf); DeliverableMapSha256 = $mapHash; CopyTo = $CopyTo }
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Parameters @{ EvidenceRoot = $EvidenceRoot; DeliverableMapPath = $DeliverableMapPath; IncludeAllRuns = [bool]$IncludeAllRuns; CopyTo = $CopyTo }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
