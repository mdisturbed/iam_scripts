<#
.SYNOPSIS
    Builds the Evidence, Scope count and Closure sections of a Jira finding from a script run folder.

.DESCRIPTION
    Reads run-manifest.json, dataset-status.csv and summary.csv from one run folder and prints
    Markdown that drops straight into the finding template (docs/jira-finding-template.md):

      - Scope: affected-object count for a dataset, optionally filtered on one column
      - Evidence: script and version, run folder, dataset, filter, SHA-256, run-by account,
        data-as-of time, dataset status
      - Closure criteria: the exact rerun command (same parameters as this run) and the
        summary metric with its current value

    Reads the run folder only; it never writes into it. Output goes to the console, and
    optionally to -OutFile and / or the clipboard.

.PARAMETER RunFolder
    A run folder, e.g. D:\Evidence\22-PimRoleSettings\20261021-140501Z

.PARAMETER Dataset
    Dataset name or file, e.g. pim-role-settings or pim-role-settings.csv

.PARAMETER FilterColumn / FilterValue / FilterMode
    Count only rows where FilterColumn matches FilterValue. FilterMode: Like (wildcards, default),
    Equals, Match (regex), Contains.

.PARAMETER Metric
    Exact (or wildcard) metric name from summary.csv for the closure line. Use -ListMetrics to see them.

.EXAMPLE
    .\tools\New-FindingEvidence.ps1 -RunFolder D:\Evidence\22-PimRoleSettings\20261021-140501Z -ListMetrics
.EXAMPLE
    .\tools\New-FindingEvidence.ps1 -RunFolder D:\Evidence\22-PimRoleSettings\20261021-140501Z `
        -Dataset pim-role-settings -FilterColumn Flags -FilterValue Tier0NoApproval -FilterMode Contains `
        -Metric 'Tier 0 roles activatable without approval' -TargetValue 0 -EvidenceLocation 'https://evidence.contoso.local/iam/2026-10' -Clipboard

.NOTES
    Version: 1.0.0. Read-only: reads the run folder; writes only to -OutFile / the clipboard if asked.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunFolder,
    [string]$Dataset = '',
    [string]$FilterColumn = '',
    [string]$FilterValue = '',
    [ValidateSet('Like', 'Equals', 'Match', 'Contains')][string]$FilterMode = 'Like',
    [string]$ExampleColumn = '',                      # optional: show up to 3 values from this column (use only for IDs / placeholders)
    [string]$Metric = '',
    [string]$TargetValue = '0',
    [string]$EvidenceLocation = '<link to approved evidence store>',
    [string]$VerifiedAgainst = 'Not yet verified',
    [switch]$ListMetrics,
    [string]$OutFile = '',
    [switch]$Clipboard
)

$ErrorActionPreference = 'Stop'

# ---- Load the run ----
$RunFolder = (Resolve-Path $RunFolder).Path
$manifestPath = Join-Path $RunFolder 'run-manifest.json'
if (-not (Test-Path $manifestPath)) { throw "No run-manifest.json in $RunFolder - point -RunFolder at a single timestamped run folder." }
$manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
$statusPath = Join-Path $RunFolder 'dataset-status.csv'
$status = $(if (Test-Path $statusPath) { @(Import-Csv -Path $statusPath) } else { @() })
$summaryPath = Join-Path $RunFolder 'summary.csv'
$summary = $(if (Test-Path $summaryPath) { @(Import-Csv -Path $summaryPath) } else { @() })

if ($ListMetrics) {
    if (-not $summary.Count) { Write-Host 'No summary.csv in this run folder.'; return }
    $summary | Format-Table Metric, Value, Note -AutoSize | Out-String -Width 220 | Write-Host
    Write-Host 'Datasets:' -ForegroundColor Cyan
    $status | Format-Table Dataset, Status, Rows, Note -AutoSize | Out-String -Width 220 | Write-Host
    return
}

$asOf = $(if ($manifest.StartedUtc) { ([datetime]$manifest.StartedUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
$runBy = @($manifest.GraphAccount, $(if ($manifest.Extra) { $manifest.Extra.AwsCallerArn }), $manifest.RunAsWindows) | Where-Object { $_ } | Select-Object -First 1
$runDate = $(if ($asOf) { $asOf.Substring(0, 10) } else { '' })

# ---- Dataset, filter and count ----
$dsName = ''; $dsRow = $null; $count = $null; $examples = @(); $filterText = 'none'
if ($Dataset) {
    $dsName = [IO.Path]::GetFileNameWithoutExtension($Dataset)
    $dsRow = $status | Where-Object { $_.Dataset -eq $dsName } | Select-Object -First 1
    if (-not $dsRow) { throw "Dataset '$dsName' not found in dataset-status.csv. Available: $(($status.Dataset) -join ', ')" }
    $csv = Join-Path $RunFolder ("{0}.csv" -f $dsName)
    $rows = @()
    if ((Test-Path $csv) -and (Get-Item $csv).Length -gt 3) { $rows = @(Import-Csv -Path $csv) }
    if ($FilterColumn) {
        if ($rows.Count -and -not ($rows[0].PSObject.Properties.Name -contains $FilterColumn)) { throw "Column '$FilterColumn' not in $dsName.csv. Columns: $($rows[0].PSObject.Properties.Name -join ', ')" }
        $rows = @($rows | Where-Object {
                $v = "$($_.$FilterColumn)"
                switch ($FilterMode) {
                    'Equals' { $v -eq $FilterValue }
                    'Match' { $v -match $FilterValue }
                    'Contains' { $v.IndexOf($FilterValue, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
                    default { $v -like $FilterValue }
                }
            })
        $filterText = '{0} {1} {2}' -f $FilterColumn, @{ Like = 'like'; Equals = '='; Match = 'matches'; Contains = 'contains' }[$FilterMode], $FilterValue
    }
    $count = $rows.Count
    if ($ExampleColumn -and $rows.Count) { $examples = @($rows | Select-Object -First 3 | ForEach-Object { "$($_.$ExampleColumn)" }) }
}

# ---- Closure: rerun command from the manifest's parameters ----
$scriptFile = "$($manifest.Script).ps1"
$prefix = ("$($manifest.Script)" -split '-')[0]
$scriptsDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts'
if (Test-Path $scriptsDir) { $match = Get-ChildItem -Path $scriptsDir -Filter "$prefix-*.ps1" | Select-Object -First 1; if ($match) { $scriptFile = $match.Name } }
$parts = @(".\scripts\$scriptFile")
$inputFiles = @()
if ($manifest.Parameters) {
    foreach ($p in ($manifest.Parameters.PSObject.Properties | Sort-Object Name)) {
        $v = $p.Value
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { if ($v) { $parts += "-$($p.Name)" }; continue }
        if ($v -is [array] -or $v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
            $items = @($v | Where-Object { "$_" -ne '' })
            if ($items.Count) { $parts += "-$($p.Name) " + (($items | ForEach-Object { "'$_'" }) -join ',') }
            continue
        }
        if ("$v" -eq '') { continue }
        if ($p.Name -match 'Csv|Path$') { $inputFiles += "$($p.Name)=$v" }
        $parts += $(if ("$v" -match '^-?\d+(\.\d+)?$') { "-$($p.Name) $v" } else { "-$($p.Name) '$v'" })
    }
}
if ($manifest.Server) { $parts += "-Server '$($manifest.Server)'" }
if ($manifest.AuthMode -and $manifest.AuthMode -ne 'Delegated') { $parts += "-AuthMode $($manifest.AuthMode)" }
$parts += "-OutputRoot '$(Split-Path (Split-Path $RunFolder -Parent) -Parent)'"
$rerun = $parts -join ' '

$metricRow = $null
if ($Metric) {
    $metricRow = $summary | Where-Object { $_.Metric -like $Metric } | Select-Object -First 1
    if (-not $metricRow) { throw "Metric '$Metric' not found in summary.csv. Run with -ListMetrics to see the names." }
}

# ---- Markdown ----
$md = [System.Collections.Generic.List[string]]::new()
if ($Dataset) {
    $md.Add('## Scope')
    $md.Add("- Affected objects: $count $(if ($count -eq 1) { 'row' } else { 'rows' }) in $dsName" + $(if ($FilterColumn) { " where $filterText" } else { '' }))
    if ($examples.Count) { $md.Add("- Examples: $($examples -join ', ') - full list in evidence") }
    $md.Add('')
}
$md.Add('## Evidence')
$md.Add("- Script: $scriptFile v$($manifest.ScriptVersion)")
$md.Add("- Run folder: $RunFolder")
if ($Dataset) {
    $md.Add("- Dataset(s): $dsName.csv - filter: $filterText")
    $md.Add("- SHA-256 (from dataset-status.csv): $(if ($dsRow.Sha256) { $dsRow.Sha256 } else { 'n/a (no file - see status)' })")
}
else {
    $md.Add('- Dataset(s): summary.csv')
    $dsRow = $status | Where-Object { $_.Dataset -eq 'summary' } | Select-Object -First 1
    if ($dsRow) { $md.Add("- SHA-256 (from dataset-status.csv): $($dsRow.Sha256)") }
}
$md.Add("- Run by: $runBy | Data as of: $asOf")
$md.Add("- Dataset status: $(if ($dsRow) { $dsRow.Status + $(if ($dsRow.Note) { ' - ' + $dsRow.Note } else { '' }) } else { 'see dataset-status.csv' })")
$md.Add("- Verified against: $VerifiedAgainst")
$md.Add("- Evidence location: $EvidenceLocation")
$md.Add('')
$md.Add('## Closure criteria')
$md.Add("- Rerun: ``$rerun``")
if ($inputFiles.Count) { $md.Add("- Input files used (supply current versions on rerun): $($inputFiles -join '; ')") }
if ($metricRow) { $md.Add("- Pass when: `"$($metricRow.Metric)`" = $TargetValue (was $($metricRow.Value) on $runDate)") }
elseif ($Dataset) { $md.Add("- Pass when: $dsName rows" + $(if ($FilterColumn) { " where $filterText" } else { '' }) + " = $TargetValue (was $count on $runDate)") }
else { $md.Add('- Pass when: <metric in summary.csv> = <target> (use -Metric)') }

$text = $md -join [Environment]::NewLine
Write-Output $text
if ($OutFile) { Set-Content -Path $OutFile -Value $text -Encoding UTF8; Write-Host "Written to $OutFile" -ForegroundColor Green }
if ($Clipboard) {
    if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) { $text | Set-Clipboard; Write-Host 'Copied to clipboard.' -ForegroundColor Green }
    else { Write-Warning 'Set-Clipboard is not available in this session; use -OutFile instead.' }
}
