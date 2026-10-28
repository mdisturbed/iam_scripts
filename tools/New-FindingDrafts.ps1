<#
.SYNOPSIS
    Turns summary metrics of the latest discovery runs into draft engineer findings, with stable finding IDs
    and an evidence note per finding, ready to paste into the findings review workbook.

.DESCRIPTION
    Reads a finding rule file (examples\finding-rules.psd1): one rule per candidate finding, each naming a
    script, a summary.csv metric, a condition and a threshold. For every rule it takes the latest run of that
    script under -EvidenceRoot (folders named _aborted are ignored; a run needs run-manifest.json) and:

      NoRun          the script has no run
      NotEvaluable   the metric is missing or blank, says the read failed, or the evidence behind it is not
                     usable: the rule's dataset (or summary, when the rule names none) is Blocked,
                     EvidenceUnavailable, Deferred or missing, or summary.csv no longer matches its SHA-256.
                     Nothing is ever drafted from evidence that is not there
      NotTriggered   the condition does not hold
      New            the condition holds and the rule is not in the ledger: the next finding ID is assigned,
                     the ledger gets a row, an evidence note is written and the finding is drafted
      Existing       the condition holds and the ledger already maps the rule to a finding ID: the ID is kept
                     and the finding is not drafted again (it is already in the workbook)

    The finding ledger (-LedgerPath, a CSV: RuleId, FindingId, FirstSeenUtc, RunFolder, Value) is what keeps
    IDs stable: a rule keeps its finding ID in every later run. New IDs continue from the highest ID in the
    ledger (or in -ReviewTrailCsv, the workbook export, when given); -StartNumber is used only when both are empty. An ID that already has an evidence note
    (<findings folder>\<ID>.md) is skipped too. Findings raised by hand before this tool was
    used can be seeded: a ledger with RuleId,FindingId rows (e.g. R-13-01,F-07) makes that rule reuse F-07.

    Evidence notes: <findings folder>\<ID>.md, written by tools\New-FindingEvidence.ps1 from the run folder
    (Scope when the rule has a dataset filter, Evidence with the SHA-256, Closure with the rerun command and
    the target value). An existing note is never overwritten.

    Counts only. The drafts carry metric values, never account names.

    Local only: reads run folders, writes its own run folder, the ledger and the evidence notes. Connects to nothing.

    Output: <OutputRoot>\New-FindingDrafts\<yyyyMMdd-HHmmssZ>\
      finding-drafts.csv      NEW findings only, columns in the Review Trail's Engineer order: ID, Finding,
                              Source and filter, Count, Population, Observed severity, HITRUST CSF,
                              Proposed ZT pillar / principle, Initial recommendation, Evidence note, Engineer date.
                              Paste the rows into the first empty row of the working workbook's Review Trail sheet
      finding-evaluation.csv  every rule: RuleId, FindingId, Script, Metric, Value, Condition, Threshold, Result,
                              Reason, RunFolder
      finding-ledger.csv      copy of the ledger after this run
      summary.csv, run-manifest.json, dataset-status.csv (SHA-256 of every file), run.log

.PARAMETER EvidenceRoot
    Folder holding the run folders (NN-Name\yyyyMMdd-HHmmssZ).

.PARAMETER RulesPath
    Finding rule file. Default: examples\finding-rules.psd1 in the repository.

.PARAMETER LedgerPath
    Finding ledger CSV. Default: <EvidenceRoot>\findings\finding-ledger.csv. Created when missing.

.PARAMETER FindingsFolder
    Where the evidence notes go. Default: the ledger's folder.

.PARAMETER IdPrefix
    Finding ID prefix. Default: F-

.PARAMETER StartNumber
    First finding number when the ledger is empty. Default: 1

.PARAMETER ReviewTrailCsv
    Optional: the CSV export of the workbook's Review Trail sheet. Finding IDs already in it are never
    reused: new IDs start above the highest ID in the ledger or the workbook (findings typed in by hand).

.PARAMETER ToolsRoot
    Folder holding New-FindingEvidence.ps1. Default: this tool's folder.

.PARAMETER OutputRoot
    Where the tool's run folder goes. Default: -EvidenceRoot.

.EXAMPLE
    .\tools\New-FindingDrafts.ps1 -EvidenceRoot D:\Engagement\evidence -LedgerPath D:\Engagement\findings\finding-ledger.csv -OutputRoot D:\Engagement\reports
.EXAMPLE
    .\tools\New-FindingDrafts.ps1 -EvidenceRoot D:\Evidence -StartNumber 12
    The first new finding becomes F-12 when the ledger is empty.

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x.
    Scopes  : none. Reads local files only.
    Licence : none
    Sources : run-manifest.json, dataset-status.csv and summary.csv of the latest run of each script named in the rules.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [string]$RulesPath = '',
    [string]$LedgerPath = '',
    [string]$FindingsFolder = '',
    [string]$IdPrefix = 'F-',
    [ValidateRange(1, 99999)][int]$StartNumber = 1,
    [string]$ToolsRoot = '',
    [string]$ReviewTrailCsv = '',
    [string]$OutputRoot = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = 'New-FindingDrafts'
$ScriptVersion = '1.0.0'

if (-not (Test-Path -LiteralPath $EvidenceRoot)) { throw "Evidence folder not found: $EvidenceRoot" }
$EvidenceRoot = (Resolve-Path -LiteralPath $EvidenceRoot).Path
if (-not $RulesPath) { $RulesPath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'examples') 'finding-rules.psd1' }
if (-not (Test-Path -LiteralPath $RulesPath)) { throw "Rule file not found: $RulesPath" }
if (-not $LedgerPath) { $LedgerPath = Join-Path (Join-Path $EvidenceRoot 'findings') 'finding-ledger.csv' }
$LedgerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LedgerPath)
if (-not $FindingsFolder) { $FindingsFolder = Split-Path $LedgerPath -Parent }
$FindingsFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FindingsFolder)
if (-not $ToolsRoot) { $ToolsRoot = $PSScriptRoot }
$findingEvidenceTool = Join-Path $ToolsRoot 'New-FindingEvidence.ps1'
if (-not (Test-Path -LiteralPath $findingEvidenceTool)) { throw "New-FindingEvidence.ps1 not found in -ToolsRoot: $ToolsRoot" }
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
    param([Parameter(Mandatory)][string]$Name, [object[]]$Rows, [string]$Status = 'Completed', [string]$Note = '', [string[]]$Header = @())
    $file = Join-Path $script:RunFolder ("{0}.csv" -f $Name)
    $count = 0
    if ($Rows -and @($Rows).Count -gt 0) {
        $Rows | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
        $count = @($Rows).Count
    }
    elseif ($Header.Count) { Set-Content -Path $file -Value (($Header | ForEach-Object { '"' + $_ + '"' }) -join ',') -Encoding UTF8 }
    else { Set-Content -Path $file -Value '' -Encoding UTF8 }
    $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
    $script:Datasets.Add([pscustomobject][ordered]@{ Dataset = $Name; Status = $Status; Rows = $count; File = (Split-Path $file -Leaf); Sha256 = $hash; Note = $Note })
    Write-RunLog ("{0}: {1} rows [{2}] {3}" -f $Name, $count, $Status, $Note)
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
#endregion

# ---- Tool-specific helpers ----
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$script:DraftColumns = @('ID', 'Finding', 'Source and filter', 'Count', 'Population', 'Observed severity', 'HITRUST CSF', 'Proposed ZT pillar / principle', 'Initial recommendation', 'Evidence note', 'Engineer date')

function Read-CsvSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    if ((Get-Item -LiteralPath $Path).Length -lt 4) { return @() }
    return @(Import-Csv -LiteralPath $Path)
}

function ConvertTo-Number {
    param([string]$Value)
    $d = 0.0
    $s = "$Value".Trim() -replace '\s*%$', ''
    # summary.csv written on a decimal-comma culture holds '54,1' (Export-Csv formats numbers in the current culture)
    if ($s -match '^[+-]?\d+,\d+$') { $s = $s -replace ',', '.' }
    if ([double]::TryParse($s, [Globalization.NumberStyles]::Float, $script:Inv, [ref]$d)) { return $d }
    return $null
}

function Get-MetricRegex {
    # Rule metric to an anchored, case-insensitive regex: '*' stands for a value the script fills in.
    param([string]$Pattern)
    return '^' + (([regex]::Escape($Pattern)) -replace '\\\*', '.*') + '$'
}

function Get-LatestRun {
    # Latest run folder of a script by its folder name (falls back to the NN- prefix); _aborted ignored.
    param([string]$Script)
    $dirs = @(Get-ChildItem -LiteralPath $EvidenceRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $Script })
    if (-not $dirs.Count -and $Script -match '^(\d\d)-') { $n = $Matches[1]; $dirs = @(Get-ChildItem -LiteralPath $EvidenceRoot -Directory -Filter "$n-*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '_aborted' }) }
    @($dirs | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
        Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' -and $_.FullName -notmatch '[\\/]_aborted([\\/]|$)' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'run-manifest.json')) } |
        Sort-Object Name) | Select-Object -Last 1
}

function Test-Condition {
    # $true / $false, or $null when the value cannot be compared with this condition.
    param([string]$Value, [string]$Condition, $Threshold)
    $v = ConvertTo-Number $Value; $t = ConvertTo-Number "$Threshold"
    if ($null -ne $v -and $null -ne $t) {
        switch ($Condition) { 'GreaterThan' { return $v -gt $t } 'LessThan' { return $v -lt $t } 'Equals' { return $v -eq $t } 'NotEqual' { return $v -ne $t } }
    }
    switch ($Condition) {
        'Equals' { return [string]::Equals("$Value".Trim(), "$Threshold".Trim(), [StringComparison]::OrdinalIgnoreCase) }
        'NotEqual' { return -not [string]::Equals("$Value".Trim(), "$Threshold".Trim(), [StringComparison]::OrdinalIgnoreCase) }
    }
    return $null
}

function Get-TargetText {
    param([string]$Condition, $Threshold)
    switch ($Condition) {
        'GreaterThan' { if ("$Threshold" -eq '0') { return '0' } return "$Threshold or less" }
        'LessThan' { return "$Threshold or more" }
        'Equals' { return "not $Threshold" }
        'NotEqual' { return "$Threshold" }
    }
    return "$Threshold"
}

function Get-RelativePath {
    param([string]$Path)
    if ($Path.StartsWith($EvidenceRoot, [StringComparison]::OrdinalIgnoreCase)) { return $Path.Substring($EvidenceRoot.Length).TrimStart('\', '/') }
    return $Path
}

$condText = @{ GreaterThan = '>'; LessThan = '<'; Equals = '='; NotEqual = '<>' }

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $rulesHash = (Get-FileHash -LiteralPath $RulesPath -Algorithm SHA256).Hash
    $rules = @((Import-PowerShellDataFile -Path $RulesPath).Rules)
    if (-not $rules.Count) { throw "No Rules = @( ... ) in $RulesPath" }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $rules) {
        foreach ($k in 'RuleId', 'Script', 'Metric', 'Condition', 'Finding', 'Severity') { if (-not $r[$k]) { throw "Rule '$($r.RuleId)': $k is missing." } }
        if (-not $r.ContainsKey('Threshold')) { throw "Rule '$($r.RuleId)': Threshold is missing." }
        if ($r.Condition -notin @('GreaterThan', 'LessThan', 'NotEqual', 'Equals')) { throw "Rule '$($r.RuleId)': Condition must be GreaterThan, LessThan, NotEqual or Equals." }
        if (-not $seen.Add([string]$r.RuleId)) { throw "RuleId '$($r.RuleId)' is used twice." }
    }
    Write-RunLog ("{0} rule(s) from {1} (SHA-256 {2})" -f $rules.Count, $RulesPath, $rulesHash)

    # ---- Ledger ----
    $ledger = [System.Collections.Generic.List[object]]::new()
    foreach ($l in (Read-CsvSafe $LedgerPath)) {
        if (-not "$($l.RuleId)".Trim() -or -not "$($l.FindingId)".Trim()) { continue }
        $ledger.Add([pscustomobject][ordered]@{ RuleId = "$($l.RuleId)".Trim(); FindingId = "$($l.FindingId)".Trim(); FirstSeenUtc = "$($l.FirstSeenUtc)"; RunFolder = "$($l.RunFolder)"; Value = "$($l.Value)" })
    }
    $byRule = @{}
    foreach ($l in $ledger) { if (-not $byRule.ContainsKey($l.RuleId)) { $byRule[$l.RuleId] = $l.FindingId } }
    $idRx = '^' + [regex]::Escape($IdPrefix) + '(\d+)$'
    $max = 0
    foreach ($l in $ledger) { if ($l.FindingId -match $idRx) { $n = [int]$Matches[1]; if ($n -gt $max) { $max = $n } } }
    $workbookIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($ReviewTrailCsv) {
        if (-not (Test-Path -LiteralPath $ReviewTrailCsv)) { throw "-ReviewTrailCsv not found: $ReviewTrailCsv" }
        # Comma or semicolon separated (Excel uses ';' where ',' is the decimal mark): take the first cell of each line.
        foreach ($line in (Get-Content -LiteralPath $ReviewTrailCsv)) { if ($line -match '^\s*"?([^",;]+)"?\s*[,;]') { [void]$workbookIds.Add($Matches[1].Trim()) } }
        foreach ($wid in $workbookIds) { if ($wid -match $idRx) { $n = [int]$Matches[1]; if ($n -gt $max) { $max = $n } } }
    }
    $next = $(if ($max -gt 0) { $max + 1 } else { $StartNumber })
    Write-RunLog ("Ledger: {0} row(s) in {1}; next new ID {2}{3:00}" -f $ledger.Count, $LedgerPath, $IdPrefix, $next)

    # ---- Evaluate ----
    $runCache = @{}
    $evalRows = [System.Collections.Generic.List[object]]::new()
    $drafts = [System.Collections.Generic.List[object]]::new()
    $today = $script:RunStartUtc.ToString('yyyy-MM-dd')
    foreach ($r in $rules) {
        $row = [ordered]@{ RuleId = $r.RuleId; FindingId = ''; Script = $r.Script; Metric = $r.Metric; Value = ''; Condition = $r.Condition; Threshold = "$($r.Threshold)"; Result = ''; Reason = ''; RunFolder = '' }
        if (-not $runCache.ContainsKey($r.Script)) {
            $run = Get-LatestRun $r.Script
            $info = $null
            if ($run) {
                $status = @(Read-CsvSafe (Join-Path $run.FullName 'dataset-status.csv'))
                $summaryPath = Join-Path $run.FullName 'summary.csv'
                $sumRow = @($status | Where-Object { $_.Dataset -eq 'summary' }) | Select-Object -First 1
                $hashOk = $false
                if ((Test-Path -LiteralPath $summaryPath) -and $sumRow -and $sumRow.Sha256) { $hashOk = ((Get-FileHash -LiteralPath $summaryPath -Algorithm SHA256).Hash -eq "$($sumRow.Sha256)".ToUpperInvariant()) }
                $info = [pscustomobject]@{ Dir = $run; Status = $status; Summary = @(Read-CsvSafe $summaryPath); SummaryHashOk = $hashOk; HasSummary = (Test-Path -LiteralPath $summaryPath) }
            }
            $runCache[$r.Script] = $info
        }
        $info = $runCache[$r.Script]
        if (-not $info) { $row.Result = 'NoRun'; $row.Reason = "No run of $($r.Script) in the evidence folder"; $evalRows.Add([pscustomobject]$row); continue }
        $row.RunFolder = Get-RelativePath $info.Dir.FullName
        $gateName = $(if ($r.Dataset) { [string]$r.Dataset } else { 'summary' })
        $gate = @($info.Status | Where-Object { $_.Dataset -eq $gateName }) | Select-Object -First 1
        $reason = ''
        if (-not $info.HasSummary) { $reason = 'No summary.csv in the run' }
        elseif (-not $info.SummaryHashOk) { $reason = 'summary.csv does not match the SHA-256 in dataset-status.csv (altered or not recorded)' }
        elseif (-not $gate) { $reason = "Dataset $gateName not in dataset-status.csv" }
        elseif ($gate.Status -notin @('Completed', 'Partial')) { $reason = "Dataset $gateName is $($gate.Status)" + $(if ($gate.Note) { ": $($gate.Note)" } else { '' }) }
        $metric = $null
        if (-not $reason) {
            $rx = Get-MetricRegex $r.Metric
            $metric = @($info.Summary | Where-Object { "$($_.Metric)" -match $rx }) | Select-Object -First 1
            if (-not $metric) { $reason = "Metric '$($r.Metric)' not in summary.csv (switch not used, older script version, or not computed)" }
            elseif ("$($metric.Value)".Trim() -eq '') { $reason = "Metric value is blank" + $(if ($metric.Note) { ": $($metric.Note)" } else { '' }) }
            elseif ("$($metric.Value)" -match '^(Read failed|Not evaluated|not evaluated|not checked|unknown)') { $reason = "Metric not evaluated: $($metric.Value)" }
        }
        if ($reason) { $row.Result = 'NotEvaluable'; $row.Reason = $reason; $evalRows.Add([pscustomobject]$row); continue }
        $row.Value = "$($metric.Value)".Trim()
        $hit = Test-Condition -Value $row.Value -Condition $r.Condition -Threshold $r.Threshold
        if ($null -eq $hit) { $row.Result = 'NotEvaluable'; $row.Reason = "Value '$($row.Value)' cannot be compared with $($r.Condition)"; $evalRows.Add([pscustomobject]$row); continue }
        if (-not $hit) { $row.Result = 'NotTriggered'; $row.Reason = $(if ($gate.Status -eq 'Partial') { "Dataset $gateName is Partial: the value may be understated" } else { '' }); $evalRows.Add([pscustomobject]$row); continue }

        # ---- triggered ----
        $partialNote = $(if ($gate.Status -eq 'Partial') { "Dataset $gateName is Partial" } else { '' })
        if ($byRule.ContainsKey($r.RuleId)) {
            $row.FindingId = $byRule[$r.RuleId]; $row.Result = 'Existing'; $row.Reason = (@('Already in the ledger', $partialNote) | Where-Object { $_ }) -join '; '
            $evalRows.Add([pscustomobject]$row); continue
        }
        $id = '{0}{1:00}' -f $IdPrefix, $next
        # skip IDs in the ledger, in the workbook export, or with an evidence note already (a finding raised by hand)
        while (@($ledger | Where-Object { $_.FindingId -eq $id }).Count -or $workbookIds.Contains($id) -or (Test-Path -LiteralPath (Join-Path $FindingsFolder ("{0}.md" -f $id)))) { $next++; $id = '{0}{1:00}' -f $IdPrefix, $next }
        $next++
        $byRule[$r.RuleId] = $id
        $ledger.Add([pscustomobject][ordered]@{ RuleId = $r.RuleId; FindingId = $id; FirstSeenUtc = $script:RunStartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'); RunFolder = $row.RunFolder; Value = $row.Value })
        $row.FindingId = $id; $row.Result = 'New'

        # evidence note
        $notePath = Join-Path $FindingsFolder ("{0}.md" -f $id)
        $noteMsg = ''
        if (-not (Test-Path -LiteralPath $FindingsFolder)) { New-Item -ItemType Directory -Path $FindingsFolder -Force | Out-Null }
        if (Test-Path -LiteralPath $notePath) { $noteMsg = 'Evidence note already exists; not overwritten' }
        else {
            $nfe = @{ RunFolder = $info.Dir.FullName; Metric = [Management.Automation.WildcardPattern]::Escape("$($metric.Metric)"); TargetValue = (Get-TargetText $r.Condition $r.Threshold); EvidenceLocation = $EvidenceRoot; OutFile = $notePath }
            if ($r.Dataset -and $r.FilterColumn) { $nfe['Dataset'] = [string]$r.Dataset; $nfe['FilterColumn'] = [string]$r.FilterColumn; $nfe['FilterValue'] = [string]$r.FilterValue; if ($r.FilterMode) { $nfe['FilterMode'] = [string]$r.FilterMode } }
            $written = $false
            try { & $findingEvidenceTool @nfe 6>$null | Out-Null; $written = $true }
            catch {
                if ($nfe.ContainsKey('Dataset')) {
                    $noteMsg = "Dataset filter not applied ($($_.Exception.Message))"
                    foreach ($k in 'Dataset', 'FilterColumn', 'FilterValue', 'FilterMode') { [void]$nfe.Remove($k) }
                    try { & $findingEvidenceTool @nfe 6>$null | Out-Null; $written = $true } catch { $noteMsg = "Evidence note not written: $($_.Exception.Message)" }
                }
                else { $noteMsg = "Evidence note not written: $($_.Exception.Message)" }
            }
            if ($written) {
                $head = @("# $id $($r.Finding)", '', "Drafted by $ScriptName $ScriptVersion on $today from rule $($r.RuleId): ``$($metric.Metric)`` = $($row.Value) ($($r.Condition) $($r.Threshold)). Observed severity $($r.Severity).", '')
                $body = Get-Content -LiteralPath $notePath -Raw
                Set-Content -LiteralPath $notePath -Value (($head -join [Environment]::NewLine) + [Environment]::NewLine + $body) -Encoding UTF8
            }
        }
        if ($noteMsg) { Write-RunLog ("{0} {1}: {2}" -f $id, $r.RuleId, $noteMsg) 'WARN' }
        $row.Reason = (@($partialNote, $noteMsg) | Where-Object { $_ }) -join '; '
        $evalRows.Add([pscustomobject]$row)

        # draft row in the Review Trail's Engineer column order
        $source = "[$($r.RuleId)] $(($r.Script -split '-')[0]) summary.csv: $($metric.Metric) $($condText[$r.Condition]) $($r.Threshold)"
        if ($r.Dataset -and $r.FilterColumn) { $source += "; $($r.Dataset).csv where $($r.FilterColumn) $("$($r.FilterMode)".ToLowerInvariant()) $($r.FilterValue)" }
        elseif ($r.Dataset) { $source += "; from $($r.Dataset).csv" }
        $pop = ''
        if ($r.Population) {
            $pm = @($info.Summary | Where-Object { "$($_.Metric)" -match (Get-MetricRegex ([string]$r.Population)) }) | Select-Object -First 1
            if ($pm -and "$($pm.Value)".Trim() -ne '') { $pop = "$("$($pm.Value)".Trim()) ($($pm.Metric))" }
        }
        $d = [ordered]@{}
        $vals = @($id, $r.Finding, $source, $row.Value, $pop, $r.Severity, "$($r.HitrustCsf)", ((@($r.ZtPillar, $r.ZtPrinciple) | Where-Object { $_ }) -join ' / '), "$($r.Recommendation)", "findings\$id.md", $today)
        for ($i = 0; $i -lt $script:DraftColumns.Count; $i++) { $d[$script:DraftColumns[$i]] = $vals[$i] }
        $drafts.Add([pscustomobject]$d)
    }

    # ---- Ledger out ----
    if (-not (Test-Path -LiteralPath (Split-Path $LedgerPath -Parent))) { New-Item -ItemType Directory -Path (Split-Path $LedgerPath -Parent) -Force | Out-Null }
    $ledger | Export-Csv -LiteralPath $LedgerPath -NoTypeInformation -Encoding UTF8
    Write-RunLog ("Ledger written: {0} row(s) to {1}" -f $ledger.Count, $LedgerPath)

    $counts = [ordered]@{}; foreach ($k in 'New', 'Existing', 'NotTriggered', 'NotEvaluable', 'NoRun') { $counts[$k] = @($evalRows | Where-Object Result -eq $k).Count }
    Export-Dataset -Name 'finding-drafts' -Rows $drafts -Header $script:DraftColumns -Note 'New findings only, Review Trail Engineer column order: paste into the first empty Review Trail row'
    Export-Dataset -Name 'finding-evaluation' -Rows $evalRows -Note (($counts.GetEnumerator() | ForEach-Object { "$($_.Key) $($_.Value)" }) -join '; ')
    Export-Dataset -Name 'finding-ledger' -Rows $ledger -Note "Copy of $LedgerPath after this run"
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Rules evaluated' $rules.Count -Note (Split-Path $RulesPath -Leaf)
    foreach ($k in $counts.Keys) { Add-Metric "Rules $k" $counts[$k] }
    Add-Metric 'Ledger rows' $ledger.Count
    Export-Dataset -Name 'summary' -Rows $summary
    $script:ManifestExtra = @{ RulesFile = (Split-Path $RulesPath -Leaf); RulesSha256 = $rulesHash; LedgerPath = $LedgerPath; FindingsFolder = $FindingsFolder; Counts = $counts }
    Write-RunLog ("New {0}, existing {1}, not triggered {2}, not evaluable {3}, no run {4}" -f $counts['New'], $counts['Existing'], $counts['NotTriggered'], $counts['NotEvaluable'], $counts['NoRun'])
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Parameters @{ EvidenceRoot = $EvidenceRoot; RulesPath = $RulesPath; LedgerPath = $LedgerPath; ReviewTrailCsv = $ReviewTrailCsv; FindingsFolder = $FindingsFolder; IdPrefix = $IdPrefix; StartNumber = $StartNumber }
    Write-RunLog ("Finished. Drafts: {0}" -f (Join-Path $script:RunFolder 'finding-drafts.csv'))
}
