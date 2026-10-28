<#
.SYNOPSIS
    One self-contained HTML page showing where an engagement stands: discovery runs, KPIs, readiness,
    findings and open evidence items.

.DESCRIPTION
    Builds a single HTML file from the parts of an engagement folder you pass. Every input is optional;
    a section without its input says "Not provided".

      -EvidenceRoot        latest run of each catalog script: dataset counts per status (Completed, Partial,
                           Blocked, Deferred, EvidenceUnavailable), run age and script version. Read from
                           run-manifest.json and dataset-status.csv only. Folders named _aborted (and
                           anything under them) are ignored. Also the latest Get-KpiSummary run under it:
                           kpi-summary.csv (value, target, status), hash-checked against its dataset-status.csv
      -ReadinessCsv        readiness checklist (examples\readiness-checklist.example.csv): Closed / Waived /
                           Open / In progress counts and the items still open, with owner and due date
      -FindingsCsv         findings review: the CSV export of the review workbook's Review Trail sheet
                           (examples\findings-review.example.csv). Needs ID, Finding, Observed severity,
                           Architect severity, Client decision and Stage. A blank Stage is worked out the way
                           the workbook does it. A section-title row above the headers is skipped
      -StatusRegisterCsv   status register (examples\status-register.example.csv): every item that is not
                           Completed, with rationale, owner, risk and disposition

    Counts and statuses only. Run folders are read for counts and statuses, never for the data files, so
    the page holds no account names. The registers are shown as you wrote them: keep names out of them,
    as the templates say. Every value is HTML-encoded.

    The page has no external resources (inline CSS, no scripts, no fonts or images to fetch), follows the
    browser's light or dark setting and prints cleanly.

    Local only: reads the inputs, writes only its own run folder. Connects to nothing.

    Output: <OutputRoot>\New-EngagementDashboard\<yyyyMMdd-HHmmssZ>\
      engagement-dashboard.html, summary.csv (the headline numbers), run-manifest.json, dataset-status.csv
      (SHA-256 of every file), run.log

.PARAMETER EvidenceRoot
    Folder holding the run folders (NN-Name\yyyyMMdd-HHmmssZ).

.PARAMETER ReadinessCsv
    Readiness checklist CSV.

.PARAMETER FindingsCsv
    Review Trail CSV export of the findings review workbook.

.PARAMETER StatusRegisterCsv
    Status register CSV.

.PARAMETER Title
    Page heading. Default: Engagement dashboard

.PARAMETER StaleAfterDays
    Latest runs older than this many days are marked in amber. Default 30.

.PARAMETER OutputRoot
    Where the tool's run folder goes. Default: -EvidenceRoot, or tools\output when no evidence root is given.

.EXAMPLE
    .\tools\New-EngagementDashboard.ps1 -EvidenceRoot D:\Engagement\evidence -ReadinessCsv D:\Engagement\registers\readiness-checklist.csv `
        -StatusRegisterCsv D:\Engagement\registers\status-register.csv -FindingsCsv D:\Engagement\findings\findings-review.csv `
        -Title 'Identity programme dashboard' -OutputRoot D:\Engagement\reports

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x.
    Scopes  : none. Reads local files only.
    Licence : none
    Sources : run-manifest.json and dataset-status.csv of each run; kpi-summary.csv of the latest
              Get-KpiSummary run; the register CSVs passed as parameters.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$EvidenceRoot = '',
    [string]$ReadinessCsv = '',
    [string]$FindingsCsv = '',
    [string]$StatusRegisterCsv = '',
    [string]$Title = 'Engagement dashboard',
    [int]$StaleAfterDays = 30,
    [string]$OutputRoot = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = 'New-EngagementDashboard'
$ScriptVersion = '1.0.0'

foreach ($p in @(@('EvidenceRoot', $EvidenceRoot), @('ReadinessCsv', $ReadinessCsv), @('FindingsCsv', $FindingsCsv), @('StatusRegisterCsv', $StatusRegisterCsv))) {
    if ($p[1] -and -not (Test-Path -LiteralPath $p[1])) { throw "-$($p[0]) not found: $($p[1])" }
}
if ($EvidenceRoot) { $EvidenceRoot = (Resolve-Path -LiteralPath $EvidenceRoot).Path }
if (-not $OutputRoot -and $EvidenceRoot) { $OutputRoot = $EvidenceRoot }
$catalog = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'discovery-catalog.psd1')).Scripts

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
        $Rows | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
        $count = @($Rows).Count
    }
    else { Set-Content -Path $file -Value '' -Encoding UTF8 }
    $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
    $script:Datasets.Add([pscustomobject][ordered]@{ Dataset = $Name; Status = $Status; Rows = $count; File = (Split-Path $file -Leaf); Sha256 = $hash; Note = $Note })
    Write-RunLog ("{0}: {1} rows [{2}] {3}" -f $Name, $count, $Status, $Note)
}

function Export-TextDataset {
    param([string]$Name, [string]$FileName, [string]$Text, [string]$Note = '')
    $file = Join-Path $script:RunFolder $FileName
    Set-Content -Path $file -Value $Text -Encoding UTF8
    $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
    $script:Datasets.Add([pscustomobject][ordered]@{ Dataset = $Name; Status = 'Completed'; Rows = ''; File = $FileName; Sha256 = $hash; Note = $Note })
    Write-RunLog ("{0}: written [{1}]" -f $FileName, $hash)
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
$script:Statuses = @('Completed', 'Partial', 'Blocked', 'Deferred', 'EvidenceUnavailable')
$script:Rank = @{ Completed = 0; Partial = 1; Deferred = 2; EvidenceUnavailable = 3; Blocked = 4; NotRun = 5 }

function ConvertTo-HtmlText { param($Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }

function Read-CsvSafe {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    if ((Get-Item -LiteralPath $Path).Length -lt 4) { return @() }
    return @(Import-Csv -LiteralPath $Path)
}

function Read-RegisterCsv {
    # Register CSV, skipping any title rows above the header (an Excel export of a sheet with a section row).
    param([string]$Path, [string[]]$HeaderMustContain)
    $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8)
    $start = -1
    for ($i = 0; $i -lt [math]::Min($lines.Count, 10); $i++) {
        $cells = @(($lines[$i] | ConvertFrom-Csv -Header (1..200 | ForEach-Object { "c$_" })).PSObject.Properties | ForEach-Object { "$($_.Value)".Trim() })
        $hit = $true
        foreach ($h in $HeaderMustContain) { if ($cells -notcontains $h) { $hit = $false; break } }
        if ($hit) { $start = $i; break }
    }
    if ($start -lt 0) { return [pscustomobject]@{ Rows = @(); Error = "Header row with $($HeaderMustContain -join ', ') not found in the first 10 lines" } }
    # One string, not one line at a time: a cell with a line break (Alt+Enter in Excel) stays one cell
    $rows = @(($lines[$start..($lines.Count - 1)] -join "`n") | ConvertFrom-Csv)
    return [pscustomobject]@{ Rows = $rows; Error = '' }
}

function Get-Col {
    # Value of a column by name, trimmed; '' when the column is absent.
    param($Row, [string]$Name)
    $p = $Row.PSObject.Properties[$Name]
    if ($p) { return "$($p.Value)".Trim() }
    return ''
}

function Get-Chip {
    param([string]$Text, [string]$Kind = '')
    if (-not $Kind) {
        $Kind = switch -Regex ($Text) {
            '^(Completed|Closed|Waived|Met|Accepted|Accept and remediate|Low)$' { 'ok'; break }
            '^(Partial|In progress|With client|Architect reviewed|EvidenceUnavailable|Unavailable|High|Accept risk|Stale)$' { 'warn'; break }
            '^(Medium|Defer)$' { 'info'; break }
            '^(Blocked|Open|Not met|HashMismatch|Critical|Reject|NotRun|Not run)$' { 'bad'; break }
            default { 'muted' }
        }
    }
    $label = $(if ($Text -eq 'EvidenceUnavailable') { 'Unavailable' } else { $Text })
    return "<span class=""chip $Kind"">$(ConvertTo-HtmlText $label)</span>"
}

function Get-Bar {
    # Horizontal stacked bar with a legend; Parts = ordered list of @(label, count, cssClass)
    param([object[]]$Parts, [string]$AriaLabel)
    $total = 0; foreach ($p in $Parts) { $total += [int]$p[1] }
    if ($total -le 0) { return '<p class="muted">Nothing to show.</p>' }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<div class=""bar"" role=""img"" aria-label=""$(ConvertTo-HtmlText $AriaLabel)"">")
    foreach ($p in $Parts) {
        if ([int]$p[1] -le 0) { continue }
        $w = [math]::Round(100.0 * [int]$p[1] / $total, 2).ToString($script:Inv)
        [void]$sb.Append("<span class=""seg $($p[2])"" style=""width:$w%"" title=""$(ConvertTo-HtmlText ("$($p[0]): $($p[1])"))""></span>")
    }
    [void]$sb.Append('</div><div class="legend">')
    foreach ($p in $Parts) {
        $muted = $(if ([int]$p[1] -le 0) { ' zero' } else { '' })
        [void]$sb.Append("<span class=""key$muted""><i class=""dot $($p[2])""></i>$(ConvertTo-HtmlText $p[0]) <b>$([int]$p[1])</b></span>")
    }
    [void]$sb.Append('</div>')
    return $sb.ToString()
}

function Get-NotProvided {
    param([string]$What, [string]$How)
    return "<div class=""empty""><b>Not provided.</b> $(ConvertTo-HtmlText $What) <span class=""muted"">$(ConvertTo-HtmlText $How)</span></div>"
}

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $inputs = [ordered]@{}
    foreach ($p in @(@('ReadinessCsv', $ReadinessCsv), @('FindingsCsv', $FindingsCsv), @('StatusRegisterCsv', $StatusRegisterCsv))) {
        if ($p[1]) { $inputs[$p[0]] = [ordered]@{ File = (Split-Path $p[1] -Leaf); Sha256 = (Get-FileHash -LiteralPath $p[1] -Algorithm SHA256).Hash } }
    }

    # =================================================================== 1. Runs
    $runRows = [System.Collections.Generic.List[object]]::new()
    $kpi = $null
    if ($EvidenceRoot) {
        foreach ($s in $catalog) {
            $runs = @(Get-ChildItem -LiteralPath $EvidenceRoot -Directory -Filter "$($s.Number)-*" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notmatch '_aborted' } |
                    ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
                    Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' -and $_.FullName -notmatch '[\\/]_aborted([\\/]|$)' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'run-manifest.json')) } |
                    Sort-Object Name)
            $row = [ordered]@{ Number = $s.Number; Script = $s.Title; Area = $s.Area; Runs = $runs.Count; LastRunUtc = ''; AgeDays = ''; Version = ''; Outcome = 'NotRun' }
            foreach ($st in $script:Statuses) { $row[$st] = 0 }
            if ($runs.Count) {
                $latest = $runs[-1]
                $started = [datetime]::ParseExact($latest.Name, "yyyyMMdd-HHmmss'Z'", $script:Inv, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
                $row.LastRunUtc = $started.ToString('yyyy-MM-dd HH:mm') + 'Z'
                $row.AgeDays = [math]::Floor(($script:RunStartUtc - $started).TotalDays)
                try { $m = Get-Content -LiteralPath (Join-Path $latest.FullName 'run-manifest.json') -Raw | ConvertFrom-Json; $row.Version = "$($m.ScriptVersion)" } catch { $row.Version = '?' }
                $worst = 'Completed'
                foreach ($d in (Read-CsvSafe (Join-Path $latest.FullName 'dataset-status.csv'))) {
                    if ($d.Dataset -eq 'summary') { continue }
                    if ($row.Contains($d.Status)) { $row[$d.Status]++ } else { $row['Partial']++ }
                    $st = $(if ($script:Rank.ContainsKey($d.Status)) { $d.Status } else { 'Partial' })
                    if ($script:Rank[$st] -gt $script:Rank[$worst]) { $worst = $st }
                }
                $row.Outcome = $worst
            }
            $runRows.Add([pscustomobject]$row)
        }
        Write-RunLog ("Runs: {0} of {1} scripts have a run" -f @($runRows | Where-Object { $_.Runs }).Count, $catalog.Count)

        # KPI summary: latest Get-KpiSummary run with kpi-summary.csv
        $kpiRun = @(Get-ChildItem -LiteralPath (Join-Path $EvidenceRoot 'Get-KpiSummary') -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'kpi-summary.csv')) } | Sort-Object Name) | Select-Object -Last 1
        if ($kpiRun) {
            $kpiFile = Join-Path $kpiRun.FullName 'kpi-summary.csv'
            $recorded = @(Read-CsvSafe (Join-Path $kpiRun.FullName 'dataset-status.csv') | Where-Object { $_.Dataset -eq 'kpi-summary' }) | Select-Object -First 1
            $actual = (Get-FileHash -LiteralPath $kpiFile -Algorithm SHA256).Hash
            $hashOk = [bool]($recorded -and "$($recorded.Sha256)".ToUpperInvariant() -eq $actual)
            $kpi = [pscustomobject]@{ Run = $kpiRun.Name; Rows = @(Read-CsvSafe $kpiFile); HashOk = $hashOk }
            Write-RunLog ("KPIs: {0} from Get-KpiSummary\{1}; hash {2}" -f $kpi.Rows.Count, $kpiRun.Name, $(if ($hashOk) { 'verified' } else { 'MISMATCH' })) $(if ($hashOk) { 'INFO' } else { 'WARN' })
        }
    }

    # =================================================================== 2. Registers
    $ready = $null
    if ($ReadinessCsv) {
        $r = Read-RegisterCsv -Path $ReadinessCsv -HeaderMustContain @('Prerequisite', 'Status')
        $ready = [pscustomobject]@{ Rows = @($r.Rows | Where-Object { (Get-Col $_ 'Prerequisite') -or (Get-Col $_ 'PrereqId') }); Error = $r.Error }
        Write-RunLog ("Readiness: {0} item(s) {1}" -f $ready.Rows.Count, $r.Error)
    }
    $find = $null
    if ($FindingsCsv) {
        $r = Read-RegisterCsv -Path $FindingsCsv -HeaderMustContain @('ID', 'Finding')
        $rows = @($r.Rows | Where-Object { Get-Col $_ 'ID' })
        $missing = @()
        if (-not $r.Error -and $r.Rows.Count) { foreach ($c in 'Observed severity', 'Architect severity', 'Client decision', 'Stage') { if (-not $r.Rows[0].PSObject.Properties[$c]) { $missing += $c } } }
        $items = foreach ($f in $rows) {
            $stage = Get-Col $f 'Stage'
            if (-not $stage) {
                $stage = $(if (Get-Col $f 'Client decision') { 'Closed' } elseif (Get-Col $f 'Alignment') { 'With client' } elseif (Get-Col $f 'Architect severity') { 'Architect reviewed' } else { 'Draft' })
            }
            $sev = Get-Col $f 'Architect severity'; if (-not $sev) { $sev = Get-Col $f 'Observed severity' }
            [pscustomobject]@{ ID = Get-Col $f 'ID'; Finding = Get-Col $f 'Finding'; Observed = Get-Col $f 'Observed severity'; Architect = Get-Col $f 'Architect severity'; Severity = $sev
                Stage = $stage; Waiting = Get-Col $f 'Waiting on'; Decision = Get-Col $f 'Client decision'; Tracking = Get-Col $f 'Tracking ID' }
        }
        $err = $r.Error
        if ($missing.Count) { $err = "Column(s) missing: $($missing -join ', ')" }
        $find = [pscustomobject]@{ Rows = @($items); Error = $err }
        Write-RunLog ("Findings: {0} {1}" -f $find.Rows.Count, $err)
    }
    $reg = $null
    if ($StatusRegisterCsv) {
        $r = Read-RegisterCsv -Path $StatusRegisterCsv -HeaderMustContain @('ItemId', 'EvidenceState')
        $reg = [pscustomobject]@{ Rows = @($r.Rows | Where-Object { Get-Col $_ 'ItemId' }); Error = $r.Error }
        Write-RunLog ("Status register: {0} item(s) {1}" -f $reg.Rows.Count, $r.Error)
    }

    # =================================================================== 3. Headline numbers
    $ran = @($runRows | Where-Object { $_.Runs })
    $dsTotals = [ordered]@{}; foreach ($st in $script:Statuses) { $dsTotals[$st] = ($ran | Measure-Object -Property $st -Sum).Sum; if ($null -eq $dsTotals[$st]) { $dsTotals[$st] = 0 } }
    $kpiWithTarget = @(); $kpiMet = @()
    if ($kpi) { $kpiWithTarget = @($kpi.Rows | Where-Object { "$($_.MeetsTarget)" -in @('True', 'False') }); $kpiMet = @($kpiWithTarget | Where-Object { "$($_.MeetsTarget)" -eq 'True' }) }
    $readyCounts = [ordered]@{ Closed = 0; Waived = 0; 'In progress' = 0; Open = 0; Other = 0 }
    if ($ready) { foreach ($x in $ready.Rows) { $st = Get-Col $x 'Status'; $k = @($readyCounts.Keys | Where-Object { $_ -ieq $st }) | Select-Object -First 1; if (-not $k -and $st -match '^Closed') { $k = 'Closed' }; if ($k) { $readyCounts[$k]++ } else { $readyCounts['Other']++ } } }
    $stageOrder = @('Draft', 'Architect reviewed', 'With client', 'Closed')
    $stageCounts = [ordered]@{}; foreach ($s in $stageOrder) { $stageCounts[$s] = 0 }
    $sevOrder = @('Critical', 'High', 'Medium', 'Low', 'Not rated')
    $sevCounts = [ordered]@{}; foreach ($s in $sevOrder) { $sevCounts[$s] = 0 }
    $decOrder = @('Accept and remediate', 'Accept risk', 'Defer', 'Reject', 'Pending')
    $decCounts = [ordered]@{}; foreach ($s in $decOrder) { $decCounts[$s] = 0 }
    if ($find) {
        foreach ($f in $find.Rows) {
            $k = @($stageOrder | Where-Object { $_ -ieq $f.Stage }) | Select-Object -First 1; if ($k) { $stageCounts[$k]++ } else { $stageCounts['Draft']++ }
            $k = @($sevOrder | Where-Object { $_ -ieq $f.Severity }) | Select-Object -First 1; if ($k) { $sevCounts[$k]++ } else { $sevCounts['Not rated']++ }
            $k = @($decOrder | Where-Object { $_ -ieq $f.Decision }) | Select-Object -First 1; if ($k) { $decCounts[$k]++ } else { $decCounts['Pending']++ }
        }
    }
    $regOpen = @(); if ($reg) { $regOpen = @($reg.Rows | Where-Object { (Get-Col $_ 'EvidenceState') -ne 'Completed' }) }

    # =================================================================== 4. HTML
    $sb = [System.Text.StringBuilder]::new()
    $generated = $script:RunStartUtc.ToString('yyyy-MM-dd HH:mm') + 'Z'
    $sources = @()
    if ($EvidenceRoot) { $sources += 'discovery runs' }; if ($kpi) { $sources += 'KPI summary' }; if ($ready) { $sources += 'readiness checklist' }
    if ($find) { $sources += 'findings review' }; if ($reg) { $sources += 'status register' }
    $sourcesText = $(if ($sources) { $sources -join ', ' } else { 'no inputs given' })

    function Add-Tile { param([string]$Value, [string]$Of, [string]$Label, [string]$Kind = '', [string]$Sub = '')
        $ofHtml = $(if ($Of) { "<span class=""of""> / $(ConvertTo-HtmlText $Of)</span>" } else { '' })
        $subHtml = $(if ($Sub) { "<div class=""s"">$(ConvertTo-HtmlText $Sub)</div>" } else { '' })
        [void]$sb.Append("<div class=""tile $Kind""><div class=""n"">$(ConvertTo-HtmlText $Value)$ofHtml</div><div class=""l"">$(ConvertTo-HtmlText $Label)</div>$subHtml</div>`n")
    }

    [void]$sb.Append(@"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(ConvertTo-HtmlText $Title)</title>
<style>
:root{color-scheme:light dark;--bg:#f4f6f8;--panel:#fff;--text:#18212b;--muted:#5d6975;--line:#e1e5ea;--head:#f7f8fa;--accent:#1f5fbf;
--ok:#1e7d46;--ok-bg:#e2f3e8;--warn:#9a6200;--warn-bg:#fcf0d6;--bad:#b3261e;--bad-bg:#fbe4e2;--mut:#4f5b66;--mut-bg:#eceff2;--info:#5b4bb7;--info-bg:#ebe8f8;
--seg-ok:#2e9c5a;--seg-warn:#e0a526;--seg-bad:#d2463c;--seg-mut:#a9b3bd;--seg-info:#7b6bd6;--seg-acc:#3a78d6}
@media (prefers-color-scheme:dark){:root{--bg:#11151a;--panel:#191f26;--text:#e5e9ee;--muted:#9aa6b2;--line:#2b333c;--head:#1d242c;--accent:#7eaaff;
--ok:#8be0ad;--ok-bg:#16382a;--warn:#f2c66d;--warn-bg:#3a2e12;--bad:#ffa69d;--bad-bg:#43201d;--mut:#b6c0ca;--mut-bg:#29313a;--info:#c2b8ff;--info-bg:#2c2748;
--seg-ok:#3fb26f;--seg-warn:#d9a33a;--seg-bad:#e0605a;--seg-mut:#5d6874;--seg-info:#8f80e8;--seg-acc:#5b8fe0}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1240px;margin:0 auto;padding:28px 20px 48px}
header{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:6px 20px;border-bottom:1px solid var(--line);padding-bottom:14px}
header h1{margin:0;font-size:24px;font-weight:650;letter-spacing:-.01em}
header p{margin:4px 0 0;color:var(--muted);font-size:13px}
.stamp{color:var(--muted);font-size:12.5px;text-align:right}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0 8px}
.tile{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--seg-acc);border-radius:10px;padding:13px 15px 12px}
.tile.ok{border-top-color:var(--seg-ok)}.tile.warn{border-top-color:var(--seg-warn)}.tile.bad{border-top-color:var(--seg-bad)}.tile.mut{border-top-color:var(--seg-mut)}
.tile .n{font-size:28px;font-weight:650;font-variant-numeric:tabular-nums;line-height:1.15}
.tile .of{font-size:15px;color:var(--muted);font-weight:500}
.tile .l{color:var(--text);font-size:13px;margin-top:3px;font-weight:550}
.tile .s{color:var(--muted);font-size:12px;margin-top:2px}
section{margin-top:28px}
section>h2{font-size:17px;font-weight:650;margin:0 0 4px}
section>.lead{color:var(--muted);margin:0 0 12px;font-size:13px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.panel h3{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}
.table{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11.5px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;background:var(--head);white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.z{color:var(--muted)}
td.txt{min-width:16em}
tr.notrun td{color:var(--muted)}
.chip{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.chip.ok{background:var(--ok-bg);color:var(--ok)}.chip.warn{background:var(--warn-bg);color:var(--warn)}.chip.bad{background:var(--bad-bg);color:var(--bad)}
.chip.muted{background:var(--mut-bg);color:var(--mut)}.chip.info{background:var(--info-bg);color:var(--info)}
.bar{display:flex;height:12px;border-radius:999px;overflow:hidden;background:var(--mut-bg);margin:2px 0 10px}
.seg{display:block;height:100%}
.seg.ok,.dot.ok{background:var(--seg-ok)}.seg.warn,.dot.warn{background:var(--seg-warn)}.seg.bad,.dot.bad{background:var(--seg-bad)}
.seg.mut,.dot.mut{background:var(--seg-mut)}.seg.info,.dot.info{background:var(--seg-info)}.seg.acc,.dot.acc{background:var(--seg-acc)}
.legend{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12.5px;color:var(--muted)}
.legend .key b{color:var(--text);font-weight:650;margin-left:2px}
.legend .key.zero{opacity:.55}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:0}
.meter{display:inline-block;width:70px;height:6px;border-radius:999px;background:var(--mut-bg);vertical-align:middle;margin-left:8px;position:relative;overflow:hidden}
.meter i{position:absolute;left:0;top:0;bottom:0;background:var(--seg-acc)}
.meter.ok i{background:var(--seg-ok)}.meter.bad i{background:var(--seg-bad)}
.empty{background:var(--panel);border:1px dashed var(--line);border-radius:10px;padding:14px 16px}
.alert{background:var(--warn-bg);color:var(--warn);border-radius:8px;padding:8px 12px;margin:0 0 10px;font-size:13px}
.muted{color:var(--muted)}
.sub{font-size:12px;color:var(--muted);margin-top:2px}
footer{margin-top:36px;color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);padding-top:12px}
@media (max-width:600px){.wrap{padding:18px 14px 36px}header h1{font-size:20px}.stamp{text-align:left}.tile .n{font-size:24px}.tiles{grid-template-columns:repeat(2,minmax(0,1fr))}th,td{padding:7px 9px}}
@media print{:root{--bg:#fff;--panel:#fff}body{background:#fff;font-size:12px}.wrap{max-width:none;padding:0}.table{overflow:visible}
.tile,.panel,.empty{break-inside:avoid}tr{break-inside:avoid}section{break-inside:auto}.bar,.seg,.dot,.chip,.meter i{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>
</head>
<body>
<div class="wrap">
<header>
<div><h1>$(ConvertTo-HtmlText $Title)</h1><p>Counts and statuses only &middot; sources: $(ConvertTo-HtmlText $sourcesText)</p></div>
<div class="stamp">Generated $generated</div>
</header>
<div class="tiles">
"@)

    # ---- tiles ----
    if ($EvidenceRoot) {
        $stale = @($ran | Where-Object { $_.AgeDays -ne '' -and [int]$_.AgeDays -gt $StaleAfterDays }).Count
        Add-Tile -Value "$($ran.Count)" -Of "$($catalog.Count)" -Label 'Scripts run' -Kind $(if ($ran.Count -eq $catalog.Count) { 'ok' } else { '' }) -Sub $(if ($stale) { "$stale older than $StaleAfterDays days" } else { 'Latest run of each script' })
        Add-Tile -Value "$($dsTotals['Blocked'])" -Label 'Datasets blocked' -Kind $(if ($dsTotals['Blocked']) { 'bad' } else { 'ok' }) -Sub ("{0} unavailable, {1} partial" -f $dsTotals['EvidenceUnavailable'], $dsTotals['Partial'])
    }
    else { Add-Tile -Value '-' -Label 'Scripts run' -Kind 'mut' -Sub 'No evidence root' }
    if ($kpi -and $kpiWithTarget.Count) { Add-Tile -Value "$($kpiMet.Count)" -Of "$($kpiWithTarget.Count)" -Label 'KPIs meeting target' -Kind $(if ($kpiMet.Count -eq $kpiWithTarget.Count) { 'ok' } else { 'warn' }) -Sub ("{0} KPI(s) without a value" -f (@($kpi.Rows).Count - $kpiWithTarget.Count)) }
    else { Add-Tile -Value '-' -Label 'KPIs meeting target' -Kind 'mut' -Sub $(if ($kpi) { 'No KPI with a value and target' } else { 'No KPI summary' }) }
    if ($ready -and $ready.Rows.Count) { $done = $readyCounts['Closed'] + $readyCounts['Waived']; Add-Tile -Value "$done" -Of "$($ready.Rows.Count)" -Label 'Readiness closed or waived' -Kind $(if ($done -eq $ready.Rows.Count) { 'ok' } else { 'warn' }) -Sub ("{0} open, {1} in progress" -f $readyCounts['Open'], $readyCounts['In progress']) }
    else { Add-Tile -Value '-' -Label 'Readiness closed or waived' -Kind 'mut' -Sub 'No readiness checklist' }
    if ($find -and $find.Rows.Count) { Add-Tile -Value "$($stageCounts['Closed'])" -Of "$($find.Rows.Count)" -Label 'Findings decided' -Kind $(if ($sevCounts['Critical'] -or $sevCounts['High']) { 'bad' } elseif ($stageCounts['Closed'] -eq $find.Rows.Count) { 'ok' } else { 'warn' }) -Sub ("{0} critical, {1} high" -f $sevCounts['Critical'], $sevCounts['High']) }
    else { Add-Tile -Value '-' -Label 'Findings decided' -Kind 'mut' -Sub 'No findings review' }
    if ($reg) { Add-Tile -Value "$($regOpen.Count)" -Of "$($reg.Rows.Count)" -Label 'Evidence items not completed' -Kind $(if ($regOpen.Count) { 'warn' } else { 'ok' }) -Sub ("{0} blocked, {1} deferred" -f @($regOpen | Where-Object { (Get-Col $_ 'EvidenceState') -eq 'Blocked' }).Count, @($regOpen | Where-Object { (Get-Col $_ 'EvidenceState') -eq 'Deferred' }).Count) }
    else { Add-Tile -Value '-' -Label 'Evidence items not completed' -Kind 'mut' -Sub 'No status register' }
    [void]$sb.Append("</div>`n")

    # ---- Discovery runs ----
    [void]$sb.Append("<section><h2>Discovery runs</h2><p class=""lead"">Latest run of each script and what its datasets returned. Blocked = the run account lacked access; Unavailable = the tenant cannot produce it (often licensing); Deferred = skipped on purpose.</p>`n")
    if (-not $EvidenceRoot) { [void]$sb.Append((Get-NotProvided 'No evidence root.' 'Pass -EvidenceRoot.')) }
    else {
        [void]$sb.Append('<div class="panel" style="margin-bottom:12px"><h3>Datasets across the latest runs</h3>')
        [void]$sb.Append((Get-Bar -AriaLabel 'Dataset status' -Parts @(@('Completed', $dsTotals['Completed'], 'ok'), @('Partial', $dsTotals['Partial'], 'warn'), @('Unavailable', $dsTotals['EvidenceUnavailable'], 'info'), @('Deferred', $dsTotals['Deferred'], 'mut'), @('Blocked', $dsTotals['Blocked'], 'bad'))))
        [void]$sb.Append("</div>`n<div class=""table""><table><thead><tr><th>#</th><th>Script</th><th>Area</th><th>Last run</th><th class=""num"">Age (days)</th><th>Version</th><th class=""num"">Completed</th><th class=""num"">Partial</th><th class=""num"">Blocked</th><th class=""num"">Deferred</th><th class=""num"">Unavailable</th><th>Status</th></tr></thead><tbody>`n")
        foreach ($r in $runRows) {
            if (-not $r.Runs) {
                [void]$sb.Append("<tr class=""notrun""><td>$($r.Number)</td><td>$(ConvertTo-HtmlText $r.Script)</td><td>$(ConvertTo-HtmlText $r.Area)</td><td>Not run</td><td class=""num""></td><td></td><td class=""num""></td><td class=""num""></td><td class=""num""></td><td class=""num""></td><td class=""num""></td><td>$(Get-Chip 'Not run' 'muted')</td></tr>`n")
                continue
            }
            $ageCls = $(if ([int]$r.AgeDays -gt $StaleAfterDays) { ' style="color:var(--warn);font-weight:600"' } else { '' })
            $cells = foreach ($st in $script:Statuses) { $v = [int]$r.$st; "<td class=""num$(if (-not $v) { ' z' })"">$v</td>" }
            [void]$sb.Append("<tr><td>$($r.Number)</td><td>$(ConvertTo-HtmlText $r.Script)</td><td>$(ConvertTo-HtmlText $r.Area)</td><td style=""white-space:nowrap"">$(ConvertTo-HtmlText $r.LastRunUtc)</td><td class=""num""$ageCls>$($r.AgeDays)</td><td>$(ConvertTo-HtmlText $r.Version)</td>$($cells -join '')<td>$(Get-Chip $r.Outcome)</td></tr>`n")
        }
        [void]$sb.Append("</tbody></table></div>`n")
    }
    [void]$sb.Append("</section>`n")

    # ---- KPIs ----
    [void]$sb.Append("<section><h2>KPIs</h2><p class=""lead"">From the latest Get-KpiSummary run. A KPI without a value has a reason in that run's kpi-summary.csv.</p>`n")
    if (-not $kpi) { [void]$sb.Append((Get-NotProvided 'No Get-KpiSummary run in the evidence root.' 'Run tools\Get-KpiSummary.ps1 -EvidenceRoot <evidence>.')) }
    else {
        if (-not $kpi.HashOk) { [void]$sb.Append('<div class="alert">kpi-summary.csv no longer matches the SHA-256 recorded when it was written. Rerun Get-KpiSummary before using these numbers.</div>') }
        [void]$sb.Append("<p class=""sub"" style=""margin:-6px 0 8px"">Run Get-KpiSummary\$(ConvertTo-HtmlText $kpi.Run)</p><div class=""table""><table><thead><tr><th>KPI</th><th>Name</th><th class=""num"">Value</th><th class=""num"">Target</th><th>Direction</th><th>Target met</th><th>Status</th></tr></thead><tbody>`n")
        foreach ($k in $kpi.Rows) {
            $v = "$($k.Value)"; $meets = "$($k.MeetsTarget)"
            $meetChip = $(if ($meets -eq 'True') { Get-Chip 'Met' } elseif ($meets -eq 'False') { Get-Chip 'Not met' } else { Get-Chip 'No value' 'muted' })
            $meter = ''
            $num = 0.0
            $vn = $(if ($v -match '^[+-]?\d+,\d+$') { $v -replace ',', '.' } else { $v })   # decimal-comma culture
            if ($v -and [double]::TryParse($vn, [Globalization.NumberStyles]::Float, $script:Inv, [ref]$num)) {
                $w = [math]::Max(0, [math]::Min(100, $num)).ToString('0.#', $script:Inv)
                $mcls = $(if ($meets -eq 'True') { 'ok' } elseif ($meets -eq 'False') { 'bad' } else { '' })
                $meter = "<span class=""meter $mcls""><i style=""width:$w%""></i></span>"
                $v = "$v%"
            }
            $dir = $(if ($k.Direction -eq 'LowerIsBetter') { 'Lower is better' } elseif ($k.Direction -eq 'HigherIsBetter') { 'Higher is better' } else { "$($k.Direction)" })
            $tgt = $(if ("$($k.Target)") { "$($k.Target)%" } else { '' })
            [void]$sb.Append("<tr><td style=""white-space:nowrap"">$(ConvertTo-HtmlText $k.KpiId)</td><td class=""txt"">$(ConvertTo-HtmlText $k.Name)</td><td class=""num"">$(ConvertTo-HtmlText $v)$meter</td><td class=""num"">$(ConvertTo-HtmlText $tgt)</td><td style=""white-space:nowrap"">$(ConvertTo-HtmlText $dir)</td><td>$meetChip</td><td>$(Get-Chip "$($k.Status)")</td></tr>`n")
        }
        [void]$sb.Append("</tbody></table></div>`n")
    }
    [void]$sb.Append("</section>`n")

    # ---- Readiness ----
    [void]$sb.Append("<section><h2>Readiness</h2><p class=""lead"">The pre-project gate passes when every prerequisite is Closed with evidence or formally Waived.</p>`n")
    if (-not $ready) { [void]$sb.Append((Get-NotProvided 'No readiness checklist.' 'Pass -ReadinessCsv (registers\readiness-checklist.csv).')) }
    elseif ($ready.Error) { [void]$sb.Append("<div class=""alert"">$(ConvertTo-HtmlText $ready.Error)</div>") }
    else {
        [void]$sb.Append('<div class="panel" style="margin-bottom:12px"><h3>Prerequisites</h3>')
        [void]$sb.Append((Get-Bar -AriaLabel 'Readiness status' -Parts @(@('Closed', $readyCounts['Closed'], 'ok'), @('Waived', $readyCounts['Waived'], 'acc'), @('In progress', $readyCounts['In progress'], 'warn'), @('Open', $readyCounts['Open'], 'bad'), @('Other', $readyCounts['Other'], 'mut'))))
        [void]$sb.Append('</div>')
        $open = @($ready.Rows | Where-Object { (Get-Col $_ 'Status') -notmatch '^(Closed|Waived)' })
        if ($open.Count) {
            [void]$sb.Append("<div class=""table""><table><thead><tr><th>#</th><th>Prerequisite</th><th>What closes it</th><th>Status</th><th>Owner</th><th>Due</th></tr></thead><tbody>`n")
            foreach ($x in $open) {
                $due = Get-Col $x 'DueDateUtc'; if ($due -match '^\d{4}-\d{2}-\d{2}') { $due = $due.Substring(0, 10) }
                [void]$sb.Append("<tr><td style=""white-space:nowrap"">$(ConvertTo-HtmlText (Get-Col $x 'PrereqId'))</td><td class=""txt"">$(ConvertTo-HtmlText (Get-Col $x 'Prerequisite'))</td><td class=""txt"">$(ConvertTo-HtmlText (Get-Col $x 'WhatClosesIt'))</td><td>$(Get-Chip (Get-Col $x 'Status'))</td><td>$(ConvertTo-HtmlText (Get-Col $x 'Owner'))</td><td style=""white-space:nowrap"">$(ConvertTo-HtmlText $due)</td></tr>`n")
            }
            [void]$sb.Append("</tbody></table></div>`n")
        }
        else { [void]$sb.Append('<p class="muted">Every prerequisite is Closed or Waived.</p>') }
    }
    [void]$sb.Append("</section>`n")

    # ---- Findings ----
    [void]$sb.Append("<section><h2>Findings</h2><p class=""lead"">From the findings review workbook (Review Trail). Severity is the architect's where set, otherwise the engineer's observed severity.</p>`n")
    if (-not $find) { [void]$sb.Append((Get-NotProvided 'No findings review.' 'Export the Review Trail sheet to CSV and pass -FindingsCsv.')) }
    elseif ($find.Error -and -not $find.Rows.Count) { [void]$sb.Append("<div class=""alert"">$(ConvertTo-HtmlText $find.Error)</div>") }
    else {
        if ($find.Error) { [void]$sb.Append("<div class=""alert"">$(ConvertTo-HtmlText $find.Error)</div>") }
        [void]$sb.Append('<div class="grid2" style="margin-bottom:12px"><div class="panel"><h3>Review stage</h3>')
        [void]$sb.Append((Get-Bar -AriaLabel 'Findings by stage' -Parts @(@('Draft', $stageCounts['Draft'], 'mut'), @('Architect reviewed', $stageCounts['Architect reviewed'], 'info'), @('With client', $stageCounts['With client'], 'warn'), @('Closed', $stageCounts['Closed'], 'ok'))))
        [void]$sb.Append('</div><div class="panel"><h3>Severity</h3>')
        [void]$sb.Append((Get-Bar -AriaLabel 'Findings by severity' -Parts @(@('Critical', $sevCounts['Critical'], 'bad'), @('High', $sevCounts['High'], 'warn'), @('Medium', $sevCounts['Medium'], 'info'), @('Low', $sevCounts['Low'], 'ok'), @('Not rated', $sevCounts['Not rated'], 'mut'))))
        [void]$sb.Append('</div><div class="panel"><h3>Client decision</h3>')
        [void]$sb.Append((Get-Bar -AriaLabel 'Findings by client decision' -Parts @(@('Accept and remediate', $decCounts['Accept and remediate'], 'ok'), @('Accept risk', $decCounts['Accept risk'], 'warn'), @('Defer', $decCounts['Defer'], 'info'), @('Reject', $decCounts['Reject'], 'bad'), @('Pending', $decCounts['Pending'], 'mut'))))
        [void]$sb.Append("</div></div>`n")
        $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
        $sorted = @($find.Rows | Sort-Object { if ($sevRank.ContainsKey($_.Severity)) { $sevRank[$_.Severity] } else { 9 } }, { $_.ID })
        [void]$sb.Append("<div class=""table""><table><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Stage</th><th>Waiting on</th><th>Client decision</th><th>Tracking</th></tr></thead><tbody>`n")
        foreach ($f in $sorted) {
            $sevCell = $(if ($f.Severity) { Get-Chip $f.Severity } else { Get-Chip 'Not rated' 'muted' })
            if ($f.Architect -and $f.Observed -and $f.Architect -ne $f.Observed) { $sevCell += "<div class=""sub"">observed $(ConvertTo-HtmlText $f.Observed)</div>" }
            $stageKind = switch ($f.Stage) { 'Closed' { 'ok' } 'With client' { 'warn' } 'Architect reviewed' { 'info' } default { 'muted' } }
            $waiting = $(if ($f.Waiting) { $f.Waiting } elseif ($f.Stage -eq 'Closed') { 'None' } elseif ($f.Stage -eq 'With client') { 'Client' } elseif ($f.Stage -eq 'Architect reviewed') { 'Zero Trust Architect' } else { 'Identity Architect' })
            [void]$sb.Append("<tr><td style=""white-space:nowrap"">$(ConvertTo-HtmlText $f.ID)</td><td class=""txt"">$(ConvertTo-HtmlText $f.Finding)</td><td>$sevCell</td><td>$(Get-Chip $f.Stage $stageKind)</td><td>$(ConvertTo-HtmlText $waiting)</td><td>$(ConvertTo-HtmlText $f.Decision)</td><td>$(ConvertTo-HtmlText $f.Tracking)</td></tr>`n")
        }
        [void]$sb.Append("</tbody></table></div>`n")
    }
    [void]$sb.Append("</section>`n")

    # ---- Status register ----
    [void]$sb.Append("<section><h2>Evidence items not completed</h2><p class=""lead"">From the status register. Blocked and deferred items always carry an owner, rationale, risk and follow-on, and are never presented as implemented.</p>`n")
    if (-not $reg) { [void]$sb.Append((Get-NotProvided 'No status register.' 'Pass -StatusRegisterCsv (registers\status-register.csv).')) }
    elseif ($reg.Error) { [void]$sb.Append("<div class=""alert"">$(ConvertTo-HtmlText $reg.Error)</div>") }
    elseif (-not $regOpen.Count) { [void]$sb.Append('<p class="muted">Every item in the status register is Completed.</p>') }
    else {
        $stRank = @{ Blocked = 0; EvidenceUnavailable = 1; Deferred = 2; Partial = 3 }
        [void]$sb.Append("<div class=""table""><table><thead><tr><th>#</th><th>Item</th><th>State</th><th>Rationale</th><th>Owner</th><th>Risk</th><th>Disposition</th><th>Target</th></tr></thead><tbody>`n")
        foreach ($x in @($regOpen | Sort-Object { $s = Get-Col $_ 'EvidenceState'; if ($stRank.ContainsKey($s)) { $stRank[$s] } else { 9 } }, { Get-Col $_ 'ItemId' })) {
            $tgt = Get-Col $x 'TargetDateUtc'; if ($tgt -match '^\d{4}-\d{2}-\d{2}') { $tgt = $tgt.Substring(0, 10) }
            $item = Get-Col $x 'Item'; $del = Get-Col $x 'Deliverable'; $gate = Get-Col $x 'Gate'
            $itemCell = "$(ConvertTo-HtmlText $item)" + $(if ($del -or $gate) { "<div class=""sub"">$(ConvertTo-HtmlText ((@($gate, $del) | Where-Object { $_ }) -join ' / '))</div>" } else { '' })
            [void]$sb.Append("<tr><td style=""white-space:nowrap"">$(ConvertTo-HtmlText (Get-Col $x 'ItemId'))</td><td class=""txt"">$itemCell</td><td>$(Get-Chip (Get-Col $x 'EvidenceState'))</td><td class=""txt"">$(ConvertTo-HtmlText (Get-Col $x 'Rationale'))</td><td>$(ConvertTo-HtmlText (Get-Col $x 'Owner'))</td><td class=""txt"">$(ConvertTo-HtmlText (Get-Col $x 'Risk'))</td><td>$(ConvertTo-HtmlText (Get-Col $x 'Disposition'))</td><td style=""white-space:nowrap"">$(ConvertTo-HtmlText $tgt)</td></tr>`n")
        }
        [void]$sb.Append("</tbody></table></div>`n")
    }
    [void]$sb.Append("</section>`n")

    [void]$sb.Append(@"
<footer>
Built by $ScriptName $ScriptVersion from run-manifest.json and dataset-status.csv of each run, the latest kpi-summary.csv, and the registers passed to it. It holds counts and statuses, not account names; it is still the organization's data, so share it only through approved channels.
</footer>
</div>
</body>
</html>
"@)
    Export-TextDataset -Name 'engagement-dashboard' -FileName 'engagement-dashboard.html' -Text $sb.ToString()

    # ---- summary.csv: the headline numbers ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Scripts run' $(if ($EvidenceRoot) { $ran.Count } else { '' }) -Note "of $($catalog.Count) in the catalog"
    foreach ($st in $script:Statuses) { Add-Metric "Datasets $st" $(if ($EvidenceRoot) { $dsTotals[$st] } else { '' }) -Note 'Latest run of each script' }
    Add-Metric 'KPIs meeting target' $(if ($kpi) { $kpiMet.Count } else { '' }) -Note $(if ($kpi) { "of $($kpiWithTarget.Count) with a value and target" } else { 'No KPI summary' })
    Add-Metric 'Readiness closed or waived' $(if ($ready) { $readyCounts['Closed'] + $readyCounts['Waived'] } else { '' }) -Note $(if ($ready) { "of $($ready.Rows.Count)" } else { 'Not provided' })
    Add-Metric 'Findings' $(if ($find) { $find.Rows.Count } else { '' }) -Note $(if (-not $find) { 'Not provided' } else { '' })
    foreach ($s in $stageOrder) { Add-Metric "Findings $s" $(if ($find) { $stageCounts[$s] } else { '' }) }
    Add-Metric 'Status register items not completed' $(if ($reg) { $regOpen.Count } else { '' }) -Note $(if ($reg) { "of $($reg.Rows.Count)" } else { 'Not provided' })
    Export-Dataset -Name 'summary' -Rows $summary
    $script:ManifestExtra = @{ Inputs = $inputs; KpiRun = $(if ($kpi) { $kpi.Run } else { '' }); KpiHashVerified = $(if ($kpi) { $kpi.HashOk } else { $null }) }
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Parameters @{ EvidenceRoot = $EvidenceRoot; ReadinessCsv = $ReadinessCsv; FindingsCsv = $FindingsCsv; StatusRegisterCsv = $StatusRegisterCsv; Title = $Title; StaleAfterDays = $StaleAfterDays }
    Write-RunLog ("Finished. Dashboard: {0}" -f (Join-Path $script:RunFolder 'engagement-dashboard.html'))
}
