<#
.SYNOPSIS
    Builds one self-contained HTML page summarising every discovery run in an evidence folder.

.DESCRIPTION
    Reads the latest run of each script under -OutputRoot (run-manifest.json, dataset-status.csv,
    summary.csv) and writes a single HTML file you open in a browser. No web server, no external files,
    nothing to install.

    The page shows:
      - headline tiles: scripts run, datasets completed / blocked / unavailable, scripts pilot-verified
      - a coverage table for all 22 scripts: last run, version, dataset status, pilot status, number of runs
      - per script: every summary metric with the change since the previous run, and every dataset's status
      - the scripts not run yet

    Counts only: the page is built from summary.csv and dataset-status.csv, never from the detail CSVs, so it
    holds numbers, not names. Run account, machine, domain and folder paths are left out unless you add
    -IncludeRunDetails. That makes it suitable to show a manager or CISO; it is still the client's data, so
    share it only in approved places.

    Pilot status comes from the sign-off table in docs/pilot-runbook.md.

    Reads the run folders only. Writes one file: -OutFile (default <OutputRoot>\discovery-report.html,
    overwritten each time).

.PARAMETER OutputRoot
    Evidence folder holding the NN-Name\yyyyMMdd-HHmmssZ run folders.

.PARAMETER OutFile
    Where to write the page. Default: <OutputRoot>\discovery-report.html

.PARAMETER Title
    Page heading. Default: IAM discovery report

.PARAMETER IncludeRunDetails
    Also show run account, machine, domain / server and the evidence path.

.EXAMPLE
    .\tools\New-DiscoveryReport.ps1 -OutputRoot $env:USERPROFILE\IAM-Evidence

.NOTES
    Version: 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputRoot,
    [string]$OutFile = '',
    [string]$Title = 'IAM discovery report',
    [switch]$IncludeRunDetails
)

$ErrorActionPreference = 'Stop'
$ReportVersion = '1.0.0'
$repoRoot = Split-Path $PSScriptRoot -Parent
$catalog  = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'discovery-catalog.psd1')).Scripts
$inv      = [Globalization.CultureInfo]::InvariantCulture

if (-not (Test-Path -LiteralPath $OutputRoot)) { throw "Evidence folder not found: $OutputRoot" }
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
if (-not $OutFile) { $OutFile = Join-Path $OutputRoot 'discovery-report.html' }

function ConvertTo-HtmlText { param($Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }

function Read-CsvSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    if ((Get-Item -LiteralPath $Path).Length -lt 4) { return @() }
    return @(Import-Csv -LiteralPath $Path)
}

function ConvertTo-Number {
    param([string]$Value)
    $d = 0.0
    if ([double]::TryParse($Value, [Globalization.NumberStyles]::Float, $inv, [ref]$d)) { return $d }
    return $null
}

function Format-Utc {
    param($Value)
    if (-not $Value) { return '' }
    try { return ([datetime]::Parse([string]$Value, $inv, [Globalization.DateTimeStyles]::AdjustToUniversal)).ToString('yyyy-MM-dd HH:mm') + 'Z' }
    catch { return [string]$Value }
}

# ---------------------------------------------------------------- pilot status from the runbook
$pilot = @{}
$runbook = Join-Path (Join-Path $repoRoot 'docs') 'pilot-runbook.md'
if (Test-Path -LiteralPath $runbook) {
    $inSignOff = $false
    foreach ($line in (Get-Content -LiteralPath $runbook)) {
        if ($line -match '^##\s+Sign-off') { $inSignOff = $true; continue }
        if ($inSignOff -and $line -match '^##\s') { break }
        if ($inSignOff -and $line -match '^\|\s*(\d\d)\s') {
            $cells = @($line.Trim().Trim('|') -split '\|' | ForEach-Object { $_.Trim() })
            $pilot[$Matches[1]] = [pscustomobject]@{ Date = $cells[2]; Status = $cells[-1] }
        }
    }
}

# ---------------------------------------------------------------- collect runs
$entries = foreach ($s in $catalog) {
    $runs = @(Get-ChildItem -LiteralPath $OutputRoot -Directory -Filter "$($s.Number)-*" -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
        Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'run-manifest.json')) } |
        Sort-Object Name)
    $latest = if ($runs.Count) { $runs[-1] } else { $null }
    $previous = if ($runs.Count -gt 1) { $runs[-2] } else { $null }
    $manifest = $null; $datasets = @(); $summary = @(); $prevSummary = @{}
    if ($latest) {
        $manifest = Get-Content -LiteralPath (Join-Path $latest.FullName 'run-manifest.json') -Raw | ConvertFrom-Json
        $datasets = @(Read-CsvSafe (Join-Path $latest.FullName 'dataset-status.csv') | Where-Object { $_.Dataset -ne 'summary' })
        $summary  = @(Read-CsvSafe (Join-Path $latest.FullName 'summary.csv'))
        if ($previous) { foreach ($m in (Read-CsvSafe (Join-Path $previous.FullName 'summary.csv'))) { $prevSummary[$m.Metric] = $m.Value } }
    }
    [pscustomobject]@{
        Number = $s.Number; Title = $s.Title; Area = $s.Area
        Runs = $runs.Count; Latest = $latest; Previous = $previous; Manifest = $manifest
        Datasets = $datasets; Summary = $summary; PrevSummary = $prevSummary
        Pilot = $pilot[$s.Number]
    }
}

$ran        = @($entries | Where-Object Latest)
$notRun     = @($entries | Where-Object { -not $_.Latest })
$allDs      = @($ran | ForEach-Object { $_.Datasets })
$nCompleted = @($allDs | Where-Object Status -eq 'Completed').Count
$nBlocked   = @($allDs | Where-Object Status -eq 'Blocked').Count
$nUnavail   = @($allDs | Where-Object Status -eq 'EvidenceUnavailable').Count
$nPilot     = @($entries | Where-Object { $_.Pilot -and $_.Pilot.Status -match 'Pilot-verified|Baseline' }).Count

function Get-StatusChip {
    param([string]$Status, [int]$Count = -1)
    $cls = switch ($Status) { 'Completed' { 'ok' } 'Blocked' { 'bad' } 'EvidenceUnavailable' { 'warn' } 'Deferred' { 'muted' } default { 'muted' } }
    $label = switch ($Status) { 'EvidenceUnavailable' { 'Unavailable' } default { $Status } }
    if ($Count -ge 0) { $label = "$Count $label" }
    return "<span class=""chip $cls"">$(ConvertTo-HtmlText $label)</span>"
}

function Get-PilotChip {
    param($Pilot)
    if (-not $Pilot -or -not $Pilot.Status) { return '<span class="chip muted">Not recorded</span>' }
    $cls = if ($Pilot.Status -match 'Pilot-verified|Baseline') { 'ok' } else { 'muted' }
    $txt = $Pilot.Status
    if ($Pilot.Date -and $cls -eq 'ok') { $txt += " · $($Pilot.Date)" }
    return "<span class=""chip $cls"">$(ConvertTo-HtmlText $txt)</span>"
}

# ---------------------------------------------------------------- HTML
$sb = [System.Text.StringBuilder]::new()
$generated = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm') + 'Z'
[void]$sb.Append(@"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(ConvertTo-HtmlText $Title)</title>
<style>
:root{--bg:#f6f7f9;--panel:#ffffff;--text:#1d2329;--muted:#5f6b76;--line:#dfe3e8;--accent:#2457c5;
--ok-bg:#e3f4e8;--ok-fg:#17643a;--warn-bg:#fdf1d8;--warn-fg:#8a5a00;--bad-bg:#fbe3e1;--bad-fg:#a12a1f;--muted-bg:#eceff2;--muted-fg:#4c5862;
--delta:#2457c5}
@media (prefers-color-scheme:dark){:root{--bg:#14181c;--panel:#1c2227;--text:#e6eaee;--muted:#9aa6b1;--line:#2e363d;--accent:#7aa2ff;
--ok-bg:#163a26;--ok-fg:#8fe0ad;--warn-bg:#3d2f10;--warn-fg:#f3c766;--bad-bg:#45201c;--bad-fg:#ffaa9f;--muted-bg:#2a3138;--muted-fg:#b7c1ca}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 48px}
header h1{margin:0 0 4px;font-size:24px;font-weight:650;letter-spacing:-.01em}
header p{margin:0;color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0 26px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile .n{font-size:26px;font-weight:650;font-variant-numeric:tabular-nums}
.tile .l{color:var(--muted);font-size:12.5px;margin-top:2px}
.tile.bad .n{color:var(--bad-fg)}.tile.warn .n{color:var(--warn-fg)}.tile.ok .n{color:var(--ok-fg)}
h2{font-size:17px;margin:30px 0 10px;font-weight:650}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;background:var(--panel)}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;margin:1px 4px 1px 0}
.chip.ok{background:var(--ok-bg);color:var(--ok-fg)}.chip.warn{background:var(--warn-bg);color:var(--warn-fg)}
.chip.bad{background:var(--bad-bg);color:var(--bad-fg)}.chip.muted{background:var(--muted-bg);color:var(--muted-fg)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
details.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:0 0 12px}
details.card>summary{cursor:pointer;list-style:none;padding:12px 16px;display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center}
details.card>summary::-webkit-details-marker{display:none}
details.card>summary .t{font-weight:650;font-size:15px;margin-right:auto}
details.card>summary .t::before{content:"\25B8";display:inline-block;width:1em;color:var(--muted);transition:transform .15s}
details.card[open]>summary .t::before{transform:rotate(90deg)}
details.card .meta{color:var(--muted);font-size:12.5px}
.body{padding:0 16px 14px;display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:16px}
@media (max-width:860px){.body{grid-template-columns:minmax(0,1fr)}}
.body h3{font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);margin:6px 0 6px;font-weight:600}
.body table{border:1px solid var(--line);border-radius:8px;overflow:hidden}
.note{color:var(--muted);font-size:12.5px}
.metrics td:first-child{min-width:13em}
.long{font:12px/1.4 ui-monospace,"Cascadia Mono",Consolas,monospace;word-break:break-all;max-width:22em}
td{overflow-wrap:break-word}
.delta{font-size:12px;white-space:nowrap;color:var(--accent);font-variant-numeric:tabular-nums}.delta.same{color:var(--muted)}
.area{margin-top:26px}
.notrun{color:var(--muted)}
footer{margin-top:34px;color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);padding-top:12px}
@media print{body{background:#fff}.wrap{max-width:none;padding:0}details.card>summary .t::before{display:none}.tile,.panel,details.card{break-inside:avoid}}
</style>
</head>
<body>
<div class="wrap">
<header>
<h1>$(ConvertTo-HtmlText $Title)</h1>
<p>Generated $generated &middot; latest run of each script &middot; counts only, detail stays in the run folders</p>
</header>
<section class="tiles">
<div class="tile"><div class="n">$($ran.Count)<span style="font-size:15px;color:var(--muted)"> / $($catalog.Count)</span></div><div class="l">Scripts run</div></div>
<div class="tile ok"><div class="n">$nCompleted</div><div class="l">Datasets completed</div></div>
<div class="tile $(if ($nBlocked) { 'bad' })"><div class="n">$nBlocked</div><div class="l">Datasets blocked (access)</div></div>
<div class="tile $(if ($nUnavail) { 'warn' })"><div class="n">$nUnavail</div><div class="l">Evidence unavailable (licence / tenant)</div></div>
<div class="tile"><div class="n">$nPilot<span style="font-size:15px;color:var(--muted)"> / $($catalog.Count)</span></div><div class="l">Pilot-verified</div></div>
</section>
"@)

if ($IncludeRunDetails) { [void]$sb.Append("<p class=""note"">Evidence folder: $(ConvertTo-HtmlText $OutputRoot)</p>`n") }

# coverage table
[void]$sb.Append(@"
<h2>Coverage</h2>
<div class="panel scroll"><table>
<thead><tr><th>#</th><th>Script</th><th>Area</th><th>Last run</th><th>Version</th><th>Datasets</th><th>Pilot</th><th class="num">Runs</th></tr></thead>
<tbody>
"@)
foreach ($e in $entries) {
    if ($e.Latest) {
        $groups = $e.Datasets | Group-Object Status
        $chips = (@('Completed', 'Blocked', 'EvidenceUnavailable', 'Deferred') | ForEach-Object {
                $st = $_; $g = $groups | Where-Object Name -eq $st
                if ($g) { Get-StatusChip -Status $st -Count $g.Count }
            }) -join ''
        $name = "<a href=""#s$($e.Number)"">$(ConvertTo-HtmlText $e.Title)</a>"
        [void]$sb.Append("<tr><td>$($e.Number)</td><td>$name</td><td>$(ConvertTo-HtmlText $e.Area)</td><td>$(ConvertTo-HtmlText (Format-Utc $e.Manifest.StartedUtc))</td><td>$(ConvertTo-HtmlText $e.Manifest.ScriptVersion)</td><td>$chips</td><td>$(Get-PilotChip $e.Pilot)</td><td class=""num"">$($e.Runs)</td></tr>`n")
    }
    else {
        [void]$sb.Append("<tr class=""notrun""><td>$($e.Number)</td><td>$(ConvertTo-HtmlText $e.Title)</td><td>$(ConvertTo-HtmlText $e.Area)</td><td>Not run</td><td></td><td></td><td>$(Get-PilotChip $e.Pilot)</td><td class=""num"">0</td></tr>`n")
    }
}
[void]$sb.Append("</tbody></table></div>`n")

# per-script detail, grouped by area in catalog order
$areas = @($catalog | ForEach-Object { $_.Area } | Select-Object -Unique)
foreach ($area in $areas) {
    $inArea = @($ran | Where-Object Area -eq $area)
    if (-not $inArea) { continue }
    [void]$sb.Append("<section class=""area""><h2>$(ConvertTo-HtmlText $area)</h2>`n")
    foreach ($e in $inArea) {
        $groups = $e.Datasets | Group-Object Status
        $chips = (@('Completed', 'Blocked', 'EvidenceUnavailable', 'Deferred') | ForEach-Object {
                $st = $_; $g = $groups | Where-Object Name -eq $st
                if ($g) { Get-StatusChip -Status $st -Count $g.Count }
            }) -join ''
        $meta = "v$(ConvertTo-HtmlText $e.Manifest.ScriptVersion) &middot; $(ConvertTo-HtmlText (Format-Utc $e.Manifest.StartedUtc))"
        if ($e.Previous) { $meta += " &middot; compared with $(ConvertTo-HtmlText ((Format-Utc ($e.Previous.Name -replace '^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})Z$', '$1-$2-$3T$4:$5:$6Z'))))" }
        [void]$sb.Append("<details class=""card"" id=""s$($e.Number)"" open><summary><span class=""t"">$($e.Number) &middot; $(ConvertTo-HtmlText $e.Title)</span>$chips<span class=""meta"">$meta</span></summary><div class=""body"">`n")

        # metrics
        [void]$sb.Append("<div><h3>Summary</h3><div class=""scroll""><table class=""metrics""><thead><tr><th>Metric</th><th class=""num"">Value</th><th class=""num"">Change</th></tr></thead><tbody>`n")
        if (-not $e.Summary) { [void]$sb.Append("<tr><td colspan=""3"" class=""note"">No summary.csv in this run.</td></tr>") }
        foreach ($m in $e.Summary) {
            $delta = ''
            if ($e.Previous -and $e.PrevSummary.ContainsKey($m.Metric)) {
                $now = ConvertTo-Number $m.Value; $was = ConvertTo-Number $e.PrevSummary[$m.Metric]
                if ($null -ne $now -and $null -ne $was) {
                    $d = $now - $was
                    $delta = if ($d -gt 0) { "<span class=""delta"">&#9650; +$($d.ToString('0.##', $inv))</span>" }
                             elseif ($d -lt 0) { "<span class=""delta"">&#9660; $($d.ToString('0.##', $inv))</span>" }
                             else { '<span class="delta same">no change</span>' }
                }
                elseif ($m.Value -ne $e.PrevSummary[$m.Metric]) { $delta = '<span class="delta same">changed</span>' }
            }
            $metricCell = ConvertTo-HtmlText $m.Metric
            if ($m.Note) { $metricCell += "<div class=""note"">$(ConvertTo-HtmlText $m.Note)</div>" }
            $valueClass = if ($null -ne (ConvertTo-Number $m.Value)) { 'num' } elseif (([string]$m.Value).Length -gt 20) { 'long' } else { '' }
            [void]$sb.Append("<tr><td>$metricCell</td><td class=""$valueClass"">$(ConvertTo-HtmlText $m.Value)</td><td class=""num"">$delta</td></tr>`n")
        }
        [void]$sb.Append("</tbody></table></div></div>`n")

        # datasets
        [void]$sb.Append("<div><h3>Datasets</h3><div class=""scroll""><table><thead><tr><th>Dataset</th><th>Status</th><th class=""num"">Rows</th></tr></thead><tbody>`n")
        foreach ($d in $e.Datasets) {
            $dsCell = ConvertTo-HtmlText $d.Dataset
            if ($d.Note) { $dsCell += "<div class=""note"">$(ConvertTo-HtmlText $d.Note)</div>" }
            [void]$sb.Append("<tr><td>$dsCell</td><td>$(Get-StatusChip -Status $d.Status)</td><td class=""num"">$(ConvertTo-HtmlText $d.Rows)</td></tr>`n")
        }
        [void]$sb.Append("</tbody></table></div>")
        if ($IncludeRunDetails -and $e.Manifest) {
            $who = @($e.Manifest.GraphAccount, $e.Manifest.RunAsWindows) | Where-Object { $_ } | Select-Object -First 1
            $where = @($e.Manifest.Server, $e.Manifest.Domain, $e.Manifest.TenantId) | Where-Object { $_ } | Select-Object -First 1
            [void]$sb.Append("<p class=""note"">Run by $(ConvertTo-HtmlText $who) on $(ConvertTo-HtmlText $e.Manifest.Machine)$(if ($where) { ' against ' + (ConvertTo-HtmlText $where) }) &middot; $(ConvertTo-HtmlText $e.Latest.FullName)</p>")
        }
        [void]$sb.Append("</div></div></details>`n")
    }
    [void]$sb.Append("</section>`n")
}

if ($notRun) {
    [void]$sb.Append("<h2>Not run yet</h2><div class=""panel scroll""><table><thead><tr><th>#</th><th>Script</th><th>Area</th></tr></thead><tbody>`n")
    foreach ($e in $notRun) { [void]$sb.Append("<tr><td>$($e.Number)</td><td>$(ConvertTo-HtmlText $e.Title)</td><td>$(ConvertTo-HtmlText $e.Area)</td></tr>`n") }
    [void]$sb.Append("</tbody></table></div>`n")
}

[void]$sb.Append(@"
<footer>
Blocked = the run account lacked access; Unavailable = the tenant can't produce it (often licensing); Deferred = skipped on purpose.
Change compares with the previous run of the same script (whether up or down is better depends on the metric).
Built by New-DiscoveryReport.ps1 $ReportVersion from summary.csv and dataset-status.csv only.
</footer>
</div>
</body>
</html>
"@)

Set-Content -LiteralPath $OutFile -Value $sb.ToString() -Encoding UTF8
Write-Host "Report written: $OutFile ($($ran.Count) of $($catalog.Count) scripts, $($allDs.Count) datasets)" -ForegroundColor Green
Write-Host 'Open it by double-clicking the file, or paste the path into Edge.'
