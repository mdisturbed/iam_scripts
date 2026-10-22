<#
.SYNOPSIS
    Pick and run discovery scripts from one place, with the domain controller and evidence folder filled in.

.DESCRIPTION
    Shows every discovery script with whether it can run on this machine right now, lets you tick the ones
    to run, then runs them in order with -Server and -OutputRoot passed for you. Ends with one table of what
    ran, what each dataset returned, and where the output went.

    Readiness is checked before anything runs:
      AD        RSAT ActiveDirectory module present, and Get-ADDomain answers from -Server
      Graph     Microsoft.Graph.Authentication present (you sign in when the script runs)
      Exchange  ExchangeOnlineManagement present (sign-in at run time)
      Azure     Az.Accounts present (sign-in at run time)
      AWS       AWS.Tools.Common, .SecurityToken and .IdentityManagement present (credentials at run time)
      EventLog  needs Event Log Readers on the DCs; can't be checked without reading a log, so shown as a reminder
      InputFile the launcher asks for each required file (HR / IGA / role exports)

    Nothing new is read or written by the launcher itself: it only runs the read-only scripts in .\scripts and
    reads their dataset-status.csv afterwards. Each script still writes its own timestamped run folder.

    Works in Windows PowerShell 5.1 and PowerShell 7. Uses Out-GridView for the pick list when it is available
    (Windows), otherwise a numbered list in the console.

.PARAMETER Server
    Domain controller (or domain) for the AD scripts, e.g. DC1.contoso.local. Defaults to the value set with
    $PSDefaultParameterValues['*-AD*:Server'] if there is one.

.PARAMETER OutputRoot
    Evidence folder. Asked for if not given. Keep it outside the repository.

.PARAMETER Select
    Run these scripts without the pick list, e.g. -Select 05,04,07. Use -Select Ready to run every script whose
    status is Ready (needs no sign-in, no input files and has no caveat; 'Check first' scripts such as 18 and 19
    must be named explicitly).

.PARAMETER ScriptParameters
    Extra parameters per script, keyed by number:
      -ScriptParameters @{ '07' = @{ GroupingAttributes = 'department','title','extensionAttribute5' };
                           '08' = @{ SampleValueCount = 0 } }

.PARAMETER ListOnly
    Show the readiness table and stop.

.PARAMETER NoGridView
    Use the console list even where Out-GridView exists.

.PARAMETER Report
    Build the HTML report (New-DiscoveryReport.ps1) for the evidence folder when the runs finish.

.PARAMETER SkipAdCheck
    Don't test the DC before running (the AD scripts will report their own errors).

.EXAMPLE
    .\tools\Start-Discovery.ps1 -Server DC1.contoso.local -OutputRoot $env:USERPROFILE\IAM-Evidence
    Readiness check, pick list, run, summary.

.EXAMPLE
    .\tools\Start-Discovery.ps1 -Server DC1.contoso.local -OutputRoot $env:USERPROFILE\IAM-Evidence -Select 05,04,07,08 -Report
    Run four AD scripts unattended and build the HTML report.

.EXAMPLE
    .\tools\Start-Discovery.ps1 -ListOnly
    What can run on this machine right now?

.NOTES
    Version: 1.0.1
#>
[CmdletBinding()]
param(
    [string]$Server = '',
    [string]$OutputRoot = '',
    [string[]]$Select = @(),
    [hashtable]$ScriptParameters = @{},
    [switch]$ListOnly,
    [switch]$NoGridView,
    [switch]$Report,
    [switch]$SkipAdCheck
)

$ErrorActionPreference = 'Stop'
$LauncherVersion = '1.0.1'
$repoRoot   = Split-Path $PSScriptRoot -Parent
$scriptsDir = Join-Path $repoRoot 'scripts'
$catalog    = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'discovery-catalog.psd1')).Scripts

# ---------------------------------------------------------------- helpers
function Get-ScriptParameterInfo {
    # Reads a script's param block without running it: name, mandatory, type.
    param([string]$Path)
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    $result = @{}
    if (-not $ast.ParamBlock) { return $result }
    foreach ($p in $ast.ParamBlock.Parameters) {
        $mandatory = $false
        foreach ($a in $p.Attributes) {
            if ($a -is [System.Management.Automation.Language.AttributeAst] -and $a.TypeName.Name -eq 'Parameter') {
                foreach ($na in $a.NamedArguments) {
                    if ($na.ArgumentName -eq 'Mandatory') { $mandatory = ($na.ExpressionOmitted -or $na.Argument.Extent.Text -match '\$?true') }
                }
            }
        }
        $name = $p.Name.VariablePath.UserPath
        $result[$name] = [pscustomobject]@{ Name = $name; Mandatory = $mandatory; Type = $p.StaticType.Name }
    }
    return $result
}

function Test-ModulePresent {
    param([string[]]$Name)
    foreach ($n in $Name) { if (-not (Get-Module -ListAvailable -Name $n)) { return $false } }
    return $true
}

function Get-LastRunFolder {
    param([string]$Root, [string]$Number)
    if (-not $Root -or -not (Test-Path -LiteralPath $Root)) { return $null }
    Get-ChildItem -LiteralPath $Root -Directory -Filter "$Number-*" -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
        Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' } |
        Sort-Object Name | Select-Object -Last 1
}

function ConvertFrom-RunFolderName {
    param([string]$Name)
    [datetime]::ParseExact($Name, "yyyyMMdd-HHmmss'Z'", [Globalization.CultureInfo]::InvariantCulture,
        ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
}

function Get-DatasetCount {
    param([string]$RunFolder)
    $c = [ordered]@{ Completed = 0; Partial = 0; Blocked = 0; EvidenceUnavailable = 0; Deferred = 0 }
    $f = Join-Path $RunFolder 'dataset-status.csv'
    if (Test-Path -LiteralPath $f) {
        foreach ($r in (Import-Csv -LiteralPath $f)) {
            if ($r.Dataset -eq 'summary') { continue }
            if ($c.Contains($r.Status)) { $c[$r.Status]++ }
        }
    }
    return [pscustomobject]$c
}

# ---------------------------------------------------------------- defaults
if (-not $Server -and $PSDefaultParameterValues -and $PSDefaultParameterValues['*-AD*:Server']) {
    $Server = [string]$PSDefaultParameterValues['*-AD*:Server']
}
$interactive = ($Select.Count -eq 0)
# Accept -ScriptParameters keys as 7, '7' or '07'
$normalized = @{}
foreach ($k in $ScriptParameters.Keys) { $n = 0; if ([int]::TryParse([string]$k, [ref]$n)) { $normalized[$n.ToString('00')] = $ScriptParameters[$k] } else { $normalized[[string]$k] = $ScriptParameters[$k] } }
$ScriptParameters = $normalized

Write-Host ''
Write-Host "IAM discovery launcher $LauncherVersion" -ForegroundColor Cyan
Write-Host ("  Server     : {0}" -f $(if ($Server) { $Server } else { '(none - AD scripts use the default DC)' }))

if (-not $ListOnly -and -not $OutputRoot) {
    if (-not $interactive) { throw 'Give -OutputRoot when using -Select.' }
    $OutputRoot = Read-Host '  Evidence folder (e.g. C:\Users\you\IAM-Evidence)'
    if (-not $OutputRoot) { throw 'No evidence folder given.' }
}
if ($OutputRoot) {
    $OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
    Write-Host "  Evidence   : $OutputRoot"
    $repoFull = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\', '/')
    if ($OutputRoot.StartsWith($repoFull, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning 'The evidence folder is inside the repository. Keep evidence outside it (a reset or re-clone can delete it).'
    }
}

# ---------------------------------------------------------------- readiness
Write-Host ''
Write-Host 'Checking what this machine can run...' -ForegroundColor Cyan
$capability = @{}
if (-not (Test-ModulePresent 'ActiveDirectory')) {
    $capability['AD'] = @{ Ok = $false; Detail = 'RSAT ActiveDirectory module not installed' }
}
elseif ($SkipAdCheck) {
    $capability['AD'] = @{ Ok = $true; Detail = 'AD module present (DC not tested)' }
}
else {
    try {
        $adArgs = @{ ErrorAction = 'Stop' }
        if ($Server) { $adArgs['Server'] = $Server }
        $dom = Get-ADDomain @adArgs
        $capability['AD'] = @{ Ok = $true; Detail = "AD answers ($($dom.DNSRoot))" }
    }
    catch {
        $msg = $_.Exception.Message
        if (-not $Server -and $msg -match 'default server') { $msg = 'no default DC (Entra-joined device?) - give -Server' }
        $capability['AD'] = @{ Ok = $false; Detail = "AD not reachable: $msg" }
    }
}
Write-Host ("  AD check   : {0}" -f $capability['AD'].Detail)
$capability['Graph']     = @{ Ok = (Test-ModulePresent 'Microsoft.Graph.Authentication'); SignIn = $true; Missing = 'Microsoft.Graph.Authentication module not installed' }
$capability['Exchange']  = @{ Ok = (Test-ModulePresent 'ExchangeOnlineManagement');       SignIn = $true; Missing = 'ExchangeOnlineManagement module not installed' }
$capability['Azure']     = @{ Ok = (Test-ModulePresent 'Az.Accounts');                    SignIn = $true; Missing = 'Az.Accounts module not installed' }
$capability['AWS']       = @{ Ok = (Test-ModulePresent 'AWS.Tools.Common', 'AWS.Tools.SecurityToken', 'AWS.Tools.IdentityManagement'); SignIn = $true; Missing = 'AWS.Tools modules not installed' }
$capability['EventLog']  = @{ Ok = $true; Reminder = 'needs Event Log Readers on the DCs' }
$capability['InputFile'] = @{ Ok = $true; Reminder = 'asks for input files' }

$rows = foreach ($s in $catalog) {
    $file = Get-ChildItem -LiteralPath $scriptsDir -Filter "$($s.Number)-*.ps1" -ErrorAction SilentlyContinue | Select-Object -First 1
    $blockers = @(); $notes = @(); $signIn = @()
    if (-not $file) { $blockers += 'script file not found' }
    foreach ($n in $s.Needs) {
        $cap = $capability[$n]
        if (-not $cap.Ok) { $blockers += $(if ($cap.Detail) { $cap.Detail } else { $cap.Missing }) }
        elseif ($cap.SignIn) { $signIn += $n }
        elseif ($cap.Reminder) { $notes += $cap.Reminder }
    }
    $status = if ($blockers) { 'Blocked' }
              elseif ($s.Needs -contains 'InputFile') { 'Asks for files' }
              elseif ($signIn) { 'Sign-in' }
              elseif ($notes -or $s.Note) { 'Check first' }
              else { 'Ready' }
    $detail = @()
    if ($blockers) { $detail += $blockers }
    if ($signIn) { $detail += ('sign in at run time: ' + ($signIn -join ', ')) }
    if ($notes) { $detail += $notes }
    if ($s.Note) { $detail += $s.Note }
    $last = Get-LastRunFolder -Root $OutputRoot -Number $s.Number
    [pscustomobject]@{
        Number  = $s.Number
        Script  = $s.Title
        Area    = $s.Area
        Status  = $status
        LastRun = $(if ($last) { (ConvertFrom-RunFolderName $last.Name).ToString('yyyy-MM-dd HH:mm') + 'Z' } else { '' })
        Detail  = ($detail -join '; ')
        File    = $(if ($file) { $file.FullName } else { '' })
    }
}

$rows | Format-Table Number, Script, Area, Status, LastRun, Detail -AutoSize -Wrap | Out-String -Width 220 | Write-Host
if ($ListOnly) { return }

# ---------------------------------------------------------------- selection
$picked = @()
if (-not $interactive) {
    if ($Select.Count -eq 1 -and $Select[0] -eq 'Ready') {
        $picked = @($rows | Where-Object Status -eq 'Ready')
    }
    else {
        $wanted = @($Select | ForEach-Object { ($_ -split '[,\s]+') } | Where-Object { $_ } | ForEach-Object { ([int]$_).ToString('00') })
        foreach ($w in $wanted) {
            $r = $rows | Where-Object Number -eq $w
            if (-not $r) { Write-Warning "No script numbered $w - skipped." } else { $picked += $r }
        }
    }
}
elseif (-not $NoGridView -and (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
    Write-Host 'Tick the scripts to run in the window that opened, then click OK.' -ForegroundColor Cyan
    $picked = @($rows | Select-Object Number, Script, Area, Status, LastRun, Detail |
        Out-GridView -Title 'IAM discovery - select scripts to run (Ctrl+click for several)' -PassThru)
}
else {
    $answer = Read-Host 'Scripts to run (e.g. 05,04,07 - or "ready" for every Ready script - blank to quit)'
    if ($answer -match '^\s*ready\s*$') { $picked = @($rows | Where-Object Status -eq 'Ready') }
    elseif ($answer) {
        foreach ($w in ($answer -split '[,\s]+' | Where-Object { $_ })) {
            $n = $null
            if ([int]::TryParse($w, [ref]$n)) { $r = $rows | Where-Object Number -eq $n.ToString('00') } else { $r = $null }
            if (-not $r) { Write-Warning "No script numbered $w - skipped." } else { $picked += $r }
        }
    }
}
if (-not $picked) { Write-Host 'Nothing selected.'; return }

$picked = @($picked | ForEach-Object { $num = $_.Number; $rows | Where-Object Number -eq $num } | Sort-Object Number -Unique)
$blockedPicks = @($picked | Where-Object Status -eq 'Blocked')
foreach ($b in $blockedPicks) { Write-Warning ("{0} {1} is blocked ({2}) - skipped." -f $b.Number, $b.Script, $b.Detail) }
$picked = @($picked | Where-Object Status -ne 'Blocked')
if (-not $picked) { Write-Host 'Nothing left to run.'; return }

if (-not (Test-Path -LiteralPath $OutputRoot)) { New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null }

# ---------------------------------------------------------------- run
$results = [System.Collections.Generic.List[object]]::new()
foreach ($row in $picked) {
    $pinfo = Get-ScriptParameterInfo -Path $row.File
    $splat = @{}
    if ($pinfo.ContainsKey('OutputRoot')) { $splat['OutputRoot'] = $OutputRoot }
    if ($Server -and $pinfo.ContainsKey('Server')) { $splat['Server'] = $Server }

    $skipReason = ''
    if ($ScriptParameters.ContainsKey($row.Number)) {
        foreach ($k in $ScriptParameters[$row.Number].Keys) {
            if (-not $pinfo.ContainsKey($k)) { $skipReason = "unknown parameter -$k"; break }
            $splat[$k] = $ScriptParameters[$row.Number][$k]
        }
    }
    if (-not $skipReason) {
        foreach ($p in ($pinfo.Values | Where-Object Mandatory | Sort-Object Name)) {
            if ($splat.ContainsKey($p.Name)) { continue }
            if (-not $interactive) { $skipReason = "needs -$($p.Name) (pass it with -ScriptParameters)"; break }
            $v = Read-Host ("  {0} {1} needs -{2} (blank to skip this script)" -f $row.Number, $row.Script, $p.Name)
            if (-not $v) { $skipReason = "no -$($p.Name) given"; break }
            $v = $v.Trim('"', "'", ' ')
            if ($p.Name -match '(Csv|Path)$' -and -not (Test-Path -LiteralPath $v)) { $skipReason = "file not found for -$($p.Name)"; break }
            $splat[$p.Name] = $v
        }
    }
    if (-not $skipReason -and $row.Number -eq '18' -and $interactive) {
        $ok = Read-Host '  18 reads AD permissions and can look like reconnaissance. Has the SOC been told? (y/N)'
        if ($ok -notmatch '^(y|yes)$') { $skipReason = 'SOC not yet told' }
    }
    if ($skipReason) {
        Write-Warning ("{0} {1} skipped: {2}" -f $row.Number, $row.Script, $skipReason)
        $results.Add([pscustomobject]@{ Number = $row.Number; Script = $row.Script; Outcome = 'Skipped'; Datasets = ''; Minutes = ''; RunFolder = ''; Detail = $skipReason })
        continue
    }

    Write-Host ''
    Write-Host ("==== {0} {1} ====" -f $row.Number, $row.Script) -ForegroundColor Cyan
    $shown = ($splat.GetEnumerator() | Sort-Object Name | ForEach-Object { "-$($_.Name) $(@($_.Value) -join ',')" }) -join ' '
    Write-Host "  $(Split-Path $row.File -Leaf) $shown" -ForegroundColor DarkGray

    $start = [datetime]::UtcNow
    $runError = ''
    try { & $row.File @splat | Out-Host }
    catch { $runError = $_.Exception.Message }
    $minutes = [math]::Round(([datetime]::UtcNow - $start).TotalMinutes, 1)

    $run = Get-LastRunFolder -Root $OutputRoot -Number $row.Number
    if ($run -and (ConvertFrom-RunFolderName $run.Name) -lt $start.AddSeconds(-5)) { $run = $null }   # an older run, not this one

    $counts = $null; $datasets = ''
    if ($run) {
        $counts = Get-DatasetCount -RunFolder $run.FullName
        $datasets = ('{0} completed' -f $counts.Completed)
        if ($counts.Partial) { $datasets += ", $($counts.Partial) partial" }
        if ($counts.Blocked) { $datasets += ", $($counts.Blocked) blocked" }
        if ($counts.EvidenceUnavailable) { $datasets += ", $($counts.EvidenceUnavailable) unavailable" }
        if ($counts.Deferred) { $datasets += ", $($counts.Deferred) deferred" }
    }
    $outcome = if (-not $run) { 'Failed' }
               elseif ($runError) { 'Failed (partial output)' }
               elseif ($counts.Partial -or $counts.Blocked -or $counts.EvidenceUnavailable) { 'Partial' }
               else { 'Completed' }
    $results.Add([pscustomobject]@{
        Number    = $row.Number
        Script    = $row.Script
        Outcome   = $outcome
        Datasets  = $datasets
        Minutes   = $minutes
        RunFolder = $(if ($run) { $run.FullName } else { '' })
        Detail    = $runError
    })
}

# ---------------------------------------------------------------- summary
Write-Host ''
Write-Host 'Run summary' -ForegroundColor Cyan
$results | Format-Table Number, Script, Outcome, Datasets, Minutes, Detail -AutoSize -Wrap | Out-String -Width 220 | Write-Host
$withFolder = @($results | Where-Object RunFolder)
if ($withFolder) {
    Write-Host 'Run folders:'
    foreach ($r in $withFolder) { Write-Host "  $($r.Number)  $($r.RunFolder)" }
}
if (@($results | Where-Object Outcome -eq 'Partial')) {
    Write-Host ''
    Write-Host 'Partial = some datasets Partial, Blocked or EvidenceUnavailable; the reason is in that run''s dataset-status.csv.' -ForegroundColor Yellow
}

if ($Report) {
    Write-Host ''
    & (Join-Path $PSScriptRoot 'New-DiscoveryReport.ps1') -OutputRoot $OutputRoot
}
