<#
.SYNOPSIS
    Shared helpers for the engagement kit: resolve an engagement folder's paths, list its engagement actions,
    and work out the state of every catalog script. Dot-sourced by Start-Engagement.ps1 and
    Start-EngagementConsole.ps1; not run on its own.

.DESCRIPTION
    Get-EngagementPaths     folders of an engagement (evidence, registers, config, findings, reports), its name,
                            and where the evidence lives. config\engagement.psd1 may set EvidencePath to keep
                            run folders somewhere other than evidence\: '.' = the engagement folder itself,
                            a relative path = under the engagement folder, or an absolute path.
    Get-EngagementActions   the engagement's own buttons/menu entries from config\actions.psd1
    Expand-EngagementToken  fills {EngagementPath}, {Evidence}, {Registers}, {Config}, {Findings}, {Reports},
                            {Kit}, {Server} and %ENVVARS% in an action's arguments
    Get-ScriptStates        one row per catalog script: latest run, its worst dataset status, and any
                            status-register row for that script (Script column = two-digit number)

    Reads local files only. Version 1.0.0.
#>

function Get-EngagementPaths {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EngagementPath)
    $root = (Resolve-Path -LiteralPath $EngagementPath).Path
    $p = [ordered]@{
        Root       = $root
        Name       = (Split-Path $root -Leaf)
        Evidence   = (Join-Path $root 'evidence')
        Reports    = (Join-Path $root 'reports')
        Registers  = (Join-Path $root 'registers')
        Config     = (Join-Path $root 'config')
        Findings   = (Join-Path $root 'findings')
        Readme     = (Join-Path $root 'README.md')
        ConfigFile = (Join-Path (Join-Path $root 'config') 'engagement.psd1')
        Actions    = (Join-Path (Join-Path $root 'config') 'actions.psd1')
        IsEngagement = $false
        Settings   = @{}
    }
    if (Test-Path -LiteralPath $p.ConfigFile) {
        $p.IsEngagement = $true
        try { $p.Settings = Import-PowerShellDataFile -Path $p.ConfigFile } catch { Write-Warning "config\engagement.psd1 could not be read: $($_.Exception.Message)" }
        if ($p.Settings.Name) { $p.Name = [string]$p.Settings.Name }
        $ev = [string]$p.Settings.EvidencePath
        if ($ev) {
            $ev = [Environment]::ExpandEnvironmentVariables($ev)
            if ($ev -eq '.') { $p.Evidence = $root }
            elseif ([IO.Path]::IsPathRooted($ev)) { $p.Evidence = $ev }
            else { $p.Evidence = Join-Path $root $ev }
        }
    }
    [pscustomobject]$p
}

function Get-EngagementActions {
    # config\actions.psd1: @{ Actions = @( @{ Name; Description; Script; Arguments = @{...}; Switches = @('X') } ) }
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Paths)
    if (-not (Test-Path -LiteralPath $Paths.Actions)) { return @() }
    try { $d = Import-PowerShellDataFile -Path $Paths.Actions } catch { Write-Warning "config\actions.psd1 could not be read: $($_.Exception.Message)"; return @() }
    @($d.Actions | Where-Object { $_ -and $_.Name -and $_.Script })
}

function Expand-EngagementToken {
    [CmdletBinding()]
    param([string]$Text, [Parameter(Mandatory)]$Paths, [string]$Kit = '', [string]$Server = '')
    if ($null -eq $Text) { return $Text }
    $map = @{ EngagementPath = $Paths.Root; Evidence = $Paths.Evidence; Registers = $Paths.Registers; Config = $Paths.Config
        Findings = $Paths.Findings; Reports = $Paths.Reports; Kit = $Kit; Server = $Server }
    foreach ($k in $map.Keys) { $Text = $Text.Replace('{' + $k + '}', [string]$map[$k]) }
    [Environment]::ExpandEnvironmentVariables($Text)
}

function Get-ScriptStates {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Paths, [Parameter(Mandatory)][object[]]$Catalog)
    $rank = @{ Completed = 0; Partial = 1; Deferred = 2; EvidenceUnavailable = 3; Blocked = 4 }
    $reg = @{}
    $regFile = Join-Path $Paths.Registers 'status-register.csv'
    if (Test-Path -LiteralPath $regFile) {
        foreach ($r in @(Import-Csv -LiteralPath $regFile)) {
            $n = "$($r.Script)".Trim()
            if ($n -match '^\d{1,2}$') { $reg[$n.PadLeft(2, '0')] = $r }
        }
    }
    $now = (Get-Date).ToUniversalTime()
    foreach ($s in $Catalog) {
        $runs = @(Get-ChildItem -LiteralPath $Paths.Evidence -Directory -Filter "$($s.Number)-*" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch '_aborted' } |
                ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
                Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'run-manifest.json')) } |
                Sort-Object Name)
        $row = [ordered]@{ Number = [string]$s.Number; Title = [string]$s.Title; Area = [string]$s.Area; Needs = (@($s.Needs) -join ', ')
            LastRun = ''; AgeDays = ''; State = 'Not run'; Note = ''; RunFolder = '' }
        if ($runs.Count) {
            $latest = $runs[-1]
            $row.RunFolder = $latest.FullName
            $started = [datetime]::ParseExact($latest.Name, "yyyyMMdd-HHmmss'Z'", [Globalization.CultureInfo]::InvariantCulture,
                ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
            $row.LastRun = $started.ToString('yyyy-MM-dd HH:mm') + 'Z'
            $row.AgeDays = [string][math]::Floor(($now - $started).TotalDays)
            $worst = 'Completed'
            $statusFile = Join-Path $latest.FullName 'dataset-status.csv'
            if (Test-Path -LiteralPath $statusFile) {
                foreach ($d in @(Import-Csv -LiteralPath $statusFile)) {
                    if ($d.Dataset -eq 'summary') { continue }
                    $st = $(if ($rank.ContainsKey([string]$d.Status)) { [string]$d.Status } else { 'Partial' })
                    if ($rank[$st] -gt $rank[$worst]) { $worst = $st }
                }
            }
            $row.State = $worst
        }
        $r = $reg[[string]$s.Number]
        if ($r) {
            $label = "$($r.ItemId): $($r.Rationale)".Trim(': ')
            if (-not $runs.Count -and $r.EvidenceState) { $row.State = "$($r.EvidenceState) (register)" }
            $row.Note = $label
        }
        [pscustomobject]$row
    }
}
