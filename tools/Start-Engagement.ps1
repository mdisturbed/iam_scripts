<#
.SYNOPSIS
    A simple console menu for one engagement folder: access request, readiness, discovery runs, evidence
    package, KPIs, draft findings and the dashboard, each with the folder's paths filled in.

.DESCRIPTION
    Runs the kit's tools against an engagement folder made by New-Engagement.ps1. It only calls the other
    tools with the right paths; it reads and writes nothing itself apart from showing the README.

      1  Access request     New-AccessRequest      -OutputRoot <path>\reports
      2  Readiness check    Start-Discovery        -ListOnly -Server <dc>   (what this machine can run)
      3  Run discovery      Start-Discovery        -Server <dc> -OutputRoot <path>\evidence   (pick list)
      4  Evidence package   New-EvidencePackage    -EvidenceRoot <path>\evidence -DeliverableMapPath <path>\config\deliverable-map.psd1
      5  KPI summary        Get-KpiSummary         -EvidenceRoot <path>\evidence -KpiDefinitionPath <path>\config\kpi-definitions.psd1
      6  Dashboard          New-EngagementDashboard with <path>\evidence, registers\readiness-checklist.csv,
                            registers\status-register.csv and findings\findings-review.csv (when present)
      7  Show README        the engagement README, in the console
      8  Draft findings     New-FindingDrafts      -EvidenceRoot <path>\evidence -LedgerPath <path>\findings\finding-ledger.csv
                            (config\finding-rules.psd1 when present, otherwise the repository's examples; IDs already in
                            findings\findings-review.csv are never reused)
      D  Set the domain controller for this session
      Q  Quit

    The domain controller is asked for once and kept in a session variable ($global:IamEngagementServer), so
    it is remembered when the menu is opened again in the same PowerShell window.

    Works in Windows PowerShell 5.1 and PowerShell 7, console only.

.PARAMETER EngagementPath
    The engagement folder (made by New-Engagement.ps1).

.PARAMETER Server
    Domain controller (or domain) for the AD scripts, e.g. DC1.contoso.local. Default: the session value.

.PARAMETER AuthMode
    Sign-in mode for the access request (option 1). Default: Delegated.

.PARAMETER Option
    Run these menu options in order and exit, without showing the menu, e.g. -Option 1,8,6.

.EXAMPLE
    .\tools\Start-Engagement.ps1 -EngagementPath D:\Engagements\Programme1 -Server DC1.contoso.local
.EXAMPLE
    .\tools\Start-Engagement.ps1 -EngagementPath D:\Engagements\Programme1 -Option 5,8,6
    Refresh the KPIs, draft findings and rebuild the dashboard, unattended.

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x.
    Scopes  : none itself; each tool documents its own.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EngagementPath,
    [string]$Server = '',
    [ValidateSet('Delegated', 'AppCertificate')][string]$AuthMode = 'Delegated',
    [string[]]$Option = @()
)

$ErrorActionPreference = 'Stop'
$MenuVersion = '1.0.0'

if (-not (Test-Path -LiteralPath $EngagementPath -PathType Container)) { throw "Engagement folder not found: $EngagementPath. Create one with tools\New-Engagement.ps1." }
$EngagementPath = (Resolve-Path -LiteralPath $EngagementPath).Path
$paths = @{
    Evidence   = Join-Path $EngagementPath 'evidence'
    Reports    = Join-Path $EngagementPath 'reports'
    Registers  = Join-Path $EngagementPath 'registers'
    Config     = Join-Path $EngagementPath 'config'
    Findings   = Join-Path $EngagementPath 'findings'
    Readme     = Join-Path $EngagementPath 'README.md'
}
foreach ($k in 'Evidence', 'Reports', 'Registers', 'Config', 'Findings') {
    if (-not (Test-Path -LiteralPath $paths[$k])) { throw "Not an engagement folder: $($paths[$k]) is missing. Run tools\New-Engagement.ps1 -Path '$EngagementPath' -Name <name> -Force to add it." }
}
$name = Split-Path $EngagementPath -Leaf
$engFile = Join-Path $paths.Config 'engagement.psd1'
if (Test-Path -LiteralPath $engFile) { try { $e = Import-PowerShellDataFile -Path $engFile; if ($e.Name) { $name = [string]$e.Name } } catch { Write-Warning "config\engagement.psd1 could not be read: $($_.Exception.Message)" } }

if ($Server) { $global:IamEngagementServer = $Server }
elseif (-not $global:IamEngagementServer -and $PSDefaultParameterValues -and $PSDefaultParameterValues['*-AD*:Server']) { $global:IamEngagementServer = [string]$PSDefaultParameterValues['*-AD*:Server'] }

function Get-Server {
    # The session's domain controller; asked for once when interactive.
    param([switch]$Ask)
    if ($global:IamEngagementServer -and -not $Ask) { return $global:IamEngagementServer }
    if ($script:Unattended) { return '' }
    $v = Read-Host '  Domain controller FQDN for the AD scripts (blank = none)'
    if ($v) { $global:IamEngagementServer = $v.Trim() }
    return $global:IamEngagementServer
}

function Invoke-Tool {
    # Runs one kit tool with a splat; a failure is shown and the menu carries on.
    param([string]$Tool, [hashtable]$Arguments)
    $path = Join-Path $PSScriptRoot $Tool
    $shown = ($Arguments.GetEnumerator() | Sort-Object Name | ForEach-Object { if ($_.Value -is [switch] -or $_.Value -is [bool]) { "-$($_.Name)" } else { "-$($_.Name) '$($_.Value)'" } }) -join ' '
    Write-Host ''
    Write-Host "> $Tool $shown" -ForegroundColor DarkGray
    try { & $path @Arguments | Out-Host; return $true }
    catch { Write-Host "  $Tool failed: $($_.Exception.Message)" -ForegroundColor Red; return $false }
}

function Invoke-MenuOption {
    param([string]$Choice)
    switch ($Choice.Trim().ToUpperInvariant()) {
        '1' { [void](Invoke-Tool 'New-AccessRequest.ps1' @{ AuthMode = $AuthMode; OutputRoot = $paths.Reports }) }
        '2' {
            $a = @{ ListOnly = [switch]$true; OutputRoot = $paths.Evidence }
            $dc = Get-Server; if ($dc) { $a['Server'] = $dc }
            [void](Invoke-Tool 'Start-Discovery.ps1' $a)
            Write-Host "  Readiness register: $(Join-Path $paths.Registers 'readiness-checklist.csv')" -ForegroundColor Cyan
        }
        '3' {
            if ($script:Unattended) { Write-Host '  Option 3 needs the pick list: run it from the menu, or use Start-Discovery.ps1 -Select.' -ForegroundColor Yellow; return }
            $a = @{ OutputRoot = $paths.Evidence }
            $dc = Get-Server; if ($dc) { $a['Server'] = $dc }
            Write-Host "  Input files (HR, IGA, PAM, role files, pilot test cases) are in $($paths.Registers)" -ForegroundColor Cyan
            [void](Invoke-Tool 'Start-Discovery.ps1' $a)
        }
        '4' { [void](Invoke-Tool 'New-EvidencePackage.ps1' @{ EvidenceRoot = $paths.Evidence; DeliverableMapPath = (Join-Path $paths.Config 'deliverable-map.psd1') }) }
        '5' { [void](Invoke-Tool 'Get-KpiSummary.ps1' @{ EvidenceRoot = $paths.Evidence; KpiDefinitionPath = (Join-Path $paths.Config 'kpi-definitions.psd1') }) }
        '6' {
            $a = @{ EvidenceRoot = $paths.Evidence; OutputRoot = $paths.Reports; Title = "$name dashboard" }
            $ready = Join-Path $paths.Registers 'readiness-checklist.csv'; if (Test-Path -LiteralPath $ready) { $a['ReadinessCsv'] = $ready }
            $status = Join-Path $paths.Registers 'status-register.csv'; if (Test-Path -LiteralPath $status) { $a['StatusRegisterCsv'] = $status }
            $find = Join-Path $paths.Findings 'findings-review.csv'
            if (Test-Path -LiteralPath $find) { $a['FindingsCsv'] = $find }
            else { Write-Host "  No findings\findings-review.csv yet: export the workbook's Review Trail sheet to that file to add findings." -ForegroundColor Yellow }
            [void](Invoke-Tool 'New-EngagementDashboard.ps1' $a)
        }
        '8' {
            $a = @{ EvidenceRoot = $paths.Evidence; LedgerPath = (Join-Path $paths.Findings 'finding-ledger.csv'); OutputRoot = $paths.Reports }
            $rules = Join-Path $paths.Config 'finding-rules.psd1'; if (Test-Path -LiteralPath $rules) { $a['RulesPath'] = $rules }
            $trail = Join-Path $paths.Findings 'findings-review.csv'; if (Test-Path -LiteralPath $trail) { $a['ReviewTrailCsv'] = $trail }
            if (Invoke-Tool 'New-FindingDrafts.ps1' $a) { Write-Host "  Paste the rows of finding-drafts.csv (in reports\New-FindingDrafts\<latest>) into the first empty row of the Review Trail sheet." -ForegroundColor Cyan }
        }
        '7' {
            if (Test-Path -LiteralPath $paths.Readme) { Write-Host ''; Get-Content -LiteralPath $paths.Readme | Out-Host }
            else { Write-Host '  No README.md in the engagement folder.' -ForegroundColor Yellow }
        }
        'D' { [void](Get-Server -Ask); Write-Host "  Domain controller: $(if ($global:IamEngagementServer) { $global:IamEngagementServer } else { '(none)' })" }
        'Q' { $script:Quit = $true }
        '' { }
        default { Write-Host "  '$Choice' is not an option." -ForegroundColor Yellow }
    }
}

$script:Quit = $false
$script:Unattended = [bool]$Option.Count
if ($script:Unattended) {
    foreach ($o in @($Option | ForEach-Object { "$_" -split '[,\s]+' } | Where-Object { $_ })) { Invoke-MenuOption $o; if ($script:Quit) { break } }
    return
}

while (-not $script:Quit) {
    Write-Host ''
    Write-Host "Engagement: $name  (Start-Engagement $MenuVersion)" -ForegroundColor Cyan
    Write-Host "  Folder : $EngagementPath"
    Write-Host "  DC     : $(if ($global:IamEngagementServer) { $global:IamEngagementServer } else { '(not set - D to set)' })"
    Write-Host ''
    Write-Host '  1  Access request          roles, permissions, inputs and licences for the client'
    Write-Host '  2  Readiness check         what this machine can run (Start-Discovery -ListOnly)'
    Write-Host '  3  Run discovery scripts   pick list, runs into evidence\'
    Write-Host '  4  Evidence package        intake log, hash re-check, per-deliverable status'
    Write-Host '  5  KPI summary             KPIs over the script 27 denominators'
    Write-Host '  6  Dashboard               one page: runs, KPIs, readiness, findings, open items'
    Write-Host '  7  Show README             run order and commands for this folder'
    Write-Host '  8  Draft findings          new findings from the latest runs, for the review workbook'
    Write-Host '  D  Set domain controller   Q  Quit'
    $choice = Read-Host 'Choose'
    if ($null -eq $choice) { break }   # end of input
    Invoke-MenuOption $choice
}
