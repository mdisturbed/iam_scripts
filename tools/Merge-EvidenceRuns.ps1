<#
.SYNOPSIS
    Moves run folders that landed outside the evidence root back into <Target>\<Script>\<timestamp>.

.DESCRIPTION
    A run folder is any yyyyMMdd-HHmmssZ folder holding a run-manifest.json. Runs end up outside the
    evidence root when a script is started with the wrong -OutputRoot (for example one level up, next to
    config\ and inputs\). This tool finds them under -SearchRoots and moves each one to
    <Target>\<Script>\<timestamp>, taking the script name from the run's own manifest, so it works
    however the folders were nested.

    A run that sits anywhere under a folder whose name starts with '_' (for example _aborted or
    _superseded) keeps that marker: it goes to <Target>\<Script>\_aborted\<timestamp>, so a run set
    aside stays set aside and is never picked up as the latest run.

    Preview by default; nothing moves without -Go. A destination that already exists is skipped and
    reported. Moving does not change the files, so SHA-256 checks against dataset-status.csv still pass.
    Folders that are not run folders (config, inputs, registers, reports...) are not touched. Empty
    folders left behind are listed, not deleted.

    Local only. Connects to nothing.

.PARAMETER Target
    The evidence root that should hold every run. Default: $HOME\IAM-Evidence\evidence

.PARAMETER SearchRoots
    Where to look for stray runs. Default: $HOME\IAM-Evidence and $HOME\Tools. Runs already under
    -Target are ignored.

.PARAMETER Go
    Move. Without it, only a preview is shown.

.EXAMPLE
    .\tools\Merge-EvidenceRuns.ps1
.EXAMPLE
    .\tools\Merge-EvidenceRuns.ps1 -Go
.EXAMPLE
    .\tools\Merge-EvidenceRuns.ps1 -Target D:\Engagement\evidence -SearchRoots D:\Engagement, D:\Tools -Go

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x
#>
[CmdletBinding()]
param(
    [string]$Target = (Join-Path $HOME 'IAM-Evidence\evidence'),
    [string[]]$SearchRoots = @((Join-Path $HOME 'IAM-Evidence'), (Join-Path $HOME 'Tools')),
    [switch]$Go
)

$ErrorActionPreference = 'Stop'
$sep = [IO.Path]::DirectorySeparatorChar
$Target = [IO.Path]::GetFullPath($Target).TrimEnd($sep)
if (-not (Test-Path $Target)) { throw "Target not found: $Target" }

$runs = @(Get-ChildItem -Path $SearchRoots -Recurse -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' -and
                   (Test-Path (Join-Path $_.FullName 'run-manifest.json')) -and
                   -not $_.FullName.StartsWith("$Target$sep", [StringComparison]::OrdinalIgnoreCase) })

$moved = 0; $skipped = 0; $leftParents = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($run in $runs) {
    $script = $null
    try { $script = (Get-Content (Join-Path $run.FullName 'run-manifest.json') -Raw | ConvertFrom-Json).Script } catch { $script = $null }
    if (-not $script) { Write-Host "NO SCRIPT NAME, left alone: $($run.FullName)" -ForegroundColor Yellow; $skipped++; continue }

    # A '_' folder anywhere above the run (below the search root) marks it as set aside.
    $root = @($SearchRoots | Where-Object { $run.FullName.StartsWith(([IO.Path]::GetFullPath($_).TrimEnd($sep) + $sep), [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)[0]
    $rel = $(if ($root) { $run.FullName.Substring(([IO.Path]::GetFullPath($root).TrimEnd($sep)).Length) } else { $run.FullName })
    $marker = @($rel.Split([char[]]@('\', '/'), [StringSplitOptions]::RemoveEmptyEntries) | Where-Object { $_ -like '_*' } | Select-Object -First 1)[0]

    $destParent = $(if ($marker) { Join-Path (Join-Path $Target $script) $marker } else { Join-Path $Target $script })
    $dest = Join-Path $destParent $run.Name
    if (Test-Path $dest) { Write-Host "SKIP (already there): $($run.FullName)" -ForegroundColor Yellow; $skipped++; continue }

    Write-Host ('{0}  {1}  ->  {2}' -f $(if ($Go) { 'MOVED  ' } else { 'PREVIEW' }), $run.FullName, $dest)
    if ($Go) {
        New-Item -ItemType Directory -Path $destParent -Force | Out-Null
        Move-Item -LiteralPath $run.FullName -Destination $dest
        [void]$leftParents.Add($run.Parent.FullName)
        $moved++
    }
}

Write-Host ''
if ($Go) { Write-Host "$moved run folder(s) moved, $skipped skipped. Target: $Target" -ForegroundColor Cyan }
else { Write-Host "$($runs.Count) run folder(s) outside $Target ($skipped would be skipped). Preview only: add -Go to move." -ForegroundColor Cyan }

$empty = @($leftParents | Where-Object { (Test-Path $_) -and -not (Get-ChildItem -LiteralPath $_ -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1) })
if ($empty.Count) {
    Write-Host 'Now empty (safe to delete by hand):' -ForegroundColor Cyan
    $empty | Sort-Object | ForEach-Object { Write-Host "  $_" }
}
