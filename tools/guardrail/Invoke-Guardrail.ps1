<#
.SYNOPSIS
    Blocks identifying information and secrets from entering this repo.

.DESCRIPTION
    Scans files (and commit messages) against tools/guardrail/rules.psd1 plus an optional private denylist.
    Exit code 0 = clean, 1 = findings, 2 = guardrail could not run (treated as a failure: fail closed).

    Modes
      Staged  - what is about to be committed (reads the staged blob, not the working copy). Used by pre-commit.
      All     - every tracked file plus every commit message in history. Used by CI.
      Files   - the paths given with -Path, read from disk. Used by commit-msg and by Test-Guardrail.ps1.

    Private denylist (org names, hostnames, people, agency names) - never committed:
      tools/guardrail/denylist.local.txt   one .NET regex per line, case-insensitive, # for comments
      $env:GUARDRAIL_DENYLIST              same format, newline separated (CI: repo secret of the same name)

    False positive: add  guardrail:allow  and a reason on the same line, e.g.
      $version = '10.0.17763.1'   # guardrail:allow OS build number, not an IP
    Every allow is visible in review; do not use it to keep a real value.

    Findings are printed masked so CI logs do not leak the value they caught.

.EXAMPLE
    pwsh tools/guardrail/Invoke-Guardrail.ps1 -Mode All
#>
[CmdletBinding()]
param(
    [ValidateSet('Staged', 'All', 'Files')]
    [string]$Mode = 'Staged',
    [string[]]$Path = @()
)

$ErrorActionPreference = 'Stop'

function Get-Masked([string]$value) {
    if ($value.Length -le 4) { return '****' }
    return $value.Substring(0, 3) + ('*' * [Math]::Min(12, $value.Length - 3))
}

try {
    $here     = Split-Path -Parent $MyInvocation.MyCommand.Path
    $repoRoot = Split-Path -Parent (Split-Path -Parent $here)
    $config   = Import-PowerShellDataFile (Join-Path $here 'rules.psd1')

    # ---- rules, compiled once ----
    $rules = foreach ($r in $config.Rules) {
        [pscustomobject]@{
            Id          = $r.Id
            Description = $r.Description
            Regex       = [regex]::new($r.Pattern)
            Allow       = if ($r.Allow) { [regex]::new($r.Allow) } else { $null }
        }
    }

    # ---- Microsoft-published IDs that are identical in every tenant ----
    $knownIds = @{}
    $knownFile = Join-Path $here 'known-public-ids.txt'
    if (Test-Path $knownFile) {
        foreach ($l in Get-Content $knownFile) { if ($l -match '^\s*([0-9a-fA-F-]{36})\b') { $knownIds[$Matches[1].ToLower()] = $true } }
    }

    # ---- private denylist: local file + CI secret ----
    $denyLines = @()
    $localDeny = Join-Path $here 'denylist.local.txt'
    if (Test-Path $localDeny) { $denyLines += Get-Content $localDeny }
    if ($env:GUARDRAIL_DENYLIST) { $denyLines += ($env:GUARDRAIL_DENYLIST -split "`r?`n") }
    $denyCount = 0
    foreach ($line in $denyLines) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $denyCount++
        $rules += [pscustomobject]@{
            Id = "denylist-$denyCount"; Description = 'Private denylist entry (term not shown)'
            Regex = [regex]::new($t, 'IgnoreCase'); Allow = $null
        }
    }

    # ---- what to scan: list of @{ Name; Text } (Text = $null means read failed / binary) ----
    Push-Location $repoRoot
    $items = [System.Collections.Generic.List[object]]::new()

    function Add-GitBlob([string]$name, [string]$spec) {
        $raw = & git show $spec 2>$null | Out-String
        if ($LASTEXITCODE -ne 0) { throw "git show $spec failed" }
        $items.Add([pscustomobject]@{ Name = $name; Text = $raw; Bytes = [Text.Encoding]::UTF8.GetByteCount($raw) })
    }

    switch ($Mode) {
        'Staged' {
            $names = & git diff --cached --name-only --diff-filter=ACMR
            if ($LASTEXITCODE -ne 0) { throw 'git diff --cached failed' }
            foreach ($n in $names) { if ($n) { Add-GitBlob $n ":$n" } }
        }
        'All' {
            $names = & git ls-files
            if ($LASTEXITCODE -ne 0) { throw 'git ls-files failed' }
            foreach ($n in $names) {
                if ($n -and (Test-Path -LiteralPath $n)) {
                    $items.Add([pscustomobject]@{ Name = $n; Text = [IO.File]::ReadAllText((Join-Path $repoRoot $n)); Bytes = ([IO.FileInfo](Join-Path $repoRoot $n)).Length })
                }
            }
            $hasCommits = (& git rev-parse --verify --quiet HEAD) -ne $null
            if ($hasCommits) {
                $log = & git log --format='%H%n%an <%ae>%n%B%n----END----'
                $chunk = @(); $sha = $null
                foreach ($l in $log) {
                    if ($null -eq $sha) { $sha = $l; continue }
                    if ($l -eq '----END----') {
                        # author line is checked too: a work email in an author field is identifying
                        $items.Add([pscustomobject]@{ Name = "commit $($sha.Substring(0,8)) (message/author)"; Text = ($chunk -join "`n"); Bytes = 0 })
                        $chunk = @(); $sha = $null; continue
                    }
                    $chunk += $l
                }
            }
        }
        'Files' {
            foreach ($p in $Path) {
                $full = (Resolve-Path -LiteralPath $p).Path
                $items.Add([pscustomobject]@{ Name = $p; Text = [IO.File]::ReadAllText($full); Bytes = ([IO.FileInfo]$full).Length })
            }
        }
    }
    Pop-Location

    # ---- scan ----
    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $items) {
        $isCommit = $item.Name -like 'commit *'
        if (-not $isCommit) {
            $ext = [IO.Path]::GetExtension($item.Name).ToLower()
            $nameAllowed = @($config.AllowedNamePatterns | Where-Object { ($item.Name -replace '\\', '/') -match $_ }).Count -gt 0
            if (-not $nameAllowed -and $config.BlockedExtensions -contains $ext) {
                $findings.Add([pscustomobject]@{ File = $item.Name; Line = 0; Rule = 'blocked-file-type'; Value = "$ext files are data or keys, not scripts" }); continue
            }
            foreach ($np in $config.BlockedNamePatterns) {
                if ($item.Name -match $np) { $findings.Add([pscustomobject]@{ File = $item.Name; Line = 0; Rule = 'blocked-file-name'; Value = "name matches $np" }) }
            }
            if ($item.Bytes -gt $config.MaxFileBytes) {
                $findings.Add([pscustomobject]@{ File = $item.Name; Line = 0; Rule = 'file-too-large'; Value = "$($item.Bytes) bytes; scripts are small, this looks like data" }); continue
            }
            if ($item.Text -match "`0") {
                $findings.Add([pscustomobject]@{ File = $item.Name; Line = 0; Rule = 'binary-file'; Value = 'binary content cannot be checked' }); continue
            }
        }
        $lines = $item.Text -split "`r?`n"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -match 'guardrail:allow\s+\S') { continue }
            foreach ($rule in $rules) {
                foreach ($m in $rule.Regex.Matches($line)) {
                    if ($rule.Allow -and $rule.Allow.IsMatch($m.Value)) { continue }
                    if ($rule.Id -eq 'id-guid' -and $knownIds.ContainsKey($m.Value.ToLower())) { continue }
                    $shown = if ($rule.Id -like 'denylist-*') { '(hidden)' } else { Get-Masked $m.Value }
                    $findings.Add([pscustomobject]@{ File = $item.Name; Line = $i + 1; Rule = $rule.Id; Value = $shown })
                }
            }
        }
    }

    # ---- report ----
    $scope = "$($items.Count) item(s), $($rules.Count) rule(s) incl. $denyCount private denylist entr$(if ($denyCount -eq 1) {'y'} else {'ies'})"
    if ($findings.Count -eq 0) {
        Write-Host "guardrail: clean ($Mode mode, $scope)" -ForegroundColor Green
        exit 0
    }
    Write-Host "guardrail: BLOCKED - $($findings.Count) finding(s) ($Mode mode, $scope)" -ForegroundColor Red
    foreach ($f in $findings) {
        $where = if ($f.Line) { "$($f.File):$($f.Line)" } else { $f.File }
        Write-Host ("  {0,-34} {1,-28} {2}" -f $where, $f.Rule, $f.Value)
    }
    Write-Host ''
    Write-Host 'Fix: replace the value with a placeholder (see README > Placeholders) or move it into a settings file'
    Write-Host 'that is not committed (*.local.psd1). Real false positive: add "guardrail:allow <reason>" to that line.'
    if ($denyCount -eq 0) { Write-Host 'Note: no private denylist loaded (tools/guardrail/denylist.local.txt or GUARDRAIL_DENYLIST).' -ForegroundColor Yellow }
    exit 1
}
catch {
    Write-Host "guardrail: could not run - $($_.Exception.Message). Refusing (fail closed)." -ForegroundColor Red
    exit 2
}
