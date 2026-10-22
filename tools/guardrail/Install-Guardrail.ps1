<#
.SYNOPSIS
    One-time setup on each machine that clones this repo. Turns on the guardrail hooks and creates your
    private denylist. Safe to re-run.
.EXAMPLE
    pwsh tools/guardrail/Install-Guardrail.ps1
#>
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent (Split-Path -Parent $here)
Push-Location $root
try {
    git config core.hooksPath .githooks
    if ($LASTEXITCODE -ne 0) { throw 'git config failed' }
    Write-Host 'Hooks on: pre-commit (staged files) and commit-msg (message) run the guardrail.' -ForegroundColor Green

    $deny    = Join-Path $here 'denylist.local.txt'
    $example = Join-Path $here 'denylist.example.txt'
    if (-not (Test-Path $deny)) {
        Copy-Item $example $deny
        Write-Host "Created $deny - add your org's names, hostnames, domains and people, one regex per line." -ForegroundColor Yellow
    } else {
        Write-Host "Private denylist already present: $deny"
    }

    $null = git check-ignore -q $deny; if ($LASTEXITCODE -ne 0) { throw 'denylist.local.txt is NOT ignored by git - fix .gitignore before continuing' }
    Write-Host 'Confirmed: the private denylist is gitignored.'

    & (Join-Path $here 'Invoke-Guardrail.ps1') -Mode All
}
finally { Pop-Location }
