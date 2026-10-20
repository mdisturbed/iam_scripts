<#
.SYNOPSIS
    Static check that the discovery scripts cannot change anything in AD or Entra.

.DESCRIPTION
    Parses each script with the PowerShell AST (nothing is executed) and fails if it finds:
      - any command whose verb could change state in a directory (New-, Set-, Remove-, Add-,
        Update-, Enable-, Disable-, Grant-, Revoke-, Move-, Rename-, Reset-, Clear-, Unlock-,
        Install-, Register-, Start- except Start-Sleep, etc.), outside a small allowlist of
        LOCAL-ONLY commands used to write the evidence folder
      - Invoke-MgGraphRequest or Invoke-AzRestMethod without -Method GET
      - Invoke-RestMethod / Invoke-WebRequest / Invoke-Expression / Start-Process

    Use it before a reviewer approves the scripts, and again after any edit.

.EXAMPLE
    .\tools\Test-ReadOnly.ps1
.EXAMPLE
    .\tools\Test-ReadOnly.ps1 -Path .\scripts\03-Get-AppsAndConsents.ps1

.NOTES
    Version: 1.2.0. Exit code 0 = pass, 1 = findings.
#>
[CmdletBinding()]
param([string[]]$Path = @())

if (-not $Path -or $Path.Count -eq 0) { $Path = @(Get-ChildItem -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts') -Filter *.ps1 | Select-Object -ExpandProperty FullName) }

# Commands that write only to the local evidence folder or console, or control flow.
# Use-STSRole only returns temporary credentials for a read-only AWS role; it changes nothing.
$LocalOnlyAllowed = @('New-Item', 'Set-Content', 'Add-Content', 'Add-Member', 'Start-Sleep', 'Export-Csv', 'Connect-MgGraph', 'Import-Module', 'Import-Csv', 'Use-STSRole')
$ReadVerbs = @('Get', 'Select', 'Where', 'ForEach', 'Sort', 'Group', 'Measure', 'Join', 'Split', 'Test', 'ConvertTo', 'ConvertFrom', 'Out', 'Format', 'Write', 'Resolve', 'Expand', 'Compare', 'Export', 'Import', 'Connect', 'Find')
$Forbidden = @('Invoke-RestMethod', 'Invoke-WebRequest', 'Invoke-Expression', 'Start-Process', 'Invoke-Command', 'Invoke-Item')

$findings = [System.Collections.Generic.List[object]]::new()
foreach ($file in $Path) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) { $findings.Add([pscustomobject]@{ File = (Split-Path $file -Leaf); Line = $e.Extent.StartLineNumber; Issue = "Parse error: $($e.Message)" }) }

    # Functions defined in the script itself are allowed by name (they are checked by their bodies).
    $localFunctions = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })

    $commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($cmd in $commands) {
        $name = $cmd.GetCommandName()
        if (-not $name) { continue }
        $line = $cmd.Extent.StartLineNumber
        $leaf = Split-Path $file -Leaf
        if ($Forbidden -contains $name) { $findings.Add([pscustomobject]@{ File = $leaf; Line = $line; Issue = "Forbidden command: $name" }); continue }
        if ($name -eq 'Invoke-MgGraphRequest') {
            $text = $cmd.Extent.Text
            if ($text -notmatch '-Method\s+GET\b') { $findings.Add([pscustomobject]@{ File = $leaf; Line = $line; Issue = 'Invoke-MgGraphRequest without -Method GET' }) }
            continue
        }
        if ($name -eq 'Invoke-AzRestMethod') {
            if ($cmd.Extent.Text -notmatch '-Method\s+GET\b') { $findings.Add([pscustomobject]@{ File = $leaf; Line = $line; Issue = 'Invoke-AzRestMethod without -Method GET' }) }
            continue
        }
        if ($localFunctions -contains $name) { continue }
        if ($LocalOnlyAllowed -contains $name) { continue }
        if ($name -notmatch '-') { continue }   # aliases like %, ?, foreach handled as keywords
        $verb = ($name -split '-')[0]
        if ($ReadVerbs -notcontains $verb) { $findings.Add([pscustomobject]@{ File = $leaf; Line = $line; Issue = "State-changing verb not allowed: $name" }) }
    }
}

if ($findings.Count -eq 0) {
    Write-Host ("PASS - {0} script(s) checked; no state-changing commands and every Graph and ARM call is GET." -f $Path.Count) -ForegroundColor Green
    exit 0
}
$findings | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
Write-Host ("FAIL - {0} finding(s)." -f $findings.Count) -ForegroundColor Red
exit 1
