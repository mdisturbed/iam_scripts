<#
.SYNOPSIS
    Creates a new engagement folder: evidence, registers, config, findings, templates and a README with the
    run order and the exact commands for that folder.

.DESCRIPTION
    Sets up one folder per engagement, outside this repository, holding everything the kit's tools read
    and write:

      evidence\     run folders of the discovery scripts and the evidence tools
      registers\    working copies of the registers and input templates from examples\ (".example" dropped):
                    readiness-checklist, status-register, exception-register, deliverable-acceptance-log,
                    ownership-matrix, population-exclusions, pilot-test-cases, and the input templates
                    hr, pam-accounts, iga-accounts, iga-assignments, role-definitions, rule-map
      config\       kpi-definitions.psd1, deliverable-map.psd1 and finding-rules.psd1 (from examples\),
                    engagement.psd1 (name, date)
      findings\     finding evidence notes, the finding ledger and the Review Trail CSV export
      templates\    findings-review.xlsx (blank findings review workbook)
      reports\      access requests and dashboards
      README.md     what goes where, and the run order with the exact commands for this folder

    The copies hold placeholder rows (contoso, Role1, ...). Replace them with the engagement's own values in
    the engagement folder; never copy a filled register back into this repository.

    Refuses to use a folder that already has files in it, unless -Force. With -Force it only adds what is
    missing: an existing file is never overwritten, so filled registers are safe.

    Local only: reads examples\ and templates\ in this repository, writes only under -Path. Connects to nothing.

.PARAMETER Path
    The engagement folder to create, e.g. D:\Engagements\Programme1. Keep it outside the repository, in the
    approved evidence location.

.PARAMETER Name
    Engagement name for the README and the dashboard title, e.g. 'Identity programme'.

.PARAMETER Force
    Use a folder that already has files in it. Adds missing folders and files; never overwrites a file.

.EXAMPLE
    .\tools\New-Engagement.ps1 -Path D:\Engagements\Programme1 -Name 'Identity programme'

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x.
    Scopes  : none. Reads local files only.
    Licence : none
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ScriptName    = 'New-Engagement'
$ScriptVersion = '1.0.0'

$repoRoot  = Split-Path $PSScriptRoot -Parent
$examples  = Join-Path $repoRoot 'examples'
$templates = Join-Path $repoRoot 'templates'
$Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

$repoFull = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\', '/')
if (($Path.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar).StartsWith($repoFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The engagement folder is inside the repository ($repoFull). Engagement folders hold client data: put it in the approved evidence location, outside the repository."
}
if ((Test-Path -LiteralPath $Path) -and -not (Test-Path -LiteralPath $Path -PathType Container)) { throw "-Path is a file, not a folder: $Path" }
if ((Test-Path -LiteralPath $Path) -and @(Get-ChildItem -LiteralPath $Path -Force).Count -and -not $Force) {
    throw "Folder is not empty: $Path. Choose a new folder, or use -Force to add only what is missing (existing files are never overwritten)."
}

$registerFiles = @('readiness-checklist', 'status-register', 'exception-register', 'deliverable-acceptance-log', 'ownership-matrix',
    'population-exclusions', 'pilot-test-cases', 'hr', 'pam-accounts', 'iga-accounts', 'iga-assignments', 'role-definitions', 'rule-map')
$copies = [System.Collections.Generic.List[object]]::new()
foreach ($r in $registerFiles) { $copies.Add(@{ From = Join-Path $examples "$r.example.csv"; To = Join-Path (Join-Path $Path 'registers') "$r.csv" }) }
$copies.Add(@{ From = Join-Path $examples 'kpi-definitions.example.psd1'; To = Join-Path (Join-Path $Path 'config') 'kpi-definitions.psd1' })
$copies.Add(@{ From = Join-Path $examples 'deliverable-map.example.psd1'; To = Join-Path (Join-Path $Path 'config') 'deliverable-map.psd1' })
$copies.Add(@{ From = Join-Path $examples 'finding-rules.psd1'; To = Join-Path (Join-Path $Path 'config') 'finding-rules.psd1' })
$copies.Add(@{ From = Join-Path $templates 'findings-review.template.xlsx'; To = Join-Path (Join-Path $Path 'templates') 'findings-review.xlsx' })
foreach ($c in $copies) { if (-not (Test-Path -LiteralPath $c.From)) { throw "Source missing from the repository: $($c.From)" } }

$created = [System.Collections.Generic.List[string]]::new()
$kept = [System.Collections.Generic.List[string]]::new()
foreach ($d in @('', 'evidence', 'registers', 'config', 'findings', 'templates', 'reports')) {
    $dir = $(if ($d) { Join-Path $Path $d } else { $Path })
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null; if ($d) { $created.Add("$d\") } }
}
foreach ($c in $copies) {
    $rel = $c.To.Substring($Path.TrimEnd('\', '/').Length).TrimStart('\', '/')
    if (Test-Path -LiteralPath $c.To) { $kept.Add($rel); continue }
    [System.IO.File]::Copy($c.From, $c.To, $false)
    $created.Add($rel)
}

# ---- config\engagement.psd1 ----
$engFile = Join-Path (Join-Path $Path 'config') 'engagement.psd1'
if (Test-Path -LiteralPath $engFile) { $kept.Add('config\engagement.psd1') }
else {
    $q = { param($s) "'" + ($s -replace "'", "''") + "'" }
    $engText = @(
        '@{'
        '    # Written by tools\New-Engagement.ps1. Start-Engagement.ps1 reads Name for page titles.'
        "    Name       = $(& $q $Name)"
        "    CreatedUtc = '$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))'"
        "    KitVersion = '$ScriptVersion'"
        '}'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath $engFile -Value $engText -Encoding UTF8
    $created.Add('config\engagement.psd1')
}

# ---- README.md ----
$readme = Join-Path $Path 'README.md'
if (Test-Path -LiteralPath $readme) { $kept.Add('README.md') }
else {
    $tools = Join-Path $repoRoot 'tools'
    $ev = Join-Path $Path 'evidence'; $rg = Join-Path $Path 'registers'; $cf = Join-Path $Path 'config'; $fd = Join-Path $Path 'findings'; $rp = Join-Path $Path 'reports'
    $t = { param($leaf) Join-Path $tools $leaf }
    $md = @"
# $Name

Engagement folder created $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')) by New-Engagement $ScriptVersion.

**This folder holds the organization's data.** Keep it in the approved evidence location. Never copy it,
or any filled register, into the iam_scripts repository or any other Git repository, email or chat.

## What goes where

| Folder | Holds |
|---|---|
| ``evidence\`` | Run folders of the discovery scripts and the evidence tools. Never edit a file inside a run folder. Move a failed or abandoned run into ``evidence\_aborted\`` straight away; the tools ignore it there |
| ``registers\`` | Readiness checklist, status register, exception register, acceptance log, ownership matrix, population exclusions, pilot test cases, and the input templates (HR, PAM, IGA, role files). Replace the placeholder rows with the engagement's own |
| ``config\`` | ``kpi-definitions.psd1`` and ``deliverable-map.psd1``: agree them with the programme owner; their SHA-256 goes in every run manifest. ``finding-rules.psd1``: which metrics draft a finding (tune thresholds here; keep the RuleIds) |
| ``findings\`` | Finding evidence notes (``F-xx.md``), ``finding-ledger.csv`` (keeps finding IDs stable), and ``findings-review.csv``, the CSV export of the workbook's Review Trail sheet |
| ``templates\`` | ``findings-review.xlsx``: the findings review workbook. Save the working copy under ``findings\`` |
| ``reports\`` | Access requests and dashboards |

## Run order

Start-Engagement shows the same steps as a menu:

``````powershell
& '$(& $t 'Start-Engagement.ps1')' -EngagementPath '$Path'
``````

1. **Access request** - roles, Graph permissions, other access, input files and licences, ready for a ticket or email.

   ``````powershell
   & '$(& $t 'New-AccessRequest.ps1')' -OutputRoot '$rp'
   ``````

2. **Readiness** - work through ``registers\readiness-checklist.csv`` until every row is Closed or Waived, and check what this machine can run:

   ``````powershell
   & '$(& $t 'Start-Discovery.ps1')' -ListOnly -Server <dc FQDN> -OutputRoot '$ev'
   ``````

3. **Baseline runs** - run 31 first (licences), then the rest as access allows. Input files are in ``registers\``.

   ``````powershell
   & '$(& $t 'Start-Discovery.ps1')' -Server <dc FQDN> -OutputRoot '$ev'
   ``````

   Record every dataset that is not Completed in ``registers\status-register.csv`` with owner, rationale, risk and follow-on.

4. **Evidence package** - intake log, hash re-check and per-deliverable status:

   ``````powershell
   & '$(& $t 'New-EvidencePackage.ps1')' -EvidenceRoot '$ev' -DeliverableMapPath '$(Join-Path $cf 'deliverable-map.psd1')'
   ``````

5. **KPIs** - values over the script 27 denominators:

   ``````powershell
   & '$(& $t 'Get-KpiSummary.ps1')' -EvidenceRoot '$ev' -KpiDefinitionPath '$(Join-Path $cf 'kpi-definitions.psd1')'
   ``````

6. **Findings review** - draft findings from the latest runs, then paste the rows of ``finding-drafts.csv`` into the first empty row of the workbook's Review Trail sheet. The evidence notes are already in ``findings\``.

   ``````powershell
   & '$(& $t 'New-FindingDrafts.ps1')' -EvidenceRoot '$ev' -RulesPath '$(Join-Path $cf 'finding-rules.psd1')' -LedgerPath '$(Join-Path $fd 'finding-ledger.csv')' -OutputRoot '$rp'
   ``````

   Each role fills its own column group (Engineer, Architect, Zero Trust Architect, Client). Export the Review Trail sheet to ``findings\findings-review.csv`` for the dashboard.

7. **Dashboard** - one page with runs, KPIs, readiness, findings and open evidence items:

   ``````powershell
   & '$(& $t 'New-EngagementDashboard.ps1')' -EvidenceRoot '$ev' -ReadinessCsv '$(Join-Path $rg 'readiness-checklist.csv')' -StatusRegisterCsv '$(Join-Path $rg 'status-register.csv')' -FindingsCsv '$(Join-Path $fd 'findings-review.csv')' -Title '$($Name -replace "'", "''") dashboard' -OutputRoot '$rp'
   ``````

Rerun steps 3 to 7 after each collection round or change. ``Compare-RunFolders.ps1`` gives before / after evidence for a change.
"@
    Set-Content -LiteralPath $readme -Value $md -Encoding UTF8
    $created.Add('README.md')
}

Write-Host ''
Write-Host "$ScriptName $ScriptVersion - engagement folder: $Path" -ForegroundColor Cyan
foreach ($c in $created) { Write-Host "  created  $c" -ForegroundColor Green }
foreach ($k in $kept) { Write-Host "  kept     $k (already there; not overwritten)" -ForegroundColor Yellow }
Write-Host ''
Write-Host 'Next: replace the placeholder rows in registers\, then open the menu:' -ForegroundColor Cyan
Write-Host "  & '$(Join-Path $PSScriptRoot 'Start-Engagement.ps1')' -EngagementPath '$Path'"
