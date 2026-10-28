<#
.SYNOPSIS
    Builds a client-ready access request for the discovery scripts you plan to run: roles, Graph
    permissions, other access, input files and licences, from the discovery catalog.

.DESCRIPTION
    Reads tools\discovery-catalog.psd1 (the same file the launcher and report use) and writes one access
    request for the selected scripts, ready to paste into a ticket or an email:

      a) Entra directory roles, deduplicated, with the scripts that need each one
      b) Microsoft Graph permissions, deduplicated, all read-only, worded for the sign-in mode:
           Delegated       delegated permissions consented for the operator's sign-in
           AppCertificate  application permissions on a dedicated read-only app registration (certificate)
         DeviceLocalCredential.ReadBasic.All and BitlockerKey.ReadBasic.All are marked
         "metadata only, never secrets": they read whether a password or key is backed up, not its value.
      c) Other access: Active Directory, Exchange, Azure, AWS, domain controller event logs, the SOC notice
         for script 18, and the extra steps app-only mode needs
      d) Input files the client supplies, with the template in examples\ and a column for the client owner
      e) Licence dependencies (missing licences give EvidenceUnavailable datasets, never a failed run)
      f) A read-only statement, with the result of tools\Test-ReadOnly.ps1 for the selected scripts

    Permissions needed only with an optional switch are listed separately, so the client can approve
    the default run first.

    Local only: reads the catalog and the scripts (Test-ReadOnly parses them; nothing is run), writes only
    its own run folder. Connects to nothing.

    Output: <OutputRoot>\New-AccessRequest\<yyyyMMdd-HHmmssZ>\
      access-request.md     paste into a ticket, wiki or email (Markdown)
      access-request.html   self-contained page; open it and copy into an email, or print to PDF
      access-roles.csv, access-graph-permissions.csv, access-other.csv, access-inputs.csv, access-licences.csv
      run-manifest.json, dataset-status.csv (SHA-256 of every file), run.log

.PARAMETER Select
    Script numbers to include, e.g. -Select 01,02,04 or -Select '01,02'. Default: every script in the catalog.

.PARAMETER AuthMode
    Delegated (default): the operator signs in as themselves. AppCertificate: a dedicated read-only app
    registration with a certificate. Changes the permission wording and adds the app-only steps.

.PARAMETER Format
    Markdown, Csv, Html (one or more). Default: all three.

.PARAMETER Title
    Heading of the request. Default: Access request: read-only identity discovery

.PARAMETER OutputRoot
    Where the tool's run folder goes. Default: tools\output (gitignored). Use the engagement folder.

.EXAMPLE
    .\tools\New-AccessRequest.ps1 -OutputRoot D:\Engagement\reports
.EXAMPLE
    .\tools\New-AccessRequest.ps1 -Select 01,02,04,05,12 -AuthMode AppCertificate -Format Markdown -OutputRoot D:\Engagement\reports

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x.
    Scopes  : none. Reads local files only.
    Licence : none
    Sources : tools\discovery-catalog.psd1 (Roles, Scopes, OptionalScopes, OtherAccess, Inputs, Licence).
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string[]]$Select = @(),
    [ValidateSet('Delegated', 'AppCertificate')][string]$AuthMode = 'Delegated',
    [ValidateSet('Markdown', 'Csv', 'Html')][string[]]$Format = @('Markdown', 'Csv', 'Html'),
    [string]$Title = 'Access request: read-only identity discovery',
    [string]$OutputRoot = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = 'New-AccessRequest'
$ScriptVersion = '1.0.0'

$repoRoot    = Split-Path $PSScriptRoot -Parent
$catalogPath = Join-Path $PSScriptRoot 'discovery-catalog.psd1'
$catalog     = (Import-PowerShellDataFile -Path $catalogPath).Scripts

# ---- Selection (validated before anything is written) ----
$wanted = @($Select | ForEach-Object { "$_" -split '[,\s]+' } | Where-Object { $_ })
$picked = @()
if (-not $wanted.Count) { $picked = @($catalog) }
else {
    foreach ($w in $wanted) {
        $n = 0
        if (-not [int]::TryParse($w, [ref]$n)) { throw "-Select: '$w' is not a script number." }
        $hit = @($catalog | Where-Object { $_.Number -eq $n.ToString('00') })
        if (-not $hit) { throw "-Select: no script numbered $w in the catalog." }
        $picked += $hit[0]
    }
    $picked = @($picked | Sort-Object { $_.Number } -Unique)
}

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

function Set-DatasetStatus {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][ValidateSet('Blocked', 'Deferred', 'EvidenceUnavailable')][string]$Status, [string]$Note = '')
    $script:Datasets.Add([pscustomobject][ordered]@{ Dataset = $Name; Status = $Status; Rows = 0; File = ''; Sha256 = ''; Note = $Note })
    Write-RunLog ("{0}: [{1}] {2}" -f $Name, $Status, $Note) 'WARN'
}

function Export-TextDataset {
    # Writes a text output (Markdown / HTML) to the run folder and records it with SHA-256 like a CSV dataset.
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
$script:MetadataOnly = @{
    'DeviceLocalCredential.ReadBasic.All' = 'Metadata only, never secrets: whether a local admin password is backed up and when it was rotated, never the password'
    'BitlockerKey.ReadBasic.All'          = 'Metadata only, never secrets: whether a recovery key is escrowed, never the key'
}

function ConvertTo-HtmlText { param($Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }

function Join-Numbers { param($Numbers) (@($Numbers) | Sort-Object -Unique) -join ', ' }

function Add-ToMap {
    # Map of item -> sorted list of script numbers, keeping first-seen order of the items.
    param([System.Collections.Specialized.OrderedDictionary]$Map, [string]$Key, [string]$Number)
    if (-not $Key) { return }
    if (-not $Map.Contains($Key)) { $Map[$Key] = [System.Collections.Generic.List[string]]::new() }
    if (-not $Map[$Key].Contains($Number)) { $Map[$Key].Add($Number) }
}

function Get-MdCell { param([string]$Text) ($Text -replace '\|', '\|' -replace "`r?`n", ' ') }

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Write-RunLog ("{0} script(s) selected: {1}; sign-in mode {2}" -f $picked.Count, (($picked | ForEach-Object { $_.Number }) -join ','), $AuthMode)
    $catalogHash = (Get-FileHash -LiteralPath $catalogPath -Algorithm SHA256).Hash

    # ---- a) Roles ----
    $roleMap = [ordered]@{}; $roleOptMap = [ordered]@{}
    foreach ($s in $picked) {
        foreach ($r in @($s.Roles)) { Add-ToMap $roleMap $r $s.Number }
        foreach ($r in @($s.OptionalRoles)) { Add-ToMap $roleOptMap $r $s.Number }
    }
    $roleRows = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $roleMap.Keys) { $roleRows.Add([pscustomobject][ordered]@{ Role = $k; Kind = 'Entra directory role'; When = 'Default run'; Scripts = (Join-Numbers $roleMap[$k]) }) }
    foreach ($k in $roleOptMap.Keys) { if (-not $roleMap.Contains($k)) { $roleRows.Add([pscustomobject][ordered]@{ Role = $k; Kind = 'Entra directory role'; When = 'Optional switch only'; Scripts = (Join-Numbers $roleOptMap[$k]) }) } }

    # ---- b) Graph permissions ----
    $scopeMap = [ordered]@{}; $scopeOptMap = [ordered]@{}
    foreach ($s in $picked) {
        foreach ($sc in @($s.Scopes)) { Add-ToMap $scopeMap $sc $s.Number }
        foreach ($sc in @($s.OptionalScopes)) { Add-ToMap $scopeOptMap $sc $s.Number }
    }
    $permType = $(if ($AuthMode -eq 'Delegated') { 'Delegated' } else { 'Application' })
    $scopeRows = [System.Collections.Generic.List[object]]::new()
    foreach ($k in ($scopeMap.Keys | Sort-Object)) {
        $scopeRows.Add([pscustomobject][ordered]@{ Permission = $k; Type = $permType; Access = 'Read-only'; When = 'Default run'; Scripts = (Join-Numbers $scopeMap[$k]); Note = $(if ($script:MetadataOnly.ContainsKey($k)) { $script:MetadataOnly[$k] } else { '' }) })
    }
    foreach ($k in ($scopeOptMap.Keys | Sort-Object)) {
        if ($scopeMap.Contains($k)) { continue }
        $note = $(if ($k -in @('LicenseAssignment.Read.All', 'Organization.Read.All')) { 'Alternative to Directory.Read.All for 31 (-GraphScope); LicenseAssignment.Read.All is the least privileged' } else { 'Only when the optional switch is used; see the script page' })
        $scopeRows.Add([pscustomobject][ordered]@{ Permission = $k; Type = $permType; Access = 'Read-only'; When = 'Optional switch only'; Scripts = (Join-Numbers $scopeOptMap[$k]); Note = $note })
    }

    # ---- c) Other access ----
    $otherMap = [ordered]@{}
    foreach ($s in $picked) { foreach ($o in @($s.OtherAccess)) { Add-ToMap $otherMap $o $s.Number } }
    $otherRows = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $otherMap.Keys) {
        $area = switch -Regex ($k) {
            '^Domain read|forest root|replication|Schema read' { 'Active Directory'; break }
            'Event Log|event log|audit policy' { 'Domain controllers'; break }
            '^Exchange|SharePoint' { 'Exchange Online / SharePoint'; break }
            '^Azure' { 'Azure'; break }
            '^AWS' { 'AWS'; break }
            'Purview|Information Protection' { 'Microsoft Purview'; break }
            '^SOC' { 'Notice'; break }
            '^Intune' { 'Intune'; break }
            '^Earlier runs' { 'Run order'; break }
            default { 'Other' }
        }
        $otherRows.Add([pscustomobject][ordered]@{ Area = $area; Access = $k; Scripts = (Join-Numbers $otherMap[$k]) })
    }
    $areaOrder = @('Active Directory', 'Domain controllers', 'Exchange Online / SharePoint', 'Microsoft Purview', 'Intune', 'Azure', 'AWS', 'Notice', 'Run order', 'Other')
    $otherRows = [System.Collections.Generic.List[object]]@($otherRows | Sort-Object { [array]::IndexOf($areaOrder, $_.Area) }, { $_.Scripts })
    $nums = @($picked | ForEach-Object { $_.Number })
    if ($AuthMode -eq 'AppCertificate') {
        $graphNums = @($picked | Where-Object { @($_.Scopes).Count -or @($_.OptionalScopes).Count } | ForEach-Object { $_.Number })
        if ($graphNums.Count) { $otherRows.Add([pscustomobject][ordered]@{ Area = 'App registration'; Access = 'Single-tenant app registration with a certificate (no client secret), the application permissions above, and admin consent; disabled or deleted when discovery ends'; Scripts = (Join-Numbers $graphNums) }) }
        if ($nums -contains '09') { $otherRows.Add([pscustomobject][ordered]@{ Area = 'Exchange Online / SharePoint'; Access = 'Exchange.ManageAsApp application permission and an Exchange view-only role assigned to the app''s service principal'; Scripts = '09' }) }
        if ($nums -contains '25') { $otherRows.Add([pscustomobject][ordered]@{ Area = 'Microsoft Purview'; Access = 'The same Purview role groups assigned to the app''s service principal'; Scripts = '25' }) }
        if ($nums -contains '11') { $otherRows.Add([pscustomobject][ordered]@{ Area = 'Azure'; Access = 'Reader at the root management group assigned to the app''s service principal'; Scripts = '11' }) }
    }

    # ---- d) Inputs ----
    $inputRows = [System.Collections.Generic.List[object]]::new()
    $inputKey = [ordered]@{}
    foreach ($s in $picked) {
        foreach ($i in @($s.Inputs)) {
            if (-not $i -or -not $i.Name) { continue }
            $k = "$($i.Name)|$($i.Template)"
            if (-not $inputKey.Contains($k)) { $inputKey[$k] = [pscustomobject]@{ Input = $i.Name; Template = $(if ($i.Template) { "examples/$($i.Template)" } else { '(list of values, no file)' }); Parameters = [System.Collections.Generic.List[string]]::new(); Required = [System.Collections.Generic.List[string]]::new(); Optional = [System.Collections.Generic.List[string]]::new() } }
            $e = $inputKey[$k]
            $pText = "$($s.Number) $($i.Parameter)"
            if (-not $e.Parameters.Contains($pText)) { $e.Parameters.Add($pText) }
            if ($i.Required) { $e.Required.Add($s.Number) } else { $e.Optional.Add($s.Number) }
        }
    }
    foreach ($e in $inputKey.Values) {
        $need = @()
        if ($e.Required.Count) { $need += "Required by $(Join-Numbers $e.Required)" }
        if ($e.Optional.Count) { $need += "Optional for $(Join-Numbers $e.Optional)" }
        $inputRows.Add([pscustomobject][ordered]@{ Input = $e.Input; Template = $e.Template; UsedBy = ($e.Parameters -join '; '); Need = ($need -join '; '); ClientOwner = ''; DueDate = '' })
    }

    # ---- e) Licences ----
    $licRows = [System.Collections.Generic.List[object]]::new()
    $licMap = [ordered]@{}
    foreach ($s in $picked) { if ($s.Licence) { Add-ToMap $licMap $s.Licence $s.Number } }
    foreach ($k in $licMap.Keys) { $licRows.Add([pscustomobject][ordered]@{ Licence = $k; Scripts = (Join-Numbers $licMap[$k]); IfMissing = 'Affected datasets are marked EvidenceUnavailable; the run still completes' }) }

    # ---- f) Read-only check ----
    $files = @(foreach ($n in $nums) { Get-ChildItem -LiteralPath (Join-Path $repoRoot 'scripts') -Filter "$n-*.ps1" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName })
    $readOnlyResult = 'Not checked (scripts folder not found)'
    if ($files.Count) {
        $null = & (Join-Path $PSScriptRoot 'Test-ReadOnly.ps1') -Path $files *>&1
        $readOnlyResult = $(if ($LASTEXITCODE -eq 0) { "PASS on $($script:RunStartUtc.ToString('yyyy-MM-dd')) for $($files.Count) script(s)" } else { "FAIL on $($script:RunStartUtc.ToString('yyyy-MM-dd')): run tools\Test-ReadOnly.ps1 and resolve before sending" })
        Write-RunLog ("Test-ReadOnly: {0}" -f $readOnlyResult) $(if ($LASTEXITCODE -eq 0) { 'INFO' } else { 'ERROR' })
    }
    $statement = 'Every script in this request is read-only. Microsoft Graph and Azure calls go through one function that only sends HTTP GET, and Active Directory, Exchange, event log and AWS work uses read (Get) cmdlets only. ' +
        'tools\Test-ReadOnly.ps1 proves this without running anything: it parses each script and fails on any state-changing command, any Graph or Azure call that is not GET, and any general web or remote-execution command. ' +
        "Result for the scripts in this request: $readOnlyResult. Only read permissions are requested; please do not grant write permissions. " +
        'Each run records the account, the permissions present in its token and a SHA-256 hash of every output file, and output stays in the approved evidence location.'

    $modeText = $(if ($AuthMode -eq 'Delegated') { 'Delegated: the operator signs in as themselves; an administrator consents the delegated permissions below once for the sign-in app (Microsoft Graph PowerShell or the organization''s approved app). The operator''s role limits what is read.' }
                  else { 'App-only (certificate): a dedicated single-tenant app registration holds the application permissions below, with a certificate and no client secret. It is a privileged non-human identity: give it an owner, and disable or delete it when discovery ends.' })
    $roleNote = $(if ($AuthMode -eq 'Delegated') { 'Roles for the operator account. Global Reader covers every Entra read in this request. Make roles PIM-eligible rather than permanent where PIM is in use.' }
                  else { 'In app-only mode the application permissions below replace these roles for Microsoft Graph reads; the operator still needs them to review the results in the portals, and Exchange, Purview and Azure roles go to the app''s service principal (section 3).' })
    $listNumbers = ($picked | ForEach-Object { "$($_.Number) $($_.Title)" }) -join '; '

    # ---- CSV ----
    if ($Format -contains 'Csv') {
        Export-Dataset -Name 'access-roles' -Rows $roleRows -Note 'Entra directory roles, deduplicated'
        Export-Dataset -Name 'access-graph-permissions' -Rows $scopeRows -Note "$permType permissions, read-only"
        Export-Dataset -Name 'access-other' -Rows $otherRows
        Export-Dataset -Name 'access-inputs' -Rows $inputRows -Note 'ClientOwner and DueDate left for the client'
        Export-Dataset -Name 'access-licences' -Rows $licRows
    }
    else { Set-DatasetStatus -Name 'access-csv' -Status 'Deferred' -Note 'Csv not in -Format' }

    # ---- Markdown ----
    if ($Format -contains 'Markdown') {
        $md = [System.Collections.Generic.List[string]]::new()
        $md.Add("# $Title"); $md.Add('')
        $md.Add("Prepared $($script:RunStartUtc.ToString('yyyy-MM-dd')) by $ScriptName $ScriptVersion from the discovery catalog.")
        $md.Add(''); $md.Add("**Scripts covered ($($picked.Count)):** $listNumbers"); $md.Add('')
        $md.Add("**Sign-in mode:** $modeText"); $md.Add('')
        $md.Add('## 1. Entra directory roles'); $md.Add('')
        if ($roleRows.Count) {
            $md.Add('| Role | When | Scripts |'); $md.Add('|---|---|---|')
            foreach ($r in $roleRows) { $md.Add("| $($r.Role) | $($r.When) | $($r.Scripts) |") }
            $md.Add(''); $md.Add($roleNote)
        }
        else { $md.Add('None for the selected scripts.') }
        $md.Add(''); $md.Add("## 2. Microsoft Graph permissions ($($permType.ToLower()), read-only)"); $md.Add('')
        if ($scopeRows.Count) {
            $md.Add('| Permission | Type | When | Scripts | Note |'); $md.Add('|---|---|---|---|---|')
            foreach ($r in $scopeRows) { $md.Add("| ``$($r.Permission)`` | $($r.Type), read-only | $($r.When) | $($r.Scripts) | $(Get-MdCell $r.Note) |") }
        }
        else { $md.Add('None for the selected scripts.') }
        $md.Add(''); $md.Add('## 3. Other access'); $md.Add('')
        if ($otherRows.Count) { $md.Add('| Area | Access | Scripts |'); $md.Add('|---|---|---|'); foreach ($r in $otherRows) { $md.Add("| $($r.Area) | $(Get-MdCell $r.Access) | $($r.Scripts) |") } }
        else { $md.Add('None for the selected scripts.') }
        $md.Add(''); $md.Add('## 4. Input files from the client'); $md.Add('')
        if ($inputRows.Count) {
            $md.Add('Use the template columns. Exports hold identifiers only; never passwords or secrets.'); $md.Add('')
            $md.Add('| Input | Template | Used by | Need | Client owner | Due |'); $md.Add('|---|---|---|---|---|---|')
            foreach ($r in $inputRows) { $md.Add("| $($r.Input) | ``$($r.Template)`` | $($r.UsedBy) | $($r.Need) |  |  |") }
        }
        else { $md.Add('None for the selected scripts.') }
        $md.Add(''); $md.Add('## 5. Licence dependencies'); $md.Add('')
        if ($licRows.Count) { $md.Add('A missing licence never fails a run: the affected datasets are marked EvidenceUnavailable and reported as gaps.'); $md.Add(''); $md.Add('| Licence | Scripts |'); $md.Add('|---|---|'); foreach ($r in $licRows) { $md.Add("| $(Get-MdCell $r.Licence) | $($r.Scripts) |") } }
        else { $md.Add('None for the selected scripts.') }
        $md.Add(''); $md.Add('## 6. Read-only statement'); $md.Add(''); $md.Add($statement)
        Export-TextDataset -Name 'access-request-md' -FileName 'access-request.md' -Text ($md -join [Environment]::NewLine)
    }
    else { Set-DatasetStatus -Name 'access-request-md' -Status 'Deferred' -Note 'Markdown not in -Format' }

    # ---- HTML ----
    if ($Format -contains 'Html') {
        $sb = [System.Text.StringBuilder]::new()
        function Add-HtmlTable {
            param([string[]]$Headers, [object[]]$Rows, [string[]]$Props, [string]$Empty = 'None for the selected scripts.')
            if (-not $Rows -or -not @($Rows).Count) { [void]$sb.Append("<p class=""muted"">$(ConvertTo-HtmlText $Empty)</p>`n"); return }
            [void]$sb.Append('<div class="scroll"><table><thead><tr>')
            foreach ($h in $Headers) { [void]$sb.Append("<th>$(ConvertTo-HtmlText $h)</th>") }
            [void]$sb.Append("</tr></thead><tbody>`n")
            foreach ($r in $Rows) {
                [void]$sb.Append('<tr>')
                foreach ($p in $Props) {
                    $v = [string]$r.$p
                    if ($p -eq 'Permission' -or $p -eq 'Template') { [void]$sb.Append("<td><code>$(ConvertTo-HtmlText $v)</code></td>") }
                    elseif ($p -eq 'Note' -and $v -like 'Metadata only*') { [void]$sb.Append("<td><span class=""flag"">Metadata only, never secrets</span> $(ConvertTo-HtmlText ($v -replace '^Metadata only, never secrets:\s*', ''))</td>") }
                    elseif ($p -eq 'Scripts') { [void]$sb.Append("<td class=""scr"">$(ConvertTo-HtmlText $v)</td>") }
                    elseif ($p -in @('Type', 'Access', 'When')) { [void]$sb.Append("<td class=""nw"">$(ConvertTo-HtmlText $v)</td>") }
                    else { [void]$sb.Append("<td>$(ConvertTo-HtmlText $v)</td>") }
                }
                [void]$sb.Append("</tr>`n")
            }
            [void]$sb.Append("</tbody></table></div>`n")
        }
        [void]$sb.Append(@"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(ConvertTo-HtmlText $Title)</title>
<style>
:root{--bg:#ffffff;--text:#1d2329;--muted:#5f6b76;--line:#d9dee4;--head:#f3f5f8;--accent:#2457c5;--flag-bg:#fdf1d8;--flag-fg:#7a4f00}
@media (prefers-color-scheme:dark){:root{--bg:#16191d;--text:#e6eaee;--muted:#9aa6b1;--line:#30373e;--head:#1f252b;--accent:#7aa2ff;--flag-bg:#3d2f10;--flag-fg:#f3c766}}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:28px 20px 40px}
h1{font-size:22px;margin:0 0 6px}h2{font-size:16px;margin:26px 0 8px;color:var(--accent)}
p{margin:6px 0}.muted{color:var(--muted)}
table{border-collapse:collapse;width:100%;margin:6px 0 4px}
th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}
th{background:var(--head);font-weight:600;font-size:12.5px}
code{font:12.5px ui-monospace,Consolas,monospace;white-space:nowrap}
.nw{white-space:nowrap}
td.scr{min-width:8.5em}
.scroll{overflow-x:auto}
@media (max-width:600px){.wrap{padding:18px 14px 32px}th,td{padding:5px 7px;font-size:13px}code{white-space:normal;overflow-wrap:anywhere}}
.flag{display:inline-block;background:var(--flag-bg);color:var(--flag-fg);font-weight:600;font-size:12px;padding:0 6px;border-radius:4px}
.statement{border-left:3px solid var(--accent);padding:4px 12px}
@media print{body{background:#fff;color:#000}.wrap{max-width:none;padding:0}table{break-inside:auto}tr{break-inside:avoid}}
</style>
</head>
<body><div class="wrap">
<h1>$(ConvertTo-HtmlText $Title)</h1>
<p class="muted">Prepared $($script:RunStartUtc.ToString('yyyy-MM-dd')) by $ScriptName $ScriptVersion from the discovery catalog.</p>
<p><strong>Scripts covered ($($picked.Count)):</strong> $(ConvertTo-HtmlText $listNumbers)</p>
<p><strong>Sign-in mode:</strong> $(ConvertTo-HtmlText $modeText)</p>
<h2>1. Entra directory roles</h2>
"@)
        Add-HtmlTable -Headers 'Role', 'When', 'Scripts' -Rows $roleRows -Props 'Role', 'When', 'Scripts'
        if ($roleRows.Count) { [void]$sb.Append("<p class=""muted"">$(ConvertTo-HtmlText $roleNote)</p>`n") }
        [void]$sb.Append("<h2>2. Microsoft Graph permissions ($(ConvertTo-HtmlText $permType.ToLower()), read-only)</h2>`n")
        Add-HtmlTable -Headers 'Permission', 'Type', 'Access', 'When', 'Scripts', 'Note' -Rows $scopeRows -Props 'Permission', 'Type', 'Access', 'When', 'Scripts', 'Note'
        [void]$sb.Append("<h2>3. Other access</h2>`n")
        Add-HtmlTable -Headers 'Area', 'Access', 'Scripts' -Rows $otherRows -Props 'Area', 'Access', 'Scripts'
        [void]$sb.Append("<h2>4. Input files from the client</h2>`n")
        if ($inputRows.Count) { [void]$sb.Append("<p class=""muted"">Use the template columns. Exports hold identifiers only; never passwords or secrets.</p>`n") }
        Add-HtmlTable -Headers 'Input', 'Template', 'Used by', 'Need', 'Client owner', 'Due' -Rows $inputRows -Props 'Input', 'Template', 'UsedBy', 'Need', 'ClientOwner', 'DueDate'
        [void]$sb.Append("<h2>5. Licence dependencies</h2>`n")
        if ($licRows.Count) { [void]$sb.Append("<p class=""muted"">A missing licence never fails a run: the affected datasets are marked EvidenceUnavailable and reported as gaps.</p>`n") }
        Add-HtmlTable -Headers 'Licence', 'Scripts' -Rows $licRows -Props 'Licence', 'Scripts'
        [void]$sb.Append("<h2>6. Read-only statement</h2>`n<p class=""statement"">$(ConvertTo-HtmlText $statement)</p>`n</div></body></html>`n")
        Export-TextDataset -Name 'access-request-html' -FileName 'access-request.html' -Text $sb.ToString()
    }
    else { Set-DatasetStatus -Name 'access-request-html' -Status 'Deferred' -Note 'Html not in -Format' }

    $script:ManifestExtra = @{ CatalogSha256 = $catalogHash; ScriptsCovered = $nums; ReadOnlyCheck = $readOnlyResult
        Counts = @{ Roles = $roleRows.Count; GraphPermissions = $scopeRows.Count; OtherAccess = $otherRows.Count; Inputs = $inputRows.Count; Licences = $licRows.Count } }
    Write-RunLog ("Roles {0}, Graph permissions {1}, other access {2}, inputs {3}, licences {4}" -f $roleRows.Count, $scopeRows.Count, $otherRows.Count, $inputRows.Count, $licRows.Count)
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Parameters @{ Select = $wanted; AuthMode = $AuthMode; Format = $Format; Title = $Title }
    Write-RunLog ("Finished. Output: {0}" -f $script:RunFolder)
}
