<#
.SYNOPSIS
    Read-only inventory of Microsoft Purview classification and DLP configuration: sensitivity
    labels and label policies, auto-labeling, custom sensitive information types, DLP policies and
    rules (and their mode), plus optional Content Explorer item counts.

.DESCRIPTION
    Supports "review classification and discovery evidence" for regulated data such as PHI: what
    can classify data, what is actually switched on, and roughly how much tagged content exists
    and where (by workload). It changes nothing and enforces nothing.

    Datasets:
      - purview-sensitivity-labels      every label: parent, priority, enabled, content types
      - purview-label-policies          published label policies: labels, mode, locations, settings
      - purview-autolabel-policies      auto-labeling policies: mode (simulation or on), label, locations
      - purview-autolabel-rules         their rules and the sensitive information types they look for
      - purview-dlp-policies            DLP policies: mode (on / test / off), workloads, locations
      - purview-dlp-rules               DLP rules: sensitive information types, actions, priority
      - purview-sensitive-info-types    every SIT, with custom (organization-published) ones flagged
      - purview-content-explorer-counts (-IncludeContentExplorer) items per SIT or label per workload

    Content Explorer counts: for each tag and workload the script asks for one record and keeps
    only the total from the response metadata. No item names, paths, senders or file details are
    ever written. Tags not found in the tenant are reported, not queried.

    Location lists (sites, mailboxes, users) are summarised as "All" or a count, never listed.

    READ-ONLY. Uses only Get-* cmdlets and Export-ContentExplorerData from Security & Compliance
    PowerShell (Connect-IPPSSession). The session is left open; close it with
    Disconnect-ExchangeOnline when you're done.

    Output: <OutputRoot>\25-PurviewClassification\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER IncludeContentExplorer
    Add item counts per sensitive information type (and per label with -ContentExplorerLabels).

.PARAMETER ContentExplorerSits
    Sensitive information types to count. Defaults to common identifiers in health data; names
    must match the tenant's SIT names exactly (see purview-sensitive-info-types.csv).

.PARAMETER ContentExplorerLabels
    Also count items for every sensitivity label.

.PARAMETER Workloads
    Content Explorer workloads: EXO, ODB, SPO, Teams.

.EXAMPLE
    .\25-Get-PurviewClassification.ps1
.EXAMPLE
    .\25-Get-PurviewClassification.ps1 -IncludeContentExplorer -ContentExplorerLabels
.EXAMPLE
    .\25-Get-PurviewClassification.ps1 -AuthMode AppCertificate -Organization contoso.onmicrosoft.com -ClientId <app id> -CertificateThumbprint <thumbprint>

.NOTES
    Version : 1.0.0
    Requires: PowerShell 7.x (or 5.1), ExchangeOnlineManagement v3.
    Access  : Purview "Global Reader" role group (or Entra Global Reader) for labels and DLP.
              Content Explorer counts also need the "Information Protection Readers" role group
              and "Content Explorer List viewer" (not Content viewer: item names aren't needed).
    Sources : Export-ContentExplorerData and Get-DlpCompliancePolicy reference; Purview Content
              Explorer permissions; Permissions in the Microsoft Purview portal.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$Organization = '',                              # e.g. 'contoso.onmicrosoft.com' (AppCertificate)
    [string]$ClientId = '',
    [string]$CertificateThumbprint = '',

    [switch]$IncludeContentExplorer,
    [string[]]$ContentExplorerSits = @(
        'U.S. Social Security Number (SSN)',
        'International Classification of Diseases (ICD-10-CM)',
        'International Classification of Diseases (ICD-9-CM)',
        'Drug Enforcement Agency (DEA) Number',
        'U.S. Individual Taxpayer Identification Number (ITIN)',
        'Credit Card Number'
    ),
    [switch]$ContentExplorerLabels,
    [ValidateSet('EXO', 'ODB', 'SPO', 'Teams')]
    [string[]]$Workloads = @('EXO', 'ODB', 'SPO', 'Teams')
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '25-PurviewClassification'
$ScriptVersion = '1.0.0'

#region ---- Common helpers (identical in every non-directory script (AWS, event logs); self-contained by design) ----
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
        # Normalise every DateTime to ISO 8601 UTC so CSVs are culture-independent.
        $Rows | ForEach-Object {
            $o = [ordered]@{}
            foreach ($pp in $_.PSObject.Properties) { $o[$pp.Name] = $(if ($pp.Value -is [datetime]) { $pp.Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $pp.Value }) }
            [pscustomobject]$o
        } | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
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

function Write-RunManifest {
    param([string]$DomainName, [hashtable]$Parameters)
    $manifest = [ordered]@{
        Script        = $ScriptName
        ScriptVersion = $ScriptVersion
        StartedUtc    = $script:RunStartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        FinishedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        RunAsWindows  = [Environment]::UserDomainName + '\' + [Environment]::UserName
        Machine       = [Environment]::MachineName
        PowerShell    = $PSVersionTable.PSVersion.ToString()
        Domain        = $DomainName
        Server        = $Server
        Parameters    = $Parameters
        Datasets      = $script:Datasets.ToArray()
    }
    if ($script:ManifestExtra) { $manifest['Extra'] = $script:ManifestExtra }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $script:RunFolder 'run-manifest.json') -Encoding UTF8
    $script:Datasets | Export-Csv -Path (Join-Path $script:RunFolder 'dataset-status.csv') -NoTypeInformation -Encoding UTF8
}

function Join-Values { param($Values) if ($null -eq $Values) { return '' } return (@($Values) | Where-Object { $null -ne $_ -and "$_" -ne '' }) -join '; ' }
#endregion

# ---- Script-specific helpers ----
function Get-Text { param($Value) if ($null -eq $Value) { return '' } if ($Value -is [string]) { return $Value } if ($Value.PSObject.Properties['DisplayName'] -and $Value.DisplayName) { return [string]$Value.DisplayName } if ($Value.PSObject.Properties['Name'] -and $Value.Name) { return [string]$Value.Name } return [string]$Value }

function Format-Location {
    # 'All', 'N specific' or ''; never lists the sites, mailboxes or users.
    param($Value)
    $items = @(@($Value) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { Get-Text $_ })
    if (-not $items.Count) { return '' }
    if ($items -contains 'All') { return 'All' }
    return ('{0} specific' -f $items.Count)
}

function Get-SitName {
    # Collects sensitive information type names from the nested structure used by DLP and
    # auto-labeling rules (lists of hashtables, optionally grouped under 'groups'/'sensitivetypes').
    param($Node)
    if ($null -eq $Node -or $Node -is [string]) { return }
    if ($Node -is [System.Collections.IDictionary]) {
        $keys = @($Node.Keys | ForEach-Object { "$_".ToLowerInvariant() })
        if ($keys -contains 'sensitivetypes') { foreach ($k in $Node.Keys) { if ("$k" -ieq 'sensitivetypes') { Get-SitName $Node[$k] } } ; return }
        if ($keys -contains 'groups') { foreach ($k in $Node.Keys) { if ("$k" -ieq 'groups') { Get-SitName $Node[$k] } } ; return }
        foreach ($k in $Node.Keys) { if ("$k" -ieq 'name') { [string]$Node[$k] } }
        return
    }
    if ($Node -is [System.Collections.IEnumerable]) { foreach ($i in $Node) { Get-SitName $i }; return }
    if ($Node.PSObject.Properties['name']) { [string]$Node.name }
}

function Test-HasValue {
    # True when a property holds at least one non-empty value. (@($null).Count is 1, so never count raw.)
    param($Value)
    return (@(@($Value) | Where-Object { $null -ne $_ -and "$_" -ne '' }).Count -gt 0)
}

function Get-ModeText {
    param([string]$Mode)
    switch ($Mode) {
        'Enable' { 'On (enforced)' }
        'TestWithNotifications' { 'Simulation (with notifications)' }
        'TestWithoutNotifications' { 'Simulation' }
        'Disable' { 'Off' }
        default { $Mode }
    }
}

function Invoke-Inventory {
    # Runs one Get-* inventory and exports it; a failure marks only that dataset.
    param([string]$Name, [scriptblock]$Read, [scriptblock]$Shape, [string]$Note = '')
    try {
        $raw = @(& $Read)
        $rows = @($raw | ForEach-Object { & $Shape $_ })
        Export-Dataset -Name $Name -Rows $rows -Note $Note
        return , $raw
    }
    catch {
        $msg = $_.Exception.Message
        $status = if ($msg -match 'not recognized|is not recognized as|CommandNotFound|not a valid') { 'EvidenceUnavailable' } else { 'Blocked' }
        Set-DatasetStatus -Name $Name -Status $status -Note $msg
        return , @()
    }
}

$orgName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) { throw 'Module ExchangeOnlineManagement not found. Install it (Install-Module ExchangeOnlineManagement -Scope CurrentUser) if your policy allows.' }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    if ($AuthMode -eq 'AppCertificate') {
        if (-not $Organization -or -not $ClientId -or -not $CertificateThumbprint) { throw 'AppCertificate mode needs -Organization, -ClientId and -CertificateThumbprint.' }
        Connect-IPPSSession -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -Organization $Organization -ErrorAction Stop
    }
    else { Connect-IPPSSession -ErrorAction Stop }
    $orgName = $Organization
    $script:ManifestExtra = @{ SecurityComplianceConnected = $true; Organization = $Organization; AuthMode = $AuthMode }
    Write-RunLog 'Connected to Security & Compliance PowerShell.'

    # ---- 1. Sensitivity labels ----
    $script:LabelNames = @{}
    $labels = Invoke-Inventory -Name 'purview-sensitivity-labels' -Read { $all = @(Get-Label); foreach ($x in $all) { foreach ($k in @($x.ImmutableId, $x.Guid, $x.Name)) { if ($k) { $script:LabelNames["$k"] = [string]$x.DisplayName } } }; $all } -Shape {
        param($l)
        [pscustomobject][ordered]@{
            DisplayName = [string]$l.DisplayName; Name = [string]$l.Name; ParentLabel = $(if ($l.ParentId) { if ($script:LabelNames.ContainsKey([string]$l.ParentId)) { $script:LabelNames[[string]$l.ParentId] } else { [string]$l.ParentId } } else { '' })
            Priority = $l.Priority; Disabled = $l.Disabled; ContentType = Join-Values $l.ContentType
            Tooltip = [string]$l.Tooltip; Id = [string]$(if ($l.ImmutableId) { $l.ImmutableId } else { $l.Guid })
        }
    }
    $labelById = @{}
    foreach ($l in $labels) { foreach ($k in @($l.ImmutableId, $l.Guid, $l.Name)) { if ($k) { $labelById["$k"] = [string]$l.DisplayName } } }

    # ---- 2. Label policies ----
    $labelPolicies = Invoke-Inventory -Name 'purview-label-policies' -Read { Get-LabelPolicy } -Shape {
        param($p)
        $settings = @($p.Settings | ForEach-Object { "$_" })
        $pick = { param($key) ($settings | Where-Object { $_ -match "^\[?$key\s*," } | Select-Object -First 1) -replace '^\[?[^,]+,\s*', '' -replace '\]$', '' }
        [pscustomobject][ordered]@{
            Name = [string]$p.Name; Enabled = $p.Enabled; Mode = [string]$p.Mode
            Labels = (@($p.Labels | ForEach-Object { $k = Get-Text $_; if ($labelById.ContainsKey($k)) { $labelById[$k] } else { $k } }) -join '; ')
            LabelCount = @($p.Labels).Count
            ExchangeLocation = Format-Location $p.ExchangeLocation; ModernGroupLocation = Format-Location $p.ModernGroupLocation
            MandatoryLabeling = & $pick 'mandatory'; DefaultLabelId = & $pick 'defaultlabelid'
            Priority = $p.Priority; WhenChangedUtc = $p.WhenChangedUTC
        }
    }

    # ---- 3. Auto-labeling ----
    $autoPolicies = Invoke-Inventory -Name 'purview-autolabel-policies' -Read { Get-AutoSensitivityLabelPolicy } -Shape {
        param($p)
        $lab = Get-Text $p.ApplySensitivityLabel
        [pscustomobject][ordered]@{
            Name = [string]$p.Name; Mode = Get-ModeText ([string]$p.Mode); ModeRaw = [string]$p.Mode; Enabled = $p.Enabled
            AppliesLabel = $(if ($labelById.ContainsKey($lab)) { $labelById[$lab] } else { $lab })
            ExchangeLocation = Format-Location $p.ExchangeLocation; SharePointLocation = Format-Location $p.SharePointLocation; OneDriveLocation = Format-Location $p.OneDriveLocation
            Priority = $p.Priority; WhenChangedUtc = $p.WhenChangedUTC
        }
    }
    $null = Invoke-Inventory -Name 'purview-autolabel-rules' -Read { Get-AutoSensitivityLabelRule } -Shape {
        param($r)
        $sits = @(Get-SitName $r.ContentContainsSensitiveInformation | Where-Object { $_ } | Sort-Object -Unique)
        [pscustomobject][ordered]@{
            Name = [string]$r.Name; Policy = [string]$r.ParentPolicyName; Disabled = $r.Disabled; Workload = Join-Values $r.Workload
            SensitiveInfoTypes = ($sits -join '; '); SensitiveInfoTypeCount = $sits.Count; Priority = $r.Priority
        }
    }

    # ---- 4. DLP ----
    $dlpPolicies = Invoke-Inventory -Name 'purview-dlp-policies' -Read { Get-DlpCompliancePolicy } -Shape {
        param($p)
        [pscustomobject][ordered]@{
            Name = [string]$p.Name; Mode = Get-ModeText ([string]$p.Mode); ModeRaw = [string]$p.Mode; Enabled = $p.Enabled
            Workload = Join-Values $p.Workload; Type = [string]$p.Type; Priority = $p.Priority
            ExchangeLocation = Format-Location $p.ExchangeLocation; SharePointLocation = Format-Location $p.SharePointLocation
            OneDriveLocation = Format-Location $p.OneDriveLocation; TeamsLocation = Format-Location $p.TeamsLocation
            EndpointDlpLocation = Format-Location $p.EndpointDlpLocation; WhenChangedUtc = $p.WhenChangedUTC
        }
    } -Note 'Mode: On (enforced), Simulation, or Off'
    $dlpRules = Invoke-Inventory -Name 'purview-dlp-rules' -Read { Get-DlpComplianceRule } -Shape {
        param($r)
        $sits = @(Get-SitName $r.ContentContainsSensitiveInformation | Where-Object { $_ } | Sort-Object -Unique)
        $actions = @(
            $(if ("$($r.BlockAccess)" -eq 'True') { 'BlockAccess' + $(if ($r.BlockAccessScope) { "($($r.BlockAccessScope))" } else { '' }) })
            $(if (Test-HasValue $r.NotifyUser) { 'NotifyUser' })
            $(if (Test-HasValue $r.GenerateIncidentReport) { 'IncidentReport' })
            $(if (Test-HasValue $r.GenerateAlert) { 'Alert' })
            $(if (Test-HasValue $r.EncryptRMSTemplate) { 'Encrypt' })
        ) | Where-Object { $_ }
        [pscustomobject][ordered]@{
            Name = [string]$r.Name; Policy = [string]$r.ParentPolicyName; Disabled = $r.Disabled; Priority = $r.Priority
            SensitiveInfoTypes = ($sits -join '; '); SensitiveInfoTypeCount = $sits.Count; Actions = ($actions -join '; ')
        }
    }

    # ---- 5. Sensitive information types ----
    $sitAll = Invoke-Inventory -Name 'purview-sensitive-info-types' -Read { Get-DlpSensitiveInformationType } -Shape {
        param($t)
        [pscustomobject][ordered]@{
            Name = [string]$t.Name; Publisher = [string]$t.Publisher; Custom = ([string]$t.Publisher -notmatch '^Microsoft')
            Type = [string]$t.Type; RecommendedConfidence = $t.RecommendedConfidence; Id = [string]$t.Id
        }
    } -Note 'Custom = published by the organization rather than Microsoft'

    # ---- 6. Content Explorer counts (totals only) ----
    $ceRows = [System.Collections.Generic.List[object]]::new()
    if (-not $IncludeContentExplorer) { Set-DatasetStatus -Name 'purview-content-explorer-counts' -Status 'Deferred' -Note 'Run with -IncludeContentExplorer for item counts per SIT / label and workload' }
    else {
        $sitNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($t in $sitAll) { [void]$sitNames.Add([string]$t.Name) }
        $tags = [System.Collections.Generic.List[object]]::new()
        foreach ($n in $ContentExplorerSits) { $tags.Add([pscustomobject]@{ Type = 'SensitiveInformationType'; Name = $n; Known = ($sitNames.Count -eq 0 -or $sitNames.Contains($n)) }) }
        if ($ContentExplorerLabels) { foreach ($l in $labels) { $tags.Add([pscustomobject]@{ Type = 'Sensitivity'; Name = [string]$l.DisplayName; Known = $true }) } }
        $blocked = $false
        foreach ($tag in $tags) {
            if (-not $tag.Known) { $ceRows.Add([pscustomobject][ordered]@{ TagType = $tag.Type; TagName = $tag.Name; Workload = ''; ItemCount = ''; Note = 'Not found in this tenant (check the exact name in purview-sensitive-info-types.csv)' }); continue }
            foreach ($w in $Workloads) {
                $count = ''; $note = ''
                try {
                    $resp = @(Export-ContentExplorerData -TagType $tag.Type -TagName $tag.Name -Workload $w -PageSize 1 -ErrorAction Stop)
                    # Element 0 is metadata (TotalCount, MorePagesAvailable, RecordsReturned, PageCookie). Records are discarded unread.
                    if ($resp.Count) { $count = $resp[0].TotalCount }
                }
                catch {
                    $note = $_.Exception.Message
                    if ($note -match 'denied|not authorized|permission|Forbidden|role') { $blocked = $true }
                }
                $ceRows.Add([pscustomobject][ordered]@{ TagType = $tag.Type; TagName = $tag.Name; Workload = $w; ItemCount = $count; Note = $note })
            }
        }
        $resp = $null
        if ($blocked -and -not @($ceRows | Where-Object { "$($_.ItemCount)" -ne '' }).Count) { Set-DatasetStatus -Name 'purview-content-explorer-counts' -Status 'Blocked' -Note 'Content Explorer not readable: needs Information Protection Readers and Content Explorer List viewer' }
        else { Export-Dataset -Name 'purview-content-explorer-counts' -Rows $ceRows -Note 'Item totals from Content Explorer metadata only; no item names or locations are read or kept' }
    }

    # ---- 7. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Sensitivity labels' @($labels).Count
    Add-Metric 'Sensitivity labels disabled' @($labels | Where-Object { "$($_.Disabled)" -eq 'True' }).Count
    Add-Metric 'Label policies' @($labelPolicies).Count
    Add-Metric 'Auto-labeling policies' @($autoPolicies).Count
    Add-Metric 'Auto-labeling policies on' @($autoPolicies | Where-Object { "$($_.Mode)" -eq 'Enable' }).Count
    Add-Metric 'Auto-labeling policies in simulation' @($autoPolicies | Where-Object { "$($_.Mode)" -like 'Test*' }).Count
    Add-Metric 'DLP policies' @($dlpPolicies).Count
    Add-Metric 'DLP policies on (enforced)' @($dlpPolicies | Where-Object { "$($_.Mode)" -eq 'Enable' }).Count
    Add-Metric 'DLP policies in simulation' @($dlpPolicies | Where-Object { "$($_.Mode)" -like 'Test*' }).Count
    Add-Metric 'DLP policies off' @($dlpPolicies | Where-Object { "$($_.Mode)" -eq 'Disable' }).Count
    Add-Metric 'DLP rules' @($dlpRules).Count
    Add-Metric 'Sensitive information types' @($sitAll).Count
    Add-Metric 'Custom sensitive information types' @($sitAll | Where-Object { [string]$_.Publisher -notmatch '^Microsoft' }).Count
    if ($IncludeContentExplorer) {
        foreach ($g in ($ceRows | Where-Object { "$($_.ItemCount)" -ne '' } | Group-Object TagName)) {
            Add-Metric ("Items tagged: {0}" -f $g.Name) (($g.Group | Measure-Object ItemCount -Sum).Sum) (($g.Group | ForEach-Object { '{0} {1}' -f $_.Workload, $_.ItemCount }) -join '; ')
        }
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $orgName -Parameters @{ AuthMode = $AuthMode; Organization = $Organization; IncludeContentExplorer = [bool]$IncludeContentExplorer; ContentExplorerSits = $ContentExplorerSits; ContentExplorerLabels = [bool]$ContentExplorerLabels; Workloads = $Workloads }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
