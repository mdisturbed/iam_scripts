<#
.SYNOPSIS
    Read-only inventory of Microsoft Purview classification and DLP configuration: sensitivity
    labels and label policies, auto-labeling, custom sensitive information types, DLP policies and
    rules (and their mode), who is excluded from them, who can see or bypass protection, retention,
    plus optional Content Explorer item counts and Activity Explorer override / downgrade counts.

.DESCRIPTION
    Supports "review classification and discovery evidence" for regulated data such as PHI: what
    can classify data, what is actually switched on, and roughly how much tagged content exists
    and where (by workload). It changes nothing and enforces nothing.

    Datasets:
      - purview-sensitivity-labels      every label: parent, priority, enabled, content types,
                                        encryption (rights, do-not-forward), site / group protection
      - purview-label-policies          published label policies: labels, mode, locations, settings,
                                        downgrade justification, excluded locations
      - purview-autolabel-policies      auto-labeling policies: mode (simulation or on), label, locations
      - purview-autolabel-rules         their rules and the sensitive information types they look for
      - purview-dlp-policies            DLP policies: mode (on / test / off), workloads, locations
      - purview-dlp-rules               DLP rules: sensitive information types (including rules kept
                                        in AdvancedRule), actions, user override settings, priority
      - policy-exclusions               every excluded location and rule exception (ExceptIfFrom,
                                        ExceptIfSentToMemberOf ...), resolved to type / member count
      - purview-adaptive-scopes         adaptive scopes and their queries
      - purview-sensitive-info-types    every SIT, with custom (organization-published) ones flagged
      - purview-role-holders            members of role groups that can view, export, classify or
                                        decrypt protected content; purview-ediscovery-admins;
                                        purview-aip-super-users (AIPService module, Windows PowerShell)
      - purview-retention-policies / purview-retention-labels
      - purview-content-explorer-counts (-IncludeContentExplorer) items per SIT or label per workload
      - purview-activity-summary        (-IncludeActivityExplorer) per user: DLP matches, overrides /
                                        undos, label downgrades and removals (counts only)

    Content Explorer counts: for each tag and workload the script asks for one record and keeps
    only the total from the response metadata. No item names, paths, senders or file details are
    ever written. Tags not found in the tenant are reported, not queried.

    Location lists (sites, mailboxes, users) are summarised as "All" or a count in the policy
    datasets. Exclusions are listed in policy-exclusions, because an exclusion is a gap to review.
    Excluded recipients and groups are resolved only when Exchange recipient cmdlets are present in
    the same session (connect Exchange Online first); otherwise they are listed unresolved.

    READ-ONLY. Uses only Get-* cmdlets, Export-ContentExplorerData and Export-ActivityExplorerData
    (read-only exports) from Security & Compliance PowerShell (Connect-IPPSSession). The session is left open; close it with
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

.PARAMETER SkipRoleHolders
    Skip the role group, eDiscovery administrator and AIP super user reads.

.PARAMETER IncludeActivityExplorer
    Add per-user counts of DLP matches, overrides / undos and label downgrades / removals from
    Activity Explorer for the last -ActivityDays days (maximum 30). Only counts are kept.

.PARAMETER ActivityMaxPages
    Stop Activity Explorer after this many pages of 5000 events (default 20); the dataset is then Partial.

.EXAMPLE
    .\25-Get-PurviewClassification.ps1
.EXAMPLE
    .\25-Get-PurviewClassification.ps1 -IncludeContentExplorer -ContentExplorerLabels
.EXAMPLE
    .\25-Get-PurviewClassification.ps1 -IncludeActivityExplorer -ActivityDays 14
.EXAMPLE
    .\25-Get-PurviewClassification.ps1 -AuthMode AppCertificate -Organization contoso.onmicrosoft.com -ClientId <app id> -CertificateThumbprint <thumbprint>

.NOTES
    Version : 1.1.0
    Requires: PowerShell 7.x (or 5.1), ExchangeOnlineManagement v3.
    Access  : Purview "Global Reader" role group (or Entra Global Reader) for labels and DLP.
              Content Explorer counts also need the "Information Protection Readers" role group
              and "Content Explorer List viewer" (not Content viewer: item names aren't needed).
              Role holders and eDiscovery administrators: a role group that can read role groups
              (for example Global Reader / Compliance Administrator). Activity Explorer: a role group
              with Activity explorer access. AIP super users: AIPService module and Global Reader or
              Azure Information Protection administrator, Windows PowerShell 5.1.
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
    [string[]]$Workloads = @('EXO', 'ODB', 'SPO', 'Teams'),
    [switch]$SkipRoleHolders,
    [switch]$IncludeActivityExplorer,
    [ValidateRange(1, 30)]
    [int]$ActivityDays = 30,
    [int]$ActivityMaxPages = 20
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '25-PurviewClassification'
$ScriptVersion = '1.1.0'

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

function Get-AdvancedRuleSitName {
    # Rules built in the new DLP editor keep their conditions in AdvancedRule (a JSON string).
    # Walks it and returns the 'name' of every entry under any 'sensitivetypes' list.
    param($AdvancedRule)
    if (-not $AdvancedRule) { return @() }
    $json = $null
    try { $json = "$AdvancedRule" | ConvertFrom-Json } catch { return @() }
    $names = [System.Collections.Generic.List[string]]::new()
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push($json)
    while ($stack.Count) {
        $n = $stack.Pop()
        if ($null -eq $n -or $n -is [string] -or $n -is [ValueType]) { continue }
        if ($n -is [System.Collections.IEnumerable]) { foreach ($x in $n) { $stack.Push($x) }; continue }
        foreach ($pp in $n.PSObject.Properties) {
            if ($pp.Name -ieq 'sensitivetypes') { foreach ($t in @($pp.Value)) { if ($t -and $t.PSObject.Properties['name'] -and $t.name) { $names.Add([string]$t.name) } } }
            elseif ($null -ne $pp.Value -and $pp.Value -isnot [string] -and $pp.Value -isnot [ValueType]) { $stack.Push($pp.Value) }
        }
    }
    return @($names | Sort-Object -Unique)
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

function Get-Prop {
    # Property value or $null, without failing on objects that do not have it.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-LabelActionSetting {
    # Reads a setting from a label's LabelActions JSON, e.g. Type 'encrypt' Key 'donotforward'.
    param($Label, [string]$Type, [string]$Key)
    $raw = Get-Prop $Label 'LabelActions'
    foreach ($entry in @($raw)) {
        if (-not $entry) { continue }
        $a = $entry
        if ($entry -is [string]) { try { $a = $entry | ConvertFrom-Json } catch { continue } }
        foreach ($act in @($a)) {
            if ("$($act.Type)" -ine $Type) { continue }
            foreach ($s in @($act.Settings)) { if ("$($s.Key)" -ieq $Key) { return $s.Value } }
        }
    }
    return $null
}

function Format-RightsDefinition {
    # Accepts 'identity:RIGHT,RIGHT;identity:RIGHT' or a JSON list of {Identity, Rights}.
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '' }
    $out = @()
    $text = "$Value"
    if ($text.TrimStart().StartsWith('[')) {
        try { foreach ($r in @($text | ConvertFrom-Json)) { $out += ('{0}: {1}' -f $r.Identity, $r.Rights) } ; return ($out -join ' | ') } catch { }
    }
    foreach ($v in @($Value)) { foreach ($part in ("$v" -split ';')) { if ($part.Trim()) { $out += $part.Trim() } } }
    return ($out -join ' | ')
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

# Purview roles that can view, export, classify, decrypt or manage protected content.
$SensitiveRolePattern = 'Compliance Administrator|eDiscovery|Case Management|Content Explorer|Data Classification|Information Protection|Data Loss Prevention|DLP Compliance|Sensitivity Label|^Export$|^Review$|RMS Decrypt|Communication Compliance|Insider Risk'

$script:ResolveCache = @{}
function Resolve-ExclusionValue {
    # Classifies an excluded value; resolves recipients and group member counts when the Exchange
    # cmdlets are present in this session (Get-Recipient, Get-DistributionGroupMember, Get-UnifiedGroupLinks).
    param([string]$Value, [string]$Location)
    if ($script:ResolveCache.ContainsKey($Value)) { return $script:ResolveCache[$Value] }
    $r = [pscustomobject]@{ ResolvedType = 'Unresolved'; MemberCount = ''; Note = '' }
    if ($Value -match '^https?://') { $r.ResolvedType = 'Site' }
    elseif ($Location -match 'DomainIs$') { $r.ResolvedType = 'Domain' }
    elseif ($Value -eq 'All') { $r.ResolvedType = 'All' }
    elseif (-not $script:HasRecipientCmdlet) { $r.Note = 'Exchange recipient cmdlets not in this session (connect Exchange Online in the same session to resolve)' }
    else {
        try {
            $rc = Get-Recipient -Identity $Value -ErrorAction Stop
            $r.ResolvedType = "$($rc.RecipientTypeDetails)"
            if ($r.ResolvedType -eq 'GroupMailbox' -and $script:HasUnifiedLinksCmdlet) { $r.MemberCount = @(Get-UnifiedGroupLinks -Identity $Value -LinkType Members -ResultSize Unlimited -ErrorAction Stop).Count }
            elseif ($r.ResolvedType -match 'Group' -and $script:HasDgMemberCmdlet) { $r.MemberCount = @(Get-DistributionGroupMember -Identity $Value -ResultSize Unlimited -ErrorAction Stop).Count }
        }
        catch { $r.Note = $(if ($r.ResolvedType -ne 'Unresolved') { "Members not counted: $($_.Exception.Message)" } else { "Not resolved: $($_.Exception.Message)" }) }
    }
    $script:ResolveCache[$Value] = $r
    return $r
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
    $script:HasRecipientCmdlet = [bool](Get-Command -Name Get-Recipient -ErrorAction SilentlyContinue)
    $script:HasDgMemberCmdlet = [bool](Get-Command -Name Get-DistributionGroupMember -ErrorAction SilentlyContinue)
    $script:HasUnifiedLinksCmdlet = [bool](Get-Command -Name Get-UnifiedGroupLinks -ErrorAction SilentlyContinue)

    # ---- 1. Sensitivity labels ----
    $script:LabelNames = @{}
    $labels = Invoke-Inventory -Name 'purview-sensitivity-labels' -Read { $all = @(Get-Label); foreach ($x in $all) { foreach ($k in @($x.ImmutableId, $x.Guid, $x.Name)) { if ($k) { $script:LabelNames["$k"] = [string]$x.DisplayName } } }; $all } -Shape {
        param($l)
        $encEnabled = Get-Prop $l 'EncryptionEnabled'
        if ($null -eq $encEnabled) { $d = Get-LabelActionSetting -Label $l -Type 'encrypt' -Key 'disabled'; if ($null -ne $d) { $encEnabled = ("$d" -ieq 'false') } }
        $dnf = Get-Prop $l 'EncryptionDoNotForward'
        if ($null -eq $dnf) { $dnf = Get-LabelActionSetting -Label $l -Type 'encrypt' -Key 'donotforward' }
        $rights = Get-Prop $l 'EncryptionRightsDefinitions'
        if ($null -eq $rights) { $rights = Get-LabelActionSetting -Label $l -Type 'encrypt' -Key 'rightsdefinitions' }
        $privacy = Get-Prop $l 'SiteAndGroupProtectionPrivacy'
        if ($null -eq $privacy) { $privacy = Get-LabelActionSetting -Label $l -Type 'protectgroup' -Key 'privacy' }
        $guests = Get-Prop $l 'SiteAndGroupProtectionAllowAccessToGuestUsers'
        if ($null -eq $guests) { $guests = Get-LabelActionSetting -Label $l -Type 'protectgroup' -Key 'allowaccesstoguestusers' }
        [pscustomobject][ordered]@{
            DisplayName = [string]$l.DisplayName; Name = [string]$l.Name; ParentLabel = $(if ($l.ParentId) { if ($script:LabelNames.ContainsKey([string]$l.ParentId)) { $script:LabelNames[[string]$l.ParentId] } else { [string]$l.ParentId } } else { '' })
            Priority = $l.Priority; Disabled = $l.Disabled; ContentType = Join-Values $l.ContentType
            Tooltip = [string]$l.Tooltip; Id = [string]$(if ($l.ImmutableId) { $l.ImmutableId } else { $l.Guid })
            EncryptionEnabled = $(if ($null -ne $encEnabled) { "$encEnabled" } else { '' })
            EncryptionDoNotForward = $(if ($null -ne $dnf) { "$dnf" } else { '' })
            EncryptionRightsDefinitions = Format-RightsDefinition $rights
            SiteAndGroupPrivacy = $(if ($null -ne $privacy) { "$privacy" } else { '' })
            SiteAndGroupAllowGuests = $(if ($null -ne $guests) { "$guests" } else { '' })
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
            RequireDowngradeJustification = & $pick 'requiredowngradejustification'
            ExchangeLocationException = Format-Location (Get-Prop $p 'ExchangeLocationException')
            ModernGroupLocationException = Format-Location (Get-Prop $p 'ModernGroupLocationException')
            AllSettings = ($settings -join '; ')
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
        if (-not $sits.Count) { $sits = @(Get-AdvancedRuleSitName (Get-Prop $r 'AdvancedRule')) }
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
        $adv = Get-Prop $r 'AdvancedRule'
        if (-not $sits.Count -and $adv) { $sits = @(Get-AdvancedRuleSitName $adv) }
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
            NotifyAllowOverride = Join-Values (Get-Prop $r 'NotifyAllowOverride')
            NotifyOverrideRequirements = Join-Values (Get-Prop $r 'NotifyOverrideRequirements')
            UsesAdvancedRule = [bool]$adv
        }
    }

    # ---- 4b. Who is excluded from DLP, label and auto-label policies ----
    $exclRows = [System.Collections.Generic.List[object]]::new()
    try {
        $sources = @()
        foreach ($p in $dlpPolicies) { $sources += [pscustomobject]@{ Obj = $p; Type = 'DLP policy'; Name = [string]$p.Name } }
        foreach ($p in $labelPolicies) { $sources += [pscustomobject]@{ Obj = $p; Type = 'Label policy'; Name = [string]$p.Name } }
        foreach ($p in $autoPolicies) { $sources += [pscustomobject]@{ Obj = $p; Type = 'Auto-label policy'; Name = [string]$p.Name } }
        foreach ($src in $sources) {
            foreach ($pp in $src.Obj.PSObject.Properties) {
                if ($pp.Name -notlike '*LocationException') { continue }
                foreach ($v in @($pp.Value | Where-Object { $null -ne $_ -and "$_" -ne '' })) {
                    $val = Get-Text $v
                    $res = Resolve-ExclusionValue $val $pp.Name
                    $exclRows.Add([pscustomobject][ordered]@{ Policy = $src.Name; PolicyType = $src.Type; Location = $pp.Name; ExcludedValue = $val; ResolvedType = $res.ResolvedType; MemberCount = $res.MemberCount; Note = $res.Note })
                }
            }
        }
        foreach ($r in $dlpRules) {
            foreach ($prop in 'ExceptIfFrom', 'ExceptIfFromMemberOf', 'ExceptIfSentTo', 'ExceptIfSentToMemberOf', 'ExceptIfRecipientDomainIs', 'ExceptIfSenderDomainIs') {
                foreach ($v in @((Get-Prop $r $prop) | Where-Object { $null -ne $_ -and "$_" -ne '' })) {
                    $val = Get-Text $v
                    $res = Resolve-ExclusionValue $val $prop
                    $exclRows.Add([pscustomobject][ordered]@{ Policy = [string]$r.ParentPolicyName; PolicyType = "DLP rule: $([string]$r.Name)"; Location = $prop; ExcludedValue = $val; ResolvedType = $res.ResolvedType; MemberCount = $res.MemberCount; Note = $res.Note })
                }
            }
        }
        Export-Dataset -Name 'policy-exclusions' -Rows $exclRows -Note $(if ($script:HasRecipientCmdlet) { 'Excluded locations and rule exceptions; groups resolved to member counts where possible' } else { 'Excluded locations and rule exceptions; recipients not resolved (Exchange cmdlets not in this session)' })
    }
    catch { Set-DatasetStatus -Name 'policy-exclusions' -Status 'Blocked' -Note $_.Exception.Message }

    $null = Invoke-Inventory -Name 'purview-adaptive-scopes' -Read { Get-AdaptiveScope } -Shape {
        param($s)
        $q = Get-Prop $s 'RawQuery'
        if (-not $q) { $fc = Get-Prop $s 'FilterConditions'; if ($fc) { $q = $(if ($fc -is [string]) { $fc } else { $fc | ConvertTo-Json -Depth 6 -Compress }) } }
        [pscustomobject][ordered]@{ Name = [string]$s.Name; LocationType = [string](Get-Prop $s 'LocationType'); Query = [string]$q; AdministrativeUnits = Join-Values (Get-Prop $s 'AdministrativeUnits'); WhenCreatedUtc = (Get-Prop $s 'WhenCreatedUTC') }
    } -Note 'Adaptive scopes decide membership of retention and other policies by query'

    # ---- 5. Sensitive information types ----
    $sitAll = Invoke-Inventory -Name 'purview-sensitive-info-types' -Read { Get-DlpSensitiveInformationType } -Shape {
        param($t)
        [pscustomobject][ordered]@{
            Name = [string]$t.Name; Publisher = [string]$t.Publisher; Custom = ([string]$t.Publisher -notmatch '^Microsoft')
            Type = [string]$t.Type; RecommendedConfidence = $t.RecommendedConfidence; Id = [string]$t.Id
        }
    } -Note 'Custom = published by the organization rather than Microsoft'

    # ---- 5b. Who can see or bypass protection ----
    $holderRows = [System.Collections.Generic.List[object]]::new()
    if ($SkipRoleHolders) { foreach ($n in 'purview-role-holders', 'purview-ediscovery-admins', 'purview-aip-super-users') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note '-SkipRoleHolders' } }
    else {
        try {
            $memberFailures = 0
            foreach ($rg in @(Get-RoleGroup -ErrorAction Stop)) {
                $roles = @($rg.Roles | ForEach-Object { ("$_" -split '\\')[-1] })
                $match = @($roles | Where-Object { $_ -match $SensitiveRolePattern })
                if (-not $match.Count) { continue }
                $members = $null
                try { $members = @(Get-RoleGroupMember -Identity "$($rg.Name)" -ErrorAction Stop) } catch { $memberFailures++ }
                if ($null -eq $members) { $holderRows.Add([pscustomobject][ordered]@{ RoleGroup = [string]$rg.Name; MatchingRoles = ($match -join '; '); Member = ''; MemberType = ''; Address = ''; Note = 'Members could not be read' }); continue }
                if (-not $members.Count) { $holderRows.Add([pscustomobject][ordered]@{ RoleGroup = [string]$rg.Name; MatchingRoles = ($match -join '; '); Member = ''; MemberType = ''; Address = ''; Note = 'No members' }); continue }
                foreach ($m in $members) {
                    $addr = Get-Prop $m 'PrimarySmtpAddress'; if (-not $addr) { $addr = Get-Prop $m 'WindowsLiveID' }
                    $holderRows.Add([pscustomobject][ordered]@{ RoleGroup = [string]$rg.Name; MatchingRoles = ($match -join '; '); Member = [string]$(if (Get-Prop $m 'DisplayName') { $m.DisplayName } else { $m.Name }); MemberType = [string](Get-Prop $m 'RecipientType'); Address = [string]$addr; Note = $(if ("$(Get-Prop $m 'RecipientType')" -match 'Group') { 'Group: members not expanded here' } else { '' }) })
                }
            }
            Export-Dataset -Name 'purview-role-holders' -Rows $holderRows -Status $(if ($memberFailures) { 'Partial' } else { 'Completed' }) -Note ('Role groups whose roles can view, export, classify, decrypt or manage protected content' + $(if ($memberFailures) { "; members unreadable for $memberFailures role group(s)" } else { '' }))
        }
        catch { Set-DatasetStatus -Name 'purview-role-holders' -Status $(if ($_.Exception.Message -match 'not recognized') { 'EvidenceUnavailable' } else { 'Blocked' }) -Note $_.Exception.Message }

        $null = Invoke-Inventory -Name 'purview-ediscovery-admins' -Read { Get-eDiscoveryCaseAdmin -ResultSize Unlimited } -Shape {
            param($a)
            $addr = Get-Prop $a 'PrimarySmtpAddress'; if (-not $addr) { $addr = Get-Prop $a 'WindowsLiveID' }
            [pscustomobject][ordered]@{ Name = [string]$(if (Get-Prop $a 'DisplayName') { $a.DisplayName } else { $a.Name }); Address = [string]$addr; RecipientType = [string](Get-Prop $a 'RecipientType') }
        } -Note 'eDiscovery Administrators can open every eDiscovery case'

        # AIP super users can decrypt everything protected by the tenant's labels.
        if (-not (Get-Module -ListAvailable -Name AIPService)) { Set-DatasetStatus -Name 'purview-aip-super-users' -Status 'Deferred' -Note 'Module AIPService not installed (Windows PowerShell 5.1 only); super users not read' }
        elseif ($PSVersionTable.PSEdition -ne 'Desktop') { Set-DatasetStatus -Name 'purview-aip-super-users' -Status 'Deferred' -Note 'AIPService runs only in Windows PowerShell 5.1; re-run there to read super users' }
        elseif ($AuthMode -eq 'AppCertificate') { Set-DatasetStatus -Name 'purview-aip-super-users' -Status 'Deferred' -Note 'AIPService sign-in is interactive; not attempted in AppCertificate mode' }
        else {
            try {
                Import-Module AIPService -ErrorAction Stop
                Connect-AipService -ErrorAction Stop | Out-Null
                $feature = "$(Get-AipServiceSuperUserFeature -ErrorAction Stop)"
                $suRows = [System.Collections.Generic.List[object]]::new()
                foreach ($u in @(Get-AipServiceSuperUser -ErrorAction Stop)) { if ($u) { $suRows.Add([pscustomobject][ordered]@{ Feature = $feature; SuperUser = "$u"; Source = 'User' }) } }
                foreach ($g in @(Get-AipServiceSuperUserGroup -ErrorAction SilentlyContinue)) { if ($g) { $suRows.Add([pscustomobject][ordered]@{ Feature = $feature; SuperUser = "$g"; Source = 'Group' }) } }
                if (-not $suRows.Count) { $suRows.Add([pscustomobject][ordered]@{ Feature = $feature; SuperUser = ''; Source = 'None configured' }) }
                Export-Dataset -Name 'purview-aip-super-users' -Rows $suRows -Note 'Super users can decrypt any content protected by the tenant when the feature is Enabled'
            }
            catch { Set-DatasetStatus -Name 'purview-aip-super-users' -Status 'Blocked' -Note $_.Exception.Message }
        }
    }

    # ---- 5c. Retention (counts) ----
    $retPolicies = Invoke-Inventory -Name 'purview-retention-policies' -Read { Get-RetentionCompliancePolicy } -Shape {
        param($p)
        [pscustomobject][ordered]@{ Name = [string]$p.Name; Enabled = $p.Enabled; Mode = [string](Get-Prop $p 'Mode'); Workload = Join-Values (Get-Prop $p 'Workload'); AdaptiveScopes = Join-Values (Get-Prop $p 'AdaptiveScopeLocation'); DistributionStatus = [string](Get-Prop $p 'DistributionStatus') }
    }
    $retLabels = Invoke-Inventory -Name 'purview-retention-labels' -Read { Get-ComplianceTag } -Shape {
        param($t)
        [pscustomobject][ordered]@{ Name = [string]$t.Name; RetentionAction = [string](Get-Prop $t 'RetentionAction'); RetentionDuration = [string](Get-Prop $t 'RetentionDuration'); RetentionType = [string](Get-Prop $t 'RetentionType'); IsRecordLabel = Get-Prop $t 'IsRecordLabel'; Regulatory = Get-Prop $t 'Regulatory' }
    }

    # ---- 6. Content Explorer counts (totals only) ----
    $ceRows = [System.Collections.Generic.List[object]]::new()
    if (-not $IncludeContentExplorer) { Set-DatasetStatus -Name 'purview-content-explorer-counts' -Status 'Deferred' -Note 'Run with -IncludeContentExplorer for item counts per SIT / label and workload' }
    else {
        $sitNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($t in $sitAll) { [void]$sitNames.Add([string]$t.Name) }
        $tags = [System.Collections.Generic.List[object]]::new()
        $seenTag = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $ContentExplorerSits) { if ($seenTag.Add($n)) { $tags.Add([pscustomobject]@{ Type = 'SensitiveInformationType'; Name = $n; Known = ($sitNames.Count -eq 0 -or $sitNames.Contains($n)) }) } }
        foreach ($t in @($sitAll | Where-Object { [string]$_.Publisher -notmatch '^Microsoft' })) { if ($seenTag.Add([string]$t.Name)) { $tags.Add([pscustomobject]@{ Type = 'SensitiveInformationType'; Name = [string]$t.Name; Known = $true }) } }
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
        else { Export-Dataset -Name 'purview-content-explorer-counts' -Rows $ceRows -Note 'Item totals from Content Explorer metadata only; no item names or locations are read or kept. Custom SITs are added automatically.' }
    }

    # ---- 7. Activity Explorer: DLP overrides and label downgrades per user (aggregates only) ----
    $actRows = @()
    if (-not $IncludeActivityExplorer) { Set-DatasetStatus -Name 'purview-activity-summary' -Status 'Deferred' -Note 'Run with -IncludeActivityExplorer for DLP override and label downgrade counts per user' }
    else {
        try {
            $days = [math]::Max(1, [math]::Min(30, $ActivityDays))
            $end = (Get-Date).ToUniversalTime(); $start = $end.AddDays(-$days)
            $byUser = @{}
            $page = 0; $cookie = $null; $truncated = $false
            while ($true) {
                $page++
                $ea = @{ StartTime = $start; EndTime = $end; OutputFormat = 'Json'; PageSize = 5000; Filter1 = @('Activity', 'DLPRuleMatch', 'DLPRuleUndo', 'LabelChanged', 'LabelRemoved'); ErrorAction = 'Stop' }
                if ($cookie) { $ea['PageCookie'] = $cookie }
                $res = Export-ActivityExplorerData @ea
                $records = @()
                if ($res.ResultData) { $records = @($(if ($res.ResultData -is [string]) { $res.ResultData | ConvertFrom-Json } else { $res.ResultData })) }
                foreach ($rec in $records) {
                    $user = [string](Get-Prop $rec 'User'); if (-not $user) { $user = [string](Get-Prop $rec 'UserId') }; if (-not $user) { $user = '(unknown)' }
                    if (-not $byUser.ContainsKey($user)) { $byUser[$user] = [pscustomobject][ordered]@{ User = $user; Events = 0; DlpMatches = 0; DlpOverridesOrUndos = 0; LabelDowngrades = 0; LabelRemovals = 0; Workloads = [System.Collections.Generic.HashSet[string]]::new(); FirstUtc = $null; LastUtc = $null } }
                    $u = $byUser[$user]; $u.Events++
                    $act = [string](Get-Prop $rec 'Activity')
                    $wl = [string](Get-Prop $rec 'Workload'); if ($wl) { [void]$u.Workloads.Add($wl) }
                    $hasOverride = @($rec.PSObject.Properties | Where-Object { $_.Name -match 'Override|Justification' -and $null -ne $_.Value -and "$($_.Value)" -ne '' -and "$($_.Value)" -ne 'False' }).Count -gt 0
                    switch ($act) {
                        'DLPRuleMatch' { $u.DlpMatches++; if ($hasOverride) { $u.DlpOverridesOrUndos++ } }
                        'DLPRuleUndo' { $u.DlpOverridesOrUndos++ }
                        'LabelChanged' { if ("$(Get-Prop $rec 'LabelEventType')" -match 'Downgrade') { $u.LabelDowngrades++ } }
                        'LabelRemoved' { $u.LabelRemovals++ }
                    }
                    $when = Get-Prop $rec 'Happened'
                    if ($when) { try { $dt = ([datetime]$when).ToUniversalTime(); if ($null -eq $u.FirstUtc -or $dt -lt $u.FirstUtc) { $u.FirstUtc = $dt }; if ($null -eq $u.LastUtc -or $dt -gt $u.LastUtc) { $u.LastUtc = $dt } } catch { } }
                }
                $records = $null
                if ("$($res.LastPage)" -eq 'True' -or -not $res.WaterMark) { break }
                if ($page -ge $ActivityMaxPages) { $truncated = $true; break }
                $cookie = $res.WaterMark
            }
            $actRows = @($byUser.Values | ForEach-Object { [pscustomobject][ordered]@{ User = $_.User; Events = $_.Events; DlpMatches = $_.DlpMatches; DlpOverridesOrUndos = $_.DlpOverridesOrUndos; LabelDowngrades = $_.LabelDowngrades; LabelRemovals = $_.LabelRemovals; Workloads = (@($_.Workloads) -join '; '); FirstUtc = $_.FirstUtc; LastUtc = $_.LastUtc } } | Sort-Object -Property @{ Expression = { $_.DlpOverridesOrUndos + $_.LabelDowngrades + $_.LabelRemovals }; Descending = $true }, User)
            $aNote = "Last $days day(s); counts only - no file names, paths or content are kept"
            if ($truncated) { $aNote += "; STOPPED after $ActivityMaxPages pages of 5000 events (raise -ActivityMaxPages)" }
            Export-Dataset -Name 'purview-activity-summary' -Rows $actRows -Status $(if ($truncated) { 'Partial' } else { 'Completed' }) -Note $aNote
        }
        catch { Set-DatasetStatus -Name 'purview-activity-summary' -Status $(if ($_.Exception.Message -match 'not recognized') { 'EvidenceUnavailable' } else { 'Blocked' }) -Note $_.Exception.Message }
    }

    # ---- 8. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric -Metric 'Sensitivity labels' @($labels).Count
    Add-Metric -Metric 'Sensitivity labels disabled' @($labels | Where-Object { "$($_.Disabled)" -eq 'True' }).Count
    Add-Metric -Metric 'Label policies' @($labelPolicies).Count
    Add-Metric -Metric 'Auto-labeling policies' @($autoPolicies).Count
    Add-Metric -Metric 'Auto-labeling policies on' @($autoPolicies | Where-Object { "$($_.Mode)" -eq 'Enable' }).Count
    Add-Metric -Metric 'Auto-labeling policies in simulation' @($autoPolicies | Where-Object { "$($_.Mode)" -like 'Test*' }).Count
    Add-Metric -Metric 'DLP policies' @($dlpPolicies).Count
    Add-Metric -Metric 'DLP policies on (enforced)' @($dlpPolicies | Where-Object { "$($_.Mode)" -eq 'Enable' }).Count
    Add-Metric -Metric 'DLP policies in simulation' @($dlpPolicies | Where-Object { "$($_.Mode)" -like 'Test*' }).Count
    Add-Metric -Metric 'DLP policies off' @($dlpPolicies | Where-Object { "$($_.Mode)" -eq 'Disable' }).Count
    Add-Metric -Metric 'DLP rules' @($dlpRules).Count
    Add-Metric -Metric 'DLP rules that let users override' @($dlpRules | Where-Object { Test-HasValue (Get-Prop $_ 'NotifyAllowOverride') }).Count
    Add-Metric -Metric 'Policy exclusions and rule exceptions' $exclRows.Count 'See policy-exclusions.csv'
    Add-Metric -Metric 'Sensitive information types' @($sitAll).Count
    Add-Metric -Metric 'Custom sensitive information types' @($sitAll | Where-Object { [string]$_.Publisher -notmatch '^Microsoft' }).Count
    if (-not $SkipRoleHolders) { Add-Metric -Metric 'Accounts in role groups that can view or export protected content' @($holderRows | Where-Object { $_.Member } | Select-Object -ExpandProperty Member -Unique).Count }
    Add-Metric -Metric 'Retention policies' @($retPolicies).Count
    Add-Metric -Metric 'Retention labels' @($retLabels).Count
    if ($IncludeContentExplorer) {
        foreach ($g in ($ceRows | Where-Object { "$($_.ItemCount)" -ne '' } | Group-Object TagName)) {
            Add-Metric -Metric ("Items tagged: {0}" -f $g.Name) (($g.Group | Measure-Object ItemCount -Sum).Sum) (($g.Group | ForEach-Object { '{0} {1}' -f $_.Workload, $_.ItemCount }) -join '; ')
        }
    }
    if ($IncludeActivityExplorer) {
        Add-Metric -Metric 'Users with DLP overrides or undos' @($actRows | Where-Object { $_.DlpOverridesOrUndos -gt 0 }).Count
        Add-Metric -Metric 'Users who downgraded or removed labels' @($actRows | Where-Object { ($_.LabelDowngrades + $_.LabelRemovals) -gt 0 }).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $orgName -Parameters @{ AuthMode = $AuthMode; Organization = $Organization; IncludeContentExplorer = [bool]$IncludeContentExplorer; ContentExplorerSits = $ContentExplorerSits; ContentExplorerLabels = [bool]$ContentExplorerLabels; Workloads = $Workloads; SkipRoleHolders = [bool]$SkipRoleHolders; IncludeActivityExplorer = [bool]$IncludeActivityExplorer; ActivityDays = $ActivityDays; ActivityMaxPages = $ActivityMaxPages }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
