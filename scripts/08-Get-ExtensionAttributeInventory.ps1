<#
.SYNOPSIS
    Read-only inventory of custom and extension attributes in AD and Entra ID, and of what reads them.

.DESCRIPTION
    Before an attribute is chosen to carry new data (for example the list of roles applied to a
    user by the joiner/mover/leaver automation), you need to know which attributes are already in
    use, by how many objects, in what format, and whether anything consumes them. This script
    reports that for:

      - AD users, groups, computers and contacts (-Classes): extensionAttribute1-15 plus any
        other attributes you list, with populated count and %, distinct values, maximum length,
        values per object, format hints (looks like a list / multi-valued / date / number / email)
        and a few sample values. Multi-valued attributes are counted per value.
      - Entra cloud-only users: onPremisesExtensionAttributes 1-15 (synced users mirror AD)
      - Entra devices: extensionAttributes 1-15
      - Entra directory (schema) extensions registered by apps (extension_<appId>_<name>),
        optionally with how many users hold a value
      - Entra custom security attribute definitions and how many users hold each (optional;
        needs its own permissions)
      - Consumers: dynamic group and dynamic administrative unit membership rules and
        Conditional Access device filters that reference each attribute

    An attribute that is populated on 0 objects is marked Unused. That does not prove nothing
    reads it: the consumer check covers Entra dynamic rules and Conditional Access device filters
    only. Exchange address lists, email address policies and dynamic distribution groups
    (extensionAttribute1-15 are Exchange custom attributes 1-15), Entra Connect sync rules and
    applications that query AD are not covered and must be checked before claiming one.

    READ-ONLY. Uses only Get-AD* cmdlets and Graph GET requests.

    Output: <OutputRoot>\08-ExtensionAttributes\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER SampleValueCount
    How many of the most common values to show per attribute. 0 suppresses samples (use this if
    values could contain personal data).

.PARAMETER Classes
    AD object classes to profile: User, Group, Computer, Contact.

.EXAMPLE
    .\08-Get-ExtensionAttributeInventory.ps1
.EXAMPLE
    .\08-Get-ExtensionAttributeInventory.ps1 -Classes User,Group -AdditionalAttributes employeeType,division -IncludeEntra -CountExtensionUsage
.EXAMPLE
    .\08-Get-ExtensionAttributeInventory.ps1 -SampleValueCount 0 -IncludeEntra -IncludeCustomSecurityAttributes

.NOTES
    Version : 1.1.1
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module.
              -IncludeEntra also needs Microsoft.Graph.Authentication with Directory.Read.All,
              Application.Read.All and Policy.Read.All (Conditional Access device filters).
              -IncludeCustomSecurityAttributes adds CustomSecAttributeDefinition.Read.All and
              CustomSecAttributeAssignment.Read.All with the Attribute Definition Reader and
              Attribute Assignment Reader roles.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                       # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                                   # blank = whole domain
    [string[]]$AdditionalAttributes = @('employeeType', 'employeeNumber', 'division', 'departmentNumber', 'info'),
    [switch]$IncludeCloudExtensionAttributes,                   # msDS-cloudExtensionAttribute1-20
    [ValidateSet('User', 'Group', 'Computer', 'Contact')]
    [string[]]$Classes = @('User', 'Group', 'Computer', 'Contact'),
    [switch]$IncludeGroups,                                     # accepted for compatibility; groups are in -Classes by default
    [ValidateRange(0, 20)]
    [int]$SampleValueCount = 3,

    [switch]$IncludeEntra,
    [switch]$CountExtensionUsage,
    [switch]$IncludeCustomSecurityAttributes,
    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '08-ExtensionAttributes'
$ScriptVersion = '1.1.1'
$RequiredScopes = @('Directory.Read.All', 'Application.Read.All', 'Policy.Read.All')
if ($IncludeCustomSecurityAttributes) { $RequiredScopes += @('CustomSecAttributeDefinition.Read.All', 'CustomSecAttributeAssignment.Read.All') }

#region ---- Common helpers (identical in every hybrid AD + Graph script; self-contained by design) ----
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

function Connect-DiscoveryGraph {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Module Microsoft.Graph.Authentication not found. Install it (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser) if your policy allows.'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    if ($AuthMode -eq 'AppCertificate') {
        if (-not $ClientId -or -not $CertificateThumbprint -or $TenantId -eq 'tenant-id-redacted') {
            throw 'AppCertificate mode needs -TenantId, -ClientId and -CertificateThumbprint.'
        }
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    }
    else {
        $connect = @{ Scopes = $RequiredScopes; NoWelcome = $true; ErrorAction = 'Stop' }
        if ($TenantId -and $TenantId -ne 'tenant-id-redacted') { $connect.TenantId = $TenantId }
        Connect-MgGraph @connect
    }
    $ctx = Get-MgContext
    Write-RunLog ("Connected. Tenant={0} Account={1} App={2} AuthType={3}" -f $ctx.TenantId, $ctx.Account, $ctx.ClientId, $ctx.AuthType)
    $missing = @($RequiredScopes | Where-Object { $ctx.Scopes -notcontains $_ })
    if ($missing.Count -gt 0) { Write-RunLog ("Scopes not present in token (some datasets may be Blocked): {0}" -f ($missing -join ', ')) 'WARN' }
    $writeScopes = @($ctx.Scopes | Where-Object { $_ -match 'ReadWrite|\.Write|FullControl' })
    if ($writeScopes.Count -gt 0) { Write-RunLog ("Token also carries write scopes from earlier consent: {0}. This script still only issues GET requests." -f ($writeScopes -join ', ')) 'WARN' }
    return $ctx
}

function Invoke-GraphGet {
    # The ONLY function that talks to Graph. Method is hard-coded to GET.
    # Retries up to 6 times with backoff on HTTP 408, 429 and 5xx, and on client-side timeouts
    # (HttpClient.Timeout, TaskCanceledException / OperationCanceledException, TimeoutException).
    param([Parameter(Mandatory)][string]$Uri, [hashtable]$Headers = @{})
    $attempt = 0
    while ($true) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers $Headers -OutputType PSObject -ErrorAction Stop
        }
        catch {
            $attempt++
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            # A timeout can arrive wrapped: walk the exception and its InnerException chain.
            $timedOut = $false
            $ex = $_.Exception
            while ($null -ne $ex) {
                if ($ex -is [System.OperationCanceledException] -or $ex -is [System.TimeoutException] -or "$($ex.Message)" -match 'HttpClient\.Timeout|The request was canceled|timed out') { $timedOut = $true; break }
                $ex = $ex.InnerException
            }
            if (($status -eq 408 -or $status -eq 429 -or $status -ge 500 -or $timedOut) -and $attempt -le 6) {
                $wait = [int][math]::Min(120, [math]::Pow(2, $attempt))
                try { $ra = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds; if ($ra) { $wait = [int][math]::Ceiling($ra) } } catch { }
                $reason = $(if ($status) { "HTTP $status" } else { 'Client timeout' })
                Write-RunLog ("{0} on {1}; retry {2}/6 in {3}s" -f $reason, $Uri, $attempt, $wait) 'WARN'
                Start-Sleep -Seconds $wait
            }
            else { throw }
        }
    }
}

function Invoke-GraphGetAll {
    # Follows @odata.nextLink until done (or MaxRecords reached). Returns a List[object].
    param([Parameter(Mandatory)][string]$Uri, [switch]$Eventual, [int]$MaxRecords = 0, [string]$Label = '')
    $headers = @{}
    if ($Eventual) { $headers['ConsistencyLevel'] = 'eventual' }
    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $script:LastQueryTruncated = $false
    while ($next) {
        $resp = Invoke-GraphGet -Uri $next -Headers $headers
        if ($resp.PSObject.Properties.Name -contains 'value') { foreach ($item in @($resp.value)) { if ($null -ne $item) { $results.Add($item) } } }
        else { $results.Add($resp); break }
        if ($MaxRecords -gt 0 -and $results.Count -ge $MaxRecords) {
            $script:LastQueryTruncated = $true
            Write-RunLog ("{0}: stopped at MaxRecords={1}; result is TRUNCATED." -f $Label, $MaxRecords) 'WARN'
            break
        }
        $next = $null
        if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $next = $resp.'@odata.nextLink' }
    }
    return , $results
}

function Get-FailureStatus {
    # Maps an exception to the engagement status vocabulary.
    param($ErrorRecord)
    $msg = "$($ErrorRecord.Exception.Message) $($ErrorRecord.ErrorDetails.Message)"
    if ($msg -match 'Premium|licen[cs]e|P1|P2|NonPremium|not available for this tenant') { return 'EvidenceUnavailable' }
    if ($msg -match '403|Forbidden|Authorization_RequestDenied|Insufficient privileges|AccessDenied') { return 'Blocked' }
    return 'Blocked'
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
    param([string]$DomainName, $Context, [hashtable]$Parameters)
    $manifest = [ordered]@{
        Script        = $ScriptName
        ScriptVersion = $ScriptVersion
        StartedUtc    = $script:RunStartUtc.ToString('o')
        FinishedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        RunAsWindows  = [Environment]::UserDomainName + '\' + [Environment]::UserName
        Machine       = [Environment]::MachineName
        PowerShell    = $PSVersionTable.PSVersion.ToString()
        Domain        = $DomainName
        Server        = $Server
        AuthMode      = $AuthMode
        TenantId      = $(if ($Context) { $Context.TenantId } else { '' })
        GraphAccount  = $(if ($Context) { $Context.Account } else { '' })
        GraphClientId = $(if ($Context) { $Context.ClientId } else { '' })
        ScopesInToken = $(if ($Context) { @($Context.Scopes) } else { @() })
        Parameters    = $Parameters
        Datasets      = $script:Datasets.ToArray()
    }
    if ($script:ManifestExtra) { $manifest['Extra'] = $script:ManifestExtra }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $script:RunFolder 'run-manifest.json') -Encoding UTF8
    $script:Datasets | Export-Csv -Path (Join-Path $script:RunFolder 'dataset-status.csv') -NoTypeInformation -Encoding UTF8
}

function Join-Values { param($Values) if ($null -eq $Values) { return '' } return (@($Values) | Where-Object { $null -ne $_ -and "$_" -ne '' }) -join '; ' }

$script:ObjectCache = @{}
function Resolve-DirectoryObject {
    # GET /directoryObjects/{id} with cache. Returns display label or the raw id if not resolvable.
    param([string]$Id)
    if (-not $Id) { return '' }
    if ($Id -in @('All', 'None', 'GuestsOrExternalUsers', 'AllTrusted', 'Office365', 'MicrosoftAdminPortals')) { return $Id }
    if ($script:ObjectCache.ContainsKey($Id)) { return $script:ObjectCache[$Id] }
    $label = $Id
    try {
        $o = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/directoryObjects/{0}" -f $Id)
        $name = $o.displayName
        if ($o.PSObject.Properties.Name -contains 'userPrincipalName' -and $o.userPrincipalName) { $name = $o.userPrincipalName }
        $label = '{0} ({1})' -f $name, ($o.'@odata.type' -replace '#microsoft.graph.', '')
    }
    catch { $label = "$Id (unresolved/deleted)" }
    $script:ObjectCache[$Id] = $label
    return $label
}

# Splat for every AD cmdlet so -Server is honoured consistently.
$script:AdParams = @{}
if ($Server) { $script:AdParams['Server'] = $Server }
#endregion

function Get-AttrValues {
    # Returns every value an object holds for an attribute as strings (multi-valued attributes give several).
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return @() }
    $v = $Obj.$Name
    if ($null -eq $v) { return @() }
    if ($v -is [string]) { if ([string]::IsNullOrWhiteSpace($v)) { return @() } return @($v) }
    if ($v -is [byte[]]) { return @([Convert]::ToBase64String($v)) }
    if ($v -is [System.Collections.IEnumerable]) { return @($v | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace("$_") } | ForEach-Object { "$_" }) }
    if ([string]::IsNullOrWhiteSpace("$v")) { return @() }
    return @("$v")
}

function Get-ValueProfile {
    # Summarises the values of one attribute across objects. $PerObject holds one string array per
    # object, so multi-valued attributes are counted per value and per object correctly.
    param([object[]]$PerObject, [int]$Total)
    $objWithValue = 0; $maxPer = 0
    $vals = [System.Collections.Generic.List[string]]::new()
    foreach ($arr in @($PerObject)) {
        $a = @($arr | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($a.Count) { $objWithValue++; if ($a.Count -gt $maxPer) { $maxPer = $a.Count }; foreach ($x in $a) { $vals.Add([string]$x) } }
    }
    $counts = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    foreach ($v in $vals) { if ($counts.ContainsKey($v)) { $counts[$v]++ } else { $counts[$v] = 1 } }
    $n = $vals.Count
    $hint = @()
    if ($n -gt 0) {
        $share = { param($rx) @($vals | Where-Object { $_ -match $rx }).Count / $n }
        if ($maxPer -gt 1) { $hint += 'MultiValued' }
        if ((& $share '[;,|]') -ge 0.5) { $hint += 'List' }
        if ((& $share '^\d{4}-\d{2}-\d{2}|^\d{1,2}/\d{1,2}/\d{2,4}') -ge 0.5) { $hint += 'Date' }
        if ((& $share '^-?\d+(\.\d+)?$') -ge 0.5) { $hint += 'Number' }
        if ((& $share '^([a-z]+:)?[^@\s:]+@[^@\s]+\.[^@\s]+$') -ge 0.5) { $hint += 'Email' }
        if ($counts.Count -le 5 -and $objWithValue -ge 20) { $hint += 'LowCardinality' }
        if ($counts.Count -eq $n -and $objWithValue -ge 20) { $hint += 'UniquePerObject' }
    }
    $samples = ''
    if ($SampleValueCount -gt 0 -and $counts.Count -gt 0) {
        $samples = Join-Values ($counts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $SampleValueCount | ForEach-Object {
                $s = $_.Key; if ($s.Length -gt 60) { $s = $s.Substring(0, 57) + '...' }
                '{0} ({1})' -f $s, $_.Value })
    }
    [pscustomobject]@{
        Populated          = $objWithValue
        PopulatedPct       = $(if ($Total -gt 0) { [math]::Round(100 * $objWithValue / $Total, 1) } else { 0 })
        DistinctValues     = $counts.Count
        MaxLength          = $(if ($n) { ($vals | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum } else { 0 })
        FormatHints        = Join-Values $hint
        SampleValues       = $samples
        Status             = $(if ($objWithValue -eq 0) { 'Unused' } elseif ($objWithValue / [math]::Max(1, $Total) -lt 0.01) { 'Rare' } else { 'InUse' })
        MaxValuesPerObject = $maxPer
    }
}

function New-UsageRow {
    param([string]$Source, [string]$ObjectType, [string]$Attribute, [object[]]$Objects)
    $per = @(foreach ($o in @($Objects)) { , @(Get-AttrValues $o $Attribute) })
    $prof = Get-ValueProfile -PerObject $per -Total @($Objects).Count
    $o = [ordered]@{ Source = $Source; ObjectType = $ObjectType; Attribute = $Attribute; Objects = @($Objects).Count }
    foreach ($pp in $prof.PSObject.Properties) { $o[$pp.Name] = $pp.Value }
    $o['KnownConsumers'] = ''
    return [pscustomobject]$o
}

function Get-RuleAttributes {
    # Attribute references in an Entra dynamic membership rule or device filter, e.g.
    # user.extensionAttribute1, user.onPremisesExtensionAttributes.extensionAttribute10,
    # user.extension_<appid>_name, device.extensionAttribute2, user.employeeType.
    param([string]$Rule)
    $out = @()
    if (-not $Rule) { return $out }
    foreach ($m in [regex]::Matches($Rule, '(?i)\b(user|device)\.((?:onPremisesExtensionAttributes\.)?[A-Za-z0-9_]+)')) {
        $target = $m.Groups[1].Value.ToLowerInvariant()
        $attr = $m.Groups[2].Value -replace '(?i)^onPremisesExtensionAttributes\.', ''
        if ($attr -match '(?i)^extensionAttribute(\d+)$') { $attr = 'extensionAttribute' + $Matches[1] }
        $out += [pscustomobject]@{ Target = $target; Attribute = $attr; Raw = $m.Value }
    }
    return @($out | Sort-Object Target, Attribute -Unique)
}

function Get-RuleExcerpt { param([string]$Rule) if (-not $Rule) { return '' } $r = ($Rule -replace '\s+', ' ').Trim(); if ($r.Length -gt 200) { return $r.Substring(0, 197) + '...' } return $r }

$domainName = ''
$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if ($IncludeGroups -and $Classes -notcontains 'Group') { $Classes += 'Group' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot

    $attrs = @(1..15 | ForEach-Object { "extensionAttribute$_" })
    if ($IncludeCloudExtensionAttributes) { $attrs += @(1..20 | ForEach-Object { "msDS-cloudExtensionAttribute$_" }) }
    $attrs += @($AdditionalAttributes | Where-Object { $_ })
    $attrs = @($attrs | Select-Object -Unique)

    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }

    # ---- 1. AD usage ----
    $usageRows = [System.Collections.Generic.List[object]]::new()
    $unreadableClasses = [System.Collections.Generic.List[string]]::new()
    $getters = @{
        User     = { param($a) Get-ADUser -Filter * -Properties $a @p }
        Group    = { param($a) Get-ADGroup -Filter * -Properties $a @p }
        Computer = { param($a) Get-ADComputer -Filter * -Properties $a @p }
        Contact  = { param($a) Get-ADObject -LDAPFilter '(objectClass=contact)' -Properties $a @p }
    }
    foreach ($type in @('User', 'Group', 'Computer', 'Contact' | Where-Object { $Classes -contains $_ })) {
        Write-RunLog ("Reading AD {0} objects..." -f $type)
        $objs = $null
        try { $objs = @(& $getters[$type] $attrs) }
        catch {
            # An attribute not in the schema (for this class) makes the whole query fail; retry one attribute at a time.
            Write-RunLog ("{0}: bulk read failed ({1}); retrying per attribute." -f $type, $_.Exception.Message) 'WARN'
            $objs = $null
        }
        if ($null -ne $objs) {
            foreach ($a in $attrs) { $usageRows.Add((New-UsageRow -Source 'AD' -ObjectType $type -Attribute $a -Objects $objs)) }
        }
        else {
            $classFailed = 0
            foreach ($a in $attrs) {
                try { $one = @(& $getters[$type] $a); $usageRows.Add((New-UsageRow -Source 'AD' -ObjectType $type -Attribute $a -Objects $one)) }
                catch {
                    $classFailed++
                    $st = $(if ($_.Exception.Message -match 'invalid|not.*schema|Parameter name') { 'NotInSchema' } else { 'Unreadable' })
                    $usageRows.Add([pscustomobject][ordered]@{ Source = 'AD'; ObjectType = $type; Attribute = $a; Objects = ''; Populated = ''; PopulatedPct = ''; DistinctValues = ''; MaxLength = ''; FormatHints = ''; SampleValues = ''; Status = $st; MaxValuesPerObject = ''; KnownConsumers = '' })
                }
            }
            if ($classFailed -eq $attrs.Count) { $unreadableClasses.Add($type); Write-RunLog ("{0}: no attribute could be read; rows marked NotInSchema / Unreadable." -f $type) 'WARN' }
        }
    }

    # ---- 2. Entra ----
    $consumers = [System.Collections.Generic.List[object]]::new()
    $consumerStatus = 'Deferred'
    $consumerParts = [System.Collections.Generic.List[string]]::new()
    $deviceRows = @()
    $entraNames = @('entra-cloudonly-extension-usage', 'entra-device-extension-usage', 'entra-directory-extensions', 'entra-custom-security-attributes', 'attribute-consumers')
    if (-not $IncludeEntra) {
        foreach ($n in $entraNames) { Set-DatasetStatus -Name $n -Status 'Deferred' -Note 'Run with -IncludeEntra' }
    }
    else {
        $connected = $false
        try { $ctx = Connect-DiscoveryGraph; $connected = $true }
        catch { foreach ($n in $entraNames) { Set-DatasetStatus -Name $n -Status 'Blocked' -Note ("Graph connection failed: {0}" -f $_.Exception.Message) }; $consumerStatus = 'Blocked' }
        if ($connected) {
            # 2a. Cloud-only users' onPremisesExtensionAttributes
            try {
                $eu = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,onPremisesSyncEnabled,onPremisesExtensionAttributes&$top=999' -Label 'users'
                $cloud = @($eu | Where-Object { -not $_.onPremisesSyncEnabled })
                $ea = @($cloud | ForEach-Object { if ($_.onPremisesExtensionAttributes) { $_.onPremisesExtensionAttributes } else { [pscustomobject]@{} } })
                $rows = foreach ($i in 1..15) { New-UsageRow -Source 'Entra' -ObjectType 'CloudOnlyUser' -Attribute "extensionAttribute$i" -Objects $ea }
                Export-Dataset -Name 'entra-cloudonly-extension-usage' -Rows @($rows | Select-Object Source, ObjectType, Attribute, Objects, Populated, PopulatedPct, DistinctValues, MaxLength, FormatHints, SampleValues, Status) -Note ("{0} cloud-only of {1} users; synced users mirror AD" -f $cloud.Count, $eu.Count)
            }
            catch { Set-DatasetStatus -Name 'entra-cloudonly-extension-usage' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

            # 2b. Entra devices' extensionAttributes
            try {
                $devs = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/devices?$select=id,displayName,extensionAttributes&$top=999' -Label 'devices'
                $dea = @($devs | ForEach-Object { if ($_.extensionAttributes) { $_.extensionAttributes } else { [pscustomobject]@{} } })
                $deviceRows = @(foreach ($i in 1..15) { New-UsageRow -Source 'Entra' -ObjectType 'Device' -Attribute "extensionAttribute$i" -Objects $dea })
            }
            catch { $deviceRows = $null; Set-DatasetStatus -Name 'entra-device-extension-usage' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

            # 2c. Directory (schema) extensions registered by apps
            try {
                $apps = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName' -Label 'applications'
                $extRows = [System.Collections.Generic.List[object]]::new()
                $appFail = [System.Collections.Generic.List[string]]::new()
                foreach ($a in $apps) {
                    $props = @()
                    try { $props = (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/extensionProperties" -f $a.id) -Label "extensionProperties $($a.id)") }
                    catch { $appFail.Add([string]$a.displayName); Write-RunLog ("extensionProperties of app {0} ({1}) not readable: {2}" -f $a.displayName, $a.appId, $_.Exception.Message) 'WARN'; continue }
                    foreach ($x in $props) {
                        $count = ''
                        if ($CountExtensionUsage -and (@($x.targetObjects) -contains 'User')) {
                            try {
                                $withVal = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users?`$select=id,{0}&`$top=999" -f $x.name) -Label $x.name
                                $count = @($withVal | Where-Object { $null -ne $_.($x.name) -and "$($_.($x.name))" -ne '' }).Count
                            }
                            catch { $count = 'unreadable' }
                        }
                        $extRows.Add([pscustomobject][ordered]@{
                            ExtensionName           = $x.name
                            DataType                = $x.dataType
                            TargetObjects           = Join-Values $x.targetObjects
                            IsSyncedFromOnPremises  = $x.isSyncedFromOnPremises
                            OwningApp               = $a.displayName
                            OwningAppId             = $a.appId
                            UsersWithValue          = $count
                            KnownConsumers          = ''
                        })
                    }
                }
                $extNote = $(if ($CountExtensionUsage) { 'UsersWithValue counted' } else { 'Run with -CountExtensionUsage to count users holding each' })
                if ($appFail.Count) { $extNote += ("; PARTIAL: extension properties of {0} app(s) not readable ({1})" -f $appFail.Count, ($appFail -join ', ')) }
                $script:ExtRows = $extRows
                $script:ExtNote = $extNote
            }
            catch { $script:ExtRows = $null; Set-DatasetStatus -Name 'entra-directory-extensions' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

            # 2d. Custom security attribute definitions and holders
            if (-not $IncludeCustomSecurityAttributes) { Set-DatasetStatus -Name 'entra-custom-security-attributes' -Status 'Deferred' -Note 'Run with -IncludeCustomSecurityAttributes' }
            else {
                try {
                    $csa = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/directory/customSecurityAttributeDefinitions' -Label 'customSecurityAttributeDefinitions'
                    $holders = @{}; $holderEvidence = 'Counted (users)'
                    try {
                        $cu = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,customSecurityAttributes&$top=999' -Eventual -Label 'users customSecurityAttributes'
                        foreach ($u in $cu) {
                            if (-not $u.customSecurityAttributes) { continue }
                            foreach ($set in $u.customSecurityAttributes.PSObject.Properties) {
                                if ($set.Name -like '*@*' -or $null -eq $set.Value) { continue }
                                foreach ($at in $set.Value.PSObject.Properties) {
                                    if ($at.Name -like '*@*') { continue }
                                    $k = '{0}.{1}' -f $set.Name, $at.Name
                                    if ($holders.ContainsKey($k)) { $holders[$k]++ } else { $holders[$k] = 1 }
                                }
                            }
                        }
                    }
                    catch { $holders = $null; $holderEvidence = 'EvidenceUnavailable: ' + $_.Exception.Message; Write-RunLog ("Custom security attribute values not readable (CustomSecAttributeAssignment.Read.All + Attribute Assignment Reader): {0}" -f $_.Exception.Message) 'WARN' }
                    $csaRows = foreach ($d in $csa) {
                        $k = '{0}.{1}' -f $d.attributeSet, $d.name
                        [pscustomobject][ordered]@{
                            AttributeSet            = $d.attributeSet
                            Name                    = $d.name
                            Type                    = $d.type
                            Status                  = $d.status
                            IsCollection            = $d.isCollection
                            UsePreDefinedValuesOnly = $d.usePreDefinedValuesOnly
                            Description             = $d.description
                            UsersWithValue          = $(if ($null -eq $holders) { 'EvidenceUnavailable' } elseif ($holders.ContainsKey($k)) { $holders[$k] } else { 0 })
                            HolderEvidence          = $holderEvidence
                        }
                    }
                    Export-Dataset -Name 'entra-custom-security-attributes' -Rows $csaRows -Note 'Custom security attributes apply to cloud users and service principals only; not to synced users or groups. UsersWithValue counts users, not service principals'
                }
                catch { Set-DatasetStatus -Name 'entra-custom-security-attributes' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }
            }

            # 2e. Consumers: dynamic groups, dynamic administrative units, Conditional Access device filters
            $consumerStatus = 'Completed'
            try {
                $dyn = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c eq 'DynamicMembership')&`$count=true&`$select=id,displayName,membershipRule,membershipRuleProcessingState&`$top=999" -Eventual -Label 'dynamic groups'
                foreach ($g in $dyn) {
                    foreach ($ra in (Get-RuleAttributes $g.membershipRule)) {
                        $consumers.Add([pscustomobject][ordered]@{ Attribute = $ra.Attribute; ConsumerType = 'DynamicGroup'; ConsumerName = $g.displayName; Rule = Get-RuleExcerpt $g.membershipRule; Target = $ra.Target; ConsumerState = [string]$g.membershipRuleProcessingState; ConsumerId = $g.id })
                    }
                }
                $consumerParts.Add(("{0} dynamic groups" -f @($dyn).Count))
            }
            catch { $consumerStatus = 'Partial'; $consumerParts.Add('dynamic groups NOT READ (' + $_.Exception.Message + ')'); Write-RunLog ("Dynamic groups not readable: {0}" -f $_.Exception.Message) 'WARN' }
            try {
                $aus = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=id,displayName,membershipType,membershipRule' -Label 'administrativeUnits'
                $dynAu = @($aus | Where-Object { $_.membershipType -eq 'Dynamic' -or $_.membershipRule })
                foreach ($au in $dynAu) {
                    foreach ($ra in (Get-RuleAttributes $au.membershipRule)) {
                        $consumers.Add([pscustomobject][ordered]@{ Attribute = $ra.Attribute; ConsumerType = 'DynamicAdministrativeUnit'; ConsumerName = $au.displayName; Rule = Get-RuleExcerpt $au.membershipRule; Target = $ra.Target; ConsumerState = ''; ConsumerId = $au.id })
                    }
                }
                $consumerParts.Add(("{0} dynamic administrative units" -f $dynAu.Count))
            }
            catch { $consumerStatus = 'Partial'; $consumerParts.Add('administrative units NOT READ (' + $_.Exception.Message + ')'); Write-RunLog ("Administrative units not readable: {0}" -f $_.Exception.Message) 'WARN' }
            try {
                $pol = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'conditionalAccess policies'
                $withFilter = 0
                foreach ($cp in $pol) {
                    $rule = $null
                    try { $rule = $cp.conditions.devices.deviceFilter.rule } catch { $rule = $null }
                    if (-not $rule) { continue }
                    $withFilter++
                    foreach ($ra in (Get-RuleAttributes $rule)) {
                        $consumers.Add([pscustomobject][ordered]@{ Attribute = $ra.Attribute; ConsumerType = 'ConditionalAccessDeviceFilter'; ConsumerName = $cp.displayName; Rule = Get-RuleExcerpt ("{0}: {1}" -f $cp.conditions.devices.deviceFilter.mode, $rule); Target = $ra.Target; ConsumerState = [string]$cp.state; ConsumerId = $cp.id })
                    }
                }
                $consumerParts.Add(("{0} CA policies ({1} with a device filter)" -f @($pol).Count, $withFilter))
            }
            catch { $consumerStatus = 'Partial'; $consumerParts.Add('Conditional Access NOT READ (' + $_.Exception.Message + ')'); Write-RunLog ("Conditional Access policies not readable (Policy.Read.All): {0}" -f $_.Exception.Message) 'WARN' }
            if ($consumerStatus -eq 'Partial' -and $consumerParts.Count -and -not @($consumerParts | Where-Object { $_ -notmatch 'NOT READ' }).Count) { $consumerStatus = 'Blocked' }
            $cNote = 'Read: ' + ($consumerParts -join '; ') + '. Not covered: Exchange address lists, email address policies, dynamic distribution groups (need Exchange), Entra Connect sync rules, applications reading AD'
            if ($consumerStatus -eq 'Blocked') { Set-DatasetStatus -Name 'attribute-consumers' -Status 'Blocked' -Note $cNote }
            else { Export-Dataset -Name 'attribute-consumers' -Rows @($consumers | Sort-Object Attribute, ConsumerType, ConsumerName) -Note $(if ($consumerStatus -eq 'Partial') { 'PARTIAL. ' + $cNote } else { $cNote }) }
        }
    }

    # ---- 3. Join consumers onto usage rows ----
    function Get-ConsumerCount {
        param([string]$Attribute, [string]$Target)
        if ($consumerStatus -eq 'Deferred') { return '' }
        if ($consumerStatus -eq 'Blocked') { return 'Unknown' }
        $c = @($consumers | Where-Object { $_.Target -eq $Target -and $_.Attribute -eq $Attribute }).Count
        if ($c -eq 0 -and $consumerStatus -eq 'Partial') { return 'Unknown (Partial)' }
        return $c
    }
    foreach ($r in $usageRows) { if ($r.ObjectType -eq 'User') { $r.KnownConsumers = Get-ConsumerCount $r.Attribute 'user' } }
    $usageNote = $(if ($SampleValueCount -eq 0) { 'Sample values suppressed' } else { "Top $SampleValueCount values shown; may contain personal data" })
    if ($unreadableClasses.Count) { $usageNote = ('PARTIAL: {0} not readable (Status Unreadable / NotInSchema); ' -f ($unreadableClasses -join ', ')) + $usageNote }
    Export-Dataset -Name 'ad-attribute-usage' -Rows $usageRows -Note $usageNote
    if ($IncludeEntra -and $null -ne $deviceRows -and @($deviceRows).Count) {
        foreach ($r in $deviceRows) { $r.KnownConsumers = Get-ConsumerCount $r.Attribute 'device' }
        Export-Dataset -Name 'entra-device-extension-usage' -Rows $deviceRows -Note 'Entra device extensionAttributes are set in Entra (Graph / Intune), not synced from AD computers'
    }
    if ($IncludeEntra -and $script:ExtRows) {
        foreach ($r in $script:ExtRows) { $r.KnownConsumers = Get-ConsumerCount $r.ExtensionName 'user' }
        Export-Dataset -Name 'entra-directory-extensions' -Rows $script:ExtRows -Note $script:ExtNote
    }
    elseif ($IncludeEntra -and $null -ne $script:ExtRows) { Export-Dataset -Name 'entra-directory-extensions' -Rows @() -Note $script:ExtNote }

    # ---- 4. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    foreach ($t in @($usageRows | Select-Object -ExpandProperty ObjectType -Unique)) {
        $r = @($usageRows | Where-Object ObjectType -eq $t)
        Add-Metric "AD $t attributes checked" $r.Count
        $allBad = (@($r | Where-Object Status -eq 'Unreadable').Count -eq $r.Count)
        Add-Metric -Metric "AD $t attributes unused" -Value $(if ($allBad) { '' } else { @($r | Where-Object Status -eq 'Unused').Count }) -Note $(if ($allBad) { 'Not readable' } else { 'Candidates for new data - verify nothing reads them' })
        Add-Metric "AD $t attributes unused (names)" (Join-Values ($r | Where-Object Status -eq 'Unused' | Select-Object -ExpandProperty Attribute))
        Add-Metric "AD $t attributes rare (<1%)" (Join-Values ($r | Where-Object Status -eq 'Rare' | Select-Object -ExpandProperty Attribute))
        Add-Metric "AD $t attributes not in schema" (Join-Values ($r | Where-Object Status -eq 'NotInSchema' | Select-Object -ExpandProperty Attribute))
        $ur = @($r | Where-Object Status -eq 'Unreadable' | Select-Object -ExpandProperty Attribute)
        if ($ur.Count) { Add-Metric -Metric "AD $t attributes unreadable" -Value (Join-Values $ur) -Note 'Read failed; not evidence of Unused' }
        $mv = @($r | Where-Object { $_.FormatHints -match 'MultiValued' } | Select-Object -ExpandProperty Attribute)
        if ($mv.Count) { Add-Metric "AD $t attributes multi-valued" (Join-Values $mv) }
    }
    if ($consumerStatus -ne 'Deferred') {
        Add-Metric -Metric 'Attribute consumer check' -Value $consumerStatus -Note (Join-Values $consumerParts)
        Add-Metric 'Attributes referenced by a dynamic rule or CA device filter' (Join-Values (@($consumers | ForEach-Object { '{0}.{1}' -f $_.Target, $_.Attribute }) | Sort-Object -Unique))
        $unusedRef = @($usageRows | Where-Object { $_.ObjectType -eq 'User' -and $_.Status -eq 'Unused' -and "$($_.KnownConsumers)" -match '^[1-9]' } | Select-Object -ExpandProperty Attribute)
        Add-Metric -Metric 'AD user attributes unused but referenced by a rule' -Value (Join-Values $unusedRef) -Note 'Not free: a rule already reads them'
    }
    Add-Metric -Metric 'Consumers not covered' -Value 'Exchange address lists / email address policies / dynamic distribution groups; Entra Connect sync rules; applications reading AD' -Note 'Check these before claiming an attribute'
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Context $ctx -Parameters @{ SearchBase = $SearchBase; AdditionalAttributes = $AdditionalAttributes; IncludeCloudExtensionAttributes = [bool]$IncludeCloudExtensionAttributes; Classes = $Classes; IncludeGroups = [bool]$IncludeGroups; SampleValueCount = $SampleValueCount; IncludeEntra = [bool]$IncludeEntra; CountExtensionUsage = [bool]$CountExtensionUsage; IncludeCustomSecurityAttributes = [bool]$IncludeCustomSecurityAttributes }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
