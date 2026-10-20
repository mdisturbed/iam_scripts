<#
.SYNOPSIS
    Read-only inventory of custom and extension attributes in AD and Entra ID.

.DESCRIPTION
    Before an attribute is chosen to carry new data (for example the list of roles applied to a
    user by the joiner/mover/leaver automation), you need to know which attributes are already in
    use, by how many objects, and in what format. This script reports that for:

      - AD users (and optionally groups): extensionAttribute1-15 plus any other attributes you
        list, with populated count and %, distinct values, maximum length, format hints
        (looks like a list / date / number / email) and a few sample values
      - Entra cloud-only users: onPremisesExtensionAttributes 1-15 (synced users mirror AD)
      - Entra directory (schema) extensions registered by apps (extension_<appId>_<name>),
        optionally with how many users hold a value
      - Entra custom security attribute definitions (optional; needs its own permission)

    An attribute that is populated on 0 objects is marked Unused. That does not prove nothing
    reads it: check Entra Connect sync rules, Exchange (extensionAttribute1-15 are Exchange
    custom attributes 1-15) and any app that queries AD before claiming one.

    READ-ONLY. Uses only Get-AD* cmdlets and Graph GET requests.

    Output: <OutputRoot>\08-ExtensionAttributes\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER SampleValueCount
    How many of the most common values to show per attribute. 0 suppresses samples (use this if
    values could contain personal data).

.EXAMPLE
    .\08-Get-ExtensionAttributeInventory.ps1
.EXAMPLE
    .\08-Get-ExtensionAttributeInventory.ps1 -IncludeGroups -AdditionalAttributes employeeType,division -IncludeEntra -CountExtensionUsage
.EXAMPLE
    .\08-Get-ExtensionAttributeInventory.ps1 -SampleValueCount 0 -IncludeEntra -IncludeCustomSecurityAttributes

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module.
              -IncludeEntra also needs Microsoft.Graph.Authentication with Directory.Read.All and
              Application.Read.All. -IncludeCustomSecurityAttributes adds
              CustomSecAttributeDefinition.Read.All and the Attribute Definition Reader role.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                       # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                                   # blank = whole domain
    [string[]]$AdditionalAttributes = @('employeeType', 'employeeNumber', 'division', 'departmentNumber', 'info'),
    [switch]$IncludeCloudExtensionAttributes,                   # msDS-cloudExtensionAttribute1-20
    [switch]$IncludeGroups,
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
$ScriptVersion = '1.0.0'
$RequiredScopes = @('Directory.Read.All', 'Application.Read.All')
if ($IncludeCustomSecurityAttributes) { $RequiredScopes += 'CustomSecAttributeDefinition.Read.All' }

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
            if (($status -eq 429 -or $status -ge 500) -and $attempt -le 6) {
                $wait = [int][math]::Min(120, [math]::Pow(2, $attempt))
                try { $ra = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds; if ($ra) { $wait = [int][math]::Ceiling($ra) } } catch { }
                Write-RunLog ("HTTP {0} on {1}; retry {2}/6 in {3}s" -f $status, $Uri, $attempt, $wait) 'WARN'
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

function Get-ValueProfile {
    # Summarises a list of string values: counts, length and format hints.
    param([string[]]$Values, [int]$Total)
    $vals = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $counts = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    foreach ($v in $vals) { if ($counts.ContainsKey($v)) { $counts[$v]++ } else { $counts[$v] = 1 } }
    $n = $vals.Count
    $hint = @()
    if ($n -gt 0) {
        $share = { param($rx) @($vals | Where-Object { $_ -match $rx }).Count / $n }
        if ((& $share '[;,|]') -ge 0.5) { $hint += 'List' }
        if ((& $share '^\d{4}-\d{2}-\d{2}|^\d{1,2}/\d{1,2}/\d{2,4}') -ge 0.5) { $hint += 'Date' }
        if ((& $share '^-?\d+(\.\d+)?$') -ge 0.5) { $hint += 'Number' }
        if ((& $share '^[^@\s]+@[^@\s]+\.[^@\s]+$') -ge 0.5) { $hint += 'Email' }
        if ($counts.Count -le 5 -and $n -ge 20) { $hint += 'LowCardinality' }
        if ($counts.Count -eq $n -and $n -ge 20) { $hint += 'UniquePerObject' }
    }
    $samples = ''
    if ($SampleValueCount -gt 0 -and $counts.Count -gt 0) {
        $samples = Join-Values ($counts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $SampleValueCount | ForEach-Object {
                $s = $_.Key; if ($s.Length -gt 60) { $s = $s.Substring(0, 57) + '...' }
                '{0} ({1})' -f $s, $_.Value })
    }
    [pscustomobject]@{
        Populated      = $n
        PopulatedPct   = $(if ($Total -gt 0) { [math]::Round(100 * $n / $Total, 1) } else { 0 })
        DistinctValues = $counts.Count
        MaxLength      = $(if ($n) { ($vals | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum } else { 0 })
        FormatHints    = Join-Values $hint
        SampleValues   = $samples
        Status         = $(if ($n -eq 0) { 'Unused' } elseif ($n / [math]::Max(1, $Total) -lt 0.01) { 'Rare' } else { 'InUse' })
    }
}

$domainName = ''
$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
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
    $objectSets = @(@{ Type = 'User'; Get = { Get-ADUser -Filter * -Properties $attrs @p } })
    if ($IncludeGroups) { $objectSets += @{ Type = 'Group'; Get = { Get-ADGroup -Filter * -Properties $attrs @p } } }
    foreach ($set in $objectSets) {
        Write-RunLog ("Reading AD {0} objects..." -f $set.Type)
        $objs = @()
        try { $objs = @(& $set.Get) }
        catch {
            # An attribute not in the schema makes the whole query fail; retry one attribute at a time.
            Write-RunLog ("Bulk read failed ({0}); retrying per attribute." -f $_.Exception.Message) 'WARN'
            $objs = $null
        }
        if ($null -ne $objs) {
            foreach ($a in $attrs) {
                $prof = Get-ValueProfile -Values @($objs | ForEach-Object { "$($_.$a)" }) -Total $objs.Count
                $o = [ordered]@{ Source = 'AD'; ObjectType = $set.Type; Attribute = $a; Objects = $objs.Count }
                foreach ($pp in $prof.PSObject.Properties) { $o[$pp.Name] = $pp.Value }
                $usageRows.Add([pscustomobject]$o)
            }
        }
        else {
            foreach ($a in $attrs) {
                try {
                    $one = $(if ($set.Type -eq 'User') { @(Get-ADUser -Filter * -Properties $a @p) } else { @(Get-ADGroup -Filter * -Properties $a @p) })
                    $prof = Get-ValueProfile -Values @($one | ForEach-Object { "$($_.$a)" }) -Total $one.Count
                    $o = [ordered]@{ Source = 'AD'; ObjectType = $set.Type; Attribute = $a; Objects = $one.Count }
                    foreach ($pp in $prof.PSObject.Properties) { $o[$pp.Name] = $pp.Value }
                    $usageRows.Add([pscustomobject]$o)
                }
                catch {
                    $usageRows.Add([pscustomobject][ordered]@{ Source = 'AD'; ObjectType = $set.Type; Attribute = $a; Objects = ''; Populated = ''; PopulatedPct = ''; DistinctValues = ''; MaxLength = ''; FormatHints = ''; SampleValues = ''; Status = 'NotInSchema' })
                }
            }
        }
    }
    Export-Dataset -Name 'ad-attribute-usage' -Rows $usageRows -Note $(if ($SampleValueCount -eq 0) { 'Sample values suppressed' } else { "Top $SampleValueCount values shown; may contain personal data" })

    # ---- 2. Entra ----
    if (-not $IncludeEntra) {
        foreach ($n in 'entra-cloudonly-extension-usage', 'entra-directory-extensions', 'entra-custom-security-attributes') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note 'Run with -IncludeEntra' }
    }
    else {
        $ctx = Connect-DiscoveryGraph

        # 2a. Cloud-only users' onPremisesExtensionAttributes
        try {
            $eu = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,onPremisesSyncEnabled,onPremisesExtensionAttributes&$top=999' -Label 'users'
            $cloud = @($eu | Where-Object { -not $_.onPremisesSyncEnabled })
            $rows = foreach ($i in 1..15) {
                $name = "extensionAttribute$i"
                $prof = Get-ValueProfile -Values @($cloud | ForEach-Object { if ($_.onPremisesExtensionAttributes) { "$($_.onPremisesExtensionAttributes.$name)" } }) -Total $cloud.Count
                $o = [ordered]@{ Source = 'Entra'; ObjectType = 'CloudOnlyUser'; Attribute = $name; Objects = $cloud.Count }
                foreach ($pp in $prof.PSObject.Properties) { $o[$pp.Name] = $pp.Value }
                [pscustomobject]$o
            }
            Export-Dataset -Name 'entra-cloudonly-extension-usage' -Rows $rows -Note ("{0} cloud-only of {1} users; synced users mirror AD" -f $cloud.Count, $eu.Count)
        }
        catch { Set-DatasetStatus -Name 'entra-cloudonly-extension-usage' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

        # 2b. Directory (schema) extensions registered by apps
        try {
            $apps = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName' -Label 'applications'
            $extRows = [System.Collections.Generic.List[object]]::new()
            foreach ($a in $apps) {
                $props = @()
                try { $props = (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/extensionProperties" -f $a.id) -Label "extensionProperties $($a.id)") } catch { continue }
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
                    })
                }
            }
            Export-Dataset -Name 'entra-directory-extensions' -Rows $extRows -Note $(if ($CountExtensionUsage) { 'UsersWithValue counted' } else { 'Run with -CountExtensionUsage to count users holding each' })
        }
        catch { Set-DatasetStatus -Name 'entra-directory-extensions' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

        # 2c. Custom security attribute definitions
        if (-not $IncludeCustomSecurityAttributes) { Set-DatasetStatus -Name 'entra-custom-security-attributes' -Status 'Deferred' -Note 'Run with -IncludeCustomSecurityAttributes' }
        else {
            try {
                $csa = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/directory/customSecurityAttributeDefinitions' -Label 'customSecurityAttributeDefinitions'
                $csaRows = foreach ($d in $csa) {
                    [pscustomobject][ordered]@{
                        AttributeSet            = $d.attributeSet
                        Name                    = $d.name
                        Type                    = $d.type
                        Status                  = $d.status
                        IsCollection            = $d.isCollection
                        UsePreDefinedValuesOnly = $d.usePreDefinedValuesOnly
                        Description             = $d.description
                    }
                }
                Export-Dataset -Name 'entra-custom-security-attributes' -Rows $csaRows -Note 'Custom security attributes apply to cloud users and service principals only; not to synced users or groups'
            }
            catch { Set-DatasetStatus -Name 'entra-custom-security-attributes' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }
        }
    }

    # ---- 3. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    foreach ($t in @($usageRows | Select-Object -ExpandProperty ObjectType -Unique)) {
        $r = @($usageRows | Where-Object ObjectType -eq $t)
        Add-Metric "AD $t attributes checked" $r.Count
        Add-Metric "AD $t attributes unused" @($r | Where-Object Status -eq 'Unused').Count 'Candidates for new data - verify nothing reads them'
        Add-Metric "AD $t attributes unused (names)" (Join-Values ($r | Where-Object Status -eq 'Unused' | Select-Object -ExpandProperty Attribute))
        Add-Metric "AD $t attributes rare (<1%)" (Join-Values ($r | Where-Object Status -eq 'Rare' | Select-Object -ExpandProperty Attribute))
        Add-Metric "AD $t attributes not in schema" (Join-Values ($r | Where-Object Status -eq 'NotInSchema' | Select-Object -ExpandProperty Attribute))
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Context $ctx -Parameters @{ SearchBase = $SearchBase; AdditionalAttributes = $AdditionalAttributes; IncludeCloudExtensionAttributes = [bool]$IncludeCloudExtensionAttributes; IncludeGroups = [bool]$IncludeGroups; SampleValueCount = $SampleValueCount; IncludeEntra = [bool]$IncludeEntra; CountExtensionUsage = [bool]$CountExtensionUsage; IncludeCustomSecurityAttributes = [bool]$IncludeCustomSecurityAttributes }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
