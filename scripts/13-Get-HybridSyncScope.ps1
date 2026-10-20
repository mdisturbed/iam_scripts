<#
.SYNOPSIS
    Read-only check of what on-prem AD actually synchronizes to Entra ID, and where the two disagree.

.DESCRIPTION
    Any provisioning design that writes to AD (for example ticket-driven JML) depends on knowing
    which OUs reach Entra and which objects are broken between the two. This script exports:

      - Tenant sync status: directory sync on/off, last sync and last password-hash sync times,
        and enabled sync features where readable
      - OU coverage: for every OU that holds users, how many AD users there are and what share
        has a synced Entra twin. 100% = in sync scope, 0% = out of scope, anything between needs
        an explanation (filtering, errors, or a scoping attribute)
      - Enabled AD users with no Entra twin (outside sync scope or failing)
      - Entra users marked as synced with no AD match in this domain (deleted on-prem but still
        in Entra, sync stopped, or from another domain / forest - reported separately)
      - Cloud-only Entra users that look like duplicates of an AD user (same UPN prefix, mail or
        display name)
      - Users with on-premises provisioning errors (e.g. duplicate proxyAddresses / UPN)
      - Optional: the same OU coverage and orphan checks for groups

    Matching uses the Entra Connect source anchor: onPremisesImmutableId = base64(objectGUID) by
    default, or base64(mS-DS-ConsistencyGuid) with -AnchorAttribute. Groups match on SID.

    READ-ONLY. Uses only Get-AD* cmdlets and Graph GET requests.

    Output: <OutputRoot>\13-HybridSyncScope\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\13-Get-HybridSyncScope.ps1
.EXAMPLE
    .\13-Get-HybridSyncScope.ps1 -IncludeGroups -AnchorAttribute 'mS-DS-ConsistencyGuid'

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, Microsoft.Graph.Authentication
    Scopes  : User.Read.All, Group.Read.All, Organization.Read.All
              (+ OnPremDirectorySynchronization.Read.All for sync features, optional)
    Run in each domain of a multi-domain forest; objects from other domains are reported as
    OtherDomain rather than orphaned.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # e.g. 'dc01.contoso.local'
    [ValidateSet('objectGUID', 'mS-DS-ConsistencyGuid')]
    [string]$AnchorAttribute = 'objectGUID',
    [switch]$IncludeGroups,
    [switch]$IncludeSyncFeatures,
    [int]$SyncStaleHours = 24,

    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '13-HybridSyncScope'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('User.Read.All', 'Group.Read.All', 'Organization.Read.All')
if ($IncludeSyncFeatures) { $RequiredScopes += 'OnPremDirectorySynchronization.Read.All' }

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

function Get-ParentOU { param([string]$DN) $i = $DN.IndexOf(','); if ($i -lt 0) { return $DN } return $DN.Substring($i + 1) }
function Get-Prefix { param([string]$Upn) if (-not $Upn) { return '' } return ($Upn -split '@')[0].ToLowerInvariant() }

$domainName = ''
$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot
    $netbios = (Get-ADDomain @script:AdParams).NetBIOSName
    $ctx = Connect-DiscoveryGraph
    $now = $script:RunStartUtc

    # ---- 1. Tenant sync status ----
    $statusRows = [System.Collections.Generic.List[object]]::new()
    $org = $null
    try {
        $org = (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesLastPasswordSyncDateTime' -Label 'organization')[0]
        $lastSync = $(if ($org.onPremisesLastSyncDateTime) { ([datetime]$org.onPremisesLastSyncDateTime).ToUniversalTime() } else { $null })
        $statusRows.Add([pscustomobject][ordered]@{ Setting = 'Directory sync enabled'; Value = $org.onPremisesSyncEnabled; Note = '' })
        $statusRows.Add([pscustomobject][ordered]@{ Setting = 'Last directory sync (UTC)'; Value = $(if ($lastSync) { $lastSync.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }); Note = $(if ($lastSync -and ($now - $lastSync).TotalHours -gt $SyncStaleHours) { "OLDER THAN $SyncStaleHours HOURS - sync may be stopped" } else { '' }) })
        $statusRows.Add([pscustomobject][ordered]@{ Setting = 'Last password hash sync (UTC)'; Value = $(if ($org.onPremisesLastPasswordSyncDateTime) { ([datetime]$org.onPremisesLastPasswordSyncDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'Never / not used' }); Note = '' })
    }
    catch { Write-RunLog ("organization unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    if ($IncludeSyncFeatures) {
        try {
            $sync = (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization' -Label 'onPremisesSynchronization')[0]
            foreach ($f in $sync.features.PSObject.Properties) { $statusRows.Add([pscustomobject][ordered]@{ Setting = "Feature: $($f.Name)"; Value = $f.Value; Note = '' }) }
        }
        catch { Write-RunLog ("Sync features unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    }
    Export-Dataset -Name 'sync-tenant-status' -Rows $statusRows

    # ---- 2. Users ----
    $adUsers = @(Get-ADUser -Filter * -Properties enabled, userPrincipalName, mail, displayName, objectGUID, 'mS-DS-ConsistencyGuid', whenCreated @script:AdParams)
    $sel = 'id,userPrincipalName,mail,displayName,accountEnabled,userType,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesDomainName,onPremisesSamAccountName,onPremisesDistinguishedName,onPremisesLastSyncDateTime,onPremisesProvisioningErrors,createdDateTime'
    $entra = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/users?`$select=$sel&`$top=999" -Label 'users'
    Write-RunLog ("{0} AD users, {1} Entra users" -f $adUsers.Count, $entra.Count)

    $byAnchor = @{}
    foreach ($e in $entra) { if ($e.onPremisesImmutableId) { $byAnchor[$e.onPremisesImmutableId] = $e } }
    $matched = @{}
    $ouStats = @{}
    $unsynced = [System.Collections.Generic.List[object]]::new()
    $adIndex = @{ Prefix = @{}; Mail = @{}; Name = @{} }
    foreach ($u in $adUsers) {
        $bytes = $(if ($AnchorAttribute -eq 'objectGUID') { $u.ObjectGUID.ToByteArray() } elseif ($u.'mS-DS-ConsistencyGuid') { [byte[]]$u.'mS-DS-ConsistencyGuid' } else { $null })
        $twin = $null
        if ($bytes) { $k = [Convert]::ToBase64String($bytes); if ($byAnchor.ContainsKey($k)) { $twin = $byAnchor[$k]; $matched[$twin.id] = $u } }
        $ou = Get-ParentOU $u.DistinguishedName
        if (-not $ouStats.ContainsKey($ou)) { $ouStats[$ou] = @{ Users = 0; Enabled = 0; Synced = 0; EnabledSynced = 0 } }
        $ouStats[$ou].Users++
        if ($u.Enabled) { $ouStats[$ou].Enabled++ }
        if ($twin) { $ouStats[$ou].Synced++; if ($u.Enabled) { $ouStats[$ou].EnabledSynced++ } }
        elseif ($u.Enabled) {
            $unsynced.Add([pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; UserPrincipalName = $u.UserPrincipalName; ParentOU = $ou; WhenCreated = $u.whenCreated; Note = $(if (-not $bytes) { "No $AnchorAttribute value" } else { 'No Entra object with this anchor' }) })
        }
        foreach ($pair in @(@('Prefix', (Get-Prefix $u.UserPrincipalName)), @('Mail', "$($u.mail)".ToLowerInvariant()), @('Name', "$($u.DisplayName)".ToLowerInvariant()))) {
            if ($pair[1]) { if (-not $adIndex[$pair[0]].ContainsKey($pair[1])) { $adIndex[$pair[0]][$pair[1]] = [System.Collections.Generic.List[string]]::new() }; $adIndex[$pair[0]][$pair[1]].Add($u.SamAccountName) }
        }
    }
    $ouRows = foreach ($ou in $ouStats.Keys) {
        $s = $ouStats[$ou]
        $pct = $(if ($s.Users) { [math]::Round(100 * $s.Synced / $s.Users, 1) } else { 0 })
        [pscustomobject][ordered]@{
            OU                 = $ou
            Users              = $s.Users
            EnabledUsers       = $s.Enabled
            SyncedUsers        = $s.Synced
            EnabledSynced      = $s.EnabledSynced
            SyncedPct          = $pct
            InferredScope      = $(if ($pct -eq 100) { 'InScope' } elseif ($pct -eq 0) { 'OutOfScope' } else { 'Partial - investigate' })
        }
    }
    Export-Dataset -Name 'sync-ou-coverage-users' -Rows @($ouRows | Sort-Object InferredScope, OU) -Note 'Scope is inferred from results, not read from the Entra Connect configuration'
    Export-Dataset -Name 'ad-users-not-in-entra' -Rows $unsynced -Note 'Enabled AD users only'

    # Synced Entra users with no AD match here
    $orphans = foreach ($e in $entra) {
        if (-not $e.onPremisesSyncEnabled -or $matched.ContainsKey($e.id)) { continue }
        $lastObj = $(if ($e.onPremisesLastSyncDateTime) { ([datetime]$e.onPremisesLastSyncDateTime).ToUniversalTime() } else { $null })
        $otherDomain = ($e.onPremisesDomainName -and $e.onPremisesDomainName -ne $domainName -and $e.onPremisesDomainName -ne $netbios)
        [pscustomobject][ordered]@{
            UserPrincipalName          = $e.userPrincipalName
            AccountEnabled             = $e.accountEnabled
            OnPremisesDomain           = $e.onPremisesDomainName
            OnPremisesSamAccountName   = $e.onPremisesSamAccountName
            OnPremisesDistinguishedName = $e.onPremisesDistinguishedName
            LastObjectSyncUtc          = $(if ($lastObj) { $lastObj.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            Classification             = $(if ($otherDomain) { 'OtherDomain' } elseif ($lastObj -and ($now - $lastObj).TotalDays -gt 7) { 'OrphanedSyncedObject' } else { 'NoMatchInThisDomain' })
        }
    }
    Export-Dataset -Name 'entra-synced-without-ad-match' -Rows $orphans -Note 'OrphanedSyncedObject = marked synced but not updated for 7+ days; often deleted on-prem or sync scope changed'

    # Cloud-only possible duplicates
    $dupes = foreach ($e in $entra) {
        if ($e.onPremisesSyncEnabled -or $e.userType -eq 'Guest') { continue }
        $hits = @()
        $pfx = Get-Prefix $e.userPrincipalName
        if ($pfx -and $adIndex.Prefix.ContainsKey($pfx)) { $hits += @($adIndex.Prefix[$pfx] | ForEach-Object { "UPN prefix: $_" }) }
        $m = "$($e.mail)".ToLowerInvariant()
        if ($m -and $adIndex.Mail.ContainsKey($m)) { $hits += @($adIndex.Mail[$m] | ForEach-Object { "Mail: $_" }) }
        $n = "$($e.displayName)".ToLowerInvariant()
        if ($n -and $adIndex.Name.ContainsKey($n)) { $hits += @($adIndex.Name[$n] | ForEach-Object { "Display name: $_" }) }
        if (-not $hits.Count) { continue }
        [pscustomobject][ordered]@{
            CloudUserPrincipalName = $e.userPrincipalName
            DisplayName            = $e.displayName
            AccountEnabled         = $e.accountEnabled
            CreatedUtc             = $e.createdDateTime
            MatchesADAccounts      = Join-Values ($hits | Select-Object -Unique)
            MatchStrength          = $(if ($hits -match '^(UPN prefix|Mail)') { 'Strong' } else { 'NameOnly' })
        }
    }
    Export-Dataset -Name 'cloud-only-possible-duplicates' -Rows $dupes -Note 'Candidates only. Break-glass and admin accounts are often deliberate cloud-only twins.'

    # Provisioning errors
    $errRows = foreach ($e in $entra) {
        foreach ($pe in @($e.onPremisesProvisioningErrors | Where-Object { $_ })) {
            [pscustomobject][ordered]@{ UserPrincipalName = $e.userPrincipalName; Category = $pe.category; PropertyCausingError = $pe.propertyCausingError; Value = $pe.value; OccurredUtc = $pe.occurredDateTime }
        }
    }
    Export-Dataset -Name 'user-provisioning-errors' -Rows $errRows

    # ---- 3. Groups (optional) ----
    $gOuRows = @(); $gOrphans = @()
    if (-not $IncludeGroups) {
        Set-DatasetStatus -Name 'sync-ou-coverage-groups' -Status 'Deferred' -Note 'Run with -IncludeGroups'
        Set-DatasetStatus -Name 'entra-synced-groups-without-ad-match' -Status 'Deferred' -Note 'Run with -IncludeGroups'
    }
    else {
        $adGroups = @(Get-ADGroup -Filter * -Properties objectSid @script:AdParams)
        $eg = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName,onPremisesSyncEnabled,onPremisesSecurityIdentifier,onPremisesDomainName,onPremisesLastSyncDateTime,onPremisesProvisioningErrors&$top=999' -Label 'groups'
        $bySid = @{}; foreach ($g in $eg) { if ($g.onPremisesSecurityIdentifier) { $bySid[$g.onPremisesSecurityIdentifier] = $g } }
        $gMatched = @{}; $gStats = @{}
        foreach ($g in $adGroups) {
            $ou = Get-ParentOU $g.DistinguishedName
            if (-not $gStats.ContainsKey($ou)) { $gStats[$ou] = @{ Groups = 0; Synced = 0 } }
            $gStats[$ou].Groups++
            $sid = "$($g.SID.Value)"
            if ($sid -and $bySid.ContainsKey($sid)) { $gStats[$ou].Synced++; $gMatched[$bySid[$sid].id] = $true }
        }
        $gOuRows = foreach ($ou in $gStats.Keys) {
            $s = $gStats[$ou]; $pct = [math]::Round(100 * $s.Synced / [math]::Max(1, $s.Groups), 1)
            [pscustomobject][ordered]@{ OU = $ou; Groups = $s.Groups; SyncedGroups = $s.Synced; SyncedPct = $pct; InferredScope = $(if ($pct -eq 100) { 'InScope' } elseif ($pct -eq 0) { 'OutOfScope' } else { 'Partial - investigate' }) }
        }
        Export-Dataset -Name 'sync-ou-coverage-groups' -Rows @($gOuRows | Sort-Object InferredScope, OU) -Note 'Built-in groups (Domain Admins etc.) are never synced; their OUs show as OutOfScope or Partial by design'
        $gOrphans = foreach ($g in $eg) {
            if (-not $g.onPremisesSyncEnabled -or $gMatched.ContainsKey($g.id)) { continue }
            [pscustomobject][ordered]@{ DisplayName = $g.displayName; OnPremisesDomain = $g.onPremisesDomainName; Sid = $g.onPremisesSecurityIdentifier; LastSyncUtc = $g.onPremisesLastSyncDateTime; Classification = $(if ($g.onPremisesDomainName -and $g.onPremisesDomainName -ne $domainName -and $g.onPremisesDomainName -ne $netbios) { 'OtherDomain' } else { 'NoMatchInThisDomain' }) }
        }
        Export-Dataset -Name 'entra-synced-groups-without-ad-match' -Rows $gOrphans
    }

    # ---- 4. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    if ($org) { Add-Metric 'Last directory sync (UTC)' ($statusRows | Where-Object Setting -eq 'Last directory sync (UTC)').Value }
    Add-Metric 'AD users' $adUsers.Count
    Add-Metric 'AD users with an Entra twin' $matched.Count
    Add-Metric 'Enabled AD users not in Entra' $unsynced.Count
    Add-Metric 'OUs holding users' @($ouRows).Count
    Add-Metric 'OUs fully in scope' @($ouRows | Where-Object InferredScope -eq 'InScope').Count
    Add-Metric 'OUs out of scope' @($ouRows | Where-Object InferredScope -eq 'OutOfScope').Count
    Add-Metric 'OUs partially synced' @($ouRows | Where-Object { $_.InferredScope -like 'Partial*' }).Count 'Investigate: filtering, errors or scoping attribute'
    Add-Metric 'Entra users synced from another domain' @($orphans | Where-Object Classification -eq 'OtherDomain').Count
    Add-Metric 'Synced Entra users with no AD match (this domain)' @($orphans | Where-Object Classification -ne 'OtherDomain').Count
    Add-Metric 'Cloud-only users that may duplicate an AD user' @($dupes).Count
    Add-Metric 'Users with provisioning errors' @($errRows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    if ($IncludeGroups) {
        Add-Metric 'Group OUs partially synced' @($gOuRows | Where-Object { $_.InferredScope -like 'Partial*' }).Count
        Add-Metric 'Synced Entra groups with no AD match (this domain)' @($gOrphans | Where-Object Classification -ne 'OtherDomain').Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Context $ctx -Parameters @{ AnchorAttribute = $AnchorAttribute; IncludeGroups = [bool]$IncludeGroups; IncludeSyncFeatures = [bool]$IncludeSyncFeatures; SyncStaleHours = $SyncStaleHours }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
