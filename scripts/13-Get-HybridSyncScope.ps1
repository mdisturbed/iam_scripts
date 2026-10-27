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
      - AD users with no Entra twin (outside sync scope or failing), with their enabled state
      - Entra users marked as synced with no AD match in this domain (deleted on-prem but still
        in Entra, sync stopped, or from another domain / forest - reported separately)
      - Entra users sharing one source anchor
      - Matched pairs that disagree: UPN, enabled state (AD disabled but Entra enabled is High),
        optionally display name
      - Cloud-only Entra users that look like duplicates of an AD user (same UPN prefix, mail or
        display name)
      - Users with on-premises provisioning errors (e.g. duplicate proxyAddresses / UPN)
      - Privileged AD accounts (adminCount = 1 or nested members of the built-in admin and operator
        groups) that are synced to Entra, and which of them also hold an Entra directory role
      - Entra Connect / Cloud Sync service accounts and the Seamless SSO computer account
      - Device coverage: AD computers vs hybrid-joined Entra devices, per OU
      - Optional: the same OU coverage and orphan checks for groups, plus group provisioning errors

    Matching uses the Entra Connect source anchor: onPremisesImmutableId = base64(objectGUID) by
    default, or base64(mS-DS-ConsistencyGuid) with -AnchorAttribute; an account with an empty
    mS-DS-ConsistencyGuid falls back to objectGUID, as Entra Connect does. Groups and devices
    match on SID (devices also on deviceId = objectGUID).

    READ-ONLY. Uses only Get-AD* cmdlets and Graph GET requests.

    Output: <OutputRoot>\13-HybridSyncScope\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\13-Get-HybridSyncScope.ps1
.EXAMPLE
    .\13-Get-HybridSyncScope.ps1 -IncludeGroups -AnchorAttribute 'mS-DS-ConsistencyGuid' -OrphanDays 14
.EXAMPLE
    .\13-Get-HybridSyncScope.ps1 -SkipDevices -SkipEntraRoles -IncludeDisplayNameMismatch

.NOTES
    Version : 1.1.1
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, Microsoft.Graph.Authentication
    Scopes  : User.Read.All, Group.Read.All, Organization.Read.All, RoleManagement.Read.Directory,
              GroupMember.Read.All, Device.Read.All
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
    [int]$OrphanDays = 7,                                   # synced Entra object not updated for this long = OrphanedSyncedObject
    [switch]$SkipDevices,
    [switch]$SkipEntraRoles,
    [switch]$IncludeDisplayNameMismatch,

    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '13-HybridSyncScope'
$ScriptVersion = '1.1.1'
$RequiredScopes = @('User.Read.All', 'Group.Read.All', 'Organization.Read.All')
if (-not $SkipEntraRoles) { $RequiredScopes += @('RoleManagement.Read.Directory', 'GroupMember.Read.All') }
if (-not $SkipDevices) { $RequiredScopes += 'Device.Read.All' }
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

function Get-ParentOU { param([string]$DN) $i = $DN.IndexOf(','); if ($i -lt 0) { return $DN } return $DN.Substring($i + 1) }
function Get-Prefix { param([string]$Upn) if (-not $Upn) { return '' } return ($Upn -split '@')[0].ToLowerInvariant() }
function Format-Utc { param($Date) if ($Date) { return $Date.ToString('yyyy-MM-ddTHH:mm:ssZ') } return '' }
function ConvertFrom-FileTime { param($Value) if ($null -eq $Value -or "$Value" -eq '') { return $null } $v = [int64]"$Value"; if ($v -le 0 -or $v -eq [int64]::MaxValue) { return $null } return [datetime]::FromFileTimeUtc($v) }
function Get-AnchorKey {
    # Entra Connect source anchor: mS-DS-ConsistencyGuid when chosen and set, otherwise objectGUID.
    param($AdObject)
    $bytes = $null
    if ($AnchorAttribute -eq 'mS-DS-ConsistencyGuid' -and $AdObject.'mS-DS-ConsistencyGuid') { $bytes = [byte[]]$AdObject.'mS-DS-ConsistencyGuid' }
    if (-not $bytes -and $AdObject.ObjectGUID) { $bytes = $AdObject.ObjectGUID.ToByteArray() }
    if (-not $bytes) { return '' }
    return [Convert]::ToBase64String($bytes)
}

function Get-EntraRoleHolders {
    # Users holding an Entra directory role: active assignments + eligible (PIM) assignments,
    # with group principals (role-assignable groups) expanded through transitiveMembers.
    # Status: Completed / Partial / Blocked / EvidenceUnavailable.
    param([hashtable]$UserIds)
    $r = [pscustomobject]@{ Status = 'Completed'; Note = ''; ByUser = @{}; GroupsExpanded = 0 }
    $notes = [System.Collections.Generic.List[string]]::new()
    $names = @{}
    try { foreach ($d in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName' -Label 'roleDefinitions')) { $names[[string]$d.id] = $d.displayName } }
    catch { $notes.Add("role names not readable ($($_.Exception.Message))") }
    $assign = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=principalId,roleDefinitionId,directoryScopeId&$expand=principal($select=id,displayName)' -Label 'roleAssignments')) {
            $assign.Add([pscustomobject]@{ Principal = [string]$a.principalId; Role = [string]$a.roleDefinitionId; Scope = [string]$a.directoryScopeId; State = 'Active'; PrincipalInfo = $a.principal })
        }
    }
    catch {
        $r.Status = Get-FailureStatus $_
        $r.Note = "Active role assignments not readable: $($_.Exception.Message)"
        Write-RunLog ("Entra roles: {0}" -f $r.Note) 'WARN'
        return $r
    }
    try {
        foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$select=principalId,roleDefinitionId,directoryScopeId&$expand=principal($select=id,displayName)' -Label 'roleEligibilityScheduleInstances')) {
            $assign.Add([pscustomobject]@{ Principal = [string]$a.principalId; Role = [string]$a.roleDefinitionId; Scope = [string]$a.directoryScopeId; State = 'Eligible'; PrincipalInfo = $a.principal })
        }
    }
    catch { $r.Status = 'Partial'; $notes.Add("eligible assignments not readable, so eligible-only holders are missing ($($_.Exception.Message))") }
    $groupCache = @{}
    foreach ($a in $assign) {
        $roleName = $(if ($names.ContainsKey($a.Role)) { $names[$a.Role] } else { $a.Role })
        if ($a.Scope -and $a.Scope -ne '/') { $roleName += " [scope $($a.Scope)]" }
        $holders = @(); $via = ''
        $ptype = ''; $pname = $a.Principal
        if ($a.PrincipalInfo) { $ptype = ("$($a.PrincipalInfo.'@odata.type')" -replace '#microsoft.graph.', ''); if ($a.PrincipalInfo.displayName) { $pname = $a.PrincipalInfo.displayName } }
        if ($ptype -eq 'servicePrincipal') { continue }
        if ($ptype -eq 'user' -or $UserIds.ContainsKey($a.Principal)) { $holders = @($a.Principal) }
        else {
            if (-not $groupCache.ContainsKey($a.Principal)) {
                try {
                    $m = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers/microsoft.graph.user?`$select=id,displayName" -f $a.Principal) -Label "role group $($a.Principal)"
                    $groupCache[$a.Principal] = @($m | ForEach-Object { [string]$_.id })
                    $r.GroupsExpanded++
                }
                catch {
                    $msg = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
                    if ($msg -match '404|NotFound|Request_ResourceNotFound') { $groupCache[$a.Principal] = @() }   # not a group: service principal or unknown user scope
                    else { $groupCache[$a.Principal] = @(); $r.Status = 'Partial'; $notes.Add("members of role principal $($a.Principal) not readable ($($_.Exception.Message))") }
                }
            }
            $holders = $groupCache[$a.Principal]; $via = ", via group $pname"
        }
        foreach ($h in $holders) {
            if (-not $r.ByUser.ContainsKey($h)) { $r.ByUser[$h] = [System.Collections.Generic.List[string]]::new() }
            $label = '{0} ({1}{2})' -f $roleName, $a.State, $via
            if (-not $r.ByUser[$h].Contains($label)) { $r.ByUser[$h].Add($label) }
        }
    }
    $r.Note = ($notes -join '; ')
    Write-RunLog ("Entra roles: {0} assignments, {1} groups expanded, {2} users hold a role [{3}] {4}" -f $assign.Count, $r.GroupsExpanded, $r.ByUser.Count, $r.Status, $r.Note)
    return $r
}

$domainName = ''
$ctx = $null
$InChain = '1.2.840.113556.1.4.1941'      # LDAP_MATCHING_RULE_IN_CHAIN: transitive group membership
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain @script:AdParams
    $domainName = $domain.DNSRoot
    $netbios = $domain.NetBIOSName
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
    if (-not $org -and -not $statusRows.Count) { Set-DatasetStatus -Name 'sync-tenant-status' -Status 'Blocked' -Note 'organization not readable (Organization.Read.All); see run.log' }
    else { Export-Dataset -Name 'sync-tenant-status' -Rows $statusRows -Note $(if (-not $org) { 'organization not readable; only sync features shown' } else { '' }) }

    # ---- 2. Users ----
    $adUsers = @(Get-ADUser -Filter * -Properties enabled, userPrincipalName, mail, displayName, objectGUID, 'mS-DS-ConsistencyGuid', whenCreated, adminCount @script:AdParams)
    $sel = 'id,userPrincipalName,mail,displayName,accountEnabled,userType,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesDomainName,onPremisesSamAccountName,onPremisesDistinguishedName,onPremisesLastSyncDateTime,onPremisesProvisioningErrors,createdDateTime'
    $entra = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/users?`$select=$sel&`$top=999" -Label 'users'
    Write-RunLog ("{0} AD users, {1} Entra users" -f $adUsers.Count, $entra.Count)

    $byAnchor = @{}
    $anchorGroups = @{}
    $userIds = @{}
    foreach ($e in $entra) {
        $userIds[[string]$e.id] = $true
        if (-not $e.onPremisesImmutableId) { continue }
        $k = [string]$e.onPremisesImmutableId
        if (-not $anchorGroups.ContainsKey($k)) { $anchorGroups[$k] = [System.Collections.Generic.List[object]]::new() }
        $anchorGroups[$k].Add($e)
        if (-not $byAnchor.ContainsKey($k)) { $byAnchor[$k] = $e }   # first one wins; duplicates listed in duplicate-anchors
    }
    $dupRows = foreach ($k in $anchorGroups.Keys) {
        if ($anchorGroups[$k].Count -lt 2) { continue }
        foreach ($e in $anchorGroups[$k]) {
            [pscustomobject][ordered]@{ OnPremisesImmutableId = $k; UserPrincipalName = $e.userPrincipalName; EntraObjectId = $e.id; AccountEnabled = $e.accountEnabled
                OnPremisesSyncEnabled = $e.onPremisesSyncEnabled; UsedForMatch = ($byAnchor[$k].id -eq $e.id); SharedBy = $anchorGroups[$k].Count }
        }
    }
    $matched = @{}
    $twinByDn = @{}
    $ouStats = @{}
    $unsynced = [System.Collections.Generic.List[object]]::new()
    $adIndex = @{ Prefix = @{}; Mail = @{}; Name = @{} }
    foreach ($u in $adUsers) {
        $k = Get-AnchorKey $u
        $twin = $null
        if ($k -and $byAnchor.ContainsKey($k)) { $twin = $byAnchor[$k]; $matched[$twin.id] = $u; $twinByDn[[string]$u.DistinguishedName] = $twin }
        $ou = Get-ParentOU $u.DistinguishedName
        if (-not $ouStats.ContainsKey($ou)) { $ouStats[$ou] = @{ Users = 0; Enabled = 0; Synced = 0; EnabledSynced = 0 } }
        $ouStats[$ou].Users++
        if ($u.Enabled) { $ouStats[$ou].Enabled++ }
        if ($twin) { $ouStats[$ou].Synced++; if ($u.Enabled) { $ouStats[$ou].EnabledSynced++ } }
        else {
            $unsynced.Add([pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; UserPrincipalName = $u.UserPrincipalName; ParentOU = $ou; WhenCreated = $u.whenCreated; Note = $(if (-not $k) { "No $AnchorAttribute value" } else { 'No Entra object with this anchor' }); Enabled = [bool]$u.Enabled })
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
    Export-Dataset -Name 'ad-users-not-in-entra' -Rows $unsynced -Note 'Enabled and disabled AD users; filter on Enabled'
    Export-Dataset -Name 'duplicate-anchors' -Rows $dupRows -Note 'Entra users sharing one onPremisesImmutableId; only the first was matched to AD'

    # Synced Entra users with no AD match here
    $dupLoser = @{}; foreach ($d in @($dupRows)) { if (-not $d.UsedForMatch) { $dupLoser[[string]$d.EntraObjectId] = $true } }
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
            Classification             = $(if ($otherDomain) { 'OtherDomain' } elseif ($dupLoser.ContainsKey([string]$e.id)) { 'DuplicateAnchor' } elseif ($lastObj -and ($now - $lastObj).TotalDays -gt $OrphanDays) { 'OrphanedSyncedObject' } else { 'NoMatchInThisDomain' })
        }
    }
    Export-Dataset -Name 'entra-synced-without-ad-match' -Rows $orphans -Note ("OrphanedSyncedObject = marked synced but not updated for {0}+ days (-OrphanDays); often deleted on-prem or sync scope changed. DuplicateAnchor = shares its anchor with a matched user" -f $OrphanDays)

    # Matched pairs that disagree
    $mismatch = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $adUsers) {
        $dn = [string]$u.DistinguishedName
        if (-not $twinByDn.ContainsKey($dn)) { continue }
        $t = $twinByDn[$dn]
        if ("$($u.UserPrincipalName)".ToLowerInvariant() -ne "$($t.userPrincipalName)".ToLowerInvariant()) {
            $mismatch.Add([pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; EntraUserPrincipalName = $t.userPrincipalName; Check = 'UPN'; AdValue = $u.UserPrincipalName; EntraValue = $t.userPrincipalName; Severity = 'Medium'
                    Note = 'Expected when the AD UPN suffix is not a verified domain or an alternate login ID is used; otherwise sign-in names drift' })
        }
        if ([bool]$u.Enabled -ne [bool]$t.accountEnabled) {
            $adOff = -not $u.Enabled
            $mismatch.Add([pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; EntraUserPrincipalName = $t.userPrincipalName; Check = 'Enabled'; AdValue = [bool]$u.Enabled; EntraValue = [bool]$t.accountEnabled
                    Severity = $(if ($adOff) { 'High' } else { 'Medium' })
                    Note = $(if ($adOff) { 'Disabled on-prem but still enabled in Entra: cloud sign-in still works until the next sync or if the object is filtered' } else { 'Blocked in Entra only; the next sync may re-enable it unless blocked by policy' }) })
        }
        if ($IncludeDisplayNameMismatch -and "$($u.DisplayName)" -ne "$($t.displayName)") {
            $mismatch.Add([pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; EntraUserPrincipalName = $t.userPrincipalName; Check = 'DisplayName'; AdValue = $u.DisplayName; EntraValue = $t.displayName; Severity = 'Low'; Note = 'Usually a cloud-side edit or a pending sync' })
        }
    }
    Export-Dataset -Name 'matched-pair-mismatches' -Rows @($mismatch | Sort-Object @{ Expression = { @{ High = 0; Medium = 1; Low = 2 }[$_.Severity] } }, SamAccountName) -Note $(if ($IncludeDisplayNameMismatch) { 'UPN, enabled state and display name' } else { 'UPN and enabled state; -IncludeDisplayNameMismatch adds display name' })

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
    $gOuRows = @(); $gOrphans = @(); $gErrRows = @()
    if (-not $IncludeGroups) {
        Set-DatasetStatus -Name 'sync-ou-coverage-groups' -Status 'Deferred' -Note 'Run with -IncludeGroups'
        Set-DatasetStatus -Name 'entra-synced-groups-without-ad-match' -Status 'Deferred' -Note 'Run with -IncludeGroups'
        Set-DatasetStatus -Name 'group-provisioning-errors' -Status 'Deferred' -Note 'Run with -IncludeGroups'
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
        $gErrRows = foreach ($g in $eg) {
            foreach ($pe in @($g.onPremisesProvisioningErrors | Where-Object { $_ })) {
                [pscustomobject][ordered]@{ DisplayName = $g.displayName; Sid = $g.onPremisesSecurityIdentifier; Category = $pe.category; PropertyCausingError = $pe.propertyCausingError; Value = $pe.value; OccurredUtc = $pe.occurredDateTime }
            }
        }
        Export-Dataset -Name 'group-provisioning-errors' -Rows $gErrRows
    }

    # ---- 4. Privileged AD accounts that are synced ----
    $roles = $null
    if ($SkipEntraRoles) { Write-RunLog 'Entra roles skipped (-SkipEntraRoles); SyncedAdminHoldsEntraRole is not evaluated.' }
    else { $roles = Get-EntraRoleHolders -UserIds $userIds }
    $privRows = @(); $privTotal = 0; $privNote = ''
    try {
        $rootSid = $domain.DomainSID.Value
        try { $rootSid = (Get-ADDomain -Identity (Get-ADForest @script:AdParams).RootDomain @script:AdParams).DomainSID.Value } catch { Write-RunLog ("Forest root domain not readable ({0}); Enterprise / Schema Admins looked up in this domain." -f $_.Exception.Message) 'WARN' }
        $privSpecs = @(
            @{ Label = 'Domain Admins'; Sid = "$($domain.DomainSID.Value)-512" }
            @{ Label = 'Enterprise Admins'; Sid = "$rootSid-519" }
            @{ Label = 'Schema Admins'; Sid = "$rootSid-518" }
            @{ Label = 'Administrators'; Sid = 'S-1-5-32-544' }
            @{ Label = 'Account Operators'; Sid = 'S-1-5-32-548' }
            @{ Label = 'Server Operators'; Sid = 'S-1-5-32-549' }
            @{ Label = 'Backup Operators'; Sid = 'S-1-5-32-551' }
        )
        $priv = @{}   # DN -> @{ User; Via }
        $groupFail = [System.Collections.Generic.List[string]]::new()
        $privProps = @('sAMAccountName', 'userPrincipalName', 'enabled', 'adminCount', 'objectGUID', 'mS-DS-ConsistencyGuid')
        foreach ($ps in $privSpecs) {
            try {
                $g = Get-ADGroup -Identity $ps.Sid @script:AdParams
                foreach ($m in @(Get-ADUser -LDAPFilter "(memberOf:$InChain`:=$($g.DistinguishedName))" -Properties $privProps @script:AdParams)) {
                    $dn = [string]$m.DistinguishedName
                    if (-not $priv.ContainsKey($dn)) { $priv[$dn] = @{ User = $m; Via = [System.Collections.Generic.List[string]]::new() } }
                    if (-not $priv[$dn].Via.Contains($ps.Label)) { $priv[$dn].Via.Add($ps.Label) }
                }
            }
            catch { $groupFail.Add($ps.Label); Write-RunLog ("Privileged group {0} not expanded: {1}" -f $ps.Label, $_.Exception.Message) 'WARN' }
        }
        foreach ($m in @(Get-ADUser -LDAPFilter '(adminCount=1)' -Properties $privProps @script:AdParams)) {
            $dn = [string]$m.DistinguishedName
            if (-not $priv.ContainsKey($dn)) { $priv[$dn] = @{ User = $m; Via = [System.Collections.Generic.List[string]]::new() } }
            if (-not $priv[$dn].Via.Contains('adminCount=1')) { $priv[$dn].Via.Add('adminCount=1') }
        }
        $privTotal = $priv.Count
        $privRows = foreach ($dn in $priv.Keys) {
            $m = $priv[$dn].User
            $k = Get-AnchorKey $m
            if (-not ($k -and $byAnchor.ContainsKey($k))) { continue }
            $t = $byAnchor[$k]
            $holds = ''; $roleText = ''
            if ($roles) {
                if ($roles.ByUser.ContainsKey([string]$t.id)) { $holds = 'True'; $roleText = Join-Values ($roles.ByUser[[string]$t.id] | Sort-Object) }
                elseif ($roles.Status -eq 'Completed') { $holds = 'False' }
                else { $holds = $(if ($roles.Status -eq 'Partial') { 'Unknown (Partial)' } else { 'EvidenceUnavailable' }) }
            }
            $viaGroups = @($priv[$dn].Via | Where-Object { $_ -ne 'adminCount=1' })
            [pscustomobject][ordered]@{
                SamAccountName          = $m.SamAccountName
                Enabled                 = [bool]$m.Enabled
                AdminCount              = $(if ("$($m.adminCount)" -eq '1') { 1 } else { 0 })
                PrivilegedVia           = Join-Values $priv[$dn].Via
                EntraUserPrincipalName  = $t.userPrincipalName
                EntraEnabled            = $t.accountEnabled
                HoldsEntraRole          = $holds
                EntraRoles              = $roleText
                Severity                = $(if ($holds -eq 'True') { 'High' } elseif ($viaGroups.Count) { 'Medium' } else { 'Low' })
                Flags                   = Join-Values @('SyncedPrivilegedAccount', $(if ($holds -eq 'True') { 'SyncedAdminHoldsEntraRole' }), $(if (-not $viaGroups.Count) { 'AdminCountOnly' }), $(if ([bool]$m.Enabled -ne [bool]$t.accountEnabled) { 'EnabledMismatch' }))
                DistinguishedName       = $dn
            }
        }
        $privRows = @($privRows | Sort-Object @{ Expression = { @{ High = 0; Medium = 1; Low = 2 }[$_.Severity] } }, SamAccountName)
        $privNote = "On-prem privileged accounts synced to Entra ($(@($privRows).Count) of $privTotal privileged); built-in admin groups are excluded from sync by default but their members are not"
        if ($groupFail.Count) { $privNote += '; PARTIAL: not expanded: ' + ($groupFail -join ', ') }
        if ($roles -and $roles.Status -ne 'Completed') { $privNote += "; Entra roles [$($roles.Status)]: $($roles.Note)" }
        Export-Dataset -Name 'privileged-ad-accounts-synced' -Rows $privRows -Note $privNote
    }
    catch { Set-DatasetStatus -Name 'privileged-ad-accounts-synced' -Status 'Blocked' -Note $_.Exception.Message }

    # ---- 5. Sync service accounts ----
    $svcRows = @()
    try {
        $f = '(|(sAMAccountName=MSOL_*)(sAMAccountName=Sync_*)(sAMAccountName=AAD_*)(sAMAccountName=ADSyncMSA*)(sAMAccountName=AZUREADSSOACC$))'
        $objs = @(Get-ADObject -LDAPFilter $f -Properties sAMAccountName, objectClass, userAccountControl, pwdLastSet, lastLogonTimestamp, description, whenCreated @script:AdParams)
        $svcRows = foreach ($o in $objs) {
            $sam = [string]$o.sAMAccountName
            $cls = [string]@($o.objectClass)[-1]
            $pwdSet = ConvertFrom-FileTime $o.pwdLastSet
            $last = ConvertFrom-FileTime $o.lastLogonTimestamp
            $uac = 0; try { $uac = [int]"$($o.userAccountControl)" } catch { $uac = 0 }
            $kind = $(if ($sam -like 'AZUREADSSOACC*') { 'Seamless SSO computer account' } elseif ($sam -like 'MSOL_*') { 'Entra Connect AD DS connector account' } elseif ($sam -like 'ADSyncMSA*') { 'Entra Connect sync service (managed) account' } elseif ($sam -like 'Sync_*') { 'Entra Connect sync service account (older installs)' } else { 'Sync-related account (AAD_)' })
            $pwdAge = $(if ($pwdSet) { [int]($now - $pwdSet).TotalDays } else { '' })
            $flags = @()
            if ($sam -like 'AZUREADSSOACC*' -and $pwdAge -ne '' -and $pwdAge -gt 30) { $flags += 'SsoKeyNotRolled(>30d)' }
            if ($sam -like 'MSOL_*' -and ($uac -band 65536)) { $flags += 'PasswordNeverExpires' }
            if ($sam -notlike 'AZUREADSSOACC*' -and -not ($uac -band 2) -and (-not $last -or ($now - $last).TotalDays -gt 30)) { $flags += 'NoRecentLogon(possible leftover install)' }
            [pscustomobject][ordered]@{
                SamAccountName    = $sam
                ObjectClass       = $cls
                Kind              = $kind
                Enabled           = -not ($uac -band 2)
                PwdLastSetUtc     = Format-Utc $pwdSet
                PasswordAgeDays   = $pwdAge
                LastLogonUtc      = Format-Utc $last
                WhenCreated       = $o.whenCreated
                Description       = $o.description
                Flags             = Join-Values $flags
                DistinguishedName = $o.DistinguishedName
            }
        }
        if (@($svcRows | Where-Object { $_.SamAccountName -like 'MSOL_*' -and $_.Enabled }).Count -gt 1) { foreach ($r in @($svcRows | Where-Object { $_.SamAccountName -like 'MSOL_*' })) { $r.Flags = Join-Values @($r.Flags, 'MultipleConnectorAccounts') } }
        Export-Dataset -Name 'sync-service-accounts' -Rows $svcRows -Note 'MSOL_ accounts hold replicate-directory-changes rights (password hash sync); treat as Tier 0'
    }
    catch { Set-DatasetStatus -Name 'sync-service-accounts' -Status 'Blocked' -Note $_.Exception.Message }

    # ---- 6. Device coverage ----
    $devRows = @(); $devStatus = 'Skipped'
    if ($SkipDevices) { Set-DatasetStatus -Name 'device-sync-coverage' -Status 'Deferred' -Note 'Skipped (-SkipDevices)' }
    else {
        try {
            $comps = @(Get-ADComputer -Filter * -Properties enabled, objectSid, objectGUID, operatingSystem @script:AdParams | Where-Object { $_.Name -ne 'AZUREADSSOACC' })
            $devs = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/devices?$select=id,deviceId,displayName,trustType,onPremisesSecurityIdentifier,onPremisesSyncEnabled,accountEnabled,approximateLastSignInDateTime,operatingSystem&$top=999' -Label 'devices'
            $devBySid = @{}; $devById = @{}
            foreach ($d in $devs) {
                if ($d.onPremisesSecurityIdentifier) { $devBySid[[string]$d.onPremisesSecurityIdentifier] = $d }
                if ($d.deviceId) { $devById[([string]$d.deviceId).ToLowerInvariant()] = $d }
            }
            $dStats = @{}
            foreach ($c in $comps) {
                $ou = Get-ParentOU $c.DistinguishedName
                if (-not $dStats.ContainsKey($ou)) { $dStats[$ou] = @{ Computers = 0; Enabled = 0; Hybrid = 0; Other = 0; Missing = 0 } }
                $dStats[$ou].Computers++
                if ($c.Enabled) { $dStats[$ou].Enabled++ }
                $sid = "$($c.SID.Value)"
                $d = $null
                if ($sid -and $devBySid.ContainsKey($sid)) { $d = $devBySid[$sid] }
                elseif ($c.ObjectGUID -and $devById.ContainsKey($c.ObjectGUID.ToString().ToLowerInvariant())) { $d = $devById[$c.ObjectGUID.ToString().ToLowerInvariant()] }
                if (-not $d) { $dStats[$ou].Missing++ }
                elseif ($d.trustType -eq 'ServerAd') { $dStats[$ou].Hybrid++ }
                else { $dStats[$ou].Other++ }
            }
            $devRows = foreach ($ou in $dStats.Keys) {
                $s = $dStats[$ou]
                [pscustomobject][ordered]@{
                    OU                    = $ou
                    Computers             = $s.Computers
                    EnabledComputers      = $s.Enabled
                    HybridJoined          = $s.Hybrid
                    InEntraOtherTrustType = $s.Other
                    NotInEntra            = $s.Missing
                    HybridJoinedPct       = $(if ($s.Computers) { [math]::Round(100 * $s.Hybrid / $s.Computers, 1) } else { 0 })
                }
            }
            $devRows = @($devRows | Sort-Object HybridJoinedPct, OU)
            $devStatus = 'Completed'
            Export-Dataset -Name 'device-sync-coverage' -Rows $devRows -Note ("{0} AD computers, {1} Entra devices ({2} hybrid joined). Matched on SID, then deviceId = objectGUID. Servers and DCs are often not hybrid joined by design" -f $comps.Count, @($devs).Count, @($devs | Where-Object { $_.trustType -eq 'ServerAd' }).Count)
        }
        catch { $devStatus = 'Blocked'; Set-DatasetStatus -Name 'device-sync-coverage' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }
    }

    # ---- 7. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    if ($org) { Add-Metric 'Last directory sync (UTC)' ($statusRows | Where-Object Setting -eq 'Last directory sync (UTC)').Value }
    Add-Metric 'AD users' $adUsers.Count
    Add-Metric 'AD users with an Entra twin' $matched.Count
    Add-Metric 'Enabled AD users not in Entra' @($unsynced | Where-Object Enabled).Count
    Add-Metric 'Disabled AD users not in Entra' @($unsynced | Where-Object { -not $_.Enabled }).Count
    Add-Metric 'OUs holding users' @($ouRows).Count
    Add-Metric 'OUs fully in scope' @($ouRows | Where-Object InferredScope -eq 'InScope').Count
    Add-Metric 'OUs out of scope' @($ouRows | Where-Object InferredScope -eq 'OutOfScope').Count
    Add-Metric -Metric 'OUs partially synced' -Value @($ouRows | Where-Object { $_.InferredScope -like 'Partial*' }).Count -Note 'Investigate: filtering, errors or scoping attribute'
    Add-Metric 'Entra users synced from another domain' @($orphans | Where-Object Classification -eq 'OtherDomain').Count
    Add-Metric 'Synced Entra users with no AD match (this domain)' @($orphans | Where-Object Classification -ne 'OtherDomain').Count
    Add-Metric 'Entra source anchors shared by more than one user' @($dupRows | Select-Object -ExpandProperty OnPremisesImmutableId -Unique).Count
    Add-Metric -Metric 'Matched pairs: AD disabled but Entra enabled' -Value @($mismatch | Where-Object { $_.Check -eq 'Enabled' -and $_.Severity -eq 'High' }).Count -Note 'High: cloud sign-in still possible'
    Add-Metric 'Matched pairs: UPN differs' @($mismatch | Where-Object Check -eq 'UPN').Count
    Add-Metric 'Cloud-only users that may duplicate an AD user' @($dupes).Count
    Add-Metric 'Users with provisioning errors' @($errRows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    Add-Metric -Metric 'Privileged AD accounts synced to Entra' -Value @($privRows).Count -Note ("of $privTotal privileged AD accounts")
    $rolesKnown = ($roles -and $roles.Status -in @('Completed', 'Partial'))
    Add-Metric -Metric 'Synced on-prem admins that also hold an Entra role' -Value $(if ($rolesKnown) { @($privRows | Where-Object { $_.Flags -match 'SyncedAdminHoldsEntraRole' }).Count } else { '' }) -Note $(if ($SkipEntraRoles) { 'Not evaluated (-SkipEntraRoles)' } elseif ($roles.Status -eq 'Partial') { 'At least this many: Entra role evidence Partial' } elseif ($roles) { "Entra role evidence: $($roles.Status)" } else { '' })
    Add-Metric 'Sync service accounts found' @($svcRows).Count
    if ($devStatus -eq 'Completed') {
        $tc = ($devRows | Measure-Object Computers -Sum).Sum; $th = ($devRows | Measure-Object HybridJoined -Sum).Sum
        Add-Metric -Metric 'AD computers hybrid joined in Entra' -Value $th -Note ("of $tc AD computers")
        Add-Metric 'AD computers not in Entra' ($devRows | Measure-Object NotInEntra -Sum).Sum
    }
    if ($IncludeGroups) {
        Add-Metric 'Group OUs partially synced' @($gOuRows | Where-Object { $_.InferredScope -like 'Partial*' }).Count
        Add-Metric 'Synced Entra groups with no AD match (this domain)' @($gOrphans | Where-Object Classification -ne 'OtherDomain').Count
        Add-Metric 'Groups with provisioning errors' @($gErrRows | Select-Object -ExpandProperty DisplayName -Unique).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Context $ctx -Parameters @{ AnchorAttribute = $AnchorAttribute; IncludeGroups = [bool]$IncludeGroups; IncludeSyncFeatures = [bool]$IncludeSyncFeatures; SyncStaleHours = $SyncStaleHours; OrphanDays = $OrphanDays; SkipDevices = [bool]$SkipDevices; SkipEntraRoles = [bool]$SkipEntraRoles; IncludeDisplayNameMismatch = [bool]$IncludeDisplayNameMismatch }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
