<#
.SYNOPSIS
    Read-only, combined view of account activity across on-prem AD and Entra ID.

.DESCRIPTION
    A user can look stale in AD (no domain logon) while signing in to Microsoft 365 every day, or
    the reverse. This script joins every AD user to its Entra counterpart and reports the newest
    activity from either side, together with what a stale account still holds:

      - One row per identity: Hybrid (synced), ADOnly or CloudOnly, enabled state on each side,
        AD last logon, Entra last interactive / non-interactive / successful sign-in, newest
        activity overall, days since, activity bucket, category (Admin / Service / Sync / Guest /
        User), group memberships, adminCount, SPN, manager, password age, Microsoft 365 licences,
        Entra directory roles (active and eligible, including through role-assignable groups)
        and session revocation time
      - Synced Entra users with no AD match in this scope, and Entra users sharing one source anchor
      - Stale computer accounts (on by default; -SkipComputers to leave out)
      - Managed service accounts (gMSA / sMSA) with last logon and whether any principal may
        retrieve the password
      - Summary by source and activity bucket (0-30, 31-90, 91-180, 181-365, 365+, never)

    Flags: NeverUsed, Stale (> StaleDays), EnabledMismatch (enabled on one side, disabled on the
    other), CreatedButNeverUsed (created more than NewAccountGraceDays ago, never used),
    PasswordNeverExpires (AD), Guest, StaleButPrivileged (adminCount or an Entra role),
    StaleButLicensed, DisabledButLicensed, NeverLoggedOn (no AD logon, created more than StaleDays
    ago), PasswordNeverExpiresOld, ServiceAccountNoOwner (SPN or service name, no manager / managedBy).

    Matching uses the Entra Connect source anchor: onPremisesImmutableId = base64(objectGUID) by
    default, or base64(mS-DS-ConsistencyGuid) with -AnchorAttribute; an account with an empty
    mS-DS-ConsistencyGuid falls back to objectGUID, as Entra Connect does.

    -PreciseLastLogon reads the non-replicated lastLogon from every domain controller for the
    stale candidates only and uses the newest value. It is off by default (one query per
    candidate per DC).

    READ-ONLY. Uses only Get-AD* cmdlets and Graph GET requests.

    Output: <OutputRoot>\12-StaleAccounts\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\12-Get-StaleAccounts.ps1
.EXAMPLE
    .\12-Get-StaleAccounts.ps1 -StaleDays 60 -SkipComputers -SearchBase 'OU=Corp,DC=contoso,DC=local'
.EXAMPLE
    .\12-Get-StaleAccounts.ps1 -EnabledOnly -AnchorAttribute 'mS-DS-ConsistencyGuid' -PreciseLastLogon

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, Microsoft.Graph.Authentication
    Scopes  : User.Read.All, AuditLog.Read.All (signInActivity needs Entra ID P1),
              RoleManagement.Read.Directory, GroupMember.Read.All (Entra roles; not with -SkipEntraRoles;
              eligible roles need Entra ID P2)
    Accuracy: AD lastLogonTimestamp replicates every 9-14 days, so AD dates can be up to ~14 days
              behind (use -PreciseLastLogon for the candidates). Entra non-interactive sign-ins
              include token refreshes by apps on the user's behalf, so "recent" there does not
              always mean a person was present.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                               # blank = whole domain
    [ValidateSet('objectGUID', 'mS-DS-ConsistencyGuid')]
    [string]$AnchorAttribute = 'objectGUID',
    [int]$StaleDays = 90,
    [int]$NewAccountGraceDays = 30,
    [int]$PasswordAgeDays = 365,                            # PasswordNeverExpiresOld threshold
    [switch]$EnabledOnly,
    [switch]$SkipComputers,
    [switch]$IncludeComputers,                              # accepted for compatibility; computers are included by default
    [switch]$SkipEntraRoles,
    [switch]$PreciseLastLogon,
    [string[]]$AdminNamePatterns = @('adm*', '*adm', '*-adm*', '*_adm*', 'a-*', 'a_*', 'da-*', '*admin*'),
    [string[]]$ServiceNamePatterns = @('svc*', '*-svc*', '*_svc*', 'sa-*', 'sa_*'),

    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '12-StaleAccounts'
$ScriptVersion = '1.1.0'
$RequiredScopes = @('User.Read.All', 'AuditLog.Read.All')
if (-not $SkipEntraRoles) { $RequiredScopes += @('RoleManagement.Read.Directory', 'GroupMember.Read.All') }

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

function Get-Bucket {
    param($Days)
    if ($null -eq $Days -or "$Days" -eq '') { return 'Never' }
    if ($Days -le 30) { return '0-30' }
    if ($Days -le 90) { return '31-90' }
    if ($Days -le 180) { return '91-180' }
    if ($Days -le 365) { return '181-365' }
    return '365+'
}
function Format-Utc { param($Date) if ($Date) { return $Date.ToString('yyyy-MM-ddTHH:mm:ssZ') } return '' }
function ConvertTo-UtcDate { param($Value) if ($Value) { return ([datetime]$Value).ToUniversalTime() } return $null }
function ConvertFrom-FileTime { param($Value) if ($null -eq $Value -or "$Value" -eq '') { return $null } $v = [int64]"$Value"; if ($v -le 0 -or $v -eq [int64]::MaxValue) { return $null } return [datetime]::FromFileTimeUtc($v) }
function Test-NamePattern { param([string]$Name, [string[]]$Patterns) return [bool](@($Patterns | Where-Object { $Name -like $_ }).Count) }
function Get-CnFromDn { param([string]$DN) if (-not $DN) { return '' } if ($DN -match '^CN=((?:\\,|[^,])+)') { return ($Matches[1] -replace '\\,', ',') } return $DN }
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
$SyncNamePatterns = @('MSOL_*', 'Sync_*', 'AAD_*', 'ADSyncMSA*')
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if ($IncludeComputers) { Write-RunLog '-IncludeComputers is no longer needed: computers are included by default (-SkipComputers leaves them out).' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot
    $now = $script:RunStartUtc

    # ---- AD users ----
    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    $props = @('sAMAccountName', 'userPrincipalName', 'enabled', 'whenCreated', 'lastLogonTimestamp', 'pwdLastSet', 'userAccountControl', 'objectGUID', 'mS-DS-ConsistencyGuid',
        'memberOf', 'adminCount', 'servicePrincipalName', 'manager', 'managedBy', 'description')
    $adUsers = @(Get-ADUser -Filter * -Properties $props @p)
    Write-RunLog ("{0} AD users read" -f $adUsers.Count)
    $samByDn = @{}
    foreach ($u in $adUsers) { $samByDn["$($u.DistinguishedName)".ToLowerInvariant()] = $u.SamAccountName }

    # ---- Entra users ----
    $ctx = Connect-DiscoveryGraph
    $select = 'id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesDomainName,onPremisesSamAccountName,assignedLicenses,signInSessionsValidFromDateTime'
    $signInAvailable = $true
    try { $entra = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/users?`$select=$select,signInActivity&`$top=999" -Label 'users' }
    catch {
        $signInAvailable = $false
        Write-RunLog ("signInActivity not readable ({0}); Entra activity will be blank." -f $_.Exception.Message) 'WARN'
        $entra = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=999" -Label 'users'
    }
    Write-RunLog ("{0} Entra users read" -f $entra.Count)
    $entraByAnchor = @{}
    $anchorGroups = @{}
    $userIds = @{}
    foreach ($e in $entra) {
        $userIds[[string]$e.id] = $true
        if (-not $e.onPremisesImmutableId) { continue }
        $k = [string]$e.onPremisesImmutableId
        if (-not $anchorGroups.ContainsKey($k)) { $anchorGroups[$k] = [System.Collections.Generic.List[object]]::new() }
        $anchorGroups[$k].Add($e)
        if (-not $entraByAnchor.ContainsKey($k)) { $entraByAnchor[$k] = $e }   # first one wins; duplicates listed in duplicate-anchors
    }
    $dupRows = foreach ($k in $anchorGroups.Keys) {
        if ($anchorGroups[$k].Count -lt 2) { continue }
        foreach ($e in $anchorGroups[$k]) {
            [pscustomobject][ordered]@{ OnPremisesImmutableId = $k; UserPrincipalName = $e.userPrincipalName; EntraObjectId = $e.id; AccountEnabled = $e.accountEnabled
                OnPremisesSyncEnabled = $e.onPremisesSyncEnabled; UsedForMatch = ($entraByAnchor[$k].id -eq $e.id); SharedBy = $anchorGroups[$k].Count }
        }
    }
    $matchedEntra = @{}

    # ---- Entra directory roles ----
    $roles = $null
    if ($SkipEntraRoles) { Write-RunLog 'Entra roles skipped (-SkipEntraRoles); HoldsEntraRole is blank.' }
    else { $roles = Get-EntraRoleHolders -UserIds $userIds }

    function Get-EntraActivity {
        param($E)
        $r = [pscustomobject]@{ Interactive = $null; NonInteractive = $null; Successful = $null; Newest = $null }
        if ($E -and $E.signInActivity) {
            $r.Interactive = ConvertTo-UtcDate $E.signInActivity.lastSignInDateTime
            $r.NonInteractive = ConvertTo-UtcDate $E.signInActivity.lastNonInteractiveSignInDateTime
            $r.Successful = ConvertTo-UtcDate $E.signInActivity.lastSuccessfulSignInDateTime
            $r.Newest = @($r.Interactive, $r.NonInteractive, $r.Successful | Where-Object { $_ }) | Sort-Object -Descending | Select-Object -First 1
        }
        return $r
    }

    # ---- Pair AD users with Entra twins ----
    $pairs = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $adUsers) {
        $e = $null
        $key = Get-AnchorKey $u
        if ($key -and $entraByAnchor.ContainsKey($key)) { $e = $entraByAnchor[$key]; $matchedEntra[$e.id] = $true }
        $pairs.Add([pscustomobject]@{ Ad = $u; E = $e })
    }

    # ---- Optional precise lastLogon (every DC, stale candidates only) ----
    $precise = @{}
    $dcNote = ''
    if ($PreciseLastLogon) {
        $cands = @($pairs | Where-Object {
                $adLast = ConvertFrom-FileTime $_.Ad.lastLogonTimestamp
                $newest = @($adLast, (Get-EntraActivity $_.E).Newest | Where-Object { $_ }) | Sort-Object -Descending | Select-Object -First 1
                (-not $newest) -or (($now - $newest).TotalDays -gt $StaleDays)
            })
        $dcs = @()
        try { $dcs = @(Get-ADDomainController -Filter * @script:AdParams | Where-Object { $_.HostName }) }
        catch { Write-RunLog ("Domain controllers not listed: {0}" -f $_.Exception.Message) 'WARN' }
        $dcOk = 0; $dcFail = [System.Collections.Generic.List[string]]::new()
        foreach ($dc in $dcs) {
            $dcp = @{ Server = [string]$dc.HostName }
            $failed = $false
            foreach ($c in $cands) {
                try {
                    $one = Get-ADUser -Identity $c.Ad.DistinguishedName -Properties lastLogon @dcp
                    $t = ConvertFrom-FileTime $one.lastLogon
                    $dn = [string]$c.Ad.DistinguishedName
                    if ($t -and (-not $precise.ContainsKey($dn) -or $t -gt $precise[$dn])) { $precise[$dn] = $t }
                }
                catch { $failed = $true; Write-RunLog ("lastLogon not readable on {0}: {1}; skipping this DC." -f $dc.HostName, $_.Exception.Message) 'WARN'; break }
            }
            if ($failed) { $dcFail.Add([string]$dc.HostName) } else { $dcOk++ }
        }
        $dcNote = "PreciseLastLogon: {0} candidates, {1} of {2} DCs read" -f $cands.Count, $dcOk, $dcs.Count
        if ($dcFail.Count) { $dcNote += ' (unreachable: ' + ($dcFail -join ', ') + ' - precise values may be incomplete)' }
        Write-RunLog $dcNote
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    function Add-IdentityRow {
        param($Ad, $E)
        $adEnabled = $(if ($Ad) { [bool]$Ad.Enabled } else { $null })
        $enEnabled = $(if ($E) { [bool]$E.accountEnabled } else { $null })
        if ($EnabledOnly -and -not ($adEnabled -or $enEnabled)) { return }
        $adLast = $(if ($Ad -and $Ad.lastLogonTimestamp) { [datetime]::FromFileTimeUtc([int64]$Ad.lastLogonTimestamp) } else { $null })
        $adPrecise = $(if ($Ad -and $precise.ContainsKey([string]$Ad.DistinguishedName)) { $precise[[string]$Ad.DistinguishedName] } else { $null })
        if ($adPrecise -and (-not $adLast -or $adPrecise -gt $adLast)) { $adLast = $adPrecise }
        $act = Get-EntraActivity $E
        $newest = @($adLast, $act.Newest | Where-Object { $_ }) | Sort-Object -Descending | Select-Object -First 1
        $days = $(if ($newest) { [int]($now - $newest).TotalDays } else { '' })
        $adCreated = $(if ($Ad) { ConvertTo-UtcDate $Ad.whenCreated } else { $null })
        $created = @($adCreated, $(if ($E) { ConvertTo-UtcDate $E.createdDateTime }) | Where-Object { $_ }) | Sort-Object | Select-Object -First 1
        $source = $(if ($Ad -and $E) { 'Hybrid' } elseif ($Ad) { 'ADOnly' } else { 'CloudOnly' })
        $isStale = (-not $newest) -or ($days -gt $StaleDays)

        # AD context
        $uac = $(if ($Ad) { [int]$Ad.userAccountControl } else { 0 })
        $pne = [bool]($uac -band 65536)
        $pwdSet = $(if ($Ad) { ConvertFrom-FileTime $Ad.pwdLastSet } else { $null })
        $sam = $(if ($Ad) { [string]$Ad.SamAccountName } else { '' })
        $hasSpn = $(if ($Ad) { (@($Ad.servicePrincipalName | Where-Object { $_ }).Count -gt 0) } else { '' })
        $adminCount = $(if ($Ad) { $(if ("$($Ad.adminCount)" -eq '1') { 1 } else { 0 }) } else { '' })
        $mgrName = ''
        if ($Ad -and $Ad.manager) { $mk = "$($Ad.manager)".ToLowerInvariant(); $mgrName = $(if ($samByDn.ContainsKey($mk)) { $samByDn[$mk] } else { Get-CnFromDn $Ad.manager }) }
        $isAdminNamed = $(if ($Ad) { Test-NamePattern $sam $AdminNamePatterns } else { '' })
        $isSvcNamed = ($Ad -and (Test-NamePattern $sam $ServiceNamePatterns))
        $isSync = ($Ad -and (Test-NamePattern $sam $SyncNamePatterns))
        $category = $(if ($E -and $E.userType -eq 'Guest') { 'Guest' } elseif ($isSync) { 'Sync' } elseif ($isAdminNamed -eq $true -or $adminCount -eq 1) { 'Admin' } elseif ($hasSpn -eq $true -or $isSvcNamed) { 'Service' } else { 'User' })

        # Entra context
        $licCount = $(if ($E) { @($E.assignedLicenses | Where-Object { $_ }).Count } else { '' })
        $holdsRole = ''; $roleText = ''
        if ($E -and $roles) {
            if ($roles.ByUser.ContainsKey([string]$E.id)) { $holdsRole = 'True'; $roleText = Join-Values ($roles.ByUser[[string]$E.id] | Sort-Object) }
            elseif ($roles.Status -eq 'Completed') { $holdsRole = 'False' }
            else { $holdsRole = $(if ($roles.Status -eq 'Partial') { 'Unknown (Partial)' } else { 'EvidenceUnavailable' }) }
        }

        $flags = @()
        if (-not $newest) { $flags += 'NeverUsed' }
        elseif ($days -gt $StaleDays) { $flags += "Stale(>${StaleDays}d)" }
        if ($Ad -and $E -and ($adEnabled -ne $enEnabled)) { $flags += 'EnabledMismatch' }
        if (-not $newest -and $created -and ($now - $created).TotalDays -gt $NewAccountGraceDays) { $flags += 'CreatedButNeverUsed' }
        if ($Ad -and $pne) { $flags += 'PasswordNeverExpires' }
        if ($E -and $E.userType -eq 'Guest') { $flags += 'Guest' }
        if ($source -eq 'CloudOnly' -and -not $signInAvailable) { $flags += 'NoActivityData' }
        if ($isStale -and ($adminCount -eq 1 -or $holdsRole -eq 'True')) { $flags += 'StaleButPrivileged' }
        if ($isStale -and $licCount -ne '' -and $licCount -gt 0) { $flags += 'StaleButLicensed' }
        if ($E -and -not $enEnabled -and $licCount -gt 0) { $flags += 'DisabledButLicensed' }
        if ($Ad -and -not $adLast -and $adCreated -and ($now - $adCreated).TotalDays -gt $StaleDays) { $flags += 'NeverLoggedOn' }
        if ($pne -and $pwdSet -and ($now - $pwdSet).TotalDays -gt $PasswordAgeDays) { $flags += 'PasswordNeverExpiresOld' }
        if ($Ad -and ($hasSpn -eq $true -or $isSvcNamed) -and -not $Ad.manager -and -not $Ad.managedBy) { $flags += 'ServiceAccountNoOwner' }
        $rows.Add([pscustomobject][ordered]@{
            Source                  = $source
            SamAccountName          = $sam
            UserPrincipalName       = $(if ($E) { $E.userPrincipalName } elseif ($Ad) { $Ad.UserPrincipalName } else { '' })
            UserType                = $(if ($E) { $E.userType } else { '' })
            ADEnabled               = $adEnabled
            EntraEnabled            = $enEnabled
            CreatedUtc              = Format-Utc $created
            ADLastLogonUtc          = Format-Utc $adLast
            EntraLastInteractiveUtc = Format-Utc $act.Interactive
            EntraLastNonInteractiveUtc = Format-Utc $act.NonInteractive
            EntraLastSuccessfulUtc  = Format-Utc $act.Successful
            NewestActivityUtc       = Format-Utc $newest
            NewestActivitySource    = $(if (-not $newest) { '' } elseif ($adLast -and $newest -eq $adLast) { 'AD' } else { 'Entra' })
            DaysSinceActivity       = $days
            ActivityBucket          = Get-Bucket $days
            Flags                   = Join-Values $flags
            PwdLastSetUtc           = Format-Utc $pwdSet
            PasswordNeverExpires    = $(if ($Ad) { $pne } else { '' })
            MemberOfCount           = $(if ($Ad) { @($Ad.memberOf | Where-Object { $_ }).Count } else { '' })
            AdminCount              = $adminCount
            HasSPN                  = $hasSpn
            Manager                 = $mgrName
            IsAdminNamed            = $isAdminNamed
            Category                = $category
            AssignedLicenseCount    = $licCount
            HoldsEntraRole          = $holdsRole
            EntraRoles              = $roleText
            SignInSessionsValidFromUtc = $(if ($E) { Format-Utc (ConvertTo-UtcDate $E.signInSessionsValidFromDateTime) } else { '' })
            ADLastLogonPrecise      = $(if ($adPrecise) { 'True' } elseif ($PreciseLastLogon -and $Ad -and $isStale) { 'NoDcLogon' } else { '' })
        })
    }

    foreach ($pr in $pairs) { Add-IdentityRow -Ad $pr.Ad -E $pr.E }
    foreach ($e in $entra) {
        if ($matchedEntra.ContainsKey($e.id)) { continue }
        if ($e.onPremisesSyncEnabled) { continue }   # synced from another domain/forest or outside -SearchBase; see entra-synced-unmatched
        Add-IdentityRow -Ad $null -E $e
    }
    $dupIds = @{}; foreach ($d in @($dupRows)) { if (-not $d.UsedForMatch) { $dupIds[[string]$d.EntraObjectId] = $true } }
    $unmatchedRows = foreach ($e in $entra) {
        if (-not $e.onPremisesSyncEnabled -or $matchedEntra.ContainsKey($e.id)) { continue }
        $act = Get-EntraActivity $e
        [pscustomobject][ordered]@{
            UserPrincipalName        = $e.userPrincipalName
            DisplayName              = $e.displayName
            AccountEnabled           = $e.accountEnabled
            OnPremisesDomainName     = $e.onPremisesDomainName
            OnPremisesSamAccountName = $e.onPremisesSamAccountName
            OnPremisesImmutableId    = $e.onPremisesImmutableId
            NewestEntraActivityUtc   = Format-Utc $act.Newest
            AssignedLicenseCount     = @($e.assignedLicenses | Where-Object { $_ }).Count
            Reason                   = $(if ($dupIds.ContainsKey([string]$e.id)) { 'Shares a source anchor with another Entra user (see duplicate-anchors)' } elseif ($e.onPremisesDomainName -and $e.onPremisesDomainName -ne $domainName) { 'Synced from another domain' } else { 'No AD user with this anchor in this domain / SearchBase (deleted on-prem, out of scope, or different anchor)' })
        }
    }
    $syncedUnmatched = @($unmatchedRows).Count
    Export-Dataset -Name 'identity-activity' -Rows $rows -Note $(if ($syncedUnmatched) { "$syncedUnmatched synced Entra users had no AD match in this scope; listed in entra-synced-unmatched" } else { '' })
    Export-Dataset -Name 'entra-synced-unmatched' -Rows $unmatchedRows -Note 'Synced Entra users not matched to an AD user read in this run'
    Export-Dataset -Name 'duplicate-anchors' -Rows $dupRows -Note 'Entra users sharing one onPremisesImmutableId; only the first was matched to AD'
    if ($roles -and $roles.Status -ne 'Completed') { Write-RunLog ("HoldsEntraRole is incomplete [{0}]: {1}" -f $roles.Status, $roles.Note) 'WARN' }

    # ---- Computers ----
    $compRows = @()
    $compStatus = 'Completed'
    if ($SkipComputers) { Set-DatasetStatus -Name 'ad-computers' -Status 'Deferred' -Note 'Skipped (-SkipComputers)'; $compStatus = 'Skipped' }
    else {
        try {
            $comps = @(Get-ADComputer -Filter * -Properties enabled, lastLogonTimestamp, operatingSystem, whenCreated, pwdLastSet @p)
            $compRows = foreach ($c in $comps) {
                if ($EnabledOnly -and -not $c.Enabled) { continue }
                $last = $(if ($c.lastLogonTimestamp) { [datetime]::FromFileTimeUtc([int64]$c.lastLogonTimestamp) } else { $null })
                $pwdSet = $(if ($c.pwdLastSet) { [datetime]::FromFileTimeUtc([int64]$c.pwdLastSet) } else { $null })
                $d = $(if ($last) { [int]($now - $last).TotalDays } else { '' })
                [pscustomobject][ordered]@{
                    Name              = $c.Name
                    Enabled           = $c.Enabled
                    OperatingSystem   = $c.OperatingSystem
                    CreatedUtc        = Format-Utc (ConvertTo-UtcDate $c.whenCreated)
                    LastLogonUtc      = Format-Utc $last
                    PasswordLastSetUtc = Format-Utc $pwdSet
                    DaysSinceLogon    = $d
                    ActivityBucket    = Get-Bucket $d
                    Stale             = (-not $last) -or ($d -gt $StaleDays)
                    DistinguishedName = $c.DistinguishedName
                }
            }
            Export-Dataset -Name 'ad-computers' -Rows $compRows -Note 'Computer passwords rotate every 30 days by default; an old PasswordLastSet confirms a dead machine'
        }
        catch { $compStatus = 'Blocked'; Set-DatasetStatus -Name 'ad-computers' -Status 'Blocked' -Note $_.Exception.Message }
    }

    # ---- Managed service accounts (gMSA / sMSA) ----
    $msaRows = @()
    $msaStatus = 'Completed'
    try {
        $msas = @(Get-ADServiceAccount -Filter * -Properties enabled, lastLogonTimestamp, pwdLastSet, whenCreated, servicePrincipalName, description, objectClass, PrincipalsAllowedToRetrieveManagedPassword @script:AdParams)
        $msaRows = foreach ($m in $msas) {
            $last = ConvertFrom-FileTime $m.lastLogonTimestamp
            $pwdSet = ConvertFrom-FileTime $m.pwdLastSet
            $d = $(if ($last) { [int]($now - $last).TotalDays } else { '' })
            $cls = [string]@($m.objectClass)[-1]
            $isGmsa = ($cls -eq 'msDS-GroupManagedServiceAccount')
            $retr = @($m.PrincipalsAllowedToRetrieveManagedPassword | Where-Object { $_ }).Count
            $stale = (-not $last) -or ($d -gt $StaleDays)
            [pscustomobject][ordered]@{
                Name                       = $m.Name
                SamAccountName             = $m.SamAccountName
                Type                       = $(if ($isGmsa) { 'gMSA' } else { 'sMSA' })
                Enabled                    = $m.Enabled
                LastLogonUtc               = Format-Utc $last
                DaysSinceLogon             = $d
                ActivityBucket             = Get-Bucket $d
                PasswordLastSetUtc         = Format-Utc $pwdSet
                PrincipalsAllowedToRetrievePresent = $(if ($isGmsa) { $retr -gt 0 } else { '' })
                SpnCount                   = @($m.servicePrincipalName | Where-Object { $_ }).Count
                Stale                      = $stale
                Flags                      = Join-Values @($(if ($stale) { "Stale(>${StaleDays}d)" }), $(if ($isGmsa -and $retr -eq 0) { 'NoPrincipalAllowedToRetrieve' }), $(if (Test-NamePattern $m.SamAccountName $SyncNamePatterns) { 'EntraConnectSync' }))
                Description                = $m.Description
                DistinguishedName          = $m.DistinguishedName
            }
        }
        Export-Dataset -Name 'ad-managed-service-accounts' -Rows $msaRows -Note 'NoPrincipalAllowedToRetrieve = no host can use the gMSA; usually a leftover'
    }
    catch { $msaStatus = 'Blocked'; Set-DatasetStatus -Name 'ad-managed-service-accounts' -Status 'Blocked' -Note $_.Exception.Message }

    # ---- Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    function Get-FlagCount { param([string]$Flag) return @($rows | Where-Object { $_.Flags -match $Flag }).Count }
    Add-Metric -Metric 'Identities' -Value $rows.Count -Note $(if ($EnabledOnly) { 'Enabled on at least one side' } else { 'All' })
    Add-Metric 'Entra sign-in activity available' $signInAvailable
    Add-Metric -Metric 'Entra role evidence' -Value $(if ($SkipEntraRoles) { 'Skipped' } else { $roles.Status }) -Note $(if ($roles) { $roles.Note } else { '-SkipEntraRoles' })
    foreach ($src in 'Hybrid', 'ADOnly', 'CloudOnly') { Add-Metric "Identities: $src" @($rows | Where-Object Source -eq $src).Count }
    foreach ($cat in 'User', 'Admin', 'Service', 'Sync', 'Guest') { Add-Metric "Identities: category $cat" @($rows | Where-Object Category -eq $cat).Count }
    foreach ($b in '0-30', '31-90', '91-180', '181-365', '365+') { Add-Metric "Last activity $b days ago" @($rows | Where-Object ActivityBucket -eq $b).Count }
    Add-Metric -Metric 'No recorded activity (never)' -Value @($rows | Where-Object ActivityBucket -eq 'Never').Count -Note 'No activity on either side'
    $enabledAnywhere = @($rows | Where-Object { $_.ADEnabled -or $_.EntraEnabled })
    Add-Metric -Metric "Enabled identities stale over $StaleDays days or never used" -Value @($enabledAnywhere | Where-Object { $_.Flags -match 'Stale\(|NeverUsed' }).Count -Note 'Primary clean-up population'
    Add-Metric -Metric 'Stale or never used but privileged (adminCount or Entra role)' -Value (Get-FlagCount 'StaleButPrivileged') -Note $(if ($roles -and $roles.Status -ne 'Completed') { "Highest priority. At least this many: Entra role evidence $($roles.Status)" } elseif ($SkipEntraRoles) { 'Highest priority. adminCount only (-SkipEntraRoles)' } else { 'Highest priority' })
    Add-Metric 'Stale or never used but licensed' (Get-FlagCount 'StaleButLicensed')
    Add-Metric 'Disabled in Entra but still licensed' (Get-FlagCount 'DisabledButLicensed')
    Add-Metric "AD accounts never logged on, created over $StaleDays days ago" (Get-FlagCount 'NeverLoggedOn')
    Add-Metric "Password never expires and older than $PasswordAgeDays days" (Get-FlagCount 'PasswordNeverExpiresOld')
    Add-Metric 'Service accounts with no manager / managedBy' (Get-FlagCount 'ServiceAccountNoOwner')
    Add-Metric 'Enabled on one side, disabled on the other' (Get-FlagCount 'EnabledMismatch')
    Add-Metric "Created over $NewAccountGraceDays days ago, never used" (Get-FlagCount 'CreatedButNeverUsed')
    Add-Metric -Metric 'Stale in AD but active in Entra (last 30 days)' -Value @($rows | Where-Object { $_.Source -eq 'Hybrid' -and $_.NewestActivitySource -eq 'Entra' -and "$($_.DaysSinceActivity)" -ne '' -and $_.DaysSinceActivity -le 30 -and (-not $_.ADLastLogonUtc -or ($now - ([datetime]$_.ADLastLogonUtc).ToUniversalTime()).TotalDays -gt $StaleDays) }).Count -Note 'AD-only staleness checks would wrongly flag these'
    Add-Metric -Metric 'Synced Entra users with no AD match in this scope' -Value $syncedUnmatched -Note 'entra-synced-unmatched.csv'
    Add-Metric -Metric 'Entra source anchors shared by more than one user' -Value @($dupRows | Select-Object -ExpandProperty OnPremisesImmutableId -Unique).Count -Note 'duplicate-anchors.csv'
    if ($PreciseLastLogon) { Add-Metric -Metric 'Precise lastLogon (all DCs)' -Value $precise.Count -Note $dcNote }
    if (-not $SkipComputers -and $compStatus -eq 'Completed') {
        Add-Metric 'Computers' @($compRows).Count
        Add-Metric "Computers stale over $StaleDays days or never logged on" @($compRows | Where-Object Stale).Count
    }
    if ($msaStatus -eq 'Completed') {
        Add-Metric 'Managed service accounts (gMSA / sMSA)' @($msaRows).Count
        Add-Metric "Managed service accounts stale over $StaleDays days" @($msaRows | Where-Object Stale).Count
        Add-Metric 'gMSAs no principal may retrieve' @($msaRows | Where-Object { $_.Flags -match 'NoPrincipalAllowedToRetrieve' }).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Context $ctx -Parameters @{ SearchBase = $SearchBase; AnchorAttribute = $AnchorAttribute; StaleDays = $StaleDays; NewAccountGraceDays = $NewAccountGraceDays; PasswordAgeDays = $PasswordAgeDays; EnabledOnly = [bool]$EnabledOnly; SkipComputers = [bool]$SkipComputers; SkipEntraRoles = [bool]$SkipEntraRoles; PreciseLastLogon = [bool]$PreciseLastLogon; AdminNamePatterns = $AdminNamePatterns; ServiceNamePatterns = $ServiceNamePatterns }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
