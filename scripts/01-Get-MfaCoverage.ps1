<#
.SYNOPSIS
    Read-only discovery of MFA coverage in Microsoft Entra ID.

.DESCRIPTION
    Exports the evidence needed to measure "inconsistent MFA coverage":
      - Every Conditional Access policy, flattened, with included/excluded scope resolved to names
      - One row per CA exclusion (user, group, role, guest/external)
      - Transitive members of every group excluded from any CA policy
      - MFA registration details for every user (registered vs capable vs methods)
      - Successful single-factor sign-ins over a lookback window, aggregated by user/app/client,
        with legacy-authentication clients flagged
      - A summary of headline metrics

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.
    Requested scopes are read scopes only. Nothing in the tenant is created, changed or deleted.

    Output: <OutputRoot>\01-MfaCoverage\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER AuthMode
    Delegated      - interactive sign-in as the operator (needs admin consent for the read scopes).
    AppCertificate - app registration + certificate (TenantId, ClientId, CertificateThumbprint required).

.EXAMPLE
    .\01-Get-MfaCoverage.ps1
.EXAMPLE
    .\01-Get-MfaCoverage.ps1 -SignInLookbackDays 30 -MaxSignInRecords 200000
.EXAMPLE
    .\01-Get-MfaCoverage.ps1 -AuthMode AppCertificate -TenantId tenant-id-redacted -ClientId <app-id> -CertificateThumbprint <thumbprint>

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : Policy.Read.All, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All
    Licence : Sign-in logs and registration details require Entra ID P1 or higher.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = '',

    [ValidateRange(1, 30)]
    [int]$SignInLookbackDays = 7,
    [int]$MaxSignInRecords = 50000,
    [switch]$SkipSignIns,
    [switch]$SkipExcludedGroupMembers
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '01-MfaCoverage'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('Policy.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All')

#region ---- Common helpers (identical in every Graph script; self-contained by design) ----
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
    # Records a dataset that produced no file (Blocked / Deferred / EvidenceUnavailable).
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][ValidateSet('Blocked', 'Deferred', 'EvidenceUnavailable')][string]$Status, [string]$Note = '')
    $script:Datasets.Add([pscustomobject][ordered]@{ Dataset = $Name; Status = $Status; Rows = 0; File = ''; Sha256 = ''; Note = $Note })
    Write-RunLog ("{0}: [{1}] {2}" -f $Name, $Status, $Note) 'WARN'
}

function Write-RunManifest {
    param($Context, [hashtable]$Parameters)
    $manifest = [ordered]@{
        Script        = $ScriptName
        ScriptVersion = $ScriptVersion
        StartedUtc    = $script:RunStartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        FinishedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        RunAsWindows  = [Environment]::UserDomainName + '\' + [Environment]::UserName
        Machine       = [Environment]::MachineName
        PowerShell    = $PSVersionTable.PSVersion.ToString()
        AuthMode      = $AuthMode
        TenantId      = $(if ($Context) { $Context.TenantId } else { '' })
        GraphAccount  = $(if ($Context) { $Context.Account } else { '' })
        GraphClientId = $(if ($Context) { $Context.ClientId } else { '' })
        ScopesInToken = $(if ($Context) { @($Context.Scopes) } else { @() })
        Parameters    = $Parameters
        Datasets      = $script:Datasets.ToArray()
    }
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
#endregion

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- Lookups: role names and app names used inside CA policies ----
    $roleNames = @{}
    try {
        foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName' -Label 'roleDefinitions')) {
            $roleNames[$r.id] = $r.displayName
            if ($r.templateId) { $roleNames[$r.templateId] = $r.displayName }
        }
    }
    catch { Write-RunLog ("Could not read role definitions; role IDs will be shown raw. {0}" -f $_.Exception.Message) 'WARN' }

    $appNames = @{}
    function Resolve-AppId {
        param([string]$AppId)
        if ($AppId -in @('All', 'None', 'Office365', 'MicrosoftAdminPortals')) { return $AppId }
        if ($appNames.ContainsKey($AppId)) { return $appNames[$AppId] }
        $label = $AppId
        try {
            $sp = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=displayName,appId" -f $AppId)
            if (@($sp.value).Count -gt 0) { $label = '{0} ({1})' -f $sp.value[0].displayName, $AppId }
        }
        catch { }
        $appNames[$AppId] = $label
        return $label
    }

    # ---- 1. Conditional Access policies ----
    $policies = $null
    $policyRows = [System.Collections.Generic.List[object]]::new()
    $exclusionRows = [System.Collections.Generic.List[object]]::new()
    $excludedGroups = @{}   # groupId -> list of policy names
    try {
        $policies = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'caPolicies'
        foreach ($p in $policies) {
            $c = $p.conditions; $u = $c.users; $g = $p.grantControls
            $builtIn = @(); if ($g) { $builtIn = @($g.builtInControls) }
            $authStrength = ''
            if ($g -and $g.PSObject.Properties.Name -contains 'authenticationStrength' -and $g.authenticationStrength) { $authStrength = $g.authenticationStrength.displayName }
            $requiresMfa = ($builtIn -contains 'mfa') -or [bool]$authStrength
            $clientTypes = @($c.clientAppTypes)
            $blocksLegacy = ($builtIn -contains 'block') -and (($clientTypes -contains 'exchangeActiveSync') -or ($clientTypes -contains 'other'))
            $guestScope = ''
            if ($u.PSObject.Properties.Name -contains 'includeGuestsOrExternalUsers' -and $u.includeGuestsOrExternalUsers) { $guestScope = $u.includeGuestsOrExternalUsers.guestOrExternalUserTypes }

            $session = @()
            if ($p.sessionControls) {
                foreach ($sp in $p.sessionControls.PSObject.Properties) { if ($sp.Value) { $session += $sp.Name } }
            }

            $policyRows.Add([pscustomobject][ordered]@{
                PolicyId            = $p.id
                PolicyName          = $p.displayName
                State               = $p.state
                Created             = $p.createdDateTime
                Modified            = $p.modifiedDateTime
                RequiresMfa         = $requiresMfa
                BlocksLegacyAuth    = $blocksLegacy
                GrantOperator       = $(if ($g) { $g.operator } else { '' })
                GrantControls       = Join-Values $builtIn
                AuthStrength        = $authStrength
                IncludeUsers        = Join-Values (@($u.includeUsers) | Where-Object { $_ } | ForEach-Object { Resolve-DirectoryObject $_ })
                ExcludeUsers        = Join-Values (@($u.excludeUsers) | Where-Object { $_ } | ForEach-Object { Resolve-DirectoryObject $_ })
                IncludeGroups       = Join-Values (@($u.includeGroups) | Where-Object { $_ } | ForEach-Object { Resolve-DirectoryObject $_ })
                ExcludeGroups       = Join-Values (@($u.excludeGroups) | Where-Object { $_ } | ForEach-Object { Resolve-DirectoryObject $_ })
                IncludeRoles        = Join-Values (@($u.includeRoles) | Where-Object { $_ } | ForEach-Object { if ($roleNames[$_]) { $roleNames[$_] } else { $_ } })
                ExcludeRoles        = Join-Values (@($u.excludeRoles) | Where-Object { $_ } | ForEach-Object { if ($roleNames[$_]) { $roleNames[$_] } else { $_ } })
                IncludeGuestTypes   = $guestScope
                IncludeApplications = Join-Values (@($c.applications.includeApplications) | Where-Object { $_ } | ForEach-Object { Resolve-AppId $_ })
                ExcludeApplications = Join-Values (@($c.applications.excludeApplications) | Where-Object { $_ } | ForEach-Object { Resolve-AppId $_ })
                UserActions         = Join-Values $c.applications.includeUserActions
                ClientAppTypes      = Join-Values $clientTypes
                IncludePlatforms    = $(if ($c.platforms) { Join-Values $c.platforms.includePlatforms } else { '' })
                IncludeLocations    = $(if ($c.locations) { Join-Values $c.locations.includeLocations } else { '' })
                ExcludeLocations    = $(if ($c.locations) { Join-Values $c.locations.excludeLocations } else { '' })
                SignInRiskLevels    = Join-Values $c.signInRiskLevels
                UserRiskLevels      = Join-Values $c.userRiskLevels
                SessionControls     = Join-Values $session
            })

            foreach ($id in @($u.excludeUsers)) { if ($id) { $exclusionRows.Add([pscustomobject][ordered]@{ PolicyName = $p.displayName; PolicyState = $p.state; RequiresMfa = $requiresMfa; ExclusionType = 'User'; ObjectId = $id; DisplayName = Resolve-DirectoryObject $id }) } }
            foreach ($id in @($u.excludeGroups)) {
                if ($id) {
                    $exclusionRows.Add([pscustomobject][ordered]@{ PolicyName = $p.displayName; PolicyState = $p.state; RequiresMfa = $requiresMfa; ExclusionType = 'Group'; ObjectId = $id; DisplayName = Resolve-DirectoryObject $id })
                    if (-not $excludedGroups.ContainsKey($id)) { $excludedGroups[$id] = [System.Collections.Generic.List[string]]::new() }
                    $excludedGroups[$id].Add($p.displayName)
                }
            }
            foreach ($id in @($u.excludeRoles)) { if ($id) { $exclusionRows.Add([pscustomobject][ordered]@{ PolicyName = $p.displayName; PolicyState = $p.state; RequiresMfa = $requiresMfa; ExclusionType = 'Role'; ObjectId = $id; DisplayName = $(if ($roleNames[$id]) { $roleNames[$id] } else { $id }) }) } }
            if ($u.PSObject.Properties.Name -contains 'excludeGuestsOrExternalUsers' -and $u.excludeGuestsOrExternalUsers) {
                $exclusionRows.Add([pscustomobject][ordered]@{ PolicyName = $p.displayName; PolicyState = $p.state; RequiresMfa = $requiresMfa; ExclusionType = 'GuestOrExternal'; ObjectId = ''; DisplayName = $u.excludeGuestsOrExternalUsers.guestOrExternalUserTypes })
            }
        }
        Export-Dataset -Name 'ca-policies' -Rows $policyRows
        Export-Dataset -Name 'ca-exclusions' -Rows $exclusionRows
    }
    catch {
        $st = Get-FailureStatus $_
        Set-DatasetStatus -Name 'ca-policies' -Status $st -Note $_.Exception.Message
        Set-DatasetStatus -Name 'ca-exclusions' -Status $st -Note 'Depends on ca-policies'
    }

    # ---- 2. Members of groups excluded from CA ----
    if ($SkipExcludedGroupMembers) { Set-DatasetStatus -Name 'ca-excluded-group-members' -Status 'Deferred' -Note '-SkipExcludedGroupMembers' }
    elseif ($excludedGroups.Count -gt 0) {
        $memberRows = [System.Collections.Generic.List[object]]::new()
        try {
            foreach ($gid in $excludedGroups.Keys) {
                $gname = Resolve-DirectoryObject $gid
                $members = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers" -f $gid) -Label "transitiveMembers $gid"
                foreach ($m in $members) {
                    $memberRows.Add([pscustomobject][ordered]@{
                        GroupId              = $gid
                        GroupName            = $gname
                        ExcludedFromPolicies = Join-Values $excludedGroups[$gid]
                        MemberId             = $m.id
                        MemberType           = ($m.'@odata.type' -replace '#microsoft.graph.', '')
                        MemberDisplayName    = $m.displayName
                        MemberUPN            = $(if ($m.PSObject.Properties.Name -contains 'userPrincipalName') { $m.userPrincipalName } else { '' })
                        AccountEnabled       = $(if ($m.PSObject.Properties.Name -contains 'accountEnabled') { $m.accountEnabled } else { '' })
                    })
                }
            }
            Export-Dataset -Name 'ca-excluded-group-members' -Rows $memberRows
        }
        catch { Set-DatasetStatus -Name 'ca-excluded-group-members' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }
    }
    else { Export-Dataset -Name 'ca-excluded-group-members' -Rows @() -Note 'No groups are excluded from any CA policy' }

    # ---- 3. MFA registration details ----
    $regRows = $null
    try {
        $reg = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails' -Label 'userRegistrationDetails'
        $regRows = foreach ($r in $reg) {
            $methods = @($r.methodsRegistered | Where-Object { $_ })
            [pscustomobject][ordered]@{
                UserId               = $r.id
                UserPrincipalName    = $r.userPrincipalName
                UserType             = $r.userType
                IsAdmin              = $r.isAdmin
                IsMfaRegistered      = $r.isMfaRegistered
                IsMfaCapable         = $r.isMfaCapable
                IsPasswordlessCapable = $r.isPasswordlessCapable
                IsSsprRegistered     = $r.isSsprRegistered
                DefaultMfaMethod     = $r.defaultMfaMethod
                MethodsRegistered    = Join-Values $methods
                HasPhoneMethodOnly   = (($methods.Count -gt 0) -and (@($methods | Where-Object { $_ -notmatch 'mobilePhone|alternateMobilePhone|officePhone|email' }).Count -eq 0))
                HasSmsOrVoice        = [bool](@($methods | Where-Object { $_ -match 'mobilePhone|alternateMobilePhone|officePhone' }).Count)
                LastUpdated          = $r.lastUpdatedDateTime
            }
        }
        Export-Dataset -Name 'mfa-registration' -Rows $regRows
    }
    catch { Set-DatasetStatus -Name 'mfa-registration' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 4. Successful single-factor sign-ins (includes legacy auth, which cannot do MFA) ----
    $sfRows = $null; $sfRaw = 0; $truncated = $false
    if ($SkipSignIns) { Set-DatasetStatus -Name 'signins-singlefactor-success' -Status 'Deferred' -Note '-SkipSignIns' }
    else {
        try {
            $since = $script:RunStartUtc.AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $filter = "createdDateTime ge $since and status/errorCode eq 0 and authenticationRequirement eq 'singleFactorAuthentication'"
            $uri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString($filter)
            $signIns = Invoke-GraphGetAll -Uri $uri -MaxRecords $MaxSignInRecords -Label 'signIns'
            $truncated = $script:LastQueryTruncated
            $sfRaw = $signIns.Count
            $modernClients = @('Browser', 'Mobile Apps and Desktop clients')
            $sfRows = $signIns | Group-Object -Property userPrincipalName, appDisplayName, clientAppUsed | ForEach-Object {
                $first = $_.Group[0]
                $times = @($_.Group | ForEach-Object { [datetime]$_.createdDateTime } | Sort-Object)
                [pscustomobject][ordered]@{
                    UserPrincipalName   = $first.userPrincipalName
                    UserType            = $(if ($first.PSObject.Properties.Name -contains 'userType') { $first.userType } else { '' })
                    AppDisplayName      = $first.appDisplayName
                    ClientAppUsed       = $first.clientAppUsed
                    IsLegacyAuth        = ($modernClients -notcontains $first.clientAppUsed)
                    SignInCount         = $_.Count
                    FirstSeenUtc        = $times[0].ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    LastSeenUtc         = $times[-1].ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    CaStatuses          = Join-Values (@($_.Group | ForEach-Object { $_.conditionalAccessStatus } | Sort-Object -Unique))
                    DistinctIpCount     = @($_.Group | ForEach-Object { $_.ipAddress } | Sort-Object -Unique).Count
                }
            }
            $note = "Lookback $SignInLookbackDays days; $sfRaw raw interactive sign-ins aggregated"
            if ($truncated) { $note += "; TRUNCATED at $MaxSignInRecords - rerun with a shorter lookback or higher cap" }
            Export-Dataset -Name 'signins-singlefactor-success' -Rows $sfRows -Note $note
        }
        catch { Set-DatasetStatus -Name 'signins-singlefactor-success' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }
    }

    # ---- 5. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    if ($policyRows.Count -gt 0) {
        Add-Metric 'CA policies (total)' $policyRows.Count
        Add-Metric 'CA policies enabled' @($policyRows | Where-Object State -eq 'enabled').Count
        Add-Metric 'CA policies report-only' @($policyRows | Where-Object State -eq 'enabledForReportingButNotEnforced').Count
        Add-Metric 'CA policies disabled' @($policyRows | Where-Object State -eq 'disabled').Count
        Add-Metric 'Enabled policies requiring MFA/auth strength' @($policyRows | Where-Object { $_.State -eq 'enabled' -and $_.RequiresMfa }).Count
        Add-Metric 'Enabled policies blocking legacy auth' @($policyRows | Where-Object { $_.State -eq 'enabled' -and $_.BlocksLegacyAuth }).Count 'Heuristic: block grant + EAS/other client types'
        Add-Metric 'CA exclusions (rows)' $exclusionRows.Count
        Add-Metric 'Distinct groups excluded from CA' $excludedGroups.Count
    }
    if ($regRows) {
        $members = @($regRows | Where-Object UserType -eq 'member')
        $pct = { param($n, $d) if ($d -gt 0) { [math]::Round(100 * $n / $d, 1) } else { 0 } }
        Add-Metric 'Member users in registration report' $members.Count
        Add-Metric 'Members MFA registered (%)' (& $pct @($members | Where-Object IsMfaRegistered).Count $members.Count)
        Add-Metric 'Members MFA capable (%)' (& $pct @($members | Where-Object IsMfaCapable).Count $members.Count)
        Add-Metric 'Members with SMS/voice registered' @($members | Where-Object HasSmsOrVoice).Count
        Add-Metric 'Members with phone/email methods only' @($members | Where-Object HasPhoneMethodOnly).Count
        Add-Metric 'Admins not MFA registered' @($regRows | Where-Object { $_.IsAdmin -and -not $_.IsMfaRegistered }).Count
    }
    if ($null -ne $sfRows) {
        Add-Metric 'Successful single-factor sign-ins (raw)' $sfRaw "Last $SignInLookbackDays days$(if ($truncated) { ' (TRUNCATED)' })"
        Add-Metric 'Distinct users with single-factor success' @($sfRows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
        Add-Metric 'Distinct users using legacy auth successfully' @($sfRows | Where-Object IsLegacyAuth | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ SignInLookbackDays = $SignInLookbackDays; MaxSignInRecords = $MaxSignInRecords; SkipSignIns = [bool]$SkipSignIns; SkipExcludedGroupMembers = [bool]$SkipExcludedGroupMembers }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
