<#
.SYNOPSIS
    Read-only discovery of applications, service principals, permissions and consents in Entra ID.

.DESCRIPTION
    Answers "what non-human identities can move data, and what can they reach?":
      - Tenant consent settings (can users consent? is the admin-consent workflow on?)
      - App registrations with owners and credential hygiene
      - One row per app secret / certificate with expiry status
      - Service principals classified as Microsoft / this tenant / third party / managed identity
      - Application permissions (app roles) granted to each client
      - Delegated permission grants (admin vs user consent), with high-risk scopes flagged
      - A per-app risk summary - the "data movers" list
      - A summary of headline metrics

    Microsoft first-party service principals are skipped for app-role enumeration unless
    -IncludeMicrosoftApps is set (they are numerous and rarely the question).

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.
    Service-principal last sign-in uses the Graph BETA report endpoint (still a GET).

    Output: <OutputRoot>\03-AppsAndConsents\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\03-Get-AppsAndConsents.ps1
.EXAMPLE
    .\03-Get-AppsAndConsents.ps1 -CredentialWarningDays 60 -IncludeMicrosoftApps

.NOTES
    Version : 1.0.1
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : Application.Read.All, Directory.Read.All, Policy.Read.All, AuditLog.Read.All
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

    [int]$CredentialWarningDays = 30,
    [int]$LongLivedSecretDays = 730,
    [int]$StaleDays = 90,
    [switch]$IncludeMicrosoftApps,
    [switch]$SkipSignInActivity
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '03-AppsAndConsents'
$ScriptVersion = '1.0.1'
$RequiredScopes = @('Application.Read.All', 'Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All')

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
#endregion

# Microsoft first-party tenants that own Microsoft service principals.
$MicrosoftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

# Permissions that reach bulk data (DataAccess) or can escalate privilege (PrivilegeEscalation). Extend as needed.
$HighRiskPermissions = @{
    'Mail.Read' = 'DataAccess'; 'Mail.ReadWrite' = 'DataAccess'; 'Mail.ReadBasic.All' = 'DataAccess'; 'Mail.Send' = 'DataAccess'
    'MailboxSettings.ReadWrite' = 'DataAccess'; 'full_access_as_app' = 'DataAccess'; 'EWS.AccessAsUser.All' = 'DataAccess'
    'Files.Read.All' = 'DataAccess'; 'Files.ReadWrite.All' = 'DataAccess'
    'Sites.Read.All' = 'DataAccess'; 'Sites.ReadWrite.All' = 'DataAccess'; 'Sites.Manage.All' = 'DataAccess'; 'Sites.FullControl.All' = 'DataAccess'
    'Notes.Read.All' = 'DataAccess'; 'Notes.ReadWrite.All' = 'DataAccess'
    'Chat.Read.All' = 'DataAccess'; 'Chat.ReadWrite.All' = 'DataAccess'; 'ChannelMessage.Read.All' = 'DataAccess'
    'Calendars.Read' = 'DataAccess'; 'Calendars.ReadWrite' = 'DataAccess'; 'Contacts.Read' = 'DataAccess'; 'Contacts.ReadWrite' = 'DataAccess'
    'User.Export.All' = 'DataAccess'; 'Directory.Read.All' = 'DataAccess'; 'User.Read.All' = 'DataAccess'; 'AuditLog.Read.All' = 'DataAccess'
    'Directory.ReadWrite.All' = 'PrivilegeEscalation'; 'User.ReadWrite.All' = 'PrivilegeEscalation'
    'Group.ReadWrite.All' = 'PrivilegeEscalation'; 'GroupMember.ReadWrite.All' = 'PrivilegeEscalation'
    'Application.ReadWrite.All' = 'PrivilegeEscalation'; 'Application.ReadWrite.OwnedBy' = 'PrivilegeEscalation'
    'AppRoleAssignment.ReadWrite.All' = 'PrivilegeEscalation'; 'DelegatedPermissionGrant.ReadWrite.All' = 'PrivilegeEscalation'
    'RoleManagement.ReadWrite.Directory' = 'PrivilegeEscalation'; 'Policy.ReadWrite.ConditionalAccess' = 'PrivilegeEscalation'
    'UserAuthenticationMethod.ReadWrite.All' = 'PrivilegeEscalation'; 'Domain.ReadWrite.All' = 'PrivilegeEscalation'
}

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph
    $thisTenant = $ctx.TenantId
    $now = $script:RunStartUtc

    # ---- 1. Tenant consent settings ----
    try {
        $authz = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        $acr = $null
        try { $acr = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' } catch { }
        $grantPolicies = @($authz.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
        $userConsent = 'Users cannot consent'
        if ($grantPolicies -match 'microsoft-user-default-legacy') { $userConsent = 'Users can consent to ANY app (legacy default)' }
        elseif ($grantPolicies -match 'microsoft-user-default-low') { $userConsent = 'Users can consent to verified-publisher apps for low-risk permissions' }
        elseif ($grantPolicies.Count -gt 0) { $userConsent = 'Custom grant policy: ' + ($grantPolicies -join ', ') }
        $settings = @(
            [pscustomobject][ordered]@{ Setting = 'User consent'; Value = $userConsent; Raw = Join-Values $grantPolicies }
            [pscustomobject][ordered]@{ Setting = 'Users can register applications'; Value = $authz.defaultUserRolePermissions.allowedToCreateApps; Raw = '' }
            [pscustomobject][ordered]@{ Setting = 'Users can create security groups'; Value = $authz.defaultUserRolePermissions.allowedToCreateSecurityGroups; Raw = '' }
            [pscustomobject][ordered]@{ Setting = 'Guest invite policy'; Value = $authz.allowInvitesFrom; Raw = '' }
            [pscustomobject][ordered]@{ Setting = 'Admin consent request workflow enabled'; Value = $(if ($acr) { $acr.isEnabled } else { 'unreadable' }); Raw = $(if ($acr) { 'reviewers: ' + @($acr.reviewers).Count } else { '' }) }
        )
        Export-Dataset -Name 'tenant-consent-settings' -Rows $settings
    }
    catch { Set-DatasetStatus -Name 'tenant-consent-settings' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 2. App registrations + credentials ----
    $credRows = [System.Collections.Generic.List[object]]::new()
    $appRegByAppId = @{}
    try {
        $apps = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess,publisherDomain&$expand=owners($select=id,displayName,userPrincipalName)' -Label 'applications'
        $appRows = foreach ($a in $apps) {
            $creds = @()
            foreach ($c in @($a.passwordCredentials)) { if ($c) { $creds += [pscustomobject]@{ Type = 'Secret'; Name = $c.displayName; Hint = $c.hint; Start = $c.startDateTime; End = $c.endDateTime } } }
            foreach ($c in @($a.keyCredentials)) { if ($c) { $creds += [pscustomobject]@{ Type = 'Certificate'; Name = $c.displayName; Hint = ''; Start = $c.startDateTime; End = $c.endDateTime } } }
            $myCreds = [System.Collections.Generic.List[object]]::new()
            foreach ($c in $creds) {
                $end = $(if ($c.End) { [datetime]$c.End } else { $null })
                $start = $(if ($c.Start) { [datetime]$c.Start } else { $null })
                $days = $(if ($end) { [int]($end.ToUniversalTime() - $now).TotalDays } else { $null })
                $life = $(if ($end -and $start) { [int]($end - $start).TotalDays } else { $null })
                $status = 'Valid'
                if ($null -ne $days -and $days -lt 0) { $status = 'Expired' } elseif ($null -ne $days -and $days -le $CredentialWarningDays) { $status = 'ExpiringSoon' }
                $credRow = [pscustomobject][ordered]@{
                    AppDisplayName = $a.displayName
                    AppId          = $a.appId
                    CredentialType = $c.Type
                    CredentialName = $c.Name
                    SecretHint     = $c.Hint
                    StartUtc       = $c.Start
                    EndUtc         = $c.End
                    DaysToExpiry   = $days
                    LifetimeDays   = $life
                    Status         = $status
                    LongLived      = ($c.Type -eq 'Secret' -and $null -ne $life -and $life -gt $LongLivedSecretDays)
                }
                $credRows.Add($credRow); $myCreds.Add($credRow)
            }
            $owners = @($a.owners | Where-Object { $_ })
            $nearest = @($myCreds | Where-Object { $null -ne $_.DaysToExpiry -and $_.DaysToExpiry -ge 0 } | Sort-Object DaysToExpiry | Select-Object -First 1)
            $row = [pscustomobject][ordered]@{
                AppObjectId          = $a.id
                AppId                = $a.appId
                DisplayName          = $a.displayName
                Created              = $a.createdDateTime
                SignInAudience       = $a.signInAudience
                OwnerCount           = $owners.Count
                Owners               = Join-Values ($owners | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } })
                SecretCount          = @($myCreds | Where-Object CredentialType -eq 'Secret').Count
                CertificateCount     = @($myCreds | Where-Object CredentialType -eq 'Certificate').Count
                HasExpiredCredential = [bool]@($myCreds | Where-Object Status -eq 'Expired').Count
                HasExpiringSoon      = [bool]@($myCreds | Where-Object Status -eq 'ExpiringSoon').Count
                HasLongLivedSecret   = [bool]@($myCreds | Where-Object LongLived).Count
                NextExpiryDays       = $(if ($nearest) { $nearest[0].DaysToExpiry } else { '' })
                RequestedApiCount    = @($a.requiredResourceAccess).Count
            }
            $appRegByAppId[$a.appId] = $row
            $row
        }
        Export-Dataset -Name 'app-registrations' -Rows $appRows
        Export-Dataset -Name 'app-credentials' -Rows $credRows
    }
    catch {
        $st = Get-FailureStatus $_
        Set-DatasetStatus -Name 'app-registrations' -Status $st -Note $_.Exception.Message
        Set-DatasetStatus -Name 'app-credentials' -Status $st -Note 'Depends on app-registrations'
    }

    # ---- 3. Service-principal sign-in activity (beta report) ----
    $spLastSignIn = @{}
    if ($SkipSignInActivity) { Write-RunLog 'SP sign-in activity skipped (-SkipSignInActivity).' 'WARN' }
    else {
        try {
            foreach ($s in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities' -Label 'spSignInActivities')) {
                if ($s.lastSignInActivity -and $s.lastSignInActivity.lastSignInDateTime) { $spLastSignIn[$s.appId] = [datetime]$s.lastSignInActivity.lastSignInDateTime }
            }
            Write-RunLog ("SP sign-in activity loaded for {0} apps" -f $spLastSignIn.Count)
        }
        catch { Write-RunLog ("SP sign-in activity unavailable ({0}); LastSignIn will be blank." -f $_.Exception.Message) 'WARN'; $SkipSignInActivity = $true }
    }

    # ---- 4. Service principals ----
    $sps = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,appRoleAssignmentRequired,tags,preferredSingleSignOnMode,verifiedPublisher,createdDateTime,appRoles,oauth2PermissionScopes' -Label 'servicePrincipals'
    $spById = @{}
    foreach ($s in $sps) { $spById[$s.id] = $s }
    function Get-OwnerClass {
        param($Sp)
        if ($Sp.servicePrincipalType -eq 'ManagedIdentity') { return 'ManagedIdentity' }
        if ($MicrosoftTenants -contains $Sp.appOwnerOrganizationId) { return 'Microsoft' }
        if ($Sp.appOwnerOrganizationId -eq $thisTenant) { return 'ThisTenant' }
        if (-not $Sp.appOwnerOrganizationId) { return 'Unknown' }
        return 'ThirdParty'
    }
    $spRows = foreach ($s in $sps) {
        $last = $spLastSignIn[$s.appId]
        [pscustomobject][ordered]@{
            SpObjectId           = $s.id
            AppId                = $s.appId
            DisplayName          = $s.displayName
            Type                 = $s.servicePrincipalType
            OwnerClass           = Get-OwnerClass $s
            Publisher            = $(if ($s.verifiedPublisher) { $s.verifiedPublisher.displayName } else { '' })
            AccountEnabled       = $s.accountEnabled
            AssignmentRequired   = $s.appRoleAssignmentRequired
            SsoMode              = $s.preferredSingleSignOnMode
            IsEnterpriseApp      = (@($s.tags) -contains 'WindowsAzureActiveDirectoryIntegratedApp')
            HasAppRegistration   = $appRegByAppId.ContainsKey($s.appId)
            Created              = $s.createdDateTime
            LastSignInUtc        = $(if ($last) { $last.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        }
    }
    Export-Dataset -Name 'service-principals' -Rows $spRows -Note $(if ($SkipSignInActivity) { 'LastSignIn not available' } else { '' })

    # ---- 5. Application permissions (app roles granted to client SPs) ----
    $appPermRows = [System.Collections.Generic.List[object]]::new()
    $spOwnerCount = @{}
    try {
        $targets = @($sps | Where-Object { $IncludeMicrosoftApps -or (Get-OwnerClass $_) -ne 'Microsoft' })
        Write-RunLog ("Enumerating app-role assignments and owners for {0} service principals" -f $targets.Count)
        foreach ($s in $targets) {
            try { $spOwnerCount[$s.id] = (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/owners?`$select=id" -f $s.id) -Label "owners $($s.id)").Count } catch { $spOwnerCount[$s.id] = '' }
            foreach ($ar in (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments" -f $s.id) -Label "appRoleAssignments $($s.id)")) {
                $res = $spById[$ar.resourceId]
                $perm = '(default access)'
                if ($res -and $ar.appRoleId -ne '00000000-0000-0000-0000-000000000000') {
                    $role = @($res.appRoles | Where-Object id -eq $ar.appRoleId) | Select-Object -First 1
                    $perm = $(if ($role) { $role.value } else { $ar.appRoleId })
                }
                $appPermRows.Add([pscustomobject][ordered]@{
                    ClientDisplayName = $s.displayName
                    ClientAppId       = $s.appId
                    ClientOwnerClass  = Get-OwnerClass $s
                    ResourceName      = $ar.resourceDisplayName
                    Permission        = $perm
                    RiskCategory      = $(if ($HighRiskPermissions.ContainsKey($perm)) { $HighRiskPermissions[$perm] } else { '' })
                    GrantedUtc        = $ar.createdDateTime
                })
            }
        }
        Export-Dataset -Name 'app-permissions-application' -Rows $appPermRows -Note $(if ($IncludeMicrosoftApps) { 'Includes Microsoft first-party' } else { 'Microsoft first-party clients excluded' })
    }
    catch { Set-DatasetStatus -Name 'app-permissions-application' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 6. Delegated permission grants ----
    $delRows = [System.Collections.Generic.List[object]]::new()
    $userUpn = @{}
    try {
        foreach ($g in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Label 'oauth2PermissionGrants')) {
            $client = $spById[$g.clientId]; $res = $spById[$g.resourceId]
            $scopes = @(("$($g.scope)").Trim() -split '\s+' | Where-Object { $_ })
            $risky = @($scopes | Where-Object { $HighRiskPermissions.ContainsKey($_) })
            $principal = ''
            if ($g.consentType -eq 'Principal' -and $g.principalId) {
                if (-not $userUpn.ContainsKey($g.principalId)) {
                    try { $userUpn[$g.principalId] = (Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select=userPrincipalName" -f $g.principalId)).userPrincipalName } catch { $userUpn[$g.principalId] = $g.principalId }
                }
                $principal = $userUpn[$g.principalId]
            }
            $delRows.Add([pscustomobject][ordered]@{
                ClientDisplayName = $(if ($client) { $client.displayName } else { $g.clientId })
                ClientAppId       = $(if ($client) { $client.appId } else { '' })
                ClientOwnerClass  = $(if ($client) { Get-OwnerClass $client } else { 'Unknown' })
                ResourceName      = $(if ($res) { $res.displayName } else { $g.resourceId })
                ConsentType       = $(if ($g.consentType -eq 'AllPrincipals') { 'Admin (all users)' } else { 'User' })
                ConsentedBy       = $principal
                Scopes            = Join-Values $scopes
                HighRiskScopes    = Join-Values $risky
            })
        }
        Export-Dataset -Name 'app-permissions-delegated' -Rows $delRows
    }
    catch { Set-DatasetStatus -Name 'app-permissions-delegated' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 7. Per-app risk summary ("data movers") ----
    $apByApp = @{}; foreach ($r in $appPermRows) { if (-not $apByApp.ContainsKey($r.ClientAppId)) { $apByApp[$r.ClientAppId] = [System.Collections.Generic.List[object]]::new() }; $apByApp[$r.ClientAppId].Add($r) }
    $dgByApp = @{}; foreach ($r in $delRows) { if (-not $dgByApp.ContainsKey($r.ClientAppId)) { $dgByApp[$r.ClientAppId] = [System.Collections.Generic.List[object]]::new() }; $dgByApp[$r.ClientAppId].Add($r) }
    $riskRows = foreach ($s in ($sps | Where-Object { (Get-OwnerClass $_) -ne 'Microsoft' -or $IncludeMicrosoftApps })) {
        $ap = @(); if ($apByApp.ContainsKey($s.appId)) { $ap = @($apByApp[$s.appId]) }
        $dg = @(); if ($dgByApp.ContainsKey($s.appId)) { $dg = @($dgByApp[$s.appId]) }
        if ($ap.Count -eq 0 -and $dg.Count -eq 0) { continue }
        $apRisk = @($ap | Where-Object RiskCategory)
        $dgRisk = @($dg | Where-Object HighRiskScopes)
        $reg = $appRegByAppId[$s.appId]
        $last = $spLastSignIn[$s.appId]
        $flags = @()
        if ($apRisk | Where-Object RiskCategory -eq 'DataAccess') { $flags += 'AppPerm:DataAccess' }
        if ($apRisk | Where-Object RiskCategory -eq 'PrivilegeEscalation') { $flags += 'AppPerm:PrivilegeEscalation' }
        if ($dgRisk) { $flags += 'Delegated:HighRisk' }
        if (@($dg | Where-Object ConsentType -eq 'User').Count) { $flags += 'UserConsented' }
        $owners = $(if ($reg) { $reg.OwnerCount } else { $spOwnerCount[$s.id] })
        if ($owners -eq 0) { $flags += 'NoOwner' }
        if ($reg -and $reg.HasExpiredCredential) { $flags += 'ExpiredCredential' }
        if ($reg -and $reg.HasLongLivedSecret) { $flags += 'LongLivedSecret' }
        if (-not $SkipSignInActivity -and (-not $last -or $last -lt $now.AddDays(-$StaleDays))) { $flags += "NoSignIn${StaleDays}d" }
        $score = (3 * @($apRisk).Count) + (2 * @($dgRisk).Count) + $(if ($owners -eq 0) { 2 } else { 0 }) + $(if ($flags -contains 'UserConsented') { 1 } else { 0 })
        [pscustomobject][ordered]@{
            DisplayName               = $s.displayName
            AppId                     = $s.appId
            OwnerClass                = Get-OwnerClass $s
            Publisher                 = $(if ($s.verifiedPublisher) { $s.verifiedPublisher.displayName } else { '' })
            ApplicationPermissions    = $ap.Count
            HighRiskAppPermissions    = Join-Values ($apRisk | ForEach-Object { '{0}:{1}' -f $_.ResourceName, $_.Permission } | Sort-Object -Unique)
            DelegatedGrants           = $dg.Count
            HighRiskDelegatedScopes   = Join-Values ($dgRisk | ForEach-Object { $_.HighRiskScopes -split '; ' } | Sort-Object -Unique)
            UserConsentCount          = @($dg | Where-Object ConsentType -eq 'User').Count
            OwnerCount                = $owners
            LastSignInUtc             = $(if ($last) { $last.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            Flags                     = Join-Values $flags
            TriageScore               = $score
        }
    }
    $riskRows = @($riskRows | Sort-Object TriageScore -Descending)
    Export-Dataset -Name 'app-risk-summary' -Rows $riskRows -Note 'TriageScore is a sorting aid, not a risk rating'

    # ---- 8. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'App registrations' $appRegByAppId.Count
    Add-Metric 'App registrations with no owner' @($appRegByAppId.Values | Where-Object { $_.OwnerCount -eq 0 }).Count
    Add-Metric 'App credentials expired' @($credRows | Where-Object Status -eq 'Expired').Count
    Add-Metric "App credentials expiring within $CredentialWarningDays days" @($credRows | Where-Object Status -eq 'ExpiringSoon').Count
    Add-Metric "Secrets with lifetime over $LongLivedSecretDays days" @($credRows | Where-Object LongLived).Count
    foreach ($cls in 'ThisTenant', 'ThirdParty', 'ManagedIdentity', 'Microsoft', 'Unknown') { Add-Metric "Service principals: $cls" @($spRows | Where-Object OwnerClass -eq $cls).Count }
    Add-Metric 'Application-permission grants (non-Microsoft clients)' @($appPermRows | Where-Object ClientOwnerClass -ne 'Microsoft').Count
    Add-Metric 'Application-permission grants that are high-risk' @($appPermRows | Where-Object RiskCategory).Count
    Add-Metric 'Delegated grants (admin consent)' @($delRows | Where-Object { $_.ConsentType -like 'Admin*' }).Count
    Add-Metric 'Delegated grants (user consent)' @($delRows | Where-Object ConsentType -eq 'User').Count
    Add-Metric 'Delegated grants with high-risk scopes' @($delRows | Where-Object HighRiskScopes).Count
    Add-Metric 'Apps in data-movers list' @($riskRows).Count
    Add-Metric 'Data movers with no owner' @($riskRows | Where-Object { $_.Flags -match 'NoOwner' }).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ CredentialWarningDays = $CredentialWarningDays; LongLivedSecretDays = $LongLivedSecretDays; StaleDays = $StaleDays; IncludeMicrosoftApps = [bool]$IncludeMicrosoftApps; SkipSignInActivity = [bool]$SkipSignInActivity }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
