<#
.SYNOPSIS
    Read-only discovery of device identity and compliance posture (Entra devices + Intune), the
    controls around it (registration policy, enrollment restrictions, app protection, LAPS and
    BitLocker backup), and which Conditional Access policies depend on it - and who they exempt.

.DESCRIPTION
    Zero Trust device controls only work if devices are registered, managed and evaluated. This
    script exports:
      - Entra device objects: join type (Entra joined / hybrid joined / registered), ownership,
        management and enrollment type, compliant, managed, enabled, last sign-in, flags (stale,
        unmanaged, non-compliant, personal, duplicate name) and, with -IncludeDeviceOwners, the
        registered owners and users
      - Device registration policy: who can join / register, MFA to join, device quota, whether
        the joining user becomes local admin, and whether Windows LAPS is enabled
      - LAPS and BitLocker backup coverage: counts of devices with a backed-up LAPS password or
        BitLocker recovery key against enabled joined Windows devices (metadata only; passwords
        and keys are never requested)
      - Intune managed devices: compliance state, last check-in, encryption, jailbreak, ownership,
        serial / model, threat state, and whether each one has a matching Entra device object
      - Compliance policies with their include and exclude assignments, grace period before the
        device is marked non-compliant, plus the tenant setting that decides whether a device with
        NO compliance policy counts as compliant
      - Enrollment restrictions (platform and personal-device blocks, device limits) and app
        protection (MAM) policies
      - Conditional Access policies that require a compliant / hybrid-joined device or an approved
        / app-protected client app, use device filters, or target device platforms - with their
        state and every account their user, group and role exclusions exempt
      - A summary of headline metrics

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\16-DevicePosture\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER IncludeDeviceOwners
    Read registered owners and users for every device (two calls per device; slow in large tenants).

.PARAMETER SkipLapsBitLocker
    Skip the LAPS and BitLocker backup coverage counts.

.PARAMETER SkipCaExclusionExpansion
    Do not resolve CA exclusions to accounts (excluded groups and roles are expanded by default).

.EXAMPLE
    .\16-Get-DevicePosture.ps1
.EXAMPLE
    .\16-Get-DevicePosture.ps1 -StaleDays 60 -SkipIntune
.EXAMPLE
    .\16-Get-DevicePosture.ps1 -IncludeDeviceOwners -SkipLapsBitLocker

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : Device.Read.All, Policy.Read.All, Directory.Read.All (CA exclusion expansion),
              DeviceLocalCredential.ReadBasic.All and BitlockerKey.ReadBasic.All (backup coverage),
              DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All,
              DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All (Intune)
    Roles   : Global Reader, or Intune Read Only Operator plus Global Reader for CA
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

    [int]$StaleDays = 90,
    [int]$CheckInStaleDays = 30,
    [switch]$SkipIntune,
    [switch]$IncludeDeviceOwners,
    [switch]$SkipLapsBitLocker,
    [switch]$SkipCaExclusionExpansion
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '16-DevicePosture'
$ScriptVersion = '1.1.0'
$RequiredScopes = @('Device.Read.All', 'Policy.Read.All')
if (-not $SkipCaExclusionExpansion) { $RequiredScopes += @('Directory.Read.All') }
if (-not $SkipLapsBitLocker) { $RequiredScopes += @('DeviceLocalCredential.ReadBasic.All', 'BitlockerKey.ReadBasic.All') }
if (-not $SkipIntune) { $RequiredScopes += @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All', 'DeviceManagementApps.Read.All') }

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

$JoinTypes = @{ 'AzureAd' = 'Entra joined'; 'ServerAd' = 'Hybrid joined'; 'Workplace' = 'Entra registered' }
function Format-Utc { param($Value) if ($Value) { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } return '' }
function Get-Age { param($Value) if ($Value) { return [int]($script:RunStartUtc - ([datetime]$Value).ToUniversalTime()).TotalDays } return $null }

function Get-ScopeFailureStatus {
    # EvidenceUnavailable when the token lacks the scope the call needs; otherwise the usual mapping.
    # Scope lists the scopes that would each be enough (least privileged first).
    param($ErrorRecord, [string[]]$Scope)
    $held = @($Scope | Where-Object { $script:TokenScopes -contains $_ -or $script:TokenScopes -contains ($_ -replace 'ReadBasic', 'Read') })
    if ($Scope.Count -and $script:TokenScopes.Count -and -not $held.Count) { return 'EvidenceUnavailable' }
    return (Get-FailureStatus $ErrorRecord)
}

function Invoke-GraphGetAllWithHeader {
    # Same paging as Invoke-GraphGetAll, with extra request headers (GET only, via Invoke-GraphGet).
    param([Parameter(Mandatory)][string]$Uri, [hashtable]$Headers = @{})
    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $resp = Invoke-GraphGet -Uri $next -Headers $Headers
        if ($resp.PSObject.Properties.Name -contains 'value') { foreach ($item in @($resp.value)) { if ($null -ne $item) { $results.Add($item) } } }
        $next = $null
        if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $next = $resp.'@odata.nextLink' }
    }
    return , $results
}

function Get-MembershipText {
    # deviceRegistrationMembership -> All / None / Selected (n users, n groups)
    param($Membership)
    if (-not $Membership) { return '' }
    $t = "$($Membership.'@odata.type')"
    if ($t -match 'allDeviceRegistrationMembership') { return 'All' }
    if ($t -match 'noDeviceRegistrationMembership') { return 'None' }
    if ($t -match 'enumeratedDeviceRegistrationMembership') { return ('Selected ({0} users, {1} groups)' -f @($Membership.users | Where-Object { $_ }).Count, @($Membership.groups | Where-Object { $_ }).Count) }
    return ($t -replace '#microsoft.graph.', '')
}

$script:UserCache = @{}
function Get-UserInfo {
    param([string]$Id)
    if ($script:UserCache.ContainsKey($Id)) { return $script:UserCache[$Id] }
    $info = $null
    try {
        $u = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select=id,displayName,userPrincipalName,accountEnabled,userType" -f $Id)
        $info = [pscustomobject]@{ Id = $Id; Upn = "$($u.userPrincipalName)"; DisplayName = "$($u.displayName)"; Enabled = $u.accountEnabled; UserType = "$($u.userType)"; Status = 'Resolved' }
    }
    catch { $info = [pscustomobject]@{ Id = $Id; Upn = ''; DisplayName = ''; Enabled = ''; UserType = ''; Status = $(if ("$($_.Exception.Message) $($_.ErrorDetails.Message)" -match 'Request_ResourceNotFound|\b404\b') { 'NotFound (deleted)' } else { 'Unresolved: ' + $_.Exception.Message }) } }
    $script:UserCache[$Id] = $info
    return $info
}

$script:GroupUserCache = @{}
function Get-GroupUser {
    # Transitive user members of a group; $null when the group cannot be read.
    param([string]$Id)
    if ($script:GroupUserCache.ContainsKey($Id)) { return $script:GroupUserCache[$Id] }
    $users = $null
    try {
        $raw = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers?`$select=id,displayName,userPrincipalName,accountEnabled,userType&`$top=999" -f $Id) -Label "transitiveMembers $Id"
        $users = @($raw | Where-Object { "$($_.'@odata.type')" -match 'user' } | ForEach-Object { [pscustomobject]@{ Id = "$($_.id)"; Upn = "$($_.userPrincipalName)"; DisplayName = "$($_.displayName)"; Enabled = $_.accountEnabled; UserType = "$($_.userType)"; Status = 'Resolved' } })
    }
    catch { Write-RunLog ("Group {0} could not be expanded: {1}" -f $Id, $_.Exception.Message) 'WARN' }
    $script:GroupUserCache[$Id] = $users
    return $users
}

$script:RoleHolderCache = @{}
function Get-RoleHolder {
    # Active holders of a directory role (template id); role-assignable groups expanded. $null on failure.
    param([string]$RoleTemplateId)
    if ($script:RoleHolderCache.ContainsKey($RoleTemplateId)) { return $script:RoleHolderCache[$RoleTemplateId] }
    $out = $null
    try {
        $ras = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '{0}'&`$expand=principal" -f $RoleTemplateId) -Label "roleAssignments $RoleTemplateId"
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($ra in $ras) {
            $pr = $ra.principal
            $pt = "$($pr.'@odata.type')"
            if ($pt -match 'group') {
                $gu = Get-GroupUser "$($pr.id)"
                if ($null -eq $gu) { $list.Add([pscustomobject]@{ Id = "$($pr.id)"; Upn = ''; DisplayName = "$($pr.displayName)"; Enabled = ''; UserType = ''; Status = 'Group not expanded'; Via = "group $($pr.displayName)" }) }
                else { foreach ($u in $gu) { $list.Add([pscustomobject]@{ Id = $u.Id; Upn = $u.Upn; DisplayName = $u.DisplayName; Enabled = $u.Enabled; UserType = $u.UserType; Status = 'Resolved'; Via = "group $($pr.displayName)" }) } }
            }
            elseif ($pt -match 'user') { $list.Add([pscustomobject]@{ Id = "$($pr.id)"; Upn = "$($pr.userPrincipalName)"; DisplayName = "$($pr.displayName)"; Enabled = $pr.accountEnabled; UserType = "$($pr.userType)"; Status = 'Resolved'; Via = '' }) }
        }
        $out = $list.ToArray()
    }
    catch { Write-RunLog ("Role {0} holders could not be read: {1}" -f $RoleTemplateId, $_.Exception.Message) 'WARN' }
    $script:RoleHolderCache[$RoleTemplateId] = $out
    return $out
}

$ctx = $null
$script:TokenScopes = @()
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph
    $script:TokenScopes = @($ctx.Scopes)

    # ---- 1. Entra devices ----
    $devRows = [System.Collections.Generic.List[object]]::new()
    $entraByDeviceId = @{}
    $devs = @()
    $ownerFailures = 0
    try {
        $devs = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled,approximateLastSignInDateTime,registrationDateTime,deviceOwnership,profileType,managementType,enrollmentType,enrollmentProfileName&$top=999' -Label 'devices'
        $nameCount = @{}
        foreach ($d in $devs) { $k = "$($d.displayName)".ToLowerInvariant(); if ($k) { if ($nameCount.ContainsKey($k)) { $nameCount[$k]++ } else { $nameCount[$k] = 1 } } }
        foreach ($d in $devs) { if ($d.deviceId) { $entraByDeviceId["$($d.deviceId)".ToLowerInvariant()] = $d } }
        $script:DeviceRowsById = @{}
        foreach ($d in $devs) {
            $age = Get-Age $d.approximateLastSignInDateTime
            $dup = $(if ($d.displayName) { $nameCount["$($d.displayName)".ToLowerInvariant()] } else { 1 })
            $flags = @()
            if (-not $d.accountEnabled) { $flags += 'Disabled' }
            if ($null -eq $age -or $age -gt $StaleDays) { $flags += "NoSignIn${StaleDays}d" }
            if (-not $d.isManaged) { $flags += 'Unmanaged' }
            if ($d.isManaged -and -not $d.isCompliant) { $flags += 'NonCompliant' }
            if (-not $d.trustType) { $flags += 'NoJoinType' }
            if ("$($d.deviceOwnership)" -eq 'personal') { $flags += 'PersonalDevice' }
            if ($dup -gt 1) { $flags += 'DuplicateName' }
            $owners = ''; $users = ''
            if ($IncludeDeviceOwners) {
                try {
                    $owners = Join-Values (@((Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/devices/{0}/registeredOwners?`$select=id,userPrincipalName,displayName" -f $d.id) -Label "owners $($d.id)").ToArray()) | ForEach-Object { $(if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName }) })
                    $users = Join-Values (@((Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/devices/{0}/registeredUsers?`$select=id,userPrincipalName,displayName" -f $d.id) -Label "users $($d.id)").ToArray()) | ForEach-Object { $(if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName }) })
                }
                catch { $ownerFailures++; $owners = 'Unknown (read failed)'; $users = 'Unknown (read failed)' }
            }
            $row = [pscustomobject][ordered]@{
                DisplayName       = $d.displayName
                OperatingSystem   = $d.operatingSystem
                OSVersion         = $d.operatingSystemVersion
                JoinType          = $(if ($JoinTypes.ContainsKey("$($d.trustType)")) { $JoinTypes["$($d.trustType)"] } else { "$($d.trustType)" })
                AccountEnabled    = $d.accountEnabled
                IsManaged         = [bool]$d.isManaged
                IsCompliant       = [bool]$d.isCompliant
                RegisteredUtc     = Format-Utc $d.registrationDateTime
                LastSignInUtc     = Format-Utc $d.approximateLastSignInDateTime
                DaysSinceSignIn   = $age
                Flags             = Join-Values $flags
                DeviceId          = $d.deviceId
                DeviceOwnership   = "$($d.deviceOwnership)"
                ProfileType       = "$($d.profileType)"
                ManagementType    = "$($d.managementType)"
                EnrollmentType    = "$($d.enrollmentType)"
                EnrollmentProfile = "$($d.enrollmentProfileName)"
                ObjectsWithSameName = $dup
                RegisteredOwners  = $owners
                RegisteredUsers   = $users
                HasLapsBackup     = ''
                HasBitLockerKey   = ''
            }
            $devRows.Add($row)
            if ($d.deviceId) { $script:DeviceRowsById["$($d.deviceId)".ToLowerInvariant()] = $row }
        }
    }
    catch { Set-DatasetStatus -Name 'entra-devices' -Status (Get-FailureStatus $_) -Note $_.Exception.Message; $devs = $null }

    # ---- 1b. LAPS and BitLocker backup coverage (metadata only - never passwords or keys) ----
    $covRows = [System.Collections.Generic.List[object]]::new()
    $winDevices = @($devRows | Where-Object { "$($_.OperatingSystem)" -match '^Windows' -and $_.AccountEnabled -and $_.JoinType -in @('Entra joined', 'Hybrid joined') })
    if ($SkipLapsBitLocker) { Set-DatasetStatus -Name 'laps-bitlocker-coverage' -Status 'Deferred' -Note '-SkipLapsBitLocker' }
    elseif ($null -eq $devs) { Set-DatasetStatus -Name 'laps-bitlocker-coverage' -Status 'Blocked' -Note 'Entra devices not readable, so coverage cannot be calculated' }
    else {
        $hdr = @{ 'ocp-client-name' = 'IAM discovery (read-only)'; 'ocp-client-version' = $ScriptVersion }
        $checks = @(
            @{ Control = 'Windows LAPS password backup'; Scope = 'DeviceLocalCredential.ReadBasic.All'; Uri = 'https://graph.microsoft.com/v1.0/directory/deviceLocalCredentials?$select=id,deviceName,lastBackupDateTime'; IdProp = 'id'; RowProp = 'HasLapsBackup' }
            @{ Control = 'BitLocker recovery key escrow'; Scope = 'BitlockerKey.ReadBasic.All'; Uri = 'https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys?$select=id,deviceId,createdDateTime'; IdProp = 'deviceId'; RowProp = 'HasBitLockerKey' }
        )
        $covFailures = 0
        foreach ($c in $checks) {
            try {
                $items = Invoke-GraphGetAllWithHeader -Uri $c.Uri -Headers $hdr
                $ids = @{}
                foreach ($it in $items) { $v = "$($it.($c.IdProp))".ToLowerInvariant(); if ($v) { $ids[$v] = $true } }
                foreach ($r in $devRows) { if ($r.DeviceId) { $r.($c.RowProp) = [bool]$ids.ContainsKey("$($r.DeviceId)".ToLowerInvariant()) } }
                $covered = @($winDevices | Where-Object { $ids.ContainsKey("$($_.DeviceId)".ToLowerInvariant()) }).Count
                $covRows.Add([pscustomobject][ordered]@{ Control = $c.Control; Status = 'Read'; WindowsDevices = $winDevices.Count; DevicesWithBackup = $covered; CoveragePct = $(if ($winDevices.Count) { [math]::Round(100 * $covered / $winDevices.Count, 1) } else { '' }); ObjectsReturned = $items.Count; Note = 'Enabled Entra-joined and hybrid-joined Windows devices; metadata only' })
            }
            catch {
                $covFailures++
                $st = Get-ScopeFailureStatus $_ $c.Scope
                $covRows.Add([pscustomobject][ordered]@{ Control = $c.Control; Status = $st; WindowsDevices = $winDevices.Count; DevicesWithBackup = ''; CoveragePct = ''; ObjectsReturned = ''; Note = ("Needs {0}: {1}" -f $c.Scope, $_.Exception.Message) })
                Write-RunLog ("{0} not readable: {1}" -f $c.Control, $_.Exception.Message) 'WARN'
            }
        }
        if ($covFailures -eq $checks.Count) { Set-DatasetStatus -Name 'laps-bitlocker-coverage' -Status $(if (@($covRows | Where-Object Status -eq 'EvidenceUnavailable').Count) { 'EvidenceUnavailable' } else { 'Blocked' }) -Note (($covRows | ForEach-Object { $_.Note }) -join ' | ') }
        else { Export-Dataset -Name 'laps-bitlocker-coverage' -Rows $covRows -Status $(if ($covFailures) { 'Partial' } else { 'Completed' }) -Note 'Counts of backed-up LAPS passwords and BitLocker keys; no password or key is ever requested' }
    }
    if ($null -ne $devs) {
        $dNote = 'approximateLastSignInDateTime is updated roughly every 14 days'
        if ($ownerFailures) { $dNote += "; owners/users unreadable for $ownerFailures device(s)" }
        Export-Dataset -Name 'entra-devices' -Rows $devRows -Status $(if ($ownerFailures) { 'Partial' } else { 'Completed' }) -Note $dNote
    }

    # ---- 1c. Device registration policy ----
    $regPolicy = $null
    try {
        $regPolicy = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/deviceRegistrationPolicy'
        $join = $regPolicy.azureADJoin
        $la = $(if ($join) { $join.localAdmins } else { $null })
        $regRows = @(
            [pscustomobject][ordered]@{ Setting = 'UserDeviceQuota'; Value = "$($regPolicy.userDeviceQuota)"; Note = 'Maximum devices one user can join or register' }
            [pscustomobject][ordered]@{ Setting = 'MultiFactorAuthConfiguration'; Value = "$($regPolicy.multiFactorAuthConfiguration)"; Note = 'notRequired = MFA not enforced by this setting (Conditional Access may still require it)' }
            [pscustomobject][ordered]@{ Setting = 'EntraRegistrationAllowedFor'; Value = (Get-MembershipText $regPolicy.azureADRegistration.allowedToRegister); Note = 'Who can register personal devices' }
            [pscustomobject][ordered]@{ Setting = 'EntraJoinAllowedFor'; Value = $(if ($join) { Get-MembershipText $join.allowedToJoin } else { '' }); Note = 'Who can join devices to Entra ID' }
            [pscustomobject][ordered]@{ Setting = 'GlobalAdminsAreLocalAdmins'; Value = $(if ($la) { "$($la.enableGlobalAdmins)" } else { '' }); Note = '' }
            [pscustomobject][ordered]@{ Setting = 'RegisteringUserIsLocalAdmin'; Value = $(if ($la) { Get-MembershipText $la.registeringUsers } else { '' }); Note = 'All = whoever joins a device becomes its local administrator' }
            [pscustomobject][ordered]@{ Setting = 'WindowsLapsEnabled'; Value = $(if ($regPolicy.localAdminPassword) { "$($regPolicy.localAdminPassword.isEnabled)" } else { '' }); Note = 'Entra-side switch for Windows LAPS' }
        )
        Export-Dataset -Name 'device-registration-policy' -Rows $regRows
    }
    catch { Set-DatasetStatus -Name 'device-registration-policy' -Status (Get-ScopeFailureStatus $_ @('Policy.Read.DeviceConfiguration', 'Policy.Read.All')) -Note $_.Exception.Message }

    # ---- 2. Intune ----
    $mdRows = [System.Collections.Generic.List[object]]::new()
    $polRows = @(); $secureByDefault = $null
    $enrRows = [System.Collections.Generic.List[object]]::new(); $mamRows = @()
    if ($SkipIntune) {
        foreach ($n in 'intune-devices', 'compliance-policies', 'enrollment-restrictions', 'app-protection-policies') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note '-SkipIntune' }
    }
    else {
        try {
            $md = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,managementAgent,managedDeviceOwnerType,lastSyncDateTime,enrolledDateTime,azureADDeviceId,userPrincipalName,isEncrypted,jailBroken,serialNumber,model,manufacturer,deviceEnrollmentType,partnerReportedThreatState,complianceGracePeriodExpirationDateTime,enrollmentProfileName' -Label 'managedDevices'
            foreach ($m in $md) {
                $age = Get-Age $m.lastSyncDateTime
                $hasEntra = [bool]($m.azureADDeviceId -and $entraByDeviceId.ContainsKey("$($m.azureADDeviceId)".ToLowerInvariant()))
                $flags = @()
                if ("$($m.complianceState)" -notin @('compliant', 'inGracePeriod')) { $flags += "Compliance:$($m.complianceState)" }
                if ($null -eq $age -or $age -gt $CheckInStaleDays) { $flags += "NoCheckIn${CheckInStaleDays}d" }
                if ($m.isEncrypted -eq $false) { $flags += 'NotEncrypted' }
                if ("$($m.jailBroken)" -eq 'True') { $flags += 'Jailbroken' }
                if (-not $hasEntra) { $flags += 'NoEntraDeviceObject' }
                if ("$($m.partnerReportedThreatState)" -match 'mediumSeverity|highSeverity|compromised|misconfigured|unresponsive') { $flags += "Threat:$($m.partnerReportedThreatState)" }
                if ("$($m.managedDeviceOwnerType)" -eq 'personal') { $flags += 'PersonalDevice' }
                $mdRows.Add([pscustomobject][ordered]@{
                    DeviceName        = $m.deviceName
                    OperatingSystem   = $m.operatingSystem
                    OSVersion         = $m.osVersion
                    ComplianceState   = $m.complianceState
                    ManagementAgent   = $m.managementAgent
                    Ownership         = $m.managedDeviceOwnerType
                    PrimaryUser       = $m.userPrincipalName
                    EnrolledUtc       = Format-Utc $m.enrolledDateTime
                    LastCheckInUtc    = Format-Utc $m.lastSyncDateTime
                    DaysSinceCheckIn  = $age
                    IsEncrypted       = $m.isEncrypted
                    HasEntraObject    = $hasEntra
                    Flags             = Join-Values $flags
                    SerialNumber      = "$($m.serialNumber)"
                    Model             = "$($m.model)"
                    Manufacturer      = "$($m.manufacturer)"
                    EnrollmentType    = "$($m.deviceEnrollmentType)"
                    EnrollmentProfile = "$($m.enrollmentProfileName)"
                    ThreatState       = "$($m.partnerReportedThreatState)"
                    GraceExpiresUtc   = $(if ($m.complianceGracePeriodExpirationDateTime -and ([datetime]$m.complianceGracePeriodExpirationDateTime).Year -lt 9000) { Format-Utc $m.complianceGracePeriodExpirationDateTime } else { '' })
                    AzureADDeviceId   = "$($m.azureADDeviceId)"
                })
            }
            Export-Dataset -Name 'intune-devices' -Rows $mdRows
        }
        catch { Set-DatasetStatus -Name 'intune-devices' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

        try {
            try { $dm = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/deviceManagement?$select=settings'; $secureByDefault = $dm.settings.secureByDefault } catch { Write-RunLog ("deviceManagement settings unreadable: {0}" -f $_.Exception.Message) 'WARN' }
            $pols = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$select=id,displayName,lastModifiedDateTime' -Label 'deviceCompliancePolicies'
            $asgFailures = 0; $actFailures = 0
            $polRows = foreach ($p in $pols) {
                $asg = @(); $asgRead = $true
                try { $asg = @((Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/{0}/assignments" -f $p.id) -Label "assignments $($p.id)").ToArray()) }
                catch { $asgRead = $false; $asgFailures++; Write-RunLog ("Assignments unreadable for compliance policy {0}: {1}" -f $p.displayName, $_.Exception.Message) 'WARN' }
                $include = @($asg | Where-Object { "$($_.target.'@odata.type')" -notmatch 'exclusion' })
                $exclude = @($asg | Where-Object { "$($_.target.'@odata.type')" -match 'exclusion' })
                $targets = @($asg | ForEach-Object { $(if ("$($_.target.'@odata.type')" -match 'exclusion') { 'exclude:' } else { '' }) + ("$($_.target.'@odata.type')" -replace '#microsoft.graph.', '') + $(if ($_.target.groupId) { ':' + $_.target.groupId } else { '' }) })
                $targetNames = @($asg | ForEach-Object {
                    $t = "$($_.target.'@odata.type')"
                    $n = $(if ($_.target.groupId) { Resolve-DirectoryObject "$($_.target.groupId)" } elseif ($t -match 'allDevices') { 'All devices' } elseif ($t -match 'allLicensedUsers') { 'All users' } else { $t -replace '#microsoft.graph.', '' })
                    $(if ($t -match 'exclusion') { "exclude: $n" } else { $n })
                })
                $grace = ''; $acts = ''
                try {
                    $sa = @((Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/{0}/scheduledActionsForRule?`$expand=scheduledActionConfigurations" -f $p.id) -Label "scheduledActions $($p.id)").ToArray())
                    $items = @($sa | ForEach-Object { @($_.scheduledActionConfigurations) } | Where-Object { $_ })
                    $block = @($items | Where-Object { "$($_.actionType)" -eq 'block' } | Select-Object -First 1)
                    if ($block.Count) { $grace = $block[0].gracePeriodHours }
                    $acts = Join-Values ($items | ForEach-Object { '{0} after {1}h' -f $_.actionType, $_.gracePeriodHours })
                }
                catch { $actFailures++; $grace = 'Unknown'; $acts = 'Unknown (read failed)' }
                [pscustomobject][ordered]@{
                    PolicyName      = $p.displayName
                    Platform        = ("$($p.'@odata.type')" -replace '#microsoft.graph.', '' -replace 'CompliancePolicy$', '')
                    LastModifiedUtc = Format-Utc $p.lastModifiedDateTime
                    AssignmentCount = $(if ($asgRead) { $include.Count } else { '' })
                    Targets         = $(if ($asgRead) { Join-Values $targets } else { 'Unknown (assignments not readable)' })
                    Unassigned      = $(if ($asgRead) { ($include.Count -eq 0) } else { 'Unknown' })
                    ExclusionCount  = $(if ($asgRead) { $exclude.Count } else { '' })
                    TargetNames     = $(if ($asgRead) { Join-Values $targetNames } else { '' })
                    BlockGraceHours = $grace
                    Actions         = $acts
                    AssignmentRead  = $asgRead
                }
            }
            $pNote = $(if ($null -ne $secureByDefault) { "Devices with no compliance policy are marked: $(if ($secureByDefault) { 'Not compliant (secure)' } else { 'Compliant (default)' })" } else { 'Tenant no-policy setting unreadable' })
            $pNote += '; AssignmentCount counts include targets only (exclusions do not assign a policy)'
            if ($asgFailures) { $pNote += "; assignments unreadable for $asgFailures policy(ies) (Unassigned = Unknown)" }
            if ($actFailures) { $pNote += "; actions for non-compliance unreadable for $actFailures policy(ies)" }
            Export-Dataset -Name 'compliance-policies' -Rows $polRows -Status $(if ($asgFailures) { 'Partial' } else { 'Completed' }) -Note $pNote
        }
        catch { Set-DatasetStatus -Name 'compliance-policies' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

        # Enrollment restrictions (platform and personal-device blocks, device limit)
        try {
            $cfgs = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations' -Label 'deviceEnrollmentConfigurations'
            foreach ($c in $cfgs) {
                $t = "$($c.'@odata.type')"
                if ($t -match 'PlatformRestrictionsConfiguration') {
                    foreach ($pl in @(@('Windows', 'windowsRestriction'), @('iOS', 'iosRestriction'), @('Android', 'androidRestriction'), @('macOS', 'macOSRestriction'), @('WindowsMobile', 'windowsMobileRestriction'))) {
                        $r = $c.($pl[1])
                        if (-not $r) { continue }
                        $enrRows.Add([pscustomobject][ordered]@{ Configuration = $c.displayName; Priority = $c.priority; Type = 'PlatformRestrictions'; Platform = $pl[0]; PlatformBlocked = $r.platformBlocked; PersonalDeviceEnrollmentBlocked = $r.personalDeviceEnrollmentBlocked; OsMinimumVersion = "$($r.osMinimumVersion)"; OsMaximumVersion = "$($r.osMaximumVersion)"; DeviceLimit = '' })
                    }
                }
                elseif ($t -match 'PlatformRestrictionConfiguration' -and $c.platformRestriction) {
                    $r = $c.platformRestriction
                    $enrRows.Add([pscustomobject][ordered]@{ Configuration = $c.displayName; Priority = $c.priority; Type = 'PlatformRestriction'; Platform = "$($c.platformType)"; PlatformBlocked = $r.platformBlocked; PersonalDeviceEnrollmentBlocked = $r.personalDeviceEnrollmentBlocked; OsMinimumVersion = "$($r.osMinimumVersion)"; OsMaximumVersion = "$($r.osMaximumVersion)"; DeviceLimit = '' })
                }
                elseif ($t -match 'LimitConfiguration') {
                    $enrRows.Add([pscustomobject][ordered]@{ Configuration = $c.displayName; Priority = $c.priority; Type = 'DeviceLimit'; Platform = ''; PlatformBlocked = ''; PersonalDeviceEnrollmentBlocked = ''; OsMinimumVersion = ''; OsMaximumVersion = ''; DeviceLimit = $c.limit })
                }
            }
            Export-Dataset -Name 'enrollment-restrictions' -Rows $enrRows -Note 'Priority 0 / the Default configuration applies to everyone not covered by a higher-priority assigned one'
        }
        catch { Set-DatasetStatus -Name 'enrollment-restrictions' -Status (Get-ScopeFailureStatus $_ 'DeviceManagementServiceConfig.Read.All') -Note $_.Exception.Message }

        # App protection (MAM) policies
        try {
            $mam = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/managedAppPolicies' -Label 'managedAppPolicies'
            $mamRows = @($mam | ForEach-Object {
                $t = ("$($_.'@odata.type')" -replace '#microsoft.graph.', '')
                [pscustomobject][ordered]@{
                    PolicyName       = $_.displayName
                    PolicyType       = $t
                    Platform         = $(if ($t -match '^ios') { 'iOS' } elseif ($t -match '^android') { 'Android' } elseif ($t -match 'windows|mdmWindows') { 'Windows' } else { '' })
                    IsAssigned       = $(if ($_.PSObject.Properties.Name -contains 'isAssigned') { $_.isAssigned } else { '' })
                    DeployedAppCount = $(if ($_.PSObject.Properties.Name -contains 'deployedAppCount') { $_.deployedAppCount } else { '' })
                    LastModifiedUtc  = Format-Utc $_.lastModifiedDateTime
                }
            })
            Export-Dataset -Name 'app-protection-policies' -Rows $mamRows -Note 'IsAssigned is reported for app protection policies; blank for types that do not expose it'
        }
        catch { Set-DatasetStatus -Name 'app-protection-policies' -Status (Get-ScopeFailureStatus $_ 'DeviceManagementApps.Read.All') -Note $_.Exception.Message }
    }

    # ---- 3. CA policies that depend on device or app state, and who is excluded from them ----
    $caRows = @()
    $exclRows = [System.Collections.Generic.List[object]]::new()
    $exclFailures = 0
    try {
        $ca = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'caPolicies'
        $devicePolicies = [System.Collections.Generic.List[object]]::new()
        $caRows = foreach ($p in $ca) {
            $g = @(); if ($p.grantControls) { $g = @($p.grantControls.builtInControls) }
            $c = $p.conditions
            $usesFilter = [bool]($c.devices -and $c.devices.deviceFilter -and $c.devices.deviceFilter.rule)
            $platforms = $(if ($c.platforms) { Join-Values $c.platforms.includePlatforms } else { '' })
            $requiresCompliant = $g -contains 'compliantDevice'
            $requiresHybrid = $g -contains 'domainJoinedDevice'
            $requiresApproved = $g -contains 'approvedApplication'
            $requiresProtection = $g -contains 'compliantApplication'
            if (-not ($requiresCompliant -or $requiresHybrid -or $usesFilter -or $platforms -or $requiresApproved -or $requiresProtection)) { continue }
            $devicePolicies.Add($p)
            [pscustomobject][ordered]@{
                PolicyName              = $p.displayName
                State                   = $p.state
                RequiresCompliantDevice = $requiresCompliant
                RequiresHybridJoined    = $requiresHybrid
                GrantOperator           = $(if ($p.grantControls) { $p.grantControls.operator } else { '' })
                GrantControls           = Join-Values $g
                DeviceFilterMode        = $(if ($usesFilter) { $c.devices.deviceFilter.mode } else { '' })
                DeviceFilterRule        = $(if ($usesFilter) { $c.devices.deviceFilter.rule } else { '' })
                IncludePlatforms        = $platforms
                IncludeApplications     = Join-Values $c.applications.includeApplications
                IncludeUsers            = Join-Values $c.users.includeUsers
                ExcludeGroupCount       = @($c.users.excludeGroups | Where-Object { $_ }).Count
                RequiresApprovedApp     = $requiresApproved
                RequiresAppProtection   = $requiresProtection
                ExcludeUsers            = Join-Values (@($c.users.excludeUsers | Where-Object { $_ }) | ForEach-Object { Resolve-DirectoryObject "$_" })
                ExcludeGroups           = Join-Values (@($c.users.excludeGroups | Where-Object { $_ }) | ForEach-Object { Resolve-DirectoryObject "$_" })
                ExcludeRoleCount        = @($c.users.excludeRoles | Where-Object { $_ }).Count
                ExcludePlatforms        = $(if ($c.platforms) { Join-Values $c.platforms.excludePlatforms } else { '' })
                ExcludedAccounts        = ''
            }
        }
        $caRows = @($caRows)

        # Resolve every exclusion to the accounts it actually exempts.
        if ($SkipCaExclusionExpansion) { Set-DatasetStatus -Name 'device-ca-exclusions' -Status 'Deferred' -Note '-SkipCaExclusionExpansion' }
        else {
            for ($i = 0; $i -lt $devicePolicies.Count; $i++) {
                $p = $devicePolicies[$i]; $u = $p.conditions.users
                $accounts = @{}
                $add = {
                    param($Kind, $Object, $Info, $Via)
                    $exclRows.Add([pscustomobject][ordered]@{ Policy = $p.displayName; State = $p.state; ExclusionType = $Kind; ExcludedObject = $Object; UserPrincipalName = $Info.Upn; DisplayName = $Info.DisplayName; AccountEnabled = $Info.Enabled; UserType = $Info.UserType; Via = $Via; ResolveStatus = $Info.Status; UserId = $Info.Id })
                    if ($Info.Id -and $Info.Status -eq 'Resolved') { $accounts[$Info.Id] = $true }
                }
                foreach ($id in @($u.excludeUsers | Where-Object { $_ })) {
                    if ("$id" -eq 'GuestsOrExternalUsers') { & $add 'User' 'GuestsOrExternalUsers' ([pscustomobject]@{ Id = ''; Upn = ''; DisplayName = 'All guests and external users'; Enabled = ''; UserType = 'Guest'; Status = 'Keyword' }) ''; continue }
                    $info = Get-UserInfo "$id"
                    if ($info.Status -ne 'Resolved') { $exclFailures++ }
                    & $add 'User' "$id" $info ''
                }
                foreach ($gid in @($u.excludeGroups | Where-Object { $_ })) {
                    $gName = Resolve-DirectoryObject "$gid"
                    $members = Get-GroupUser "$gid"
                    if ($null -eq $members) { $exclFailures++; & $add 'Group' $gName ([pscustomobject]@{ Id = ''; Upn = ''; DisplayName = ''; Enabled = ''; UserType = ''; Status = 'Group not expanded (read failed)' }) ''; continue }
                    if (-not @($members).Count) { & $add 'Group' $gName ([pscustomobject]@{ Id = ''; Upn = ''; DisplayName = ''; Enabled = ''; UserType = ''; Status = 'Empty group' }) ''; continue }
                    foreach ($m in $members) { & $add 'Group' $gName $m "group $gName" }
                }
                foreach ($rid in @($u.excludeRoles | Where-Object { $_ })) {
                    $holders = Get-RoleHolder "$rid"
                    if ($null -eq $holders) { $exclFailures++; & $add 'Role' "$rid" ([pscustomobject]@{ Id = ''; Upn = ''; DisplayName = ''; Enabled = ''; UserType = ''; Status = 'Role holders not readable' }) ''; continue }
                    foreach ($h in $holders) { & $add 'Role' "$rid" $h $(if ($h.Via) { "role $rid via $($h.Via)" } else { "role $rid" }) }
                }
                if ($p.conditions.users.excludeGuestsOrExternalUsers) { & $add 'GuestsOrExternalUsers' 'excludeGuestsOrExternalUsers' ([pscustomobject]@{ Id = ''; Upn = ''; DisplayName = 'Guest / external user types'; Enabled = ''; UserType = 'Guest'; Status = 'Keyword' }) '' }
                $match = @($caRows | Where-Object { $_.PolicyName -eq $p.displayName })
                foreach ($mr in $match) { $mr.ExcludedAccounts = $accounts.Count }
            }
            Export-Dataset -Name 'device-ca-exclusions' -Rows $exclRows -Status $(if ($exclFailures) { 'Partial' } else { 'Completed' }) -Note ('Accounts exempted from device / app-protection CA policies: excluded users, transitive members of excluded groups, and holders of excluded roles' + $(if ($exclFailures) { "; $exclFailures exclusion(s) could not be resolved (see ResolveStatus)" } else { '' }))
        }
        Export-Dataset -Name 'ca-device-requirements' -Rows $caRows -Note 'Policies that require device state or an approved / app-protected client app, use a device filter, or target platforms'
    }
    catch {
        Set-DatasetStatus -Name 'ca-device-requirements' -Status (Get-FailureStatus $_) -Note $_.Exception.Message
        if (-not $SkipCaExclusionExpansion) { Set-DatasetStatus -Name 'device-ca-exclusions' -Status (Get-FailureStatus $_) -Note 'CA policies not readable' }
    }

    # ---- 4. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $enabled = @($devRows | Where-Object AccountEnabled)
    Add-Metric -Metric 'Entra device objects' $devRows.Count
    foreach ($j in 'Entra joined', 'Hybrid joined', 'Entra registered') { Add-Metric -Metric "Devices: $j" @($devRows | Where-Object JoinType -eq $j).Count }
    Add-Metric -Metric "Enabled devices with no sign-in in $StaleDays days" @($enabled | Where-Object { $_.Flags -match 'NoSignIn' }).Count 'Clean-up candidates'
    Add-Metric -Metric 'Enabled devices unmanaged' @($enabled | Where-Object { -not $_.IsManaged }).Count 'Cannot satisfy a require-compliant-device control'
    Add-Metric -Metric 'Managed devices marked non-compliant' @($enabled | Where-Object { $_.Flags -match 'NonCompliant' }).Count
    Add-Metric -Metric 'Enabled personal devices' @($enabled | Where-Object { $_.Flags -match 'PersonalDevice' }).Count
    Add-Metric -Metric 'Device objects sharing a display name' @($devRows | Where-Object { $_.Flags -match 'DuplicateName' }).Count 'Often stale re-joins; check before relying on name-based filters'
    foreach ($cr in $covRows) { Add-Metric -Metric ("{0} coverage (%)" -f $cr.Control) $(if ($cr.Status -eq 'Read') { $cr.CoveragePct } else { "unknown ($($cr.Status))" }) $(if ($cr.Status -eq 'Read') { "$($cr.DevicesWithBackup) of $($cr.WindowsDevices) enabled joined Windows devices" } else { $cr.Note }) }
    if ($regPolicy) {
        Add-Metric -Metric 'Device join allowed for' (Get-MembershipText $regPolicy.azureADJoin.allowedToJoin)
        Add-Metric -Metric 'Registering user becomes local admin' (Get-MembershipText $regPolicy.azureADJoin.localAdmins.registeringUsers) 'All = every user who joins a device is its local admin'
        Add-Metric -Metric 'Windows LAPS enabled in Entra' "$($regPolicy.localAdminPassword.isEnabled)"
    }
    if (-not $SkipIntune) {
        Add-Metric -Metric 'Intune managed devices' $mdRows.Count
        Add-Metric -Metric 'Intune devices compliant (%)' $(if ($mdRows.Count) { [math]::Round(100 * @($mdRows | Where-Object { "$($_.ComplianceState)" -in @('compliant', 'inGracePeriod') }).Count / $mdRows.Count, 1) } else { '' })
        Add-Metric -Metric "Intune devices not checked in for $CheckInStaleDays days" @($mdRows | Where-Object { $_.Flags -match 'NoCheckIn' }).Count
        Add-Metric -Metric 'Intune devices not encrypted' @($mdRows | Where-Object { $_.IsEncrypted -eq $false }).Count
        Add-Metric -Metric 'Intune devices with a reported threat' @($mdRows | Where-Object { $_.Flags -match 'Threat:' }).Count
        Add-Metric -Metric 'Compliance policies' @($polRows).Count
        Add-Metric -Metric 'Compliance policies not assigned' @($polRows | Where-Object { $_.Unassigned -eq $true }).Count 'Exclusion-only assignments count as not assigned'
        Add-Metric -Metric 'Compliance policies with unreadable assignments' @($polRows | Where-Object { "$($_.Unassigned)" -eq 'Unknown' }).Count
        Add-Metric -Metric 'Devices with no policy treated as compliant' $(if ($null -eq $secureByDefault) { 'unknown' } else { -not [bool]$secureByDefault }) 'True = weaker: an unassigned device passes a compliant-device check'
        Add-Metric -Metric 'Enrollment restrictions allowing personal devices' @($enrRows | Where-Object { $_.Type -match 'Platform' -and "$($_.PlatformBlocked)" -ne 'True' -and "$($_.PersonalDeviceEnrollmentBlocked)" -ne 'True' }).Count 'Platform rows where personal enrollment is not blocked'
        Add-Metric -Metric 'App protection policies' @($mamRows).Count
        Add-Metric -Metric 'App protection policies not assigned' @($mamRows | Where-Object { "$($_.IsAssigned)" -eq 'False' }).Count
    }
    Add-Metric -Metric 'CA policies requiring a compliant device (enabled)' @($caRows | Where-Object { $_.RequiresCompliantDevice -and $_.State -eq 'enabled' }).Count
    Add-Metric -Metric 'CA policies requiring a compliant device (report-only)' @($caRows | Where-Object { $_.RequiresCompliantDevice -and $_.State -eq 'enabledForReportingButNotEnforced' }).Count
    Add-Metric -Metric 'CA policies requiring an approved or app-protected client' @($caRows | Where-Object { $_.RequiresApprovedApp -or $_.RequiresAppProtection }).Count
    Add-Metric -Metric 'CA policies using device filters' @($caRows | Where-Object DeviceFilterRule).Count
    if (-not $SkipCaExclusionExpansion) { Add-Metric -Metric 'Accounts excluded from device CA policies' @($exclRows | Where-Object { $_.UserId } | Select-Object -ExpandProperty UserId -Unique).Count 'Distinct users exempted by user, group or role exclusions' }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ StaleDays = $StaleDays; CheckInStaleDays = $CheckInStaleDays; SkipIntune = [bool]$SkipIntune; IncludeDeviceOwners = [bool]$IncludeDeviceOwners; SkipLapsBitLocker = [bool]$SkipLapsBitLocker; SkipCaExclusionExpansion = [bool]$SkipCaExclusionExpansion }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
