<#
.SYNOPSIS
    Read-only discovery of device identity and compliance posture (Entra devices + Intune), and of
    which Conditional Access policies actually depend on it.

.DESCRIPTION
    Zero Trust device controls only work if devices are registered, managed and evaluated. This
    script exports:
      - Entra device objects: join type (Entra joined / hybrid joined / registered), compliant,
        managed, enabled, last sign-in, and flags (stale, unmanaged, non-compliant)
      - Intune managed devices: compliance state, last check-in, encryption, jailbreak, ownership,
        and whether each one has a matching Entra device object
      - Compliance policies with how many assignments they have, plus the tenant setting that
        decides whether a device with NO compliance policy counts as compliant
      - Conditional Access policies that require a compliant / hybrid-joined device, use device
        filters, or target device platforms - with their state
      - A summary of headline metrics

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\16-DevicePosture\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\16-Get-DevicePosture.ps1
.EXAMPLE
    .\16-Get-DevicePosture.ps1 -StaleDays 60 -SkipIntune

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : Device.Read.All, DeviceManagementManagedDevices.Read.All,
              DeviceManagementConfiguration.Read.All, Policy.Read.All
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
    [switch]$SkipIntune
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '16-DevicePosture'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('Device.Read.All', 'Policy.Read.All')
if (-not $SkipIntune) { $RequiredScopes += @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All') }

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

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- 1. Entra devices ----
    $devRows = [System.Collections.Generic.List[object]]::new()
    $entraByDeviceId = @{}
    try {
        $devs = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled,approximateLastSignInDateTime,registrationDateTime&$top=999' -Label 'devices'
        foreach ($d in $devs) {
            if ($d.deviceId) { $entraByDeviceId["$($d.deviceId)".ToLowerInvariant()] = $d }
            $age = Get-Age $d.approximateLastSignInDateTime
            $flags = @()
            if (-not $d.accountEnabled) { $flags += 'Disabled' }
            if ($null -eq $age -or $age -gt $StaleDays) { $flags += "NoSignIn${StaleDays}d" }
            if (-not $d.isManaged) { $flags += 'Unmanaged' }
            if ($d.isManaged -and -not $d.isCompliant) { $flags += 'NonCompliant' }
            if (-not $d.trustType) { $flags += 'NoJoinType' }
            $devRows.Add([pscustomobject][ordered]@{
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
            })
        }
        Export-Dataset -Name 'entra-devices' -Rows $devRows -Note 'approximateLastSignInDateTime is updated roughly every 14 days'
    }
    catch { Set-DatasetStatus -Name 'entra-devices' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 2. Intune ----
    $mdRows = [System.Collections.Generic.List[object]]::new()
    $polRows = @(); $secureByDefault = $null
    if ($SkipIntune) {
        foreach ($n in 'intune-devices', 'compliance-policies') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note '-SkipIntune' }
    }
    else {
        try {
            $md = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,managementAgent,managedDeviceOwnerType,lastSyncDateTime,enrolledDateTime,azureADDeviceId,userPrincipalName,isEncrypted,jailBroken' -Label 'managedDevices'
            foreach ($m in $md) {
                $age = Get-Age $m.lastSyncDateTime
                $hasEntra = [bool]($m.azureADDeviceId -and $entraByDeviceId.ContainsKey("$($m.azureADDeviceId)".ToLowerInvariant()))
                $flags = @()
                if ("$($m.complianceState)" -notin @('compliant', 'inGracePeriod')) { $flags += "Compliance:$($m.complianceState)" }
                if ($null -eq $age -or $age -gt $CheckInStaleDays) { $flags += "NoCheckIn${CheckInStaleDays}d" }
                if ($m.isEncrypted -eq $false) { $flags += 'NotEncrypted' }
                if ("$($m.jailBroken)" -eq 'True') { $flags += 'Jailbroken' }
                if (-not $hasEntra) { $flags += 'NoEntraDeviceObject' }
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
                })
            }
            Export-Dataset -Name 'intune-devices' -Rows $mdRows
        }
        catch { Set-DatasetStatus -Name 'intune-devices' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

        try {
            try { $dm = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/deviceManagement?$select=settings'; $secureByDefault = $dm.settings.secureByDefault } catch { Write-RunLog ("deviceManagement settings unreadable: {0}" -f $_.Exception.Message) 'WARN' }
            $pols = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$select=id,displayName,lastModifiedDateTime' -Label 'deviceCompliancePolicies'
            $polRows = foreach ($p in $pols) {
                $asg = @()
                try { $asg = (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/{0}/assignments" -f $p.id) -Label "assignments $($p.id)") } catch { }
                $targets = @($asg | ForEach-Object { ("$($_.target.'@odata.type')" -replace '#microsoft.graph.', '') + $(if ($_.target.groupId) { ':' + $_.target.groupId } else { '' }) })
                [pscustomobject][ordered]@{
                    PolicyName      = $p.displayName
                    Platform        = ("$($p.'@odata.type')" -replace '#microsoft.graph.', '' -replace 'CompliancePolicy$', '')
                    LastModifiedUtc = Format-Utc $p.lastModifiedDateTime
                    AssignmentCount = @($asg).Count
                    Targets         = Join-Values $targets
                    Unassigned      = (@($asg).Count -eq 0)
                }
            }
            Export-Dataset -Name 'compliance-policies' -Rows $polRows -Note $(if ($null -ne $secureByDefault) { "Devices with no compliance policy are marked: $(if ($secureByDefault) { 'Not compliant (secure)' } else { 'Compliant (default)' })" } else { 'Tenant no-policy setting unreadable' })
        }
        catch { Set-DatasetStatus -Name 'compliance-policies' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }
    }

    # ---- 3. CA policies that depend on device state ----
    $caRows = @()
    try {
        $ca = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'caPolicies'
        $caRows = foreach ($p in $ca) {
            $g = @(); if ($p.grantControls) { $g = @($p.grantControls.builtInControls) }
            $c = $p.conditions
            $usesFilter = [bool]($c.devices -and $c.devices.deviceFilter -and $c.devices.deviceFilter.rule)
            $platforms = $(if ($c.platforms) { Join-Values $c.platforms.includePlatforms } else { '' })
            $requiresCompliant = $g -contains 'compliantDevice'
            $requiresHybrid = $g -contains 'domainJoinedDevice'
            if (-not ($requiresCompliant -or $requiresHybrid -or $usesFilter -or $platforms)) { continue }
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
            }
        }
        Export-Dataset -Name 'ca-device-requirements' -Rows $caRows -Note 'Only policies that require device state, use a device filter, or target platforms'
    }
    catch { Set-DatasetStatus -Name 'ca-device-requirements' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 4. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $enabled = @($devRows | Where-Object AccountEnabled)
    Add-Metric 'Entra device objects' $devRows.Count
    foreach ($j in 'Entra joined', 'Hybrid joined', 'Entra registered') { Add-Metric "Devices: $j" @($devRows | Where-Object JoinType -eq $j).Count }
    Add-Metric "Enabled devices with no sign-in in $StaleDays days" @($enabled | Where-Object { $_.Flags -match 'NoSignIn' }).Count 'Clean-up candidates'
    Add-Metric 'Enabled devices unmanaged' @($enabled | Where-Object { -not $_.IsManaged }).Count 'Cannot satisfy a require-compliant-device control'
    Add-Metric 'Managed devices marked non-compliant' @($enabled | Where-Object { $_.Flags -match 'NonCompliant' }).Count
    if (-not $SkipIntune) {
        Add-Metric 'Intune managed devices' $mdRows.Count
        Add-Metric 'Intune devices compliant (%)' $(if ($mdRows.Count) { [math]::Round(100 * @($mdRows | Where-Object { "$($_.ComplianceState)" -in @('compliant', 'inGracePeriod') }).Count / $mdRows.Count, 1) } else { '' })
        Add-Metric "Intune devices not checked in for $CheckInStaleDays days" @($mdRows | Where-Object { $_.Flags -match 'NoCheckIn' }).Count
        Add-Metric 'Intune devices not encrypted' @($mdRows | Where-Object { $_.IsEncrypted -eq $false }).Count
        Add-Metric 'Compliance policies' @($polRows).Count
        Add-Metric 'Compliance policies not assigned' @($polRows | Where-Object Unassigned).Count
        Add-Metric 'Devices with no policy treated as compliant' $(if ($null -eq $secureByDefault) { 'unknown' } else { -not [bool]$secureByDefault }) 'True = weaker: an unassigned device passes a compliant-device check'
    }
    Add-Metric 'CA policies requiring a compliant device (enabled)' @($caRows | Where-Object { $_.RequiresCompliantDevice -and $_.State -eq 'enabled' }).Count
    Add-Metric 'CA policies requiring a compliant device (report-only)' @($caRows | Where-Object { $_.RequiresCompliantDevice -and $_.State -eq 'enabledForReportingButNotEnforced' }).Count
    Add-Metric 'CA policies using device filters' @($caRows | Where-Object DeviceFilterRule).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ StaleDays = $StaleDays; CheckInStaleDays = $CheckInStaleDays; SkipIntune = [bool]$SkipIntune }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
