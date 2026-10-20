<#
.SYNOPSIS
    Read-only snapshot of Entra ID Protection: users currently at risk, recent risk detections,
    risky workload identities, and whether Conditional Access acts on risk.

.DESCRIPTION
    Exports:
      - Risky users (at risk or confirmed compromised), with risk level, detail and age, and a
        flag when the user holds a directory role
      - Risk detections over a lookback window, one row per detection, plus an aggregate by
        detection type and level
      - Risky service principals (needs Workload Identities Premium; otherwise marked
        EvidenceUnavailable)
      - Conditional Access policies that use user risk or sign-in risk, with their state
      - A summary of headline metrics

    Legacy Identity Protection user-risk / sign-in-risk policies (configured outside CA) are not
    exposed by Microsoft Graph; check them in the portal if CA shows no risk policies.

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\21-IdentityRisk\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\21-Get-IdentityRisk.ps1
.EXAMPLE
    .\21-Get-IdentityRisk.ps1 -DetectionLookbackDays 90 -IncludeRemediated

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All,
              IdentityRiskyServicePrincipal.Read.All, Policy.Read.All, RoleManagement.Read.Directory
    Roles   : Security Reader or Global Reader
    Licence : Entra ID P2 for full risk data (P1 / free tenants see limited detail)
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

    [ValidateRange(1, 90)]
    [int]$DetectionLookbackDays = 30,
    [switch]$IncludeRemediated,
    [switch]$SkipServicePrincipals
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '21-IdentityRisk'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory')
if (-not $SkipServicePrincipals) { $RequiredScopes += 'IdentityRiskyServicePrincipal.Read.All' }

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

function Get-Age { param($Value) if ($Value) { return [int]($script:RunStartUtc - ([datetime]$Value).ToUniversalTime()).TotalDays } return '' }

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # Role holders, to flag risky admins
    $roleHolders = @{}
    try {
        $defs = @{}
        foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName' -Label 'roleDefinitions')) { $defs[$r.id] = $r.displayName }
        foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=principalId,roleDefinitionId' -Label 'roleAssignments')) {
            if (-not $roleHolders.ContainsKey($a.principalId)) { $roleHolders[$a.principalId] = [System.Collections.Generic.List[string]]::new() }
            $roleHolders[$a.principalId].Add($(if ($defs.ContainsKey($a.roleDefinitionId)) { $defs[$a.roleDefinitionId] } else { $a.roleDefinitionId }))
        }
    }
    catch { Write-RunLog ("Role assignments unreadable; risky-admin flag unavailable ({0})" -f $_.Exception.Message) 'WARN' }

    # ---- 1. Risky users ----
    $userRows = @()
    try {
        $ru = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskyUsers' -Label 'riskyUsers'
        $userRows = foreach ($u in $ru) {
            $state = "$($u.riskState)"
            if (-not $IncludeRemediated -and $state -notin @('atRisk', 'confirmedCompromised')) { continue }
            $roles = $(if ($roleHolders.ContainsKey($u.id)) { Join-Values ($roleHolders[$u.id] | Select-Object -Unique) } else { '' })
            [pscustomobject][ordered]@{
                UserPrincipalName = $u.userPrincipalName
                RiskLevel         = $u.riskLevel
                RiskState         = $state
                RiskDetail        = $u.riskDetail
                LastUpdatedUtc    = $u.riskLastUpdatedDateTime
                DaysSinceUpdate   = Get-Age $u.riskLastUpdatedDateTime
                IsDeleted         = $u.isDeleted
                DirectoryRoles    = $roles
                Flags             = Join-Values @($(if ($roles) { 'RiskyAdmin' }), $(if ($state -eq 'confirmedCompromised') { 'ConfirmedCompromised' }), $(if ("$($u.riskLevel)" -eq 'high') { 'HighRisk' }))
            }
        }
        $userRows = @($userRows | Sort-Object @{ Expression = { $_.Flags -notmatch 'RiskyAdmin' } }, @{ Expression = { @{ high = 0; medium = 1; low = 2 }["$($_.RiskLevel)"] } })
        Export-Dataset -Name 'risky-users' -Rows $userRows -Note $(if ($IncludeRemediated) { 'All risk states' } else { 'atRisk and confirmedCompromised only' })
    }
    catch { Set-DatasetStatus -Name 'risky-users' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 2. Risk detections ----
    $detRows = @()
    try {
        $since = $script:RunStartUtc.AddDays(-$DetectionLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $det = Invoke-GraphGetAll -Uri ('https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$filter=' + [uri]::EscapeDataString("detectedDateTime ge $since")) -Label 'riskDetections'
        $detRows = foreach ($d in $det) {
            [pscustomobject][ordered]@{
                DetectedUtc       = $d.detectedDateTime
                UserPrincipalName = $d.userPrincipalName
                RiskEventType     = $d.riskEventType
                RiskLevel         = $d.riskLevel
                RiskState         = $d.riskState
                DetectionTiming   = $d.detectionTimingType
                Source            = $d.source
                IpAddress         = $d.ipAddress
                Country           = $(if ($d.location) { $d.location.countryOrRegion } else { '' })
                IsAdmin           = [bool]($d.userId -and $roleHolders.ContainsKey($d.userId))
            }
        }
        Export-Dataset -Name 'risk-detections' -Rows $detRows -Note "Last $DetectionLookbackDays days"
        $agg = $detRows | Group-Object RiskEventType, RiskLevel | ForEach-Object {
            [pscustomobject][ordered]@{
                RiskEventType = $_.Group[0].RiskEventType
                RiskLevel     = $_.Group[0].RiskLevel
                Detections    = $_.Count
                DistinctUsers = @($_.Group | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
                AdminUsers    = @($_.Group | Where-Object IsAdmin | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
            }
        } | Sort-Object Detections -Descending
        Export-Dataset -Name 'risk-detections-by-type' -Rows $agg
    }
    catch {
        $st = Get-FailureStatus $_
        Set-DatasetStatus -Name 'risk-detections' -Status $st -Note $_.Exception.Message
        Set-DatasetStatus -Name 'risk-detections-by-type' -Status $st -Note 'Depends on risk-detections'
    }

    # ---- 3. Risky service principals ----
    $spRows = @()
    if ($SkipServicePrincipals) { Set-DatasetStatus -Name 'risky-service-principals' -Status 'Deferred' -Note '-SkipServicePrincipals' }
    else {
        try {
            $rsp = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals' -Label 'riskyServicePrincipals'
            $spRows = foreach ($s in $rsp) {
                if (-not $IncludeRemediated -and "$($s.riskState)" -notin @('atRisk', 'confirmedCompromised')) { continue }
                [pscustomobject][ordered]@{ DisplayName = $s.displayName; AppId = $s.appId; RiskLevel = $s.riskLevel; RiskState = $s.riskState; RiskDetail = $s.riskDetail; LastUpdatedUtc = $s.riskLastUpdatedDateTime; HoldsDirectoryRole = [bool]$roleHolders.ContainsKey($s.id) }
            }
            Export-Dataset -Name 'risky-service-principals' -Rows $spRows
        }
        catch { Set-DatasetStatus -Name 'risky-service-principals' -Status 'EvidenceUnavailable' -Note ("Workload Identities Premium or permission missing: {0}" -f $_.Exception.Message) }
    }

    # ---- 4. CA risk policies ----
    $caRows = @()
    try {
        $ca = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'caPolicies'
        $caRows = foreach ($p in $ca) {
            $ur = @($p.conditions.userRiskLevels | Where-Object { $_ })
            $sr = @($p.conditions.signInRiskLevels | Where-Object { $_ })
            $spr = @(); if ($p.conditions.PSObject.Properties.Name -contains 'servicePrincipalRiskLevels') { $spr = @($p.conditions.servicePrincipalRiskLevels | Where-Object { $_ }) }
            if (-not ($ur.Count -or $sr.Count -or $spr.Count)) { continue }
            [pscustomobject][ordered]@{
                PolicyName          = $p.displayName
                State               = $p.state
                UserRiskLevels      = Join-Values $ur
                SignInRiskLevels    = Join-Values $sr
                WorkloadRiskLevels  = Join-Values $spr
                GrantControls       = $(if ($p.grantControls) { Join-Values $p.grantControls.builtInControls } else { '' })
                AuthStrength        = $(if ($p.grantControls -and $p.grantControls.authenticationStrength) { $p.grantControls.authenticationStrength.displayName } else { '' })
                SessionControls     = $(if ($p.sessionControls -and $p.sessionControls.signInFrequency -and $p.sessionControls.signInFrequency.isEnabled) { 'SignInFrequency' } else { '' })
                IncludeUsers        = Join-Values $p.conditions.users.includeUsers
                ExcludeGroupCount   = @($p.conditions.users.excludeGroups | Where-Object { $_ }).Count
            }
        }
        Export-Dataset -Name 'ca-risk-policies' -Rows $caRows
    }
    catch { Set-DatasetStatus -Name 'ca-risk-policies' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 5. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $active = @($userRows | Where-Object { $_.RiskState -in @('atRisk', 'confirmedCompromised') })
    Add-Metric 'Users currently at risk' $active.Count
    foreach ($l in 'high', 'medium', 'low') { Add-Metric "At-risk users: $l" @($active | Where-Object { "$($_.RiskLevel)" -eq $l }).Count }
    Add-Metric 'Confirmed compromised users' @($active | Where-Object RiskState -eq 'confirmedCompromised').Count
    Add-Metric 'At-risk users holding a directory role' @($active | Where-Object { $_.Flags -match 'RiskyAdmin' }).Count 'Review first'
    Add-Metric 'At-risk users not updated in 30+ days' @($active | Where-Object { $_.DaysSinceUpdate -ne '' -and $_.DaysSinceUpdate -gt 30 }).Count 'Risk left open - no remediation or dismissal'
    Add-Metric "Risk detections (last $DetectionLookbackDays days)" @($detRows).Count
    Add-Metric 'Users with detections' @($detRows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    if (-not $SkipServicePrincipals) { Add-Metric 'Risky service principals' @($spRows).Count }
    Add-Metric 'CA policies using user risk (enabled)' @($caRows | Where-Object { $_.UserRiskLevels -and $_.State -eq 'enabled' }).Count
    Add-Metric 'CA policies using sign-in risk (enabled)' @($caRows | Where-Object { $_.SignInRiskLevels -and $_.State -eq 'enabled' }).Count
    Add-Metric 'CA risk policies in report-only' @($caRows | Where-Object State -eq 'enabledForReportingButNotEnforced').Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ DetectionLookbackDays = $DetectionLookbackDays; IncludeRemediated = [bool]$IncludeRemediated; SkipServicePrincipals = [bool]$SkipServicePrincipals }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
