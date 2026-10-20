<#
.SYNOPSIS
    Read-only, combined view of account activity across on-prem AD and Entra ID.

.DESCRIPTION
    A user can look stale in AD (no domain logon) while signing in to Microsoft 365 every day, or
    the reverse. This script joins every AD user to its Entra counterpart and reports the newest
    activity from either side:

      - One row per identity: Hybrid (synced), ADOnly or CloudOnly, enabled state on each side,
        AD last logon, Entra last interactive / non-interactive / successful sign-in, newest
        activity overall, days since, activity bucket, and flags
      - Optional: stale computer accounts in AD
      - Summary by source and activity bucket (0-30, 31-90, 91-180, 181-365, 365+, never)

    Flags: NeverUsed, Stale (> StaleDays), EnabledMismatch (enabled on one side, disabled on the
    other), CreatedButNeverUsed (created more than NewAccountGraceDays ago, never used),
    PasswordNeverExpires (AD), Guest.

    Matching uses the Entra Connect source anchor: onPremisesImmutableId = base64(objectGUID) by
    default, or base64(mS-DS-ConsistencyGuid) with -AnchorAttribute.

    READ-ONLY. Uses only Get-AD* cmdlets and Graph GET requests.

    Output: <OutputRoot>\12-StaleAccounts\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\12-Get-StaleAccounts.ps1
.EXAMPLE
    .\12-Get-StaleAccounts.ps1 -StaleDays 60 -IncludeComputers -SearchBase 'OU=Corp,DC=contoso,DC=local'
.EXAMPLE
    .\12-Get-StaleAccounts.ps1 -EnabledOnly -AnchorAttribute 'mS-DS-ConsistencyGuid'

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, Microsoft.Graph.Authentication
    Scopes  : User.Read.All, AuditLog.Read.All (signInActivity needs Entra ID P1)
    Accuracy: AD lastLogonTimestamp replicates every 9-14 days, so AD dates can be up to ~14 days
              behind. Entra non-interactive sign-ins include token refreshes by apps on the
              user's behalf, so "recent" there does not always mean a person was present.
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
    [switch]$EnabledOnly,
    [switch]$IncludeComputers,

    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '12-StaleAccounts'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('User.Read.All', 'AuditLog.Read.All')

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
    if ($null -eq $Days -or $Days -eq '') { return 'Never' }
    if ($Days -le 30) { return '0-30' }
    if ($Days -le 90) { return '31-90' }
    if ($Days -le 180) { return '91-180' }
    if ($Days -le 365) { return '181-365' }
    return '365+'
}
function Format-Utc { param($Date) if ($Date) { return $Date.ToString('yyyy-MM-ddTHH:mm:ssZ') } return '' }
function ConvertTo-UtcDate { param($Value) if ($Value) { return ([datetime]$Value).ToUniversalTime() } return $null }

$domainName = ''
$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot
    $now = $script:RunStartUtc

    # ---- AD users ----
    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    $props = @('sAMAccountName', 'userPrincipalName', 'enabled', 'whenCreated', 'lastLogonTimestamp', 'pwdLastSet', 'userAccountControl', 'objectGUID', 'mS-DS-ConsistencyGuid')
    $adUsers = @(Get-ADUser -Filter * -Properties $props @p)
    Write-RunLog ("{0} AD users read" -f $adUsers.Count)

    # ---- Entra users ----
    $ctx = Connect-DiscoveryGraph
    $select = 'id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,onPremisesSyncEnabled,onPremisesImmutableId'
    $signInAvailable = $true
    try { $entra = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/users?`$select=$select,signInActivity&`$top=999" -Label 'users' }
    catch {
        $signInAvailable = $false
        Write-RunLog ("signInActivity not readable ({0}); Entra activity will be blank." -f $_.Exception.Message) 'WARN'
        $entra = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=999" -Label 'users'
    }
    Write-RunLog ("{0} Entra users read" -f $entra.Count)
    $entraByAnchor = @{}
    foreach ($e in $entra) { if ($e.onPremisesImmutableId) { $entraByAnchor[$e.onPremisesImmutableId] = $e } }
    $matchedEntra = @{}

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

    $rows = [System.Collections.Generic.List[object]]::new()
    function Add-IdentityRow {
        param($Ad, $E)
        $adEnabled = $(if ($Ad) { [bool]$Ad.Enabled } else { $null })
        $enEnabled = $(if ($E) { [bool]$E.accountEnabled } else { $null })
        if ($EnabledOnly -and -not ($adEnabled -or $enEnabled)) { return }
        $adLast = $(if ($Ad -and $Ad.lastLogonTimestamp) { [datetime]::FromFileTimeUtc([int64]$Ad.lastLogonTimestamp) } else { $null })
        $act = Get-EntraActivity $E
        $newest = @($adLast, $act.Newest | Where-Object { $_ }) | Sort-Object -Descending | Select-Object -First 1
        $days = $(if ($newest) { [int]($now - $newest).TotalDays } else { '' })
        $created = @($(if ($Ad) { ConvertTo-UtcDate $Ad.whenCreated }), $(if ($E) { ConvertTo-UtcDate $E.createdDateTime }) | Where-Object { $_ }) | Sort-Object | Select-Object -First 1
        $source = $(if ($Ad -and $E) { 'Hybrid' } elseif ($Ad) { 'ADOnly' } else { 'CloudOnly' })
        $flags = @()
        if (-not $newest) { $flags += 'NeverUsed' }
        elseif ($days -gt $StaleDays) { $flags += "Stale(>${StaleDays}d)" }
        if ($Ad -and $E -and ($adEnabled -ne $enEnabled)) { $flags += 'EnabledMismatch' }
        if (-not $newest -and $created -and ($now - $created).TotalDays -gt $NewAccountGraceDays) { $flags += 'CreatedButNeverUsed' }
        if ($Ad -and ([int]$Ad.userAccountControl -band 65536)) { $flags += 'PasswordNeverExpires' }
        if ($E -and $E.userType -eq 'Guest') { $flags += 'Guest' }
        if ($source -eq 'CloudOnly' -and -not $signInAvailable) { $flags += 'NoActivityData' }
        $rows.Add([pscustomobject][ordered]@{
            Source                  = $source
            SamAccountName          = $(if ($Ad) { $Ad.SamAccountName } else { '' })
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
        })
    }

    foreach ($u in $adUsers) {
        $anchorBytes = $(if ($AnchorAttribute -eq 'objectGUID') { $u.ObjectGUID.ToByteArray() } elseif ($u.'mS-DS-ConsistencyGuid') { [byte[]]$u.'mS-DS-ConsistencyGuid' } else { $null })
        $e = $null
        if ($anchorBytes) {
            $key = [Convert]::ToBase64String($anchorBytes)
            if ($entraByAnchor.ContainsKey($key)) { $e = $entraByAnchor[$key]; $matchedEntra[$e.id] = $true }
        }
        Add-IdentityRow -Ad $u -E $e
    }
    foreach ($e in $entra) {
        if ($matchedEntra.ContainsKey($e.id)) { continue }
        if ($e.onPremisesSyncEnabled) { continue }   # synced from another domain/forest or outside -SearchBase; see script 13
        Add-IdentityRow -Ad $null -E $e
    }
    $syncedUnmatched = @($entra | Where-Object { $_.onPremisesSyncEnabled -and -not $matchedEntra.ContainsKey($_.id) }).Count
    Export-Dataset -Name 'identity-activity' -Rows $rows -Note $(if ($syncedUnmatched) { "$syncedUnmatched synced Entra users had no AD match in this scope (other domain, outside SearchBase, or different anchor) and are not listed" } else { '' })

    # ---- Computers ----
    $compRows = @()
    if (-not $IncludeComputers) { Set-DatasetStatus -Name 'ad-computers' -Status 'Deferred' -Note 'Run with -IncludeComputers' }
    else {
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

    # ---- Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Identities' $rows.Count $(if ($EnabledOnly) { 'Enabled on at least one side' } else { 'All' })
    Add-Metric 'Entra sign-in activity available' $signInAvailable
    foreach ($src in 'Hybrid', 'ADOnly', 'CloudOnly') { Add-Metric "Identities: $src" @($rows | Where-Object Source -eq $src).Count }
    foreach ($b in '0-30', '31-90', '91-180', '181-365', '365+') { Add-Metric "Last activity $b days ago" @($rows | Where-Object ActivityBucket -eq $b).Count }
    Add-Metric 'No recorded activity (never)' @($rows | Where-Object ActivityBucket -eq 'Never').Count 'No activity on either side'
    $enabledAnywhere = @($rows | Where-Object { $_.ADEnabled -or $_.EntraEnabled })
    Add-Metric "Enabled identities stale over $StaleDays days or never used" @($enabledAnywhere | Where-Object { $_.Flags -match 'Stale|NeverUsed' }).Count 'Primary clean-up population'
    Add-Metric 'Enabled on one side, disabled on the other' @($rows | Where-Object { $_.Flags -match 'EnabledMismatch' }).Count
    Add-Metric "Created over $NewAccountGraceDays days ago, never used" @($rows | Where-Object { $_.Flags -match 'CreatedButNeverUsed' }).Count
    Add-Metric 'Stale in AD but active in Entra (last 30 days)' @($rows | Where-Object { $_.Source -eq 'Hybrid' -and $_.NewestActivitySource -eq 'Entra' -and $_.DaysSinceActivity -ne '' -and $_.DaysSinceActivity -le 30 -and (-not $_.ADLastLogonUtc -or ($now - ([datetime]$_.ADLastLogonUtc).ToUniversalTime()).TotalDays -gt $StaleDays) }).Count 'AD-only staleness checks would wrongly flag these'
    if ($IncludeComputers) {
        Add-Metric 'Computers' @($compRows).Count
        Add-Metric "Computers stale over $StaleDays days or never logged on" @($compRows | Where-Object Stale).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Context $ctx -Parameters @{ SearchBase = $SearchBase; AnchorAttribute = $AnchorAttribute; StaleDays = $StaleDays; NewAccountGraceDays = $NewAccountGraceDays; EnabledOnly = [bool]$EnabledOnly; IncludeComputers = [bool]$IncludeComputers }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
