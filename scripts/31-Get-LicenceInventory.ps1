<#
.SYNOPSIS
    Read-only licence inventory: which Microsoft licences and service plans the tenant has, how many
    are assigned, and which licence-dependent evidence could not be collected.

.DESCRIPTION
    Answers: which Microsoft licences and service plans does the tenant actually have, how many are
    assigned, and which licence-dependent evidence could not be collected?

    It is the licence-confirmation evidence for a readiness gate. Other scripts mark a dataset
    EvidenceUnavailable when a feature looks unlicensed; this script reads the subscriptions
    themselves, so a licence gap is confirmed rather than inferred.

    The script reads every subscribed SKU from Microsoft Graph v1.0 (/subscribedSkus) with its
    prepaid units (enabled, suspended, warning, locked out), consumed units and service plans, then:

      - lists every SKU with its unit counts and flags (Suspended, Warning, LockedOut, Deleted,
        OverAssigned, NoneAssigned, CompanyLevel)
      - lists every service plan of every SKU with its provisioning status
      - checks each capability in -CapabilityMap (a label -> service plan names). A capability is
        Present when at least one SKU whose capabilityStatus is Enabled or Warning carries one of
        its service plans with provisioningStatus Success

    With -EvidenceRoot it also reads the latest run of every other script under that folder
    (<NN-Name>\<yyyyMMdd-HHmmssZ>\ with run-manifest.json; folders named _aborted are skipped) and
    lists every dataset that run recorded as EvidenceUnavailable.

    READ-ONLY. Every Graph call is an HTTP GET. The evidence root is only read.

    Output: <OutputRoot>\31-LicenceInventory\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER EvidenceRoot
    Evidence folder holding the run folders of the other scripts (NN-Name\yyyyMMdd-HHmmssZ), usually
    the -OutputRoot they were run with. Adds licence-gaps-observed.csv. Without it that dataset is
    Deferred.

.PARAMETER CapabilityMap
    Capability label -> array of service plan names (servicePlanName, as in Microsoft's "Product names
    and service plan identifiers for licensing" reference). Replaces the default map. Pass an
    [ordered] hashtable to keep your order in licence-capabilities.csv. Plan names are matched
    case-insensitively.

.PARAMETER GraphScope
    Delegated scope requested at sign-in: Directory.Read.All (default), LicenseAssignment.Read.All (least
    privileged; consent it first) or Organization.Read.All. App-only mode uses the app's granted permissions.

.EXAMPLE
    .\31-Get-LicenceInventory.ps1
.EXAMPLE
    .\31-Get-LicenceInventory.ps1 -EvidenceRoot .\output
.EXAMPLE
    .\31-Get-LicenceInventory.ps1 -CapabilityMap ([ordered]@{ 'Entra ID P2' = @('AAD_PREMIUM_P2'); 'Intune' = @('INTUNE_A') })

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication.
    Scopes  : Directory.Read.All by default (already consented for the other Graph scripts). Use
              -GraphScope LicenseAssignment.Read.All for the least-privileged option (needs its own
              consent). Role: Global Reader or Directory Readers.
    Licence : None.
    Sources : Microsoft Graph subscribedSku, licenseUnitsDetail and servicePlanInfo (v1.0); Microsoft
              "Product names and service plan identifiers for licensing" for the default map.
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

    [string]$EvidenceRoot = '',
    [System.Collections.IDictionary]$CapabilityMap = $null,
    # Delegated scope to request. Directory.Read.All is already consented wherever the other Graph scripts run,
    # so it signs in without a new consent prompt. LicenseAssignment.Read.All is the least-privileged option.
    [ValidateSet('Directory.Read.All', 'LicenseAssignment.Read.All', 'Organization.Read.All')]
    [string]$GraphScope = 'Directory.Read.All'
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '31-LicenceInventory'
$ScriptVersion = '1.0.0'
$RequiredScopes = @($GraphScope)


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

function Get-OptionalValue {
    # Property value when the object has it, otherwise $null (Graph omits properties it does not return).
    param($Object, [string]$Name)
    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $null
}

function ConvertTo-Count {
    # Graph Int32 (or missing) -> [int]; missing counts as 0.
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return 0 }
    return [int]$Value
}

# Default capability map: label -> service plan names (servicePlanName).
# Every name was checked against Microsoft's "Product names and service plan identifiers for licensing":
# https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference   # guardrail:allow Microsoft docs URL, not a user profile path
# Plans the reference marks RETIRED, and plans that only carry a basic or foundation service, are left out.
$DefaultCapabilityMap = [ordered]@{
    'Entra ID P1'                              = @('AAD_PREMIUM')
    'Entra ID P2'                              = @('AAD_PREMIUM_P2')
    'Entra ID Governance'                      = @('Entra_Identity_Governance')
    'Workload Identities Premium'              = @('AAD_WRKLDID_P1', 'AAD_WRKLDID_P2')
    'Intune'                                   = @('INTUNE_A', 'INTUNE_A_GOV', 'INTUNE_A_VL', 'INTUNE_EDU', 'INTUNE_SMBIZ')
    'Defender for Identity'                    = @('ATA')
    'Defender for Office 365 Plan 1'           = @('ATP_ENTERPRISE', 'ATP_ENTERPRISE_GOV')
    'Defender for Office 365 Plan 2'           = @('THREAT_INTELLIGENCE', 'THREAT_INTELLIGENCE_GOV')
    'Purview Information Protection Standard'  = @('MIP_S_CLP1')
    'Purview Information Protection Premium'   = @('MIP_S_CLP2')
    'Azure Rights Management'                  = @('RMS_S_ENTERPRISE', 'RMS_S_ENTERPRISE_GOV')
    'Azure Information Protection Premium P1'  = @('RMS_S_PREMIUM', 'RMS_S_PREMIUM_GOV')
    'Azure Information Protection Premium P2'  = @('RMS_S_PREMIUM2', 'RMS_S_PREMIUM2_GOV')
    'Purview DLP for Teams'                    = @('COMMUNICATIONS_DLP')
    'Purview Endpoint DLP'                     = @('MICROSOFTENDPOINTDLP')
    'Purview DLP add-on'                       = @('BPOS_S_DlpAddOn')
    'Purview Insider Risk Management'          = @('INSIDER_RISK')
    'Purview Communication Compliance'         = @('MICROSOFT_COMMUNICATION_COMPLIANCE')
    'Exchange Online'                          = @('EXCHANGE_S_STANDARD', 'EXCHANGE_S_ENTERPRISE', 'EXCHANGE_S_DESKLESS', 'EXCHANGE_S_ESSENTIALS', 'EXCHANGE_L_STANDARD', 'EXCHANGE_B_STANDARD', 'EXCHANGE_S_STANDARD_MIDMARKET', 'EXCHANGE_S_STANDARD_GOV', 'EXCHANGE_S_ENTERPRISE_GOV', 'EXCHANGE_S_DESKLESS_GOV')
    'SharePoint Online'                        = @('SHAREPOINTSTANDARD', 'SHAREPOINTENTERPRISE', 'SHAREPOINTDESKLESS', 'SHAREPOINTENTERPRISE_MIDMARKET', 'SHAREPOINTSTANDARD_EDU', 'SHAREPOINTENTERPRISE_EDU', 'SHAREPOINTENTERPRISE_GOV', 'SHAREPOINTDESKLESS_GOV')
}

# A plan counts as active only on a SKU in one of these states, with provisioningStatus Success.
$ActiveSkuStates = @('Enabled', 'Warning')

$ctx = $null
$mapSource = $(if ($null -ne $CapabilityMap -and $CapabilityMap.Count -gt 0) { 'Parameter' } else { 'Default' })
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- 1. Capability map ----
    $capMap = [ordered]@{}
    $srcMap = $(if ($mapSource -eq 'Parameter') { $CapabilityMap } else { $DefaultCapabilityMap })
    foreach ($k in @($srcMap.Keys)) {
        $label = ([string]$k).Trim()
        if (-not $label) { continue }
        $capMap[$label] = @(@($srcMap[$k]) | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    }
    $planToCap = @{}   # case-insensitive: plan name -> capability labels
    foreach ($label in $capMap.Keys) {
        foreach ($p in $capMap[$label]) {
            if (-not $planToCap.ContainsKey($p)) { $planToCap[$p] = [System.Collections.Generic.List[string]]::new() }
            $planToCap[$p].Add($label)
        }
    }
    $script:ManifestExtra = [ordered]@{ CapabilityMapSource = $mapSource; CapabilityMap = $capMap; ActiveSkuStates = $ActiveSkuStates }
    Write-RunLog ("Capability map: {0} ({1} capabilities, {2} service plan names)" -f $mapSource, $capMap.Count, $planToCap.Count)

    # ---- 2. Read subscribed SKUs ----
    $skuOk = $false; $skus = @(); $skuStatus = ''; $skuNote = ''
    try {
        $skus = @((Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -Label 'subscribedSkus').ToArray() | Where-Object { $null -ne $_ })
        $skuOk = $true
        Write-RunLog ("{0} subscribed SKUs read" -f $skus.Count)
    }
    catch {
        # Reading subscribed SKUs needs no licence, so any failure here is Blocked, never EvidenceUnavailable.
        $skuStatus = Get-FailureStatus $_
        if ($skuStatus -ne 'Blocked') { $skuStatus = 'Blocked' }
        $skuNote = "subscribedSkus not readable: $($_.Exception.Message)"
        Write-RunLog $skuNote 'WARN'
    }

    $skuRows = @(); $capRows = @()
    if ($skuOk) {
        $sorted = @($skus | Sort-Object -Property @{ Expression = { [string]$_.skuPartNumber } }, @{ Expression = { [string]$_.skuId } })

        # ---- 3. SKUs ----
        $skuRows = @(foreach ($s in $sorted) {
            $pu = Get-OptionalValue $s 'prepaidUnits'
            $enabled   = ConvertTo-Count (Get-OptionalValue $pu 'enabled')
            $suspended = ConvertTo-Count (Get-OptionalValue $pu 'suspended')
            $warning   = ConvertTo-Count (Get-OptionalValue $pu 'warning')
            $locked    = ConvertTo-Count (Get-OptionalValue $pu 'lockedOut')
            $consumed  = ConvertTo-Count (Get-OptionalValue $s 'consumedUnits')
            $state     = [string](Get-OptionalValue $s 'capabilityStatus')
            $applies   = [string](Get-OptionalValue $s 'appliesTo')
            $flags = [System.Collections.Generic.List[string]]::new()
            if ($state -eq 'Suspended' -or $suspended -gt 0) { $flags.Add('Suspended') }
            if ($state -eq 'Warning' -or $warning -gt 0) { $flags.Add('Warning') }
            if ($state -eq 'LockedOut' -or $locked -gt 0) { $flags.Add('LockedOut') }
            if ($state -eq 'Deleted') { $flags.Add('Deleted') }
            if ($consumed -gt $enabled) { $flags.Add('OverAssigned') }
            if ($applies -eq 'Company') { $flags.Add('CompanyLevel') }
            elseif ($consumed -eq 0 -and $enabled -gt 0) { $flags.Add('NoneAssigned') }
            [pscustomobject][ordered]@{
                SkuPartNumber    = [string](Get-OptionalValue $s 'skuPartNumber')
                SkuId            = [string](Get-OptionalValue $s 'skuId')
                CapabilityStatus = $state
                Enabled          = $enabled
                Suspended        = $suspended
                Warning          = $warning
                LockedOut        = $locked
                Consumed         = $consumed
                Available        = $enabled - $consumed
                ServicePlanCount = @(Get-OptionalValue $s 'servicePlans' | Where-Object { $null -ne $_ }).Count
                Flags            = Join-Values $flags
            }
        })
        Export-Dataset -Name 'licence-skus' -Rows $skuRows -Note 'One row per subscribed SKU; Available = Enabled - Consumed'

        # ---- 4. Service plans ----
        $planRows = [System.Collections.Generic.List[object]]::new()
        $hits = [System.Collections.Generic.List[object]]::new()   # mapped plans seen, for the capability check
        foreach ($s in $sorted) {
            $part = [string](Get-OptionalValue $s 'skuPartNumber')
            $state = [string](Get-OptionalValue $s 'capabilityStatus')
            $pu = Get-OptionalValue $s 'prepaidUnits'
            $plans = @(Get-OptionalValue $s 'servicePlans' | Where-Object { $null -ne $_ } | Sort-Object -Property @{ Expression = { [string]$_.servicePlanName } }, @{ Expression = { [string]$_.servicePlanId } })
            foreach ($p in $plans) {
                $name = [string](Get-OptionalValue $p 'servicePlanName')
                $prov = [string](Get-OptionalValue $p 'provisioningStatus')
                $caps = $(if ($name -and $planToCap.ContainsKey($name)) { @($planToCap[$name]) } else { @() })
                $planRows.Add([pscustomobject][ordered]@{
                    SkuPartNumber      = $part
                    ServicePlanName    = $name
                    ServicePlanId      = [string](Get-OptionalValue $p 'servicePlanId')
                    ProvisioningStatus = $prov
                    AppliesTo          = [string](Get-OptionalValue $p 'appliesTo')
                    Capability         = Join-Values $caps
                })
                foreach ($c in $caps) {
                    $hits.Add([pscustomobject]@{
                        Capability = $c; SkuId = [string](Get-OptionalValue $s 'skuId'); SkuPartNumber = $part; SkuState = $state
                        Plan = $name; Provisioning = $prov
                        Enabled = ConvertTo-Count (Get-OptionalValue $pu 'enabled'); Consumed = ConvertTo-Count (Get-OptionalValue $s 'consumedUnits')
                        Active = ($prov -eq 'Success' -and $ActiveSkuStates -contains $state)
                    })
                }
            }
        }
        Export-Dataset -Name 'licence-service-plans' -Rows $planRows.ToArray() -Note ("One row per SKU and service plan; Capability from the {0} capability map" -f $mapSource.ToLowerInvariant())

        # ---- 5. Capabilities ----
        $capRows = @(foreach ($label in $capMap.Keys) {
            $h = @($hits | Where-Object { $_.Capability -eq $label })
            $active = @($h | Where-Object { $_.Active })
            $activeSkus = @($active | Sort-Object -Property SkuId -Unique)
            $notes = [System.Collections.Generic.List[string]]::new()
            if (-not $capMap[$label].Count) { $notes.Add('No service plan names mapped') }
            elseif (-not $h.Count) { $notes.Add('No subscribed SKU carries a mapped service plan') }
            elseif (-not $active.Count) { $notes.Add('Mapped plan found, but not provisioned (Success) on an Enabled or Warning SKU') }
            $warnSkus = @($activeSkus | Where-Object { $_.SkuState -eq 'Warning' } | ForEach-Object { $_.SkuPartNumber })
            if ($warnSkus.Count -and $warnSkus.Count -eq $activeSkus.Count) { $notes.Add('Only via SKUs in Warning (grace period): ' + ($warnSkus -join ', ')) }
            elseif ($warnSkus.Count) { $notes.Add('Also via SKUs in Warning: ' + ($warnSkus -join ', ')) }
            if (@($h | Where-Object { $_.Provisioning -eq 'PendingActivation' }).Count) { $notes.Add('PendingActivation on some SKUs: an admin must activate the service') }
            [pscustomobject][ordered]@{
                Capability           = $label
                MappedPlans          = Join-Values $capMap[$label]
                Present              = [bool]$active.Count
                ProvisioningStatuses = Join-Values (@($h | ForEach-Object { $_.Provisioning } | Where-Object { $_ }) | Sort-Object -Unique)
                ViaSkus              = Join-Values (@($h | ForEach-Object { '{0} ({1}{2})' -f $_.SkuPartNumber, $_.Provisioning, $(if ($_.SkuState -ne 'Enabled') { ', SKU ' + $_.SkuState } else { '' }) }) | Sort-Object -Unique)
                EnabledUnits         = [int](($activeSkus | Measure-Object -Property Enabled -Sum).Sum)
                ConsumedUnits        = [int](($activeSkus | Measure-Object -Property Consumed -Sum).Sum)
                Note                 = Join-Values $notes
            }
        })
        Export-Dataset -Name 'licence-capabilities' -Rows $capRows -Note ("One row per capability in the {0} capability map; Present = a mapped plan with provisioningStatus Success on an Enabled or Warning SKU" -f $mapSource.ToLowerInvariant())
    }
    else {
        Set-DatasetStatus -Name 'licence-skus' -Status $skuStatus -Note $skuNote
        Set-DatasetStatus -Name 'licence-service-plans' -Status $skuStatus -Note $skuNote
        Set-DatasetStatus -Name 'licence-capabilities' -Status $skuStatus -Note $skuNote
    }

    # ---- 6. Licence-dependent evidence that other runs could not collect ----
    $gapRows = $null; $gapNote = ''; $runsScanned = 0
    $scriptDirs = $null
    if (-not $EvidenceRoot) { $gapNote = 'No -EvidenceRoot given' }
    elseif (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) { $gapNote = "EvidenceRoot not found: $EvidenceRoot" }
    else {
        try {
            $scriptDirs = @(Get-ChildItem -LiteralPath $EvidenceRoot -Directory -ErrorAction Stop |
                Where-Object { $_.Name -match '^\d{2}-' -and $_.Name -ne '_aborted' -and $_.Name -ne $ScriptName } | Sort-Object Name)
        }
        catch { $gapNote = "EvidenceRoot not readable: $($_.Exception.Message)" }
    }
    if (-not $EvidenceRoot) { Set-DatasetStatus -Name 'licence-gaps-observed' -Status 'Deferred' -Note $gapNote }
    elseif ($null -eq $scriptDirs) { Set-DatasetStatus -Name 'licence-gaps-observed' -Status 'Blocked' -Note $gapNote }
    else {
        $gapList = [System.Collections.Generic.List[object]]::new()
        $problems = [System.Collections.Generic.List[string]]::new()
        foreach ($sd in $scriptDirs) {
            # Latest run folder with a run-manifest.json; anything under _aborted is never a candidate.
            $latest = @(Get-ChildItem -LiteralPath $sd.FullName -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne '_aborted' -and $_.Name -match '^\d{8}-\d{6}Z$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'run-manifest.json')) } |
                Sort-Object Name | Select-Object -Last 1)
            if (-not $latest.Count) { continue }
            $run = $latest[0]
            $runsScanned++
            $statusFile = Join-Path $run.FullName 'dataset-status.csv'
            if (-not (Test-Path -LiteralPath $statusFile)) { $problems.Add("$($sd.Name)\$($run.Name): no dataset-status.csv"); continue }
            try { $statusRows = @(Import-Csv -LiteralPath $statusFile) }
            catch { $problems.Add("$($sd.Name)\$($run.Name): dataset-status.csv not readable"); continue }
            foreach ($r in ($statusRows | Where-Object { $_.Status -eq 'EvidenceUnavailable' })) {
                $gapList.Add([pscustomobject][ordered]@{ Script = $sd.Name; RunFolder = $run.Name; Dataset = [string]$r.Dataset; Note = [string]$r.Note })
            }
        }
        $gapRows = $gapList.ToArray()
        $gapNote = "Latest run of $runsScanned script(s) scanned"
        if ($problems.Count) { $gapNote += '; ' + ($problems -join '; ') }
        Export-Dataset -Name 'licence-gaps-observed' -Rows $gapRows -Status $(if ($problems.Count) { 'Partial' } else { 'Completed' }) -Note $gapNote
    }

    # ---- 7. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $failNote = "$($skuStatus): $skuNote"
    function Add-SkuFlagMetric {
        param([string]$Metric, [string]$Flag)
        if (-not $skuOk) { Add-Metric $Metric '' -Note $failNote; return }
        $m = @($skuRows | Where-Object { (@($_.Flags -split '; ') -contains $Flag) })
        Add-Metric $Metric $m.Count -Note (Join-Values ($m | ForEach-Object { $_.SkuPartNumber }))
    }
    Add-Metric 'Subscribed SKUs' $(if ($skuOk) { $skuRows.Count } else { '' }) -Note $(if ($skuOk) { '' } else { $failNote })
    Add-SkuFlagMetric 'SKUs suspended' 'Suspended'
    Add-SkuFlagMetric 'SKUs in warning' 'Warning'
    Add-SkuFlagMetric 'SKUs locked out' 'LockedOut'
    Add-SkuFlagMetric 'SKUs over-assigned' 'OverAssigned'
    if ($skuOk) {
        $present = @($capRows | Where-Object { $_.Present }); $absent = @($capRows | Where-Object { -not $_.Present })
        Add-Metric 'Capabilities present' $present.Count -Note (Join-Values ($present | ForEach-Object { $_.Capability }))
        Add-Metric 'Capabilities absent' $absent.Count -Note (Join-Values ($absent | ForEach-Object { $_.Capability }))
    }
    else {
        Add-Metric 'Capabilities present' '' -Note $failNote
        Add-Metric 'Capabilities absent' '' -Note $failNote
    }
    if ($null -ne $gapRows) {
        Add-Metric 'Script runs scanned' $runsScanned -Note $gapNote
        Add-Metric 'Datasets EvidenceUnavailable in latest runs' @($gapRows).Count -Note (Join-Values (@($gapRows | ForEach-Object { $_.Script }) | Sort-Object -Unique))
    }
    else {
        Add-Metric 'Script runs scanned' '' -Note $gapNote
        Add-Metric 'Datasets EvidenceUnavailable in latest runs' '' -Note $gapNote
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ EvidenceRoot = $EvidenceRoot; CapabilityMap = $mapSource }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
