<#
.SYNOPSIS
    Read-only, agreed in-scope identity population and the denominators every KPI divides by.

.DESCRIPTION
    A figure like "MFA coverage 94%" is only defensible when everyone agrees what it is 94% of.
    This script answers: who exactly is in scope, how many of each kind are there, and who was
    excluded and why? It reads AD users, Entra users and (optionally) an HR export and an approved
    exclusions list, puts every identity in one category, and writes:

      - population-denominators.csv: the standard populations (Entra users (all), Entra members
        enabled, Human workforce enabled (Entra) / (AD), HR active workers ...) with the count and a
        written Definition / Includes / Excludes an approver can sign. A population that cannot be
        computed is still listed, with a blank count and Status Blocked / Deferred /
        EvidenceUnavailable
      - identity-population.csv: one row per identity (AD and Entra joined by source anchor, plus
        active HR records with no account), with the category, the rule that classified it,
        enabled state on each side, HR status, whether it counts in each human-workforce
        population, the approved exclusion and flags
      - population-exclusions.csv: every enabled identity left out of a human-workforce
        population and why (category, approved exclusion, no HR match, HR status not active)
      - population-reconciliation.csv: HR active vs AD vs Entra, one row per identity per issue
        (HrActiveNoAdAccount, HrActiveNoEntraAccount, HrTerminatedAdEnabled,
        HrTerminatedEntraEnabled, AdEnabledHumanNotInHr, EntraEnabledHumanNotInHr)
      - unmatched-exclusions.csv: exclusion rows that matched no identity

    Categories, first matching rule wins: BreakGlass (-BreakGlassUpns), Guest (userType Guest),
    ExternalMember (userType Member with #EXT# in the UPN), ServiceAccount (built-in AD accounts,
    directory sync account names, -ServiceNamePatterns), AdminAccount (-AdminNamePatterns; checked
    before service names), TestAccount (-TestNamePatterns), ResourceOrShared (-ResourceNamePatterns),
    ServiceAccount (servicePrincipalName set and no HR match), HumanWorkforce (HR match, or any
    remaining member when no HR file is given), Unclassified-NoHR (HR file given, no match, no
    pattern). Name patterns are tested against the sAMAccountName and the UPN prefix.

    Mailbox type (shared, room, equipment) cannot be read without Exchange. Resource and shared
    accounts are found by -ResourceNamePatterns only; list the rest in -ExclusionsCsv.

    Matching: AD to Entra by the Entra Connect source anchor (onPremisesImmutableId =
    base64(objectGUID) by default, or base64(mS-DS-ConsistencyGuid) with -AnchorAttribute; an
    empty mS-DS-ConsistencyGuid falls back to objectGUID, as Entra Connect does). HR to AD by
    -AdEmployeeIdAttribute (employeeID) and to Entra by employeeId; when both ids are blank, by UPN
    or mail against the HR UPN / mail columns if the file has them. Exclusions by UPN or
    sAMAccountName (DOMAIN\ prefix ignored).

    Flags: NoHrMatch, HrTerminatedButEnabled, HrActiveButDisabled, MultipleAccountsSameHrId,
    AdminCountNotAdminNamed, PersonAccountWithSpn, EnabledMismatch, DuplicateAnchor,
    SyncedNoAdMatch, ExclusionExpired, ExclusionNotApproved, ExclusionBadDate,
    PatternAndExclusionConflict.

    INPUT (optional): an HR export and an exclusions list that YOU supply. The HR file contains
    personal data - handle and store it per your data-handling rules.

    READ-ONLY. Uses only Get-AD* cmdlets and Graph GET requests.

    Output: <OutputRoot>\27-IdentityPopulation\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER OutputRoot
    Folder for the evidence run folders. Default: .\output next to the script.
.PARAMETER Server
    Domain controller or domain to query, e.g. 'dc01.contoso.local'. Blank = default.
.PARAMETER SearchBase
    OU holding the users in scope, e.g. 'OU=Corp,DC=contoso,DC=local'. Blank = whole domain.
.PARAMETER AnchorAttribute
    Entra Connect source anchor: objectGUID (default) or mS-DS-ConsistencyGuid.
.PARAMETER SkipAD
    Do not read AD. AD populations are listed as Deferred.
.PARAMETER SkipEntra
    Do not read Entra. Entra populations are listed as Deferred. -SkipAD and -SkipEntra cannot both be set.
.PARAMETER HrCsvPath
    HR export (optional). Without it, HR populations are Deferred and every remaining enabled
    member counts as human workforce.
.PARAMETER HrIdColumn
    HR column holding the worker id. Default EmployeeId.
.PARAMETER HrStatusColumn
    HR column holding the employment status. Default EmploymentStatus.
.PARAMETER ActiveStatusValues
    Status values that mean "currently working". Default Active. Any other value is not active.
.PARAMETER HrUpnColumn
    HR column with the UPN, used for fallback matching when present in the file.
.PARAMETER HrMailColumn
    HR column with the mail address, used for fallback matching when present in the file.
.PARAMETER AdEmployeeIdAttribute
    AD attribute holding the HR id. Default employeeID.
.PARAMETER AdminNamePatterns
    -like patterns for admin accounts.
.PARAMETER ServiceNamePatterns
    -like patterns for service accounts.
.PARAMETER TestNamePatterns
    -like patterns for test accounts.
.PARAMETER ResourceNamePatterns
    -like patterns for resource, room and shared accounts.
.PARAMETER BreakGlassUpns
    UPNs (or sAMAccountNames) of the emergency access accounts.
.PARAMETER ExclusionsCsv
    Approved exclusions (examples\population-exclusions.example.csv): Identity, Reason, ApprovedBy,
    ApprovedOnUtc, ExpiresUtc. Expired rows and rows without ApprovedBy are not applied.

.EXAMPLE
    .\27-Get-IdentityPopulation.ps1
.EXAMPLE
    .\27-Get-IdentityPopulation.ps1 -HrCsvPath .\hr-export.csv -ExclusionsCsv .\population-exclusions.csv -BreakGlassUpns 'bg1@contoso.com','bg2@contoso.com'
.EXAMPLE
    .\27-Get-IdentityPopulation.ps1 -SkipAD -HrCsvPath .\hr-export.csv -ActiveStatusValues 'Active','Leave of Absence'

.NOTES
    Version : 1.0.1
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module (not with -SkipAD),
              Microsoft.Graph.Authentication (not with -SkipEntra)
    Scopes  : User.Read.All (Directory.Read.All also works)
    Licence : None beyond Entra ID Free
    Sources : AD users (Get-ADUser), Entra users (GET /users), HR export and exclusions list (optional)
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                               # blank = whole domain
    [ValidateSet('objectGUID', 'mS-DS-ConsistencyGuid')]
    [string]$AnchorAttribute = 'objectGUID',
    [switch]$SkipAD,
    [switch]$SkipEntra,

    # HR file (optional) and column mapping
    [string]$HrCsvPath = '',
    [string]$HrIdColumn = 'EmployeeId',
    [string]$HrStatusColumn = 'EmploymentStatus',
    [string[]]$ActiveStatusValues = @('Active'),
    [string]$HrUpnColumn = 'UserPrincipalName',             # used for fallback matching when present in the file
    [string]$HrMailColumn = 'Email',                        # used for fallback matching when present in the file
    [string]$AdEmployeeIdAttribute = 'employeeID',          # AD attribute holding the HR id

    # Classification
    [string[]]$AdminNamePatterns = @('adm*', '*adm', '*-adm*', '*_adm*', 'a-*', 'a_*', 'da-*', '*admin*'),
    [string[]]$ServiceNamePatterns = @('svc*', '*-svc*', '*_svc*', 'sa-*', 'sa_*'),
    [string[]]$TestNamePatterns = @('test*', '*-test*', '*_test*', 'tst-*', 'tst_*'),
    [string[]]$ResourceNamePatterns = @('room-*', 'room_*', 'rm-*', 'conf-*', 'shared-*', 'shared_*', 'mbx-*', 'res-*', 'equip-*', 'noreply*', 'no-reply*'),
    [string[]]$BreakGlassUpns = @(),                        # e.g. 'bg1@contoso.com'
    [string]$ExclusionsCsv = '',                            # approved exclusions (examples\population-exclusions.example.csv)

    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '27-IdentityPopulation'
$ScriptVersion = '1.0.1'
$RequiredScopes = @('User.Read.All')
if ($SkipAD -and $SkipEntra) { throw '-SkipAD and -SkipEntra cannot both be set: at least one directory must be read.' }

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

function Get-Key { param($Value) return "$Value".Trim().ToLowerInvariant() }
function Get-UpnPrefix { param([string]$Upn) if (-not $Upn) { return '' } return ($Upn -split '@')[0] }
function Get-SamKey { param([string]$Value) $v = Get-Key $Value; if ($v -match '^[^\\]+\\(.+)$') { return $Matches[1] } return $v }
function Format-Utc { param($Date) if ($Date) { return $Date.ToString('yyyy-MM-ddTHH:mm:ssZ') } return '' }
function Find-NamePattern {
    # First -like pattern matched by any of the names; '' when none.
    param([string[]]$Names, [string[]]$Patterns)
    foreach ($pt in $Patterns) { foreach ($n in $Names) { if ($n -and $n -like $pt) { return $pt } } }
    return ''
}
function Get-AnchorKey {
    # Entra Connect source anchor: mS-DS-ConsistencyGuid when chosen and set, otherwise objectGUID.
    param($AdObject)
    $bytes = $null
    if ($AnchorAttribute -eq 'mS-DS-ConsistencyGuid' -and $AdObject.'mS-DS-ConsistencyGuid') { $bytes = [byte[]]$AdObject.'mS-DS-ConsistencyGuid' }
    if (-not $bytes -and $AdObject.ObjectGUID) { $bytes = $AdObject.ObjectGUID.ToByteArray() }
    if (-not $bytes) { return '' }
    return [Convert]::ToBase64String($bytes)
}
function ConvertFrom-UtcText {
    # Parses an ISO 8601 / invariant date as UTC. Returns $null for blank, 'Invalid' when unparseable.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $out = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($Value.Trim(), [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$out)) { return $out }
    return 'Invalid'
}
function Get-WorstStatus {
    # Combines dataset statuses: the weakest one wins.
    param([string[]]$Statuses)
    foreach ($s in @('Blocked', 'EvidenceUnavailable', 'Partial', 'Deferred')) { if ($Statuses -contains $s) { return $s } }
    return 'Completed'
}

$domainName = ''
$ctx = $null
$SyncNamePatterns = @('MSOL_*', 'Sync_*', 'AAD_*', 'ADSyncMSA*')
$BuiltInRids = @{ '500' = 'AdminAccount'; '501' = 'ServiceAccount'; '502' = 'ServiceAccount'; '503' = 'ServiceAccount' }
$adStatus = 'Deferred'; $adNote = 'Skipped (-SkipAD)'
$entraStatus = 'Deferred'; $entraNote = 'Skipped (-SkipEntra)'
$hrStatus = 'Deferred'; $hrNote = 'No HR file supplied (-HrCsvPath)'
$exStatus = 'Deferred'; $exNote = 'No exclusions file supplied (-ExclusionsCsv)'
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $now = $script:RunStartUtc
    $useHr = [bool]$HrCsvPath
    $bgSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($b in $BreakGlassUpns) { if ("$b".Trim()) { [void]$bgSet.Add((Get-SamKey $b)) } }

    # ---- 1. HR input (optional) ----
    $hrById = @{}
    $hrByKey = @{}
    $hasUpn = $false; $hasMail = $false
    $hrDuplicates = 0
    $hrHash = ''
    if ($useHr) {
        if (-not (Test-Path $HrCsvPath)) { throw "HR file not found: $HrCsvPath" }
        $hr = @(Import-Csv -Path $HrCsvPath)
        $hrCols = $(if ($hr.Count) { @($hr[0].PSObject.Properties.Name) } else { @() })
        foreach ($col in @($HrIdColumn, $HrStatusColumn)) {
            if ($hr.Count -and -not ($hrCols -contains $col)) { throw "HR file has no column '$col'. Columns found: $($hrCols -join ', ')" }
        }
        $hasUpn = [bool]($HrUpnColumn -and $hrCols -contains $HrUpnColumn)
        $hasMail = [bool]($HrMailColumn -and $hrCols -contains $HrMailColumn)
        if (-not ($hasUpn -or $hasMail)) { Write-RunLog ("HR file has neither '{0}' nor '{1}'; accounts with a blank employee id cannot be matched to HR." -f $HrUpnColumn, $HrMailColumn) 'WARN' }
        $hrHash = (Get-FileHash -Path $HrCsvPath -Algorithm SHA256).Hash
        foreach ($h in $hr) {
            $id = "$($h.$HrIdColumn)".Trim()
            if (-not $id) { continue }
            if ($hrById.ContainsKey($id)) { $hrDuplicates++; Write-RunLog ("Duplicate HR id {0}; the first row is kept." -f $id) 'WARN'; continue }
            $st = "$($h.$HrStatusColumn)".Trim()
            $hrById[$id] = [pscustomobject]@{
                Id       = $id
                Status   = $st
                IsActive = [bool]($ActiveStatusValues -contains $st)
                Upn      = $(if ($hasUpn) { Get-Key $h.$HrUpnColumn } else { '' })
                Mail     = $(if ($hasMail) { Get-Key $h.$HrMailColumn } else { '' })
            }
        }
        foreach ($rec in $hrById.Values) { foreach ($k in @($rec.Upn, $rec.Mail)) { if ($k -and -not $hrByKey.ContainsKey($k)) { $hrByKey[$k] = $rec } } }
        $hrStatus = 'Completed'
        $hrNote = "{0} ({1} records, {2} active; SHA256 {3})" -f (Split-Path $HrCsvPath -Leaf), $hrById.Count, @($hrById.Values | Where-Object IsActive).Count, $hrHash
        Write-RunLog ("HR file: {0}" -f $hrNote)
    }

    # ---- 2. Exclusions input (optional) ----
    $exRows = [System.Collections.Generic.List[object]]::new()
    $exByKey = @{}
    if ($ExclusionsCsv) {
        if (-not (Test-Path $ExclusionsCsv)) { throw "Exclusions file not found: $ExclusionsCsv" }
        $ex = @(Import-Csv -Path $ExclusionsCsv)
        $exCols = $(if ($ex.Count) { @($ex[0].PSObject.Properties.Name) } else { @() })
        foreach ($col in @('Identity', 'Reason', 'ApprovedBy', 'ApprovedOnUtc', 'ExpiresUtc')) {
            if ($ex.Count -and -not ($exCols -contains $col)) { throw "Exclusions file has no column '$col'. Columns found: $($exCols -join ', ')" }
        }
        foreach ($x in $ex) {
            $ident = "$($x.Identity)".Trim()
            if (-not $ident) { continue }
            $exp = ConvertFrom-UtcText $x.ExpiresUtc
            $state = 'Applied'
            if (-not "$($x.ApprovedBy)".Trim()) { $state = 'NotApproved' }
            elseif ($exp -is [string]) { $state = 'BadDate' }
            elseif ($exp -and $exp -le $now) { $state = 'Expired' }
            $row = [pscustomobject]@{
                Identity = $ident; Reason = "$($x.Reason)".Trim(); ApprovedBy = "$($x.ApprovedBy)".Trim()
                ApprovedOnUtc = "$($x.ApprovedOnUtc)".Trim(); ExpiresUtc = "$($x.ExpiresUtc)".Trim(); State = $state; Matched = $false
            }
            $exRows.Add($row)
            $k = Get-SamKey $ident
            if (-not $exByKey.ContainsKey($k)) { $exByKey[$k] = [System.Collections.Generic.List[object]]::new() }
            $exByKey[$k].Add($row)
        }
        $exStatus = 'Completed'
        $exNote = "{0} ({1} rows: {2} applicable, {3} expired, {4} not approved, {5} bad date; SHA256 {6})" -f (Split-Path $ExclusionsCsv -Leaf), $exRows.Count,
            @($exRows | Where-Object State -eq 'Applied').Count, @($exRows | Where-Object State -eq 'Expired').Count,
            @($exRows | Where-Object State -eq 'NotApproved').Count, @($exRows | Where-Object State -eq 'BadDate').Count, (Get-FileHash -Path $ExclusionsCsv -Algorithm SHA256).Hash
        Write-RunLog ("Exclusions: {0}" -f $exNote)
    }

    # ---- 3. AD users ----
    $adUsers = @()
    if (-not $SkipAD) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $domainName = (Get-ADDomain @script:AdParams).DNSRoot
            $p = @{} + $script:AdParams
            if ($SearchBase) { $p['SearchBase'] = $SearchBase }
            $props = @('sAMAccountName', 'userPrincipalName', 'mail', 'displayName', 'enabled', 'objectGUID', 'mS-DS-ConsistencyGuid', 'objectSid',
                'servicePrincipalName', 'adminCount', $AdEmployeeIdAttribute) | Select-Object -Unique
            $adUsers = @(Get-ADUser -Filter * -Properties $props @p)
            $adStatus = 'Completed'
            $adNote = "{0} users read{1}" -f $adUsers.Count, $(if ($SearchBase) { " under $SearchBase" } else { " in $domainName" })
            Write-RunLog ("AD: {0}" -f $adNote)
        }
        catch {
            $adStatus = 'Blocked'
            $adNote = "AD users not readable: $($_.Exception.Message)"
            Write-RunLog $adNote 'WARN'
            $adUsers = @()
        }
    }

    # ---- 4. Entra users ----
    $entra = @()
    if (-not $SkipEntra) {
        try {
            $ctx = Connect-DiscoveryGraph
            $select = 'id,userPrincipalName,displayName,accountEnabled,userType,creationType,employeeId,employeeType,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesSamAccountName,mail,createdDateTime'
            $entra = @((Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=999" -Label 'users').ToArray())
            $entraStatus = 'Completed'
            $entraNote = "{0} users read" -f $entra.Count
            Write-RunLog ("Entra: {0}" -f $entraNote)
        }
        catch {
            $entraStatus = Get-FailureStatus $_
            $entraNote = "Entra users not readable: $($_.Exception.Message)"
            Write-RunLog $entraNote 'WARN'
            $entra = @()
        }
    }

    # ---- 5. Join AD and Entra on the source anchor ----
    $entraByAnchor = @{}
    $anchorGroups = @{}
    foreach ($e in $entra) {
        if (-not $e.onPremisesImmutableId) { continue }
        $k = [string]$e.onPremisesImmutableId
        if (-not $anchorGroups.ContainsKey($k)) { $anchorGroups[$k] = [System.Collections.Generic.List[object]]::new() }
        $anchorGroups[$k].Add($e)
        if (-not $entraByAnchor.ContainsKey($k)) { $entraByAnchor[$k] = $e }   # first one wins; the others are flagged DuplicateAnchor
    }
    $dupIds = @{}
    foreach ($k in $anchorGroups.Keys) { if ($anchorGroups[$k].Count -gt 1) { foreach ($e in $anchorGroups[$k]) { $dupIds[[string]$e.id] = $true } } }
    $ids = [System.Collections.Generic.List[object]]::new()
    $matchedEntra = @{}
    foreach ($u in $adUsers) {
        $e = $null
        $key = Get-AnchorKey $u
        if ($key -and $entraByAnchor.ContainsKey($key)) { $e = $entraByAnchor[$key]; $matchedEntra[[string]$e.id] = $true }
        $ids.Add([pscustomobject]@{ Ad = $u; E = $e; Hr = $null; HrBy = ''; Key = ('AD:' + $u.ObjectGUID); Category = ''; ClassifiedBy = ''; Flags = [System.Collections.Generic.List[string]]::new(); Exclusion = $null; Source = $(if ($e) { 'AD+Entra' } else { 'AD only' }) })
    }
    foreach ($e in $entra) {
        if ($matchedEntra.ContainsKey([string]$e.id)) { continue }
        $ids.Add([pscustomobject]@{ Ad = $null; E = $e; Hr = $null; HrBy = ''; Key = ('Entra:' + $e.id); Category = ''; ClassifiedBy = ''; Flags = [System.Collections.Generic.List[string]]::new(); Exclusion = $null; Source = 'Entra only' })
    }

    # ---- 6. HR match, classification, exclusions ----
    $hrMatches = @{}
    foreach ($i in $ids) {
        $ad = $i.Ad; $e = $i.E
        $sam = $(if ($ad) { [string]$ad.SamAccountName } elseif ($e) { [string]$e.onPremisesSamAccountName } else { '' })
        $upn = $(if ($e) { [string]$e.userPrincipalName } elseif ($ad) { [string]$ad.UserPrincipalName } else { '' })
        $adUpn = $(if ($ad) { [string]$ad.UserPrincipalName } else { '' })
        $names = @($sam, (Get-UpnPrefix $upn), (Get-UpnPrefix $adUpn) | Where-Object { $_ } | Select-Object -Unique)
        $i | Add-Member -NotePropertyName Sam -NotePropertyValue $sam
        $i | Add-Member -NotePropertyName Upn -NotePropertyValue $upn
        $userType = $(if ($e) { [string]$e.userType } else { '' })
        $isGuest = ($userType -eq 'Guest')
        $isExtMember = (-not $isGuest -and $upn -match '#EXT#')

        # HR match (not for guests or external members)
        if ($useHr -and -not $isGuest -and -not $isExtMember) {
            $adEid = $(if ($ad) { "$($ad.$AdEmployeeIdAttribute)".Trim() } else { '' })
            $enEid = $(if ($e) { "$($e.employeeId)".Trim() } else { '' })
            if ($adEid -and $hrById.ContainsKey($adEid)) { $i.Hr = $hrById[$adEid]; $i.HrBy = "AD $AdEmployeeIdAttribute" }
            elseif ($enEid -and $hrById.ContainsKey($enEid)) { $i.Hr = $hrById[$enEid]; $i.HrBy = 'Entra employeeId' }
            elseif (-not $adEid -and -not $enEid) {
                if ($hasUpn) { foreach ($k in @((Get-Key $adUpn), (Get-Key $upn))) { if (-not $i.Hr -and $k -and $hrByKey.ContainsKey($k) -and $hrByKey[$k].Upn -eq $k) { $i.Hr = $hrByKey[$k]; $i.HrBy = 'UPN' } } }
                if ($hasMail -and -not $i.Hr) {
                    foreach ($k in @($(if ($ad) { Get-Key $ad.mail }), $(if ($e) { Get-Key $e.mail }))) { if (-not $i.Hr -and $k -and $hrByKey.ContainsKey($k) -and $hrByKey[$k].Mail -eq $k) { $i.Hr = $hrByKey[$k]; $i.HrBy = 'Mail' } }
                }
            }
        }

        # Classification: first matching rule wins
        $rid = ''
        if ($ad -and $ad.SID) { $rid = ("$($ad.SID)" -split '-')[-1] }
        $hasSpn = [bool]($ad -and @($ad.servicePrincipalName | Where-Object { $_ }).Count)
        $bgHit = @($upn, $adUpn, $sam | Where-Object { $_ -and $bgSet.Contains((Get-SamKey $_)) })
        $pt = ''
        if ($bgHit.Count) { $i.Category = 'BreakGlass'; $i.ClassifiedBy = 'BreakGlassUpns' }
        elseif ($isGuest) { $i.Category = 'Guest'; $i.ClassifiedBy = 'Entra userType Guest' }
        elseif ($isExtMember) { $i.Category = 'ExternalMember'; $i.ClassifiedBy = 'Entra userType Member with #EXT# in UPN' }
        elseif ($rid -and $BuiltInRids.ContainsKey($rid)) { $i.Category = $BuiltInRids[$rid]; $i.ClassifiedBy = "AD built-in account (RID $rid)" }
        elseif (($pt = Find-NamePattern $names $SyncNamePatterns)) { $i.Category = 'ServiceAccount'; $i.ClassifiedBy = "Directory sync account name: $pt" }
        elseif (($pt = Find-NamePattern $names $AdminNamePatterns)) { $i.Category = 'AdminAccount'; $i.ClassifiedBy = "AdminNamePatterns: $pt" }
        elseif (($pt = Find-NamePattern $names $ServiceNamePatterns)) { $i.Category = 'ServiceAccount'; $i.ClassifiedBy = "ServiceNamePatterns: $pt" }
        elseif (($pt = Find-NamePattern $names $TestNamePatterns)) { $i.Category = 'TestAccount'; $i.ClassifiedBy = "TestNamePatterns: $pt" }
        elseif (($pt = Find-NamePattern $names $ResourceNamePatterns)) { $i.Category = 'ResourceOrShared'; $i.ClassifiedBy = "ResourceNamePatterns: $pt" }
        elseif ($hasSpn -and -not $i.Hr) { $i.Category = 'ServiceAccount'; $i.ClassifiedBy = 'servicePrincipalName set, no HR match' }
        elseif ($useHr -and $i.Hr) { $i.Category = 'HumanWorkforce'; $i.ClassifiedBy = "HR match ($($i.HrBy))" }
        elseif ($useHr) { $i.Category = 'Unclassified-NoHR'; $i.ClassifiedBy = 'No HR match and no name pattern' }
        else { $i.Category = 'HumanWorkforce'; $i.ClassifiedBy = 'Member account, no name pattern (no HR file)' }
        if ($i.Hr) {
            if (-not $hrMatches.ContainsKey($i.Hr.Id)) { $hrMatches[$i.Hr.Id] = [System.Collections.Generic.List[object]]::new() }
            $hrMatches[$i.Hr.Id].Add($i)
        }

        # Exclusions by UPN or sAMAccountName
        $cands = [System.Collections.Generic.List[object]]::new()
        foreach ($k in @((Get-SamKey $upn), (Get-SamKey $adUpn), (Get-SamKey $sam)) | Where-Object { $_ } | Select-Object -Unique) {
            if ($exByKey.ContainsKey($k)) { foreach ($r in $exByKey[$k]) { if (-not $cands.Contains($r)) { $cands.Add($r) } } }
        }
        foreach ($r in $cands) { $r.Matched = $true }
        $applied = @($cands | Where-Object State -eq 'Applied' | Select-Object -First 1)
        if ($applied.Count) { $i.Exclusion = $applied[0] }
        else {
            if (@($cands | Where-Object State -eq 'Expired').Count) { $i.Flags.Add('ExclusionExpired') }
            if (@($cands | Where-Object State -eq 'NotApproved').Count) { $i.Flags.Add('ExclusionNotApproved') }
            if (@($cands | Where-Object State -eq 'BadDate').Count) { $i.Flags.Add('ExclusionBadDate') }
        }

        # Populations
        $adEnabled = $(if ($ad) { [bool]$ad.Enabled } else { $null })
        $enEnabled = $(if ($e) { [bool]$e.accountEnabled } else { $null })
        $hrOk = (-not $useHr) -or ($i.Hr -and $i.Hr.IsActive)
        $humanBase = ($i.Category -eq 'HumanWorkforce') -and (-not $i.Exclusion) -and $hrOk
        $i | Add-Member -NotePropertyName AdEnabled -NotePropertyValue $adEnabled
        $i | Add-Member -NotePropertyName EntraEnabled -NotePropertyValue $enEnabled
        $i | Add-Member -NotePropertyName UserType -NotePropertyValue $userType
        $i | Add-Member -NotePropertyName HasSpn -NotePropertyValue $hasSpn
        $i | Add-Member -NotePropertyName InHwEntra -NotePropertyValue $(if ($entraStatus -ne 'Completed') { '' } else { [bool]($e -and $enEnabled -and $userType -eq 'Member' -and $humanBase) })
        $i | Add-Member -NotePropertyName InHwAD -NotePropertyValue $(if ($adStatus -ne 'Completed') { '' } else { [bool]($ad -and $adEnabled -and $humanBase) })
    }

    # HR-only rows: active HR records matched by no account
    if ($useHr) {
        foreach ($rec in $hrById.Values) {
            if (-not $rec.IsActive -or $hrMatches.ContainsKey($rec.Id)) { continue }
            $i = [pscustomobject]@{ Ad = $null; E = $null; Hr = $rec; HrBy = ''; Key = ('HR:' + $rec.Id); Category = 'HumanWorkforce'; ClassifiedBy = 'Active HR record, no account matched'; Flags = [System.Collections.Generic.List[string]]::new(); Exclusion = $null; Source = 'HR only'
                Sam = ''; Upn = $rec.Upn; AdEnabled = $null; EntraEnabled = $null; UserType = ''; HasSpn = $false; InHwEntra = $(if ($entraStatus -eq 'Completed') { $false } else { '' }); InHwAD = $(if ($adStatus -eq 'Completed') { $false } else { '' }) }
            $ids.Add($i)
        }
    }

    # ---- 7. Flags and exclusion reasons ----
    $exclRows = [System.Collections.Generic.List[object]]::new()
    $nonHumanCats = @('AdminAccount', 'ServiceAccount', 'BreakGlass', 'Guest', 'ExternalMember', 'ResourceOrShared', 'TestAccount')
    foreach ($i in $ids) {
        $ad = $i.Ad; $e = $i.E
        $enabledAny = ($i.AdEnabled -eq $true) -or ($i.EntraEnabled -eq $true)
        if ($i.Source -ne 'HR only') {
            if ($useHr -and -not $i.Hr -and $enabledAny -and $i.Category -eq 'Unclassified-NoHR') { $i.Flags.Add('NoHrMatch') }
            if ($i.Hr -and -not $i.Hr.IsActive -and $enabledAny) { $i.Flags.Add('HrTerminatedButEnabled') }
            if ($i.Hr -and $i.Hr.IsActive -and $i.Category -eq 'HumanWorkforce' -and -not $enabledAny) { $i.Flags.Add('HrActiveButDisabled') }
            if ($i.Hr -and $i.Category -eq 'HumanWorkforce' -and @($hrMatches[$i.Hr.Id] | Where-Object Category -eq 'HumanWorkforce').Count -gt 1) { $i.Flags.Add('MultipleAccountsSameHrId') }
            if ($ad -and "$($ad.adminCount)" -eq '1' -and $i.Category -notin @('AdminAccount', 'BreakGlass') -and $i.ClassifiedBy -notlike 'AD built-in*') { $i.Flags.Add('AdminCountNotAdminNamed') }
            if ($i.HasSpn -and $i.Category -eq 'HumanWorkforce') { $i.Flags.Add('PersonAccountWithSpn') }
            if ($ad -and $e -and ($i.AdEnabled -ne $i.EntraEnabled)) { $i.Flags.Add('EnabledMismatch') }
            if ($e -and $dupIds.ContainsKey([string]$e.id)) { $i.Flags.Add('DuplicateAnchor') }
            if ($e -and -not $ad -and $adStatus -eq 'Completed' -and "$($e.onPremisesSyncEnabled)" -eq 'True') { $i.Flags.Add('SyncedNoAdMatch') }
            if ($i.Exclusion -and $i.Category -in $nonHumanCats) { $i.Flags.Add('PatternAndExclusionConflict') }
        }

        # Excluded = enabled on a side that was read, but not counted in that side's human-workforce population
        $from = @()
        if ($i.InHwEntra -eq $false -and $e -and $i.EntraEnabled) { $from += 'Human workforce enabled (Entra)' }
        if ($i.InHwAD -eq $false -and $ad -and $i.AdEnabled) { $from += 'Human workforce enabled (AD)' }
        $type = ''; $reason = ''
        if ($from.Count) {
            if ($i.Category -in $nonHumanCats) {
                $type = 'Category'; $reason = "Category $($i.Category) ($($i.ClassifiedBy))"
                if ($i.Exclusion) { $reason += "; also on the exclusions list: $($i.Exclusion.Reason)" }
            }
            elseif ($i.Exclusion) { $type = 'ApprovedExclusion'; $reason = "Approved exclusion: $($i.Exclusion.Reason) (approved by $($i.Exclusion.ApprovedBy)$(if ($i.Exclusion.ExpiresUtc) { ', expires ' + $i.Exclusion.ExpiresUtc } else { ', no expiry' }))" }
            elseif ($i.Category -eq 'Unclassified-NoHR') { $type = 'NoHrMatch'; $reason = 'No HR record matched and no name pattern; listed in population-reconciliation.csv' }
            elseif ($i.Hr -and -not $i.Hr.IsActive) { $type = 'HrNotActive'; $reason = "HR status '$($i.Hr.Status)' is not an active status" }
            elseif ($e -and $i.EntraEnabled -and $i.UserType -ne 'Member') { $type = 'Category'; $reason = "Entra userType '$($i.UserType)'" }
            else { $type = 'Other'; $reason = 'Not counted; check the row' }
        }
        $i | Add-Member -NotePropertyName Excluded -NotePropertyValue ([bool]$from.Count)
        $i | Add-Member -NotePropertyName ExclusionReason -NotePropertyValue $reason
        if ($from.Count) {
            $exclRows.Add([pscustomobject][ordered]@{
                Key             = $i.Key
                Upn             = $i.Upn
                SamAccountName  = $i.Sam
                DisplayName     = $(if ($e) { $e.displayName } elseif ($ad) { $ad.DisplayName } else { '' })
                Source          = $i.Source
                Category        = $i.Category
                ExclusionType   = $type
                ExclusionReason = $reason
                ExcludedFrom    = Join-Values $from
                ApprovedBy      = $(if ($i.Exclusion) { $i.Exclusion.ApprovedBy } else { '' })
                ApprovedOnUtc   = $(if ($i.Exclusion) { $i.Exclusion.ApprovedOnUtc } else { '' })
                ExpiresUtc      = $(if ($i.Exclusion) { $i.Exclusion.ExpiresUtc } else { '' })
            })
        }
    }

    # ---- 8. identity-population.csv ----
    $rows = foreach ($i in $ids) {
        $ad = $i.Ad; $e = $i.E
        [pscustomobject][ordered]@{
            Key                   = $i.Key
            Upn                   = $i.Upn
            SamAccountName        = $i.Sam
            DisplayName           = $(if ($e) { $e.displayName } elseif ($ad) { $ad.DisplayName } else { '' })
            Source                = $i.Source
            Category              = $i.Category
            ClassifiedBy          = $i.ClassifiedBy
            AdEnabled             = $i.AdEnabled
            EntraEnabled          = $i.EntraEnabled
            UserType              = $i.UserType
            HrStatus              = $(if ($i.Hr) { $i.Hr.Status } else { '' })
            HrMatchedBy           = $(if ($i.Source -eq 'HR only') { 'HR only' } else { $i.HrBy })
            InHumanWorkforceEntra = $i.InHwEntra
            InHumanWorkforceAD    = $i.InHwAD
            Excluded              = $i.Excluded
            ExclusionReason       = $i.ExclusionReason
            Flags                 = Join-Values $i.Flags
            HrId                  = $(if ($i.Hr) { $i.Hr.Id } else { '' })
            Mail                  = $(if ($e -and $e.mail) { $e.mail } elseif ($ad) { $ad.mail } else { '' })
            EmployeeType          = $(if ($e) { $e.employeeType } else { '' })
            CreationType          = $(if ($e) { $e.creationType } else { '' })
            OnPremisesSyncEnabled = $(if ($e) { $e.onPremisesSyncEnabled } else { '' })
            AdminCount            = $(if ($ad) { $(if ("$($ad.adminCount)" -eq '1') { 1 } else { 0 }) } else { '' })
            HasSpn                = $(if ($ad) { $i.HasSpn } else { '' })
            EntraObjectId         = $(if ($e) { $e.id } else { '' })
            EntraCreatedUtc       = $(if ($e -and $e.createdDateTime) { Format-Utc (([datetime]$e.createdDateTime).ToUniversalTime()) } else { '' })
        }
    }
    $srcStatus = Get-WorstStatus @($(if (-not $SkipAD) { $adStatus }), $(if (-not $SkipEntra) { $entraStatus }))
    $idStatus = $(if ($srcStatus -eq 'Completed') { 'Completed' } elseif (@($adStatus, $entraStatus) -contains 'Completed') { 'Partial' } else { $srcStatus })
    $idNote = Join-Values @("AD: $adStatus", "Entra: $entraStatus", "HR: $hrStatus", "Exclusions: $exStatus")
    Export-Dataset -Name 'identity-population' -Rows @($rows) -Status $idStatus -Note $idNote
    Export-Dataset -Name 'population-exclusions' -Rows $exclRows -Status $idStatus -Note 'Enabled identities not counted in a human-workforce population, with the reason'

    # ---- 9. Reconciliation: HR vs AD vs Entra ----
    $recRows = [System.Collections.Generic.List[object]]::new()
    function Add-RecRow {
        param([string]$Issue, $I, $Hr, [string]$Note)
        $recRows.Add([pscustomobject][ordered]@{
            Issue          = $Issue
            Key            = $(if ($I) { $I.Key } else { 'HR:' + $Hr.Id })
            HrId           = $(if ($Hr) { $Hr.Id } else { '' })
            HrStatus       = $(if ($Hr) { $Hr.Status } else { '' })
            Upn            = $(if ($I) { $I.Upn } elseif ($Hr) { $Hr.Upn } else { '' })
            SamAccountName = $(if ($I) { $I.Sam } else { '' })
            DisplayName    = $(if ($I -and $I.E) { $I.E.displayName } elseif ($I -and $I.Ad) { $I.Ad.DisplayName } else { '' })
            Category       = $(if ($I) { $I.Category } else { '' })
            AdEnabled      = $(if ($I) { $I.AdEnabled } else { '' })
            EntraEnabled   = $(if ($I) { $I.EntraEnabled } else { '' })
            Note           = $Note
        })
    }
    if ($useHr) {
        foreach ($rec in ($hrById.Values | Sort-Object Id)) {
            if (-not $rec.IsActive) { continue }
            $m = $(if ($hrMatches.ContainsKey($rec.Id)) { @($hrMatches[$rec.Id]) } else { @() })
            $secondary = Join-Values @($m | Where-Object { $_.Category -ne 'HumanWorkforce' } | ForEach-Object { $_.Sam + $(if (-not $_.Sam) { $_.Upn }) })
            $note = $(if ($secondary) { "Only secondary accounts matched: $secondary" } else { '' })
            if ($adStatus -eq 'Completed' -and -not @($m | Where-Object { $_.Ad -and $_.Category -eq 'HumanWorkforce' }).Count) { Add-RecRow 'HrActiveNoAdAccount' $null $rec $note }
            if ($entraStatus -eq 'Completed' -and -not @($m | Where-Object { $_.E -and $_.Category -eq 'HumanWorkforce' }).Count) { Add-RecRow 'HrActiveNoEntraAccount' $null $rec $note }
        }
        foreach ($i in $ids) {
            if ($i.Source -eq 'HR only') { continue }
            if ($i.Hr -and -not $i.Hr.IsActive) {
                if ($i.AdEnabled -eq $true) { Add-RecRow 'HrTerminatedAdEnabled' $i $i.Hr "Matched by $($i.HrBy)" }
                if ($i.EntraEnabled -eq $true) { Add-RecRow 'HrTerminatedEntraEnabled' $i $i.Hr "Matched by $($i.HrBy)" }
            }
            if ($i.Category -eq 'Unclassified-NoHR' -and -not $i.Exclusion) {
                if ($i.AdEnabled -eq $true) { Add-RecRow 'AdEnabledHumanNotInHr' $i $null 'Enabled, no name pattern, no HR match: a person not in HR, or an unnamed non-person account' }
                if ($i.EntraEnabled -eq $true -and $i.UserType -eq 'Member') { Add-RecRow 'EntraEnabledHumanNotInHr' $i $null 'Enabled member, no name pattern, no HR match: a person not in HR, or an unnamed non-person account' }
            }
        }
        $recStatus = $(if ($srcStatus -eq 'Completed') { 'Completed' } elseif ($idStatus -eq 'Partial') { 'Partial' } else { $idStatus })
        Export-Dataset -Name 'population-reconciliation' -Rows $recRows -Status $recStatus -Note $(if ($recStatus -eq 'Completed') { 'One row per identity per issue; approved exclusions are not listed' } else { "Checks needing a source that was not read are left out ($idNote)" })
    }
    else { Set-DatasetStatus -Name 'population-reconciliation' -Status 'Deferred' -Note 'Pass -HrCsvPath to reconcile HR with AD and Entra' }

    # ---- 10. Unmatched exclusions ----
    if ($ExclusionsCsv) {
        $unRows = foreach ($r in $exRows) {
            if ($r.Matched) { continue }
            [pscustomobject][ordered]@{ Identity = $r.Identity; Reason = $r.Reason; ApprovedBy = $r.ApprovedBy; ApprovedOnUtc = $r.ApprovedOnUtc; ExpiresUtc = $r.ExpiresUtc; RowState = $r.State
                Note = 'No AD or Entra identity with this UPN or sAMAccountName' + $(if ($srcStatus -ne 'Completed') { ' in the sources read (not all were read)' } else { '' }) }
        }
        Export-Dataset -Name 'unmatched-exclusions' -Rows @($unRows) -Status $(if ($srcStatus -eq 'Completed') { 'Completed' } elseif ($idStatus -eq 'Partial') { 'Partial' } else { $idStatus }) -Note 'Exclusion rows that matched no identity: renamed, deleted or mistyped'
    }
    else { Set-DatasetStatus -Name 'unmatched-exclusions' -Status 'Deferred' -Note 'No exclusions file supplied (-ExclusionsCsv)' }

    # ---- 11. Denominators ----
    $patText = "admin names ($($AdminNamePatterns -join ', ')); service names ($($ServiceNamePatterns -join ', ')) and directory sync account names ($($SyncNamePatterns -join ', ')); test names ($($TestNamePatterns -join ', ')); resource or shared names ($($ResourceNamePatterns -join ', '))"
    $bgText = $(if ($bgSet.Count) { "break-glass accounts listed in -BreakGlassUpns ($($bgSet.Count))" } else { 'break-glass accounts (none listed: -BreakGlassUpns was empty)' })
    $exText = $(if ($ExclusionsCsv) { "identities on an approved, unexpired exclusion in $(Split-Path $ExclusionsCsv -Leaf)" } else { 'approved exclusions (none supplied)' })
    $hrText = $(if ($useHr) { " It must also match an HR record whose status is one of: $($ActiveStatusValues -join ', ') (matched on HR $HrIdColumn = AD $AdEmployeeIdAttribute or Entra employeeId; on UPN or mail only when both ids are blank). Enabled accounts with no active HR match are not counted here; they are listed in population-reconciliation.csv." } else { ' No HR file was supplied, so HR status was not checked: every remaining enabled member account counts.' })
    $scopeText = $(if ($SearchBase) { " AD scope: $SearchBase." } else { '' })
    $den = [System.Collections.Generic.List[object]]::new()
    function Add-Denominator {
        param([string]$Population, $Count, [string]$Definition, [string]$Includes, [string]$Excludes, [string]$Source, [string]$Status, [string]$StatusNote = '')
        $den.Add([pscustomobject][ordered]@{
            Population = $Population
            Count      = $(if ($Status -in @('Completed', 'Partial')) { $Count } else { '' })
            Definition = $Definition + $(if ($StatusNote) { " [${Status}: $StatusNote]" } else { '' })
            Includes   = $Includes
            Excludes   = $Excludes
            Source     = $Source
            Status     = $Status
        })
    }
    function Get-StatusNote { param([string[]]$Pairs) return Join-Values @(for ($n = 0; $n -lt $Pairs.Count; $n += 2) { if ($Pairs[$n] -ne 'Completed') { $Pairs[$n + 1] } }) }
    $hrAdStatus = Get-WorstStatus @($hrStatus, $adStatus)
    $hrEnStatus = Get-WorstStatus @($hrStatus, $entraStatus)
    $realIds = @($ids | Where-Object { $_.Source -ne 'HR only' })
    $bgFound = @($realIds | Where-Object Category -eq 'BreakGlass')
    $bgMissing = @($bgSet | Where-Object { $k = $_; -not @($bgFound | Where-Object { @((Get-SamKey $_.Upn), (Get-SamKey $_.Sam), $(if ($_.Ad) { Get-SamKey $_.Ad.UserPrincipalName })) -contains $k }).Count })
    $bgStatus = $(if (-not $bgSet.Count) { 'Deferred' } elseif ($srcStatus -ne 'Completed') { Get-WorstStatus @($srcStatus, 'Partial') } elseif ($bgMissing.Count) { 'Partial' } else { 'Completed' })
    $hrActive = @($hrById.Values | Where-Object IsActive)
    $extraSrc = @($(if ($useHr) { 'HR file' }), $(if ($ExclusionsCsv) { 'exclusions file' }) | Where-Object { $_ })
    $hwEnSrc = (@('Entra') + $extraSrc) -join ' + '
    $hwAdSrc = (@('AD') + $extraSrc) -join ' + '
    $hwEnStatus = $(if ($entraStatus -ne 'Completed') { $entraStatus } elseif (-not $SkipAD -and $adStatus -ne 'Completed') { 'Partial' } else { 'Completed' })
    $hrWith = { param($Side) @($hrActive | Where-Object { $hrMatches.ContainsKey($_.Id) -and @($hrMatches[$_.Id] | Where-Object { $_.$Side -and $_.Category -eq 'HumanWorkforce' }).Count }).Count }

    Add-Denominator 'Entra users (all)' $entra.Count 'Every user object in the Entra tenant, enabled or disabled, member or guest.' 'Members, guests, synced and cloud-only users, admin, service, break-glass and test accounts.' 'Deleted users (recycle bin); service principals and managed identities (not user objects).' 'Entra (GET /users)' $entraStatus (Get-StatusNote @($entraStatus, $entraNote))
    Add-Denominator 'Entra members enabled' @($entra | Where-Object { $_.accountEnabled -and $_.userType -eq 'Member' }).Count 'Entra users with accountEnabled = true and userType = Member.' 'Synced and cloud-only members, including admin, service, break-glass, test, resource and external (#EXT#) member accounts.' 'Guests (userType Guest); disabled accounts.' 'Entra (GET /users)' $entraStatus (Get-StatusNote @($entraStatus, $entraNote))
    Add-Denominator 'Entra guests' @($entra | Where-Object { $_.userType -eq 'Guest' }).Count 'Entra users with userType = Guest, enabled or disabled.' 'Invited B2B guests and any user set to userType Guest.' "Members, including external members (userType Member with #EXT# in the UPN), counted under ExternalMember: $(@($realIds | Where-Object Category -eq 'ExternalMember').Count)." 'Entra (GET /users)' $entraStatus (Get-StatusNote @($entraStatus, $entraNote))
    Add-Denominator 'Human workforce enabled (Entra)' @($realIds | Where-Object { $_.InHwEntra -eq $true }).Count ("Enabled Entra member accounts that belong to a person in the workforce: accountEnabled = true, userType = Member, classified HumanWorkforce, not on an approved exclusion." + $hrText) 'Synced and cloud-only member accounts of people.' "Guests and external members; $patText; $bgText; $exText; accounts with a servicePrincipalName and no HR match; disabled accounts." $hwEnSrc $hwEnStatus (Get-StatusNote @($entraStatus, $entraNote, $(if ($SkipAD) { 'Completed' } else { $adStatus }), 'AD not read, so synced accounts were classified on Entra data only'))
    Add-Denominator 'Human workforce enabled (AD)' @($realIds | Where-Object { $_.InHwAD -eq $true }).Count ("Enabled AD user accounts that belong to a person in the workforce: Enabled = true, classified HumanWorkforce, not on an approved exclusion." + $hrText + $scopeText) 'AD user accounts of people, synced or not.' "Built-in accounts (RID 500-503); $patText; $bgText; $exText; accounts with a servicePrincipalName and no HR match; Entra guests and external members; disabled accounts; managed service accounts (not user objects)." $hwAdSrc $adStatus (Get-StatusNote @($adStatus, $adNote))
    Add-Denominator 'AD users enabled' @($adUsers | Where-Object Enabled).Count ("Every enabled AD user object." + $scopeText) 'People, admin, service, test, resource and built-in accounts.' 'Disabled accounts; computer accounts; managed service accounts (gMSA / sMSA).' 'AD (Get-ADUser)' $adStatus (Get-StatusNote @($adStatus, $adNote))
    Add-Denominator 'AD service accounts enabled' @($realIds | Where-Object { $_.Ad -and $_.AdEnabled -and $_.Category -eq 'ServiceAccount' }).Count ("Enabled AD user accounts classified ServiceAccount." + $scopeText) "Names matching $($ServiceNamePatterns -join ', ') or $($SyncNamePatterns -join ', '); accounts with a servicePrincipalName and no HR match$(if (-not $useHr) { ' (without an HR file: every account with a servicePrincipalName and no admin, test or resource name)' }); built-in krbtgt, Guest and DefaultAccount when enabled." 'Managed service accounts (gMSA / sMSA, not user objects; see script 04 or 12); service accounts whose names match an admin pattern (counted as admin); service accounts with no SPN and no service name (not detectable: add a name pattern or an exclusion).' 'AD (Get-ADUser)' $adStatus (Get-StatusNote @($adStatus, $adNote))
    Add-Denominator 'AD admin accounts enabled' @($realIds | Where-Object { $_.Ad -and $_.AdEnabled -and $_.Category -eq 'AdminAccount' }).Count ("Enabled AD user accounts classified AdminAccount by name." + $scopeText) "Names matching $($AdminNamePatterns -join ', '); the built-in Administrator (RID 500)." "Break-glass accounts; adminCount = 1 accounts without an admin name (flagged AdminCountNotAdminNamed); group-based privilege is not checked here (see scripts 04 and 18)." 'AD (Get-ADUser)' $adStatus (Get-StatusNote @($adStatus, $adNote))
    Add-Denominator 'Entra admin accounts enabled' @($realIds | Where-Object { $_.E -and $_.EntraEnabled -and $_.Category -eq 'AdminAccount' }).Count 'Enabled Entra member accounts classified AdminAccount by name (synced or cloud-only).' "Names (UPN prefix or on-premises sAMAccountName) matching $($AdminNamePatterns -join ', ')." 'Break-glass accounts; Entra role holders without an admin name are not detected here (see script 02 for role holders).' 'Entra (GET /users)' $entraStatus (Get-StatusNote @($entraStatus, $entraNote))
    Add-Denominator 'Break-glass accounts' $bgFound.Count 'Accounts listed in -BreakGlassUpns and found in AD or Entra, enabled or disabled.' $(if ($bgSet.Count) { "Listed: $(@($bgSet) -join ', ')" } else { 'None listed' }) 'Any account not listed in -BreakGlassUpns.' 'Parameter -BreakGlassUpns + AD / Entra' $bgStatus $(if (-not $bgSet.Count) { 'no -BreakGlassUpns given' } else { Join-Values @($(if ($bgMissing.Count) { "not found: $($bgMissing -join ', ')" }), (Get-StatusNote @($adStatus, $adNote, $entraStatus, $entraNote))) })
    Add-Denominator 'HR active workers' $hrActive.Count "HR records (unique $HrIdColumn) whose $HrStatusColumn is one of: $($ActiveStatusValues -join ', ')." 'Every active worker in the HR file, with or without an account.' "Any other status value; rows with a blank $HrIdColumn; duplicate ids after the first ($hrDuplicates)." $(if ($useHr) { "HR file $(Split-Path $HrCsvPath -Leaf)" } else { 'HR file' }) $hrStatus (Get-StatusNote @($hrStatus, $hrNote))
    Add-Denominator 'HR active with AD account' $(if ($hrAdStatus -eq 'Completed') { & $hrWith 'Ad' } else { '' }) "Active HR workers matched to at least one AD user account classified HumanWorkforce, enabled or disabled." "Matches on AD $AdEmployeeIdAttribute, or on UPN / mail when the id is blank." 'Workers whose only matched accounts are admin, service or test accounts (listed in population-reconciliation.csv as HrActiveNoAdAccount).' 'HR file + AD' $hrAdStatus (Get-StatusNote @($hrStatus, $hrNote, $adStatus, $adNote))
    Add-Denominator 'HR active with Entra account' $(if ($hrEnStatus -eq 'Completed') { & $hrWith 'E' } else { '' }) "Active HR workers matched to at least one Entra member account classified HumanWorkforce, enabled or disabled." 'Matches on AD employee id through the source anchor, on Entra employeeId, or on UPN / mail when both ids are blank.' 'Guests and external members; workers whose only matched accounts are admin, service or test accounts.' 'HR file + Entra' $hrEnStatus (Get-StatusNote @($hrStatus, $hrNote, $entraStatus, $entraNote))
    Add-Denominator 'Approved exclusions' @($realIds | Where-Object { $_.Exclusion }).Count 'Identities matched to an approved exclusion row (ApprovedBy set, ExpiresUtc blank or in the future) by UPN or sAMAccountName.' 'Applied exclusions, whatever the identity category (PatternAndExclusionConflict marks ones already excluded by a pattern).' 'Expired rows (flag ExclusionExpired); rows without ApprovedBy (ExclusionNotApproved) or with an unreadable date (ExclusionBadDate); rows that matched no identity (unmatched-exclusions.csv).' $(if ($ExclusionsCsv) { "Exclusions file $(Split-Path $ExclusionsCsv -Leaf)" } else { 'Exclusions file' }) $(if ($exStatus -eq 'Completed' -and $srcStatus -ne 'Completed') { 'Partial' } else { $exStatus }) (Get-StatusNote @($exStatus, $exNote, $srcStatus, 'not every directory source was read'))
    Export-Dataset -Name 'population-denominators' -Rows $den -Status $(if ((Get-WorstStatus @($den | ForEach-Object Status)) -eq 'Completed') { 'Completed' } else { 'Partial' }) -Note 'One row per standard population; Count is blank when the population could not be computed (see Status)'

    # ---- 12. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric -Metric 'AD users' -Value $adStatus -Note $adNote
    Add-Metric -Metric 'Entra users' -Value $entraStatus -Note $entraNote
    Add-Metric -Metric 'HR file' -Value $hrStatus -Note $hrNote
    Add-Metric -Metric 'Exclusions file' -Value $exStatus -Note $exNote
    foreach ($d in $den) { Add-Metric -Metric "Population: $($d.Population)" -Value $(if ($d.Status -in @('Completed', 'Partial')) { $d.Count } else { $d.Status }) -Note $(if ($d.Status -ne 'Completed') { "Status $($d.Status)" } else { '' }) }
    # Counts from a source that was not read are never reported as zero.
    $noData = ($idStatus -in @('Blocked', 'EvidenceUnavailable'))
    $partNote = $(if ($idStatus -eq 'Partial') { "Partial: $idNote" } else { '' })
    Add-Metric -Metric 'Identities' -Value $(if ($noData) { $idStatus } else { $realIds.Count }) -Note (Join-Values @('AD and Entra accounts after the anchor join (HR-only rows not counted)', $partNote))
    foreach ($src in 'AD+Entra', 'AD only', 'Entra only', 'HR only') { Add-Metric -Metric "Identities: source $src" -Value $(if ($noData) { $idStatus } else { @($ids | Where-Object Source -eq $src).Count }) -Note $partNote }
    foreach ($cat in 'HumanWorkforce', 'AdminAccount', 'ServiceAccount', 'BreakGlass', 'Guest', 'ExternalMember', 'ResourceOrShared', 'TestAccount', 'Unclassified-NoHR') {
        Add-Metric -Metric "Identities: category $cat" -Value $(if ($noData) { $idStatus } else { @($realIds | Where-Object Category -eq $cat).Count }) -Note $(if ($cat -eq 'Unclassified-NoHR') { $(if ($useHr) { 'Enabled ones are in population-reconciliation.csv; classify them with a name pattern, an HR record or an exclusion' } else { 'Only used with an HR file' }) } else { '' })
    }
    Add-Metric -Metric 'Unclassified (enabled, no HR match, no pattern)' -Value $(if ($noData) { $idStatus } elseif ($useHr) { @($realIds | Where-Object { $_.Category -eq 'Unclassified-NoHR' -and (($_.AdEnabled -eq $true) -or ($_.EntraEnabled -eq $true)) }).Count } else { 'Deferred' }) -Note $(if ($useHr) { 'Should trend to zero before the denominators are signed' } else { 'Needs -HrCsvPath' })
    if ($useHr) {
        $memberEnabled = @($realIds | Where-Object { $_.Category -notin @('Guest', 'ExternalMember') -and (($_.AdEnabled -eq $true) -or ($_.EntraEnabled -eq $true)) })
        $memberMatched = @($memberEnabled | Where-Object { $_.Hr })
        Add-Metric -Metric 'HR match rate: enabled member accounts matched to HR (%)' -Value $(if ($memberEnabled.Count) { [math]::Round(100 * $memberMatched.Count / $memberEnabled.Count, 1) } else { '' }) -Note ("{0} of {1}; service, test and resource accounts normally have no HR record" -f $memberMatched.Count, $memberEnabled.Count)
        $hwEnabled = @($realIds | Where-Object { $_.Category -in @('HumanWorkforce', 'Unclassified-NoHR') -and (($_.AdEnabled -eq $true) -or ($_.EntraEnabled -eq $true)) })
        Add-Metric -Metric 'HR match rate: enabled person-like accounts matched to HR (%)' -Value $(if ($hwEnabled.Count) { [math]::Round(100 * @($hwEnabled | Where-Object { $_.Hr }).Count / $hwEnabled.Count, 1) } else { '' }) -Note 'HumanWorkforce + Unclassified-NoHR'
        Add-Metric -Metric 'HR active workers matched to any account (%)' -Value $(if ($hrActive.Count) { [math]::Round(100 * @($hrActive | Where-Object { $hrMatches.ContainsKey($_.Id) }).Count / $hrActive.Count, 1) } else { '' })
        Add-Metric 'HR matches by fallback (UPN / mail)' @($realIds | Where-Object { $_.HrBy -in @('UPN', 'Mail') }).Count
        Add-Metric 'HR duplicate ids (ignored)' $hrDuplicates
        foreach ($iss in 'HrActiveNoAdAccount', 'HrActiveNoEntraAccount', 'HrTerminatedAdEnabled', 'HrTerminatedEntraEnabled', 'AdEnabledHumanNotInHr', 'EntraEnabledHumanNotInHr') { Add-Metric "Reconciliation: $iss" @($recRows | Where-Object Issue -eq $iss).Count }
    }
    Add-Metric -Metric 'Excluded from a human-workforce population (enabled identities)' -Value $(if ($noData) { $idStatus } else { $exclRows.Count }) -Note (Join-Values @('population-exclusions.csv', $partNote))
    foreach ($t in 'Category', 'ApprovedExclusion', 'NoHrMatch', 'HrNotActive') { Add-Metric -Metric "Excluded: $t" -Value $(if ($noData) { $idStatus } else { @($exclRows | Where-Object ExclusionType -eq $t).Count }) -Note $partNote }
    if ($ExclusionsCsv) { Add-Metric -Metric 'Exclusion rows matching no identity' -Value @($exRows | Where-Object { -not $_.Matched }).Count -Note 'unmatched-exclusions.csv' }
    foreach ($f in 'NoHrMatch', 'HrTerminatedButEnabled', 'HrActiveButDisabled', 'MultipleAccountsSameHrId', 'AdminCountNotAdminNamed', 'PersonAccountWithSpn', 'EnabledMismatch', 'DuplicateAnchor', 'SyncedNoAdMatch', 'ExclusionExpired', 'ExclusionNotApproved', 'ExclusionBadDate', 'PatternAndExclusionConflict') {
        Add-Metric -Metric "Flag: $f" -Value $(if ($noData) { $idStatus } else { @($realIds | Where-Object { $_.Flags.Contains($f) }).Count }) -Note $partNote
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Context $ctx -Parameters @{ SearchBase = $SearchBase; AnchorAttribute = $AnchorAttribute; SkipAD = [bool]$SkipAD; SkipEntra = [bool]$SkipEntra
        HrCsvPath = $(if ($HrCsvPath) { Split-Path $HrCsvPath -Leaf } else { '' }); HrIdColumn = $HrIdColumn; HrStatusColumn = $HrStatusColumn; ActiveStatusValues = $ActiveStatusValues; AdEmployeeIdAttribute = $AdEmployeeIdAttribute
        ExclusionsCsv = $(if ($ExclusionsCsv) { Split-Path $ExclusionsCsv -Leaf } else { '' }); BreakGlassCount = $BreakGlassUpns.Count
        AdminNamePatterns = $AdminNamePatterns; ServiceNamePatterns = $ServiceNamePatterns; TestNamePatterns = $TestNamePatterns; ResourceNamePatterns = $ResourceNamePatterns }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
