<#
.SYNOPSIS
    Read-only snapshot of the Conditional Access configuration, with drift against an earlier snapshot.

.DESCRIPTION
    Answers: what exactly is the Conditional Access configuration right now, and what changed since
    the last snapshot?

    Take a snapshot before an approved change (the frozen baseline and the rollback artifact), and
    again after it (the before / after proof). After a rollback, a snapshot compared with the
    pre-change baseline should show every policy as Unchanged.

    The script reads, from Microsoft Graph v1.0:
      - Conditional Access policies
      - named locations
      - authentication strength policies
      - the authentication methods policy
      - the security defaults policy

    Each is written as JSON exactly as read (IDs, not names), in a stable order: objects sorted by
    id, properties sorted by name, dates as UTC ISO 8601. Two snapshots of an unchanged
    configuration therefore produce the same JSON, apart from a few volatile fields (see the doc
    page). Every JSON file is recorded in dataset-status.csv with its SHA-256, like the CSV files.

    ca-policies.csv flattens each policy to one row. With -ResolveNames (on by default) user, group,
    role, application and named location IDs in the CSV are shown as names; the JSON stays raw.
    PolicyHash is the SHA-256 of the canonical JSON of that one policy without volatile fields, so
    the same hash in two snapshots means the same configuration.

    -BaselineRunFolder points at an earlier run folder of this script. Every policy, named location
    and authentication strength is then compared by id: Added, Removed, Changed (with the dot paths
    of every value that differs, such as conditions.users.excludeGroups) or Unchanged. The baseline
    JSON is checked against the SHA-256 the baseline run recorded. If the baseline cannot be used,
    the drift datasets are Blocked and the snapshot still runs.

    READ-ONLY. Every Graph call is an HTTP GET.

    Output: <OutputRoot>\28-CaPolicySnapshot\<yyyyMMdd-HHmmssZ>\*.csv, *.json + run-manifest.json + run.log

.PARAMETER BaselineRunFolder
    An earlier run folder of this script (the one holding its run-manifest.json and ca-policies.json).
    Adds ca-policy-drift.csv, named-location-drift.csv and authentication-strength-drift.csv.

.PARAMETER ResolveNames
    Show names instead of IDs for users, groups, roles, applications and named locations in
    ca-policies.csv. Default $true. Pass -ResolveNames $false for a faster run with raw IDs only.
    The JSON files always hold the raw IDs.

.EXAMPLE
    .\28-Export-CaPolicySnapshot.ps1
.EXAMPLE
    .\28-Export-CaPolicySnapshot.ps1 -BaselineRunFolder .\output\28-CaPolicySnapshot\20261001-090000Z
.EXAMPLE
    .\28-Export-CaPolicySnapshot.ps1 -ResolveNames $false

.NOTES
    Version : 1.0.1
    Requires: PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication.
    Scopes  : Policy.Read.All; Directory.Read.All and Application.Read.All for name resolution.
              Role: Global Reader or Security Reader.
    Licence : Conditional Access needs Entra ID P1.
    Sources : Microsoft Graph conditionalAccessPolicy, namedLocation, authenticationStrengthPolicy,
              authenticationMethodsPolicy and identitySecurityDefaultsEnforcementPolicy (v1.0).
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

    [string]$BaselineRunFolder = '',
    [bool]$ResolveNames = $true
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '28-CaPolicySnapshot'
$ScriptVersion = '1.0.1'
$RequiredScopes = @('Policy.Read.All')
if ($ResolveNames) { $RequiredScopes += @('Directory.Read.All', 'Application.Read.All') }


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

function ConvertTo-UtcText {
    # Graph date (string or DateTime) -> 'yyyy-MM-ddTHH:mm:ssZ', '' when empty or unparsable.
    param($Value)
    if (-not $Value) { return '' }
    try { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return "$Value" }
}

# ---- Stable JSON: sorted form for the files, canonical form for hashes and drift ----
$script:IsoDatePattern = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$'
$script:Invariant = [System.Globalization.CultureInfo]::InvariantCulture

function ConvertTo-StableDateText {
    # Any date (DateTime, DateTimeOffset or ISO 8601 string) -> UTC 'yyyy-MM-ddTHH:mm:ss[.fffffff]Z'.
    # A date without a zone is taken as UTC (Graph dates are UTC).
    param($Value)
    $dto = $null
    if ($Value -is [datetimeoffset]) { $dto = $Value }
    elseif ($Value -is [datetime]) {
        $dt = $Value
        if ($dt.Kind -eq [System.DateTimeKind]::Unspecified) { $dt = [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Utc) }
        $dto = [datetimeoffset]$dt
    }
    else {
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        $parsed = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse([string]$Value, $script:Invariant, $styles, [ref]$parsed)) { return [string]$Value }
        $dto = $parsed
    }
    return $dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.FFFFFFFZ', $script:Invariant)
}

function Test-EmptyValue {
    # True for $null, an empty list or an empty object (left out of the canonical form).
    param($Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [System.Collections.IDictionary]) { return ($Value.Count -eq 0) }
    if ($Value -is [System.Collections.IList]) { return ($Value.Count -eq 0) }
    return $false
}

function Get-SortedKeys {
    # Property names in ordinal order, so the order never depends on the culture of the machine.
    param([string[]]$Keys)
    $k = @($Keys)
    [Array]::Sort([Array]$k, [System.Collections.IComparer][System.StringComparer]::Ordinal)
    return , $k
}

function ConvertTo-SortedValue {
    # Rebuilds a Graph object as nested ordered dictionaries with properties in ordinal order and
    # dates as UTC text. -Canonical also: drops null / empty values, sorts lists (list order carries
    # no meaning in these policies) and leaves out the -Exclude dot paths (volatile fields).
    param($Value, [switch]$Canonical, [string[]]$Exclude = @(), [string]$Path = '')
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if ($Value -match $script:IsoDatePattern) { return (ConvertTo-StableDateText $Value) }
        return $Value
    }
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) { return (ConvertTo-StableDateText $Value) }
    if ($Value -is [bool] -or $Value -is [ValueType]) { return $Value }

    $pairs = [ordered]@{}
    $isObject = $false
    if ($Value -is [System.Collections.IDictionary]) {
        $isObject = $true
        foreach ($k in $Value.Keys) { $pairs[[string]$k] = $Value[$k] }
    }
    elseif ($Value -is [System.Management.Automation.PSCustomObject]) {
        $isObject = $true
        foreach ($p in $Value.PSObject.Properties) { $pairs[$p.Name] = $p.Value }
    }
    if ($isObject) {
        $out = [ordered]@{}
        foreach ($k in (Get-SortedKeys -Keys @($pairs.Keys))) {
            if ($k -in @('@odata.context', '@odata.nextLink', '@odata.count')) { continue }
            $childPath = $(if ($Path) { "$Path.$k" } else { $k })
            if ($Canonical -and $Exclude -contains $childPath) { continue }
            $v = ConvertTo-SortedValue -Value $pairs[$k] -Canonical:$Canonical -Exclude $Exclude -Path $childPath
            if ($Canonical -and (Test-EmptyValue $v)) { continue }
            $out[$k] = $v
        }
        return $out
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($i in $Value) {
            $v = ConvertTo-SortedValue -Value $i -Canonical:$Canonical -Exclude $Exclude -Path $Path
            if ($Canonical -and (Test-EmptyValue $v)) { continue }
            $items.Add($v)
        }
        if ($Canonical -and $items.Count -gt 1) {
            $keyed = @(foreach ($i in $items) { [pscustomobject]@{ Key = (ConvertTo-CanonicalJson $i); Item = $i } })
            $keys = [string[]]@($keyed | ForEach-Object { $_.Key })
            $arr = [object[]]@($keyed | ForEach-Object { $_.Item })
            [Array]::Sort([Array]$keys, [Array]$arr, [System.Collections.IComparer][System.StringComparer]::Ordinal)
            return , $arr
        }
        return , $items.ToArray()
    }
    return [string]$Value
}

function ConvertTo-CanonicalJson {
    # Compact JSON written the same way on PowerShell 5.1 and 7, so hashes match across versions.
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [string]) {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append('"')
        foreach ($ch in $Value.ToCharArray()) {
            switch ($ch) {
                '"' { [void]$sb.Append('\"') }
                '\' { [void]$sb.Append('\\') }
                default {
                    if ([int]$ch -lt 32) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) } else { [void]$sb.Append($ch) }
                }
            }
        }
        [void]$sb.Append('"')
        return $sb.ToString()
    }
    if ($Value -is [double] -or $Value -is [single]) { return ([double]$Value).ToString('R', $script:Invariant) }
    if ($Value -is [ValueType]) { return ([System.Convert]::ToString($Value, $script:Invariant)) }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = @(foreach ($k in $Value.Keys) { (ConvertTo-CanonicalJson ([string]$k)) + ':' + (ConvertTo-CanonicalJson $Value[$k]) })
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = @(foreach ($i in $Value) { ConvertTo-CanonicalJson $i })
        return '[' + ($parts -join ',') + ']'
    }
    return (ConvertTo-CanonicalJson ([string]$Value))
}

function Get-TextSha256 {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) } finally { $sha.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-ObjectHash {
    # SHA-256 of the canonical JSON of one object, volatile fields left out.
    param($Object, [string[]]$Volatile)
    return (Get-TextSha256 (ConvertTo-CanonicalJson (ConvertTo-SortedValue -Value $Object -Canonical -Exclude $Volatile)))
}

function Get-SortedById {
    # Objects ordered by id (ordinal), so two snapshots list them in the same order.
    param($Items)
    $list = @($Items | Where-Object { $null -ne $_ })
    if ($list.Count -lt 2) { return , [object[]]$list }
    $keys = [string[]]@($list | ForEach-Object { [string]$_.id })
    $arr = [object[]]$list
    [Array]::Sort([Array]$keys, [Array]$arr, [System.Collections.IComparer][System.StringComparer]::Ordinal)
    return , $arr
}

function Export-JsonDataset {
    # Writes <Name>.json (ConvertTo-Json -Depth 20 of the sorted form), hashes it and records its status
    # in dataset-status.csv as '<Name>-json', like Export-Dataset does for CSV files.
    param([Parameter(Mandatory)][string]$Name, $Data, [switch]$IsList, [string]$Status = 'Completed', [string]$Note = '')
    $file = Join-Path $script:RunFolder ("{0}.json" -f $Name)
    if ($IsList) {
        $sorted = [object[]]@(foreach ($i in (Get-SortedById $Data)) { ConvertTo-SortedValue -Value $i })
        $json = $(if ($sorted.Count) { ConvertTo-Json -InputObject $sorted -Depth 20 } else { '[]' })
        $count = $sorted.Count
    }
    else {
        $json = ConvertTo-Json -InputObject (ConvertTo-SortedValue -Value $Data) -Depth 20
        $count = $(if ($null -ne $Data) { 1 } else { 0 })
    }
    Set-Content -Path $file -Value $json -Encoding UTF8
    $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
    $script:Datasets.Add([pscustomobject][ordered]@{ Dataset = "$Name-json"; Status = $Status; Rows = $count; File = (Split-Path $file -Leaf); Sha256 = $hash; Note = $Note })
    Write-RunLog ("{0}.json: {1} objects [{2}] {3}" -f $Name, $count, $Status, $Note)
}

function Get-ChangedPath {
    # Writes the dot path of every leaf value that differs between two canonical objects.
    # Lists are compared as a whole (their path is reported, not an index).
    param($Baseline, $Current, [string]$Path = '')
    $bIsObj = $Baseline -is [System.Collections.IDictionary]
    $cIsObj = $Current -is [System.Collections.IDictionary]
    if (($bIsObj -or $null -eq $Baseline) -and ($cIsObj -or $null -eq $Current) -and ($bIsObj -or $cIsObj)) {
        $b = $(if ($bIsObj) { $Baseline } else { @{} })
        $c = $(if ($cIsObj) { $Current } else { @{} })
        $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($k in $b.Keys) { [void]$names.Add([string]$k) }
        foreach ($k in $c.Keys) { [void]$names.Add([string]$k) }
        foreach ($k in (Get-SortedKeys -Keys @($names))) {
            $child = $(if ($Path) { "$Path.$k" } else { $k })
            $bv = $(if ($b.Contains($k)) { $b[$k] } else { $null })
            $cv = $(if ($c.Contains($k)) { $c[$k] } else { $null })
            Get-ChangedPath -Baseline $bv -Current $cv -Path $child
        }
        return
    }
    if ((ConvertTo-CanonicalJson $Baseline) -cne (ConvertTo-CanonicalJson $Current)) { $(if ($Path) { $Path } else { '(root)' }) }
}

function Compare-SnapshotSet {
    # Compares two id -> canonical object maps. One row per id: Added / Removed / Changed / Unchanged.
    param([hashtable]$Baseline, [hashtable]$Current)
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $Baseline.Keys) { [void]$ids.Add($k) }
    foreach ($k in $Current.Keys) { [void]$ids.Add($k) }
    foreach ($id in (Get-SortedKeys -Keys @($ids))) {
        $inB = $Baseline.ContainsKey($id); $inC = $Current.ContainsKey($id)
        $type = 'Unchanged'; $paths = @()
        if ($inB -and -not $inC) { $type = 'Removed' }
        elseif ($inC -and -not $inB) { $type = 'Added' }
        else {
            $paths = @(Get-ChangedPath -Baseline $Baseline[$id] -Current $Current[$id])
            if ($paths.Count) { $type = 'Changed' }
        }
        [pscustomobject]@{ Id = $id; ChangeType = $type; ChangedPaths = ($paths -join '; ') }
    }
}

function Get-CanonicalMap {
    # id -> canonical object (volatile fields left out), for drift.
    param($Items, [string[]]$Volatile)
    $map = @{}
    foreach ($i in @($Items)) { if ($null -ne $i -and $i.PSObject.Properties.Name -contains 'id') { $map[[string]$i.id] = ConvertTo-SortedValue -Value $i -Canonical -Exclude $Volatile } }
    return $map
}

function Get-RawMap {
    param($Items)
    $map = @{}
    foreach ($i in @($Items)) { if ($null -ne $i -and $i.PSObject.Properties.Name -contains 'id') { $map[[string]$i.id] = $i } }
    return $map
}

# Fields that change without a configuration change (an edit that is later reverted, or a service update).
# They are kept in the JSON files but left out of every hash and drift comparison.
$VolatilePolicy   = @('modifiedDateTime', 'grantControls.authenticationStrength.createdDateTime', 'grantControls.authenticationStrength.modifiedDateTime')
$VolatileLocation = @('modifiedDateTime')
$VolatileStrength = @('modifiedDateTime')
$VolatileMethods  = @('lastModifiedDateTime')

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph
    $script:ManifestExtra = [ordered]@{ ResolveNames = $ResolveNames; VolatileFieldsExcludedFromHashes = 'policies: modifiedDateTime, grantControls.authenticationStrength.createdDateTime/modifiedDateTime; namedLocations and authenticationStrengths: modifiedDateTime; authenticationMethodsPolicy: lastModifiedDateTime' }

    # ---- 1. Reads ----
    $read = [ordered]@{}
    function Read-SnapshotSource {
        param([string]$Key, [string]$Uri, [switch]$Single)
        $r = [pscustomobject]@{ Key = $Key; Ok = $false; Data = $null; Status = ''; Note = '' }
        try {
            if ($Single) { $r.Data = Invoke-GraphGet -Uri $Uri }
            else { $list = Invoke-GraphGetAll -Uri $Uri -Label $Key; $r.Data = $list.ToArray() }
            $r.Ok = $true
        }
        catch {
            $r.Status = Get-FailureStatus $_
            $r.Note = "$Key not readable: $($_.Exception.Message)"
            Write-RunLog $r.Note 'WARN'
        }
        $read[$Key] = $r
        return $r
    }
    $rPol = Read-SnapshotSource -Key 'policies' -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    $rLoc = Read-SnapshotSource -Key 'namedLocations' -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations'
    $rStr = Read-SnapshotSource -Key 'authenticationStrengthPolicies' -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies'
    $rAmp = Read-SnapshotSource -Key 'authenticationMethodsPolicy' -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' -Single
    $rSd  = Read-SnapshotSource -Key 'securityDefaults' -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -Single
    if ($rPol.Ok) { Write-RunLog ("{0} Conditional Access policies read" -f @($rPol.Data).Count) }

    # ---- 2. Name lookups (CSV only) ----
    $roleNames = @{}
    $appNames = @{}
    $locationNames = @{}
    $strengthNames = @{}
    $lookupNotes = [System.Collections.Generic.List[string]]::new()
    if ($rLoc.Ok) { foreach ($l in $rLoc.Data) { $locationNames[[string]$l.id] = [string]$l.displayName } }
    if ($rStr.Ok) { foreach ($s in $rStr.Data) { $strengthNames[[string]$s.id] = [string]$s.displayName } }
    if ($ResolveNames -and $rPol.Ok) {
        try {
            foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName' -Label 'roleDefinitions')) {
                $roleNames[[string]$r.id] = [string]$r.displayName
                if ($r.templateId) { $roleNames[[string]$r.templateId] = [string]$r.displayName }
            }
        }
        catch { $lookupNotes.Add('role names not readable (IDs shown)'); Write-RunLog ("Role definitions not readable; role IDs shown raw. {0}" -f $_.Exception.Message) 'WARN' }
    }
    function Resolve-AppId {
        param([string]$AppId)
        if (-not $ResolveNames -or $AppId -in @('All', 'None', 'Office365', 'MicrosoftAdminPortals')) { return $AppId }
        if ($appNames.ContainsKey($AppId)) { return $appNames[$AppId] }
        $label = "$AppId (unresolved)"
        try {
            $sp = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=displayName,appId" -f $AppId)
            if (@($sp.value).Count -gt 0) { $label = '{0} ({1})' -f $sp.value[0].displayName, $AppId }
        }
        catch { }
        $appNames[$AppId] = $label
        return $label
    }
    function Resolve-ObjectId {
        param([string]$Id)
        if (-not $ResolveNames) { return $Id }
        return (Resolve-DirectoryObject $Id)
    }
    function Resolve-RoleId {
        param([string]$Id)
        if (-not $ResolveNames) { return $Id }
        if ($roleNames.ContainsKey($Id)) { return $roleNames[$Id] }
        return $Id
    }
    function Resolve-LocationId {
        param([string]$Id)
        if (-not $ResolveNames -or $Id -in @('All', 'AllTrusted')) { return $Id }
        if ($locationNames.ContainsKey($Id)) { return $locationNames[$Id] }
        return "$Id (unresolved)"
    }
    function ConvertTo-GuestText {
        param($Guests)
        if (-not $Guests) { return '' }
        $text = [string](Get-OptionalValue $Guests 'guestOrExternalUserTypes')
        $ext = Get-OptionalValue $Guests 'externalTenants'
        if ($ext) {
            $kind = [string](Get-OptionalValue $ext 'membershipKind')
            $members = Join-Values (Get-OptionalValue $ext 'members')
            $text += ' | tenants: ' + $kind + $(if ($members) { " ($members)" } else { '' })
        }
        return $text
    }
    function ConvertTo-IncludeExcludeText {
        param($Include, $Exclude)
        $i = Join-Values $Include; $e = Join-Values $Exclude
        return (@($(if ($i) { "Include: $i" }), $(if ($e) { "Exclude: $e" })) | Where-Object { $_ }) -join ' | '
    }
    function ConvertTo-SessionText {
        param($Session)
        if (-not $Session) { return '' }
        $parts = @()
        $sif = Get-OptionalValue $Session 'signInFrequency'
        if ($sif -and (Get-OptionalValue $sif 'isEnabled')) {
            $parts += $(if ("$(Get-OptionalValue $sif 'frequencyInterval')" -eq 'everyTime') { 'signInFrequency: every time' } else { 'signInFrequency: {0} {1}' -f (Get-OptionalValue $sif 'value'), (Get-OptionalValue $sif 'type') })
        }
        $pb = Get-OptionalValue $Session 'persistentBrowser'
        if ($pb -and (Get-OptionalValue $pb 'isEnabled')) { $parts += 'persistentBrowser: {0}' -f (Get-OptionalValue $pb 'mode') }
        $cas = Get-OptionalValue $Session 'cloudAppSecurity'
        if ($cas -and (Get-OptionalValue $cas 'isEnabled')) { $parts += 'cloudAppSecurity: {0}' -f (Get-OptionalValue $cas 'cloudAppSecurityType') }
        $aer = Get-OptionalValue $Session 'applicationEnforcedRestrictions'
        if ($aer -and (Get-OptionalValue $aer 'isEnabled')) { $parts += 'applicationEnforcedRestrictions' }
        if ((Get-OptionalValue $Session 'disableResilienceDefaults') -eq $true) { $parts += 'disableResilienceDefaults' }
        return Join-Values $parts
    }

    # ---- 3. Current snapshot files ----
    $policyHashes = @{}
    if ($rPol.Ok) {
        Export-JsonDataset -Name 'ca-policies' -Data $rPol.Data -IsList -Note 'Raw policies (IDs, not names), sorted by id'
        $polRows = foreach ($p in (Get-SortedById $rPol.Data)) {
            $c = Get-OptionalValue $p 'conditions'
            $u = Get-OptionalValue $c 'users'
            $a = Get-OptionalValue $c 'applications'
            $g = Get-OptionalValue $p 'grantControls'
            $pl = Get-OptionalValue $c 'platforms'
            $lo = Get-OptionalValue $c 'locations'
            $dv = Get-OptionalValue $c 'devices'
            $df = Get-OptionalValue $dv 'deviceFilter'
            $as = Get-OptionalValue $g 'authenticationStrength'
            $asText = ''
            if ($as) { $asText = $(if (Get-OptionalValue $as 'displayName') { [string]$as.displayName } elseif ($strengthNames.ContainsKey([string]$as.id)) { $strengthNames[[string]$as.id] } else { [string]$as.id }) }
            $hash = Get-ObjectHash -Object $p -Volatile $VolatilePolicy
            $policyHashes[[string]$p.id] = $hash
            [pscustomobject][ordered]@{
                PolicyId                = [string]$p.id
                DisplayName             = [string]$p.displayName
                State                   = [string]$p.state
                CreatedUtc              = ConvertTo-UtcText (Get-OptionalValue $p 'createdDateTime')
                ModifiedUtc             = ConvertTo-UtcText (Get-OptionalValue $p 'modifiedDateTime')
                IncludeUsers            = Join-Values (@(Get-OptionalValue $u 'includeUsers') | Where-Object { $_ } | ForEach-Object { Resolve-ObjectId $_ })
                ExcludeUsers            = Join-Values (@(Get-OptionalValue $u 'excludeUsers') | Where-Object { $_ } | ForEach-Object { Resolve-ObjectId $_ })
                IncludeGroups           = Join-Values (@(Get-OptionalValue $u 'includeGroups') | Where-Object { $_ } | ForEach-Object { Resolve-ObjectId $_ })
                ExcludeGroups           = Join-Values (@(Get-OptionalValue $u 'excludeGroups') | Where-Object { $_ } | ForEach-Object { Resolve-ObjectId $_ })
                IncludeRoles            = Join-Values (@(Get-OptionalValue $u 'includeRoles') | Where-Object { $_ } | ForEach-Object { Resolve-RoleId $_ })
                ExcludeRoles            = Join-Values (@(Get-OptionalValue $u 'excludeRoles') | Where-Object { $_ } | ForEach-Object { Resolve-RoleId $_ })
                IncludeGuestsOrExternal = ConvertTo-GuestText (Get-OptionalValue $u 'includeGuestsOrExternalUsers')
                ExcludeGuestsOrExternal = ConvertTo-GuestText (Get-OptionalValue $u 'excludeGuestsOrExternalUsers')
                IncludeApplications     = Join-Values (@(Get-OptionalValue $a 'includeApplications') | Where-Object { $_ } | ForEach-Object { Resolve-AppId $_ })
                ExcludeApplications     = Join-Values (@(Get-OptionalValue $a 'excludeApplications') | Where-Object { $_ } | ForEach-Object { Resolve-AppId $_ })
                UserActions             = Join-Values (Get-OptionalValue $a 'includeUserActions')
                AuthContexts            = Join-Values (Get-OptionalValue $a 'includeAuthenticationContextClassReferences')
                ClientAppTypes          = Join-Values (Get-OptionalValue $c 'clientAppTypes')
                Platforms               = ConvertTo-IncludeExcludeText (Get-OptionalValue $pl 'includePlatforms') (Get-OptionalValue $pl 'excludePlatforms')
                Locations               = ConvertTo-IncludeExcludeText (@(Get-OptionalValue $lo 'includeLocations') | Where-Object { $_ } | ForEach-Object { Resolve-LocationId $_ }) (@(Get-OptionalValue $lo 'excludeLocations') | Where-Object { $_ } | ForEach-Object { Resolve-LocationId $_ })
                SignInRisk              = Join-Values (Get-OptionalValue $c 'signInRiskLevels')
                UserRisk                = Join-Values (Get-OptionalValue $c 'userRiskLevels')
                DeviceFilter            = $(if ($df) { '{0}: {1}' -f (Get-OptionalValue $df 'mode'), (Get-OptionalValue $df 'rule') } else { '' })
                GrantOperator           = [string](Get-OptionalValue $g 'operator')
                BuiltInControls         = Join-Values (Get-OptionalValue $g 'builtInControls')
                AuthenticationStrength  = $asText
                TermsOfUse              = Join-Values (Get-OptionalValue $g 'termsOfUse')
                SessionControls         = ConvertTo-SessionText (Get-OptionalValue $p 'sessionControls')
                PolicyHash              = $hash
            }
        }
        $unresolved = @($script:ObjectCache.Values | Where-Object { "$_" -like '*(unresolved*' }).Count + @($appNames.Values | Where-Object { "$_" -like '*(unresolved*' }).Count
        if ($unresolved) { $lookupNotes.Add("$unresolved ID(s) could not be resolved (deleted, or no read access) and are shown with '(unresolved)'") }
        $csvNote = $(if ($ResolveNames) { 'Names resolved in this file only; ca-policies.json holds the raw IDs' } else { 'IDs shown raw (-ResolveNames $false)' })
        if ($ResolveNames -and -not $rLoc.Ok) { $lookupNotes.Insert(0, 'named locations not readable (location IDs shown)') }
        if ($lookupNotes.Count) { $csvNote += '; ' + ($lookupNotes -join '; ') }
        Export-Dataset -Name 'ca-policies' -Rows @($polRows) -Status $(if ($lookupNotes.Count) { 'Partial' } else { 'Completed' }) -Note $csvNote
    }
    else {
        Set-DatasetStatus -Name 'ca-policies-json' -Status $rPol.Status -Note $rPol.Note
        Set-DatasetStatus -Name 'ca-policies' -Status $rPol.Status -Note $rPol.Note
    }

    # Which policies use each named location and authentication strength.
    $locUse = @{}; $strUse = @{}
    if ($rPol.Ok) {
        foreach ($p in $rPol.Data) {
            $lo = Get-OptionalValue (Get-OptionalValue $p 'conditions') 'locations'
            foreach ($id in @(@(Get-OptionalValue $lo 'includeLocations') + @(Get-OptionalValue $lo 'excludeLocations'))) {
                if (-not $id) { continue }
                if (-not $locUse.ContainsKey([string]$id)) { $locUse[[string]$id] = [System.Collections.Generic.List[string]]::new() }
                $locUse[[string]$id].Add([string]$p.displayName)
            }
            $as = Get-OptionalValue (Get-OptionalValue $p 'grantControls') 'authenticationStrength'
            if ($as -and $as.id) {
                if (-not $strUse.ContainsKey([string]$as.id)) { $strUse[[string]$as.id] = [System.Collections.Generic.List[string]]::new() }
                $strUse[[string]$as.id].Add([string]$p.displayName)
            }
        }
    }
    $useNote = $(if ($rPol.Ok) { '' } else { '; UsedByPolicies blank: policies not readable' })

    if ($rLoc.Ok) {
        Export-JsonDataset -Name 'named-locations' -Data $rLoc.Data -IsList -Note 'Raw named locations, sorted by id'
        $locRows = foreach ($l in (Get-SortedById $rLoc.Data)) {
            $ranges = @(Get-OptionalValue $l 'ipRanges') | Where-Object { $_ } | ForEach-Object { [string](Get-OptionalValue $_ 'cidrAddress') }
            [pscustomobject][ordered]@{
                LocationId              = [string]$l.id
                DisplayName             = [string]$l.displayName
                LocationType            = ([string](Get-OptionalValue $l '@odata.type') -replace '#microsoft.graph.', '')
                IsTrusted               = Get-OptionalValue $l 'isTrusted'
                IpRanges                = Join-Values $ranges
                Countries               = Join-Values (Get-OptionalValue $l 'countriesAndRegions')
                IncludeUnknownCountries = Get-OptionalValue $l 'includeUnknownCountriesAndRegions'
                CountryLookupMethod     = [string](Get-OptionalValue $l 'countryLookupMethod')
                CreatedUtc              = ConvertTo-UtcText (Get-OptionalValue $l 'createdDateTime')
                ModifiedUtc             = ConvertTo-UtcText (Get-OptionalValue $l 'modifiedDateTime')
                UsedByPolicies          = $(if ($locUse.ContainsKey([string]$l.id)) { Join-Values ($locUse[[string]$l.id] | Sort-Object -Unique) } else { '' })
                LocationHash            = Get-ObjectHash -Object $l -Volatile $VolatileLocation
            }
        }
        Export-Dataset -Name 'named-locations' -Rows @($locRows) -Note ('One row per named location' + $useNote)
    }
    else {
        Set-DatasetStatus -Name 'named-locations-json' -Status $rLoc.Status -Note $rLoc.Note
        Set-DatasetStatus -Name 'named-locations' -Status $rLoc.Status -Note $rLoc.Note
    }

    if ($rStr.Ok) {
        Export-JsonDataset -Name 'authentication-strengths' -Data $rStr.Data -IsList -Note 'Raw authentication strength policies (built-in and custom), sorted by id'
        $strRows = foreach ($s in (Get-SortedById $rStr.Data)) {
            [pscustomobject][ordered]@{
                StrengthId            = [string]$s.id
                DisplayName           = [string]$s.displayName
                PolicyType            = [string](Get-OptionalValue $s 'policyType')
                RequirementsSatisfied = [string](Get-OptionalValue $s 'requirementsSatisfied')
                AllowedCombinations   = Join-Values (Get-OptionalValue $s 'allowedCombinations')
                Description           = [string](Get-OptionalValue $s 'description')
                CreatedUtc            = ConvertTo-UtcText (Get-OptionalValue $s 'createdDateTime')
                ModifiedUtc           = ConvertTo-UtcText (Get-OptionalValue $s 'modifiedDateTime')
                UsedByPolicies        = $(if ($strUse.ContainsKey([string]$s.id)) { Join-Values ($strUse[[string]$s.id] | Sort-Object -Unique) } else { '' })
                StrengthHash          = Get-ObjectHash -Object $s -Volatile $VolatileStrength
            }
        }
        Export-Dataset -Name 'authentication-strengths' -Rows @($strRows) -Note ('One row per authentication strength' + $useNote)
    }
    else {
        Set-DatasetStatus -Name 'authentication-strengths-json' -Status $rStr.Status -Note $rStr.Note
        Set-DatasetStatus -Name 'authentication-strengths' -Status $rStr.Status -Note $rStr.Note
    }

    if ($rAmp.Ok) { Export-JsonDataset -Name 'authentication-methods-policy' -Data $rAmp.Data -Note 'Raw authentication methods policy with its method configurations' }
    else { Set-DatasetStatus -Name 'authentication-methods-policy-json' -Status $rAmp.Status -Note $rAmp.Note }
    if ($rSd.Ok) { Export-JsonDataset -Name 'security-defaults' -Data $rSd.Data -Note 'Raw security defaults policy' }
    else { Set-DatasetStatus -Name 'security-defaults-json' -Status $rSd.Status -Note $rSd.Note }

    # ---- 4. Drift against a baseline snapshot ----
    $drift = @{}   # dataset name -> rows (only when compared)
    $driftNames = @('ca-policy-drift', 'named-location-drift', 'authentication-strength-drift', 'auth-methods-drift')
    if (-not $BaselineRunFolder) {
        foreach ($n in $driftNames) { Set-DatasetStatus -Name $n -Status 'Deferred' -Note 'No -BaselineRunFolder given: this run is a baseline only' }
    }
    else {
        $base = [pscustomobject]@{ Ok = $false; Folder = ''; Manifest = $null; Status = $null; Note = '' }
        try {
            $resolved = Resolve-Path -LiteralPath $BaselineRunFolder -ErrorAction Stop
            $base.Folder = $resolved.ProviderPath
            $mPath = Join-Path $base.Folder 'run-manifest.json'
            $sPath = Join-Path $base.Folder 'dataset-status.csv'
            if (-not (Test-Path -LiteralPath $mPath)) { throw 'run-manifest.json not found in the baseline folder' }
            if (-not (Test-Path -LiteralPath $sPath)) { throw 'dataset-status.csv not found in the baseline folder' }
            $base.Manifest = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $mPath -Raw)
            if ([string]$base.Manifest.Script -ne $ScriptName) { throw ("baseline run is from '{0}', not {1}" -f $base.Manifest.Script, $ScriptName) }
            $base.Status = @(Import-Csv -LiteralPath $sPath)
            if ($base.Folder -eq $script:RunFolder) { throw 'baseline folder is this run' }
            $script:ManifestExtra['BaselineRunFolder'] = $base.Folder
            $script:ManifestExtra['BaselineManifestSha256'] = (Get-FileHash -LiteralPath $mPath -Algorithm SHA256).Hash
            $script:ManifestExtra['BaselineStartedUtc'] = ConvertTo-UtcText $base.Manifest.StartedUtc
            $script:ManifestExtra['BaselineScriptVersion'] = [string]$base.Manifest.ScriptVersion
            $base.Ok = $true
            Write-RunLog ("Baseline: {0} (started {1})" -f $base.Folder, (ConvertTo-UtcText $base.Manifest.StartedUtc))
        }
        catch {
            $base.Note = "Baseline not usable ($BaselineRunFolder): $($_.Exception.Message)"
            Write-RunLog $base.Note 'WARN'
        }

        function Read-BaselineJson {
            # Reads one baseline JSON file after checking it against the SHA-256 the baseline run recorded.
            param([string]$File)
            $dsName = ($File -replace '\.json$', '') + '-json'
            $row = @($base.Status | Where-Object { $_.File -eq $File -or $_.Dataset -eq $dsName } | Select-Object -First 1)
            if (-not $row.Count) { throw "$File is not recorded in the baseline dataset-status.csv" }
            if ($row[0].Status -notin @('Completed', 'Partial')) { throw ("{0} was {1} in the baseline run: {2}" -f $File, $row[0].Status, $row[0].Note) }
            $path = Join-Path $base.Folder $File
            if (-not (Test-Path -LiteralPath $path)) { throw "$File not found in the baseline folder" }
            $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            if ($h -ne $row[0].Sha256) { throw "$File SHA-256 does not match the baseline dataset-status.csv: the file was changed after the baseline run" }
            $script:ManifestExtra["Baseline:$File"] = $h
            return (ConvertFrom-Json -InputObject (Get-Content -LiteralPath $path -Raw))
        }

        function Get-DriftInput {
            # Returns the baseline items for one comparison, or a reason it cannot be compared.
            param([string]$File, $CurrentRead, [switch]$Single)
            $res = [pscustomobject]@{ Ok = $false; Items = $null; Status = 'Blocked'; Note = '' }
            if (-not $base.Ok) { $res.Note = $base.Note; return $res }
            if (-not $CurrentRead.Ok) { $res.Status = $CurrentRead.Status; $res.Note = "Current $($CurrentRead.Note)"; return $res }
            try {
                $data = Read-BaselineJson -File $File
                $res.Items = $(if ($Single) { $data } else { [object[]]@($data | Where-Object { $null -ne $_ }) })
                $res.Ok = $true
            }
            catch { $res.Note = "Baseline $($_.Exception.Message)"; Write-RunLog $res.Note 'WARN' }
            return $res
        }
        $baseLabel = $(if ($base.Ok) { 'Compared with baseline {0} (started {1})' -f (Split-Path $base.Folder -Leaf), (ConvertTo-UtcText $base.Manifest.StartedUtc) } else { '' })

        # Policies
        $in = Get-DriftInput -File 'ca-policies.json' -CurrentRead $rPol
        if ($in.Ok) {
            $bRaw = Get-RawMap $in.Items; $cRaw = Get-RawMap $rPol.Data
            $rows = foreach ($d in (Compare-SnapshotSet -Baseline (Get-CanonicalMap $in.Items $VolatilePolicy) -Current (Get-CanonicalMap $rPol.Data $VolatilePolicy))) {
                $b = $(if ($bRaw.ContainsKey($d.Id)) { $bRaw[$d.Id] } else { $null })
                $c = $(if ($cRaw.ContainsKey($d.Id)) { $cRaw[$d.Id] } else { $null })
                [pscustomobject][ordered]@{
                    PolicyId            = $d.Id
                    PolicyName          = $(if ($c) { [string]$c.displayName } else { [string]$b.displayName })
                    ChangeType          = $d.ChangeType
                    ChangedPaths        = $d.ChangedPaths
                    BaselineState       = $(if ($b) { [string]$b.state } else { '' })
                    CurrentState        = $(if ($c) { [string]$c.state } else { '' })
                    BaselineModifiedUtc = $(if ($b) { ConvertTo-UtcText (Get-OptionalValue $b 'modifiedDateTime') } else { '' })
                    CurrentModifiedUtc  = $(if ($c) { ConvertTo-UtcText (Get-OptionalValue $c 'modifiedDateTime') } else { '' })
                }
            }
            $drift['ca-policy-drift'] = @($rows)
            Export-Dataset -Name 'ca-policy-drift' -Rows @($rows) -Note $baseLabel
        }
        else { Set-DatasetStatus -Name 'ca-policy-drift' -Status $in.Status -Note $in.Note }

        # Named locations
        $in = Get-DriftInput -File 'named-locations.json' -CurrentRead $rLoc
        if ($in.Ok) {
            $bRaw = Get-RawMap $in.Items; $cRaw = Get-RawMap $rLoc.Data
            $rows = foreach ($d in (Compare-SnapshotSet -Baseline (Get-CanonicalMap $in.Items $VolatileLocation) -Current (Get-CanonicalMap $rLoc.Data $VolatileLocation))) {
                $b = $(if ($bRaw.ContainsKey($d.Id)) { $bRaw[$d.Id] } else { $null })
                $c = $(if ($cRaw.ContainsKey($d.Id)) { $cRaw[$d.Id] } else { $null })
                $o = $(if ($c) { $c } else { $b })
                [pscustomobject][ordered]@{
                    LocationId          = $d.Id
                    LocationName        = [string]$o.displayName
                    LocationType        = ([string](Get-OptionalValue $o '@odata.type') -replace '#microsoft.graph.', '')
                    ChangeType          = $d.ChangeType
                    ChangedPaths        = $d.ChangedPaths
                    BaselineIsTrusted   = $(if ($b) { Get-OptionalValue $b 'isTrusted' } else { '' })
                    CurrentIsTrusted    = $(if ($c) { Get-OptionalValue $c 'isTrusted' } else { '' })
                    BaselineModifiedUtc = $(if ($b) { ConvertTo-UtcText (Get-OptionalValue $b 'modifiedDateTime') } else { '' })
                    CurrentModifiedUtc  = $(if ($c) { ConvertTo-UtcText (Get-OptionalValue $c 'modifiedDateTime') } else { '' })
                }
            }
            $drift['named-location-drift'] = @($rows)
            Export-Dataset -Name 'named-location-drift' -Rows @($rows) -Note $baseLabel
        }
        else { Set-DatasetStatus -Name 'named-location-drift' -Status $in.Status -Note $in.Note }

        # Authentication strengths
        $in = Get-DriftInput -File 'authentication-strengths.json' -CurrentRead $rStr
        if ($in.Ok) {
            $bRaw = Get-RawMap $in.Items; $cRaw = Get-RawMap $rStr.Data
            $rows = foreach ($d in (Compare-SnapshotSet -Baseline (Get-CanonicalMap $in.Items $VolatileStrength) -Current (Get-CanonicalMap $rStr.Data $VolatileStrength))) {
                $b = $(if ($bRaw.ContainsKey($d.Id)) { $bRaw[$d.Id] } else { $null })
                $c = $(if ($cRaw.ContainsKey($d.Id)) { $cRaw[$d.Id] } else { $null })
                $o = $(if ($c) { $c } else { $b })
                [pscustomobject][ordered]@{
                    StrengthId          = $d.Id
                    StrengthName        = [string]$o.displayName
                    PolicyType          = [string](Get-OptionalValue $o 'policyType')
                    ChangeType          = $d.ChangeType
                    ChangedPaths        = $d.ChangedPaths
                    BaselineModifiedUtc = $(if ($b) { ConvertTo-UtcText (Get-OptionalValue $b 'modifiedDateTime') } else { '' })
                    CurrentModifiedUtc  = $(if ($c) { ConvertTo-UtcText (Get-OptionalValue $c 'modifiedDateTime') } else { '' })
                }
            }
            $drift['authentication-strength-drift'] = @($rows)
            Export-Dataset -Name 'authentication-strength-drift' -Rows @($rows) -Note $baseLabel
        }
        else { Set-DatasetStatus -Name 'authentication-strength-drift' -Status $in.Status -Note $in.Note }

        # Authentication methods policy (one row per method configuration, plus the policy itself) and security defaults
        $amRows = [System.Collections.Generic.List[object]]::new()
        $amProblems = [System.Collections.Generic.List[string]]::new()
        $inAm = Get-DriftInput -File 'authentication-methods-policy.json' -CurrentRead $rAmp -Single
        if ($inAm.Ok) {
            $bCfg = @(Get-OptionalValue $inAm.Items 'authenticationMethodConfigurations' | Where-Object { $null -ne $_ })
            $cCfg = @(Get-OptionalValue $rAmp.Data 'authenticationMethodConfigurations' | Where-Object { $null -ne $_ })
            $bTop = ConvertTo-SortedValue -Value $inAm.Items -Canonical -Exclude (@($VolatileMethods) + 'authenticationMethodConfigurations')
            $cTop = ConvertTo-SortedValue -Value $rAmp.Data -Canonical -Exclude (@($VolatileMethods) + 'authenticationMethodConfigurations')
            $paths = @(Get-ChangedPath -Baseline $bTop -Current $cTop)
            $amRows.Add([pscustomobject][ordered]@{ Item = 'authenticationMethodsPolicy'; ChangeType = $(if ($paths.Count) { 'Changed' } else { 'Unchanged' }); ChangedPaths = ($paths -join '; '); BaselineState = [string](Get-OptionalValue $inAm.Items 'policyMigrationState'); CurrentState = [string](Get-OptionalValue $rAmp.Data 'policyMigrationState') })
            $bRaw = Get-RawMap $bCfg; $cRaw = Get-RawMap $cCfg
            foreach ($d in (Compare-SnapshotSet -Baseline (Get-CanonicalMap $bCfg @()) -Current (Get-CanonicalMap $cCfg @()))) {
                $amRows.Add([pscustomobject][ordered]@{
                    Item          = "method:$($d.Id)"
                    ChangeType    = $d.ChangeType
                    ChangedPaths  = $d.ChangedPaths
                    BaselineState = $(if ($bRaw.ContainsKey($d.Id)) { [string]$bRaw[$d.Id].state } else { '' })
                    CurrentState  = $(if ($cRaw.ContainsKey($d.Id)) { [string]$cRaw[$d.Id].state } else { '' })
                })
            }
        }
        else { $amProblems.Add("authentication methods policy: $($inAm.Note)") }
        $inSd = Get-DriftInput -File 'security-defaults.json' -CurrentRead $rSd -Single
        if ($inSd.Ok) {
            $paths = @(Get-ChangedPath -Baseline (ConvertTo-SortedValue -Value $inSd.Items -Canonical) -Current (ConvertTo-SortedValue -Value $rSd.Data -Canonical))
            $amRows.Add([pscustomobject][ordered]@{ Item = 'securityDefaults'; ChangeType = $(if ($paths.Count) { 'Changed' } else { 'Unchanged' }); ChangedPaths = ($paths -join '; '); BaselineState = $(if ($inSd.Items.isEnabled) { 'enabled' } else { 'disabled' }); CurrentState = $(if ($rSd.Data.isEnabled) { 'enabled' } else { 'disabled' }) })
        }
        else { $amProblems.Add("security defaults: $($inSd.Note)") }
        if ($amRows.Count) {
            $drift['auth-methods-drift'] = @($amRows)
            Export-Dataset -Name 'auth-methods-drift' -Rows $amRows.ToArray() -Status $(if ($amProblems.Count) { 'Partial' } else { 'Completed' }) -Note ((@($baseLabel) + @($amProblems) | Where-Object { $_ }) -join '; ')
        }
        else { Set-DatasetStatus -Name 'auth-methods-drift' -Status $(if ($inAm.Status -eq 'EvidenceUnavailable') { 'EvidenceUnavailable' } else { 'Blocked' }) -Note ($amProblems -join '; ') }
    }

    # ---- 5. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    function Get-CountOrBlank { param($Read, [scriptblock]$Filter) if (-not $Read.Ok) { return '' } return @($Read.Data | Where-Object $Filter).Count }
    $polNote = $(if ($rPol.Ok) { '' } else { "$($rPol.Status): $($rPol.Note)" })
    Add-Metric 'Conditional Access policies' (Get-CountOrBlank $rPol { $true }) -Note $polNote
    Add-Metric 'Policies enabled' (Get-CountOrBlank $rPol { $_.state -eq 'enabled' }) -Note $polNote
    Add-Metric 'Policies in report-only' (Get-CountOrBlank $rPol { $_.state -eq 'enabledForReportingButNotEnforced' }) -Note $polNote
    Add-Metric 'Policies disabled' (Get-CountOrBlank $rPol { $_.state -eq 'disabled' }) -Note $polNote
    $locNote = $(if ($rLoc.Ok) { '' } else { "$($rLoc.Status): $($rLoc.Note)" })
    Add-Metric 'Named locations' (Get-CountOrBlank $rLoc { $true }) -Note $locNote
    Add-Metric 'Trusted named locations' (Get-CountOrBlank $rLoc { (Get-OptionalValue $_ 'isTrusted') -eq $true }) -Note $locNote
    $strNote = $(if ($rStr.Ok) { '' } else { "$($rStr.Status): $($rStr.Note)" })
    Add-Metric 'Authentication strengths (custom)' (Get-CountOrBlank $rStr { "$(Get-OptionalValue $_ 'policyType')" -eq 'custom' }) -Note $strNote
    Add-Metric 'Authentication strengths (built-in)' (Get-CountOrBlank $rStr { "$(Get-OptionalValue $_ 'policyType')" -eq 'builtIn' }) -Note $strNote
    $enabledMethods = $(if ($rAmp.Ok) { @(@(Get-OptionalValue $rAmp.Data 'authenticationMethodConfigurations') | Where-Object { $_ -and "$($_.state)" -eq 'enabled' } | ForEach-Object { [string]$_.id } | Sort-Object) } else { @() })
    Add-Metric 'Authentication methods enabled' $(if ($rAmp.Ok) { $enabledMethods.Count } else { '' }) -Note $(if ($rAmp.Ok) { Join-Values $enabledMethods } else { "$($rAmp.Status): $($rAmp.Note)" })
    Add-Metric 'Security defaults enabled' $(if ($rSd.Ok) { [bool]$rSd.Data.isEnabled } else { '' }) -Note $(if ($rSd.Ok) { '' } else { "$($rSd.Status): $($rSd.Note)" })

    if (-not $BaselineRunFolder) {
        Add-Metric 'Baseline run' '' -Note 'No -BaselineRunFolder: this run is a baseline only'
    }
    else {
        Add-Metric 'Baseline run' $(if ($base.Ok) { Split-Path $base.Folder -Leaf } else { '' }) -Note $(if ($base.Ok) { "Started $(ConvertTo-UtcText $base.Manifest.StartedUtc)" } else { $base.Note })
        $pd = $(if ($drift.ContainsKey('ca-policy-drift')) { $drift['ca-policy-drift'] } else { $null })
        $pdNote = $(if ($pd) { '' } else { 'Policy drift not compared; see dataset-status.csv' })
        foreach ($t in 'Added', 'Removed', 'Changed', 'Unchanged') {
            Add-Metric ("Policies {0} vs baseline" -f $t.ToLowerInvariant()) $(if ($null -ne $pd) { @($pd | Where-Object ChangeType -eq $t).Count } else { '' }) -Note $pdNote
        }
        Add-Metric 'Policies whose state changed vs baseline' $(if ($null -ne $pd) { @($pd | Where-Object { $_.ChangeType -eq 'Changed' -and $_.BaselineState -ne $_.CurrentState }).Count } else { '' }) -Note $pdNote
        foreach ($pair in @(@('named-location-drift', 'Named locations added, removed or changed vs baseline'), @('authentication-strength-drift', 'Authentication strengths added, removed or changed vs baseline'), @('auth-methods-drift', 'Authentication method settings added, removed or changed vs baseline'))) {
            $dr = $(if ($drift.ContainsKey($pair[0])) { $drift[$pair[0]] } else { $null })
            Add-Metric $pair[1] $(if ($null -ne $dr) { @($dr | Where-Object ChangeType -ne 'Unchanged').Count } else { '' }) -Note $(if ($null -ne $dr) { '' } else { "$($pair[0]) not compared; see dataset-status.csv" })
        }
        $allCompared = (@($driftNames | Where-Object { -not $drift.ContainsKey($_) }).Count -eq 0) -and -not @($script:Datasets | Where-Object { $_.Dataset -eq 'auth-methods-drift' -and $_.Status -ne 'Completed' }).Count
        $anyDrift = [bool](@($drift.Values | ForEach-Object { $_ } | Where-Object { $_.ChangeType -ne 'Unchanged' }).Count)
        Add-Metric 'Configuration identical to baseline' $(if ($anyDrift) { $false } elseif ($allCompared) { $true } else { '' }) -Note $(if (-not $anyDrift -and -not $allCompared) { 'Not every part could be compared; see dataset-status.csv' } else { 'Policies, named locations, authentication strengths, authentication methods and security defaults; volatile fields ignored' })
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ BaselineRunFolder = $BaselineRunFolder; ResolveNames = $ResolveNames }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
