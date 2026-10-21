<#
.SYNOPSIS
    Read-only Conditional Access impact analysis from sign-in logs: for every policy, what it did
    (or, in report-only mode, would have done) to real sign-ins.

.DESCRIPTION
    Before a report-only Conditional Access policy is switched on, you need to know who it would
    block or challenge. Entra records that for every sign-in: each sign-in carries the result of
    every policy, including report-only policies ("reportOnlyFailure" = would have blocked,
    "reportOnlyInterrupted" = would have required an extra step such as MFA).

    This script reads the policies and the sign-in logs for a lookback window and reports:

      - per policy: state, sign-ins evaluated, and counts for every result
        (success / failure / notApplied / reportOnlySuccess / reportOnlyFailure /
        reportOnlyInterrupted / reportOnlyNotApplied), distinct users that would be blocked or
        interrupted, and the top applications involved
      - per policy, user and app: every report-only "would block" or "would interrupt" outcome,
        with count, client app and last seen (the list to work through before enforcing)
      - enabled policies that blocked sign-ins (what enforcement is already stopping)

    Report-only results are only returned when the request sends
    "Prefer: include-unknown-enum-members" (Microsoft Graph appliedConditionalAccessPolicy); the
    script always sends it. Conditional Access results are only included in sign-in logs for
    callers who can read Conditional Access (Policy.Read.All, or Global Reader / Security Reader).

    Interactive sign-ins are read from v1.0. -IncludeNonInteractive adds non-interactive sign-ins
    from the beta endpoint (signInEventTypes filter), which is much larger and is not a supported
    production API.

    READ-ONLY. Every Graph call is an HTTP GET.

    Output: <OutputRoot>\24-CaReportOnlyImpact\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER SignInLookbackDays
    Days of sign-in logs to read (1-30). Report-only decisions usually want 14-30 days.

.PARAMETER MaxSignInRecords
    Safety cap per sign-in query; output is marked TRUNCATED if reached.

.PARAMETER ReportOnlyPoliciesOnly
    Only keep results for policies in report-only state.

.PARAMETER IncludeNonInteractive
    Also read non-interactive sign-ins (beta endpoint; large).

.EXAMPLE
    .\24-Get-CaReportOnlyImpact.ps1 -SignInLookbackDays 14
.EXAMPLE
    .\24-Get-CaReportOnlyImpact.ps1 -SignInLookbackDays 30 -MaxSignInRecords 300000 -ReportOnlyPoliciesOnly

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication.
    Scopes  : Policy.Read.All, AuditLog.Read.All. Role: Global Reader or Security Reader.
    Licence : sign-in logs need Entra ID P1.
    Sources : Microsoft Graph appliedConditionalAccessPolicy resource and List signIns (v1.0, beta).
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
    [int]$SignInLookbackDays = 14,
    [int]$MaxSignInRecords = 100000,
    [switch]$ReportOnlyPoliciesOnly,
    [switch]$IncludeNonInteractive,
    [ValidateRange(1, 20)]
    [int]$TopAppCount = 5
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '24-CaReportOnlyImpact'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('Policy.Read.All', 'AuditLog.Read.All')

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

# Report-only results are an evolvable enum: Graph only returns them with this header.
$EnumHeader = @{ Prefer = 'include-unknown-enum-members' }
$ResultNames = @('success', 'failure', 'notApplied', 'notEnabled', 'reportOnlySuccess', 'reportOnlyFailure', 'reportOnlyInterrupted', 'reportOnlyNotApplied', 'unknown')

function Get-SignInPage {
    # Pages sign-ins with the enum header (Invoke-GraphGetAll does not take headers).
    param([string]$Uri, [int]$MaxRecords, [string]$Label)
    $out = [System.Collections.Generic.List[object]]::new()
    $next = $Uri; $truncated = $false
    while ($next) {
        $resp = Invoke-GraphGet -Uri $next -Headers $EnumHeader
        foreach ($item in @($resp.value)) { if ($null -ne $item) { $out.Add($item) } }
        if ($MaxRecords -gt 0 -and $out.Count -ge $MaxRecords) { $truncated = $true; Write-RunLog ("{0}: stopped at {1} records; TRUNCATED" -f $Label, $MaxRecords) 'WARN'; break }
        $next = $null
        if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $next = $resp.'@odata.nextLink' }
        if ($out.Count -and ($out.Count % 10000) -lt 1000) { Write-RunLog ("{0}: {1} read so far" -f $Label, $out.Count) }
    }
    return [pscustomobject]@{ Items = $out; Truncated = $truncated }
}

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- 1. Policies ----
    $policies = @{}
    try {
        foreach ($p in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'policies')) { $policies[[string]$p.id] = $p }
        Write-RunLog ("{0} Conditional Access policies; {1} in report-only" -f $policies.Count, @($policies.Values | Where-Object state -eq 'enabledForReportingButNotEnforced').Count)
    }
    catch {
        Set-DatasetStatus -Name 'ca-policy-results' -Status (Get-FailureStatus $_) -Note "Policies not readable: $($_.Exception.Message)"
        throw
    }

    # ---- 2. Sign-ins ----
    $since = (Get-Date).ToUniversalTime().AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $signIns = [System.Collections.Generic.List[object]]::new()
    $truncatedAny = $false; $signInStatus = 'Completed'; $signInNote = ''
    try {
        $uri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString("createdDateTime ge $since")
        $r = Get-SignInPage -Uri $uri -MaxRecords $MaxSignInRecords -Label 'interactive sign-ins'
        foreach ($s in $r.Items) { $s | Add-Member -NotePropertyName '_type' -NotePropertyValue 'interactive' -Force; $signIns.Add($s) }
        $truncatedAny = $r.Truncated
        if ($IncludeNonInteractive) {
            $f = "createdDateTime ge $since and signInEventTypes/any(t: t eq 'nonInteractiveUser')"
            $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString($f)
            $r = Get-SignInPage -Uri $uri -MaxRecords $MaxSignInRecords -Label 'non-interactive sign-ins'
            foreach ($s in $r.Items) { $s | Add-Member -NotePropertyName '_type' -NotePropertyValue 'nonInteractive' -Force; $signIns.Add($s) }
            $truncatedAny = $truncatedAny -or $r.Truncated
        }
        Write-RunLog ("{0} sign-ins read (since {1})" -f $signIns.Count, $since)
    }
    catch {
        $signInStatus = Get-FailureStatus $_
        $signInNote = "Sign-in logs not readable: $($_.Exception.Message)"
        Write-RunLog $signInNote 'WARN'
    }

    $withCa = @($signIns | Where-Object { $_.PSObject.Properties.Name -contains 'appliedConditionalAccessPolicies' -and @($_.appliedConditionalAccessPolicies).Count -gt 0 }).Count
    if ($signIns.Count -and -not $withCa) {
        Write-RunLog 'No sign-in carried Conditional Access results: the account probably cannot read Conditional Access (needs Policy.Read.All or Global Reader / Security Reader).' 'WARN'
        $signInNote = ($signInNote + ' No Conditional Access results in the sign-ins returned: check the run account can read Conditional Access.').Trim()
    }

    # ---- 3. Aggregate ----
    $agg = @{}        # policyId -> counters
    $impact = @{}     # policyId|user|app|result -> row
    foreach ($s in $signIns) {
        $upn = [string]$s.userPrincipalName; $app = [string]$s.appDisplayName
        foreach ($ap in @($s.appliedConditionalAccessPolicies)) {
            if ($null -eq $ap) { continue }
            $pid_ = [string]$ap.id
            $state = if ($policies.ContainsKey($pid_)) { [string]$policies[$pid_].state } else { '' }
            if ($ReportOnlyPoliciesOnly -and $state -ne 'enabledForReportingButNotEnforced') { continue }
            if (-not $agg.ContainsKey($pid_)) {
                $c = [ordered]@{}; foreach ($n in $ResultNames) { $c[$n] = 0 }
                $agg[$pid_] = [pscustomobject]@{ Name = [string]$ap.displayName; Counts = $c; Evaluated = 0
                    BlockUsers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    InterruptUsers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    FailUsers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    Apps = @{} }
            }
            $a = $agg[$pid_]
            $res = [string]$ap.result
            if (-not $a.Counts.Contains($res)) { $res = 'unknown' }
            $a.Counts[$res]++
            $a.Evaluated++
            if ($res -in 'reportOnlyFailure', 'reportOnlyInterrupted', 'failure') {
                if ($res -eq 'reportOnlyFailure') { [void]$a.BlockUsers.Add($upn) }
                elseif ($res -eq 'reportOnlyInterrupted') { [void]$a.InterruptUsers.Add($upn) }
                else { [void]$a.FailUsers.Add($upn) }
                if (-not $a.Apps.ContainsKey($app)) { $a.Apps[$app] = 0 }
                $a.Apps[$app]++
                $key = "$pid_|$upn|$app|$res"
                if (-not $impact.ContainsKey($key)) {
                    $impact[$key] = [pscustomobject][ordered]@{
                        PolicyName = $a.Name; PolicyState = $state; Result = $res
                        Meaning = $(switch ($res) { 'reportOnlyFailure' { 'Would be blocked if enforced' } 'reportOnlyInterrupted' { 'Would need an extra step (e.g. MFA) if enforced' } default { 'Blocked by the enforced policy' } })
                        UserPrincipalName = $upn; AppDisplayName = $app; ClientAppUsed = [string]$s.clientAppUsed; SignInType = [string]$s._type
                        SignIns = 0; FirstSeenUtc = $null; LastSeenUtc = $null; PolicyId = $pid_
                    }
                }
                $row = $impact[$key]; $row.SignIns++
                $t = $null; try { $t = ([datetime]$s.createdDateTime).ToUniversalTime() } catch { }
                if ($t) { if (-not $row.FirstSeenUtc -or $t -lt $row.FirstSeenUtc) { $row.FirstSeenUtc = $t }; if (-not $row.LastSeenUtc -or $t -gt $row.LastSeenUtc) { $row.LastSeenUtc = $t } }
            }
        }
    }

    # ---- 4. Datasets ----
    $policyRows = foreach ($p in ($policies.Values | Sort-Object displayName)) {
        $id = [string]$p.id
        if ($ReportOnlyPoliciesOnly -and $p.state -ne 'enabledForReportingButNotEnforced') { continue }
        $a = if ($agg.ContainsKey($id)) { $agg[$id] } else { $null }
        $row = [ordered]@{ PolicyName = [string]$p.displayName; State = [string]$p.state; SignInsEvaluated = $(if ($a) { $a.Evaluated } else { 0 }) }
        foreach ($n in $ResultNames) { $row[$n] = $(if ($a) { $a.Counts[$n] } else { 0 }) }
        $row['UsersWouldBeBlocked']     = $(if ($a) { $a.BlockUsers.Count } else { 0 })
        $row['UsersWouldBeInterrupted'] = $(if ($a) { $a.InterruptUsers.Count } else { 0 })
        $row['UsersBlocked']            = $(if ($a) { $a.FailUsers.Count } else { 0 })
        $row['TopAppsAffected'] = $(if ($a -and $a.Apps.Count) { (($a.Apps.GetEnumerator() | Sort-Object -Property @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key'; Descending = $false } | Select-Object -First $TopAppCount | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value }) -join '; ') } else { '' })
        $row['Flags'] = (@(
                $(if ($p.state -eq 'enabledForReportingButNotEnforced' -and $a -and ($a.BlockUsers.Count -or $a.InterruptUsers.Count)) { 'ReportOnlyWouldImpactUsers' })
                $(if ($p.state -eq 'enabledForReportingButNotEnforced' -and (-not $a -or $a.Evaluated -eq 0)) { 'ReportOnlyNoSignInsEvaluated' })
                $(if ($p.state -eq 'enabled' -and $a -and $a.Counts['failure']) { 'EnforcedBlocking' })
            ) | Where-Object { $_ }) -join '; '
        $row['PolicyId'] = $id
        [pscustomobject]$row
    }
    # Policies seen in sign-ins but no longer in the policy list (deleted since, or not readable)
    $gone = @($agg.Keys | Where-Object { -not $policies.ContainsKey($_) })
    $policyRows = @($policyRows) + @(foreach ($id in ($gone | Sort-Object)) {
        $a = $agg[$id]
        $row = [ordered]@{ PolicyName = $a.Name; State = 'deleted or not readable'; SignInsEvaluated = $a.Evaluated }
        foreach ($n in $ResultNames) { $row[$n] = $a.Counts[$n] }
        $row['UsersWouldBeBlocked'] = $a.BlockUsers.Count; $row['UsersWouldBeInterrupted'] = $a.InterruptUsers.Count; $row['UsersBlocked'] = $a.FailUsers.Count
        $row['TopAppsAffected'] = (($a.Apps.GetEnumerator() | Sort-Object -Property @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key'; Descending = $false } | Select-Object -First $TopAppCount | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value }) -join '; ')
        $row['Flags'] = 'PolicyNotInCurrentList'; $row['PolicyId'] = $id
        [pscustomobject]$row
    })
    $note = "Sign-ins since $since"
    if ($truncatedAny) { $note += "; TRUNCATED at $MaxSignInRecords per query - shorten the lookback or raise -MaxSignInRecords" }
    if ($IncludeNonInteractive) { $note += '; includes non-interactive (beta)' }
    if ($signInStatus -ne 'Completed') {
        Export-Dataset -Name 'ca-policy-results' -Rows @($policyRows) -Note ($signInNote + ' Policy list only; no results.')
        Set-DatasetStatus -Name 'ca-reportonly-impact' -Status $signInStatus -Note $signInNote
    }
    else {
        Export-Dataset -Name 'ca-policy-results' -Rows @($policyRows) -Note ($note + $(if ($signInNote) { "; $signInNote" } else { '' }))
        $impactRows = @($impact.Values | Sort-Object PolicyName, Result, @{ Expression = 'SignIns'; Descending = $true }, UserPrincipalName)
        Export-Dataset -Name 'ca-reportonly-impact' -Rows $impactRows -Note 'One row per policy, user, app and result: report-only would-block / would-interrupt, and enforced blocks'
    }

    # ---- 5. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $ro = @($policies.Values | Where-Object state -eq 'enabledForReportingButNotEnforced')
    $roIds = @($ro | ForEach-Object { [string]$_.id })
    $blockAll = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $intAll = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $roIds) { if ($agg.ContainsKey($id)) { foreach ($u in $agg[$id].BlockUsers) { [void]$blockAll.Add($u) }; foreach ($u in $agg[$id].InterruptUsers) { [void]$intAll.Add($u) } } }
    Add-Metric 'Conditional Access policies' $policies.Count
    Add-Metric 'Policies in report-only' $ro.Count
    Add-Metric 'Policies enabled' @($policies.Values | Where-Object state -eq 'enabled').Count
    Add-Metric 'Policies disabled' @($policies.Values | Where-Object state -eq 'disabled').Count
    Add-Metric 'Sign-ins read' $signIns.Count $note
    Add-Metric 'Sign-ins carrying Conditional Access results' $withCa
    Add-Metric 'Report-only policies that would block or interrupt someone' @($roIds | Where-Object { $agg.ContainsKey($_) -and ($agg[$_].BlockUsers.Count -or $agg[$_].InterruptUsers.Count) }).Count
    Add-Metric 'Report-only policies with no sign-ins evaluated' @($roIds | Where-Object { -not $agg.ContainsKey($_) -or $agg[$_].Evaluated -eq 0 }).Count 'Conditions never matched in the window, or nobody signed in to the targeted apps'
    Add-Metric 'Users a report-only policy would block' $blockAll.Count 'Distinct users across all report-only policies'
    Add-Metric 'Users a report-only policy would interrupt' $intAll.Count 'Would need an extra step, such as MFA'
    Add-Metric 'Enabled policies that blocked sign-ins' @($policies.Values | Where-Object { $_.state -eq 'enabled' -and $agg.ContainsKey([string]$_.id) -and $agg[[string]$_.id].Counts['failure'] }).Count
    Add-Metric 'Sign-in data truncated' $truncatedAny
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ SignInLookbackDays = $SignInLookbackDays; MaxSignInRecords = $MaxSignInRecords; ReportOnlyPoliciesOnly = [bool]$ReportOnlyPoliciesOnly; IncludeNonInteractive = [bool]$IncludeNonInteractive; TopAppCount = $TopAppCount }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
