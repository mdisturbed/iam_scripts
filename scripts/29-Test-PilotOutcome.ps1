<#
.SYNOPSIS
    Read-only pilot test evidence: did each pilot test case produce the result it should, proven by sign-ins.

.DESCRIPTION
    Answers: did each pilot test case (expected and adverse) produce the result it should, and is
    there sign-in evidence to prove it?

    Use it after a Conditional Access or MFA change has been piloted, and again after a rollback.
    You list the test cases in a CSV file: who signs in, to which app, which policy, what that
    policy should do (for example success for a pilot user, notApplied for someone outside the
    pilot, failure for a blocked legacy client), and whether the sign-in should succeed.

    For every test user the script reads that user's sign-ins since the earliest NotBeforeUtc of
    their cases (or the -LookbackHours window), then for each case:
      - finds the sign-ins for the same user, the same app (display name or appId, or '*' for any)
        and created at or after NotBeforeUtc
      - takes the LATEST of them (or, with -EvaluateAll, every one of them)
      - reads the policy's result on that sign-in (by PolicyId, else PolicyName) and the sign-in
        outcome (error code 0 = Success, anything else = Failure)
      - reports Pass, Fail, NoEvidence (no matching sign-in) or Blocked (the evidence could not be
        read), with the sign-in's time, correlation ID and request ID as proof

    A policy that does not appear in the sign-in's Conditional Access results is reported as
    'notInSignIn'; it counts as notApplied when the case expects notApplied.

    Optional checks:
      - -PilotGroupId: reads the pilot group's members (transitive) and checks each test user's
        membership against the InPilotExpected column of the test-case file
      - -CheckScopeLeak: reads every interactive sign-in in the window and lists users outside the
        pilot group on whom a pilot policy was enforced (result success or failure)

    Report-only results are only returned when the request sends
    "Prefer: include-unknown-enum-members"; the script always sends it. Conditional Access results
    are only included in sign-in logs for callers who can read Conditional Access. When none of the
    sign-ins read carry them, policy checks are Blocked, not failed.

    Interactive sign-ins are read from v1.0. -IncludeNonInteractive adds non-interactive sign-ins
    from the beta endpoint (signInEventTypes filter), which is not a supported production API.
    No IP address, location or device details are written.

    READ-ONLY. Every Graph call is an HTTP GET.

    Output: <OutputRoot>\29-PilotOutcome\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER TestCaseCsv
    The test-case file (template: examples/pilot-test-cases.example.csv). Columns: TestId,
    CaseType (Expected | Adverse), Description, UserPrincipalName, App, PolicyId, PolicyName,
    ExpectedPolicyResult, ExpectedSignIn (Success | Failure | Any), NotBeforeUtc, and optional
    InPilotExpected (True | False | blank).

.PARAMETER LookbackHours
    Sign-ins read for a case with no NotBeforeUtc start this many hours before the run (1-720).

.PARAMETER MaxSignInsPerUser
    Safety cap on sign-ins read per test user; the case note says TRUNCATED if reached.

.PARAMETER IncludeNonInteractive
    Also read the test users' non-interactive sign-ins (beta endpoint).

.PARAMETER EvaluateAll
    A case passes only when every matching sign-in meets the expectation (default: the latest one).

.PARAMETER PilotGroupId
    Object ID of the pilot group. Adds pilot-scope-check.csv.

.PARAMETER PolicyIds
    Pilot policies checked by -CheckScopeLeak. Default: the PolicyId values in the test-case file.

.PARAMETER CheckScopeLeak
    Read every interactive sign-in in the -LookbackHours window and list users outside the pilot
    group on whom a pilot policy was enforced. Needs -PilotGroupId.

.PARAMETER MaxSignInRecords
    Safety cap for the -CheckScopeLeak read; output is marked TRUNCATED if reached.

.EXAMPLE
    .\29-Test-PilotOutcome.ps1 -TestCaseCsv .\pilot-test-cases.csv
.EXAMPLE
    .\29-Test-PilotOutcome.ps1 -TestCaseCsv .\pilot-test-cases.csv -PilotGroupId 00000000-0000-0000-0000-000000000000 -CheckScopeLeak -LookbackHours 48
.EXAMPLE
    .\29-Test-PilotOutcome.ps1 -TestCaseCsv .\rollback-test-cases.csv -EvaluateAll

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication.
    Scopes  : AuditLog.Read.All, Policy.Read.All, Directory.Read.All; GroupMember.Read.All for the
              pilot group. Role: Global Reader or Security Reader (and Reports Reader for sign-ins).
    Licence : sign-in logs need Entra ID P1.
    Sources : Microsoft Graph List signIns and appliedConditionalAccessPolicy (v1.0, beta),
              group transitiveMembers, conditionalAccessPolicy (v1.0).
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

    [Parameter(Mandatory)]
    [string]$TestCaseCsv,
    [ValidateRange(1, 720)]
    [int]$LookbackHours = 72,
    [int]$MaxSignInsPerUser = 5000,
    [switch]$IncludeNonInteractive,
    [switch]$EvaluateAll,
    [string]$PilotGroupId = '',
    [string[]]$PolicyIds = @(),
    [switch]$CheckScopeLeak,
    [int]$MaxSignInRecords = 100000
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '29-PilotOutcome'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('AuditLog.Read.All', 'Policy.Read.All', 'Directory.Read.All')
if ($PilotGroupId) { $RequiredScopes += 'GroupMember.Read.All' }


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

# Report-only results are an evolvable enum: Graph only returns them with this header.
$EnumHeader = @{ Prefer = 'include-unknown-enum-members' }
$PolicyResultValues = @('success', 'failure', 'notApplied', 'notEnabled', 'reportOnlySuccess', 'reportOnlyFailure', 'reportOnlyInterrupted', 'reportOnlyNotApplied')
$SignInExpectations = @('Success', 'Failure', 'Any')
# Results that mean an enforced policy actually applied to the sign-in.
$EnforcedResults = @('success', 'failure')
$TestCaseColumns = @('TestId', 'CaseType', 'Description', 'UserPrincipalName', 'App', 'PolicyId', 'PolicyName', 'ExpectedPolicyResult', 'ExpectedSignIn', 'NotBeforeUtc')

function ConvertTo-SlimSignIn {
    # Keeps only the fields this script uses. List signIns does not document $select, so the full
    # record is returned by Graph and reduced here, page by page. IP address, location and device
    # details are dropped on purpose: they are not needed as evidence.
    param($SignIn, [string]$Type)
    $props = $SignIn.PSObject.Properties.Name
    $ca = @()
    if ($props -contains 'appliedConditionalAccessPolicies') {
        $ca = @(foreach ($ap in @($SignIn.appliedConditionalAccessPolicies)) { if ($null -ne $ap) { [pscustomobject]@{ id = [string]$ap.id; displayName = [string]$ap.displayName; result = [string]$ap.result } } })
    }
    $status = Get-OptionalValue $SignIn 'status'
    $t = $null; try { $t = ([datetime]$SignIn.createdDateTime).ToUniversalTime() } catch { }
    [pscustomobject]@{
        createdDateTime           = $SignIn.createdDateTime
        CreatedUtc                = $t
        userPrincipalName         = [string]$SignIn.userPrincipalName
        userId                    = [string]$SignIn.userId
        appDisplayName            = [string]$SignIn.appDisplayName
        appId                     = [string]$SignIn.appId
        clientAppUsed             = [string](Get-OptionalValue $SignIn 'clientAppUsed')
        errorCode                 = $(if ($status -and $null -ne (Get-OptionalValue $status 'errorCode')) { [int]$status.errorCode } else { $null })
        failureReason             = $(if ($status) { [string](Get-OptionalValue $status 'failureReason') } else { '' })
        conditionalAccessStatus   = [string](Get-OptionalValue $SignIn 'conditionalAccessStatus')
        authenticationRequirement = [string](Get-OptionalValue $SignIn 'authenticationRequirement')
        correlationId             = [string](Get-OptionalValue $SignIn 'correlationId')
        requestId                 = [string](Get-OptionalValue $SignIn 'id')
        HasCaProperty             = ($props -contains 'appliedConditionalAccessPolicies')
        appliedConditionalAccessPolicies = $ca
        _type                     = $Type
    }
}

function Get-SignInPage {
    # Pages sign-ins with the enum header (Invoke-GraphGetAll does not take headers).
    # Returns the slimmed items, whether the cap was hit, and the earliest / latest createdDateTime read.
    param([string]$Uri, [int]$MaxRecords, [string]$Label, [string]$Type)
    $out = [System.Collections.Generic.List[object]]::new()
    $next = $Uri; $truncated = $false
    $earliest = $null; $latest = $null
    while ($next) {
        $resp = Invoke-GraphGet -Uri $next -Headers $EnumHeader
        foreach ($item in @($resp.value)) {
            if ($null -eq $item) { continue }
            $slim = ConvertTo-SlimSignIn -SignIn $item -Type $Type
            $out.Add($slim)
            $t = $slim.CreatedUtc
            if ($t) { if (-not $earliest -or $t -lt $earliest) { $earliest = $t }; if (-not $latest -or $t -gt $latest) { $latest = $t } }
        }
        if ($MaxRecords -gt 0 -and $out.Count -ge $MaxRecords) { $truncated = $true; Write-RunLog ("{0}: stopped at {1} records; TRUNCATED (earliest read {2})" -f $Label, $MaxRecords, $(if ($earliest) { $earliest.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'n/a' })) 'WARN'; break }
        $next = $null
        if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $next = $resp.'@odata.nextLink' }
        if ($out.Count -and ($out.Count % 10000) -lt 1000) { Write-RunLog ("{0}: {1} read so far" -f $Label, $out.Count) }
    }
    return [pscustomobject]@{ Items = $out; Truncated = $truncated; Earliest = $earliest; Latest = $latest; Label = $Label }
}

function ConvertFrom-UtcText {
    # 'yyyy-MM-ddTHH:mm:ssZ' (or any ISO 8601 date) -> UTC DateTime; a date without a zone is taken as UTC. $null if blank or invalid.
    param([string]$Text)
    if (-not $Text) { return $null }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($Text.Trim(), [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function Test-AppMatch {
    # Case-insensitive match on app display name or appId; '*' (or blank) matches any app.
    param($SignIn, [string]$App)
    if (-not $App -or $App -eq '*') { return $true }
    return ($SignIn.appDisplayName -ieq $App -or $SignIn.appId -ieq $App)
}

function Get-PolicyResultOnSignIn {
    # The named policy's result on one sign-in, by PolicyId (preferred) else PolicyName. 'notInSignIn' when absent.
    param($SignIn, [string]$PolicyId, [string]$PolicyName)
    $hit = $null
    if ($PolicyId) { $hit = @($SignIn.appliedConditionalAccessPolicies | Where-Object { $_.id -ieq $PolicyId } | Select-Object -First 1) }
    elseif ($PolicyName) { $hit = @($SignIn.appliedConditionalAccessPolicies | Where-Object { $_.displayName -ieq $PolicyName } | Select-Object -First 1) }
    if ($hit -and $hit.Count) { return [string]$hit[0].result }
    return 'notInSignIn'
}

function Test-SignInAgainstCase {
    # Evaluates one sign-in against one test case.
    param($SignIn, $Case)
    $observedPolicy = ''
    $policyOk = $true
    if ($Case.HasPolicy) {
        $observedPolicy = Get-PolicyResultOnSignIn -SignIn $SignIn -PolicyId $Case.PolicyId -PolicyName $Case.PolicyName
        if ($Case.ExpectedPolicyResult) {
            $policyOk = ($observedPolicy -ieq $Case.ExpectedPolicyResult) -or ($Case.ExpectedPolicyResult -ieq 'notApplied' -and $observedPolicy -eq 'notInSignIn')
        }
    }
    $observedSignIn = $(if ($null -eq $SignIn.errorCode) { 'Unknown' } elseif ($SignIn.errorCode -eq 0) { 'Success' } else { 'Failure' })
    $signInOk = ($Case.ExpectedSignIn -eq 'Any') -or ($Case.ExpectedSignIn -eq $observedSignIn)
    $reasons = @()
    if (-not $policyOk) { $reasons += ('policy result {0}, expected {1}' -f $observedPolicy, $Case.ExpectedPolicyResult) }
    if (-not $signInOk) { $reasons += ('sign-in {0}{1}, expected {2}' -f $observedSignIn, $(if ($null -ne $SignIn.errorCode) { " (errorCode $($SignIn.errorCode))" } else { '' }), $Case.ExpectedSignIn) }
    [pscustomobject]@{ Met = ($policyOk -and $signInOk); ObservedPolicy = $observedPolicy; ObservedSignIn = $observedSignIn; Reason = ($reasons -join '; ') }
}

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)

    # ---- 0. Test cases (checked before connecting, so a bad file fails fast) ----
    if (-not (Test-Path -LiteralPath $TestCaseCsv)) { throw "Test-case file not found: $TestCaseCsv" }
    $rawCases = @(Import-Csv -LiteralPath $TestCaseCsv)
    if (-not $rawCases.Count) { throw "Test-case file has no rows: $TestCaseCsv" }
    $cols = @($rawCases[0].PSObject.Properties.Name)
    $missingCols = @($TestCaseColumns | Where-Object { $cols -notcontains $_ })
    if ($missingCols.Count) { throw ("Test-case file is missing column(s): {0}. Columns found: {1}" -f ($missingCols -join ', '), ($cols -join ', ')) }
    $hasPilotCol = $cols -contains 'InPilotExpected'
    $windowStart = $script:RunStartUtc.AddHours(-$LookbackHours)
    $script:ManifestExtra = [ordered]@{
        TestCaseFile       = (Resolve-Path -LiteralPath $TestCaseCsv).ProviderPath
        TestCaseFileSha256 = (Get-FileHash -LiteralPath $TestCaseCsv -Algorithm SHA256).Hash
        WindowStartUtc     = $windowStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Evaluation         = $(if ($EvaluateAll) { 'All matching sign-ins' } else { 'Latest matching sign-in' })
    }

    $seenIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $cases = foreach ($r in $rawCases) {
        $problems = @()
        $tid = ([string]$r.TestId).Trim()
        if (-not $tid) { $problems += 'TestId is blank' }
        elseif (-not $seenIds.Add($tid)) { $problems += 'TestId is used more than once' }
        $type = ([string]$r.CaseType).Trim()
        $typeMatch = @('Expected', 'Adverse') | Where-Object { $_ -ieq $type }
        if ($typeMatch) { $type = $typeMatch } else { $problems += "CaseType '$type' is not Expected or Adverse" }
        $upn = ([string]$r.UserPrincipalName).Trim()
        if (-not $upn) { $problems += 'UserPrincipalName is blank' }
        $app = ([string]$r.App).Trim(); if (-not $app) { $app = '*' }
        $policyId = ([string]$r.PolicyId).Trim(); $policyName = ([string]$r.PolicyName).Trim()
        $epr = ([string]$r.ExpectedPolicyResult).Trim()
        if ($epr) {
            $m = $PolicyResultValues | Where-Object { $_ -ieq $epr }
            if ($m) { $epr = $m } else { $problems += "ExpectedPolicyResult '$epr' is not one of: $($PolicyResultValues -join ', ')" }
            if (-not $policyId -and -not $policyName) { $problems += 'ExpectedPolicyResult is set but PolicyId and PolicyName are both blank' }
        }
        $esi = ([string]$r.ExpectedSignIn).Trim(); if (-not $esi) { $esi = 'Any' }
        $m = $SignInExpectations | Where-Object { $_ -ieq $esi }
        if ($m) { $esi = $m } else { $problems += "ExpectedSignIn '$esi' is not Success, Failure or Any" }
        $nbText = ([string]$r.NotBeforeUtc).Trim()
        $nb = $windowStart
        if ($nbText) { $nb = ConvertFrom-UtcText $nbText; if (-not $nb) { $problems += "NotBeforeUtc '$nbText' is not a date" } }
        $inPilot = ''
        if ($hasPilotCol) {
            $ip = ([string]$r.InPilotExpected).Trim()
            if ($ip -ieq 'True') { $inPilot = 'True' } elseif ($ip -ieq 'False') { $inPilot = 'False' } elseif ($ip) { $problems += "InPilotExpected '$ip' is not True, False or blank" }
        }
        [pscustomobject]@{
            TestId = $tid; CaseType = $type; Description = [string]$r.Description; UserPrincipalName = $upn; App = $app
            PolicyId = $policyId; PolicyName = $policyName; HasPolicy = [bool]($policyId -or $policyName)
            ExpectedPolicyResult = $epr; ExpectedSignIn = $esi; NotBeforeUtc = $nb; InPilotExpected = $inPilot
            Valid = (-not $problems.Count); Problem = ($problems -join '; ')
        }
    }
    $cases = @($cases)
    Write-RunLog ("{0} test case(s) read; {1} invalid" -f $cases.Count, @($cases | Where-Object { -not $_.Valid }).Count)

    $ctx = Connect-DiscoveryGraph

    # ---- 1. Policies (names and whether each listed policy still exists) ----
    $policies = @{}
    $policyReadNote = ''
    try {
        foreach ($p in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'policies')) { $policies[[string]$p.id] = $p }
        Write-RunLog ("{0} Conditional Access policies read" -f $policies.Count)
    }
    catch {
        $policyReadNote = "Policy list not readable ($(Get-FailureStatus $_)): $($_.Exception.Message)"
        Write-RunLog $policyReadNote 'WARN'
    }
    function Get-PolicyLabel {
        param($Case)
        $name = $Case.PolicyName
        if ($Case.PolicyId -and $policies.ContainsKey($Case.PolicyId)) { $name = [string]$policies[$Case.PolicyId].displayName }
        if ($name -and $Case.PolicyId) { return '{0} ({1})' -f $name, $Case.PolicyId }
        if ($name) { return $name }
        return $Case.PolicyId
    }

    # ---- 2. Sign-ins per test user ----
    $userReads = @{}   # upn -> read result
    $allSignIns = [System.Collections.Generic.List[object]]::new()
    $readFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($g in ($cases | Where-Object { $_.Valid } | Group-Object UserPrincipalName)) {
        $upn = $g.Group[0].UserPrincipalName
        $since = ($g.Group | ForEach-Object { $_.NotBeforeUtc } | Sort-Object | Select-Object -First 1)
        $sinceText = $since.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $upnLiteral = $upn -replace "'", "''"
        $ur = [pscustomobject]@{ Ok = $true; Items = [System.Collections.Generic.List[object]]::new(); Truncated = $false; Earliest = $null; Status = ''; Note = ''; Since = $since }
        try {
            $f = "userPrincipalName eq '$upnLiteral' and createdDateTime ge $sinceText"
            $r = Get-SignInPage -Uri ('https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString($f)) -MaxRecords $MaxSignInsPerUser -Label "sign-ins $upn" -Type 'interactive'
            foreach ($s in $r.Items) { $ur.Items.Add($s) }
            $ur.Truncated = $r.Truncated; $ur.Earliest = $r.Earliest
            if ($IncludeNonInteractive) {
                $f = "userPrincipalName eq '$upnLiteral' and createdDateTime ge $sinceText and signInEventTypes/any(t: t eq 'nonInteractiveUser')"
                $r = Get-SignInPage -Uri ('https://graph.microsoft.com/beta/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString($f)) -MaxRecords $MaxSignInsPerUser -Label "non-interactive sign-ins $upn" -Type 'nonInteractive'
                foreach ($s in $r.Items) { $ur.Items.Add($s) }
                if ($r.Truncated) { $ur.Truncated = $true; if (-not $ur.Earliest -or ($r.Earliest -and $r.Earliest -gt $ur.Earliest)) { $ur.Earliest = $r.Earliest } }
            }
        }
        catch {
            $ur.Ok = $false
            $ur.Status = Get-FailureStatus $_
            $ur.Note = "Sign-ins not readable ($($ur.Status)): $($_.Exception.Message)"
            $readFailures.Add($ur.Status)
            Write-RunLog ("{0}: {1}" -f $upn, $ur.Note) 'WARN'
        }
        foreach ($s in $ur.Items) { $allSignIns.Add($s) }
        $userReads[$upn] = $ur
    }
    $usersRead = @($userReads.Values | Where-Object Ok).Count
    $caReadable = [bool](@($allSignIns | Where-Object { $_.HasCaProperty -and @($_.appliedConditionalAccessPolicies).Count -gt 0 }).Count)
    $caNote = 'No Conditional Access results in the sign-ins read: the run account cannot read Conditional Access (Policy.Read.All, or Global Reader / Security Reader), so policy results cannot be checked'
    if ($allSignIns.Count -and -not $caReadable) { Write-RunLog $caNote 'WARN' }
    Write-RunLog ("{0} sign-ins read for {1} test user(s)" -f $allSignIns.Count, $userReads.Count)

    # ---- 3. Evaluate each case ----
    $results = [System.Collections.Generic.List[object]]::new()
    $evidence = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $cases) {
        $row = [ordered]@{
            TestId = $c.TestId; CaseType = $c.CaseType; Description = $c.Description; UserPrincipalName = $c.UserPrincipalName; App = $c.App
            Policy = $(if ($c.HasPolicy) { Get-PolicyLabel $c } else { '' }); ExpectedPolicyResult = $c.ExpectedPolicyResult; ObservedPolicyResult = ''
            ExpectedSignIn = $c.ExpectedSignIn; ObservedSignIn = ''; Outcome = ''; SignInsMatched = 0; EvidenceSignInTimeUtc = ''
            CorrelationId = ''; RequestId = ''; ErrorCode = ''; FailureReason = ''; Note = ''
        }
        $notes = @()
        if (-not $c.Valid) {
            $row.Outcome = 'Blocked'; $row.Note = "Invalid test case: $($c.Problem)"
            $results.Add([pscustomobject]$row); continue
        }
        if ($c.PolicyId -and $policies.Count -and -not $policies.ContainsKey($c.PolicyId)) { $notes += 'policy is not in the current policy list (deleted, or the ID is wrong)' }
        elseif ($c.PolicyId -and $policies.ContainsKey($c.PolicyId)) { $notes += "policy state now: $($policies[$c.PolicyId].state)" }
        $ur = $userReads[$c.UserPrincipalName]
        if (-not $ur.Ok) {
            $row.Outcome = 'Blocked'; $row.Note = (@($ur.Note) + $notes) -join '; '
            $results.Add([pscustomobject]$row); continue
        }
        $matched = @($ur.Items | Where-Object { $_.CreatedUtc -and $_.CreatedUtc -ge $c.NotBeforeUtc -and (Test-AppMatch -SignIn $_ -App $c.App) } |
                Sort-Object -Property @{ Expression = 'CreatedUtc'; Descending = $true }, @{ Expression = 'requestId'; Descending = $false })
        $row.SignInsMatched = $matched.Count
        if ($ur.Truncated) { $notes += ('sign-ins TRUNCATED at {0}; earliest read {1}' -f $MaxSignInsPerUser, $(if ($ur.Earliest) { $ur.Earliest.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'n/a' })) }
        if (-not $matched.Count) {
            $row.Outcome = 'NoEvidence'
            $notes = @("no sign-in by this user to app '$($c.App)' since $($c.NotBeforeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))") + $notes
            $row.Note = $notes -join '; '
            $results.Add([pscustomobject]$row); continue
        }
        if ($c.HasPolicy -and $c.ExpectedPolicyResult -and (-not $caReadable -or @($matched | Where-Object { -not $_.HasCaProperty }).Count -eq $matched.Count)) {
            $row.Outcome = 'Blocked'
            $row.Note = (@($caNote) + $notes) -join '; '
            $results.Add([pscustomobject]$row); continue
        }
        $toCheck = $(if ($EvaluateAll) { $matched } else { @($matched[0]) })
        $checks = @(foreach ($s in $toCheck) { [pscustomobject]@{ SignIn = $s; Check = (Test-SignInAgainstCase -SignIn $s -Case $c) } })
        $failed = @($checks | Where-Object { -not $_.Check.Met })
        $shown = $(if ($failed.Count) { $failed[0] } else { $checks[0] })
        $s = $shown.SignIn
        $row.ObservedPolicyResult = $(if ($c.HasPolicy -and -not $caReadable) { '' } else { $shown.Check.ObservedPolicy })
        $row.ObservedSignIn = $shown.Check.ObservedSignIn
        $row.Outcome = $(if ($failed.Count) { 'Fail' } else { 'Pass' })
        $row.EvidenceSignInTimeUtc = $(if ($s.CreatedUtc) { $s.CreatedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        $row.CorrelationId = $s.correlationId; $row.RequestId = $s.requestId
        $row.ErrorCode = $s.errorCode; $row.FailureReason = $(if ($s.errorCode) { $s.failureReason } else { '' })
        if ($EvaluateAll) { $notes = @(('{0} of {1} matching sign-ins met the expectation' -f ($checks.Count - $failed.Count), $checks.Count)) + $notes }
        else { $notes = @('latest matching sign-in evaluated') + $notes }
        if ($failed.Count) { $notes = @($shown.Check.Reason) + $notes }
        if ($row.ObservedPolicyResult -eq 'notInSignIn') { $notes += 'policy not in the sign-in''s Conditional Access results (counts as notApplied)' }
        if ($c.HasPolicy -and -not $c.ExpectedPolicyResult) { $notes += 'ExpectedPolicyResult blank: only the sign-in outcome was checked' }
        $row.Note = $notes -join '; '
        $results.Add([pscustomobject]$row)
        foreach ($ch in $checks) {
            $e = $ch.SignIn
            $evidence.Add([pscustomobject][ordered]@{
                TestId                    = $c.TestId
                CaseType                  = $c.CaseType
                CreatedUtc                = $(if ($e.CreatedUtc) { $e.CreatedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { [string]$e.createdDateTime })
                UserPrincipalName         = $e.userPrincipalName
                AppDisplayName            = $e.appDisplayName
                AppId                     = $e.appId
                ClientAppUsed             = $e.clientAppUsed
                SignInType                = $e._type
                ErrorCode                 = $e.errorCode
                FailureReason             = $(if ($e.errorCode) { $e.failureReason } else { '' })
                ConditionalAccessStatus   = $e.conditionalAccessStatus
                PolicyResult              = $(if ($c.HasPolicy -and $caReadable) { $ch.Check.ObservedPolicy } else { '' })
                AuthenticationRequirement = $e.authenticationRequirement
                MetExpectation            = $ch.Check.Met
                CorrelationId             = $e.correlationId
                RequestId                 = $e.requestId
            })
        }
    }

    $anyTrunc = [bool](@($userReads.Values | Where-Object Truncated).Count)
    $allReadsFailed = ($userReads.Count -gt 0 -and $usersRead -eq 0)
    $failStatus = $(if ($readFailures -contains 'EvidenceUnavailable') { 'EvidenceUnavailable' } else { 'Blocked' })
    $resNote = ('One row per test case; {0}' -f $(if ($EvaluateAll) { 'every matching sign-in evaluated (-EvaluateAll)' } else { 'latest matching sign-in evaluated' }))
    if ($policyReadNote) { $resNote += "; $policyReadNote" }
    if ($allSignIns.Count -and -not $caReadable) { $resNote += "; $caNote" }
    if ($anyTrunc) { $resNote += '; sign-ins TRUNCATED for at least one user (see Note)' }
    if ($readFailures.Count) { $resNote += "; sign-ins not readable for $($readFailures.Count) user(s)" }
    $resStatus = $(if ($allReadsFailed) { $failStatus } elseif (@($results | Where-Object Outcome -eq 'Blocked').Count -or $anyTrunc) { 'Partial' } else { 'Completed' })
    Export-Dataset -Name 'pilot-test-results' -Rows $results.ToArray() -Status $resStatus -Note $resNote
    if ($allReadsFailed) { Set-DatasetStatus -Name 'pilot-signin-evidence' -Status $failStatus -Note 'No test user''s sign-ins could be read' }
    else {
        Export-Dataset -Name 'pilot-signin-evidence' -Rows $evidence.ToArray() -Status $(if ($readFailures.Count -or $anyTrunc -or ($allSignIns.Count -and -not $caReadable)) { 'Partial' } else { 'Completed' }) -Note ('Every sign-in used as evidence; no IP address, location or device details' + $(if ($allSignIns.Count -and -not $caReadable) { "; PolicyResult blank: $caNote" } else { '' }))
    }

    # ---- 4. Pilot group membership ----
    $pilotIds = $null; $pilotUpns = $null; $pilotNote = ''; $pilotStatus = ''
    if ($PilotGroupId) {
        try {
            $members = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers?`$select=id,userPrincipalName" -f $PilotGroupId) -Label 'pilot group members'
            $pilotIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $pilotUpns = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($m in $members) {
                if ($m.PSObject.Properties.Name -contains '@odata.type' -and "$($m.'@odata.type')" -ne '#microsoft.graph.user') { continue }
                [void]$pilotIds.Add([string]$m.id)
                if ($m.PSObject.Properties.Name -contains 'userPrincipalName' -and $m.userPrincipalName) { [void]$pilotUpns.Add([string]$m.userPrincipalName) }
            }
            Write-RunLog ("Pilot group: {0} user member(s), transitive" -f $pilotIds.Count)
        }
        catch {
            $pilotStatus = Get-FailureStatus $_
            $pilotNote = "Pilot group members not readable ($pilotStatus): $($_.Exception.Message)"
            Write-RunLog $pilotNote 'WARN'
        }
    }
    if (-not $PilotGroupId) { Set-DatasetStatus -Name 'pilot-scope-check' -Status 'Deferred' -Note 'No -PilotGroupId given' }
    elseif ($null -eq $pilotIds) { Set-DatasetStatus -Name 'pilot-scope-check' -Status $pilotStatus -Note $pilotNote }
    else {
        $scopeRows = foreach ($c in $cases) {
            $inGroup = $(if ($c.UserPrincipalName) { $pilotUpns.Contains($c.UserPrincipalName) } else { '' })
            $flags = @()
            if ($c.InPilotExpected -and "$inGroup" -ne $c.InPilotExpected) { $flags += 'CaseTypeConflict' }
            [pscustomobject][ordered]@{
                TestId            = $c.TestId
                CaseType          = $c.CaseType
                Description       = $c.Description
                UserPrincipalName = $c.UserPrincipalName
                InPilotGroup      = $inGroup
                InPilotExpected   = $c.InPilotExpected
                Check             = $(if (-not $c.InPilotExpected) { 'NotChecked' } elseif ($flags.Count) { 'Mismatch' } else { 'Match' })
                Flags             = ($flags -join '; ')
            }
        }
        Export-Dataset -Name 'pilot-scope-check' -Rows @($scopeRows) -Note $(if ($hasPilotCol) { 'Membership is transitive; Check is NotChecked where InPilotExpected is blank' } else { 'Test-case file has no InPilotExpected column: membership listed, nothing checked' })
    }

    # ---- 5. Pilot scope leak ----
    $leakRows = $null; $leakRead = $null
    $leakPolicyIds = @($(if ($PolicyIds.Count) { $PolicyIds } else { $cases | Where-Object { $_.PolicyId } | ForEach-Object { $_.PolicyId } }) | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $CheckScopeLeak) { Set-DatasetStatus -Name 'pilot-scope-leak' -Status 'Deferred' -Note 'No -CheckScopeLeak' }
    elseif (-not $PilotGroupId) { Set-DatasetStatus -Name 'pilot-scope-leak' -Status 'Blocked' -Note '-CheckScopeLeak needs -PilotGroupId' }
    elseif ($null -eq $pilotIds) { Set-DatasetStatus -Name 'pilot-scope-leak' -Status $pilotStatus -Note $pilotNote }
    elseif (-not $leakPolicyIds.Count) { Set-DatasetStatus -Name 'pilot-scope-leak' -Status 'Blocked' -Note 'No policy IDs: pass -PolicyIds or fill PolicyId in the test-case file' }
    else {
        try {
            $f = 'createdDateTime ge ' + $windowStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
            $leakRead = Get-SignInPage -Uri ('https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString($f)) -MaxRecords $MaxSignInRecords -Label 'all interactive sign-ins' -Type 'interactive'
            $leakCaReadable = [bool](@($leakRead.Items | Where-Object { $_.HasCaProperty -and @($_.appliedConditionalAccessPolicies).Count -gt 0 }).Count)
            if ($leakRead.Items.Count -and -not $leakCaReadable) { Set-DatasetStatus -Name 'pilot-scope-leak' -Status 'Blocked' -Note $caNote }
            else {
                $agg = @{}
                foreach ($s in $leakRead.Items) {
                    if ($pilotIds.Contains($s.userId)) { continue }
                    foreach ($ap in @($s.appliedConditionalAccessPolicies)) {
                        if ($leakPolicyIds -notcontains $ap.id -or $EnforcedResults -notcontains $ap.result) { continue }
                        $k = "$($s.userId)|$($ap.id)"
                        if (-not $agg.ContainsKey($k)) {
                            $agg[$k] = [pscustomobject][ordered]@{
                                UserPrincipalName = $s.userPrincipalName
                                PolicyName        = $(if ($policies.ContainsKey($ap.id)) { [string]$policies[$ap.id].displayName } else { $ap.displayName })
                                PolicyState       = $(if ($policies.ContainsKey($ap.id)) { [string]$policies[$ap.id].state } else { '' })
                                Results           = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                                SignIns           = 0
                                Apps              = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                                FirstSeenUtc      = $null
                                LastSeenUtc       = $null
                                UserId            = $s.userId
                                PolicyId          = $ap.id
                            }
                        }
                        $a = $agg[$k]; $a.SignIns++
                        [void]$a.Results.Add($ap.result); if ($s.appDisplayName) { [void]$a.Apps.Add($s.appDisplayName) }
                        $t = $s.CreatedUtc
                        if ($t) { if (-not $a.FirstSeenUtc -or $t -lt $a.FirstSeenUtc) { $a.FirstSeenUtc = $t }; if (-not $a.LastSeenUtc -or $t -gt $a.LastSeenUtc) { $a.LastSeenUtc = $t } }
                    }
                }
                $leakRows = @($agg.Values | ForEach-Object {
                        $_.Results = (@($_.Results) | Sort-Object) -join '; '
                        $_.Apps = (@($_.Apps) | Sort-Object) -join '; '
                        $_
                    } | Sort-Object PolicyName, @{ Expression = 'SignIns'; Descending = $true }, UserPrincipalName)
                $leakNote = 'Users outside the pilot group on whom a listed policy was enforced (success or failure); interactive sign-ins since {0}; policies: {1}' -f $windowStart.ToString('yyyy-MM-ddTHH:mm:ssZ'), ($leakPolicyIds -join ', ')
                if ($leakRead.Truncated) { $leakNote += ('; TRUNCATED at {0}: earliest sign-in read {1}' -f $MaxSignInRecords, $(if ($leakRead.Earliest) { $leakRead.Earliest.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'n/a' })) }
                Export-Dataset -Name 'pilot-scope-leak' -Rows $leakRows -Status $(if ($leakRead.Truncated) { 'Partial' } else { 'Completed' }) -Note $leakNote
            }
        }
        catch {
            $st = Get-FailureStatus $_
            Set-DatasetStatus -Name 'pilot-scope-leak' -Status $st -Note "Sign-in logs not readable: $($_.Exception.Message)"
        }
    }

    # ---- 6. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $res = $results.ToArray()
    $nPass = @($res | Where-Object Outcome -eq 'Pass').Count
    $nFail = @($res | Where-Object Outcome -eq 'Fail').Count
    $nNoEv = @($res | Where-Object Outcome -eq 'NoEvidence').Count
    $nBlk  = @($res | Where-Object Outcome -eq 'Blocked').Count
    Add-Metric 'Test cases' $res.Count -Note ("Evaluation: {0}" -f $script:ManifestExtra.Evaluation)
    Add-Metric 'Test cases passed' $nPass
    Add-Metric 'Test cases failed' $nFail
    Add-Metric 'Test cases with no evidence' $nNoEv -Note 'No matching sign-in in the window: the test has not been run yet, or the app / time is wrong'
    Add-Metric 'Test cases blocked' $nBlk -Note 'Invalid test case, or the evidence could not be read; see Note'
    foreach ($t in 'Expected', 'Adverse') {
        $sub = @($res | Where-Object CaseType -eq $t)
        Add-Metric "$t cases" $sub.Count
        Add-Metric "$t cases passed" @($sub | Where-Object Outcome -eq 'Pass').Count
        Add-Metric "$t cases failed" @($sub | Where-Object Outcome -eq 'Fail').Count
        Add-Metric "$t cases with no evidence or blocked" @($sub | Where-Object { $_.Outcome -in @('NoEvidence', 'Blocked') }).Count
    }
    $allPass = $(if ($nFail) { $false } elseif ($nNoEv -or $nBlk) { '' } else { $true })
    Add-Metric 'All test cases passed' $allPass -Note $(if ($nFail) { 'At least one case failed' } elseif ($nNoEv -or $nBlk) { 'Not known: some cases have no evidence or are blocked' } else { '' })
    Add-Metric 'Test users' $userReads.Count -Note $(if ($readFailures.Count) { "Sign-ins not readable for $($readFailures.Count) user(s)" } else { '' })
    Add-Metric 'Sign-ins read for test users' $(if ($allReadsFailed) { '' } else { $allSignIns.Count }) -Note $(if ($allReadsFailed) { "$failStatus`: no test user's sign-ins could be read" } elseif ($IncludeNonInteractive) { 'Includes non-interactive (beta)' } else { 'Interactive only' })
    Add-Metric 'Sign-ins used as evidence' $evidence.Count
    Add-Metric 'Sign-ins carrying Conditional Access results' $(if ($allSignIns.Count) { $caReadable } else { '' }) -Note $(if ($allSignIns.Count -and -not $caReadable) { $caNote } else { '' })
    Add-Metric 'Sign-in data truncated' $anyTrunc
    if ($PilotGroupId) {
        Add-Metric 'Pilot group user members' $(if ($null -ne $pilotIds) { $pilotIds.Count } else { '' }) -Note $pilotNote
        Add-Metric 'Test cases with CaseTypeConflict' $(if ($null -ne $pilotIds) { @($scopeRows | Where-Object { $_.Flags -match 'CaseTypeConflict' }).Count } else { '' }) -Note $(if ($null -ne $pilotIds) { 'Test user''s pilot group membership differs from InPilotExpected' } else { $pilotNote })
    }
    if ($CheckScopeLeak) {
        $leakDs = @($script:Datasets | Where-Object Dataset -eq 'pilot-scope-leak' | Select-Object -First 1)
        Add-Metric 'Users outside the pilot with a pilot policy enforced' $(if ($null -ne $leakRows) { @($leakRows | Select-Object -ExpandProperty UserId -Unique).Count } else { '' }) -Note $(if ($leakDs.Count) { "$($leakDs[0].Status) $($leakDs[0].Note)".Trim() } else { '' })
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ TestCaseCsv = $TestCaseCsv; LookbackHours = $LookbackHours; MaxSignInsPerUser = $MaxSignInsPerUser; IncludeNonInteractive = [bool]$IncludeNonInteractive; EvaluateAll = [bool]$EvaluateAll; PilotGroupId = $PilotGroupId; PolicyIds = @($PolicyIds); CheckScopeLeak = [bool]$CheckScopeLeak; MaxSignInRecords = $MaxSignInRecords }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
