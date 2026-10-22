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
      - successful sign-ins that no enforced policy applied to (only report-only, not applied or
        disabled results), by user and app: the gaps enforcement does not cover today
      - whether each affected user is privileged (any directory role path: active, eligible, via
        group or PIM for Groups) and whether that role is Tier 0

    When the sign-in read stops at -MaxSignInRecords, the window actually covered (from the
    earliest sign-in read) is reported, so a truncated run is never read as the full lookback.

    Report-only results are only returned when the request sends
    "Prefer: include-unknown-enum-members" (Microsoft Graph appliedConditionalAccessPolicy); the
    script always sends it. Conditional Access results are only included in sign-in logs for
    callers who can read Conditional Access (Policy.Read.All, or Global Reader / Security Reader).

    Interactive sign-ins are read from v1.0. -IncludeNonInteractive adds non-interactive sign-ins
    from the beta endpoint (signInEventTypes filter), which is much larger and is not a supported
    production API. -IncludeServicePrincipal adds service principal (workload identity) sign-ins
    from the beta endpoint, so Conditional Access policies for workload identities show impact.
    Sign-ins are reduced to the fields used here as they are read, to keep memory down.

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

.PARAMETER IncludeServicePrincipal
    Also read service principal sign-ins (beta endpoint).

.PARAMETER SkipPrivilegeJoin
    Do not read directory role holders; IsPrivileged / IsTier0 are left blank.

.EXAMPLE
    .\24-Get-CaReportOnlyImpact.ps1 -SignInLookbackDays 14
.EXAMPLE
    .\24-Get-CaReportOnlyImpact.ps1 -SignInLookbackDays 30 -MaxSignInRecords 300000 -ReportOnlyPoliciesOnly
.EXAMPLE
    .\24-Get-CaReportOnlyImpact.ps1 -SignInLookbackDays 7 -IncludeServicePrincipal

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication.
    Scopes  : Policy.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, Directory.Read.All,
              PrivilegedEligibilitySchedule.Read.AzureADGroup. Role: Global Reader or Security Reader.
    Licence : sign-in logs need Entra ID P1. Eligible roles and PIM for Groups need Entra ID P2.
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
    [switch]$IncludeServicePrincipal,
    [switch]$SkipPrivilegeJoin,
    [ValidateRange(1, 20)]
    [int]$TopAppCount = 5
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '24-CaReportOnlyImpact'
$ScriptVersion = '1.1.0'
$RequiredScopes = @('Policy.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'Directory.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')


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

#region ---- Effective privileged principals (identical in every Entra script that uses it; self-contained by design) ----
# Built-in role template IDs treated as Tier 0. One list for every script. Extend with -AdditionalTier0Roles where offered.
$script:Tier0RoleTemplates = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
    '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e' = 'Identity Governance Administrator'
}

function Get-HttpStatusFromError {
    # Returns the HTTP status code of a failed Graph call, or 0 when there is none.
    param($ErrorRecord)
    $code = 0
    try { $code = [int]$ErrorRecord.Exception.Response.StatusCode } catch { }
    if (-not $code) {
        $msg = "$($ErrorRecord.Exception.Message) $($ErrorRecord.ErrorDetails.Message)"
        if ($msg -match 'Request_ResourceNotFound|ResourceNotFound|\bNotFound\b|Not Found|does not exist') { $code = 404 }
        elseif ($msg -match 'Authorization_RequestDenied|\bForbidden\b|Insufficient privileges|AccessDenied') { $code = 403 }
        elseif ($msg -match 'TooManyRequests|throttl') { $code = 429 }
        elseif ($msg -match '\bUnauthorized\b') { $code = 401 }
        elseif ($msg -match '\bBadRequest\b|Bad Request') { $code = 400 }
        elseif ($msg -match '(?:status code|StatusCode|HTTP)[^0-9]{0,4}([1-5]\d\d)\b') { $code = [int]$Matches[1] }
    }
    return $code
}

$script:PrivPrincipalCache = @{}
function Get-PrivPrincipal {
    # Resolves a directory object id to type/name/UPN/enabled. Exists is $false only on a real 404.
    param([string]$Id)
    if ($script:PrivPrincipalCache.ContainsKey($Id)) { return $script:PrivPrincipalCache[$Id] }
    $info = [pscustomobject]@{ Id = $Id; Type = 'unknown'; Name = $Id; Upn = ''; Enabled = ''; UserType = ''; Exists = $true; Error = '' }
    try {
        $o = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/directoryObjects/{0}" -f $Id)
        $info.Type = ("$($o.'@odata.type')" -replace '#microsoft.graph.', '')
        $info.Name = "$($o.displayName)"
        foreach ($p in 'userPrincipalName', 'accountEnabled', 'userType') {
            if ($o.PSObject.Properties.Name -contains $p) {
                switch ($p) { 'userPrincipalName' { $info.Upn = "$($o.$p)" } 'accountEnabled' { $info.Enabled = "$($o.$p)" } 'userType' { $info.UserType = "$($o.$p)" } }
            }
        }
    }
    catch {
        $code = Get-HttpStatusFromError $_
        if ($code -eq 404) { $info.Exists = $false; $info.Name = "$Id (deleted)" }
        else { $info.Error = "HTTP $code"; $info.Name = "$Id (unresolved: HTTP $code)" }
    }
    $script:PrivPrincipalCache[$Id] = $info
    return $info
}

function Get-PrivilegedPrincipalSet {
    # Builds the effective set of principals that hold Entra directory roles, down to the real accounts:
    #   1. active role assignments (schedule instances; falls back to roleAssignments without P2)
    #   2. eligible (PIM) role assignments
    #   3. every group holding a role, expanded transitively to its user / service principal / device members
    #   4. PIM for Groups eligible members and owners of those groups (expanded if a group)
    #   5. owners of those groups (an owner can add themselves)
    # Returns: Rows (one per principal x role x path), ByPrincipal (id -> rows), Status (per source), RoleNames.
    param([switch]$SkipEligible, [switch]$SkipPimGroups, [switch]$SkipOwners)

    $rows   = [System.Collections.Generic.List[object]]::new()
    $status = [ordered]@{ Active = ''; Eligible = ''; GroupExpansion = 'Completed'; PimForGroups = ''; GroupOwners = '' }
    $defs   = @{}
    foreach ($d in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn' -Label 'roleDefinitions')) {
        $defs["$($d.id)"] = $d
        if ($d.templateId) { $defs["$($d.templateId)"] = $d }
    }
    function Get-RoleMeta {
        param([string]$RoleId)
        $d = $(if ($defs.ContainsKey($RoleId)) { $defs[$RoleId] } else { $null })
        $tpl = $(if ($d -and $d.templateId) { "$($d.templateId)" } else { $RoleId })
        [pscustomobject]@{
            Name    = $(if ($d) { "$($d.displayName)" } else { $RoleId })
            BuiltIn = $(if ($d) { [bool]$d.isBuiltIn } else { $false })
            Tier0   = $script:Tier0RoleTemplates.ContainsKey($tpl)
        }
    }

    $assignments = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances' -Label 'roleAssignmentScheduleInstances')) {
            $state = $(if ("$($a.assignmentType)" -eq 'Activated') { 'Activated (eligible, in use now)' } else { 'Active' })
            $assignments.Add([pscustomobject]@{ RoleId = "$($a.roleDefinitionId)"; PrincipalId = "$($a.principalId)"; State = $state; Scope = "$($a.directoryScopeId)"; End = $a.endDateTime; MemberType = "$($a.memberType)" })
        }
        $status.Active = 'Completed'
    }
    catch {
        Write-RunLog ("Role schedule instances not readable ({0}); falling back to roleAssignments." -f $_.Exception.Message) 'WARN'
        foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' -Label 'roleAssignments')) {
            $assignments.Add([pscustomobject]@{ RoleId = "$($a.roleDefinitionId)"; PrincipalId = "$($a.principalId)"; State = 'Active'; Scope = "$($a.directoryScopeId)"; End = $null; MemberType = 'Direct' })
        }
        $status.Active = 'Completed (fallback: no time-bound detail)'
    }
    if ($SkipEligible) { $status.Eligible = 'Skipped' }
    else {
        try {
            foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' -Label 'roleEligibilityScheduleInstances')) {
                $assignments.Add([pscustomobject]@{ RoleId = "$($a.roleDefinitionId)"; PrincipalId = "$($a.principalId)"; State = 'Eligible'; Scope = "$($a.directoryScopeId)"; End = $a.endDateTime; MemberType = "$($a.memberType)" })
            }
            $status.Eligible = 'Completed'
        }
        catch {
            $status.Eligible = Get-FailureStatus $_
            Write-RunLog ("Eligible role assignments not readable: {0}" -f $_.Exception.Message) 'WARN'
        }
    }

    $memberCache = @{}
    function Get-GroupMembersDeep {
        param([string]$GroupId)
        if ($memberCache.ContainsKey($GroupId)) { return $memberCache[$GroupId] }
        $list = @()
        try {
            $list = @(Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers?`$select=id,displayName,userPrincipalName,accountEnabled,userType" -f $GroupId) -Label "transitiveMembers $GroupId")
        }
        catch {
            $status.GroupExpansion = 'Partial'
            Write-RunLog ("Members of group {0} not readable: {1}" -f $GroupId, $_.Exception.Message) 'WARN'
            $list = $null
        }
        $memberCache[$GroupId] = $list
        return $list
    }
    function Add-PrivRow {
        param($Principal, $Role, $Assignment, [string]$Via, [string]$ViaGroup)
        $rows.Add([pscustomobject][ordered]@{
            PrincipalId     = $Principal.Id
            PrincipalType   = $Principal.Type
            PrincipalName   = $Principal.Name
            Upn             = $Principal.Upn
            AccountEnabled  = $Principal.Enabled
            UserType        = $Principal.UserType
            Role            = $Role.Name
            Tier0           = $Role.Tier0
            BuiltInRole     = $Role.BuiltIn
            AssignmentState = $Assignment.State
            Via             = $Via
            ViaGroup        = $ViaGroup
            DirectoryScope  = $Assignment.Scope
            EndDateTime     = $Assignment.End
        })
    }
    function ConvertTo-PrivPrincipal {
        param($Member)
        [pscustomobject]@{
            Id       = "$($Member.id)"
            Type     = ("$($Member.'@odata.type')" -replace '#microsoft.graph.', '')
            Name     = "$($Member.displayName)"
            Upn      = $(if ($Member.PSObject.Properties.Name -contains 'userPrincipalName') { "$($Member.userPrincipalName)" } else { '' })
            Enabled  = $(if ($Member.PSObject.Properties.Name -contains 'accountEnabled') { "$($Member.accountEnabled)" } else { '' })
            UserType = $(if ($Member.PSObject.Properties.Name -contains 'userType') { "$($Member.userType)" } else { '' })
        }
    }

    $roleGroups = @{}
    foreach ($a in $assignments) {
        $role = Get-RoleMeta $a.RoleId
        $p = Get-PrivPrincipal $a.PrincipalId
        Add-PrivRow -Principal $p -Role $role -Assignment $a -Via 'Direct' -ViaGroup ''
        if ($p.Type -ne 'group') { continue }
        if (-not $roleGroups.ContainsKey($p.Id)) { $roleGroups[$p.Id] = [System.Collections.Generic.List[object]]::new() }
        $roleGroups[$p.Id].Add([pscustomobject]@{ Role = $role; Assignment = $a; Group = $p })
        $members = Get-GroupMembersDeep $p.Id
        foreach ($m in @($members)) {
            if (-not $m) { continue }
            $mp = ConvertTo-PrivPrincipal $m
            if ($mp.Type -eq 'group') { continue }
            Add-PrivRow -Principal $mp -Role $role -Assignment $a -Via 'Group member' -ViaGroup $p.Name
        }
    }

    if ($SkipPimGroups) { $status.PimForGroups = 'Skipped' }
    elseif (-not $roleGroups.Count) { $status.PimForGroups = 'Completed (no role-holding groups)' }
    else {
        $pimOk = $true
        foreach ($gid in $roleGroups.Keys) {
            try {
                $inst = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '{0}'" -f $gid) -Label "pimGroupEligibility $gid"
            }
            catch {
                $pimOk = $false
                $status.PimForGroups = Get-FailureStatus $_
                Write-RunLog ("PIM for Groups eligibility not readable ({0}); eligible group members are not included." -f $_.Exception.Message) 'WARN'
                break
            }
            foreach ($e in $inst) {
                $ep = Get-PrivPrincipal "$($e.principalId)"
                $via = $(if ("$($e.accessId)" -eq 'owner') { 'PIM for Groups eligible owner' } else { 'PIM for Groups eligible member' })
                $targets = @($ep)
                if ($ep.Type -eq 'group') {
                    $nested = Get-GroupMembersDeep $ep.Id
                    $targets = @(foreach ($nm in @($nested)) { if ($nm) { $np = ConvertTo-PrivPrincipal $nm; if ($np.Type -ne 'group') { $np } } })
                }
                foreach ($g in $roleGroups[$gid]) {
                    $a = [pscustomobject]@{ State = 'Eligible (via PIM for Groups)'; Scope = $g.Assignment.Scope; End = $e.endDateTime }
                    foreach ($t in $targets) { Add-PrivRow -Principal $t -Role $g.Role -Assignment $a -Via $via -ViaGroup $g.Group.Name }
                }
            }
        }
        if ($pimOk) { $status.PimForGroups = 'Completed' }
    }

    if ($SkipOwners) { $status.GroupOwners = 'Skipped' }
    else {
        $status.GroupOwners = 'Completed'
        foreach ($gid in $roleGroups.Keys) {
            try { $owners = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/owners?`$select=id,displayName,userPrincipalName,accountEnabled,userType" -f $gid) -Label "owners $gid" }
            catch { $status.GroupOwners = 'Partial'; Write-RunLog ("Owners of group {0} not readable: {1}" -f $gid, $_.Exception.Message) 'WARN'; continue }
            foreach ($o in $owners) {
                $op = ConvertTo-PrivPrincipal $o
                foreach ($g in $roleGroups[$gid]) {
                    $a = [pscustomobject]@{ State = "$($g.Assignment.State) (owner can add self)"; Scope = $g.Assignment.Scope; End = $g.Assignment.End }
                    Add-PrivRow -Principal $op -Role $g.Role -Assignment $a -Via 'Owner of role-holding group' -ViaGroup $g.Group.Name
                }
            }
        }
    }

    $byPrincipal = @{}
    foreach ($r in $rows) {
        if (-not $byPrincipal.ContainsKey($r.PrincipalId)) { $byPrincipal[$r.PrincipalId] = [System.Collections.Generic.List[object]]::new() }
        $byPrincipal[$r.PrincipalId].Add($r)
    }
    return [pscustomobject]@{ Rows = $rows; ByPrincipal = $byPrincipal; Status = $status; RoleGroupIds = @($roleGroups.Keys) }
}

function Get-PrivilegeSummary {
    # One-line view of a principal's effective privilege, for joining into other datasets.
    param($Set, [string]$PrincipalId)
    if (-not $Set -or -not $Set.ByPrincipal.ContainsKey($PrincipalId)) { return [pscustomobject]@{ IsPrivileged = $false; IsTier0 = $false; Roles = ''; Paths = '' } }
    $r = $Set.ByPrincipal[$PrincipalId]
    [pscustomobject]@{
        IsPrivileged = $true
        IsTier0      = [bool](@($r | Where-Object { $_.Tier0 }).Count)
        Roles        = (@($r | ForEach-Object { $_.Role } | Sort-Object -Unique) -join '; ')
        Paths        = (@($r | ForEach-Object { if ($_.ViaGroup) { "$($_.AssignmentState) via $($_.Via): $($_.ViaGroup)" } else { $_.AssignmentState } } | Sort-Object -Unique) -join '; ')
    }
}

function Test-PhishResistantMethod {
    # True when a userRegistrationDetails methodsRegistered list includes a phishing-resistant method.
    param($Methods)
    return [bool](@($Methods | Where-Object { "$_" -match '^(fido2|passKey|passKeyDeviceBound|passKeyDeviceBoundAuthenticator|passKeyDeviceBoundWindowsHello|windowsHelloForBusiness|x509Certificate|x509CertificateMultiFactor|x509CertificateSingleFactor|platformCredential)' }).Count)
}
#endregion

# Report-only results are an evolvable enum: Graph only returns them with this header.
$EnumHeader = @{ Prefer = 'include-unknown-enum-members' }
$ResultNames = @('success', 'failure', 'notApplied', 'notEnabled', 'reportOnlySuccess', 'reportOnlyFailure', 'reportOnlyInterrupted', 'reportOnlyNotApplied', 'unknown')
# Results that mean an enforced policy actually applied to the sign-in.
$EnforcedResults = @('success', 'failure')

function ConvertTo-SlimSignIn {
    # Keeps only the fields this script uses. List signIns does not document $select, so the full
    # record is returned by Graph and reduced here, page by page, to keep memory down.
    param($SignIn, [string]$Type)
    $isSp = ($Type -eq 'servicePrincipal')
    $props = $SignIn.PSObject.Properties.Name
    $ca = @()
    if ($props -contains 'appliedConditionalAccessPolicies') {
        $ca = @(foreach ($ap in @($SignIn.appliedConditionalAccessPolicies)) { if ($null -ne $ap) { [pscustomobject]@{ id = [string]$ap.id; displayName = [string]$ap.displayName; result = [string]$ap.result } } })
    }
    [pscustomobject]@{
        createdDateTime   = $SignIn.createdDateTime
        userPrincipalName = $(if ($isSp) { [string]$SignIn.servicePrincipalName } else { [string]$SignIn.userPrincipalName })
        userId            = $(if ($isSp) { [string]$SignIn.servicePrincipalId } else { [string]$SignIn.userId })
        appDisplayName    = $(if ($isSp) { [string]$SignIn.resourceDisplayName } else { [string]$SignIn.appDisplayName })
        appId             = $(if ($isSp) { [string]$SignIn.resourceId } else { [string]$SignIn.appId })
        clientAppUsed     = [string]$SignIn.clientAppUsed
        errorCode         = $(if ($props -contains 'status' -and $SignIn.status -and $null -ne $SignIn.status.errorCode) { [int]$SignIn.status.errorCode } else { $null })
        HasCaProperty     = ($props -contains 'appliedConditionalAccessPolicies')
        appliedConditionalAccessPolicies = $ca
        _type             = $Type
        PrincipalType     = $(if ($isSp) { 'ServicePrincipal' } else { 'User' })
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
            $t = $null; try { $t = ([datetime]$slim.createdDateTime).ToUniversalTime() } catch { }
            if ($t) { if (-not $earliest -or $t -lt $earliest) { $earliest = $t }; if (-not $latest -or $t -gt $latest) { $latest = $t } }
        }
        if ($MaxRecords -gt 0 -and $out.Count -ge $MaxRecords) { $truncated = $true; Write-RunLog ("{0}: stopped at {1} records; TRUNCATED (earliest read {2})" -f $Label, $MaxRecords, $(if ($earliest) { $earliest.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'n/a' })) 'WARN'; break }
        $next = $null
        if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $next = $resp.'@odata.nextLink' }
        if ($out.Count -and ($out.Count % 10000) -lt 1000) { Write-RunLog ("{0}: {1} read so far" -f $Label, $out.Count) }
    }
    return [pscustomobject]@{ Items = $out; Truncated = $truncated; Earliest = $earliest; Latest = $latest; Label = $Label }
}

function Format-Window {
    # "<label>: <earliest> to <latest> (N.N of D days)" for one sign-in query.
    param($Read, [datetime]$Since)
    if (-not $Read.Items.Count) { return ('{0}: no sign-ins' -f $Read.Label) }
    $from = $(if ($Read.Truncated -and $Read.Earliest) { $Read.Earliest } else { $Since })
    $days = [math]::Round(((Get-Date).ToUniversalTime() - $from).TotalDays, 1)
    $text = '{0}: {1} to {2} ({3} of {4} days)' -f $Read.Label, $from.ToString('yyyy-MM-ddTHH:mm:ssZ'), $(if ($Read.Latest) { $Read.Latest.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'n/a' }), $days, $SignInLookbackDays
    if ($Read.Truncated) { $text += ' TRUNCATED' }
    return $text
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
    $sinceDt = (Get-Date).ToUniversalTime().AddDays(-$SignInLookbackDays)
    $since = $sinceDt.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $signIns = [System.Collections.Generic.List[object]]::new()
    $reads = [System.Collections.Generic.List[object]]::new()
    $truncatedAny = $false; $signInStatus = 'Completed'; $signInNote = ''
    try {
        $uri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString("createdDateTime ge $since")
        $r = Get-SignInPage -Uri $uri -MaxRecords $MaxSignInRecords -Label 'interactive sign-ins' -Type 'interactive'
        foreach ($s in $r.Items) { $signIns.Add($s) }
        $reads.Add($r)
        if ($IncludeNonInteractive) {
            $f = "createdDateTime ge $since and signInEventTypes/any(t: t eq 'nonInteractiveUser')"
            $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString($f)
            $r = Get-SignInPage -Uri $uri -MaxRecords $MaxSignInRecords -Label 'non-interactive sign-ins' -Type 'nonInteractive'
            foreach ($s in $r.Items) { $signIns.Add($s) }
            $reads.Add($r)
        }
        if ($IncludeServicePrincipal) {
            $f = "createdDateTime ge $since and signInEventTypes/any(t: t eq 'servicePrincipal')"
            $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString($f)
            $r = Get-SignInPage -Uri $uri -MaxRecords $MaxSignInRecords -Label 'service principal sign-ins' -Type 'servicePrincipal'
            foreach ($s in $r.Items) { $signIns.Add($s) }
            $reads.Add($r)
        }
        $truncatedAny = [bool](@($reads | Where-Object Truncated).Count)
        Write-RunLog ("{0} sign-ins read (since {1})" -f $signIns.Count, $since)
    }
    catch {
        $signInStatus = Get-FailureStatus $_
        $signInNote = "Sign-in logs not readable: $($_.Exception.Message)"
        Write-RunLog $signInNote 'WARN'
    }
    $windowText = (@($reads | ForEach-Object { Format-Window -Read $_ -Since $sinceDt }) -join '; ')
    $earliestRead = @($reads | Where-Object { $_.Earliest } | ForEach-Object { $_.Earliest } | Sort-Object | Select-Object -First 1)
    $coveredFrom = $(if ($truncatedAny) { @($reads | Where-Object { $_.Truncated -and $_.Earliest } | ForEach-Object { $_.Earliest } | Sort-Object -Descending | Select-Object -First 1) } else { @($sinceDt) })

    $withCa = @($signIns | Where-Object { $_.HasCaProperty -and @($_.appliedConditionalAccessPolicies).Count -gt 0 }).Count
    if ($signIns.Count -and -not $withCa) {
        Write-RunLog 'No sign-in carried Conditional Access results: the account probably cannot read Conditional Access (needs Policy.Read.All or Global Reader / Security Reader).' 'WARN'
        $signInNote = ($signInNote + ' No Conditional Access results in the sign-ins returned: check the run account can read Conditional Access.').Trim()
    }

    # ---- 2b. Privileged principals (for IsPrivileged / IsTier0) ----
    $priv = $null; $privNote = ''
    if ($SkipPrivilegeJoin) { $privNote = 'Skipped (-SkipPrivilegeJoin)' }
    else {
        try {
            $priv = Get-PrivilegedPrincipalSet -SkipOwners
            $privNote = Join-Values ($priv.Status.GetEnumerator() | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value })
        }
        catch { $privNote = "Not readable: $($_.Exception.Message)"; Write-RunLog ("Role holders not readable ({0}); IsPrivileged / IsTier0 left blank." -f $_.Exception.Message) 'WARN' }
    }
    function Get-PrivFlag {
        param([string]$PrincipalId)
        if (-not $priv) { return [pscustomobject]@{ IsPrivileged = ''; IsTier0 = '' } }
        $ps = Get-PrivilegeSummary -Set $priv -PrincipalId $PrincipalId
        return [pscustomobject]@{ IsPrivileged = $ps.IsPrivileged; IsTier0 = $ps.IsTier0 }
    }

    # ---- 3. Aggregate ----
    $agg = @{}        # policyId -> counters
    $impact = @{}     # policyId|user|app|result -> row
    $noEnf = @{}      # user|app -> row (successful sign-ins with no enforced policy applied)
    foreach ($s in $signIns) {
        $upn = [string]$s.userPrincipalName; $app = [string]$s.appDisplayName
        $t = $null; try { $t = ([datetime]$s.createdDateTime).ToUniversalTime() } catch { }
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
                    $pf = Get-PrivFlag $s.userId
                    $impact[$key] = [pscustomobject][ordered]@{
                        PolicyName = $a.Name; PolicyState = $state; Result = $res
                        Meaning = $(switch ($res) { 'reportOnlyFailure' { 'Would be blocked if enforced' } 'reportOnlyInterrupted' { 'Would need an extra step (e.g. MFA) if enforced' } default { 'Blocked by the enforced policy' } })
                        UserPrincipalName = $upn; AppDisplayName = $app; ClientAppUsed = [string]$s.clientAppUsed; SignInType = [string]$s._type
                        SignIns = 0; FirstSeenUtc = $null; LastSeenUtc = $null; PolicyId = $pid_
                        PrincipalType = $s.PrincipalType; PrincipalId = $s.userId; IsPrivileged = $pf.IsPrivileged; IsTier0 = $pf.IsTier0
                    }
                }
                $row = $impact[$key]; $row.SignIns++
                if ($t) { if (-not $row.FirstSeenUtc -or $t -lt $row.FirstSeenUtc) { $row.FirstSeenUtc = $t }; if (-not $row.LastSeenUtc -or $t -gt $row.LastSeenUtc) { $row.LastSeenUtc = $t } }
            }
        }

        # Successful sign-in where no enforced policy applied (all results not applied / disabled / report-only).
        if ($s.HasCaProperty -and $s.errorCode -eq 0) {
            $results = @($s.appliedConditionalAccessPolicies | ForEach-Object { [string]$_.result })
            if (-not @($results | Where-Object { $EnforcedResults -contains $_ }).Count) {
                $nk = "$($s.userId)|$upn|$app"
                if (-not $noEnf.ContainsKey($nk)) {
                    $pf = Get-PrivFlag $s.userId
                    $noEnf[$nk] = [pscustomobject][ordered]@{
                        UserPrincipalName       = $upn
                        AppDisplayName          = $app
                        PrincipalType           = $s.PrincipalType
                        SignIns                 = 0
                        NoPolicyEvaluated       = 0
                        ReportOnlyWouldBlock    = 0
                        ReportOnlyWouldInterrupt = 0
                        ClientApps              = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                        SignInTypes             = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                        FirstSeenUtc            = $null
                        LastSeenUtc             = $null
                        IsPrivileged            = $pf.IsPrivileged
                        IsTier0                 = $pf.IsTier0
                        PrincipalId             = $s.userId
                        AppId                   = $s.appId
                    }
                }
                $nr = $noEnf[$nk]; $nr.SignIns++
                if (-not $results.Count) { $nr.NoPolicyEvaluated++ }
                if ($results -contains 'reportOnlyFailure') { $nr.ReportOnlyWouldBlock++ }
                if ($results -contains 'reportOnlyInterrupted') { $nr.ReportOnlyWouldInterrupt++ }
                if ($s.clientAppUsed) { [void]$nr.ClientApps.Add([string]$s.clientAppUsed) }
                [void]$nr.SignInTypes.Add([string]$s._type)
                if ($t) { if (-not $nr.FirstSeenUtc -or $t -lt $nr.FirstSeenUtc) { $nr.FirstSeenUtc = $t }; if (-not $nr.LastSeenUtc -or $t -gt $nr.LastSeenUtc) { $nr.LastSeenUtc = $t } }
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
                $(if ($truncatedAny) { 'SignInsTruncated' })
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
    if ($truncatedAny) { $note += "; TRUNCATED at $MaxSignInRecords per query - window actually covered: $windowText. Shorten the lookback or raise -MaxSignInRecords" }
    if ($IncludeNonInteractive) { $note += '; includes non-interactive (beta)' }
    if ($IncludeServicePrincipal) { $note += '; includes service principal sign-ins (beta)' }
    $privPart = $(if ($SkipPrivilegeJoin) { '' } elseif ($priv) { '' } else { "; IsPrivileged blank: $privNote" })
    if ($signInStatus -ne 'Completed') {
        Export-Dataset -Name 'ca-policy-results' -Rows @($policyRows) -Note ($signInNote + ' Policy list only; no results.')
        Set-DatasetStatus -Name 'ca-reportonly-impact' -Status $signInStatus -Note $signInNote
        Set-DatasetStatus -Name 'no-enforced-policy-signins' -Status $signInStatus -Note $signInNote
    }
    else {
        $noCa = ($signIns.Count -and -not $withCa)
        $partial = $(if ($truncatedAny -or $noCa) { 'Partial' } else { 'Completed' })
        Export-Dataset -Name 'ca-policy-results' -Rows @($policyRows) -Status $partial -Note ($note + $(if ($signInNote) { "; $signInNote" } else { '' }))
        if ($noCa) {
            $noCaNote = 'No Conditional Access results in the sign-ins: the run account cannot read Conditional Access (Policy.Read.All, or Global Reader / Security Reader), so impact and gaps cannot be evaluated'
            Set-DatasetStatus -Name 'ca-reportonly-impact' -Status 'Blocked' -Note $noCaNote
            Set-DatasetStatus -Name 'no-enforced-policy-signins' -Status 'Blocked' -Note $noCaNote
        }
        else {
            $impactRows = @($impact.Values | Sort-Object PolicyName, Result, @{ Expression = 'SignIns'; Descending = $true }, UserPrincipalName)
            Export-Dataset -Name 'ca-reportonly-impact' -Rows $impactRows -Status $(if ($truncatedAny -or $privPart) { 'Partial' } else { 'Completed' }) -Note ('One row per policy, user, app and result: report-only would-block / would-interrupt, and enforced blocks' + $(if ($truncatedAny) { "; TRUNCATED: $windowText" } else { '' }) + $privPart)
            $neRows = @($noEnf.Values | ForEach-Object {
                    $_.ClientApps = (@($_.ClientApps) | Sort-Object) -join '; '
                    $_.SignInTypes = (@($_.SignInTypes) | Sort-Object) -join '; '
                    $_
                } | Sort-Object @{ Expression = { $_.IsTier0 -eq $true }; Descending = $true }, @{ Expression = { $_.IsPrivileged -eq $true }; Descending = $true }, @{ Expression = 'SignIns'; Descending = $true }, UserPrincipalName)
            Export-Dataset -Name 'no-enforced-policy-signins' -Rows $neRows -Status $(if ($truncatedAny -or $privPart) { 'Partial' } else { 'Completed' }) -Note ('Successful sign-ins where no enforced policy applied (every result notApplied / notEnabled / report-only), by user and app' + $(if ($truncatedAny) { "; TRUNCATED: $windowText" } else { '' }) + $privPart)
        }
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
    Add-Metric 'Sign-ins read' $signIns.Count -Note $note
    Add-Metric 'Sign-ins carrying Conditional Access results' $withCa
    Add-Metric 'Report-only policies that would block or interrupt someone' @($roIds | Where-Object { $agg.ContainsKey($_) -and ($agg[$_].BlockUsers.Count -or $agg[$_].InterruptUsers.Count) }).Count
    Add-Metric 'Report-only policies with no sign-ins evaluated' @($roIds | Where-Object { -not $agg.ContainsKey($_) -or $agg[$_].Evaluated -eq 0 }).Count -Note 'Conditions never matched in the window, or nobody signed in to the targeted apps'
    Add-Metric 'Users a report-only policy would block' $blockAll.Count -Note 'Distinct users across all report-only policies'
    Add-Metric 'Users a report-only policy would interrupt' $intAll.Count -Note 'Would need an extra step, such as MFA'
    Add-Metric 'Enabled policies that blocked sign-ins' @($policies.Values | Where-Object { $_.state -eq 'enabled' -and $agg.ContainsKey([string]$_.id) -and $agg[[string]$_.id].Counts['failure'] }).Count
    Add-Metric 'Sign-in data truncated' $truncatedAny
    Add-Metric 'Earliest sign-in read' $(if ($earliestRead) { $earliestRead[0].ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }) -Note $windowText
    Add-Metric 'Sign-in window covered (days)' $(if ($signIns.Count -and $coveredFrom) { [math]::Round(((Get-Date).ToUniversalTime() - $coveredFrom[0]).TotalDays, 1) } else { '' }) -Note ("Requested: $SignInLookbackDays days" + $(if ($truncatedAny) { '; shorter because a query was truncated' } else { '' }))
    $neAll = @($noEnf.Values)
    Add-Metric 'Successful sign-ins with no enforced policy' (($neAll | Measure-Object SignIns -Sum).Sum) -Note 'Only report-only, not applied or disabled results'
    Add-Metric 'Users / principals signing in with no enforced policy' @($neAll | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    if ($priv) {
        Add-Metric 'Privileged users signing in with no enforced policy' @($neAll | Where-Object { $_.IsPrivileged -eq $true } | Select-Object -ExpandProperty UserPrincipalName -Unique).Count -Note $privNote
        Add-Metric 'Tier 0 users signing in with no enforced policy' @($neAll | Where-Object { $_.IsTier0 -eq $true } | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
        Add-Metric 'Privileged users a report-only policy would block or interrupt' @($impact.Values | Where-Object { $_.IsPrivileged -eq $true -and $_.Result -like 'reportOnly*' } | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    }
    elseif (-not $SkipPrivilegeJoin) { Add-Metric 'Privileged users signing in with no enforced policy' '' -Note $privNote }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ SignInLookbackDays = $SignInLookbackDays; MaxSignInRecords = $MaxSignInRecords; ReportOnlyPoliciesOnly = [bool]$ReportOnlyPoliciesOnly; IncludeNonInteractive = [bool]$IncludeNonInteractive; IncludeServicePrincipal = [bool]$IncludeServicePrincipal; SkipPrivilegeJoin = [bool]$SkipPrivilegeJoin; TopAppCount = $TopAppCount }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
