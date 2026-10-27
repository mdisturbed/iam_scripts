<#
.SYNOPSIS
    Read-only access review evidence: for each access review instance that ran, who reviewed what,
    what they decided and why, and whether the removals were actually applied.

.DESCRIPTION
    Script 20 measures coverage (which apps, groups and roles are reviewed at all) and gives
    decision counts for each review's latest instance. This script produces the audit evidence
    behind those numbers: one row per decision, for every instance that ran in the window.

    For each access review definition (optionally filtered by ID or name) it reads the instances
    that ended (or started) within -SinceDays, and for each instance:

      - the stages, when the review is multi-stage, and the decisions made in each stage
      - the final decisions (paged in full): decision, justification, reviewer, review time,
        who applied it, when, and the apply result, plus the system recommendation
      - the reviewers who were actually contacted

    It then lists the decisions and instances that need follow-up: not reviewed, denials not
    applied, self-review, approvals without the required justification, decisions against the
    recommendation, privileged principals left unreviewed, instances with no reviewers contacted,
    and instances still in progress after their end date.

    Each principal is joined to the effective privileged set (any directory role path: active,
    eligible, via group or PIM for Groups) to mark IsPrivileged and IsTier0.

    Instances are filtered by date on the client: the instances list only supports filtering on
    status, so every instance of each definition is read and the window is applied locally.

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\30-AccessReviewEvidence\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER DefinitionIds
    Only these access review definition IDs. Default: all definitions.

.PARAMETER DefinitionNameLike
    Only definitions whose display name matches any of these wildcard patterns (for example
    '*Finance*'). Matched on the client, case-insensitive.

.PARAMETER SinceDays
    Instances whose end date (or start date, when there is no end date) falls within this many
    days before now. Default 180.

.PARAMETER IncludeInProgress
    Also include instances that are still running or finishing (InProgress, Starting, Completing,
    AutoReviewing, AutoReviewed, Applying). They are marked InProgress in Flags. By default only
    Completed and Applied instances are included.

.PARAMETER SkipPrivilegeJoin
    Do not read directory role holders; IsPrivileged / IsTier0 are left blank and the
    PrivilegedApprovedWithoutReview exception is not evaluated.

.EXAMPLE
    .\30-Get-AccessReviewEvidence.ps1
.EXAMPLE
    .\30-Get-AccessReviewEvidence.ps1 -SinceDays 365 -DefinitionNameLike '*Group1*', '*App1*'
.EXAMPLE
    .\30-Get-AccessReviewEvidence.ps1 -DefinitionIds '00000000-0000-0000-0000-000000000000' -IncludeInProgress

.NOTES
    Version : 1.0.1
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : AccessReview.Read.All, Directory.Read.All, RoleManagement.Read.Directory,
              PrivilegedEligibilitySchedule.Read.AzureADGroup
    Licence : Access reviews need Entra ID P2 / ID Governance. Eligible roles and PIM for Groups need
              Entra ID P2.
    Sources : Microsoft Graph v1.0 accessReviewScheduleDefinition, accessReviewInstance,
              accessReviewStage, accessReviewInstanceDecisionItem, accessReviewReviewer.
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

    [string[]]$DefinitionIds = @(),
    [string[]]$DefinitionNameLike = @(),
    [ValidateRange(1, 3650)]
    [int]$SinceDays = 180,
    [switch]$IncludeInProgress,
    [switch]$SkipPrivilegeJoin
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '30-AccessReviewEvidence'
$ScriptVersion = '1.0.1'
$RequiredScopes = @('AccessReview.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')

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

function Get-ReviewScope {
    # Classifies an access review definition: what it targets, and which members it reviews.
    #   Type: Application / DirectoryRole / Group / AllGroups / AllM365Groups / GroupsFiltered / AzureResource / AccessPackage / Other
    #   CoversMembers: All, or GuestsOnly when the principal scope is filtered to guests.
    param($Definition)
    $queries = [System.Collections.Generic.List[string]]::new()
    foreach ($sc in @($Definition.scope, $Definition.instanceEnumerationScope)) {
        if (-not $sc) { continue }
        if ($sc.PSObject.Properties.Name -contains 'query' -and $sc.query) { $queries.Add([uri]::UnescapeDataString("$($sc.query)").Replace('+', ' ')) }
        foreach ($ps in @($sc.principalScopes)) { if ($ps -and $ps.query) { $queries.Add([uri]::UnescapeDataString("$($ps.query)").Replace('+', ' ')) } }
        foreach ($rs in @($sc.resourceScopes)) { if ($rs -and $rs.query) { $queries.Add([uri]::UnescapeDataString("$($rs.query)").Replace('+', ' ')) } }
    }
    $all = $queries -join ' | '
    $members = $(if ($all -match "userType eq 'Guest'") { 'GuestsOnly' } else { 'All' })
    $type = 'Other'; $id = ''; $detail = ''
    foreach ($s in $queries) {
        if ($s -match '/servicePrincipals/([0-9a-fA-F-]{36})') { $type = 'Application'; $id = $Matches[1]; break }
        if ($s -match 'roleDefinitionId eq ''?([0-9a-fA-F-]{36})' -or $s -match '/roleDefinitions/([0-9a-fA-F-]{36})') { $type = 'DirectoryRole'; $id = $Matches[1]; break }
        if ($s -match 'privilegedAccess/group/.*groupId eq ''?([0-9a-fA-F-]{36})') { $type = 'Group'; $id = $Matches[1]; $detail = 'PIM for Groups'; break }
        if ($s -match '/groups/([0-9a-fA-F-]{36})') { $type = 'Group'; $id = $Matches[1]; break }
        if ($s -match '(/subscriptions/[^ ?|]+)') { $type = 'AzureResource'; $id = $Matches[1]; break }
        if ($s -match '^/(v1\.0/|beta/)?groups(\?|$)') {
            $filter = ''
            if ($s -match '\$filter=([^&]+)') { $filter = $Matches[1] }
            if (-not $filter) { $type = 'AllGroups' }
            elseif ($filter -match "groupTypes/any\(\s*\w+\s*:\s*\w+\s+eq\s+'Unified'\s*\)" -and $filter -notmatch '\band\b|\bor\b|\bnot\b') { $type = 'AllM365Groups' }
            else { $type = 'GroupsFiltered'; $detail = $filter }
            break
        }
        if ($s -match 'accessPackage') { $type = 'AccessPackage'; break }
    }
    [pscustomobject]@{ Type = $type; Id = $id; Detail = $detail; CoversMembers = $members; Query = $all }
}

function Get-ReviewerType {
    # Self-review (no reviewers), manager, group owners, specific users, members of a group.
    param($Definition)
    $q = @($Definition.reviewers | Where-Object { $_ } | ForEach-Object { "$($_.query)" })
    if (-not $q.Count) { return 'Self-review' }
    $t = foreach ($x in $q) {
        if ($x -match '^/?(\./)?me$') { 'Self-review' }
        elseif ($x -match 'manager') { 'Manager' }
        elseif ($x -match 'owners') { 'GroupOwners' }
        elseif ($x -match '^/users/[^/]+$') { 'SpecificUsers' }
        elseif ($x -match '/groups/[^/]+/(transitiveMembers|members)') { 'GroupMembers' }
        else { 'Other' }
    }
    return (@($t | Sort-Object -Unique) -join '+')
}

$script:TargetNameCache = @{}
function Get-ReviewTargetName {
    # Display name of what a review targets (cached). Same lookups as script 20.
    param($Target)
    if ($Target.Type -eq 'AzureResource') { return $Target.Id }
    if ($Target.Type -in @('AllGroups', 'AllM365Groups', 'GroupsFiltered')) {
        return $(switch ($Target.Type) { 'AllGroups' { 'All groups' } 'AllM365Groups' { 'All Microsoft 365 groups' } default { "Groups matching: $($Target.Detail)" } })
    }
    if (-not $Target.Id) { return '' }
    $k = '{0}|{1}' -f $Target.Type, $Target.Id.ToLowerInvariant()
    if ($script:TargetNameCache.ContainsKey($k)) { return $script:TargetNameCache[$k] }
    $name = ''
    try {
        $obj = $(if ($Target.Type -eq 'DirectoryRole') { Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{0}?`$select=displayName" -f $Target.Id) } else { Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/directoryObjects/{0}" -f $Target.Id) })
        $name = "$($obj.displayName)"
    }
    catch {
        $code = Get-HttpStatusFromError $_
        $name = $(if ($code -eq 404) { "$($Target.Id) (deleted)" } else { "$($Target.Id) (unresolved: HTTP $code)" })
    }
    $script:TargetNameCache[$k] = $name
    return $name
}

function Test-EmptyIdentityId {
    # True when an identity id is missing or the all-zero id Graph uses for "nobody yet".
    param([string]$Id)
    return (-not $Id -or $Id -match '^0{8}-0{4}-0{4}-0{4}-0{12}$')
}

function Get-DateOrNull {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try { return ([datetime]$Value).ToUniversalTime() } catch { return $null }
}

function Get-LinkInfo {
    # Object type and id from a principalLink / resourceLink such as https://graph.microsoft.com/v1.0/users/{id}.
    param([string]$Link)
    if ($Link -match '/(users|servicePrincipals|groups|roleDefinitions|accessPackages|applications)/([^/?]+)') {
        $t = switch ($Matches[1]) { 'users' { 'user' } 'servicePrincipals' { 'servicePrincipal' } 'groups' { 'group' } 'roleDefinitions' { 'DirectoryRole' } 'accessPackages' { 'AccessPackage' } default { 'application' } }
        return [pscustomobject]@{ Type = $t; Id = $Matches[2] }
    }
    return [pscustomobject]@{ Type = ''; Id = '' }
}

function Get-TruncatedText {
    param([string]$Text, [int]$Max = 500)
    if (-not $Text) { return '' }
    $t = ($Text -replace '[\r\n\t]+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    return $t
}

function Get-CountOf {
    param([hashtable]$Counts, [string]$Key)
    if ($Counts.ContainsKey($Key)) { return $Counts[$Key] }
    return 0
}

$ctx = $null
$sinceUtc = (Get-Date).ToUniversalTime().AddDays(-$SinceDays)
$nowUtc = (Get-Date).ToUniversalTime()
$doneStatuses = @('Completed', 'Applied')
$runningStatuses = @('InProgress', 'Starting', 'Completing', 'AutoReviewing', 'AutoReviewed', 'Applying')
$appliedResults = @('AppliedSuccessfully', 'AppliedSuccessfullyButObjectNotFound')
$exceptionTypes = @('NotReviewed', 'DenyNotApplied', 'SelfReview', 'ApprovedWithoutJustification', 'DecidedAgainstRecommendation', 'PrivilegedApprovedWithoutReview', 'InstanceNoReviewersContacted', 'InstanceOverdue')
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Write-RunLog ("Window: instances ending (or starting) on or after {0}" -f $sinceUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))
    $ctx = Connect-DiscoveryGraph

    $instRows = [System.Collections.Generic.List[object]]::new()
    $decRows  = [System.Collections.Generic.List[object]]::new()
    $excRows  = [System.Collections.Generic.List[object]]::new()
    $instNotes = [System.Collections.Generic.List[string]]::new()
    $reviewsAvailable = $true
    $reviewsStatus = 'Completed'
    $reviewsNote = ''
    $defsTotal = 0
    $defsInScope = @()
    $overdueNotIncluded = 0
    $priv = $null; $privNote = ''

    # ---- 1. Definitions ----
    try {
        $defs = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions' -Label 'accessReviewDefinitions'
        $defsTotal = $defs.Count
        $idSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($i in $DefinitionIds) { if ($i) { [void]$idSet.Add($i.Trim()) } }
        $defsInScope = @($defs | Where-Object {
                $d = $_
                $okId = (-not $idSet.Count) -or $idSet.Contains("$($d.id)")
                $okName = (-not @($DefinitionNameLike).Count) -or [bool](@($DefinitionNameLike | Where-Object { "$($d.displayName)" -like $_ }).Count)
                $okId -and $okName
            })
        Write-RunLog ("Definitions read: {0}; in scope after filters: {1}" -f $defsTotal, $defsInScope.Count)
        if ($idSet.Count) {
            $found = @($defs | ForEach-Object { "$($_.id)" })
            foreach ($i in $idSet) { if ($found -notcontains $i) { $instNotes.Add("definition $i not found"); Write-RunLog ("Definition {0} not found." -f $i) 'WARN' } }
        }
    }
    catch {
        $reviewsAvailable = $false
        $reviewsStatus = Get-FailureStatus $_
        $reviewsNote = "Access review definitions not readable: $($_.Exception.Message)"
        Write-RunLog $reviewsNote 'WARN'
    }

    # ---- 2. Privileged principals (for IsPrivileged / IsTier0) ----
    if ($SkipPrivilegeJoin) { $privNote = 'Skipped (-SkipPrivilegeJoin)' }
    elseif (-not $reviewsAvailable) { $privNote = 'Not read: access reviews not readable' }
    else {
        try {
            $priv = Get-PrivilegedPrincipalSet -SkipOwners
            $privNote = Join-Values ($priv.Status.GetEnumerator() | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value })
        }
        catch { $privNote = "Not readable: $($_.Exception.Message)"; Write-RunLog ("Role holders not readable ({0}); IsPrivileged / IsTier0 left blank." -f $_.Exception.Message) 'WARN' }
    }
    function Get-PrivFlag {
        param([string]$PrincipalId)
        if (-not $priv -or -not $PrincipalId) { return [pscustomobject]@{ IsPrivileged = ''; IsTier0 = '' } }
        $ps = Get-PrivilegeSummary -Set $priv -PrincipalId $PrincipalId
        return [pscustomobject]@{ IsPrivileged = $ps.IsPrivileged; IsTier0 = $ps.IsTier0 }
    }

    function ConvertTo-DecisionRow {
        # Flattens one accessReviewInstanceDecisionItem into the review-decisions shape.
        param($Item, $Def, $Inst, [string]$Stage, [string]$TargetName, [string]$TargetType)
        $p = $Item.principal
        $pLink = Get-LinkInfo "$($Item.principalLink)"
        $prinId = $(if ($p -and $p.id) { "$($p.id)" } else { $pLink.Id })
        $pType = $(if ($p -and $p.'@odata.type') { ("$($p.'@odata.type')" -replace '#microsoft.graph.', '' -replace 'Identity$', '') } else { $pLink.Type })
        $pName = $(if ($p) { "$($p.displayName)" } else { '' })
        $pUpn = $(if ($p -and $p.PSObject.Properties.Name -contains 'userPrincipalName') { "$($p.userPrincipalName)" } else { '' })
        if (-not $pName -and $prinId) { $pp = Get-PrivPrincipal $prinId; $pName = $pp.Name; if (-not $pUpn) { $pUpn = $pp.Upn }; if (-not $pType) { $pType = $pp.Type } }
        $r = $Item.resource
        $rLink = Get-LinkInfo "$($Item.resourceLink)"
        $rType = $(if ($r -and $r.type) { "$($r.type)" } elseif ($rLink.Type) { $rLink.Type } else { $TargetType })
        $rName = $(if ($r -and $r.displayName) { "$($r.displayName)" } else { $TargetName })
        $rb = $Item.reviewedBy
        $rbId = $(if ($rb) { "$($rb.id)" } else { '' })
        $reviewed = -not (Test-EmptyIdentityId $rbId) -or ($rb -and "$($rb.displayName)")
        $ab = $Item.appliedBy
        $abId = $(if ($ab) { "$($ab.id)" } else { '' })
        $pf = Get-PrivFlag $prinId
        [pscustomobject][ordered]@{
            DefinitionName = "$($Def.displayName)"
            InstanceId     = "$($Inst.id)"
            Stage          = $Stage
            PrincipalType  = $pType
            PrincipalName  = $pName
            PrincipalUpn   = $pUpn
            ResourceType   = $rType
            ResourceName   = $rName
            Decision       = "$($Item.decision)"
            Recommendation = "$($Item.recommendation)"
            Justification  = Get-TruncatedText "$($Item.justification)" 500
            ReviewedBy     = $(if ($reviewed) { "$($rb.displayName)" } else { '' })
            ReviewedByUpn  = $(if ($reviewed -and $rb.PSObject.Properties.Name -contains 'userPrincipalName') { "$($rb.userPrincipalName)" } else { '' })
            ReviewedUtc    = Get-DateOrNull $Item.reviewedDateTime
            AppliedBy      = $(if (-not (Test-EmptyIdentityId $abId) -or ($ab -and "$($ab.displayName)")) { $(if ($ab.PSObject.Properties.Name -contains 'userPrincipalName' -and $ab.userPrincipalName) { "$($ab.userPrincipalName)" } else { "$($ab.displayName)" }) } else { '' })
            AppliedUtc     = Get-DateOrNull $Item.appliedDateTime
            ApplyResult    = "$($Item.applyResult)"
            IsPrivileged   = $pf.IsPrivileged
            IsTier0        = $pf.IsTier0
            Flags          = ''
            ApplyDescription = Get-TruncatedText "$($Item.applyDescription)" 200
            DefinitionId   = "$($Def.id)"
            DecisionId     = "$($Item.id)"
            PrincipalId    = $prinId
            ReviewedById   = $(if (Test-EmptyIdentityId $rbId) { '' } else { $rbId })
        }
    }

    function Add-ExceptionRow {
        param([string]$Type, $Def, $Inst, $Row, [string]$Detail)
        $excRows.Add([pscustomobject][ordered]@{
            ExceptionType  = $Type
            DefinitionName = "$($Def.displayName)"
            InstanceId     = "$($Inst.id)"
            InstanceStatus = "$($Inst.status)"
            Stage          = $(if ($Row) { $Row.Stage } else { '' })
            PrincipalType  = $(if ($Row) { $Row.PrincipalType } else { '' })
            PrincipalName  = $(if ($Row) { $Row.PrincipalName } else { '' })
            PrincipalUpn   = $(if ($Row) { $Row.PrincipalUpn } else { '' })
            ResourceName   = $(if ($Row) { $Row.ResourceName } else { '' })
            Decision       = $(if ($Row) { $Row.Decision } else { '' })
            Recommendation = $(if ($Row) { $Row.Recommendation } else { '' })
            ReviewedBy     = $(if ($Row) { $Row.ReviewedBy } else { '' })
            ReviewedByUpn  = $(if ($Row) { $Row.ReviewedByUpn } else { '' })
            ReviewedUtc    = $(if ($Row) { $Row.ReviewedUtc } else { $null })
            ApplyResult    = $(if ($Row) { $Row.ApplyResult } else { '' })
            IsPrivileged   = $(if ($Row) { $Row.IsPrivileged } else { '' })
            IsTier0        = $(if ($Row) { $Row.IsTier0 } else { '' })
            Detail         = $Detail
            InstanceEndUtc = Get-DateOrNull $Inst.endDateTime
            DefinitionId   = "$($Def.id)"
            DecisionId     = $(if ($Row) { $Row.DecisionId } else { '' })
        })
        if ($Row) { $Row.Flags = Join-Values (@(@($Row.Flags -split '; ') + $Type) | Where-Object { $_ } | Select-Object -Unique) }
    }

    # ---- 3. Instances, stages, decisions, contacted reviewers ----
    $instReadFailures = 0; $decReadFailures = 0; $partialInstances = 0
    if ($reviewsAvailable) {
        foreach ($d in $defsInScope) {
            $s = $d.settings
            $stageSettings = @($d.stageSettings | Where-Object { $_ })
            $multiStage = ($stageSettings.Count -gt 0)
            $autoApply = [bool]($s -and $s.autoApplyDecisionsEnabled)
            $defaultDecision = $(if ($s -and $s.defaultDecisionEnabled) { "$($s.defaultDecision)" } else { 'None' })
            $justReq = [bool]($s -and $s.justificationRequiredOnApproval)
            $recEnabled = $(if ($multiStage) { Join-Values ($stageSettings | ForEach-Object { 'Stage {0}: {1}' -f $_.stageId, [bool]$_.recommendationsEnabled }) } else { [bool]($s -and $s.recommendationsEnabled) })
            $recAny = $(if ($multiStage) { [bool](@($stageSettings | Where-Object { $_.recommendationsEnabled }).Count) } else { [bool]$recEnabled })
            $reviewerType = $(if ($multiStage) { Join-Values ($stageSettings | ForEach-Object { 'Stage {0}: {1}' -f $_.stageId, (Get-ReviewerType $_) }) } else { Get-ReviewerType $d })
            $defTarget = Get-ReviewScope $d

            try {
                $instances = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/{0}/instances" -f $d.id) -Label "instances $($d.id)"
            }
            catch {
                $instReadFailures++
                $code = Get-HttpStatusFromError $_
                Write-RunLog ("Instances unreadable for {0}: {1}" -f $d.displayName, $_.Exception.Message) 'WARN'
                $instRows.Add([pscustomobject][ordered]@{
                    DefinitionId = "$($d.id)"; DefinitionName = "$($d.displayName)"; ScopeSummary = ''; ReviewerType = $reviewerType; InstanceId = ''
                    Status = 'Unreadable'; StartUtc = $null; EndUtc = $null; Stages = ''; Decisions = ''; Approve = ''; Deny = ''; NotReviewed = ''; DontKnow = ''
                    'Reviewed%' = ''; DeniesApplied = ''; DeniesNotApplied = ''; AutoApplyEnabled = $autoApply; DefaultDecision = $defaultDecision
                    JustificationRequired = $justReq; RecommendationsEnabled = $recEnabled; ContactedReviewers = ''; Flags = 'InstancesUnreadable'
                    EvidenceStatus = (Get-FailureStatus $_); EvidenceNote = "Instances not readable (HTTP $code)"; ContactedReviewerUpns = ''
                })
                continue
            }

            foreach ($inst in $instances) {
                $start = Get-DateOrNull $inst.startDateTime
                $end = Get-DateOrNull $inst.endDateTime
                $when = $(if ($end) { $end } else { $start })
                $st = "$($inst.status)"
                $isRunning = $runningStatuses -contains $st
                $isOverdue = ($isRunning -and $end -and $end -lt $nowUtc)
                $inWindow = ($when -and $when -ge $sinceUtc)
                if (-not $inWindow) { continue }
                if ($isOverdue) {
                    Add-ExceptionRow -Type 'InstanceOverdue' -Def $d -Inst $inst -Row $null -Detail ("Status {0}, ended {1}" -f $st, $end.ToString('yyyy-MM-ddTHH:mm:ssZ'))
                }
                $include = ($doneStatuses -contains $st) -or ($IncludeInProgress -and $isRunning)
                if (-not $include) {
                    if ($isOverdue) { $overdueNotIncluded++ }
                    continue
                }

                $flags = [System.Collections.Generic.List[string]]::new()
                $notes = [System.Collections.Generic.List[string]]::new()
                if ($isRunning) { $flags.Add('InProgress') }
                if ($isOverdue) { $flags.Add('InstanceOverdue') }
                if (-not $autoApply) { $flags.Add('ManualApply') }

                $instTarget = Get-ReviewScope $inst
                $target = $(if ($instTarget.Id) { $instTarget } else { $defTarget })
                $targetName = Get-ReviewTargetName $target
                $scopeSummary = '{0}: {1}{2}' -f $target.Type, $targetName, $(if ($defTarget.CoversMembers -eq 'GuestsOnly' -or $instTarget.CoversMembers -eq 'GuestsOnly') { ' (guests only)' } else { '' })
                $base = "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/{0}/instances/{1}" -f $d.id, $inst.id
                $instStatus = 'Completed'

                # Stages (multi-stage reviews only) and the decisions made in each stage.
                $stageRows = [System.Collections.Generic.List[object]]::new()
                $stagesValue = '1'
                $stageDecisionsOk = $true
                if ($multiStage) {
                    try {
                        $stageList = Invoke-GraphGetAll -Uri "$base/stages" -Label "stages $($inst.id)"
                        $stages = @($stageList | Sort-Object { Get-DateOrNull $_.startDateTime })
                        $stagesValue = "$($stages.Count)"
                        $n = 0
                        foreach ($stg in $stages) {
                            $n++
                            try {
                                foreach ($item in (Invoke-GraphGetAll -Uri ("{0}/stages/{1}/decisions?`$top=100" -f $base, $stg.id) -Label "stageDecisions $($stg.id)")) {
                                    $stageRows.Add((ConvertTo-DecisionRow -Item $item -Def $d -Inst $inst -Stage "$n" -TargetName $targetName -TargetType $target.Type))
                                }
                            }
                            catch {
                                $stageDecisionsOk = $false
                                $flags.Add('StageDecisionsUnreadable'); $notes.Add("stage $n decisions unreadable (HTTP $(Get-HttpStatusFromError $_))")
                                Write-RunLog ("Stage {0} decisions unreadable for {1}: {2}" -f $n, $d.displayName, $_.Exception.Message) 'WARN'
                            }
                        }
                    }
                    catch {
                        $stageDecisionsOk = $false
                        $stagesValue = "$($stageSettings.Count) (stages unreadable)"
                        $flags.Add('StagesUnreadable'); $notes.Add("stages unreadable (HTTP $(Get-HttpStatusFromError $_))")
                        Write-RunLog ("Stages unreadable for {0}: {1}" -f $d.displayName, $_.Exception.Message) 'WARN'
                    }
                }

                # Final decisions for the instance (paged in full).
                $finalRows = [System.Collections.Generic.List[object]]::new()
                $decisionsOk = $true
                try {
                    foreach ($item in (Invoke-GraphGetAll -Uri "$base/decisions?`$top=100" -Label "decisions $($inst.id)")) {
                        $finalRows.Add((ConvertTo-DecisionRow -Item $item -Def $d -Inst $inst -Stage $(if ($multiStage) { 'Final' } else { '' }) -TargetName $targetName -TargetType $target.Type))
                    }
                }
                catch {
                    $decisionsOk = $false; $decReadFailures++
                    $flags.Add('DecisionsUnreadable'); $notes.Add("decisions unreadable (HTTP $(Get-HttpStatusFromError $_)); counts left blank")
                    Write-RunLog ("Decisions unreadable for {0} instance {1}: {2}" -f $d.displayName, $inst.id, $_.Exception.Message) 'WARN'
                }

                # Contacted reviewers.
                $contacted = $null
                try { $contacted = Invoke-GraphGetAll -Uri "$base/contactedReviewers" -Label "contactedReviewers $($inst.id)" }
                catch {
                    $flags.Add('ContactedReviewersUnreadable'); $notes.Add("contacted reviewers unreadable (HTTP $(Get-HttpStatusFromError $_))")
                    Write-RunLog ("Contacted reviewers unreadable for {0} instance {1}: {2}" -f $d.displayName, $inst.id, $_.Exception.Message) 'WARN'
                }
                if ($null -ne $contacted -and $contacted.Count -eq 0) {
                    $flags.Add('InstanceNoReviewersContacted')
                    Add-ExceptionRow -Type 'InstanceNoReviewersContacted' -Def $d -Inst $inst -Row $null -Detail ("Reviewer type: {0}" -f $reviewerType)
                }

                # Per-decision exceptions. Reviewer behaviour is judged on stage decisions when they exist;
                # the outcome (reviewed, applied) is judged on the final decision.
                $reviewerRows = $(if ($multiStage -and $stageDecisionsOk -and $stageRows.Count) { $stageRows } else { $finalRows })
                foreach ($r in $reviewerRows) {
                    if ($r.ReviewedById -and $r.PrincipalId -and $r.ReviewedById -eq $r.PrincipalId) {
                        Add-ExceptionRow -Type 'SelfReview' -Def $d -Inst $inst -Row $r -Detail 'Reviewer is the principal under review'
                    }
                    if ($justReq -and $r.Decision -eq 'Approve' -and $r.ReviewedById -and -not $r.Justification) {
                        Add-ExceptionRow -Type 'ApprovedWithoutJustification' -Def $d -Inst $inst -Row $r -Detail 'Definition requires justification on approval'
                    }
                    if ($r.Decision -in @('Approve', 'Deny') -and $r.Recommendation -in @('Approve', 'Deny') -and $r.Decision -ne $r.Recommendation -and $r.ReviewedById) {
                        Add-ExceptionRow -Type 'DecidedAgainstRecommendation' -Def $d -Inst $inst -Row $r -Detail $(if ($recAny) { 'Recommendation shown to reviewers' } else { 'Recommendations not shown to reviewers' })
                    }
                }
                foreach ($r in $finalRows) {
                    if ($r.Decision -eq 'NotReviewed') {
                        Add-ExceptionRow -Type 'NotReviewed' -Def $d -Inst $inst -Row $r -Detail ("Default decision: {0}" -f $defaultDecision)
                        $staysIn = ($defaultDecision -in @('None', 'Approve')) -or ($defaultDecision -eq 'Recommendation' -and $r.Recommendation -ne 'Deny')
                        if ($r.IsPrivileged -eq $true -and $staysIn) {
                            Add-ExceptionRow -Type 'PrivilegedApprovedWithoutReview' -Def $d -Inst $inst -Row $r -Detail ("Privileged principal kept access without review (default decision: {0}{1})" -f $defaultDecision, $(if ($r.IsTier0 -eq $true) { '; Tier 0' } else { '' }))
                        }
                    }
                    if ($r.Decision -eq 'Deny' -and -not $isRunning -and $appliedResults -notcontains $r.ApplyResult) {
                        Add-ExceptionRow -Type 'DenyNotApplied' -Def $d -Inst $inst -Row $r -Detail ("Apply result: {0}; auto-apply: {1}" -f $(if ($r.ApplyResult) { $r.ApplyResult } else { 'blank' }), $autoApply)
                    }
                    if ($r.ApplyResult -eq 'AppliedSuccessfullyButObjectNotFound') { $r.Flags = Join-Values (@(@($r.Flags -split '; ') + 'AppliedButObjectNotFound') | Where-Object { $_ } | Select-Object -Unique) }
                }
                foreach ($r in @($stageRows) + @($finalRows)) {
                    if ($isRunning) { $r.Flags = Join-Values (@(@($r.Flags -split '; ') + 'InProgress') | Where-Object { $_ } | Select-Object -Unique) }
                    $decRows.Add($r)
                }

                $c = @{}; foreach ($x in $finalRows) { $v = $x.Decision; if ($c.ContainsKey($v)) { $c[$v]++ } else { $c[$v] = 1 } }
                $n = $finalRows.Count
                $nr = Get-CountOf $c 'NotReviewed'
                $denies = @($finalRows | Where-Object { $_.Decision -eq 'Deny' })
                $dApplied = @($denies | Where-Object { $appliedResults -contains $_.ApplyResult }).Count
                if (@($finalRows | Where-Object { $_.Flags -match 'DenyNotApplied' }).Count) { $flags.Add('DeniesNotApplied') }
                if (-not $decisionsOk -or $flags -contains 'StagesUnreadable' -or $flags -contains 'StageDecisionsUnreadable' -or $flags -contains 'ContactedReviewersUnreadable') { $instStatus = 'Partial'; $partialInstances++ }
                $instRows.Add([pscustomobject][ordered]@{
                    DefinitionId           = "$($d.id)"
                    DefinitionName         = "$($d.displayName)"
                    ScopeSummary           = $scopeSummary
                    ReviewerType           = $reviewerType
                    InstanceId             = "$($inst.id)"
                    Status                 = $st
                    StartUtc               = $start
                    EndUtc                 = $end
                    Stages                 = $stagesValue
                    Decisions              = $(if ($decisionsOk) { $n } else { '' })
                    Approve                = $(if ($decisionsOk) { Get-CountOf $c 'Approve' } else { '' })
                    Deny                   = $(if ($decisionsOk) { Get-CountOf $c 'Deny' } else { '' })
                    NotReviewed            = $(if ($decisionsOk) { $nr } else { '' })
                    DontKnow               = $(if ($decisionsOk) { Get-CountOf $c 'DontKnow' } else { '' })
                    'Reviewed%'            = $(if ($decisionsOk -and $n) { [math]::Round(100 * ($n - $nr) / $n, 1) } else { '' })
                    DeniesApplied          = $(if ($decisionsOk) { $dApplied } else { '' })
                    DeniesNotApplied       = $(if ($decisionsOk) { $denies.Count - $dApplied } else { '' })
                    AutoApplyEnabled       = $autoApply
                    DefaultDecision        = $defaultDecision
                    JustificationRequired  = $justReq
                    RecommendationsEnabled = $recEnabled
                    ContactedReviewers     = $(if ($null -ne $contacted) { $contacted.Count } else { '' })
                    Flags                  = Join-Values ($flags | Select-Object -Unique)
                    EvidenceStatus         = $instStatus
                    EvidenceNote           = Join-Values $notes
                    ContactedReviewerUpns  = $(if ($null -ne $contacted) { Join-Values ($contacted | ForEach-Object { if ($_.userPrincipalName) { "$($_.userPrincipalName)" } else { "$($_.displayName)" } } | Sort-Object -Unique) } else { '' })
                })
            }
        }
    }

    # ---- 4. Export ----
    $scopeNote = "Instances ending (or starting) on or after $($sinceUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')); statuses: Completed, Applied$(if ($IncludeInProgress) { ' + in progress' })"
    if (-not $reviewsAvailable) {
        foreach ($n in 'review-instances', 'review-decisions', 'review-exceptions') { Set-DatasetStatus -Name $n -Status $reviewsStatus -Note $reviewsNote }
    }
    else {
        $iNote = @($scopeNote)
        if ($instReadFailures) { $iNote += "instances unreadable for $instReadFailures definition(s) (Status = Unreadable rows)" }
        if ($partialInstances) { $iNote += "$partialInstances instance(s) read only in part (see EvidenceStatus / EvidenceNote)" }
        if ($instNotes.Count) { $iNote += $instNotes }
        Export-Dataset -Name 'review-instances' -Rows @($instRows | Sort-Object DefinitionName, StartUtc) -Status $(if ($instReadFailures -or $partialInstances -or $instNotes.Count) { 'Partial' } else { 'Completed' }) -Note ($iNote -join '; ')

        $dNote = @('One row per decision; Stage = stage number, Final for the outcome of a multi-stage review, blank for a single-stage review')
        if ($instReadFailures -or $decReadFailures) { $dNote += ('decisions missing for {0} instance(s) and {1} definition(s) whose instances could not be read' -f $decReadFailures, $instReadFailures) }
        if (-not $SkipPrivilegeJoin -and -not $priv) { $dNote += "IsPrivileged blank: $privNote" }
        $decPartial = ($instReadFailures -or $decReadFailures -or @($instRows | Where-Object { $_.Flags -match 'StagesUnreadable|StageDecisionsUnreadable' }).Count)
        Export-Dataset -Name 'review-decisions' -Rows @($decRows | Sort-Object DefinitionName, InstanceId, Stage, PrincipalName) -Status $(if ($decPartial) { 'Partial' } else { 'Completed' }) -Note ($dNote -join '; ')

        $eNote = @('One row per decision or instance needing follow-up')
        if ($decPartial) { $eNote += 'exceptions cannot be judged where decisions were not readable' }
        if ($SkipPrivilegeJoin) { $eNote += 'PrivilegedApprovedWithoutReview not evaluated (-SkipPrivilegeJoin)' }
        elseif (-not $priv) { $eNote += 'PrivilegedApprovedWithoutReview not evaluated: role holders not readable' }
        $excPartial = ($decPartial -or (-not $SkipPrivilegeJoin -and -not $priv))
        Export-Dataset -Name 'review-exceptions' -Rows @($excRows | Sort-Object ExceptionType, DefinitionName, InstanceId, PrincipalName) -Status $(if ($excPartial) { 'Partial' } else { 'Completed' }) -Note ($eNote -join '; ')
    }

    # ---- 5. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    if (-not $reviewsAvailable) {
        Add-Metric 'Access review definitions' '' -Note "$reviewsStatus - $reviewsNote"
        Add-Metric 'Instances in window' '' -Note $reviewsStatus
        Add-Metric 'Decisions' '' -Note $reviewsStatus
    }
    else {
        $readInst = @($instRows | Where-Object { $_.InstanceId })
        $okInst = @($readInst | Where-Object { $_.Decisions -ne '' })
        $final = @($decRows | Where-Object { $_.Stage -in @('', 'Final') })
        $nDec = $final.Count
        $nNr = @($final | Where-Object Decision -eq 'NotReviewed').Count
        $gapNote = $(if ($decReadFailures -or $instReadFailures) { "Partial: $decReadFailures instance(s) with unreadable decisions, $instReadFailures definition(s) with unreadable instances" } else { '' })
        Add-Metric 'Access review definitions' $defsTotal
        Add-Metric 'Definitions in scope' $defsInScope.Count -Note $(if (@($DefinitionIds).Count -or @($DefinitionNameLike).Count) { 'Filtered by -DefinitionIds / -DefinitionNameLike' } else { 'All definitions' })
        Add-Metric 'Window start' $sinceUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') -Note "-SinceDays $SinceDays"
        Add-Metric 'Instances in window' $readInst.Count -Note $scopeNote
        Add-Metric 'Instances in progress (included)' @($readInst | Where-Object { $_.Flags -match 'InProgress' }).Count
        Add-Metric 'Instances read only in part' $partialInstances
        if ($instReadFailures) { Add-Metric 'Definitions whose instances could not be read' $instReadFailures }
        Add-Metric 'Decisions' $nDec -Note ('Final decisions only (stage decisions not counted twice). ' + $gapNote).Trim()
        Add-Metric 'Decisions reviewed (%)' $(if ($nDec) { [math]::Round(100 * ($nDec - $nNr) / $nDec, 1) } else { '' }) -Note ('{0} of {1} not reviewed' -f $nNr, $nDec)
        foreach ($v in 'Approve', 'Deny', 'DontKnow', 'NotReviewed') { Add-Metric "Decisions: $v" @($final | Where-Object Decision -eq $v).Count }
        Add-Metric 'Denies applied' (@($okInst | Measure-Object DeniesApplied -Sum).Sum + 0)
        Add-Metric 'Denies not applied' (@($okInst | Measure-Object DeniesNotApplied -Sum).Sum + 0) -Note 'Includes in-progress instances, which are not raised as DenyNotApplied'
        foreach ($t in $exceptionTypes) {
            $cnt = @($excRows | Where-Object ExceptionType -eq $t).Count
            $note = ''
            if ($t -eq 'PrivilegedApprovedWithoutReview' -and -not $priv) { $cnt = ''; $note = $privNote }
            elseif ($t -eq 'InstanceOverdue' -and $overdueNotIncluded) { $note = "$overdueNotIncluded not in review-instances (use -IncludeInProgress)" }
            elseif ($gapNote -and $t -notin @('InstanceOverdue')) { $note = $gapNote }
            Add-Metric "Exceptions: $t" $cnt -Note $note
        }
        $ends = @($readInst | Where-Object { $_.EndUtc } | ForEach-Object { $_.EndUtc } | Sort-Object)
        Add-Metric 'Earliest instance end' $(if ($ends.Count) { $ends[0].ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        Add-Metric 'Latest instance end' $(if ($ends.Count) { $ends[-1].ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        Add-Metric 'Privileged principal join' $(if ($priv) { 'Completed' } elseif ($SkipPrivilegeJoin) { 'Skipped' } else { 'Not available' }) -Note $privNote
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ DefinitionIds = @($DefinitionIds); DefinitionNameLike = @($DefinitionNameLike); SinceDays = $SinceDays; IncludeInProgress = [bool]$IncludeInProgress; SkipPrivilegeJoin = [bool]$SkipPrivilegeJoin }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
