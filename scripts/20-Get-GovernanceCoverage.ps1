<#
.SYNOPSIS
    Read-only discovery of Entra ID Governance coverage: access reviews, how well they are
    completed, which apps / groups / roles they actually cover, entitlement management access
    packages (what they grant and to how many), and lifecycle workflows.

.DESCRIPTION
    Answers "what share of the things that should be certified actually are?" Exports:

      - Access review definitions: target type and name, which members are in scope (all or
        guests only), reviewers and reviewer type (self-review, manager without fallback),
        recurrence, status, and the latest instance's dates
      - Latest-instance decision statistics (optional): approved / denied / not reviewed,
        and whether results were applied
      - Coverage: every enterprise app that requires assignment, every role-assignable group,
        every group holding a directory role (including PIM for Groups), every group containing
        guests, and every directory role that has holders (Tier 0 marked) - marked Covered or
        NotCovered by any recurring review. "All groups" reviews only count for the groups their
        filter matches (for example all Microsoft 365 groups), and guest-only reviews only cover
        guest members. Optionally your own in-scope application list is checked too
      - Access packages with catalog, policies, approval, expiration, built-in reviews,
        assignment counts and incompatible packages
      - What each access package grants (groups, apps, sites and their roles)
      - Lifecycle workflows (joiner / mover / leaver) with their tasks
      - A summary of headline metrics

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\20-GovernanceCoverage\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER InScopeAppsCsv
    Optional CSV listing the applications that must be certified. Needs a column named AppName
    or AppId (or both).

.EXAMPLE
    .\20-Get-GovernanceCoverage.ps1
.EXAMPLE
    .\20-Get-GovernanceCoverage.ps1 -IncludeDecisionStats -InScopeAppsCsv .\in-scope-apps.csv
.EXAMPLE
    .\20-Get-GovernanceCoverage.ps1 -SkipAccessPackageAssignments -SkipGuestGroups     # faster pass

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : AccessReview.Read.All, EntitlementManagement.Read.All, Application.Read.All,
              Group.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory, Directory.Read.All,
              LifecycleWorkflows.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup
    Licence : Access reviews, entitlement management, lifecycle workflows and PIM need Entra ID P2 /
              ID Governance.
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

    [switch]$IncludeDecisionStats,
    [switch]$SkipGuestGroups,
    [string]$InScopeAppsCsv = '',
    [switch]$SkipAccessPackageAssignments,
    [switch]$SkipLifecycleWorkflows
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '20-GovernanceCoverage'
$ScriptVersion = '1.1.0'
$RequiredScopes = @('AccessReview.Read.All', 'EntitlementManagement.Read.All', 'Application.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory', 'Directory.Read.All', 'LifecycleWorkflows.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')

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

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- 1. Access review definitions ----
    $defRows = [System.Collections.Generic.List[object]]::new()
    $statRows = [System.Collections.Generic.List[object]]::new()
    $covered = @{}   # "Type|Id" -> list of { Name; Members } (recurring, not completed)
    $groupWide = [System.Collections.Generic.List[object]]::new()   # recurring reviews over many groups
    $reviewsAvailable = $true
    $reviewsStatus = 'Completed'
    $instFailures = 0
    try {
        $defs = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions' -Label 'accessReviewDefinitions'
        foreach ($d in $defs) {
            $target = Get-ReviewScope $d
            $rec = $d.settings.recurrence
            $recurring = [bool]($rec -and $rec.pattern -and $rec.pattern.type)
            $freq = $(if ($recurring) { '{0} every {1}' -f $rec.pattern.type, $rec.pattern.interval } else { 'One-time' })
            $targetName = ''
            if ($target.Id -and $target.Type -ne 'AzureResource') {
                try {
                    $obj = $(if ($target.Type -eq 'DirectoryRole') { Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{0}?`$select=displayName" -f $target.Id) } else { Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/directoryObjects/{0}" -f $target.Id) })
                    $targetName = $obj.displayName
                }
                catch {
                    $code = Get-HttpStatusFromError $_
                    $targetName = $(if ($code -eq 404) { "$($target.Id) (deleted)" } else { "$($target.Id) (unresolved: HTTP $code)" })
                }
            }
            elseif ($target.Type -eq 'AzureResource') { $targetName = $target.Id }
            elseif ($target.Type -in @('AllGroups', 'AllM365Groups', 'GroupsFiltered')) { $targetName = $(switch ($target.Type) { 'AllGroups' { 'All groups' } 'AllM365Groups' { 'All Microsoft 365 groups' } default { "Groups matching: $($target.Detail)" } }) }
            $active = ($recurring -and "$($d.status)" -notin @('Completed'))
            if ($target.Id -and $active -and $target.Type -ne 'AzureResource') {
                $k = '{0}|{1}' -f $target.Type, $target.Id.ToLowerInvariant()
                if (-not $covered.ContainsKey($k)) { $covered[$k] = [System.Collections.Generic.List[object]]::new() }
                $covered[$k].Add([pscustomobject]@{ Name = "$($d.displayName)"; Members = $target.CoversMembers })
            }
            if ($active -and $target.Type -in @('AllGroups', 'AllM365Groups', 'GroupsFiltered')) { $groupWide.Add([pscustomobject]@{ Name = "$($d.displayName)"; Kind = $target.Type; Members = $target.CoversMembers; Filter = $target.Detail }) }
            $latest = $null; $instRead = 'Completed'
            try {
                $inst = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/{0}/instances" -f $d.id) -Label "instances $($d.id)"
                $latest = $inst | Sort-Object { [datetime]$_.startDateTime } -Descending | Select-Object -First 1
            }
            catch {
                $instFailures++
                $instRead = "Unreadable (HTTP $(Get-HttpStatusFromError $_))"
                Write-RunLog ("Instances unreadable for {0}: {1}" -f $d.displayName, $_.Exception.Message) 'WARN'
            }
            $reviewers = @($d.reviewers | ForEach-Object { "$($_.query)" -replace '^/users/[0-9a-f-]{36}$', 'specific user' -replace '.*manager.*', 'manager' -replace '^\./?owners$', 'group owners' })
            $rType = Get-ReviewerType $d
            $flags = @()
            if ($rType -match 'Self-review') { $flags += 'SelfReview' }
            if ($rType -match 'Manager' -and -not @($d.fallbackReviewers | Where-Object { $_ }).Count) { $flags += 'ManagerNoFallback' }
            if ($target.CoversMembers -eq 'GuestsOnly') { $flags += 'GuestsOnly' }
            if ($target.Type -eq 'GroupsFiltered') { $flags += 'FilteredGroupScope' }
            $defRows.Add([pscustomobject][ordered]@{
                ReviewName        = $d.displayName
                Status            = $d.status
                TargetType        = $target.Type
                TargetName        = $targetName
                Recurrence        = $freq
                Reviewers         = Join-Values ($reviewers | Select-Object -Unique)
                AutoApplyResults  = $d.settings.autoApplyDecisionsEnabled
                DefaultDecision   = $(if ($d.settings.defaultDecisionEnabled) { $d.settings.defaultDecision } else { 'None' })
                Created           = $d.createdDateTime
                LatestStartUtc    = $(if ($latest) { $latest.startDateTime } else { '' })
                LatestEndUtc      = $(if ($latest) { $latest.endDateTime } else { '' })
                LatestStatus      = $(if ($latest) { $latest.status } else { '' })
                CoversMembers     = $target.CoversMembers
                ReviewerType      = $rType
                Flags             = Join-Values $flags
                ScopeQuery        = $target.Query
                InstancesRead     = $instRead
            })
            if ($IncludeDecisionStats -and $latest) {
                try {
                    $dec = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/{0}/instances/{1}/decisions?`$select=decision,applyResult" -f $d.id, $latest.id) -Label "decisions $($d.id)"
                    $n = $dec.Count
                    $c = @{}; foreach ($x in $dec) { $v = "$($x.decision)"; if ($c.ContainsKey($v)) { $c[$v]++ } else { $c[$v] = 1 } }
                    $notReviewed = $(if ($c.ContainsKey('NotReviewed')) { $c['NotReviewed'] } else { 0 })
                    $statRows.Add([pscustomobject][ordered]@{
                        ReviewName      = $d.displayName
                        InstanceStatus  = $latest.status
                        InstanceEndUtc  = $latest.endDateTime
                        Decisions       = $n
                        Approved        = $(if ($c.ContainsKey('Approve')) { $c['Approve'] } else { 0 })
                        Denied          = $(if ($c.ContainsKey('Deny')) { $c['Deny'] } else { 0 })
                        DontKnow        = $(if ($c.ContainsKey('DontKnow')) { $c['DontKnow'] } else { 0 })
                        NotReviewed     = $notReviewed
                        CompletionPct   = $(if ($n) { [math]::Round(100 * ($n - $notReviewed) / $n, 1) } else { '' })
                        Applied         = @($dec | Where-Object { "$($_.applyResult)" -in @('AppliedSuccessfully', 'AppliedSuccessfullyButObjectNotFound') }).Count
                        ApplyFailed     = @($dec | Where-Object { "$($_.applyResult)" -match 'Fail' }).Count
                    })
                }
                catch { Write-RunLog ("Decisions unreadable for {0}: {1}" -f $d.displayName, $_.Exception.Message) 'WARN' }
            }
        }
        Export-Dataset -Name 'access-review-definitions' -Rows $defRows -Status $(if ($instFailures) { 'Partial' } else { 'Completed' }) -Note $(if ($instFailures) { "Instances unreadable for $instFailures review(s): latest-instance columns blank there (see InstancesRead)" } else { '' })
    }
    catch {
        $reviewsAvailable = $false
        $reviewsStatus = Get-FailureStatus $_
        Set-DatasetStatus -Name 'access-review-definitions' -Status $reviewsStatus -Note $_.Exception.Message
    }
    if (-not $IncludeDecisionStats) { Set-DatasetStatus -Name 'access-review-latest-decisions' -Status 'Deferred' -Note 'Run with -IncludeDecisionStats' }
    elseif ($reviewsAvailable) { Export-Dataset -Name 'access-review-latest-decisions' -Rows $statRows }
    else { Set-DatasetStatus -Name 'access-review-latest-decisions' -Status 'Blocked' -Note 'Access reviews not readable' }

    # ---- 2. Coverage denominator ----
    $targets = [System.Collections.Generic.List[object]]::new()
    $targetIndex = @{}
    $covNotes = [System.Collections.Generic.List[string]]::new()
    function Add-Target {
        # GroupTypes: the group's groupTypes when known (an empty list is a known non-Microsoft 365 group).
        param([string]$Type, [string]$Id, [string]$Name, [string]$Why, [bool]$Tier0 = $false, [object[]]$GroupTypes, [switch]$TypesKnown)
        $k = '{0}|{1}' -f $Type, $Id.ToLowerInvariant()
        if ($targetIndex.ContainsKey($k)) {
            $t = $targetIndex[$k]
            if (@($t.Why) -notcontains $Why) { $t.Why += $Why }
            if ($Tier0) { $t.Tier0 = $true }
            if ($TypesKnown -and -not $t.TypesKnown) { $t.GroupTypes = @($GroupTypes | Where-Object { $_ }); $t.TypesKnown = $true }
            return
        }
        $t = [pscustomobject]@{ Type = $Type; Id = $Id; Name = $Name; Why = @($Why); Tier0 = $Tier0; GroupTypes = @($GroupTypes | Where-Object { $_ }); TypesKnown = [bool]$TypesKnown }
        $targets.Add($t); $targetIndex[$k] = $t
    }
    $spsByName = @{}; $spsById = @{}
    try {
        $sps = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appRoleAssignmentRequired,tags,servicePrincipalType' -Label 'servicePrincipals'
        foreach ($s in $sps) {
            $spsByName["$($s.displayName)".ToLowerInvariant()] = $s; $spsById["$($s.appId)".ToLowerInvariant()] = $s
            if ($s.appRoleAssignmentRequired -and @($s.tags) -contains 'WindowsAzureActiveDirectoryIntegratedApp') { Add-Target -Type 'Application' -Id $s.id -Name $s.displayName -Why 'Enterprise app requiring assignment' }
        }
    }
    catch { $covNotes.Add('service principals unreadable'); Write-RunLog ("Service principals unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    try {
        foreach ($g in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true&$count=true&$select=id,displayName,groupTypes' -Eventual -Label 'roleAssignableGroups')) { Add-Target -Type 'Group' -Id $g.id -Name $g.displayName -Why 'Role-assignable group' -GroupTypes @($g.groupTypes) -TypesKnown }
    }
    catch { $covNotes.Add('role-assignable groups unreadable'); Write-RunLog ("Role-assignable groups unreadable: {0}" -f $_.Exception.Message) 'WARN' }

    # Effective role holders: every role with an active or eligible holder, and every group holding a role.
    $priv = $null; $privNote = ''
    try {
        $priv = Get-PrivilegedPrincipalSet -SkipOwners
        $privNote = Join-Values ($priv.Status.GetEnumerator() | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value })
    }
    catch { $privNote = "Role holders not readable: $($_.Exception.Message)"; $covNotes.Add('role holders unreadable (Tier 0 roles used instead)'); Write-RunLog $privNote 'WARN' }
    $roleDefs = @()
    try { $roleDefs = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName' -Label 'roleDefinitions' }
    catch { $covNotes.Add('role definitions unreadable'); Write-RunLog ("Role definitions unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    $roleByName = @{}; foreach ($r in $roleDefs) { $roleByName["$($r.displayName)"] = $r }
    if ($priv) {
        foreach ($grp in ($priv.Rows | Group-Object Role)) {
            $rd = $roleByName[$grp.Name]
            $rid = $(if ($rd -and $rd.templateId) { "$($rd.templateId)" } elseif ($rd) { "$($rd.id)" } else { '' })
            if (-not $rid) { continue }
            $holders = @($grp.Group | Where-Object { $_.PrincipalType -ne 'group' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
            $t0 = [bool](@($grp.Group | Where-Object Tier0).Count)
            Add-Target -Type 'DirectoryRole' -Id $rid -Name $grp.Name -Why ("Directory role with {0} effective holder(s){1}" -f $holders, $(if ($t0) { ' - Tier 0' } else { '' })) -Tier0 $t0
        }
        foreach ($gid in @($priv.RoleGroupIds)) {
            $gRows = @($priv.Rows | Where-Object { $_.PrincipalId -eq $gid })
            $t0 = [bool](@($gRows | Where-Object Tier0).Count)
            $gName = $(if ($gRows.Count) { $gRows[0].PrincipalName } else { $gid })
            $gt = @(); $known = $false
            if (-not $targetIndex.ContainsKey(('Group|{0}' -f "$gid".ToLowerInvariant()))) {
                try { $gt = @((Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/groups/{0}?`$select=id,displayName,groupTypes" -f $gid)).groupTypes); $known = $true } catch { }
            }
            Add-Target -Type 'Group' -Id $gid -Name $gName -Why ('Holds a directory role (' + (Join-Values ($gRows | ForEach-Object { $_.Role } | Sort-Object -Unique)) + ')') -Tier0 $t0 -GroupTypes $gt -TypesKnown:$known
        }
    }
    else {
        foreach ($r in $roleDefs) { if ($script:Tier0RoleTemplates.ContainsKey("$($r.templateId)")) { Add-Target -Type 'DirectoryRole' -Id $r.templateId -Name $r.displayName -Why 'Tier 0 directory role (holders not readable)' -Tier0 $true } }
    }
    if (-not $SkipGuestGroups) {
        try {
            $guestGroups = @{}
            foreach ($gu in (Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$count=true&`$select=id" -Eventual -Label 'guests')) {
                foreach ($m in (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/memberOf/microsoft.graph.group?`$select=id,displayName,groupTypes" -f $gu.id) -Label "memberOf $($gu.id)")) { $guestGroups[$m.id] = $m }
            }
            foreach ($gid in $guestGroups.Keys) { Add-Target -Type 'Group' -Id $gid -Name $guestGroups[$gid].displayName -Why 'Contains guests' -GroupTypes @($guestGroups[$gid].groupTypes) -TypesKnown }
        }
        catch { $covNotes.Add('guest group membership unreadable'); Write-RunLog ("Guest group membership unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    }
    $notFound = [System.Collections.Generic.List[object]]::new()
    if ($InScopeAppsCsv) {
        $list = @(Import-Csv -Path $InScopeAppsCsv)
        foreach ($row in $list) {
            $sp = $null
            if ($row.PSObject.Properties.Name -contains 'AppId' -and $row.AppId) { $sp = $spsById["$($row.AppId)".Trim().ToLowerInvariant()] }
            if (-not $sp -and $row.PSObject.Properties.Name -contains 'AppName' -and $row.AppName) { $sp = $spsByName["$($row.AppName)".Trim().ToLowerInvariant()] }
            $label = $(if ($row.PSObject.Properties.Name -contains 'AppName') { $row.AppName } else { $row.AppId })
            if (-not $sp) { $notFound.Add($label); continue }
            Add-Target -Type 'Application' -Id $sp.id -Name $sp.displayName -Why 'In-scope list'
        }
    }

    # Evaluate coverage for every target.
    $covRows = [System.Collections.Generic.List[object]]::new()
    foreach ($t in $targets) {
        $k = '{0}|{1}' -f $t.Type, $t.Id.ToLowerInvariant()
        $matched = [System.Collections.Generic.List[object]]::new()
        if ($covered.ContainsKey($k)) { foreach ($c in $covered[$k]) { $matched.Add([pscustomobject]@{ Label = $c.Name; Members = $c.Members }) } }
        $note = @()
        if ($t.Type -eq 'Group') {
            $isM365 = (@($t.GroupTypes) -contains 'Unified')
            foreach ($gw in $groupWide) {
                if ($gw.Kind -eq 'AllGroups') { $matched.Add([pscustomobject]@{ Label = "$($gw.Name) (all-groups review)"; Members = $gw.Members }) }
                elseif ($gw.Kind -eq 'AllM365Groups') {
                    if (-not $t.TypesKnown) { $note += "Group type unknown; may be covered by $($gw.Name) (all Microsoft 365 groups)" }
                    elseif ($isM365) { $matched.Add([pscustomobject]@{ Label = "$($gw.Name) (all Microsoft 365 groups)"; Members = $gw.Members }) }
                }
                else { $note += "May be covered by filtered review $($gw.Name) ($($gw.Filter)); check manually" }
            }
        }
        $allM = @($matched | Where-Object Members -eq 'All')
        if ($allM.Count) { $note = @($note | Where-Object { $_ -notlike 'May be covered*' -and $_ -notlike 'Group type unknown*' }) }
        $guestM = @($matched | Where-Object Members -eq 'GuestsOnly')
        $guestReasonOnly = (@($t.Why | Where-Object { $_ -ne 'Contains guests' }).Count -eq 0)
        $isCov = ($allM.Count -gt 0) -or ($guestReasonOnly -and $guestM.Count -gt 0)
        if (-not $allM.Count -and $guestM.Count -and -not $guestReasonOnly) { $note += 'Only guest members are reviewed; member access is not certified' }
        $covRows.Add([pscustomobject][ordered]@{
            TargetType    = $t.Type
            TargetName    = $t.Name
            WhyInScope    = ($t.Why -join '; ')
            Covered       = $isCov
            CoveredBy     = Join-Values ($matched | ForEach-Object { if ($_.Members -eq 'GuestsOnly') { "$($_.Label) (guests only)" } else { $_.Label } })
            TargetId      = $t.Id
            CoversMembers = $(if ($allM.Count) { 'All' } elseif ($guestM.Count) { 'GuestsOnly' } else { '' })
            Tier0         = $t.Tier0
            CoverageNote  = Join-Values ($note | Sort-Object -Unique)
        })
    }
    foreach ($label in $notFound) { $covRows.Add([pscustomobject][ordered]@{ TargetType = 'Application'; TargetName = $label; WhyInScope = 'In-scope list'; Covered = $false; CoveredBy = 'NOT FOUND IN TENANT (not SSO-integrated, or name differs)'; TargetId = ''; CoversMembers = ''; Tier0 = $false; CoverageNote = '' }) }
    $covNote = 'Covered = targeted by a recurring, not-completed access review that reviews all members (guest-only reviews count only for groups in scope because they contain guests)'
    if (-not $reviewsAvailable) { $covNote = 'Access reviews not readable: the targets are listed, Covered is left blank' }
    if ($covNotes.Count) { $covNote += '; Partial: ' + ($covNotes -join ', ') }
    $covStatus = $(if (-not $reviewsAvailable) { $reviewsStatus } elseif ($covNotes.Count) { 'Partial' } else { 'Completed' })
    if (-not $reviewsAvailable) { foreach ($r in $covRows) { if ($r.CoveredBy -notlike 'NOT FOUND*') { $r.Covered = ''; $r.CoveredBy = ''; $r.CoversMembers = '' } } }
    Export-Dataset -Name 'review-coverage' -Rows @($covRows | Sort-Object Covered, TargetType, TargetName) -Status $covStatus -Note $covNote

    # ---- 3. Access packages: settings, what they grant, assignment counts ----
    $apRows = @()
    $resRows = [System.Collections.Generic.List[object]]::new()
    $apDetailFailures = 0
    try {
        $aps = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages?$expand=assignmentPolicies,catalog' -Label 'accessPackages'
        $catalogResources = @{}
        $apRows = foreach ($a in $aps) {
            $pols = @($a.assignmentPolicies)
            $detail = @()
            $catId = $(if ($a.catalog) { "$($a.catalog.id)" } else { '' })
            if ($catId -and -not $catalogResources.ContainsKey($catId)) {
                $map = @{}
                try { foreach ($r in (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/catalogs/{0}/resources" -f $catId) -Label "catalogResources $catId")) { $map["$($r.originId)"] = $r } }
                catch { Write-RunLog ("Catalog resources unreadable for {0}: {1}" -f $a.catalog.displayName, $_.Exception.Message) 'WARN' }
                $catalogResources[$catId] = $map
            }
            $resMap = $(if ($catId) { $catalogResources[$catId] } else { @{} })
            $roleCount = ''
            try {
                $full = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/{0}?`$expand=resourceRoleScopes(`$expand=role,scope)" -f $a.id)
                $rrs = @($full.resourceRoleScopes | Where-Object { $_ })
                $roleCount = $rrs.Count
                foreach ($x in $rrs) {
                    $origin = "$($x.scope.originId)"
                    $res = $(if ($resMap.ContainsKey($origin)) { $resMap[$origin] } else { $null })
                    $resRows.Add([pscustomobject][ordered]@{
                        AccessPackage        = $a.displayName
                        Catalog              = $(if ($a.catalog) { $a.catalog.displayName } else { '' })
                        ResourceName         = $(if ($res) { $res.displayName } else { '' })
                        ResourceOriginSystem = $(if ($x.role.originSystem) { $x.role.originSystem } else { $x.scope.originSystem })
                        ResourceOriginId     = $origin
                        Role                 = $x.role.displayName
                        RoleOriginId         = $x.role.originId
                        Scope                = $x.scope.displayName
                        IsRootScope          = $x.scope.isRootScope
                    })
                }
            }
            catch { $apDetailFailures++; $detail += "resources unreadable (HTTP $(Get-HttpStatusFromError $_))" }
            $delivered = ''; $totalAsg = ''
            if (-not $SkipAccessPackageAssignments) {
                try {
                    $asg = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/assignments?`$filter=accessPackage/id eq '{0}'&`$select=id,state" -f $a.id) -Label "assignments $($a.id)"
                    $totalAsg = $asg.Count
                    $delivered = @($asg | Where-Object { "$($_.state)" -eq 'delivered' }).Count
                }
                catch { $apDetailFailures++; $detail += "assignments unreadable (HTTP $(Get-HttpStatusFromError $_))" }
            }
            $incompat = ''
            try { $incompat = Join-Values ((Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/{0}/incompatibleAccessPackages?`$select=id,displayName" -f $a.id) -Label "incompatible $($a.id)") | ForEach-Object { $_.displayName }) }
            catch { $apDetailFailures++; $detail += "incompatible packages unreadable (HTTP $(Get-HttpStatusFromError $_))"; $incompat = 'unreadable' }
            [pscustomobject][ordered]@{
                AccessPackage       = $a.displayName
                Catalog             = $(if ($a.catalog) { $a.catalog.displayName } else { '' })
                IsHidden            = $a.isHidden
                Policies            = $pols.Count
                AnyApprovalRequired = [bool](@($pols | Where-Object { $_.requestApprovalSettings -and $_.requestApprovalSettings.isApprovalRequiredForAdd }).Count)
                AnyReviewConfigured = [bool](@($pols | Where-Object { $_.reviewSettings -and $_.reviewSettings.isEnabled }).Count)
                AnyNoExpiration     = [bool](@($pols | Where-Object { $_.expiration -and "$($_.expiration.type)" -eq 'noExpiration' }).Count)
                AllowedTargetScopes = Join-Values ($pols | ForEach-Object { $_.allowedTargetScope } | Select-Object -Unique)
                Modified            = $a.modifiedDateTime
                ResourceRoles       = $roleCount
                AssignmentsDelivered = $delivered
                AssignmentsTotal    = $totalAsg
                IncompatiblePackages = $incompat
                DetailStatus        = $(if ($detail.Count) { $detail -join '; ' } else { 'Completed' })
            }
        }
        Export-Dataset -Name 'access-packages' -Rows $apRows -Status $(if ($apDetailFailures) { 'Partial' } else { 'Completed' }) -Note (@($(if ($SkipAccessPackageAssignments) { 'Assignment counts skipped (-SkipAccessPackageAssignments)' }), $(if ($apDetailFailures) { "$apDetailFailures detail read(s) failed: see DetailStatus" })) -join '; ').Trim('; ')
        $resFail = @($apRows | Where-Object { $_.DetailStatus -match 'resources unreadable' }).Count
        if (@($aps).Count -and $resFail -ge @($aps).Count) { Set-DatasetStatus -Name 'access-package-resources' -Status 'Blocked' -Note 'resourceRoleScopes not readable' }
        else { Export-Dataset -Name 'access-package-resources' -Rows $resRows -Status $(if ($resFail) { 'Partial' } else { 'Completed' }) -Note $(if ($resFail) { "$resFail package(s) unreadable" } else { 'One row per resource role an access package grants' }) }
    }
    catch {
        $st = Get-FailureStatus $_
        Set-DatasetStatus -Name 'access-packages' -Status $st -Note $_.Exception.Message
        Set-DatasetStatus -Name 'access-package-resources' -Status $st -Note 'Depends on access-packages'
    }

    # ---- 4. Lifecycle workflows ----
    $lwRows = [System.Collections.Generic.List[object]]::new()
    if ($SkipLifecycleWorkflows) { Set-DatasetStatus -Name 'lifecycle-workflows' -Status 'Deferred' -Note 'Skipped (-SkipLifecycleWorkflows)' }
    else {
        try {
            $taskFailures = 0
            foreach ($w in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows' -Label 'lifecycleWorkflows')) {
                $tasks = $null; $tStatus = 'Completed'
                try { $tasks = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/{0}/tasks" -f $w.id) -Label "workflowTasks $($w.id)" }
                catch { $taskFailures++; $tStatus = "Unreadable (HTTP $(Get-HttpStatusFromError $_))" }
                $lwRows.Add([pscustomobject][ordered]@{
                    Workflow            = $w.displayName
                    Category            = $w.category
                    IsEnabled           = $w.isEnabled
                    IsSchedulingEnabled = $w.isSchedulingEnabled
                    TaskCount           = $(if ($null -ne $tasks) { $tasks.Count } else { '' })
                    Tasks               = Join-Values (@($tasks) | Where-Object { $_ } | Sort-Object executionSequence | ForEach-Object { if ($_.isEnabled -eq $false) { "$($_.displayName) (disabled)" } else { "$($_.displayName)" } })
                    TasksStatus         = $tStatus
                    Version             = $w.version
                    Created             = $w.createdDateTime
                    LastModified        = $w.lastModifiedDateTime
                })
            }
            Export-Dataset -Name 'lifecycle-workflows' -Rows $lwRows -Status $(if ($taskFailures) { 'Partial' } else { 'Completed' }) -Note $(if ($taskFailures) { "Tasks unreadable for $taskFailures workflow(s)" } else { '' })
        }
        catch { Set-DatasetStatus -Name 'lifecycle-workflows' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }
    }

    # ---- 5. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Access review definitions' $defRows.Count
    Add-Metric 'Recurring reviews' @($defRows | Where-Object { $_.Recurrence -ne 'One-time' }).Count
    Add-Metric 'Reviews without auto-apply' @($defRows | Where-Object { -not $_.AutoApplyResults }).Count -Note 'Decisions must be applied manually'
    Add-Metric 'Self-reviews' @($defRows | Where-Object { $_.Flags -match 'SelfReview' }).Count -Note 'Users attest their own access'
    Add-Metric 'Manager reviews without fallback reviewers' @($defRows | Where-Object { $_.Flags -match 'ManagerNoFallback' }).Count -Note 'Users without a manager are not reviewed'
    Add-Metric 'Guest-only reviews' @($defRows | Where-Object { $_.CoversMembers -eq 'GuestsOnly' }).Count
    Add-Metric 'Azure resource reviews' @($defRows | Where-Object { $_.TargetType -eq 'AzureResource' }).Count -Note 'Not part of the coverage list; see script 11 for Azure RBAC'
    if ($instFailures) { Add-Metric 'Reviews whose instances could not be read' $instFailures }
    foreach ($t in 'Application', 'Group', 'DirectoryRole') {
        $all = @($covRows | Where-Object TargetType -eq $t)
        $cv = @($all | Where-Object Covered).Count
        Add-Metric "$t targets in scope" $all.Count
        Add-Metric "$t targets covered (%)" $(if ($all.Count -and $reviewsAvailable) { [math]::Round(100 * $cv / $all.Count, 1) } else { '' }) -Note ("{0} of {1}" -f $cv, $all.Count)
    }
    $t0 = @($covRows | Where-Object { $_.Tier0 -eq $true })
    Add-Metric 'Tier 0 roles and groups covered (%)' $(if ($t0.Count -and $reviewsAvailable) { [math]::Round(100 * @($t0 | Where-Object Covered).Count / $t0.Count, 1) } else { '' }) -Note ("{0} of {1}" -f @($t0 | Where-Object Covered).Count, $t0.Count)
    if ($InScopeAppsCsv) { Add-Metric 'In-scope list apps not found in tenant' $notFound.Count }
    if ($IncludeDecisionStats -and $statRows.Count) {
        $avg = ($statRows | Where-Object { $_.CompletionPct -ne '' } | Measure-Object CompletionPct -Average).Average
        Add-Metric 'Average completion of latest instances (%)' $(if ($null -ne $avg) { [math]::Round($avg, 1) } else { '' })
        Add-Metric 'Decisions that failed to apply' ($statRows | Measure-Object ApplyFailed -Sum).Sum
    }
    Add-Metric 'Access packages' @($apRows).Count
    Add-Metric 'Access packages with no expiration policy' @($apRows | Where-Object AnyNoExpiration).Count
    Add-Metric 'Access packages with built-in reviews' @($apRows | Where-Object AnyReviewConfigured).Count
    Add-Metric 'Access packages granting a role-assignable or role-holding group' @($resRows | Where-Object { $targetIndex.ContainsKey(('Group|{0}' -f "$($_.ResourceOriginId)".ToLowerInvariant())) } | Select-Object -ExpandProperty AccessPackage -Unique).Count
    if (-not $SkipAccessPackageAssignments) { Add-Metric 'Access package assignments delivered' (@($apRows | Where-Object { $_.AssignmentsDelivered -is [int] }) | Measure-Object AssignmentsDelivered -Sum).Sum }
    if (-not $SkipLifecycleWorkflows) {
        foreach ($cat in 'joiner', 'mover', 'leaver') { Add-Metric "Enabled $cat workflows" @($lwRows | Where-Object { $_.Category -eq $cat -and $_.IsEnabled -eq $true }).Count }
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ IncludeDecisionStats = [bool]$IncludeDecisionStats; SkipGuestGroups = [bool]$SkipGuestGroups; InScopeAppsCsv = $(if ($InScopeAppsCsv) { Split-Path $InScopeAppsCsv -Leaf } else { '' }); SkipAccessPackageAssignments = [bool]$SkipAccessPackageAssignments; SkipLifecycleWorkflows = [bool]$SkipLifecycleWorkflows }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
