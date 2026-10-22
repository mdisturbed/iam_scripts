<#
.SYNOPSIS
    Read-only export of Privileged Identity Management (PIM) settings for Entra directory roles and
    for PIM for Groups: what it actually takes to activate each role, who approves, whether the
    authentication context is really enforced, and whether permanent assignment is allowed.

.DESCRIPTION
    PIM only reduces risk if activation is hard enough. For every directory role this exports
    the role management policy rules:

      - Activation: maximum duration, MFA required, justification, ticket information,
        approval required (approvers resolved to accounts, groups expanded), authentication
        context required and whether an enabled Conditional Access policy enforces it
      - Eligible assignment: whether it can be permanent, maximum duration if not
      - Active assignment: whether it can be permanent, MFA / justification on admin assignment
      - Notifications: whether admins, approvers and requestors are alerted on activation and
        assignment
    The same settings are exported for PIM for Groups (member and owner) on every group that
    holds a directory role, every role-assignable group, and any group passed in -PimGroupIds.

    Roles are flagged when activation has no approval, has no MFA or enforced authentication
    context, lasts longer than -MaxActivationHours, raises no admin alert, permanent assignment
    is allowed, or an approver is also eligible for the role. Tier 0 roles carry Tier0-prefixed
    flags; every other role that has holders in the effective privileged set is flagged too.
    Active, activated-now and eligible counts are added so settings can be prioritised. Open PIM
    alerts for directory roles are exported when readable.

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\22-PimRoleSettings\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\22-Get-PimRoleSettings.ps1
.EXAMPLE
    .\22-Get-PimRoleSettings.ps1 -OnlyAssignedRoles -MaxActivationHours 4
.EXAMPLE
    .\22-Get-PimRoleSettings.ps1 -PimGroupIds '00000000-0000-0000-0000-000000000001'

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : RoleManagementPolicy.Read.Directory, RoleManagement.Read.Directory, Directory.Read.All,
              Policy.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup,
              RoleManagementPolicy.Read.AzureADGroup, RoleManagementAlert.Read.Directory
    Licence : Entra ID P2 / ID Governance (PIM)
    Scope   : Directory roles and PIM for Groups. Azure resource roles are configured per scope
              and are not covered here.
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

    [int]$MaxActivationHours = 8,
    [switch]$OnlyAssignedRoles,
    [string[]]$PimGroupIds = @(),
    [switch]$SkipPimGroups,
    [switch]$SkipAlerts
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '22-PimRoleSettings'
$ScriptVersion = '1.1.0'
$RequiredScopes = @('RoleManagementPolicy.Read.Directory', 'RoleManagement.Read.Directory', 'Directory.Read.All', 'Policy.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
if (-not $SkipPimGroups) { $RequiredScopes += 'RoleManagementPolicy.Read.AzureADGroup' }
if (-not $SkipAlerts) { $RequiredScopes += 'RoleManagementAlert.Read.Directory' }

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

function Test-LicenceError {
    # True when a failed Graph call failed because the tenant lacks the licence for the feature.
    param($ErrorRecord)
    $msg = "$($ErrorRecord.Exception.Message) $($ErrorRecord.ErrorDetails.Message)"
    return [bool]($msg -match 'premium|licen[cs]e|not licensed|not available for this tenant')
}


function Get-EffectivePrivilegedSet {
    # Builds the effective privileged set once. Returns $null (and logs) when role data cannot be read at all.
    $script:PrivSetError = ''
    $script:PrivSetErrorStatus = 'Blocked'
    try {
        $set = Get-PrivilegedPrincipalSet
        Write-RunLog ("Effective privileged set: {0} rows, {1} principals. Sources: {2}" -f $set.Rows.Count, $set.ByPrincipal.Count, (Get-PrivSetStatusText $set))
        return $set
    }
    catch {
        $script:PrivSetErrorStatus = $(if (Test-LicenceError $_) { 'EvidenceUnavailable' } else { 'Blocked' })
        $script:PrivSetError = "HTTP $(Get-HttpStatusFromError $_): $($_.Exception.Message)"
        Write-RunLog ("Effective privileged set not readable; privilege columns left blank. {0}" -f $_.Exception.Message) 'WARN'
        return $null
    }
}

function Get-PrivSetStatusText {
    param($Set)
    if (-not $Set) { return '' }
    return (@($Set.Status.Keys | ForEach-Object { '{0}={1}' -f $_, $Set.Status[$_] }) -join '; ')
}

function Test-PrivSetComplete {
    # True when every source of the privileged set completed (or was skipped on purpose).
    param($Set)
    if (-not $Set) { return $false }
    return -not [bool](@($Set.Status.Values | Where-Object { "$_" -notmatch '^(Completed|Skipped)' }).Count)
}

function Test-RowEffectiveForCa {
    # Conditional Access directory-role conditions see active (or activated) assignments, direct or
    # through a role-assignable group. Eligible-only and group-owner paths do not count until used.
    param($Row)
    return [bool](("$($Row.AssignmentState)" -match '^(Active|Activated)') -and ("$($Row.AssignmentState)" -notmatch 'owner can add self') -and ($Row.Via -in @('Direct', 'Group member')))
}

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

function ConvertFrom-IsoDuration {
    # 'PT8H' / 'P1D' / 'PT30M' / 'P365D' -> hours (double), '' if empty
    param([string]$Value)
    if (-not $Value) { return '' }
    try { return [math]::Round([System.Xml.XmlConvert]::ToTimeSpan($Value).TotalHours, 2) } catch { return $Value }
}

function Test-NotificationOn {
    # A notification rule is on when default recipients are enabled or extra recipients are listed.
    param($Rule)
    if (-not $Rule) { return '' }
    return [bool]((Get-OptionalValue $Rule 'isDefaultRecipientsEnabled') -or @(Get-OptionalValue $Rule 'notificationRecipients' | Where-Object { $_ }).Count)
}

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- Role names and assignment counts (Assigned vs Activated split) ----
    $roles = @{}
    foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn' -Label 'roleDefinitions')) { $roles[$r.id] = $r; if ($r.templateId) { $roles[$r.templateId] = $r } }
    $activeCount = @{}; $activatedCount = @{}; $eligibleCount = @{}; $countsAvailable = $true
    try {
        foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$select=roleDefinitionId,assignmentType' -Label 'activeInstances')) {
            $k = $a.roleDefinitionId
            if ("$($a.assignmentType)" -eq 'Activated') { $activatedCount[$k] = 1 + $(if ($activatedCount.ContainsKey($k)) { $activatedCount[$k] } else { 0 }) }
            else { $activeCount[$k] = 1 + $(if ($activeCount.ContainsKey($k)) { $activeCount[$k] } else { 0 }) }
        }
        foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$select=roleDefinitionId' -Label 'eligibleInstances')) { $k = $a.roleDefinitionId; $eligibleCount[$k] = 1 + $(if ($eligibleCount.ContainsKey($k)) { $eligibleCount[$k] } else { 0 }) }
    }
    catch { $countsAvailable = $false; Write-RunLog ("Assignment counts unavailable ({0})" -f $_.Exception.Message) 'WARN' }

    # ---- Effective privileged set: who really holds each role ----
    $privSet = Get-EffectivePrivilegedSet
    $setByRole = @{}
    if ($privSet) {
        foreach ($r in $privSet.Rows) {
            if ($r.PrincipalType -eq 'group') { continue }
            if (-not $setByRole.ContainsKey($r.Role)) { $setByRole[$r.Role] = @{} }
            $setByRole[$r.Role][$r.PrincipalId] = $true
        }
    }

    # ---- Authentication contexts and the CA policies that enforce them ----
    $ctxRefs = @{}
    $ctxError = ''
    try { foreach ($c in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences' -Label 'authContexts')) { $ctxRefs["$($c.id)"] = $c } }
    catch { $ctxError = 'HTTP {0}' -f (Get-HttpStatusFromError $_); Write-RunLog ("Authentication contexts not readable ({0})" -f $_.Exception.Message) 'WARN' }
    $caPolicies = $null
    $caError = ''
    try { $caPolicies = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'caPolicies' }
    catch { $caError = 'HTTP {0}' -f (Get-HttpStatusFromError $_); Write-RunLog ("CA policies not readable; authentication context enforcement not evaluated ({0})" -f $_.Exception.Message) 'WARN' }
    function Get-AuthContextView {
        param([string]$Claim)
        $name = $(if ($ctxRefs.ContainsKey($Claim)) { "$($ctxRefs[$Claim].displayName)" } elseif ($ctxError) { "$Claim (unresolved: $ctxError)" } else { "$Claim (not defined)" })
        if ($null -eq $caPolicies) { return [pscustomobject]@{ Name = $name; Enforced = "Unknown (CA not readable: $caError)"; Grant = '' } }
        $hits = @($caPolicies | Where-Object { "$($_.state)" -eq 'enabled' -and @(Get-OptionalValue $_.conditions.applications 'includeAuthenticationContextClassReferences') -contains $Claim })
        $grant = Join-Values ($hits | ForEach-Object {
                $g = $_.grantControls
                $parts = @()
                if ($g) {
                    $parts += @($g.builtInControls | Where-Object { $_ })
                    $as = Get-OptionalValue $g 'authenticationStrength'
                    if ($as) { $parts += "authStrength: $($as.displayName)" }
                }
                '{0} [{1}]' -f $_.displayName, (Join-Values $parts)
            })
        return [pscustomobject]@{ Name = $name; Enforced = [bool]$hits.Count; Grant = $grant }
    }

    # ---- Approver resolution (groups expanded to accounts) ----
    $memberCache = @{}
    function Get-GroupAccounts {
        param([string]$GroupId)
        if ($memberCache.ContainsKey($GroupId)) { return $memberCache[$GroupId] }
        $out = [System.Collections.Generic.List[object]]::new()
        try {
            foreach ($m in (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers?`$select=id,displayName,userPrincipalName" -f $GroupId) -Label "transitiveMembers $GroupId")) {
                if ("$($m.'@odata.type')" -eq '#microsoft.graph.group') { continue }
                $out.Add([pscustomobject]@{ Id = "$($m.id)"; Label = $(if ((Get-OptionalValue $m 'userPrincipalName')) { "$($m.userPrincipalName)" } else { "$($m.displayName)" }) })
            }
        }
        catch { $out = $null; Write-RunLog ("Members of approver group {0} not readable: {1}" -f $GroupId, $_.Exception.Message) 'WARN' }
        $memberCache[$GroupId] = $out
        return $out
    }
    function Get-ApproverView {
        param($ApprovalRule)
        $names = @(); $accounts = @{}; $issues = @()
        if (-not ($ApprovalRule -and $ApprovalRule.setting -and $ApprovalRule.setting.isApprovalRequired)) { return [pscustomobject]@{ Names = ''; Accounts = @{}; Issues = '' } }
        foreach ($stage in @($ApprovalRule.setting.approvalStages)) {
            $list = @($stage.primaryApprovers)
            if ((Get-OptionalValue $stage 'isEscalationEnabled')) { $list += @(Get-OptionalValue $stage 'escalationApprovers') }
            foreach ($ap in $list) {
                if (-not $ap) { continue }
                $t = ("$($ap.'@odata.type')" -replace '#microsoft.graph.', '')
                $uid = "$(Get-OptionalValue $ap 'userId')"
                $gid = "$(Get-OptionalValue $ap 'groupId')"
                if ($uid) {
                    $p = Get-PrivPrincipal $uid
                    $label = $(if ($p.Upn) { $p.Upn } else { $p.Name })
                    $names += $label
                    if ($p.Error -or -not $p.Exists) { $issues += $label } else { $accounts[$uid] = $label }
                }
                elseif ($gid) {
                    $g = Get-PrivPrincipal $gid
                    $names += "group: $($g.Name)"
                    $mem = Get-GroupAccounts $gid
                    if ($null -eq $mem) { $issues += "group $($g.Name) members not readable" }
                    else { foreach ($m in $mem) { $accounts[$m.Id] = $m.Label } }
                }
                else { $names += $(if ($ap.description) { "$($ap.description)" } else { $t }) }
            }
        }
        return [pscustomobject]@{ Names = (Join-Values ($names | Select-Object -Unique)); Accounts = $accounts; Issues = (Join-Values $issues) }
    }

    # ---- Row builder shared by directory roles and PIM for Groups ----
    function New-SettingsRow {
        param($Rules, [string]$Name, $IsTier0, $IsBuiltIn, $Act, $Activated, $Elg, [bool]$HasHolders, $Holders, $Effective, [string]$PolicyId)
        $actExp = $Rules['Expiration_EndUser_Assignment']
        $actEnable = $Rules['Enablement_EndUser_Assignment']
        $approval = $Rules['Approval_EndUser_Assignment']
        $authCtx = $Rules['AuthenticationContext_EndUser_Assignment']
        $eligExp = $Rules['Expiration_Admin_Eligibility']
        $activeExp = $Rules['Expiration_Admin_Assignment']
        $adminEnable = $Rules['Enablement_Admin_Assignment']

        $enabled = @(); if ($actEnable) { $enabled = @($actEnable.enabledRules) }
        $adminEnabled = @(); if ($adminEnable) { $adminEnabled = @($adminEnable.enabledRules) }
        $approvalRequired = [bool]($approval -and $approval.setting -and $approval.setting.isApprovalRequired)
        $apv = Get-ApproverView $approval
        $authCtxOn = [bool]($authCtx -and $authCtx.isEnabled)
        $acv = $(if ($authCtxOn) { Get-AuthContextView "$($authCtx.claimValue)" } else { [pscustomobject]@{ Name = ''; Enforced = ''; Grant = '' } })
        $maxActHours = $(if ($actExp) { ConvertFrom-IsoDuration $actExp.maximumDuration } else { '' })
        $eligPermanent = [bool]($eligExp -and -not $eligExp.isExpirationRequired)
        $activePermanent = [bool]($activeExp -and -not $activeExp.isExpirationRequired)
        $mfaOn = ($enabled -contains 'MultiFactorAuthentication')
        $ctxProtects = $authCtxOn -and ("$($acv.Enforced)" -ne 'False')
        $notifyAdminAct = Test-NotificationOn $Rules['Notification_Admin_EndUser_Assignment']
        $conflicts = @()
        if ($Holders) { $conflicts = @($apv.Accounts.Keys | Where-Object { $Holders.ContainsKey($_) } | ForEach-Object { $apv.Accounts[$_] }) }

        $flags = @()
        $prefix = $(if ($IsTier0 -eq $true) { 'Tier0' } elseif ($HasHolders) { '' } else { $null })
        if ($null -ne $prefix) {
            if (-not $approvalRequired) { $flags += "${prefix}NoApproval" }
            if (-not $mfaOn -and -not $ctxProtects) { $flags += "${prefix}NoMfaOrAuthContext" }
            if ($maxActHours -ne '' -and $maxActHours -gt $MaxActivationHours) { $flags += "${prefix}ActivationOver${MaxActivationHours}h" }
            if ($activePermanent) { $flags += "${prefix}PermanentActiveAllowed" }
            if ($eligPermanent) { $flags += "${prefix}PermanentEligibleAllowed" }
            if ($authCtxOn -and "$($acv.Enforced)" -eq 'False') { $flags += "${prefix}AuthContextNotEnforcedByCa" }
            if ($notifyAdminAct -eq $false) { $flags += "${prefix}NoActivationAlert" }
            if ($conflicts.Count) { $flags += "${prefix}ApproverAlsoEligible" }
        }
        if (-not ($enabled -contains 'Justification')) { $flags += 'NoJustification' }
        if ("$Act" -ne '' -and $Act -gt 0 -and "$Elg" -ne '' -and $Elg -eq 0 -and $IsTier0 -eq $true) { $flags += 'Tier0OnlyActiveAssignments' }

        [pscustomobject][ordered]@{
            RoleName                     = $Name
            IsTier0                      = $IsTier0
            IsBuiltIn                    = $IsBuiltIn
            ActiveAssignments            = $Act
            EligibleAssignments          = $Elg
            MaxActivationHours           = $maxActHours
            ActivationRequiresMfa        = $mfaOn
            ActivationRequiresJustification = ($enabled -contains 'Justification')
            ActivationRequiresTicket     = ($enabled -contains 'Ticketing')
            ActivationRequiresAuthContext = $authCtxOn
            AuthContextClaim             = $(if ($authCtxOn) { $authCtx.claimValue } else { '' })
            ApprovalRequired             = $approvalRequired
            Approvers                    = $apv.Names
            PermanentEligibleAllowed     = $eligPermanent
            MaxEligibleDays              = $(if ($eligExp -and $eligExp.isExpirationRequired) { [math]::Round((ConvertFrom-IsoDuration $eligExp.maximumDuration) / 24, 0) } else { '' })
            PermanentActiveAllowed       = $activePermanent
            MaxActiveDays                = $(if ($activeExp -and $activeExp.isExpirationRequired) { [math]::Round((ConvertFrom-IsoDuration $activeExp.maximumDuration) / 24, 0) } else { '' })
            AdminAssignmentRequiresMfa   = ($adminEnabled -contains 'MultiFactorAuthentication')
            Flags                        = Join-Values $flags
            PolicyId                     = $PolicyId
            ActivatedNow                 = $Activated
            EffectivePrincipals          = $Effective
            ApproverAccounts             = Join-Values ($apv.Accounts.Values | Sort-Object -Unique)
            ApproverAlsoEligible         = $(if ($approvalRequired -and $Holders) { [bool]$conflicts.Count } else { '' })
            ApproverConflicts            = Join-Values $conflicts
            ApproverIssues               = $apv.Issues
            AuthContextName              = $acv.Name
            AuthContextEnforcedByCa      = $acv.Enforced
            AuthContextGrant             = $acv.Grant
            NotifyAdminOnActivation      = $notifyAdminAct
            NotifyApproverOnActivation   = Test-NotificationOn $Rules['Notification_Approver_EndUser_Assignment']
            NotifyRequestorOnActivation  = Test-NotificationOn $Rules['Notification_Requestor_EndUser_Assignment']
            NotifyAdminOnEligibleAssignment = Test-NotificationOn $Rules['Notification_Admin_Admin_Eligibility']
            NotifyAdminOnActiveAssignment = Test-NotificationOn $Rules['Notification_Admin_Admin_Assignment']
            ActivationAlertRecipients    = $(if ($Rules['Notification_Admin_EndUser_Assignment']) { Join-Values (Get-OptionalValue $Rules['Notification_Admin_EndUser_Assignment'] 'notificationRecipients') } else { '' })
        }
    }

    # ---- 1. Directory role policies ----
    $rows = [System.Collections.Generic.List[object]]::new()
    $uri = 'https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?$filter=' + [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole'") + '&$expand=policy($expand=rules)'
    $assignments = Invoke-GraphGetAll -Uri $uri -Label 'roleManagementPolicyAssignments'
    Write-RunLog ("{0} role policies read" -f $assignments.Count)
    foreach ($pa in $assignments) {
        $rid = $pa.roleDefinitionId
        $role = $roles[$rid]
        $name = $(if ($role) { $role.displayName } else { $rid })
        $template = $(if ($role -and $role.templateId) { $role.templateId } else { $rid })
        $act = $(if ($activeCount.ContainsKey($rid)) { $activeCount[$rid] } else { 0 })
        $actd = $(if ($activatedCount.ContainsKey($rid)) { $activatedCount[$rid] } else { 0 })
        $elg = $(if ($eligibleCount.ContainsKey($rid)) { $eligibleCount[$rid] } else { 0 })
        $holders = $(if ($setByRole.ContainsKey($name)) { $setByRole[$name] } else { $null })
        $hasHolders = [bool]($holders -and $holders.Count) -or (($act + $actd + $elg) -gt 0)
        if ($OnlyAssignedRoles -and -not $hasHolders) { continue }
        $rules = @{}
        foreach ($rule in @($pa.policy.rules)) { $rules[$rule.id] = $rule }
        $rows.Add((New-SettingsRow -Rules $rules -Name $name -IsTier0 $script:Tier0RoleTemplates.ContainsKey("$template") -IsBuiltIn $(if ($role) { $role.isBuiltIn } else { '' }) `
                    -Act $(if ($countsAvailable) { $act } else { '' }) -Activated $(if ($countsAvailable) { $actd } else { '' }) -Elg $(if ($countsAvailable) { $elg } else { '' }) `
                    -HasHolders $hasHolders -Holders $holders -Effective $(if ($privSet) { $(if ($holders) { $holders.Count } else { 0 }) } else { '' }) -PolicyId $pa.policyId))
    }
    $rows = @($rows | Sort-Object @{ Expression = 'IsTier0'; Descending = $true }, @{ Expression = { [int]("$($_.ActiveAssignments)" -replace '^$', '0') + [int]("$($_.EligibleAssignments)" -replace '^$', '0') }; Descending = $true }, RoleName)
    $rsNotes = @($(if ($OnlyAssignedRoles) { 'Roles with at least one assignment' } else { 'All directory roles' }))
    if (-not $privSet) { $rsNotes += "effective holders unknown (privileged set not readable: $script:PrivSetError)" }
    elseif (-not (Test-PrivSetComplete $privSet)) { $rsNotes += "privileged set incomplete: $(Get-PrivSetStatusText $privSet)" }
    if ($caError) { $rsNotes += "auth context enforcement not evaluated (CA policies $caError)" }
    $rsPartial = (-not $privSet) -or (-not (Test-PrivSetComplete $privSet)) -or [bool]$caError -or -not $countsAvailable
    Export-Dataset -Name 'pim-role-settings' -Rows $rows -Status $(if ($rsPartial) { 'Partial' } else { 'Completed' }) -Note ($rsNotes -join '; ')

    # ---- 2. PIM for Groups policies ----
    $groupRows = [System.Collections.Generic.List[object]]::new()
    if ($SkipPimGroups) { Set-DatasetStatus -Name 'pim-group-settings' -Status 'Deferred' -Note '-SkipPimGroups' }
    else {
        $groups = [ordered]@{}
        if ($privSet) { foreach ($g in $privSet.RoleGroupIds) { $groups["$g"] = 'Holds a directory role' } }
        try {
            foreach ($g in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true&$count=true&$select=id,displayName' -Eventual -Label 'roleAssignableGroups')) {
                if (-not $groups.Contains("$($g.id)")) { $groups["$($g.id)"] = 'Role-assignable' }
            }
        }
        catch { Write-RunLog ("Role-assignable groups not readable ({0}); only role-holding groups checked." -f $_.Exception.Message) 'WARN' }
        foreach ($g in $PimGroupIds) { if ($g -and -not $groups.Contains($g)) { $groups[$g] = 'Requested (-PimGroupIds)' } }
        $grpBlocked = ''
        $grpIssues = 0
        foreach ($gid in @($groups.Keys)) {
            $gp = Get-PrivPrincipal $gid
            $guri = 'https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?$filter=' + [uri]::EscapeDataString("scopeId eq '$gid' and scopeType eq 'Group'") + '&$expand=policy($expand=rules)'
            try { $gpa = Invoke-GraphGetAll -Uri $guri -Label "groupPolicy $gid" }
            catch {
                $code = Get-HttpStatusFromError $_
                if ($code -eq 403 -or (Test-LicenceError $_)) { $grpBlocked = '{0}: {1}' -f $(if (Test-LicenceError $_) { 'EvidenceUnavailable' } else { 'Blocked' }), $_.Exception.Message; break }
                $grpIssues++; Write-RunLog ("PIM for Groups policy of {0} not readable: {1}" -f $gp.Name, $_.Exception.Message) 'WARN'; continue
            }
            if (-not $gpa.Count) { continue }
            # Eligible members / owners of the group, expanded when the eligible principal is a group
            $elgBy = @{ member = @{}; owner = @{} }
            $elgRead = $true
            try {
                foreach ($e in (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '{0}'" -f $gid) -Label "pimGroupEligibility $gid")) {
                    $acc = $(if ("$($e.accessId)" -eq 'owner') { 'owner' } else { 'member' })
                    $ep = Get-PrivPrincipal "$($e.principalId)"
                    if ($ep.Type -eq 'group') { $mem = Get-GroupAccounts $ep.Id; foreach ($m in @($mem)) { if ($m) { $elgBy[$acc][$m.Id] = $true } } }
                    else { $elgBy[$acc][$ep.Id] = $true }
                }
            }
            catch { $elgRead = $false; $grpIssues++; Write-RunLog ("PIM for Groups eligibility of {0} not readable: {1}" -f $gp.Name, $_.Exception.Message) 'WARN' }
            $holdsTier0 = $(if ($privSet) { [bool](@($privSet.Rows | Where-Object { $_.PrincipalId -eq $gid -and $_.Tier0 }).Count) } else { '' })
            foreach ($pa in $gpa) {
                $acc = "$($pa.roleDefinitionId)"
                $rules = @{}
                foreach ($rule in @($pa.policy.rules)) { $rules[$rule.id] = $rule }
                $holders = $(if ($elgRead) { $elgBy[$(if ($acc -eq 'owner') { 'owner' } else { 'member' })] } else { $null })
                $elgN = $(if ($elgRead) { $holders.Count } else { '' })
                $hasHolders = [bool]($groups[$gid] -eq 'Holds a directory role') -or ("$elgN" -ne '' -and $elgN -gt 0)
                $row = New-SettingsRow -Rules $rules -Name ('{0} ({1})' -f $gp.Name, $acc) -IsTier0 $holdsTier0 -IsBuiltIn '' -Act '' -Activated '' -Elg $elgN -HasHolders $hasHolders -Holders $holders -Effective '' -PolicyId $pa.policyId
                $row | Add-Member -NotePropertyName GroupId -NotePropertyValue $gid
                $row | Add-Member -NotePropertyName GroupName -NotePropertyValue $gp.Name
                $row | Add-Member -NotePropertyName AccessId -NotePropertyValue $acc
                $row | Add-Member -NotePropertyName WhyIncluded -NotePropertyValue $groups[$gid]
                $groupRows.Add($row)
            }
        }
        if ($grpBlocked) { Set-DatasetStatus -Name 'pim-group-settings' -Status $(if ($grpBlocked -like 'EvidenceUnavailable*') { 'EvidenceUnavailable' } else { 'Blocked' }) -Note ("PIM for Groups policies not readable ({0}). Needs RoleManagementPolicy.Read.AzureADGroup." -f $grpBlocked) }
        else { Export-Dataset -Name 'pim-group-settings' -Rows $groupRows -Status $(if ($grpIssues) { 'Partial' } else { 'Completed' }) -Note ("{0} group(s) checked; ActiveAssignments not collected for groups{1}" -f $groups.Count, $(if ($grpIssues) { "; $grpIssues read(s) failed" } else { '' })) }
    }

    # ---- 3. PIM alerts for directory roles ----
    $alertRows = @()
    $alertsRead = $false
    if ($SkipAlerts) { Set-DatasetStatus -Name 'pim-alerts' -Status 'Deferred' -Note '-SkipAlerts' }
    else {
        try {
            $al = Invoke-GraphGetAll -Uri ('https://graph.microsoft.com/beta/identityGovernance/roleManagementAlerts/alerts?$filter=' + [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole'") + '&$expand=alertDefinition') -Label 'pimAlerts'
            $alertsRead = $true
            $alertRows = foreach ($a in $al) {
                $def = Get-OptionalValue $a 'alertDefinition'
                [pscustomobject][ordered]@{
                    AlertId          = $a.id
                    AlertDefinitionId = Get-OptionalValue $a 'alertDefinitionId'
                    AlertName        = $(if ($def) { $def.displayName } else { '' })
                    Severity         = $(if ($def) { Get-OptionalValue $def 'severityLevel' } else { '' })
                    IsActive         = $a.isActive
                    IncidentCount    = Get-OptionalValue $a 'incidentCount'
                    LastScannedUtc   = ConvertTo-UtcText (Get-OptionalValue $a 'lastScannedDateTime')
                    LastModifiedUtc  = ConvertTo-UtcText (Get-OptionalValue $a 'lastModifiedDateTime')
                    SecurityImpact   = $(if ($def) { Get-OptionalValue $def 'securityImpact' } else { '' })
                    MitigationSteps  = $(if ($def) { Get-OptionalValue $def 'mitigationSteps' } else { '' })
                }
            }
            $alertRows = @($alertRows | Sort-Object @{ Expression = { "$($_.IsActive)" -ne 'True' } }, @{ Expression = { @{ high = 0; medium = 1; low = 2 }["$($_.Severity)"] } })
            Export-Dataset -Name 'pim-alerts' -Rows $alertRows -Note 'Directory role alerts (beta endpoint)'
        }
        catch {
            Set-DatasetStatus -Name 'pim-alerts' -Status $(if (Test-LicenceError $_) { 'EvidenceUnavailable' } else { Get-FailureStatus $_ }) -Note ("PIM alerts not readable (needs RoleManagementAlert.Read.Directory and P2): {0}" -f $_.Exception.Message)
        }
    }

    # ---- 4. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $t0 = @($rows | Where-Object IsTier0)
    $held = @($rows | Where-Object { "$($_.EffectivePrincipals)" -ne '' -and $_.EffectivePrincipals -gt 0 })
    Add-Metric 'Roles reported' $rows.Count
    Add-Metric 'Tier 0 roles reported' $t0.Count
    Add-Metric 'Tier 0 roles activatable without approval' @($t0 | Where-Object { -not $_.ApprovalRequired }).Count
    Add-Metric 'Tier 0 roles without MFA or auth context on activation' @($t0 | Where-Object { $_.Flags -match 'Tier0NoMfaOrAuthContext' }).Count -Note 'An authentication context counts only when an enabled CA policy enforces it'
    Add-Metric "Tier 0 roles with activation over $MaxActivationHours h" @($t0 | Where-Object { $_.Flags -match 'Tier0ActivationOver' }).Count
    Add-Metric 'Tier 0 roles allowing permanent active assignment' @($t0 | Where-Object PermanentActiveAllowed).Count
    Add-Metric 'Tier 0 roles allowing permanent eligibility' @($t0 | Where-Object PermanentEligibleAllowed).Count
    Add-Metric 'Roles using an authentication context' @($rows | Where-Object ActivationRequiresAuthContext).Count -Note 'Lets CA require phishing-resistant MFA or a compliant device at activation'
    Add-Metric 'Roles whose authentication context no enabled CA policy enforces' @($rows | Where-Object { "$($_.AuthContextEnforcedByCa)" -eq 'False' }).Count
    Add-Metric 'Roles requiring a ticket number on activation' @($rows | Where-Object ActivationRequiresTicket).Count
    if ($countsAvailable) { Add-Metric 'Role activations in use now' (@($rows | ForEach-Object { [int]("$($_.ActivatedNow)" -replace '^$', '0') }) | Measure-Object -Sum).Sum }
    if ($privSet) {
        Add-Metric 'Roles with holders in the effective privileged set' $held.Count
        Add-Metric 'Held roles activatable without approval' @($held | Where-Object { -not $_.ApprovalRequired }).Count
        Add-Metric 'Roles where an approver is also eligible' @($rows | Where-Object { $_.ApproverAlsoEligible -eq $true }).Count -Note 'Approver can approve their own path to the role'
    }
    Add-Metric 'Held roles with no admin alert on activation' @($rows | Where-Object { $_.Flags -match 'NoActivationAlert' }).Count
    if (-not $SkipPimGroups) { Add-Metric 'PIM for Groups policies reported' $groupRows.Count }
    if ($alertsRead) { Add-Metric 'Active PIM alerts' @($alertRows | Where-Object { "$($_.IsActive)" -eq 'True' }).Count }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    if ($_.Exception.Message -match 'Premium|licen|P2') { Set-DatasetStatus -Name 'pim-role-settings' -Status 'EvidenceUnavailable' -Note 'PIM not licensed' }
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ MaxActivationHours = $MaxActivationHours; OnlyAssignedRoles = [bool]$OnlyAssignedRoles; PimGroupIds = @($PimGroupIds); SkipPimGroups = [bool]$SkipPimGroups; SkipAlerts = [bool]$SkipAlerts }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
