<#
.SYNOPSIS
    Read-only discovery of guest (B2B) and external member accounts in Entra ID and what they can reach.

.DESCRIPTION
    Guests are often the largest pool of stale access. This script exports:
      - External collaboration settings: who can invite, guest directory permissions, invitation
        domain allow / block list, the default cross-tenant access policy (access type and
        targets per direction), plus the number of partner-specific policies
      - One row per partner-specific cross-tenant policy: inbound trust (MFA, compliant and
        hybrid-joined devices), automatic redemption, B2B collaboration and direct connect
        settings per direction, and whether cross-tenant sync into this tenant is allowed
      - One row per external account: guests (userType Guest) and external members
        (userType Member with an external user state or an #EXT# UPN), with home domain,
        invitation state, created date, last sign-in, transitive group membership,
        role-assignable groups, directory roles, app assignments (names), owned objects,
        sponsors, effective privilege, and flags (pending invitation, never signed in, stale,
        disabled, holds a directory role, privileged, owns objects, no sponsor)
      - Every group each external account is in (transitive), every object it owns, and every
        privileged role path it holds (active, eligible, via group, via PIM for Groups)
      - One row per home domain with totals and stale counts
      - A summary of headline metrics

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.
    The invitation domain list is read from the Graph beta legacy policy endpoint (still a GET).

    Output: <OutputRoot>\10-GuestAccess\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\10-Get-GuestAccess.ps1
.EXAMPLE
    .\10-Get-GuestAccess.ps1 -StaleDays 60
.EXAMPLE
    .\10-Get-GuestAccess.ps1 -SkipMemberships -SkipSponsors -SkipPrivilegeJoin   # fast: no per-guest calls

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : User.Read.All, Directory.Read.All, AuditLog.Read.All, Policy.Read.All,
              RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup
    Licence : signInActivity needs Entra ID P1. Eligible roles and PIM for Groups need Entra ID P2.
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

    [int]$StaleDays = 90,
    [int]$PendingDays = 30,
    [switch]$SkipMemberships,
    [switch]$SkipSponsors,
    [switch]$SkipExternalMembers,
    [switch]$SkipPrivilegeJoin,
    # Kept so existing command lines still work; sponsors are read by default (use -SkipSponsors).
    [switch]$IncludeSponsors
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '10-GuestAccess'
$ScriptVersion = '1.1.0'
$RequiredScopes = @('User.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')

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

$GuestRoleNames = @{
    'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'Same access as members'
    '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Limited access (default)'
    '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'Restricted access (most restrictive)'
}

function Get-GuestDomain {
    param($User)
    if ($User.mail -and $User.mail -match '@') { return ($User.mail -split '@')[-1].ToLowerInvariant() }
    if ($User.userPrincipalName -match '^(.+)#EXT#@') {
        $local = $Matches[1]
        $i = $local.LastIndexOf('_')
        if ($i -ge 0) { return $local.Substring($i + 1).ToLowerInvariant() }
    }
    foreach ($id in @($User.identities)) { if ($id.issuer -and $id.issuer -notmatch 'onmicrosoft\.com$') { return "$($id.issuer)".ToLowerInvariant() } }
    return 'unknown'
}

function Format-CtapTargets {
    # "accessType (target:type, ...)" for one usersAndGroups / applications node of a cross-tenant policy.
    param($Node)
    if (-not $Node) { return '' }
    $t = @($Node.targets | Where-Object { $_ } | ForEach-Object { if ("$($_.targetType)") { '{0}:{1}' -f $_.target, $_.targetType } else { "$($_.target)" } })
    if ($t.Count) { return '{0} ({1})' -f $Node.accessType, ($t -join ', ') }
    return "$($Node.accessType)"
}

function Format-CtapDirection {
    # One direction (b2bCollaborationInbound etc.) of a partner policy. Empty node = inherits the default policy.
    param($Node)
    if (-not $Node) { return 'Inherits default' }
    return 'users: {0}; apps: {1}' -f (Format-CtapTargets $Node.usersAndGroups), (Format-CtapTargets $Node.applications)
}

function Test-SignInActivityDenied {
    # True only when the failure is the licence / permission error for signInActivity, not any other error.
    param($ErrorRecord)
    $msg = "$($ErrorRecord.Exception.Message) $($ErrorRecord.ErrorDetails.Message)"
    return ((Get-HttpStatusFromError $ErrorRecord) -eq 403 -or $msg -match 'NonPremium|Premium|licen[cs]e|signInActivity')
}

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if ($IncludeSponsors) { Write-RunLog '-IncludeSponsors is no longer needed: sponsors are read by default (use -SkipSponsors to turn off).' }
    $ctx = Connect-DiscoveryGraph
    $now = $script:RunStartUtc

    # ---- 1. External collaboration settings ----
    $settings = [System.Collections.Generic.List[object]]::new()
    $settingsFailures = [System.Collections.Generic.List[string]]::new()
    try {
        $authz = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        $gr = "$($authz.guestUserRoleId)"
        $settings.Add([pscustomobject][ordered]@{ Area = 'Invitations'; Setting = 'Who can invite guests'; Value = $authz.allowInvitesFrom })
        $settings.Add([pscustomobject][ordered]@{ Area = 'Guest permissions'; Setting = 'Guest user access level'; Value = $(if ($GuestRoleNames.ContainsKey($gr)) { $GuestRoleNames[$gr] } else { $gr }) })
        $settings.Add([pscustomobject][ordered]@{ Area = 'Self-service'; Setting = 'Email-verified users can join'; Value = $authz.allowEmailVerifiedUsersToJoinOrganization })
    }
    catch { $settingsFailures.Add('authorizationPolicy'); Write-RunLog ("authorizationPolicy unreadable: {0}" -f $_.Exception.Message) 'WARN' }

    # Invitation domain allow / block list. Microsoft Graph has no v1.0 API for it; the beta legacy
    # policy endpoint returns the B2BManagementPolicy definition. Best effort: confirm in the portal.
    try {
        $b2bFound = $false
        foreach ($lp in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/beta/legacy/policies' -Label 'legacyPolicies')) {
            foreach ($def in @($lp.definition)) {
                $j = $null
                try { $j = "$def" | ConvertFrom-Json } catch { continue }
                if (-not $j -or -not ($j.PSObject.Properties.Name -contains 'B2BManagementPolicy')) { continue }
                $b2bFound = $true
                $dp = $j.B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy
                $mode = 'Any domain (no list)'; $domains = ''
                if ($dp -and $dp.PSObject.Properties.Name -contains 'AllowedDomains') { $mode = 'Allow list (only these domains)'; $domains = Join-Values $dp.AllowedDomains }
                elseif ($dp -and $dp.PSObject.Properties.Name -contains 'BlockedDomains') { $mode = 'Block list'; $domains = Join-Values $dp.BlockedDomains }
                $settings.Add([pscustomobject][ordered]@{ Area = 'Invitations'; Setting = 'Invitation domain restriction'; Value = $mode })
                $settings.Add([pscustomobject][ordered]@{ Area = 'Invitations'; Setting = 'Invitation domains listed'; Value = $domains })
            }
        }
        if (-not $b2bFound) { $settings.Add([pscustomobject][ordered]@{ Area = 'Invitations'; Setting = 'Invitation domain restriction'; Value = 'Any domain (no B2B management policy found)' }) }
    }
    catch {
        $settingsFailures.Add('invitation domain policy')
        $settings.Add([pscustomobject][ordered]@{ Area = 'Invitations'; Setting = 'Invitation domain restriction'; Value = ("unreadable (HTTP {0})" -f (Get-HttpStatusFromError $_)) })
        Write-RunLog ("Invitation domain policy (beta legacy/policies) unreadable: {0}" -f $_.Exception.Message) 'WARN'
    }

    $partners = @()
    $partnerRows = [System.Collections.Generic.List[object]]::new()
    $partnersRead = $false
    try {
        $ct = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default'
        foreach ($dir in 'b2bCollaborationInbound', 'b2bCollaborationOutbound', 'b2bDirectConnectInbound', 'b2bDirectConnectOutbound') {
            $node = $ct.$dir
            if ($node) {
                $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = "$dir users/groups"; Value = "$($node.usersAndGroups.accessType)" })
                $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = "$dir applications"; Value = "$($node.applications.accessType)" })
                $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = "$dir users/groups targets"; Value = Format-CtapTargets $node.usersAndGroups })
                $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = "$dir applications targets"; Value = Format-CtapTargets $node.applications })
            }
        }
        if ($ct.inboundTrust) {
            $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = 'Trust external MFA'; Value = $ct.inboundTrust.isMfaAccepted })
            $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = 'Trust external compliant devices'; Value = $ct.inboundTrust.isCompliantDeviceAccepted })
            $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = 'Trust external hybrid-joined devices'; Value = $ct.inboundTrust.isHybridAzureADJoinedDeviceAccepted })
        }
        if ($ct.automaticUserConsentSettings) {
            $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = 'Automatic redemption inbound'; Value = $ct.automaticUserConsentSettings.inboundAllowed })
            $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = 'Automatic redemption outbound'; Value = $ct.automaticUserConsentSettings.outboundAllowed })
        }
        $partners = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners' -Label 'partners'
        $partnersRead = $true
        $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant'; Setting = 'Partner-specific policies'; Value = $partners.Count })
    }
    catch { $settingsFailures.Add('crossTenantAccessPolicy'); Write-RunLog ("crossTenantAccessPolicy unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    if ($settings.Count) { Export-Dataset -Name 'external-collaboration-settings' -Rows $settings -Status $(if ($settingsFailures.Count) { 'Partial' } else { 'Completed' }) -Note $(if ($settingsFailures.Count) { 'Not readable: ' + ($settingsFailures -join ', ') } else { '' }) }
    else { Set-DatasetStatus -Name 'external-collaboration-settings' -Status 'Blocked' -Note 'Policy.Read.All needed' }

    # ---- 1b. Partner-specific cross-tenant policies ----
    if ($partnersRead) {
        $syncFailures = 0
        foreach ($p in $partners) {
            $sync = ''
            try {
                $is = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners/{0}/identitySynchronization" -f $p.tenantId)
                $sync = $(if ($is.userSyncInbound -and $is.userSyncInbound.isSyncAllowed) { 'Allowed' } else { 'Configured, not allowed' })
            }
            catch {
                $code = Get-HttpStatusFromError $_
                if ($code -eq 404) { $sync = 'Not configured' } else { $syncFailures++; $sync = "unreadable (HTTP $code)" }
            }
            $it = $p.inboundTrust
            $auc = $p.automaticUserConsentSettings
            $flags = @()
            if ($it -and $it.isMfaAccepted) { $flags += 'TrustsExternalMfa' }
            if ($it -and ($it.isCompliantDeviceAccepted -or $it.isHybridAzureADJoinedDeviceAccepted)) { $flags += 'TrustsExternalDevices' }
            if ($auc -and $auc.inboundAllowed) { $flags += 'AutoRedeemInbound' }
            if ($sync -eq 'Allowed') { $flags += 'InboundSyncAllowed' }
            if ($p.b2bDirectConnectInbound -and "$($p.b2bDirectConnectInbound.usersAndGroups.accessType)" -eq 'allowed') { $flags += 'DirectConnectInboundAllowed' }
            $partnerRows.Add([pscustomobject][ordered]@{
                PartnerTenantId             = $p.tenantId
                IsServiceProvider           = $p.isServiceProvider
                IsInMultiTenantOrganization = $p.isInMultiTenantOrganization
                TrustExternalMfa            = $(if ($it) { $it.isMfaAccepted } else { 'Inherits default' })
                TrustCompliantDevice        = $(if ($it) { $it.isCompliantDeviceAccepted } else { 'Inherits default' })
                TrustHybridJoinedDevice     = $(if ($it) { $it.isHybridAzureADJoinedDeviceAccepted } else { 'Inherits default' })
                AutoRedeemInbound           = $(if ($auc) { $auc.inboundAllowed } else { '' })
                AutoRedeemOutbound          = $(if ($auc) { $auc.outboundAllowed } else { '' })
                B2BCollaborationInbound     = Format-CtapDirection $p.b2bCollaborationInbound
                B2BCollaborationOutbound    = Format-CtapDirection $p.b2bCollaborationOutbound
                B2BDirectConnectInbound     = Format-CtapDirection $p.b2bDirectConnectInbound
                B2BDirectConnectOutbound    = Format-CtapDirection $p.b2bDirectConnectOutbound
                IdentitySyncInbound         = $sync
                Flags                       = Join-Values $flags
            })
        }
        Export-Dataset -Name 'cross-tenant-partners' -Rows $partnerRows -Status $(if ($syncFailures) { 'Partial' } else { 'Completed' }) -Note $(if ($syncFailures) { "identitySynchronization unreadable for $syncFailures partner(s)" } else { 'IdentitySyncInbound: Not configured = no cross-tenant sync policy for that partner' })
    }
    else { Set-DatasetStatus -Name 'cross-tenant-partners' -Status 'Blocked' -Note 'crossTenantAccessPolicy not readable (Policy.Read.All)' }

    # ---- 2. Guests and external members ----
    $select = 'id,displayName,mail,userPrincipalName,createdDateTime,accountEnabled,externalUserState,externalUserStateChangeDateTime,creationType,identities,userType'
    $signInAvailable = $true
    try {
        $guests = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$count=true&`$top=999&`$select={0},signInActivity" -f $select) -Eventual -Label 'guests'
    }
    catch {
        if (-not (Test-SignInActivityDenied $_)) { throw }
        $signInAvailable = $false
        Write-RunLog ("signInActivity not readable ({0}); continuing without last sign-in." -f $_.Exception.Message) 'WARN'
        $guests = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$count=true&`$top=999&`$select={0}" -f $select) -Eventual -Label 'guests'
    }
    Write-RunLog ("{0} guests found" -f $guests.Count)

    $externals = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $guests) { $externals.Add([pscustomobject]@{ User = $g; ExternalType = 'Guest' }) }
    $extMemberStatus = 'Skipped'
    if (-not $SkipExternalMembers) {
        try {
            $members = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Member'&`$select=id,userPrincipalName,externalUserState&`$top=999" -Label 'members (external check)'
            $extIds = @($members | Where-Object { $_.externalUserState -or "$($_.userPrincipalName)" -match '#EXT#' } | ForEach-Object { "$($_.id)" })
            $extFail = 0
            foreach ($id in $extIds) {
                try {
                    $sel = $(if ($signInAvailable) { "$select,signInActivity" } else { $select })
                    $externals.Add([pscustomobject]@{ User = (Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select={1}" -f $id, $sel)); ExternalType = 'ExternalMember' })
                }
                catch { $extFail++; Write-RunLog ("External member {0} not readable: {1}" -f $id, $_.Exception.Message) 'WARN' }
            }
            $extMemberStatus = $(if ($extFail) { "Partial ($extFail unreadable)" } else { 'Completed' })
            Write-RunLog ("{0} external members found (userType Member with external state or #EXT# UPN)" -f $extIds.Count)
        }
        catch {
            $extMemberStatus = 'Unreadable: ' + (Get-FailureStatus $_)
            Write-RunLog ("Members not readable for the external-member check ({0}); external members are NOT included." -f $_.Exception.Message) 'WARN'
        }
    }
    if (-not $SkipMemberships -and $externals.Count -gt 2000) { Write-RunLog ("{0} external accounts: per-account membership calls will take a while. Use -SkipMemberships for a fast pass." -f $externals.Count) 'WARN' }

    # ---- 2b. Effective privilege (active, eligible, via groups, PIM for Groups) ----
    $priv = $null; $privNote = ''
    if ($SkipPrivilegeJoin) { $privNote = 'Skipped (-SkipPrivilegeJoin)' }
    else {
        try {
            $priv = Get-PrivilegedPrincipalSet
            $privNote = Join-Values ($priv.Status.GetEnumerator() | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value })
        }
        catch { $privNote = "Not readable: $($_.Exception.Message)"; Write-RunLog ("Privileged role holders not readable ({0}); IsPrivileged left blank." -f $_.Exception.Message) 'WARN' }
    }

    $guestRows = [System.Collections.Generic.List[object]]::new()
    $grpRows = [System.Collections.Generic.List[object]]::new()
    $ownRows = [System.Collections.Generic.List[object]]::new()
    $memFailures = 0; $ownFailures = 0; $appFailures = 0; $sponsorFailures = 0
    $i = 0
    foreach ($x in $externals) {
        $g = $x.User
        $i++
        if ($i % 500 -eq 0) { Write-RunLog ("  {0}/{1} external accounts" -f $i, $externals.Count) }
        $last = $null
        if ($signInAvailable -and $g.PSObject.Properties.Name -contains 'signInActivity' -and $g.signInActivity) {
            $c = @($g.signInActivity.lastSuccessfulSignInDateTime, $g.signInActivity.lastSignInDateTime, $g.signInActivity.lastNonInteractiveSignInDateTime) | Where-Object { $_ }
            if ($c) { $last = ($c | ForEach-Object { ([datetime]$_).ToUniversalTime() } | Sort-Object -Descending | Select-Object -First 1) }
        }
        $created = $(if ($g.createdDateTime) { ([datetime]$g.createdDateTime).ToUniversalTime() } else { $null })
        $stateChanged = $(if ($g.externalUserStateChangeDateTime) { ([datetime]$g.externalUserStateChangeDateTime).ToUniversalTime() } else { $created })
        $groups = ''; $roles = ''; $groupNames = ''; $apps = ''; $sponsors = ''; $sponsorsRead = $false
        $groupTotal = ''; $roleAssignable = ''; $appNames = ''; $owned = ''
        if (-not $SkipMemberships) {
            try {
                $mem = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/transitiveMemberOf?`$select=id,displayName,isAssignableToRole,groupTypes,securityEnabled,mailEnabled&`$top=999" -f $g.id) -Label "transitiveMemberOf $($g.id)"
                $grp = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' })
                $rol = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' })
                $groups = $grp.Count; $groupTotal = $grp.Count
                $roles = Join-Values ($rol | ForEach-Object { $_.displayName })
                $groupNames = Join-Values ($grp | Select-Object -First 10 | ForEach-Object { $_.displayName })
                if ($grp.Count -gt 10) { $groupNames += "; (+$($grp.Count - 10) more)" }
                $roleAssignable = Join-Values ($grp | Where-Object { $_.isAssignableToRole } | ForEach-Object { $_.displayName })
                foreach ($gr in $grp) {
                    $gt = $(if (@($gr.groupTypes) -contains 'Unified') { 'Microsoft 365' } elseif ($gr.securityEnabled -and $gr.mailEnabled) { 'Mail-enabled security' } elseif ($gr.securityEnabled) { 'Security' } elseif ($gr.mailEnabled) { 'Distribution' } else { '' })
                    $grpRows.Add([pscustomobject][ordered]@{
                        UserId             = $g.id
                        UserPrincipalName  = $g.userPrincipalName
                        DisplayName        = $g.displayName
                        ExternalType       = $x.ExternalType
                        GroupId            = $gr.id
                        GroupName          = $gr.displayName
                        GroupType          = $gt
                        IsAssignableToRole = [bool]$gr.isAssignableToRole
                        Dynamic            = (@($gr.groupTypes) -contains 'DynamicMembership')
                    })
                }
            }
            catch { $memFailures++; $groups = 'unreadable'; $groupTotal = 'unreadable' }
            try {
                $ar = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/appRoleAssignments?`$select=resourceDisplayName,resourceId" -f $g.id) -Label "appRoleAssignments $($g.id)"
                $apps = $ar.Count
                $appNames = Join-Values ($ar | ForEach-Object { $_.resourceDisplayName } | Sort-Object -Unique)
            }
            catch { $appFailures++; $apps = 'unreadable'; $appNames = 'unreadable' }
            try {
                $oo = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/ownedObjects?`$select=id,displayName" -f $g.id) -Label "ownedObjects $($g.id)"
                $owned = $oo.Count
                foreach ($o in $oo) {
                    $ownRows.Add([pscustomobject][ordered]@{
                        UserId            = $g.id
                        UserPrincipalName = $g.userPrincipalName
                        ExternalType      = $x.ExternalType
                        ObjectType        = ("$($o.'@odata.type')" -replace '#microsoft.graph.', '')
                        ObjectId          = $o.id
                        ObjectName        = $o.displayName
                    })
                }
            }
            catch { $ownFailures++; $owned = 'unreadable' }
        }
        if (-not $SkipSponsors) {
            try {
                $sponsors = Join-Values ((Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/sponsors?`$select=displayName,userPrincipalName" -f $g.id) -Label "sponsors $($g.id)") | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } })
                $sponsorsRead = $true
            }
            catch { $sponsorFailures++; $sponsors = 'unreadable' }
        }
        $ps = $(if ($priv) { Get-PrivilegeSummary -Set $priv -PrincipalId "$($g.id)" } else { $null })
        $flags = @()
        if ($x.ExternalType -eq 'ExternalMember') { $flags += 'ExternalMember' }
        if (-not $g.accountEnabled) { $flags += 'Disabled' }
        if ($g.externalUserState -eq 'PendingAcceptance') {
            $flags += 'PendingInvitation'
            if ($stateChanged -and ($now - $stateChanged).TotalDays -gt $PendingDays) { $flags += "PendingOver${PendingDays}d" }
        }
        if ($signInAvailable) {
            if (-not $last) { $flags += 'NeverSignedIn' }
            elseif (($now - $last).TotalDays -gt $StaleDays) { $flags += "NoSignIn${StaleDays}d" }
        }
        if ($roles -or ($ps -and $ps.IsPrivileged)) { $flags += 'HoldsDirectoryRole' }
        if ($ps -and $ps.IsPrivileged) { $flags += 'Privileged' }
        if ($ps -and $ps.IsTier0) { $flags += 'PrivilegedTier0' }
        if ($roleAssignable) { $flags += 'InRoleAssignableGroup' }
        if ($owned -is [int] -and $owned -gt 0) { $flags += 'OwnsObjects' }
        if ($sponsorsRead -and -not $sponsors) { $flags += 'NoSponsor' }
        $guestRows.Add([pscustomobject][ordered]@{
            UserId              = $g.id
            DisplayName         = $g.displayName
            Mail                = $g.mail
            HomeDomain          = Get-GuestDomain $g
            AccountEnabled      = $g.accountEnabled
            InvitationState     = $g.externalUserState
            StateChangedUtc     = $(if ($stateChanged) { $stateChanged.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            CreatedUtc          = $(if ($created) { $created.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            CreationType        = $g.creationType
            LastSignInUtc       = $(if ($last) { $last.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            DaysSinceSignIn     = $(if ($last) { [int]($now - $last).TotalDays } else { '' })
            GroupCount          = $groups
            Groups              = $groupNames
            DirectoryRoles      = $roles
            AppAssignments      = $apps
            Sponsors            = $sponsors
            Flags               = Join-Values $flags
            ExternalType        = $x.ExternalType
            UserPrincipalName   = $g.userPrincipalName
            GroupCountTotal     = $groupTotal
            RoleAssignableGroups = $roleAssignable
            AppAssignmentNames  = $appNames
            OwnedObjects        = $owned
            IsPrivileged        = $(if ($priv) { [bool]$ps.IsPrivileged } else { '' })
            IsTier0             = $(if ($priv) { [bool]$ps.IsTier0 } else { '' })
            Roles               = $(if ($ps) { $ps.Roles } else { '' })
            PrivilegePaths      = $(if ($ps) { $ps.Paths } else { '' })
        })
    }
    $gNotes = @()
    if (-not $signInAvailable) { $gNotes += 'signInActivity unavailable; staleness not evaluated' }
    if ($extMemberStatus -ne 'Completed') { $gNotes += "External members: $extMemberStatus" }
    if ($memFailures) { $gNotes += "transitiveMemberOf unreadable for $memFailures" }
    if ($appFailures) { $gNotes += "appRoleAssignments unreadable for $appFailures" }
    if ($ownFailures) { $gNotes += "ownedObjects unreadable for $ownFailures" }
    if ($sponsorFailures) { $gNotes += "sponsors unreadable for $sponsorFailures" }
    if (-not $SkipPrivilegeJoin -and -not $priv) { $gNotes += 'privilege join unavailable (IsPrivileged blank)' }
    $gPartial = ($memFailures -or $appFailures -or $ownFailures -or $sponsorFailures -or ($extMemberStatus -ne 'Completed' -and $extMemberStatus -ne 'Skipped') -or (-not $SkipPrivilegeJoin -and -not $priv))
    Export-Dataset -Name 'guests' -Rows $guestRows -Status $(if ($gPartial) { 'Partial' } else { 'Completed' }) -Note ($gNotes -join '; ')

    if ($SkipMemberships) {
        Set-DatasetStatus -Name 'guest-group-memberships' -Status 'Deferred' -Note 'Skipped (-SkipMemberships)'
        Set-DatasetStatus -Name 'guest-owned-objects' -Status 'Deferred' -Note 'Skipped (-SkipMemberships)'
    }
    else {
        if ($externals.Count -and $memFailures -ge $externals.Count) { Set-DatasetStatus -Name 'guest-group-memberships' -Status 'Blocked' -Note 'transitiveMemberOf not readable' }
        else { Export-Dataset -Name 'guest-group-memberships' -Rows $grpRows -Status $(if ($memFailures) { 'Partial' } else { 'Completed' }) -Note $(if ($memFailures) { "$memFailures account(s) unreadable" } else { 'Transitive (includes nested groups)' }) }
        if ($externals.Count -and $ownFailures -ge $externals.Count) { Set-DatasetStatus -Name 'guest-owned-objects' -Status 'Blocked' -Note 'ownedObjects not readable' }
        else { Export-Dataset -Name 'guest-owned-objects' -Rows $ownRows -Status $(if ($ownFailures) { 'Partial' } else { 'Completed' }) -Note $(if ($ownFailures) { "$ownFailures account(s) unreadable" } else { '' }) }
    }

    # ---- 2c. Privileged external accounts (one row per role path) ----
    if ($SkipPrivilegeJoin) { Set-DatasetStatus -Name 'privileged-guests' -Status 'Deferred' -Note 'Skipped (-SkipPrivilegeJoin)' }
    elseif (-not $priv) { Set-DatasetStatus -Name 'privileged-guests' -Status 'Blocked' -Note $privNote }
    else {
        $extById = @{}; foreach ($x in $externals) { $extById["$($x.User.id)"] = $x.ExternalType }
        $pgRows = foreach ($r in $priv.Rows) {
            $isExt = $extById.ContainsKey("$($r.PrincipalId)") -or "$($r.UserType)" -eq 'Guest' -or "$($r.Upn)" -match '#EXT#'
            if (-not $isExt) { continue }
            [pscustomobject][ordered]@{
                UserId            = $r.PrincipalId
                UserPrincipalName = $r.Upn
                DisplayName       = $r.PrincipalName
                ExternalType      = $(if ($extById.ContainsKey("$($r.PrincipalId)")) { $extById["$($r.PrincipalId)"] } elseif ("$($r.UserType)" -eq 'Guest') { 'Guest' } else { 'ExternalMember' })
                AccountEnabled    = $r.AccountEnabled
                Role              = $r.Role
                Tier0             = $r.Tier0
                AssignmentState   = $r.AssignmentState
                Via               = $r.Via
                ViaGroup          = $r.ViaGroup
                EndDateTime       = $r.EndDateTime
            }
        }
        $privPartial = @($priv.Status.Values | Where-Object { "$_" -notmatch '^(Completed|Skipped)' }).Count
        Export-Dataset -Name 'privileged-guests' -Rows @($pgRows) -Status $(if ($privPartial) { 'Partial' } else { 'Completed' }) -Note $privNote
    }

    # ---- 3. By home domain ----
    $domainRows = $guestRows | Group-Object HomeDomain | ForEach-Object {
        $grp = @($_.Group)
        [pscustomobject][ordered]@{
            HomeDomain       = $_.Name
            Guests           = $grp.Count
            Enabled          = @($grp | Where-Object AccountEnabled).Count
            PendingInvitation = @($grp | Where-Object { $_.Flags -match 'PendingInvitation' }).Count
            NeverSignedIn    = @($grp | Where-Object { $_.Flags -match 'NeverSignedIn' }).Count
            Stale            = @($grp | Where-Object { $_.Flags -match 'NoSignIn' }).Count
            LastSignInUtc    = (@($grp | Where-Object LastSignInUtc | Sort-Object LastSignInUtc -Descending | Select-Object -First 1 -ExpandProperty LastSignInUtc) -join '')
            ExternalMembers  = @($grp | Where-Object ExternalType -eq 'ExternalMember').Count
            Privileged       = @($grp | Where-Object { $_.IsPrivileged -eq $true }).Count
        }
    } | Sort-Object Guests -Descending
    Export-Dataset -Name 'guests-by-domain' -Rows $domainRows -Note 'Guests column counts all external accounts (guests and external members)'

    # ---- 4. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $total = $guestRows.Count
    $pct = { param($n) if ($total) { [math]::Round(100 * $n / $total, 1) } else { 0 } }
    Add-Metric 'Guests' @($guestRows | Where-Object ExternalType -eq 'Guest').Count
    Add-Metric 'External members' $(if ($SkipExternalMembers) { '' } else { @($guestRows | Where-Object ExternalType -eq 'ExternalMember').Count }) -Note $extMemberStatus
    Add-Metric 'Guest home domains' @($domainRows).Count
    Add-Metric 'Guests enabled' @($guestRows | Where-Object AccountEnabled).Count -Note 'All external accounts'
    $pend = @($guestRows | Where-Object { $_.Flags -match 'PendingInvitation' }).Count
    Add-Metric 'Pending invitations' $pend -Note ("{0}%" -f (& $pct $pend))
    Add-Metric "Pending invitations older than $PendingDays days" @($guestRows | Where-Object { $_.Flags -match 'PendingOver' }).Count
    if ($signInAvailable) {
        $never = @($guestRows | Where-Object { $_.Flags -match 'NeverSignedIn' }).Count
        $stale = @($guestRows | Where-Object { $_.Flags -match 'NoSignIn' }).Count
        Add-Metric 'Guests never signed in' $never -Note ("{0}%" -f (& $pct $never))
        Add-Metric "Guests with no sign-in in $StaleDays days" $stale -Note ("{0}%" -f (& $pct $stale))
        Add-Metric 'Enabled guests that are stale or never signed in' @($guestRows | Where-Object { $_.AccountEnabled -and $_.Flags -match 'NeverSignedIn|NoSignIn' }).Count -Note 'Review / removal candidates'
    }
    if (-not $SkipMemberships) {
        Add-Metric 'Guests holding a directory role' @($guestRows | Where-Object { $_.Flags -match 'HoldsDirectoryRole' }).Count
        Add-Metric 'Guests in at least one group' @($guestRows | Where-Object { $_.GroupCount -is [int] -and $_.GroupCount -gt 0 }).Count -Note 'Transitive membership'
        Add-Metric 'Guests in a role-assignable group' @($guestRows | Where-Object RoleAssignableGroups).Count
        Add-Metric 'Guests owning directory objects' @($guestRows | Where-Object { $_.Flags -match 'OwnsObjects' }).Count
        Add-Metric 'Guests owning applications or service principals' @($ownRows | Where-Object { $_.ObjectType -in @('application', 'servicePrincipal') } | Select-Object -ExpandProperty UserId -Unique).Count
    }
    if ($priv) {
        Add-Metric 'Privileged guests (any role path)' @($guestRows | Where-Object { $_.IsPrivileged -eq $true }).Count -Note $privNote
        Add-Metric 'Guests with a Tier 0 role path' @($guestRows | Where-Object { $_.IsTier0 -eq $true }).Count
    }
    elseif (-not $SkipPrivilegeJoin) { Add-Metric 'Privileged guests (any role path)' '' -Note $privNote }
    if (-not $SkipSponsors) { Add-Metric 'Guests without a sponsor' @($guestRows | Where-Object { $_.Flags -match 'NoSponsor' }).Count -Note $(if ($sponsorFailures) { "$sponsorFailures unreadable" } else { '' }) }
    if ($partnersRead) {
        Add-Metric 'Partner tenants trusting external MFA' @($partnerRows | Where-Object { $_.Flags -match 'TrustsExternalMfa' }).Count
        Add-Metric 'Partner tenants allowed to sync users in' @($partnerRows | Where-Object { $_.Flags -match 'InboundSyncAllowed' }).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ StaleDays = $StaleDays; PendingDays = $PendingDays; SkipMemberships = [bool]$SkipMemberships; SkipSponsors = [bool]$SkipSponsors; SkipExternalMembers = [bool]$SkipExternalMembers; SkipPrivilegeJoin = [bool]$SkipPrivilegeJoin; IncludeSponsors = [bool]$IncludeSponsors }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
