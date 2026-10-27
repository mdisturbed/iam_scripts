<#
.SYNOPSIS
    Read-only snapshot of Entra ID Protection: users currently at risk, recent risk detections,
    risky workload identities, and whether Conditional Access acts on risk - and who it skips.

.DESCRIPTION
    Exports:
      - Risky users (at risk or confirmed compromised), with risk level, detail and age, effective
        privilege (direct, group, eligible, PIM for Groups, group owner) and MFA registration, so
        risky admins and users who cannot self-remediate stand out
      - Risk detections over a lookback window, one row per detection, plus an aggregate by
        detection type and level
      - Risky service principals and service principal risk detections (need Workload Identities
        Premium; otherwise marked EvidenceUnavailable)
      - Conditional Access policies that use user risk or sign-in risk, with their state
      - The accounts excluded from those risk policies (users, transitive group members, role
        holders, service principals)
      - Optionally, the risk history of dismissed / remediated users (who closed the risk)
      - A summary of headline metrics

    Legacy Identity Protection user-risk / sign-in-risk policies (configured outside CA) are not
    exposed by Microsoft Graph; check them in the portal if CA shows no risk policies.

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\21-IdentityRisk\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\21-Get-IdentityRisk.ps1
.EXAMPLE
    .\21-Get-IdentityRisk.ps1 -DetectionLookbackDays 90 -IncludeRemediated -IncludeRiskHistory
.EXAMPLE
    .\21-Get-IdentityRisk.ps1 -RiskStaleDays 14

.NOTES
    Version : 1.1.1
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All,
              IdentityRiskyServicePrincipal.Read.All, Policy.Read.All, RoleManagement.Read.Directory,
              Directory.Read.All, AuditLog.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup
    Roles   : Security Reader or Global Reader
    Licence : Entra ID P2 for full risk data (P1 / free tenants see limited detail); Workload
              Identities Premium for service principal risk.
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

    [ValidateRange(1, 90)]
    [int]$DetectionLookbackDays = 30,
    [int]$RiskStaleDays = 30,
    [switch]$IncludeRemediated,
    [switch]$IncludeRiskHistory,
    [int]$MaxHistoryUsers = 500,
    [switch]$SkipServicePrincipals,
    [switch]$SkipPrivilegeJoin
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '21-IdentityRisk'
$ScriptVersion = '1.1.1'
$RequiredScopes = @('IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'Directory.Read.All', 'AuditLog.Read.All')
if (-not $SkipServicePrincipals) { $RequiredScopes += 'IdentityRiskyServicePrincipal.Read.All' }
if (-not $SkipPrivilegeJoin) { $RequiredScopes += 'PrivilegedEligibilitySchedule.Read.AzureADGroup' }

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

function Get-Age { param($Value) if ($Value) { return [int]($script:RunStartUtc - ([datetime]$Value).ToUniversalTime()).TotalDays } return '' }

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- Effective privilege, to flag risky admins (falls back to direct active assignments) ----
    $privSet = $null
    if (-not $SkipPrivilegeJoin) { $privSet = Get-EffectivePrivilegedSet }
    $roleHolders = @{}
    $privMode = 'EffectiveSet'
    if (-not $privSet) {
        $privMode = 'DirectActiveOnly'
        try {
            $defs = @{}
            foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName' -Label 'roleDefinitions')) { $defs[$r.id] = $r.displayName }
            foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=principalId,roleDefinitionId' -Label 'roleAssignments')) {
                if (-not $roleHolders.ContainsKey($a.principalId)) { $roleHolders[$a.principalId] = [System.Collections.Generic.List[string]]::new() }
                $roleHolders[$a.principalId].Add($(if ($defs.ContainsKey($a.roleDefinitionId)) { $defs[$a.roleDefinitionId] } else { $a.roleDefinitionId }))
            }
        }
        catch { $privMode = 'Unavailable'; Write-RunLog ("Role assignments unreadable; risky-admin flag unavailable ({0})" -f $_.Exception.Message) 'WARN' }
    }
    function Get-PrivilegeView {
        param([string]$Id)
        if ($privMode -eq 'EffectiveSet') { return Get-PrivilegeSummary -Set $privSet -PrincipalId $Id }
        if ($privMode -eq 'DirectActiveOnly') {
            if ($roleHolders.ContainsKey($Id)) { return [pscustomobject]@{ IsPrivileged = $true; IsTier0 = ''; Roles = (Join-Values ($roleHolders[$Id] | Select-Object -Unique)); Paths = 'Active (direct assignments only)' } }
            return [pscustomobject]@{ IsPrivileged = $false; IsTier0 = ''; Roles = ''; Paths = '' }
        }
        return [pscustomobject]@{ IsPrivileged = ''; IsTier0 = ''; Roles = ''; Paths = '' }
    }
    $privNote = $(switch ($privMode) { 'EffectiveSet' { $(if (Test-PrivSetComplete $privSet) { '' } else { "Privileged set incomplete: $(Get-PrivSetStatusText $privSet)" }) } 'DirectActiveOnly' { $(if ($SkipPrivilegeJoin) { 'Privilege from direct active assignments only (-SkipPrivilegeJoin)' } else { "Privilege from direct active assignments only (privileged set not readable: $script:PrivSetError)" }) } default { 'Privilege not evaluated: role data not readable' } })

    # MFA registration for risky users (one read per user; stops after an access error)
    $regCache = @{}
    $script:RegBlocked = ''
    function Get-Registration {
        param([string]$Id)
        if ($regCache.ContainsKey($Id)) { return $regCache[$Id] }
        $r = $null
        if (-not $script:RegBlocked) {
            try { $r = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails/{0}" -f $Id) }
            catch {
                $code = Get-HttpStatusFromError $_
                if ($code -ne 404) {
                    $script:RegBlocked = '{0} (HTTP {1})' -f $(if (Test-LicenceError $_) { 'EvidenceUnavailable' } else { 'Blocked' }), $code
                    Write-RunLog ("Registration details not readable ({0}); MFA columns left blank." -f $_.Exception.Message) 'WARN'
                }
            }
        }
        $regCache[$Id] = $r
        return $r
    }

    # ---- 1. Risky users ----
    $userRows = @()
    $ru = $null
    $atRiskIds = @{}
    try {
        $ru = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskyUsers' -Label 'riskyUsers'
        $userRows = foreach ($u in $ru) {
            $state = "$($u.riskState)"
            if ($state -in @('atRisk', 'confirmedCompromised')) { $atRiskIds["$($u.id)"] = $state }
            if (-not $IncludeRemediated -and $state -notin @('atRisk', 'confirmedCompromised')) { continue }
            $pv = Get-PrivilegeView "$($u.id)"
            $reg = Get-Registration "$($u.id)"
            $age = Get-Age $u.riskLastUpdatedDateTime
            $notReg = [bool]($reg -and -not $reg.isMfaRegistered -and $state -in @('atRisk', 'confirmedCompromised'))
            [pscustomobject][ordered]@{
                UserPrincipalName     = $u.userPrincipalName
                RiskLevel             = $u.riskLevel
                RiskState             = $state
                RiskDetail            = $u.riskDetail
                LastUpdatedUtc        = $u.riskLastUpdatedDateTime
                DaysSinceUpdate       = $age
                IsDeleted             = $u.isDeleted
                DirectoryRoles        = $pv.Roles
                Flags                 = Join-Values @($(if ($pv.IsPrivileged -eq $true) { 'RiskyAdmin' }), $(if ($pv.IsTier0 -eq $true) { 'RiskyTier0Admin' }), $(if ($state -eq 'confirmedCompromised') { 'ConfirmedCompromised' }), $(if ("$($u.riskLevel)" -eq 'high') { 'HighRisk' }), $(if ($notReg) { 'RiskyNotMfaRegistered' }), $(if ($state -eq 'atRisk' -and $age -ne '' -and $age -gt $RiskStaleDays) { "RiskLeftOpen${RiskStaleDays}d" }))
                UserId                = $u.id
                IsPrivileged          = $pv.IsPrivileged
                IsTier0               = $pv.IsTier0
                PrivilegePaths        = $pv.Paths
                IsMfaRegistered       = $(if ($reg) { $reg.isMfaRegistered } else { '' })
                MethodsRegistered     = $(if ($reg) { Join-Values $reg.methodsRegistered } else { '' })
                RiskyNotMfaRegistered = $(if ($reg) { $notReg } else { '' })
            }
        }
        $userRows = @($userRows | Sort-Object @{ Expression = { $_.Flags -notmatch 'RiskyAdmin' } }, @{ Expression = { @{ high = 0; medium = 1; low = 2 }["$($_.RiskLevel)"] } })
        $ruNotes = @($(if ($IncludeRemediated) { 'All risk states' } else { 'atRisk and confirmedCompromised only' }))
        if ($privNote) { $ruNotes += $privNote }
        if ($script:RegBlocked) { $ruNotes += "registration details $($script:RegBlocked)" }
        Export-Dataset -Name 'risky-users' -Rows $userRows -Status $(if (($privMode -ne 'EffectiveSet' -and -not $SkipPrivilegeJoin) -or ($privMode -eq 'EffectiveSet' -and -not (Test-PrivSetComplete $privSet)) -or $script:RegBlocked) { 'Partial' } else { 'Completed' }) -Note ($ruNotes -join '; ')
    }
    catch { Set-DatasetStatus -Name 'risky-users' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 2. Risk detections ----
    $detRows = @()
    try {
        $since = $script:RunStartUtc.AddDays(-$DetectionLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $det = Invoke-GraphGetAll -Uri ('https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$filter=' + [uri]::EscapeDataString("detectedDateTime ge $since")) -Label 'riskDetections'
        $detRows = foreach ($d in $det) {
            [pscustomobject][ordered]@{
                DetectedUtc       = $d.detectedDateTime
                UserPrincipalName = $d.userPrincipalName
                RiskEventType     = $d.riskEventType
                RiskLevel         = $d.riskLevel
                RiskState         = $d.riskState
                DetectionTiming   = Get-OptionalValue $d 'detectionTimingType'
                Source            = Get-OptionalValue $d 'source'
                IpAddress         = Get-OptionalValue $d 'ipAddress'
                Country           = $(if ((Get-OptionalValue $d 'location')) { $d.location.countryOrRegion } else { '' })
                IsAdmin           = $(if ($privMode -eq 'Unavailable') { '' } else { [bool]($d.userId -and (Get-PrivilegeView "$($d.userId)").IsPrivileged -eq $true) })
            }
        }
        Export-Dataset -Name 'risk-detections' -Rows $detRows -Note ((@("Last $DetectionLookbackDays days") + @($privNote | Where-Object { $_ })) -join '; ')
        $agg = $detRows | Group-Object RiskEventType, RiskLevel | ForEach-Object {
            [pscustomobject][ordered]@{
                RiskEventType = $_.Group[0].RiskEventType
                RiskLevel     = $_.Group[0].RiskLevel
                Detections    = $_.Count
                DistinctUsers = @($_.Group | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
                AdminUsers    = @($_.Group | Where-Object { $_.IsAdmin -eq $true } | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
            }
        } | Sort-Object Detections -Descending
        Export-Dataset -Name 'risk-detections-by-type' -Rows $agg
    }
    catch {
        $st = Get-FailureStatus $_
        Set-DatasetStatus -Name 'risk-detections' -Status $st -Note $_.Exception.Message
        Set-DatasetStatus -Name 'risk-detections-by-type' -Status $st -Note 'Depends on risk-detections'
    }

    # ---- 3. Risky service principals and their detections ----
    $spRows = @()
    $spDetRows = @()
    $spDetRead = $false
    if ($SkipServicePrincipals) {
        Set-DatasetStatus -Name 'risky-service-principals' -Status 'Deferred' -Note '-SkipServicePrincipals'
        Set-DatasetStatus -Name 'service-principal-risk-detections' -Status 'Deferred' -Note '-SkipServicePrincipals'
    }
    else {
        try {
            $rsp = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals' -Label 'riskyServicePrincipals'
            $spRows = foreach ($s in $rsp) {
                if (-not $IncludeRemediated -and "$($s.riskState)" -notin @('atRisk', 'confirmedCompromised')) { continue }
                $pv = Get-PrivilegeView "$($s.id)"
                [pscustomobject][ordered]@{ DisplayName = $s.displayName; AppId = $s.appId; RiskLevel = $s.riskLevel; RiskState = $s.riskState; RiskDetail = $s.riskDetail; LastUpdatedUtc = $s.riskLastUpdatedDateTime; HoldsDirectoryRole = $pv.IsPrivileged; ServicePrincipalId = $s.id; IsTier0 = $pv.IsTier0; DirectoryRoles = $pv.Roles; PrivilegePaths = $pv.Paths }
            }
            Export-Dataset -Name 'risky-service-principals' -Rows $spRows
        }
        catch { Set-DatasetStatus -Name 'risky-service-principals' -Status $(if (Test-LicenceError $_) { 'EvidenceUnavailable' } else { Get-FailureStatus $_ }) -Note ("Workload Identities Premium or permission missing: {0}" -f $_.Exception.Message) }
        try {
            $since = $script:RunStartUtc.AddDays(-$DetectionLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $spd = Invoke-GraphGetAll -Uri ('https://graph.microsoft.com/v1.0/identityProtection/servicePrincipalRiskDetections?$filter=' + [uri]::EscapeDataString("detectedDateTime ge $since")) -Label 'servicePrincipalRiskDetections'
            $spDetRead = $true
            $spDetRows = foreach ($d in $spd) {
                $pv = Get-PrivilegeView "$($d.servicePrincipalId)"
                [pscustomobject][ordered]@{
                    DetectedUtc        = $d.detectedDateTime
                    ServicePrincipalId = $d.servicePrincipalId
                    DisplayName        = Get-OptionalValue $d 'servicePrincipalDisplayName'
                    AppId              = Get-OptionalValue $d 'appId'
                    RiskEventType      = $d.riskEventType
                    RiskLevel          = $d.riskLevel
                    RiskState          = $d.riskState
                    DetectionTiming    = Get-OptionalValue $d 'detectionTimingType'
                    Source             = Get-OptionalValue $d 'source'
                    IpAddress          = Get-OptionalValue $d 'ipAddress'
                    HoldsDirectoryRole = $pv.IsPrivileged
                    IsTier0            = $pv.IsTier0
                }
            }
            Export-Dataset -Name 'service-principal-risk-detections' -Rows $spDetRows -Note "Last $DetectionLookbackDays days"
        }
        catch { Set-DatasetStatus -Name 'service-principal-risk-detections' -Status $(if (Test-LicenceError $_) { 'EvidenceUnavailable' } else { Get-FailureStatus $_ }) -Note ("Workload Identities Premium or permission missing: {0}" -f $_.Exception.Message) }
    }

    # ---- 4. CA risk policies ----
    $caRows = @()
    $riskPolicies = [System.Collections.Generic.List[object]]::new()
    $caRead = $false
    $caStatus = ''
    try {
        $ca = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'caPolicies'
        $caRead = $true
        $caRows = foreach ($p in $ca) {
            $ur = @($p.conditions.userRiskLevels | Where-Object { $_ })
            $sr = @($p.conditions.signInRiskLevels | Where-Object { $_ })
            $spr = @(); if ($p.conditions.PSObject.Properties.Name -contains 'servicePrincipalRiskLevels') { $spr = @($p.conditions.servicePrincipalRiskLevels | Where-Object { $_ }) }
            if (-not ($ur.Count -or $sr.Count -or $spr.Count)) { continue }
            $riskPolicies.Add([pscustomobject]@{ Policy = $p; RiskTypes = (Join-Values @($(if ($ur.Count) { 'User' }), $(if ($sr.Count) { 'SignIn' }), $(if ($spr.Count) { 'Workload' }))) })
            [pscustomobject][ordered]@{
                PolicyName          = $p.displayName
                State               = $p.state
                UserRiskLevels      = Join-Values $ur
                SignInRiskLevels    = Join-Values $sr
                WorkloadRiskLevels  = Join-Values $spr
                GrantControls       = $(if ($p.grantControls) { Join-Values $p.grantControls.builtInControls } else { '' })
                AuthStrength        = $(if ($p.grantControls -and (Get-OptionalValue $p.grantControls 'authenticationStrength')) { $p.grantControls.authenticationStrength.displayName } else { '' })
                SessionControls     = $(if ($p.sessionControls -and (Get-OptionalValue $p.sessionControls 'signInFrequency') -and $p.sessionControls.signInFrequency.isEnabled) { 'SignInFrequency' } else { '' })
                IncludeUsers        = Join-Values $p.conditions.users.includeUsers
                ExcludeGroupCount   = @($p.conditions.users.excludeGroups | Where-Object { $_ }).Count
            }
        }
        Export-Dataset -Name 'ca-risk-policies' -Rows $caRows
    }
    catch { $caStatus = Get-FailureStatus $_; Set-DatasetStatus -Name 'ca-risk-policies' -Status $caStatus -Note $_.Exception.Message }

    # ---- 5. Who the risk policies skip ----
    $exRows = [System.Collections.Generic.List[object]]::new()
    if (-not $caRead) { Set-DatasetStatus -Name 'risk-policy-exclusions' -Status $caStatus -Note 'Depends on ca-risk-policies, which could not be read' }
    else {
        $exIssues = 0
        $memberCache = @{}
        $roleNameById = @{}
        try {
            foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName' -Label 'roleDefinitions')) {
                $roleNameById["$($r.id)"] = "$($r.displayName)"
                if ($r.templateId) { $roleNameById["$($r.templateId)"] = "$($r.displayName)" }
            }
        }
        catch { Write-RunLog ("Role definitions not readable; excluded roles cannot be named or expanded ({0})" -f $_.Exception.Message) 'WARN' }
        function Add-ExclusionRow {
            param($PolicyItem, [string]$Type, [string]$Via, [string]$Id, [string]$PType, [string]$Name, [string]$Upn, $Enabled, $Effective, [string]$Status = 'Resolved')
            $pv = $(if ($Id) { Get-PrivilegeView $Id } else { [pscustomobject]@{ IsPrivileged = ''; IsTier0 = '' } })
            $exRows.Add([pscustomobject][ordered]@{
                PolicyName       = $PolicyItem.Policy.displayName
                PolicyState      = $PolicyItem.Policy.state
                RiskTypes        = $PolicyItem.RiskTypes
                ExclusionType    = $Type
                ExcludedVia      = $Via
                PrincipalId      = $Id
                PrincipalType    = $PType
                PrincipalName    = $Name
                Upn              = $Upn
                AccountEnabled   = $Enabled
                IsPrivileged     = $pv.IsPrivileged
                IsTier0          = $pv.IsTier0
                CurrentlyAtRisk  = $(if ($Id -and $atRiskIds.ContainsKey($Id)) { $atRiskIds[$Id] } else { '' })
                EffectiveForCa   = $Effective
                Status           = $Status
            })
        }
        foreach ($item in $riskPolicies) {
            $u = $item.Policy.conditions.users
            foreach ($id in @(Get-OptionalValue $u 'excludeUsers' | Where-Object { $_ })) {
                $p = Get-PrivPrincipal "$id"
                Add-ExclusionRow -PolicyItem $item -Type 'User' -Via '' -Id "$id" -PType $p.Type -Name $p.Name -Upn $p.Upn -Enabled $p.Enabled -Effective $p.Exists -Status $(if ($p.Error) { "Unresolved ($($p.Error))" } elseif (-not $p.Exists) { 'Deleted' } else { 'Resolved' })
            }
            foreach ($gid in @(Get-OptionalValue $u 'excludeGroups' | Where-Object { $_ })) {
                $g = Get-PrivPrincipal "$gid"
                if (-not $memberCache.ContainsKey("$gid")) {
                    try { $memberCache["$gid"] = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers?`$select=id,displayName,userPrincipalName,accountEnabled" -f $gid) -Label "transitiveMembers $gid" }
                    catch { $memberCache["$gid"] = 'HTTP {0}' -f (Get-HttpStatusFromError $_) }
                }
                $mem = $memberCache["$gid"]
                if ($mem -is [string]) {
                    $exIssues++
                    Add-ExclusionRow -PolicyItem $item -Type 'Group member' -Via $g.Name -Id '' -PType '' -Name '' -Upn '' -Enabled '' -Effective '' -Status "Unresolved (members not readable: $mem)"
                    continue
                }
                $any = $false
                foreach ($m in $mem) {
                    $t = ("$($m.'@odata.type')" -replace '#microsoft.graph.', '')
                    if ($t -eq 'group') { continue }
                    $any = $true
                    Add-ExclusionRow -PolicyItem $item -Type 'Group member' -Via $g.Name -Id "$($m.id)" -PType $t -Name "$($m.displayName)" -Upn "$(Get-OptionalValue $m 'userPrincipalName')" -Enabled (Get-OptionalValue $m 'accountEnabled') -Effective $true
                }
                if (-not $any) { Add-ExclusionRow -PolicyItem $item -Type 'Group member' -Via $g.Name -Id '' -PType '' -Name '' -Upn '' -Enabled '' -Effective $false -Status 'Group has no members' }
            }
            foreach ($rid in @(Get-OptionalValue $u 'excludeRoles' | Where-Object { $_ })) {
                if ($privMode -ne 'EffectiveSet') {
                    $exIssues++
                    Add-ExclusionRow -PolicyItem $item -Type 'Role holder' -Via "$rid" -Id '' -PType '' -Name '' -Upn '' -Enabled '' -Effective '' -Status 'Not expanded (privileged set not available)'
                    continue
                }
                $tplRows = @()
                if ($roleNameById.ContainsKey("$rid")) {
                    $roleName = $roleNameById["$rid"]
                    $tplRows = @($privSet.Rows | Where-Object { $_.PrincipalType -ne 'group' -and $_.Role -eq $roleName })
                }
                else { $roleName = "$rid (role name not resolved)"; $exIssues++ }
                if (-not $tplRows.Count) { Add-ExclusionRow -PolicyItem $item -Type 'Role holder' -Via $roleName -Id '' -PType '' -Name '' -Upn '' -Enabled '' -Effective $false -Status 'No current holders' }
                foreach ($h in $tplRows) { Add-ExclusionRow -PolicyItem $item -Type 'Role holder' -Via ('{0} ({1})' -f $roleName, $h.AssignmentState) -Id $h.PrincipalId -PType $h.PrincipalType -Name $h.PrincipalName -Upn $h.Upn -Enabled $h.AccountEnabled -Effective (Test-RowEffectiveForCa $h) }
            }
            $gx = Get-OptionalValue $u 'excludeGuestsOrExternalUsers'
            if ($gx) { Add-ExclusionRow -PolicyItem $item -Type 'GuestOrExternal' -Via "$($gx.guestOrExternalUserTypes)" -Id '' -PType '' -Name '' -Upn '' -Enabled '' -Effective $true }
            $capps = Get-OptionalValue $item.Policy.conditions 'clientApplications'
            foreach ($sid in @(Get-OptionalValue $capps 'excludeServicePrincipals' | Where-Object { $_ })) {
                $p = Get-PrivPrincipal "$sid"
                Add-ExclusionRow -PolicyItem $item -Type 'ServicePrincipal' -Via '' -Id "$sid" -PType $p.Type -Name $p.Name -Upn '' -Enabled $p.Enabled -Effective $p.Exists -Status $(if ($p.Error) { "Unresolved ($($p.Error))" } elseif (-not $p.Exists) { 'Deleted' } else { 'Resolved' })
            }
        }
        $exNote = @()
        if (-not $riskPolicies.Count) { $exNote += 'No CA policy uses risk conditions' }
        if ($exIssues) { $exNote += "$exIssues exclusion(s) not fully resolved (see Status)" }
        if ($privMode -eq 'EffectiveSet' -and -not (Test-PrivSetComplete $privSet)) { $exNote += "privileged set incomplete: $(Get-PrivSetStatusText $privSet)" }
        Export-Dataset -Name 'risk-policy-exclusions' -Rows $exRows -Status $(if ($exIssues -or ($privMode -eq 'EffectiveSet' -and -not (Test-PrivSetComplete $privSet))) { 'Partial' } else { 'Completed' }) -Note ($exNote -join '; ')
    }

    # ---- 6. Risk history of dismissed / remediated users (who closed the risk) ----
    $histRows = [System.Collections.Generic.List[object]]::new()
    if (-not $IncludeRiskHistory) { Set-DatasetStatus -Name 'risky-user-history' -Status 'Deferred' -Note 'Not requested (-IncludeRiskHistory)' }
    elseif ($null -eq $ru) { Set-DatasetStatus -Name 'risky-user-history' -Status 'Blocked' -Note 'Depends on risky-users, which could not be read' }
    else {
        $closed = @($ru | Where-Object { "$($_.riskState)" -in @('dismissed', 'remediated') })
        $histIssues = 0
        foreach ($u in @($closed | Select-Object -First $MaxHistoryUsers)) {
            try { $hist = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/{0}/history" -f $u.id) -Label "riskyUserHistory $($u.id)" }
            catch { $histIssues++; Write-RunLog ("Risk history of {0} not readable: {1}" -f $u.userPrincipalName, $_.Exception.Message) 'WARN'; continue }
            foreach ($h in $hist) {
                $by = "$(Get-OptionalValue $h 'initiatedBy')"
                $act = Get-OptionalValue $h 'activity'
                $histRows.Add([pscustomobject][ordered]@{
                    UserId           = $u.id
                    UserPrincipalName = $u.userPrincipalName
                    CurrentRiskState = $u.riskState
                    EventRiskState   = $h.riskState
                    RiskLevel        = $h.riskLevel
                    RiskDetail       = $h.riskDetail
                    ActivityDetail   = $(if ($act) { $act.detail } else { '' })
                    RiskEventTypes   = $(if ($act) { Join-Values $act.riskEventTypes } else { '' })
                    InitiatedBy      = $by
                    InitiatedByName  = $(if ($by) { $p = Get-PrivPrincipal $by; $(if ($p.Upn) { $p.Upn } else { $p.Name }) } else { '' })
                    UpdatedUtc       = ConvertTo-UtcText $h.riskLastUpdatedDateTime
                    Flags            = Join-Values @($(if ("$($h.riskDetail)" -match 'adminDismissed') { 'AdminDismissed' }), $(if ("$($h.riskDetail)" -match 'adminConfirmedUserCompromised') { 'AdminConfirmedCompromised' }))
                })
            }
        }
        $hNote = @("$([math]::Min($closed.Count, $MaxHistoryUsers)) of $($closed.Count) dismissed/remediated users read")
        if ($histIssues) { $hNote += "$histIssues history read(s) failed" }
        Export-Dataset -Name 'risky-user-history' -Rows $histRows -Status $(if ($histIssues -or $closed.Count -gt $MaxHistoryUsers) { 'Partial' } else { 'Completed' }) -Note ($hNote -join '; ')
    }

    # ---- 7. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $active = @($userRows | Where-Object { $_.RiskState -in @('atRisk', 'confirmedCompromised') })
    Add-Metric 'Users currently at risk' $active.Count
    foreach ($l in 'high', 'medium', 'low') { Add-Metric "At-risk users: $l" @($active | Where-Object { "$($_.RiskLevel)" -eq $l }).Count }
    Add-Metric 'Confirmed compromised users' @($active | Where-Object RiskState -eq 'confirmedCompromised').Count
    Add-Metric 'At-risk users holding a directory role' @($active | Where-Object { $_.Flags -match 'RiskyAdmin' }).Count -Note $(if ($privNote) { "Review first. $privNote" } else { 'Review first (direct, group, eligible, PIM for Groups and owner paths)' })
    Add-Metric 'At-risk users holding a Tier 0 role' @($active | Where-Object { $_.IsTier0 -eq $true }).Count
    Add-Metric 'At-risk users not MFA registered' @($active | Where-Object { $_.RiskyNotMfaRegistered -eq $true }).Count -Note 'Cannot self-remediate with MFA'
    Add-Metric "At-risk users not updated in $RiskStaleDays+ days" @($active | Where-Object { $_.DaysSinceUpdate -ne '' -and $_.DaysSinceUpdate -gt $RiskStaleDays }).Count -Note 'Risk left open - no remediation or dismissal'
    Add-Metric "Risk detections (last $DetectionLookbackDays days)" @($detRows).Count
    Add-Metric 'Users with detections' @($detRows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    if (-not $SkipServicePrincipals) {
        Add-Metric 'Risky service principals' @($spRows).Count
        if ($spDetRead) { Add-Metric "Service principal risk detections (last $DetectionLookbackDays days)" @($spDetRows).Count }
    }
    Add-Metric 'CA policies using user risk (enabled)' @($caRows | Where-Object { $_.UserRiskLevels -and $_.State -eq 'enabled' }).Count
    Add-Metric 'CA policies using sign-in risk (enabled)' @($caRows | Where-Object { $_.SignInRiskLevels -and $_.State -eq 'enabled' }).Count
    Add-Metric 'CA risk policies in report-only' @($caRows | Where-Object State -eq 'enabledForReportingButNotEnforced').Count
    if ($caRead) {
        Add-Metric 'Accounts excluded from an enabled risk policy' @($exRows | Where-Object { $_.PolicyState -eq 'enabled' -and $_.PrincipalId -and $_.EffectiveForCa -eq $true } | ForEach-Object { $_.PrincipalId } | Sort-Object -Unique).Count
        Add-Metric 'Privileged accounts excluded from an enabled risk policy' @($exRows | Where-Object { $_.PolicyState -eq 'enabled' -and $_.IsPrivileged -eq $true -and $_.EffectiveForCa -eq $true } | ForEach-Object { $_.PrincipalId } | Sort-Object -Unique).Count
        Add-Metric 'At-risk users excluded from an enabled risk policy' @($exRows | Where-Object { $_.PolicyState -eq 'enabled' -and $_.CurrentlyAtRisk -and $_.EffectiveForCa -eq $true } | ForEach-Object { $_.PrincipalId } | Sort-Object -Unique).Count
    }
    if ($IncludeRiskHistory) { Add-Metric 'Risk events dismissed by an admin (history read)' @($histRows | Where-Object { $_.Flags -match 'AdminDismissed' }).Count }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ DetectionLookbackDays = $DetectionLookbackDays; RiskStaleDays = $RiskStaleDays; IncludeRemediated = [bool]$IncludeRemediated; IncludeRiskHistory = [bool]$IncludeRiskHistory; MaxHistoryUsers = $MaxHistoryUsers; SkipServicePrincipals = [bool]$SkipServicePrincipals; SkipPrivilegeJoin = [bool]$SkipPrivilegeJoin }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
