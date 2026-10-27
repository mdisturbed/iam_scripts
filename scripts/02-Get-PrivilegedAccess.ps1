<#
.SYNOPSIS
    Read-only discovery of privileged access in Microsoft Entra ID, resolved down to the real accounts.

.DESCRIPTION
    Exports the evidence needed to measure "privileged account sprawl" on the Entra side:
      - Active directory-role assignments (permanent vs time-bound, direct vs via group), with
        administrative-unit scopes resolved to names
      - Eligible (PIM) directory-role assignments
      - Members of every group that holds a role (expanded transitively)
      - Role-assignable groups and their owners
      - The effective privileged set: every principal that holds a role directly, through a group
        (active or eligible), through PIM for Groups eligibility, or as owner of a role-holding group
      - One row per privileged user with sync source, last sign-in, MFA registration,
        phishing-resistant MFA, break-glass status and flags
      - Service principals and managed identities that hold roles, with owners, credentials and
        last sign-in
      - Custom role definitions with risky permissions flagged
      - Administrative units and their scoped role members
      - PIM self-activations over a lookback window
      - A summary of headline metrics

    Falls back to /roleManagement/directory/roleAssignments if PIM schedule APIs are not
    available (no Entra ID P2 / Governance licence). Eligible assignments are then marked
    EvidenceUnavailable rather than silently empty.

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\02-PrivilegedAccess\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\02-Get-PrivilegedAccess.ps1
.EXAMPLE
    .\02-Get-PrivilegedAccess.ps1 -StaleDays 60 -ActivationDays 90
.EXAMPLE
    .\02-Get-PrivilegedAccess.ps1 -BreakGlassUpns 'breakglass1@contoso.local','breakglass2@contoso.local'

.NOTES
    Version : 1.1.1
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : RoleManagement.Read.Directory, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All,
              PrivilegedEligibilitySchedule.Read.AzureADGroup, Policy.Read.All (only with -BreakGlassUpns)
    Licence : signInActivity and service principal sign-in activity need Entra ID P1; PIM schedules,
              PIM for Groups and activation history need P2 / ID Governance.
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
    [string[]]$BreakGlassUpns = @(),
    [ValidateRange(1, 365)]
    [int]$ActivationDays = 30,
    [switch]$SkipServicePrincipalDetail,
    [switch]$SkipAdministrativeUnits
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '02-PrivilegedAccess'
$ScriptVersion = '1.1.1'
$RequiredScopes = @('RoleManagement.Read.Directory', 'Directory.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
if ($BreakGlassUpns.Count -gt 0) { $RequiredScopes += 'Policy.Read.All' }

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

# Custom-role permissions that let the holder take over identities, roles, apps or policies.
$RiskyActionPattern = '^microsoft\.directory/(roleAssignments|roleDefinitions|applications/credentials|servicePrincipals/credentials|users/password|users/authenticationMethods|conditionalAccessPolicies|groups/members|.*/allProperties/allTasks)'

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- Role definitions ----
    $roleDefs = @{}
    $roleTemplateByName = @{}
    foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn' -Label 'roleDefinitions')) {
        $roleDefs[$r.id] = $r
        if ($r.templateId -and -not $roleDefs.ContainsKey($r.templateId)) { $roleDefs[$r.templateId] = $r }
        $roleTemplateByName["$($r.displayName)"] = $(if ($r.templateId) { "$($r.templateId)" } else { "$($r.id)" })
    }
    function Get-RoleInfo {
        param([string]$RoleDefinitionId)
        $d = $roleDefs[$RoleDefinitionId]
        $template = $(if ($d -and $d.templateId) { $d.templateId } else { $RoleDefinitionId })
        [pscustomobject]@{
            Name      = $(if ($d) { $d.displayName } else { $RoleDefinitionId })
            IsBuiltIn = $(if ($d) { $d.isBuiltIn } else { '' })
            IsTier0   = $script:Tier0RoleTemplates.ContainsKey("$template")
        }
    }

    function Get-PrincipalInfo {
        param($Principal, [string]$PrincipalId)
        if ($Principal) {
            $type = ($Principal.'@odata.type' -replace '#microsoft.graph.', '')
            $upn = $(if ($Principal.PSObject.Properties.Name -contains 'userPrincipalName') { $Principal.userPrincipalName } else { '' })
            return [pscustomobject]@{ Type = $type; Name = $Principal.displayName; Upn = $upn }
        }
        $label = Resolve-DirectoryObject $PrincipalId
        return [pscustomobject]@{ Type = 'unknown'; Name = $label; Upn = '' }
    }

    # ---- Administrative units (also used to name AU-scoped assignments) ----
    $auNames = @{}
    $auList = $null
    $auError = ''
    if (-not $SkipAdministrativeUnits) {
        try {
            $auList = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/directory/administrativeUnits' -Label 'administrativeUnits'
            foreach ($au in $auList) { $auNames["$($au.id)"] = "$($au.displayName)" }
        }
        catch {
            $auError = $_
            Write-RunLog ("Administrative units not readable ({0}); AU scopes resolved one by one." -f $_.Exception.Message) 'WARN'
        }
    }
    function Resolve-ScopeName {
        param([string]$Scope)
        if (-not $Scope -or $Scope -eq '/') { return 'Tenant' }
        if ($Scope -match '^/administrativeUnits/(.+)$') {
            $auId = $Matches[1]
            if (-not $auNames.ContainsKey($auId)) {
                try {
                    $o = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/directory/administrativeUnits/{0}?`$select=id,displayName" -f $auId)
                    $auNames[$auId] = "$($o.displayName)"
                }
                catch {
                    $code = Get-HttpStatusFromError $_
                    $auNames[$auId] = $(if ($code -eq 404) { "$auId (deleted)" } else { "$auId (unresolved: HTTP $code)" })
                }
            }
            return "Administrative unit: $($auNames[$auId])"
        }
        if ($Scope -match '^/([^/]+)$') { return "Object: $(Resolve-DirectoryObject $Matches[1])" }
        return $Scope
    }

    # ---- 1. Active assignments (PIM schedule instances, fallback to roleAssignments) ----
    $activeRows = [System.Collections.Generic.List[object]]::new()
    $pimAvailable = $true
    try {
        $active = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal' -Label 'roleAssignmentScheduleInstances'
        foreach ($a in $active) {
            $role = Get-RoleInfo $a.roleDefinitionId
            $pr = Get-PrincipalInfo $a.principal $a.principalId
            $activeRows.Add([pscustomobject][ordered]@{
                RoleName        = $role.Name
                IsTier0Role     = $role.IsTier0
                RoleIsBuiltIn   = $role.IsBuiltIn
                PrincipalId     = $a.principalId
                PrincipalType   = $pr.Type
                PrincipalName   = $pr.Name
                PrincipalUPN    = $pr.Upn
                AssignmentType  = $a.assignmentType          # Assigned | Activated
                MemberType      = $a.memberType              # Direct | Group | Inherited
                StartDateTime   = $a.startDateTime
                EndDateTime     = $a.endDateTime
                IsPermanent     = ($a.assignmentType -eq 'Assigned' -and -not $a.endDateTime)
                DirectoryScope  = $a.directoryScopeId
                Source          = 'roleAssignmentScheduleInstances'
                ScopeName       = Resolve-ScopeName $a.directoryScopeId
            })
        }
    }
    catch {
        $pimAvailable = $false
        Write-RunLog ("PIM schedule API unavailable ({0}); falling back to roleAssignments." -f $_.Exception.Message) 'WARN'
        $active = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal' -Label 'roleAssignments'
        foreach ($a in $active) {
            $role = Get-RoleInfo $a.roleDefinitionId
            $pr = Get-PrincipalInfo $a.principal $a.principalId
            $activeRows.Add([pscustomobject][ordered]@{
                RoleName        = $role.Name
                IsTier0Role     = $role.IsTier0
                RoleIsBuiltIn   = $role.IsBuiltIn
                PrincipalId     = $a.principalId
                PrincipalType   = $pr.Type
                PrincipalName   = $pr.Name
                PrincipalUPN    = $pr.Upn
                AssignmentType  = 'Assigned'
                MemberType      = 'Direct'
                StartDateTime   = ''
                EndDateTime     = ''
                IsPermanent     = $true
                DirectoryScope  = $a.directoryScopeId
                Source          = 'roleAssignments (no PIM data)'
                ScopeName       = Resolve-ScopeName $a.directoryScopeId
            })
        }
    }
    Export-Dataset -Name 'role-assignments-active' -Rows $activeRows -Note $(if ($pimAvailable) { '' } else { 'PIM not available: permanence cannot be distinguished; all shown as permanent' })

    # ---- 2. Eligible assignments ----
    $eligibleRows = [System.Collections.Generic.List[object]]::new()
    try {
        $eligible = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal' -Label 'roleEligibilityScheduleInstances'
        foreach ($e in $eligible) {
            $role = Get-RoleInfo $e.roleDefinitionId
            $pr = Get-PrincipalInfo $e.principal $e.principalId
            $eligibleRows.Add([pscustomobject][ordered]@{
                RoleName       = $role.Name
                IsTier0Role    = $role.IsTier0
                PrincipalId    = $e.principalId
                PrincipalType  = $pr.Type
                PrincipalName  = $pr.Name
                PrincipalUPN   = $pr.Upn
                MemberType     = $e.memberType
                StartDateTime  = $e.startDateTime
                EndDateTime    = $e.endDateTime
                IsPermanentlyEligible = (-not $e.endDateTime)
                DirectoryScope = $e.directoryScopeId
                ScopeName      = Resolve-ScopeName $e.directoryScopeId
            })
        }
        Export-Dataset -Name 'role-assignments-eligible' -Rows $eligibleRows
    }
    catch { Set-DatasetStatus -Name 'role-assignments-eligible' -Status 'EvidenceUnavailable' -Note ("PIM eligibility not readable: {0}" -f $_.Exception.Message) }

    # ---- 3. Expand role-holding groups ----
    $groupMemberRows = [System.Collections.Generic.List[object]]::new()
    $roleGroups = @{}
    foreach ($row in @($activeRows) + @($eligibleRows)) {
        if ($row.PrincipalType -eq 'group') {
            $kind = $(if ($row.PSObject.Properties.Name -contains 'AssignmentType') { 'Active' } else { 'Eligible' })
            if (-not $roleGroups.ContainsKey($row.PrincipalId)) { $roleGroups[$row.PrincipalId] = [System.Collections.Generic.List[string]]::new() }
            $roleGroups[$row.PrincipalId].Add(('{0} [{1}]' -f $row.RoleName, $kind))
        }
    }
    $groupFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($gid in $roleGroups.Keys) {
        $gname = Resolve-DirectoryObject $gid
        try { $members = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers" -f $gid) -Label "transitiveMembers $gid" }
        catch {
            $groupFailures.Add(('{0} (HTTP {1})' -f $gname, (Get-HttpStatusFromError $_)))
            Write-RunLog ("Members of role-holding group {0} not readable: {1}" -f $gname, $_.Exception.Message) 'WARN'
            continue
        }
        foreach ($m in $members) {
            $groupMemberRows.Add([pscustomobject][ordered]@{
                GroupId        = $gid
                GroupName      = $gname
                RolesGranted   = Join-Values ($roleGroups[$gid] | Sort-Object -Unique)
                MemberId       = $m.id
                MemberType     = ($m.'@odata.type' -replace '#microsoft.graph.', '')
                MemberName     = $m.displayName
                MemberUPN      = $(if ($m.PSObject.Properties.Name -contains 'userPrincipalName') { $m.userPrincipalName } else { '' })
                AccountEnabled = $(if ($m.PSObject.Properties.Name -contains 'accountEnabled') { $m.accountEnabled } else { '' })
            })
        }
    }
    $gmNote = "{0} role-holding groups expanded" -f $roleGroups.Count
    if ($groupFailures.Count) { $gmNote += "; NOT readable: $(Join-Values $groupFailures)" }
    Export-Dataset -Name 'role-group-members' -Rows $groupMemberRows -Status $(if ($groupFailures.Count) { 'Partial' } else { 'Completed' }) -Note $gmNote

    # ---- 4. Role-assignable groups ----
    try {
        $rag = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true&$count=true&$select=id,displayName,createdDateTime,onPremisesSyncEnabled,securityEnabled,mailEnabled,description' -Eventual -Label 'roleAssignableGroups'
        $ownerFailures = 0
        $ragRows = foreach ($g in $rag) {
            $owners = @()
            $ownerError = ''
            try { $owners = (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/owners?`$select=id,displayName,userPrincipalName" -f $g.id) -Label "owners $($g.id)") }
            catch { $ownerError = 'Unresolved (HTTP {0})' -f (Get-HttpStatusFromError $_); $ownerFailures++ }
            [pscustomobject][ordered]@{
                GroupId          = $g.id
                GroupName        = $g.displayName
                Created          = $g.createdDateTime
                SyncedFromOnPrem = [bool]$g.onPremisesSyncEnabled
                HoldsRoles       = Join-Values ($(if ($roleGroups.ContainsKey($g.id)) { $roleGroups[$g.id] | Sort-Object -Unique } else { @() }))
                OwnerCount       = $(if ($ownerError) { '' } else { $owners.Count })
                Owners           = $(if ($ownerError) { $ownerError } else { Join-Values ($owners | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) })
                HasDescription   = [bool]$g.description
            }
        }
        Export-Dataset -Name 'role-assignable-groups' -Rows $ragRows -Status $(if ($ownerFailures) { 'Partial' } else { 'Completed' }) -Note $(if ($ownerFailures) { "$ownerFailures group(s) with owners not readable" } else { '' })
    }
    catch { Set-DatasetStatus -Name 'role-assignable-groups' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 5. Effective privileged set (direct, group, eligible, PIM for Groups, group owners) ----
    $privSet = Get-EffectivePrivilegedSet
    if ($privSet) {
        Export-Dataset -Name 'privileged-principals-effective' -Rows $privSet.Rows -Status $(if (Test-PrivSetComplete $privSet) { 'Completed' } else { 'Partial' }) -Note (Get-PrivSetStatusText $privSet)
    }
    else { Set-DatasetStatus -Name 'privileged-principals-effective' -Status $script:PrivSetErrorStatus -Note $script:PrivSetError }

    # ---- Break-glass: which enforced CA policies still apply to each break-glass account ----
    $breakGlass = @{}
    foreach ($b in $BreakGlassUpns) { if ($b) { $breakGlass[$b.Trim().ToLowerInvariant()] = $true } }
    $caPolicies = $null
    $caError = ''
    if ($breakGlass.Count) {
        try { $caPolicies = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'caPolicies' }
        catch {
            $caError = '{0} (HTTP {1})' -f (Get-FailureStatus $_), (Get-HttpStatusFromError $_)
            Write-RunLog ("CA policies not readable; break-glass exclusion not evaluated ({0})" -f $_.Exception.Message) 'WARN'
        }
    }
    function Get-CaCoverage {
        # Returns @{ Excluded = 'True'/'False'/'Unknown (...)'; Applying = 'policy names' } for one user.
        param([string]$UserId, $Rows, [bool]$IsGuest)
        if ($null -eq $caPolicies) { return @{ Excluded = "Unknown (CA policies not readable: $caError)"; Applying = '' } }
        $enforced = @($caPolicies | Where-Object { "$($_.state)" -eq 'enabled' })
        $groupIds = @{}
        try {
            foreach ($g in (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/transitiveMemberOf?`$select=id" -f $UserId) -Label "transitiveMemberOf $UserId")) { $groupIds["$($g.id)"] = $true }
        }
        catch { return @{ Excluded = ('Unknown (group membership not readable: HTTP {0})' -f (Get-HttpStatusFromError $_)); Applying = '' } }
        $roleIds = @{}
        foreach ($r in @($Rows | Where-Object { Test-RowEffectiveForCa $_ })) { if ($roleTemplateByName.ContainsKey("$($r.Role)")) { $roleIds[$roleTemplateByName["$($r.Role)"]] = $true } }
        $applying = @()
        foreach ($p in $enforced) {
            $u = $p.conditions.users
            $included = (@($u.includeUsers) -contains 'All') -or (@($u.includeUsers) -contains $UserId) -or
                [bool](@($u.includeGroups | Where-Object { $groupIds.ContainsKey("$_") }).Count) -or
                [bool](@($u.includeRoles | Where-Object { $roleIds.ContainsKey("$_") }).Count) -or
                ($IsGuest -and [bool](Get-OptionalValue $u 'includeGuestsOrExternalUsers'))
            $excluded = (@($u.excludeUsers) -contains $UserId) -or
                [bool](@($u.excludeGroups | Where-Object { $groupIds.ContainsKey("$_") }).Count) -or
                [bool](@($u.excludeRoles | Where-Object { $roleIds.ContainsKey("$_") }).Count)
            if ($included -and -not $excluded) { $applying += "$($p.displayName)" }
        }
        return @{ Excluded = $(if ($applying.Count) { 'False' } else { 'True' }); Applying = (Join-Values $applying) }
    }

    # ---- 6. Per privileged user (every user in the effective set) ----
    $privRows = [System.Collections.Generic.List[object]]::new()
    $signInLicenceBlocked = $false
    $signInPerUserFailures = 0
    $unresolvedUsers = 0
    $mfaBlocked = ''
    $baseSelect = 'id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,createdDateTime'
    $principalIds = @()
    if ($privSet) { $principalIds = @($privSet.ByPrincipal.Keys) }
    foreach ($uid in $principalIds) {
        $rs = @($privSet.ByPrincipal[$uid])
        $first = $rs[0]
        if ($first.PrincipalType -notin @('user', 'unknown')) { continue }
        $u = $null
        $siaRead = $false
        $siaFailed = $false
        $readError = ''
        if (-not $signInLicenceBlocked) {
            try {
                $u = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select={1},signInActivity" -f $uid, $baseSelect)
                $siaRead = $true
            }
            catch {
                if (Test-LicenceError $_) {
                    $signInLicenceBlocked = $true
                    Write-RunLog ("signInActivity needs Entra ID P1 ({0}); continuing without last sign-in for all users." -f $_.Exception.Message) 'WARN'
                }
                else { $siaFailed = $true }
            }
        }
        if (-not $u) {
            try {
                $u = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select={1}" -f $uid, $baseSelect)
                if ($siaFailed) {
                    $signInPerUserFailures++
                    Write-RunLog ("User {0}: signInActivity not readable for this user; staleness not evaluated for it." -f $uid) 'WARN'
                }
            }
            catch {
                $readError = 'HTTP {0}' -f (Get-HttpStatusFromError $_)
                $unresolvedUsers++
                Write-RunLog ("Privileged principal {0} not readable as a user ({1}); kept with Status Unresolved." -f $uid, $_.Exception.Message) 'WARN'
            }
        }
        $last = $null
        if ($u -and $siaRead -and $u.PSObject.Properties.Name -contains 'signInActivity' -and $u.signInActivity) {
            $cands = @($u.signInActivity.lastSuccessfulSignInDateTime, $u.signInActivity.lastSignInDateTime, $u.signInActivity.lastNonInteractiveSignInDateTime) | Where-Object { $_ }
            if ($cands) { $last = ($cands | ForEach-Object { ([datetime]$_).ToUniversalTime() } | Sort-Object -Descending | Select-Object -First 1) }
        }
        $mfa = $null
        if (-not $mfaBlocked) {
            try { $mfa = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails/{0}" -f $uid) }
            catch {
                $code = Get-HttpStatusFromError $_
                if ($code -eq 403 -or (Test-LicenceError $_)) {
                    $mfaBlocked = '{0} (HTTP {1})' -f $(if (Test-LicenceError $_) { 'EvidenceUnavailable' } else { 'Blocked' }), $code
                    Write-RunLog ("Registration details not readable ({0}); MFA columns left blank." -f $_.Exception.Message) 'WARN'
                }
            }
        }
        $upn = $(if ($u) { "$($u.userPrincipalName)" } else { "$($first.Upn)" })
        $userType = $(if ($u) { "$($u.userType)" } else { "$($first.UserType)" })
        $enabled = $(if ($u) { $u.accountEnabled } else { $first.AccountEnabled })
        $roleNames = @($rs | ForEach-Object { $_.Role } | Sort-Object -Unique)
        $roleTexts = @($rs | ForEach-Object {
                $state = "$($_.AssignmentState)"
                if ($state -eq 'Active' -and -not $_.EndDateTime -and $_.Via -in @('Direct', 'Group member')) { $state = 'Active,Permanent' }
                if ($_.ViaGroup) { '{0} [{1} via {2}: {3}]' -f $_.Role, $state, $_.Via, $_.ViaGroup } else { '{0} [{1}]' -f $_.Role, $state }
            } | Sort-Object -Unique)
        $isTier0 = [bool](@($rs | Where-Object { $_.Tier0 }).Count)
        $viaPimGroups = [bool](@($rs | Where-Object { "$($_.Via)" -like 'PIM for Groups*' }).Count)
        $ownerPath = [bool](@($rs | Where-Object { $_.Via -eq 'Owner of role-holding group' }).Count)
        $permanentActive = [bool](@($rs | Where-Object { "$($_.AssignmentState)" -eq 'Active' -and -not $_.EndDateTime -and $_.Via -in @('Direct', 'Group member') }).Count)
        $phish = $(if ($mfa) { Test-PhishResistantMethod $mfa.methodsRegistered } else { '' })
        $isBreakGlass = [bool]($upn -and $breakGlass.ContainsKey($upn.ToLowerInvariant()))
        $ca = @{ Excluded = ''; Applying = '' }
        if ($isBreakGlass) { $ca = Get-CaCoverage -UserId $uid -Rows $rs -IsGuest ($userType -eq 'Guest') }

        $flags = @()
        if ($u -and $u.onPremisesSyncEnabled) { $flags += 'SyncedFromOnPrem' }
        if ("$enabled" -eq 'False') { $flags += 'Disabled' }
        if ($siaRead -and (-not $last -or $last -lt $script:RunStartUtc.AddDays(-$StaleDays))) { $flags += "NoSignIn${StaleDays}d" }
        if ($mfa -and -not $mfa.isMfaRegistered) { $flags += 'NotMfaRegistered' }
        if ($permanentActive) { $flags += 'PermanentActive' }
        if ($userType -eq 'Guest') { $flags += 'Guest' }
        if ($isTier0 -and $mfa -and -not $phish) { $flags += 'Tier0WithoutPhishResistantMfa' }
        if ($isBreakGlass) { $flags += 'BreakGlass' }
        if ($isBreakGlass -and $ca.Excluded -eq 'False') { $flags += 'BreakGlassNotExcludedFromAllCa' }

        $status = 'Resolved'
        if ($readError) { $status = "Unresolved ($readError)" }
        elseif (-not $siaRead) { $status = 'Resolved (sign-in activity not readable)' }

        $privRows.Add([pscustomobject][ordered]@{
            UserId            = $uid
            UserPrincipalName = $upn
            DisplayName       = $(if ($u) { $u.displayName } else { $first.PrincipalName })
            UserType          = $userType
            AccountEnabled    = $enabled
            SyncedFromOnPrem  = $(if ($u) { [bool]$u.onPremisesSyncEnabled } else { '' })
            Created           = $(if ($u) { $u.createdDateTime } else { '' })
            LastSignInUtc     = $(if ($last) { $last.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            IsMfaRegistered   = $(if ($mfa) { $mfa.isMfaRegistered } else { '' })
            MethodsRegistered = $(if ($mfa) { Join-Values $mfa.methodsRegistered } else { '' })
            HoldsTier0Role    = $isTier0
            RoleCount         = $roleNames.Count
            Roles             = Join-Values $roleTexts
            Flags             = Join-Values $flags
            Paths             = (Get-PrivilegeSummary -Set $privSet -PrincipalId $uid).Paths
            ViaPimForGroups   = $viaPimGroups
            IsGroupOwnerPath  = $ownerPath
            PhishResistantMfa = $phish
            IsBreakGlass      = $isBreakGlass
            ExcludedFromAllCa = $ca.Excluded
            CaPoliciesApplying = $ca.Applying
            Status            = $status
        })
    }
    $privRows = @($privRows | Sort-Object @{ Expression = 'HoldsTier0Role'; Descending = $true }, UserPrincipalName)
    $missingBreakGlass = @($breakGlass.Keys | Where-Object { $k = $_; -not @($privRows | Where-Object { "$($_.UserPrincipalName)".ToLowerInvariant() -eq $k }).Count })
    foreach ($m in $missingBreakGlass) { Write-RunLog ("Break-glass account {0} holds no directory role; not in privileged-users." -f $m) 'WARN' }
    if ($privSet) {
        $notes = @()
        if ($signInLicenceBlocked) { $notes += 'signInActivity unavailable (licence); staleness not evaluated' }
        if ($signInPerUserFailures) { $notes += "signInActivity not readable for $signInPerUserFailures user(s)" }
        if ($unresolvedUsers) { $notes += "$unresolvedUsers principal(s) not readable (Status Unresolved)" }
        if ($mfaBlocked) { $notes += "registration details $mfaBlocked" }
        if ($caError) { $notes += "break-glass CA check not evaluated: CA policies $caError" }
        if (-not (Test-PrivSetComplete $privSet)) { $notes += "privileged set incomplete: $(Get-PrivSetStatusText $privSet)" }
        $puStatus = $(if ($unresolvedUsers -or $mfaBlocked -or $caError -or -not (Test-PrivSetComplete $privSet)) { 'Partial' } else { 'Completed' })
        Export-Dataset -Name 'privileged-users' -Rows $privRows -Status $puStatus -Note ($notes -join '; ')
    }
    else { Set-DatasetStatus -Name 'privileged-users' -Status $script:PrivSetErrorStatus -Note "Effective privileged set not readable: $script:PrivSetError" }

    # ---- 7. Service principals and managed identities holding roles ----
    $spOut = [System.Collections.Generic.List[object]]::new()
    if ($SkipServicePrincipalDetail) { Set-DatasetStatus -Name 'privileged-service-principals' -Status 'Deferred' -Note '-SkipServicePrincipalDetail' }
    elseif (-not $privSet) { Set-DatasetStatus -Name 'privileged-service-principals' -Status $script:PrivSetErrorStatus -Note 'Depends on the effective privileged set' }
    else {
        $spSignInState = ''
        $spIssues = 0
        foreach ($sid in @($privSet.ByPrincipal.Keys)) {
            $rs = @($privSet.ByPrincipal[$sid])
            if ($rs[0].PrincipalType -ne 'servicePrincipal') { continue }
            $sp = $null
            $status = 'Resolved'
            try { $sp = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}?`$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,passwordCredentials,keyCredentials" -f $sid) }
            catch { $status = 'Unresolved (HTTP {0})' -f (Get-HttpStatusFromError $_); $spIssues++ }
            $spType = $(if ($sp) { "$($sp.servicePrincipalType)" } else { '' })
            $owners = ''; $ownerCount = ''
            try {
                $o = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/owners?`$select=id,displayName,userPrincipalName" -f $sid) -Label "spOwners $sid"
                $ownerCount = $o.Count
                $owners = Join-Values ($o | ForEach-Object { if ((Get-OptionalValue $_ 'userPrincipalName')) { $_.userPrincipalName } else { $_.displayName } })
            }
            catch { $owners = 'Unresolved (HTTP {0})' -f (Get-HttpStatusFromError $_); $spIssues++ }
            $app = $null; $appOwners = ''; $appNote = ''
            if ($sp -and $spType -eq 'Application' -and $sp.appId) {
                try {
                    $appResp = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '{0}'&`$select=id,displayName,passwordCredentials,keyCredentials" -f $sp.appId)
                    if (@($appResp.value).Count) {
                        $app = @($appResp.value)[0]
                        try {
                            $ao = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/owners?`$select=id,displayName,userPrincipalName" -f $app.id) -Label "appOwners $($app.id)"
                            $appOwners = Join-Values ($ao | ForEach-Object { if ((Get-OptionalValue $_ 'userPrincipalName')) { $_.userPrincipalName } else { $_.displayName } })
                        }
                        catch { $appOwners = 'Unresolved (HTTP {0})' -f (Get-HttpStatusFromError $_) }
                    }
                    else { $appNote = 'NoAppObjectInTenant' }
                }
                catch { $appNote = 'AppUnresolved'; $spIssues++ }
            }
            $creds = @()
            foreach ($src in @($sp, $app)) {
                if (-not $src) { continue }
                foreach ($c in @(Get-OptionalValue $src 'passwordCredentials') + @(Get-OptionalValue $src 'keyCredentials')) { if ($c -and $c.endDateTime) { $creds += ([datetime]$c.endDateTime).ToUniversalTime() } }
            }
            $future = @($creds | Where-Object { $_ -ge $script:RunStartUtc } | Sort-Object)
            $expired = @($creds | Where-Object { $_ -lt $script:RunStartUtc }).Count
            $lastSignIn = ''
            $signInRead = $false
            if ($sp -and $sp.appId -and -not $spSignInState) {
                try {
                    $si = Invoke-GraphGet -Uri ("https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?`$filter=appId eq '{0}'" -f $sp.appId)
                    $signInRead = $true
                    $v = @($si.value)
                    if ($v.Count -and $v[0].lastSignInActivity) { $lastSignIn = ConvertTo-UtcText $v[0].lastSignInActivity.lastSignInDateTime }
                }
                catch {
                    $spSignInState = '{0} (HTTP {1})' -f $(if (Test-LicenceError $_) { 'EvidenceUnavailable' } else { 'Blocked' }), (Get-HttpStatusFromError $_)
                    Write-RunLog ("Service principal sign-in activity not readable ({0}); LastSignInUtc left blank." -f $_.Exception.Message) 'WARN'
                }
            }
            $isTier0 = [bool](@($rs | Where-Object { $_.Tier0 }).Count)
            $spPwd = @(Get-OptionalValue $sp 'passwordCredentials' | Where-Object { $_ }).Count
            $flags = @()
            if ($isTier0) { $flags += 'Tier0ServicePrincipal' }
            if ($spType -ne 'ManagedIdentity' -and "$ownerCount" -eq '0' -and -not $appOwners) { $flags += 'NoOwner' }
            if ($spPwd -gt 0) { $flags += 'SecretOnServicePrincipal' }
            if ($expired -gt 0) { $flags += 'ExpiredCredential' }
            if ($signInRead -and (-not $lastSignIn -or ([datetime]$lastSignIn).ToUniversalTime() -lt $script:RunStartUtc.AddDays(-$StaleDays))) { $flags += "NoSignIn${StaleDays}d" }
            if ($sp -and -not $sp.accountEnabled) { $flags += 'Disabled' }
            if ($appNote) { $flags += $appNote }
            $spOut.Add([pscustomobject][ordered]@{
                ServicePrincipalId         = $sid
                DisplayName                = $(if ($sp) { $sp.displayName } else { $rs[0].PrincipalName })
                AppId                      = $(if ($sp) { $sp.appId } else { '' })
                ServicePrincipalType       = $spType
                AccountEnabled             = $(if ($sp) { $sp.accountEnabled } else { $rs[0].AccountEnabled })
                HoldsTier0Role             = $isTier0
                Roles                      = Join-Values ($rs | ForEach-Object { $_.Role } | Sort-Object -Unique)
                Paths                      = (Get-PrivilegeSummary -Set $privSet -PrincipalId $sid).Paths
                Owners                     = $owners
                OwnerCount                 = $ownerCount
                AppOwners                  = $appOwners
                SpPasswordCredentials      = $(if ($sp) { $spPwd } else { '' })
                SpKeyCredentials           = $(if ($sp) { @(Get-OptionalValue $sp 'keyCredentials' | Where-Object { $_ }).Count } else { '' })
                AppPasswordCredentials     = $(if ($app) { @(Get-OptionalValue $app 'passwordCredentials' | Where-Object { $_ }).Count } else { '' })
                AppKeyCredentials          = $(if ($app) { @(Get-OptionalValue $app 'keyCredentials' | Where-Object { $_ }).Count } else { '' })
                NearestCredentialExpiryUtc = $(if ($future.Count) { $future[0].ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                ExpiredCredentials         = $expired
                LastSignInUtc              = $lastSignIn
                Flags                      = Join-Values $flags
                Status                     = $status
            })
        }
        $spNote = @()
        if ($spIssues) { $spNote += "$spIssues read(s) failed (see Status / Owners)" }
        if ($spSignInState) { $spNote += "sign-in activity $spSignInState" }
        Export-Dataset -Name 'privileged-service-principals' -Rows $spOut -Status $(if ($spIssues -or $spSignInState) { 'Partial' } else { 'Completed' }) -Note ($spNote -join '; ')
    }

    # ---- 8. Custom role definitions ----
    $customRows = @()
    try {
        $cr = Invoke-GraphGetAll -Uri ('https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$filter=' + [uri]::EscapeDataString('isBuiltIn eq false')) -Label 'customRoleDefinitions'
        $customRows = foreach ($d in $cr) {
            $actions = @($d.rolePermissions | ForEach-Object { @($_.allowedResourceActions) } | Where-Object { $_ } | Sort-Object -Unique)
            $risky = @($actions | Where-Object { $_ -match $RiskyActionPattern })
            $holders = @()
            if ($privSet) { $holders = @($privSet.Rows | Where-Object { $_.Role -eq $d.displayName -and $_.PrincipalType -ne 'group' }) }
            $holderIds = @($holders | ForEach-Object { $_.PrincipalId } | Sort-Object -Unique)
            $flags = @()
            if ($risky.Count) { $flags += 'RiskyPermissions' }
            if ($risky.Count -and $holderIds.Count) { $flags += 'AssignedRiskyCustomRole' }
            if ($privSet -and -not $holderIds.Count) { $flags += 'Unassigned' }
            if ((Get-OptionalValue $d 'isEnabled') -eq $false) { $flags += 'Disabled' }
            [pscustomobject][ordered]@{
                RoleDefinitionId       = $d.id
                DisplayName            = $d.displayName
                Description            = $d.description
                IsEnabled              = Get-OptionalValue $d 'isEnabled'
                AllowedActionCount     = $actions.Count
                RiskyActionCount       = $risky.Count
                RiskyActions           = Join-Values $risky
                AllowedResourceActions = Join-Values $actions
                Conditions             = Join-Values ($d.rolePermissions | ForEach-Object { Get-OptionalValue $_ 'condition' })
                AssignedPrincipals     = $(if ($privSet) { $holderIds.Count } else { '' })
                AssignedTo             = Join-Values ($holders | ForEach-Object { if ($_.Upn) { $_.Upn } else { $_.PrincipalName } } | Sort-Object -Unique)
                Flags                  = Join-Values $flags
            }
        }
        Export-Dataset -Name 'custom-role-definitions' -Rows $customRows -Note $(if ($privSet) { '' } else { 'Assignment counts unavailable (privileged set not readable)' })
    }
    catch { Set-DatasetStatus -Name 'custom-role-definitions' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 9. Administrative units ----
    $auRows = @()
    if ($SkipAdministrativeUnits) { Set-DatasetStatus -Name 'administrative-units' -Status 'Deferred' -Note '-SkipAdministrativeUnits' }
    elseif ($null -eq $auList) { Set-DatasetStatus -Name 'administrative-units' -Status $(if ($auError -and (Test-LicenceError $auError)) { 'EvidenceUnavailable' } else { 'Blocked' }) -Note ("Not readable: {0}" -f $(if ($auError) { $auError.Exception.Message } else { '' })) }
    else {
        $dirRoleNames = @{}
        try { foreach ($dr in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName,roleTemplateId' -Label 'directoryRoles')) { $dirRoleNames["$($dr.id)"] = "$($dr.displayName)" } }
        catch { Write-RunLog ("Directory roles not readable; scoped role ids shown raw ({0})" -f $_.Exception.Message) 'WARN' }
        $auIssues = 0
        $auRows = foreach ($au in $auList) {
            $memberCount = ''
            try {
                $cnt = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/directory/administrativeUnits/{0}/members/`$count" -f $au.id) -Headers @{ ConsistencyLevel = 'eventual' }
                $n = 0
                if ([int]::TryParse("$cnt".Trim(), [ref]$n)) { $memberCount = $n } else { $memberCount = "$cnt" }
            }
            catch { $memberCount = 'Unresolved (HTTP {0})' -f (Get-HttpStatusFromError $_); $auIssues++ }
            $scoped = ''
            try {
                $srm = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/directory/administrativeUnits/{0}/scopedRoleMembers" -f $au.id) -Label "scopedRoleMembers $($au.id)"
                $scoped = Join-Values ($srm | ForEach-Object {
                        $rn = $(if ($dirRoleNames.ContainsKey("$($_.roleId)")) { $dirRoleNames["$($_.roleId)"] } else { "$($_.roleId)" })
                        '{0} ({1})' -f $_.roleMemberInfo.displayName, $rn
                    })
            }
            catch { $scoped = 'Unresolved (HTTP {0})' -f (Get-HttpStatusFromError $_); $auIssues++ }
            [pscustomobject][ordered]@{
                AdministrativeUnitId         = $au.id
                DisplayName                  = $au.displayName
                Description                  = Get-OptionalValue $au 'description'
                IsMemberManagementRestricted = Get-OptionalValue $au 'isMemberManagementRestricted'
                MembershipType               = Get-OptionalValue $au 'membershipType'
                MembershipRule               = Get-OptionalValue $au 'membershipRule'
                Visibility                   = Get-OptionalValue $au 'visibility'
                MemberCount                  = $memberCount
                ScopedRoleMembers            = $scoped
                ScopedAssignmentsInSet       = $(if ($privSet) { @($privSet.Rows | Where-Object { "$($_.DirectoryScope)" -eq "/administrativeUnits/$($au.id)" }).Count } else { '' })
            }
        }
        Export-Dataset -Name 'administrative-units' -Rows $auRows -Status $(if ($auIssues) { 'Partial' } else { 'Completed' }) -Note $(if ($auIssues) { "$auIssues read(s) failed (see Unresolved cells)" } else { '' })
    }

    # ---- 10. PIM self-activations ----
    $actRows = @()
    $actRead = $false
    try {
        $since = $script:RunStartUtc.AddDays(-$ActivationDays)
        $req = Invoke-GraphGetAll -Uri ('https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests?$filter=' + [uri]::EscapeDataString("action eq 'selfActivate'")) -Label 'roleAssignmentScheduleRequests'
        $actRead = $true
        $actRows = foreach ($q in $req) {
            if (-not $q.createdDateTime -or ([datetime]$q.createdDateTime).ToUniversalTime() -lt $since) { continue }
            $p = Get-PrivPrincipal "$($q.principalId)"
            $role = Get-RoleInfo $q.roleDefinitionId
            $si = Get-OptionalValue $q 'scheduleInfo'
            $ti = Get-OptionalValue $q 'ticketInfo'
            [pscustomobject][ordered]@{
                CreatedUtc       = ConvertTo-UtcText $q.createdDateTime
                PrincipalId      = $q.principalId
                PrincipalName    = $p.Name
                Upn              = $p.Upn
                RoleName         = $role.Name
                IsTier0Role      = $role.IsTier0
                Justification    = $q.justification
                RequestStatus    = $q.status
                ScheduleStartUtc = $(if ($si) { ConvertTo-UtcText $si.startDateTime } else { '' })
                Duration         = $(if ($si -and $si.expiration) { "$($si.expiration.duration)" } else { '' })
                TicketNumber     = $(if ($ti) { "$($ti.ticketNumber)" } else { '' })
                DirectoryScope   = $q.directoryScopeId
                ScopeName        = Resolve-ScopeName $q.directoryScopeId
            }
        }
        $actRows = @($actRows | Sort-Object CreatedUtc -Descending)
        Export-Dataset -Name 'pim-activations' -Rows $actRows -Note "Self-activations created in the last $ActivationDays days"
    }
    catch {
        Set-DatasetStatus -Name 'pim-activations' -Status $(if (Test-LicenceError $_) { 'EvidenceUnavailable' } else { Get-FailureStatus $_ }) -Note ("Activation requests not readable: {0}" -f $_.Exception.Message)
    }

    # ---- 11. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $ga = 'Global Administrator'
    Add-Metric 'PIM schedule data available' $pimAvailable
    Add-Metric 'Active role assignments' $activeRows.Count
    Add-Metric 'Active assignments that are permanent' @($activeRows | Where-Object IsPermanent).Count
    Add-Metric 'Eligible role assignments' $eligibleRows.Count
    Add-Metric 'Global Admin - permanent active (direct principals)' @($activeRows | Where-Object { $_.RoleName -eq $ga -and $_.IsPermanent }).Count
    Add-Metric 'Global Admin - eligible (direct principals)' @($eligibleRows | Where-Object { $_.RoleName -eq $ga }).Count
    Add-Metric 'Role assignments to service principals' @($activeRows | Where-Object PrincipalType -eq 'servicePrincipal').Count
    Add-Metric 'Role-holding groups' $roleGroups.Count
    Add-Metric 'Distinct privileged users' $privRows.Count -Note 'Effective set: direct, group (active or eligible), PIM for Groups and group owners'
    Add-Metric 'Privileged users holding a Tier 0 role' @($privRows | Where-Object HoldsTier0Role).Count
    Add-Metric 'Privileged users synced from on-prem' @($privRows | Where-Object SyncedFromOnPrem).Count -Note 'Best practice: cloud-only admin accounts'
    Add-Metric 'Privileged users not MFA registered' @($privRows | Where-Object { $_.Flags -match 'NotMfaRegistered' }).Count
    Add-Metric "Privileged users with no sign-in in $StaleDays days" @($privRows | Where-Object { $_.Flags -match 'NoSignIn' }).Count -Note $(if ($signInLicenceBlocked) { 'Not evaluated: signInActivity unavailable' } else { '' })
    Add-Metric 'Privileged guest users' @($privRows | Where-Object { $_.Flags -match 'Guest' }).Count
    if ($privSet) {
        Add-Metric 'Effective privileged principals (all types)' $privSet.ByPrincipal.Count -Note (Get-PrivSetStatusText $privSet)
        Add-Metric 'Privileged users reached via PIM for Groups' @($privRows | Where-Object ViaPimForGroups).Count
        Add-Metric 'Privileged users reached as owner of a role-holding group' @($privRows | Where-Object IsGroupOwnerPath).Count -Note 'An owner can add themselves to the group'
        Add-Metric 'Tier 0 users without phishing-resistant MFA' @($privRows | Where-Object { $_.Flags -match 'Tier0WithoutPhishResistantMfa' }).Count
        Add-Metric 'Privileged principals not resolved' @($privRows | Where-Object { $_.Status -like 'Unresolved*' }).Count -Note 'Read failed; not evidence of absence'
    }
    if (-not $SkipServicePrincipalDetail -and $privSet) {
        Add-Metric 'Service principals / managed identities holding roles' $spOut.Count
        Add-Metric 'Service principals holding a Tier 0 role' @($spOut | Where-Object HoldsTier0Role).Count
        Add-Metric 'Role-holding service principals with a secret on the service principal' @($spOut | Where-Object { $_.Flags -match 'SecretOnServicePrincipal' }).Count
    }
    Add-Metric 'Custom roles with risky permissions' @($customRows | Where-Object { $_.Flags -match 'RiskyPermissions' }).Count
    Add-Metric 'Active assignments scoped to an administrative unit' @($activeRows | Where-Object { "$($_.DirectoryScope)" -like '/administrativeUnits/*' }).Count
    if ($actRead) { Add-Metric "PIM self-activations (last $ActivationDays days)" @($actRows).Count }
    if ($breakGlass.Count) {
        Add-Metric 'Break-glass accounts named' $breakGlass.Count
        Add-Metric 'Break-glass accounts still covered by an enforced CA policy' @($privRows | Where-Object { $_.IsBreakGlass -and $_.ExcludedFromAllCa -eq 'False' }).Count
        Add-Metric 'Break-glass accounts holding no directory role' $missingBreakGlass.Count -Note (Join-Values $missingBreakGlass)
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ StaleDays = $StaleDays; BreakGlassUpns = @($BreakGlassUpns); ActivationDays = $ActivationDays; SkipServicePrincipalDetail = [bool]$SkipServicePrincipalDetail; SkipAdministrativeUnits = [bool]$SkipAdministrativeUnits }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
