<#
.SYNOPSIS
    Read-only discovery of MFA coverage in Microsoft Entra ID.

.DESCRIPTION
    Exports the evidence needed to measure "inconsistent MFA coverage":
      - Every Conditional Access policy, flattened, with included/excluded scope, named locations,
        authentication strength combinations, authentication flows and device filters resolved
      - One row per CA exclusion (user, group, role, guest/external)
      - Transitive members of every group excluded from any CA policy
      - The accounts that hold every role excluded from any CA policy (effective privileged set)
      - MFA registration details for every user (registered vs capable vs methods), with method
        strength, phishing-resistant MFA, account enabled / synced state and privilege
      - The authentication methods policy (which methods are on, for whom), the registration
        campaign and security defaults
      - Successful single-factor sign-ins over a lookback window, aggregated by user/app/client,
        with legacy-authentication clients flagged (optionally non-interactive sign-ins too)
      - A summary of headline metrics

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.
    Requested scopes are read scopes only. Nothing in the tenant is created, changed or deleted.

    Output: <OutputRoot>\01-MfaCoverage\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER AuthMode
    Delegated      - interactive sign-in as the operator (needs admin consent for the read scopes).
    AppCertificate - app registration + certificate (TenantId, ClientId, CertificateThumbprint required).

.EXAMPLE
    .\01-Get-MfaCoverage.ps1
.EXAMPLE
    .\01-Get-MfaCoverage.ps1 -SignInLookbackDays 30 -MaxSignInRecords 200000
.EXAMPLE
    .\01-Get-MfaCoverage.ps1 -IncludeNonInteractive -SignInLookbackDays 2
.EXAMPLE
    .\01-Get-MfaCoverage.ps1 -AuthMode AppCertificate -TenantId tenant-id-redacted -ClientId <app-id> -CertificateThumbprint <thumbprint>

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : Policy.Read.All, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All,
              RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup (not with -SkipPrivilegeJoin)
    Licence : Sign-in logs and registration details require Entra ID P1 or higher. PIM data in the
              privileged set needs P2 / ID Governance (marked EvidenceUnavailable without it).
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
    [int]$SignInLookbackDays = 7,
    [int]$MaxSignInRecords = 50000,
    [switch]$SkipSignIns,
    [switch]$SkipExcludedGroupMembers,
    [switch]$SkipPrivilegeJoin,
    [switch]$IncludeNonInteractive
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '01-MfaCoverage'
$ScriptVersion = '1.1.0'
$RequiredScopes = @('Policy.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All')
if (-not $SkipPrivilegeJoin) { $RequiredScopes += @('RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup') }

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

function Get-MethodStrength {
    # Strongest registered method class: PhishResistant > Authenticator > PhoneOnly > EmailOnly > None.
    param($Methods)
    $m = @($Methods | Where-Object { $_ } | ForEach-Object { "$_" })
    if (Test-PhishResistantMethod $m) { return 'PhishResistant' }
    if (@($m | Where-Object { $_ -match '^(microsoftAuthenticator|softwareOneTimePasscode|hardwareOneTimePasscode)' }).Count) { return 'Authenticator' }
    if (@($m | Where-Object { $_ -match '^(mobilePhone|alternateMobilePhone|officePhone)$' }).Count) { return 'PhoneOnly' }
    if (@($m | Where-Object { $_ -eq 'email' }).Count) { return 'EmailOnly' }
    return 'None'
}

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- Lookups: role names, app names, named locations and authentication strengths used inside CA policies ----
    $roleNames = @{}
    try {
        foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName' -Label 'roleDefinitions')) {
            $roleNames[$r.id] = $r.displayName
            if ($r.templateId) { $roleNames[$r.templateId] = $r.displayName }
        }
    }
    catch { Write-RunLog ("Could not read role definitions; role IDs will be shown raw. {0}" -f $_.Exception.Message) 'WARN' }

    $appNames = @{}
    function Resolve-AppId {
        param([string]$AppId)
        if ($AppId -in @('All', 'None', 'Office365', 'MicrosoftAdminPortals')) { return $AppId }
        if ($appNames.ContainsKey($AppId)) { return $appNames[$AppId] }
        $label = $AppId
        try {
            $sp = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=displayName,appId" -f $AppId)
            if (@($sp.value).Count -gt 0) { $label = '{0} ({1})' -f $sp.value[0].displayName, $AppId }
        }
        catch { }
        $appNames[$AppId] = $label
        return $label
    }

    $locationNames = @{}
    try { foreach ($l in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations' -Label 'namedLocations')) { $locationNames["$($l.id)"] = "$($l.displayName)" } }
    catch { Write-RunLog ("Named locations not readable; location IDs shown raw. {0}" -f $_.Exception.Message) 'WARN' }
    function Resolve-LocationId {
        param([string]$Id)
        if ($Id -in @('All', 'AllTrusted')) { return $Id }
        if ($locationNames.ContainsKey($Id)) { return $locationNames[$Id] }
        return "$Id (unresolved)"
    }

    $strengths = @{}
    try { foreach ($s in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies' -Label 'authenticationStrengthPolicies')) { $strengths["$($s.id)"] = $s } }
    catch { Write-RunLog ("Authentication strength policies not readable; combinations taken from the CA policy only. {0}" -f $_.Exception.Message) 'WARN' }

    # ---- Effective privileged set (who really holds each role) ----
    $privSet = $null
    if (-not $SkipPrivilegeJoin) { $privSet = Get-EffectivePrivilegedSet }

    # ---- 1. Conditional Access policies ----
    $policies = $null
    $caRead = $false
    $caError = ''
    $policyRows = [System.Collections.Generic.List[object]]::new()
    $exclusionRows = [System.Collections.Generic.List[object]]::new()
    $excludedGroups = @{}   # groupId -> list of policy names
    $excludedRoles = [System.Collections.Generic.List[object]]::new()
    try {
        $policies = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Label 'caPolicies'
        $caRead = $true
        foreach ($p in $policies) {
            $c = $p.conditions; $u = $c.users; $g = $p.grantControls
            $builtIn = @(); if ($g) { $builtIn = @($g.builtInControls) }
            $authStrength = ''
            $combos = ''
            if ($g -and $g.PSObject.Properties.Name -contains 'authenticationStrength' -and $g.authenticationStrength) {
                $authStrength = $g.authenticationStrength.displayName
                $sid = "$($g.authenticationStrength.id)"
                if ($strengths.ContainsKey($sid)) { $combos = Join-Values $strengths[$sid].allowedCombinations }
                else { $combos = Join-Values (Get-OptionalValue $g.authenticationStrength 'allowedCombinations') }
            }
            $requiresMfa = ($builtIn -contains 'mfa') -or [bool]$authStrength
            $clientTypes = @($c.clientAppTypes)
            $blocksLegacy = ($builtIn -contains 'block') -and (($clientTypes -contains 'exchangeActiveSync') -or ($clientTypes -contains 'other'))
            $guestScope = ''
            if ($u.PSObject.Properties.Name -contains 'includeGuestsOrExternalUsers' -and $u.includeGuestsOrExternalUsers) { $guestScope = $u.includeGuestsOrExternalUsers.guestOrExternalUserTypes }

            $session = @()
            if ($p.sessionControls) {
                foreach ($sp in $p.sessionControls.PSObject.Properties) { if ($sp.Value) { $session += $sp.Name } }
            }
            $flows = Get-OptionalValue $c 'authenticationFlows'
            $devices = Get-OptionalValue $c 'devices'
            $deviceFilter = $(if ($devices -and (Get-OptionalValue $devices 'deviceFilter')) { '{0}: {1}' -f $devices.deviceFilter.mode, $devices.deviceFilter.rule } else { '' })

            $policyRows.Add([pscustomobject][ordered]@{
                PolicyId            = $p.id
                PolicyName          = $p.displayName
                State               = $p.state
                Created             = $p.createdDateTime
                Modified            = $p.modifiedDateTime
                RequiresMfa         = $requiresMfa
                BlocksLegacyAuth    = $blocksLegacy
                GrantOperator       = $(if ($g) { $g.operator } else { '' })
                GrantControls       = Join-Values $builtIn
                AuthStrength        = $authStrength
                IncludeUsers        = Join-Values (@($u.includeUsers) | Where-Object { $_ } | ForEach-Object { Resolve-DirectoryObject $_ })
                ExcludeUsers        = Join-Values (@($u.excludeUsers) | Where-Object { $_ } | ForEach-Object { Resolve-DirectoryObject $_ })
                IncludeGroups       = Join-Values (@($u.includeGroups) | Where-Object { $_ } | ForEach-Object { Resolve-DirectoryObject $_ })
                ExcludeGroups       = Join-Values (@($u.excludeGroups) | Where-Object { $_ } | ForEach-Object { Resolve-DirectoryObject $_ })
                IncludeRoles        = Join-Values (@($u.includeRoles) | Where-Object { $_ } | ForEach-Object { if ($roleNames[$_]) { $roleNames[$_] } else { $_ } })
                ExcludeRoles        = Join-Values (@($u.excludeRoles) | Where-Object { $_ } | ForEach-Object { if ($roleNames[$_]) { $roleNames[$_] } else { $_ } })
                IncludeGuestTypes   = $guestScope
                IncludeApplications = Join-Values (@($c.applications.includeApplications) | Where-Object { $_ } | ForEach-Object { Resolve-AppId $_ })
                ExcludeApplications = Join-Values (@($c.applications.excludeApplications) | Where-Object { $_ } | ForEach-Object { Resolve-AppId $_ })
                UserActions         = Join-Values $c.applications.includeUserActions
                ClientAppTypes      = Join-Values $clientTypes
                IncludePlatforms    = $(if ($c.platforms) { Join-Values $c.platforms.includePlatforms } else { '' })
                IncludeLocations    = $(if ($c.locations) { Join-Values $c.locations.includeLocations } else { '' })
                ExcludeLocations    = $(if ($c.locations) { Join-Values $c.locations.excludeLocations } else { '' })
                SignInRiskLevels    = Join-Values $c.signInRiskLevels
                UserRiskLevels      = Join-Values $c.userRiskLevels
                SessionControls     = Join-Values $session
                IncludeLocationNames = $(if ($c.locations) { Join-Values (@($c.locations.includeLocations) | Where-Object { $_ } | ForEach-Object { Resolve-LocationId $_ }) } else { '' })
                ExcludeLocationNames = $(if ($c.locations) { Join-Values (@($c.locations.excludeLocations) | Where-Object { $_ } | ForEach-Object { Resolve-LocationId $_ }) } else { '' })
                AuthenticationFlows = $(if ($flows) { Join-Values $flows.transferMethods } else { '' })
                DeviceFilter        = $deviceFilter
                AuthStrengthCombinations = $combos
                AuthContexts        = Join-Values (Get-OptionalValue $c.applications 'includeAuthenticationContextClassReferences')
            })

            foreach ($id in @($u.excludeUsers)) { if ($id) { $exclusionRows.Add([pscustomobject][ordered]@{ PolicyName = $p.displayName; PolicyState = $p.state; RequiresMfa = $requiresMfa; ExclusionType = 'User'; ObjectId = $id; DisplayName = Resolve-DirectoryObject $id }) } }
            foreach ($id in @($u.excludeGroups)) {
                if ($id) {
                    $exclusionRows.Add([pscustomobject][ordered]@{ PolicyName = $p.displayName; PolicyState = $p.state; RequiresMfa = $requiresMfa; ExclusionType = 'Group'; ObjectId = $id; DisplayName = Resolve-DirectoryObject $id })
                    if (-not $excludedGroups.ContainsKey($id)) { $excludedGroups[$id] = [System.Collections.Generic.List[string]]::new() }
                    $excludedGroups[$id].Add($p.displayName)
                }
            }
            foreach ($id in @($u.excludeRoles)) {
                if ($id) {
                    $exclusionRows.Add([pscustomobject][ordered]@{ PolicyName = $p.displayName; PolicyState = $p.state; RequiresMfa = $requiresMfa; ExclusionType = 'Role'; ObjectId = $id; DisplayName = $(if ($roleNames[$id]) { $roleNames[$id] } else { $id }) })
                    $excludedRoles.Add([pscustomobject]@{ PolicyName = $p.displayName; PolicyState = $p.state; RequiresMfa = $requiresMfa; RoleId = $id; RoleName = $(if ($roleNames[$id]) { $roleNames[$id] } else { $id }) })
                }
            }
            if ($u.PSObject.Properties.Name -contains 'excludeGuestsOrExternalUsers' -and $u.excludeGuestsOrExternalUsers) {
                $exclusionRows.Add([pscustomobject][ordered]@{ PolicyName = $p.displayName; PolicyState = $p.state; RequiresMfa = $requiresMfa; ExclusionType = 'GuestOrExternal'; ObjectId = ''; DisplayName = $u.excludeGuestsOrExternalUsers.guestOrExternalUserTypes })
            }
        }
        Export-Dataset -Name 'ca-policies' -Rows $policyRows
        Export-Dataset -Name 'ca-exclusions' -Rows $exclusionRows
    }
    catch {
        $caError = Get-FailureStatus $_
        Set-DatasetStatus -Name 'ca-policies' -Status $caError -Note $_.Exception.Message
        Set-DatasetStatus -Name 'ca-exclusions' -Status $caError -Note 'Depends on ca-policies'
    }

    # ---- 2. Members of groups excluded from CA ----
    if ($SkipExcludedGroupMembers) { Set-DatasetStatus -Name 'ca-excluded-group-members' -Status 'Deferred' -Note '-SkipExcludedGroupMembers' }
    elseif (-not $caRead) { Set-DatasetStatus -Name 'ca-excluded-group-members' -Status $caError -Note 'Depends on ca-policies, which could not be read' }
    elseif ($excludedGroups.Count -gt 0) {
        $memberRows = [System.Collections.Generic.List[object]]::new()
        $failedGroups = [System.Collections.Generic.List[string]]::new()
        foreach ($gid in $excludedGroups.Keys) {
            $gname = Resolve-DirectoryObject $gid
            try { $members = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers" -f $gid) -Label "transitiveMembers $gid" }
            catch {
                $failedGroups.Add(('{0} (HTTP {1})' -f $gname, (Get-HttpStatusFromError $_)))
                Write-RunLog ("Members of excluded group {0} not readable: {1}" -f $gname, $_.Exception.Message) 'WARN'
                continue
            }
            foreach ($m in $members) {
                $memberRows.Add([pscustomobject][ordered]@{
                    GroupId              = $gid
                    GroupName            = $gname
                    ExcludedFromPolicies = Join-Values $excludedGroups[$gid]
                    MemberId             = $m.id
                    MemberType           = ($m.'@odata.type' -replace '#microsoft.graph.', '')
                    MemberDisplayName    = $m.displayName
                    MemberUPN            = $(if ($m.PSObject.Properties.Name -contains 'userPrincipalName') { $m.userPrincipalName } else { '' })
                    AccountEnabled       = $(if ($m.PSObject.Properties.Name -contains 'accountEnabled') { $m.accountEnabled } else { '' })
                })
            }
        }
        if ($failedGroups.Count) { Export-Dataset -Name 'ca-excluded-group-members' -Rows $memberRows -Status 'Partial' -Note ("Members NOT readable for: {0}" -f (Join-Values $failedGroups)) }
        else { Export-Dataset -Name 'ca-excluded-group-members' -Rows $memberRows }
    }
    else { Export-Dataset -Name 'ca-excluded-group-members' -Rows @() -Note 'No groups are excluded from any CA policy' }

    # ---- 2b. Accounts holding roles excluded from CA ----
    $roleHolderRows = [System.Collections.Generic.List[object]]::new()
    if ($SkipPrivilegeJoin) { Set-DatasetStatus -Name 'ca-excluded-role-holders' -Status 'Deferred' -Note '-SkipPrivilegeJoin' }
    elseif (-not $caRead) { Set-DatasetStatus -Name 'ca-excluded-role-holders' -Status $caError -Note 'Depends on ca-policies, which could not be read' }
    elseif (-not $privSet) { Set-DatasetStatus -Name 'ca-excluded-role-holders' -Status $script:PrivSetErrorStatus -Note "Effective privileged set not readable: $script:PrivSetError" }
    else {
        foreach ($x in $excludedRoles) {
            $holders = @($privSet.Rows | Where-Object { $_.Role -eq $x.RoleName -and $_.PrincipalType -ne 'group' })
            if (-not $holders.Count) {
                $roleHolderRows.Add([pscustomobject][ordered]@{ PolicyName = $x.PolicyName; PolicyState = $x.PolicyState; RequiresMfa = $x.RequiresMfa; RoleId = $x.RoleId; RoleName = $x.RoleName; PrincipalId = ''; PrincipalType = ''; PrincipalName = ''; Upn = ''; AccountEnabled = ''; AssignmentState = 'No current holders'; Via = ''; ViaGroup = ''; EffectiveForCa = $false })
                continue
            }
            foreach ($h in $holders) {
                $roleHolderRows.Add([pscustomobject][ordered]@{
                    PolicyName      = $x.PolicyName
                    PolicyState     = $x.PolicyState
                    RequiresMfa     = $x.RequiresMfa
                    RoleId          = $x.RoleId
                    RoleName        = $x.RoleName
                    PrincipalId     = $h.PrincipalId
                    PrincipalType   = $h.PrincipalType
                    PrincipalName   = $h.PrincipalName
                    Upn             = $h.Upn
                    AccountEnabled  = $h.AccountEnabled
                    AssignmentState = $h.AssignmentState
                    Via             = $h.Via
                    ViaGroup        = $h.ViaGroup
                    EffectiveForCa  = Test-RowEffectiveForCa $h
                })
            }
        }
        $complete = Test-PrivSetComplete $privSet
        Export-Dataset -Name 'ca-excluded-role-holders' -Rows $roleHolderRows -Status $(if ($complete) { 'Completed' } else { 'Partial' }) -Note $(if ($excludedRoles.Count -eq 0) { 'No roles are excluded from any CA policy' } elseif ($complete) { '' } else { "Privileged set incomplete: $(Get-PrivSetStatusText $privSet)" })
    }

    # ---- 3. MFA registration details ----
    $regRows = $null
    $userInfo = @{}
    $userJoinError = ''
    try {
        foreach ($x in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,accountEnabled,onPremisesSyncEnabled&$top=999' -Label 'users')) { $userInfo["$($x.id)"] = $x }
    }
    catch {
        $userJoinError = '{0} (HTTP {1})' -f (Get-FailureStatus $_), (Get-HttpStatusFromError $_)
        Write-RunLog ("Users not readable; AccountEnabled / OnPremisesSynced left blank. {0}" -f $_.Exception.Message) 'WARN'
    }
    try {
        $reg = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails' -Label 'userRegistrationDetails'
        $regRows = foreach ($r in $reg) {
            $methods = @($r.methodsRegistered | Where-Object { $_ })
            $strength = Get-MethodStrength $methods
            $priv = $(if ($privSet) { Get-PrivilegeSummary -Set $privSet -PrincipalId "$($r.id)" } else { $null })
            $ui = $(if ($userInfo.ContainsKey("$($r.id)")) { $userInfo["$($r.id)"] } else { $null })
            [pscustomobject][ordered]@{
                UserId               = $r.id
                UserPrincipalName    = $r.userPrincipalName
                UserType             = $r.userType
                IsAdmin              = $r.isAdmin
                IsMfaRegistered      = $r.isMfaRegistered
                IsMfaCapable         = $r.isMfaCapable
                IsPasswordlessCapable = $r.isPasswordlessCapable
                IsSsprRegistered     = $r.isSsprRegistered
                DefaultMfaMethod     = $r.defaultMfaMethod
                MethodsRegistered    = Join-Values $methods
                HasPhoneMethodOnly   = ($strength -eq 'PhoneOnly')
                HasSmsOrVoice        = [bool](@($methods | Where-Object { $_ -match 'mobilePhone|alternateMobilePhone|officePhone' }).Count)
                LastUpdated          = $r.lastUpdatedDateTime
                PhishResistant       = ($strength -eq 'PhishResistant')
                MethodStrength       = $strength
                IsPrivileged         = $(if ($priv) { $priv.IsPrivileged } else { '' })
                IsTier0              = $(if ($priv) { $priv.IsTier0 } else { '' })
                AccountEnabled       = $(if ($ui) { $ui.accountEnabled } else { '' })
                OnPremisesSynced     = $(if ($ui) { [bool]$ui.onPremisesSyncEnabled } else { '' })
            }
        }
        $regNotes = @()
        if ($SkipPrivilegeJoin) { $regNotes += 'IsPrivileged/IsTier0 not evaluated (-SkipPrivilegeJoin)' }
        elseif (-not $privSet) { $regNotes += "IsPrivileged/IsTier0 blank: privileged set not readable ($script:PrivSetError)" }
        elseif (-not (Test-PrivSetComplete $privSet)) { $regNotes += "privileged set incomplete: $(Get-PrivSetStatusText $privSet)" }
        if ($userJoinError) { $regNotes += "AccountEnabled/OnPremisesSynced blank: users $userJoinError" }
        $regPartial = ((-not $SkipPrivilegeJoin) -and ((-not $privSet) -or -not (Test-PrivSetComplete $privSet))) -or [bool]$userJoinError
        Export-Dataset -Name 'mfa-registration' -Rows $regRows -Status $(if ($regPartial) { 'Partial' } else { 'Completed' }) -Note ($regNotes -join '; ')
    }
    catch { Set-DatasetStatus -Name 'mfa-registration' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 3b. Authentication methods policy, registration campaign, security defaults ----
    $amRows = [System.Collections.Generic.List[object]]::new()
    $amErrors = @()
    function ConvertTo-TargetText {
        param($Targets)
        Join-Values (@($Targets) | Where-Object { $_ } | ForEach-Object { if ("$($_.id)" -eq 'all_users') { 'All users' } else { Resolve-DirectoryObject "$($_.id)" } })
    }
    try {
        $amp = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
        foreach ($cfg in @($amp.authenticationMethodConfigurations)) {
            if (-not $cfg) { continue }
            $flags = @()
            $on = ("$($cfg.state)" -eq 'enabled')
            if ($on -and "$($cfg.id)" -eq 'Sms') { $flags += 'SmsEnabled' }
            if ($on -and "$($cfg.id)" -eq 'Voice') { $flags += 'VoiceEnabled' }
            $detail = @()
            $usable = @(@(Get-OptionalValue $cfg 'includeTargets') | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'isUsableForSignIn' -and $_.isUsableForSignIn })
            if ($usable.Count) { $detail += 'Usable for sign-in'; if ($on -and "$($cfg.id)" -eq 'Sms') { $flags += 'SmsSignInEnabled' } }
            $amRows.Add([pscustomobject][ordered]@{
                Section        = 'MethodConfiguration'
                Id             = $cfg.id
                State          = $cfg.state
                IncludeTargets = ConvertTo-TargetText (Get-OptionalValue $cfg 'includeTargets')
                ExcludeTargets = ConvertTo-TargetText (Get-OptionalValue $cfg 'excludeTargets')
                Detail         = Join-Values $detail
                Flags          = Join-Values $flags
            })
        }
        if ($amp.PSObject.Properties.Name -contains 'policyMigrationState') {
            $amRows.Add([pscustomobject][ordered]@{ Section = 'PolicyMigration'; Id = 'policyMigrationState'; State = $amp.policyMigrationState; IncludeTargets = ''; ExcludeTargets = ''; Detail = 'migrationComplete = legacy MFA / SSPR method settings no longer apply'; Flags = $(if ("$($amp.policyMigrationState)" -ne 'migrationComplete') { 'LegacyMethodSettingsStillApply' } else { '' }) })
        }
        $camp = $null
        $re = Get-OptionalValue $amp 'registrationEnforcement'
        if ($re) { $camp = Get-OptionalValue $re 'authenticationMethodsRegistrationCampaign' }
        if ($camp) {
            $amRows.Add([pscustomobject][ordered]@{
                Section        = 'RegistrationCampaign'
                Id             = 'authenticationMethodsRegistrationCampaign'
                State          = $camp.state
                IncludeTargets = ConvertTo-TargetText (Get-OptionalValue $camp 'includeTargets')
                ExcludeTargets = ConvertTo-TargetText (Get-OptionalValue $camp 'excludeTargets')
                Detail         = ('Snooze {0} day(s); method {1}' -f (Get-OptionalValue $camp 'snoozeDurationInDays'), (Join-Values (@(Get-OptionalValue $camp 'includeTargets') | Where-Object { $_ } | ForEach-Object { Get-OptionalValue $_ 'targetedAuthenticationMethod' })))
                Flags          = $(if ("$($camp.state)" -eq 'disabled') { 'RegistrationCampaignOff' } else { '' })
            })
        }
    }
    catch {
        $amErrors += 'authenticationMethodsPolicy {0} (HTTP {1})' -f (Get-FailureStatus $_), (Get-HttpStatusFromError $_)
        Write-RunLog ("Authentication methods policy not readable: {0}" -f $_.Exception.Message) 'WARN'
    }
    $secDefaults = ''
    try {
        $sd = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
        $secDefaults = $(if ($sd.isEnabled) { 'enabled' } else { 'disabled' })
        $amRows.Add([pscustomobject][ordered]@{ Section = 'SecurityDefaults'; Id = 'identitySecurityDefaultsEnforcementPolicy'; State = $secDefaults; IncludeTargets = ''; ExcludeTargets = ''; Detail = ''; Flags = $(if ($sd.isEnabled -and $policyRows.Count) { 'SecurityDefaultsAndCaBothPresent' } else { '' }) })
    }
    catch {
        $amErrors += 'security defaults {0} (HTTP {1})' -f (Get-FailureStatus $_), (Get-HttpStatusFromError $_)
        Write-RunLog ("Security defaults policy not readable: {0}" -f $_.Exception.Message) 'WARN'
    }
    if ($amErrors.Count -eq 2) { Set-DatasetStatus -Name 'auth-methods-policy' -Status 'Blocked' -Note ($amErrors -join '; ') }
    else { Export-Dataset -Name 'auth-methods-policy' -Rows $amRows -Status $(if ($amErrors.Count) { 'Partial' } else { 'Completed' }) -Note ($amErrors -join '; ') }

    # ---- 4. Successful single-factor sign-ins (includes legacy auth, which cannot do MFA) ----
    $sfRows = $null; $sfRaw = 0; $truncated = $false
    if ($SkipSignIns) { Set-DatasetStatus -Name 'signins-singlefactor-success' -Status 'Deferred' -Note '-SkipSignIns' }
    else {
        try {
            $since = $script:RunStartUtc.AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $filter = "createdDateTime ge $since and status/errorCode eq 0 and authenticationRequirement eq 'singleFactorAuthentication'"
            $uri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString($filter)
            $signIns = Invoke-GraphGetAll -Uri $uri -MaxRecords $MaxSignInRecords -Label 'signIns'
            $truncated = $script:LastQueryTruncated
            $sfRaw = $signIns.Count
            $modernClients = @('Browser', 'Mobile Apps and Desktop clients')
            $sfRows = $signIns | Group-Object -Property userPrincipalName, appDisplayName, clientAppUsed | ForEach-Object {
                $first = $_.Group[0]
                $times = @($_.Group | ForEach-Object { [datetime]$_.createdDateTime } | Sort-Object)
                [pscustomobject][ordered]@{
                    UserPrincipalName   = $first.userPrincipalName
                    UserType            = $(if ($first.PSObject.Properties.Name -contains 'userType') { $first.userType } else { '' })
                    AppDisplayName      = $first.appDisplayName
                    ClientAppUsed       = $first.clientAppUsed
                    IsLegacyAuth        = ($modernClients -notcontains $first.clientAppUsed)
                    SignInCount         = $_.Count
                    FirstSeenUtc        = $times[0].ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    LastSeenUtc         = $times[-1].ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    CaStatuses          = Join-Values (@($_.Group | ForEach-Object { $_.conditionalAccessStatus } | Sort-Object -Unique))
                    DistinctIpCount     = @($_.Group | ForEach-Object { $_.ipAddress } | Sort-Object -Unique).Count
                }
            }
            $note = "Lookback $SignInLookbackDays days; $sfRaw raw interactive sign-ins aggregated"
            if ($truncated) { $note += "; TRUNCATED at $MaxSignInRecords - rerun with a shorter lookback or higher cap" }
            Export-Dataset -Name 'signins-singlefactor-success' -Rows $sfRows -Note $note
        }
        catch { Set-DatasetStatus -Name 'signins-singlefactor-success' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }
    }

    # ---- 4b. Non-interactive single-factor sign-ins (opt-in: high volume) ----
    $niRows = $null; $niRaw = 0; $niTruncated = $false
    if (-not $IncludeNonInteractive) { Set-DatasetStatus -Name 'signins-noninteractive-singlefactor' -Status 'Deferred' -Note 'Not requested (-IncludeNonInteractive)' }
    else {
        try {
            $privUpns = @{}
            if ($privSet) { foreach ($r in $privSet.Rows) { if ($r.Upn) { $privUpns["$($r.Upn)".ToLowerInvariant()] = $true } } }
            $since = $script:RunStartUtc.AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $filter = "createdDateTime ge $since and status/errorCode eq 0 and authenticationRequirement eq 'singleFactorAuthentication' and signInEventTypes/any(t: t eq 'nonInteractiveUser')"
            $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$top=999&$filter=' + [uri]::EscapeDataString($filter)
            $ni = Invoke-GraphGetAll -Uri $uri -MaxRecords $MaxSignInRecords -Label 'signIns nonInteractive'
            $niTruncated = $script:LastQueryTruncated
            $niRaw = $ni.Count
            $niRows = $ni | Group-Object -Property userPrincipalName, appDisplayName, resourceDisplayName, clientAppUsed | ForEach-Object {
                $first = $_.Group[0]
                $times = @($_.Group | ForEach-Object { ([datetime]$_.createdDateTime).ToUniversalTime() } | Sort-Object)
                [pscustomobject][ordered]@{
                    UserPrincipalName   = $first.userPrincipalName
                    AppDisplayName      = $first.appDisplayName
                    ResourceDisplayName = Get-OptionalValue $first 'resourceDisplayName'
                    ClientAppUsed       = $first.clientAppUsed
                    SignInCount         = $_.Count
                    FirstSeenUtc        = $times[0].ToString('yyyy-MM-ddTHH:mm:ssZ')
                    LastSeenUtc         = $times[-1].ToString('yyyy-MM-ddTHH:mm:ssZ')
                    DistinctIpCount     = @($_.Group | ForEach-Object { $_.ipAddress } | Sort-Object -Unique).Count
                    IsPrivileged        = $(if ($privSet) { [bool]($first.userPrincipalName -and $privUpns.ContainsKey("$($first.userPrincipalName)".ToLowerInvariant())) } else { '' })
                }
            }
            $note = "Lookback $SignInLookbackDays days; $niRaw raw non-interactive sign-ins aggregated (beta endpoint)"
            if ($niTruncated) { $note += "; TRUNCATED at $MaxSignInRecords - rerun with a shorter lookback or higher cap" }
            Export-Dataset -Name 'signins-noninteractive-singlefactor' -Rows $niRows -Note $note
        }
        catch { Set-DatasetStatus -Name 'signins-noninteractive-singlefactor' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }
    }

    # ---- 5. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    if ($policyRows.Count -gt 0) {
        Add-Metric 'CA policies (total)' $policyRows.Count
        Add-Metric 'CA policies enabled' @($policyRows | Where-Object State -eq 'enabled').Count
        Add-Metric 'CA policies report-only' @($policyRows | Where-Object State -eq 'enabledForReportingButNotEnforced').Count
        Add-Metric 'CA policies disabled' @($policyRows | Where-Object State -eq 'disabled').Count
        Add-Metric 'Enabled policies requiring MFA/auth strength' @($policyRows | Where-Object { $_.State -eq 'enabled' -and $_.RequiresMfa }).Count
        Add-Metric 'Enabled policies blocking legacy auth' @($policyRows | Where-Object { $_.State -eq 'enabled' -and $_.BlocksLegacyAuth }).Count -Note 'Heuristic: block grant + EAS/other client types'
        Add-Metric 'CA exclusions (rows)' $exclusionRows.Count
        Add-Metric 'Distinct groups excluded from CA' $excludedGroups.Count
    }
    if ($roleHolderRows.Count -gt 0) {
        Add-Metric 'Accounts excluded from CA through an excluded role' @($roleHolderRows | Where-Object { $_.EffectiveForCa } | ForEach-Object { $_.PrincipalId } | Sort-Object -Unique).Count -Note 'Active or activated holders; eligible holders become excluded when they activate'
    }
    if ($regRows) {
        $members = @($regRows | Where-Object UserType -eq 'member')
        $pct = { param($n, $d) if ($d -gt 0) { [math]::Round(100 * $n / $d, 1) } else { 0 } }
        Add-Metric 'Member users in registration report' $members.Count
        Add-Metric 'Members MFA registered (%)' (& $pct @($members | Where-Object IsMfaRegistered).Count $members.Count)
        Add-Metric 'Members MFA capable (%)' (& $pct @($members | Where-Object IsMfaCapable).Count $members.Count)
        Add-Metric 'Members with SMS/voice registered' @($members | Where-Object HasSmsOrVoice).Count
        Add-Metric 'Members with phone methods only' @($members | Where-Object HasPhoneMethodOnly).Count -Note 'Strongest registered method is SMS/voice'
        Add-Metric 'Members with email method only' @($members | Where-Object { $_.MethodStrength -eq 'EmailOnly' }).Count -Note 'Email is not an MFA method'
        Add-Metric 'Members with phishing-resistant method (%)' (& $pct @($members | Where-Object PhishResistant).Count $members.Count)
        Add-Metric 'Admins not MFA registered' @($regRows | Where-Object { $_.IsAdmin -and -not $_.IsMfaRegistered }).Count
        if ($privSet) {
            Add-Metric 'Privileged users (effective set) not MFA registered' @($regRows | Where-Object { $_.IsPrivileged -eq $true -and -not $_.IsMfaRegistered }).Count
            Add-Metric 'Tier 0 users without phishing-resistant method' @($regRows | Where-Object { $_.IsTier0 -eq $true -and -not $_.PhishResistant }).Count
        }
        if (-not $userJoinError) { Add-Metric 'Enabled members MFA registered (%)' (& $pct @($members | Where-Object { "$($_.AccountEnabled)" -eq 'True' -and $_.IsMfaRegistered }).Count @($members | Where-Object { "$($_.AccountEnabled)" -eq 'True' }).Count) }
    }
    if ($amRows.Count) {
        Add-Metric 'SMS enabled in authentication methods policy' ([bool]@($amRows | Where-Object { $_.Flags -match 'SmsEnabled' }).Count)
        Add-Metric 'Voice enabled in authentication methods policy' ([bool]@($amRows | Where-Object { $_.Flags -match 'VoiceEnabled' }).Count)
        if ($secDefaults) { Add-Metric 'Security defaults' $secDefaults }
    }
    if ($null -ne $sfRows) {
        Add-Metric 'Successful single-factor sign-ins (raw)' $sfRaw -Note "Last $SignInLookbackDays days$(if ($truncated) { ' (TRUNCATED)' })"
        Add-Metric 'Distinct users with single-factor success' @($sfRows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
        Add-Metric 'Distinct users using legacy auth successfully' @($sfRows | Where-Object IsLegacyAuth | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    }
    if ($null -ne $niRows) {
        Add-Metric 'Successful single-factor non-interactive sign-ins (raw)' $niRaw -Note "Last $SignInLookbackDays days$(if ($niTruncated) { ' (TRUNCATED)' })"
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ SignInLookbackDays = $SignInLookbackDays; MaxSignInRecords = $MaxSignInRecords; SkipSignIns = [bool]$SkipSignIns; SkipExcludedGroupMembers = [bool]$SkipExcludedGroupMembers; SkipPrivilegeJoin = [bool]$SkipPrivilegeJoin; IncludeNonInteractive = [bool]$IncludeNonInteractive }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
