<#
.SYNOPSIS
    Read-only discovery of applications, service principals, permissions and consents in Entra ID.

.DESCRIPTION
    Answers "what non-human identities can move data, and what can they reach?":
      - Tenant consent settings (can users consent? is the admin-consent workflow on?)
      - App registrations with owners (names, guest / disabled owners) and credential hygiene
      - One row per app secret / certificate with expiry status
      - Service principals classified as Microsoft / this tenant / third party / managed identity
      - One row per secret / certificate held directly on a service principal, for EVERY service
        principal including Microsoft first-party ones (a credential added to a first-party or
        multi-tenant service principal is a known persistence technique)
      - Federated identity credentials per app registration, with wildcard / broad subjects flagged
      - App configuration risks: http or wildcard redirect URIs, implicit grant, fallback public client
      - Tenant default and custom app management policies (credential restrictions)
      - Application permissions (app roles) granted to each client, with Tier 0-equivalent
        permissions marked
      - Delegated permission grants (admin vs user consent), with high-risk scopes flagged
      - Who is assigned to each enterprise app that requires assignment (users / groups)
      - Directory roles held by service principals (active, eligible, via group), joined into
        the per-app risk summary
      - A per-app risk summary - the "data movers" list
      - A summary of headline metrics

    Microsoft first-party service principals are skipped for app-role enumeration, owners and
    assignments unless -IncludeMicrosoftApps is set (they are numerous and rarely the question).
    Credentials on them are always reported.

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.
    Service-principal last sign-in uses the Graph BETA report endpoint (still a GET).

    Output: <OutputRoot>\03-AppsAndConsents\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\03-Get-AppsAndConsents.ps1
.EXAMPLE
    .\03-Get-AppsAndConsents.ps1 -CredentialWarningDays 60 -IncludeMicrosoftApps
.EXAMPLE
    .\03-Get-AppsAndConsents.ps1 -SkipAppAssignments -SkipPrivilegeJoin     # faster pass

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : Application.Read.All, Directory.Read.All, Policy.Read.All, AuditLog.Read.All,
              RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup
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

    [int]$CredentialWarningDays = 30,
    [int]$LongLivedSecretDays = 730,
    [int]$StaleDays = 90,
    [switch]$IncludeMicrosoftApps,
    [switch]$SkipSignInActivity,
    [int]$MaxAssignmentsPerApp = 5000,
    [switch]$SkipAppAssignments,
    [switch]$SkipPrivilegeJoin
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '03-AppsAndConsents'
$ScriptVersion = '1.1.0'
$RequiredScopes = @('Application.Read.All', 'Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')

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

# Microsoft first-party tenants that own Microsoft service principals.
$MicrosoftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

# Permissions that reach bulk data (DataAccess) or can escalate privilege (PrivilegeEscalation). Extend as needed.
$HighRiskPermissions = @{
    'Mail.Read' = 'DataAccess'; 'Mail.ReadWrite' = 'DataAccess'; 'Mail.ReadBasic.All' = 'DataAccess'; 'Mail.Send' = 'DataAccess'
    'MailboxSettings.ReadWrite' = 'DataAccess'; 'full_access_as_app' = 'DataAccess'; 'EWS.AccessAsUser.All' = 'DataAccess'
    'Files.Read.All' = 'DataAccess'; 'Files.ReadWrite.All' = 'DataAccess'
    'Sites.Read.All' = 'DataAccess'; 'Sites.ReadWrite.All' = 'DataAccess'; 'Sites.Manage.All' = 'DataAccess'; 'Sites.FullControl.All' = 'DataAccess'
    'Notes.Read.All' = 'DataAccess'; 'Notes.ReadWrite.All' = 'DataAccess'
    'Chat.Read.All' = 'DataAccess'; 'Chat.ReadWrite.All' = 'DataAccess'; 'ChannelMessage.Read.All' = 'DataAccess'
    'Calendars.Read' = 'DataAccess'; 'Calendars.ReadWrite' = 'DataAccess'; 'Contacts.Read' = 'DataAccess'; 'Contacts.ReadWrite' = 'DataAccess'
    'User.Export.All' = 'DataAccess'; 'Directory.Read.All' = 'DataAccess'; 'User.Read.All' = 'DataAccess'; 'AuditLog.Read.All' = 'DataAccess'
    'Directory.ReadWrite.All' = 'PrivilegeEscalation'; 'User.ReadWrite.All' = 'PrivilegeEscalation'
    'Group.ReadWrite.All' = 'PrivilegeEscalation'; 'GroupMember.ReadWrite.All' = 'PrivilegeEscalation'
    'Application.ReadWrite.All' = 'PrivilegeEscalation'; 'Application.ReadWrite.OwnedBy' = 'PrivilegeEscalation'
    'AppRoleAssignment.ReadWrite.All' = 'PrivilegeEscalation'; 'DelegatedPermissionGrant.ReadWrite.All' = 'PrivilegeEscalation'
    'RoleManagement.ReadWrite.Directory' = 'PrivilegeEscalation'; 'Policy.ReadWrite.ConditionalAccess' = 'PrivilegeEscalation'
    'UserAuthenticationMethod.ReadWrite.All' = 'PrivilegeEscalation'; 'Domain.ReadWrite.All' = 'PrivilegeEscalation'
    'Directory.AccessAsUser.All' = 'PrivilegeEscalation'
    'RoleAssignmentSchedule.ReadWrite.Directory' = 'PrivilegeEscalation'; 'RoleEligibilitySchedule.ReadWrite.Directory' = 'PrivilegeEscalation'
    'PrivilegedAccess.ReadWrite.AzureADGroup' = 'PrivilegeEscalation'; 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup' = 'PrivilegeEscalation'
    'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup' = 'PrivilegeEscalation'
    'Policy.ReadWrite.AuthenticationMethod' = 'PrivilegeEscalation'; 'Policy.ReadWrite.PermissionGrant' = 'PrivilegeEscalation'
    'Organization.ReadWrite.All' = 'PrivilegeEscalation'; 'Synchronization.ReadWrite.All' = 'PrivilegeEscalation'
}
# Permissions that let the holder make itself (or anyone) Global Administrator, directly or in one step.
$Tier0EquivalentPermissions = @(
    'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All', 'Directory.ReadWrite.All'
    'RoleAssignmentSchedule.ReadWrite.Directory', 'RoleEligibilitySchedule.ReadWrite.Directory'
    'PrivilegedAccess.ReadWrite.AzureADGroup', 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup', 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup'
)

function Get-OwnerInfo {
    # Owner names with Guest / Disabled / non-user tags. Count is blank when the owners could not be read.
    param($Owners, [string]$Status = 'Completed')
    $list = @($Owners | Where-Object { $_ })
    $names = foreach ($o in $list) {
        $props = $o.PSObject.Properties.Name
        $n = $(if ($props -contains 'userPrincipalName' -and $o.userPrincipalName) { "$($o.userPrincipalName)" } else { "$($o.displayName)" })
        $tags = @()
        if ($props -contains 'userType' -and "$($o.userType)" -eq 'Guest') { $tags += 'Guest' }
        if ($props -contains 'accountEnabled' -and $o.accountEnabled -eq $false) { $tags += 'Disabled' }
        $t = ("$($o.'@odata.type')" -replace '#microsoft.graph.', '')
        if ($t -and $t -ne 'user') { $tags += $t }
        if ($tags.Count) { '{0} [{1}]' -f $n, ($tags -join ', ') } else { $n }
    }
    [pscustomobject]@{
        Count    = $(if ($Status -eq 'Completed') { $list.Count } else { '' })
        Names    = $(if ($Status -eq 'Completed') { Join-Values $names } else { "Unresolved ($Status)" })
        Guest    = @($list | Where-Object { $_.PSObject.Properties.Name -contains 'userType' -and "$($_.userType)" -eq 'Guest' }).Count
        Disabled = @($list | Where-Object { $_.PSObject.Properties.Name -contains 'accountEnabled' -and $_.accountEnabled -eq $false }).Count
        Status   = $Status
    }
}

function Get-RedirectRisk {
    param([string]$Uri)
    $r = @()
    if ($Uri -match '\*') { $r += 'WildcardRedirect' }
    if ($Uri -match '^http://' -and $Uri -notmatch '^http://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(/|$)') { $r += 'HttpRedirectNonLocalhost' }
    return $r
}

function Get-FederatedCredentialRisk {
    param($Fic)
    $sub = "$($Fic.subject)"; $iss = "$($Fic.issuer)"
    $f = @()
    if (-not $sub) { $f += 'NoSubject' }
    if ($sub -match '\*') { $f += 'SubjectWildcard' }
    if ($iss -match 'token\.actions\.githubusercontent\.com') {
        if ($sub -match '^repo:[^/:]+/\*' -or $sub -match '^repo:[^:]+:\*') { $f += 'BroadGitHubSubject' }
        elseif ($sub -match ':pull_request$') { $f += 'GitHubPullRequestSubject' }
    }
    return $f
}

function Get-DaysTo {
    param($When, $Now)
    if (-not $When) { return $null }
    try { return [int](([datetime]$When).ToUniversalTime() - $Now).TotalDays } catch { return $null }
}

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph
    $thisTenant = $ctx.TenantId
    $now = $script:RunStartUtc

    # ---- 1. Tenant consent settings ----
    try {
        $authz = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        $acr = $null
        try { $acr = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' } catch { }
        $grantPolicies = @($authz.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
        $userConsent = 'Users cannot consent'
        if ($grantPolicies -match 'microsoft-user-default-legacy') { $userConsent = 'Users can consent to ANY app (legacy default)' }
        elseif ($grantPolicies -match 'microsoft-user-default-recommended') { $userConsent = 'Users can consent under the Microsoft-managed recommended policy (currently verified publishers, low-risk permissions)' }
        elseif ($grantPolicies -match 'microsoft-user-default-low') { $userConsent = 'Users can consent to verified-publisher apps for low-risk permissions' }
        elseif ($grantPolicies.Count -gt 0) { $userConsent = 'Custom grant policy: ' + ($grantPolicies -join ', ') }
        $settings = @(
            [pscustomobject][ordered]@{ Setting = 'User consent'; Value = $userConsent; Raw = Join-Values $grantPolicies }
            [pscustomobject][ordered]@{ Setting = 'Users can register applications'; Value = $authz.defaultUserRolePermissions.allowedToCreateApps; Raw = '' }
            [pscustomobject][ordered]@{ Setting = 'Users can create security groups'; Value = $authz.defaultUserRolePermissions.allowedToCreateSecurityGroups; Raw = '' }
            [pscustomobject][ordered]@{ Setting = 'Guest invite policy'; Value = $authz.allowInvitesFrom; Raw = '' }
            [pscustomobject][ordered]@{ Setting = 'Admin consent request workflow enabled'; Value = $(if ($acr) { $acr.isEnabled } else { 'unreadable' }); Raw = $(if ($acr) { 'reviewers: ' + @($acr.reviewers).Count } else { '' }) }
        )
        Export-Dataset -Name 'tenant-consent-settings' -Rows $settings
    }
    catch { Set-DatasetStatus -Name 'tenant-consent-settings' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 2. App registrations, credentials, federated credentials, configuration ----
    $credRows = [System.Collections.Generic.List[object]]::new()
    $ficRows = [System.Collections.Generic.List[object]]::new()
    $cfgRows = [System.Collections.Generic.List[object]]::new()
    $appRegByAppId = @{}
    $appsRead = $false
    $ownerPageFailures = 0; $ficFailures = 0; $appCount = 0
    try {
        $apps = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess,publisherDomain,web,spa,publicClient,isFallbackPublicClient&$expand=owners($select=id,displayName,userPrincipalName,userType,accountEnabled)' -Label 'applications'
        $appsRead = $true
        $appCount = $apps.Count
        $appRows = foreach ($a in $apps) {
            $creds = @()
            foreach ($c in @($a.passwordCredentials)) { if ($c) { $creds += [pscustomobject]@{ Type = 'Secret'; Name = $c.displayName; Hint = $c.hint; Start = $c.startDateTime; End = $c.endDateTime } } }
            foreach ($c in @($a.keyCredentials)) { if ($c) { $creds += [pscustomobject]@{ Type = 'Certificate'; Name = $c.displayName; Hint = ''; Start = $c.startDateTime; End = $c.endDateTime } } }
            $myCreds = [System.Collections.Generic.List[object]]::new()
            foreach ($c in $creds) {
                $end = $(if ($c.End) { [datetime]$c.End } else { $null })
                $start = $(if ($c.Start) { [datetime]$c.Start } else { $null })
                $days = $(if ($end) { [int]($end.ToUniversalTime() - $now).TotalDays } else { $null })
                $life = $(if ($end -and $start) { [int]($end - $start).TotalDays } else { $null })
                $status = 'Valid'
                if ($null -ne $days -and $days -lt 0) { $status = 'Expired' } elseif ($null -ne $days -and $days -le $CredentialWarningDays) { $status = 'ExpiringSoon' }
                $credRow = [pscustomobject][ordered]@{
                    AppDisplayName = $a.displayName
                    AppId          = $a.appId
                    CredentialType = $c.Type
                    CredentialName = $c.Name
                    SecretHint     = $c.Hint
                    StartUtc       = $c.Start
                    EndUtc         = $c.End
                    DaysToExpiry   = $days
                    LifetimeDays   = $life
                    Status         = $status
                    LongLived      = ($c.Type -eq 'Secret' -and $null -ne $life -and $life -gt $LongLivedSecretDays)
                }
                $credRows.Add($credRow); $myCreds.Add($credRow)
            }

            # Owners: $expand returns at most 20; page the full list when the cap is hit.
            $ownerList = @($a.owners | Where-Object { $_ })
            $ownerStatus = 'Completed'
            if ($ownerList.Count -ge 20) {
                try { $ownerList = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/owners?`$select=id,displayName,userPrincipalName,userType,accountEnabled" -f $a.id) -Label "app owners $($a.id)" }
                catch { $ownerPageFailures++; $ownerStatus = 'Partial (first 20 only)'; Write-RunLog ("Owners of app {0} beyond the first 20 not readable: {1}" -f $a.displayName, $_.Exception.Message) 'WARN' }
            }
            $oi = Get-OwnerInfo -Owners $ownerList
            if ($ownerStatus -ne 'Completed') { $oi.Status = $ownerStatus }

            # Federated identity credentials
            $myFic = @()
            $ficStatus = 'Completed'
            try {
                foreach ($fc in (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/federatedIdentityCredentials" -f $a.id) -Label "federatedIdentityCredentials $($a.id)")) {
                    $ff = @(Get-FederatedCredentialRisk $fc)
                    $fr = [pscustomobject][ordered]@{
                        AppDisplayName = $a.displayName
                        AppId          = $a.appId
                        Name           = $fc.name
                        Issuer         = $fc.issuer
                        Subject        = $fc.subject
                        Audiences      = Join-Values $fc.audiences
                        Description    = $fc.description
                        Flags          = Join-Values $ff
                    }
                    $ficRows.Add($fr); $myFic += $fr
                }
            }
            catch {
                $ficFailures++; $ficStatus = 'Unreadable'
                Write-RunLog ("Federated credentials of app {0} not readable: {1}" -f $a.displayName, $_.Exception.Message) 'WARN'
            }

            # Configuration risks
            $myCfg = @()
            $uriSets = @(
                @{ Kind = 'web'; Uris = $(if ($a.web) { @($a.web.redirectUris) } else { @() }) }
                @{ Kind = 'spa'; Uris = $(if ($a.spa) { @($a.spa.redirectUris) } else { @() }) }
                @{ Kind = 'publicClient'; Uris = $(if ($a.publicClient) { @($a.publicClient.redirectUris) } else { @() }) }
            )
            foreach ($set in $uriSets) {
                foreach ($ru in @($set.Uris | Where-Object { $_ })) {
                    foreach ($risk in @(Get-RedirectRisk "$ru")) { $myCfg += [pscustomobject][ordered]@{ AppDisplayName = $a.displayName; AppId = $a.appId; Setting = "$($set.Kind).redirectUris"; Value = "$ru"; Risk = $risk } }
                }
            }
            if ($a.web -and $a.web.implicitGrantSettings) {
                if ($a.web.implicitGrantSettings.enableAccessTokenIssuance) { $myCfg += [pscustomobject][ordered]@{ AppDisplayName = $a.displayName; AppId = $a.appId; Setting = 'web.implicitGrantSettings.enableAccessTokenIssuance'; Value = 'True'; Risk = 'ImplicitAccessToken' } }
                if ($a.web.implicitGrantSettings.enableIdTokenIssuance) { $myCfg += [pscustomobject][ordered]@{ AppDisplayName = $a.displayName; AppId = $a.appId; Setting = 'web.implicitGrantSettings.enableIdTokenIssuance'; Value = 'True'; Risk = 'ImplicitIdToken' } }
            }
            if ($a.isFallbackPublicClient) { $myCfg += [pscustomobject][ordered]@{ AppDisplayName = $a.displayName; AppId = $a.appId; Setting = 'isFallbackPublicClient'; Value = 'True'; Risk = 'FallbackPublicClient' } }
            foreach ($cr in $myCfg) { $cfgRows.Add($cr) }

            $nearest = @($myCreds | Where-Object { $null -ne $_.DaysToExpiry -and $_.DaysToExpiry -ge 0 } | Sort-Object DaysToExpiry | Select-Object -First 1)
            $row = [pscustomobject][ordered]@{
                AppObjectId          = $a.id
                AppId                = $a.appId
                DisplayName          = $a.displayName
                Created              = $a.createdDateTime
                SignInAudience       = $a.signInAudience
                OwnerCount           = $oi.Count
                Owners               = $oi.Names
                SecretCount          = @($myCreds | Where-Object CredentialType -eq 'Secret').Count
                CertificateCount     = @($myCreds | Where-Object CredentialType -eq 'Certificate').Count
                HasExpiredCredential = [bool]@($myCreds | Where-Object Status -eq 'Expired').Count
                HasExpiringSoon      = [bool]@($myCreds | Where-Object Status -eq 'ExpiringSoon').Count
                HasLongLivedSecret   = [bool]@($myCreds | Where-Object LongLived).Count
                NextExpiryDays       = $(if ($nearest) { $nearest[0].DaysToExpiry } else { '' })
                RequestedApiCount    = @($a.requiredResourceAccess).Count
                OwnerGuestCount      = $oi.Guest
                OwnerDisabledCount   = $oi.Disabled
                OwnerReadStatus      = $oi.Status
                FederatedCredentials = $(if ($ficStatus -eq 'Completed') { $myFic.Count } else { 'unreadable' })
                FederatedCredentialFlags = Join-Values ($myFic | ForEach-Object { $_.Flags -split '; ' } | Where-Object { $_ } | Sort-Object -Unique)
                ConfigRisks          = Join-Values ($myCfg | ForEach-Object { $_.Risk } | Sort-Object -Unique)
            }
            $appRegByAppId[$a.appId] = $row
            $row
        }
        Export-Dataset -Name 'app-registrations' -Rows $appRows -Status $(if ($ownerPageFailures) { 'Partial' } else { 'Completed' }) -Note $(if ($ownerPageFailures) { "$ownerPageFailures app(s) with more than 20 owners: only the first 20 read (see OwnerReadStatus)" } else { '' })
        Export-Dataset -Name 'app-credentials' -Rows $credRows
        if ($ficFailures -and $ficFailures -ge $appCount) { Set-DatasetStatus -Name 'federated-credentials' -Status 'Blocked' -Note 'federatedIdentityCredentials not readable for any app' }
        else { Export-Dataset -Name 'federated-credentials' -Rows $ficRows -Status $(if ($ficFailures) { 'Partial' } else { 'Completed' }) -Note $(if ($ficFailures) { "$ficFailures app(s) unreadable (FederatedCredentials = unreadable)" } else { 'Flags: SubjectWildcard, BroadGitHubSubject, GitHubPullRequestSubject, NoSubject' }) }
        Export-Dataset -Name 'app-config-risks' -Rows $cfgRows -Note 'Risks: HttpRedirectNonLocalhost, WildcardRedirect, ImplicitAccessToken, ImplicitIdToken, FallbackPublicClient'
    }
    catch {
        $st = Get-FailureStatus $_
        Set-DatasetStatus -Name 'app-registrations' -Status $st -Note $_.Exception.Message
        Set-DatasetStatus -Name 'app-credentials' -Status $st -Note 'Depends on app-registrations'
        if (-not $appsRead) {
            Set-DatasetStatus -Name 'federated-credentials' -Status $st -Note 'Depends on app-registrations'
            Set-DatasetStatus -Name 'app-config-risks' -Status $st -Note 'Depends on app-registrations'
        }
    }

    # ---- 2b. App management policies (credential restrictions) ----
    $ampRows = [System.Collections.Generic.List[object]]::new()
    function Add-AmpRows {
        param([string]$Policy, [string]$PolicyType, $IsEnabled, $Restrictions, [string]$Target, $AppliesTo)
        $any = $false
        foreach ($kind in 'passwordCredentials', 'keyCredentials') {
            foreach ($r in @($Restrictions.$kind | Where-Object { $_ })) {
                $any = $true
                $ampRows.Add([pscustomobject][ordered]@{
                    Policy                      = $Policy
                    PolicyType                  = $PolicyType
                    IsEnabled                   = $IsEnabled
                    Target                      = $Target
                    CredentialKind              = $kind
                    RestrictionType             = $r.restrictionType
                    State                       = $r.state
                    MaxLifetime                 = $r.maxLifetime
                    RestrictForAppsCreatedAfter = $r.restrictForAppsCreatedAfterDateTime
                    AppliesTo                   = $AppliesTo
                })
            }
        }
        return $any
    }
    try {
        $dp = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy'
        $a1 = $(if ($dp.applicationRestrictions) { Add-AmpRows -Policy 'Tenant default' -PolicyType 'TenantDefault' -IsEnabled $dp.isEnabled -Restrictions $dp.applicationRestrictions -Target 'Applications' -AppliesTo 'All (unless a custom policy applies)' } else { $false })
        $a2 = $(if ($dp.servicePrincipalRestrictions) { Add-AmpRows -Policy 'Tenant default' -PolicyType 'TenantDefault' -IsEnabled $dp.isEnabled -Restrictions $dp.servicePrincipalRestrictions -Target 'ServicePrincipals' -AppliesTo 'All (unless a custom policy applies)' } else { $false })
        if (-not $a1 -and -not $a2) { $ampRows.Add([pscustomobject][ordered]@{ Policy = 'Tenant default'; PolicyType = 'TenantDefault'; IsEnabled = $dp.isEnabled; Target = ''; CredentialKind = ''; RestrictionType = '(no restrictions configured)'; State = ''; MaxLifetime = ''; RestrictForAppsCreatedAfter = ''; AppliesTo = '' }) }
        $ampStatus = 'Completed'; $ampNote = ''
        try {
            foreach ($p in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/policies/appManagementPolicies' -Label 'appManagementPolicies')) {
                $applies = ''
                try { $applies = (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/policies/appManagementPolicies/{0}/appliesTo?`$select=id,displayName" -f $p.id) -Label "appliesTo $($p.id)").Count } catch { $applies = 'unreadable' }
                $any = $(if ($p.restrictions) { Add-AmpRows -Policy $p.displayName -PolicyType 'Custom' -IsEnabled $p.isEnabled -Restrictions $p.restrictions -Target 'Assigned apps / service principals' -AppliesTo $applies } else { $false })
                if (-not $any) { $ampRows.Add([pscustomobject][ordered]@{ Policy = $p.displayName; PolicyType = 'Custom'; IsEnabled = $p.isEnabled; Target = 'Assigned apps / service principals'; CredentialKind = ''; RestrictionType = '(no restrictions configured)'; State = ''; MaxLifetime = ''; RestrictForAppsCreatedAfter = ''; AppliesTo = $applies }) }
            }
        }
        catch { $ampStatus = 'Partial'; $ampNote = "Custom policies not readable: $($_.Exception.Message)"; Write-RunLog $ampNote 'WARN' }
        Export-Dataset -Name 'app-management-policies' -Rows $ampRows -Status $ampStatus -Note $ampNote
    }
    catch { Set-DatasetStatus -Name 'app-management-policies' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 3. Service-principal sign-in activity (beta report) ----
    $spLastSignIn = @{}
    if ($SkipSignInActivity) { Write-RunLog 'SP sign-in activity skipped (-SkipSignInActivity).' 'WARN' }
    else {
        try {
            foreach ($s in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities' -Label 'spSignInActivities')) {
                if ($s.lastSignInActivity -and $s.lastSignInActivity.lastSignInDateTime) { $spLastSignIn[$s.appId] = [datetime]$s.lastSignInActivity.lastSignInDateTime }
            }
            Write-RunLog ("SP sign-in activity loaded for {0} apps" -f $spLastSignIn.Count)
        }
        catch { Write-RunLog ("SP sign-in activity unavailable ({0}); LastSignIn will be blank." -f $_.Exception.Message) 'WARN'; $SkipSignInActivity = $true }
    }

    # ---- 4. Service principals + credentials held directly on them ----
    $sps = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,appRoleAssignmentRequired,tags,preferredSingleSignOnMode,verifiedPublisher,createdDateTime,appRoles,oauth2PermissionScopes,passwordCredentials,keyCredentials' -Label 'servicePrincipals'
    $spById = @{}
    foreach ($s in $sps) { $spById[$s.id] = $s }
    function Get-OwnerClass {
        param($Sp)
        if ($Sp.servicePrincipalType -eq 'ManagedIdentity') { return 'ManagedIdentity' }
        if ($MicrosoftTenants -contains $Sp.appOwnerOrganizationId) { return 'Microsoft' }
        if ($Sp.appOwnerOrganizationId -eq $thisTenant) { return 'ThisTenant' }
        if (-not $Sp.appOwnerOrganizationId) { return 'Unknown' }
        return 'ThirdParty'
    }
    $spCredRows = [System.Collections.Generic.List[object]]::new()
    $spCredBySp = @{}
    foreach ($s in $sps) {
        $cls = Get-OwnerClass $s
        $isMs = ($cls -eq 'Microsoft')
        $isMulti = ($cls -eq 'Microsoft' -or $cls -eq 'ThirdParty')
        $items = @()
        foreach ($c in @($s.passwordCredentials)) { if ($c) { $items += [pscustomobject]@{ Type = 'Secret'; Usage = ''; Name = $c.displayName; Start = $c.startDateTime; End = $c.endDateTime } } }
        foreach ($c in @($s.keyCredentials)) { if ($c) { $items += [pscustomobject]@{ Type = 'Certificate'; Usage = "$($c.usage)"; Name = $c.displayName; Start = $c.startDateTime; End = $c.endDateTime } } }
        foreach ($c in $items) {
            $days = Get-DaysTo $c.End $now
            $flag = ''; $sev = ''
            if ($isMs) { $flag = 'CredentialOnFirstPartySp'; $sev = 'High' }
            elseif ($cls -eq 'ThirdParty') { $flag = 'CredentialOnMultiTenantSp'; $sev = $(if ($c.Type -eq 'Secret') { 'High' } else { 'Medium' }) }
            elseif ($cls -eq 'ManagedIdentity') { $flag = 'ManagedIdentityCredential'; $sev = 'Info' }
            elseif ($c.Type -eq 'Certificate' -and "$($s.preferredSingleSignOnMode)" -eq 'saml') { $flag = 'SamlSigningCertificate'; $sev = 'Info' }
            elseif ($c.Type -eq 'Secret') { $flag = 'SecretOnServicePrincipal'; $sev = 'Medium' }
            else { $flag = 'CertificateOnServicePrincipal'; $sev = 'Low' }
            $r = [pscustomobject][ordered]@{
                ServicePrincipal       = $s.displayName
                SpObjectId             = $s.id
                AppId                  = $s.appId
                AppOwnerOrganizationId = $s.appOwnerOrganizationId
                OwnerClass             = $cls
                IsMicrosoft            = $isMs
                IsMultiTenant          = $isMulti
                CredentialType         = $c.Type
                Usage                  = $c.Usage
                DisplayName            = $c.Name
                StartUtc               = $c.Start
                EndUtc                 = $c.End
                Expired                = ($null -ne $days -and $days -lt 0)
                DaysToExpiry           = $days
                Flag                   = $flag
                Severity               = $sev
            }
            $spCredRows.Add($r)
            if (-not $spCredBySp.ContainsKey($s.id)) { $spCredBySp[$s.id] = [System.Collections.Generic.List[object]]::new() }
            $spCredBySp[$s.id].Add($r)
        }
    }
    Export-Dataset -Name 'service-principal-credentials' -Rows @($spCredRows | Sort-Object @{ Expression = { switch ($_.Severity) { 'High' { 0 } 'Medium' { 1 } 'Low' { 2 } default { 3 } } } }, ServicePrincipal) -Note 'All service principals incl. Microsoft first-party. High = credential on a first-party or multi-tenant service principal'

    $spRows = foreach ($s in $sps) {
        $last = $spLastSignIn[$s.appId]
        $sc = $(if ($spCredBySp.ContainsKey($s.id)) { @($spCredBySp[$s.id]) } else { @() })
        [pscustomobject][ordered]@{
            SpObjectId           = $s.id
            AppId                = $s.appId
            DisplayName          = $s.displayName
            Type                 = $s.servicePrincipalType
            OwnerClass           = Get-OwnerClass $s
            Publisher            = $(if ($s.verifiedPublisher) { $s.verifiedPublisher.displayName } else { '' })
            AccountEnabled       = $s.accountEnabled
            AssignmentRequired   = $s.appRoleAssignmentRequired
            SsoMode              = $s.preferredSingleSignOnMode
            IsEnterpriseApp      = (@($s.tags) -contains 'WindowsAzureActiveDirectoryIntegratedApp')
            HasAppRegistration   = $appRegByAppId.ContainsKey($s.appId)
            Created              = $s.createdDateTime
            LastSignInUtc        = $(if ($last) { $last.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            SpCredentialCount    = $sc.Count
            SpCredentialFlags    = Join-Values ($sc | ForEach-Object { $_.Flag } | Sort-Object -Unique)
        }
    }
    Export-Dataset -Name 'service-principals' -Rows $spRows -Note $(if ($SkipSignInActivity) { 'LastSignIn not available' } else { '' })

    # ---- 5. Application permissions (app roles granted to client SPs) + SP owners ----
    $appPermRows = [System.Collections.Generic.List[object]]::new()
    $spOwners = @{}
    $targets = @($sps | Where-Object { $IncludeMicrosoftApps -or (Get-OwnerClass $_) -ne 'Microsoft' })
    $permFailures = 0; $ownerFailures = 0
    Write-RunLog ("Enumerating app-role assignments and owners for {0} service principals" -f $targets.Count)
    foreach ($s in $targets) {
        try { $spOwners[$s.id] = Get-OwnerInfo -Owners (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/owners?`$select=id,displayName,userPrincipalName,userType,accountEnabled" -f $s.id) -Label "owners $($s.id)") }
        catch {
            $ownerFailures++
            $spOwners[$s.id] = Get-OwnerInfo -Owners @() -Status ("HTTP {0}" -f (Get-HttpStatusFromError $_))
        }
        try {
            foreach ($ar in (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments" -f $s.id) -Label "appRoleAssignments $($s.id)")) {
                $res = $spById[$ar.resourceId]
                $perm = '(default access)'
                if ($res -and $ar.appRoleId -ne '00000000-0000-0000-0000-000000000000') {
                    $role = @($res.appRoles | Where-Object id -eq $ar.appRoleId) | Select-Object -First 1
                    $perm = $(if ($role) { $role.value } else { $ar.appRoleId })
                }
                $appPermRows.Add([pscustomobject][ordered]@{
                    ClientDisplayName = $s.displayName
                    ClientAppId       = $s.appId
                    ClientOwnerClass  = Get-OwnerClass $s
                    ResourceName      = $ar.resourceDisplayName
                    Permission        = $perm
                    RiskCategory      = $(if ($HighRiskPermissions.ContainsKey($perm)) { $HighRiskPermissions[$perm] } else { '' })
                    GrantedUtc        = $ar.createdDateTime
                    Tier0Equivalent   = ($Tier0EquivalentPermissions -contains $perm)
                })
            }
        }
        catch {
            $permFailures++
            Write-RunLog ("App-role assignments of {0} not readable: {1}" -f $s.displayName, $_.Exception.Message) 'WARN'
        }
    }
    if ($targets.Count -and $permFailures -ge $targets.Count) { Set-DatasetStatus -Name 'app-permissions-application' -Status 'Blocked' -Note 'appRoleAssignments not readable for any service principal' }
    else {
        $apNote = $(if ($IncludeMicrosoftApps) { 'Includes Microsoft first-party' } else { 'Microsoft first-party clients excluded' })
        if ($permFailures) { $apNote += "; $permFailures service principal(s) unreadable" }
        Export-Dataset -Name 'app-permissions-application' -Rows $appPermRows -Status $(if ($permFailures) { 'Partial' } else { 'Completed' }) -Note $apNote
    }
    if ($ownerFailures) { Write-RunLog ("Owners unreadable for {0} service principal(s); shown as Unresolved, not as NoOwner." -f $ownerFailures) 'WARN' }

    # ---- 5b. Who is assigned to apps that require assignment ----
    if ($SkipAppAssignments) { Set-DatasetStatus -Name 'app-assignments' -Status 'Deferred' -Note 'Skipped (-SkipAppAssignments)' }
    else {
        $asgRows = [System.Collections.Generic.List[object]]::new()
        $asgFailures = 0
        $asgTargets = @($targets | Where-Object { $_.appRoleAssignmentRequired })
        foreach ($s in $asgTargets) {
            $st = 'Completed'; $list = @()
            try {
                $list = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignedTo?`$select=principalType,principalId,principalDisplayName,appRoleId&`$top=999" -f $s.id) -MaxRecords $MaxAssignmentsPerApp -Label "appRoleAssignedTo $($s.id)"
                if ($script:LastQueryTruncated) { $st = "Truncated at $MaxAssignmentsPerApp" }
            }
            catch { $asgFailures++; $st = "Unreadable (HTTP $(Get-HttpStatusFromError $_))" }
            $grpNames = @($list | Where-Object { "$($_.principalType)" -eq 'Group' } | ForEach-Object { "$($_.principalDisplayName)" } | Sort-Object -Unique)
            $asgRows.Add([pscustomobject][ordered]@{
                AppDisplayName     = $s.displayName
                AppId              = $s.appId
                SpObjectId         = $s.id
                OwnerClass         = Get-OwnerClass $s
                AssignmentRequired = $s.appRoleAssignmentRequired
                Users              = $(if ($st -like 'Unreadable*') { '' } else { @($list | Where-Object { "$($_.principalType)" -eq 'User' }).Count })
                Groups             = $(if ($st -like 'Unreadable*') { '' } else { $grpNames.Count })
                ServicePrincipals  = $(if ($st -like 'Unreadable*') { '' } else { @($list | Where-Object { "$($_.principalType)" -eq 'ServicePrincipal' }).Count })
                Total              = $(if ($st -like 'Unreadable*') { '' } else { $list.Count })
                GroupNames         = Join-Values $grpNames
                Status             = $st
            })
        }
        if ($asgTargets.Count -and $asgFailures -ge $asgTargets.Count) { Set-DatasetStatus -Name 'app-assignments' -Status 'Blocked' -Note 'appRoleAssignedTo not readable' }
        else { Export-Dataset -Name 'app-assignments' -Rows $asgRows -Status $(if ($asgFailures -or @($asgRows | Where-Object { $_.Status -like 'Truncated*' }).Count) { 'Partial' } else { 'Completed' }) -Note ("Apps with assignment required. Group members are not expanded here (see script 07/15). Cap {0} per app (-MaxAssignmentsPerApp)" -f $MaxAssignmentsPerApp) }
    }

    # ---- 6. Delegated permission grants ----
    $delRows = [System.Collections.Generic.List[object]]::new()
    $userUpn = @{}
    try {
        foreach ($g in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Label 'oauth2PermissionGrants')) {
            $client = $spById[$g.clientId]; $res = $spById[$g.resourceId]
            $scopes = @(("$($g.scope)").Trim() -split '\s+' | Where-Object { $_ })
            $risky = @($scopes | Where-Object { $HighRiskPermissions.ContainsKey($_) })
            $principal = ''
            if ($g.consentType -eq 'Principal' -and $g.principalId) {
                if (-not $userUpn.ContainsKey($g.principalId)) {
                    try { $userUpn[$g.principalId] = (Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select=userPrincipalName" -f $g.principalId)).userPrincipalName } catch { $userUpn[$g.principalId] = $g.principalId }
                }
                $principal = $userUpn[$g.principalId]
            }
            $delRows.Add([pscustomobject][ordered]@{
                ClientDisplayName = $(if ($client) { $client.displayName } else { $g.clientId })
                ClientAppId       = $(if ($client) { $client.appId } else { '' })
                ClientOwnerClass  = $(if ($client) { Get-OwnerClass $client } else { 'Unknown' })
                ResourceName      = $(if ($res) { $res.displayName } else { $g.resourceId })
                ConsentType       = $(if ($g.consentType -eq 'AllPrincipals') { 'Admin (all users)' } else { 'User' })
                ConsentedBy       = $principal
                Scopes            = Join-Values $scopes
                HighRiskScopes    = Join-Values $risky
                Tier0EquivalentScopes = Join-Values @($scopes | Where-Object { $Tier0EquivalentPermissions -contains $_ })
            })
        }
        Export-Dataset -Name 'app-permissions-delegated' -Rows $delRows
    }
    catch { Set-DatasetStatus -Name 'app-permissions-delegated' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 6b. Directory roles held by service principals ----
    $priv = $null; $privNote = ''
    if ($SkipPrivilegeJoin) { $privNote = 'Skipped (-SkipPrivilegeJoin)' }
    else {
        try {
            $priv = Get-PrivilegedPrincipalSet
            $privNote = Join-Values ($priv.Status.GetEnumerator() | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value })
            Write-RunLog ("Privileged principal set: {0} rows; {1}" -f $priv.Rows.Count, $privNote)
        }
        catch {
            $privNote = "Not readable (HoldsDirectoryRole blank): $($_.Exception.Message)"
            Write-RunLog ("Directory roles of service principals not readable ({0}); HoldsDirectoryRole left blank." -f $_.Exception.Message) 'WARN'
        }
    }

    # ---- 7. Per-app risk summary ("data movers") ----
    $apByApp = @{}; foreach ($r in $appPermRows) { if (-not $apByApp.ContainsKey($r.ClientAppId)) { $apByApp[$r.ClientAppId] = [System.Collections.Generic.List[object]]::new() }; $apByApp[$r.ClientAppId].Add($r) }
    $dgByApp = @{}; foreach ($r in $delRows) { if (-not $dgByApp.ContainsKey($r.ClientAppId)) { $dgByApp[$r.ClientAppId] = [System.Collections.Generic.List[object]]::new() }; $dgByApp[$r.ClientAppId].Add($r) }
    $riskRows = foreach ($s in $sps) {
        $cls = Get-OwnerClass $s
        $sc = $(if ($spCredBySp.ContainsKey($s.id)) { @($spCredBySp[$s.id]) } else { @() })
        $highCred = @($sc | Where-Object { $_.Severity -eq 'High' })
        $ps = $(if ($priv) { Get-PrivilegeSummary -Set $priv -PrincipalId $s.id } else { $null })
        if ($cls -eq 'Microsoft' -and -not $IncludeMicrosoftApps -and -not $highCred.Count) { continue }
        $ap = @(); if ($apByApp.ContainsKey($s.appId)) { $ap = @($apByApp[$s.appId]) }
        $dg = @(); if ($dgByApp.ContainsKey($s.appId)) { $dg = @($dgByApp[$s.appId]) }
        $holdsRole = [bool]($ps -and $ps.IsPrivileged)
        if ($ap.Count -eq 0 -and $dg.Count -eq 0 -and -not $holdsRole -and -not $highCred.Count) { continue }
        $apRisk = @($ap | Where-Object RiskCategory)
        $dgRisk = @($dg | Where-Object HighRiskScopes)
        $t0 = @($ap | Where-Object Tier0Equivalent) + @($dg | Where-Object Tier0EquivalentScopes)
        $reg = $appRegByAppId[$s.appId]
        $last = $spLastSignIn[$s.appId]
        $so = $(if ($spOwners.ContainsKey($s.id)) { $spOwners[$s.id] } else { $null })
        $flags = @()
        if ($apRisk | Where-Object RiskCategory -eq 'DataAccess') { $flags += 'AppPerm:DataAccess' }
        if ($apRisk | Where-Object RiskCategory -eq 'PrivilegeEscalation') { $flags += 'AppPerm:PrivilegeEscalation' }
        if ($t0.Count) { $flags += 'Tier0EquivalentPermission' }
        if ($dgRisk) { $flags += 'Delegated:HighRisk' }
        if (@($dg | Where-Object ConsentType -eq 'User').Count) { $flags += 'UserConsented' }
        $owners = $(if ($reg) { $reg.OwnerCount } elseif ($so) { $so.Count } else { '' })
        if ("$owners" -eq '0') { $flags += 'NoOwner' }
        if (($reg -and $reg.OwnerReadStatus -ne 'Completed') -or ($so -and $so.Status -ne 'Completed')) { $flags += 'OwnerUnresolved' }
        if (($reg -and $reg.OwnerGuestCount) -or ($so -and $so.Guest)) { $flags += 'OwnerIsGuest' }
        if (($reg -and $reg.OwnerDisabledCount) -or ($so -and $so.Disabled)) { $flags += 'OwnerDisabled' }
        if ($reg -and $reg.HasExpiredCredential) { $flags += 'ExpiredCredential' }
        if ($reg -and $reg.HasLongLivedSecret) { $flags += 'LongLivedSecret' }
        if ($reg -and $reg.FederatedCredentialFlags) { $flags += 'FederatedCredentialBroad' }
        if ($reg -and $reg.ConfigRisks) { $flags += 'ConfigRisk' }
        foreach ($f in @($highCred | ForEach-Object { $_.Flag } | Sort-Object -Unique)) { $flags += $f }
        if ($holdsRole) { $flags += 'HoldsDirectoryRole' }
        if ($ps -and $ps.IsTier0) { $flags += 'HoldsTier0Role' }
        if (-not $SkipSignInActivity -and (-not $last -or $last -lt $now.AddDays(-$StaleDays))) { $flags += "NoSignIn${StaleDays}d" }
        $score = (3 * @($apRisk).Count) + (2 * @($dgRisk).Count) + $(if ("$owners" -eq '0') { 2 } else { 0 }) + $(if ($flags -contains 'UserConsented') { 1 } else { 0 })
        $score += $(if ($t0.Count) { 5 } else { 0 }) + $(if ($ps -and $ps.IsTier0) { 5 } elseif ($holdsRole) { 3 } else { 0 }) + (5 * $highCred.Count)
        [pscustomobject][ordered]@{
            DisplayName               = $s.displayName
            AppId                     = $s.appId
            OwnerClass                = $cls
            Publisher                 = $(if ($s.verifiedPublisher) { $s.verifiedPublisher.displayName } else { '' })
            ApplicationPermissions    = $ap.Count
            HighRiskAppPermissions    = Join-Values ($apRisk | ForEach-Object { '{0}:{1}' -f $_.ResourceName, $_.Permission } | Sort-Object -Unique)
            DelegatedGrants           = $dg.Count
            HighRiskDelegatedScopes   = Join-Values ($dgRisk | ForEach-Object { $_.HighRiskScopes -split '; ' } | Sort-Object -Unique)
            UserConsentCount          = @($dg | Where-Object ConsentType -eq 'User').Count
            OwnerCount                = $owners
            LastSignInUtc             = $(if ($last) { $last.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            Flags                     = Join-Values $flags
            TriageScore               = $score
            HoldsDirectoryRole        = $(if ($priv) { $holdsRole } else { '' })
            DirectoryRoles            = $(if ($ps) { $ps.Roles } else { '' })
            HoldsTier0Role            = $(if ($priv) { [bool]($ps -and $ps.IsTier0) } else { '' })
            RolePaths                 = $(if ($ps) { $ps.Paths } else { '' })
            Tier0EquivalentPermissions = Join-Values (@($ap | Where-Object Tier0Equivalent | ForEach-Object { $_.Permission }) + @($dg | ForEach-Object { $_.Tier0EquivalentScopes -split '; ' }) | Where-Object { $_ } | Sort-Object -Unique)
            Owners                    = $(if ($reg) { $reg.Owners } elseif ($so) { $so.Names } else { '' })
            SpCredentialFlags         = Join-Values ($sc | ForEach-Object { $_.Flag } | Sort-Object -Unique)
        }
    }
    $riskRows = @($riskRows | Sort-Object TriageScore -Descending)
    Export-Dataset -Name 'app-risk-summary' -Rows $riskRows -Status $(if (-not $SkipPrivilegeJoin -and -not $priv) { 'Partial' } else { 'Completed' }) -Note ('TriageScore is a sorting aid, not a risk rating. Directory roles: ' + $(if ($privNote) { $privNote } else { 'n/a' }))

    # ---- 8. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'App registrations' $appRegByAppId.Count
    Add-Metric 'App registrations with no owner' @($appRegByAppId.Values | Where-Object { "$($_.OwnerCount)" -eq '0' }).Count
    Add-Metric 'App registrations with a guest or disabled owner' @($appRegByAppId.Values | Where-Object { $_.OwnerGuestCount -or $_.OwnerDisabledCount }).Count
    Add-Metric 'App credentials expired' @($credRows | Where-Object Status -eq 'Expired').Count
    Add-Metric "App credentials expiring within $CredentialWarningDays days" @($credRows | Where-Object Status -eq 'ExpiringSoon').Count
    Add-Metric "Secrets with lifetime over $LongLivedSecretDays days" @($credRows | Where-Object LongLived).Count
    Add-Metric 'Credentials on Microsoft first-party service principals' @($spCredRows | Where-Object Flag -eq 'CredentialOnFirstPartySp').Count -Note 'High: review every one'
    Add-Metric 'Credentials on multi-tenant (third-party) service principals' @($spCredRows | Where-Object Flag -eq 'CredentialOnMultiTenantSp').Count
    Add-Metric 'Federated credentials' $ficRows.Count
    Add-Metric 'Federated credentials with wildcard or broad subjects' @($ficRows | Where-Object Flags).Count
    Add-Metric 'App configuration risks' $cfgRows.Count
    Add-Metric 'App management policy restrictions enforced' @($ampRows | Where-Object { $_.State -eq 'enabled' -and "$($_.IsEnabled)" -eq 'True' }).Count
    foreach ($cls in 'ThisTenant', 'ThirdParty', 'ManagedIdentity', 'Microsoft', 'Unknown') { Add-Metric "Service principals: $cls" @($spRows | Where-Object OwnerClass -eq $cls).Count }
    Add-Metric 'Application-permission grants (non-Microsoft clients)' @($appPermRows | Where-Object ClientOwnerClass -ne 'Microsoft').Count
    Add-Metric 'Application-permission grants that are high-risk' @($appPermRows | Where-Object RiskCategory).Count
    Add-Metric 'Application-permission grants that are Tier 0-equivalent' @($appPermRows | Where-Object Tier0Equivalent).Count
    Add-Metric 'Delegated grants (admin consent)' @($delRows | Where-Object { $_.ConsentType -like 'Admin*' }).Count
    Add-Metric 'Delegated grants (user consent)' @($delRows | Where-Object ConsentType -eq 'User').Count
    Add-Metric 'Delegated grants with high-risk scopes' @($delRows | Where-Object HighRiskScopes).Count
    if ($priv) {
        Add-Metric 'Service principals holding a directory role' @($riskRows | Where-Object { $_.HoldsDirectoryRole -eq $true }).Count -Note $privNote
        Add-Metric 'Service principals holding a Tier 0 role' @($riskRows | Where-Object { $_.HoldsTier0Role -eq $true }).Count
    }
    else { Add-Metric 'Service principals holding a directory role' '' -Note $privNote }
    Add-Metric 'Apps in data-movers list' @($riskRows).Count
    Add-Metric 'Data movers with no owner' @($riskRows | Where-Object { $_.Flags -match 'NoOwner' }).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ CredentialWarningDays = $CredentialWarningDays; LongLivedSecretDays = $LongLivedSecretDays; StaleDays = $StaleDays; IncludeMicrosoftApps = [bool]$IncludeMicrosoftApps; SkipSignInActivity = [bool]$SkipSignInActivity; MaxAssignmentsPerApp = $MaxAssignmentsPerApp; SkipAppAssignments = [bool]$SkipAppAssignments; SkipPrivilegeJoin = [bool]$SkipPrivilegeJoin }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
