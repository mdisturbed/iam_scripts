<#
.SYNOPSIS
    Read-only discovery of privileged access in Microsoft Entra ID.

.DESCRIPTION
    Exports the evidence needed to measure "privileged account sprawl" on the Entra side:
      - Active directory-role assignments (permanent vs time-bound, direct vs via group)
      - Eligible (PIM) directory-role assignments
      - Members of every group that holds a role (expanded transitively)
      - Role-assignable groups and their owners
      - One row per privileged user with sync source, last sign-in, MFA registration and flags
      - A summary of headline metrics

    Falls back to /roleManagement/directory/roleAssignments if PIM schedule APIs are not
    available (no Entra ID P2 / Governance licence). Eligible assignments are then marked
    EvidenceUnavailable rather than silently empty.

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\02-PrivilegedAccess\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\02-Get-PrivilegedAccess.ps1
.EXAMPLE
    .\02-Get-PrivilegedAccess.ps1 -StaleDays 60

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : RoleManagement.Read.Directory, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All
    Licence : signInActivity needs Entra ID P1; PIM schedules need P2 / ID Governance.
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

    [int]$StaleDays = 90
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '02-PrivilegedAccess'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('RoleManagement.Read.Directory', 'Directory.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All')

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

# Built-in role template IDs treated as Tier 0 / highly privileged. Extend as needed.
$Tier0RoleTemplates = @{
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

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- Role definitions ----
    $roleDefs = @{}
    foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn' -Label 'roleDefinitions')) {
        $roleDefs[$r.id] = $r
        if ($r.templateId -and -not $roleDefs.ContainsKey($r.templateId)) { $roleDefs[$r.templateId] = $r }
    }
    function Get-RoleInfo {
        param([string]$RoleDefinitionId)
        $d = $roleDefs[$RoleDefinitionId]
        $template = $(if ($d -and $d.templateId) { $d.templateId } else { $RoleDefinitionId })
        [pscustomobject]@{
            Name      = $(if ($d) { $d.displayName } else { $RoleDefinitionId })
            IsBuiltIn = $(if ($d) { $d.isBuiltIn } else { '' })
            IsTier0   = $Tier0RoleTemplates.ContainsKey($template)
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
    try {
        foreach ($gid in $roleGroups.Keys) {
            $gname = Resolve-DirectoryObject $gid
            foreach ($m in (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers" -f $gid) -Label "transitiveMembers $gid")) {
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
        Export-Dataset -Name 'role-group-members' -Rows $groupMemberRows -Note ("{0} role-holding groups expanded" -f $roleGroups.Count)
    }
    catch { Set-DatasetStatus -Name 'role-group-members' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 4. Role-assignable groups ----
    try {
        $rag = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true&$count=true&$select=id,displayName,createdDateTime,onPremisesSyncEnabled,securityEnabled,mailEnabled,description' -Eventual -Label 'roleAssignableGroups'
        $ragRows = foreach ($g in $rag) {
            $owners = @()
            try { $owners = @(Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/owners?`$select=id,displayName,userPrincipalName" -f $g.id) -Label "owners $($g.id)") } catch { }
            [pscustomobject][ordered]@{
                GroupId          = $g.id
                GroupName        = $g.displayName
                Created          = $g.createdDateTime
                SyncedFromOnPrem = [bool]$g.onPremisesSyncEnabled
                HoldsRoles       = Join-Values ($(if ($roleGroups.ContainsKey($g.id)) { $roleGroups[$g.id] | Sort-Object -Unique } else { @() }))
                OwnerCount       = $owners.Count
                Owners           = Join-Values ($owners | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } })
                HasDescription   = [bool]$g.description
            }
        }
        Export-Dataset -Name 'role-assignable-groups' -Rows $ragRows
    }
    catch { Set-DatasetStatus -Name 'role-assignable-groups' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 5. Per privileged user ----
    $userRoles = @{}   # userId -> list of 'Role [Active/Eligible, Direct/Group]'
    function Add-UserRole { param($Id, $Text) if (-not $userRoles.ContainsKey($Id)) { $userRoles[$Id] = [System.Collections.Generic.List[string]]::new() }; $userRoles[$Id].Add($Text) }
    foreach ($r in $activeRows) { if ($r.PrincipalType -eq 'user') { Add-UserRole $r.PrincipalId ('{0} [Active{1}]' -f $r.RoleName, $(if ($r.IsPermanent) { ',Permanent' } else { '' })) } }
    foreach ($r in $eligibleRows) { if ($r.PrincipalType -eq 'user') { Add-UserRole $r.PrincipalId ('{0} [Eligible]' -f $r.RoleName) } }
    foreach ($m in $groupMemberRows) { if ($m.MemberType -eq 'user') { Add-UserRole $m.MemberId ('{0} [via group {1}]' -f $m.RolesGranted, $m.GroupName) } }
    $tier0Names = @($Tier0RoleTemplates.Values)

    $privRows = [System.Collections.Generic.List[object]]::new()
    $signInBlocked = $false
    foreach ($uid in $userRoles.Keys) {
        $u = $null
        try {
            $select = 'id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,createdDateTime'
            if (-not $signInBlocked) { $select += ',signInActivity' }
            $u = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select={1}" -f $uid, $select)
        }
        catch {
            if (-not $signInBlocked) {
                $signInBlocked = $true
                Write-RunLog ("signInActivity not readable ({0}); continuing without last sign-in." -f $_.Exception.Message) 'WARN'
                try { $u = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select=id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,createdDateTime" -f $uid) } catch { }
            }
        }
        if (-not $u) { continue }
        $last = $null
        if ($u.PSObject.Properties.Name -contains 'signInActivity' -and $u.signInActivity) {
            $cands = @($u.signInActivity.lastSuccessfulSignInDateTime, $u.signInActivity.lastSignInDateTime, $u.signInActivity.lastNonInteractiveSignInDateTime) | Where-Object { $_ }
            if ($cands) { $last = ($cands | ForEach-Object { [datetime]$_ } | Sort-Object -Descending | Select-Object -First 1) }
        }
        $mfa = $null
        try { $mfa = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails/{0}" -f $uid) } catch { }
        $roles = @($userRoles[$uid] | Sort-Object -Unique)
        $isTier0 = [bool](@($roles | Where-Object { $r = $_; @($tier0Names | Where-Object { $r -like "*$_*" }).Count -gt 0 }).Count)
        $flags = @()
        if ($u.onPremisesSyncEnabled) { $flags += 'SyncedFromOnPrem' }
        if (-not $u.accountEnabled) { $flags += 'Disabled' }
        if ($signInBlocked -eq $false -and (-not $last -or $last -lt $script:RunStartUtc.AddDays(-$StaleDays))) { $flags += "NoSignIn${StaleDays}d" }
        if ($mfa -and -not $mfa.isMfaRegistered) { $flags += 'NotMfaRegistered' }
        if (@($roles | Where-Object { $_ -match 'Permanent' }).Count) { $flags += 'PermanentActive' }
        if ($u.userType -eq 'Guest') { $flags += 'Guest' }
        $privRows.Add([pscustomobject][ordered]@{
            UserId           = $u.id
            UserPrincipalName = $u.userPrincipalName
            DisplayName      = $u.displayName
            UserType         = $u.userType
            AccountEnabled   = $u.accountEnabled
            SyncedFromOnPrem = [bool]$u.onPremisesSyncEnabled
            Created          = $u.createdDateTime
            LastSignInUtc    = $(if ($last) { $last.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            IsMfaRegistered  = $(if ($mfa) { $mfa.isMfaRegistered } else { '' })
            MethodsRegistered = $(if ($mfa) { Join-Values $mfa.methodsRegistered } else { '' })
            HoldsTier0Role   = $isTier0
            RoleCount        = $roles.Count
            Roles            = Join-Values $roles
            Flags            = Join-Values $flags
        })
    }
    Export-Dataset -Name 'privileged-users' -Rows $privRows -Note $(if ($signInBlocked) { 'signInActivity unavailable; staleness not evaluated' } else { '' })

    # ---- 6. Summary ----
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
    Add-Metric 'Distinct privileged users' $privRows.Count
    Add-Metric 'Privileged users holding a Tier 0 role' @($privRows | Where-Object HoldsTier0Role).Count
    Add-Metric 'Privileged users synced from on-prem' @($privRows | Where-Object SyncedFromOnPrem).Count 'Best practice: cloud-only admin accounts'
    Add-Metric 'Privileged users not MFA registered' @($privRows | Where-Object { $_.Flags -match 'NotMfaRegistered' }).Count
    Add-Metric "Privileged users with no sign-in in $StaleDays days" @($privRows | Where-Object { $_.Flags -match 'NoSignIn' }).Count
    Add-Metric 'Privileged guest users' @($privRows | Where-Object { $_.Flags -match 'Guest' }).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ StaleDays = $StaleDays }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
