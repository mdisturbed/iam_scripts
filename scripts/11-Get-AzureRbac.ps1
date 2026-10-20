<#
.SYNOPSIS
    Read-only discovery of Azure RBAC role assignments across management groups and subscriptions.

.DESCRIPTION
    Entra directory roles (script 02) control the tenant; Azure RBAC controls the resources. This
    script reads Azure Resource Manager and exports:
      - Management groups and subscriptions visible to the operator
      - Every role assignment (management group, subscription, resource group and resource scope),
        de-duplicated, with the role, scope level and principal resolved to a name via Graph
      - Eligible (PIM for Azure resources) assignments per subscription, where licensed
      - Custom role definitions, flagged when they contain wildcard or authorization-write actions
      - Classic subscription administrators (co-administrators)
      - A summary of headline metrics

    Flags on assignments: DirectUserAssignment (to a user rather than a group), GuestPrincipal,
    OrphanedPrincipal (principal deleted or unresolvable), PrivilegedAtBroadScope (Owner, User
    Access Administrator, RBAC Administrator or Contributor at root / management group /
    subscription), ServicePrincipalPrivileged, CustomRoleRisky.

    READ-ONLY. ARM calls go through Invoke-ArmGet, which only issues Invoke-AzRestMethod -Method GET.
    Graph calls go through Invoke-GraphGet (GET only).

    Output: <OutputRoot>\11-AzureRbac\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\11-Get-AzureRbac.ps1
.EXAMPLE
    .\11-Get-AzureRbac.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002'
.EXAMPLE
    .\11-Get-AzureRbac.ps1 -AuthMode AppCertificate -TenantId tenant-id-redacted -ClientId <app-id> -CertificateThumbprint <thumbprint>

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, Az.Accounts module, Microsoft.Graph.Authentication module
    Azure   : Reader on the root management group (or each subscription) to see all assignments
    Graph   : Directory.Read.All (to resolve principal names; skip with -SkipPrincipalResolution)
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string[]]$SubscriptionId = @(),                        # blank = every subscription visible
    [switch]$SkipManagementGroups,
    [switch]$SkipEligible,
    [switch]$SkipPrincipalResolution,

    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '11-AzureRbac'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('Directory.Read.All')

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

$PrivilegedRoleNames = @('Owner', 'User Access Administrator', 'Role Based Access Control Administrator', 'Contributor')
$Arm = 'https://management.azure.com'

function Invoke-ArmGet {
    # The ONLY function that talks to Azure Resource Manager. Method is hard-coded to GET.
    param([Parameter(Mandatory)][string]$Uri)
    $attempt = 0
    while ($true) {
        $resp = Invoke-AzRestMethod -Method GET -Uri $Uri -ErrorAction Stop
        $code = [int]$resp.StatusCode
        if ($code -ge 200 -and $code -lt 300) { return ($resp.Content | ConvertFrom-Json) }
        $attempt++
        if (($code -eq 429 -or $code -ge 500) -and $attempt -le 6) {
            $wait = [int][math]::Min(120, [math]::Pow(2, $attempt))
            Write-RunLog ("ARM HTTP {0} on {1}; retry {2}/6 in {3}s" -f $code, $Uri, $attempt, $wait) 'WARN'
            Start-Sleep -Seconds $wait
            continue
        }
        $msg = $resp.Content
        try { $msg = ($resp.Content | ConvertFrom-Json).error.message } catch { }
        throw ("ARM HTTP {0}: {1}" -f $code, $msg)
    }
}

function Invoke-ArmGetAll {
    param([Parameter(Mandatory)][string]$Uri)
    $out = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $r = Invoke-ArmGet -Uri $next
        foreach ($v in @($r.value)) { if ($null -ne $v) { $out.Add($v) } }
        $next = $null
        if ($r.PSObject.Properties.Name -contains 'nextLink' -and $r.nextLink) { $next = $r.nextLink }
    }
    return , $out
}

function Get-ScopeLevel {
    param([string]$Scope)
    if ($Scope -eq '/') { return 'Root' }
    if ($Scope -match '^/providers/Microsoft\.Management/managementGroups/[^/]+$') { return 'ManagementGroup' }
    if ($Scope -match '^/subscriptions/[^/]+$') { return 'Subscription' }
    if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 'ResourceGroup' }
    return 'Resource'
}

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)

    # ---- Connect to Azure ----
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) { throw 'Module Az.Accounts not found. Install it (Install-Module Az.Accounts -Scope CurrentUser) if your policy allows.' }
    Import-Module Az.Accounts -ErrorAction Stop
    $azArgs = @{ ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
    if ($TenantId -and $TenantId -ne 'tenant-id-redacted') { $azArgs['Tenant'] = $TenantId }
    if ($AuthMode -eq 'AppCertificate') {
        if (-not $ClientId -or -not $CertificateThumbprint -or $TenantId -eq 'tenant-id-redacted') { throw 'AppCertificate mode needs -TenantId, -ClientId and -CertificateThumbprint.' }
        Connect-AzAccount -ServicePrincipal -ApplicationId $ClientId -CertificateThumbprint $CertificateThumbprint @azArgs | Out-Null
    }
    else { Connect-AzAccount @azArgs | Out-Null }
    $az = Get-AzContext
    Write-RunLog ("Connected to Azure. Tenant={0} Account={1}" -f $az.Tenant.Id, $az.Account.Id)
    $script:ManifestExtra = @{ AzureAccount = "$($az.Account.Id)"; AzureTenant = "$($az.Tenant.Id)" }

    if (-not $SkipPrincipalResolution) {
        try { $ctx = Connect-DiscoveryGraph }
        catch { Write-RunLog ("Graph unavailable ({0}); principals will show as IDs." -f $_.Exception.Message) 'WARN'; $SkipPrincipalResolution = $true }
    }

    # ---- 1. Management groups ----
    $mgRows = @()
    if ($SkipManagementGroups) { Set-DatasetStatus -Name 'azure-management-groups' -Status 'Deferred' -Note '-SkipManagementGroups' }
    else {
        try {
            $mgs = Invoke-ArmGetAll -Uri "$Arm/providers/Microsoft.Management/managementGroups?api-version=2021-04-01"
            $mgRows = foreach ($m in $mgs) { [pscustomobject][ordered]@{ Name = $m.name; DisplayName = $m.properties.displayName; Id = $m.id } }
            Export-Dataset -Name 'azure-management-groups' -Rows $mgRows
        }
        catch { Set-DatasetStatus -Name 'azure-management-groups' -Status 'Blocked' -Note $_.Exception.Message }
    }

    # ---- 2. Subscriptions ----
    $subs = (Invoke-ArmGetAll -Uri "$Arm/subscriptions?api-version=2022-12-01")
    if ($SubscriptionId.Count) { $subs = @($subs | Where-Object { $SubscriptionId -contains $_.subscriptionId }) }
    Export-Dataset -Name 'azure-subscriptions' -Rows @($subs | ForEach-Object { [pscustomobject][ordered]@{ SubscriptionId = $_.subscriptionId; Name = $_.displayName; State = $_.state } })
    $subName = @{}; foreach ($s in $subs) { $subName[$s.subscriptionId] = $s.displayName }

    # ---- 3. Role definitions (built-in + custom), keyed by GUID ----
    $roleDefs = @{}
    $customRoles = @{}
    foreach ($s in $subs) {
        try {
            foreach ($d in (Invoke-ArmGetAll -Uri "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01")) {
                $guid = ($d.id -split '/')[-1]
                if (-not $roleDefs.ContainsKey($guid)) { $roleDefs[$guid] = $d }
                if ($d.properties.type -eq 'CustomRole') { $customRoles[$guid] = $d }
            }
        }
        catch { Write-RunLog ("Role definitions unreadable for {0}: {1}" -f $s.subscriptionId, $_.Exception.Message) 'WARN' }
    }
    function Test-RiskyRole {
        param($Def)
        $actions = @(); foreach ($p in @($Def.properties.permissions)) { $actions += @($p.actions) }
        return [bool](@($actions | Where-Object { $_ -eq '*' -or $_ -match '^Microsoft\.Authorization/(\*|roleAssignments/(\*|write))' -or $_ -eq '*/write' }).Count)
    }

    # ---- 4. Role assignments ----
    $assignments = @{}
    $sources = @()
    foreach ($m in $mgRows) { $sources += @{ Label = "MG $($m.Name)"; Uri = "$Arm$($m.Id)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=atScope()" } }
    foreach ($s in $subs) { $sources += @{ Label = "Sub $($s.subscriptionId)"; Uri = "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" } }
    $blockedSources = 0
    foreach ($src in $sources) {
        try { foreach ($a in (Invoke-ArmGetAll -Uri $src.Uri)) { $assignments[$a.id] = $a } }
        catch { $blockedSources++; Write-RunLog ("{0}: {1}" -f $src.Label, $_.Exception.Message) 'WARN' }
    }
    Write-RunLog ("{0} distinct role assignments" -f $assignments.Count)

    $principalCache = @{}
    function Get-Principal {
        param([string]$Id)
        if ($principalCache.ContainsKey($Id)) { return $principalCache[$Id] }
        $info = [pscustomobject]@{ Name = $Id; Upn = ''; UserType = ''; Exists = '' }
        if (-not $SkipPrincipalResolution) {
            try {
                $o = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/directoryObjects/{0}" -f $Id)
                $info = [pscustomobject]@{
                    Name     = $o.displayName
                    Upn      = $(if ($o.PSObject.Properties.Name -contains 'userPrincipalName') { $o.userPrincipalName } else { '' })
                    UserType = $(if ($o.PSObject.Properties.Name -contains 'userType') { $o.userType } else { '' })
                    Exists   = $true
                }
            }
            catch { $info = [pscustomobject]@{ Name = $Id; Upn = ''; UserType = ''; Exists = $false } }
        }
        $principalCache[$Id] = $info
        return $info
    }

    $assignRows = foreach ($a in $assignments.Values) {
        $pr = $a.properties
        $guid = ($pr.roleDefinitionId -split '/')[-1]
        $def = $roleDefs[$guid]
        $roleName = $(if ($def) { $def.properties.roleName } else { $guid })
        $isCustom = [bool]$customRoles.ContainsKey($guid)
        $level = Get-ScopeLevel $pr.scope
        $p = Get-Principal $pr.principalId
        $subId = $(if ($pr.scope -match '^/subscriptions/([^/]+)') { $Matches[1] } else { '' })
        $privileged = ($PrivilegedRoleNames -contains $roleName) -or ($isCustom -and (Test-RiskyRole $def))
        $flags = @()
        if ($pr.principalType -eq 'User') { $flags += 'DirectUserAssignment' }
        if ($p.UserType -eq 'Guest') { $flags += 'GuestPrincipal' }
        if ($p.Exists -eq $false -or $pr.principalType -eq 'Unknown') { $flags += 'OrphanedPrincipal' }
        if ($privileged -and $level -in @('Root', 'ManagementGroup', 'Subscription')) { $flags += 'PrivilegedAtBroadScope' }
        if ($privileged -and $pr.principalType -eq 'ServicePrincipal') { $flags += 'ServicePrincipalPrivileged' }
        if ($isCustom -and (Test-RiskyRole $def)) { $flags += 'CustomRoleRisky' }
        [pscustomobject][ordered]@{
            Scope            = $pr.scope
            ScopeLevel       = $level
            Subscription     = $(if ($subId) { $subName[$subId] } else { '' })
            RoleName         = $roleName
            RoleType         = $(if ($isCustom) { 'Custom' } else { 'BuiltIn' })
            IsPrivilegedRole = $privileged
            PrincipalType    = $pr.principalType
            PrincipalId      = $pr.principalId
            PrincipalName    = $p.Name
            PrincipalUPN     = $p.Upn
            HasCondition     = [bool]$pr.condition
            CreatedOnUtc     = $pr.createdOn
            Flags            = Join-Values $flags
            AssignmentId     = $a.id
        }
    }
    $assignRows = @($assignRows | Sort-Object ScopeLevel, Scope, RoleName)
    Export-Dataset -Name 'azure-role-assignments' -Rows $assignRows -Note $(if ($blockedSources) { "$blockedSources scope(s) could not be read; see run.log" } else { '' })

    # ---- 5. Eligible (PIM) ----
    if ($SkipEligible) { Set-DatasetStatus -Name 'azure-eligible-assignments' -Status 'Deferred' -Note '-SkipEligible' }
    else {
        $eligRows = [System.Collections.Generic.List[object]]::new()
        $eligFailed = 0
        foreach ($s in $subs) {
            try {
                foreach ($e in (Invoke-ArmGetAll -Uri "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01")) {
                    $ep = $e.properties
                    $guid = ($ep.roleDefinitionId -split '/')[-1]
                    $p = Get-Principal $ep.principalId
                    $eligRows.Add([pscustomobject][ordered]@{
                        Scope         = $ep.scope
                        ScopeLevel    = Get-ScopeLevel $ep.scope
                        Subscription  = $s.displayName
                        RoleName      = $(if ($roleDefs[$guid]) { $roleDefs[$guid].properties.roleName } else { $guid })
                        PrincipalType = $ep.principalType
                        PrincipalName = $p.Name
                        PrincipalUPN  = $p.Upn
                        StartUtc      = $ep.startDateTime
                        EndUtc        = $ep.endDateTime
                        MemberType    = $ep.memberType
                    })
                }
            }
            catch { $eligFailed++; Write-RunLog ("Eligible assignments unreadable for {0}: {1}" -f $s.subscriptionId, $_.Exception.Message) 'WARN' }
        }
        if ($eligFailed -eq $subs.Count -and $subs.Count -gt 0) { Set-DatasetStatus -Name 'azure-eligible-assignments' -Status 'EvidenceUnavailable' -Note 'PIM for Azure resources not readable in any subscription (licence or permission)' }
        else { Export-Dataset -Name 'azure-eligible-assignments' -Rows $eligRows -Note $(if ($eligFailed) { "$eligFailed subscription(s) unreadable" } else { '' }) }
    }

    # ---- 6. Custom roles ----
    $customRows = foreach ($d in $customRoles.Values) {
        $actions = @(); $notActions = @(); $dataActions = @()
        foreach ($p in @($d.properties.permissions)) { $actions += @($p.actions); $notActions += @($p.notActions); $dataActions += @($p.dataActions) }
        $guid = ($d.id -split '/')[-1]
        [pscustomobject][ordered]@{
            RoleName         = $d.properties.roleName
            Description      = $d.properties.description
            AssignableScopes = Join-Values $d.properties.assignableScopes
            ActionCount      = @($actions | Where-Object { $_ }).Count
            DataActionCount  = @($dataActions | Where-Object { $_ }).Count
            Actions          = Join-Values $actions
            NotActions       = Join-Values $notActions
            Risky            = (Test-RiskyRole $d)
            AssignmentCount  = @($assignRows | Where-Object { $_.AssignmentId -and ($assignments[$_.AssignmentId].properties.roleDefinitionId -split '/')[-1] -eq $guid }).Count
        }
    }
    Export-Dataset -Name 'azure-custom-roles' -Rows $customRows -Note 'Risky = contains *, */write, or Microsoft.Authorization write actions'

    # ---- 7. Classic administrators ----
    $classicRows = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $subs) {
        try {
            foreach ($c in (Invoke-ArmGetAll -Uri "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-07-01")) {
                $classicRows.Add([pscustomobject][ordered]@{ Subscription = $s.displayName; EmailAddress = $c.properties.emailAddress; Role = $c.properties.role })
            }
        }
        catch { Write-RunLog ("Classic administrators unreadable for {0}: {1}" -f $s.subscriptionId, $_.Exception.Message) 'WARN' }
    }
    Export-Dataset -Name 'azure-classic-administrators' -Rows $classicRows -Note 'Classic administrators are retired by Microsoft; any remaining should be converted to RBAC'

    # ---- 8. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Management groups visible' @($mgRows).Count
    Add-Metric 'Subscriptions in scope' $subs.Count
    Add-Metric 'Role assignments' $assignRows.Count
    Add-Metric 'Scopes that could not be read' $blockedSources $(if ($blockedSources) { 'Assignments in these scopes are missing - see run.log; usually needs Reader there' } else { '' })
    foreach ($lvl in 'Root', 'ManagementGroup', 'Subscription', 'ResourceGroup', 'Resource') { Add-Metric "Assignments at $lvl scope" @($assignRows | Where-Object ScopeLevel -eq $lvl).Count }
    Add-Metric 'Assignments made directly to users' @($assignRows | Where-Object { $_.Flags -match 'DirectUserAssignment' }).Count 'Best practice: assign to groups'
    Add-Metric 'Privileged roles at broad scope' @($assignRows | Where-Object { $_.Flags -match 'PrivilegedAtBroadScope' }).Count 'Owner / UAA / RBAC Admin / Contributor at root, MG or subscription'
    Add-Metric 'Owner assignments' @($assignRows | Where-Object RoleName -eq 'Owner').Count
    Add-Metric 'User Access Administrator assignments' @($assignRows | Where-Object RoleName -eq 'User Access Administrator').Count
    Add-Metric 'Assignments to orphaned principals' @($assignRows | Where-Object { $_.Flags -match 'OrphanedPrincipal' }).Count 'Principal deleted - safe clean-up candidates'
    Add-Metric 'Assignments to guests' @($assignRows | Where-Object { $_.Flags -match 'GuestPrincipal' }).Count
    Add-Metric 'Privileged assignments to service principals' @($assignRows | Where-Object { $_.Flags -match 'ServicePrincipalPrivileged' }).Count
    Add-Metric 'Custom roles' @($customRows).Count
    Add-Metric 'Custom roles flagged risky' @($customRows | Where-Object Risky).Count
    Add-Metric 'Classic administrators' $classicRows.Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ SubscriptionId = $SubscriptionId; SkipManagementGroups = [bool]$SkipManagementGroups; SkipEligible = [bool]$SkipEligible; SkipPrincipalResolution = [bool]$SkipPrincipalResolution }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
