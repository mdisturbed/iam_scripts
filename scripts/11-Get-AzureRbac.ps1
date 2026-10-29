<#
.SYNOPSIS
    Read-only discovery of Azure RBAC role assignments across management groups and subscriptions,
    resolved down to the users, service principals and managed identities that hold them.

.DESCRIPTION
    Entra directory roles (script 02) control the tenant; Azure RBAC controls the resources. This
    script reads Azure Resource Manager and exports:
      - Management groups (with parent) and subscriptions visible to the operator
      - Every role assignment (management group, subscription, resource group and resource scope),
        de-duplicated, with the role, scope level, condition, principal resolved to a name via
        Graph, and whether it is permanent, time-bound or a PIM activation
      - Eligible (PIM for Azure resources) assignments at management group and subscription scope
      - Effective users: every active and eligible assignment with group assignments expanded to
        their transitive members (users and service principals)
      - Custom role definitions (subscription and management group), flagged when their actions
        or data actions reach access control, secrets, keys, blob data or VM run command
      - Classic subscription administrators (co-administrators)
      - Key Vaults (RBAC or legacy access-policy model) and their access policies
      - Azure Lighthouse delegations (principals in other tenants), deny assignments and
        user-assigned managed identities with their role assignments
      - A summary of headline metrics

    Flags on assignments: DirectUserAssignment (to a user rather than a group), GuestPrincipal,
    OrphanedPrincipal (Graph returned 404: principal deleted), PrincipalNotVerified (Graph read
    failed for another reason - not evidence of deletion), PrivilegedAtBroadScope (privileged role
    at root / management group / subscription), ServicePrincipalPrivileged, CustomRoleRisky,
    RoleDefinitionUnresolved.

    READ-ONLY. ARM calls go through Invoke-ArmGet, which only issues Invoke-AzRestMethod -Method GET.
    Graph calls go through Invoke-GraphGet (GET only).

    Output: <OutputRoot>\11-AzureRbac\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER AdditionalPrivilegedRoles
    Extra role names (built-in or custom) to treat as privileged, on top of Owner, User Access
    Administrator, Role Based Access Control Administrator, Contributor, Key Vault Administrator /
    Secrets Officer / Data Access Administrator, Storage Blob Data Owner, Storage Account
    Contributor, Virtual Machine Administrator Login, Virtual Machine Contributor, the AKS cluster
    admin roles and Managed Identity Operator.

.PARAMETER SkipGroupExpansion
    Do not expand group assignments to members in azure-effective-users (one Graph call per group).

.PARAMETER SkipKeyVaults
    Skip the Key Vault and access-policy read.

.EXAMPLE
    .\11-Get-AzureRbac.ps1
.EXAMPLE
    .\11-Get-AzureRbac.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002'
.EXAMPLE
    .\11-Get-AzureRbac.ps1 -AdditionalPrivilegedRoles 'App1 Operator' -SkipKeyVaults
.EXAMPLE
    .\11-Get-AzureRbac.ps1 -AuthMode AppCertificate -TenantId tenant-id-redacted -ClientId <app-id> -CertificateThumbprint <thumbprint>

.NOTES
    Version : 1.1.2
    Requires: PowerShell 5.1 or 7.x, Az.Accounts module, Microsoft.Graph.Authentication module
    Azure   : Reader on the root management group (or each subscription) to see all assignments,
              Key Vaults, Lighthouse registrations, deny assignments and managed identities
    Graph   : Directory.Read.All (resolve principals and expand groups; skip with -SkipPrincipalResolution)
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string[]]$SubscriptionId = @(),                        # blank = every subscription visible
    [switch]$SkipManagementGroups,
    [switch]$SkipEligible,
    [switch]$SkipPrincipalResolution,
    [switch]$SkipGroupExpansion,
    [switch]$SkipKeyVaults,
    [string[]]$AdditionalPrivilegedRoles = @(),

    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '11-AzureRbac'
$ScriptVersion = '1.1.2'
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

$PrivilegedRoleNames = @(
    'Owner', 'User Access Administrator', 'Role Based Access Control Administrator', 'Contributor',
    'Key Vault Administrator', 'Key Vault Secrets Officer', 'Key Vault Data Access Administrator',
    'Storage Blob Data Owner', 'Storage Account Contributor',
    'Virtual Machine Administrator Login', 'Virtual Machine Contributor',
    'Azure Kubernetes Service Cluster Admin Role', 'Azure Kubernetes Service RBAC Cluster Admin',
    'Managed Identity Operator'
) + @($AdditionalPrivilegedRoles | Where-Object { $_ })
$Arm = 'https://management.azure.com'
# Operations that amount to control of access, secrets, data or compute. A role whose actions or
# data actions cover one of these (and does not exclude it with notActions) is flagged risky.
$SensitiveOperations = @(
    'Microsoft.Authorization/roleAssignments/write',
    'Microsoft.Authorization/roleDefinitions/write',
    'Microsoft.Authorization/elevateAccess/action',
    'Microsoft.Authorization/policyAssignments/write',
    'Microsoft.Compute/virtualMachines/runCommand/action',
    'Microsoft.Compute/virtualMachines/extensions/write',
    'Microsoft.Storage/storageAccounts/listKeys/action',
    'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read',
    'Microsoft.KeyVault/vaults/secrets/getSecret/action',
    'Microsoft.KeyVault/vaults/secrets/readSecret/action',
    'Microsoft.KeyVault/vaults/accessPolicies/write',
    'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action',
    'Microsoft.Web/sites/config/list/action'
)

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

function Get-RoleRiskReason {
    # Returns why a role definition is risky: wildcard grants, or actions / data actions that cover
    # a sensitive operation which notActions / notDataActions do not take away.
    param($Def)
    if (-not $Def) { return @() }
    $allow = @(); $deny = @()
    foreach ($p in @($Def.properties.permissions)) {
        $allow += @($p.actions) + @($p.dataActions)
        $deny += @($p.notActions) + @($p.notDataActions)
    }
    $allow = @($allow | Where-Object { $_ } | ForEach-Object { "$_" })
    $deny = @($deny | Where-Object { $_ } | ForEach-Object { "$_" })
    $why = [System.Collections.Generic.List[string]]::new()
    foreach ($a in $allow) {
        if ($a -eq '*') { if (-not $why.Contains('Wildcard *')) { $why.Add('Wildcard *') } }
        elseif ($a -eq '*/write') { if (-not $why.Contains('Wildcard */write')) { $why.Add('Wildcard */write') } }
        elseif ($a -match '^Microsoft\.Authorization/\*') { if (-not $why.Contains("Authorization wildcard $a")) { $why.Add("Authorization wildcard $a") } }
        elseif ($a -match '/runCommand/action$|/listKeys/action$|^Microsoft\.KeyVault/vaults/secrets/|^Microsoft\.Storage/.*/blobs/') { if (-not $why.Contains($a)) { $why.Add($a) } }
    }
    foreach ($op in $SensitiveOperations) {
        $granted = @($allow | Where-Object { $op -like $_ }).Count -gt 0
        if (-not $granted) { continue }
        $removed = @($deny | Where-Object { $op -like $_ }).Count -gt 0
        if (-not $removed -and -not $why.Contains($op)) { $why.Add($op) }
    }
    return $why.ToArray()
}

function Test-GraphNotFound {
    # True only for a real 404 / Request_ResourceNotFound - the object is deleted.
    param($ErrorRecord)
    $status = $null
    try { $status = [int]$ErrorRecord.Exception.Response.StatusCode } catch { }
    if ($status -eq 404) { return $true }
    $msg = "$($ErrorRecord.Exception.Message) $($ErrorRecord.ErrorDetails.Message)"
    return ($msg -match 'Request_ResourceNotFound|\b404\b|NotFound|does not exist')
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
        catch { Write-RunLog ("Graph unavailable ({0}); principals will show as IDs and groups will not be expanded." -f $_.Exception.Message) 'WARN'; $SkipPrincipalResolution = $true }
    }

    # ---- 1. Management groups (with parent from the hierarchy) ----
    $mgRows = @()
    if ($SkipManagementGroups) { Set-DatasetStatus -Name 'azure-management-groups' -Status 'Deferred' -Note '-SkipManagementGroups' }
    else {
        try {
            $mgs = Invoke-ArmGetAll -Uri "$Arm/providers/Microsoft.Management/managementGroups?api-version=2021-04-01"
            $parent = @{}
            $mgNote = ''
            # Whole tree from the tenant root group in one call; fall back to one GET per group.
            $treeRead = $false
            try {
                $root = Invoke-ArmGet -Uri ("$Arm/providers/Microsoft.Management/managementGroups/{0}?api-version=2020-05-01&`$expand=children&`$recurse=true" -f $az.Tenant.Id)
                $stack = [System.Collections.Generic.List[object]]::new()
                $stack.Add([pscustomobject]@{ Node = $root; Children = @($root.properties.children) })
                while ($stack.Count) {
                    $item = $stack[0]; $stack.RemoveAt(0)
                    foreach ($c in @($item.Children | Where-Object { $_ })) {
                        if ("$($c.type)" -notmatch 'managementGroups') { continue }
                        $parent["$($c.name)"] = [pscustomobject]@{ Name = "$($item.Node.name)"; DisplayName = $(if ($item.Node.properties) { "$($item.Node.properties.displayName)" } else { "$($item.Node.displayName)" }) }
                        $stack.Add([pscustomobject]@{ Node = $c; Children = @($c.children) })
                    }
                }
                $treeRead = $true
            }
            catch { Write-RunLog ("Management group tree not readable from the root ({0}); reading each group" -f $_.Exception.Message) 'WARN' }
            $parentFailures = 0
            if (-not $treeRead) {
                foreach ($m in $mgs) {
                    try {
                        $d = Invoke-ArmGet -Uri ("$Arm{0}?api-version=2021-04-01" -f $m.id)
                        if ($d.properties.details.parent) { $parent["$($m.name)"] = [pscustomobject]@{ Name = ("$($d.properties.details.parent.id)" -split '/')[-1]; DisplayName = "$($d.properties.details.parent.displayName)" } }
                    }
                    catch { $parentFailures++ }
                }
            }
            $mgRows = foreach ($m in $mgs) {
                $pp = $parent["$($m.name)"]
                [pscustomobject][ordered]@{ Name = $m.name; DisplayName = $m.properties.displayName; Id = $m.id; Parent = $(if ($pp) { $pp.Name } else { '' }); ParentDisplayName = $(if ($pp) { $pp.DisplayName } else { '' }) }
            }
            if ($parentFailures) { $mgNote = "$parentFailures group(s): parent could not be read" }
            Export-Dataset -Name 'azure-management-groups' -Rows $mgRows -Status $(if ($parentFailures) { 'Partial' } else { 'Completed' }) -Note $mgNote
        }
        catch { Set-DatasetStatus -Name 'azure-management-groups' -Status 'Blocked' -Note $_.Exception.Message }
    }

    # ---- 2. Subscriptions ----
    $subs = (Invoke-ArmGetAll -Uri "$Arm/subscriptions?api-version=2022-12-01")
    if ($SubscriptionId.Count) { $subs = @($subs | Where-Object { $SubscriptionId -contains $_.subscriptionId }) }
    Export-Dataset -Name 'azure-subscriptions' -Rows @($subs | ForEach-Object { [pscustomobject][ordered]@{ SubscriptionId = $_.subscriptionId; Name = $_.displayName; State = $_.state } })
    $subName = @{}; foreach ($s in $subs) { $subName[$s.subscriptionId] = $s.displayName }

    # ---- 3. Role definitions (built-in + custom at subscription and management group), keyed by GUID ----
    $roleDefs = @{}
    $customRoles = @{}
    $customDefinedAt = @{}
    $roleDefFailures = [System.Collections.Generic.List[string]]::new()
    $defSources = @()
    foreach ($s in $subs) { $defSources += @{ Label = "subscription $($s.subscriptionId)"; Uri = "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01" } }
    foreach ($m in $mgRows) { $defSources += @{ Label = "management group $($m.Name)"; Uri = "$Arm$($m.Id)/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&`$filter=type%20eq%20'CustomRole'" } }
    foreach ($src in $defSources) {
        try {
            foreach ($d in (Invoke-ArmGetAll -Uri $src.Uri)) {
                $guid = ($d.id -split '/')[-1]
                if (-not $roleDefs.ContainsKey($guid)) { $roleDefs[$guid] = $d }
                if ($d.properties.type -eq 'CustomRole' -and -not $customRoles.ContainsKey($guid)) { $customRoles[$guid] = $d; $customDefinedAt[$guid] = $src.Label }
            }
        }
        catch { $roleDefFailures.Add($src.Label); Write-RunLog ("Role definitions unreadable for {0}: {1}" -f $src.Label, $_.Exception.Message) 'WARN' }
    }
    $riskCache = @{}
    function Get-CachedRisk { param([string]$Guid) if (-not $riskCache.ContainsKey($Guid)) { $riskCache[$Guid] = @(Get-RoleRiskReason $roleDefs[$Guid]) }; return $riskCache[$Guid] }
    function Test-PrivilegedRole {
        param([string]$Guid, [string]$RoleName)
        if ($PrivilegedRoleNames -contains $RoleName) { return $true }
        if ($customRoles.ContainsKey($Guid) -and @(Get-CachedRisk $Guid).Count) { return $true }
        return $false
    }
    function Get-RoleName { param([string]$Guid) if ($roleDefs[$Guid]) { return $roleDefs[$Guid].properties.roleName } return $Guid }

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

    # Active schedule instances separate permanent from time-bound / PIM-activated assignments.
    $scheduleByKey = @{}
    $scheduleUnreadable = @{}
    $schedSources = @()
    foreach ($m in $mgRows) { $schedSources += @{ Key = "$($m.Id)"; Uri = "$Arm$($m.Id)/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01&`$filter=atScope()" } }
    foreach ($s in $subs) { $schedSources += @{ Key = "/subscriptions/$($s.subscriptionId)"; Uri = "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01" } }
    foreach ($src in $schedSources) {
        try {
            foreach ($si in (Invoke-ArmGetAll -Uri $src.Uri)) {
                $sp = $si.properties
                $k = ('{0}|{1}|{2}' -f $sp.principalId, (("$($sp.roleDefinitionId)" -split '/')[-1]), "$($sp.scope)").ToLowerInvariant()
                $scheduleByKey[$k] = $sp
            }
        }
        catch { $scheduleUnreadable[$src.Key.ToLowerInvariant()] = $true; Write-RunLog ("Assignment schedules unreadable for {0}: {1}" -f $src.Key, $_.Exception.Message) 'WARN' }
    }
    function Get-AssignmentType {
        param([string]$PrincipalId, [string]$RoleGuid, [string]$Scope)
        $k = ('{0}|{1}|{2}' -f $PrincipalId, $RoleGuid, $Scope).ToLowerInvariant()
        if ($scheduleByKey.ContainsKey($k)) {
            $sp = $scheduleByKey[$k]
            if ("$($sp.assignmentType)" -eq 'Activated') { return 'Activated' }
            if ($sp.endDateTime) { return 'TimeBound' }
            return 'Permanent'
        }
        $owner = $(if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] } else { $Scope })
        if ($scheduleUnreadable.ContainsKey($owner.ToLowerInvariant())) { return 'Unknown' }
        return 'Permanent'
    }

    $principalCache = @{}
    $script:PrincipalNotVerified = 0
    function Get-Principal {
        # Exists: $true (found), $false (Graph 404 - deleted), 'Unknown' (any other failure), '' (not checked)
        param([string]$Id)
        if (-not $Id) { return [pscustomobject]@{ Name = ''; Upn = ''; UserType = ''; Exists = ''; ODataType = '' } }
        if ($principalCache.ContainsKey($Id)) { return $principalCache[$Id] }
        $info = [pscustomobject]@{ Name = $Id; Upn = ''; UserType = ''; Exists = ''; ODataType = '' }
        if (-not $SkipPrincipalResolution) {
            try {
                $o = Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/directoryObjects/{0}" -f $Id)
                $info = [pscustomobject]@{
                    Name      = $o.displayName
                    Upn       = $(if ($o.PSObject.Properties.Name -contains 'userPrincipalName') { $o.userPrincipalName } else { '' })
                    UserType  = $(if ($o.PSObject.Properties.Name -contains 'userType') { $o.userType } else { '' })
                    Exists    = $true
                    ODataType = ("$($o.'@odata.type')" -replace '#microsoft.graph.', '')
                }
            }
            catch {
                if (Test-GraphNotFound $_) { $info = [pscustomobject]@{ Name = $Id; Upn = ''; UserType = ''; Exists = $false; ODataType = '' } }
                else {
                    $script:PrincipalNotVerified++
                    Write-RunLog ("Principal {0} could not be verified: {1}" -f $Id, $_.Exception.Message) 'WARN'
                    $info = [pscustomobject]@{ Name = $Id; Upn = ''; UserType = ''; Exists = 'Unknown'; ODataType = '' }
                }
            }
        }
        $principalCache[$Id] = $info
        return $info
    }

    $assignRows = foreach ($a in $assignments.Values) {
        $pr = $a.properties
        $guid = ($pr.roleDefinitionId -split '/')[-1]
        $roleName = Get-RoleName $guid
        $isCustom = [bool]$customRoles.ContainsKey($guid)
        $level = Get-ScopeLevel $pr.scope
        $p = Get-Principal $pr.principalId
        $subId = $(if ($pr.scope -match '^/subscriptions/([^/]+)') { $Matches[1] } else { '' })
        $privileged = Test-PrivilegedRole -Guid $guid -RoleName $roleName
        $risky = $isCustom -and @(Get-CachedRisk $guid).Count -gt 0
        $flags = @()
        if ($pr.principalType -eq 'User') { $flags += 'DirectUserAssignment' }
        if ($p.UserType -eq 'Guest') { $flags += 'GuestPrincipal' }
        if ($p.Exists -eq $false) { $flags += 'OrphanedPrincipal' }
        if ("$($p.Exists)" -eq 'Unknown') { $flags += 'PrincipalNotVerified' }
        if ($privileged -and $level -in @('Root', 'ManagementGroup', 'Subscription')) { $flags += 'PrivilegedAtBroadScope' }
        if ($privileged -and $pr.principalType -eq 'ServicePrincipal') { $flags += 'ServicePrincipalPrivileged' }
        if ($risky) { $flags += 'CustomRoleRisky' }
        if (-not $roleDefs[$guid]) { $flags += 'RoleDefinitionUnresolved' }
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
            Condition        = "$($pr.condition)"
            AssignmentType   = Get-AssignmentType -PrincipalId $pr.principalId -RoleGuid $guid -Scope $pr.scope
        }
    }
    $assignRows = @($assignRows | Sort-Object ScopeLevel, Scope, RoleName)
    $raNotes = @()
    if ($blockedSources) { $raNotes += "$blockedSources scope(s) could not be read; see run.log" }
    if ($roleDefFailures.Count) { $raNotes += "role definitions unreadable for $($roleDefFailures.Count) scope(s): some RoleName values are GUIDs and IsPrivilegedRole may be understated" }
    if ($scheduleUnreadable.Count) { $raNotes += "assignment schedules unreadable for $($scheduleUnreadable.Count) scope(s): AssignmentType Unknown there" }
    if ($script:PrincipalNotVerified) { $raNotes += "$($script:PrincipalNotVerified) principal(s) could not be verified in Graph (PrincipalNotVerified, not orphaned)" }
    Export-Dataset -Name 'azure-role-assignments' -Rows $assignRows -Status $(if ($blockedSources -or $roleDefFailures.Count) { 'Partial' } else { 'Completed' }) -Note (($raNotes) -join '; ')

    # ---- 5. Eligible (PIM) at management group and subscription scope ----
    $eligRows = [System.Collections.Generic.List[object]]::new()
    if ($SkipEligible) { Set-DatasetStatus -Name 'azure-eligible-assignments' -Status 'Deferred' -Note '-SkipEligible' }
    else {
        $eligFailed = 0
        $eligSources = @()
        foreach ($m in $mgRows) { $eligSources += @{ Label = "MG $($m.Name)"; Sub = ''; Uri = "$Arm$($m.Id)/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&`$filter=atScope()" } }
        foreach ($s in $subs) { $eligSources += @{ Label = "Sub $($s.subscriptionId)"; Sub = $s.displayName; Uri = "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01" } }
        $seenElig = @{}
        foreach ($src in $eligSources) {
            try {
                foreach ($e in (Invoke-ArmGetAll -Uri $src.Uri)) {
                    $ep = $e.properties
                    $guid = ($ep.roleDefinitionId -split '/')[-1]
                    $k = ('{0}|{1}|{2}' -f $ep.principalId, $guid, $ep.scope).ToLowerInvariant()
                    if ($seenElig.ContainsKey($k)) { continue }
                    $seenElig[$k] = $true
                    $p = Get-Principal $ep.principalId
                    $eSub = $(if ("$($ep.scope)" -match '^/subscriptions/([^/]+)') { $subName[$Matches[1]] } else { $src.Sub })
                    $eligRows.Add([pscustomobject][ordered]@{
                        Scope         = $ep.scope
                        ScopeLevel    = Get-ScopeLevel $ep.scope
                        Subscription  = $eSub
                        RoleName      = Get-RoleName $guid
                        PrincipalType = $ep.principalType
                        PrincipalName = $p.Name
                        PrincipalUPN  = $p.Upn
                        StartUtc      = $ep.startDateTime
                        EndUtc        = $ep.endDateTime
                        MemberType    = $ep.memberType
                        PrincipalId   = $ep.principalId
                        RoleGuid      = $guid
                    })
                }
            }
            catch { $eligFailed++; Write-RunLog ("Eligible assignments unreadable for {0}: {1}" -f $src.Label, $_.Exception.Message) 'WARN' }
        }
        if ($eligFailed -eq $eligSources.Count -and $eligSources.Count -gt 0) { Set-DatasetStatus -Name 'azure-eligible-assignments' -Status 'EvidenceUnavailable' -Note 'PIM for Azure resources not readable at any scope (licence or permission)' }
        else { Export-Dataset -Name 'azure-eligible-assignments' -Rows $eligRows -Status $(if ($eligFailed) { 'Partial' } else { 'Completed' }) -Note $(if ($eligFailed) { "$eligFailed scope(s) unreadable; see run.log" } else { '' }) }
    }

    # ---- 6. Effective users: direct and eligible assignments, groups expanded to members ----
    $effRows = [System.Collections.Generic.List[object]]::new()
    $groupCache = @{}
    $groupFailures = [System.Collections.Generic.List[string]]::new()
    function Get-GroupMemberPrincipal {
        param([string]$GroupId)
        if ($groupCache.ContainsKey($GroupId)) { return $groupCache[$GroupId] }
        $members = @()
        try {
            $raw = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers?`$select=id,displayName,userPrincipalName&`$top=999" -f $GroupId) -Label "transitiveMembers $GroupId"
            $members = @($raw | Where-Object { "$($_.'@odata.type')" -match 'user|servicePrincipal' } | ForEach-Object {
                [pscustomobject]@{ Id = "$($_.id)"; DisplayName = "$($_.displayName)"; Upn = $(if ($_.PSObject.Properties.Name -contains 'userPrincipalName') { "$($_.userPrincipalName)" } else { '' }); Type = $(if ("$($_.'@odata.type')" -match 'servicePrincipal') { 'ServicePrincipal' } else { 'User' }) }
            })
        }
        catch { $groupFailures.Add($GroupId); Write-RunLog ("Group {0} could not be expanded: {1}" -f $GroupId, $_.Exception.Message) 'WARN'; $members = $null }
        $groupCache[$GroupId] = $members
        return $members
    }
    function Add-EffectiveRow {
        param($SubscriptionName, $Scope, $RoleGuid, $PrincipalId, $PrincipalType, $State, $AssignmentType)
        $roleName = Get-RoleName $RoleGuid
        $priv = Test-PrivilegedRole -Guid $RoleGuid -RoleName $roleName
        if ("$PrincipalType" -eq 'Group') {
            if ($SkipGroupExpansion) { return }
            $g = Get-Principal $PrincipalId
            $members = Get-GroupMemberPrincipal $PrincipalId
            if ($null -eq $members) { return }
            foreach ($m in $members) {
                $effRows.Add([pscustomobject][ordered]@{ SubscriptionName = $SubscriptionName; Scope = $Scope; RoleName = $roleName; IsPrivilegedRole = $priv; PrincipalId = $m.Id; Upn = $m.Upn; DisplayName = $m.DisplayName; AssignmentState = $State; Via = 'Group member'; ViaGroup = $g.Name; PrincipalType = $m.Type; AssignmentType = $AssignmentType })
            }
            return
        }
        $p = Get-Principal $PrincipalId
        $ptype = $(if ($PrincipalType) { "$PrincipalType" } else { $p.ODataType })
        $effRows.Add([pscustomobject][ordered]@{ SubscriptionName = $SubscriptionName; Scope = $Scope; RoleName = $roleName; IsPrivilegedRole = $priv; PrincipalId = $PrincipalId; Upn = $(if ($ptype -eq 'User') { $p.Upn } else { '' }); DisplayName = $p.Name; AssignmentState = $State; Via = 'Direct'; ViaGroup = ''; PrincipalType = $ptype; AssignmentType = $AssignmentType })
    }
    if ($SkipPrincipalResolution) { Set-DatasetStatus -Name 'azure-effective-users' -Status 'Deferred' -Note 'Needs Graph (principal resolution was skipped or unavailable)' }
    else {
        foreach ($r in $assignRows) {
            $guid = (("$($assignments[$r.AssignmentId].properties.roleDefinitionId)") -split '/')[-1]
            Add-EffectiveRow -SubscriptionName $r.Subscription -Scope $r.Scope -RoleGuid $guid -PrincipalId $r.PrincipalId -PrincipalType $r.PrincipalType -State 'Active' -AssignmentType $r.AssignmentType
        }
        foreach ($e in $eligRows) { Add-EffectiveRow -SubscriptionName $e.Subscription -Scope $e.Scope -RoleGuid $e.RoleGuid -PrincipalId $e.PrincipalId -PrincipalType $e.PrincipalType -State 'Eligible' -AssignmentType 'Eligible' }
        $effNotes = @()
        if ($SkipGroupExpansion) { $effNotes += '-SkipGroupExpansion: group assignments not expanded (direct principals only)' }
        if ($groupFailures.Count) { $effNotes += ("{0} group(s) could not be expanded: {1}" -f $groupFailures.Count, (($groupFailures | Select-Object -First 10) -join ', ')) }
        if ($blockedSources) { $effNotes += "$blockedSources assignment scope(s) unreadable" }
        Export-Dataset -Name 'azure-effective-users' -Rows $effRows -Status $(if ($groupFailures.Count -or $blockedSources) { 'Partial' } else { 'Completed' }) -Note (($effNotes) -join '; ')
    }

    # ---- 7. Custom roles ----
    $customRows = foreach ($g in $customRoles.Keys) {
        $d = $customRoles[$g]
        $actions = @(); $notActions = @(); $dataActions = @(); $notDataActions = @()
        foreach ($p in @($d.properties.permissions)) { $actions += @($p.actions); $notActions += @($p.notActions); $dataActions += @($p.dataActions); $notDataActions += @($p.notDataActions) }
        $why = @(Get-CachedRisk $g)
        [pscustomobject][ordered]@{
            RoleName         = $d.properties.roleName
            Description      = $d.properties.description
            AssignableScopes = Join-Values $d.properties.assignableScopes
            ActionCount      = @($actions | Where-Object { $_ }).Count
            DataActionCount  = @($dataActions | Where-Object { $_ }).Count
            Actions          = Join-Values $actions
            NotActions       = Join-Values $notActions
            Risky            = [bool]$why.Count
            AssignmentCount  = @($assignRows | Where-Object { $_.AssignmentId -and ($assignments[$_.AssignmentId].properties.roleDefinitionId -split '/')[-1] -eq $g }).Count
            DataActions      = Join-Values $dataActions
            NotDataActions   = Join-Values $notDataActions
            RiskReasons      = Join-Values $why
            DefinedAt        = $customDefinedAt[$g]
        }
    }
    Export-Dataset -Name 'azure-custom-roles' -Rows $customRows -Status $(if ($roleDefFailures.Count) { 'Partial' } else { 'Completed' }) -Note ('Risky = actions or data actions (not removed by notActions) that cover *, */write, Microsoft.Authorization writes, runCommand, listKeys, Key Vault secrets or blob data' + $(if ($roleDefFailures.Count) { "; role definitions unreadable for: $(($roleDefFailures | Select-Object -First 10) -join ', ')" } else { '' }))

    # ---- 8. Classic administrators ----
    $classicRows = [System.Collections.Generic.List[object]]::new()
    $classicFailed = 0
    foreach ($s in $subs) {
        try {
            foreach ($c in (Invoke-ArmGetAll -Uri "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-07-01")) {
                $classicRows.Add([pscustomobject][ordered]@{ Subscription = $s.displayName; EmailAddress = $c.properties.emailAddress; Role = $c.properties.role })
            }
        }
        catch { $classicFailed++; Write-RunLog ("Classic administrators unreadable for {0}: {1}" -f $s.subscriptionId, $_.Exception.Message) 'WARN' }
    }
    Export-Dataset -Name 'azure-classic-administrators' -Rows $classicRows -Status $(if ($classicFailed) { 'Partial' } else { 'Completed' }) -Note ('Classic administrators are retired by Microsoft; any remaining should be converted to RBAC' + $(if ($classicFailed) { "; $classicFailed subscription(s) unreadable" } else { '' }))

    # ---- 9. Key Vaults: permission model and access policies ----
    $kvRows = [System.Collections.Generic.List[object]]::new()
    $kvPolRows = [System.Collections.Generic.List[object]]::new()
    if ($SkipKeyVaults) { foreach ($n in 'keyvaults', 'keyvault-access-policies') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note '-SkipKeyVaults' } }
    else {
        $kvFailed = 0
        foreach ($s in $subs) {
            try {
                foreach ($v in (Invoke-ArmGetAll -Uri "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.KeyVault/vaults?api-version=2024-11-01")) {
                    $vp = $v.properties
                    $rbac = ("$($vp.enableRbacAuthorization)" -eq 'True')
                    $pols = @($vp.accessPolicies | Where-Object { $_ })
                    $rg = $(if ("$($v.id)" -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { '' })
                    $vf = @()
                    if (-not $rbac) { $vf += 'LegacyAccessPolicyModel' }
                    if ("$($vp.publicNetworkAccess)" -ne 'Disabled' -and -not ($vp.networkAcls -and "$($vp.networkAcls.defaultAction)" -eq 'Deny')) { $vf += 'PublicNetworkOpen' }
                    $kvRows.Add([pscustomobject][ordered]@{ Subscription = $s.displayName; VaultName = $v.name; ResourceGroup = $rg; Location = $v.location; PermissionModel = $(if ($rbac) { 'RBAC' } else { 'AccessPolicy' }); AccessPolicyCount = $pols.Count; EnableSoftDelete = $vp.enableSoftDelete; EnablePurgeProtection = $vp.enablePurgeProtection; Flags = Join-Values $vf })
                    foreach ($ap in $pols) {
                        $p = Get-Principal "$($ap.objectId)"
                        $secrets = @($ap.permissions.secrets | ForEach-Object { "$_".ToLowerInvariant() })
                        $keys = @($ap.permissions.keys | ForEach-Object { "$_".ToLowerInvariant() })
                        $certs = @($ap.permissions.certificates | ForEach-Object { "$_".ToLowerInvariant() })
                        $pf = @()
                        if ($secrets -contains 'get' -or $secrets -contains 'list' -or $secrets -contains 'all') { $pf += 'CanReadSecrets' }
                        if ($keys -contains 'all' -or $secrets -contains 'all' -or $certs -contains 'all') { $pf += 'AllPermissions' }
                        if ($rbac) { $pf += 'IgnoredRbacModel' }
                        if ($p.Exists -eq $false) { $pf += 'OrphanedPrincipal' }
                        if ("$($p.Exists)" -eq 'Unknown') { $pf += 'PrincipalNotVerified' }
                        $kvPolRows.Add([pscustomobject][ordered]@{ Subscription = $s.displayName; VaultName = $v.name; PermissionModel = $(if ($rbac) { 'RBAC' } else { 'AccessPolicy' }); PrincipalId = "$($ap.objectId)"; PrincipalName = $p.Name; PrincipalUPN = $p.Upn; PrincipalType = $p.ODataType; ApplicationId = "$($ap.applicationId)"; KeyPermissions = Join-Values $keys; SecretPermissions = Join-Values $secrets; CertificatePermissions = Join-Values $certs; Flags = Join-Values $pf })
                    }
                }
            }
            catch { $kvFailed++; Write-RunLog ("Key Vaults unreadable for {0}: {1}" -f $s.subscriptionId, $_.Exception.Message) 'WARN' }
        }
        $kvStatus = $(if ($kvFailed) { 'Partial' } else { 'Completed' })
        $kvNote = $(if ($kvFailed) { "$kvFailed subscription(s) unreadable; " } else { '' })
        Export-Dataset -Name 'keyvaults' -Rows $kvRows -Status $kvStatus -Note ($kvNote + 'LegacyAccessPolicyModel = data access is controlled by access policies, not Azure RBAC')
        Export-Dataset -Name 'keyvault-access-policies' -Rows $kvPolRows -Status $kvStatus -Note ($kvNote + 'IgnoredRbacModel = vault uses RBAC so this policy has no effect')
    }

    # ---- 10. Lighthouse (delegated resource management), deny assignments, managed identities ----
    $lhRows = [System.Collections.Generic.List[object]]::new(); $lhFailed = 0
    $denyRows = [System.Collections.Generic.List[object]]::new(); $denyFailed = 0
    $miRows = [System.Collections.Generic.List[object]]::new(); $miFailed = 0
    foreach ($s in $subs) {
        try {
            foreach ($ra in (Invoke-ArmGetAll -Uri "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.ManagedServices/registrationAssignments?`$expandRegistrationDefinition=true&api-version=2022-10-01")) {
                $def = $ra.properties.registrationDefinition.properties
                if (-not $def) { continue }
                $auths = @(@($def.authorizations | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Kind = 'Permanent'; A = $_ } }) + @($def.eligibleAuthorizations | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Kind = 'Eligible'; A = $_ } }))
                foreach ($x in $auths) {
                    $guid = ("$($x.A.roleDefinitionId)" -split '/')[-1]
                    $rn = Get-RoleName $guid
                    $lhRows.Add([pscustomobject][ordered]@{ Subscription = $s.displayName; Offer = "$($def.registrationDefinitionName)"; ManagedByTenantId = "$($def.managedByTenantId)"; ManagedByTenantName = "$($def.managedByTenantName)"; AuthorizationType = $x.Kind; PrincipalId = "$($x.A.principalId)"; PrincipalDisplayName = "$($x.A.principalIdDisplayName)"; RoleName = $rn; IsPrivilegedRole = ($PrivilegedRoleNames -contains $rn); DelegatedRoleIds = Join-Values $x.A.delegatedRoleDefinitionIds })
                }
            }
        }
        catch { $lhFailed++; Write-RunLog ("Lighthouse delegations unreadable for {0}: {1}" -f $s.subscriptionId, $_.Exception.Message) 'WARN' }
        try {
            foreach ($da in (Invoke-ArmGetAll -Uri "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01")) {
                $dp = $da.properties
                $acts = @(); $nacts = @(); $dacts = @()
                foreach ($pm in @($dp.permissions)) { $acts += @($pm.actions); $nacts += @($pm.notActions); $dacts += @($pm.dataActions) }
                $denyRows.Add([pscustomobject][ordered]@{ Subscription = $s.displayName; Name = "$($dp.denyAssignmentName)"; Scope = "$($dp.scope)"; IsSystemProtected = $dp.isSystemProtected; DoNotApplyToChildScopes = $dp.doNotApplyToChildScopes; Principals = Join-Values (@($dp.principals) | ForEach-Object { '{0}:{1}' -f $_.type, $_.id }); ExcludePrincipals = @($dp.excludePrincipals | Where-Object { $_ }).Count; Actions = Join-Values $acts; NotActions = Join-Values $nacts; DataActions = Join-Values $dacts })
            }
        }
        catch { $denyFailed++; Write-RunLog ("Deny assignments unreadable for {0}: {1}" -f $s.subscriptionId, $_.Exception.Message) 'WARN' }
        try {
            foreach ($mi in (Invoke-ArmGetAll -Uri "$Arm/subscriptions/$($s.subscriptionId)/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2024-11-30")) {
                $miPid = "$($mi.properties.principalId)"
                $mine = @($assignRows | Where-Object { $_.PrincipalId -eq $miPid })
                $privMine = @($mine | Where-Object IsPrivilegedRole)
                $mf = @()
                if ($privMine.Count) { $mf += 'PrivilegedRole' }
                if (@($privMine | Where-Object { $_.ScopeLevel -in @('Root', 'ManagementGroup', 'Subscription') }).Count) { $mf += 'PrivilegedAtBroadScope' }
                if (-not $mine.Count) { $mf += 'NoRoleAssignments' }
                $miRows.Add([pscustomobject][ordered]@{ Subscription = $s.displayName; Name = $mi.name; ResourceGroup = $(if ("$($mi.id)" -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { '' }); Location = $mi.location; PrincipalId = $miPid; ClientId = "$($mi.properties.clientId)"; RoleAssignments = Join-Values ($mine | ForEach-Object { '{0} @ {1}' -f $_.RoleName, $_.Scope }); PrivilegedAssignments = $privMine.Count; Flags = Join-Values $mf })
            }
        }
        catch { $miFailed++; Write-RunLog ("Managed identities unreadable for {0}: {1}" -f $s.subscriptionId, $_.Exception.Message) 'WARN' }
    }
    Export-Dataset -Name 'lighthouse-delegations' -Rows $lhRows -Status $(if ($lhFailed) { 'Partial' } else { 'Completed' }) -Note ('Principals in ANOTHER tenant that hold roles on these subscriptions (Azure Lighthouse); subscription-level registrations' + $(if ($lhFailed) { "; $lhFailed subscription(s) unreadable" } else { '' }))
    Export-Dataset -Name 'azure-deny-assignments' -Rows $denyRows -Status $(if ($denyFailed) { 'Partial' } else { 'Completed' }) -Note $(if ($denyFailed) { "$denyFailed subscription(s) unreadable" } else { 'Deny assignments override role assignments; most are created by Azure (managed apps, blueprints, deployment stacks)' })
    Export-Dataset -Name 'managed-identities' -Rows $miRows -Status $(if ($miFailed) { 'Partial' } else { 'Completed' }) -Note ('User-assigned managed identities joined to their role assignments; system-assigned identities appear in azure-role-assignments as ServicePrincipal' + $(if ($miFailed) { "; $miFailed subscription(s) unreadable" } else { '' }))

    # ---- No visible subscriptions: Azure returns an empty list (not 403) when the run account has no Azure RBAC role ----
    $noSubs = (@($subs).Count -eq 0)
    $noSubsNote = 'No subscriptions visible to the run account. Azure returns an empty list, not an error, when the account holds no Azure RBAC role, so zero rows here are not evidence of "none". Grant Reader at the root management group (or on each in-scope subscription) and rerun.'
    if ($noSubs) {
        Write-RunLog $noSubsNote 'WARN'
        foreach ($d in $script:Datasets) {
            if ($d.Dataset -in @('azure-management-groups', 'summary')) { continue }
            if ($d.Status -in @('Completed', 'Partial') -and [int]$d.Rows -eq 0) { $d.Status = 'Blocked'; $d.Note = $noSubsNote }
        }
    }

    # ---- 11. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric -Metric 'Management groups visible' @($mgRows).Count
    Add-Metric -Metric 'Subscriptions in scope' $subs.Count
    Add-Metric -Metric 'Role assignments' $assignRows.Count
    Add-Metric -Metric 'Scopes that could not be read' $blockedSources $(if ($blockedSources) { 'Assignments in these scopes are missing - see run.log; usually needs Reader there' } else { '' })
    Add-Metric -Metric 'Role definition scopes that could not be read' $roleDefFailures.Count $(if ($roleDefFailures.Count) { 'Some roles show as GUIDs and may not be classed as privileged' } else { '' })
    foreach ($lvl in 'Root', 'ManagementGroup', 'Subscription', 'ResourceGroup', 'Resource') { Add-Metric -Metric "Assignments at $lvl scope" @($assignRows | Where-Object ScopeLevel -eq $lvl).Count }
    Add-Metric -Metric 'Assignments made directly to users' @($assignRows | Where-Object { $_.Flags -match 'DirectUserAssignment' }).Count 'Best practice: assign to groups'
    Add-Metric -Metric 'Privileged roles at broad scope' @($assignRows | Where-Object { $_.Flags -match 'PrivilegedAtBroadScope' }).Count 'Privileged role (Owner, UAA, RBAC Admin, Contributor, Key Vault / storage data / VM admin roles or risky custom) at root, MG or subscription'
    Add-Metric -Metric 'Permanent privileged assignments' @($assignRows | Where-Object { $_.IsPrivilegedRole -and $_.AssignmentType -eq 'Permanent' }).Count 'Candidates for PIM eligibility'
    Add-Metric -Metric 'Owner assignments' @($assignRows | Where-Object RoleName -eq 'Owner').Count
    Add-Metric -Metric 'User Access Administrator assignments' @($assignRows | Where-Object RoleName -eq 'User Access Administrator').Count
    Add-Metric -Metric 'Assignments to orphaned principals' @($assignRows | Where-Object { $_.Flags -match 'OrphanedPrincipal' }).Count 'Graph returned 404 (principal deleted) - clean-up candidates'
    Add-Metric -Metric 'Assignments whose principal could not be verified' @($assignRows | Where-Object { $_.Flags -match 'PrincipalNotVerified' }).Count 'Graph read failed for a reason other than 404 - NOT evidence of deletion; do not clean up on this basis'
    Add-Metric -Metric 'Assignments to guests' @($assignRows | Where-Object { $_.Flags -match 'GuestPrincipal' }).Count
    Add-Metric -Metric 'Privileged assignments to service principals' @($assignRows | Where-Object { $_.Flags -match 'ServicePrincipalPrivileged' }).Count
    if (-not $SkipPrincipalResolution) {
        $effUsers = @($effRows | Where-Object { $_.PrincipalType -eq 'User' })
        Add-Metric -Metric 'Distinct users with an Azure role (active or eligible)' @($effUsers | Select-Object -ExpandProperty PrincipalId -Unique).Count 'Groups expanded to members'
        Add-Metric -Metric 'Distinct users with a privileged Azure role' @($effUsers | Where-Object IsPrivilegedRole | Select-Object -ExpandProperty PrincipalId -Unique).Count
        Add-Metric -Metric 'Users holding a privileged role through a group' @($effUsers | Where-Object { $_.IsPrivilegedRole -and $_.Via -eq 'Group member' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
        Add-Metric -Metric 'Groups that could not be expanded' $groupFailures.Count
    }
    Add-Metric -Metric 'Custom roles' @($customRows).Count
    Add-Metric -Metric 'Custom roles flagged risky' @($customRows | Where-Object Risky).Count
    Add-Metric -Metric 'Classic administrators' $classicRows.Count
    if (-not $SkipKeyVaults) {
        Add-Metric -Metric 'Key Vaults' $kvRows.Count
        Add-Metric -Metric 'Key Vaults using access policies (legacy model)' @($kvRows | Where-Object PermissionModel -eq 'AccessPolicy').Count 'Prefer Azure RBAC for data access'
        Add-Metric -Metric 'Access policies that can read secrets' @($kvPolRows | Where-Object { $_.Flags -match 'CanReadSecrets' -and $_.Flags -notmatch 'IgnoredRbacModel' }).Count
    }
    Add-Metric -Metric 'Lighthouse authorizations (other tenants)' $lhRows.Count
    Add-Metric -Metric 'Lighthouse authorizations with privileged roles' @($lhRows | Where-Object IsPrivilegedRole).Count
    Add-Metric -Metric 'Deny assignments' $denyRows.Count
    Add-Metric -Metric 'User-assigned managed identities' $miRows.Count
    Add-Metric -Metric 'Managed identities with privileged roles' @($miRows | Where-Object { $_.Flags -match 'PrivilegedRole' }).Count
    if ($noSubs) {
        foreach ($m in $summary) {
            if ($m.Metric -in @('Management groups visible', 'Subscriptions in scope')) { if ($m.Metric -eq 'Subscriptions in scope') { $m.Note = $noSubsNote }; continue }
            $m.Value = ''; $m.Note = 'Not assessed: no subscriptions visible to the run account'
        }
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ SubscriptionId = $SubscriptionId; SkipManagementGroups = [bool]$SkipManagementGroups; SkipEligible = [bool]$SkipEligible; SkipPrincipalResolution = [bool]$SkipPrincipalResolution; SkipGroupExpansion = [bool]$SkipGroupExpansion; SkipKeyVaults = [bool]$SkipKeyVaults; AdditionalPrivilegedRoles = $AdditionalPrivilegedRoles }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
