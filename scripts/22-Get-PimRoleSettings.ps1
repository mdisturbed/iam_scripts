<#
.SYNOPSIS
    Read-only export of Privileged Identity Management (PIM) role settings for Entra directory
    roles: what it actually takes to activate each role, and whether permanent assignment is
    allowed.

.DESCRIPTION
    PIM only reduces risk if activation is hard enough. For every directory role this exports
    the role management policy rules:

      - Activation: maximum duration, MFA required, justification, ticket information,
        approval required (and approvers), authentication context (Conditional Access) required
      - Eligible assignment: whether it can be permanent, maximum duration if not
      - Active assignment: whether it can be permanent, MFA / justification on admin
        assignment
    and flags Tier 0 roles that can be activated without approval, without MFA or an
    authentication context, for longer than -MaxActivationHours, or assigned permanently.
    Role assignment counts (active / eligible) are added so settings can be prioritised.

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\22-PimRoleSettings\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\22-Get-PimRoleSettings.ps1
.EXAMPLE
    .\22-Get-PimRoleSettings.ps1 -OnlyAssignedRoles -MaxActivationHours 4

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : RoleManagementPolicy.Read.Directory, RoleManagement.Read.Directory
    Licence : Entra ID P2 / ID Governance (PIM)
    Scope   : Directory roles only. PIM for Groups and Azure resource roles are configured per
              group / scope and are not covered here.
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
    [switch]$OnlyAssignedRoles
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '22-PimRoleSettings'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('RoleManagementPolicy.Read.Directory', 'RoleManagement.Read.Directory')

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

$Tier0RoleTemplates = @('62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', '194ae4cb-b126-40b2-bd5b-6091b380977d', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', '158c047a-c907-4556-b7ef-446551a6b5f7', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2', 'c4e39bd9-1100-46d3-8c65-fb160da0071f', 'fe930be7-5e62-47db-91af-98c3a49a38b1', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '3a2c62db-5318-420d-8d74-23affee5d9d5', '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e')

function ConvertFrom-IsoDuration {
    # 'PT8H' / 'P1D' / 'PT30M' / 'P365D' -> hours (double), '' if empty
    param([string]$Value)
    if (-not $Value) { return '' }
    try { return [math]::Round([System.Xml.XmlConvert]::ToTimeSpan($Value).TotalHours, 2) } catch { return $Value }
}

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # Role names and assignment counts
    $roles = @{}
    foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName,isBuiltIn' -Label 'roleDefinitions')) { $roles[$r.id] = $r; if ($r.templateId) { $roles[$r.templateId] = $r } }
    $activeCount = @{}; $eligibleCount = @{}; $countsAvailable = $true
    try {
        foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$select=roleDefinitionId' -Label 'activeInstances')) { $k = $a.roleDefinitionId; $activeCount[$k] = 1 + $(if ($activeCount.ContainsKey($k)) { $activeCount[$k] } else { 0 }) }
        foreach ($a in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$select=roleDefinitionId' -Label 'eligibleInstances')) { $k = $a.roleDefinitionId; $eligibleCount[$k] = 1 + $(if ($eligibleCount.ContainsKey($k)) { $eligibleCount[$k] } else { 0 }) }
    }
    catch { $countsAvailable = $false; Write-RunLog ("Assignment counts unavailable ({0})" -f $_.Exception.Message) 'WARN' }

    # Policies
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
        $elg = $(if ($eligibleCount.ContainsKey($rid)) { $eligibleCount[$rid] } else { 0 })
        if ($OnlyAssignedRoles -and ($act + $elg) -eq 0) { continue }
        $rules = @{}
        foreach ($rule in @($pa.policy.rules)) { $rules[$rule.id] = $rule }

        $actExp = $rules['Expiration_EndUser_Assignment']
        $actEnable = $rules['Enablement_EndUser_Assignment']
        $approval = $rules['Approval_EndUser_Assignment']
        $authCtx = $rules['AuthenticationContext_EndUser_Assignment']
        $eligExp = $rules['Expiration_Admin_Eligibility']
        $activeExp = $rules['Expiration_Admin_Assignment']
        $adminEnable = $rules['Enablement_Admin_Assignment']

        $enabled = @(); if ($actEnable) { $enabled = @($actEnable.enabledRules) }
        $adminEnabled = @(); if ($adminEnable) { $adminEnabled = @($adminEnable.enabledRules) }
        $approvalRequired = [bool]($approval -and $approval.setting -and $approval.setting.isApprovalRequired)
        $approvers = @()
        if ($approvalRequired) {
            foreach ($stage in @($approval.setting.approvalStages)) {
                foreach ($ap in @($stage.primaryApprovers)) { $approvers += $(if ($ap.description) { $ap.description } elseif ($ap.userId) { "user:$($ap.userId)" } elseif ($ap.groupId) { "group:$($ap.groupId)" } else { ("$($ap.'@odata.type')" -replace '#microsoft.graph.', '') }) }
            }
        }
        $authCtxOn = [bool]($authCtx -and $authCtx.isEnabled)
        $maxActHours = $(if ($actExp) { ConvertFrom-IsoDuration $actExp.maximumDuration } else { '' })
        $eligPermanent = [bool]($eligExp -and -not $eligExp.isExpirationRequired)
        $activePermanent = [bool]($activeExp -and -not $activeExp.isExpirationRequired)
        $isTier0 = $Tier0RoleTemplates -contains $template

        $flags = @()
        if ($isTier0) {
            if (-not $approvalRequired) { $flags += 'Tier0NoApproval' }
            if (-not ($enabled -contains 'MultiFactorAuthentication') -and -not $authCtxOn) { $flags += 'Tier0NoMfaOrAuthContext' }
            if ($maxActHours -ne '' -and $maxActHours -gt $MaxActivationHours) { $flags += "Tier0ActivationOver${MaxActivationHours}h" }
            if ($activePermanent) { $flags += 'Tier0PermanentActiveAllowed' }
            if ($eligPermanent) { $flags += 'Tier0PermanentEligibleAllowed' }
        }
        if (-not ($enabled -contains 'Justification')) { $flags += 'NoJustification' }
        if ($act -gt 0 -and $elg -eq 0 -and $isTier0) { $flags += 'Tier0OnlyActiveAssignments' }

        $rows.Add([pscustomobject][ordered]@{
            RoleName                     = $name
            IsTier0                      = $isTier0
            IsBuiltIn                    = $(if ($role) { $role.isBuiltIn } else { '' })
            ActiveAssignments            = $(if ($countsAvailable) { $act } else { '' })
            EligibleAssignments          = $(if ($countsAvailable) { $elg } else { '' })
            MaxActivationHours           = $maxActHours
            ActivationRequiresMfa        = ($enabled -contains 'MultiFactorAuthentication')
            ActivationRequiresJustification = ($enabled -contains 'Justification')
            ActivationRequiresTicket     = ($enabled -contains 'Ticketing')
            ActivationRequiresAuthContext = $authCtxOn
            AuthContextClaim             = $(if ($authCtxOn) { $authCtx.claimValue } else { '' })
            ApprovalRequired             = $approvalRequired
            Approvers                    = Join-Values ($approvers | Select-Object -Unique)
            PermanentEligibleAllowed     = $eligPermanent
            MaxEligibleDays              = $(if ($eligExp -and $eligExp.isExpirationRequired) { [math]::Round((ConvertFrom-IsoDuration $eligExp.maximumDuration) / 24, 0) } else { '' })
            PermanentActiveAllowed       = $activePermanent
            MaxActiveDays                = $(if ($activeExp -and $activeExp.isExpirationRequired) { [math]::Round((ConvertFrom-IsoDuration $activeExp.maximumDuration) / 24, 0) } else { '' })
            AdminAssignmentRequiresMfa   = ($adminEnabled -contains 'MultiFactorAuthentication')
            Flags                        = Join-Values $flags
            PolicyId                     = $pa.policyId
        })
    }
    $rows = @($rows | Sort-Object @{ Expression = 'IsTier0'; Descending = $true }, @{ Expression = { [int]("$($_.ActiveAssignments)" -replace '^$', '0') + [int]("$($_.EligibleAssignments)" -replace '^$', '0') }; Descending = $true }, RoleName)
    Export-Dataset -Name 'pim-role-settings' -Rows $rows -Note $(if ($OnlyAssignedRoles) { 'Roles with at least one assignment' } else { 'All directory roles' })

    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $t0 = @($rows | Where-Object IsTier0)
    Add-Metric 'Roles reported' $rows.Count
    Add-Metric 'Tier 0 roles reported' $t0.Count
    Add-Metric 'Tier 0 roles activatable without approval' @($t0 | Where-Object { -not $_.ApprovalRequired }).Count
    Add-Metric 'Tier 0 roles without MFA or auth context on activation' @($t0 | Where-Object { $_.Flags -match 'Tier0NoMfaOrAuthContext' }).Count
    Add-Metric "Tier 0 roles with activation over $MaxActivationHours h" @($t0 | Where-Object { $_.Flags -match 'Tier0ActivationOver' }).Count
    Add-Metric 'Tier 0 roles allowing permanent active assignment' @($t0 | Where-Object PermanentActiveAllowed).Count
    Add-Metric 'Tier 0 roles allowing permanent eligibility' @($t0 | Where-Object PermanentEligibleAllowed).Count
    Add-Metric 'Roles using an authentication context' @($rows | Where-Object ActivationRequiresAuthContext).Count 'Lets CA require phishing-resistant MFA or a compliant device at activation'
    Add-Metric 'Roles requiring a ticket number on activation' @($rows | Where-Object ActivationRequiresTicket).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    if ($_.Exception.Message -match 'Premium|licen|P2') { Set-DatasetStatus -Name 'pim-role-settings' -Status 'EvidenceUnavailable' -Note 'PIM not licensed' }
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ MaxActivationHours = $MaxActivationHours; OnlyAssignedRoles = [bool]$OnlyAssignedRoles }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
