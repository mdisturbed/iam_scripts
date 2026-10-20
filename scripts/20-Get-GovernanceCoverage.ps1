<#
.SYNOPSIS
    Read-only discovery of Entra ID Governance coverage: access reviews, how well they are
    completed, which apps / groups / roles they actually cover, and entitlement management
    access packages.

.DESCRIPTION
    Answers "what share of the things that should be certified actually are?" Exports:

      - Access review definitions: target type and name, reviewers, recurrence, status, and the
        latest instance's dates
      - Latest-instance decision statistics (optional): approved / denied / not reviewed,
        and whether results were applied
      - Coverage: every enterprise app that requires assignment, every role-assignable group,
        every group containing guests, and every privileged directory role - marked Covered or
        NotCovered by any recurring review. Optionally your own in-scope application list
        (for example the certification scope list) is checked too
      - Access packages with catalog, policies, approval, expiration and built-in reviews
      - A summary of headline metrics

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\20-GovernanceCoverage\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER InScopeAppsCsv
    Optional CSV listing the applications that must be certified. Needs a column named AppName
    or AppId (or both).

.EXAMPLE
    .\20-Get-GovernanceCoverage.ps1
.EXAMPLE
    .\20-Get-GovernanceCoverage.ps1 -IncludeDecisionStats -InScopeAppsCsv .\in-scope-apps.csv

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : AccessReview.Read.All, EntitlementManagement.Read.All, Application.Read.All,
              Group.Read.All, RoleManagement.Read.Directory, GroupMember.Read.All
    Licence : Access reviews and entitlement management need Entra ID P2 / ID Governance.
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

    [switch]$IncludeDecisionStats,
    [switch]$SkipGuestGroups,
    [string]$InScopeAppsCsv = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '20-GovernanceCoverage'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('AccessReview.Read.All', 'EntitlementManagement.Read.All', 'Application.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory')

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

$Tier0RoleTemplates = @('62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', '194ae4cb-b126-40b2-bd5b-6091b380977d', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', '158c047a-c907-4556-b7ef-446551a6b5f7', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2', 'c4e39bd9-1100-46d3-8c65-fb160da0071f', 'fe930be7-5e62-47db-91af-98c3a49a38b1')

function Get-ReviewTarget {
    # Classifies an access review scope query.
    param($Scope)
    $q = "$($Scope.query)"
    $principalScopes = @($Scope.principalScopes | ForEach-Object { "$($_.query)" })
    $resourceScopes = @($Scope.resourceScopes | ForEach-Object { "$($_.query)" })
    $all = @($q) + $principalScopes + $resourceScopes | Where-Object { $_ }
    foreach ($s in $all) {
        if ($s -match '/servicePrincipals/([0-9a-f-]{36})') { return [pscustomobject]@{ Type = 'Application'; Id = $Matches[1] } }
        if ($s -match 'roleDefinitionId eq ''?([0-9a-f-]{36})' -or $s -match '/roleDefinitions/([0-9a-f-]{36})') { return [pscustomobject]@{ Type = 'DirectoryRole'; Id = $Matches[1] } }
        if ($s -match '/groups/([0-9a-f-]{36})') { return [pscustomobject]@{ Type = 'Group'; Id = $Matches[1] } }
        if ($s -match '^/groups(\?|$)') { return [pscustomobject]@{ Type = 'AllGroups'; Id = '' } }
        if ($s -match 'accessPackage') { return [pscustomobject]@{ Type = 'AccessPackage'; Id = '' } }
    }
    return [pscustomobject]@{ Type = 'Other'; Id = '' }
}

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph

    # ---- 1. Access review definitions ----
    $defRows = [System.Collections.Generic.List[object]]::new()
    $statRows = [System.Collections.Generic.List[object]]::new()
    $covered = @{}   # "Type|Id" -> list of review names (recurring only)
    $reviewsAvailable = $true
    try {
        $defs = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions' -Label 'accessReviewDefinitions'
        foreach ($d in $defs) {
            $target = Get-ReviewTarget $d.scope
            if ($target.Type -eq 'Other' -and $d.instanceEnumerationScope) { $target = Get-ReviewTarget $d.instanceEnumerationScope }
            $rec = $d.settings.recurrence
            $recurring = [bool]($rec -and $rec.pattern -and $rec.pattern.type)
            $freq = $(if ($recurring) { '{0} every {1}' -f $rec.pattern.type, $rec.pattern.interval } else { 'One-time' })
            $targetName = ''
            if ($target.Id) {
                try {
                    $obj = $(if ($target.Type -eq 'DirectoryRole') { Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{0}?`$select=displayName" -f $target.Id) } else { Invoke-GraphGet -Uri ("https://graph.microsoft.com/v1.0/directoryObjects/{0}" -f $target.Id) })
                    $targetName = $obj.displayName
                }
                catch { $targetName = "$($target.Id) (unresolved)" }
            }
            if ($target.Id -and $recurring -and "$($d.status)" -notin @('Completed')) {
                $k = '{0}|{1}' -f $target.Type, $target.Id.ToLowerInvariant()
                if (-not $covered.ContainsKey($k)) { $covered[$k] = [System.Collections.Generic.List[string]]::new() }
                $covered[$k].Add($d.displayName)
            }
            $latest = $null
            try {
                $inst = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/{0}/instances" -f $d.id) -Label "instances $($d.id)"
                $latest = $inst | Sort-Object { [datetime]$_.startDateTime } -Descending | Select-Object -First 1
            }
            catch { }
            $reviewers = @($d.reviewers | ForEach-Object { "$($_.query)" -replace '^/users/[0-9a-f-]{36}$', 'specific user' -replace '.*manager.*', 'manager' -replace '^\./?owners$', 'group owners' })
            $defRows.Add([pscustomobject][ordered]@{
                ReviewName        = $d.displayName
                Status            = $d.status
                TargetType        = $target.Type
                TargetName        = $targetName
                Recurrence        = $freq
                Reviewers         = Join-Values ($reviewers | Select-Object -Unique)
                AutoApplyResults  = $d.settings.autoApplyDecisionsEnabled
                DefaultDecision   = $(if ($d.settings.defaultDecisionEnabled) { $d.settings.defaultDecision } else { 'None' })
                Created           = $d.createdDateTime
                LatestStartUtc    = $(if ($latest) { $latest.startDateTime } else { '' })
                LatestEndUtc      = $(if ($latest) { $latest.endDateTime } else { '' })
                LatestStatus      = $(if ($latest) { $latest.status } else { '' })
            })
            if ($IncludeDecisionStats -and $latest) {
                try {
                    $dec = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/{0}/instances/{1}/decisions?`$select=decision,applyResult" -f $d.id, $latest.id) -Label "decisions $($d.id)"
                    $n = $dec.Count
                    $c = @{}; foreach ($x in $dec) { $v = "$($x.decision)"; if ($c.ContainsKey($v)) { $c[$v]++ } else { $c[$v] = 1 } }
                    $notReviewed = $(if ($c.ContainsKey('NotReviewed')) { $c['NotReviewed'] } else { 0 })
                    $statRows.Add([pscustomobject][ordered]@{
                        ReviewName      = $d.displayName
                        InstanceStatus  = $latest.status
                        InstanceEndUtc  = $latest.endDateTime
                        Decisions       = $n
                        Approved        = $(if ($c.ContainsKey('Approve')) { $c['Approve'] } else { 0 })
                        Denied          = $(if ($c.ContainsKey('Deny')) { $c['Deny'] } else { 0 })
                        DontKnow        = $(if ($c.ContainsKey('DontKnow')) { $c['DontKnow'] } else { 0 })
                        NotReviewed     = $notReviewed
                        CompletionPct   = $(if ($n) { [math]::Round(100 * ($n - $notReviewed) / $n, 1) } else { '' })
                        Applied         = @($dec | Where-Object { "$($_.applyResult)" -in @('AppliedSuccessfully', 'AppliedSuccessfullyButObjectNotFound') }).Count
                        ApplyFailed     = @($dec | Where-Object { "$($_.applyResult)" -match 'Fail' }).Count
                    })
                }
                catch { Write-RunLog ("Decisions unreadable for {0}: {1}" -f $d.displayName, $_.Exception.Message) 'WARN' }
            }
        }
        Export-Dataset -Name 'access-review-definitions' -Rows $defRows
    }
    catch {
        $reviewsAvailable = $false
        Set-DatasetStatus -Name 'access-review-definitions' -Status (Get-FailureStatus $_) -Note $_.Exception.Message
    }
    if (-not $IncludeDecisionStats) { Set-DatasetStatus -Name 'access-review-latest-decisions' -Status 'Deferred' -Note 'Run with -IncludeDecisionStats' }
    elseif ($reviewsAvailable) { Export-Dataset -Name 'access-review-latest-decisions' -Rows $statRows }
    else { Set-DatasetStatus -Name 'access-review-latest-decisions' -Status 'Blocked' -Note 'Access reviews not readable' }
    $allGroupsReviewed = [bool](@($defRows | Where-Object { $_.TargetType -eq 'AllGroups' -and $_.Recurrence -ne 'One-time' }).Count)

    # ---- 2. Coverage denominator ----
    $covRows = [System.Collections.Generic.List[object]]::new()
    function Add-Coverage {
        param([string]$Type, [string]$Id, [string]$Name, [string]$Why)
        $k = '{0}|{1}' -f $Type, $Id.ToLowerInvariant()
        $isCov = $covered.ContainsKey($k) -or ($Type -eq 'Group' -and $allGroupsReviewed)
        $covRows.Add([pscustomobject][ordered]@{
            TargetType    = $Type
            TargetName    = $Name
            WhyInScope    = $Why
            Covered       = $isCov
            CoveredBy     = $(if ($covered.ContainsKey($k)) { Join-Values $covered[$k] } elseif ($isCov) { '(all-groups review)' } else { '' })
            TargetId      = $Id
        })
    }
    $spsByName = @{}; $spsById = @{}
    try {
        $sps = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appRoleAssignmentRequired,tags,servicePrincipalType' -Label 'servicePrincipals'
        foreach ($s in $sps) {
            $spsByName["$($s.displayName)".ToLowerInvariant()] = $s; $spsById["$($s.appId)".ToLowerInvariant()] = $s
            if ($s.appRoleAssignmentRequired -and @($s.tags) -contains 'WindowsAzureActiveDirectoryIntegratedApp') { Add-Coverage 'Application' $s.id $s.displayName 'Enterprise app requiring assignment' }
        }
    }
    catch { Write-RunLog ("Service principals unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    try {
        foreach ($g in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true&$count=true&$select=id,displayName' -Eventual -Label 'roleAssignableGroups')) { Add-Coverage 'Group' $g.id $g.displayName 'Role-assignable group' }
    }
    catch { Write-RunLog ("Role-assignable groups unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    if (-not $SkipGuestGroups) {
        try {
            $guestGroups = @{}
            foreach ($gu in (Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$count=true&`$select=id" -Eventual -Label 'guests')) {
                foreach ($m in (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/memberOf/microsoft.graph.group?`$select=id,displayName" -f $gu.id) -Label "memberOf $($gu.id)")) { $guestGroups[$m.id] = $m.displayName }
            }
            foreach ($gid in $guestGroups.Keys) { if (-not ($covRows | Where-Object { $_.TargetId -eq $gid })) { Add-Coverage 'Group' $gid $guestGroups[$gid] 'Contains guests' } }
        }
        catch { Write-RunLog ("Guest group membership unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    }
    try {
        foreach ($r in (Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName' -Label 'roleDefinitions')) {
            if ($Tier0RoleTemplates -contains $r.templateId) { Add-Coverage 'DirectoryRole' $r.templateId $r.displayName 'Tier 0 directory role' }
        }
    }
    catch { Write-RunLog ("Role definitions unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    if ($InScopeAppsCsv) {
        $list = @(Import-Csv -Path $InScopeAppsCsv)
        foreach ($row in $list) {
            $sp = $null
            if ($row.PSObject.Properties.Name -contains 'AppId' -and $row.AppId) { $sp = $spsById["$($row.AppId)".Trim().ToLowerInvariant()] }
            if (-not $sp -and $row.PSObject.Properties.Name -contains 'AppName' -and $row.AppName) { $sp = $spsByName["$($row.AppName)".Trim().ToLowerInvariant()] }
            $label = $(if ($row.PSObject.Properties.Name -contains 'AppName') { $row.AppName } else { $row.AppId })
            if (-not $sp) { $covRows.Add([pscustomobject][ordered]@{ TargetType = 'Application'; TargetName = $label; WhyInScope = 'In-scope list'; Covered = $false; CoveredBy = 'NOT FOUND IN TENANT (not SSO-integrated, or name differs)'; TargetId = '' }); continue }
            $existing = @($covRows | Where-Object { $_.TargetId -eq $sp.id })
            if ($existing.Count) { foreach ($e in $existing) { $e.WhyInScope = "$($e.WhyInScope); In-scope list" } }
            else { Add-Coverage 'Application' $sp.id $sp.displayName 'In-scope list' }
        }
    }
    Export-Dataset -Name 'review-coverage' -Rows @($covRows | Sort-Object Covered, TargetType, TargetName) -Note 'Covered = targeted by a recurring, not-completed access review'

    # ---- 3. Access packages ----
    $apRows = @()
    try {
        $aps = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages?$expand=assignmentPolicies,catalog' -Label 'accessPackages'
        $apRows = foreach ($a in $aps) {
            $pols = @($a.assignmentPolicies)
            [pscustomobject][ordered]@{
                AccessPackage       = $a.displayName
                Catalog             = $(if ($a.catalog) { $a.catalog.displayName } else { '' })
                IsHidden            = $a.isHidden
                Policies            = $pols.Count
                AnyApprovalRequired = [bool](@($pols | Where-Object { $_.requestApprovalSettings -and $_.requestApprovalSettings.isApprovalRequiredForAdd }).Count)
                AnyReviewConfigured = [bool](@($pols | Where-Object { $_.reviewSettings -and $_.reviewSettings.isEnabled }).Count)
                AnyNoExpiration     = [bool](@($pols | Where-Object { $_.expiration -and "$($_.expiration.type)" -eq 'noExpiration' }).Count)
                AllowedTargetScopes = Join-Values ($pols | ForEach-Object { $_.allowedTargetScope } | Select-Object -Unique)
                Modified            = $a.modifiedDateTime
            }
        }
        Export-Dataset -Name 'access-packages' -Rows $apRows
    }
    catch { Set-DatasetStatus -Name 'access-packages' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }

    # ---- 4. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Access review definitions' $defRows.Count
    Add-Metric 'Recurring reviews' @($defRows | Where-Object { $_.Recurrence -ne 'One-time' }).Count
    Add-Metric 'Reviews without auto-apply' @($defRows | Where-Object { -not $_.AutoApplyResults }).Count 'Decisions must be applied manually'
    foreach ($t in 'Application', 'Group', 'DirectoryRole') {
        $all = @($covRows | Where-Object TargetType -eq $t)
        $cv = @($all | Where-Object Covered).Count
        Add-Metric "$t targets in scope" $all.Count
        Add-Metric "$t targets covered (%)" $(if ($all.Count) { [math]::Round(100 * $cv / $all.Count, 1) } else { '' }) ("{0} of {1}" -f $cv, $all.Count)
    }
    if ($InScopeAppsCsv) { Add-Metric 'In-scope list apps not found in tenant' @($covRows | Where-Object { $_.CoveredBy -like 'NOT FOUND*' }).Count }
    if ($IncludeDecisionStats -and $statRows.Count) {
        $avg = ($statRows | Where-Object { $_.CompletionPct -ne '' } | Measure-Object CompletionPct -Average).Average
        Add-Metric 'Average completion of latest instances (%)' $(if ($null -ne $avg) { [math]::Round($avg, 1) } else { '' })
        Add-Metric 'Decisions that failed to apply' ($statRows | Measure-Object ApplyFailed -Sum).Sum
    }
    Add-Metric 'Access packages' @($apRows).Count
    Add-Metric 'Access packages with no expiration policy' @($apRows | Where-Object AnyNoExpiration).Count
    Add-Metric 'Access packages with built-in reviews' @($apRows | Where-Object AnyReviewConfigured).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ IncludeDecisionStats = [bool]$IncludeDecisionStats; SkipGuestGroups = [bool]$SkipGuestGroups; InScopeAppsCsv = $(if ($InScopeAppsCsv) { Split-Path $InScopeAppsCsv -Leaf } else { '' }) }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
