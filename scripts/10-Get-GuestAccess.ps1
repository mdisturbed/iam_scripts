<#
.SYNOPSIS
    Read-only discovery of guest (B2B) accounts in Entra ID and what they can reach.

.DESCRIPTION
    Guests are often the largest pool of stale access. This script exports:
      - External collaboration settings: who can invite, guest directory permissions, and the
        default cross-tenant access policy, plus the number of partner-specific policies
      - One row per guest: home domain, invitation state, created date, last sign-in, group /
        role / app-assignment counts, sponsors, and flags (pending invitation, never signed in,
        stale, disabled, holds a directory role, no sponsor)
      - One row per guest home domain with totals and stale counts
      - A summary of headline metrics

    READ-ONLY. Every Graph call goes through Invoke-GraphGet, which only issues HTTP GET.

    Output: <OutputRoot>\10-GuestAccess\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\10-Get-GuestAccess.ps1
.EXAMPLE
    .\10-Get-GuestAccess.ps1 -StaleDays 60 -IncludeSponsors
.EXAMPLE
    .\10-Get-GuestAccess.ps1 -SkipMemberships        # fast: one query, no per-guest calls

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, module Microsoft.Graph.Authentication (only)
    Scopes  : User.Read.All, Directory.Read.All, AuditLog.Read.All, Policy.Read.All
    Licence : signInActivity needs Entra ID P1.
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
    [switch]$IncludeSponsors
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '10-GuestAccess'
$ScriptVersion = '1.0.0'
$RequiredScopes = @('User.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'Policy.Read.All')

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

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $ctx = Connect-DiscoveryGraph
    $now = $script:RunStartUtc

    # ---- 1. External collaboration settings ----
    $settings = [System.Collections.Generic.List[object]]::new()
    try {
        $authz = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
        $gr = "$($authz.guestUserRoleId)"
        $settings.Add([pscustomobject][ordered]@{ Area = 'Invitations'; Setting = 'Who can invite guests'; Value = $authz.allowInvitesFrom })
        $settings.Add([pscustomobject][ordered]@{ Area = 'Guest permissions'; Setting = 'Guest user access level'; Value = $(if ($GuestRoleNames.ContainsKey($gr)) { $GuestRoleNames[$gr] } else { $gr }) })
        $settings.Add([pscustomobject][ordered]@{ Area = 'Self-service'; Setting = 'Email-verified users can join'; Value = $authz.allowEmailVerifiedUsersToJoinOrganization })
    }
    catch { Write-RunLog ("authorizationPolicy unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    try {
        $ct = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default'
        foreach ($dir in 'b2bCollaborationInbound', 'b2bCollaborationOutbound', 'b2bDirectConnectInbound', 'b2bDirectConnectOutbound') {
            $node = $ct.$dir
            if ($node) {
                $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = "$dir users/groups"; Value = "$($node.usersAndGroups.accessType)" })
                $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = "$dir applications"; Value = "$($node.applications.accessType)" })
            }
        }
        if ($ct.inboundTrust) {
            $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = 'Trust external MFA'; Value = $ct.inboundTrust.isMfaAccepted })
            $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant default'; Setting = 'Trust external compliant devices'; Value = $ct.inboundTrust.isCompliantDeviceAccepted })
        }
        $partners = Invoke-GraphGetAll -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners' -Label 'partners'
        $settings.Add([pscustomobject][ordered]@{ Area = 'Cross-tenant'; Setting = 'Partner-specific policies'; Value = $partners.Count })
    }
    catch { Write-RunLog ("crossTenantAccessPolicy unreadable: {0}" -f $_.Exception.Message) 'WARN' }
    if ($settings.Count) { Export-Dataset -Name 'external-collaboration-settings' -Rows $settings }
    else { Set-DatasetStatus -Name 'external-collaboration-settings' -Status 'Blocked' -Note 'Policy.Read.All needed' }

    # ---- 2. Guests ----
    $select = 'id,displayName,mail,userPrincipalName,createdDateTime,accountEnabled,externalUserState,externalUserStateChangeDateTime,creationType,identities'
    $signInAvailable = $true
    try {
        $guests = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$count=true&`$top=999&`$select={0},signInActivity" -f $select) -Eventual -Label 'guests'
    }
    catch {
        $signInAvailable = $false
        Write-RunLog ("signInActivity not readable ({0}); continuing without last sign-in." -f $_.Exception.Message) 'WARN'
        $guests = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$count=true&`$top=999&`$select={0}" -f $select) -Eventual -Label 'guests'
    }
    Write-RunLog ("{0} guests found" -f $guests.Count)
    if (-not $SkipMemberships -and $guests.Count -gt 2000) { Write-RunLog ("{0} guests: per-guest membership calls will take a while. Use -SkipMemberships for a fast pass." -f $guests.Count) 'WARN' }

    $guestRows = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($g in $guests) {
        $i++
        if ($i % 500 -eq 0) { Write-RunLog ("  {0}/{1} guests" -f $i, $guests.Count) }
        $last = $null
        if ($signInAvailable -and $g.signInActivity) {
            $c = @($g.signInActivity.lastSuccessfulSignInDateTime, $g.signInActivity.lastSignInDateTime, $g.signInActivity.lastNonInteractiveSignInDateTime) | Where-Object { $_ }
            if ($c) { $last = ($c | ForEach-Object { ([datetime]$_).ToUniversalTime() } | Sort-Object -Descending | Select-Object -First 1) }
        }
        $created = $(if ($g.createdDateTime) { ([datetime]$g.createdDateTime).ToUniversalTime() } else { $null })
        $stateChanged = $(if ($g.externalUserStateChangeDateTime) { ([datetime]$g.externalUserStateChangeDateTime).ToUniversalTime() } else { $created })
        $groups = ''; $roles = ''; $groupNames = ''; $apps = ''; $sponsors = ''
        if (-not $SkipMemberships) {
            try {
                $mem = (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/memberOf?`$select=id,displayName" -f $g.id) -Label "memberOf $($g.id)")
                $grp = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' })
                $rol = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' })
                $groups = $grp.Count; $roles = Join-Values ($rol | ForEach-Object { $_.displayName })
                $groupNames = Join-Values ($grp | Select-Object -First 10 | ForEach-Object { $_.displayName })
                if ($grp.Count -gt 10) { $groupNames += "; (+$($grp.Count - 10) more)" }
            }
            catch { $groups = 'unreadable' }
            try { $apps = (Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/appRoleAssignments?`$select=resourceDisplayName" -f $g.id) -Label "appRoleAssignments $($g.id)").Count } catch { $apps = 'unreadable' }
        }
        if ($IncludeSponsors) {
            try { $sponsors = Join-Values ((Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/users/{0}/sponsors?`$select=displayName,userPrincipalName" -f $g.id) -Label "sponsors $($g.id)") | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) }
            catch { $sponsors = 'unreadable' }
        }
        $flags = @()
        if (-not $g.accountEnabled) { $flags += 'Disabled' }
        if ($g.externalUserState -eq 'PendingAcceptance') {
            $flags += 'PendingInvitation'
            if ($stateChanged -and ($now - $stateChanged).TotalDays -gt $PendingDays) { $flags += "PendingOver${PendingDays}d" }
        }
        if ($signInAvailable) {
            if (-not $last) { $flags += 'NeverSignedIn' }
            elseif (($now - $last).TotalDays -gt $StaleDays) { $flags += "NoSignIn${StaleDays}d" }
        }
        if ($roles) { $flags += 'HoldsDirectoryRole' }
        if ($IncludeSponsors -and -not $sponsors) { $flags += 'NoSponsor' }
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
        })
    }
    Export-Dataset -Name 'guests' -Rows $guestRows -Note $(if ($signInAvailable) { '' } else { 'signInActivity unavailable; staleness not evaluated' })

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
        }
    } | Sort-Object Guests -Descending
    Export-Dataset -Name 'guests-by-domain' -Rows $domainRows

    # ---- 4. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $total = $guestRows.Count
    $pct = { param($n) if ($total) { [math]::Round(100 * $n / $total, 1) } else { 0 } }
    Add-Metric 'Guests' $total
    Add-Metric 'Guest home domains' @($domainRows).Count
    Add-Metric 'Guests enabled' @($guestRows | Where-Object AccountEnabled).Count
    $pend = @($guestRows | Where-Object { $_.Flags -match 'PendingInvitation' }).Count
    Add-Metric 'Pending invitations' $pend ("{0}%" -f (& $pct $pend))
    Add-Metric "Pending invitations older than $PendingDays days" @($guestRows | Where-Object { $_.Flags -match 'PendingOver' }).Count
    if ($signInAvailable) {
        $never = @($guestRows | Where-Object { $_.Flags -match 'NeverSignedIn' }).Count
        $stale = @($guestRows | Where-Object { $_.Flags -match 'NoSignIn' }).Count
        Add-Metric 'Guests never signed in' $never ("{0}%" -f (& $pct $never))
        Add-Metric "Guests with no sign-in in $StaleDays days" $stale ("{0}%" -f (& $pct $stale))
        Add-Metric 'Enabled guests that are stale or never signed in' @($guestRows | Where-Object { $_.AccountEnabled -and $_.Flags -match 'NeverSignedIn|NoSignIn' }).Count 'Review / removal candidates'
    }
    if (-not $SkipMemberships) {
        Add-Metric 'Guests holding a directory role' @($guestRows | Where-Object DirectoryRoles).Count
        Add-Metric 'Guests in at least one group' @($guestRows | Where-Object { $_.GroupCount -is [int] -and $_.GroupCount -gt 0 }).Count
    }
    if ($IncludeSponsors) { Add-Metric 'Guests without a sponsor' @($guestRows | Where-Object { $_.Flags -match 'NoSponsor' }).Count }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ StaleDays = $StaleDays; PendingDays = $PendingDays; SkipMemberships = [bool]$SkipMemberships; IncludeSponsors = [bool]$IncludeSponsors }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
