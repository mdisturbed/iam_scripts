<#
.SYNOPSIS
    Read-only discovery of the ways people and apps can send data out of Microsoft 365: mail
    forwarding, forwarding and redirect rules, mailbox delegation, transport rules and connectors,
    application mailbox access, and SharePoint / OneDrive external sharing.

.DESCRIPTION
    Companion to 03-Get-AppsAndConsents.ps1 (which covers app consents). This covers the routes for
    "where is my data going, and who can read or send as whom":

    Exchange Online
      - Accepted domains (used to decide internal vs external)
      - Mailboxes (user, shared, room, equipment) with forwarding set, flagged external
      - Inbox rules (hidden rules included) that forward, redirect or forward-as-attachment, flagged
        external, plus rules that delete or bury mail (move to RSS Feeds / Deleted Items / Archive /
        Conversation History) - a common sign of a compromised mailbox hiding replies. Mailboxes
        whose rules cannot be read are listed, not counted as "no rules".
      - Mailbox delegation: FullAccess, SendAs and SendOnBehalf grants. Group trustees are expanded
        to their (nested) members so every account that actually holds the right is listed.
      - Transport (mail flow) rules that redirect, copy or BCC mail, and rules that weaken
        protection (route via a connector, SCL -1, remove encryption, set bypass headers)
      - Outbound connectors (smart hosts, recipient domains, TLS)
      - Remote domains with automatic forwarding allowed; outbound spam policy forwarding mode
      - Application access policies and RBAC for Applications role assignments (apps that can read
        mailboxes)
    SharePoint / OneDrive
      - Tenant sharing settings (via Graph)
      - Per-site sharing capability, domain restrictions, default link type and link / guest
        expiry (via the SharePoint Online module, when installed)
      - Optional external users per site (-IncludeExternalUsers)

    READ-ONLY. Uses only Get-* Exchange / SharePoint cmdlets and Graph GET requests.

    Output: <OutputRoot>\09-MailAndSharing\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER ExchangeOrganization
    Tenant's initial domain, e.g. contoso.onmicrosoft.com. Required for app-only Exchange sign-in.

.PARAMETER MaxMailboxes
    Limit the inbox-rule scan to the FIRST N user / shared mailboxes returned by Exchange (0 = all).
    Inbox rules are read one mailbox at a time, so large tenants take a while. The note on
    exo-inbox-rules records the limit. Delegation and forwarding always cover every mailbox.

.PARAMETER SkipDelegation
    Skip the FullAccess / SendAs / SendOnBehalf read (one permission call per mailbox).

.PARAMETER SkipSiteSharing
    Skip the per-site SharePoint / OneDrive sharing read. It runs by default when the SharePoint
    Online module is installed (one call per site).

.PARAMETER IncludeSiteSharing
    Kept for compatibility; per-site sharing now runs by default.

.PARAMETER SharePointAdminUrl
    e.g. https://contoso-admin.sharepoint.com. When blank it is derived from the initial
    *.onmicrosoft.com accepted domain.

.PARAMETER IncludeExternalUsers
    List external users per site that allows external sharing (Get-SPOExternalUser, pages of 50).

.EXAMPLE
    .\09-Get-MailForwardingAndSharing.ps1
.EXAMPLE
    .\09-Get-MailForwardingAndSharing.ps1 -SkipInboxRules -SkipDelegation
.EXAMPLE
    .\09-Get-MailForwardingAndSharing.ps1 -SharePointAdminUrl https://contoso-admin.sharepoint.com -IncludeExternalUsers

.NOTES
    Version : 1.1.1
    Requires: PowerShell 5.1 or 7.x
              ExchangeOnlineManagement v3 module; Exchange role: Global Reader or View-Only Organization Management
              Microsoft.Graph.Authentication with SharePointTenantSettings.Read.All (tenant sharing settings)
              Per-site sharing: Microsoft.Online.SharePoint.PowerShell (Windows PowerShell 5.1) and
              SharePoint Administrator or Global Reader
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$ExchangeOrganization = '',                     # e.g. 'contoso.onmicrosoft.com'
    [int]$MaxMailboxes = 0,
    [switch]$SkipInboxRules,
    [switch]$SkipDelegation,
    [switch]$SkipSharePointSettings,
    [switch]$SkipSiteSharing,
    [switch]$IncludeSiteSharing,                            # no-op: per-site sharing runs by default
    [string]$SharePointAdminUrl = '',                       # e.g. 'https://contoso-admin.sharepoint.com'
    [switch]$IncludeOneDrive,
    [switch]$IncludeExternalUsers,

    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '09-MailAndSharing'
$ScriptVersion = '1.1.1'
$RequiredScopes = @('SharePointTenantSettings.Read.All')

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

$HidingFolders = 'RSS|Deleted Items|Archive|Conversation History|Junk'
# Trustees that hold mailbox rights by product design (not delegations someone granted).
$SystemTrusteePattern = '^(NT AUTHORITY\\|S-1-5-(18|19|20)$)|\\(Organization Management|Exchange Servers|Exchange Trusted Subsystem|Exchange Windows Permissions|Managed Availability Servers|Discovery Management|Public Folder Management|Delegated Setup|Exchange Domain Servers|Domain Admins|Enterprise Admins|Administrators|ExchangeLegacyInterop|Exchange Services|Exchange View-Only Administrators|Exchange Organization Administrators|Exchange Public Folder Administrators)$|^(Organization Management|Exchange Servers|Exchange Trusted Subsystem|Managed Availability Servers|Discovery Management|Administrator|Domain Admins|Enterprise Admins)$'
# Transport-rule headers that switch off filtering (bypass) - BypassClutter is benign and skipped.
$BypassHeaderPattern = '^X-MS-Exchange-Organization-(SkipSafeLinksProcessing|SkipSafeAttachmentProcessing|BypassFocusedInbox)$|^X-Forefront-Antispam-Report$|^X-MS-Exchange-Organization-SCL$'

function Get-SmtpAddress {
    # Pulls SMTP addresses out of rule targets such as '"Name" [SMTP:user@contoso.local]'.
    param($Values)
    $out = @()
    foreach ($v in @($Values | Where-Object { $_ })) {
        $s = "$v"
        $m = [regex]::Matches($s, '(?i)smtp:([^\]\s;"]+)')
        if ($m.Count) { foreach ($x in $m) { $out += $x.Groups[1].Value } }
        elseif ($s -match '^[^@\s]+@[^@\s]+$') { $out += $s }
    }
    return @($out | Select-Object -Unique)
}

$script:Accepted = @()
function Test-External {
    param([string]$Address)
    if (-not $Address -or $Address -notmatch '@') { return $false }
    $domain = ($Address -split '@')[-1].ToLowerInvariant()
    foreach ($d in $script:Accepted) { if ($domain -eq $d -or $domain.EndsWith('.' + $d)) { return $false } }
    return $true
}

$script:TrusteeCache = @{}
function Resolve-Trustee {
    # Name / UPN / SID of a permission trustee -> type and address. Exchange reads only.
    param([string]$Name)
    if (-not $Name) { return [pscustomobject]@{ Name = ''; Address = ''; Type = 'Unresolved'; Id = '' } }
    if ($script:TrusteeCache.ContainsKey($Name)) { return $script:TrusteeCache[$Name] }
    $info = $null
    try {
        $r = Get-EXORecipient -Identity $Name -Properties PrimarySmtpAddress, RecipientTypeDetails, ExternalDirectoryObjectId, DisplayName -ErrorAction Stop
        $info = [pscustomobject]@{ Name = $Name; Address = "$($r.PrimarySmtpAddress)"; Type = "$($r.RecipientTypeDetails)"; Id = "$($r.ExternalDirectoryObjectId)" }
    }
    catch {
        try {
            $g = Get-Group -Identity $Name -ErrorAction Stop
            $info = [pscustomobject]@{ Name = $Name; Address = "$($g.Name)"; Type = "$($g.RecipientTypeDetails)"; Id = "$($g.ExternalDirectoryObjectId)" }
        }
        catch {
            $type = $(if ($Name -match '^S-1-5-21-') { 'Unresolved (SID only - object probably deleted)' } else { 'Unresolved' })
            $info = [pscustomobject]@{ Name = $Name; Address = ''; Type = $type; Id = '' }
        }
    }
    $script:TrusteeCache[$Name] = $info
    return $info
}

$script:GroupMemberCache = @{}
function Get-TrusteeGroupMember {
    # Returns the transitive members of a group trustee as resolved trustee objects.
    # Mail-enabled groups: Get-DistributionGroupMember; Microsoft 365 groups: Get-UnifiedGroupLinks;
    # security groups that are not mail-enabled: Get-Group .Members. Nested groups are followed.
    param([object]$Group, [hashtable]$Seen = @{})
    $key = "$($Group.Name)"
    if ($Seen.ContainsKey($key)) { return @() }
    $Seen[$key] = $true
    $out = [System.Collections.Generic.List[object]]::new()
    $direct = @()
    if ($script:GroupMemberCache.ContainsKey($key)) { $direct = $script:GroupMemberCache[$key] }
    else {
        if ($Group.Type -eq 'GroupMailbox') {
            $direct = @(Get-UnifiedGroupLinks -Identity $key -LinkType Members -ResultSize Unlimited -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; Address = "$($_.PrimarySmtpAddress)"; Type = "$($_.RecipientTypeDetails)"; Id = "$($_.ExternalDirectoryObjectId)" } })
        }
        elseif ($Group.Type -like 'Mail*Group' -or $Group.Type -eq 'RoomList') {
            $direct = @(Get-DistributionGroupMember -Identity $key -ResultSize Unlimited -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; Address = "$($_.PrimarySmtpAddress)"; Type = "$($_.RecipientTypeDetails)"; Id = "$($_.ExternalDirectoryObjectId)" } })
        }
        else {
            $g = Get-Group -Identity $key -ErrorAction Stop
            $direct = @(@($g.Members) | Where-Object { $_ } | ForEach-Object { Resolve-Trustee "$_" })
        }
        $script:GroupMemberCache[$key] = $direct
    }
    foreach ($m in $direct) {
        if ("$($m.Type)" -match 'Group$|^GroupMailbox$|^RoomList$') {
            foreach ($n in @(Get-TrusteeGroupMember -Group $m -Seen $Seen)) { $out.Add([pscustomobject]@{ Name = $n.Name; Address = $n.Address; Type = $n.Type; Id = $n.Id; ViaGroup = $(if ($n.ViaGroup) { "$($m.Name) > $($n.ViaGroup)" } else { "$($m.Name)" }) }) }
        }
        else { $out.Add([pscustomobject]@{ Name = $m.Name; Address = $m.Address; Type = $m.Type; Id = $m.Id; ViaGroup = '' }) }
    }
    return $out.ToArray()
}

function Get-SharePointAdminUrl {
    # Derives the admin URL (contoso.onmicrosoft.com -> https://contoso-admin.sharepoint.com) from the initial domain.
    foreach ($d in $script:Accepted) { if ($d -match '^([a-z0-9-]+)\.onmicrosoft\.com$') { return ('https://{0}-admin.sharepoint.com' -f $Matches[1]) } }   # guardrail:allow URL template filled from the tenant's own initial domain
    return ''
}

$ctx = $null
$readErrors = [System.Collections.Generic.List[object]]::new()
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if ($IncludeSiteSharing) { Write-RunLog '-IncludeSiteSharing is no longer needed: per-site sharing runs by default (use -SkipSiteSharing to turn it off).' }

    # ---- Exchange Online ----
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) { throw 'Module ExchangeOnlineManagement not found. Install it (Install-Module ExchangeOnlineManagement -Scope CurrentUser) if your policy allows.' }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    if ($AuthMode -eq 'AppCertificate') {
        if (-not $ExchangeOrganization -or -not $ClientId -or -not $CertificateThumbprint) { throw 'AppCertificate mode needs -ExchangeOrganization, -ClientId and -CertificateThumbprint.' }
        Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -Organization $ExchangeOrganization -ShowBanner:$false -ErrorAction Stop
    }
    else { Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop }
    Write-RunLog 'Connected to Exchange Online.'
    $script:ManifestExtra = @{ ExchangeConnected = $true; ExchangeOrganization = $ExchangeOrganization }

    # 1. Accepted domains
    $acc = @(Get-AcceptedDomain)
    $script:Accepted = @($acc | ForEach-Object { "$($_.DomainName)".ToLowerInvariant() })
    Export-Dataset -Name 'exo-accepted-domains' -Rows @($acc | ForEach-Object { [pscustomobject][ordered]@{ DomainName = $_.DomainName; DomainType = $_.DomainType; Default = $_.Default } })

    # 2. Mailbox forwarding (user, shared, room and equipment mailboxes)
    Write-RunLog 'Reading mailboxes...'
    $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox, RoomMailbox, EquipmentMailbox -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward, GrantSendOnBehalfTo)
    $fwdRows = foreach ($m in $mailboxes) {
        if (-not $m.ForwardingSmtpAddress -and -not $m.ForwardingAddress) { continue }
        $smtp = "$($m.ForwardingSmtpAddress)" -replace '^(?i)smtp:', ''
        $resolved = ''
        if ($m.ForwardingAddress) {
            try { $r = Get-EXORecipient -Identity "$($m.ForwardingAddress)" -Properties PrimarySmtpAddress, ExternalEmailAddress, RecipientTypeDetails; $resolved = $(if ($r.ExternalEmailAddress) { "$($r.ExternalEmailAddress)" -replace '^(?i)smtp:', '' } else { "$($r.PrimarySmtpAddress)" }) }
            catch { $resolved = "$($m.ForwardingAddress) (unresolved)" }
        }
        $targets = @($smtp, $resolved | Where-Object { $_ })
        [pscustomobject][ordered]@{
            Mailbox                    = $m.UserPrincipalName
            MailboxType                = $m.RecipientTypeDetails
            ForwardingSmtpAddress      = $smtp
            ForwardingAddressResolved  = $resolved
            DeliverToMailboxAndForward = $m.DeliverToMailboxAndForward
            IsExternal                 = [bool](@($targets | Where-Object { Test-External $_ }).Count)
        }
    }
    Export-Dataset -Name 'exo-mailbox-forwarding' -Rows $fwdRows -Note ("{0} mailboxes checked (user, shared, room, equipment)" -f $mailboxes.Count)

    # 3. Inbox rules (user and shared mailboxes; hidden rules included)
    $ruleRows = [System.Collections.Generic.List[object]]::new()
    $ruleErrors = 0
    if ($SkipInboxRules) { Set-DatasetStatus -Name 'exo-inbox-rules' -Status 'Deferred' -Note '-SkipInboxRules' }
    else {
        $ruleScope = @($mailboxes | Where-Object { "$($_.RecipientTypeDetails)" -in @('UserMailbox', 'SharedMailbox') })
        $scan = $(if ($MaxMailboxes -gt 0) { @($ruleScope | Select-Object -First $MaxMailboxes) } else { $ruleScope })
        Write-RunLog ("Reading inbox rules for {0} mailboxes (one call per mailbox)..." -f $scan.Count)
        $i = 0
        foreach ($m in $scan) {
            $i++
            if ($i % 250 -eq 0) { Write-RunLog ("  {0}/{1} mailboxes" -f $i, $scan.Count) }
            $rules = @()
            try { $rules = @(Get-InboxRule -Mailbox $m.UserPrincipalName -IncludeHidden -ErrorAction Stop) }
            catch { $ruleErrors++; $readErrors.Add([pscustomobject][ordered]@{ Mailbox = $m.UserPrincipalName; Error = $_.Exception.Message; Source = 'InboxRules' }); continue }
            foreach ($r in $rules) {
                $fwd = @(Get-SmtpAddress $r.ForwardTo)
                $att = @(Get-SmtpAddress $r.ForwardAsAttachmentTo)
                $red = @(Get-SmtpAddress $r.RedirectTo)
                $all = @(@($fwd) + @($att) + @($red) | Where-Object { $_ })
                $ext = @($all | Where-Object { Test-External $_ })
                $hiding = ([bool]$r.DeleteMessage) -or ("$($r.MoveToFolder)" -match $HidingFolders)
                $hasTarget = (@(@($r.ForwardTo) + @($r.ForwardAsAttachmentTo) + @($r.RedirectTo) | Where-Object { $_ }).Count -gt 0)
                if (-not $hasTarget -and -not $hiding) { continue }
                $flags = @()
                if ($ext.Count) { $flags += 'ExternalForward' }
                elseif ($hasTarget) { $flags += 'InternalForward' }
                if ($hiding) { $flags += 'DeletesOrBuriesMail' }
                if ($hiding -and $hasTarget) { $flags += 'ForwardAndHide' }
                $ruleRows.Add([pscustomobject][ordered]@{
                    Mailbox                = $m.UserPrincipalName
                    RuleName               = $r.Name
                    Enabled                = $r.Enabled
                    ForwardTo              = Join-Values $fwd
                    ForwardAsAttachmentTo  = Join-Values $att
                    RedirectTo             = Join-Values $red
                    ExternalTargets        = Join-Values $ext
                    MoveToFolder           = $r.MoveToFolder
                    DeleteMessage          = $r.DeleteMessage
                    MarkAsRead             = $r.MarkAsRead
                    Conditions             = ($r.Description -replace '\s+', ' ')
                    Flags                  = Join-Values $flags
                })
            }
        }
        $note = "{0} mailboxes scanned; {1} could not be read (see mailbox-read-errors.csv); hidden rules included" -f ($scan.Count - $ruleErrors), $ruleErrors
        if ($MaxMailboxes -gt 0 -and $ruleScope.Count -gt $MaxMailboxes) { $note += "; LIMITED to the first $MaxMailboxes of $($ruleScope.Count) user/shared mailboxes" }
        Export-Dataset -Name 'exo-inbox-rules' -Rows $ruleRows -Status $(if ($ruleErrors) { 'Partial' } else { 'Completed' }) -Note $note
    }

    # 4. Mailbox delegation: FullAccess, SendAs, SendOnBehalf - group trustees expanded to members
    $delRows = [System.Collections.Generic.List[object]]::new()
    $delErrors = 0; $expandErrors = 0
    if ($SkipDelegation) { Set-DatasetStatus -Name 'mailbox-delegation' -Status 'Deferred' -Note '-SkipDelegation' }
    else {
        $mbxByKey = @{}
        foreach ($m in $mailboxes) { foreach ($k in @($m.Identity, $m.Name, $m.Alias, $m.UserPrincipalName, $m.PrimarySmtpAddress, $m.ExternalDirectoryObjectId)) { if ($k -and -not $mbxByKey.ContainsKey("$k")) { $mbxByKey["$k"] = $m } } }
        $addRows = {
            param($Mailbox, $MailboxType, $TrusteeName, $Right, $IsInherited)
            $t = Resolve-Trustee $TrusteeName
            $delRows.Add([pscustomobject][ordered]@{ Mailbox = $Mailbox; MailboxType = $MailboxType; Trustee = $(if ($t.Address) { $t.Address } else { $TrusteeName }); TrusteeType = $t.Type; Right = $Right; IsInherited = $IsInherited; ViaGroup = '' })
            if ("$($t.Type)" -match 'Group$|^GroupMailbox$|^RoomList$') {
                try {
                    foreach ($mem in @(Get-TrusteeGroupMember -Group $t)) {
                        $delRows.Add([pscustomobject][ordered]@{ Mailbox = $Mailbox; MailboxType = $MailboxType; Trustee = $(if ($mem.Address) { $mem.Address } else { $mem.Name }); TrusteeType = $mem.Type; Right = $Right; IsInherited = $IsInherited; ViaGroup = $(if ($mem.ViaGroup) { "$TrusteeName > $($mem.ViaGroup)" } else { $TrusteeName }) })
                    }
                }
                catch { $script:delExpandErrors++; Write-RunLog ("Could not expand group trustee {0}: {1}" -f $TrusteeName, $_.Exception.Message) 'WARN' }
            }
        }
        $script:delExpandErrors = 0
        Write-RunLog ("Reading FullAccess permissions for {0} mailboxes (one call per mailbox)..." -f $mailboxes.Count)
        $i = 0
        foreach ($m in $mailboxes) {
            $i++
            if ($i % 250 -eq 0) { Write-RunLog ("  {0}/{1} mailboxes" -f $i, $mailboxes.Count) }
            $perms = @()
            try { $perms = @(Get-EXOMailboxPermission -Identity $m.UserPrincipalName -ResultSize Unlimited -ErrorAction Stop) }
            catch { $delErrors++; $readErrors.Add([pscustomobject][ordered]@{ Mailbox = $m.UserPrincipalName; Error = $_.Exception.Message; Source = 'MailboxPermission' }); continue }
            foreach ($pm in $perms) {
                $user = "$($pm.User)"
                if (-not $user -or $user -eq 'NT AUTHORITY\SELF') { continue }
                if ("$($pm.Deny)" -eq 'True') { continue }
                if (@($pm.AccessRights) -notcontains 'FullAccess' -and "$($pm.AccessRights)" -notmatch 'FullAccess') { continue }
                if ($user -match $SystemTrusteePattern) { continue }
                & $addRows $m.UserPrincipalName "$($m.RecipientTypeDetails)" $user 'FullAccess' ("$($pm.IsInherited)" -eq 'True')
            }
            foreach ($sob in @($m.GrantSendOnBehalfTo | Where-Object { $_ })) { & $addRows $m.UserPrincipalName "$($m.RecipientTypeDetails)" "$sob" 'SendOnBehalf' $false }
        }
        $sendAsNote = ''
        try {
            foreach ($rp in @(Get-EXORecipientPermission -ResultSize Unlimited -ErrorAction Stop)) {
                $tr = "$($rp.Trustee)"
                if (-not $tr -or $tr -eq 'NT AUTHORITY\SELF' -or $tr -match $SystemTrusteePattern) { continue }
                if ("$($rp.AccessControlType)" -and "$($rp.AccessControlType)" -ne 'Allow') { continue }
                if ("$($rp.AccessRights)" -notmatch 'SendAs') { continue }
                $mb = $mbxByKey["$($rp.Identity)"]
                $mbName = $(if ($mb) { $mb.UserPrincipalName } else { "$($rp.Identity)" })
                $mbType = $(if ($mb) { "$($mb.RecipientTypeDetails)" } else { 'Recipient (not a scanned mailbox)' })
                & $addRows $mbName $mbType $tr 'SendAs' ("$($rp.IsInherited)" -eq 'True')
            }
        }
        catch { $delErrors++; $sendAsNote = "SendAs not readable: $($_.Exception.Message)"; $readErrors.Add([pscustomobject][ordered]@{ Mailbox = '(all)'; Error = $_.Exception.Message; Source = 'RecipientPermission (SendAs)' }) }
        $expandErrors = $script:delExpandErrors
        $dNote = "{0} mailboxes; {1} permission read(s) failed; {2} group trustee(s) could not be expanded. Group trustees are listed once with blank ViaGroup and again per member with ViaGroup set." -f $mailboxes.Count, $delErrors, $expandErrors
        if ($sendAsNote) { $dNote += " $sendAsNote" }
        Export-Dataset -Name 'mailbox-delegation' -Rows $delRows -Status $(if ($delErrors -or $expandErrors) { 'Partial' } else { 'Completed' }) -Note $dNote
    }
    Export-Dataset -Name 'mailbox-read-errors' -Rows $readErrors -Note 'Mailboxes whose inbox rules or permissions could not be read; their absence elsewhere is not evidence of "none"'

    # 5. Transport rules (copy / redirect, and rules that weaken protection)
    $trRows = @(); $riskyRows = [System.Collections.Generic.List[object]]::new(); $tr = @()
    try {
        $tr = @(Get-TransportRule -ResultSize Unlimited)
        $trRows = foreach ($r in $tr) {
            $targets = @()
            foreach ($prop in 'RedirectMessageTo', 'BlindCopyTo', 'CopyTo', 'AddToRecipients') { $targets += @($r.$prop | Where-Object { $_ } | ForEach-Object { "$_" }) }
            if (-not $targets.Count) { continue }
            [pscustomobject][ordered]@{
                RuleName          = $r.Name
                State             = $r.State
                Mode              = $r.Mode
                Priority          = $r.Priority
                RedirectMessageTo = Join-Values $r.RedirectMessageTo
                BlindCopyTo       = Join-Values $r.BlindCopyTo
                CopyTo            = Join-Values $r.CopyTo
                AddToRecipients   = Join-Values $r.AddToRecipients
                ExternalTargets   = Join-Values ($targets | Where-Object { Test-External $_ })
                Description       = $r.Description -replace '\s+', ' '
            }
        }
        Export-Dataset -Name 'exo-transport-rules' -Rows $trRows -Note ("{0} transport rules checked; only rules that redirect, copy or BCC are listed" -f $tr.Count)
        foreach ($r in $tr) {
            $why = @()
            if ($r.RouteMessageOutboundConnector) { $why += 'RoutesViaOutboundConnector' }
            if ("$($r.SetSCL)" -eq '-1') { $why += 'BypassSpamFiltering(SCL-1)' }
            if ("$($r.RemoveOME)" -eq 'True' -or "$($r.RemoveOMEv2)" -eq 'True') { $why += 'RemovesMessageEncryption' }
            if ("$($r.RemoveRMSAttachmentEncryption)" -eq 'True') { $why += 'RemovesAttachmentEncryption' }
            if ($r.SetHeaderName -and "$($r.SetHeaderName)" -match $BypassHeaderPattern) { $why += 'SetsBypassHeader' }
            if (-not $why.Count) { continue }
            $riskyRows.Add([pscustomobject][ordered]@{
                RuleName                      = $r.Name
                State                         = $r.State
                Mode                          = $r.Mode
                Priority                      = $r.Priority
                RiskReasons                   = Join-Values $why
                RouteMessageOutboundConnector = "$($r.RouteMessageOutboundConnector)"
                SetSCL                        = "$($r.SetSCL)"
                SetHeaderName                 = "$($r.SetHeaderName)"
                SetHeaderValue                = "$($r.SetHeaderValue)"
                Description                   = ("$($r.Description)" -replace '\s+', ' ')
            })
        }
        Export-Dataset -Name 'transport-rules-risky' -Rows $riskyRows -Note 'Rules that route through a specific connector, bypass spam filtering (SCL -1), strip encryption or set filtering-bypass headers'
    }
    catch {
        Set-DatasetStatus -Name 'exo-transport-rules' -Status 'Blocked' -Note $_.Exception.Message
        Set-DatasetStatus -Name 'transport-rules-risky' -Status 'Blocked' -Note $_.Exception.Message
    }

    # 6. Outbound connectors
    $connRows = @()
    try {
        $connRows = @(Get-OutboundConnector -ErrorAction Stop | ForEach-Object {
            $f = @()
            $smart = @($_.SmartHosts | Where-Object { $_ } | ForEach-Object { "$_" })
            if ("$($_.Enabled)" -eq 'True' -and -not "$($_.TlsSettings)" ) { $f += 'NoTlsRequirement' }
            if (@($_.RecipientDomains | Where-Object { "$_" -eq '*' }).Count -and "$($_.IsTransportRuleScoped)" -ne 'True') { $f += 'AllRecipientDomains' }
            if ("$($_.IsTransportRuleScoped)" -eq 'True') { $f += 'UsedByTransportRules' }
            if ($smart.Count) { $f += 'SmartHostRouting' }
            [pscustomobject][ordered]@{
                Name                  = $_.Name
                Enabled               = $_.Enabled
                ConnectorType         = $_.ConnectorType
                SmartHosts            = Join-Values $smart
                RecipientDomains      = Join-Values ($_.RecipientDomains | ForEach-Object { "$_" })
                UseMXRecord           = $_.UseMXRecord
                TlsSettings           = "$($_.TlsSettings)"
                TlsDomain             = "$($_.TlsDomain)"
                IsTransportRuleScoped = $_.IsTransportRuleScoped
                Flags                 = Join-Values $f
            }
        })
        Export-Dataset -Name 'outbound-connectors' -Rows $connRows -Note 'A transport-rule-scoped connector only carries mail that a rule routes to it (see transport-rules-risky)'
    }
    catch { Set-DatasetStatus -Name 'outbound-connectors' -Status 'Blocked' -Note $_.Exception.Message }

    # 7. Remote domains and outbound spam policies
    $remote = @()
    try {
        $remote = @(Get-RemoteDomain)
        Export-Dataset -Name 'exo-remote-domains' -Rows @($remote | ForEach-Object { [pscustomobject][ordered]@{ Name = $_.Name; DomainName = $_.DomainName; AutoForwardEnabled = $_.AutoForwardEnabled; AllowedOOFType = $_.AllowedOOFType } })
    }
    catch { Set-DatasetStatus -Name 'exo-remote-domains' -Status 'Blocked' -Note $_.Exception.Message }
    try {
        Export-Dataset -Name 'exo-outbound-spam-policies' -Rows @(Get-HostedOutboundSpamFilterPolicy | ForEach-Object { [pscustomobject][ordered]@{ Name = $_.Name; IsDefault = $_.IsDefault; AutoForwardingMode = $_.AutoForwardingMode } }) -Note 'AutoForwardingMode: Automatic = blocked by default (system-controlled), On = allowed, Off = blocked'
    }
    catch { Set-DatasetStatus -Name 'exo-outbound-spam-policies' -Status 'Blocked' -Note $_.Exception.Message }

    # 8. Applications with mailbox access (legacy application access policies and RBAC for Applications)
    $aapRows = @(); $appRbacRows = @()
    try {
        $aapRows = @(Get-ApplicationAccessPolicy -ErrorAction Stop | ForEach-Object {
            [pscustomobject][ordered]@{ AppId = "$($_.AppId)"; AccessRight = "$($_.AccessRight)"; ScopeName = "$($_.ScopeName)"; ScopeIdentity = "$($_.ScopeIdentity)"; Description = "$($_.Description)"; IsValid = $_.IsValid }
        })
        Export-Dataset -Name 'application-access-policies' -Rows $aapRows -Note 'RestrictAccess = app limited to the scope group; DenyAccess = app blocked from it. Apps with Graph mail permissions and NO policy can read every mailbox (see script 03).'
    }
    catch { Set-DatasetStatus -Name 'application-access-policies' -Status 'Blocked' -Note $_.Exception.Message }
    try {
        $appRbacRows = @(Get-ManagementRoleAssignment -ResultSize Unlimited -ErrorAction Stop | Where-Object { "$($_.RoleAssigneeType)" -eq 'ServicePrincipal' } | ForEach-Object {
            [pscustomobject][ordered]@{ App = "$($_.RoleAssigneeName)"; Role = "$($_.Role)"; AssignmentName = "$($_.Name)"; CustomResourceScope = "$($_.CustomResourceScope)"; RecipientWriteScope = "$($_.RecipientWriteScope)"; Enabled = $_.Enabled; Flags = $(if (-not "$($_.CustomResourceScope)" -and "$($_.RecipientWriteScope)" -match 'Organization|^$') { 'OrganizationWide' } else { '' }) }
        })
        Export-Dataset -Name 'app-rbac-role-assignments' -Rows $appRbacRows -Note 'Exchange RBAC for Applications: application roles granted to service principals; OrganizationWide = no custom resource scope'
    }
    catch { Set-DatasetStatus -Name 'app-rbac-role-assignments' -Status 'Blocked' -Note $_.Exception.Message }

    # ---- SharePoint / OneDrive ----
    $spoSettings = $null
    if ($SkipSharePointSettings) { Set-DatasetStatus -Name 'spo-tenant-sharing-settings' -Status 'Deferred' -Note '-SkipSharePointSettings' }
    else {
        try {
            $ctx = Connect-DiscoveryGraph
            $spoSettings = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings'
            $setRows = foreach ($pp in $spoSettings.PSObject.Properties) {
                if ($pp.Name -like '@odata*') { continue }
                [pscustomobject][ordered]@{ Setting = $pp.Name; Value = $(if ($pp.Value -is [array]) { Join-Values $pp.Value } else { "$($pp.Value)" }) }
            }
            Export-Dataset -Name 'spo-tenant-sharing-settings' -Rows $setRows
        }
        catch { Set-DatasetStatus -Name 'spo-tenant-sharing-settings' -Status (Get-FailureStatus $_) -Note $_.Exception.Message }
    }

    $siteRows = $null; $extRows = [System.Collections.Generic.List[object]]::new()
    $spoReady = $false
    if ($SkipSiteSharing) {
        Set-DatasetStatus -Name 'spo-site-sharing' -Status 'Deferred' -Note '-SkipSiteSharing'
    }
    elseif (-not (Get-Module -ListAvailable -Name Microsoft.Online.SharePoint.PowerShell)) {
        Set-DatasetStatus -Name 'spo-site-sharing' -Status 'Deferred' -Note 'Module Microsoft.Online.SharePoint.PowerShell not installed; per-site sharing not read'
    }
    else {
        try {
            $adminUrl = $SharePointAdminUrl
            if (-not $adminUrl) {
                $adminUrl = Get-SharePointAdminUrl
                if (-not $adminUrl) { throw 'Could not derive the SharePoint admin URL from the accepted domains; pass -SharePointAdminUrl.' }
                Write-RunLog ("SharePoint admin URL derived from the initial domain: {0}" -f $adminUrl)
            }
            Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
            Connect-SPOService -Url $adminUrl -ErrorAction Stop
            $spoReady = $true
            $sites = @(Get-SPOSite -Limit All -IncludePersonalSite:([bool]$IncludeOneDrive))
            Write-RunLog ("Reading sharing detail for {0} sites (one call per site)..." -f $sites.Count)
            $detailErrors = 0; $i = 0
            $siteRows = foreach ($s in $sites) {
                $i++
                if ($i % 250 -eq 0) { Write-RunLog ("  {0}/{1} sites" -f $i, $sites.Count) }
                # List mode leaves the sharing properties at default values; read each site by identity.
                $d = $null
                try { $d = Get-SPOSite -Identity $s.Url -ErrorAction Stop } catch { $detailErrors++; Write-RunLog ("Site detail unreadable for {0}: {1}" -f $s.Url, $_.Exception.Message) 'WARN' }
                $src = $(if ($d) { $d } else { $s })
                $cap = "$($src.SharingCapability)"
                [pscustomobject][ordered]@{
                    Url                           = $s.Url
                    Template                      = $s.Template
                    Owner                         = $s.Owner
                    SharingCapability             = $cap
                    AnyoneLinksAllowed            = ($cap -eq 'ExternalUserAndGuestSharing')
                    ExternalSharingAllowed        = ($cap -ne 'Disabled')
                    LastContentModifiedDate       = $s.LastContentModifiedDate
                    LockState                     = $s.LockState
                    SharingDomainRestrictionMode  = $(if ($d) { "$($d.SharingDomainRestrictionMode)" } else { '' })
                    SharingAllowedDomainList      = $(if ($d) { "$($d.SharingAllowedDomainList)" } else { '' })
                    SharingBlockedDomainList      = $(if ($d) { "$($d.SharingBlockedDomainList)" } else { '' })
                    DefaultSharingLinkType        = $(if ($d) { "$($d.DefaultSharingLinkType)" } else { '' })
                    AnonymousLinkExpirationInDays = $(if ($d) { $d.AnonymousLinkExpirationInDays } else { '' })
                    ExternalUserExpirationInDays  = $(if ($d) { $d.ExternalUserExpirationInDays } else { '' })
                    DetailRead                    = [bool]$d
                }
            }
            $sNote = $(if ($IncludeOneDrive) { 'Includes OneDrive sites' } else { 'SharePoint sites only' })
            if ($detailErrors) { $sNote += "; $detailErrors site(s) read in list mode only (DetailRead=False: sharing values may be defaults)" }
            Export-Dataset -Name 'spo-site-sharing' -Rows $siteRows -Status $(if ($detailErrors) { 'Partial' } else { 'Completed' }) -Note $sNote
        }
        catch { Set-DatasetStatus -Name 'spo-site-sharing' -Status 'Blocked' -Note $_.Exception.Message }
    }

    if (-not $IncludeExternalUsers) { Set-DatasetStatus -Name 'spo-external-users' -Status 'Deferred' -Note 'Run with -IncludeExternalUsers (one paged call per site that allows external sharing)' }
    elseif (-not $spoReady -or $null -eq $siteRows) { Set-DatasetStatus -Name 'spo-external-users' -Status 'Deferred' -Note 'Needs the per-site sharing read (SharePoint Online module and connection)' }
    else {
        $extErrors = 0
        foreach ($s in @($siteRows | Where-Object { $_.ExternalSharingAllowed })) {
            $pos = 0
            try {
                while ($true) {
                    $page = @(Get-SPOExternalUser -SiteUrl $s.Url -Position $pos -PageSize 50 -ErrorAction Stop)
                    foreach ($u in $page) {
                        $extRows.Add([pscustomobject][ordered]@{ SiteUrl = $s.Url; DisplayName = "$($u.DisplayName)"; Email = "$($u.Email)"; AcceptedAs = "$($u.AcceptedAs)"; WhenCreated = $u.WhenCreated; InvitedBy = "$($u.InvitedBy)" })
                    }
                    if ($page.Count -lt 50) { break }
                    $pos += 50
                }
            }
            catch { $extErrors++; Write-RunLog ("External users unreadable for {0}: {1}" -f $s.Url, $_.Exception.Message) 'WARN' }
        }
        Export-Dataset -Name 'spo-external-users' -Rows $extRows -Status $(if ($extErrors) { 'Partial' } else { 'Completed' }) -Note $(if ($extErrors) { "$extErrors site(s) could not be read; see run.log" } else { 'Sites with external sharing disabled are not queried' })
    }

    # ---- Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric -Metric 'Mailboxes checked' $mailboxes.Count 'User, shared, room and equipment mailboxes'
    Add-Metric -Metric 'Mailboxes with forwarding set' @($fwdRows).Count
    Add-Metric -Metric 'Mailboxes forwarding externally' @($fwdRows | Where-Object IsExternal).Count
    if (-not $SkipInboxRules) {
        Add-Metric -Metric 'Inbox rules forwarding externally' @($ruleRows | Where-Object { $_.Flags -match 'ExternalForward' }).Count
        Add-Metric -Metric 'Inbox rules that delete or bury mail' @($ruleRows | Where-Object { $_.Flags -match 'DeletesOrBuriesMail' }).Count
        Add-Metric -Metric 'Inbox rules that forward AND hide' @($ruleRows | Where-Object { $_.Flags -match 'ForwardAndHide' }).Count 'Review first - common compromise pattern'
        Add-Metric -Metric 'Mailboxes whose inbox rules could not be read' $ruleErrors $(if ($ruleErrors) { 'Not evidence of "no rules" - see mailbox-read-errors.csv' } else { '' })
    }
    if (-not $SkipDelegation) {
        Add-Metric -Metric 'Mailbox delegations (direct grants)' @($delRows | Where-Object { -not $_.ViaGroup }).Count
        Add-Metric -Metric 'FullAccess grants' @($delRows | Where-Object { $_.Right -eq 'FullAccess' -and -not $_.ViaGroup }).Count
        Add-Metric -Metric 'SendAs grants' @($delRows | Where-Object { $_.Right -eq 'SendAs' -and -not $_.ViaGroup }).Count
        Add-Metric -Metric 'SendOnBehalf grants' @($delRows | Where-Object { $_.Right -eq 'SendOnBehalf' -and -not $_.ViaGroup }).Count
        Add-Metric -Metric 'Accounts holding a mailbox right through a group' @($delRows | Where-Object ViaGroup | Select-Object -ExpandProperty Trustee -Unique).Count
        Add-Metric -Metric 'Delegations to unresolved trustees' @($delRows | Where-Object { $_.TrusteeType -like 'Unresolved*' }).Count 'Often a deleted account (SID only); confirm before removing'
        Add-Metric -Metric 'Mailbox permission reads that failed' $delErrors
    }
    Add-Metric -Metric 'Transport rules that redirect/copy/BCC' @($trRows).Count
    Add-Metric -Metric 'Transport rules that weaken protection' $riskyRows.Count 'Connector routing, SCL -1, encryption removal or bypass headers'
    Add-Metric -Metric 'Outbound connectors' @($connRows).Count
    Add-Metric -Metric 'Remote domains allowing auto-forward' @($remote | Where-Object AutoForwardEnabled).Count
    Add-Metric -Metric 'Application access policies' @($aapRows).Count
    Add-Metric -Metric 'RBAC for Applications role assignments' @($appRbacRows).Count
    if ($spoSettings) {
        Add-Metric -Metric 'SharePoint tenant sharing capability' "$($spoSettings.sharingCapability)"
        Add-Metric -Metric 'SharePoint sharing domain restriction' "$($spoSettings.sharingDomainRestrictionMode)"
    }
    if ($siteRows) {
        Add-Metric -Metric 'Sites checked' @($siteRows).Count
        Add-Metric -Metric 'Sites allowing Anyone links' @($siteRows | Where-Object AnyoneLinksAllowed).Count
        Add-Metric -Metric 'Sites allowing any external sharing' @($siteRows | Where-Object ExternalSharingAllowed).Count
        Add-Metric -Metric 'Sites with Anyone links that never expire' @($siteRows | Where-Object { $_.AnyoneLinksAllowed -and $_.DetailRead -and "$($_.AnonymousLinkExpirationInDays)" -in @('0', '') }).Count 'Site value 0 = follows the tenant setting'
    }
    if ($IncludeExternalUsers -and $extRows.Count) { Add-Metric 'External users (site-level)' $extRows.Count }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ ExchangeOrganization = $ExchangeOrganization; MaxMailboxes = $MaxMailboxes; SkipInboxRules = [bool]$SkipInboxRules; SkipDelegation = [bool]$SkipDelegation; SkipSharePointSettings = [bool]$SkipSharePointSettings; SkipSiteSharing = [bool]$SkipSiteSharing; IncludeSiteSharing = [bool]$IncludeSiteSharing; IncludeOneDrive = [bool]$IncludeOneDrive; IncludeExternalUsers = [bool]$IncludeExternalUsers }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
