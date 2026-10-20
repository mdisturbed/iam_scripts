<#
.SYNOPSIS
    Read-only discovery of the ways people can send data out of Microsoft 365: mail forwarding,
    forwarding and redirect rules, transport rules, and SharePoint / OneDrive external sharing.

.DESCRIPTION
    Companion to 03-Get-AppsAndConsents.ps1 (which covers apps). This covers the human routes for
    "where is my data going":

    Exchange Online
      - Accepted domains (used to decide internal vs external)
      - Mailboxes with forwarding set (ForwardingSmtpAddress or ForwardingAddress), flagged external
      - Inbox rules that forward, redirect or forward-as-attachment, flagged external, plus rules
        that delete or bury mail (move to RSS Feeds / Deleted Items / Archive / Conversation History)
        - a common sign of a compromised mailbox hiding replies
      - Transport (mail flow) rules that redirect, copy or BCC mail
      - Remote domains with automatic forwarding allowed
      - Outbound spam policies and their automatic-forwarding mode
    SharePoint / OneDrive
      - Tenant sharing settings (via Graph)
      - Optional per-site sharing capability (via the SharePoint Online module)

    READ-ONLY. Uses only Get-* Exchange / SharePoint cmdlets and Graph GET requests.

    Output: <OutputRoot>\09-MailAndSharing\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER ExchangeOrganization
    Tenant's initial domain, e.g. contoso.onmicrosoft.com. Required for app-only Exchange sign-in.

.PARAMETER MaxMailboxes
    Limit the inbox-rule scan to this many mailboxes (0 = all). Inbox rules are read one mailbox
    at a time, so large tenants take a while.

.EXAMPLE
    .\09-Get-MailForwardingAndSharing.ps1
.EXAMPLE
    .\09-Get-MailForwardingAndSharing.ps1 -SkipInboxRules
.EXAMPLE
    .\09-Get-MailForwardingAndSharing.ps1 -IncludeSiteSharing -SharePointAdminUrl https://contoso-admin.sharepoint.com

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x
              ExchangeOnlineManagement v3 module; Exchange role: Global Reader or View-Only Organization Management
              Microsoft.Graph.Authentication with SharePointTenantSettings.Read.All (tenant sharing settings)
              -IncludeSiteSharing: Microsoft.Online.SharePoint.PowerShell (Windows PowerShell 5.1) and
              SharePoint Administrator or Global Reader
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$ExchangeOrganization = '',                     # e.g. 'contoso.onmicrosoft.com'
    [int]$MaxMailboxes = 0,
    [switch]$SkipInboxRules,
    [switch]$SkipSharePointSettings,
    [switch]$IncludeSiteSharing,
    [string]$SharePointAdminUrl = '',                       # e.g. 'https://contoso-admin.sharepoint.com'
    [switch]$IncludeOneDrive,

    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '09-MailAndSharing'
$ScriptVersion = '1.0.0'
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

$HidingFolders = 'RSS|Deleted Items|Archive|Conversation History|Junk'

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

$ctx = $null
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)

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

    # 2. Mailbox forwarding
    Write-RunLog 'Reading mailboxes...'
    $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward)
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
    Export-Dataset -Name 'exo-mailbox-forwarding' -Rows $fwdRows -Note ("{0} mailboxes checked" -f $mailboxes.Count)

    # 3. Inbox rules
    if ($SkipInboxRules) { Set-DatasetStatus -Name 'exo-inbox-rules' -Status 'Deferred' -Note '-SkipInboxRules' }
    else {
        $scan = $(if ($MaxMailboxes -gt 0) { @($mailboxes | Select-Object -First $MaxMailboxes) } else { $mailboxes })
        Write-RunLog ("Reading inbox rules for {0} mailboxes (one call per mailbox)..." -f $scan.Count)
        $ruleRows = [System.Collections.Generic.List[object]]::new()
        $ruleErrors = 0; $i = 0
        foreach ($m in $scan) {
            $i++
            if ($i % 250 -eq 0) { Write-RunLog ("  {0}/{1} mailboxes" -f $i, $scan.Count) }
            $rules = @()
            try { $rules = @(Get-InboxRule -Mailbox $m.UserPrincipalName -ErrorAction Stop) } catch { $ruleErrors++; continue }
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
        $note = "{0} mailboxes scanned; {1} could not be read" -f ($scan.Count - $ruleErrors), $ruleErrors
        if ($MaxMailboxes -gt 0 -and $mailboxes.Count -gt $MaxMailboxes) { $note += "; LIMITED to first $MaxMailboxes of $($mailboxes.Count)" }
        Export-Dataset -Name 'exo-inbox-rules' -Rows $ruleRows -Note $note
    }

    # 4. Transport rules
    $trRows = @()
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
    }
    catch { Set-DatasetStatus -Name 'exo-transport-rules' -Status 'Blocked' -Note $_.Exception.Message }

    # 5. Remote domains and outbound spam policies
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

    $siteRows = $null
    if (-not $IncludeSiteSharing) { Set-DatasetStatus -Name 'spo-site-sharing' -Status 'Deferred' -Note 'Run with -IncludeSiteSharing -SharePointAdminUrl ...' }
    else {
        try {
            if (-not $SharePointAdminUrl) { throw '-SharePointAdminUrl is required with -IncludeSiteSharing.' }
            Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
            Connect-SPOService -Url $SharePointAdminUrl -ErrorAction Stop
            $sites = @(Get-SPOSite -Limit All -IncludePersonalSite:([bool]$IncludeOneDrive))
            $siteRows = foreach ($s in $sites) {
                [pscustomobject][ordered]@{
                    Url                     = $s.Url
                    Template                = $s.Template
                    Owner                   = $s.Owner
                    SharingCapability       = $s.SharingCapability
                    AnyoneLinksAllowed      = ("$($s.SharingCapability)" -eq 'ExternalUserAndGuestSharing')
                    ExternalSharingAllowed  = ("$($s.SharingCapability)" -ne 'Disabled')
                    LastContentModifiedDate = $s.LastContentModifiedDate
                    LockState               = $s.LockState
                }
            }
            Export-Dataset -Name 'spo-site-sharing' -Rows $siteRows -Note $(if ($IncludeOneDrive) { 'Includes OneDrive sites' } else { 'SharePoint sites only' })
        }
        catch { Set-DatasetStatus -Name 'spo-site-sharing' -Status 'Blocked' -Note $_.Exception.Message }
    }

    # ---- Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Mailboxes checked' $mailboxes.Count
    Add-Metric 'Mailboxes with forwarding set' @($fwdRows).Count
    Add-Metric 'Mailboxes forwarding externally' @($fwdRows | Where-Object IsExternal).Count
    if (-not $SkipInboxRules) {
        Add-Metric 'Inbox rules forwarding externally' @($ruleRows | Where-Object { $_.Flags -match 'ExternalForward' }).Count
        Add-Metric 'Inbox rules that delete or bury mail' @($ruleRows | Where-Object { $_.Flags -match 'DeletesOrBuriesMail' }).Count
        Add-Metric 'Inbox rules that forward AND hide' @($ruleRows | Where-Object { $_.Flags -match 'ForwardAndHide' }).Count 'Review first - common compromise pattern'
    }
    Add-Metric 'Transport rules that redirect/copy/BCC' @($trRows).Count
    Add-Metric 'Remote domains allowing auto-forward' @($remote | Where-Object AutoForwardEnabled).Count
    if ($spoSettings) {
        Add-Metric 'SharePoint tenant sharing capability' "$($spoSettings.sharingCapability)"
        Add-Metric 'SharePoint sharing domain restriction' "$($spoSettings.sharingDomainRestrictionMode)"
    }
    if ($siteRows) {
        Add-Metric 'Sites checked' @($siteRows).Count
        Add-Metric 'Sites allowing Anyone links' @($siteRows | Where-Object AnyoneLinksAllowed).Count
        Add-Metric 'Sites allowing any external sharing' @($siteRows | Where-Object ExternalSharingAllowed).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -Context $ctx -Parameters @{ ExchangeOrganization = $ExchangeOrganization; MaxMailboxes = $MaxMailboxes; SkipInboxRules = [bool]$SkipInboxRules; SkipSharePointSettings = [bool]$SkipSharePointSettings; IncludeSiteSharing = [bool]$IncludeSiteSharing; IncludeOneDrive = [bool]$IncludeOneDrive }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
