<#
.SYNOPSIS
    Read-only discovery of privileged and service accounts in on-premises Active Directory.

.DESCRIPTION
    Exports the on-prem evidence for "service and privileged account sprawl":
      - Membership of every protected / privileged group, expanded through nesting down to the
        accounts, with the full nesting path, a Tier label (Tier0 / Tier1-access / Info) and the
        members that only hold the group as their primary group (primaryGroupID). Groups that live
        in the forest root (Schema Admins, Enterprise Admins, Enterprise Key Admins, Enterprise
        Read-only Domain Controllers) are read from the root domain; members in other domains are
        read from their own domain. Foreign security principals are translated to account names.
      - One row per privileged account with hygiene flags (stale, password never expires, old
        password, Kerberos pre-auth disabled, delegation, SPN on an admin account), tier, admin
        naming, product-default category, Protected Users membership and delegation protection
      - Domain-wide risky account settings (every user and computer, not only privileged ones):
        unconstrained / constrained / resource-based delegation, pre-auth disabled, password not
        required, reversible encryption, DES only, old never-expiring passwords, SID history,
        key credentials on users, Kerberoastable user accounts, admins not marked sensitive
      - Age of the domain secrets: krbtgt (and RODC krbtgt_*), the built-in Administrator (RID 500)
        and the Seamless SSO computer account (AZUREADSSOACC$)
      - Who can retrieve each gMSA password, expanded through groups to the accounts
      - Service-account candidates found by several detection methods, with the reasons listed
      - adminCount=1 users, computers and groups that are no longer in any Tier 0 group
        (AdminSDHolder leftovers)
      - A summary of headline metrics

    A read that fails is logged and the affected dataset is marked Partial; it is never reported
    as "no members" or "none found".

    READ-ONLY. Uses only Get-AD* cmdlets. Nothing in the directory is changed.

    Output: <OutputRoot>\04-ADPrivilegedAndServiceAccounts\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER Server
    Domain controller or domain to query (e.g. dc01.contoso.local). Blank = default DC for the session.
    Objects in other domains of the forest (root groups, cross-domain members) are read from a DC
    of the domain that owns them, located by its DNS name.

.PARAMETER SearchBase
    Limits the service-account name / description / SPN detections. Every other section is domain-wide.

.PARAMETER ServiceNamePatterns
    sAMAccountName wildcard patterns that indicate a service account in this environment.

.PARAMETER AdditionalPrivilegedGroups
    Names of custom admin groups to expand as Tier 0.

.PARAMETER AdminNamePatterns
    sAMAccountName wildcards that mark an admin account (IsAdminNamed column). Set to the naming standard.

.PARAMETER PasswordAgeWarningDays
    Passwords older than this are flagged. Alias: -PasswordAgeDays.

.PARAMETER SkipRiskFlags
    Do not run the domain-wide risky-setting queries (ad-account-risk-flags).

.EXAMPLE
    .\04-Get-ADPrivilegedAndServiceAccounts.ps1
.EXAMPLE
    .\04-Get-ADPrivilegedAndServiceAccounts.ps1 -Server dc01.contoso.local -ServiceNamePatterns 'svc*','sa_*' -AdditionalPrivilegedGroups 'Group1','Group2'
.EXAMPLE
    .\04-Get-ADPrivilegedAndServiceAccounts.ps1 -AdminNamePatterns 'adm-*','*-a' -PasswordAgeDays 180

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account (read).
              In a child domain the run account must also be able to read the forest root domain.
    Note    : msDS-KeyCredentialLink and gMSA password-reader lists may not be readable by every
              account; an empty result there is reported as "not readable or none", never as none.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                    # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                                # e.g. 'OU=Service Accounts,DC=contoso,DC=local' (blank = whole domain)
    [string[]]$ServiceNamePatterns = @('svc*', 'svc-*', 'svc_*', 'sa-*', 'sa_*', '*_svc', '*-svc', 'srv-*'),
    [string[]]$AdditionalPrivilegedGroups = @(),             # names of custom admin groups, e.g. 'Group1'
    [string[]]$AdminNamePatterns = @('adm*', '*adm', '*-adm*', '*_adm*', 'a-*', 'a_*', 'da-*', '*admin*'),
    [int]$StaleDays = 90,
    [Alias('PasswordAgeDays')]
    [int]$PasswordAgeWarningDays = 365,
    [switch]$SkipRiskFlags
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '04-ADPrivilegedAndServiceAccounts'
$ScriptVersion = '1.1.0'

#region ---- Common helpers (identical in every AD script; self-contained by design) ----
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
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][ValidateSet('Blocked', 'Deferred', 'EvidenceUnavailable')][string]$Status, [string]$Note = '')
    $script:Datasets.Add([pscustomobject][ordered]@{ Dataset = $Name; Status = $Status; Rows = 0; File = ''; Sha256 = ''; Note = $Note })
    Write-RunLog ("{0}: [{1}] {2}" -f $Name, $Status, $Note) 'WARN'
}

function Write-RunManifest {
    param([string]$DomainName, [hashtable]$Parameters)
    $manifest = [ordered]@{
        Script        = $ScriptName
        ScriptVersion = $ScriptVersion
        StartedUtc    = $script:RunStartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        FinishedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        RunAsWindows  = [Environment]::UserDomainName + '\' + [Environment]::UserName
        Machine       = [Environment]::MachineName
        PowerShell    = $PSVersionTable.PSVersion.ToString()
        Domain        = $DomainName
        Server        = $Server
        Parameters    = $Parameters
        Datasets      = $script:Datasets.ToArray()
    }
    if ($script:ManifestExtra) { $manifest['Extra'] = $script:ManifestExtra }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $script:RunFolder 'run-manifest.json') -Encoding UTF8
    $script:Datasets | Export-Csv -Path (Join-Path $script:RunFolder 'dataset-status.csv') -NoTypeInformation -Encoding UTF8
}

function Join-Values { param($Values) if ($null -eq $Values) { return '' } return (@($Values) | Where-Object { $null -ne $_ -and "$_" -ne '' }) -join '; ' }

# Splat for every AD cmdlet so -Server is honoured consistently.
$script:AdParams = @{}
if ($Server) { $script:AdParams['Server'] = $Server }
#endregion

$AccountProps = @('sAMAccountName', 'name', 'objectClass', 'objectSid', 'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet',
    'adminCount', 'servicePrincipalName', 'description', 'managedBy', 'whenCreated', 'msDS-AllowedToDelegateTo', 'member', 'distinguishedName',
    'primaryGroupID', 'sIDHistory', 'msDS-SupportedEncryptionTypes')

$UacBits = @{ Disabled = 2; PasswordNotRequired = 32; ReversibleEncryption = 128; ServerTrust = 8192; PasswordNeverExpires = 65536; TrustedForDelegation = 524288
    NotDelegated = 1048576; DesOnly = 2097152; NoPreAuth = 4194304; TrustedToAuthForDelegation = 16777216; PartialSecrets = 67108864 }
$BitAnd  = '1.2.840.113556.1.4.803'     # LDAP_MATCHING_RULE_BIT_AND
$InChain = '1.2.840.113556.1.4.1941'    # LDAP_MATCHING_RULE_IN_CHAIN: transitive group membership
$AccountTypeFilter = '(|(sAMAccountType=805306368)(sAMAccountType=805306369))'   # user accounts; computer and managed service accounts
$UserTypeFilter    = '(sAMAccountType=805306368)'
$ExchangeGroupNames = @('Organization Management', 'Exchange Windows Permissions', 'Exchange Trusted Subsystem')
$SyncPatterns = @('MSOL_*', 'AAD_*', 'ADSync*', 'Sync_*')
$TierRank = @{ 'Tier0' = 0; 'Tier1-access' = 1; 'Info' = 2 }
$PrivilegedRids = @(500, 512, 516, 518, 519, 520, 521, 526, 527)

function ConvertFrom-FileTime { param($Value) if ($null -eq $Value -or "$Value" -eq '' -or [int64]"$Value" -le 0 -or [int64]"$Value" -eq [int64]::MaxValue) { return $null } return [datetime]::FromFileTimeUtc([int64]"$Value") }
function Format-FileTimeUtc { param($Value) $d = ConvertFrom-FileTime $Value; if ($d) { return $d.ToString('yyyy-MM-ddTHH:mm:ssZ') } return '' }
function Get-UacValue { param($Obj) $v = 0; try { if ($null -ne $Obj.userAccountControl -and "$($Obj.userAccountControl)" -ne '') { $v = [int64]"$($Obj.userAccountControl)" } } catch { $v = 0 }; return $v }

function ConvertTo-AccountInfo {
    param($Obj)
    $uac = [int]$Obj.userAccountControl
    $lastLogon = ConvertFrom-FileTime $Obj.lastLogonTimestamp
    $pwdSet = ConvertFrom-FileTime $Obj.pwdLastSet
    $now = $script:RunStartUtc
    [pscustomobject][ordered]@{
        SamAccountName        = $Obj.sAMAccountName
        Name                  = $Obj.name
        ObjectClass           = @($Obj.objectClass)[-1]
        DistinguishedName     = $Obj.distinguishedName
        Enabled               = -not ($uac -band $UacBits.Disabled)
        LastLogonUtc          = $(if ($lastLogon) { $lastLogon.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        DaysSinceLogon        = $(if ($lastLogon) { [int]($now - $lastLogon).TotalDays } else { '' })
        Stale                 = (-not $lastLogon) -or (($now - $lastLogon).TotalDays -gt $StaleDays)
        PasswordLastSetUtc    = $(if ($pwdSet) { $pwdSet.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        PasswordAgeDays       = $(if ($pwdSet) { [int]($now - $pwdSet).TotalDays } else { '' })
        PasswordNeverExpires  = [bool]($uac -band $UacBits.PasswordNeverExpires)
        KerberosPreAuthDisabled = [bool]($uac -band $UacBits.NoPreAuth)
        UnconstrainedDelegation = [bool]($uac -band $UacBits.TrustedForDelegation)
        ProtocolTransition    = [bool]($uac -band $UacBits.TrustedToAuthForDelegation)
        ConstrainedDelegationTargets = @($Obj.'msDS-AllowedToDelegateTo' | Where-Object { $_ }).Count
        HasSpn                = (@($Obj.servicePrincipalName | Where-Object { $_ }).Count -gt 0)
        SpnCount              = @($Obj.servicePrincipalName | Where-Object { $_ }).Count
        AdminCount            = $Obj.adminCount
        HasManagedBy          = [bool]$Obj.managedBy
        Description           = $Obj.description
        WhenCreated           = $Obj.whenCreated
    }
}

# ---- Forest-aware reads: every DN is read from a DC of the domain that owns it ----
$script:DomainDns = ''
function Get-DnsDomainFromDN { param([string]$DN) return ((@([regex]::Matches($DN, '(?i)(?:^|,)DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }) -join '.').ToLowerInvariant()) }
function Get-ParamsForDN {
    param([string]$DN)
    $d = Get-DnsDomainFromDN $DN
    if (-not $d -or $d -eq $script:DomainDns) { return $script:AdParams }
    return @{ Server = $d }
}
function Test-NotFound { param($ErrorRecord) $e = $ErrorRecord.Exception; return ($e.GetType().Name -like '*NotFound*' -or $e.Message -match 'Cannot find an object') }

$script:Gaps = [System.Collections.Generic.List[string]]::new()
function Add-Gap { param([string]$Text) if (-not $script:Gaps.Contains($Text)) { $script:Gaps.Add($Text); Write-RunLog $Text 'WARN' } }

$script:ObjCache = @{}
function Get-AdObjectCached {
    param([string]$DN)
    if ($script:ObjCache.ContainsKey($DN)) { return $script:ObjCache[$DN] }
    $o = $null
    $p = Get-ParamsForDN $DN
    try { $o = Get-ADObject -Identity $DN -Properties $AccountProps @p }
    catch { Add-Gap ("Could not read {0} (from {1}): {2}" -f $DN, $(if ($p.Server) { $p.Server } else { 'default DC' }), $_.Exception.Message) }
    $script:ObjCache[$DN] = $o
    return $o
}

function Get-SidText {
    param($Obj)
    if ($null -eq $Obj -or $null -eq $Obj.objectSid) { return '' }
    $s = $Obj.objectSid
    if ($s -is [byte[]]) { try { return ([System.Security.Principal.SecurityIdentifier]::new($s, 0)).Value } catch { return '' } }
    return "$s"
}
$script:SidNames = @{}
function Resolve-ForeignSid {
    # SID -> DOMAIN\name via the Windows name translation; '' when it cannot be translated.
    param([string]$Sid)
    if ($script:SidNames.ContainsKey($Sid)) { return $script:SidNames[$Sid] }
    $n = ''
    try { $n = ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value } catch { $n = '' }
    $script:SidNames[$Sid] = $n
    return $n
}
function ConvertTo-LdapValue {
    param([string]$Value)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $Value.ToCharArray()) {
        switch ([int]$ch) { 92 { [void]$sb.Append('\5c') } 42 { [void]$sb.Append('\2a') } 40 { [void]$sb.Append('\28') } 41 { [void]$sb.Append('\29') } 0 { [void]$sb.Append('\00') } default { [void]$sb.Append($ch) } }
    }
    return $sb.ToString()
}
function Test-AdminName { param([string]$Sam) if (-not $Sam) { return $false } return [bool](@($AdminNamePatterns | Where-Object { $Sam -like $_ }).Count) }
function Get-AccountCategory {
    # Product-default labels so expected accounts can be filtered: Builtin, Domain controller, Entra Connect, Exchange, Managed service account, Custom.
    param($Obj, [string]$Via = '')
    $sam = [string]$Obj.sAMAccountName
    $cls = [string]@($Obj.objectClass)[-1]
    $sid = Get-SidText $Obj
    $uac = Get-UacValue $Obj
    if ($cls -eq 'foreignSecurityPrincipal') { return 'Foreign principal' }
    if ($sid -match '-(500|501|502)$' -or $sam -like 'krbtgt*') { return 'Builtin' }
    if (($uac -band $UacBits.ServerTrust) -or "$($Obj.primaryGroupID)" -in '516', '521') { return 'Domain controller' }
    if (@($SyncPatterns | Where-Object { $sam -like $_ }).Count) { return 'Entra Connect (sync account)' }
    if ($sam -like 'HealthMailbox*' -or $sam -like 'SM_*' -or @($ExchangeGroupNames | Where-Object { $Via -like "*$_*" }).Count) { return 'Exchange (product default)' }
    if ($cls -in 'msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount') { return 'Managed service account' }
    return 'Custom'
}

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain @script:AdParams
    $forest = Get-ADForest @script:AdParams
    $domainName = $domain.DNSRoot
    $script:DomainDns = ([string]$domainName).ToLowerInvariant()
    $domainSid = $domain.DomainSID.Value
    $rootDns = ([string]$forest.RootDomain).ToLowerInvariant()
    $rootParams = $(if ($rootDns -eq $script:DomainDns) { $script:AdParams } else { @{ Server = [string]$forest.RootDomain } })
    $rootSid = $null
    try { $rootSid = (Get-ADDomain -Identity $forest.RootDomain @rootParams).DomainSID.Value }
    catch { Add-Gap ("Forest root domain {0} not readable; root groups (Schema / Enterprise Admins ...) not expanded: {1}" -f $forest.RootDomain, $_.Exception.Message) }
    Write-RunLog ("Domain {0}; forest root {1}" -f $domainName, $forest.RootDomain)

    # ---- Protected / privileged groups to expand ----
    # Tier0 = control of the domain or forest; Tier1-access = logon / service-level rights; Info = reported, not privileged.
    $groupSpecs = @(
        @{ Label = 'Domain Admins';                Sid = "$domainSid-512"; Root = $false; Tier = 'Tier0'; Required = $true }
        @{ Label = 'Group Policy Creator Owners';  Sid = "$domainSid-520"; Root = $false; Tier = 'Tier0'; Required = $true }
        @{ Label = 'Key Admins';                   Sid = "$domainSid-526"; Root = $false; Tier = 'Tier0'; Required = $false }
        @{ Label = 'Domain Controllers';           Sid = "$domainSid-516"; Root = $false; Tier = 'Tier0'; Required = $true }
        @{ Label = 'Read-only Domain Controllers'; Sid = "$domainSid-521"; Root = $false; Tier = 'Tier0'; Required = $false }
        @{ Label = 'Cert Publishers';              Sid = "$domainSid-517"; Root = $false; Tier = 'Tier0'; Required = $true }
        @{ Label = 'Schema Admins';                Sid = "$rootSid-518";   Root = $true;  Tier = 'Tier0'; Required = $true }
        @{ Label = 'Enterprise Admins';            Sid = "$rootSid-519";   Root = $true;  Tier = 'Tier0'; Required = $true }
        @{ Label = 'Enterprise Key Admins';        Sid = "$rootSid-527";   Root = $true;  Tier = 'Tier0'; Required = $false }
        @{ Label = 'Enterprise Read-only Domain Controllers'; Sid = "$rootSid-498"; Root = $true; Tier = 'Tier0'; Required = $false }
        @{ Label = 'Administrators';               Sid = 'S-1-5-32-544';   Root = $false; Tier = 'Tier0'; Required = $true }
        @{ Label = 'Account Operators';            Sid = 'S-1-5-32-548';   Root = $false; Tier = 'Tier0'; Required = $true }
        @{ Label = 'Server Operators';             Sid = 'S-1-5-32-549';   Root = $false; Tier = 'Tier0'; Required = $true }
        @{ Label = 'Print Operators';              Sid = 'S-1-5-32-550';   Root = $false; Tier = 'Tier0'; Required = $true }
        @{ Label = 'Backup Operators';             Sid = 'S-1-5-32-551';   Root = $false; Tier = 'Tier0'; Required = $true }
        @{ Label = 'Cryptographic Operators';      Sid = 'S-1-5-32-569';   Root = $false; Tier = 'Tier0'; Required = $false }
        @{ Label = 'Hyper-V Administrators';       Sid = 'S-1-5-32-578';   Root = $false; Tier = 'Tier0'; Required = $false }
        @{ Label = 'Remote Desktop Users';         Sid = 'S-1-5-32-555';   Root = $false; Tier = 'Tier1-access'; Required = $false }
        @{ Label = 'Remote Management Users';      Sid = 'S-1-5-32-580';   Root = $false; Tier = 'Tier1-access'; Required = $false }
        @{ Label = 'Event Log Readers';            Sid = 'S-1-5-32-573';   Root = $false; Tier = 'Info'; Required = $false }
        @{ Label = 'Protected Users';              Sid = "$domainSid-525"; Root = $false; Tier = 'Info'; Required = $false }
    )
    $groups = [System.Collections.Generic.List[object]]::new()
    $groupDNs = @{}
    foreach ($spec in $groupSpecs) {
        if ($spec.Root -and -not $rootSid) { continue }
        try {
            $p = $(if ($spec.Root) { $rootParams } else { $script:AdParams })
            $g = Get-ADGroup -Identity $spec.Sid @p
            if (-not $groupDNs.ContainsKey($g.DistinguishedName)) {
                $groupDNs[$g.DistinguishedName] = $true
                $groups.Add([pscustomobject]@{ Label = $spec.Label; DN = $g.DistinguishedName; Source = 'Built-in protected'; Tier = $spec.Tier })
            }
        }
        catch {
            if ($spec.Required -or -not (Test-NotFound $_)) { Add-Gap ("Group {0} ({1}) could not be read: {2}" -f $spec.Label, $spec.Sid, $_.Exception.Message) }
            else { Write-RunLog ("Group {0} ({1}) not present; skipped." -f $spec.Label, $spec.Sid) }
        }
    }
    $named = @(@{ Name = 'DnsAdmins'; Tier = 'Tier0'; Source = 'Built-in'; TryRoot = $false }
        @{ Name = 'DHCP Administrators'; Tier = 'Tier1-access'; Source = 'Built-in (DHCP)'; TryRoot = $false })
    foreach ($n in $ExchangeGroupNames) { $named += @{ Name = $n; Tier = 'Tier0'; Source = 'Exchange (product default)'; TryRoot = $true } }
    foreach ($n in @($AdditionalPrivilegedGroups | Where-Object { $_ })) { $named += @{ Name = $n; Tier = 'Tier0'; Source = 'Additional (config)'; TryRoot = $false; Required = $true } }
    foreach ($n in $named) {
        $tryList = @(, $script:AdParams)
        if ($n.TryRoot -and $rootSid -and $rootDns -ne $script:DomainDns) { $tryList += , $rootParams }
        $found = $null; $lastErr = ''
        foreach ($p in $tryList) {
            try { $found = Get-ADGroup -Identity $n.Name @p; break }
            catch { if (-not (Test-NotFound $_)) { $lastErr = $_.Exception.Message } }
        }
        if ($found) {
            if (-not $groupDNs.ContainsKey($found.DistinguishedName)) {
                $groupDNs[$found.DistinguishedName] = $true
                $groups.Add([pscustomobject]@{ Label = [string]$found.Name; DN = $found.DistinguishedName; Source = $n.Source; Tier = $n.Tier })
            }
        }
        elseif ($n.TryRoot -and -not $rootSid -and $rootDns -ne $script:DomainDns) { Add-Gap ("Group '{0}' not in this domain and the forest root could not be read" -f $n.Name) }
        elseif ($lastErr -or $n.Required) { Add-Gap ("Group '{0}' could not be read: {1}" -f $n.Name, $(if ($lastErr) { $lastErr } else { 'not found' })) }
        else { Write-RunLog ("Group '{0}' not present; skipped." -f $n.Name) }
    }

    # ---- 1. Expand membership with nesting path (member attribute + primaryGroupID) ----
    $memberRows = [System.Collections.Generic.List[object]]::new()
    $script:PrimaryCache = @{}
    function New-MemberRow {
        param($Label, $Tier, $Sam, $Name, $Class, $Depth, $Path, $DN)
        [pscustomobject][ordered]@{ PrivilegedGroup = $Label; MemberSam = $Sam; MemberName = $Name; MemberClass = $Class; Depth = $Depth; NestingPath = $Path; DistinguishedName = $DN; Tier = $Tier }
    }
    function Get-PrimaryGroupMember {
        # Accounts whose primaryGroupID is this group's RID are members but are not listed in 'member'.
        param($GroupObj)
        $gdn = [string]$GroupObj.distinguishedName
        if ($script:PrimaryCache.ContainsKey($gdn)) { return $script:PrimaryCache[$gdn] }
        $res = @()
        $sid = Get-SidText $GroupObj
        if ($sid -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') {
            $rid = [int]$Matches[1]
            if ($rid -in 513, 514, 515) { Add-Gap ("{0} is nested in a privileged group: its primaryGroupID members (normally every user or computer) are not listed" -f $GroupObj.name) }
            else {
                $p = Get-ParamsForDN $gdn
                try { $res = @(Get-ADObject -LDAPFilter "(primaryGroupID=$rid)" -Properties $AccountProps @p) }
                catch { Add-Gap ("primaryGroupID members of {0} could not be read: {1}" -f $GroupObj.name, $_.Exception.Message) }
            }
        }
        $script:PrimaryCache[$gdn] = $res
        return $res
    }
    function Expand-Group {
        param([string]$GroupLabel, [string]$Tier, [string]$DN, [string[]]$Path, [string[]]$PathDN, [int]$Depth)
        $grp = Get-AdObjectCached $DN
        if (-not $grp) { return }
        $pathText = $Path -join ' > '
        foreach ($m in @($grp.member)) {
            if (-not $m) { continue }
            $o = Get-AdObjectCached $m
            if (-not $o) {
                $memberRows.Add((New-MemberRow -Label $GroupLabel -Tier $Tier -Sam '' -Name $m -Class 'unresolved (read failed)' -Depth $Depth -Path $pathText -DN $m))
                continue
            }
            $class = [string]@($o.objectClass)[-1]
            if ($class -eq 'group') {
                if ($PathDN -contains [string]$o.distinguishedName) { Write-RunLog ("Circular nesting detected under {0}: {1}" -f $GroupLabel, (($Path + [string]$o.name) -join ' > ')) 'WARN'; continue }
                $memberRows.Add((New-MemberRow -Label $GroupLabel -Tier $Tier -Sam $o.sAMAccountName -Name $o.name -Class 'group' -Depth $Depth -Path $pathText -DN $o.distinguishedName))
                Expand-Group -GroupLabel $GroupLabel -Tier $Tier -DN $o.distinguishedName -Path ($Path + [string]$o.name) -PathDN ($PathDN + [string]$o.distinguishedName) -Depth ($Depth + 1)
            }
            elseif ($class -eq 'foreignSecurityPrincipal') {
                $sid = Get-SidText $o
                if (-not $sid) { $sid = [string]$o.name }
                $nt = Resolve-ForeignSid $sid
                $memberRows.Add((New-MemberRow -Label $GroupLabel -Tier $Tier -Sam $nt -Name $(if ($nt) { $nt } else { $sid }) -Class $class -Depth $Depth -Path $pathText -DN $o.distinguishedName))
            }
            else {
                $memberRows.Add((New-MemberRow -Label $GroupLabel -Tier $Tier -Sam $o.sAMAccountName -Name $o.name -Class $class -Depth $Depth -Path $pathText -DN $o.distinguishedName))
            }
        }
        foreach ($o in @(Get-PrimaryGroupMember $grp)) {
            if (-not $o) { continue }
            $script:ObjCache[[string]$o.distinguishedName] = $o
            $memberRows.Add((New-MemberRow -Label $GroupLabel -Tier $Tier -Sam $o.sAMAccountName -Name $o.name -Class ([string]@($o.objectClass)[-1]) -Depth $Depth -Path ($pathText + ' (primaryGroupID)') -DN $o.distinguishedName))
        }
    }
    foreach ($g in $groups) { Expand-Group -GroupLabel $g.Label -Tier $g.Tier -DN $g.DN -Path @($g.Label) -PathDN @($g.DN) -Depth 1 }
    $membershipGaps = $script:Gaps.Count
    $membershipStatus = $(if ($membershipGaps) { 'Partial' } else { 'Completed' })
    $gapNote = $(if ($membershipGaps) { ("; PARTIAL: {0} read gap(s) - a group, member or domain could not be read (see run.log): {1}" -f $membershipGaps, ((@($script:Gaps) | Select-Object -First 3) -join ' | ')) } else { '' })
    Export-Dataset -Name 'ad-privileged-membership' -Rows $memberRows -Status $membershipStatus -Note ("{0} privileged groups expanded; Depth 1 = direct member; Tier on every row{1}" -f $groups.Count, $gapNote)

    # ---- 2. Per privileged account ----
    $accountClasses = @('user', 'computer', 'msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount', 'inetOrgPerson', 'foreignSecurityPrincipal')
    $privDN = @{}; $tierOf = @{}; $protectedUsers = @{}
    foreach ($r in $memberRows) {
        if ($r.MemberClass -notin $accountClasses) { continue }
        $dn = [string]$r.DistinguishedName
        if ($r.PrivilegedGroup -eq 'Protected Users') { $protectedUsers[$dn] = $true; continue }
        if (-not $privDN.ContainsKey($dn)) { $privDN[$dn] = [System.Collections.Generic.List[string]]::new(); $tierOf[$dn] = $r.Tier }
        elseif ($TierRank[$r.Tier] -lt $TierRank[$tierOf[$dn]]) { $tierOf[$dn] = $r.Tier }
        $via = $(if ($r.NestingPath -like '*(primaryGroupID)') { '{0} (primaryGroupID)' -f $r.PrivilegedGroup } elseif ($r.Depth -gt 1) { '{0} (nested: {1})' -f $r.PrivilegedGroup, $r.NestingPath } else { $r.PrivilegedGroup })
        $privDN[$dn].Add($via)
    }
    $tier0Set = @{}
    foreach ($dn in $privDN.Keys) { if ($tierOf[$dn] -eq 'Tier0') { $tier0Set[$dn] = $true } }

    $privRows = foreach ($dn in $privDN.Keys) {
        $obj = Get-AdObjectCached $dn
        if (-not $obj) { continue }
        $info = ConvertTo-AccountInfo $obj
        $uac = Get-UacValue $obj
        $isFsp = ($info.ObjectClass -eq 'foreignSecurityPrincipal')
        $flags = @()
        if ($isFsp) {
            $sid = Get-SidText $obj
            if (-not $sid) { $sid = [string]$obj.name }
            $nt = Resolve-ForeignSid $sid
            $info.SamAccountName = $(if ($nt) { $nt } else { $sid })
            $info.Name = $(if ($nt) { $nt } else { "$sid (not translated)" })
            foreach ($blank in 'Enabled', 'Stale', 'PasswordNeverExpires', 'KerberosPreAuthDisabled', 'UnconstrainedDelegation', 'ProtocolTransition', 'HasSpn') { $info.$blank = '' }
            $flags += 'ForeignPrincipal'
            if ($sid -notlike 'S-1-5-21-*') { $flags += 'WellKnownPrincipal' }
        }
        else {
            if (-not $info.Enabled) { $flags += 'Disabled' }
            if ($info.Enabled -and $info.Stale) { $flags += "NoLogon${StaleDays}d" }
            if ($info.PasswordNeverExpires) { $flags += 'PasswordNeverExpires' }
            if ($info.PasswordAgeDays -ne '' -and $info.PasswordAgeDays -gt $PasswordAgeWarningDays) { $flags += "PasswordOlderThan${PasswordAgeWarningDays}d" }
            if ($info.HasSpn -and $info.ObjectClass -eq 'user') { $flags += 'SpnOnPrivilegedUser(Kerberoastable)' }
            if ($info.KerberosPreAuthDisabled) { $flags += 'PreAuthDisabled' }
            if ($info.UnconstrainedDelegation -and $info.ObjectClass -eq 'user') { $flags += 'UnconstrainedDelegation' }
        }
        if (@($privDN[$dn] | Where-Object { $_ -match 'nested' }).Count) { $flags += 'NestedOnly' }
        if (@($privDN[$dn] | Where-Object { $_ -notmatch 'nested' }).Count) { $flags = @($flags | Where-Object { $_ -ne 'NestedOnly' }) }
        $viaText = Join-Values ($privDN[$dn] | Sort-Object -Unique)
        $o = [ordered]@{ PrivilegedVia = $viaText; Flags = Join-Values $flags }
        foreach ($p in $info.PSObject.Properties) { $o[$p.Name] = $p.Value }
        $o['Tier'] = $tierOf[$dn]
        $o['IsAdminNamed'] = $(if ($isFsp) { '' } else { Test-AdminName ([string]$obj.sAMAccountName) })
        $o['Category'] = Get-AccountCategory $obj $viaText
        $o['InProtectedUsers'] = $protectedUsers.ContainsKey($dn)
        $o['AccountNotDelegated'] = $(if ($isFsp) { '' } else { [bool]($uac -band $UacBits.NotDelegated) })
        $o['SIDHistoryPresent'] = (@($obj.sIDHistory | Where-Object { $_ }).Count -gt 0)
        $o['msDS-SupportedEncryptionTypes'] = $(if ($null -ne $obj.'msDS-SupportedEncryptionTypes') { $obj.'msDS-SupportedEncryptionTypes' } else { '' })
        [pscustomobject]$o
    }
    $privRows = @($privRows | Sort-Object -Property @{ Expression = { $TierRank[$_.Tier] } }, @{ Expression = 'SamAccountName' })
    Export-Dataset -Name 'ad-privileged-accounts' -Rows $privRows -Status $membershipStatus -Note ("Tier0 = domain / forest control; Tier1-access = logon or service rights; Info = low (Event Log Readers). Protected Users members are not listed here{0}" -f $gapNote)
    $privT0 = @($privRows | Where-Object { $_.Tier -eq 'Tier0' })

    # ---- 3. Service-account candidates ----
    $svc = @{}   # DN -> @{ Obj; Reasons }
    function Add-Candidate { param($Obj, [string]$Reason) if (-not $Obj) { return }; $dn = $Obj.distinguishedName; if (-not $svc.ContainsKey($dn)) { $svc[$dn] = @{ Obj = $Obj; Reasons = [System.Collections.Generic.List[string]]::new() } }; if (-not $svc[$dn].Reasons.Contains($Reason)) { $svc[$dn].Reasons.Add($Reason) } }
    $searchParams = @{} + $script:AdParams
    if ($SearchBase) { $searchParams['SearchBase'] = $SearchBase }
    $userBase = '(objectCategory=person)(objectClass=user)'
    $detections = @(
        @{ Reason = 'HasSPN';               Filter = "(&$userBase(servicePrincipalName=*))" }
        @{ Reason = 'PasswordNeverExpires'; Filter = "(&$userBase(userAccountControl:1.2.840.113556.1.4.803:=65536))" }
        @{ Reason = 'DescriptionMentionsService'; Filter = "(&$userBase(|(description=*service*)(description=*svc*)))" }
    )
    foreach ($pattern in $ServiceNamePatterns) { $detections += @{ Reason = "NamePattern:$pattern"; Filter = "(&$userBase(sAMAccountName=$pattern))" } }
    $svcFailed = [System.Collections.Generic.List[string]]::new()
    foreach ($d in $detections) {
        try { foreach ($o in (Get-ADObject -LDAPFilter $d.Filter -Properties $AccountProps @searchParams)) { Add-Candidate $o $d.Reason } }
        catch { $svcFailed.Add($d.Reason); Write-RunLog ("Detection '{0}' failed: {1}" -f $d.Reason, $_.Exception.Message) 'WARN' }
    }
    try { foreach ($o in (Get-ADObject -LDAPFilter '(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))' -Properties $AccountProps @script:AdParams)) { Add-Candidate $o 'ManagedServiceAccount(gMSA/sMSA)' } }
    catch { $svcFailed.Add('ManagedServiceAccount'); Write-RunLog ("Managed service account query failed: {0}" -f $_.Exception.Message) 'WARN' }

    $svcRows = foreach ($dn in $svc.Keys) {
        $info = ConvertTo-AccountInfo $svc[$dn].Obj
        $o = [ordered]@{
            DetectionReasons = Join-Values $svc[$dn].Reasons
            ReasonCount      = $svc[$dn].Reasons.Count
            IsPrivileged     = $tier0Set.ContainsKey($dn)
            PrivilegedVia    = $(if ($privDN.ContainsKey($dn)) { Join-Values ($privDN[$dn] | Sort-Object -Unique) } else { '' })
        }
        foreach ($p in $info.PSObject.Properties) { $o[$p.Name] = $p.Value }
        [pscustomobject]$o
    }
    $svcRows = @($svcRows | Sort-Object -Property @{ Expression = 'IsPrivileged'; Descending = $true }, @{ Expression = 'ReasonCount'; Descending = $true })
    Export-Dataset -Name 'ad-service-account-candidates' -Rows $svcRows -Status $(if ($svcFailed.Count) { 'Partial' } else { 'Completed' }) -Note ('Candidates only - confirm with owners. One account can match several detections. IsPrivileged = Tier 0.' + $(if ($svcFailed.Count) { ' PARTIAL: detections failed: ' + ($svcFailed -join ', ') } else { '' }))

    # ---- 4. AdminSDHolder leftovers (users, computers and groups) ----
    $tier0GroupDNs = @{}
    foreach ($g in $groups) { if ($g.Tier -eq 'Tier0') { $tier0GroupDNs[$g.DN] = $true } }
    foreach ($r in $memberRows) { if ($r.Tier -eq 'Tier0' -and $r.MemberClass -eq 'group') { $tier0GroupDNs[[string]$r.DistinguishedName] = $true } }
    $orphanRows = @()
    $orphanRead = $true
    try {
        $adminCountObjs = Get-ADObject -LDAPFilter '(&(adminCount=1)(|(objectClass=user)(objectClass=group)))' -Properties $AccountProps @script:AdParams
        $orphanRows = @(foreach ($o in $adminCountObjs) {
                $dn = [string]$o.distinguishedName
                if ($tier0Set.ContainsKey($dn) -or $tier0GroupDNs.ContainsKey($dn)) { continue }
                if ((Get-SidText $o) -match '-502$') { continue }      # krbtgt: protected by default, not through a group
                $i = ConvertTo-AccountInfo $o
                if ($i.ObjectClass -eq 'group') { foreach ($blank in 'Enabled', 'LastLogonUtc', 'DaysSinceLogon', 'Stale', 'PasswordLastSetUtc', 'PasswordAgeDays', 'PasswordNeverExpires', 'KerberosPreAuthDisabled', 'UnconstrainedDelegation', 'ProtocolTransition') { $i.$blank = '' } }
                $i
            })
        Export-Dataset -Name 'ad-admincount-orphans' -Rows $orphanRows -Status $membershipStatus -Note ('adminCount=1 users, computers and groups not in any expanded Tier 0 group: inheritance may still be blocked on these objects' + $(if ($membershipGaps) { '. PARTIAL: membership had read gaps, so some of these may still be protected' } else { '' }))
    }
    catch { $orphanRead = $false; Set-DatasetStatus -Name 'ad-admincount-orphans' -Status 'Blocked' -Note $_.Exception.Message }

    # ---- 5. Domain-wide risky account settings ----
    $riskRows = [System.Collections.Generic.List[object]]::new()
    $riskFailed = [System.Collections.Generic.List[string]]::new()
    $riskChecks = @()
    if (-not $SkipRiskFlags) {
        function Add-RiskRow {
            param($Obj, [string]$Flag, [string]$Detail)
            $dn = [string]$Obj.distinguishedName
            $uac = Get-UacValue $Obj
            $via = $(if ($privDN.ContainsKey($dn)) { Join-Values $privDN[$dn] } else { '' })
            $riskRows.Add([pscustomobject][ordered]@{
                    SamAccountName    = [string]$Obj.sAMAccountName
                    ObjectClass       = [string]@($Obj.objectClass)[-1]
                    Enabled           = -not ($uac -band $UacBits.Disabled)
                    Flag              = $Flag
                    Detail            = $Detail
                    IsPrivileged      = $tier0Set.ContainsKey($dn)
                    IsAdminNamed      = Test-AdminName ([string]$Obj.sAMAccountName)
                    Category          = Get-AccountCategory $Obj $via
                    PwdLastSetUtc     = Format-FileTimeUtc $Obj.pwdLastSet
                    LastLogonUtc      = Format-FileTimeUtc $Obj.lastLogonTimestamp
                    DistinguishedName = $dn
                })
        }
        $cutoff = $script:RunStartUtc.AddDays(-$PasswordAgeWarningDays).ToFileTimeUtc()
        $riskChecks = @(
            @{ Flag = 'UnconstrainedDelegation';     Filter = ('(&{0}(userAccountControl:{1}:={2}))' -f $AccountTypeFilter, $BitAnd, $UacBits.TrustedForDelegation) }
            @{ Flag = 'ProtocolTransition';          Filter = ('(&{0}(userAccountControl:{1}:={2}))' -f $AccountTypeFilter, $BitAnd, $UacBits.TrustedToAuthForDelegation) }
            @{ Flag = 'ConstrainedDelegation';       Filter = ('(&{0}(msDS-AllowedToDelegateTo=*))' -f $AccountTypeFilter) }
            @{ Flag = 'ResourceBasedDelegation';     Filter = ('(&{0}(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' -f $AccountTypeFilter) }
            @{ Flag = 'PreAuthNotRequired';          Filter = ('(&{0}(userAccountControl:{1}:={2}))' -f $AccountTypeFilter, $BitAnd, $UacBits.NoPreAuth) }
            @{ Flag = 'PasswordNotRequired';         Filter = ('(&{0}(userAccountControl:{1}:={2}))' -f $AccountTypeFilter, $BitAnd, $UacBits.PasswordNotRequired) }
            @{ Flag = 'ReversibleEncryption';        Filter = ('(&{0}(userAccountControl:{1}:={2}))' -f $AccountTypeFilter, $BitAnd, $UacBits.ReversibleEncryption) }
            @{ Flag = 'DesOnly';                     Filter = ('(&{0}(userAccountControl:{1}:={2}))' -f $AccountTypeFilter, $BitAnd, $UacBits.DesOnly) }
            @{ Flag = 'PasswordNeverExpiresAndOld';  Filter = ('(&{0}(userAccountControl:{1}:={2})(pwdLastSet<={3}))' -f $AccountTypeFilter, $BitAnd, $UacBits.PasswordNeverExpires, $cutoff) }
            @{ Flag = 'SIDHistory';                  Filter = ('(&{0}(sIDHistory=*))' -f $AccountTypeFilter) }
            @{ Flag = 'KeyCredentialOnUser';         Filter = ('(&{0}(msDS-KeyCredentialLink=*))' -f $UserTypeFilter) }
            @{ Flag = 'Kerberoastable';              Filter = ('(&{0}(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(sAMAccountName=krbtgt_*)))' -f $UserTypeFilter) }
        )
        Write-RunLog ("Checking {0} risky account settings domain-wide..." -f $riskChecks.Count)
        foreach ($c in $riskChecks) {
            try {
                $found = @(Get-ADObject -LDAPFilter $c.Filter -Properties $AccountProps -ResultPageSize 500 @script:AdParams)
                foreach ($o in $found) {
                    $uac = Get-UacValue $o
                    $flag = $c.Flag; $detail = ''
                    switch ($c.Flag) {
                        'UnconstrainedDelegation' {
                            if (($uac -band $UacBits.ServerTrust) -or "$($o.primaryGroupID)" -eq '516') { $flag = 'UnconstrainedDelegation-DomainController'; $detail = 'Expected on domain controllers' }
                            else { $detail = 'Any account that authenticates to it leaves a reusable ticket-granting ticket' }
                        }
                        'ProtocolTransition' {
                            if (($uac -band $UacBits.ServerTrust) -or ($uac -band $UacBits.PartialSecrets) -or "$($o.primaryGroupID)" -in '516', '521') { $flag = 'ProtocolTransition-DomainController'; $detail = 'Set by default on read-only domain controllers' }
                            else { $t = Join-Values $o.'msDS-AllowedToDelegateTo'; $detail = $(if ($t) { "Can obtain tickets as any user to: $t" } else { 'Protocol transition set, no msDS-AllowedToDelegateTo targets' }) }
                        }
                        'ConstrainedDelegation' { $detail = 'Targets: ' + (Join-Values $o.'msDS-AllowedToDelegateTo') }
                        'ResourceBasedDelegation' { $detail = 'msDS-AllowedToActOnBehalfOfOtherIdentity is set: other principals can delegate to this account (not decoded)' }
                        'PreAuthNotRequired' { $detail = 'AS-REP roastable: an offline-crackable reply can be requested without a password' }
                        'PasswordNotRequired' { $detail = 'PASSWD_NOTREQD: an empty password may be allowed' }
                        'ReversibleEncryption' { $detail = 'Password stored with reversible encryption after the next change' }
                        'DesOnly' { $detail = 'USE_DES_KEY_ONLY: weak Kerberos encryption' }
                        'PasswordNeverExpiresAndOld' { $pw = ConvertFrom-FileTime $o.pwdLastSet; $detail = $(if ($pw) { "Password never expires; last set {0} days ago" -f [int]($script:RunStartUtc - $pw).TotalDays } else { 'Password never expires; never set' }) }
                        'SIDHistory' {
                            $parts = foreach ($s in @($o.sIDHistory | Where-Object { $_ })) {
                                $t = "$s"; $ann = @()
                                if ($domainSid -and $t -like "$domainSid-*") { $ann += 'same-domain SID' }
                                if ($t -match '-(\d+)$' -and [int]$Matches[1] -in $PrivilegedRids) { $ann += 'privileged RID' }
                                if ($ann.Count) { '{0} ({1})' -f $t, ($ann -join ', ') } else { $t }
                            }
                            $detail = Join-Values $parts
                        }
                        'KeyCredentialOnUser' { $detail = 'msDS-KeyCredentialLink present (also written by Windows Hello for Business key trust and device registration): confirm the source' }
                        'Kerberoastable' {
                            $et = "$($o.'msDS-SupportedEncryptionTypes')"
                            $enc = $(if ($et -eq '') { 'msDS-SupportedEncryptionTypes not set (domain default applies; RC4 tickets often still issued)' } elseif ([int64]$et -band 24) { "msDS-SupportedEncryptionTypes=$et (AES enabled)" } else { "msDS-SupportedEncryptionTypes=$et (no AES)" })
                            $detail = 'SPNs: {0}; {1}' -f @($o.servicePrincipalName | Where-Object { $_ }).Count, $enc
                        }
                    }
                    Add-RiskRow -Obj $o -Flag $flag -Detail $detail
                }
            }
            catch { $riskFailed.Add($c.Flag); Write-RunLog ("Risk check '{0}' failed (not reported as none): {1}" -f $c.Flag, $_.Exception.Message) 'WARN' }
        }
        # Enabled Tier 0 user accounts without "Account is sensitive and cannot be delegated" and not in Protected Users
        foreach ($dn in $tier0Set.Keys) {
            $obj = Get-AdObjectCached $dn
            if (-not $obj) { continue }
            if ([string]@($obj.objectClass)[-1] -notin 'user', 'inetOrgPerson') { continue }
            $uac = Get-UacValue $obj
            if ($uac -band $UacBits.Disabled) { continue }
            if (($uac -band $UacBits.NotDelegated) -or $protectedUsers.ContainsKey($dn)) { continue }
            Add-RiskRow -Obj $obj -Flag 'SensitiveNotDelegatedMissing' -Detail 'Tier 0 account not marked "Account is sensitive and cannot be delegated" and not in Protected Users'
        }
        $riskStatus = $(if ($riskFailed.Count -eq $riskChecks.Count) { 'Blocked' } elseif ($riskFailed.Count) { 'Partial' } else { 'Completed' })
        Export-Dataset -Name 'ad-account-risk-flags' -Rows $riskRows -Status $riskStatus -Note ('Domain-wide, every user and computer account; one row per account and flag. IsPrivileged = Tier 0.' + $(if ($riskFailed.Count) { ' PARTIAL: checks that failed (no result, not none): ' + ($riskFailed -join ', ') } else { '' }))
    }
    else { Set-DatasetStatus -Name 'ad-account-risk-flags' -Status 'Deferred' -Note 'Skipped (-SkipRiskFlags)' }

    # ---- 6. Age of the domain secrets ----
    $secretRows = [System.Collections.Generic.List[object]]::new()
    $secretFailed = [System.Collections.Generic.List[string]]::new()
    function Add-SecretRow {
        param($Obj, [string]$Kind, [string]$Detail, [string]$Account = '')
        $pw = $null; $uac = 0
        if ($Obj) { $pw = ConvertFrom-FileTime $Obj.pwdLastSet; $uac = Get-UacValue $Obj }
        $secretRows.Add([pscustomobject][ordered]@{
                Account           = $(if ($Obj) { [string]$Obj.sAMAccountName } else { $Account })
                Kind              = $Kind
                Enabled           = $(if ($Obj) { -not ($uac -band $UacBits.Disabled) } else { '' })
                PwdLastSetUtc     = $(if ($pw) { $pw.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                AgeDays           = $(if ($pw) { [int]($script:RunStartUtc - $pw).TotalDays } else { '' })
                LastLogonUtc      = $(if ($Obj) { Format-FileTimeUtc $Obj.lastLogonTimestamp } else { '' })
                Detail            = $Detail
                DistinguishedName = $(if ($Obj) { [string]$Obj.distinguishedName } else { '' })
            })
    }
    try {
        $k = @(Get-ADObject -LDAPFilter '(|(sAMAccountName=krbtgt)(sAMAccountName=krbtgt_*))' -Properties $AccountProps @script:AdParams)
        if (-not @($k | Where-Object { $_.sAMAccountName -eq 'krbtgt' }).Count) { $secretFailed.Add('krbtgt (not returned)') }
        foreach ($o in $k) {
            if ($o.sAMAccountName -eq 'krbtgt') { Add-SecretRow -Obj $o -Kind 'krbtgt' -Detail 'Key that signs every Kerberos ticket-granting ticket in the domain' }
            else { Add-SecretRow -Obj $o -Kind 'krbtgt (RODC)' -Detail 'Key used by one read-only domain controller' }
        }
    }
    catch { $secretFailed.Add('krbtgt'); Write-RunLog ("krbtgt not readable: {0}" -f $_.Exception.Message) 'WARN' }
    try {
        $a = @(Get-ADObject -LDAPFilter "(objectSid=$domainSid-500)" -Properties $AccountProps @script:AdParams)
        if ($a.Count) { Add-SecretRow -Obj $a[0] -Kind 'Built-in Administrator (RID 500)' -Detail 'Built-in administrator: cannot be locked out' } else { $secretFailed.Add('Built-in Administrator (not returned)') }
    }
    catch { $secretFailed.Add('Built-in Administrator'); Write-RunLog ("Built-in Administrator not readable: {0}" -f $_.Exception.Message) 'WARN' }
    try {
        $s = @(Get-ADObject -LDAPFilter '(sAMAccountName=AZUREADSSOACC$)' -Properties $AccountProps @script:AdParams)
        if ($s.Count) { Add-SecretRow -Obj $s[0] -Kind 'Seamless SSO computer account' -Detail 'Kerberos decryption key for Entra Seamless SSO: roll it over regularly' }
        else { Add-SecretRow -Obj $null -Kind 'Seamless SSO computer account' -Detail 'Not present in this domain (Seamless SSO not configured here)' -Account 'AZUREADSSOACC$' }
    }
    catch { $secretFailed.Add('AZUREADSSOACC$'); Write-RunLog ("AZUREADSSOACC$ lookup failed: {0}" -f $_.Exception.Message) 'WARN' }
    Export-Dataset -Name 'ad-domain-secrets-age' -Rows $secretRows -Status $(if ($secretFailed.Count) { 'Partial' } else { 'Completed' }) -Note $(if ($secretFailed.Count) { 'PARTIAL: not read: ' + ($secretFailed -join ', ') } else { 'AgeDays = days since the password (key) was last set' })

    # ---- 7. Who can retrieve each gMSA password ----
    $gmsaRows = [System.Collections.Generic.List[object]]::new()
    $gmsaCount = 0; $gmsaRead = $true
    try {
        $gmsas = @(Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, sAMAccountName, objectClass @script:AdParams | Where-Object { [string]@($_.ObjectClass)[-1] -eq 'msDS-GroupManagedServiceAccount' })
        $gmsaCount = $gmsas.Count
        $gmsaGaps = 0
        function Add-GmsaRow {
            param($Gmsa, [string]$GrantedTo, [string]$GrantedToClass, $Principal, [string]$Via, [string]$Status, [string]$PrincipalDN = '')
            $pcls = ''; $pen = ''; $pname = ''
            if ($Principal) {
                $pcls = [string]@($Principal.objectClass)[-1]
                $pname = $(if ($Principal.sAMAccountName) { [string]$Principal.sAMAccountName } else { [string]$Principal.name })
                if ($pcls -ne 'group') { $pen = -not ((Get-UacValue $Principal) -band $UacBits.Disabled) }
                $PrincipalDN = [string]$Principal.distinguishedName
            }
            $gmsaRows.Add([pscustomobject][ordered]@{
                    GmsaSamAccountName = [string]$Gmsa.SamAccountName
                    GmsaEnabled        = $Gmsa.Enabled
                    GrantedTo          = $GrantedTo
                    GrantedToClass     = $GrantedToClass
                    Principal          = $pname
                    PrincipalClass     = $pcls
                    PrincipalEnabled   = $pen
                    Via                = $Via
                    IsPrivileged       = $(if ($PrincipalDN) { $tier0Set.ContainsKey($PrincipalDN) } else { '' })
                    IsAdminNamed       = $(if ($pname -and $pcls -ne 'group') { Test-AdminName $pname } else { '' })
                    Status             = $Status
                    PrincipalDN        = $PrincipalDN
                })
        }
        foreach ($g in $gmsas) {
            $readers = @($g.PrincipalsAllowedToRetrieveManagedPassword | Where-Object { $_ })
            if (-not $readers.Count) { Add-GmsaRow -Gmsa $g -GrantedTo '' -GrantedToClass '' -Principal $null -Via '' -Status 'NoReadersListed (or not readable by the run account)'; continue }
            foreach ($rdn in $readers) {
                $ro = Get-AdObjectCached ([string]$rdn)
                if (-not $ro) { $gmsaGaps++; Add-GmsaRow -Gmsa $g -GrantedTo ([string]$rdn) -GrantedToClass '' -Principal $null -Via '' -Status 'Unresolved' -PrincipalDN ([string]$rdn); continue }
                $rcls = [string]@($ro.objectClass)[-1]
                $rname = $(if ($ro.sAMAccountName) { [string]$ro.sAMAccountName } else { [string]$ro.name })
                Add-GmsaRow -Gmsa $g -GrantedTo $rname -GrantedToClass $rcls -Principal $ro -Via 'Direct' -Status 'Resolved'
                if ($rcls -eq 'group') {
                    $p = Get-ParamsForDN ([string]$rdn)
                    try {
                        $members = @(Get-ADObject -LDAPFilter ('(&(objectClass=user)(memberOf:{0}:={1}))' -f $InChain, (ConvertTo-LdapValue ([string]$rdn))) -Properties $AccountProps @p)
                        foreach ($m in $members) { Add-GmsaRow -Gmsa $g -GrantedTo $rname -GrantedToClass $rcls -Principal $m -Via "Member of $rname (direct or nested)" -Status 'Resolved' }
                    }
                    catch { $gmsaGaps++; Add-GmsaRow -Gmsa $g -GrantedTo $rname -GrantedToClass $rcls -Principal $null -Via '' -Status ("ExpansionFailed: {0}" -f $_.Exception.Message) -PrincipalDN ([string]$rdn); Write-RunLog ("Members of gMSA reader group {0} not readable: {1}" -f $rname, $_.Exception.Message) 'WARN' }
                }
            }
        }
        Export-Dataset -Name 'ad-gmsa-password-readers' -Rows $gmsaRows -Status $(if ($gmsaGaps) { 'Partial' } else { 'Completed' }) -Note ("{0} gMSAs; groups expanded to every user and computer account in the chain{1}" -f $gmsaCount, $(if ($gmsaGaps) { "; PARTIAL: $gmsaGaps principal(s) or group(s) could not be read" } else { '' }))
    }
    catch { $gmsaRead = $false; Set-DatasetStatus -Name 'ad-gmsa-password-readers' -Status 'Blocked' -Note ("gMSAs not readable: {0}" -f $_.Exception.Message) }

    # ---- 8. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric -Metric 'Privileged groups expanded' -Value $groups.Count -Note ("Tier0 {0}; Tier1-access {1}; Info {2}" -f @($groups | Where-Object Tier -eq 'Tier0').Count, @($groups | Where-Object Tier -eq 'Tier1-access').Count, @($groups | Where-Object Tier -eq 'Info').Count)
    Add-Metric -Metric 'Membership read gaps' -Value $membershipGaps -Note $(if ($membershipGaps) { 'Membership datasets are Partial: see run.log' } else { '' })
    Add-Metric 'Max nesting depth in privileged groups' $(if ($memberRows.Count) { ($memberRows | Measure-Object Depth -Maximum).Maximum } else { 0 })
    Add-Metric -Metric 'Distinct privileged accounts' -Value $privT0.Count -Note 'Tier 0'
    Add-Metric -Metric 'Privileged accounts enabled' -Value @($privT0 | Where-Object { $_.Enabled -eq $true }).Count -Note 'Tier 0'
    Add-Metric -Metric 'Privileged accounts privileged only through nesting' -Value @($privT0 | Where-Object { $_.Flags -match 'NestedOnly' }).Count -Note 'Tier 0'
    Add-Metric -Metric "Enabled privileged accounts with no logon in $StaleDays days" -Value @($privT0 | Where-Object { $_.Flags -match 'NoLogon' }).Count -Note 'Tier 0'
    Add-Metric -Metric 'Privileged accounts with password never expires' -Value @($privT0 | Where-Object { $_.PasswordNeverExpires -eq $true }).Count -Note 'Tier 0'
    Add-Metric -Metric 'Privileged user accounts with an SPN (Kerberoastable)' -Value @($privT0 | Where-Object { $_.Flags -match 'Kerberoastable' }).Count -Note 'Tier 0'
    Add-Metric -Metric 'Accounts with access-tier rights only (Tier1-access)' -Value @($privRows | Where-Object Tier -eq 'Tier1-access').Count -Note 'Remote Desktop Users, Remote Management Users, DHCP Administrators'
    Add-Metric -Metric 'Accounts in Info groups only' -Value @($privRows | Where-Object Tier -eq 'Info').Count -Note 'Event Log Readers'
    Add-Metric -Metric 'Members through primaryGroupID' -Value @($memberRows | Where-Object { $_.NestingPath -like '*(primaryGroupID)' } | Select-Object -ExpandProperty DistinguishedName -Unique).Count -Note 'Not listed in the group member attribute'
    Add-Metric -Metric 'Foreign security principals in privileged groups' -Value @($privRows | Where-Object ObjectClass -eq 'foreignSecurityPrincipal').Count -Note 'Accounts or groups from another forest, or well-known SIDs'
    Add-Metric 'Tier 0 accounts in Protected Users' @($privT0 | Where-Object { $_.InProtectedUsers -eq $true }).Count
    Add-Metric -Metric 'Tier 0 user accounts not admin-named' -Value @($privT0 | Where-Object { $_.ObjectClass -in 'user', 'inetOrgPerson' -and $_.IsAdminNamed -eq $false -and $_.Category -eq 'Custom' }).Count -Note ("Regular-looking accounts with Tier 0 rights; admin naming used: {0}" -f ($AdminNamePatterns -join ', '))
    Add-Metric 'Tier 0 accounts with SID history' @($privT0 | Where-Object { $_.SIDHistoryPresent -eq $true }).Count
    Add-Metric 'Service-account candidates' @($svcRows).Count
    Add-Metric -Metric 'Service-account candidates that are privileged' -Value @($svcRows | Where-Object IsPrivileged).Count -Note 'Tier 0'
    Add-Metric 'Service-account candidates enabled and stale' @($svcRows | Where-Object { $_.Enabled -and $_.Stale }).Count
    Add-Metric 'Service-account candidates with no managedBy owner' @($svcRows | Where-Object { -not $_.HasManagedBy }).Count
    Add-Metric 'Managed service accounts (gMSA/sMSA)' @($svcRows | Where-Object { $_.DetectionReasons -match 'ManagedServiceAccount' }).Count
    Add-Metric "Service-account candidates with password older than $PasswordAgeWarningDays days" @($svcRows | Where-Object { $_.PasswordAgeDays -ne '' -and $_.PasswordAgeDays -gt $PasswordAgeWarningDays }).Count
    if ($orphanRead) {
        foreach ($cls in 'user', 'computer', 'group') { Add-Metric ("adminCount=1 {0}s not in any Tier 0 group" -f $cls) @($orphanRows | Where-Object ObjectClass -eq $cls).Count }
    }
    else { Add-Metric 'adminCount=1 objects not in any Tier 0 group' 'Read failed' }
    if (-not $SkipRiskFlags) {
        $flagNames = @($riskChecks | ForEach-Object { $_.Flag }) + @('UnconstrainedDelegation-DomainController', 'ProtocolTransition-DomainController', 'SensitiveNotDelegatedMissing')
        foreach ($f in $flagNames) {
            $base = $f -replace '-DomainController$', ''
            if ($riskFailed.Contains($base)) { Add-Metric -Metric "Risk flag: $f (accounts)" -Value 'Read failed' -Note 'Query failed: not a count of zero'; continue }
            $hits = @($riskRows | Where-Object Flag -eq $f)
            $note = switch ($f) {
                'KeyCredentialOnUser' { '0 can also mean msDS-KeyCredentialLink is not readable by the run account' }
                'Kerberoastable' { 'User accounts with an SPN (krbtgt excluded)' }
                'PasswordNeverExpiresAndOld' { "Password older than $PasswordAgeWarningDays days" }
                'UnconstrainedDelegation' { 'Domain controllers excluded (listed separately)' }
                'ProtocolTransition' { 'Read-only domain controllers excluded (listed separately)' }
                default { '' }
            }
            Add-Metric -Metric "Risk flag: $f (accounts)" -Value @($hits | Select-Object -ExpandProperty DistinguishedName -Unique).Count -Note $note
            if ($hits.Count) { Add-Metric "Risk flag: $f (enabled, Tier 0)" @($hits | Where-Object { $_.Enabled -eq $true -and $_.IsPrivileged -eq $true }).Count }
        }
    }
    foreach ($r in $secretRows) { Add-Metric -Metric ("Password age (days): {0} {1}" -f $r.Kind, $r.Account) -Value $(if ($r.AgeDays -ne '') { $r.AgeDays } else { 'n/a' }) -Note $r.Detail }
    foreach ($f in $secretFailed) { Add-Metric "Password age (days): $f" 'Read failed' }
    if ($gmsaRead) {
        $eff = @($gmsaRows | Where-Object { $_.Status -eq 'Resolved' -and $_.PrincipalClass -and $_.PrincipalClass -ne 'group' })
        Add-Metric 'gMSAs' $gmsaCount
        Add-Metric -Metric 'gMSAs with no password readers listed' -Value @($gmsaRows | Where-Object { $_.Status -like 'NoReadersListed*' }).Count -Note 'Empty or not readable by the run account'
        Add-Metric -Metric 'Distinct accounts that can retrieve a gMSA password' -Value @($eff | Select-Object -ExpandProperty PrincipalDN -Unique).Count -Note 'Groups expanded'
        Add-Metric -Metric 'User accounts (not computers) that can retrieve a gMSA password' -Value @($eff | Where-Object { $_.PrincipalClass -in 'user', 'inetOrgPerson' } | Select-Object -ExpandProperty PrincipalDN -Unique).Count -Note 'Usually only servers should'
    }
    else { Add-Metric 'gMSAs' 'Read failed' }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ SearchBase = $SearchBase; ServiceNamePatterns = $ServiceNamePatterns; AdditionalPrivilegedGroups = $AdditionalPrivilegedGroups; AdminNamePatterns = $AdminNamePatterns; StaleDays = $StaleDays; PasswordAgeWarningDays = $PasswordAgeWarningDays; SkipRiskFlags = [bool]$SkipRiskFlags }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
