<#
.SYNOPSIS
    Read-only discovery of privileged and service accounts in on-premises Active Directory.

.DESCRIPTION
    Exports the on-prem evidence for "service and privileged account sprawl":
      - Membership of every protected/privileged group, expanded through nesting, with the
        full nesting path (so indirect admin rights are visible)
      - One row per privileged account with hygiene flags (stale, password never expires,
        old password, Kerberos pre-auth disabled, delegation, SPN on an admin account)
      - Service-account candidates found by several detection methods, with the reasons listed
      - adminCount=1 accounts that are no longer in any protected group (AdminSDHolder leftovers)
      - A summary of headline metrics

    READ-ONLY. Uses only Get-AD* cmdlets. Nothing in the directory is changed.

    Output: <OutputRoot>\04-ADPrivilegedAndServiceAccounts\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER Server
    Domain controller or domain to query (e.g. dc01.contoso.local). Blank = default DC for the session.

.PARAMETER ServiceNamePatterns
    sAMAccountName wildcard patterns that indicate a service account in this environment.

.EXAMPLE
    .\04-Get-ADPrivilegedAndServiceAccounts.ps1
.EXAMPLE
    .\04-Get-ADPrivilegedAndServiceAccounts.ps1 -Server dc01.contoso.local -ServiceNamePatterns 'svc*','sa_*' -AdditionalPrivilegedGroups 'Group1','Group2'

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account (read)
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                    # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                                # e.g. 'OU=Service Accounts,DC=contoso,DC=local' (blank = whole domain)
    [string[]]$ServiceNamePatterns = @('svc*', 'svc-*', 'svc_*', 'sa-*', 'sa_*', '*_svc', '*-svc', 'srv-*'),
    [string[]]$AdditionalPrivilegedGroups = @(),             # names of custom admin groups, e.g. 'Group1'
    [int]$StaleDays = 90,
    [int]$PasswordAgeWarningDays = 365
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '04-ADPrivilegedAndServiceAccounts'
$ScriptVersion = '1.0.0'

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
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $script:RunFolder 'run-manifest.json') -Encoding UTF8
    $script:Datasets | Export-Csv -Path (Join-Path $script:RunFolder 'dataset-status.csv') -NoTypeInformation -Encoding UTF8
}

function Join-Values { param($Values) if ($null -eq $Values) { return '' } return (@($Values) | Where-Object { $null -ne $_ -and "$_" -ne '' }) -join '; ' }

# Splat for every AD cmdlet so -Server is honoured consistently.
$script:AdParams = @{}
if ($Server) { $script:AdParams['Server'] = $Server }
#endregion

$AccountProps = @('sAMAccountName', 'name', 'objectClass', 'objectSid', 'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet',
    'adminCount', 'servicePrincipalName', 'description', 'managedBy', 'whenCreated', 'msDS-AllowedToDelegateTo', 'member', 'distinguishedName')

$UAC = @{ Disabled = 2; PasswordNeverExpires = 65536; TrustedForDelegation = 524288; NoPreAuth = 4194304; TrustedToAuthForDelegation = 16777216 }

function ConvertFrom-FileTime { param($Value) if ($null -eq $Value -or [int64]$Value -le 0 -or [int64]$Value -eq [int64]::MaxValue) { return $null } return [datetime]::FromFileTimeUtc([int64]$Value) }

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
        Enabled               = -not ($uac -band $UAC.Disabled)
        LastLogonUtc          = $(if ($lastLogon) { $lastLogon.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        DaysSinceLogon        = $(if ($lastLogon) { [int]($now - $lastLogon).TotalDays } else { '' })
        Stale                 = (-not $lastLogon) -or (($now - $lastLogon).TotalDays -gt $StaleDays)
        PasswordLastSetUtc    = $(if ($pwdSet) { $pwdSet.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        PasswordAgeDays       = $(if ($pwdSet) { [int]($now - $pwdSet).TotalDays } else { '' })
        PasswordNeverExpires  = [bool]($uac -band $UAC.PasswordNeverExpires)
        KerberosPreAuthDisabled = [bool]($uac -band $UAC.NoPreAuth)
        UnconstrainedDelegation = [bool]($uac -band $UAC.TrustedForDelegation)
        ProtocolTransition    = [bool]($uac -band $UAC.TrustedToAuthForDelegation)
        ConstrainedDelegationTargets = @($Obj.'msDS-AllowedToDelegateTo' | Where-Object { $_ }).Count
        HasSpn                = (@($Obj.servicePrincipalName | Where-Object { $_ }).Count -gt 0)
        SpnCount              = @($Obj.servicePrincipalName | Where-Object { $_ }).Count
        AdminCount            = $Obj.adminCount
        HasManagedBy          = [bool]$Obj.managedBy
        Description           = $Obj.description
        WhenCreated           = $Obj.whenCreated
    }
}

$script:ObjCache = @{}
function Get-AdObjectCached {
    param([string]$DN)
    if ($script:ObjCache.ContainsKey($DN)) { return $script:ObjCache[$DN] }
    $o = $null
    try { $o = Get-ADObject -Identity $DN -Properties $AccountProps @script:AdParams } catch { $o = $null }
    $script:ObjCache[$DN] = $o
    return $o
}

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain @script:AdParams
    $forest = Get-ADForest @script:AdParams
    $domainName = $domain.DNSRoot
    $domainSid = $domain.DomainSID.Value
    $rootParams = @{ Server = $forest.RootDomain }
    $rootSid = (Get-ADDomain -Identity $forest.RootDomain @rootParams).DomainSID.Value
    Write-RunLog ("Domain {0}; forest root {1}" -f $domainName, $forest.RootDomain)

    # ---- Protected / privileged groups to expand ----
    $groupSpecs = @(
        @{ Label = 'Domain Admins';              Sid = "$domainSid-512"; Root = $false }
        @{ Label = 'Group Policy Creator Owners'; Sid = "$domainSid-520"; Root = $false }
        @{ Label = 'Key Admins';                 Sid = "$domainSid-526"; Root = $false }
        @{ Label = 'Schema Admins';              Sid = "$rootSid-518";   Root = $true }
        @{ Label = 'Enterprise Admins';          Sid = "$rootSid-519";   Root = $true }
        @{ Label = 'Enterprise Key Admins';      Sid = "$rootSid-527";   Root = $true }
        @{ Label = 'Administrators';             Sid = 'S-1-5-32-544';   Root = $false }
        @{ Label = 'Account Operators';          Sid = 'S-1-5-32-548';   Root = $false }
        @{ Label = 'Server Operators';           Sid = 'S-1-5-32-549';   Root = $false }
        @{ Label = 'Print Operators';            Sid = 'S-1-5-32-550';   Root = $false }
        @{ Label = 'Backup Operators';           Sid = 'S-1-5-32-551';   Root = $false }
    )
    $groups = [System.Collections.Generic.List[object]]::new()
    foreach ($spec in $groupSpecs) {
        try {
            $p = $(if ($spec.Root) { $rootParams } else { $script:AdParams })
            $g = Get-ADGroup -Identity $spec.Sid @p
            $groups.Add([pscustomobject]@{ Label = $spec.Label; DN = $g.DistinguishedName; Source = 'Built-in protected' })
        }
        catch { Write-RunLog ("Group {0} ({1}) not found in this domain; skipped." -f $spec.Label, $spec.Sid) 'WARN' }
    }
    foreach ($n in @('DnsAdmins') + @($AdditionalPrivilegedGroups)) {
        try { $g = Get-ADGroup -Identity $n @script:AdParams; $groups.Add([pscustomobject]@{ Label = $g.Name; DN = $g.DistinguishedName; Source = $(if ($n -eq 'DnsAdmins') { 'Built-in' } else { 'Additional (config)' }) }) }
        catch { Write-RunLog ("Group '{0}' not found; skipped." -f $n) 'WARN' }
    }

    # ---- 1. Expand membership with nesting path ----
    $memberRows = [System.Collections.Generic.List[object]]::new()
    function Expand-Group {
        param([string]$GroupLabel, [string]$DN, [string[]]$Path, [int]$Depth)
        $grp = Get-AdObjectCached $DN
        if (-not $grp) { return }
        foreach ($m in @($grp.member)) {
            if (-not $m) { continue }
            $o = Get-AdObjectCached $m
            if (-not $o) {
                $memberRows.Add([pscustomobject][ordered]@{ PrivilegedGroup = $GroupLabel; MemberSam = ''; MemberName = $m; MemberClass = 'unresolved (other domain / FSP)'; Depth = $Depth; NestingPath = ($Path -join ' > '); DistinguishedName = $m })
                continue
            }
            $class = @($o.objectClass)[-1]
            if ($class -eq 'group') {
                if ($Path -contains $o.name) { Write-RunLog ("Circular nesting detected under {0}: {1}" -f $GroupLabel, (($Path + $o.name) -join ' > ')) 'WARN'; continue }
                $memberRows.Add([pscustomobject][ordered]@{ PrivilegedGroup = $GroupLabel; MemberSam = $o.sAMAccountName; MemberName = $o.name; MemberClass = 'group'; Depth = $Depth; NestingPath = ($Path -join ' > '); DistinguishedName = $o.distinguishedName })
                Expand-Group -GroupLabel $GroupLabel -DN $o.distinguishedName -Path ($Path + $o.name) -Depth ($Depth + 1)
            }
            else {
                $memberRows.Add([pscustomobject][ordered]@{ PrivilegedGroup = $GroupLabel; MemberSam = $o.sAMAccountName; MemberName = $o.name; MemberClass = $class; Depth = $Depth; NestingPath = ($Path -join ' > '); DistinguishedName = $o.distinguishedName })
            }
        }
    }
    foreach ($g in $groups) { Expand-Group -GroupLabel $g.Label -DN $g.DN -Path @($g.Label) -Depth 1 }
    Export-Dataset -Name 'ad-privileged-membership' -Rows $memberRows -Note ("{0} privileged groups expanded; Depth 1 = direct member" -f $groups.Count)

    # ---- 2. Per privileged account ----
    $privDN = @{}
    foreach ($r in $memberRows) {
        if ($r.MemberClass -in @('user', 'computer', 'msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount', 'inetOrgPerson')) {
            if (-not $privDN.ContainsKey($r.DistinguishedName)) { $privDN[$r.DistinguishedName] = [System.Collections.Generic.List[string]]::new() }
            $privDN[$r.DistinguishedName].Add($(if ($r.Depth -gt 1) { '{0} (nested: {1})' -f $r.PrivilegedGroup, $r.NestingPath } else { $r.PrivilegedGroup }))
        }
    }
    $privRows = foreach ($dn in $privDN.Keys) {
        $info = ConvertTo-AccountInfo (Get-AdObjectCached $dn)
        $flags = @()
        if (-not $info.Enabled) { $flags += 'Disabled' }
        if ($info.Enabled -and $info.Stale) { $flags += "NoLogon${StaleDays}d" }
        if ($info.PasswordNeverExpires) { $flags += 'PasswordNeverExpires' }
        if ($info.PasswordAgeDays -ne '' -and $info.PasswordAgeDays -gt $PasswordAgeWarningDays) { $flags += "PasswordOlderThan${PasswordAgeWarningDays}d" }
        if ($info.HasSpn -and $info.ObjectClass -eq 'user') { $flags += 'SpnOnPrivilegedUser(Kerberoastable)' }
        if ($info.KerberosPreAuthDisabled) { $flags += 'PreAuthDisabled' }
        if ($info.UnconstrainedDelegation -and $info.ObjectClass -eq 'user') { $flags += 'UnconstrainedDelegation' }
        if (@($privDN[$dn] | Where-Object { $_ -match 'nested' }).Count) { $flags += 'NestedOnly' }
        if (@($privDN[$dn] | Where-Object { $_ -notmatch 'nested' }).Count) { $flags = @($flags | Where-Object { $_ -ne 'NestedOnly' }) }
        $o = [ordered]@{ PrivilegedVia = Join-Values ($privDN[$dn] | Sort-Object -Unique); Flags = Join-Values $flags }
        foreach ($p in $info.PSObject.Properties) { $o[$p.Name] = $p.Value }
        [pscustomobject]$o
    }
    Export-Dataset -Name 'ad-privileged-accounts' -Rows $privRows

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
    foreach ($d in $detections) {
        try { foreach ($o in (Get-ADObject -LDAPFilter $d.Filter -Properties $AccountProps @searchParams)) { Add-Candidate $o $d.Reason } }
        catch { Write-RunLog ("Detection '{0}' failed: {1}" -f $d.Reason, $_.Exception.Message) 'WARN' }
    }
    try { foreach ($o in (Get-ADObject -LDAPFilter '(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))' -Properties $AccountProps @script:AdParams)) { Add-Candidate $o 'ManagedServiceAccount(gMSA/sMSA)' } }
    catch { Write-RunLog ("Managed service account query failed: {0}" -f $_.Exception.Message) 'WARN' }

    $svcRows = foreach ($dn in $svc.Keys) {
        $info = ConvertTo-AccountInfo $svc[$dn].Obj
        $o = [ordered]@{
            DetectionReasons = Join-Values $svc[$dn].Reasons
            ReasonCount      = $svc[$dn].Reasons.Count
            IsPrivileged     = $privDN.ContainsKey($dn)
            PrivilegedVia    = $(if ($privDN.ContainsKey($dn)) { Join-Values ($privDN[$dn] | Sort-Object -Unique) } else { '' })
        }
        foreach ($p in $info.PSObject.Properties) { $o[$p.Name] = $p.Value }
        [pscustomobject]$o
    }
    $svcRows = @($svcRows | Sort-Object -Property @{ Expression = 'IsPrivileged'; Descending = $true }, @{ Expression = 'ReasonCount'; Descending = $true })
    Export-Dataset -Name 'ad-service-account-candidates' -Rows $svcRows -Note 'Candidates only - confirm with owners. One account can match several detections.'

    # ---- 4. AdminSDHolder leftovers ----
    try {
        $adminCountObjs = Get-ADObject -LDAPFilter "(&$userBase(adminCount=1))" -Properties $AccountProps @script:AdParams
        $orphanRows = foreach ($o in $adminCountObjs) {
            if ($privDN.ContainsKey($o.distinguishedName)) { continue }
            ConvertTo-AccountInfo $o
        }
        Export-Dataset -Name 'ad-admincount-orphans' -Rows $orphanRows -Note 'adminCount=1 but not in any expanded privileged group: inheritance may still be blocked on these accounts'
    }
    catch { Set-DatasetStatus -Name 'ad-admincount-orphans' -Status 'Blocked' -Note $_.Exception.Message }

    # ---- 5. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Privileged groups expanded' $groups.Count
    Add-Metric 'Max nesting depth in privileged groups' $(if ($memberRows.Count) { ($memberRows | Measure-Object Depth -Maximum).Maximum } else { 0 })
    Add-Metric 'Distinct privileged accounts' @($privRows).Count
    Add-Metric 'Privileged accounts enabled' @($privRows | Where-Object Enabled).Count
    Add-Metric 'Privileged accounts privileged only through nesting' @($privRows | Where-Object { $_.Flags -match 'NestedOnly' }).Count
    Add-Metric "Enabled privileged accounts with no logon in $StaleDays days" @($privRows | Where-Object { $_.Flags -match 'NoLogon' }).Count
    Add-Metric 'Privileged accounts with password never expires' @($privRows | Where-Object PasswordNeverExpires).Count
    Add-Metric 'Privileged user accounts with an SPN (Kerberoastable)' @($privRows | Where-Object { $_.Flags -match 'Kerberoastable' }).Count
    Add-Metric 'Service-account candidates' @($svcRows).Count
    Add-Metric 'Service-account candidates that are privileged' @($svcRows | Where-Object IsPrivileged).Count
    Add-Metric 'Service-account candidates enabled and stale' @($svcRows | Where-Object { $_.Enabled -and $_.Stale }).Count
    Add-Metric 'Service-account candidates with no managedBy owner' @($svcRows | Where-Object { -not $_.HasManagedBy }).Count
    Add-Metric 'Managed service accounts (gMSA/sMSA)' @($svcRows | Where-Object { $_.DetectionReasons -match 'ManagedServiceAccount' }).Count
    Add-Metric "Service-account candidates with password older than $PasswordAgeWarningDays days" @($svcRows | Where-Object { $_.PasswordAgeDays -ne '' -and $_.PasswordAgeDays -gt $PasswordAgeWarningDays }).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ SearchBase = $SearchBase; ServiceNamePatterns = $ServiceNamePatterns; AdditionalPrivilegedGroups = $AdditionalPrivilegedGroups; StaleDays = $StaleDays; PasswordAgeWarningDays = $PasswordAgeWarningDays }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
