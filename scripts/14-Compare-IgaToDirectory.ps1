<#
.SYNOPSIS
    Read-only reconciliation of an IGA platform export (accounts and assignments) against Active Directory.

.DESCRIPTION
    Shows where the governance system's view of accounts and group access differs from what is
    actually in AD. Before JML moves to a new platform, this documents what the current IGA does
    and does not control. Inputs are CSV exports you supply; nothing connects to the IGA itself.

    Accounts (required export)
      - AD accounts the IGA does not know about (unmanaged; service/admin patterns marked
        separately), with adminCount, group count, manager, SPN and admin-name flags
      - IGA accounts with no AD account (deleted outside the IGA, or never provisioned)
      - Status mismatches: IGA says disabled/terminated but AD is enabled, or the reverse
      - Leavers still holding access: inactive in the IGA, disabled in AD, still in groups
      - Duplicate or blank keys on either side, which would otherwise hide accounts or groups
    Group access (optional export)
      - Governed groups: every group that appears in an IGA assignment, with counts of members in
        both, AD-only (granted outside governance) and IGA-only (not provisioned)
      - Memberships outside governance: user directly in a governed group with no IGA assignment
      - Nested memberships: users who reach a governed group through another group, resolved
        transitively, with the group they come through (on by default; -SkipNestedExpansion)
      - Non-user members of governed groups: groups, computers, foreign security principals and
        users outside -SearchBase
      - Assignments not in AD: IGA assignment with no matching AD membership
      - Ungoverned groups: AD security groups with users (direct or through nesting) that the
        IGA never assigns
    Also writes an input profile (rows, systems and status values seen) so you can confirm the
    column mapping before trusting the results.

    READ-ONLY. Uses only Get-AD* cmdlets and Import-Csv.

    Output: <OutputRoot>\14-IgaReconciliation\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER AccountsCsv
    IGA export with one row per account per system. Default column names: AccountName, System,
    Status, IdentityId. Map different names with the -Acct*Column parameters.

.PARAMETER AssignmentsCsv
    Optional IGA export with one row per account per resource (group). Default column names:
    AccountName, System, ResourceName, Status. Map with the -Asg*Column parameters.

.PARAMETER SystemName
    Value in the System column that identifies AD rows. Wildcards allowed, e.g. '*Active Directory*'.

.PARAMETER AdGroupKey
    The AD group attribute matched against the IGA ResourceName. Defaults to sAMAccountName
    (unique in a domain). Use Name if the IGA exports the group's CN, or DistinguishedName.

.PARAMETER SkipNestedExpansion
    Do not resolve transitive (nested) members of governed groups. Saves one LDAP query per
    governed group.

.EXAMPLE
    .\14-Compare-IgaToDirectory.ps1 -AccountsCsv .\iga-accounts.csv
.EXAMPLE
    .\14-Compare-IgaToDirectory.ps1 -AccountsCsv .\iga-accounts.csv -AssignmentsCsv .\iga-assignments.csv -SystemName '*AD*'
.EXAMPLE
    .\14-Compare-IgaToDirectory.ps1 -AccountsCsv .\accts.csv -AcctNameColumn 'Account' -AcctStatusColumn 'AccountState' -AdAccountKey userPrincipalName -AdGroupKey Name

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account (read)
    A blank IGA status is classed as Unknown (not Active) and counted in the summary.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [Parameter(Mandatory)]
    [string]$AccountsCsv,
    [string]$AssignmentsCsv = '',
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                               # user scope (blank = whole domain)
    [string]$GroupSearchBase = '',                          # group scope (blank = whole domain)

    [string]$SystemName = 'Active Directory',
    [string]$AcctNameColumn = 'AccountName',
    [string]$AcctSystemColumn = 'System',
    [string]$AcctStatusColumn = 'Status',
    [string]$AcctIdentityColumn = 'IdentityId',
    [string]$AsgAccountColumn = 'AccountName',
    [string]$AsgSystemColumn = 'System',
    [string]$AsgResourceColumn = 'ResourceName',
    [string]$AsgStatusColumn = 'Status',

    [string[]]$ActiveStatusValues = @('Active', 'Enabled'),
    [string[]]$InactiveStatusValues = @('Disabled', 'Inactive', 'Terminated', 'Deleted', 'Expired', 'Removed', 'Revoked'),
    [ValidateSet('sAMAccountName', 'userPrincipalName')]
    [string]$AdAccountKey = 'sAMAccountName',
    [ValidateSet('Name', 'sAMAccountName', 'DistinguishedName')]
    [string]$AdGroupKey = 'sAMAccountName',
    [string[]]$ServiceNamePatterns = @('svc*', 'sa-*', 'sa_*', 'adm*', '*admin*', 'test*', 'krbtgt', 'Guest', 'DefaultAccount'),
    [string[]]$AdminNamePatterns = @('adm*', '*adm', '*-adm*', '*_adm*', 'a-*', 'a_*', 'da-*', '*admin*'),
    [switch]$SkipNestedExpansion
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '14-IgaReconciliation'
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

$InChain = '1.2.840.113556.1.4.1941'      # LDAP_MATCHING_RULE_IN_CHAIN: transitive group membership

function Test-Column { param($Rows, [string]$Column, [string]$File) if ($Rows.Count -and -not ($Rows[0].PSObject.Properties.Name -contains $Column)) { throw "$File has no column '$Column'. Columns found: $($Rows[0].PSObject.Properties.Name -join ', ')" } }
function Get-StatusClass {
    # A blank status is Unknown, never Active: an empty export column must not read as "all active".
    param([string]$Status)
    $s = "$Status".Trim()
    if (-not $s) { return 'Unknown' }
    if ($ActiveStatusValues -contains $s) { return 'Active' }
    if ($InactiveStatusValues -contains $s) { return 'Inactive' }
    return 'Unknown'
}
function Test-AdminName { param([string]$Sam) return [bool](@($AdminNamePatterns | Where-Object { $Sam -like $_ }).Count) }
function ConvertTo-LdapValue { param([string]$Value) return ($Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace "`0", '\00') }
function Get-CnFromDn { param([string]$DN) return ($DN -replace '^CN=((?:[^,\\]|\\.)+),.*$', '$1' -replace '\\(.)', '$1') }
function Format-Capped {
    param($Values, [int]$Cap = 50)
    $v = @($Values | Where-Object { $_ } | Sort-Object)
    if ($v.Count -le $Cap) { return Join-Values $v }
    return ('{0}; ... (+{1} more)' -f (Join-Values ($v | Select-Object -First $Cap)), ($v.Count - $Cap))
}

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot

    # ---- Inputs ----
    if (-not (Test-Path $AccountsCsv)) { throw "Accounts file not found: $AccountsCsv" }
    $acctAll = @(Import-Csv -Path $AccountsCsv)
    foreach ($c in $AcctNameColumn, $AcctSystemColumn, $AcctStatusColumn) { Test-Column -Rows $acctAll -Column $c -File 'Accounts file' }
    $acct = @($acctAll | Where-Object { "$($_.$AcctSystemColumn)" -like $SystemName })
    $inputProfile = [System.Collections.Generic.List[object]]::new()
    $inputProfile.Add([pscustomobject][ordered]@{ File = 'Accounts'; Item = 'Rows read'; Value = $acctAll.Count })
    $inputProfile.Add([pscustomobject][ordered]@{ File = 'Accounts'; Item = 'SHA256'; Value = (Get-FileHash $AccountsCsv -Algorithm SHA256).Hash })
    $inputProfile.Add([pscustomobject][ordered]@{ File = 'Accounts'; Item = 'Systems seen'; Value = Join-Values ($acctAll | Group-Object $AcctSystemColumn | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count }) })
    $inputProfile.Add([pscustomobject][ordered]@{ File = 'Accounts'; Item = "Rows matching System '$SystemName'"; Value = $acct.Count })
    $inputProfile.Add([pscustomobject][ordered]@{ File = 'Accounts'; Item = 'Status values seen'; Value = Join-Values ($acct | Group-Object $AcctStatusColumn | ForEach-Object { '{0} -> {1} ({2})' -f $(if ($_.Name) { $_.Name } else { '(blank)' }), (Get-StatusClass $_.Name), $_.Count }) })
    if ($acct.Count -eq 0) { throw "No account rows match System '$SystemName'. See the Systems seen line in iga-input-profile.csv." }

    $asg = @()
    if ($AssignmentsCsv) {
        if (-not (Test-Path $AssignmentsCsv)) { throw "Assignments file not found: $AssignmentsCsv" }
        $asgAll = @(Import-Csv -Path $AssignmentsCsv)
        foreach ($c in $AsgAccountColumn, $AsgSystemColumn, $AsgResourceColumn) { Test-Column -Rows $asgAll -Column $c -File 'Assignments file' }
        $hasStatus = ($asgAll.Count -and ($asgAll[0].PSObject.Properties.Name -contains $AsgStatusColumn))
        $asg = @($asgAll | Where-Object { "$($_.$AsgSystemColumn)" -like $SystemName -and (-not $hasStatus -or (Get-StatusClass "$($_.$AsgStatusColumn)") -ne 'Inactive') })
        $inputProfile.Add([pscustomobject][ordered]@{ File = 'Assignments'; Item = 'Rows read'; Value = $asgAll.Count })
        $inputProfile.Add([pscustomobject][ordered]@{ File = 'Assignments'; Item = 'SHA256'; Value = (Get-FileHash $AssignmentsCsv -Algorithm SHA256).Hash })
        $inputProfile.Add([pscustomobject][ordered]@{ File = 'Assignments'; Item = "Active rows matching System '$SystemName'"; Value = $asg.Count })
        if ($hasStatus) { $inputProfile.Add([pscustomobject][ordered]@{ File = 'Assignments'; Item = 'Status values seen'; Value = Join-Values ($asgAll | Group-Object $AsgStatusColumn | ForEach-Object { '{0} -> {1} ({2})' -f $(if ($_.Name) { $_.Name } else { '(blank)' }), (Get-StatusClass $_.Name), $_.Count }) }) }
    }
    Export-Dataset -Name 'iga-input-profile' -Rows $inputProfile -Note 'Check the status mapping before trusting mismatches'

    # ---- AD ----
    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    $adUsers = @(Get-ADUser -Filter * -Properties enabled, userPrincipalName, whenCreated, lastLogonTimestamp, adminCount, memberOf, manager, servicePrincipalName @p)
    $adByKey = @{}; $adByDN = @{}
    $dupRows = [System.Collections.Generic.List[object]]::new()
    $adDup = @{}; $unkeyed = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $adUsers) {
        $adByDN[$u.DistinguishedName] = $u
        $k = "$($u.$AdAccountKey)".Trim().ToLowerInvariant()
        if (-not $k) { $unkeyed.Add($u); continue }
        if ($adByKey.ContainsKey($k)) {
            if (-not $adDup.ContainsKey($k)) { $adDup[$k] = [System.Collections.Generic.List[string]]::new(); $adDup[$k].Add($adByKey[$k].DistinguishedName) }
            $adDup[$k].Add($u.DistinguishedName)
        }
        else { $adByKey[$k] = $u }
    }
    foreach ($k in $adDup.Keys) { $dupRows.Add([pscustomobject][ordered]@{ Source = 'AD account'; Key = $k; Issue = 'DuplicateKey'; Count = $adDup[$k].Count; Objects = Join-Values $adDup[$k]; Handling = 'First object used for matching; the others are not compared' }) }
    foreach ($u in $unkeyed) { $dupRows.Add([pscustomobject][ordered]@{ Source = 'AD account'; Key = ''; Issue = 'BlankKey'; Count = 1; Objects = ('{0} ({1})' -f $u.SamAccountName, $u.DistinguishedName); Handling = ("Blank {0}: skipped, not matched and not counted as unmanaged" -f $AdAccountKey) }) }
    if ($unkeyed.Count) { Write-RunLog ("{0} AD users have a blank {1} and are skipped (listed in duplicate-keys.csv)" -f $unkeyed.Count, $AdAccountKey) 'WARN' }
    $keyedCount = $adUsers.Count - $unkeyed.Count
    Write-RunLog ("{0} AD users; {1} IGA account rows for this system" -f $adUsers.Count, $acct.Count)
    function Get-AdKey { param([string]$DN) if ($adByDN.ContainsKey($DN)) { return "$($adByDN[$DN].$AdAccountKey)".Trim().ToLowerInvariant() } return '' }

    # ---- 1. Accounts ----
    $igaByKey = @{}; $igaDup = @{}
    foreach ($r in $acct) {
        $k = "$($r.$AcctNameColumn)".Trim().ToLowerInvariant()
        if (-not $k) { continue }
        if ($igaByKey.ContainsKey($k)) {
            if (-not $igaDup.ContainsKey($k)) { $igaDup[$k] = [System.Collections.Generic.List[object]]::new(); $igaDup[$k].Add($igaByKey[$k]) }
            $igaDup[$k].Add($r)
            # Prefer an Active row so a stale duplicate cannot hide a live account.
            if ((Get-StatusClass $r.$AcctStatusColumn) -eq 'Active' -and (Get-StatusClass $igaByKey[$k].$AcctStatusColumn) -ne 'Active') { $igaByKey[$k] = $r }
        }
        else { $igaByKey[$k] = $r }
    }
    foreach ($k in $igaDup.Keys) { $dupRows.Add([pscustomobject][ordered]@{ Source = 'IGA account'; Key = $k; Issue = 'DuplicateKey'; Count = $igaDup[$k].Count; Objects = Join-Values ($igaDup[$k] | ForEach-Object { 'Status=' + $(if ("$($_.$AcctStatusColumn)") { $_.$AcctStatusColumn } else { '(blank)' }) }); Handling = 'Row with an Active status used, otherwise the first row' }) }
    $blankStatus = @($igaByKey.Values | Where-Object { -not "$($_.$AcctStatusColumn)".Trim() }).Count
    if ($blankStatus) { Write-RunLog ("{0} IGA accounts have a blank status; classed as Unknown" -f $blankStatus) 'WARN' }

    $adNotInIga = foreach ($u in $adUsers) {
        $k = "$($u.$AdAccountKey)".Trim().ToLowerInvariant()
        if (-not $k) { continue }
        if ($igaByKey.ContainsKey($k)) { continue }
        $svc = [bool](@($ServiceNamePatterns | Where-Object { $u.SamAccountName -like $_ }).Count)
        $mgr = "$($u.manager)"
        [pscustomobject][ordered]@{
            SamAccountName    = $u.SamAccountName
            UserPrincipalName = $u.UserPrincipalName
            Enabled           = $u.Enabled
            WhenCreated       = $u.whenCreated
            LastLogonUtc      = $(if ($u.lastLogonTimestamp) { [datetime]::FromFileTimeUtc([int64]$u.lastLogonTimestamp).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            Classification    = $(if ($svc) { 'ServiceOrAdminPattern' } elseif ($u.Enabled) { 'UnmanagedEnabled' } else { 'UnmanagedDisabled' })
            DistinguishedName = $u.DistinguishedName
            AdminCount        = $(if ("$($u.adminCount)" -eq '1') { 1 } else { '' })
            MemberOfCount     = @($u.memberOf | Where-Object { $_ }).Count
            Manager           = $(if (-not $mgr) { '' } elseif ($adByDN.ContainsKey($mgr)) { $adByDN[$mgr].SamAccountName } else { Get-CnFromDn $mgr })
            HasSpn            = [bool](@($u.servicePrincipalName | Where-Object { $_ }).Count)
            IsAdminNamed      = Test-AdminName ([string]$u.SamAccountName)
        }
    }
    Export-Dataset -Name 'accounts-ad-not-in-iga' -Rows $adNotInIga

    $igaNotInAd = foreach ($k in $igaByKey.Keys) {
        if ($adByKey.ContainsKey($k)) { continue }
        $r = $igaByKey[$k]
        [pscustomobject][ordered]@{ AccountName = $r.$AcctNameColumn; IgaStatus = $r.$AcctStatusColumn; IgaStatusClass = Get-StatusClass $r.$AcctStatusColumn; IdentityId = $(if ($r.PSObject.Properties.Name -contains $AcctIdentityColumn) { $r.$AcctIdentityColumn } else { '' }) }
    }
    Export-Dataset -Name 'accounts-iga-not-in-ad' -Rows $igaNotInAd -Note 'Active rows here = IGA believes an account exists that AD does not have'

    $mismatch = foreach ($k in $igaByKey.Keys) {
        if (-not $adByKey.ContainsKey($k)) { continue }
        $r = $igaByKey[$k]; $u = $adByKey[$k]
        $cls = Get-StatusClass $r.$AcctStatusColumn
        $type = $null
        if ($cls -eq 'Inactive' -and $u.Enabled) { $type = 'IgaInactive_ADEnabled' }
        elseif ($cls -eq 'Active' -and -not $u.Enabled) { $type = 'IgaActive_ADDisabled' }
        elseif ($cls -eq 'Unknown') { $type = 'UnmappedIgaStatus' }
        if (-not $type) { continue }
        [pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; IgaStatus = $r.$AcctStatusColumn; ADEnabled = $u.Enabled; MismatchType = $type; IdentityId = $(if ($r.PSObject.Properties.Name -contains $AcctIdentityColumn) { $r.$AcctIdentityColumn } else { '' }) }
    }
    Export-Dataset -Name 'account-status-mismatch' -Rows $mismatch -Note 'IgaInactive_ADEnabled is the highest-risk row type; a blank IGA status shows as UnmappedIgaStatus'

    # ---- 2. Group access ----
    $govRows = @(); $outside = [System.Collections.Generic.List[object]]::new(); $notInAd = [System.Collections.Generic.List[object]]::new(); $ungoverned = @()
    $nestedRows = [System.Collections.Generic.List[object]]::new(); $nonUserRows = [System.Collections.Generic.List[object]]::new()
    $groupByDN = @{}; $groupByKey = @{}; $igaMembers = @{}
    $expansionFailures = 0; $blankKeyMemberships = 0
    if (-not $AssignmentsCsv) {
        foreach ($n in 'governed-groups', 'memberships-outside-iga', 'nested-memberships-outside-iga', 'governed-group-nonuser-members', 'assignments-not-in-ad', 'ungoverned-groups') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note 'Supply -AssignmentsCsv' }
    }
    else {
        $gp = @{} + $script:AdParams
        if ($GroupSearchBase) { $gp['SearchBase'] = $GroupSearchBase }
        $adGroups = @(Get-ADGroup -Filter * -Properties member, sAMAccountName @gp)
        $grpDup = @{}
        foreach ($g in $adGroups) {
            $groupByDN[$g.DistinguishedName] = $g
            $k = "$($g.$AdGroupKey)".Trim().ToLowerInvariant()
            if (-not $k) { continue }
            if ($groupByKey.ContainsKey($k)) {
                if (-not $grpDup.ContainsKey($k)) { $grpDup[$k] = [System.Collections.Generic.List[string]]::new(); $grpDup[$k].Add($groupByKey[$k].DistinguishedName) }
                $grpDup[$k].Add($g.DistinguishedName)
            }
            else { $groupByKey[$k] = $g }
        }
        foreach ($k in $grpDup.Keys) { $dupRows.Add([pscustomobject][ordered]@{ Source = 'AD group'; Key = $k; Issue = 'DuplicateKey'; Count = $grpDup[$k].Count; Objects = Join-Values $grpDup[$k]; Handling = ("First group used; IGA assignments to this {0} are ambiguous - consider -AdGroupKey sAMAccountName or DistinguishedName" -f $AdGroupKey) }) }

        $igaGroupDisplay = @{}
        foreach ($r in $asg) {
            $gk = "$($r.$AsgResourceColumn)".Trim().ToLowerInvariant(); $ak = "$($r.$AsgAccountColumn)".Trim().ToLowerInvariant()
            if (-not $gk -or -not $ak) { continue }
            if (-not $igaMembers.ContainsKey($gk)) { $igaMembers[$gk] = [System.Collections.Generic.HashSet[string]]::new(); $igaGroupDisplay[$gk] = "$($r.$AsgResourceColumn)".Trim() }
            [void]$igaMembers[$gk].Add($ak)
        }

        # Nested groups below a group (in-memory, within -GroupSearchBase) with a parent map for the path.
        function Get-GroupTree {
            param([string]$RootDN)
            $parent = @{}; $users = [System.Collections.Generic.HashSet[string]]::new()
            $seen = [System.Collections.Generic.HashSet[string]]::new(); [void]$seen.Add($RootDN)
            $queue = [System.Collections.Generic.Queue[string]]::new(); $queue.Enqueue($RootDN)
            while ($queue.Count) {
                $cur = $queue.Dequeue(); $cg = $groupByDN[$cur]
                if (-not $cg) { continue }
                foreach ($m in @($cg.member | Where-Object { $_ })) {
                    if ($groupByDN.ContainsKey($m)) { if ($seen.Add($m)) { $parent[$m] = $cur; $queue.Enqueue($m) } }
                    elseif ($adByDN.ContainsKey($m)) { [void]$users.Add($m) }
                }
            }
            return @{ Parent = $parent; Users = $users }
        }
        function Get-NestingPath {
            param([hashtable]$Parent, [string]$DN)
            $names = [System.Collections.Generic.List[string]]::new(); $cur = $DN; $guard = 0
            while ($cur -and $guard -lt 50) { $names.Insert(0, $(if ($groupByDN.ContainsKey($cur)) { $groupByDN[$cur].Name } else { Get-CnFromDn $cur })); $cur = $Parent[$cur]; $guard++ }
            return ($names -join ' > ')
        }
        $memberTypeCache = @{}
        function Get-MemberType {
            param([string]$DN)
            if ($groupByDN.ContainsKey($DN)) { return @{ Type = 'Group'; Name = $groupByDN[$DN].Name; Note = '' } }
            if ($DN -match '(^|,)CN=ForeignSecurityPrincipals,') { return @{ Type = 'ForeignSecurityPrincipal'; Name = (Get-CnFromDn $DN); Note = 'Account or group from another domain/forest' } }
            if ($memberTypeCache.ContainsKey($DN)) { return $memberTypeCache[$DN] }
            $r = $null
            try {
                $o = Get-ADObject -Identity $DN -Properties objectClass, sAMAccountName @script:AdParams
                $cls = "$(@($o.objectClass)[-1])"
                $type = switch ($cls) { 'computer' { 'Computer' } 'user' { 'UserOutsideSearchBase' } 'inetOrgPerson' { 'UserOutsideSearchBase' } 'group' { 'GroupOutsideGroupSearchBase' } 'msDS-GroupManagedServiceAccount' { 'ManagedServiceAccount' } 'msDS-ManagedServiceAccount' { 'ManagedServiceAccount' } default { $cls } }
                $r = @{ Type = $type; Name = $(if ($o.sAMAccountName) { "$($o.sAMAccountName)" } else { Get-CnFromDn $DN }); Note = '' }
            }
            catch { $r = @{ Type = 'Unresolved'; Name = (Get-CnFromDn $DN); Note = ("Lookup failed: {0}" -f $_.Exception.Message) } }
            $memberTypeCache[$DN] = $r
            return $r
        }

        $govRows = foreach ($gk in $igaMembers.Keys) {
            $g = $groupByKey[$gk]
            $gName = $(if ($g) { $g.Name } else { $igaGroupDisplay[$gk] })
            $adSet = [System.Collections.Generic.HashSet[string]]::new()
            $directDNs = [System.Collections.Generic.HashSet[string]]::new()
            $nonUser = 0
            if ($g) {
                foreach ($m in @($g.member | Where-Object { $_ })) {
                    if ($adByDN.ContainsKey($m)) {
                        [void]$directDNs.Add($m)
                        $ak = Get-AdKey $m
                        if ($ak) { [void]$adSet.Add($ak) } else { $blankKeyMemberships++ }
                    }
                    else {
                        $mt = Get-MemberType $m
                        $nonUser++
                        $nonUserRows.Add([pscustomobject][ordered]@{ Group = $gName; Member = $mt.Name; MemberType = $mt.Type; MemberDistinguishedName = $m; InIga = $igaMembers[$gk].Contains("$($mt.Name)".ToLowerInvariant()); Note = $mt.Note })
                    }
                }
            }
            $both = 0
            foreach ($a in $adSet) {
                if ($igaMembers[$gk].Contains($a)) { $both++ }
                else { $outside.Add([pscustomobject][ordered]@{ Group = $gName; Account = $adByKey[$a].SamAccountName; ADEnabled = $adByKey[$a].Enabled; Finding = 'InADNotInIga'; GroupDistinguishedName = $(if ($g) { $g.DistinguishedName } else { '' }) }) }
            }

            # Transitive members: users who reach this group through another group.
            $nestedKeys = [System.Collections.Generic.HashSet[string]]::new()
            $nestedCount = 0; $nestedOutside = 0
            $expStatus = $(if (-not $g) { 'GroupMissingInAD' } elseif ($SkipNestedExpansion) { 'Skipped' } else { 'Completed' })
            if ($g -and -not $SkipNestedExpansion) {
                try {
                    $chain = @(Get-ADUser -LDAPFilter ("(memberOf:{0}:={1})" -f $InChain, (ConvertTo-LdapValue $g.DistinguishedName)) -Properties enabled, memberOf @p)
                    $tree = Get-GroupTree $g.DistinguishedName
                    foreach ($cu in $chain) {
                        if ($directDNs.Contains($cu.DistinguishedName)) { continue }
                        $ak = "$($cu.$AdAccountKey)".Trim().ToLowerInvariant()
                        if (-not $ak) { $blankKeyMemberships++; continue }
                        $nestedCount++
                        [void]$nestedKeys.Add($ak)
                        $via = @($cu.memberOf | Where-Object { $_ -and $tree.Parent.ContainsKey($_) })
                        $inIga = $igaMembers[$gk].Contains($ak)
                        if (-not $inIga) { $nestedOutside++ }
                        $nestedRows.Add([pscustomobject][ordered]@{
                            Account     = $cu.SamAccountName
                            Group       = $gName
                            ViaGroup    = $(if ($via.Count) { Join-Values ($via | ForEach-Object { $groupByDN[$_].Name }) } else { '(group outside -GroupSearchBase)' })
                            Enabled     = $cu.Enabled
                            InIga       = $inIga
                            NestingPath = $(if ($via.Count) { Join-Values ($via | ForEach-Object { Get-NestingPath $tree.Parent $_ }) } else { '' })
                        })
                    }
                }
                catch {
                    $expansionFailures++
                    $expStatus = "Failed: $($_.Exception.Message)"
                    Write-RunLog ("Nested members of {0} not readable: {1}" -f $gName, $_.Exception.Message) 'WARN'
                }
            }
            foreach ($a in $igaMembers[$gk]) {
                if (-not $adSet.Contains($a)) {
                    $finding = $(if (-not $g) { 'GroupMissingInAD' } elseif (-not $adByKey.ContainsKey($a)) { 'AccountMissingInAD' } elseif ($nestedKeys.Contains($a)) { 'ProvisionedViaNesting' } else { 'NotProvisioned' })
                    $notInAd.Add([pscustomobject][ordered]@{ Group = $gName; Account = $a; GroupExistsInAD = [bool]$g; AccountExistsInAD = $adByKey.ContainsKey($a); Finding = $finding })
                }
            }
            [pscustomobject][ordered]@{
                Group             = $gName
                ExistsInAD        = [bool]$g
                IgaAssignments    = $igaMembers[$gk].Count
                ADUserMembers     = $adSet.Count
                InBoth            = $both
                ADOnly            = $adSet.Count - $both
                IgaOnly           = $igaMembers[$gk].Count - $both
                NestedUserMembers = $nestedCount
                NestedNotInIga    = $nestedOutside
                NonUserMembers    = $nonUser
                ExpansionStatus   = $expStatus
                DistinguishedName = $(if ($g) { $g.DistinguishedName } else { '' })
            }
        }
        Export-Dataset -Name 'governed-groups' -Rows @($govRows | Sort-Object ADOnly -Descending)
        Export-Dataset -Name 'memberships-outside-iga' -Rows $outside -Note 'Access granted directly in AD to a governed group'
        if ($SkipNestedExpansion) { Set-DatasetStatus -Name 'nested-memberships-outside-iga' -Status 'Deferred' -Note '-SkipNestedExpansion' }
        elseif ($expansionFailures) { Export-Dataset -Name 'nested-memberships-outside-iga' -Rows $nestedRows -Status 'Partial' -Note ("{0} governed group(s) could not be expanded; see ExpansionStatus in governed-groups.csv" -f $expansionFailures) }
        else { Export-Dataset -Name 'nested-memberships-outside-iga' -Rows $nestedRows -Note 'Users reaching a governed group through another group; InIga=False is access the IGA does not grant' }
        Export-Dataset -Name 'governed-group-nonuser-members' -Rows $nonUserRows -Note 'Groups, computers, foreign principals and out-of-scope users inside governed groups'
        Export-Dataset -Name 'assignments-not-in-ad' -Rows $notInAd -Note 'ProvisionedViaNesting = the account holds the access through a nested group, not directly'

        $ungoverned = foreach ($g in $adGroups) {
            if ($g.GroupCategory -ne 'Security') { continue }
            $k = "$($g.$AdGroupKey)".Trim().ToLowerInvariant()
            if ($k -and $igaMembers.ContainsKey($k)) { continue }
            $userMembers = @($g.member | Where-Object { $_ -and $adByDN.ContainsKey($_) }).Count
            $transitive = $userMembers
            if (@($g.member | Where-Object { $_ -and $groupByDN.ContainsKey($_) }).Count) { $transitive = (Get-GroupTree $g.DistinguishedName).Users.Count }
            if ($userMembers -eq 0 -and $transitive -eq 0) { continue }
            [pscustomobject][ordered]@{ Group = $g.Name; UserMembers = $userMembers; Scope = $g.GroupScope; DistinguishedName = $g.DistinguishedName; TransitiveUserMembers = $transitive }
        }
        Export-Dataset -Name 'ungoverned-groups' -Rows @($ungoverned | Sort-Object TransitiveUserMembers, UserMembers -Descending) -Note 'Security groups with users (direct or nested) that no IGA assignment references'
    }

    # ---- Leavers still holding access: inactive in IGA, disabled in AD, still in groups ----
    $governedDN = @{}
    foreach ($gk in $igaMembers.Keys) { if ($groupByKey.ContainsKey($gk)) { $governedDN[$groupByKey[$gk].DistinguishedName] = $true } }
    $inactiveMember = foreach ($k in $igaByKey.Keys) {
        if (-not $adByKey.ContainsKey($k)) { continue }
        $r = $igaByKey[$k]; $u = $adByKey[$k]
        if ((Get-StatusClass $r.$AcctStatusColumn) -ne 'Inactive' -or $u.Enabled) { continue }
        $mo = @($u.memberOf | Where-Object { $_ })
        if ($mo.Count -eq 0) { continue }
        [pscustomobject][ordered]@{
            SamAccountName = $u.SamAccountName
            IgaStatus      = $r.$AcctStatusColumn
            ADEnabled      = $u.Enabled
            MemberOfCount  = $mo.Count
            Groups         = Format-Capped ($mo | ForEach-Object { Get-CnFromDn $_ })
            GovernedGroups = $(if ($AssignmentsCsv) { Join-Values ($mo | Where-Object { $governedDN.ContainsKey($_) } | ForEach-Object { Get-CnFromDn $_ }) } else { 'n/a (no -AssignmentsCsv)' })
            IdentityId     = $(if ($r.PSObject.Properties.Name -contains $AcctIdentityColumn) { $r.$AcctIdentityColumn } else { '' })
        }
    }
    Export-Dataset -Name 'inactive-but-still-member' -Rows @($inactiveMember | Sort-Object MemberOfCount -Descending) -Note 'Disabled leavers keep group memberships: re-enabling restores all of it. Primary group not counted.'
    Export-Dataset -Name 'duplicate-keys' -Rows $dupRows -Note 'Duplicate or blank match keys; rows here were not (or not fully) reconciled'

    # ---- 3. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'AD users in scope' $adUsers.Count
    Add-Metric 'IGA accounts for this system' $igaByKey.Count
    Add-Metric -Metric 'AD accounts managed by IGA (%)' -Value $(if ($keyedCount) { [math]::Round(100 * ($keyedCount - @($adNotInIga).Count) / $keyedCount, 1) } else { 0 }) -Note $(if ($unkeyed.Count) { "Of $keyedCount AD users with a $AdAccountKey" } else { '' })
    Add-Metric -Metric 'Enabled AD accounts unknown to IGA' -Value @($adNotInIga | Where-Object Classification -eq 'UnmanagedEnabled').Count -Note 'Excludes service/admin name patterns'
    Add-Metric 'Service/admin-pattern accounts unknown to IGA' @($adNotInIga | Where-Object Classification -eq 'ServiceOrAdminPattern').Count
    Add-Metric -Metric 'Accounts unknown to IGA with adminCount=1' -Value @($adNotInIga | Where-Object AdminCount).Count -Note 'Protected (current or former privileged) accounts outside governance'
    Add-Metric 'Active IGA accounts missing from AD' @($igaNotInAd | Where-Object IgaStatusClass -eq 'Active').Count
    Add-Metric -Metric 'IGA inactive but AD enabled' -Value @($mismatch | Where-Object MismatchType -eq 'IgaInactive_ADEnabled').Count -Note 'Highest risk'
    Add-Metric 'IGA active but AD disabled' @($mismatch | Where-Object MismatchType -eq 'IgaActive_ADDisabled').Count
    Add-Metric -Metric 'IGA status values not mapped' -Value @($mismatch | Where-Object MismatchType -eq 'UnmappedIgaStatus').Count -Note 'Extend -ActiveStatusValues / -InactiveStatusValues'
    Add-Metric -Metric 'IGA accounts with a blank status' -Value $blankStatus -Note 'Classed as Unknown, not Active'
    Add-Metric -Metric 'IGA inactive, AD disabled, still in groups' -Value @($inactiveMember).Count -Note 'See inactive-but-still-member.csv'
    Add-Metric -Metric 'AD users with a blank match key (skipped)' -Value $unkeyed.Count -Note $AdAccountKey
    Add-Metric -Metric 'Duplicate keys' -Value @($dupRows | Where-Object Issue -eq 'DuplicateKey').Count -Note 'See duplicate-keys.csv'
    if ($AssignmentsCsv) {
        Add-Metric 'Groups governed by IGA' @($govRows).Count
        Add-Metric 'Governed groups missing in AD' @($govRows | Where-Object { -not $_.ExistsInAD }).Count
        Add-Metric -Metric 'Memberships granted outside IGA' -Value $outside.Count -Note 'Direct membership'
        Add-Metric -Metric 'Nested memberships not granted by IGA' -Value $(if ($SkipNestedExpansion) { 'not checked' } else { @($nestedRows | Where-Object { -not $_.InIga }).Count }) -Note $(if ($expansionFailures) { "$expansionFailures group(s) could not be expanded - lower bound" } else { '' })
        Add-Metric 'Non-user members of governed groups' $nonUserRows.Count
        Add-Metric -Metric 'IGA assignments not present in AD' -Value @($notInAd | Where-Object Finding -ne 'ProvisionedViaNesting').Count -Note 'Excludes assignments held through nesting'
        Add-Metric -Metric 'Ungoverned security groups with members' -Value @($ungoverned).Count -Note 'Direct or nested users'
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ AccountsCsv = (Split-Path $AccountsCsv -Leaf); AssignmentsCsv = $(if ($AssignmentsCsv) { Split-Path $AssignmentsCsv -Leaf } else { '' }); SystemName = $SystemName; AdAccountKey = $AdAccountKey; AdGroupKey = $AdGroupKey; ActiveStatusValues = $ActiveStatusValues; InactiveStatusValues = $InactiveStatusValues; SearchBase = $SearchBase; GroupSearchBase = $GroupSearchBase; AdminNamePatterns = $AdminNamePatterns; SkipNestedExpansion = [bool]$SkipNestedExpansion }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
