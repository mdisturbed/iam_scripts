<#
.SYNOPSIS
    Read-only analysis of group nesting and group hygiene in on-premises Active Directory.

.DESCRIPTION
    Builds the full group-in-group graph for the domain in memory and exports:
      - One row per group: type, scope, direct member counts, how deep nesting goes beneath it
        (DepthDown) and above it (DepthUp), circular-nesting membership, hygiene flags (empty, no
        owner, owner disabled or stale, no description, mail-enabled security group, all members
        disabled, naming-convention miss) and whether the full member list could be read
      - One row per circular-nesting loop
      - One row per nesting edge (group inside group), including members that could not be
        followed because they sit outside -SearchBase or in another domain (Status OutOfScope)
      - Per group, the accounts it really reaches through nesting: effective users (enabled /
        disabled), computers, foreign principals and contacts, including accounts that hold a group
        as their primary group, and whether the group is nested (at any depth) into a privileged
        built-in group, with the path
      - A summary of headline metrics

    Groups with very large membership are read with ranged retrieval (member;range=...) so counts
    are complete; a group whose full list cannot be read is marked Partial.

    Feeds the "nested groups / RBAC" part of the gap analysis and is the baseline for role mining.

    READ-ONLY. Uses only Get-AD* cmdlets. Nothing in the directory is changed.

    Output: <OutputRoot>\05-ADGroupNesting\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER SearchBase
    Limits which groups are read and analysed. Members outside it are still classified (one
    domain-wide read of users, computers, contacts and foreign principals); groups outside it are
    recorded as OutOfScope edges and not followed.

.PARAMETER NamingConventionRegex
    Optional regex a well-named group should match, e.g. '^(RB|APP|FS|ADM)-'. Blank = not evaluated.

.PARAMETER StaleDays
    An enabled owner (managedBy) with no logon for this many days is flagged OwnerStale.

.PARAMETER SkipReach
    Do not compute effective membership and privileged reach (ad-group-reach). Faster in very large domains.

.EXAMPLE
    .\05-Get-ADGroupNesting.ps1
.EXAMPLE
    .\05-Get-ADGroupNesting.ps1 -Server dc01.contoso.local -DeepNestingThreshold 3 -NamingConventionRegex '^(RB|APP)-'
.EXAMPLE
    .\05-Get-ADGroupNesting.ps1 -SearchBase 'OU=Groups,DC=contoso,DC=local' -SkipReach

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account (read)
    Load    : one read of every group (with members) and one read of every user, computer, contact
              and foreign principal (classification only). Groups with 1500 or more members get an
              extra ranged read.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                       # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                   # blank = whole domain
    [int]$DeepNestingThreshold = 3,
    [string]$NamingConventionRegex = '',
    [int]$StaleDays = 90,
    [switch]$SkipReach
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '05-ADGroupNesting'
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

$RangeStep = 1500       # values per ranged read; lists of this size or more are re-read in ranges
$script:DomainDns = ''
function Get-DnsDomainFromDN { param([string]$DN) return ((@([regex]::Matches($DN, '(?i)(?:^|,)DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }) -join '.').ToLowerInvariant()) }
function Get-ParamsForDN {
    param([string]$DN)
    $d = Get-DnsDomainFromDN $DN
    if (-not $d -or $d -eq $script:DomainDns) { return $script:AdParams }
    return @{ Server = $d }
}
function ConvertFrom-FileTime { param($Value) if ($null -eq $Value -or "$Value" -eq '' -or [int64]"$Value" -le 0 -or [int64]"$Value" -eq [int64]::MaxValue) { return $null } return [datetime]::FromFileTimeUtc([int64]"$Value") }
function Get-SidText {
    param($Obj)
    $s = $null
    if ($null -ne $Obj.SID) { $s = $Obj.SID } elseif ($null -ne $Obj.objectSid) { $s = $Obj.objectSid }
    if ($null -eq $s) { return '' }
    if ($s -is [byte[]]) { try { return ([System.Security.Principal.SecurityIdentifier]::new($s, 0)).Value } catch { return '' } }
    if ($null -ne $s.Value) { return [string]$s.Value }
    return "$s"
}
function Get-RangedMember {
    # Full member list through ranged retrieval (member;range=low-high), RangeStep values per read.
    param([string]$DN)
    $all = [System.Collections.Generic.List[string]]::new()
    $p = Get-ParamsForDN $DN
    $low = 0
    for ($guard = 0; $guard -lt 100000; $guard++) {
        $attr = 'member;range={0}-{1}' -f $low, ($low + $RangeStep - 1)
        $o = Get-ADObject -Identity $DN -Properties $attr @p
        $names = $(if ($null -ne $o.PropertyNames) { @($o.PropertyNames) } else { @($o.PSObject.Properties.Name) })
        $pn = @($names | Where-Object { "$_" -like 'member;range=*' } | Select-Object -First 1)
        if (-not $pn.Count) { if ($low -eq 0) { throw 'the ranged member attribute was not returned' } break }
        $vals = @($o.($pn[0]) | Where-Object { $_ })
        foreach ($v in $vals) { $all.Add([string]$v) }
        if ("$($pn[0])" -match '-\*$' -or -not $vals.Count) { break }
        $low += $vals.Count
    }
    return , $all.ToArray()
}

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain @script:AdParams
    $domainName = $domain.DNSRoot
    $script:DomainDns = ([string]$domainName).ToLowerInvariant()
    $domainSid = $domain.DomainSID.Value

    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    Write-RunLog 'Reading all groups (this can take a few minutes in large domains)...'
    $groups = @(Get-ADGroup -Filter * -Properties member, memberOf, managedBy, description, mail, whenCreated, whenChanged, adminCount, objectSid @p)
    Write-RunLog ("{0} groups read" -f $groups.Count)

    # ---- Full member lists (ranged retrieval for large groups) ----
    $memberList = @{}; $partialGroups = @{}
    foreach ($g in $groups) {
        $dn = $g.DistinguishedName
        $m = @($g.member | Where-Object { $_ })
        if ($m.Count -ge $RangeStep) {
            try {
                $full = Get-RangedMember $dn
                if ($full.Count -ge $m.Count) { $m = @($full) }
                Write-RunLog ("{0}: {1} members read with ranged retrieval" -f $g.Name, $m.Count)
            }
            catch { $partialGroups[$dn] = $_.Exception.Message; Write-RunLog ("{0}: ranged member read failed, member list may be incomplete ({1} read): {2}" -f $g.Name, $m.Count, $_.Exception.Message) 'WARN' }
        }
        $memberList[$dn] = $m
    }

    # ---- Classify every possible member once (domain-wide, not limited by -SearchBase) ----
    $principals = @{}       # DN -> Kind (user / computer / contact / foreign), Enabled, LastLogon, Sam
    $primaryOf = @{}        # primaryGroupID (RID) -> list of account DNs
    $principalRead = $true; $principalError = ''
    try {
        Write-RunLog 'Reading users, computers, contacts and foreign principals for classification...'
        Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=contact)(objectClass=foreignSecurityPrincipal))' -Properties objectClass, userAccountControl, lastLogonTimestamp, sAMAccountName, primaryGroupID -ResultPageSize 1000 @script:AdParams | ForEach-Object {
            $cls = [string]@($_.objectClass)[-1]
            $kind = switch ($cls) {
                'computer' { 'computer' } 'msDS-GroupManagedServiceAccount' { 'computer' } 'msDS-ManagedServiceAccount' { 'computer' }
                'contact' { 'contact' } 'foreignSecurityPrincipal' { 'foreign' } default { 'user' }
            }
            $uacVal = 0; if ($null -ne $_.userAccountControl -and "$($_.userAccountControl)" -ne '') { $uacVal = [int64]"$($_.userAccountControl)" }
            $dn = [string]$_.DistinguishedName
            $principals[$dn] = [pscustomobject]@{ Kind = $kind; Enabled = $(if ($kind -in 'user', 'computer') { -not ($uacVal -band 2) } else { $null }); LastLogon = ConvertFrom-FileTime $_.lastLogonTimestamp; Sam = [string]$_.sAMAccountName; Class = $cls }
            if ($kind -in 'user', 'computer' -and "$($_.primaryGroupID)" -ne '') {
                $rid = [string]$_.primaryGroupID
                if (-not $primaryOf.ContainsKey($rid)) { $primaryOf[$rid] = [System.Collections.Generic.List[string]]::new() }
                $primaryOf[$rid].Add($dn)
            }
        }
        Write-RunLog ("{0} users, computers, contacts and foreign principals classified" -f $principals.Count)
    }
    catch { $principalRead = $false; $principalError = $_.Exception.Message; Write-RunLog ("Member classification read failed; reach, owner and all-disabled checks limited: {0}" -f $principalError) 'WARN' }
    $allGroupDNs = @{}
    if ($SearchBase) {
        try { Get-ADObject -LDAPFilter '(objectClass=group)' -ResultPageSize 1000 @script:AdParams | ForEach-Object { $allGroupDNs[[string]$_.DistinguishedName] = $true } }
        catch { Write-RunLog ("Domain-wide group list not readable; out-of-scope members are not typed: {0}" -f $_.Exception.Message) 'WARN' }
    }

    # ---- Build graph: parent DN -> child group DNs; record edges that cannot be followed ----
    $byDN = @{}
    foreach ($g in $groups) { $byDN[$g.DistinguishedName] = $g }
    $children = @{}; $parents = @{}; $nonGroup = @{}; $outOfScope = @{}; $primaryCount = @{}
    foreach ($g in $groups) { $dn = $g.DistinguishedName; $children[$dn] = [System.Collections.Generic.List[string]]::new(); $parents[$dn] = [System.Collections.Generic.List[string]]::new(); $nonGroup[$dn] = [System.Collections.Generic.List[string]]::new(); $outOfScope[$dn] = 0; $primaryCount[$dn] = 0 }
    $edgeRows = [System.Collections.Generic.List[object]]::new()
    $script:Unclassified = 0
    foreach ($g in $groups) {
        $dn = $g.DistinguishedName
        foreach ($m in $memberList[$dn]) {
            if ($byDN.ContainsKey($m)) {
                $children[$dn].Add($m); $parents[$m].Add($dn)
                $edgeRows.Add([pscustomobject][ordered]@{ ParentGroup = $g.Name; MemberName = $byDN[$m].Name; MemberType = 'group'; Status = 'InScope'; Reason = ''; ParentDN = $dn; MemberDN = $m })
                continue
            }
            if ($principals.ContainsKey($m)) { $nonGroup[$dn].Add($m); continue }
            $mDomain = Get-DnsDomainFromDN $m
            $isGroup = $allGroupDNs.ContainsKey($m)
            if (-not $principalRead -and -not $isGroup -and (-not $mDomain -or $mDomain -eq $script:DomainDns)) { $script:Unclassified++; continue }   # cannot tell a user from a group here
            $reason = $(if ($mDomain -and $mDomain -ne $script:DomainDns) { "In another domain ($mDomain): not followed" }
                elseif ($isGroup) { 'Group outside -SearchBase: not followed' }
                elseif ($SearchBase) { 'Outside -SearchBase or not readable: not followed' }
                else { 'Not readable by the run account' })
            $outOfScope[$dn]++
            $edgeRows.Add([pscustomobject][ordered]@{ ParentGroup = $g.Name; MemberName = ($m -replace '^CN=((?:[^,\\]|\\.)+),.*$', '$1'); MemberType = $(if ($isGroup) { 'group' } else { 'unknown' }); Status = 'OutOfScope'; Reason = $reason; ParentDN = $dn; MemberDN = $m })
        }
        $sid = Get-SidText $g
        if ($domainSid -and $sid -like "$domainSid-*") {
            $rid = ($sid -split '-')[-1]
            if ($primaryOf.ContainsKey($rid)) { foreach ($pdn in $primaryOf[$rid]) { $nonGroup[$dn].Add($pdn) }; $primaryCount[$dn] = $primaryOf[$rid].Count }
        }
    }
    $oosEdges = @($edgeRows | Where-Object Status -eq 'OutOfScope').Count

    # ---- Circular nesting: Tarjan strongly-connected components (every group gets a component id) ----
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $onStack = @{}; $idx = @{}; $low = @{}
    $cycleOf = @{}; $cycles = [System.Collections.Generic.List[object]]::new()
    $compOf = @{}; $compMembers = @{}
    function Invoke-Tarjan {
        param([string]$v)
        $idx[$v] = $script:tIndex; $low[$v] = $script:tIndex; $script:tIndex++
        $stack.Push($v); $onStack[$v] = $true
        foreach ($w in $children[$v]) {
            if (-not $idx.ContainsKey($w)) { Invoke-Tarjan $w; $low[$v] = [math]::Min($low[$v], $low[$w]) }
            elseif ($onStack[$w]) { $low[$v] = [math]::Min($low[$v], $idx[$w]) }
        }
        if ($low[$v] -eq $idx[$v]) {
            $comp = [System.Collections.Generic.List[string]]::new()
            do { $w = $stack.Pop(); $onStack[$w] = $false; $comp.Add($w) } while ($w -ne $v)
            $compId = 'S{0}' -f $compMembers.Count
            $compMembers[$compId] = $comp
            foreach ($c in $comp) { $compOf[$c] = $compId }
            $selfLoop = $children[$v].Contains($v)
            if ($comp.Count -gt 1 -or $selfLoop) {
                $cid = 'C{0:000}' -f ($cycles.Count + 1)
                foreach ($c in $comp) { $cycleOf[$c] = $cid }
                $cycles.Add([pscustomobject][ordered]@{ CycleId = $cid; GroupCount = $comp.Count; Groups = Join-Values ($comp | ForEach-Object { $byDN[$_].Name }) })
            }
        }
    }
    $script:tIndex = 0
    foreach ($g in $groups) { if (-not $idx.ContainsKey($g.DistinguishedName)) { Invoke-Tarjan $g.DistinguishedName } }

    # ---- Depth on the condensed graph (each loop collapsed to one node, so depth is never cut short next to a loop) ----
    $downC = @{}; $upC = @{}
    foreach ($cid in $compMembers.Keys) { $downC[$cid] = [System.Collections.Generic.HashSet[string]]::new(); $upC[$cid] = [System.Collections.Generic.HashSet[string]]::new() }
    foreach ($v in $children.Keys) { foreach ($w in $children[$v]) { $a = $compOf[$v]; $b = $compOf[$w]; if ($a -ne $b) { [void]$downC[$a].Add($b); [void]$upC[$b].Add($a) } } }
    function Get-CompDepth {
        param([string]$Comp, [hashtable]$Edges, [hashtable]$Memo)
        if ($Memo.ContainsKey($Comp)) { return $Memo[$Comp] }
        $max = 0
        foreach ($c2 in $Edges[$Comp]) { $d = 1 + (Get-CompDepth -Comp $c2 -Edges $Edges -Memo $Memo); if ($d -gt $max) { $max = $d } }
        $Memo[$Comp] = $max
        return $max
    }
    $downMemo = @{}; $upMemo = @{}

    # ---- Owners (managedBy) ----
    $ownerCache = @{}
    function Get-OwnerInfo {
        param([string]$OwnerDN)
        if ($ownerCache.ContainsKey($OwnerDN)) { return $ownerCache[$OwnerDN] }
        $info = [pscustomobject]@{ Name = ($OwnerDN -replace '^CN=((?:[^,\\]|\\.)+),.*$', '$1'); Class = ''; Enabled = ''; LastLogon = $null; Status = '' }
        if ($principals.ContainsKey($OwnerDN)) {
            $pr = $principals[$OwnerDN]
            $info.Name = $(if ($pr.Sam) { $pr.Sam } else { $info.Name }); $info.Class = $pr.Class; $info.Enabled = $pr.Enabled; $info.LastLogon = $pr.LastLogon
        }
        elseif ($byDN.ContainsKey($OwnerDN)) { $info.Name = $byDN[$OwnerDN].Name; $info.Class = 'group' }
        else {
            $op = Get-ParamsForDN $OwnerDN
            try {
                $o = Get-ADObject -Identity $OwnerDN -Properties objectClass, userAccountControl, lastLogonTimestamp, sAMAccountName @op
                $info.Class = [string]@($o.objectClass)[-1]
                if ($o.sAMAccountName) { $info.Name = [string]$o.sAMAccountName }
                if ($info.Class -ne 'group' -and $info.Class -ne 'contact' -and "$($o.userAccountControl)" -ne '') { $info.Enabled = -not ([int64]"$($o.userAccountControl)" -band 2); $info.LastLogon = ConvertFrom-FileTime $o.lastLogonTimestamp }
            }
            catch { $info.Status = 'Unresolved'; Write-RunLog ("Owner {0} not readable: {1}" -f $OwnerDN, $_.Exception.Message) 'WARN' }
        }
        if (-not $info.Status) {
            $info.Status = $(if ($info.Class -eq 'group') { 'OwnerIsGroup' }
                elseif ($info.Class -eq 'contact') { 'OwnerIsContact' }
                elseif ($info.Enabled -eq $false) { 'OwnerDisabled' }
                elseif ($info.Enabled -eq $true -and ((-not $info.LastLogon) -or (($script:RunStartUtc - $info.LastLogon).TotalDays -gt $StaleDays))) { 'OwnerStale' }
                else { 'OK' })
        }
        $ownerCache[$OwnerDN] = $info
        return $info
    }

    # ---- Effective membership and privileged reach ----
    $reachByComp = @{}
    $privTargets = [System.Collections.Generic.List[object]]::new()   # Label, DN, InScope
    $reachNotes = [System.Collections.Generic.List[string]]::new()
    if (-not $SkipReach -and $principalRead) {
        Write-RunLog 'Computing effective membership for every group...'
        foreach ($cid in $compMembers.Keys) {
            $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $seenC = [System.Collections.Generic.HashSet[string]]::new()
            $q = [System.Collections.Generic.Queue[string]]::new(); $q.Enqueue($cid)
            $oos = 0; $partial = $false; $nested = 0
            while ($q.Count) {
                $c = $q.Dequeue()
                if (-not $seenC.Add($c)) { continue }
                foreach ($v in $compMembers[$c]) {
                    foreach ($m in $nonGroup[$v]) { [void]$set.Add($m) }
                    $oos += $outOfScope[$v]
                    if ($partialGroups.ContainsKey($v)) { $partial = $true }
                    if ($c -ne $cid) { $nested++ }
                }
                foreach ($c2 in $downC[$c]) { $q.Enqueue($c2) }
            }
            $nested += $compMembers[$cid].Count - 1
            $r = [pscustomobject]@{ Users = 0; EnabledUsers = 0; DisabledUsers = 0; Computers = 0; EnabledComputers = 0; Foreign = 0; Contacts = 0; OutOfScope = $oos; Partial = $partial; NestedGroups = $nested }
            foreach ($m in $set) {
                $pr = $principals[$m]
                switch ($pr.Kind) {
                    'user' { $r.Users++; if ($pr.Enabled) { $r.EnabledUsers++ } else { $r.DisabledUsers++ } }
                    'computer' { $r.Computers++; if ($pr.Enabled) { $r.EnabledComputers++ } }
                    'foreign' { $r.Foreign++ }
                    'contact' { $r.Contacts++ }
                }
            }
            $reachByComp[$cid] = $r
        }

        # Privileged built-in groups: this domain's from the groups read; forest-root ones read from the root domain.
        $privRid = @{ '512' = 'Domain Admins'; '520' = 'Group Policy Creator Owners'; '526' = 'Key Admins' }
        $privBuiltin = @{ 'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-548' = 'Account Operators'; 'S-1-5-32-549' = 'Server Operators'; 'S-1-5-32-550' = 'Print Operators'; 'S-1-5-32-551' = 'Backup Operators' }
        $rootRid = @{ '518' = 'Schema Admins'; '519' = 'Enterprise Admins'; '527' = 'Enterprise Key Admins' }
        $forest = $null; $rootDns = $script:DomainDns
        try { $forest = Get-ADForest @script:AdParams; $rootDns = ([string]$forest.RootDomain).ToLowerInvariant() } catch { $reachNotes.Add("Forest not readable: $($_.Exception.Message)") }
        foreach ($g in $groups) {
            $sid = Get-SidText $g
            $label = ''
            if ($privBuiltin.ContainsKey($sid)) { $label = $privBuiltin[$sid] }
            elseif ($domainSid -and $sid -like "$domainSid-*") {
                $rid = ($sid -split '-')[-1]
                if ($privRid.ContainsKey($rid)) { $label = $privRid[$rid] }
                elseif ($rootDns -eq $script:DomainDns -and $rootRid.ContainsKey($rid)) { $label = $rootRid[$rid] }
            }
            if (-not $label -and [string]$g.SamAccountName -eq 'DnsAdmins') { $label = 'DnsAdmins' }
            if ($label) { $privTargets.Add([pscustomobject]@{ Label = $label; DN = $g.DistinguishedName; InScope = $true; Members = $null }) }
        }
        if ($forest -and $rootDns -ne $script:DomainDns) {
            try {
                $rp = @{ Server = [string]$forest.RootDomain }
                $rootSid = (Get-ADDomain -Identity $forest.RootDomain @rp).DomainSID.Value
                foreach ($rid in $rootRid.Keys) {
                    try {
                        $rg = Get-ADGroup -Identity "$rootSid-$rid" @rp
                        $rm = @(Get-ADObject -Identity $rg.DistinguishedName -Properties member @rp | ForEach-Object { $_.member } | Where-Object { $_ })
                        $privTargets.Add([pscustomobject]@{ Label = $rootRid[$rid]; DN = [string]$rg.DistinguishedName; InScope = $false; Members = $rm })
                    }
                    catch { $reachNotes.Add(("{0} in the forest root not read: {1}" -f $rootRid[$rid], $_.Exception.Message)) }
                }
            }
            catch { $reachNotes.Add(("Forest root {0} not readable; Schema / Enterprise Admins reach not evaluated: {1}" -f $forest.RootDomain, $_.Exception.Message)) }
        }
        foreach ($n in $reachNotes) { Write-RunLog $n 'WARN' }

        # Reverse BFS from each privileged group down through its nested groups; next-hop map gives the path.
        $privReach = @{}     # group DN -> List of @{ Label; Path }
        foreach ($t in $privTargets) {
            $next = @{}
            $q = [System.Collections.Generic.Queue[string]]::new()
            $seeds = $(if ($t.InScope) { @($children[$t.DN]) } else { @($t.Members | Where-Object { $byDN.ContainsKey($_) }) })
            foreach ($s in $seeds) { if (-not $next.ContainsKey($s)) { $next[$s] = $t.DN; $q.Enqueue($s) } }
            while ($q.Count) {
                $x = $q.Dequeue()
                foreach ($c in $children[$x]) { if ($c -ne $t.DN -and -not $next.ContainsKey($c)) { $next[$c] = $x; $q.Enqueue($c) } }
            }
            foreach ($gdn in $next.Keys) {
                $names = [System.Collections.Generic.List[string]]::new(); $cur = $gdn; $hops = 0
                while ($cur -ne $t.DN -and $hops -lt 1000) { $names.Add([string]$byDN[$cur].Name); $cur = $next[$cur]; $hops++ }
                $names.Add($t.Label)
                if (-not $privReach.ContainsKey($gdn)) { $privReach[$gdn] = [System.Collections.Generic.List[object]]::new() }
                $privReach[$gdn].Add([pscustomobject]@{ Label = $t.Label; Path = ($names -join ' > '); Hops = $names.Count })
            }
        }
    }
    elseif (-not $SkipReach) { $reachNotes.Add("Member classification read failed: $principalError") }
    $privDNs = @{}; foreach ($t in $privTargets) { if ($t.InScope) { $privDNs[$t.DN] = $t.Label } }

    # ---- 1. Per-group rows ----
    $reachRows = [System.Collections.Generic.List[object]]::new()
    $rows = foreach ($g in $groups) {
        $dn = $g.DistinguishedName
        $members = @($memberList[$dn])
        $groupMembers = $children[$dn].Count
        $down = Get-CompDepth -Comp $compOf[$dn] -Edges $downC -Memo $downMemo
        $up = Get-CompDepth -Comp $compOf[$dn] -Edges $upC -Memo $upMemo
        $isSecurity = ($g.GroupCategory -eq 'Security')
        $owner = $null
        if ($g.managedBy) { $owner = Get-OwnerInfo ([string]$g.managedBy) }
        $reach = $(if ($reachByComp.ContainsKey($compOf[$dn])) { $reachByComp[$compOf[$dn]] } else { $null })
        # All members disabled: every account reached (or, without reach, every direct account) is disabled, nothing unclassified.
        $allDisabled = ''
        if ($reach) {
            $accts = $reach.Users + $reach.Computers
            $allDisabled = ($accts -gt 0 -and ($reach.EnabledUsers + $reach.EnabledComputers) -eq 0 -and $reach.Foreign -eq 0 -and $reach.OutOfScope -eq 0 -and -not $reach.Partial)
        }
        elseif ($principalRead -and $groupMembers -eq 0 -and $outOfScope[$dn] -eq 0 -and -not $partialGroups.ContainsKey($dn)) {
            $direct = @($nonGroup[$dn] | ForEach-Object { $principals[$_] } | Where-Object { $_.Kind -in 'user', 'computer', 'foreign' })
            $allDisabled = ($direct.Count -gt 0 -and @($direct | Where-Object { $_.Enabled -ne $false }).Count -eq 0)
        }
        $flags = @()
        if ($members.Count -eq 0 -and $primaryCount[$dn] -eq 0) { $flags += 'Empty' }
        if (-not $g.managedBy) { $flags += 'NoManagedBy' }
        elseif ($owner.Status -in 'OwnerDisabled', 'OwnerStale') { $flags += $owner.Status }
        elseif ($owner.Status -eq 'Unresolved') { $flags += 'OwnerUnresolved' }
        if (-not $g.description) { $flags += 'NoDescription' }
        if ($isSecurity -and $g.mail) { $flags += 'MailEnabledSecurity' }
        if ($down -ge $DeepNestingThreshold) { $flags += "DeepNesting(>=$DeepNestingThreshold)" }
        if ($cycleOf.ContainsKey($dn)) { $flags += 'CircularNesting' }
        if ($partialGroups.ContainsKey($dn)) { $flags += 'MemberListTruncated' }
        if ($allDisabled -eq $true) { $flags += 'AllMembersDisabled' }
        if ($outOfScope[$dn] -gt 0) { $flags += 'HasOutOfScopeMembers' }
        if ($NamingConventionRegex -and ($g.Name -notmatch $NamingConventionRegex)) { $flags += 'NamingConventionMiss' }
        [pscustomobject][ordered]@{
            Name                 = $g.Name
            SamAccountName       = $g.SamAccountName
            Category             = $g.GroupCategory
            Scope                = $g.GroupScope
            DirectMembers        = $members.Count
            DirectGroupMembers   = $groupMembers
            DirectOtherMembers   = $members.Count - $groupMembers
            MemberOfGroups       = $parents[$dn].Count
            DepthDown            = $down
            DepthUp              = $up
            CycleId              = $(if ($cycleOf.ContainsKey($dn)) { $cycleOf[$dn] } else { '' })
            AdminCount           = $g.adminCount
            HasManagedBy         = [bool]$g.managedBy
            MailEnabled          = [bool]$g.mail
            WhenCreated          = $g.whenCreated
            WhenChanged          = $g.whenChanged
            Flags                = Join-Values $flags
            DistinguishedName    = $dn
            OutOfScopeMembers    = $outOfScope[$dn]
            PrimaryGroupMembers  = $(if ($principalRead) { $primaryCount[$dn] } else { '' })
            MemberReadStatus     = $(if ($partialGroups.ContainsKey($dn)) { 'Partial' } else { 'Complete' })
            OwnerName            = $(if ($owner) { $owner.Name } else { '' })
            OwnerClass           = $(if ($owner) { $owner.Class } else { '' })
            OwnerEnabled         = $(if ($owner) { $owner.Enabled } else { '' })
            OwnerLastLogonUtc    = $(if ($owner -and $owner.LastLogon) { $owner.LastLogon.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            OwnerStatus          = $(if ($owner) { $owner.Status } else { 'NoOwner' })
            AllMembersDisabled   = $allDisabled
        }
        if ($reach) {
            $pr = $(if ($privReach.ContainsKey($dn)) { @($privReach[$dn] | Sort-Object Hops) } else { @() })
            $reachRows.Add([pscustomobject][ordered]@{
                    Name                    = $g.Name
                    EffectiveUsers          = $reach.Users
                    EnabledUsers            = $reach.EnabledUsers
                    DisabledUsers           = $reach.DisabledUsers
                    Computers               = $reach.Computers
                    EnabledComputers        = $reach.EnabledComputers
                    ForeignPrincipals       = $reach.Foreign
                    Contacts                = $reach.Contacts
                    OutOfScopeMembers       = $reach.OutOfScope
                    NestedGroups            = $reach.NestedGroups
                    IsPrivilegedGroup       = $privDNs.ContainsKey($dn)
                    ReachesPrivilegedGroup  = ($pr.Count -gt 0)
                    PrivilegedGroupsReached = Join-Values ($pr | ForEach-Object { $_.Label } | Sort-Object -Unique)
                    PrivilegedPath          = $(if ($pr.Count) { $pr[0].Path } else { '' })
                    Status                  = $(if ($reach.Partial -or $reach.OutOfScope -gt 0) { 'Partial' } else { 'Complete' })
                    DistinguishedName       = $dn
                })
        }
    }
    $rows = @($rows)
    $groupNote = 'DepthDown = levels of groups nested inside; DepthUp = levels of groups this group sits inside; groups in one loop share depth'
    if ($partialGroups.Count) { $groupNote += ("; PARTIAL: {0} group(s) whose full member list could not be read (MemberReadStatus)" -f $partialGroups.Count) }
    if (-not $principalRead) { $groupNote += '; member classification read failed: owner, AllMembersDisabled and PrimaryGroupMembers limited' }
    Export-Dataset -Name 'ad-groups' -Rows $rows -Status $(if ($partialGroups.Count -or -not $principalRead) { 'Partial' } else { 'Completed' }) -Note $groupNote
    Export-Dataset -Name 'ad-circular-nesting' -Rows $cycles
    $edgeNote = "Group-in-group edges; {0} member(s) not followed (Status OutOfScope: outside -SearchBase, another domain or not readable)" -f $oosEdges
    if ($script:Unclassified) { $edgeNote += ("; PARTIAL: {0} member(s) could not be classified as user or group (member classification read failed)" -f $script:Unclassified) }
    Export-Dataset -Name 'ad-group-edges' -Rows $edgeRows -Status $(if ($script:Unclassified) { 'Partial' } else { 'Completed' }) -Note $edgeNote
    if ($SkipReach) { Set-DatasetStatus -Name 'ad-group-reach' -Status 'Deferred' -Note 'Skipped (-SkipReach)' }
    elseif (-not $principalRead) { Set-DatasetStatus -Name 'ad-group-reach' -Status 'Blocked' -Note ("Member classification read failed: {0}" -f $principalError) }
    else {
        $partialReach = @($reachRows | Where-Object Status -eq 'Partial').Count
        $rn = 'Accounts reached through nesting (member attribute and primaryGroupID); privileged = Domain / Enterprise / Schema Admins, Administrators, Account / Server / Backup / Print Operators, DnsAdmins, Group Policy Creator Owners, Key Admins, Enterprise Key Admins'
        if ($partialReach) { $rn += "; $partialReach group(s) Partial: some members out of scope or not fully read" }
        if ($reachNotes.Count) { $rn += '; ' + ($reachNotes -join '; ') }
        Export-Dataset -Name 'ad-group-reach' -Rows $reachRows -Status $(if ($reachNotes.Count) { 'Partial' } else { 'Completed' }) -Note $rn
    }

    # ---- 2. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Groups' $rows.Count
    Add-Metric 'Security groups' @($rows | Where-Object Category -eq 'Security').Count
    Add-Metric 'Distribution groups' @($rows | Where-Object Category -eq 'Distribution').Count
    Add-Metric 'Empty groups' @($rows | Where-Object { $_.Flags -match 'Empty' }).Count
    Add-Metric 'Groups with no managedBy owner' @($rows | Where-Object { -not $_.HasManagedBy }).Count
    Add-Metric 'Groups whose owner is disabled' @($rows | Where-Object OwnerStatus -eq 'OwnerDisabled').Count
    Add-Metric "Groups whose owner has no logon in $StaleDays days" @($rows | Where-Object OwnerStatus -eq 'OwnerStale').Count
    Add-Metric 'Groups whose owner could not be read' @($rows | Where-Object OwnerStatus -eq 'Unresolved').Count
    Add-Metric 'Groups whose members are all disabled' @($rows | Where-Object { $_.AllMembersDisabled -eq $true }).Count
    Add-Metric 'Mail-enabled security groups' @($rows | Where-Object { $_.Flags -match 'MailEnabledSecurity' }).Count
    Add-Metric 'Groups containing other groups' @($rows | Where-Object { $_.DirectGroupMembers -gt 0 }).Count
    Add-Metric 'Max nesting depth (down)' $(if ($rows.Count) { ($rows | Measure-Object DepthDown -Maximum).Maximum } else { 0 })
    Add-Metric "Groups with nesting depth >= $DeepNestingThreshold" @($rows | Where-Object { $_.DepthDown -ge $DeepNestingThreshold }).Count
    Add-Metric 'Circular nesting loops' $cycles.Count
    Add-Metric 'Groups in a circular loop' $cycleOf.Count
    Add-Metric 'Member edges not followed (OutOfScope)' $oosEdges -Note 'Outside -SearchBase, in another domain or not readable'
    Add-Metric 'Groups with a partial member list' $partialGroups.Count -Note 'Ranged read failed'
    if ($reachRows.Count) {
        $nonPriv = @($reachRows | Where-Object { -not $_.IsPrivilegedGroup -and $_.ReachesPrivilegedGroup })
        Add-Metric 'Groups nested into a privileged built-in group' $nonPriv.Count -Note 'Excludes the privileged groups themselves'
        Add-Metric 'Enabled users reached through those groups (sum per group)' (($nonPriv | Measure-Object EnabledUsers -Sum).Sum) -Note 'Per-group sums overlap; see script 04 for distinct accounts'
        Add-Metric 'Largest effective user count' (($reachRows | Measure-Object EffectiveUsers -Maximum).Maximum)
    }
    elseif ($SkipReach) { Add-Metric 'Groups nested into a privileged built-in group' 'Not evaluated' -Note '-SkipReach' }
    else { Add-Metric 'Groups nested into a privileged built-in group' 'Read failed' -Note 'Member classification read failed' }
    if ($NamingConventionRegex) { Add-Metric -Metric 'Groups not matching naming convention' -Value @($rows | Where-Object { $_.Flags -match 'NamingConventionMiss' }).Count -Note $NamingConventionRegex }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ SearchBase = $SearchBase; DeepNestingThreshold = $DeepNestingThreshold; NamingConventionRegex = $NamingConventionRegex; StaleDays = $StaleDays; SkipReach = [bool]$SkipReach }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
