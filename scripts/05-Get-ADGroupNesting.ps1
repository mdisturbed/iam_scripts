<#
.SYNOPSIS
    Read-only analysis of group nesting and group hygiene in on-premises Active Directory.

.DESCRIPTION
    Builds the full group-in-group graph for the domain in memory and exports:
      - One row per group: type, scope, direct member counts, how deep nesting goes beneath it
        (DepthDown) and above it (DepthUp), circular-nesting membership, and hygiene flags
        (empty, no owner, no description, mail-enabled security group, naming-convention miss)
      - One row per circular-nesting loop
      - A summary of headline metrics

    Feeds the "nested groups / RBAC" part of the gap analysis and is the baseline for role mining.

    READ-ONLY. Uses only Get-ADGroup. Nothing in the directory is changed.

    Output: <OutputRoot>\05-ADGroupNesting\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER NamingConventionRegex
    Optional regex a well-named group should match, e.g. '^(RB|APP|FS|ADM)-'. Blank = not evaluated.

.EXAMPLE
    .\05-Get-ADGroupNesting.ps1
.EXAMPLE
    .\05-Get-ADGroupNesting.ps1 -Server dc01.contoso.local -DeepNestingThreshold 3 -NamingConventionRegex '^(RB|APP)-'

.NOTES
    Version : 1.0.1
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account (read)
    Very large groups: AD Web Services limits a single 'member' read (default 5000 values).
    Groups over that limit are flagged MemberListTruncated rather than failing the run.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                       # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                   # blank = whole domain
    [int]$DeepNestingThreshold = 3,
    [string]$NamingConventionRegex = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '05-ADGroupNesting'
$ScriptVersion = '1.0.1'

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

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot

    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    Write-RunLog 'Reading all groups (this can take a few minutes in large domains)...'
    $groups = @(Get-ADGroup -Filter * -Properties member, memberOf, managedBy, description, mail, whenCreated, whenChanged, adminCount @p)
    Write-RunLog ("{0} groups read" -f $groups.Count)

    # ---- Build graph: parent DN -> child group DNs ----
    $byDN = @{}
    foreach ($g in $groups) { $byDN[$g.DistinguishedName] = $g }
    $children = @{}; $parents = @{}
    foreach ($g in $groups) { $children[$g.DistinguishedName] = [System.Collections.Generic.List[string]]::new(); $parents[$g.DistinguishedName] = [System.Collections.Generic.List[string]]::new() }
    foreach ($g in $groups) {
        foreach ($m in @($g.member)) { if ($m -and $byDN.ContainsKey($m)) { $children[$g.DistinguishedName].Add($m); $parents[$m].Add($g.DistinguishedName) } }
    }

    # ---- Circular nesting: Tarjan strongly-connected components ----
    $index = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $onStack = @{}; $idx = @{}; $low = @{}
    $cycleOf = @{}; $cycles = [System.Collections.Generic.List[object]]::new()
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
            $selfLoop = $children[$v].Contains($v)
            if ($comp.Count -gt 1 -or $selfLoop) {
                $cid = 'C{0:000}' -f ($cycles.Count + 1)
                foreach ($c in $comp) { $cycleOf[$c] = $cid }
                $cycles.Add([pscustomobject][ordered]@{ CycleId = $cid; GroupCount = $comp.Count; Groups = Join-Values ($comp | ForEach-Object { $byDN[$_].Name }) })
            }
        }
    }
    $script:tIndex = $index
    foreach ($g in $groups) { if (-not $idx.ContainsKey($g.DistinguishedName)) { Invoke-Tarjan $g.DistinguishedName } }

    # ---- Depth (memoised; edges inside a cycle are not followed) ----
    $downMemo = @{}; $upMemo = @{}
    function Get-Depth {
        param([string]$v, [hashtable]$Edges, [hashtable]$Memo, [hashtable]$InProgress)
        if ($Memo.ContainsKey($v)) { return $Memo[$v] }
        $InProgress[$v] = $true
        $max = 0
        foreach ($w in $Edges[$v]) {
            if ($InProgress.ContainsKey($w)) { continue }                         # back-edge (cycle)
            if ($cycleOf.ContainsKey($v) -and $cycleOf[$v] -eq $cycleOf[$w]) { continue }
            $d = 1 + (Get-Depth $w $Edges $Memo $InProgress)
            if ($d -gt $max) { $max = $d }
        }
        $InProgress.Remove($v)
        $Memo[$v] = $max
        return $max
    }

    # ---- 1. Per-group rows ----
    $rows = foreach ($g in $groups) {
        $dn = $g.DistinguishedName
        $members = @($g.member | Where-Object { $_ })
        $groupMembers = $children[$dn].Count
        $down = Get-Depth $dn $children $downMemo @{}
        $up = Get-Depth $dn $parents $upMemo @{}
        $isSecurity = ($g.GroupCategory -eq 'Security')
        $flags = @()
        if ($members.Count -eq 0) { $flags += 'Empty' }
        if (-not $g.managedBy) { $flags += 'NoManagedBy' }
        if (-not $g.description) { $flags += 'NoDescription' }
        if ($isSecurity -and $g.mail) { $flags += 'MailEnabledSecurity' }
        if ($down -ge $DeepNestingThreshold) { $flags += "DeepNesting(>=$DeepNestingThreshold)" }
        if ($cycleOf.ContainsKey($dn)) { $flags += 'CircularNesting' }
        if ($members.Count -ge 5000) { $flags += 'MemberListTruncated' }
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
        }
    }
    Export-Dataset -Name 'ad-groups' -Rows $rows -Note 'DepthDown = levels of groups nested inside; DepthUp = levels of groups this group sits inside'
    Export-Dataset -Name 'ad-circular-nesting' -Rows $cycles

    # ---- 2. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $rows = @($rows)
    Add-Metric 'Groups' $rows.Count
    Add-Metric 'Security groups' @($rows | Where-Object Category -eq 'Security').Count
    Add-Metric 'Distribution groups' @($rows | Where-Object Category -eq 'Distribution').Count
    Add-Metric 'Empty groups' @($rows | Where-Object { $_.Flags -match 'Empty' }).Count
    Add-Metric 'Groups with no managedBy owner' @($rows | Where-Object { -not $_.HasManagedBy }).Count
    Add-Metric 'Mail-enabled security groups' @($rows | Where-Object { $_.Flags -match 'MailEnabledSecurity' }).Count
    Add-Metric 'Groups containing other groups' @($rows | Where-Object { $_.DirectGroupMembers -gt 0 }).Count
    Add-Metric 'Max nesting depth (down)' $(if ($rows.Count) { ($rows | Measure-Object DepthDown -Maximum).Maximum } else { 0 })
    Add-Metric "Groups with nesting depth >= $DeepNestingThreshold" @($rows | Where-Object { $_.DepthDown -ge $DeepNestingThreshold }).Count
    Add-Metric 'Circular nesting loops' $cycles.Count
    Add-Metric 'Groups in a circular loop' $cycleOf.Count
    if ($NamingConventionRegex) { Add-Metric 'Groups not matching naming convention' @($rows | Where-Object { $_.Flags -match 'NamingConventionMiss' }).Count $NamingConventionRegex }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ SearchBase = $SearchBase; DeepNestingThreshold = $DeepNestingThreshold; NamingConventionRegex = $NamingConventionRegex }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
