<#
.SYNOPSIS
    Read-only role mining: finds the groups that people in the same department or job code share.

.DESCRIPTION
    Supports the move from ad-hoc access to RBAC (birthright -> department roles -> job-code roles).
    For every value of each grouping attribute (for example department, then title or a job-code
    attribute) it measures how many people in that population hold each group, and exports:

      - Attribute quality per grouping attribute: blanks, distinct values, and values that look
        like the same thing spelled differently ("IT" vs "I.T." vs "Information Technology"
        needs a human; "IT" vs "it " is caught automatically)
      - Value variants: every normalised value with the raw spellings behind it
      - Populations: the size of each department / job-code group
      - Birthright candidates: groups held by almost everyone in scope
      - Role candidates: groups held by most of one population (default 80%+)
      - Outliers: people missing a role-candidate group their peers have, and people holding a
        group that is rare both in their population and overall
      - Layered populations (optional): a combined key such as department|title, mined the same way
      - Access load: each person's group count against the median of their peers, flagging people
        with far more access than the rest of their population
      - Excluded accounts: accounts left out of the mining by name pattern (service / admin /
        test), listed with their groups so admin accounts are never invisible
      - No-population users: people with a blank grouping attribute, listed with their groups
      - A summary of headline metrics

    Group membership is resolved down to the account: direct membership, the primary group
    (primaryGroupID, normally Domain Users) and access inherited through nested groups are all
    counted by default. Use -DirectOnly for direct membership only. Groups are keyed by
    distinguishedName, so two groups with the same name in different OUs stay separate.

    Clean, consistent attribute values are a prerequisite for rule-based roles; the quality
    files show whether the data can carry the rules before anyone designs them.

    READ-ONLY. Uses only Get-AD* cmdlets. Nothing in the directory is changed.

    Output: <OutputRoot>\07-RoleMining\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER GroupingAttributes
    AD attributes that define populations, in order of the role layers. Defaults to department
    then title. Add the job-code attribute used in your environment, e.g. 'extensionAttribute5'.
    The first attribute is also the peer population for the access-load check.

.PARAMETER LayeredAttributes
    Two or more attributes mined together as one combined population key, e.g.
    'department','title' gives populations such as "Dept1|Title1". Rows use the Attribute value
    'department|title'. A user with any of the attributes blank is not in a layered population.

.PARAMETER NormalizeValues
    Group populations on the normalised value (case, spacing and punctuation ignored) instead of
    the raw value. Use once the variants file shows those differences are only cosmetic.

.PARAMETER DirectOnly
    Count direct membership and the primary group only, not access inherited through nested
    groups. Nested membership is counted by default.

.PARAMETER ExpandNested
    Deprecated and ignored. Nested membership is now counted by default; use -DirectOnly to turn
    it off. Kept so existing command lines keep working.

.PARAMETER AccessLoadRatio
    A user is flagged HighAccessForPeers when their group count is more than this multiple of
    their peer population's median and above -AccessLoadMinGroups.

.EXAMPLE
    .\07-Get-RoleMiningCandidates.ps1
.EXAMPLE
    .\07-Get-RoleMiningCandidates.ps1 -GroupingAttributes department,extensionAttribute5 -SearchBase 'OU=Users,DC=contoso,DC=local'
.EXAMPLE
    .\07-Get-RoleMiningCandidates.ps1 -LayeredAttributes department,title -RoleThreshold 0.9 -MinPopulation 10 -NormalizeValues
.EXAMPLE
    .\07-Get-RoleMiningCandidates.ps1 -DirectOnly -AccessLoadRatio 3

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account (read)
    The primary group (normally Domain Users) is resolved from primaryGroupID and counted as
    direct membership.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                           # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                                       # OU holding people accounts (blank = whole domain)
    [string[]]$GroupingAttributes = @('department', 'title'),
    [string[]]$LayeredAttributes = @(),                             # e.g. 'department','title' -> combined key
    [ValidateRange(1, 100000)]
    [int]$MinPopulation = 5,
    [ValidateRange(0.0, 1.0)]
    [double]$RoleThreshold = 0.8,
    [ValidateRange(0.0, 1.0)]
    [double]$CommonThreshold = 0.5,
    [ValidateRange(0.0, 1.0)]
    [double]$BirthrightThreshold = 0.9,
    [ValidateRange(0.0, 1.0)]
    [double]$OutlierThreshold = 0.1,
    [ValidateRange(1.0, 100.0)]
    [double]$AccessLoadRatio = 2,
    [ValidateRange(0, 100000)]
    [int]$AccessLoadMinGroups = 10,
    [string[]]$ExcludeNamePatterns = @('svc*', 'sa-*', 'sa_*', 'adm*', '*admin*', 'test*'),
    [string]$ExcludeGroupRegex = '',                                # e.g. '^(All Staff|Everyone)'
    [switch]$IncludeDisabled,
    [switch]$IncludeDistributionGroups,
    [switch]$DirectOnly,
    [switch]$ExpandNested,                                          # deprecated no-op (nested is the default)
    [switch]$NormalizeValues,
    [switch]$SkipOutliers
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '07-RoleMining'
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

function ConvertTo-NormalKey {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $v = $Value.Trim().ToLowerInvariant() -replace '&', ' and '
    return ($v -replace '[^a-z0-9]', '')
}

function Format-Pct { param([double]$Value) return [math]::Round(100 * $Value, 1) }

function Get-Median {
    param([double[]]$Values)
    $s = @($Values | Sort-Object)
    if ($s.Count -eq 0) { return 0 }
    $mid = [math]::Floor($s.Count / 2)
    if ($s.Count % 2) { return [double]$s[$mid] }
    return ([double]$s[$mid - 1] + [double]$s[$mid]) / 2
}

function Get-StdDev {
    param([double[]]$Values)
    if (@($Values).Count -lt 2) { return 0 }
    $mean = ($Values | Measure-Object -Average).Average
    $sum = 0.0
    foreach ($v in $Values) { $sum += [math]::Pow($v - $mean, 2) }
    return [math]::Sqrt($sum / (@($Values).Count - 1))
}

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if ($ExpandNested) { Write-RunLog '-ExpandNested is deprecated and ignored: nested membership is counted by default. Use -DirectOnly to turn it off.' 'WARN' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain @script:AdParams
    $domainName = $domain.DNSRoot
    $domainSid = "$($domain.DomainSID.Value)"

    # Layered key (combined population such as department|title)
    $layerLabel = ''
    $layerParts = @($LayeredAttributes | Where-Object { $_ })
    if ($layerParts.Count -ge 2) { $layerLabel = $layerParts -join '|' }
    elseif ($layerParts.Count -eq 1) { Write-RunLog ("-LayeredAttributes needs two or more attributes; '{0}' alone is already mined through -GroupingAttributes. Layered mining skipped." -f $layerParts[0]) 'WARN' }
    $miningKeys = @($GroupingAttributes)
    if ($layerLabel) { $miningKeys += $layerLabel }

    # ---- Groups ----
    Write-RunLog 'Reading groups...'
    $allGroups = @(Get-ADGroup -Filter * -Properties memberOf @script:AdParams)
    $groupByDN = @{}; $groupBySid = @{}; $nameCount = @{}
    foreach ($g in $allGroups) {
        $groupByDN[$g.DistinguishedName] = $g
        if ($g.SID) { $groupBySid["$($g.SID.Value)"] = $g.DistinguishedName }
        $nk = "$($g.Name)".ToLowerInvariant()
        if ($nameCount.ContainsKey($nk)) { $nameCount[$nk]++ } else { $nameCount[$nk] = 1 }
    }
    # Display label: the group name, plus its parent container when another group has the same name.
    $groupLabel = @{}
    $duplicateNames = 0
    foreach ($g in $allGroups) {
        if ($nameCount["$($g.Name)".ToLowerInvariant()] -gt 1) {
            $duplicateNames++
            $parent = ($g.DistinguishedName -replace '^(?:[^,\\]|\\.)+,', '')
            $groupLabel[$g.DistinguishedName] = '{0} [{1}]' -f $g.Name, $parent
        }
        else { $groupLabel[$g.DistinguishedName] = "$($g.Name)" }
    }
    if ($duplicateNames) { Write-RunLog ("{0} groups share a name with another group; their labels include the parent container" -f $duplicateNames) 'WARN' }

    function Test-GroupInScope {
        param($Group)
        if (-not $Group) { return $false }
        if (-not $IncludeDistributionGroups -and $Group.GroupCategory -ne 'Security') { return $false }
        if ($ExcludeGroupRegex -and $Group.Name -match $ExcludeGroupRegex) { return $false }
        return $true
    }

    # Transitive parent groups per group (memoised); skipped with -DirectOnly
    $ancestorMemo = @{}
    function Get-Ancestor {
        param([string]$DN, [hashtable]$Visiting)
        if ($ancestorMemo.ContainsKey($DN)) { return $ancestorMemo[$DN] }
        $set = [System.Collections.Generic.HashSet[string]]::new()
        $Visiting[$DN] = $true
        $g = $groupByDN[$DN]
        if ($g) {
            foreach ($p in @($g.memberOf | Where-Object { $_ })) {
                if ($Visiting.ContainsKey($p)) { continue }
                [void]$set.Add($p)
                foreach ($a in (Get-Ancestor $p $Visiting)) { [void]$set.Add($a) }
            }
        }
        $Visiting.Remove($DN)
        $ancestorMemo[$DN] = $set
        return $set
    }

    $missingPrimary = 0
    function Get-UserGroupSet {
        # Returns DN sets: Direct (memberOf + primary group) and All (Direct + nested ancestors), in-scope groups only.
        param($User)
        $direct = [System.Collections.Generic.HashSet[string]]::new()
        $all = [System.Collections.Generic.HashSet[string]]::new()
        $dns = @($User.memberOf | Where-Object { $_ })
        if ($User.primaryGroupID) {
            $pgDN = $groupBySid[("{0}-{1}" -f $domainSid, $User.primaryGroupID)]
            if ($pgDN) { $dns += $pgDN } else { $script:missingPrimary++ }
        }
        foreach ($dn in $dns) {
            if (Test-GroupInScope $groupByDN[$dn]) { [void]$direct.Add($dn); [void]$all.Add($dn) }
            if (-not $DirectOnly) {
                foreach ($a in (Get-Ancestor $dn @{})) { if (Test-GroupInScope $groupByDN[$a]) { [void]$all.Add($a) } }
            }
        }
        return [pscustomobject]@{ Direct = $direct; All = $all }
    }

    function Format-GroupList {
        # Sorted labels, nested-only memberships marked, capped at 50 with a count of the rest.
        param($All, $Direct, [int]$Cap = 50)
        $labels = @($All | ForEach-Object { if ($Direct.Contains($_)) { $groupLabel[$_] } else { '{0} (nested)' -f $groupLabel[$_] } } | Sort-Object)
        if ($labels.Count -le $Cap) { return Join-Values $labels }
        return ('{0}; ... (+{1} more)' -f (Join-Values ($labels | Select-Object -First $Cap)), ($labels.Count - $Cap))
    }

    # ---- Users ----
    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    $filter = $(if ($IncludeDisabled) { '*' } else { 'Enabled -eq $true' })
    $props = @(@('memberOf', 'sAMAccountName', 'primaryGroupID') + $GroupingAttributes + $layerParts | Select-Object -Unique)
    Write-RunLog ("Reading users (filter: {0})..." -f $filter)
    $rawUsers = @(Get-ADUser -Filter $filter -Properties $props @p)
    $users = [System.Collections.Generic.List[object]]::new()
    $excludedRows = [System.Collections.Generic.List[object]]::new()
    $noPopRows = [System.Collections.Generic.List[object]]::new()
    $excludedCount = 0
    foreach ($u in $rawUsers) {
        $sam = $u.SamAccountName
        $gs = Get-UserGroupSet $u
        $matched = @($ExcludeNamePatterns | Where-Object { $sam -like $_ })
        if ($matched.Count) {
            $excludedCount++
            $excludedRows.Add([pscustomobject][ordered]@{
                SamAccountName = $sam
                Enabled        = $u.Enabled
                MatchedPattern = Join-Values $matched
                GroupCount     = $gs.All.Count
                Groups         = Format-GroupList $gs.All $gs.Direct
            })
            continue
        }
        $attrs = @{}; $norm = @{}; $blankAttrs = @()
        foreach ($attr in $GroupingAttributes) {
            $attrs[$attr] = "$($u.$attr)".Trim()
            $norm[$attr] = ConvertTo-NormalKey $attrs[$attr]
            if (-not $attrs[$attr]) { $blankAttrs += $attr }
        }
        if ($layerLabel) {
            $parts = @($layerParts | ForEach-Object { "$($u.$_)".Trim() })
            if (@($parts | Where-Object { -not $_ }).Count) { $attrs[$layerLabel] = ''; $norm[$layerLabel] = '' }
            else { $attrs[$layerLabel] = $parts -join '|'; $norm[$layerLabel] = (@($parts | ForEach-Object { ConvertTo-NormalKey $_ }) -join '|') }
        }
        $users.Add([pscustomobject]@{ Sam = $sam; Enabled = $u.Enabled; Groups = $gs.All; Direct = $gs.Direct; Attrs = $attrs; Norm = $norm })
        if ($blankAttrs.Count) {
            $noPopRows.Add([pscustomobject][ordered]@{
                SamAccountName  = $sam
                Enabled         = $u.Enabled
                BlankAttributes = Join-Values $blankAttrs
                GroupCount      = $gs.All.Count
                Groups          = Format-GroupList $gs.All $gs.Direct
            })
        }
    }
    $total = $users.Count
    Write-RunLog ("{0} users in scope ({1} excluded by name pattern; {2} with a blank grouping attribute)" -f $total, $excludedCount, $noPopRows.Count)
    if ($missingPrimary) { Write-RunLog ("{0} users have a primaryGroupID that matched no group read; their primary group is not counted" -f $missingPrimary) 'WARN' }
    Export-Dataset -Name 'excluded-accounts' -Rows @($excludedRows | Sort-Object @{ Expression = 'GroupCount'; Descending = $true }) -Note 'Left out of the mining math by -ExcludeNamePatterns; review their access separately'
    if ($total -eq 0) { throw 'No users in scope. Check -SearchBase and -ExcludeNamePatterns.' }
    Export-Dataset -Name 'no-population-users' -Rows @($noPopRows | Sort-Object @{ Expression = 'GroupCount'; Descending = $true }) -Note 'Blank grouping attribute: not in that attribute''s populations, so roles cannot be assigned by rule'

    # ---- Global prevalence ----
    $globalCount = @{}; $globalNested = @{}
    foreach ($u in $users) {
        foreach ($g in $u.Groups) {
            if ($globalCount.ContainsKey($g)) { $globalCount[$g]++ } else { $globalCount[$g] = 1 }
            if (-not $u.Direct.Contains($g)) { if ($globalNested.ContainsKey($g)) { $globalNested[$g]++ } else { $globalNested[$g] = 1 } }
        }
    }
    $birthright = @{}
    $birthrightRows = foreach ($g in $globalCount.Keys) {
        $pct = $globalCount[$g] / $total
        if ($pct -ge $BirthrightThreshold) {
            $birthright[$g] = $true
            [pscustomobject][ordered]@{ Group = $groupLabel[$g]; Holders = $globalCount[$g]; InScopeUsers = $total; PctOfAllUsers = (Format-Pct $pct); NestedHolders = [int]$globalNested[$g]; GroupDistinguishedName = $g }
        }
    }
    Export-Dataset -Name 'birthright-candidates' -Rows @($birthrightRows | Sort-Object PctOfAllUsers -Descending) -Note ("Held by at least {0}% of in-scope users" -f (Format-Pct $BirthrightThreshold))

    # ---- Per attribute (and the layered key) ----
    $qualityRows = [System.Collections.Generic.List[object]]::new()
    $variantRows = [System.Collections.Generic.List[object]]::new()
    $populationRows = [System.Collections.Generic.List[object]]::new()
    $candidateRows = [System.Collections.Generic.List[object]]::new()
    $outlierRows = [System.Collections.Generic.List[object]]::new()

    foreach ($attr in $miningKeys) {
        # Quality and variants
        $rawCounts = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal); $normToRaw = @{}; $blank = 0
        foreach ($u in $users) {
            $v = $u.Attrs[$attr]
            if (-not $v) { $blank++; continue }
            if ($rawCounts.ContainsKey($v)) { $rawCounts[$v]++ } else { $rawCounts[$v] = 1 }
            $k = $u.Norm[$attr]
            if (-not $normToRaw.ContainsKey($k)) { $normToRaw[$k] = [System.Collections.Generic.HashSet[string]]::new() }
            [void]$normToRaw[$k].Add($v)
        }
        $variantKeys = 0
        foreach ($k in $normToRaw.Keys) {
            $raws = @($normToRaw[$k])
            if ($raws.Count -gt 1) { $variantKeys++ }
            $variantRows.Add([pscustomobject][ordered]@{
                Attribute     = $attr
                NormalizedKey = $k
                VariantCount  = $raws.Count
                Variants      = Join-Values ($raws | Sort-Object | ForEach-Object { '{0} ({1})' -f $_, $rawCounts[$_] })
                TotalUsers    = ($raws | ForEach-Object { $rawCounts[$_] } | Measure-Object -Sum).Sum
            })
        }

        # Populations
        $pops = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)   # case-sensitive: raw values stay distinct
        foreach ($u in $users) {
            $v = $u.Attrs[$attr]
            if (-not $v) { continue }
            $key = $(if ($NormalizeValues) { $u.Norm[$attr] } else { $v })
            if (-not $pops.ContainsKey($key)) { $pops[$key] = [System.Collections.Generic.List[object]]::new() }
            $pops[$key].Add($u)
        }
        $qualifying = 0; $roleCandidates = 0
        foreach ($key in $pops.Keys) {
            $members = $pops[$key]
            $size = $members.Count
            $label = $(if ($NormalizeValues) { Join-Values (@($normToRaw[$key]) | Sort-Object) } else { $key })
            $meets = ($size -ge $MinPopulation)
            if ($meets) { $qualifying++ }
            $populationRows.Add([pscustomobject][ordered]@{ Attribute = $attr; Value = $label; Users = $size; MeetsMinPopulation = $meets })
            if (-not $meets) { continue }

            $popCount = @{}; $popNested = @{}
            foreach ($u in $members) {
                foreach ($g in $u.Groups) {
                    if ($popCount.ContainsKey($g)) { $popCount[$g]++ } else { $popCount[$g] = 1 }
                    if (-not $u.Direct.Contains($g)) { if ($popNested.ContainsKey($g)) { $popNested[$g]++ } else { $popNested[$g] = 1 } }
                }
            }
            $roleSet = @{}; $pctMap = @{}
            foreach ($g in $popCount.Keys) {
                $pct = $popCount[$g] / $size
                $pctMap[$g] = $pct
                if ($pct -lt $CommonThreshold) { continue }
                $gPct = $globalCount[$g] / $total
                $class = $(if ($birthright.ContainsKey($g)) { 'BirthrightCandidate' } elseif ($pct -ge $RoleThreshold) { 'RoleCandidate' } else { 'Common' })
                if ($class -eq 'RoleCandidate') { $roleSet[$g] = $true; $roleCandidates++ }
                $candidateRows.Add([pscustomobject][ordered]@{
                    Attribute              = $attr
                    Value                  = $label
                    PopulationSize         = $size
                    Group                  = $groupLabel[$g]
                    Holders                = $popCount[$g]
                    PctInPopulation        = (Format-Pct $pct)
                    PctOfAllUsers          = (Format-Pct $gPct)
                    Lift                   = $(if ($gPct -gt 0) { [math]::Round($pct / $gPct, 2) } else { '' })
                    Classification         = $class
                    NestedHolders          = [int]$popNested[$g]
                    GroupDistinguishedName = $g
                })
            }

            if ($SkipOutliers) { continue }
            foreach ($u in $members) {
                foreach ($g in $roleSet.Keys) {
                    if (-not $u.Groups.Contains($g)) {
                        $outlierRows.Add([pscustomobject][ordered]@{ Attribute = $attr; Value = $label; SamAccountName = $u.Sam; Group = $groupLabel[$g]; Type = 'MissingRoleCandidate'; PctInPopulation = (Format-Pct $pctMap[$g]); PctOfAllUsers = (Format-Pct ($globalCount[$g] / $total)); MembershipSource = ''; GroupDistinguishedName = $g })
                    }
                }
                foreach ($g in $u.Groups) {
                    $gp = $globalCount[$g] / $total
                    if ($pctMap[$g] -le $OutlierThreshold -and $gp -le $OutlierThreshold) {
                        $outlierRows.Add([pscustomobject][ordered]@{ Attribute = $attr; Value = $label; SamAccountName = $u.Sam; Group = $groupLabel[$g]; Type = 'UncommonAccess'; PctInPopulation = (Format-Pct $pctMap[$g]); PctOfAllUsers = (Format-Pct $gp); MembershipSource = $(if ($u.Direct.Contains($g)) { 'Direct' } else { 'Nested' }); GroupDistinguishedName = $g })
                    }
                }
            }
        }

        $qualityRows.Add([pscustomobject][ordered]@{
            Attribute               = $attr
            InScopeUsers            = $total
            BlankUsers              = $blank
            BlankPct                = (Format-Pct ($blank / $total))
            DistinctRawValues       = $rawCounts.Count
            DistinctNormalizedValues = $normToRaw.Count
            ValuesWithSpellingVariants = $variantKeys
            Populations             = $pops.Count
            PopulationsMeetingMin   = $qualifying
            RoleCandidateRows       = $roleCandidates
        })
    }

    Export-Dataset -Name 'attribute-quality' -Rows $qualityRows
    Export-Dataset -Name 'attribute-value-variants' -Rows @($variantRows | Sort-Object Attribute, @{ Expression = 'VariantCount'; Descending = $true }, @{ Expression = 'TotalUsers'; Descending = $true }) -Note 'VariantCount > 1 = same value spelled differently'
    Export-Dataset -Name 'populations' -Rows @($populationRows | Sort-Object Attribute, @{ Expression = 'Users'; Descending = $true })
    Export-Dataset -Name 'role-candidates' -Rows @($candidateRows | Sort-Object Attribute, Value, @{ Expression = 'PctInPopulation'; Descending = $true }) -Note ("Rows where a group is held by at least {0}% of a population of {1}+ users" -f (Format-Pct $CommonThreshold), $MinPopulation)
    if ($SkipOutliers) { Set-DatasetStatus -Name 'outliers' -Status 'Deferred' -Note '-SkipOutliers' }
    else { Export-Dataset -Name 'outliers' -Rows $outlierRows -Note 'Questions for managers, not findings' }

    # ---- Access load: group count against the peer population (first grouping attribute) ----
    $peerAttr = $GroupingAttributes[0]
    $peerCounts = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)   # case-sensitive like the populations
    foreach ($u in $users) {
        $k = $(if ($NormalizeValues) { $u.Norm[$peerAttr] } else { $u.Attrs[$peerAttr] })
        if (-not $k) { continue }
        if (-not $peerCounts.ContainsKey($k)) { $peerCounts[$k] = [System.Collections.Generic.List[double]]::new() }
        $peerCounts[$k].Add([double]$u.Groups.Count)
    }
    $allCounts = @($users | ForEach-Object { [double]$_.Groups.Count })
    $globalStats = @{ Median = (Get-Median $allCounts); Mean = ($allCounts | Measure-Object -Average).Average; StdDev = (Get-StdDev $allCounts); Size = $allCounts.Count }
    $peerStats = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($k in $peerCounts.Keys) {
        $vals = $peerCounts[$k].ToArray()
        $peerStats[$k] = @{ Median = (Get-Median $vals); Mean = ($vals | Measure-Object -Average).Average; StdDev = (Get-StdDev $vals); Size = $vals.Count }
    }
    $loadRows = foreach ($u in $users) {
        $k = $(if ($NormalizeValues) { $u.Norm[$peerAttr] } else { $u.Attrs[$peerAttr] })
        $usePeers = ($k -and $peerStats.ContainsKey($k) -and $peerStats[$k].Size -ge $MinPopulation)
        $st = $(if ($usePeers) { $peerStats[$k] } else { $globalStats })
        $count = $u.Groups.Count
        $ratio = $(if ($st.Median -gt 0) { [math]::Round($count / $st.Median, 2) } else { '' })
        $z = $(if ($st.StdDev -gt 0) { [math]::Round(($count - $st.Mean) / $st.StdDev, 2) } else { 0 })
        $high = ($count -gt $AccessLoadMinGroups -and $count -gt ($AccessLoadRatio * $st.Median))
        [pscustomobject][ordered]@{
            SamAccountName   = $u.Sam
            Enabled          = $u.Enabled
            GroupCount       = $count
            DirectGroupCount = $u.Direct.Count
            NestedGroupCount = $count - $u.Direct.Count
            PeerAttribute    = $peerAttr
            PeerPopulation   = $(if ($usePeers) { $u.Attrs[$peerAttr] } elseif ($k) { '(all in-scope users; population below MinPopulation)' } else { '(all in-scope users; attribute blank)' })
            PeerSize         = $st.Size
            PeerMedian       = $st.Median
            Ratio            = $ratio
            ZScore           = $z
            Flag             = $(if ($high) { 'HighAccessForPeers' } else { '' })
        }
    }
    Export-Dataset -Name 'access-load' -Rows @($loadRows | Sort-Object @{ Expression = { $_.Flag -ne 'HighAccessForPeers' } }, @{ Expression = 'GroupCount'; Descending = $true }) -Note ("HighAccessForPeers = more than {0}x the peer median ({1}) and more than {2} groups" -f $AccessLoadRatio, $peerAttr, $AccessLoadMinGroups)

    # ---- Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric -Metric 'Users in scope' -Value $total -Note $(if ($IncludeDisabled) { 'Includes disabled' } else { 'Enabled only' })
    Add-Metric -Metric 'Users excluded by name pattern' -Value $excludedCount -Note 'Listed with their groups in excluded-accounts.csv'
    Add-Metric -Metric 'Users with a blank grouping attribute' -Value $noPopRows.Count -Note 'Listed in no-population-users.csv'
    Add-Metric -Metric 'Distinct groups held' -Value $globalCount.Count -Note $(if ($DirectOnly) { 'Direct membership + primary group only (-DirectOnly)' } else { 'Direct + primary group + nested' })
    Add-Metric -Metric 'Birthright candidates' -Value @($birthrightRows).Count -Note ("Held by >= {0}% of users" -f (Format-Pct $BirthrightThreshold))
    foreach ($q in $qualityRows) {
        Add-Metric ("{0}: blank (%)" -f $q.Attribute) $q.BlankPct
        Add-Metric ("{0}: distinct values" -f $q.Attribute) $q.DistinctRawValues
        Add-Metric ("{0}: values with spelling variants" -f $q.Attribute) $q.ValuesWithSpellingVariants
        Add-Metric ("{0}: populations with {1}+ users" -f $q.Attribute, $MinPopulation) $q.PopulationsMeetingMin
        Add-Metric -Metric ("{0}: role-candidate rows" -f $q.Attribute) -Value $q.RoleCandidateRows -Note ("Groups held by >= {0}% of a population" -f (Format-Pct $RoleThreshold))
    }
    if (-not $SkipOutliers) {
        Add-Metric 'Outlier rows - missing a role-candidate group' @($outlierRows | Where-Object Type -eq 'MissingRoleCandidate').Count
        Add-Metric -Metric 'Outlier rows - uncommon access' -Value @($outlierRows | Where-Object Type -eq 'UncommonAccess').Count -Note ("Held by <= {0}% of the population and of all users" -f (Format-Pct $OutlierThreshold))
    }
    Add-Metric -Metric 'Users with high access for their peers' -Value @($loadRows | Where-Object Flag -eq 'HighAccessForPeers').Count -Note ("> {0}x the {1} median and > {2} groups" -f $AccessLoadRatio, $peerAttr, $AccessLoadMinGroups)
    Add-Metric -Metric 'Groups sharing a name with another group' -Value $duplicateNames -Note 'Labelled with their parent container'
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ SearchBase = $SearchBase; GroupingAttributes = $GroupingAttributes; LayeredAttributes = $LayeredAttributes; MinPopulation = $MinPopulation; RoleThreshold = $RoleThreshold; CommonThreshold = $CommonThreshold; BirthrightThreshold = $BirthrightThreshold; OutlierThreshold = $OutlierThreshold; AccessLoadRatio = $AccessLoadRatio; AccessLoadMinGroups = $AccessLoadMinGroups; ExcludeGroupRegex = $ExcludeGroupRegex; IncludeDisabled = [bool]$IncludeDisabled; IncludeDistributionGroups = [bool]$IncludeDistributionGroups; DirectOnly = [bool]$DirectOnly; ExpandNested = [bool]$ExpandNested; NormalizeValues = [bool]$NormalizeValues }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
