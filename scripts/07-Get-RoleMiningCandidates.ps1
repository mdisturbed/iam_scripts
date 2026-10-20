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
      - A summary of headline metrics

    Clean, consistent attribute values are a prerequisite for rule-based roles; the quality
    files show whether the data can carry the rules before anyone designs them.

    READ-ONLY. Uses only Get-AD* cmdlets. Nothing in the directory is changed.

    Output: <OutputRoot>\07-RoleMining\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER GroupingAttributes
    AD attributes that define populations, in order of the role layers. Defaults to department
    then title. Add the job-code attribute used in your environment, e.g. 'extensionAttribute5'.

.PARAMETER NormalizeValues
    Group populations on the normalised value (case, spacing and punctuation ignored) instead of
    the raw value. Use once the variants file shows those differences are only cosmetic.

.PARAMETER ExpandNested
    Count access granted through nested groups as well as direct membership.

.EXAMPLE
    .\07-Get-RoleMiningCandidates.ps1
.EXAMPLE
    .\07-Get-RoleMiningCandidates.ps1 -GroupingAttributes department,extensionAttribute5 -SearchBase 'OU=Users,DC=contoso,DC=local' -ExpandNested
.EXAMPLE
    .\07-Get-RoleMiningCandidates.ps1 -RoleThreshold 0.9 -MinPopulation 10 -NormalizeValues

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account (read)
    The primary group (normally Domain Users) is not part of memberOf and is not counted.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                           # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                                       # OU holding people accounts (blank = whole domain)
    [string[]]$GroupingAttributes = @('department', 'title'),
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
    [string[]]$ExcludeNamePatterns = @('svc*', 'sa-*', 'sa_*', 'adm*', '*admin*', 'test*'),
    [string]$ExcludeGroupRegex = '',                                # e.g. '^(All Staff|Everyone)'
    [switch]$IncludeDisabled,
    [switch]$IncludeDistributionGroups,
    [switch]$ExpandNested,
    [switch]$NormalizeValues,
    [switch]$SkipOutliers
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '07-RoleMining'
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

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot

    # ---- Groups ----
    Write-RunLog 'Reading groups...'
    $allGroups = @(Get-ADGroup -Filter * -Properties memberOf @script:AdParams)
    $groupByDN = @{}
    foreach ($g in $allGroups) { $groupByDN[$g.DistinguishedName] = $g }
    function Test-GroupInScope {
        param($Group)
        if (-not $Group) { return $false }
        if (-not $IncludeDistributionGroups -and $Group.GroupCategory -ne 'Security') { return $false }
        if ($ExcludeGroupRegex -and $Group.Name -match $ExcludeGroupRegex) { return $false }
        return $true
    }

    # Transitive parent groups per group (memoised), used only with -ExpandNested
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

    # ---- Users ----
    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    $filter = $(if ($IncludeDisabled) { '*' } else { 'Enabled -eq $true' })
    $props = @('memberOf', 'sAMAccountName') + $GroupingAttributes
    Write-RunLog ("Reading users (filter: {0})..." -f $filter)
    $rawUsers = @(Get-ADUser -Filter $filter -Properties $props @p)
    $users = [System.Collections.Generic.List[object]]::new()
    $excludedCount = 0
    foreach ($u in $rawUsers) {
        $sam = $u.SamAccountName
        if (@($ExcludeNamePatterns | Where-Object { $sam -like $_ }).Count) { $excludedCount++; continue }
        $groups = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($dn in @($u.memberOf | Where-Object { $_ })) {
            if (Test-GroupInScope $groupByDN[$dn]) { [void]$groups.Add($groupByDN[$dn].Name) }
            if ($ExpandNested) {
                foreach ($a in (Get-Ancestor $dn @{})) { if (Test-GroupInScope $groupByDN[$a]) { [void]$groups.Add($groupByDN[$a].Name) } }
            }
        }
        $attrs = @{}
        foreach ($attr in $GroupingAttributes) { $attrs[$attr] = "$($u.$attr)".Trim() }
        $users.Add([pscustomobject]@{ Sam = $sam; Groups = $groups; Attrs = $attrs })
    }
    $total = $users.Count
    Write-RunLog ("{0} users in scope ({1} excluded by name pattern)" -f $total, $excludedCount)
    if ($total -eq 0) { throw 'No users in scope. Check -SearchBase and -ExcludeNamePatterns.' }

    # ---- Global prevalence ----
    $globalCount = @{}
    foreach ($u in $users) { foreach ($g in $u.Groups) { if ($globalCount.ContainsKey($g)) { $globalCount[$g]++ } else { $globalCount[$g] = 1 } } }
    $birthright = @{}
    $birthrightRows = foreach ($g in $globalCount.Keys) {
        $pct = $globalCount[$g] / $total
        if ($pct -ge $BirthrightThreshold) {
            $birthright[$g] = $true
            [pscustomobject][ordered]@{ Group = $g; Holders = $globalCount[$g]; InScopeUsers = $total; PctOfAllUsers = (Format-Pct $pct) }
        }
    }
    Export-Dataset -Name 'birthright-candidates' -Rows @($birthrightRows | Sort-Object PctOfAllUsers -Descending) -Note ("Held by at least {0}% of in-scope users" -f (Format-Pct $BirthrightThreshold))

    # ---- Per attribute ----
    $qualityRows = [System.Collections.Generic.List[object]]::new()
    $variantRows = [System.Collections.Generic.List[object]]::new()
    $populationRows = [System.Collections.Generic.List[object]]::new()
    $candidateRows = [System.Collections.Generic.List[object]]::new()
    $outlierRows = [System.Collections.Generic.List[object]]::new()

    foreach ($attr in $GroupingAttributes) {
        # Quality and variants
        $rawCounts = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal); $normToRaw = @{}; $blank = 0
        foreach ($u in $users) {
            $v = $u.Attrs[$attr]
            if (-not $v) { $blank++; continue }
            if ($rawCounts.ContainsKey($v)) { $rawCounts[$v]++ } else { $rawCounts[$v] = 1 }
            $k = ConvertTo-NormalKey $v
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
            $key = $(if ($NormalizeValues) { ConvertTo-NormalKey $v } else { $v })
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

            $popCount = @{}
            foreach ($u in $members) { foreach ($g in $u.Groups) { if ($popCount.ContainsKey($g)) { $popCount[$g]++ } else { $popCount[$g] = 1 } } }
            $roleSet = @{}; $pctMap = @{}
            foreach ($g in $popCount.Keys) {
                $pct = $popCount[$g] / $size
                $pctMap[$g] = $pct
                if ($pct -lt $CommonThreshold) { continue }
                $gPct = $globalCount[$g] / $total
                $class = $(if ($birthright.ContainsKey($g)) { 'BirthrightCandidate' } elseif ($pct -ge $RoleThreshold) { 'RoleCandidate' } else { 'Common' })
                if ($class -eq 'RoleCandidate') { $roleSet[$g] = $true; $roleCandidates++ }
                $candidateRows.Add([pscustomobject][ordered]@{
                    Attribute        = $attr
                    Value            = $label
                    PopulationSize   = $size
                    Group            = $g
                    Holders          = $popCount[$g]
                    PctInPopulation  = (Format-Pct $pct)
                    PctOfAllUsers    = (Format-Pct $gPct)
                    Lift             = $(if ($gPct -gt 0) { [math]::Round($pct / $gPct, 2) } else { '' })
                    Classification   = $class
                })
            }

            if ($SkipOutliers) { continue }
            foreach ($u in $members) {
                foreach ($g in $roleSet.Keys) {
                    if (-not $u.Groups.Contains($g)) {
                        $outlierRows.Add([pscustomobject][ordered]@{ Attribute = $attr; Value = $label; SamAccountName = $u.Sam; Group = $g; Type = 'MissingRoleCandidate'; PctInPopulation = (Format-Pct $pctMap[$g]); PctOfAllUsers = (Format-Pct ($globalCount[$g] / $total)) })
                    }
                }
                foreach ($g in $u.Groups) {
                    $gp = $globalCount[$g] / $total
                    if ($pctMap[$g] -le $OutlierThreshold -and $gp -le $OutlierThreshold) {
                        $outlierRows.Add([pscustomobject][ordered]@{ Attribute = $attr; Value = $label; SamAccountName = $u.Sam; Group = $g; Type = 'UncommonAccess'; PctInPopulation = (Format-Pct $pctMap[$g]); PctOfAllUsers = (Format-Pct $gp) })
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

    # ---- Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Users in scope' $total $(if ($IncludeDisabled) { 'Includes disabled' } else { 'Enabled only' })
    Add-Metric 'Users excluded by name pattern' $excludedCount
    Add-Metric 'Distinct groups held' $globalCount.Count $(if ($ExpandNested) { 'Direct + nested' } else { 'Direct membership only' })
    Add-Metric 'Birthright candidates' @($birthrightRows).Count ("Held by >= {0}% of users" -f (Format-Pct $BirthrightThreshold))
    foreach ($q in $qualityRows) {
        Add-Metric ("{0}: blank (%)" -f $q.Attribute) $q.BlankPct
        Add-Metric ("{0}: distinct values" -f $q.Attribute) $q.DistinctRawValues
        Add-Metric ("{0}: values with spelling variants" -f $q.Attribute) $q.ValuesWithSpellingVariants
        Add-Metric ("{0}: populations with {1}+ users" -f $q.Attribute, $MinPopulation) $q.PopulationsMeetingMin
        Add-Metric ("{0}: role-candidate rows" -f $q.Attribute) $q.RoleCandidateRows ("Groups held by >= {0}% of a population" -f (Format-Pct $RoleThreshold))
    }
    if (-not $SkipOutliers) {
        Add-Metric 'Outlier rows - missing a role-candidate group' @($outlierRows | Where-Object Type -eq 'MissingRoleCandidate').Count
        Add-Metric 'Outlier rows - uncommon access' @($outlierRows | Where-Object Type -eq 'UncommonAccess').Count ("Held by <= {0}% of the population and of all users" -f (Format-Pct $OutlierThreshold))
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ SearchBase = $SearchBase; GroupingAttributes = $GroupingAttributes; MinPopulation = $MinPopulation; RoleThreshold = $RoleThreshold; CommonThreshold = $CommonThreshold; BirthrightThreshold = $BirthrightThreshold; OutlierThreshold = $OutlierThreshold; ExcludeGroupRegex = $ExcludeGroupRegex; IncludeDisabled = [bool]$IncludeDisabled; IncludeDistributionGroups = [bool]$IncludeDistributionGroups; ExpandNested = [bool]$ExpandNested; NormalizeValues = [bool]$NormalizeValues }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
