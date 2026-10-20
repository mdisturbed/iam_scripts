<#
.SYNOPSIS
    Read-only drift check for rule-managed (RBAC) access: are the roles recorded on each user, the
    roles their HR attributes say they should have, and their actual group memberships in step?

.DESCRIPTION
    Designed for a model where:
      - each role (Birthright, a department role, a job-code role) maps to one or more AD groups
        (the role definition file),
      - the JML automation records the roles it applied on the user in an attribute
        (e.g. extensionAttribute10 = "Birthright;Dept-Dept1;Job-JobCode1"),
      - rule-managed groups are identifiable (by a name pattern, a group attribute tag, or simply
        by appearing in the role definition file), and are never used for requested access.

    For every user in scope it reports:
      - AppliedRoles (from the attribute) and, if a rule map is supplied, ExpectedRoles (from HR
        attributes such as department and job code), with RolesToAdd / RolesToRemove - a mover
        the automation did not process
      - UnknownRoles: role codes on the user that the definition file does not contain
      - MissingGroups: groups the applied roles require that the user is not in
      - ExtraRuleGroups: rule-managed groups the user is in that no applied role justifies
        (manual additions, or access left over from an old role)
    Plus a role-definition check (groups that don't exist, groups not tagged as rule-managed,
    rule-managed groups no role uses) and a summary. Run it on a schedule after go-live and the
    output becomes ongoing evidence that rule-based access is behaving.

    READ-ONLY. Uses only Get-AD* cmdlets and Import-Csv.

    Output: <OutputRoot>\15-RuleManagedAccess\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER RoleDefinitionCsv
    One row per role-to-group mapping. Columns: RoleCode, GroupName.
        RoleCode,GroupName
        Birthright,Group1
        Dept-Dept1,Group2

.PARAMETER RuleMapCsv
    Optional. One row per attribute value that grants a role. Columns: Attribute, Value, RoleCode.
    Use Attribute '*' for roles everyone in scope gets.
        Attribute,Value,RoleCode
        *,*,Birthright
        department,Dept1,Dept-Dept1
        extensionAttribute5,JobCode1,Job-JobCode1

.EXAMPLE
    .\15-Test-RuleManagedAccess.ps1 -RoleDefinitionCsv .\roles.csv
.EXAMPLE
    .\15-Test-RuleManagedAccess.ps1 -RoleDefinitionCsv .\roles.csv -RuleMapCsv .\rule-map.csv -AppliedRolesAttribute extensionAttribute10 -RuleManagedGroupRegex '^RB-'
.EXAMPLE
    .\15-Test-RuleManagedAccess.ps1 -RoleDefinitionCsv .\roles.csv -GroupTagAttribute extensionAttribute1 -GroupTagValues Birthright,Department,JobCode

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account (read)
    Compares DIRECT group membership, which is how rule-based provisioning normally assigns.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [Parameter(Mandatory)]
    [string]$RoleDefinitionCsv,
    [string]$RuleMapCsv = '',
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                               # people OU (blank = whole domain)

    [string]$AppliedRolesAttribute = 'extensionAttribute10',
    [string]$Separator = ';',
    [string]$RuleManagedGroupRegex = '',                    # e.g. '^RB-'
    [string]$GroupTagAttribute = '',                        # e.g. 'extensionAttribute1' on the group
    [string[]]$GroupTagValues = @('Birthright', 'Department', 'JobCode'),

    [string[]]$ExcludeNamePatterns = @('svc*', 'sa-*', 'sa_*', 'adm*', '*admin*', 'test*'),
    [switch]$IncludeDisabled,
    [switch]$OnlyDrift                                      # write only users with differences
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '15-RuleManagedAccess'
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

function Split-Roles { param([string]$Value) if (-not $Value) { return @() } return @($Value -split [regex]::Escape($Separator) | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
function Get-Lower { param($Values) return @($Values | ForEach-Object { "$_".ToLowerInvariant() }) }

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot

    # ---- Inputs ----
    if (-not (Test-Path $RoleDefinitionCsv)) { throw "Role definition file not found: $RoleDefinitionCsv" }
    $roleRows = @(Import-Csv -Path $RoleDefinitionCsv)
    foreach ($c in 'RoleCode', 'GroupName') { if ($roleRows.Count -and -not ($roleRows[0].PSObject.Properties.Name -contains $c)) { throw "Role definition file needs columns RoleCode, GroupName." } }
    $roleGroups = @{}   # roleCode(lower) -> HashSet of group names (lower)
    $roleDisplay = @{}
    $groupDisplay = @{}
    foreach ($r in $roleRows) {
        $rc = "$($r.RoleCode)".Trim(); $gn = "$($r.GroupName)".Trim()
        if (-not $rc -or -not $gn) { continue }
        $k = $rc.ToLowerInvariant()
        if (-not $roleGroups.ContainsKey($k)) { $roleGroups[$k] = [System.Collections.Generic.HashSet[string]]::new(); $roleDisplay[$k] = $rc }
        [void]$roleGroups[$k].Add($gn.ToLowerInvariant())
        if (-not $groupDisplay.ContainsKey($gn.ToLowerInvariant())) { $groupDisplay[$gn.ToLowerInvariant()] = $gn }
    }
    $mapRows = @()
    if ($RuleMapCsv) {
        if (-not (Test-Path $RuleMapCsv)) { throw "Rule map file not found: $RuleMapCsv" }
        $mapRows = @(Import-Csv -Path $RuleMapCsv)
        foreach ($c in 'Attribute', 'Value', 'RoleCode') { if ($mapRows.Count -and -not ($mapRows[0].PSObject.Properties.Name -contains $c)) { throw "Rule map file needs columns Attribute, Value, RoleCode." } }
    }
    foreach ($m in $mapRows) { $rc = "$($m.RoleCode)".Trim(); if ($rc -and -not $roleDisplay.ContainsKey($rc.ToLowerInvariant())) { $roleDisplay[$rc.ToLowerInvariant()] = $rc } }
    $mapAttributes = @($mapRows | ForEach-Object { "$($_.Attribute)".Trim() } | Where-Object { $_ -and $_ -ne '*' } | Select-Object -Unique)

    # ---- Groups ----
    $gProps = @('member')
    if ($GroupTagAttribute) { $gProps += $GroupTagAttribute }
    $allGroups = @(Get-ADGroup -Filter * -Properties $gProps @script:AdParams)
    $groupByName = @{}; $groupByDN = @{}
    foreach ($g in $allGroups) { $groupByName[$g.Name.ToLowerInvariant()] = $g; $groupByDN[$g.DistinguishedName] = $g }
    $definedGroups = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($set in $roleGroups.Values) { foreach ($n in $set) { [void]$definedGroups.Add($n) } }
    function Test-RuleManaged {
        param($Group)
        if ($RuleManagedGroupRegex -and $Group.Name -match $RuleManagedGroupRegex) { return $true }
        if ($GroupTagAttribute -and ($GroupTagValues -contains "$($Group.$GroupTagAttribute)")) { return $true }
        return $false
    }
    $tagMode = [bool]($RuleManagedGroupRegex -or $GroupTagAttribute)
    $ruleManaged = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($g in $allGroups) { if ((Test-RuleManaged $g) -or (-not $tagMode -and $definedGroups.Contains($g.Name.ToLowerInvariant()))) { [void]$ruleManaged.Add($g.Name.ToLowerInvariant()) } }
    Write-RunLog ("{0} roles defined; {1} rule-managed groups identified ({2})" -f $roleGroups.Count, $ruleManaged.Count, $(if ($tagMode) { 'by tag/pattern' } else { 'from role definition file' }))

    # ---- 1. Role definition check ----
    $defCheck = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $roleGroups.Keys) {
        foreach ($gn in $roleGroups[$k]) {
            $g = $groupByName[$gn]
            $issue = @()
            if (-not $g) { $issue += 'GroupNotFound' }
            elseif ($tagMode -and -not (Test-RuleManaged $g)) { $issue += 'GroupNotTaggedRuleManaged' }
            $defCheck.Add([pscustomobject][ordered]@{ Item = 'RoleGroup'; RoleCode = $roleDisplay[$k]; GroupName = $(if ($g) { $g.Name } else { $groupDisplay[$gn] }); DirectMembers = $(if ($g) { @($g.member | Where-Object { $_ }).Count } else { '' }); Issue = Join-Values $issue })
        }
    }
    foreach ($n in $ruleManaged) {
        if (-not $definedGroups.Contains($n)) { $defCheck.Add([pscustomobject][ordered]@{ Item = 'RuleManagedGroup'; RoleCode = ''; GroupName = $groupByName[$n].Name; DirectMembers = @($groupByName[$n].member | Where-Object { $_ }).Count; Issue = 'TaggedButNotInAnyRole' }) }
    }
    foreach ($m in $mapRows) {
        $rc = "$($m.RoleCode)".Trim()
        if ($rc -and -not $roleGroups.ContainsKey($rc.ToLowerInvariant())) { $defCheck.Add([pscustomobject][ordered]@{ Item = 'RuleMap'; RoleCode = $rc; GroupName = ''; DirectMembers = ''; Issue = "RoleInMapNotDefined ($($m.Attribute)=$($m.Value))" }) }
    }
    Export-Dataset -Name 'role-definition-check' -Rows $defCheck -Note 'Rows with an Issue need fixing before user results can be trusted'

    # ---- Users ----
    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    $uProps = @('memberOf', $AppliedRolesAttribute) + $mapAttributes
    $filter = $(if ($IncludeDisabled) { '*' } else { 'Enabled -eq $true' })
    $users = @(Get-ADUser -Filter $filter -Properties $uProps @p | Where-Object { $sam = $_.SamAccountName; -not @($ExcludeNamePatterns | Where-Object { $sam -like $_ }).Count })
    Write-RunLog ("{0} users in scope" -f $users.Count)

    $userRows = [System.Collections.Generic.List[object]]::new()
    $detail = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $users) {
        $applied = @(Split-Roles "$($u.$AppliedRolesAttribute)")
        $appliedL = @(Get-Lower $applied)
        foreach ($a in $applied) { if (-not $roleDisplay.ContainsKey($a.ToLowerInvariant())) { $roleDisplay[$a.ToLowerInvariant()] = $a } }
        $expectedL = $null
        if ($mapRows.Count) {
            $exp = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($m in $mapRows) {
                $attr = "$($m.Attribute)".Trim()
                if ($attr -eq '*' -or ("$($u.$attr)".Trim() -ieq "$($m.Value)".Trim() -and "$($m.Value)".Trim())) { [void]$exp.Add("$($m.RoleCode)".Trim().ToLowerInvariant()) }
            }
            $expectedL = @($exp)
        }
        $unknown = @($appliedL | Where-Object { -not $roleGroups.ContainsKey($_) })
        $required = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($r in $appliedL) { if ($roleGroups.ContainsKey($r)) { foreach ($gn in $roleGroups[$r]) { [void]$required.Add($gn) } } }
        $actualAll = [System.Collections.Generic.HashSet[string]]::new()
        $actualRule = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($dn in @($u.memberOf | Where-Object { $_ })) {
            $g = $groupByDN[$dn]
            if (-not $g) { continue }
            $gl = $g.Name.ToLowerInvariant()
            [void]$actualAll.Add($gl)
            if ($ruleManaged.Contains($gl)) { [void]$actualRule.Add($gl) }
        }
        $missing = @($required | Where-Object { -not $actualAll.Contains($_) })
        $extra = @($actualRule | Where-Object { -not $required.Contains($_) })
        $toAdd = @(); $toRemove = @()
        if ($null -ne $expectedL) {
            $toAdd = @($expectedL | Where-Object { $appliedL -notcontains $_ })
            $toRemove = @($appliedL | Where-Object { $expectedL -notcontains $_ })
        }
        $issues = @()
        if (-not $applied.Count) { $issues += 'NoAppliedRoles' }
        if ($unknown.Count) { $issues += 'UnknownRoles' }
        if ($toAdd.Count -or $toRemove.Count) { $issues += 'RoleDrift' }
        if ($missing.Count) { $issues += 'MissingGroups' }
        if ($extra.Count) { $issues += 'ExtraRuleGroups' }
        $status = $(if ($issues.Count -eq 0 -or ($issues.Count -eq 1 -and $issues[0] -eq 'NoAppliedRoles' -and -not $actualRule.Count -and -not $toAdd.Count)) { 'InSync' } else { 'Drift' })
        if ($OnlyDrift -and $status -eq 'InSync') { continue }
        $name = { param($k) if ($roleDisplay.ContainsKey($k)) { $roleDisplay[$k] } else { $k } }
        $gname = { param($k) if ($groupByName.ContainsKey($k)) { $groupByName[$k].Name } elseif ($groupDisplay.ContainsKey($k)) { $groupDisplay[$k] } else { $k } }
        $userRows.Add([pscustomobject][ordered]@{
            SamAccountName  = $u.SamAccountName
            Enabled         = $u.Enabled
            AppliedRoles    = Join-Values $applied
            ExpectedRoles   = $(if ($null -ne $expectedL) { Join-Values ($expectedL | ForEach-Object { & $name $_ }) } else { 'n/a (no rule map)' })
            RolesToAdd      = Join-Values ($toAdd | ForEach-Object { & $name $_ })
            RolesToRemove   = Join-Values ($toRemove | ForEach-Object { & $name $_ })
            UnknownRoles    = Join-Values ($unknown | ForEach-Object { & $name $_ })
            MissingGroups   = Join-Values ($missing | ForEach-Object { & $gname $_ })
            ExtraRuleGroups = Join-Values ($extra | ForEach-Object { & $gname $_ })
            Issues          = Join-Values $issues
            Status          = $status
        })
        foreach ($m in $missing) { $detail.Add([pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; Type = 'MissingGroup'; Group = & $gname $m; Note = 'Required by an applied role' }) }
        foreach ($x in $extra) { $detail.Add([pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; Type = 'ExtraRuleGroup'; Group = & $gname $x; Note = 'Rule-managed group not justified by applied roles' }) }
        foreach ($r in $toAdd) { $detail.Add([pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; Type = 'RoleToAdd'; Group = & $name $r; Note = 'HR attributes grant this role; not applied' }) }
        foreach ($r in $toRemove) { $detail.Add([pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; Type = 'RoleToRemove'; Group = & $name $r; Note = 'Applied but HR attributes no longer grant it' }) }
    }
    Export-Dataset -Name 'user-reconciliation' -Rows $userRows -Note $(if ($OnlyDrift) { 'Drift rows only' } else { 'All users in scope' })
    Export-Dataset -Name 'drift-detail' -Rows $detail

    # ---- Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $drift = @($userRows | Where-Object Status -eq 'Drift')
    Add-Metric 'Users in scope' $users.Count
    Add-Metric 'Role definition file SHA256' (Get-FileHash -Path $RoleDefinitionCsv -Algorithm SHA256).Hash (Split-Path $RoleDefinitionCsv -Leaf)
    if ($RuleMapCsv) { Add-Metric 'Rule map file SHA256' (Get-FileHash -Path $RuleMapCsv -Algorithm SHA256).Hash (Split-Path $RuleMapCsv -Leaf) }
    Add-Metric 'Users in sync' ($users.Count - $drift.Count) ("{0}%" -f $(if ($users.Count) { [math]::Round(100 * ($users.Count - $drift.Count) / $users.Count, 1) } else { 0 }))
    Add-Metric 'Users with drift' $drift.Count
    Add-Metric 'Users with no applied roles' @($userRows | Where-Object { $_.Issues -match 'NoAppliedRoles' }).Count $(if ($OnlyDrift) { 'Drift rows only' } else { '' })
    Add-Metric 'Users with role drift (mover not processed)' @($drift | Where-Object { $_.Issues -match 'RoleDrift' }).Count $(if (-not $RuleMapCsv) { 'Needs -RuleMapCsv' } else { '' })
    Add-Metric 'Users missing required groups' @($drift | Where-Object { $_.Issues -match 'MissingGroups' }).Count
    Add-Metric 'Users with extra rule-managed groups' @($drift | Where-Object { $_.Issues -match 'ExtraRuleGroups' }).Count 'Manual additions or leftovers from an old role'
    Add-Metric 'Users with unknown role codes' @($drift | Where-Object { $_.Issues -match 'UnknownRoles' }).Count
    Add-Metric 'Role definition issues' @($defCheck | Where-Object Issue).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ RoleDefinitionCsv = (Split-Path $RoleDefinitionCsv -Leaf); RuleMapCsv = $(if ($RuleMapCsv) { Split-Path $RuleMapCsv -Leaf } else { '' }); AppliedRolesAttribute = $AppliedRolesAttribute; Separator = $Separator; RuleManagedGroupRegex = $RuleManagedGroupRegex; GroupTagAttribute = $GroupTagAttribute; GroupTagValues = $GroupTagValues; SearchBase = $SearchBase; IncludeDisabled = [bool]$IncludeDisabled; OnlyDrift = [bool]$OnlyDrift }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
