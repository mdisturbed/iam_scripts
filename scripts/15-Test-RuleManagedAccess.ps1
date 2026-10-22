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

    For every user in scope (enabled and disabled; disabled users are reported with
    Enabled = False) it reports:
      - AppliedRoles (from the attribute) and, if a rule map is supplied, ExpectedRoles (from HR
        attributes such as department and job code), with RolesToAdd / RolesToRemove - a mover
        the automation did not process
      - UnknownRoles: role codes on the user that the definition file does not contain
      - MissingGroups: groups the applied roles require that the user is not in
      - ExtraRuleGroups: rule-managed groups the user is in that no applied role justifies
        (manual additions, or access left over from an old role)
      - DisabledHoldsRuleGroups: a disabled account (usually a leaver) still in rule-managed groups
    From the group side, every member of every rule-managed group that is not an evaluated,
    enabled user is listed: disabled accounts, users outside -SearchBase, service/admin-named
    accounts, nested groups, computers and foreign security principals.
    Plus a role-definition check (groups that don't exist or whose name is ambiguous, groups not
    tagged as rule-managed, rule-managed groups no role uses, rule-map attributes not in the
    schema) and a summary. Run it on a schedule after go-live and the output becomes ongoing
    evidence that rule-based access is behaving.

    Groups are matched by distinguishedName internally. A GroupName in the role definition file
    is resolved as a distinguishedName, then sAMAccountName, then name.

    READ-ONLY. Uses only Get-AD* cmdlets and Import-Csv.

    Output: <OutputRoot>\15-RuleManagedAccess\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER RoleDefinitionCsv
    One row per role-to-group mapping. Columns: RoleCode, GroupName.
        RoleCode,GroupName
        Birthright,Group1
        Dept-Dept1,Group2

.PARAMETER RuleMapCsv
    Optional. One row per attribute value that grants a role. Columns: Attribute, Value, RoleCode.
    Use Attribute '*' for roles everyone in scope gets. Each row is a single-attribute rule; several
    rows for the same role are alternatives (OR). Rules that need two attributes together (AND)
    are not supported by this format.
        Attribute,Value,RoleCode
        *,*,Birthright
        department,Dept1,Dept-Dept1
        extensionAttribute5,JobCode1,Job-JobCode1

.PARAMETER EnabledOnly
    Evaluate enabled users only. By default disabled users are evaluated too, because leavers
    keeping birthright and department groups is the main finding.

.PARAMETER IncludeDisabled
    Deprecated and ignored: disabled users are included by default. Use -EnabledOnly to leave
    them out.

.EXAMPLE
    .\15-Test-RuleManagedAccess.ps1 -RoleDefinitionCsv .\roles.csv
.EXAMPLE
    .\15-Test-RuleManagedAccess.ps1 -RoleDefinitionCsv .\roles.csv -RuleMapCsv .\rule-map.csv -AppliedRolesAttribute extensionAttribute10 -RuleManagedGroupRegex '^RB-'
.EXAMPLE
    .\15-Test-RuleManagedAccess.ps1 -RoleDefinitionCsv .\roles.csv -GroupTagAttribute extensionAttribute1 -GroupTagValues Birthright,Department,JobCode -EnabledOnly

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account (read)
    Compares DIRECT group membership, which is how rule-based provisioning normally assigns.
    Nested groups inside rule-managed groups are reported in rule-group-unexpected-members.
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
    [switch]$EnabledOnly,
    [switch]$IncludeDisabled,                               # deprecated no-op (disabled users are included by default)
    [switch]$OnlyDrift                                      # write only users with differences
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '15-RuleManagedAccess'
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

function Split-Roles { param([string]$Value) if (-not $Value) { return @() } return @($Value -split [regex]::Escape($Separator) | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
function Get-Lower { param($Values) return @($Values | ForEach-Object { "$_".ToLowerInvariant() }) }
function Get-CnFromDn { param([string]$DN) return ($DN -replace '^CN=((?:[^,\\]|\\.)+),.*$', '$1' -replace '\\(.)', '$1') }

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if ($IncludeDisabled) { Write-RunLog '-IncludeDisabled is deprecated and ignored: disabled users are included by default. Use -EnabledOnly to leave them out.' 'WARN' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot

    # ---- Inputs ----
    if (-not (Test-Path $RoleDefinitionCsv)) { throw "Role definition file not found: $RoleDefinitionCsv" }
    $roleRows = @(Import-Csv -Path $RoleDefinitionCsv)
    foreach ($c in 'RoleCode', 'GroupName') { if ($roleRows.Count -and -not ($roleRows[0].PSObject.Properties.Name -contains $c)) { throw "Role definition file needs columns RoleCode, GroupName." } }
    $mapRows = @()
    if ($RuleMapCsv) {
        if (-not (Test-Path $RuleMapCsv)) { throw "Rule map file not found: $RuleMapCsv" }
        $mapRows = @(Import-Csv -Path $RuleMapCsv)
        foreach ($c in 'Attribute', 'Value', 'RoleCode') { if ($mapRows.Count -and -not ($mapRows[0].PSObject.Properties.Name -contains $c)) { throw "Rule map file needs columns Attribute, Value, RoleCode." } }
    }
    $mapAttributes = @($mapRows | ForEach-Object { "$($_.Attribute)".Trim() } | Where-Object { $_ -and $_ -ne '*' } | Select-Object -Unique)

    # ---- Schema check: an attribute missing from the schema would make the user query fail ----
    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    $attrOk = @{}
    $schemaMethod = 'schema'
    $toCheck = @(@($AppliedRolesAttribute) + $mapAttributes | Select-Object -Unique)
    try {
        $schemaNC = (Get-ADRootDSE @script:AdParams).schemaNamingContext
        foreach ($a in $toCheck) {
            if ($a -notmatch '^[A-Za-z][A-Za-z0-9-]*$') { $attrOk[$a] = $false; continue }
            $attrOk[$a] = (@(Get-ADObject -SearchBase $schemaNC -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$a))" -Properties lDAPDisplayName @script:AdParams).Count -gt 0)
        }
    }
    catch {
        # Schema not readable: probe each attribute with a one-user query instead.
        $schemaMethod = 'probe'
        Write-RunLog ("Schema not readable ({0}); probing attributes one at a time" -f $_.Exception.Message) 'WARN'
        foreach ($a in $toCheck) {
            try { $null = Get-ADUser -Filter * -ResultSetSize 1 -Properties $a @p; $attrOk[$a] = $true } catch { $attrOk[$a] = $false }
        }
    }
    if (-not $attrOk[$AppliedRolesAttribute]) { throw "Attribute '$AppliedRolesAttribute' (-AppliedRolesAttribute) is not in the AD schema." }
    $badAttributes = @($mapAttributes | Where-Object { -not $attrOk[$_] })
    $goodMapAttributes = @($mapAttributes | Where-Object { $attrOk[$_] })
    $unevaluableRoles = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in $mapRows) { if ($badAttributes -contains "$($m.Attribute)".Trim()) { [void]$unevaluableRoles.Add("$($m.RoleCode)".Trim().ToLowerInvariant()) } }
    if ($badAttributes.Count) { Write-RunLog ("Rule-map attribute(s) not in the schema, rules on them not evaluated: {0}" -f ($badAttributes -join ', ')) 'WARN' }

    # ---- Groups ----
    $gProps = @('member')
    if ($GroupTagAttribute) { $gProps += $GroupTagAttribute }
    $allGroups = @(Get-ADGroup -Filter * -Properties $gProps @script:AdParams)
    $groupByDN = @{}; $groupBySam = @{}; $groupsByName = @{}
    foreach ($g in $allGroups) {
        $groupByDN[$g.DistinguishedName] = $g
        if ($g.SamAccountName) { $groupBySam["$($g.SamAccountName)".ToLowerInvariant()] = $g }
        $nk = "$($g.Name)".ToLowerInvariant()
        if (-not $groupsByName.ContainsKey($nk)) { $groupsByName[$nk] = [System.Collections.Generic.List[object]]::new() }
        $groupsByName[$nk].Add($g)
    }
    $groupLabel = @{}
    foreach ($g in $allGroups) {
        $groupLabel[$g.DistinguishedName] = $(if ($groupsByName["$($g.Name)".ToLowerInvariant()].Count -gt 1) { '{0} [{1}]' -f $g.Name, ($g.DistinguishedName -replace '^(?:[^,\\]|\\.)+,', '') } else { "$($g.Name)" })
    }
    function Resolve-GroupName {
        # distinguishedName, then sAMAccountName, then name (may be ambiguous)
        param([string]$Name)
        if ($groupByDN.ContainsKey($Name)) { return @($groupByDN[$Name]) }
        $l = $Name.ToLowerInvariant()
        if ($groupBySam.ContainsKey($l)) { return @($groupBySam[$l]) }
        if ($groupsByName.ContainsKey($l)) { return @($groupsByName[$l]) }
        return @()
    }

    # Role -> group keys (DN when resolved, '?name' when not found)
    $roleGroups = @{}; $roleDisplay = @{}; $groupDisplay = @{}; $resolveIssue = @{}
    foreach ($r in $roleRows) {
        $rc = "$($r.RoleCode)".Trim(); $gn = "$($r.GroupName)".Trim()
        if (-not $rc -or -not $gn) { continue }
        $k = $rc.ToLowerInvariant()
        if (-not $roleGroups.ContainsKey($k)) { $roleGroups[$k] = [System.Collections.Generic.HashSet[string]]::new(); $roleDisplay[$k] = $rc }
        $found = @(Resolve-GroupName $gn)
        if ($found.Count -eq 0) { $key = '?' + $gn.ToLowerInvariant(); $groupDisplay[$key] = $gn; $resolveIssue["$k|$key"] = 'GroupNotFound' }
        else {
            $key = $found[0].DistinguishedName
            if ($found.Count -gt 1) { $resolveIssue["$k|$key"] = ("AmbiguousGroupName ({0} groups named '{1}'; first used - use sAMAccountName or DN in the file)" -f $found.Count, $gn) }
        }
        [void]$roleGroups[$k].Add($key)
    }
    foreach ($m in $mapRows) { $rc = "$($m.RoleCode)".Trim(); if ($rc -and -not $roleDisplay.ContainsKey($rc.ToLowerInvariant())) { $roleDisplay[$rc.ToLowerInvariant()] = $rc } }
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
    foreach ($g in $allGroups) { if ((Test-RuleManaged $g) -or (-not $tagMode -and $definedGroups.Contains($g.DistinguishedName))) { [void]$ruleManaged.Add($g.DistinguishedName) } }
    Write-RunLog ("{0} roles defined; {1} rule-managed groups identified ({2})" -f $roleGroups.Count, $ruleManaged.Count, $(if ($tagMode) { 'by tag/pattern' } else { 'from role definition file' }))
    $gname = { param($k) if ($groupLabel.ContainsKey($k)) { $groupLabel[$k] } elseif ($groupDisplay.ContainsKey($k)) { $groupDisplay[$k] } else { $k } }

    # ---- 1. Role definition check ----
    $defCheck = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $roleGroups.Keys) {
        foreach ($gk in $roleGroups[$k]) {
            $g = $groupByDN[$gk]
            $issue = @()
            if ($resolveIssue.ContainsKey("$k|$gk")) { $issue += $resolveIssue["$k|$gk"] }
            if ($g -and $tagMode -and -not (Test-RuleManaged $g)) { $issue += 'GroupNotTaggedRuleManaged' }
            $defCheck.Add([pscustomobject][ordered]@{ Item = 'RoleGroup'; RoleCode = $roleDisplay[$k]; GroupName = (& $gname $gk); DirectMembers = $(if ($g) { @($g.member | Where-Object { $_ }).Count } else { '' }); Issue = Join-Values $issue })
        }
    }
    foreach ($n in $ruleManaged) {
        if (-not $definedGroups.Contains($n)) { $defCheck.Add([pscustomobject][ordered]@{ Item = 'RuleManagedGroup'; RoleCode = ''; GroupName = $groupLabel[$n]; DirectMembers = @($groupByDN[$n].member | Where-Object { $_ }).Count; Issue = 'TaggedButNotInAnyRole' }) }
    }
    foreach ($m in $mapRows) {
        $rc = "$($m.RoleCode)".Trim()
        if ($rc -and -not $roleGroups.ContainsKey($rc.ToLowerInvariant())) { $defCheck.Add([pscustomobject][ordered]@{ Item = 'RuleMap'; RoleCode = $rc; GroupName = ''; DirectMembers = ''; Issue = "RoleInMapNotDefined ($($m.Attribute)=$($m.Value))" }) }
    }
    foreach ($a in $badAttributes) {
        $roles = @($mapRows | Where-Object { "$($_.Attribute)".Trim() -eq $a } | ForEach-Object { "$($_.RoleCode)".Trim() } | Select-Object -Unique)
        $defCheck.Add([pscustomobject][ordered]@{ Item = 'RuleMapAttribute'; RoleCode = Join-Values $roles; GroupName = ''; DirectMembers = ''; Issue = ("AttributeNotInSchema ({0}) - rules on it are not evaluated; role drift for these roles is not reported (checked by {1})" -f $a, $schemaMethod) })
    }
    Export-Dataset -Name 'role-definition-check' -Rows $defCheck -Note 'Rows with an Issue need fixing before user results can be trusted'

    # ---- Users (read once; disabled and name-excluded accounts kept aside for the group-side check) ----
    $uProps = @(@('memberOf', $AppliedRolesAttribute) + $goodMapAttributes | Select-Object -Unique)
    $allUsers = @(Get-ADUser -Filter * -Properties $uProps @p)
    $userByDN = @{}; $excludedByDN = @{}; $evaluated = @{}
    $users = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $allUsers) {
        $userByDN[$u.DistinguishedName] = $u
        $sam = $u.SamAccountName
        if (@($ExcludeNamePatterns | Where-Object { $sam -like $_ }).Count) { $excludedByDN[$u.DistinguishedName] = $true; continue }
        if ($EnabledOnly -and -not $u.Enabled) { continue }
        $users.Add($u); $evaluated[$u.DistinguishedName] = $true
    }
    $disabledEvaluated = @($users | Where-Object { -not $_.Enabled }).Count
    Write-RunLog ("{0} users in scope ({1} disabled; {2} excluded by name pattern)" -f $users.Count, $disabledEvaluated, $excludedByDN.Count)

    $userRows = [System.Collections.Generic.List[object]]::new()
    $detail = [System.Collections.Generic.List[object]]::new()
    $name = { param($k) if ($roleDisplay.ContainsKey($k)) { $roleDisplay[$k] } else { $k } }
    foreach ($u in $users) {
        $applied = @(Split-Roles "$($u.$AppliedRolesAttribute)")
        $appliedL = @(Get-Lower $applied)
        foreach ($a in $applied) { if (-not $roleDisplay.ContainsKey($a.ToLowerInvariant())) { $roleDisplay[$a.ToLowerInvariant()] = $a } }
        $expectedL = $null
        if ($mapRows.Count) {
            $exp = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($m in $mapRows) {
                $attr = "$($m.Attribute)".Trim()
                if ($badAttributes -contains $attr) { continue }
                if ($attr -eq '*' -or ("$($u.$attr)".Trim() -ieq "$($m.Value)".Trim() -and "$($m.Value)".Trim())) { [void]$exp.Add("$($m.RoleCode)".Trim().ToLowerInvariant()) }
            }
            $expectedL = @($exp)
        }
        $unknown = @($appliedL | Where-Object { -not $roleGroups.ContainsKey($_) })
        $required = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($r in $appliedL) { if ($roleGroups.ContainsKey($r)) { foreach ($gk in $roleGroups[$r]) { [void]$required.Add($gk) } } }
        $actualAll = [System.Collections.Generic.HashSet[string]]::new()
        $actualRule = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($dn in @($u.memberOf | Where-Object { $_ })) {
            if (-not $groupByDN.ContainsKey($dn)) { continue }
            [void]$actualAll.Add($dn)
            if ($ruleManaged.Contains($dn)) { [void]$actualRule.Add($dn) }
        }
        $missing = @($required | Where-Object { -not $actualAll.Contains($_) })
        $extra = @($actualRule | Where-Object { -not $required.Contains($_) })
        $toAdd = @(); $toRemove = @()
        if ($null -ne $expectedL) {
            $toAdd = @($expectedL | Where-Object { $appliedL -notcontains $_ -and -not $unevaluableRoles.Contains($_) })
            $toRemove = @($appliedL | Where-Object { $expectedL -notcontains $_ -and -not $unevaluableRoles.Contains($_) })
        }
        $issues = @()
        if (-not $applied.Count) { $issues += 'NoAppliedRoles' }
        if ($unknown.Count) { $issues += 'UnknownRoles' }
        if ($toAdd.Count -or $toRemove.Count) { $issues += 'RoleDrift' }
        if ($missing.Count) { $issues += 'MissingGroups' }
        if ($extra.Count) { $issues += 'ExtraRuleGroups' }
        if (-not $u.Enabled -and $actualRule.Count) { $issues += 'DisabledHoldsRuleGroups' }
        $status = $(if ($issues.Count -eq 0 -or ($issues.Count -eq 1 -and $issues[0] -eq 'NoAppliedRoles' -and -not $actualRule.Count -and -not $toAdd.Count)) { 'InSync' } else { 'Drift' })
        if ($OnlyDrift -and $status -eq 'InSync') { continue }
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
        if (-not $u.Enabled) { foreach ($x in $actualRule) { $detail.Add([pscustomobject][ordered]@{ SamAccountName = $u.SamAccountName; Type = 'DisabledHoldsRuleGroup'; Group = & $gname $x; Note = 'Disabled account still in a rule-managed group; re-enabling restores the access' }) } }
    }
    Export-Dataset -Name 'user-reconciliation' -Rows $userRows -Note $(if ($OnlyDrift) { 'Drift rows only' } else { 'All users in scope' })
    Export-Dataset -Name 'drift-detail' -Rows $detail

    # ---- 2. Group side: members of rule-managed groups that are not evaluated, enabled users ----
    $unexpected = [System.Collections.Generic.List[object]]::new()
    $lookupFailures = 0
    foreach ($gdn in $ruleManaged) {
        $g = $groupByDN[$gdn]
        $roles = Join-Values (@($roleGroups.Keys | Where-Object { $roleGroups[$_].Contains($gdn) } | ForEach-Object { $roleDisplay[$_] }) | Sort-Object)
        foreach ($m in @($g.member | Where-Object { $_ })) {
            $reason = ''; $enabled = ''; $memberName = Get-CnFromDn $m; $note = ''
            if ($evaluated.ContainsKey($m)) {
                $u = $userByDN[$m]
                if ($u.Enabled) { continue }
                $reason = 'DisabledMember'; $enabled = $false; $memberName = $u.SamAccountName; $note = 'Also reported in user-reconciliation'
            }
            elseif ($userByDN.ContainsKey($m)) {
                $u = $userByDN[$m]; $enabled = $u.Enabled; $memberName = $u.SamAccountName
                if ($excludedByDN.ContainsKey($m)) { $reason = 'ExcludedNameMember'; $note = 'Service/admin/test name pattern; not evaluated' }
                else { $reason = 'DisabledMember'; $note = 'Not evaluated (-EnabledOnly)' }
            }
            elseif ($groupByDN.ContainsKey($m)) { $reason = 'NestedGroup'; $memberName = $groupLabel[$m]; $note = ("{0} direct members get this group's access" -f @($groupByDN[$m].member | Where-Object { $_ }).Count) }
            elseif ($m -match '(^|,)CN=ForeignSecurityPrincipals,') { $reason = 'FSP'; $note = 'Account or group from another domain/forest' }
            else {
                try {
                    $o = Get-ADObject -Identity $m -Properties objectClass, sAMAccountName, userAccountControl @script:AdParams
                    $cls = "$(@($o.objectClass)[-1])"
                    if ($o.sAMAccountName) { $memberName = "$($o.sAMAccountName)" }
                    if ($null -ne $o.userAccountControl -and "$($o.userAccountControl)" -ne '') { $enabled = -not ([int]"$($o.userAccountControl)" -band 2) }
                    $reason = switch ($cls) { 'computer' { 'Computer' } 'user' { 'OutOfScopeMember' } 'inetOrgPerson' { 'OutOfScopeMember' } 'msDS-GroupManagedServiceAccount' { 'ManagedServiceAccount' } 'msDS-ManagedServiceAccount' { 'ManagedServiceAccount' } default { $cls } }
                    if ($reason -eq 'OutOfScopeMember') { $note = 'User outside -SearchBase' }
                }
                catch { $lookupFailures++; $reason = 'Unresolved'; $note = ("Lookup failed: {0}" -f $_.Exception.Message) }
            }
            $unexpected.Add([pscustomobject][ordered]@{ Group = $groupLabel[$gdn]; RoleCodes = $roles; Member = $memberName; Reason = $reason; Enabled = $enabled; MemberDistinguishedName = $m; Note = $note })
        }
    }
    Export-Dataset -Name 'rule-group-unexpected-members' -Rows @($unexpected | Sort-Object Reason, Group, Member) -Note $(if ($lookupFailures) { "$lookupFailures member(s) could not be looked up (Reason Unresolved)" } else { 'Members of rule-managed groups other than evaluated, enabled users' })

    # ---- Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $drift = @($userRows | Where-Object Status -eq 'Drift')
    Add-Metric -Metric 'Users in scope' -Value $users.Count -Note $(if ($EnabledOnly) { 'Enabled only (-EnabledOnly)' } else { "Includes $disabledEvaluated disabled" })
    Add-Metric -Metric 'Role definition file SHA256' -Value (Get-FileHash -Path $RoleDefinitionCsv -Algorithm SHA256).Hash -Note (Split-Path $RoleDefinitionCsv -Leaf)
    if ($RuleMapCsv) { Add-Metric -Metric 'Rule map file SHA256' -Value (Get-FileHash -Path $RuleMapCsv -Algorithm SHA256).Hash -Note (Split-Path $RuleMapCsv -Leaf) }
    Add-Metric -Metric 'Users in sync' -Value ($users.Count - $drift.Count) -Note ("{0}%" -f $(if ($users.Count) { [math]::Round(100 * ($users.Count - $drift.Count) / $users.Count, 1) } else { 0 }))
    Add-Metric 'Users with drift' $drift.Count
    Add-Metric -Metric 'Users with no applied roles' -Value @($userRows | Where-Object { $_.Issues -match 'NoAppliedRoles' }).Count -Note $(if ($OnlyDrift) { 'Drift rows only' } else { '' })
    Add-Metric -Metric 'Users with role drift (mover not processed)' -Value @($drift | Where-Object { $_.Issues -match 'RoleDrift' }).Count -Note $(if (-not $RuleMapCsv) { 'Needs -RuleMapCsv' } elseif ($unevaluableRoles.Count) { 'Roles on attributes missing from the schema not compared' } else { '' })
    Add-Metric 'Users missing required groups' @($drift | Where-Object { $_.Issues -match 'MissingGroups' }).Count
    Add-Metric -Metric 'Users with extra rule-managed groups' -Value @($drift | Where-Object { $_.Issues -match 'ExtraRuleGroups' }).Count -Note 'Manual additions or leftovers from an old role'
    Add-Metric 'Users with unknown role codes' @($drift | Where-Object { $_.Issues -match 'UnknownRoles' }).Count
    Add-Metric -Metric 'Disabled users still in rule-managed groups' -Value $(if ($EnabledOnly) { 'not evaluated' } else { @($drift | Where-Object { $_.Issues -match 'DisabledHoldsRuleGroups' }).Count }) -Note $(if ($EnabledOnly) { 'Not evaluated (-EnabledOnly); see rule-group-unexpected-members' } else { 'Usually leavers' })
    Add-Metric -Metric 'Unexpected members of rule-managed groups' -Value $unexpected.Count -Note (Join-Values ($unexpected | Group-Object Reason | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }))
    Add-Metric -Metric 'Rule-map attributes not in the schema' -Value $badAttributes.Count -Note (Join-Values $badAttributes)
    Add-Metric 'Role definition issues' @($defCheck | Where-Object Issue).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ RoleDefinitionCsv = (Split-Path $RoleDefinitionCsv -Leaf); RuleMapCsv = $(if ($RuleMapCsv) { Split-Path $RuleMapCsv -Leaf } else { '' }); AppliedRolesAttribute = $AppliedRolesAttribute; Separator = $Separator; RuleManagedGroupRegex = $RuleManagedGroupRegex; GroupTagAttribute = $GroupTagAttribute; GroupTagValues = $GroupTagValues; SearchBase = $SearchBase; EnabledOnly = [bool]$EnabledOnly; IncludeDisabled = [bool]$IncludeDisabled; OnlyDrift = [bool]$OnlyDrift }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
