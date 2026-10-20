<#
.SYNOPSIS
    Read-only reconciliation of an IGA platform export (accounts and assignments) against Active Directory.

.DESCRIPTION
    Shows where the governance system's view of accounts and group access differs from what is
    actually in AD. Before JML moves to a new platform, this documents what the current IGA does
    and does not control. Inputs are CSV exports you supply; nothing connects to the IGA itself.

    Accounts (required export)
      - AD accounts the IGA does not know about (unmanaged; service/admin patterns marked separately)
      - IGA accounts with no AD account (deleted outside the IGA, or never provisioned)
      - Status mismatches: IGA says disabled/terminated but AD is enabled, or the reverse
    Group access (optional export)
      - Governed groups: every group that appears in an IGA assignment, with counts of members in
        both, AD-only (granted outside governance) and IGA-only (not provisioned)
      - Memberships outside governance: user in a governed group with no IGA assignment
      - Assignments not in AD: IGA assignment with no matching AD membership
      - Ungoverned groups: AD security groups with members that the IGA never assigns
    Also writes an input profile (rows, systems and status values seen) so you can confirm the
    column mapping before trusting the results.

    Compares DIRECT group membership. Access the IGA grants through group nesting will show as
    "not in AD" for the parent group - check those rows against the nesting in script 05.

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

.EXAMPLE
    .\14-Compare-IgaToDirectory.ps1 -AccountsCsv .\iga-accounts.csv
.EXAMPLE
    .\14-Compare-IgaToDirectory.ps1 -AccountsCsv .\iga-accounts.csv -AssignmentsCsv .\iga-assignments.csv -SystemName '*AD*'
.EXAMPLE
    .\14-Compare-IgaToDirectory.ps1 -AccountsCsv .\accts.csv -AcctNameColumn 'Account' -AcctStatusColumn 'AccountState' -AdAccountKey userPrincipalName

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account (read)
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
    [string]$AdGroupKey = 'Name',
    [string[]]$ServiceNamePatterns = @('svc*', 'sa-*', 'sa_*', 'adm*', '*admin*', 'test*', 'krbtgt', 'Guest', 'DefaultAccount')
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '14-IgaReconciliation'
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

function Test-Column { param($Rows, [string]$Column, [string]$File) if ($Rows.Count -and -not ($Rows[0].PSObject.Properties.Name -contains $Column)) { throw "$File has no column '$Column'. Columns found: $($Rows[0].PSObject.Properties.Name -join ', ')" } }
function Get-StatusClass { param([string]$Status) if ($ActiveStatusValues -contains $Status) { return 'Active' } if ($InactiveStatusValues -contains $Status) { return 'Inactive' } if (-not $Status) { return 'Active' } return 'Unknown' }

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot

    # ---- Inputs ----
    if (-not (Test-Path $AccountsCsv)) { throw "Accounts file not found: $AccountsCsv" }
    $acctAll = @(Import-Csv -Path $AccountsCsv)
    foreach ($c in $AcctNameColumn, $AcctSystemColumn, $AcctStatusColumn) { Test-Column $acctAll $c 'Accounts file' }
    $acct = @($acctAll | Where-Object { "$($_.$AcctSystemColumn)" -like $SystemName })
    $inputProfile = [System.Collections.Generic.List[object]]::new()
    $inputProfile.Add([pscustomobject][ordered]@{ File = 'Accounts'; Item = 'Rows read'; Value = $acctAll.Count })
    $inputProfile.Add([pscustomobject][ordered]@{ File = 'Accounts'; Item = 'SHA256'; Value = (Get-FileHash $AccountsCsv -Algorithm SHA256).Hash })
    $inputProfile.Add([pscustomobject][ordered]@{ File = 'Accounts'; Item = 'Systems seen'; Value = Join-Values ($acctAll | Group-Object $AcctSystemColumn | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count }) })
    $inputProfile.Add([pscustomobject][ordered]@{ File = 'Accounts'; Item = "Rows matching System '$SystemName'"; Value = $acct.Count })
    $inputProfile.Add([pscustomobject][ordered]@{ File = 'Accounts'; Item = 'Status values seen'; Value = Join-Values ($acct | Group-Object $AcctStatusColumn | ForEach-Object { '{0} -> {1} ({2})' -f $_.Name, (Get-StatusClass $_.Name), $_.Count }) })
    if ($acct.Count -eq 0) { throw "No account rows match System '$SystemName'. See the Systems seen line in iga-input-profile.csv." }

    $asg = @()
    if ($AssignmentsCsv) {
        if (-not (Test-Path $AssignmentsCsv)) { throw "Assignments file not found: $AssignmentsCsv" }
        $asgAll = @(Import-Csv -Path $AssignmentsCsv)
        foreach ($c in $AsgAccountColumn, $AsgSystemColumn, $AsgResourceColumn) { Test-Column $asgAll $c 'Assignments file' }
        $hasStatus = ($asgAll.Count -and ($asgAll[0].PSObject.Properties.Name -contains $AsgStatusColumn))
        $asg = @($asgAll | Where-Object { "$($_.$AsgSystemColumn)" -like $SystemName -and (-not $hasStatus -or (Get-StatusClass "$($_.$AsgStatusColumn)") -ne 'Inactive') })
        $inputProfile.Add([pscustomobject][ordered]@{ File = 'Assignments'; Item = 'Rows read'; Value = $asgAll.Count })
        $inputProfile.Add([pscustomobject][ordered]@{ File = 'Assignments'; Item = 'SHA256'; Value = (Get-FileHash $AssignmentsCsv -Algorithm SHA256).Hash })
        $inputProfile.Add([pscustomobject][ordered]@{ File = 'Assignments'; Item = "Active rows matching System '$SystemName'"; Value = $asg.Count })
        if ($hasStatus) { $inputProfile.Add([pscustomobject][ordered]@{ File = 'Assignments'; Item = 'Status values seen'; Value = Join-Values ($asgAll | Group-Object $AsgStatusColumn | ForEach-Object { '{0} -> {1} ({2})' -f $_.Name, (Get-StatusClass $_.Name), $_.Count }) }) }
    }
    Export-Dataset -Name 'iga-input-profile' -Rows $inputProfile -Note 'Check the status mapping before trusting mismatches'

    # ---- AD ----
    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    $adUsers = @(Get-ADUser -Filter * -Properties enabled, userPrincipalName, whenCreated, lastLogonTimestamp @p)
    $adByKey = @{}; $adByDN = @{}
    foreach ($u in $adUsers) {
        $k = "$($u.$AdAccountKey)".ToLowerInvariant()
        if ($k) { $adByKey[$k] = $u }
        $adByDN[$u.DistinguishedName] = $u
    }
    Write-RunLog ("{0} AD users; {1} IGA account rows for this system" -f $adUsers.Count, $acct.Count)

    # ---- 1. Accounts ----
    $igaByKey = @{}
    foreach ($r in $acct) { $k = "$($r.$AcctNameColumn)".Trim().ToLowerInvariant(); if ($k) { $igaByKey[$k] = $r } }

    $adNotInIga = foreach ($u in $adUsers) {
        $k = "$($u.$AdAccountKey)".ToLowerInvariant()
        if ($igaByKey.ContainsKey($k)) { continue }
        $svc = [bool](@($ServiceNamePatterns | Where-Object { $u.SamAccountName -like $_ }).Count)
        [pscustomobject][ordered]@{
            SamAccountName    = $u.SamAccountName
            UserPrincipalName = $u.UserPrincipalName
            Enabled           = $u.Enabled
            WhenCreated       = $u.whenCreated
            LastLogonUtc      = $(if ($u.lastLogonTimestamp) { [datetime]::FromFileTimeUtc([int64]$u.lastLogonTimestamp).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            Classification    = $(if ($svc) { 'ServiceOrAdminPattern' } elseif ($u.Enabled) { 'UnmanagedEnabled' } else { 'UnmanagedDisabled' })
            DistinguishedName = $u.DistinguishedName
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
    Export-Dataset -Name 'account-status-mismatch' -Rows $mismatch -Note 'IgaInactive_ADEnabled is the highest-risk row type'

    # ---- 2. Group access ----
    $govRows = @(); $outside = [System.Collections.Generic.List[object]]::new(); $notInAd = [System.Collections.Generic.List[object]]::new(); $ungoverned = @()
    if (-not $AssignmentsCsv) {
        foreach ($n in 'governed-groups', 'memberships-outside-iga', 'assignments-not-in-ad', 'ungoverned-groups') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note 'Supply -AssignmentsCsv' }
    }
    else {
        $gp = @{} + $script:AdParams
        if ($GroupSearchBase) { $gp['SearchBase'] = $GroupSearchBase }
        $adGroups = @(Get-ADGroup -Filter * -Properties member @gp)
        $groupByKey = @{}
        foreach ($g in $adGroups) { $groupByKey["$($g.$AdGroupKey)".ToLowerInvariant()] = $g }

        $igaMembers = @{}   # groupKey -> HashSet of account keys
        $igaGroupDisplay = @{}
        foreach ($r in $asg) {
            $gk = "$($r.$AsgResourceColumn)".Trim().ToLowerInvariant(); $ak = "$($r.$AsgAccountColumn)".Trim().ToLowerInvariant()
            if (-not $gk -or -not $ak) { continue }
            if (-not $igaMembers.ContainsKey($gk)) { $igaMembers[$gk] = [System.Collections.Generic.HashSet[string]]::new(); $igaGroupDisplay[$gk] = "$($r.$AsgResourceColumn)".Trim() }
            [void]$igaMembers[$gk].Add($ak)
        }

        $govRows = foreach ($gk in $igaMembers.Keys) {
            $g = $groupByKey[$gk]
            $adSet = [System.Collections.Generic.HashSet[string]]::new()
            if ($g) { foreach ($m in @($g.member | Where-Object { $_ })) { if ($adByDN.ContainsKey($m)) { [void]$adSet.Add("$($adByDN[$m].$AdAccountKey)".ToLowerInvariant()) } } }
            $both = 0
            foreach ($a in $adSet) {
                if ($igaMembers[$gk].Contains($a)) { $both++ }
                else { $outside.Add([pscustomobject][ordered]@{ Group = $(if ($g) { $g.Name } else { $igaGroupDisplay[$gk] }); Account = $adByKey[$a].SamAccountName; ADEnabled = $adByKey[$a].Enabled; Finding = 'InADNotInIga' }) }
            }
            foreach ($a in $igaMembers[$gk]) {
                if (-not $adSet.Contains($a)) { $notInAd.Add([pscustomobject][ordered]@{ Group = $(if ($g) { $g.Name } else { $igaGroupDisplay[$gk] }); Account = $a; GroupExistsInAD = [bool]$g; AccountExistsInAD = $adByKey.ContainsKey($a); Finding = $(if (-not $g) { 'GroupMissingInAD' } elseif (-not $adByKey.ContainsKey($a)) { 'AccountMissingInAD' } else { 'NotProvisioned' }) }) }
            }
            [pscustomobject][ordered]@{
                Group             = $(if ($g) { $g.Name } else { $igaGroupDisplay[$gk] })
                ExistsInAD        = [bool]$g
                IgaAssignments    = $igaMembers[$gk].Count
                ADUserMembers     = $adSet.Count
                InBoth            = $both
                ADOnly            = $adSet.Count - $both
                IgaOnly           = $igaMembers[$gk].Count - $both
            }
        }
        Export-Dataset -Name 'governed-groups' -Rows @($govRows | Sort-Object ADOnly -Descending)
        Export-Dataset -Name 'memberships-outside-iga' -Rows $outside -Note 'Access granted directly in AD to a governed group'
        Export-Dataset -Name 'assignments-not-in-ad' -Rows $notInAd

        $ungoverned = foreach ($g in $adGroups) {
            if ($g.GroupCategory -ne 'Security') { continue }
            $k = "$($g.$AdGroupKey)".ToLowerInvariant()
            if ($igaMembers.ContainsKey($k)) { continue }
            $userMembers = @($g.member | Where-Object { $_ -and $adByDN.ContainsKey($_) }).Count
            if ($userMembers -eq 0) { continue }
            [pscustomobject][ordered]@{ Group = $g.Name; UserMembers = $userMembers; Scope = $g.GroupScope; DistinguishedName = $g.DistinguishedName }
        }
        Export-Dataset -Name 'ungoverned-groups' -Rows @($ungoverned | Sort-Object UserMembers -Descending) -Note 'Security groups with user members that no IGA assignment references'
    }

    # ---- 3. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'AD users in scope' $adUsers.Count
    Add-Metric 'IGA accounts for this system' $igaByKey.Count
    Add-Metric 'AD accounts managed by IGA (%)' $(if ($adUsers.Count) { [math]::Round(100 * ($adUsers.Count - @($adNotInIga).Count) / $adUsers.Count, 1) } else { 0 })
    Add-Metric 'Enabled AD accounts unknown to IGA' @($adNotInIga | Where-Object Classification -eq 'UnmanagedEnabled').Count 'Excludes service/admin name patterns'
    Add-Metric 'Service/admin-pattern accounts unknown to IGA' @($adNotInIga | Where-Object Classification -eq 'ServiceOrAdminPattern').Count
    Add-Metric 'Active IGA accounts missing from AD' @($igaNotInAd | Where-Object IgaStatusClass -eq 'Active').Count
    Add-Metric 'IGA inactive but AD enabled' @($mismatch | Where-Object MismatchType -eq 'IgaInactive_ADEnabled').Count 'Highest risk'
    Add-Metric 'IGA active but AD disabled' @($mismatch | Where-Object MismatchType -eq 'IgaActive_ADDisabled').Count
    Add-Metric 'IGA status values not mapped' @($mismatch | Where-Object MismatchType -eq 'UnmappedIgaStatus').Count 'Extend -ActiveStatusValues / -InactiveStatusValues'
    if ($AssignmentsCsv) {
        Add-Metric 'Groups governed by IGA' @($govRows).Count
        Add-Metric 'Governed groups missing in AD' @($govRows | Where-Object { -not $_.ExistsInAD }).Count
        Add-Metric 'Memberships granted outside IGA' $outside.Count
        Add-Metric 'IGA assignments not present in AD' $notInAd.Count
        Add-Metric 'Ungoverned security groups with members' @($ungoverned).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ AccountsCsv = (Split-Path $AccountsCsv -Leaf); AssignmentsCsv = $(if ($AssignmentsCsv) { Split-Path $AssignmentsCsv -Leaf } else { '' }); SystemName = $SystemName; AdAccountKey = $AdAccountKey; AdGroupKey = $AdGroupKey; ActiveStatusValues = $ActiveStatusValues; InactiveStatusValues = $InactiveStatusValues; SearchBase = $SearchBase; GroupSearchBase = $GroupSearchBase }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
