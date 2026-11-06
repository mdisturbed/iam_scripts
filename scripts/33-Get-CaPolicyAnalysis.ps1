<#
.SYNOPSIS
    Read-only Conditional Access analysis: every policy's scope, controls, exclusions, state and
    dependencies, plus the gaps, overlaps and conflicts between policies.

.DESCRIPTION
    Analyses a script 28 snapshot offline; connects to nothing:

      - 28-CaPolicySnapshot    ca-policies.json (raw IDs), ca-policies.csv (names), named-locations,
                               authentication-strengths, security-defaults.json
      - 27-IdentityPopulation  optional: break-glass accounts (category BreakGlass), so the analysis can
                               check that every policy excludes them. -BreakGlassUpns works without 27
      - 01-MfaCoverage         optional: ca-excluded-group-members, for excluded-group sizes and
                               break-glass exclusion through a group

    Per policy:
      - Scope (users, apps, conditions), controls (grant and session), exclusions, state and age
      - Purpose: block legacy authentication, MFA baseline, MFA for admins, phishing-resistant MFA,
        risk-based, device compliance, session control, security info registration, block, other
      - Dependencies: every user, group, role, app, named location, authentication strength, terms of
        use and authentication context it refers to, and whether that object still exists

    Issues (one row each, with severity and a recommendation):
      - Gap        tenant baseline missing: MFA for all users, legacy authentication blocked, MFA and
                   phishing-resistant MFA for admins, device code flow blocked, user and sign-in risk,
                   security info registration protected, guests required to use MFA, break-glass excluded
      - Conflict   a block policy that covers every sign-in another enabled policy covers (that policy
                   can never grant access); the same object both included and excluded; different
                   sign-in frequencies for the same sign-ins
      - Overlap    duplicate policies; a policy whose sign-ins and controls are already covered by
                   another; policies with the same scope and different controls
      - Exclusion  break-glass not excluded; an exclusion with no fallback policy; very large excluded
                   groups; MFA skipped from trusted locations; baseline policies that exclude apps
      - Hygiene    deleted references; report-only or disabled for a long time; policies with no control

    Policy comparison is exact, not a simulation. "Covers" means every condition of the wider policy
    is unset or the same as the other's and its includes are a superset and its excludes a subset.
    Policies that overlap only partly are not reported. Use script 24 (report-only impact) and the
    What If tool for sign-in level questions.

    Datasets:
      - ca-policy-inventory      one row per policy: scope, controls, exclusions, state, dependencies,
                                 issue codes. This is the table to report
      - ca-policy-issues         one row per issue: category, severity, policies, detail, recommendation
      - ca-policy-dependencies   one row per policy and referenced object
      - ca-coverage-checks       tenant baseline checks with the standard each one maps to
      - source-runs              every source dataset read: run folder, status, SHA-256 check

    READ-ONLY. Reads earlier run folders only; connects to nothing.

    Output: <OutputRoot>\33-CaPolicyAnalysis\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER EvidenceRoot
    Folder holding the earlier runs. Defaults to -OutputRoot.

.PARAMETER SnapshotRunFolder
    Pin a run folder of script 28 instead of the latest one.

.PARAMETER BreakGlassUpns
    Break-glass account UPNs. Added to the break-glass accounts found in the latest run of script 27.

.PARAMETER ReportOnlyMaxDays
    A report-only policy not modified for longer than this is flagged ReportOnlyStale.

.PARAMETER DisabledMaxDays
    A disabled policy not modified for longer than this is flagged DisabledStale.

.PARAMETER BroadExclusionThreshold
    An excluded group with more members than this (from script 01) is flagged BroadExclusion.

.EXAMPLE
    .\33-Get-CaPolicyAnalysis.ps1 -OutputRoot D:\Evidence
.EXAMPLE
    .\33-Get-CaPolicyAnalysis.ps1 -OutputRoot D:\Evidence -BreakGlassUpns bg1@contoso.com, bg2@contoso.com

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x. An earlier run of 28 in the evidence folder (27 and 01 optional).
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$EvidenceRoot = '',
    [string]$SnapshotRunFolder = '',
    [string]$PopulationRunFolder = '',
    [string]$MfaRunFolder = '',
    [string[]]$BreakGlassUpns = @(),
    [int]$ReportOnlyMaxDays = 30,
    [int]$DisabledMaxDays = 90,
    [int]$BroadExclusionThreshold = 25,
    [switch]$AllowHashMismatch
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '33-CaPolicyAnalysis'
$ScriptVersion = '1.0.0'
$Server        = ''

#region ---- Common helpers (identical in every non-directory script (AWS, event logs); self-contained by design) ----
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
#endregion

#region ---- Evidence-source helpers (identical in 32, 33 and 34; self-contained by design) ----
# Each source dataset is read from one run folder of an earlier script, its SHA-256 is checked against
# the SHA-256 that run recorded in dataset-status.csv, and the read is logged in source-runs.
$script:SourceRows = [System.Collections.Generic.List[object]]::new()
$script:StatusRank = @{ 'Completed' = 0; 'Partial' = 1; 'Deferred' = 2; 'EvidenceUnavailable' = 3; 'Blocked' = 4; 'NotRun' = 5 }

function Get-WorstStatus {
    param([string[]]$Statuses)
    $worst = 'Completed'
    foreach ($s in @($Statuses | Where-Object { $_ })) {
        $r = $(if ($script:StatusRank.ContainsKey($s)) { $script:StatusRank[$s] } else { 4 })
        if ($r -gt $script:StatusRank[$worst]) { $worst = $(if ($script:StatusRank.ContainsKey($s)) { $s } else { 'Blocked' }) }
    }
    return $worst
}

function Get-LatestRunFolder {
    # Newest run folder (yyyyMMdd-HHmmssZ) of script NN that holds a run-manifest.json, or ''.
    param([string]$Root, [string]$Number)
    $runs = @(Get-ChildItem -LiteralPath $Root -Directory -Filter "$Number-*" -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
            Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'run-manifest.json')) } |
            Sort-Object Name)
    if ($runs.Count) { return $runs[-1].FullName }
    return ''
}

function Resolve-SourceRun {
    # The run folder to read for script NN: the pinned folder when one is given, else the latest run.
    param([string]$Number, [string]$Pinned)
    if ($Pinned) {
        if (-not (Test-Path -LiteralPath (Join-Path $Pinned 'run-manifest.json'))) { throw "Not a run folder (no run-manifest.json): $Pinned" }
        return (Resolve-Path -LiteralPath $Pinned).ProviderPath
    }
    return (Get-LatestRunFolder -Root $EvidenceRoot -Number $Number)
}

function Get-RunStartUtc {
    param([string]$RunFolder)
    if (-not $RunFolder) { return $null }
    $out = [datetime]::MinValue
    if ([datetime]::TryParseExact((Split-Path $RunFolder -Leaf), "yyyyMMdd-HHmmss'Z'", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$out)) { return $out }
    return $null
}

function Read-SourceDataset {
    # Reads one dataset of an earlier run. Returns Ok, Status, Note, Rows (CSV) or Data (JSON).
    # Ok is true only for a Completed or Partial dataset whose file still matches its recorded SHA-256.
    param([string]$Script, [string]$RunFolder, [string]$Dataset, [switch]$Json, [switch]$Optional)
    $res = [pscustomobject]@{ Ok = $false; Status = ''; Note = ''; Rows = @(); Data = $null; RunFolder = $RunFolder; File = '' }
    $src = [ordered]@{ Script = $Script; Dataset = $Dataset; RunFolder = $RunFolder; RunStartedUtc = ''; File = ''; SourceStatus = ''; SourceNote = ''; Rows = ''; RecordedSha256 = ''; Sha256 = ''; HashCheck = ''; UsedAs = '' }
    if (-not $RunFolder) {
        $res.Status = 'NotRun'; $res.Note = "script $Script has no run in the evidence folder"
    }
    else {
        $src.RunStartedUtc = $(if (Get-RunStartUtc $RunFolder) { (Get-RunStartUtc $RunFolder).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        $statusFile = Join-Path $RunFolder 'dataset-status.csv'
        $row = $null
        if (Test-Path -LiteralPath $statusFile) { $row = @(Import-Csv -LiteralPath $statusFile | Where-Object { $_.Dataset -eq $Dataset }) | Select-Object -First 1 }
        if (-not $row) {
            $res.Status = 'Blocked'; $res.Note = "dataset $Dataset not in $Script run $(Split-Path $RunFolder -Leaf) (older script version, or switched off)"
        }
        else {
            $src.File = [string]$row.File; $src.SourceStatus = [string]$row.Status; $src.SourceNote = [string]$row.Note; $src.RecordedSha256 = [string]$row.Sha256
            $res.File = [string]$row.File
            if ($row.Status -notin @('Completed', 'Partial')) {
                $res.Status = [string]$row.Status; $res.Note = "source dataset $Dataset is $($row.Status) in that run: $($row.Note)"
            }
            else {
                $path = Join-Path $RunFolder ([string]$row.File)
                if (-not (Test-Path -LiteralPath $path)) { $res.Status = 'Blocked'; $res.Note = "file $($row.File) missing from the run folder"; $src.HashCheck = 'MissingFile' }
                else {
                    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
                    $src.Sha256 = $hash
                    $match = ($row.Sha256 -and $hash -eq [string]$row.Sha256)
                    $src.HashCheck = $(if ($match) { 'Verified' } elseif (-not $row.Sha256) { 'NotRecorded' } else { 'Mismatch' })
                    if (-not $match -and $row.Sha256 -and -not $AllowHashMismatch) {
                        $res.Status = 'Blocked'; $res.Note = "file $($row.File) changed after its run (SHA-256 mismatch; often opened and saved in Excel). Restore the original or rerun script $Script"
                    }
                    else {
                        if ($Json) { $res.Data = $(if ((Get-Item -LiteralPath $path).Length -gt 2) { Get-Content -LiteralPath $path -Raw | ConvertFrom-Json } else { $null }) }
                        else { $res.Rows = $(if ((Get-Item -LiteralPath $path).Length -gt 3) { @(Import-Csv -LiteralPath $path) } else { @() }) }
                        $res.Ok = $true
                        $res.Status = [string]$row.Status
                        $res.Note = $(if ($row.Status -eq 'Partial') { "source dataset $Dataset is Partial: $($row.Note)" } else { '' })
                        if ($src.HashCheck -eq 'Mismatch') { $res.Status = 'Partial'; $res.Note = (@($res.Note, "file $($row.File) changed after its run (used because of -AllowHashMismatch)") | Where-Object { $_ }) -join '; ' }
                        $src.Rows = $(if ($Json) { @($res.Data).Count } else { @($res.Rows).Count })
                    }
                }
            }
        }
    }
    $src.UsedAs = $(if ($res.Ok) { 'Used' } elseif ($Optional) { "Not used (optional): $($res.Status)" } else { "Not used: $($res.Status)" })
    if (-not $res.Ok) { Write-RunLog ("{0} {1}: {2}" -f $Script, $Dataset, $res.Note) $(if ($Optional) { 'INFO' } else { 'WARN' }) }
    $script:SourceRows.Add([pscustomobject]$src)
    return $res
}

function Test-True { param($Value) return ("$Value" -eq 'True') }

function Split-List { param([string]$Text) if (-not $Text) { return @() } return @($Text -split ';\s*' | Where-Object { $_ }) }
#endregion

# ---- Script-specific helpers ----
function Get-OptionalValue {
    param($Object, [string]$Name)
    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $null
}

function Get-List {
    # Always an array (never unrolled to a single string or to `$null), so .Count and -contains behave.
    param($Value)
    return , @(@($Value) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ })
}

function ConvertTo-UtcDate {
    # A date from JSON (DateTime in PowerShell 7, string in 5.1) as UTC DateTime, or `$null.
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $out = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$out)) { return $out }
    return $null
}

function ConvertTo-Canon {
    # Order-independent form: properties sorted, null / empty dropped, lists of scalars sorted.
    param($Object)
    if ($null -eq $Object) { return $null }
    if ($Object -is [string] -or $Object -is [ValueType]) { return $Object }
    if ($Object -is [System.Collections.IEnumerable] -and $Object -isnot [System.Collections.IDictionary]) {
        $items = @(foreach ($i in $Object) { $c = ConvertTo-Canon $i; if ($null -ne $c -and "$c" -ne '') { $c } })
        if (-not $items.Count) { return $null }
        if (@($items | Where-Object { $_ -isnot [string] -and $_ -isnot [ValueType] }).Count -eq 0) { return , @($items | Sort-Object) }
        return , @($items | Sort-Object { $_ | ConvertTo-Json -Depth 30 -Compress })
    }
    $props = $(if ($Object -is [System.Collections.IDictionary]) { @($Object.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $Object[$_] } }) } else { @($Object.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) })
    $o = [ordered]@{}
    foreach ($p in ($props | Sort-Object Name)) {
        if ($p.Name -like '@odata*') { continue }
        $c = ConvertTo-Canon $p.Value
        if ($null -eq $c -or "$c" -eq '') { continue }
        if ($c -is [System.Collections.IDictionary] -and $c.Count -eq 0) { continue }
        $o[$p.Name] = $c
    }
    if (-not $o.Count) { return $null }
    return $o
}

function Get-CanonText { param($Object) $c = ConvertTo-Canon $Object; if ($null -eq $c) { return '' } return ($c | ConvertTo-Json -Depth 30 -Compress) }

function Test-Subset {
    # True when every non-empty item of Sub is in Super (an empty Sub is a subset of anything).
    param([string[]]$Sub, [string[]]$Super)
    foreach ($s in @($Sub | Where-Object { $_ })) { if (@($Super) -notcontains $s) { return $false } }
    return $true
}

function Test-SameSet { param([string[]]$A, [string[]]$B) return ((Test-Subset $A $B) -and (Test-Subset $B $A)) }

function Test-UsersCover {
    # True when policy A's user scope includes every user policy B's does (exact comparison).
    param($A, $B)
    if ($A.IncUsers -notcontains 'All') {
        if ($B.IncUsers -contains 'All') { return $false }
        if (-not (Test-Subset ($B.IncUsers | Where-Object { $_ -ne 'None' }) $A.IncUsers)) { return $false }
        if (-not (Test-Subset $B.IncGroups $A.IncGroups)) { return $false }
        if (-not (Test-Subset $B.IncRoles $A.IncRoles)) { return $false }
        if ($B.IncGuests -and $B.IncGuests -ne $A.IncGuests) { return $false }
    }
    if (-not (Test-Subset $A.ExcUsers $B.ExcUsers)) { return $false }
    if (-not (Test-Subset $A.ExcGroups $B.ExcGroups)) { return $false }
    if (-not (Test-Subset $A.ExcRoles $B.ExcRoles)) { return $false }
    if ($A.ExcGuests -and $A.ExcGuests -ne $B.ExcGuests) { return $false }
    return $true
}

function Test-ConditionsCover {
    # True when every non-user condition of policy A is unset or the same as policy B's (A applies to all of B's sign-ins, users aside).
    param($A, $B)
    # A condition this function does not understand (for example insider risk) makes A narrower in an unknown way.
    if ($A.OtherCond -and $A.OtherCond -ne $B.OtherCond) { return $false }
    if ($A.UserActions.Count -or $B.UserActions.Count -or $A.AuthCtx.Count -or $B.AuthCtx.Count) {
        if (-not (Test-SameSet $A.UserActions $B.UserActions) -or -not (Test-SameSet $A.AuthCtx $B.AuthCtx)) { return $false }
    }
    else {
        if ($A.IncApps -notcontains 'All') {
            if ($B.IncApps -contains 'All') { return $false }
            if (-not (Test-Subset $B.IncApps $A.IncApps)) { return $false }
        }
        if (-not (Test-Subset $A.ExcApps $B.ExcApps)) { return $false }
    }
    foreach ($k in @('ClientApps', 'IncPlat', 'IncLoc', 'SignInRisk', 'UserRisk', 'SpRisk')) {
        # Distinct names: PowerShell variables are case-insensitive, so $a would overwrite $A.
        $valueA = @($A.$k); $valueB = @($B.$k)
        $open = (-not $valueA.Count) -or ($valueA -contains 'all')
        if (-not $open -and -not (Test-SameSet $valueA $valueB)) { return $false }
    }
    if (-not (Test-Subset $A.ExcPlat $B.ExcPlat)) { return $false }
    if (-not (Test-Subset $A.ExcLoc $B.ExcLoc)) { return $false }
    if ($A.DeviceFilter -and $A.DeviceFilter -ne $B.DeviceFilter) { return $false }
    if ($A.AuthFlows -and $A.AuthFlows -ne $B.AuthFlows) { return $false }
    return $true
}

function Test-Covers {
    # True when policy A applies to every sign-in policy B applies to (exact comparison, no simulation).
    param($A, $B)
    return ((Test-UsersCover $A $B) -and (Test-ConditionsCover $A $B))
}

function Test-AllUsersAllApps {
    # Enabled-style baseline shape: all users, all apps, every client, no include-narrowing condition.
    param($P)
    if ($P.IncUsers -notcontains 'All' -or $P.IncApps -notcontains 'All' -or $P.UserActions.Count -or $P.AuthCtx.Count) { return $false }
    if ($P.ClientApps.Count -and $P.ClientApps -notcontains 'all' -and -not (($P.ClientApps -contains 'browser') -and ($P.ClientApps -contains 'mobileAppsAndDesktopClients'))) { return $false }
    if ($P.SignInRisk.Count -or $P.UserRisk.Count -or $P.SpRisk.Count) { return $false }
    if ($P.IncLoc.Count -and $P.IncLoc -notcontains 'All') { return $false }
    if ($P.IncPlat.Count -and $P.IncPlat -notcontains 'all') { return $false }
    return $true
}

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if (-not $EvidenceRoot) { $EvidenceRoot = $OutputRoot }
    if (-not (Test-Path -LiteralPath $EvidenceRoot)) { throw "Evidence folder not found: $EvidenceRoot" }
    $now = $script:RunStartUtc

    # ---- 1. Sources ----
    $run28 = Resolve-SourceRun -Number '28' -Pinned $SnapshotRunFolder
    $run27 = Resolve-SourceRun -Number '27' -Pinned $PopulationRunFolder
    $run01 = Resolve-SourceRun -Number '01' -Pinned $MfaRunFolder
    $pj  = Read-SourceDataset -Script '28' -RunFolder $run28 -Dataset 'ca-policies-json' -Json
    $pc  = Read-SourceDataset -Script '28' -RunFolder $run28 -Dataset 'ca-policies'
    $nl  = Read-SourceDataset -Script '28' -RunFolder $run28 -Dataset 'named-locations'
    $as  = Read-SourceDataset -Script '28' -RunFolder $run28 -Dataset 'authentication-strengths'
    $sd  = Read-SourceDataset -Script '28' -RunFolder $run28 -Dataset 'security-defaults-json' -Json -Optional
    $pop = Read-SourceDataset -Script '27' -RunFolder $run27 -Dataset 'identity-population' -Optional
    $gm  = Read-SourceDataset -Script '01' -RunFolder $run01 -Dataset 'ca-excluded-group-members' -Optional
    if (-not $pj.Ok) { throw "The CA policy snapshot (script 28 ca-policies.json) is needed: $($pj.Note)" }
    $baseStatus = Get-WorstStatus @($pj.Status, $(if (-not $pc.Ok) { 'Partial' }), $(if (-not $nl.Ok) { 'Partial' }), $(if (-not $as.Ok) { 'Partial' }))
    $statusNotes = [System.Collections.Generic.List[string]]::new()
    if (-not $pc.Ok) { $statusNotes.Add("names not available (ca-policies.csv $($pc.Status)); IDs shown") }
    if (-not $nl.Ok) { $statusNotes.Add("named locations not available ($($nl.Status)); location checks limited") }
    if (-not $as.Ok) { $statusNotes.Add("authentication strengths not available ($($as.Status)); phishing-resistant check uses built-in IDs only") }

    # Name maps (ID -> name) aligned from ca-policies.csv, which lists names in the same order as the JSON IDs.
    $names = @{}
    $csvById = @{}
    if ($pc.Ok) { foreach ($r in $pc.Rows) { $csvById["$($r.PolicyId)"] = $r } }
    function Add-Names { param($Ids, [string]$Text)
        $ids = Get-List $Ids; $labels = @(Split-List $Text)
        if ($ids.Count -and $ids.Count -eq $labels.Count) { for ($i = 0; $i -lt $ids.Count; $i++) { if (-not $names.ContainsKey($ids[$i])) { $names[$ids[$i]] = $labels[$i] } } } }
    $locById = @{}
    if ($nl.Ok) { foreach ($l in $nl.Rows) { $locById["$($l.LocationId)"] = $l; $names["$($l.LocationId)"] = "$($l.DisplayName)" } }
    $strById = @{}
    if ($as.Ok) { foreach ($s in $as.Rows) { $strById["$($s.StrengthId)"] = $s } }
    function Get-Name { param([string]$Id) if ($names.ContainsKey($Id)) { return $names[$Id] } return $Id }

    # Break-glass accounts: object IDs from 27, plus -BreakGlassUpns matched to names in the policies.
    $bgIds = @{}
    if ($pop.Ok) { foreach ($i in @($pop.Rows | Where-Object { $_.Category -eq 'BreakGlass' -and $_.EntraObjectId })) { $bgIds["$($i.EntraObjectId)"] = "$($i.Upn)" } }
    $bgUpns = @($BreakGlassUpns | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })

    # Excluded group members from 01
    $groupMembers = @{}
    if ($gm.Ok) { foreach ($m in $gm.Rows) { $g = "$($m.GroupId)"; if (-not $groupMembers.ContainsKey($g)) { $groupMembers[$g] = [System.Collections.Generic.List[object]]::new() }; $groupMembers[$g].Add($m) } }

    # ---- 2. Policy model ----
    $handledConditions = @('users', 'applications', 'clientAppTypes', 'platforms', 'locations', 'signInRiskLevels', 'userRiskLevels', 'servicePrincipalRiskLevels', 'devices', 'authenticationFlows')
    $phishCombos = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello')
    $policies = foreach ($p in @($pj.Data)) {
        $c = Get-OptionalValue $p 'conditions'; $u = Get-OptionalValue $c 'users'; $a = Get-OptionalValue $c 'applications'
        $pl = Get-OptionalValue $c 'platforms'; $lo = Get-OptionalValue $c 'locations'; $dv = Get-OptionalValue $c 'devices'
        $g = Get-OptionalValue $p 'grantControls'; $s = Get-OptionalValue $p 'sessionControls'
        $csv = $(if ($csvById.ContainsKey("$($p.id)")) { $csvById["$($p.id)"] } else { $null })
        if ($csv) {
            Add-Names (Get-OptionalValue $u 'includeUsers') $csv.IncludeUsers; Add-Names (Get-OptionalValue $u 'excludeUsers') $csv.ExcludeUsers
            Add-Names (Get-OptionalValue $u 'includeGroups') $csv.IncludeGroups; Add-Names (Get-OptionalValue $u 'excludeGroups') $csv.ExcludeGroups
            Add-Names (Get-OptionalValue $u 'includeRoles') $csv.IncludeRoles; Add-Names (Get-OptionalValue $u 'excludeRoles') $csv.ExcludeRoles
            Add-Names (Get-OptionalValue $a 'includeApplications') $csv.IncludeApplications; Add-Names (Get-OptionalValue $a 'excludeApplications') $csv.ExcludeApplications
        }
        $df = Get-OptionalValue $dv 'deviceFilter'
        $str = Get-OptionalValue $g 'authenticationStrength'
        $strId = $(if ($str) { [string](Get-OptionalValue $str 'id') } else { '' })
        $strName = $(if ($str -and (Get-OptionalValue $str 'displayName')) { [string]$str.displayName } elseif ($strId -and $strById.ContainsKey($strId)) { [string]$strById[$strId].DisplayName } else { $strId })
        $strCombos = @()
        if ($str -and (Get-OptionalValue $str 'allowedCombinations')) { $strCombos = Get-List $str.allowedCombinations }
        elseif ($strId -and $strById.ContainsKey($strId)) { $strCombos = Split-List $strById[$strId].AllowedCombinations }
        $controls = Get-List (Get-OptionalValue $g 'builtInControls')
        $flows = Get-OptionalValue $c 'authenticationFlows'
        $sif = Get-OptionalValue $s 'signInFrequency'
        [pscustomobject]@{
            Id = [string]$p.id; Name = [string]$p.displayName; State = [string]$p.state
            Created = ConvertTo-UtcDate (Get-OptionalValue $p 'createdDateTime'); Modified = ConvertTo-UtcDate (Get-OptionalValue $p 'modifiedDateTime')
            IncUsers = Get-List (Get-OptionalValue $u 'includeUsers'); ExcUsers = Get-List (Get-OptionalValue $u 'excludeUsers')
            IncGroups = Get-List (Get-OptionalValue $u 'includeGroups'); ExcGroups = Get-List (Get-OptionalValue $u 'excludeGroups')
            IncRoles = Get-List (Get-OptionalValue $u 'includeRoles'); ExcRoles = Get-List (Get-OptionalValue $u 'excludeRoles')
            IncGuests = Get-CanonText (Get-OptionalValue $u 'includeGuestsOrExternalUsers'); ExcGuests = Get-CanonText (Get-OptionalValue $u 'excludeGuestsOrExternalUsers')
            IncGuestText = $(if ($csv) { $csv.IncludeGuestsOrExternal } else { '' }); ExcGuestText = $(if ($csv) { $csv.ExcludeGuestsOrExternal } else { '' })
            IncApps = Get-List (Get-OptionalValue $a 'includeApplications'); ExcApps = Get-List (Get-OptionalValue $a 'excludeApplications')
            UserActions = Get-List (Get-OptionalValue $a 'includeUserActions'); AuthCtx = Get-List (Get-OptionalValue $a 'includeAuthenticationContextClassReferences')
            ClientApps = Get-List (Get-OptionalValue $c 'clientAppTypes')
            IncPlat = Get-List (Get-OptionalValue $pl 'includePlatforms'); ExcPlat = Get-List (Get-OptionalValue $pl 'excludePlatforms')
            IncLoc = Get-List (Get-OptionalValue $lo 'includeLocations'); ExcLoc = Get-List (Get-OptionalValue $lo 'excludeLocations')
            SignInRisk = Get-List (Get-OptionalValue $c 'signInRiskLevels'); UserRisk = Get-List (Get-OptionalValue $c 'userRiskLevels'); SpRisk = Get-List (Get-OptionalValue $c 'servicePrincipalRiskLevels')
            DeviceFilter = $(if ($df) { '{0}: {1}' -f (Get-OptionalValue $df 'mode'), (Get-OptionalValue $df 'rule') } else { '' })
            AuthFlows = $(if ($flows) { Join-Values (Get-OptionalValue $flows 'transferMethods') } else { '' })
            GrantOp = [string](Get-OptionalValue $g 'operator'); Controls = $controls
            StrengthId = $strId; StrengthName = $strName; StrengthCombos = $strCombos
            TermsOfUse = Get-List (Get-OptionalValue $g 'termsOfUse')
            SessionText = $(if ($csv) { [string]$csv.SessionControls } else { Get-CanonText $s })
            SignInFrequency = $(if ($sif -and (Get-OptionalValue $sif 'isEnabled')) { $(if ("$(Get-OptionalValue $sif 'frequencyInterval')" -eq 'everyTime') { 'every time' } else { '{0} {1}' -f (Get-OptionalValue $sif 'value'), (Get-OptionalValue $sif 'type') }) } else { '' })
            IsBlock = ($controls -contains 'block')
            RequiresMfa = (($controls -contains 'mfa') -or [bool]$strId)
            PhishResistant = ($strId -eq '00000000-0000-0000-0000-000000000004') -or ($strCombos.Count -and -not @($strCombos | Where-Object { $phishCombos -notcontains $_ }).Count)
            OtherCond = $(if ($null -ne $c) { $cc = ConvertTo-Canon $c; $other = [ordered]@{}; if ($cc) { foreach ($ck in @($cc.Keys)) { if ($ck -notin $handledConditions) { $other[$ck] = $cc[$ck] } } }; if ($other.Count) { $other | ConvertTo-Json -Depth 30 -Compress } else { '' } } else { '' })
            CondCanon = Get-CanonText $c; GrantCanon = Get-CanonText $g; SessionCanon = Get-CanonText $s
            Hash = $(if ($csv) { [string]$csv.PolicyHash } else { '' })
        }
    }
    $policies = @($policies | Sort-Object Name)
    Write-RunLog ("Policies: {0} ({1} enabled, {2} report-only, {3} disabled)" -f $policies.Count, @($policies | Where-Object State -eq 'enabled').Count, @($policies | Where-Object State -eq 'enabledForReportingButNotEnforced').Count, @($policies | Where-Object State -eq 'disabled').Count)
    $enabled = @($policies | Where-Object State -eq 'enabled')
    $active = @($policies | Where-Object { $_.State -ne 'disabled' })
    # Built-in Tier 0 role template IDs: the same list as the Entra scripts' $script:Tier0RoleTemplates.
    $tier0Roles = @(
        '62e90394-69f5-4237-9190-012177145e10',  # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814',  # Privileged Role Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13',  # Privileged Authentication Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d',  # Security Administrator
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',  # Application Administrator
        '158c047a-c907-4556-b7ef-446551a6b5f7',  # Cloud Application Administrator
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',  # Conditional Access Administrator
        '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2',  # Hybrid Identity Administrator
        'c4e39bd9-1100-46d3-8c65-fb160da0071f',  # Authentication Administrator
        'fe930be7-5e62-47db-91af-98c3a49a38b1',  # User Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de',  # Exchange Administrator
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',  # SharePoint Administrator
        '3a2c62db-5318-420d-8d74-23affee5d9d5',  # Intune Administrator
        '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e'   # Identity Governance Administrator
    )
    function Test-IsBreakGlass { param([string]$Id) if ($bgIds.ContainsKey($Id)) { return $true }; if ($bgUpns.Count) { $n = (Get-Name $Id).ToLowerInvariant() -replace '\s*\(user\)$', ''; return ($bgUpns -contains $n) }; return $false }
    # Break-glass accounts as objects: object ID (when known) and UPN. A -BreakGlassUpns entry that no policy refers to has no ID here,
    # which is itself the finding for every policy that targets All users.
    $bgAccounts = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $bgIds.Keys) { $bgAccounts.Add([pscustomobject]@{ Id = $id; Upn = "$($bgIds[$id])".ToLowerInvariant(); Label = $bgIds[$id] }) }
    foreach ($u in $bgUpns) {
        if (@($bgAccounts | Where-Object { $_.Upn -eq $u }).Count) { continue }
        $hit = @($names.Keys | Where-Object { ((Get-Name $_).ToLowerInvariant() -replace '\s*\(user\)$', '') -eq $u }) | Select-Object -First 1
        $bgAccounts.Add([pscustomobject]@{ Id = $(if ($hit) { [string]$hit } else { '' }); Upn = $u; Label = $u })
    }
    $bgUnreferenced = @($bgAccounts | Where-Object { -not $_.Id } | ForEach-Object { $_.Upn })

    # ---- 3. Issues ----
    $issues = [System.Collections.Generic.List[object]]::new()
    $sevRank = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    function Add-Issue { param([string]$Category, [string]$Severity, [string]$Code, $Policies, [string]$Detail, [string]$Recommendation, [string]$Reference = '')
        $ps = @($Policies | Where-Object { $_ })
        $issues.Add([pscustomobject][ordered]@{ IssueId = ''; Category = $Category; Severity = $Severity; Code = $Code
                Policies = Join-Values ($ps | ForEach-Object { $_.Name }); PolicyIds = Join-Values ($ps | ForEach-Object { $_.Id }); PolicyStates = Join-Values ($ps | ForEach-Object { $_.State })
                Detail = $Detail; Recommendation = $Recommendation; Reference = $Reference }) }

    # 3a. Tenant checks
    $checks = [System.Collections.Generic.List[object]]::new()
    $gapCodes = @{ 'MFA required for all users and all apps' = 'NoMfaForAllUsers'; 'Legacy authentication blocked' = 'LegacyAuthNotBlocked'; 'MFA required for Tier 0 admin roles' = 'NoAdminMfa'
        'Phishing-resistant MFA for Tier 0 admin roles' = 'NoPhishResistantAdminMfa'; 'Device code flow blocked' = 'DeviceCodeFlowNotBlocked'; 'High user risk blocked or remediated' = 'NoUserRiskPolicy'
        'High sign-in risk blocked or challenged' = 'NoSignInRiskPolicy'; 'Security info registration protected' = 'SecurityInfoRegistrationUnprotected'; 'MFA required for guests and external users' = 'NoGuestMfa' }
    function Add-Check { param([string]$Check, [string]$Reference, $Satisfying, $ReportOnly, [string]$GapSeverity, [string]$Recommendation, [string]$NotAssessedReason = '')
        $sat = @($Satisfying | Where-Object { $_ }); $ro = @($ReportOnly | Where-Object { $_ })
        $result = $(if ($NotAssessedReason) { 'NotAssessed' } elseif ($sat.Count) { 'Pass' } elseif ($ro.Count) { 'ReportOnlyOnly' } else { 'Gap' })
        $checks.Add([pscustomobject][ordered]@{ Check = $Check; Reference = $Reference; Result = $result; SatisfiedBy = Join-Values ($sat | ForEach-Object { $_.Name }); ReportOnlyCandidates = Join-Values ($ro | ForEach-Object { $_.Name }); Note = $(if ($NotAssessedReason) { $NotAssessedReason } else { $Recommendation }) })
        if ($result -in @('Gap', 'ReportOnlyOnly')) { Add-Issue -Category 'Gap' -Severity $GapSeverity -Code $gapCodes[$Check] -Policies $ro -Detail $(if ($result -eq 'ReportOnlyOnly') { "${Check}: only in report-only policies" } else { "${Check}: no enabled policy" }) -Recommendation $Recommendation -Reference $Reference } }
    $q = { param($Set, $Filter) @($Set | Where-Object $Filter) }
    $isMfaBase = { $_.RequiresMfa -and (Test-AllUsersAllApps $_) }
    Add-Check 'MFA required for all users and all apps' 'CISA MS.AAD.3.2' (& $q $enabled $isMfaBase) (& $q ($active | Where-Object State -ne 'enabled') $isMfaBase) 'High' 'Enable one policy requiring MFA (or an authentication strength) for All users and All cloud apps, excluding only break-glass accounts'
    $isLegacy = { $_.IsBlock -and $_.IncUsers -contains 'All' -and $_.IncApps -contains 'All' -and ($_.ClientApps -contains 'exchangeActiveSync') -and ($_.ClientApps -contains 'other') }
    Add-Check 'Legacy authentication blocked' 'CISA MS.AAD.1.1' (& $q $enabled $isLegacy) (& $q ($active | Where-Object State -ne 'enabled') $isLegacy) 'High' 'Block client app types Exchange ActiveSync and Other clients for All users and All cloud apps'
    $coversAdmins = { $_.IncUsers -contains 'All' -or @($_.IncRoles | Where-Object { $tier0Roles -contains $_ }).Count }
    $isAdminMfa = { $_.RequiresMfa -and (& $coversAdmins) -and $_.IncApps -contains 'All' -and -not @($_.ExcRoles | Where-Object { $tier0Roles -contains $_ }).Count }
    Add-Check 'MFA required for Tier 0 admin roles' 'CISA MS.AAD.3.2 and 3.6' (& $q $enabled $isAdminMfa) (& $q ($active | Where-Object State -ne 'enabled') $isAdminMfa) 'High' 'Require MFA for admin roles (Global Administrator and the other Tier 0 roles), All cloud apps'
    $isAdminPhish = { $_.PhishResistant -and (& $coversAdmins) -and -not @($_.ExcRoles | Where-Object { $tier0Roles -contains $_ }).Count }
    Add-Check 'Phishing-resistant MFA for Tier 0 admin roles' 'CISA MS.AAD.3.6' (& $q $enabled $isAdminPhish) (& $q ($active | Where-Object State -ne 'enabled') $isAdminPhish) 'Medium' 'Require the Phishing-resistant MFA authentication strength for Tier 0 roles, after admins have registered a phishing-resistant method'
    $isDcf = { $_.IsBlock -and $_.AuthFlows -match 'deviceCodeFlow' }
    Add-Check 'Device code flow blocked' 'CISA MS.AAD.3.9' (& $q $enabled $isDcf) (& $q ($active | Where-Object State -ne 'enabled') $isDcf) 'Medium' 'Block the device code authentication flow for all users, with exceptions only for documented device scenarios'
    $isUr = { $_.UserRisk -contains 'high' -and ($_.IsBlock -or $_.Controls -contains 'passwordChange' -or $_.RequiresMfa) }
    Add-Check 'High user risk blocked or remediated' 'CISA MS.AAD.2.1' (& $q $enabled $isUr) (& $q ($active | Where-Object State -ne 'enabled') $isUr) 'Medium' 'Block or require a secure password change for high user risk (needs Entra ID P2)'
    $isSr = { $_.SignInRisk -contains 'high' -and ($_.IsBlock -or $_.RequiresMfa) }
    Add-Check 'High sign-in risk blocked or challenged' 'CISA MS.AAD.2.3' (& $q $enabled $isSr) (& $q ($active | Where-Object State -ne 'enabled') $isSr) 'Medium' 'Block or require MFA for high sign-in risk (needs Entra ID P2)'
    $isReg = { $_.UserActions -contains 'urn:user:registersecurityinfo' -and $_.Controls.Count }
    Add-Check 'Security info registration protected' 'CISA MS.AAD.3.8' (& $q $enabled $isReg) (& $q ($active | Where-Object State -ne 'enabled') $isReg) 'Low' 'Protect the Register security information user action (trusted location, compliant device or Temporary Access Pass)'
    $isGuestMfa = { $_.RequiresMfa -and $_.IncApps -contains 'All' -and (($_.IncUsers -contains 'All' -and -not $_.ExcGuests) -or $_.IncGuests -or $_.IncUsers -contains 'GuestsOrExternalUsers') }
    Add-Check 'MFA required for guests and external users' 'Zero Trust identity' (& $q $enabled $isGuestMfa) (& $q ($active | Where-Object State -ne 'enabled') $isGuestMfa) 'Medium' 'Make sure guests and external users are covered by an MFA policy (the all-users baseline, or a guest policy)'
    $sdEnabled = $(if ($sd.Ok -and $sd.Data) { [bool](Get-OptionalValue $sd.Data 'isEnabled') } else { $null })
    if ($sdEnabled -and $enabled.Count) { Add-Issue 'Hygiene' 'Low' 'SecurityDefaultsWithCa' @() 'Security defaults are enabled while Conditional Access policies are also enabled' 'Turn security defaults off once the Conditional Access baseline covers MFA and legacy authentication' }
    $checks.Add([pscustomobject][ordered]@{ Check = 'Security defaults off while Conditional Access is used'; Reference = 'Microsoft guidance'; Result = $(if ($null -eq $sdEnabled) { 'NotAssessed' } elseif ($sdEnabled -and $enabled.Count) { 'Gap' } else { 'Pass' }); SatisfiedBy = ''; ReportOnlyCandidates = ''; Note = $(if ($null -eq $sdEnabled) { "security-defaults.json not usable: $($sd.Status)" } else { "Security defaults enabled: $sdEnabled" }) })

    # 3b. Per policy
    $deps = [System.Collections.Generic.List[object]]::new()
    $bgCheck = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $policies) {
        $live = ($p.State -ne 'disabled')
        # Dependencies
        $refs = @(
            foreach ($i in $p.IncUsers) { if ($i -notin @('All', 'None', 'GuestsOrExternalUsers')) { @{ U = 'Include'; T = 'User'; Id = $i } } }
            foreach ($i in $p.ExcUsers) { if ($i -notin @('All', 'None', 'GuestsOrExternalUsers')) { @{ U = 'Exclude'; T = 'User'; Id = $i } } }
            foreach ($i in $p.IncGroups) { @{ U = 'Include'; T = 'Group'; Id = $i } }
            foreach ($i in $p.ExcGroups) { @{ U = 'Exclude'; T = 'Group'; Id = $i } }
            foreach ($i in $p.IncRoles) { @{ U = 'Include'; T = 'Role'; Id = $i } }
            foreach ($i in $p.ExcRoles) { @{ U = 'Exclude'; T = 'Role'; Id = $i } }
            foreach ($i in $p.IncApps) { if ($i -notin @('All', 'None', 'Office365', 'MicrosoftAdminPortals')) { @{ U = 'Include'; T = 'Application'; Id = $i } } }
            foreach ($i in $p.ExcApps) { if ($i -notin @('All', 'None', 'Office365', 'MicrosoftAdminPortals')) { @{ U = 'Exclude'; T = 'Application'; Id = $i } } }
            foreach ($i in $p.IncLoc) { if ($i -notin @('All', 'AllTrusted')) { @{ U = 'Include'; T = 'NamedLocation'; Id = $i } } }
            foreach ($i in $p.ExcLoc) { if ($i -notin @('All', 'AllTrusted')) { @{ U = 'Exclude'; T = 'NamedLocation'; Id = $i } } }
            if ($p.StrengthId) { @{ U = 'Grant'; T = 'AuthenticationStrength'; Id = $p.StrengthId } }
            foreach ($i in $p.TermsOfUse) { @{ U = 'Grant'; T = 'TermsOfUse'; Id = $i } }
            foreach ($i in $p.AuthCtx) { @{ U = 'Include'; T = 'AuthenticationContext'; Id = $i } }
        )
        $deleted = @()
        foreach ($r in $refs) {
            $name = Get-Name $r.Id
            $resolved = $(if ($r.T -eq 'NamedLocation') { $(if ($nl.Ok) { $locById.ContainsKey($r.Id) } else { '' }) }
                elseif ($r.T -eq 'AuthenticationStrength') { $(if ($as.Ok) { $strById.ContainsKey($r.Id) -or [bool]$p.StrengthName -and $p.StrengthName -ne $r.Id } else { '' }) }
                elseif ($r.T -in @('TermsOfUse', 'AuthenticationContext')) { '' }
                elseif (-not $pc.Ok) { '' }
                else { $name -notmatch '\(unresolved' })
            $detail = $(switch ($r.T) {
                    'NamedLocation' { if ($locById.ContainsKey($r.Id)) { $l = $locById[$r.Id]; '{0}; trusted: {1}' -f $l.LocationType, $l.IsTrusted } }
                    'AuthenticationStrength' { if ($strById.ContainsKey($r.Id)) { 'Allowed: ' + $strById[$r.Id].AllowedCombinations } }
                    'Group' { if ($r.U -eq 'Exclude' -and $groupMembers.ContainsKey($r.Id)) { '{0} members (from 01)' -f $groupMembers[$r.Id].Count } elseif ($r.U -eq 'Exclude' -and $gm.Ok) { 'members not listed in 01' } }
                    'User' { if (Test-IsBreakGlass $r.Id) { 'Break-glass account' } }
                    default { '' }
                })
            $deps.Add([pscustomobject][ordered]@{ PolicyName = $p.Name; PolicyState = $p.State; Usage = $r.U; ObjectType = $r.T; ObjectId = $r.Id; ObjectName = $(if ($r.T -eq 'AuthenticationStrength' -and $p.StrengthName) { $p.StrengthName } else { $name }); Resolved = $resolved; Detail = $detail })
            if ($resolved -eq $false) { $deleted += ('{0} {1} {2}' -f $r.U, $r.T, $r.Id) }
        }
        if ($deleted.Count -and $live) { Add-Issue 'Hygiene' 'Medium' 'DeletedReference' @($p) ('References objects that no longer exist: ' + ($deleted -join '; ')) 'Remove the stale references. A deleted excluded group is usually an old exception nobody cleaned up; confirm nothing else depended on it' 'Maester MT.1038' }

        # Same object included and excluded
        $both = @()
        foreach ($pair in @(@('IncUsers', 'ExcUsers'), @('IncGroups', 'ExcGroups'), @('IncRoles', 'ExcRoles'), @('IncApps', 'ExcApps'), @('IncLoc', 'ExcLoc'), @('IncPlat', 'ExcPlat'))) {
            foreach ($x in @($p.($pair[0]) | Where-Object { @($p.($pair[1])) -contains $_ })) { $both += (Get-Name $x) }
        }
        if ($both.Count -and $live) { Add-Issue 'Conflict' 'Medium' 'IncludeExcludeSameObject' @($p) ('Included and excluded at once (exclude wins): ' + ($both -join '; ')) 'Remove the include or the exclude so the intent is clear' }

        # Age in state
        $mod = $(if ($p.Modified) { $p.Modified } else { $p.Created })
        $age = $(if ($mod) { [int]($now - $mod).TotalDays } else { $null })
        if ($p.State -eq 'enabledForReportingButNotEnforced' -and $null -ne $age -and $age -gt $ReportOnlyMaxDays) { Add-Issue 'Hygiene' 'Low' 'ReportOnlyStale' @($p) "Report-only and not modified for $age days" 'Review the report-only results (script 24) and enable it through change control, or remove it' }
        if ($p.State -eq 'disabled' -and $null -ne $age -and $age -gt $DisabledMaxDays) { Add-Issue 'Hygiene' 'Info' 'DisabledStale' @($p) "Disabled and not modified for $age days" 'Delete it after taking a snapshot (script 28), or document why it is kept' }
        if ($live -and -not $p.Controls.Count -and -not $p.StrengthId -and -not $p.TermsOfUse.Count -and -not $p.SessionCanon) { Add-Issue 'Hygiene' 'Low' 'NoControls' @($p) 'No grant or session control: the policy does nothing' 'Add the intended control or remove the policy' }

        # Trusted-location MFA bypass and app exclusions on a baseline
        if ($live -and $p.RequiresMfa) {
            $trustedEx = @($p.ExcLoc | Where-Object { $_ -eq 'AllTrusted' -or ($locById.ContainsKey($_) -and (Test-True $locById[$_].IsTrusted)) })
            if ($trustedEx.Count) { Add-Issue 'Exclusion' 'Medium' 'TrustedLocationBypass' @($p) ('MFA is skipped from: ' + (($trustedEx | ForEach-Object { if ($_ -eq 'AllTrusted') { 'All trusted locations' } else { Get-Name $_ } }) -join '; ')) 'Do not exempt network locations from MFA; use device compliance or phishing-resistant methods to reduce prompts instead' 'Zero Trust: verify explicitly' }
            if ((Test-AllUsersAllApps $p) -and $p.ExcApps.Count) { Add-Issue 'Exclusion' 'Low' 'BaselineExcludesApps' @($p) ('MFA baseline excludes apps: ' + (($p.ExcApps | ForEach-Object { Get-Name $_ }) -join '; ')) 'Confirm each app exclusion is documented in the exception register with a compensating control' }
        }

        # Broad excluded groups
        if ($live -and ($p.RequiresMfa -or $p.IsBlock)) {
            foreach ($gid in $p.ExcGroups) {
                if ($groupMembers.ContainsKey($gid) -and $groupMembers[$gid].Count -gt $BroadExclusionThreshold) { Add-Issue 'Exclusion' 'Medium' 'BroadExclusion' @($p) ('Excluded group {0} has {1} members (threshold {2})' -f (Get-Name $gid), $groupMembers[$gid].Count, $BroadExclusionThreshold) 'Reduce the group to named, approved exceptions with an expiry, or replace it with a narrower policy' 'Maester MT.1036' }
            }
        }

        # Break-glass exclusion (enabled policies with any grant control can lock them out)
        if ($p.State -eq 'enabled' -and ($p.Controls.Count -or $p.StrengthId -or $p.TermsOfUse.Count)) {
            foreach ($bg in $bgAccounts) {
                $targetsAll = ($p.IncUsers -contains 'All')
                $directInc = ($bg.Id -and $p.IncUsers -contains $bg.Id)
                $byGroupOrRole = [bool]($p.IncGroups.Count -or $p.IncRoles.Count)
                if (-not ($targetsAll -or $directInc -or $byGroupOrRole)) { continue }
                $direct = ($bg.Id -and $p.ExcUsers -contains $bg.Id)
                $viaGroup = @($p.ExcGroups | Where-Object { $groupMembers.ContainsKey($_) -and @($groupMembers[$_] | Where-Object { ($bg.Id -and "$($_.MemberId)" -eq $bg.Id) -or ($bg.Upn -and "$($_.MemberUPN)" -eq $bg.Upn) }).Count })
                $unexpanded = @($p.ExcGroups | Where-Object { -not $groupMembers.ContainsKey($_) })
                $state = $(if ($direct) { 'Excluded (user)' }
                    elseif ($viaGroup.Count) { 'Excluded (group: ' + (($viaGroup | ForEach-Object { Get-Name $_ }) -join '; ') + ')' }
                    elseif ($unexpanded.Count -and -not $gm.Ok) { 'Unverified (excluded groups not expanded: run 01)' }
                    elseif (-not $targetsAll -and -not $directInc) { 'Unverified (policy targets groups or roles; membership not known offline)' }
                    else { 'NotExcluded' })
                $bgCheck.Add([pscustomobject]@{ Policy = $p; Account = $bg.Label; State = $state })
                if ($state -eq 'NotExcluded') { Add-Issue 'Exclusion' 'High' 'BreakGlassNotExcluded' @($p) ("Break-glass account {0} is not excluded{1}" -f $bg.Label, $(if (-not $bg.Id) { ' (the UPN is not referenced by any policy; check it is spelled as in Entra)' } else { '' })) 'Exclude every break-glass account from every policy (directly or through one dedicated group), and alert on their sign-ins' 'Maester MT.1005' }
            }
        }
    }
    $bgKnown = ($bgIds.Count -or $bgUpns.Count)
    $bgFail = @($bgCheck | Where-Object { $_.State -eq 'NotExcluded' })
    $checks.Add([pscustomobject][ordered]@{ Check = 'Break-glass accounts excluded from every enabled policy'; Reference = 'Maester MT.1005'
            Result = $(if (-not $bgKnown) { 'NotAssessed' } elseif ($bgFail.Count) { 'Gap' } elseif (@($bgCheck | Where-Object { $_.State -like 'Unverified*' }).Count) { 'Partial' } else { 'Pass' })
            SatisfiedBy = ''; ReportOnlyCandidates = ''
            Note = $(if (-not $bgKnown) { 'No break-glass accounts known: run 27 with -BreakGlassUpns, or pass -BreakGlassUpns here' } else { ('{0} policy checks, {1} not excluded, {2} unverified' -f $bgCheck.Count, $bgFail.Count, @($bgCheck | Where-Object { $_.State -like 'Unverified*' }).Count) + $(if ($bgUnreferenced.Count) { '; not referenced by any policy: ' + ($bgUnreferenced -join ', ') } else { '' }) }) })

    # 3c. Exclusions without a fallback policy (enabled MFA or block policies). A fallback must be of the same kind,
    # include the excluded object without excluding it, and apply to every sign-in the excluding policy applies to.
    foreach ($p in @($enabled | Where-Object { $_.RequiresMfa -or $_.IsBlock })) {
        $kind = $(if ($p.IsBlock) { 'block' } else { 'MFA' })
        foreach ($t in @(@('User', 'ExcUsers', 'IncUsers'), @('Group', 'ExcGroups', 'IncGroups'), @('Role', 'ExcRoles', 'IncRoles'))) {
            foreach ($x in @($p.($t[1]))) {
                if ($t[0] -eq 'User' -and (Test-IsBreakGlass $x)) { continue }
                if ($t[0] -eq 'User' -and @($bgAccounts | Where-Object { $_.Id -eq $x }).Count) { continue }
                if ($t[0] -eq 'Group' -and $groupMembers.ContainsKey($x) -and $groupMembers[$x].Count -and $bgAccounts.Count) {
                    $nonBg = @($groupMembers[$x] | Where-Object { $m = $_; -not @($bgAccounts | Where-Object { ($_.Id -and "$($m.MemberId)" -eq $_.Id) -or ($_.Upn -and "$($m.MemberUPN)" -eq $_.Upn) }).Count })
                    if (-not $nonBg.Count) { continue }   # a dedicated break-glass group: expected
                }
                $fallback = @($enabled | Where-Object {
                        $_.Id -ne $p.Id -and $(if ($p.IsBlock) { $_.IsBlock } else { $_.RequiresMfa }) -and
                        ($_.IncUsers -contains 'All' -or @($_.($t[2])) -contains $x) -and @($_.($t[1])) -notcontains $x -and
                        (Test-ConditionsCover $_ $p) })
                if (-not $fallback.Count) { Add-Issue 'Exclusion' 'Medium' 'ExclusionNoFallback' @($p) ('{0} {1} is excluded and no other enabled {2} policy covers it for the same sign-ins' -f $t[0], (Get-Name $x), $kind) 'Cover the excluded object with a fallback policy (for example MFA from a compliant device only), or record it in the exception register with an expiry' 'Maester MT.1036' }
            }
        }
    }

    # 3d. Pairs: duplicates, redundancy, block shadowing, same scope with different controls
    $pairDone = @{}
    for ($i = 0; $i -lt $active.Count; $i++) {
        for ($j = 0; $j -lt $active.Count; $j++) {
            if ($i -eq $j) { continue }
            $A = $active[$i]; $B = $active[$j]
            $pk = (@($A.Id, $B.Id) | Sort-Object) -join '|'
            $sameCond = ($A.CondCanon -eq $B.CondCanon)
            if ($sameCond -and $i -lt $j) {
                if ($A.GrantCanon -eq $B.GrantCanon -and $A.SessionCanon -eq $B.SessionCanon) {
                    if ($A.State -eq $B.State) { Add-Issue 'Overlap' 'Low' 'Duplicate' @($A, $B) 'Same conditions, grant and session controls' 'Keep one; delete the other after a snapshot' }
                    else { Add-Issue 'Overlap' 'Info' 'ReportOnlyCopy' @($A, $B) 'A report-only copy of an enabled policy with the same configuration' 'Delete the report-only copy once the change it was testing is complete' }
                }
                elseif ($A.State -eq 'enabled' -and $B.State -eq 'enabled') {
                    Add-Issue 'Overlap' 'Info' 'SameScopeDifferentControls' @($A, $B) 'Same conditions with different controls; both apply and every grant must be met' 'Consider merging into one policy so the requirement is in one place'
                    if ($A.SignInFrequency -and $B.SignInFrequency -and $A.SignInFrequency -ne $B.SignInFrequency) { Add-Issue 'Conflict' 'Low' 'SessionFrequencyConflict' @($A, $B) ('Sign-in frequency {0} vs {1} for the same sign-ins (the stricter wins)' -f $A.SignInFrequency, $B.SignInFrequency) 'Keep one sign-in frequency per scope' }
                }
                $pairDone[$pk] = $true
                continue
            }
            if ($pairDone.ContainsKey($pk) -or $A.State -ne 'enabled' -or $B.State -ne 'enabled') { continue }
            if (-not (Test-Covers $A $B)) { continue }
            if ($A.IsBlock -and -not $B.IsBlock) { Add-Issue 'Conflict' 'High' 'BlockShadowsPolicy' @($A, $B) ("'{0}' blocks every sign-in '{1}' applies to, so '{1}' can never grant access" -f $A.Name, $B.Name) 'Narrow the block policy, or remove the shadowed policy' }
            elseif (-not $A.IsBlock -and -not $B.IsBlock -and $A.GrantCanon -eq $B.GrantCanon -and (-not $B.SessionCanon -or $B.SessionCanon -eq $A.SessionCanon)) { Add-Issue 'Overlap' 'Low' 'RedundantPolicy' @($B, $A) ("'{0}' requires the same controls for a subset of the sign-ins '{1}' already covers" -f $B.Name, $A.Name) "Remove '$($B.Name)' or fold its intent into '$($A.Name)'" }
        }
    }

    # Number the issues
    $issues = @($issues | Sort-Object @{ Expression = { $sevRank[$_.Severity] } }, Category, Code, Policies)
    for ($k = 0; $k -lt $issues.Count; $k++) { $issues[$k].IssueId = 'CA-{0:D3}' -f ($k + 1) }

    # ---- 4. Inventory ----
    function Get-NameList { param($Ids) return Join-Values (@($Ids) | ForEach-Object { Get-Name $_ }) }
    $inventory = foreach ($p in $policies) {
        $mine = @($issues | Where-Object { (Split-List $_.PolicyIds) -contains $p.Id })
        $purpose = $(if ($p.IsBlock -and ($p.ClientApps -contains 'exchangeActiveSync' -or $p.ClientApps -contains 'other')) { 'Block legacy authentication' }
            elseif ($p.IsBlock -and $p.AuthFlows) { 'Block authentication flows' }
            elseif ($p.SignInRisk.Count -or $p.UserRisk.Count) { 'Risk-based' }
            elseif ($p.UserActions.Count) { 'User action (security info / device registration)' }
            elseif ($p.IsBlock) { 'Block' }
            elseif ($p.PhishResistant) { 'Phishing-resistant MFA' }
            elseif ($p.RequiresMfa -and (Test-AllUsersAllApps $p)) { 'MFA baseline (all users)' }
            elseif ($p.RequiresMfa -and $p.IncRoles.Count) { 'MFA for admin roles' }
            elseif ($p.RequiresMfa) { 'MFA (scoped)' }
            elseif ($p.Controls -contains 'compliantDevice' -or $p.Controls -contains 'domainJoinedDevice') { 'Device compliance' }
            elseif ($p.SessionCanon -and -not $p.Controls.Count) { 'Session control' }
            elseif ($p.TermsOfUse.Count) { 'Terms of use' }
            else { 'Other' })
        $users = @(
            $(if ($p.IncUsers.Count) { 'Users: ' + (Get-NameList $p.IncUsers) })
            $(if ($p.IncGroups.Count) { 'Groups: ' + (Get-NameList $p.IncGroups) })
            $(if ($p.IncRoles.Count) { 'Roles: ' + (Get-NameList $p.IncRoles) })
            $(if ($p.IncGuestText) { 'Guests: ' + $p.IncGuestText })
        ) | Where-Object { $_ }
        $apps = @(
            $(if ($p.IncApps.Count) { Get-NameList $p.IncApps })
            $(if ($p.UserActions.Count) { 'User actions: ' + (Join-Values $p.UserActions) })
            $(if ($p.AuthCtx.Count) { 'Auth contexts: ' + (Join-Values $p.AuthCtx) })
        ) | Where-Object { $_ }
        $conds = @(
            $(if ($p.ClientApps.Count -and $p.ClientApps -notcontains 'all') { 'Client apps: ' + (Join-Values $p.ClientApps) })
            $(if ($p.IncPlat.Count) { 'Platforms: ' + (Join-Values $p.IncPlat) })
            $(if ($p.IncLoc.Count) { 'Locations: ' + (Get-NameList $p.IncLoc) })
            $(if ($p.SignInRisk.Count) { 'Sign-in risk: ' + (Join-Values $p.SignInRisk) })
            $(if ($p.UserRisk.Count) { 'User risk: ' + (Join-Values $p.UserRisk) })
            $(if ($p.SpRisk.Count) { 'Service principal risk: ' + (Join-Values $p.SpRisk) })
            $(if ($p.DeviceFilter) { 'Device filter: ' + $p.DeviceFilter })
            $(if ($p.AuthFlows) { 'Authentication flows: ' + $p.AuthFlows })
        ) | Where-Object { $_ }
        $excl = @(
            $(if ($p.ExcUsers.Count) { 'Users: ' + (Get-NameList $p.ExcUsers) })
            $(if ($p.ExcGroups.Count) { 'Groups: ' + (Join-Values ($p.ExcGroups | ForEach-Object { $(if ($groupMembers.ContainsKey($_)) { '{0} ({1} members)' -f (Get-Name $_), $groupMembers[$_].Count } else { Get-Name $_ }) })) })
            $(if ($p.ExcRoles.Count) { 'Roles: ' + (Get-NameList $p.ExcRoles) })
            $(if ($p.ExcGuestText) { 'Guests: ' + $p.ExcGuestText })
            $(if ($p.ExcApps.Count) { 'Apps: ' + (Get-NameList $p.ExcApps) })
            $(if ($p.ExcLoc.Count) { 'Locations: ' + (($p.ExcLoc | ForEach-Object { if ($_ -eq 'AllTrusted') { 'All trusted locations' } else { Get-Name $_ } }) -join '; ') })
            $(if ($p.ExcPlat.Count) { 'Platforms: ' + (Join-Values $p.ExcPlat) })
        ) | Where-Object { $_ }
        $grant = @(
            $(if ($p.Controls.Count) { (Join-Values $p.Controls) + $(if ($p.Controls.Count -gt 1) { " ($($p.GrantOp))" } else { '' }) })
            $(if ($p.StrengthName) { 'Authentication strength: ' + $p.StrengthName })
            $(if ($p.TermsOfUse.Count) { 'Terms of use' })
        ) | Where-Object { $_ }
        $myDeps = @($deps | Where-Object { $_.PolicyName -eq $p.Name -and $_.PolicyState -eq $p.State })
        $depSummary = @($myDeps | Group-Object ObjectType | Sort-Object Name | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name })
        [pscustomobject][ordered]@{
            PolicyId = $p.Id; PolicyName = $p.Name; State = $p.State; ModifiedUtc = $(if ($p.Modified) { $p.Modified.ToString('yyyy-MM-ddTHH:mm:ssZ') } elseif ($p.Created) { $p.Created.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }); Purpose = $purpose
            ScopeUsers = ($users -join ' | '); ScopeApps = ($apps -join ' | '); ScopeConditions = ($conds -join ' | ')
            GrantControls = ($grant -join ' | '); SessionControls = $p.SessionText
            Exclusions = ($excl -join ' | '); ExclusionCount = ($p.ExcUsers.Count + $p.ExcGroups.Count + $p.ExcRoles.Count + $p.ExcApps.Count + $p.ExcLoc.Count + $(if ($p.ExcGuests) { 1 } else { 0 }))
            Dependencies = Join-Values $depSummary; DeletedDependencies = @($myDeps | Where-Object { $_.Resolved -eq $false }).Count
            IssueCount = $mine.Count; Issues = Join-Values ($mine | ForEach-Object { '{0} {1}' -f $_.IssueId, $_.Code })
            HighestSeverity = $(if ($mine.Count) { ($mine | Sort-Object { $sevRank[$_.Severity] } | Select-Object -First 1).Severity } else { '' })
            PolicyHash = $p.Hash
        }
    }
    $stOrder = @{ enabled = 0; enabledForReportingButNotEnforced = 1; disabled = 2 }
    $inventory = @($inventory | Sort-Object @{ Expression = { $stOrder["$($_.State)"] } }, PolicyName)
    $invNote = (@($statusNotes) + $(if (-not $gm.Ok) { 'excluded-group sizes and break-glass exclusion through groups not checked (no usable 01 run)' }) + $(if (-not $bgKnown) { 'break-glass not assessed: no break-glass accounts known' })) -join '; '
    $invStatus = Get-WorstStatus @($baseStatus, $(if (-not $gm.Ok -or -not $bgKnown) { 'Partial' }))
    Export-Dataset -Name 'ca-policy-inventory' -Rows $inventory -Status $invStatus -Note $invNote
    Export-Dataset -Name 'ca-policy-issues' -Rows $issues -Status $invStatus -Note ('Exact comparison of policy definitions, not a sign-in simulation. ' + $invNote)
    Export-Dataset -Name 'ca-policy-dependencies' -Rows $deps -Status $baseStatus -Note $(if ($pc.Ok) { 'Resolved = False: the object no longer exists (or could not be read when 28 ran)' } else { 'Resolved blank: names were not available' })
    Export-Dataset -Name 'ca-coverage-checks' -Rows $checks -Status $baseStatus -Note 'Pass = an enabled policy meets the check as written; ReportOnlyOnly = only a report-only policy does'
    Export-Dataset -Name 'source-runs' -Rows $script:SourceRows -Note 'Every source dataset read: run folder, source status and SHA-256 check against that run'

    # ---- 5. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Snapshot analysed' $(if ($run28) { Split-Path $run28 -Leaf } else { '' }) 'Script 28 run'
    Add-Metric 'Policies' $policies.Count ('{0} enabled, {1} report-only, {2} disabled' -f $enabled.Count, @($policies | Where-Object State -eq 'enabledForReportingButNotEnforced').Count, @($policies | Where-Object State -eq 'disabled').Count)
    foreach ($cat in @('Gap', 'Conflict', 'Overlap', 'Exclusion', 'Hygiene')) { Add-Metric "Issues: $cat" @($issues | Where-Object Category -eq $cat).Count (Join-Values (@($issues | Where-Object Category -eq $cat | Group-Object Code | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }))) }
    Add-Metric 'Issues: High severity' @($issues | Where-Object Severity -eq 'High').Count
    Add-Metric 'Coverage checks passed' @($checks | Where-Object Result -eq 'Pass').Count ('of {0}; gaps: {1}' -f $checks.Count, (Join-Values ($checks | Where-Object { $_.Result -in @('Gap', 'ReportOnlyOnly') } | ForEach-Object { $_.Check })))
    Add-Metric 'Deleted references' @($deps | Where-Object { $_.Resolved -eq $false }).Count
    Add-Metric 'Break-glass accounts checked' $(if ($bgKnown) { $bgAccounts.Count } else { '' }) $(if ($bgKnown) { '' } else { 'Not assessed' })
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName '' -Parameters @{ EvidenceRoot = $EvidenceRoot; SnapshotRunFolder = $SnapshotRunFolder; PopulationRunFolder = $PopulationRunFolder; MfaRunFolder = $MfaRunFolder; BreakGlassUpns = @($BreakGlassUpns).Count; ReportOnlyMaxDays = $ReportOnlyMaxDays; DisabledMaxDays = $DisabledMaxDays; BroadExclusionThreshold = $BroadExclusionThreshold; AllowHashMismatch = [bool]$AllowHashMismatch }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
