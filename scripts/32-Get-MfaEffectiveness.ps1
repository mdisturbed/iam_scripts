<#
.SYNOPSIS
    Read-only MFA effectiveness: for an agreed population, how many identities are protected by MFA,
    who is excluded and why, where MFA failed in practice, and which evidence each figure comes from.

.DESCRIPTION
    Joins earlier runs in the same evidence folder; connects to nothing:

      - 27-IdentityPopulation   identity-population, population-denominators, population-exclusions
                                (the agreed denominators; without a run of 27 the denominator falls back
                                to enabled member accounts and every measure is Partial)
      - 01-MfaCoverage          mfa-registration, ca-policies, ca-exclusions, ca-excluded-group-members,
                                ca-excluded-role-holders, signins-singlefactor-success,
                                signins-noninteractive-singlefactor (when 01 ran with -IncludeNonInteractive)
      - exception register      optional; approved exceptions mark Conditional Access exclusions as approved

    For each identity in a population it decides:
      - Registered   IsMfaRegistered in the registration report
      - Enforcement  Enforced: covered by at least one enabled baseline MFA policy and not excluded from it.
                     EnforcedWithConditions: only by baseline policies that leave something out (excluded
                     locations, apps, platforms or a device filter). Excluded: excluded from every baseline
                     policy. NotCovered: no enabled baseline policy exists. Unknown: policies not readable.
                     A baseline MFA policy is enabled, requires MFA (grant or authentication strength), and
                     targets All users, All cloud apps and every client app, with no risk condition and no
                     include-location or include-platform condition. -MfaPolicyNames overrides the detection.
      - MfaState     Protected (registered and enforced), EnforcedNotRegistered, RegisteredNotEnforced,
                     Excluded, Unprotected, NoRegistrationData, Unknown
      - Failures     successful single-factor sign-ins in 01's lookback window (interactive, and
                     non-interactive when collected), with the likely cause. Sign-ins by the token broker
                     and Windows logon (-TokenBrokerApps: Microsoft Authentication Broker, Windows Sign In)
                     are logged as single-factor with Conditional Access not applied because CA is not
                     evaluated when a Primary Refresh Token is issued or renewed; MFA was satisfied earlier
                     in the session. They are kept in mfa-failures with IsTokenBroker = True and reported
                     as a separate measure, so the failure count is shown with and without them.

    Datasets:
      - mfa-effectiveness-measures  one row per population and measure: value, denominator, percent,
                                    definition, source runs and status. This is the table to report
      - mfa-effectiveness           one row per identity in any population
      - mfa-exclusions              identities left out of a population (27) and identities excluded from a
                                    baseline MFA policy (by user, group, role or guest type), approved or not
      - mfa-failures                successful single-factor sign-ins of in-scope identities, with likely cause
      - mfa-baseline-policies       the policies counted as baseline, and every other MFA policy with the
                                    reason it is not baseline
      - source-runs                 every source dataset read: run folder, status, SHA-256 check

    READ-ONLY. Reads earlier run folders only; connects to nothing.

    Output: <OutputRoot>\32-MfaEffectiveness\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER EvidenceRoot
    Folder holding the earlier runs (NN-Name\yyyyMMdd-HHmmssZ). Defaults to -OutputRoot.

.PARAMETER MfaRunFolder
    Pin a run folder of script 01 instead of the latest one.

.PARAMETER PopulationRunFolder
    Pin a run folder of script 27 instead of the latest one.

.PARAMETER MfaPolicyNames
    Exact names of the policies to count as baseline MFA policies, instead of detecting them.

.PARAMETER MfaPolicyNamesFile
    Text file with one baseline policy name per line (blank lines and lines starting with # are ignored).
    Default: <parent of EvidenceRoot>\config\mfa-baseline-policies.txt, for the engagement layout
    IAM-Evidence\evidence + IAM-Evidence\config. Read when -MfaPolicyNames is not given and the file
    exists, so a rerun uses the same baseline without retyping it. -MfaPolicyNames wins over the file.

.PARAMETER SaveMfaPolicyNames
    Write the names given with -MfaPolicyNames to -MfaPolicyNamesFile (creating the config folder), so
    later runs pick them up without the parameter.

.PARAMETER ExceptionRegisterCsv
    Exception register (examples\exception-register.example.csv). Rows with Status Accepted or Approved,
    not expired, whose Identity or Scope names a user or excluded group mark that exclusion as approved.

.PARAMETER MaxRunSpreadDays
    When the 01 and 27 runs are further apart than this, measures are Partial (numerator and denominator
    from different points in time).

.PARAMETER TokenBrokerApps
    AppDisplayName values treated as token-broker / Windows sign-in (PRT) events: logged as single-factor
    with CA not applied by design, not MFA bypasses. Legacy-protocol sign-ins are never treated as broker
    events. Pass @() to count every single-factor sign-in as a failure.

.PARAMETER AllowHashMismatch
    Use a source file whose SHA-256 no longer matches its run (the result is Partial). Off by default:
    a changed file is Blocked.

.EXAMPLE
    .\32-Get-MfaEffectiveness.ps1 -OutputRoot D:\Evidence
.EXAMPLE
    .\32-Get-MfaEffectiveness.ps1 -OutputRoot D:\Evidence -ExceptionRegisterCsv D:\Engagement\registers\exception-register.csv
.EXAMPLE
    .\32-Get-MfaEffectiveness.ps1 -OutputRoot D:\Evidence -MfaPolicyNames 'Require MFA - all users', 'Require MFA - guests'
.EXAMPLE
    .\32-Get-MfaEffectiveness.ps1 -OutputRoot D:\Engagement\evidence -MfaPolicyNames 'Require MFA - all users' -SaveMfaPolicyNames
    Later runs: .\32-Get-MfaEffectiveness.ps1 -OutputRoot D:\Engagement\evidence  (reads D:\Engagement\config\mfa-baseline-policies.txt)

.NOTES
    Version : 1.3.0
    Requires: PowerShell 5.1 or 7.x. Earlier runs of 01 and (for an agreed denominator) 27 in the evidence folder.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$EvidenceRoot = '',
    [string]$MfaRunFolder = '',
    [string]$PopulationRunFolder = '',
    [string[]]$MfaPolicyNames = @(),
    [string]$MfaPolicyNamesFile = '',
    [switch]$SaveMfaPolicyNames,
    [string]$ExceptionRegisterCsv = '',
    [int]$MaxRunSpreadDays = 7,
    [string[]]$TokenBrokerApps = @('Microsoft Authentication Broker', 'Windows Sign In'),
    [switch]$AllowHashMismatch
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '32-MfaEffectiveness'
$ScriptVersion = '1.3.0'
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
function Test-TokenBrokerSignIn {
    # Token broker / Windows logon (PRT) sign-in: single-factor and CA not applied by design (CA is not evaluated on PRT issue or renewal).
    param($Row)
    if (-not $TokenBrokerApps.Count -or (Test-LegacySignIn $Row)) { return $false }
    return ($TokenBrokerApps -contains "$($Row.AppDisplayName)".Trim())
}

function Get-Percent { param($Part, $Whole) if ($null -eq $Whole -or "$Whole" -eq '' -or [int]$Whole -eq 0 -or "$Part" -eq '') { return '' } return [math]::Round(100.0 * [double]$Part / [double]$Whole, 1) }

function Get-BaselineVerdict {
    # Why a policy row from 01's ca-policies.csv is or is not a baseline MFA policy.
    param($P)
    if ("$($P.State)" -ne 'enabled') { return $(if ("$($P.State)" -eq 'enabledForReportingButNotEnforced') { 'Report-only (not enforced)' } else { "State $($P.State)" }) }
    if (-not (Test-True $P.RequiresMfa)) { return 'Does not require MFA' }
    if ((Split-List $P.IncludeUsers) -notcontains 'All') { return 'Not all users (scoped to users, groups or roles)' }
    if ((Split-List $P.IncludeApplications) -notcontains 'All') { return 'Not all cloud apps' }
    if ($P.UserActions) { return 'User action policy' }
    $clients = @(Split-List $P.ClientAppTypes)
    if ($clients.Count -and $clients -notcontains 'all' -and -not (($clients -contains 'browser') -and ($clients -contains 'mobileAppsAndDesktopClients'))) { return 'Limited client app types' }
    if ($P.SignInRiskLevels -or $P.UserRiskLevels) { return 'Risk-based condition' }
    $incLoc = @(Split-List $P.IncludeLocations)
    if ($incLoc.Count -and $incLoc -notcontains 'All') { return 'Limited to some locations' }
    $plat = @(Split-List $P.IncludePlatforms)
    if ($plat.Count -and $plat -notcontains 'all') { return 'Limited to some platforms' }
    return 'Baseline'
}

function Get-BaselineCondition {
    # What a baseline policy still leaves out (makes enforcement conditional).
    param($P)
    $c = @()
    if ($P.ExcludeLocations) { $c += 'excluded locations: ' + $(if ($P.ExcludeLocationNames) { $P.ExcludeLocationNames } else { $P.ExcludeLocations }) }
    if ($P.ExcludeApplications) { $c += "excluded apps: $($P.ExcludeApplications)" }
    if ($P.DeviceFilter) { $c += "device filter: $($P.DeviceFilter)" }
    if ($P.IncludeApplications -and (Split-List $P.IncludeApplications) -notcontains 'All') { $c += "only apps: $($P.IncludeApplications)" }
    if ($P.UserActions) { $c += "only user actions: $($P.UserActions)" }
    return ($c -join '; ')
}

function Test-LegacySignIn {
    # Interactive rows carry IsLegacyAuth; non-interactive rows only ClientAppUsed.
    param($Row)
    if ($Row.PSObject.Properties['IsLegacyAuth'] -and "$($Row.IsLegacyAuth)" -ne '') { return (Test-True $Row.IsLegacyAuth) }
    return ("$($Row.ClientAppUsed)" -and "$($Row.ClientAppUsed)" -notin @('Browser', 'Mobile Apps and Desktop clients'))
}

function Test-ExceptionApproved {
    # True when an accepted, unexpired exception names the identity or the excluding group / role.
    param([string[]]$Names)
    if (-not $ExceptionRegisterCsv) { return '' }
    foreach ($n in @($Names | Where-Object { $_ })) {
        $k = ($n -replace '\s*\((user|group|directoryRole)\)$', '').Trim().ToLowerInvariant()
        if ($script:Exceptions.ContainsKey($k)) { return $true }
    }
    return $false
}

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if (-not $EvidenceRoot) { $EvidenceRoot = $OutputRoot }
    if (-not (Test-Path -LiteralPath $EvidenceRoot)) { throw "Evidence folder not found: $EvidenceRoot" }
    $now = $script:RunStartUtc

    # Baseline policy names: -MfaPolicyNames, else the config file, else detection.
    if (-not $MfaPolicyNamesFile) { $MfaPolicyNamesFile = Join-Path (Join-Path (Split-Path -Path ([IO.Path]::GetFullPath($EvidenceRoot)) -Parent) 'config') 'mfa-baseline-policies.txt' }
    $policyNamesSource = 'Detected'
    if ($MfaPolicyNames.Count) {
        $MfaPolicyNames = @($MfaPolicyNames | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Select-Object -Unique)
        $policyNamesSource = '-MfaPolicyNames'
        if ($SaveMfaPolicyNames) {
            New-Item -ItemType Directory -Path (Split-Path $MfaPolicyNamesFile -Parent) -Force | Out-Null
            @("# Baseline MFA policies for script 32, one exact policy name per line. Saved $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) by 32 v$ScriptVersion.") + $MfaPolicyNames | Set-Content -Path $MfaPolicyNamesFile -Encoding UTF8
            Write-RunLog "Saved $($MfaPolicyNames.Count) baseline policy name(s) to $MfaPolicyNamesFile"
        }
    }
    elseif (Test-Path -LiteralPath $MfaPolicyNamesFile) {
        $MfaPolicyNames = @(Get-Content -LiteralPath $MfaPolicyNamesFile -Encoding UTF8 | ForEach-Object { "$_".Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } | Select-Object -Unique)
        $policyNamesSource = "File $(Split-Path $MfaPolicyNamesFile -Leaf)"
        Write-RunLog "Baseline policy names from $MfaPolicyNamesFile ($($MfaPolicyNames.Count))"
    }
    elseif ($SaveMfaPolicyNames) { Write-RunLog '-SaveMfaPolicyNames needs -MfaPolicyNames; nothing saved' 'WARN' }

    # ---- 1. Sources ----
    $run01 = Resolve-SourceRun -Number '01' -Pinned $MfaRunFolder
    $run27 = Resolve-SourceRun -Number '27' -Pinned $PopulationRunFolder
    Write-RunLog ("Script 01 run: {0}" -f $(if ($run01) { $run01 } else { 'none' }))
    Write-RunLog ("Script 27 run: {0}" -f $(if ($run27) { $run27 } else { 'none' }))

    $reg   = Read-SourceDataset -Script '01' -RunFolder $run01 -Dataset 'mfa-registration'
    $pol   = Read-SourceDataset -Script '01' -RunFolder $run01 -Dataset 'ca-policies'
    $exc   = Read-SourceDataset -Script '01' -RunFolder $run01 -Dataset 'ca-exclusions'
    $grp   = Read-SourceDataset -Script '01' -RunFolder $run01 -Dataset 'ca-excluded-group-members'
    $role  = Read-SourceDataset -Script '01' -RunFolder $run01 -Dataset 'ca-excluded-role-holders'
    $sf    = Read-SourceDataset -Script '01' -RunFolder $run01 -Dataset 'signins-singlefactor-success'
    $ni    = Read-SourceDataset -Script '01' -RunFolder $run01 -Dataset 'signins-noninteractive-singlefactor' -Optional
    $scope = Read-SourceDataset -Script '01' -RunFolder $run01 -Dataset 'ca-included-scope-members' -Optional
    $popId = Read-SourceDataset -Script '27' -RunFolder $run27 -Dataset 'identity-population'
    $popDn = Read-SourceDataset -Script '27' -RunFolder $run27 -Dataset 'population-denominators'
    $popEx = Read-SourceDataset -Script '27' -RunFolder $run27 -Dataset 'population-exclusions' -Optional

    if (-not $reg.Ok) { throw "MFA registration from script 01 is needed: $($reg.Note)" }

    # Denominator quality: agreed (27 with HR), naming rules only (27 without HR), or fallback (no 27).
    $denomMode = 'Fallback'
    $denomNotes = [System.Collections.Generic.List[string]]::new()
    if ($popId.Ok) {
        $hrRow = @($popDn.Rows | Where-Object { $_.Population -eq 'HR active workers' }) | Select-Object -First 1
        if ($hrRow -and $hrRow.Status -eq 'Completed') { $denomMode = 'Agreed' }
        else { $denomMode = 'NamingRules'; $denomNotes.Add('script 27 ran without an HR file, so the workforce is defined by naming rules only; rerun 27 with -HrCsvPath and the approved exclusions') }
    }
    else { $denomNotes.Add("no usable run of script 27 ($($popId.Status)): denominator is every enabled member account in the registration report, including service and shared accounts") }
    $spread = $null
    if ($run01 -and $run27) {
        $spread = [math]::Abs(((Get-RunStartUtc $run01) - (Get-RunStartUtc $run27)).TotalDays)
        if ($spread -gt $MaxRunSpreadDays) { $denomNotes.Add(('runs of 01 and 27 are {0:N1} days apart (more than {1}): numerator and denominator are from different points in time' -f $spread, $MaxRunSpreadDays)) }
    }
    $baseStatus = Get-WorstStatus @($reg.Status, $(if ($popId.Ok) { Get-WorstStatus @($popId.Status, $popDn.Status) } else { 'Partial' }))
    if ($denomMode -ne 'Agreed' -or ($spread -and $spread -gt $MaxRunSpreadDays)) { $baseStatus = Get-WorstStatus @($baseStatus, 'Partial') }

    # Exception register
    $script:Exceptions = @{}
    if ($ExceptionRegisterCsv) {
        if (-not (Test-Path -LiteralPath $ExceptionRegisterCsv)) { throw "Exception register not found: $ExceptionRegisterCsv" }
        foreach ($e in @(Import-Csv -LiteralPath $ExceptionRegisterCsv)) {
            if ("$($e.Status)" -notin @('Accepted', 'Approved')) { continue }
            if ($e.PSObject.Properties['Control'] -and "$($e.Control)" -and "$($e.Control)" -notmatch 'MFA|multi-?factor|authentication strength') { continue }
            $exp = $null
            if ($e.PSObject.Properties['ExpiresUtc'] -and "$($e.ExpiresUtc)") { $tmp = [datetime]::MinValue; if ([datetime]::TryParse("$($e.ExpiresUtc)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$tmp)) { $exp = $tmp } }
            if ($exp -and $exp -lt $now) { continue }
            foreach ($col in @('Identity', 'Scope')) {
                if (-not $e.PSObject.Properties[$col]) { continue }
                $v = ("$($e.$col)" -replace '^[^\\]+\\', '').Trim().ToLowerInvariant()
                if ($v) { $script:Exceptions[$v] = $e }
            }
        }
        Write-RunLog ("Exception register: {0} accepted, unexpired entries" -f $script:Exceptions.Count)
        $script:ManifestExtra = @{ ExceptionRegisterFile = (Split-Path $ExceptionRegisterCsv -Leaf); ExceptionRegisterSha256 = (Get-FileHash -LiteralPath $ExceptionRegisterCsv -Algorithm SHA256).Hash }
    }

    # ---- 2. Baseline MFA policies ----
    $policyRows = [System.Collections.Generic.List[object]]::new()
    $baseline = @()
    if ($pol.Ok) {
        foreach ($p in $pol.Rows) {
            $verdict = $(if ($MfaPolicyNames.Count) { if ($MfaPolicyNames -notcontains $p.PolicyName) { "Not named ($policyNamesSource)" } elseif ("$($p.State)" -ne 'enabled') { "Named ($policyNamesSource) but state is $($p.State)" } else { 'Baseline' } } else { Get-BaselineVerdict $p })
            if (-not (Test-True $p.RequiresMfa) -and $verdict -ne 'Baseline') { continue }
            $policyRows.Add([pscustomobject][ordered]@{
                    PolicyName = $p.PolicyName; State = $p.State; CountsAsBaseline = ($verdict -eq 'Baseline'); Reason = $(if ($verdict -eq 'Baseline') { $(if ($MfaPolicyNames.Count) { "Named ($policyNamesSource)" } else { 'Enabled, MFA, all users, all apps, all clients' }) } else { $verdict })
                    LeavesOut = $(if ($verdict -eq 'Baseline') { Get-BaselineCondition $p } else { '' })
                    IncludeUsers = $p.IncludeUsers; IncludeGroups = $p.IncludeGroups; IncludeRoles = $p.IncludeRoles; ExcludeUsers = $p.ExcludeUsers; ExcludeGroups = $p.ExcludeGroups; ExcludeRoles = $p.ExcludeRoles
                    IncludeApplications = $p.IncludeApplications; ExcludeApplications = $p.ExcludeApplications; GrantControls = $p.GrantControls; AuthStrength = $p.AuthStrength
                })
            if ($verdict -eq 'Baseline') { $baseline += $p }
        }
        foreach ($n in $MfaPolicyNames) { if (-not @($pol.Rows | Where-Object { $_.PolicyName -eq $n }).Count) { Write-RunLog "Baseline policy name ($policyNamesSource) not found in 01 ca-policies: $n" 'WARN' } }
        Write-RunLog ("Baseline MFA policies: {0} ({1})" -f $baseline.Count, (($baseline | ForEach-Object { $_.PolicyName }) -join '; '))
        if (-not $baseline.Count) { Write-RunLog ("NO baseline MFA policy ({0}): Protected and Enforced will be 0. Name the policies with -MfaPolicyNames, and add -SaveMfaPolicyNames to keep them in {1}" -f $policyNamesSource, $MfaPolicyNamesFile) 'WARN' }
    }
    Export-Dataset -Name 'mfa-baseline-policies' -Rows $policyRows -Status $(if ($pol.Ok) { $pol.Status } else { 'Blocked' }) -Note $(if ($pol.Ok) { 'CountsAsBaseline = True decides enforcement; other MFA policies are listed with the reason they do not count' } else { $pol.Note })

    # Exclusions per user id: policy name -> how
    $exclByUser = @{}
    function Add-UserExclusion { param([string]$UserId, [string]$Policy, [string]$Via, [string]$ViaName)
        if (-not $UserId) { return }
        if (-not $exclByUser.ContainsKey($UserId)) { $exclByUser[$UserId] = [System.Collections.Generic.List[object]]::new() }
        $exclByUser[$UserId].Add([pscustomobject]@{ Policy = $Policy; Via = $Via; ViaName = $ViaName }) }
    $baselineNames = @($baseline | ForEach-Object { $_.PolicyName })
    # Who each enabled baseline policy targets when it names users, groups or roles (01 1.2.0 and later)
    $scopeByPolicy = @{}
    if ($scope.Ok) {
        foreach ($s in @($scope.Rows | Where-Object { "$($_.PolicyState)" -eq 'enabled' -and $baselineNames -contains $_.PolicyName -and (Test-True $_.EffectiveForCa) })) {
            if (-not $scopeByPolicy.ContainsKey($s.PolicyName)) { $scopeByPolicy[$s.PolicyName] = @{} }
            if ($s.MemberId) { $scopeByPolicy[$s.PolicyName]["$($s.MemberId)"] = "$($s.IncludedVia): $($s.ScopeName)" }
        }
    }
    $guestExcludedFrom = @()
    $exclusionGaps = [System.Collections.Generic.List[string]]::new()
    if ($exc.Ok) {
        foreach ($x in @($exc.Rows | Where-Object { $baselineNames -contains $_.PolicyName -and "$($_.PolicyState)" -eq 'enabled' })) {
            switch ($x.ExclusionType) {
                'User' { Add-UserExclusion -UserId $x.ObjectId -Policy $x.PolicyName -Via 'User' -ViaName $x.DisplayName }
                'GuestOrExternal' { $guestExcludedFrom += [pscustomobject]@{ Policy = $x.PolicyName; Types = "$($x.DisplayName)" } }
            }
        }
    }
    elseif ($baseline.Count) { $exclusionGaps.Add("user exclusions unknown: $($exc.Note)") }
    if ($grp.Ok) {
        foreach ($m in $grp.Rows) {
            foreach ($pn in (Split-List $m.ExcludedFromPolicies)) { if ($baselineNames -contains $pn) { Add-UserExclusion -UserId $m.MemberId -Policy $pn -Via 'Group' -ViaName $m.GroupName } }
        }
        if ($grp.Status -eq 'Partial') { $exclusionGaps.Add("some excluded groups could not be expanded: $($grp.Note)") }
    }
    elseif ($baseline.Count) { $exclusionGaps.Add("group exclusions not expanded: $($grp.Note)") }
    if ($role.Ok) {
        foreach ($h in @($role.Rows | Where-Object { $baselineNames -contains $_.PolicyName -and "$($_.PolicyState)" -eq 'enabled' -and (Test-True $_.EffectiveForCa) })) { Add-UserExclusion -UserId $h.PrincipalId -Policy $h.PolicyName -Via 'Role' -ViaName $h.RoleName }
    }
    elseif ($baseline.Count) { $exclusionGaps.Add("role exclusions not resolved to accounts: $($role.Note)") }

    # Single-factor sign-ins per UPN
    $sfByUpn = @{}
    foreach ($src in @(@{ R = $sf; Kind = 'Interactive' }, @{ R = $ni; Kind = 'NonInteractive' })) {
        if (-not $src.R.Ok) { continue }
        foreach ($s in $src.R.Rows) {
            $k = "$($s.UserPrincipalName)".ToLowerInvariant()
            if (-not $k) { continue }
            if (-not $sfByUpn.ContainsKey($k)) { $sfByUpn[$k] = [System.Collections.Generic.List[object]]::new() }
            $sfByUpn[$k].Add([pscustomobject]@{ Kind = $src.Kind; Row = $s })
        }
    }

    # ---- 3. Populations ----
    $regById = @{}; $regByUpn = @{}
    foreach ($r in $reg.Rows) { if ($r.UserId) { $regById["$($r.UserId)"] = $r }; if ($r.UserPrincipalName) { $regByUpn["$($r.UserPrincipalName)".ToLowerInvariant()] = $r } }
    $members = [ordered]@{}   # key -> identity object
    function Add-PopulationMember { param([string]$Population, $Identity)
        $key = $(if ($Identity.UserId) { $Identity.UserId } else { "upn:$($Identity.Upn)".ToLowerInvariant() })
        if (-not $members.Contains($key)) { $members[$key] = $Identity; $Identity | Add-Member -NotePropertyName Populations -NotePropertyValue ([System.Collections.Generic.List[string]]::new()) }
        if (-not $members[$key].Populations.Contains($Population)) { $members[$key].Populations.Add($Population) } }
    function ConvertTo-IdentityRecord { param([string]$UserId, [string]$Upn, [string]$DisplayName, [string]$Category, [string]$HrId = '')
        [pscustomobject]@{ UserId = $UserId; Upn = $Upn; DisplayName = $DisplayName; Category = $Category; HrId = $HrId } }

    $popNames = [ordered]@{}
    if ($popId.Ok) {
        $popNames['Human workforce enabled (Entra)'] = 'Agreed workforce population from script 27 (enabled member accounts in the HumanWorkforce category, not on an approved exclusion' + $(if ($denomMode -eq 'Agreed') { ', matched to an active HR record)' } else { '; no HR file, naming rules only)' })
        $popNames['Admin accounts enabled (Entra)'] = 'Script 27 category AdminAccount, enabled in Entra'
        $popNames['Guests and external members enabled'] = 'Script 27 category Guest or ExternalMember, enabled in Entra'
        $popNames['Break-glass accounts'] = 'Script 27 category BreakGlass (expected to be excluded from MFA policies)'
        foreach ($i in $popId.Rows) {
            $id = "$($i.EntraObjectId)"
            if (-not $id -and -not $i.Upn) { continue }
            $o = ConvertTo-IdentityRecord -UserId $id -Upn $i.Upn -DisplayName $i.DisplayName -Category $i.Category -HrId $i.HrId
            if (Test-True $i.InHumanWorkforceEntra) { Add-PopulationMember 'Human workforce enabled (Entra)' $o }
            if (-not (Test-True $i.EntraEnabled)) { continue }
            if ($i.Category -eq 'AdminAccount') { Add-PopulationMember 'Admin accounts enabled (Entra)' $o }
            if ($i.Category -in @('Guest', 'ExternalMember')) { Add-PopulationMember 'Guests and external members enabled' $o }
            if ($i.Category -eq 'BreakGlass') { Add-PopulationMember 'Break-glass accounts' $o }
        }
    }
    else {
        $popNames['Enabled member accounts (fallback, not agreed)'] = 'Every enabled member account in the MFA registration report. Includes service, shared and test accounts: run script 27 for the agreed population'
        $popNames['Guests enabled'] = 'Every enabled guest in the MFA registration report'
        foreach ($r in $reg.Rows) {
            if ("$($r.AccountEnabled)" -eq 'False') { continue }
            $o = ConvertTo-IdentityRecord -UserId $r.UserId -Upn $r.UserPrincipalName -DisplayName '' -Category ''
            if ("$($r.UserType)" -eq 'guest' -or "$($r.UserType)" -eq 'Guest') { Add-PopulationMember 'Guests enabled' $o } else { Add-PopulationMember 'Enabled member accounts (fallback, not agreed)' $o }
        }
    }
    $popNames['Privileged accounts enabled (Entra roles)'] = 'Enabled accounts holding any Entra directory role (active, eligible or through a group) per script 01 IsPrivileged'
    $privKnown = @($reg.Rows | Where-Object { "$($_.IsPrivileged)" -ne '' }).Count -gt 0
    foreach ($r in @($reg.Rows | Where-Object { (Test-True $_.IsPrivileged) -and "$($_.AccountEnabled)" -ne 'False' })) {
        $o = ConvertTo-IdentityRecord -UserId $r.UserId -Upn $r.UserPrincipalName -DisplayName '' -Category ''
        Add-PopulationMember 'Privileged accounts enabled (Entra roles)' $o
    }

    # ---- 4. Per identity ----
    $rows = foreach ($key in $members.Keys) {
        $m = $members[$key]
        $r = $(if ($m.UserId -and $regById.ContainsKey("$($m.UserId)")) { $regById["$($m.UserId)"] } elseif ($m.Upn -and $regByUpn.ContainsKey("$($m.Upn)".ToLowerInvariant())) { $regByUpn["$($m.Upn)".ToLowerInvariant()] } else { $null })
        $uid = $(if ($m.UserId) { $m.UserId } elseif ($r) { $r.UserId } else { '' })
        $upn = $(if ($m.Upn) { $m.Upn } elseif ($r) { $r.UserPrincipalName } else { '' })
        $isGuest = ($m.Category -in @('Guest', 'ExternalMember')) -or ($r -and "$($r.UserType)" -match '^[Gg]uest$') -or ($upn -match '#EXT#')
        $excl = $(if ($uid -and $exclByUser.ContainsKey($uid)) { @($exclByUser[$uid]) } else { @() })
        $excludedFrom = @($excl | ForEach-Object { $_.Policy } | Sort-Object -Unique)
        # Guest-type exclusions apply only to the matching guest type (b2bCollaborationGuest / internalGuest for guests, b2bCollaborationMember for external members).
        $guestTypeHit = @()
        if ($isGuest) {
            $myTypes = $(if ($m.Category -eq 'ExternalMember') { @('b2bCollaborationMember') } else { @('b2bCollaborationGuest', 'internalGuest') })
            $guestTypeHit = @($guestExcludedFrom | Where-Object { $t = $_.Types; @($myTypes | Where-Object { $t -match $_ }).Count } | ForEach-Object { $_.Policy })
            if ($guestTypeHit.Count) { $excludedFrom = @(@($excludedFrom) + $guestTypeHit | Sort-Object -Unique) }
        }
        # A baseline policy covers this identity when it targets All users, or names the user directly; group or role targeting can't be resolved offline.
        $label = "$upn (user)"
        $applies = @($baseline | Where-Object {
                (Split-List $_.IncludeUsers) -contains 'All' -or ($upn -and (Split-List $_.IncludeUsers) -contains $label) -or
                ($uid -and $scopeByPolicy.ContainsKey($_.PolicyName) -and $scopeByPolicy[$_.PolicyName].ContainsKey("$uid")) })
        $covering = @($applies | Where-Object { $excludedFrom -notcontains $_.PolicyName })
        # Group or role targeting can only be resolved with 01's ca-included-scope-members; without it, Unknown.
        $maybe = @($baseline | Where-Object { $applies -notcontains $_ -and ($_.IncludeGroups -or $_.IncludeRoles) -and -not $scope.Ok -and $excludedFrom -notcontains $_.PolicyName })
        $enforcement = $(if (-not $pol.Ok) { 'Unknown' }
            elseif (-not $baseline.Count) { 'NotCovered' }
            elseif (@($covering | Where-Object { -not (Get-BaselineCondition $_) }).Count) { 'Enforced' }
            elseif ($covering.Count) { 'EnforcedWithConditions' }
            elseif ($maybe.Count) { 'Unknown' }
            elseif ($excludedFrom.Count) { 'Excluded' }
            else { 'NotCovered' })
        $registered = $(if ($r) { Test-True $r.IsMfaRegistered } else { $null })
        $sfList = $(if ($upn -and $sfByUpn.ContainsKey($upn.ToLowerInvariant())) { @($sfByUpn[$upn.ToLowerInvariant()]) } else { @() })
        $sfCount = 0; $legacyCount = 0; $brokerCount = 0
        foreach ($s in $sfList) {
            $cnt = [int]("0$($s.Row.SignInCount)")
            $sfCount += $cnt
            if (Test-LegacySignIn $s.Row) { $legacyCount += $cnt }
            elseif (Test-TokenBrokerSignIn $s.Row) { $brokerCount += $cnt }
        }
        $sfOtherCount = $sfCount - $brokerCount
        $state = $(if (-not $r) { 'NoRegistrationData' }
            elseif ($enforcement -eq 'Unknown') { 'Unknown' }
            elseif ($enforcement -eq 'Excluded') { 'Excluded' }
            elseif ($registered -and $enforcement -like 'Enforced*') { 'Protected' }
            elseif ($enforcement -like 'Enforced*') { 'EnforcedNotRegistered' }
            elseif ($registered) { 'RegisteredNotEnforced' }
            else { 'Unprotected' })
        $viaNames = @($excl | ForEach-Object { $_.ViaName }) + @($upn)
        $approved = $(if ($excludedFrom.Count) { Test-ExceptionApproved $viaNames } else { '' })
        $flags = @(
            $(if ($sfOtherCount) { 'SingleFactorSignIn' })
            $(if ($brokerCount -and -not $sfOtherCount) { 'TokenBrokerSignInOnly' })
            $(if ($legacyCount) { 'LegacyAuthSignIn' })
            $(if ($r -and (Test-True $r.HasPhoneMethodOnly)) { 'PhoneOnly' })
            $(if ($excludedFrom.Count -and $covering.Count) { 'PartiallyExcluded' })
            $(if ($enforcement -eq 'EnforcedWithConditions') { 'EnforcedOnlyWithConditions' })
            $(if ($m.Category -eq 'BreakGlass' -and $enforcement -eq 'Excluded') { 'ExpectedExclusion(BreakGlass)' })
            $(if ($m.Category -eq 'BreakGlass' -and $enforcement -like 'Enforced*') { 'BreakGlassNotExcluded' })
            $(if ($excludedFrom.Count -and $approved -eq $false -and $m.Category -ne 'BreakGlass') { 'ExclusionNotInExceptionRegister' })
            $(if ($r -and (Test-True $r.IsTier0) -and -not (Test-True $r.PhishResistant)) { 'Tier0WithoutPhishResistant' })
        ) | Where-Object { $_ }
        [pscustomobject][ordered]@{
            Upn = $upn; DisplayName = $m.DisplayName; UserId = $uid; Category = $m.Category
            Populations = ($m.Populations -join '; ')
            MfaState = $state; Enforcement = $enforcement
            MfaRegistered = $(if ($r) { $r.IsMfaRegistered } else { '' }); MfaCapable = $(if ($r) { $r.IsMfaCapable } else { '' })
            MethodStrength = $(if ($r) { $r.MethodStrength } else { '' }); PhishResistant = $(if ($r) { $r.PhishResistant } else { '' }); PhoneOnly = $(if ($r) { $r.HasPhoneMethodOnly } else { '' })
            IsPrivileged = $(if ($r) { $r.IsPrivileged } else { '' }); IsTier0 = $(if ($r) { $r.IsTier0 } else { '' })
            EnforcedBy = Join-Values ($covering | ForEach-Object { $_.PolicyName })
            ExcludedFrom = Join-Values $excludedFrom
            ExclusionVia = Join-Values (@($excl | ForEach-Object { '{0}: {1}' -f $_.Via, $_.ViaName } | Sort-Object -Unique) + $(if ($guestTypeHit.Count) { 'Guest or external user type' }))
            ExclusionApproved = $approved
            SingleFactorSignIns = $sfCount; TokenBrokerSignIns = $brokerCount; SingleFactorSignInsExBroker = $sfOtherCount; LegacyAuthSignIns = $legacyCount
            Flags = ($flags -join '; ')
        }
    }
    $stateOrder = @{ Unprotected = 0; Excluded = 1; RegisteredNotEnforced = 2; EnforcedNotRegistered = 3; NoRegistrationData = 4; Unknown = 5; Protected = 6 }
    $rows = @($rows | Sort-Object @{ Expression = { $stateOrder[$_.MfaState] } }, Upn)
    $rowStatus = Get-WorstStatus @($baseStatus, $(if ($pol.Ok) { $pol.Status } else { 'Blocked' }), $(if ($exclusionGaps.Count) { 'Partial' }))
    Export-Dataset -Name 'mfa-effectiveness' -Rows $rows -Status $(if ($rowStatus -eq 'Completed') { 'Completed' } else { 'Partial' }) -Note ((@($denomNotes) + @($exclusionGaps) + $(if (-not $pol.Ok) { "CA policies not usable: $($pol.Note)" })) -join '; ')

    # ---- 5. Exclusions ----
    $exRows = [System.Collections.Generic.List[object]]::new()
    if ($popEx.Ok) {
        foreach ($x in $popEx.Rows) {
            if ("$($x.ExcludedFrom)" -notmatch 'Entra') { continue }
            $exRows.Add([pscustomobject][ordered]@{ ExclusionKind = 'Population'; Upn = $x.Upn; Category = $x.Category; ExcludedFrom = $x.ExcludedFrom; Via = $x.ExclusionType; Reason = $x.ExclusionReason
                    Approved = $(if ($x.ExclusionType -eq 'ApprovedExclusion') { $true } elseif ($x.ExclusionType -eq 'Category') { 'By category rule' } else { $false }); ApprovedBy = $x.ApprovedBy; ExpiresUtc = $x.ExpiresUtc; Source = '27 population-exclusions' })
        }
    }
    foreach ($r in @($rows | Where-Object { $_.ExcludedFrom })) {
        foreach ($pn in (Split-List $r.ExcludedFrom)) {
            $guestPolicies = @($guestExcludedFrom | ForEach-Object { $_.Policy })
            $via = @($exclByUser[$r.UserId] | Where-Object { $_.Policy -eq $pn } | ForEach-Object { '{0}: {1}' -f $_.Via, $_.ViaName }) + $(if ($guestPolicies -contains $pn -and $r.ExclusionVia -match 'Guest or external user type') { 'Guest or external user type' })
            $exRows.Add([pscustomobject][ordered]@{ ExclusionKind = 'BaselineMfaPolicy'; Upn = $r.Upn; Category = $r.Category; ExcludedFrom = $pn; Via = Join-Values ($via | Where-Object { $_ } | Sort-Object -Unique)
                    Reason = $(if ($r.Category -eq 'BreakGlass') { 'Break-glass account (expected)' } else { '' })
                    Approved = $(if ($r.Category -eq 'BreakGlass') { 'Expected' } else { $r.ExclusionApproved }); ApprovedBy = ''; ExpiresUtc = ''; Source = '01 ca-exclusions / ca-excluded-group-members / ca-excluded-role-holders' })
        }
    }
    Export-Dataset -Name 'mfa-exclusions' -Rows $exRows -Status $(if ($exclusionGaps.Count -or -not $popEx.Ok) { 'Partial' } else { 'Completed' }) -Note ((@($exclusionGaps) + $(if (-not $popEx.Ok) { "population exclusions not listed: $($popEx.Note)" }) + $(if (-not $ExceptionRegisterCsv) { 'no -ExceptionRegisterCsv: Approved is blank for policy exclusions' })) -join '; ')

    # ---- 6. Failures ----
    $inScope = @{}
    foreach ($r in $rows) { if ($r.Upn) { $inScope[$r.Upn.ToLowerInvariant()] = $r } }
    $failRows = foreach ($k in $sfByUpn.Keys) {
        $r = $(if ($inScope.ContainsKey($k)) { $inScope[$k] } else { $null })
        foreach ($s in $sfByUpn[$k]) {
            $isBroker = Test-TokenBrokerSignIn $s.Row
            $cause = $(if (Test-LegacySignIn $s.Row) { 'Legacy authentication client' }
                elseif ($isBroker) { 'Token broker / Windows sign-in (PRT): CA not evaluated on PRT issue or renewal; MFA satisfied earlier in the session' }
                elseif ($r -and $r.Enforcement -eq 'Excluded') { 'Excluded from every baseline MFA policy' }
                elseif ("$($s.Row.CaStatuses)" -match '^notApplied$') { 'No Conditional Access policy applied' }
                elseif ($r -and $r.Enforcement -eq 'EnforcedWithConditions') { 'Sign-in matched an excluded location, app or device' }
                elseif ($r -and $r.Enforcement -eq 'NotCovered') { 'No baseline MFA policy' }
                else { 'Policy applied without an MFA requirement for this sign-in (check location, app and client conditions)' })
            [pscustomobject][ordered]@{
                Upn = $s.Row.UserPrincipalName; InScope = [bool]$r; Category = $(if ($r) { $r.Category } else { '' }); Populations = $(if ($r) { $r.Populations } else { '' })
                SignInKind = $s.Kind; AppDisplayName = $s.Row.AppDisplayName; ClientAppUsed = $s.Row.ClientAppUsed; IsLegacyAuth = (Test-LegacySignIn $s.Row); IsTokenBroker = $isBroker
                SignInCount = $s.Row.SignInCount; FirstSeenUtc = $s.Row.FirstSeenUtc; LastSeenUtc = $s.Row.LastSeenUtc; CaStatuses = $s.Row.CaStatuses
                Enforcement = $(if ($r) { $r.Enforcement } else { '' }); LikelyCause = $cause
            }
        }
    }
    $failRows = @($failRows | Sort-Object @{ Expression = 'InScope'; Descending = $true }, @{ Expression = { [int]("0$($_.SignInCount)") }; Descending = $true })
    if (-not $sf.Ok -and -not $ni.Ok) { Set-DatasetStatus -Name 'mfa-failures' -Status $(if ($sf.Status -in @('Blocked', 'Deferred', 'EvidenceUnavailable')) { $sf.Status } else { 'Blocked' }) -Note "single-factor sign-ins not usable: $($sf.Note)" }
    else { Export-Dataset -Name 'mfa-failures' -Rows $failRows -Status $(Get-WorstStatus @($sf.Status, $(if (-not $sf.Ok) { 'Partial' }))) -Note ((@("Successful single-factor sign-ins in the 01 lookback window") + $(if ($TokenBrokerApps.Count) { "IsTokenBroker = True for $(Join-Values $TokenBrokerApps) (PRT events, not bypasses)" }) + $(if (-not $ni.Ok) { "non-interactive sign-ins not included ($($ni.Status)); run 01 with -IncludeNonInteractive to add them" }) + $(if ($sf.Note) { $sf.Note })) -join '; ') }

    # ---- 7. Measures ----
    $measures = [System.Collections.Generic.List[object]]::new()
    $src01 = $(if ($run01) { '01 ' + (Split-Path $run01 -Leaf) } else { '' })
    $src27 = $(if ($run27 -and $popId.Ok) { '27 ' + (Split-Path $run27 -Leaf) } else { '' })
    function Add-Measure { param([string]$Population, [string]$Measure, $Value, $Denominator, [string]$Definition, [string]$Source, [string]$Status, [string]$Note = '')
        # A value that could not be computed is blank, never zero.
        $unknown = ($Status -in @('Blocked', 'NotRun', 'EvidenceUnavailable', 'Deferred'))
        $measures.Add([pscustomobject][ordered]@{ Population = $Population; Measure = $Measure; Value = $(if ($unknown) { '' } else { $Value }); Denominator = $Denominator
                Percent = $(if (-not $unknown -and $null -ne $Denominator -and "$Denominator" -ne '') { Get-Percent $Value $Denominator } else { '' }); Definition = $Definition; Source = $Source; Status = $Status
                Note = $(if ($unknown -and -not $Note) { 'Not computed: a source dataset is not usable (see source-runs)' } else { $Note }) }) }
    $sfStatus = $(if ($sf.Ok) { $sf.Status } else { $sf.Status })
    foreach ($pn in $popNames.Keys) {
        $set = @($rows | Where-Object { (Split-List $_.Populations) -contains $pn })
        $n = $set.Count
        $isPriv = ($pn -like 'Privileged*')
        $popSrc = $(if ($isPriv -or -not $popId.Ok) { $src01 } else { "$src27; $src01" })
        $st = $(if ($isPriv) { Get-WorstStatus @($reg.Status, $(if (-not $privKnown) { 'Blocked' }), $(if ($spread -and $spread -gt $MaxRunSpreadDays) { 'Partial' })) } else { $baseStatus })
        $stCa = Get-WorstStatus @($st, $(if ($pol.Ok) { $pol.Status } else { 'Blocked' }), $(if ($exclusionGaps.Count) { 'Partial' }))
        $note = $(if ($isPriv -and -not $privKnown) { 'IsPrivileged was not evaluated in the 01 run (-SkipPrivilegeJoin or privileged set unreadable)' } elseif (-not $isPriv) { $denomNotes -join '; ' } else { '' })
        $dnRow = $(if ($popDn.Ok -and $pn -eq 'Human workforce enabled (Entra)') { @($popDn.Rows | Where-Object { $_.Population -eq $pn }) | Select-Object -First 1 } else { $null })
        Add-Measure $pn 'Population (denominator)' $n '' $(if ($dnRow) { "$($popNames[$pn]). 27 definition: $($dnRow.Definition)" } else { $popNames[$pn] }) $popSrc $st $(if ($dnRow -and "$($dnRow.Count)" -ne '' -and [int]$dnRow.Count -ne $n) { "27 population-denominators says $($dnRow.Count); $($n) identities found in identity-population" } else { $note })
        if (-not $n) { continue }
        $c = { param($f) @($set | Where-Object $f).Count }
        Add-Measure $pn 'Protected (registered and enforced)' (& $c { $_.MfaState -eq 'Protected' }) $n 'Registered for MFA and covered by a baseline MFA policy they are not excluded from' $popSrc $stCa
        Add-Measure $pn 'Protected with no single-factor sign-in' (& $c { $_.MfaState -eq 'Protected' -and [int]$_.SingleFactorSignIns -eq 0 }) $n 'Protected, and no successful single-factor sign-in in the 01 lookback window (token broker / Windows sign-in counted)' $popSrc (Get-WorstStatus @($stCa, $sfStatus))
        if ($TokenBrokerApps.Count) { Add-Measure $pn 'Protected with no single-factor sign-in (excluding token broker)' (& $c { $_.MfaState -eq 'Protected' -and [int]$_.SingleFactorSignInsExBroker -eq 0 }) $n "Protected, and no successful single-factor sign-in other than $(Join-Values $TokenBrokerApps) (PRT events)" $popSrc (Get-WorstStatus @($stCa, $sfStatus)) }
        Add-Measure $pn 'Registered for MFA' (& $c { Test-True $_.MfaRegistered }) $n 'isMfaRegistered in the authentication methods registration report' $popSrc $st
        Add-Measure $pn 'Phishing-resistant method registered' (& $c { Test-True $_.PhishResistant }) $n 'FIDO2, passkey, Windows Hello or certificate registered' $popSrc $st
        Add-Measure $pn 'Phone (SMS / voice) is the strongest method' (& $c { Test-True $_.PhoneOnly }) $n 'Strongest registered method is SMS or voice' $popSrc $st
        Add-Measure $pn 'Enforced by a baseline MFA policy' (& $c { $_.Enforcement -like 'Enforced*' }) $n 'Covered by at least one baseline policy they are not excluded from (EnforcedWithConditions counted)' $popSrc $stCa
        Add-Measure $pn 'Enforced only with conditions' (& $c { $_.Enforcement -eq 'EnforcedWithConditions' }) $n 'Every covering baseline policy leaves out locations, apps or devices' $popSrc $stCa
        Add-Measure $pn 'Excluded from every baseline MFA policy' (& $c { $_.Enforcement -eq 'Excluded' }) $n 'Excluded by user, group, role or guest type from all baseline policies' $popSrc $stCa
        Add-Measure $pn 'Excluded from at least one baseline MFA policy' (& $c { $_.ExcludedFrom }) $n 'Any exclusion, including ones covered by another baseline policy' $popSrc $stCa
        if ($ExceptionRegisterCsv) { Add-Measure $pn 'Exclusions not in the exception register' (& $c { $_.Flags -match 'ExclusionNotInExceptionRegister' }) $n 'Excluded from a baseline policy with no accepted, unexpired exception' $popSrc $stCa }
        Add-Measure $pn 'Enforced but not registered' (& $c { $_.MfaState -eq 'EnforcedNotRegistered' }) $n 'Will be asked to register at next sign-in; whoever signs in first registers the method' $popSrc $stCa
        Add-Measure $pn 'Registered but not enforced' (& $c { $_.MfaState -eq 'RegisteredNotEnforced' }) $n 'Has a method, but no baseline policy requires it' $popSrc $stCa
        Add-Measure $pn 'Not in the registration report' (& $c { $_.MfaState -eq 'NoRegistrationData' }) $n 'In the population but not in the 01 registration report (deleted since, or not readable)' $popSrc $st
        $sfNote = $(if (-not $ni.Ok) { 'Interactive sign-ins only (01 ran without -IncludeNonInteractive)' } else { 'Interactive and non-interactive sign-ins' })
        Add-Measure $pn 'With successful single-factor sign-ins (raw)' (& $c { [int]$_.SingleFactorSignIns -gt 0 }) $n 'At least one successful single-factor sign-in in the 01 lookback window, token broker / Windows sign-in (PRT) events included' $popSrc (Get-WorstStatus @($st, $sfStatus)) $sfNote
        Add-Measure $pn 'With successful single-factor sign-ins (failures)' (& $c { [int]$_.SingleFactorSignInsExBroker -gt 0 }) $n $(if ($TokenBrokerApps.Count) { "At least one successful single-factor sign-in other than $(Join-Values $TokenBrokerApps), which are PRT events with CA not evaluated by design" } else { 'At least one successful single-factor sign-in in the 01 lookback window' }) $popSrc (Get-WorstStatus @($st, $sfStatus)) $sfNote
        if ($TokenBrokerApps.Count) { Add-Measure $pn 'With token broker / Windows sign-in (PRT) events only' (& $c { [int]$_.TokenBrokerSignIns -gt 0 -and [int]$_.SingleFactorSignInsExBroker -eq 0 }) $n 'Every single-factor sign-in is a token broker or Windows sign-in (PRT) event: not a failure' $popSrc (Get-WorstStatus @($st, $sfStatus)) $sfNote }
        Add-Measure $pn 'With legacy authentication sign-ins' (& $c { [int]$_.LegacyAuthSignIns -gt 0 }) $n 'At least one successful legacy-protocol sign-in' $popSrc (Get-WorstStatus @($st, $sfStatus))
    }
    Add-Measure 'Tenant' 'Baseline MFA policies' $baseline.Count '' (Join-Values ($baseline | ForEach-Object { $_.PolicyName })) $src01 $(if ($pol.Ok) { $pol.Status } else { 'Blocked' }) $(if ($MfaPolicyNames.Count) { "Named ($policyNamesSource)" } else { 'Detected: enabled, MFA, all users, all apps, all clients, no risk / include-location / include-platform condition' + $(if (-not $baseline.Count -and $pol.Ok -and @($pol.Rows | Where-Object { "$($_.State)" -eq 'enabled' -and (Test-True $_.RequiresMfa) }).Count) { '. NONE detected although enabled MFA policies exist: name them with -MfaPolicyNames (and -SaveMfaPolicyNames)' } else { '' }) })
    if ($popEx.Ok) { Add-Measure 'Tenant' 'Enabled accounts left out of the workforce population' @($exRows | Where-Object { $_.ExclusionKind -eq 'Population' }).Count '' 'Script 27 population-exclusions for the Entra workforce (category rules, approved exclusions, no HR match, HR not active)' $src27 $popEx.Status }
    Add-Measure 'Tenant' 'Single-factor sign-ins by accounts outside every population' @($failRows | Where-Object { -not $_.InScope -and -not $_.IsTokenBroker }).Count '' 'Service, shared or unclassified accounts signing in without MFA (rows; token broker / Windows sign-in rows not counted)' $src01 $sfStatus
    Export-Dataset -Name 'mfa-effectiveness-measures' -Rows $measures -Status $(if ((Get-WorstStatus @($measures | ForEach-Object { $_.Status })) -eq 'Completed') { 'Completed' } else { 'Partial' }) -Note ('Status per row; a row that is not Completed says why in Note or in source-runs. ' + ($denomNotes -join '; '))
    Export-Dataset -Name 'source-runs' -Rows $script:SourceRows -Note 'Every source dataset read: run folder, source status and SHA-256 check against that run'

    # ---- 8. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $mainPop = @($popNames.Keys)[0]
    Add-Metric 'Denominator basis' $denomMode $(if ($denomMode -eq 'Agreed') { 'Script 27 with an HR file' } else { $denomNotes -join '; ' })
    foreach ($mName in @('Population (denominator)', 'Protected (registered and enforced)', 'Registered for MFA', 'Enforced by a baseline MFA policy', 'Excluded from every baseline MFA policy', 'Enforced only with conditions', 'With successful single-factor sign-ins (raw)', 'With successful single-factor sign-ins (failures)', 'Phishing-resistant method registered')) {
        $mr = @($measures | Where-Object { $_.Population -eq $mainPop -and $_.Measure -eq $mName }) | Select-Object -First 1
        if ($mr) { Add-Metric "$mainPop - $mName" $mr.Value $(if ("$($mr.Percent)" -ne '') { "$($mr.Percent)% [$($mr.Status)]" } else { "[$($mr.Status)]" }) }
    }
    $pp = @($measures | Where-Object { $_.Population -like 'Privileged*' -and $_.Measure -eq 'Protected (registered and enforced)' }) | Select-Object -First 1
    if ($pp) { Add-Metric 'Privileged accounts protected' $pp.Value $(if ("$($pp.Percent)" -ne '') { "$($pp.Percent)% of $($pp.Denominator) [$($pp.Status)]" } else { "[$($pp.Status)]" }) }
    Add-Metric 'Baseline MFA policies' $baseline.Count (Join-Values ($baseline | ForEach-Object { $_.PolicyName }))
    Add-Metric 'Baseline policy names from' $policyNamesSource $(if ($policyNamesSource -like 'File*') { $MfaPolicyNamesFile } elseif (-not $baseline.Count) { 'No baseline policy: Protected and Enforced are 0. Name the policies with -MfaPolicyNames (add -SaveMfaPolicyNames to keep them)' } else { '' })
    Add-Metric 'Identities assessed' $rows.Count
    Add-Metric 'Source datasets not usable' @($script:SourceRows | Where-Object { $_.UsedAs -like 'Not used:*' }).Count (Join-Values ($script:SourceRows | Where-Object { $_.UsedAs -like 'Not used:*' } | ForEach-Object { "$($_.Script) $($_.Dataset): $($_.UsedAs -replace '^Not used: ', '')" }))
    Add-Metric 'Source files failing the SHA-256 check' @($script:SourceRows | Where-Object { $_.HashCheck -eq 'Mismatch' }).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName '' -Parameters @{ EvidenceRoot = $EvidenceRoot; MfaRunFolder = $MfaRunFolder; PopulationRunFolder = $PopulationRunFolder; MfaPolicyNames = $MfaPolicyNames; MfaPolicyNamesSource = $policyNamesSource; ExceptionRegisterCsv = $(if ($ExceptionRegisterCsv) { Split-Path $ExceptionRegisterCsv -Leaf } else { '' }); MaxRunSpreadDays = $MaxRunSpreadDays; AllowHashMismatch = [bool]$AllowHashMismatch }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
