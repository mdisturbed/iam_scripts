<#
.SYNOPSIS
    Read-only privileged identity register: one row per privileged account and one per privileged role,
    with owner, purpose, privilege, vault status and evidence state, so unmanaged privilege is visible.

.DESCRIPTION
    Joins earlier runs in the same evidence folder; connects to nothing:

      - 02-PrivilegedAccess          privileged-users (Entra role holders), privileged-service-principals
      - 04-ADPrivilegedAndService... ad-privileged-accounts, ad-privileged-membership, ad-admincount-orphans,
                                     ad-service-account-candidates (privileged ones; all with -IncludeServiceAccountCandidates)
      - 18-ADDelegation              ad-delegation-effective-users (High and Critical rights)
      - 11-AzureRbac                 azure-effective-users (privileged roles)
      - 17-AwsIamPosture             aws-effective-admins
      - 22-PimRoleSettings           pim-role-settings (activation controls per Entra role)
      - 27-IdentityPopulation        identity-population: joins an AD account to its Entra account and gives
                                     the category (admin, service, break-glass, workforce) and HR id
      - 26-PamVaultCoverage          privileged-vault-coverage, when a PAM vault exists and 26 has run
      - attestation file             optional: owner and purpose confirmed by a named person

    Owner and purpose can't be read from a directory with any certainty, so the register keeps two
    columns for each: a suggestion (app owners, the person an admin account belongs to by HR id or by
    name, the AD description) and the attested value. Only an attested value counts. The script writes an
    attestation worksheet to send to owners; save the answers as a CSV and pass it with -AttestationCsv.

    Vault status, in order: the attestation file's VaultStatus column, then script 26's match against the
    vault export, then -NoPamPlatform ('NotVaulted (no PAM platform)'), otherwise 'Unknown'.

    Managed = an attested owner, an attested purpose, and either vaulted or eligible-only (just in time).
    Everything else is listed with the reasons it is unmanaged.

    Datasets:
      - privileged-register              one row per privileged identity (an AD account and its synced
                                         Entra account are one row when script 27 joined them)
      - privileged-roles                 one row per privileged role or group: holders, standing vs eligible,
                                         activation controls, owner
      - privileged-attestation-worksheet the rows to send to owners, with suggestions and existing answers
      - source-runs                      every source dataset read: run folder, status, SHA-256 check

    READ-ONLY. Reads earlier run folders and the attestation file only; connects to nothing.

    Output: <OutputRoot>\34-PrivilegedRegister\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER EvidenceRoot
    Folder holding the earlier runs. Defaults to -OutputRoot.

.PARAMETER AttestationCsv
    Owner and purpose answers (examples\privileged-attestation.example.csv): Identity, Owner, Purpose,
    AttestedBy, AttestedOnUtc, ReviewByUtc, VaultStatus, Notes. Identity is a UPN, sAMAccountName,
    DOMAIN\name, service principal name, or role:<Platform>:<Role> for a role row.

.PARAMETER NoPamPlatform
    State that no PAM vault exists. Accounts with no other vault evidence show 'NotVaulted (no PAM platform)'
    instead of 'Unknown'.

.PARAMETER IncludeServiceAccountCandidates
    Also list AD service account candidates that hold no privilege (default: privileged ones only).

.PARAMETER IncludeComputerAccounts
    Also list computer accounts found in privileged groups (default: left out and counted in the summary).

.PARAMETER AdminAffixPatterns
    Regular expressions removed from an admin account name to find the person's own account (owner suggestion).

.EXAMPLE
    .\34-Get-PrivilegedRegister.ps1 -OutputRoot D:\Evidence -NoPamPlatform
.EXAMPLE
    .\34-Get-PrivilegedRegister.ps1 -OutputRoot D:\Evidence -NoPamPlatform -AttestationCsv D:\Engagement\registers\privileged-attestation.csv

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x. Earlier runs of 02 and 04 (11, 17, 18, 22, 26 and 27 when available).
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$EvidenceRoot = '',
    [string]$AttestationCsv = '',
    [switch]$NoPamPlatform,
    [switch]$IncludeServiceAccountCandidates,
    [switch]$IncludeComputerAccounts,
    [string[]]$AdminAffixPatterns = @('^(adm|admin|a|da|sa|ea|t0|t1)[-_.]', '[-_.](adm|admin|a|da|t0|t1)$', '^adm(?=[a-z])', '(?<=[a-z])adm$'),
    [string[]]$DelegationSeverities = @('Critical', 'High'),
    [switch]$AllowHashMismatch
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '34-PrivilegedRegister'
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
function ConvertTo-DateOrNull {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $out = [datetime]::MinValue
    if ([datetime]::TryParse($Value.Trim(), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$out)) { return $out }
    return $null
}

function Get-ShortName { param([string]$Name) return ((($Name.Trim().ToLowerInvariant()) -replace '^[^\\]+\\', '') -replace '@.*$', '') }

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if (-not $EvidenceRoot) { $EvidenceRoot = $OutputRoot }
    if (-not (Test-Path -LiteralPath $EvidenceRoot)) { throw "Evidence folder not found: $EvidenceRoot" }
    $now = $script:RunStartUtc

    # ---- 1. Sources ----
    $runs = @{}
    foreach ($n in @('02', '04', '11', '17', '18', '22', '26', '27')) { $runs[$n] = Get-LatestRunFolder -Root $EvidenceRoot -Number $n }
    $pu   = Read-SourceDataset -Script '02' -RunFolder $runs['02'] -Dataset 'privileged-users'
    $psp  = Read-SourceDataset -Script '02' -RunFolder $runs['02'] -Dataset 'privileged-service-principals'
    $adp  = Read-SourceDataset -Script '04' -RunFolder $runs['04'] -Dataset 'ad-privileged-accounts'
    $adm  = Read-SourceDataset -Script '04' -RunFolder $runs['04'] -Dataset 'ad-privileged-membership'
    $ado  = Read-SourceDataset -Script '04' -RunFolder $runs['04'] -Dataset 'ad-admincount-orphans' -Optional
    $ads  = Read-SourceDataset -Script '04' -RunFolder $runs['04'] -Dataset 'ad-service-account-candidates'
    $add  = Read-SourceDataset -Script '18' -RunFolder $runs['18'] -Dataset 'ad-delegation-effective-users' -Optional
    $az   = Read-SourceDataset -Script '11' -RunFolder $runs['11'] -Dataset 'azure-effective-users' -Optional
    $aws  = Read-SourceDataset -Script '17' -RunFolder $runs['17'] -Dataset 'aws-effective-admins' -Optional
    $pim  = Read-SourceDataset -Script '22' -RunFolder $runs['22'] -Dataset 'pim-role-settings' -Optional
    $pop  = Read-SourceDataset -Script '27' -RunFolder $runs['27'] -Dataset 'identity-population' -Optional
    $vlt  = Read-SourceDataset -Script '26' -RunFolder $runs['26'] -Dataset 'privileged-vault-coverage' -Optional
    if (-not $pu.Ok -and -not $adp.Ok) { throw "Needs at least script 02 (privileged-users) or script 04 (ad-privileged-accounts): $($pu.Note); $($adp.Note)" }
    $srcLabel = { param($Script, $R) '{0} {1} @ {2}' -f $Script, $(if ($R.File) { $R.File } else { '' }), $(if ($R.RunFolder) { Split-Path $R.RunFolder -Leaf } else { '' }) }

    # Population join (27)
    $popBySam = @{}; $popByUpn = @{}; $popByKey = @{}; $workforceByHr = @{}; $workforceByShort = @{}
    if ($pop.Ok) {
        foreach ($i in $pop.Rows) {
            if ($i.SamAccountName) { $popBySam["$($i.SamAccountName)".ToLowerInvariant()] = $i }
            if ($i.Upn) { $popByUpn["$($i.Upn)".ToLowerInvariant()] = $i }
            $popByKey["$($i.Key)"] = $i
            if ($i.Category -eq 'HumanWorkforce') {
                if ($i.HrId) { $workforceByHr["$($i.HrId)"] = $i }
                if ($i.SamAccountName) { $workforceByShort["$($i.SamAccountName)".ToLowerInvariant()] = $i }
                if ($i.Upn) { $workforceByShort[(Get-ShortName $i.Upn)] = $i }
            }
        }
    }

    # Attestations
    $att = @{}
    if ($AttestationCsv) {
        if (-not (Test-Path -LiteralPath $AttestationCsv)) { throw "Attestation file not found: $AttestationCsv" }
        $attRows = @(Import-Csv -LiteralPath $AttestationCsv)
        if ($attRows.Count -and -not $attRows[0].PSObject.Properties['Identity']) { throw "Attestation file has no Identity column. Columns: $($attRows[0].PSObject.Properties.Name -join ', ')" }
        foreach ($a in $attRows) {
            $k = "$($a.Identity)".Trim().ToLowerInvariant()
            if (-not $k) { continue }
            $att[$k] = $a
            if ($k -notlike 'role:*') { $att['short:' + (Get-ShortName $k)] = $a }
        }
        Write-RunLog ("Attestation file: {0} rows" -f $attRows.Count)
        $script:ManifestExtra = @{ AttestationFile = (Split-Path $AttestationCsv -Leaf); AttestationSha256 = (Get-FileHash -LiteralPath $AttestationCsv -Algorithm SHA256).Hash }
    }
    function Get-Attestation { param([string[]]$Keys)
        foreach ($k in @($Keys | Where-Object { $_ })) { $l = $k.Trim().ToLowerInvariant(); if ($att.ContainsKey($l)) { return $att[$l] } }
        foreach ($k in @($Keys | Where-Object { $_ -and $_ -notlike 'role:*' })) { $s = 'short:' + (Get-ShortName $k); if ($att.ContainsKey($s)) { return $att[$s] } }
        return $null }
    function Get-AttestationState { param($A)
        if (-not $A) { return 'Pending' }
        if (-not "$($A.AttestedBy)".Trim()) { return 'NotApproved' }
        $rb = ConvertTo-DateOrNull "$($A.ReviewByUtc)"
        if ($rb -and $rb -lt $now) { return 'Expired' }
        return 'Attested' }

    # Vault (26)
    $vaultByName = @{}
    $vRank = @{ 'True' = 3; 'Unconfirmed' = 2; 'False' = 1 }
    if ($vlt.Ok) {
        foreach ($v in $vlt.Rows) {
            foreach ($k in @("$($v.Account)".ToLowerInvariant(), (Get-ShortName "$($v.Account)"))) {
                if (-not $k) { continue }
                if (-not $vaultByName.ContainsKey($k) -or $vRank["$($v.Vaulted)"] -gt $vRank["$($vaultByName[$k].Vaulted)"]) { $vaultByName[$k] = $v }
            }
        }
    }

    # ---- 2. Collect privileged identities ----
    $reg = [ordered]@{}
    $skippedComputers = 0
    function Get-Entry { param([string]$Kind, [string]$Upn, [string]$Sam, [string]$Name, [string]$FallbackKey)
        $p = $null
        if ($Sam -and $popBySam.ContainsKey($Sam.ToLowerInvariant())) { $p = $popBySam[$Sam.ToLowerInvariant()] }
        elseif ($Upn -and $popByUpn.ContainsKey($Upn.ToLowerInvariant())) { $p = $popByUpn[$Upn.ToLowerInvariant()] }
        $key = $(if ($p) { 'pop:' + $p.Key } elseif ($Upn) { 'upn:' + $Upn.ToLowerInvariant() } else { $FallbackKey.ToLowerInvariant() })
        if (-not $reg.Contains($key)) {
            $reg[$key] = [pscustomobject]@{ Kind = $Kind; Upn = $(if ($p -and $p.Upn) { [string]$p.Upn } else { $Upn }); Sam = $(if ($p -and $p.SamAccountName) { [string]$p.SamAccountName } else { $Sam }); Name = $(if ($p -and $p.DisplayName) { [string]$p.DisplayName } else { $Name })
                Pop = $p; Platforms = [System.Collections.Generic.List[string]]::new(); Privileges = [System.Collections.Generic.List[string]]::new(); Tier0 = $false; Standing = $false; Eligible = $false
                Enabled = [System.Collections.Generic.List[string]]::new(); LastActivity = $null; Descriptions = [System.Collections.Generic.List[string]]::new(); AppOwners = ''; SpType = ''
                Flags = [System.Collections.Generic.List[string]]::new(); Statuses = [System.Collections.Generic.List[string]]::new(); Evidence = [System.Collections.Generic.List[string]]::new(); IsBreakGlass = $false; AdminNamed = $false; AdCategory = '' }
        }
        $e = $reg[$key]
        if (-not $e.Upn -and $Upn) { $e.Upn = $Upn }
        if (-not $e.Sam -and $Sam) { $e.Sam = $Sam }
        if (-not $e.Name -and $Name) { $e.Name = $Name }
        return $e }
    function Add-Privilege { param($Entry, [string]$Platform, [string]$Text, [bool]$Tier0, [string]$Enabled, $Last, $Source, [string]$Status)
        if (-not $Entry.Platforms.Contains($Platform)) { $Entry.Platforms.Add($Platform) }
        $t = "${Platform}: $Text"; if (-not $Entry.Privileges.Contains($t)) { $Entry.Privileges.Add($t) }
        if ($Tier0) { $Entry.Tier0 = $true }
        if ($Enabled -ne '') { $Entry.Enabled.Add("$Enabled") }
        if ($Last -and (-not $Entry.LastActivity -or $Last -gt $Entry.LastActivity)) { $Entry.LastActivity = $Last }
        $ev = & $srcLabel $Source.Script $Source.R; if (-not $Entry.Evidence.Contains($ev)) { $Entry.Evidence.Add($ev) }
        $Entry.Statuses.Add($Status) }

    # Entra role holders (02)
    if ($pu.Ok) {
        foreach ($r in $pu.Rows) {
            if (-not $r.UserPrincipalName) { continue }
            $e = Get-Entry -Kind 'User' -Upn $r.UserPrincipalName -Sam '' -Name $r.DisplayName -FallbackKey "entra:$($r.UserPrincipalName)"
            $roles = "$($r.Roles)"
            Add-Privilege $e 'Entra' $roles (Test-True $r.HoldsTier0Role) "$($r.AccountEnabled)" (ConvertTo-DateOrNull $r.LastSignInUtc) @{ Script = '02'; R = $pu } $pu.Status
            if ($roles -match '\[Active' -or "$($r.Flags)" -match 'PermanentActive') { $e.Standing = $true }
            if ($roles -match '\[Eligible') { $e.Eligible = $true }
            if (Test-True $r.IsBreakGlass) { $e.IsBreakGlass = $true }
            if ("$($r.Flags)" -match 'PermanentActive') { $e.Flags.Add('PermanentActiveRole') }
            if ("$($r.Flags)" -match 'NotMfaRegistered') { $e.Flags.Add('NotMfaRegistered') }
            if ("$($r.Flags)" -match 'Tier0WithoutPhishResistantMfa') { $e.Flags.Add('Tier0WithoutPhishResistantMfa') }
            if ("$($r.Flags)" -match 'NoSignIn') { $e.Flags.Add('NoRecentSignIn') }
            if (Test-True $r.SyncedFromOnPrem) { $e.Flags.Add('PrivilegedSyncedFromAD') }
        }
    }
    # Entra workload identities (02)
    if ($psp.Ok) {
        foreach ($r in $psp.Rows) {
            $e = Get-Entry -Kind 'ServicePrincipal' -Upn '' -Sam '' -Name $r.DisplayName -FallbackKey "sp:$($r.ServicePrincipalId)"
            $e.SpType = "$($r.ServicePrincipalType)"
            $e.AppOwners = Join-Values (@(Split-List $r.Owners) + @(Split-List $r.AppOwners) | Sort-Object -Unique)
            Add-Privilege $e 'Entra' ("$($r.Roles)" + ' [workload identity]') (Test-True $r.HoldsTier0Role) "$($r.AccountEnabled)" (ConvertTo-DateOrNull "$($r.LastSignInUtc)") @{ Script = '02'; R = $psp } $psp.Status
            $e.Standing = $true
            foreach ($f in (Split-List $r.Flags)) { if ($f -in @('NoOwner', 'SecretOnServicePrincipal', 'ExpiredCredential')) { $e.Flags.Add($f) } }
        }
    }
    # AD privileged accounts (04)
    if ($adp.Ok) {
        foreach ($r in $adp.Rows) {
            if (-not $r.SamAccountName) { continue }
            if ("$($r.ObjectClass)" -eq 'computer' -and -not $IncludeComputerAccounts) { $skippedComputers++; continue }
            $e = Get-Entry -Kind 'User' -Upn '' -Sam $r.SamAccountName -Name $r.Name -FallbackKey "ad:$($r.SamAccountName)"
            Add-Privilege $e 'AD' ("$($r.PrivilegedVia)" + $(if ($r.Tier) { " [$($r.Tier)]" } else { '' })) ("$($r.Tier)" -eq 'Tier0') "$($r.Enabled)" (ConvertTo-DateOrNull $r.LastLogonUtc) @{ Script = '04'; R = $adp } $adp.Status
            $e.Standing = $true
            if ($r.Description) { $e.Descriptions.Add("$($r.Description)") }
            if (Test-True $r.IsAdminNamed) { $e.AdminNamed = $true }
            if ($r.Category) { $e.AdCategory = "$($r.Category)" }
            foreach ($f in (Split-List $r.Flags)) { if ($f -match '^(PasswordNeverExpires|SpnOnPrivilegedUser|PreAuthDisabled|UnconstrainedDelegation|NoLogon)') { $e.Flags.Add(($f -replace '\(.*$', '')) } }
        }
    }
    if ($ado.Ok) {
        foreach ($r in @($ado.Rows | Where-Object { "$($_.ObjectClass)" -eq 'user' -and $_.SamAccountName })) {
            $e = Get-Entry -Kind 'User' -Upn '' -Sam $r.SamAccountName -Name $r.Name -FallbackKey "ad:$($r.SamAccountName)"
            if ($e.Privileges.Count) { $e.Flags.Add('AdminCountOrphan'); continue }
            Add-Privilege $e 'AD' 'adminCount=1 but no longer in a protected group (residual)' $false "$($r.Enabled)" (ConvertTo-DateOrNull $r.LastLogonUtc) @{ Script = '04'; R = $ado } $ado.Status
            $e.Flags.Add('AdminCountOrphan')
        }
    }
    if ($ads.Ok) {
        foreach ($r in $ads.Rows) {
            if (-not $r.SamAccountName) { continue }
            $isPriv = (Test-True $r.IsPrivileged) -or [bool]"$($r.PrivilegedVia)"
            $key = "$($r.SamAccountName)".ToLowerInvariant()
            $known = @($reg.Values | Where-Object { "$($_.Sam)".ToLowerInvariant() -eq $key }).Count
            if ($known) { ($reg.Values | Where-Object { "$($_.Sam)".ToLowerInvariant() -eq $key } | Select-Object -First 1).Flags.Add('ServiceAccountCandidate'); continue }
            if (-not $isPriv -and -not $IncludeServiceAccountCandidates) { continue }
            $e = Get-Entry -Kind 'User' -Upn '' -Sam $r.SamAccountName -Name $r.Name -FallbackKey "ad:$($r.SamAccountName)"
            Add-Privilege $e 'AD' ('Service account candidate: ' + "$($r.DetectionReasons)" + $(if ($r.PrivilegedVia) { "; via $($r.PrivilegedVia)" } else { '' })) (Test-True $r.IsPrivileged) "$($r.Enabled)" (ConvertTo-DateOrNull $r.LastLogonUtc) @{ Script = '04'; R = $ads } $ads.Status
            $e.Standing = $true
            $e.Flags.Add('ServiceAccountCandidate')
            if ($r.Description) { $e.Descriptions.Add("$($r.Description)") }
        }
    }
    # AD delegation (18)
    if ($add.Ok) {
        foreach ($r in @($add.Rows | Where-Object { $DelegationSeverities -contains "$($_.HighestSeverity)" -and $_.SamAccountName })) {
            $e = Get-Entry -Kind 'User' -Upn '' -Sam $r.SamAccountName -Name '' -FallbackKey "ad:$($r.SamAccountName)"
            Add-Privilege $e 'AD delegation' ('{0} rights: {1} via {2}' -f $r.HighestSeverity, $r.Rights, $r.Via) ("$($r.HighestSeverity)" -eq 'Critical' -or (Test-True $r.HoldsTier0Rights)) "$($r.Enabled)" $null @{ Script = '18'; R = $add } $add.Status
            $e.Standing = $true
            if ("$($r.Flags)" -match 'RegularAccountWithElevatedRights') { $e.Flags.Add('RegularAccountWithElevatedRights') }
        }
    }
    # Azure (11)
    if ($az.Ok) {
        $azUsers = [ordered]@{}
        foreach ($r in @($az.Rows | Where-Object { (Test-True $_.IsPrivilegedRole) -and $_.Upn -and (-not $_.PrincipalType -or $_.PrincipalType -eq 'User') })) {
            $k = "$($r.Upn)".ToLowerInvariant()
            if (-not $azUsers.Contains($k)) { $azUsers[$k] = [System.Collections.Generic.List[object]]::new() }
            $azUsers[$k].Add($r)
        }
        foreach ($k in $azUsers.Keys) {
            $rs = $azUsers[$k]
            $e = Get-Entry -Kind 'User' -Upn $rs[0].Upn -Sam '' -Name $rs[0].DisplayName -FallbackKey "upn:$k"
            $broad = [bool](@($rs | Where-Object { "$($_.Scope)" -eq '/' -or "$($_.Scope)" -match '^/providers/Microsoft\.Management/managementGroups/[^/]+$' -or "$($_.Scope)" -match '^/subscriptions/[^/]+$' }).Count)
            Add-Privilege $e 'Azure' (Join-Values (@($rs | ForEach-Object { '{0} [{1}] on {2}' -f $_.RoleName, $_.AssignmentState, $(if ($_.SubscriptionName) { $_.SubscriptionName } else { $_.Scope }) }) | Sort-Object -Unique)) $broad '' $null @{ Script = '11'; R = $az } $az.Status
            if (@($rs | Where-Object { "$($_.AssignmentState)" -notmatch 'Eligible' }).Count) { $e.Standing = $true }
            if (@($rs | Where-Object { "$($_.AssignmentState)" -match 'Eligible' }).Count) { $e.Eligible = $true }
        }
    }
    # AWS (17)
    if ($aws.Ok) {
        foreach ($r in $aws.Rows) {
            if (-not $r.PrincipalName) { continue }
            $e = Get-Entry -Kind 'AWS' -Upn '' -Sam '' -Name ('{0} (account {1})' -f $r.PrincipalName, $r.AccountId) -FallbackKey ('aws:{0}:{1}' -f $r.AccountId, $r.PrincipalName)
            Add-Privilege $e 'AWS' ('{0}: {1}' -f $r.Via, $r.Evidence) $true '' $null @{ Script = '17'; R = $aws } $aws.Status
            $e.Standing = $true
        }
    }
    if ($skippedComputers) { Write-RunLog ("{0} computer accounts in privileged groups left out (domain controllers and similar); -IncludeComputerAccounts lists them" -f $skippedComputers) }

    # ---- 3. Register rows ----
    $rows = foreach ($key in $reg.Keys) {
        $e = $reg[$key]
        $p = $e.Pop
        $cat = $(if ($p) { "$($p.Category)" } else { '' })
        $type = $(if ($e.Kind -eq 'ServicePrincipal') { $(if ($e.SpType -eq 'ManagedIdentity') { 'Managed identity' } else { 'Workload identity (service principal)' }) }
            elseif ($e.Kind -eq 'AWS') { 'AWS principal' }
            elseif ($e.IsBreakGlass -or $cat -eq 'BreakGlass') { 'Break-glass account' }
            elseif ($cat -eq 'ServiceAccount' -or $e.Flags.Contains('ServiceAccountCandidate') -or $e.AdCategory -in @('Managed service account', 'Entra Connect (sync account)')) { 'Service account' }
            elseif ($e.AdCategory -eq 'Builtin') { 'Built-in account' }
            elseif ($cat -eq 'AdminAccount' -or $e.AdminNamed) { 'Admin account' }
            elseif ($cat -eq 'HumanWorkforce') { 'Regular user account' }
            elseif ($cat -in @('Guest', 'ExternalMember')) { 'Guest or external' }
            elseif ($cat -eq 'TestAccount') { 'Test account' }
            elseif ($cat -eq 'ResourceOrShared') { 'Shared or resource account' }
            else { 'Unclassified' })
        if ($type -eq 'Regular user account') { $e.Flags.Add('PrivilegeOnRegularAccount') }
        if ($type -eq 'Guest or external') { $e.Flags.Add('PrivilegedGuest') }

        # Owner suggestion
        $sugOwner = ''; $sugSrc = ''
        if ($e.Kind -eq 'ServicePrincipal' -and $e.AppOwners) { $sugOwner = $e.AppOwners; $sugSrc = 'App / service principal owners (directory)' }
        elseif ($type -eq 'Regular user account') { $sugOwner = $(if ($e.Upn) { $e.Upn } else { $e.Sam }); $sugSrc = "The person's own account" }
        elseif ($p -and $p.HrId -and $workforceByHr.ContainsKey("$($p.HrId)") -and $workforceByHr["$($p.HrId)"].Key -ne $p.Key) { $w = $workforceByHr["$($p.HrId)"]; $sugOwner = $(if ($w.Upn) { $w.Upn } else { $w.SamAccountName }); $sugSrc = 'Same HR id as a workforce account (script 27)' }
        elseif ($type -in @('Admin account', 'Unclassified') -and $workforceByShort.Count) {
            foreach ($nm in @($e.Sam, $(if ($e.Upn) { Get-ShortName $e.Upn })) | Where-Object { $_ }) {
                $base = $nm.ToLowerInvariant()
                foreach ($rx in $AdminAffixPatterns) { $base = $base -replace $rx, '' }
                if ($base -and $base -ne $nm.ToLowerInvariant() -and $workforceByShort.ContainsKey($base)) { $w = $workforceByShort[$base]; $sugOwner = $(if ($w.Upn) { $w.Upn } else { $w.SamAccountName }); $sugSrc = 'Name match to a workforce account (confirm)'; break }
            }
        }
        $sugPurpose = $(if ($e.Descriptions.Count) { 'AD description: ' + (Join-Values ($e.Descriptions | Sort-Object -Unique)) } elseif ($e.Kind -eq 'ServicePrincipal') { "Application: $($e.Name)" } elseif ($type -eq 'Break-glass account') { 'Emergency access' } else { '' })

        # Attestation
        $ids = @($e.Upn, $e.Sam, $e.Name) | Where-Object { $_ }
        $a = Get-Attestation $ids
        $aState = Get-AttestationState $a
        $owner = $(if ($aState -eq 'Attested' -and "$($a.Owner)".Trim()) { "$($a.Owner)".Trim() } else { '' })
        $purpose = $(if ($aState -eq 'Attested' -and "$($a.Purpose)".Trim()) { "$($a.Purpose)".Trim() } else { '' })

        # Vault
        $vault = ''; $vaultSrc = ''; $vaultStatus = 'Completed'
        if ($a -and $a.PSObject.Properties['VaultStatus'] -and "$($a.VaultStatus)".Trim() -and $aState -eq 'Attested') { $vault = "$($a.VaultStatus)".Trim(); $vaultSrc = 'Attestation' }
        elseif ($e.Kind -in @('ServicePrincipal')) { $vault = 'N/A (workload identity)'; $vaultSrc = 'Not vaultable as an account; see credential flags' }
        else {
            $hit = $null
            foreach ($k in @($e.Sam, $e.Upn, $e.Name) | Where-Object { $_ }) { $kk = "$k".ToLowerInvariant(); if ($vaultByName.ContainsKey($kk)) { $hit = $vaultByName[$kk]; break }; $kk = Get-ShortName $k; if ($vaultByName.ContainsKey($kk)) { $hit = $vaultByName[$kk]; break } }
            if ($hit) { $vault = $(switch ("$($hit.Vaulted)") { 'True' { 'Vaulted' } 'Unconfirmed' { 'Unconfirmed (name-only match)' } default { 'NotVaulted' } }); $vaultSrc = (& $srcLabel '26' $vlt); $vaultStatus = $vlt.Status }
            elseif ($vlt.Ok) { $vault = 'NotVaulted'; $vaultSrc = (& $srcLabel '26' $vlt) + ' (not in the vault coverage list)'; $vaultStatus = 'Partial' }
            elseif ($NoPamPlatform) { $vault = 'NotVaulted (no PAM platform)'; $vaultSrc = 'Declared with -NoPamPlatform' }
            else { $vault = 'Unknown'; $vaultSrc = 'No PAM export (script 26 not run) and -NoPamPlatform not set'; $vaultStatus = 'EvidenceUnavailable' }
        }
        $residualOnly = (@($e.Privileges | Where-Object { $_ -notlike '*adminCount=1 but no longer*' }).Count -eq 0)
        $model = $(if ($residualOnly) { 'None (residual adminCount only)' } elseif ($e.Standing -and $e.Eligible) { 'Mixed (standing and eligible)' } elseif ($e.Standing) { 'Standing' } elseif ($e.Eligible) { 'Eligible only (just in time)' } else { 'Unknown' })
        $enabledText = $(if ($e.Enabled -contains 'True') { 'True' } elseif ($e.Enabled -contains 'False') { 'False' } else { '' })

        # Vaulted counts only as 'Vaulted' (26 or attested), 'Sealed' (attested break-glass procedure) or N/A (workload identity).
        $vaultOk = ($vault -match '^(Vaulted|Sealed|N/A)')
        # Managed?
        $why = @(
            $(if (-not $owner) { 'No attested owner' })
            $(if (-not $purpose) { 'No attested purpose' })
            $(if ($aState -eq 'Expired') { 'Attestation expired' })
            $(if ($residualOnly) { 'Residual adminCount: clear it or confirm the account still needs protection' })
            $(if (-not $residualOnly -and -not $vaultOk -and $model -ne 'Eligible only (just in time)') { 'Standing access not vaulted' })
        ) | Where-Object { $_ }
        if ($e.Tier0 -and $model -ne 'Eligible only (just in time)' -and -not $vaultOk -and $type -ne 'Break-glass account') { $e.Flags.Add('Tier0StandingNotVaulted') }
        if (-not $owner -and -not $sugOwner) { $e.Flags.Add('NoOwnerFound') }
        if ($enabledText -eq 'False') { $e.Flags.Add('Disabled') }
        $evState = Get-WorstStatus (@($e.Statuses) + @($vaultStatus))
        [pscustomobject][ordered]@{
            Identity = $(if ($e.Upn) { $e.Upn } elseif ($e.Sam) { $e.Sam } else { $e.Name }); DisplayName = $e.Name; SamAccountName = $e.Sam
            IdentityType = $type; Category = $cat; Platforms = Join-Values $e.Platforms
            Privilege = Join-Values $e.Privileges; Tier0 = $e.Tier0; AssignmentModel = $model; Enabled = $enabledText
            LastActivityUtc = $(if ($e.LastActivity) { $e.LastActivity.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            Owner = $owner; SuggestedOwner = $sugOwner; SuggestedOwnerSource = $sugSrc
            Purpose = $purpose; SuggestedPurpose = $sugPurpose
            VaultStatus = $vault; VaultSource = $vaultSrc
            Attestation = $aState; AttestedBy = $(if ($a) { $a.AttestedBy } else { '' }); AttestedOnUtc = $(if ($a) { $a.AttestedOnUtc } else { '' }); ReviewByUtc = $(if ($a -and $a.PSObject.Properties['ReviewByUtc']) { $a.ReviewByUtc } else { '' })
            Managed = (-not $why.Count); UnmanagedReasons = ($why -join '; ')
            EvidenceState = $evState; EvidenceSources = Join-Values $e.Evidence
            Flags = Join-Values ($e.Flags | Sort-Object -Unique)
        }
    }
    $typeOrder = @{ 'Break-glass account' = 0; 'Admin account' = 1; 'Regular user account' = 2; 'Service account' = 3; 'Workload identity (service principal)' = 4; 'Managed identity' = 5; 'Built-in account' = 6; 'AWS principal' = 7 }
    $rows = @($rows | Sort-Object @{ Expression = 'Managed' }, @{ Expression = 'Tier0'; Descending = $true }, @{ Expression = { $(if ($typeOrder.ContainsKey($_.IdentityType)) { $typeOrder[$_.IdentityType] } else { 9 }) } }, Identity)
    $regNotes = @(
        $(if (-not $pop.Ok) { "no usable run of 27: AD and Entra accounts of the same person are separate rows and owner suggestions by HR id or name are not made ($($pop.Status))" })
        $(if (-not $vlt.Ok -and -not $NoPamPlatform) { 'vault status Unknown: run 26 with a vault export, or pass -NoPamPlatform when no vault exists' })
        $(if (-not $AttestationCsv) { 'no -AttestationCsv: Owner and Purpose are blank until attested; send privileged-attestation-worksheet.csv to owners' })
        $(foreach ($s in @($pu, $psp, $adp, $ads)) { if (-not $s.Ok) { "$($s.Note)" } })
        $(foreach ($s in @(@{ R = $add; L = 'AD delegation (18)' }, @{ R = $az; L = 'Azure (11)' }, @{ R = $aws; L = 'AWS (17)' }, @{ R = $pim; L = 'PIM role settings (22)' })) {
                if ($s.R.Status -eq 'NotRun') { "$($s.L) not run: no rows from that source" }
                elseif (-not $s.R.Ok) { "$($s.L) ran but is $($s.R.Status): privileged accounts from that source are missing" } })
    ) | Where-Object { $_ }
    $optionalGap = [bool](@(@($add, $az, $aws, $pim) | Where-Object { -not $_.Ok -and $_.Status -ne 'NotRun' }).Count)
    $regStatus = Get-WorstStatus (@($rows | ForEach-Object { $_.EvidenceState }) + $(if (-not $pu.Ok -or -not $psp.Ok -or -not $adp.Ok -or -not $ads.Ok -or -not $pop.Ok -or $optionalGap) { 'Partial' }))
    Export-Dataset -Name 'privileged-register' -Rows $rows -Status $(if ($regStatus -eq 'Completed') { 'Completed' } else { 'Partial' }) -Note ($regNotes -join '; ')

    # ---- 4. Roles ----
    $roleRows = [System.Collections.Generic.List[object]]::new()
    function Add-RoleRow { param([string]$Platform, [string]$Role, [string]$Scope, [bool]$Tier0, $Holders, $Standing, $Eligible, [string]$Controls, [string]$Flags, [string]$Source, [string]$Status)
        $a = Get-Attestation @("role:${Platform}:$Role")
        $aState = Get-AttestationState $a
        $roleRows.Add([pscustomobject][ordered]@{ Platform = $Platform; Role = $Role; Scope = $Scope; Tier0 = $Tier0; Holders = $Holders; StandingHolders = $Standing; EligibleHolders = $Eligible
                ActivationControls = $Controls; Owner = $(if ($aState -eq 'Attested') { "$($a.Owner)" } else { '' }); Purpose = $(if ($aState -eq 'Attested') { "$($a.Purpose)" } else { '' }); Attestation = $aState
                Flags = $Flags; EvidenceState = $Status; EvidenceSource = $Source }) }
    if ($pim.Ok) {
        foreach ($r in @($pim.Rows | Where-Object { [int]("0$($_.ActiveAssignments)") + [int]("0$($_.EligibleAssignments)") -gt 0 -or (Test-True $_.IsTier0) })) {
            $ctl = @(
                $(if ("$($r.MaxActivationHours)") { "max $($r.MaxActivationHours) h" })
                $(if (Test-True $r.ActivationRequiresMfa) { 'MFA' })
                $(if (Test-True $r.ActivationRequiresAuthContext) { "auth context $($r.AuthContextName)" })
                $(if (Test-True $r.ApprovalRequired) { 'approval' })
                $(if (Test-True $r.ActivationRequiresJustification) { 'justification' })
                $(if (Test-True $r.ActivationRequiresTicket) { 'ticket' })
                $(if (Test-True $r.PermanentActiveAllowed) { 'permanent active allowed' })
            ) | Where-Object { $_ }
            Add-RoleRow 'Entra' $r.RoleName 'Directory' (Test-True $r.IsTier0) $r.EffectivePrincipals $r.ActiveAssignments $r.EligibleAssignments ($ctl -join '; ') "$($r.Flags)" (& $srcLabel '22' $pim) $pim.Status
        }
    }
    elseif ($pu.Ok) {
        $byRole = @{}
        foreach ($r in $pu.Rows) { foreach ($t in (Split-List $r.Roles)) { $rn = ($t -replace '\s*\[.*$', '').Trim(); if (-not $byRole.ContainsKey($rn)) { $byRole[$rn] = @{ H = 0; S = 0; E = 0 } }; $byRole[$rn].H++; if ($t -match '\[Active') { $byRole[$rn].S++ } elseif ($t -match '\[Eligible') { $byRole[$rn].E++ } } }
        foreach ($rn in ($byRole.Keys | Sort-Object)) { Add-RoleRow 'Entra' $rn 'Directory' $false $byRole[$rn].H $byRole[$rn].S $byRole[$rn].E 'Not read (script 22 not usable)' '' (& $srcLabel '02' $pu) 'Partial' }
    }
    if ($adm.Ok) {
        foreach ($g in @($adm.Rows | Group-Object PrivilegedGroup | Sort-Object Name)) {
            $users = @($g.Group | Where-Object { "$($_.MemberClass)" -eq 'user' } | Select-Object -ExpandProperty MemberSam -Unique)
            $nested = @($g.Group | Where-Object { "$($_.MemberClass)" -eq 'group' }).Count
            Add-RoleRow 'AD' $g.Name 'Domain' ("$($g.Group[0].Tier)" -eq 'Tier0') $users.Count $users.Count 0 'Standing membership (no just-in-time in AD)' $(if ($nested) { "$nested nested group(s)" } else { '' }) (& $srcLabel '04' $adm) $adm.Status
        }
    }
    if ($az.Ok) {
        foreach ($g in @($az.Rows | Where-Object { Test-True $_.IsPrivilegedRole } | Group-Object RoleName, Scope | Sort-Object Name)) {
            $f = $g.Group[0]
            $u = @($g.Group | Select-Object -ExpandProperty Upn -Unique | Where-Object { $_ })
            Add-RoleRow 'Azure' $f.RoleName $(if ($f.SubscriptionName) { "$($f.SubscriptionName) ($($f.Scope))" } else { $f.Scope }) ("$($f.Scope)" -eq '/' -or "$($f.Scope)" -match '^/subscriptions/[^/]+$' -or "$($f.Scope)" -match 'managementGroups/[^/]+$') $u.Count @($g.Group | Where-Object { "$($_.AssignmentState)" -notmatch 'Eligible' } | Select-Object -ExpandProperty Upn -Unique).Count @($g.Group | Where-Object { "$($_.AssignmentState)" -match 'Eligible' } | Select-Object -ExpandProperty Upn -Unique).Count '' '' (& $srcLabel '11' $az) $az.Status
        }
    }
    if ($roleRows.Count) { Export-Dataset -Name 'privileged-roles' -Rows @($roleRows | Sort-Object @{ Expression = 'Tier0'; Descending = $true }, Platform, Role) -Status $(if ((Get-WorstStatus @($roleRows | ForEach-Object { $_.EvidenceState })) -eq 'Completed') { 'Completed' } else { 'Partial' }) -Note 'Roles and groups with holders (and every Tier 0 Entra role). Owner and Purpose come from role:<Platform>:<Role> rows in the attestation file' }
    else { Set-DatasetStatus -Name 'privileged-roles' -Status 'Blocked' -Note 'No usable role source (22, 02, 04 or 11)' }

    # ---- 5. Attestation worksheet ----
    $ws = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $rows) {
        $a = Get-Attestation @($r.Identity, $r.SamAccountName, $r.DisplayName)
        $ws.Add([pscustomobject][ordered]@{ Identity = $r.Identity; IdentityType = $r.IdentityType; Platforms = $r.Platforms; Privilege = $r.Privilege; Tier0 = $r.Tier0; AssignmentModel = $r.AssignmentModel
                SuggestedOwner = $r.SuggestedOwner; SuggestedOwnerSource = $r.SuggestedOwnerSource; SuggestedPurpose = $r.SuggestedPurpose
                Owner = $(if ($a) { $a.Owner } else { '' }); Purpose = $(if ($a) { $a.Purpose } else { '' }); AttestedBy = $(if ($a) { $a.AttestedBy } else { '' }); AttestedOnUtc = $(if ($a) { $a.AttestedOnUtc } else { '' })
                ReviewByUtc = $(if ($a -and $a.PSObject.Properties['ReviewByUtc']) { $a.ReviewByUtc } else { '' }); VaultStatus = $(if ($a -and $a.PSObject.Properties['VaultStatus']) { $a.VaultStatus } else { '' }); Notes = $(if ($a -and $a.PSObject.Properties['Notes']) { $a.Notes } else { '' }); CurrentState = $r.Attestation })
    }
    foreach ($r in $roleRows) {
        $id = "role:$($r.Platform):$($r.Role)"
        $a = Get-Attestation @($id)
        $ws.Add([pscustomobject][ordered]@{ Identity = $id; IdentityType = 'Role'; Platforms = $r.Platform; Privilege = $r.Scope; Tier0 = $r.Tier0; AssignmentModel = ''
                SuggestedOwner = ''; SuggestedOwnerSource = ''; SuggestedPurpose = ''
                Owner = $(if ($a) { $a.Owner } else { '' }); Purpose = $(if ($a) { $a.Purpose } else { '' }); AttestedBy = $(if ($a) { $a.AttestedBy } else { '' }); AttestedOnUtc = $(if ($a) { $a.AttestedOnUtc } else { '' })
                ReviewByUtc = $(if ($a -and $a.PSObject.Properties['ReviewByUtc']) { $a.ReviewByUtc } else { '' }); VaultStatus = ''; Notes = $(if ($a -and $a.PSObject.Properties['Notes']) { $a.Notes } else { '' }); CurrentState = $r.Attestation })
    }
    Export-Dataset -Name 'privileged-attestation-worksheet' -Rows $ws -Note 'Send to owners. Fill Owner, Purpose, AttestedBy, AttestedOnUtc (and ReviewByUtc, VaultStatus if known); save as CSV and pass back with -AttestationCsv. Suggested values are not counted'
    Export-Dataset -Name 'source-runs' -Rows $script:SourceRows -Note 'Every source dataset read: run folder, source status and SHA-256 check against that run'

    # ---- 6. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $en = @($rows | Where-Object { $_.Enabled -ne 'False' })
    $pct = { param($a, $b) if ($b) { '{0}%' -f [math]::Round(100.0 * $a / $b, 1) } else { '' } }
    Add-Metric 'Privileged identities (enabled or unknown)' $en.Count (Join-Values (@($en | Group-Object IdentityType | Sort-Object Count -Descending | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name })))
    Add-Metric 'Tier 0 identities' @($en | Where-Object Tier0).Count
    Add-Metric 'Managed' @($en | Where-Object Managed).Count (& $pct @($en | Where-Object Managed).Count $en.Count)
    Add-Metric 'Unmanaged' @($en | Where-Object { -not $_.Managed }).Count (Join-Values (@($en | ForEach-Object { Split-List $_.UnmanagedReasons } | Group-Object | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })))
    Add-Metric 'Attested owner' @($en | Where-Object { $_.Owner }).Count (& $pct @($en | Where-Object { $_.Owner }).Count $en.Count)
    Add-Metric 'Attested purpose' @($en | Where-Object { $_.Purpose }).Count (& $pct @($en | Where-Object { $_.Purpose }).Count $en.Count)
    Add-Metric 'Owner suggested but not attested' @($en | Where-Object { -not $_.Owner -and $_.SuggestedOwner }).Count
    Add-Metric 'No owner found at all' @($en | Where-Object { $_.Flags -match 'NoOwnerFound' }).Count
    Add-Metric 'Vault status' (Join-Values (@($en | Group-Object VaultStatus | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }))) ''
    Add-Metric 'Tier 0 with standing access, not vaulted' @($en | Where-Object { $_.Flags -match 'Tier0StandingNotVaulted' }).Count 'Break-glass accounts not counted'
    Add-Metric 'Standing vs just in time' (Join-Values (@($en | Group-Object AssignmentModel | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }))) ''
    Add-Metric 'Privilege on a regular user account' @($en | Where-Object { $_.Flags -match 'PrivilegeOnRegularAccount|RegularAccountWithElevatedRights' }).Count
    Add-Metric 'Evidence state' (Join-Values (@($rows | Group-Object EvidenceState | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }))) ''
    Add-Metric 'Privileged roles and groups listed' $roleRows.Count
    Add-Metric 'Computer accounts left out' $skippedComputers 'Domain controllers and other computers in privileged groups; -IncludeComputerAccounts lists them'
    Add-Metric 'Source datasets not usable' @($script:SourceRows | Where-Object { $_.UsedAs -like 'Not used*' }).Count (Join-Values ($script:SourceRows | Where-Object { $_.UsedAs -like 'Not used*' } | ForEach-Object { "$($_.Script) $($_.Dataset): $($_.UsedAs -replace '^Not used( \(optional\))?: ', '')" }))
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName '' -Parameters @{ EvidenceRoot = $EvidenceRoot; AttestationCsv = $(if ($AttestationCsv) { Split-Path $AttestationCsv -Leaf } else { '' }); NoPamPlatform = [bool]$NoPamPlatform; IncludeServiceAccountCandidates = [bool]$IncludeServiceAccountCandidates; IncludeComputerAccounts = [bool]$IncludeComputerAccounts; AdminAffixPatterns = $AdminAffixPatterns; DelegationSeverities = $DelegationSeverities; AllowHashMismatch = [bool]$AllowHashMismatch }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
