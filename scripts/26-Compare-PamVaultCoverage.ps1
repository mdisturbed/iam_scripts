<#
.SYNOPSIS
    Read-only PAM vault coverage: which privileged accounts found by the other discovery scripts are
    managed in the privileged access management (PAM) vault, and which are not.

.DESCRIPTION
    Reconciles a PAM account export (any vault that exports CSV) against the privileged accounts
    found by earlier runs of the discovery scripts in the same evidence folder:

      - AD     04-ADPrivilegedAndServiceAccounts  ad-privileged-accounts.csv   (protected-group members)
      - Entra  02-PrivilegedAccess                privileged-users.csv         (directory role holders)
      - Azure  11-AzureRbac                       azure-role-assignments.csv   (privileged roles, users)
      - AWS    17-AwsIamPosture                   aws-iam-users.csv            (IAM users with admin access)

    The latest run of each is used; a source that hasn't been run is reported, not guessed.

    Matching: account names are compared case-insensitively, first exactly (UPN or sAMAccountName),
    then by name only (DOMAIN\ prefix and @suffix removed). Name-only matches are labelled so
    they can be checked, because two systems can hold the same short name.

    Datasets:
      - privileged-vault-coverage  one row per privileged account: source, Tier 0, enabled, vaulted,
                                   how it matched, and the matching vault entry (platform, safe)
      - pam-entries-unmatched      vault entries that match no privileged account (no longer
                                   privileged, renamed, deleted, or their source not run)
      - source-runs                which run and file each source came from, with SHA-256

    READ-ONLY. Reads CSV files only; connects to nothing.

    Output: <OutputRoot>\26-PamVaultCoverage\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER PamExportCsv
    CSV export of vaulted accounts from the PAM tool.

.PARAMETER EvidenceRoot
    Folder holding the earlier runs (NN-Name\yyyyMMdd-HHmmssZ). Defaults to -OutputRoot.

.PARAMETER PamAccountColumn
    Column with the account name (UPN, DOMAIN\name or name). Other column parameters map the
    optional address / domain, platform, safe and last-verified columns; leave blank if absent.

.PARAMETER Sources
    Which privileged lists to check: AD, Entra, Azure, AWS.

.EXAMPLE
    .\26-Compare-PamVaultCoverage.ps1 -PamExportCsv .\pam-accounts.csv -OutputRoot D:\Evidence
.EXAMPLE
    .\26-Compare-PamVaultCoverage.ps1 -PamExportCsv .\export.csv -PamAccountColumn 'Account Name' -PamAddressColumn 'Domain' -PamPlatformColumn 'Template' -PamSafeColumn 'Folder' -OutputRoot D:\Evidence

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x. Earlier runs of 02, 04, 11 and / or 17 in the evidence folder.
    Input   : the PAM export holds account names and vault structure only; never include passwords.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [Parameter(Mandatory)]
    [string]$PamExportCsv,
    [string]$EvidenceRoot = '',
    [string]$PamAccountColumn = 'UserName',
    [string]$PamAddressColumn = 'Address',
    [string]$PamPlatformColumn = 'PlatformId',
    [string]$PamSafeColumn = 'SafeName',
    [string]$PamLastVerifiedColumn = '',
    [ValidateSet('AD', 'Entra', 'Azure', 'AWS')]
    [string[]]$Sources = @('AD', 'Entra', 'Azure', 'AWS')
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '26-PamVaultCoverage'
$ScriptVersion = '1.0.0'

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

# ---- Script-specific helpers ----
function Get-NameKey {
    # Full key: lower-case, trimmed. Short key: also without DOMAIN\ prefix and @suffix.
    param([string]$Name)
    $full = $Name.Trim().ToLowerInvariant()
    $short = ($full -replace '^[^\\]+\\', '') -replace '@.*$', ''
    return [pscustomobject]@{ Full = $full; Short = $short }
}

function Get-LatestRunFile {
    param([string]$Root, [string]$Number, [string]$File)
    $run = Get-ChildItem -LiteralPath $Root -Directory -Filter "$Number-*" -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
        Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' -and (Test-Path -LiteralPath (Join-Path $_.FullName $File)) } |
        Sort-Object Name | Select-Object -Last 1
    if (-not $run) { return $null }
    return [pscustomobject]@{ RunFolder = $run.FullName; Path = (Join-Path $run.FullName $File) }
}

function Read-SourceCsv {
    param([string]$Path)
    if ((Get-Item -LiteralPath $Path).Length -lt 4) { return @() }
    return @(Import-Csv -LiteralPath $Path)
}

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if (-not $EvidenceRoot) { $EvidenceRoot = $OutputRoot }
    if (-not (Test-Path -LiteralPath $PamExportCsv)) { throw "PAM export not found: $PamExportCsv" }
    if (-not (Test-Path -LiteralPath $EvidenceRoot)) { throw "Evidence folder not found: $EvidenceRoot" }

    # ---- 1. PAM export ----
    $pam = @(Import-Csv -LiteralPath $PamExportCsv)
    $pamHash = (Get-FileHash -LiteralPath $PamExportCsv -Algorithm SHA256).Hash
    $cols = if ($pam.Count) { @($pam[0].PSObject.Properties.Name) } else { @() }
    if ($pam.Count -and $cols -notcontains $PamAccountColumn) { throw "PAM export has no column '$PamAccountColumn'. Columns: $($cols -join ', '). Map it with -PamAccountColumn." }
    $colOrBlank = { param($row, $col) if ($col -and $cols -contains $col) { [string]$row.$col } else { '' } }
    foreach ($c in @($PamAddressColumn, $PamPlatformColumn, $PamSafeColumn, $PamLastVerifiedColumn)) { if ($c -and $pam.Count -and $cols -notcontains $c) { Write-RunLog "PAM export has no column '$c'; it will be left blank." 'WARN' } }
    Write-RunLog ("PAM export: {0} entries (SHA-256 {1})" -f $pam.Count, $pamHash)

    $pamEntries = [System.Collections.Generic.List[object]]::new()
    $byFull = @{}; $byShort = @{}
    foreach ($row in $pam) {
        $acct = [string]$row.$PamAccountColumn
        if (-not $acct.Trim()) { continue }
        $k = Get-NameKey $acct
        $e = [pscustomobject]@{ Account = $acct; Address = (& $colOrBlank $row $PamAddressColumn); Platform = (& $colOrBlank $row $PamPlatformColumn)
            Safe = (& $colOrBlank $row $PamSafeColumn); LastVerified = (& $colOrBlank $row $PamLastVerifiedColumn); Key = $k; Matched = $false }
        $pamEntries.Add($e)
        if (-not $byFull.ContainsKey($k.Full)) { $byFull[$k.Full] = [System.Collections.Generic.List[object]]::new() }; $byFull[$k.Full].Add($e)
        if (-not $byShort.ContainsKey($k.Short)) { $byShort[$k.Short] = [System.Collections.Generic.List[object]]::new() }; $byShort[$k.Short].Add($e)
    }

    # ---- 2. Privileged accounts from earlier runs ----
    $sourceDefs = @(
        @{ Source = 'AD';    Number = '04'; File = 'ad-privileged-accounts.csv' }
        @{ Source = 'Entra'; Number = '02'; File = 'privileged-users.csv' }
        @{ Source = 'Azure'; Number = '11'; File = 'azure-role-assignments.csv' }
        @{ Source = 'AWS';   Number = '17'; File = 'aws-iam-users.csv' }
    )
    $sourceRows = [System.Collections.Generic.List[object]]::new()
    $privileged = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $sourceDefs) {
        if ($Sources -notcontains $d.Source) { $sourceRows.Add([pscustomobject][ordered]@{ Source = $d.Source; Script = $d.Number; Status = 'Skipped (-Sources)'; RunFolder = ''; File = $d.File; Sha256 = ''; Accounts = '' }); continue }
        $f = Get-LatestRunFile -Root $EvidenceRoot -Number $d.Number -File $d.File
        if (-not $f) {
            Write-RunLog ("{0}: no run of script {1} with {2} under {3}" -f $d.Source, $d.Number, $d.File, $EvidenceRoot) 'WARN'
            $sourceRows.Add([pscustomobject][ordered]@{ Source = $d.Source; Script = $d.Number; Status = 'Not run'; RunFolder = ''; File = $d.File; Sha256 = ''; Accounts = 0 }); continue
        }
        $rows = Read-SourceCsv $f.Path
        $before = $privileged.Count
        switch ($d.Source) {
            'AD' {
                foreach ($r in $rows) {
                    if (-not $r.SamAccountName) { continue }
                    $privileged.Add([pscustomobject]@{ Source = 'AD'; Account = [string]$r.SamAccountName; Tier0 = $true; Enabled = [string]$r.Enabled; Detail = [string]$r.PrivilegedVia; Keys = @((Get-NameKey $r.SamAccountName)) })
                }
            }
            'Entra' {
                foreach ($r in $rows) {
                    if (-not $r.UserPrincipalName) { continue }
                    $privileged.Add([pscustomobject]@{ Source = 'Entra'; Account = [string]$r.UserPrincipalName; Tier0 = ("$($r.HoldsTier0Role)" -eq 'True'); Enabled = [string]$r.AccountEnabled
                        Detail = ([string]$r.Roles + $(if ("$($r.SyncedFromOnPrem)" -eq 'True') { ' [synced from AD]' } else { '' })); Keys = @((Get-NameKey $r.UserPrincipalName)) })
                }
            }
            'Azure' {
                $users = @{}
                foreach ($r in ($rows | Where-Object { "$($_.IsPrivilegedRole)" -eq 'True' -and "$($_.PrincipalType)" -eq 'User' })) {
                    $name = if ($r.PrincipalUPN) { [string]$r.PrincipalUPN } else { [string]$r.PrincipalName }
                    if (-not $name) { continue }
                    if (-not $users.ContainsKey($name)) { $users[$name] = [pscustomobject]@{ Roles = [System.Collections.Generic.List[string]]::new(); Broad = $false } }
                    $users[$name].Roles.Add(("{0} at {1}" -f $r.RoleName, $r.ScopeLevel))
                    if ("$($r.Flags)" -match 'PrivilegedAtBroadScope') { $users[$name].Broad = $true }
                }
                foreach ($n in $users.Keys) { $privileged.Add([pscustomobject]@{ Source = 'Azure'; Account = $n; Tier0 = $users[$n].Broad; Enabled = ''; Detail = (($users[$n].Roles | Sort-Object -Unique) -join '; '); Keys = @((Get-NameKey $n)) }) }
            }
            'AWS' {
                foreach ($r in ($rows | Where-Object { "$($_.Flags)" -match 'AdminAccess' })) {
                    $privileged.Add([pscustomobject]@{ Source = 'AWS'; Account = ('{0} (account {1})' -f $r.UserName, $r.AccountId); Tier0 = $true; Enabled = ''; Detail = ("account {0}: {1}" -f $r.AccountId, $r.AttachedPolicies); Keys = @((Get-NameKey $r.UserName)); Hint = [string]$r.AccountId })
                }
            }
        }
        $sourceRows.Add([pscustomobject][ordered]@{ Source = $d.Source; Script = $d.Number; Status = 'Used'; RunFolder = $f.RunFolder; File = $d.File; Sha256 = (Get-FileHash -LiteralPath $f.Path -Algorithm SHA256).Hash; Accounts = ($privileged.Count - $before) })
        Write-RunLog ("{0}: {1} privileged accounts from {2}" -f $d.Source, ($privileged.Count - $before), $f.Path)
    }

    # ---- 3. Match ----
    $coverage = foreach ($p in $privileged) {
        $hits = @(); $method = ''
        foreach ($k in $p.Keys) { if ($byFull.ContainsKey($k.Full)) { $hits = @($byFull[$k.Full]); $method = 'Exact' } }
        if (-not $hits.Count) {
            foreach ($k in $p.Keys) { if ($k.Short -and $byShort.ContainsKey($k.Short)) { $hits = @($byShort[$k.Short]); $method = 'Name only (domain / suffix ignored)' } }
        }
        # Same name in several places (e.g. one IAM user name in two AWS accounts): prefer vault entries whose address carries the hint
        if ($hits.Count -and $p.PSObject.Properties['Hint'] -and $p.Hint) {
            $narrow = @($hits | Where-Object { $_.Address -and $_.Address -like "*$($p.Hint)*" })
            if ($narrow.Count) { $hits = $narrow; $method += ' + address' }
            elseif (@($hits | Where-Object { $_.Address }).Count) { $method += ' (address differs: check)' }
        }
        foreach ($h in $hits) { $h.Matched = $true }
        $first = $hits | Select-Object -First 1
        [pscustomobject][ordered]@{
            Source = $p.Source; Account = $p.Account; Tier0 = $p.Tier0; Enabled = $p.Enabled; Vaulted = ($hits.Count -gt 0)
            MatchMethod = $method; VaultEntries = $hits.Count
            PamAccount = $(if ($first) { $first.Account } else { '' }); PamAddress = $(if ($first) { $first.Address } else { '' })
            PamPlatform = $(if ($first) { $first.Platform } else { '' }); PamSafe = $(if ($first) { $first.Safe } else { '' })
            PamLastVerified = $(if ($first) { $first.LastVerified } else { '' })
            Flags = (@(
                    $(if (-not $hits.Count -and $p.Tier0 -and "$($p.Enabled)" -ne 'False') { 'Tier0NotVaulted' })
                    $(if (-not $hits.Count -and -not $p.Tier0 -and "$($p.Enabled)" -ne 'False') { 'NotVaulted' })
                    $(if ($method -like 'Name only*' -or $method -like '*address differs*') { 'CheckMatch' })
                    $(if ($hits.Count -gt 1) { 'MultipleVaultEntries' })
                    $(if ("$($p.Enabled)" -eq 'False') { 'Disabled' })
                ) | Where-Object { $_ }) -join '; '
            PrivilegedVia = $p.Detail
        }
    }
    $coverage = @($coverage | Sort-Object @{ Expression = 'Vaulted'; Descending = $false }, @{ Expression = 'Tier0'; Descending = $true }, Source, Account)
    Export-Dataset -Name 'privileged-vault-coverage' -Rows $coverage -Note 'One row per privileged account per source; the same person can appear under several sources'
    $unmatched = @($pamEntries | Where-Object { -not $_.Matched } | ForEach-Object {
            [pscustomobject][ordered]@{ PamAccount = $_.Account; PamAddress = $_.Address; PamPlatform = $_.Platform; PamSafe = $_.Safe; PamLastVerified = $_.LastVerified
                Note = 'Matches no privileged account: no longer privileged, renamed, deleted, a non-human or local account, or its source not run' } })
    Export-Dataset -Name 'pam-entries-unmatched' -Rows $unmatched
    Export-Dataset -Name 'source-runs' -Rows $sourceRows -Note 'Which earlier run each privileged list came from'

    # ---- 4. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'PAM vault entries' $pamEntries.Count
    foreach ($src in @('AD', 'Entra', 'Azure', 'AWS')) {
        $sr = $sourceRows | Where-Object Source -eq $src
        if ($sr.Status -ne 'Used') { Add-Metric "$src privileged accounts" '' $sr.Status; continue }
        $rows = @($coverage | Where-Object Source -eq $src)
        $enabled = @($rows | Where-Object { "$($_.Enabled)" -ne 'False' })
        $v = @($enabled | Where-Object Vaulted).Count
        Add-Metric "$src privileged accounts (enabled)" $enabled.Count
        Add-Metric "$src privileged accounts vaulted" $v $(if ($enabled.Count) { '{0}%' -f [math]::Round(100.0 * $v / $enabled.Count, 1) } else { '' })
    }
    Add-Metric 'Tier 0 accounts not vaulted (enabled)' @($coverage | Where-Object { $_.Flags -match 'Tier0NotVaulted' }).Count 'AD protected-group members, Entra Tier 0 roles, Azure broad-scope privileged roles, AWS admin users'
    Add-Metric 'Matches to check' @($coverage | Where-Object { $_.Flags -match 'CheckMatch' }).Count 'Name-only matches, or same name with a different address'
    Add-Metric 'Vault entries matching no privileged account' $unmatched.Count
    Add-Metric 'Sources not run' @($sourceRows | Where-Object Status -eq 'Not run').Count (($sourceRows | Where-Object Status -eq 'Not run' | ForEach-Object { "$($_.Source) (script $($_.Script))" }) -join ', ')
    Export-Dataset -Name 'summary' -Rows $summary
    $script:ManifestExtra = @{ PamExportFile = (Split-Path $PamExportCsv -Leaf); PamExportSha256 = $pamHash; EvidenceRoot = $EvidenceRoot }
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName '' -Parameters @{ PamExportCsv = (Split-Path $PamExportCsv -Leaf); EvidenceRoot = $EvidenceRoot; PamAccountColumn = $PamAccountColumn; PamAddressColumn = $PamAddressColumn; PamPlatformColumn = $PamPlatformColumn; PamSafeColumn = $PamSafeColumn; PamLastVerifiedColumn = $PamLastVerifiedColumn; Sources = $Sources }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
