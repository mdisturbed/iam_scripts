<#
.SYNOPSIS
    Read-only PAM vault coverage: which privileged accounts found by the other discovery scripts are
    managed in the privileged access management (PAM) vault, and which are not.

.DESCRIPTION
    Reconciles a PAM account export (any vault that exports CSV) against the privileged accounts
    found by earlier runs of the discovery scripts in the same evidence folder:

      - AD               04-ADPrivilegedAndServiceAccounts  ad-privileged-accounts.csv (protected-group members;
                                                            Tier 0 = Domain / Enterprise / Schema Admins or Administrators)
                                                            ad-admincount-orphans.csv (adminCount leftovers)
      - AD service acct  04-ADPrivilegedAndServiceAccounts  ad-service-account-candidates.csv (not already privileged)
      - AD delegation    18-ADDelegation                    ad-delegation-effective-users.csv (Tier 0 = Critical rights)
      - Entra            02-PrivilegedAccess                privileged-principals-effective.csv (users; preferred)
                                                            or privileged-users.csv (directory role holders)
      - Azure            11-AzureRbac                       azure-effective-users.csv (preferred) or
                                                            azure-role-assignments.csv + azure-eligible-assignments.csv
      - AWS              17-AwsIamPosture                   aws-effective-admins.csv (preferred) or aws-iam-users.csv

    The latest run of each is used; a source or file that hasn't been produced is reported
    (Not run / NotFound in source-runs), not guessed.

    Matching: account names are compared case-insensitively, first exactly (UPN or sAMAccountName),
    then by name only (DOMAIN\ prefix and @suffix removed). A name-only match is Vaulted =
    Unconfirmed, not True, because two systems can hold the same short name.

    Vault hygiene: PamLastVerified older than -VerifiedMaxDays is flagged VaultVerificationOld; with
    -PamLastChangedColumn, an AD password set more than a day after the vault's last change is
    flagged PasswordChangedOutsideVault.

    Datasets:
      - privileged-vault-coverage  one row per privileged account per source: source, Tier 0, enabled,
                                   vaulted (True / False / Unconfirmed), how it matched, and the
                                   matching vault entry (platform, safe)
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
    optional address / domain, platform, safe, last-verified and last-changed columns; leave blank if absent.

.PARAMETER Sources
    Which privileged lists to check: AD, ADServiceAccount, ADDelegation, Entra, Azure, AWS.

.PARAMETER VerifiedMaxDays
    PamLastVerified older than this many days is flagged VaultVerificationOld.

.EXAMPLE
    .\26-Compare-PamVaultCoverage.ps1 -PamExportCsv .\pam-accounts.csv -OutputRoot D:\Evidence
.EXAMPLE
    .\26-Compare-PamVaultCoverage.ps1 -PamExportCsv .\export.csv -PamAccountColumn 'Account Name' -PamAddressColumn 'Domain' -PamPlatformColumn 'Template' -PamSafeColumn 'Folder' -PamLastVerifiedColumn 'LastVerified' -PamLastChangedColumn 'LastChanged' -OutputRoot D:\Evidence

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x. Earlier runs of 02, 04, 11, 17 and / or 18 in the evidence folder.
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
    [string]$PamLastChangedColumn = '',
    [int]$VerifiedMaxDays = 90,
    [ValidateSet('AD', 'ADServiceAccount', 'ADDelegation', 'Entra', 'Azure', 'AWS')]
    [string[]]$Sources = @('AD', 'ADServiceAccount', 'ADDelegation', 'Entra', 'Azure', 'AWS'),
    [string[]]$AzurePrivilegedRoleNames = @('Owner', 'User Access Administrator', 'Role Based Access Control Administrator', 'Contributor',
        'Key Vault Administrator', 'Key Vault Secrets Officer', 'Key Vault Data Access Administrator', 'Storage Blob Data Owner', 'Storage Account Contributor',
        'Virtual Machine Administrator Login', 'Virtual Machine Contributor', 'Azure Kubernetes Service Cluster Admin Role', 'Azure Kubernetes Service RBAC Cluster Admin',
        'Managed Identity Operator')                     # used only for azure-eligible-assignments.csv, which has no IsPrivilegedRole column
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '26-PamVaultCoverage'
$ScriptVersion = '1.1.0'

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
    return [pscustomobject]@{ RunFolder = $run.FullName; Path = (Join-Path $run.FullName $File); RunName = $run.Name }
}

function Test-ScriptRan {
    # True when any run folder of script NN exists (used to tell 'Not run' from 'NotFound').
    param([string]$Root, [string]$Number)
    return [bool](@(Get-ChildItem -LiteralPath $Root -Directory -Filter "$Number-*" -ErrorAction SilentlyContinue |
                ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
                Where-Object { $_.Name -match '^\d{8}-\d{6}Z$' }).Count)
}

function Read-SourceCsv {
    param([string]$Path)
    if ((Get-Item -LiteralPath $Path).Length -lt 4) { return @() }
    return @(Import-Csv -LiteralPath $Path)
}

function Get-Col {
    # Column value or '' when the column does not exist in this file version.
    param($Row, [string]$Name)
    if ($Row.PSObject.Properties[$Name]) { return [string]$Row.$Name }
    return ''
}

function ConvertTo-DateOrNull {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $out = [datetime]::MinValue
    if ([datetime]::TryParse($Value.Trim(), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$out)) { return $out }
    return $null
}

function Test-AdTier0Via {
    # Tier 0 = membership (direct or nested) of Domain Admins, Enterprise Admins, Schema Admins or Administrators.
    param([string]$Via)
    foreach ($entry in ($Via -split ';\s*')) {
        $label = ($entry -replace '\s*\(nested:.*$', '').Trim()
        if ($label -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')) { return $true }
    }
    return $false
}

function Get-AzureScopeLevel {
    param([string]$Scope)
    if ($Scope -eq '/') { return 'Root' }
    if ($Scope -match '^/providers/Microsoft\.Management/managementGroups/[^/]+$') { return 'ManagementGroup' }
    if ($Scope -match '^/subscriptions/[^/]+$') { return 'Subscription' }
    if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 'ResourceGroup' }
    return 'Resource'
}

try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if (-not $EvidenceRoot) { $EvidenceRoot = $OutputRoot }
    if (-not (Test-Path -LiteralPath $PamExportCsv)) { throw "PAM export not found: $PamExportCsv" }
    if (-not (Test-Path -LiteralPath $EvidenceRoot)) { throw "Evidence folder not found: $EvidenceRoot" }
    $now = $script:RunStartUtc

    # ---- 1. PAM export ----
    $pam = @(Import-Csv -LiteralPath $PamExportCsv)
    $pamHash = (Get-FileHash -LiteralPath $PamExportCsv -Algorithm SHA256).Hash
    $cols = if ($pam.Count) { @($pam[0].PSObject.Properties.Name) } else { @() }
    if ($pam.Count -and $cols -notcontains $PamAccountColumn) { throw "PAM export has no column '$PamAccountColumn'. Columns: $($cols -join ', '). Map it with -PamAccountColumn." }
    $colOrBlank = { param($row, $col) if ($col -and $cols -contains $col) { [string]$row.$col } else { '' } }
    foreach ($c in @($PamAddressColumn, $PamPlatformColumn, $PamSafeColumn, $PamLastVerifiedColumn, $PamLastChangedColumn)) { if ($c -and $pam.Count -and $cols -notcontains $c) { Write-RunLog "PAM export has no column '$c'; it will be left blank." 'WARN' } }
    Write-RunLog ("PAM export: {0} entries (SHA-256 {1})" -f $pam.Count, $pamHash)

    $pamEntries = [System.Collections.Generic.List[object]]::new()
    $byFull = @{}; $byShort = @{}
    foreach ($row in $pam) {
        $acct = [string]$row.$PamAccountColumn
        if (-not $acct.Trim()) { continue }
        $k = Get-NameKey $acct
        $e = [pscustomobject]@{ Account = $acct; Address = (& $colOrBlank $row $PamAddressColumn); Platform = (& $colOrBlank $row $PamPlatformColumn)
            Safe = (& $colOrBlank $row $PamSafeColumn); LastVerified = (& $colOrBlank $row $PamLastVerifiedColumn); LastChanged = (& $colOrBlank $row $PamLastChangedColumn); Key = $k; Matched = $false }
        $pamEntries.Add($e)
        if (-not $byFull.ContainsKey($k.Full)) { $byFull[$k.Full] = [System.Collections.Generic.List[object]]::new() }; $byFull[$k.Full].Add($e)
        if (-not $byShort.ContainsKey($k.Short)) { $byShort[$k.Short] = [System.Collections.Generic.List[object]]::new() }; $byShort[$k.Short].Add($e)
    }

    # ---- 2. Privileged accounts from earlier runs ----
    $sourceRows = [System.Collections.Generic.List[object]]::new()
    $privileged = [System.Collections.Generic.List[object]]::new()
    function Add-Privileged {
        param([string]$Source, [string]$Account, [bool]$Tier0, [string]$Enabled, [string]$Detail, [string]$KeyName, [string]$Hint = '', $PwdLastSet = $null, [string]$File = '')
        $privileged.Add([pscustomobject]@{ Source = $Source; Account = $Account; Tier0 = $Tier0; Enabled = $Enabled; Detail = $Detail; Keys = @((Get-NameKey $KeyName)); Hint = $Hint; PwdLastSet = $PwdLastSet; File = $File })
    }
    function Add-SourceRun {
        param([string]$Source, [string]$Script, [string]$Status, $Found, [string]$File, $Accounts)
        $sourceRows.Add([pscustomobject][ordered]@{ Source = $Source; Script = $Script; Status = $Status
                RunFolder = $(if ($Found) { $Found.RunFolder } else { '' }); File = $File
                Sha256 = $(if ($Found -and $Status -like 'Used*') { (Get-FileHash -LiteralPath $Found.Path -Algorithm SHA256).Hash } else { '' }); Accounts = $Accounts })
        if ($Status -notlike 'Used*' -and $Status -notlike 'Skipped*') { Write-RunLog ("{0}: {1} {2} (script {3})" -f $Source, $File, $Status, $Script) 'WARN' }
    }
    function Find-SourceFile {
        # Returns the latest run file, or $null; Status is Not run (script never ran) or NotFound (ran, file absent).
        param([string]$Number, [string]$File)
        $f = Get-LatestRunFile -Root $EvidenceRoot -Number $Number -File $File
        $st = $(if ($f) { 'Found' } elseif (Test-ScriptRan -Root $EvidenceRoot -Number $Number) { 'NotFound' } else { 'Not run' })
        return [pscustomobject]@{ File = $f; Status = $st; Name = $File }
    }
    function Select-Preferred {
        # Picks the newer-format file when present and not older than the classic one.
        param($New, $Old)
        if ($New.File -and (-not $Old.File -or $New.File.RunName -ge $Old.File.RunName)) { return 'New' }
        if ($Old.File) { return 'Old' }
        return ''
    }
    $sourceLabels = @{ AD = 'AD'; ADServiceAccount = 'AD service account'; ADDelegation = 'AD delegation'; Entra = 'Entra'; Azure = 'Azure'; AWS = 'AWS' }
    $skipped = { param($s, $n, $files) foreach ($fn in $files) { Add-SourceRun -Source $sourceLabels[$s] -Script $n -Status 'Skipped (-Sources)' -Found $null -File $fn -Accounts '' } }
    $adSams = @{}

    # AD: privileged accounts + adminCount orphans (script 04)
    if ($Sources -notcontains 'AD') { & $skipped 'AD' '04' @('ad-privileged-accounts.csv', 'ad-admincount-orphans.csv') }
    else {
        $f = Find-SourceFile '04' 'ad-privileged-accounts.csv'
        if ($f.File) {
            $before = $privileged.Count
            foreach ($r in (Read-SourceCsv $f.File.Path)) {
                if (-not $r.SamAccountName) { continue }
                $tierCol = Get-Col $r 'Tier'
                $t0 = $(if ($tierCol) { $tierCol -eq 'Tier0' } else { Test-AdTier0Via ([string]$r.PrivilegedVia) })
                Add-Privileged -Source 'AD' -Account $r.SamAccountName -Tier0 $t0 -Enabled ([string]$r.Enabled) -Detail ([string]$r.PrivilegedVia) -KeyName $r.SamAccountName -PwdLastSet (ConvertTo-DateOrNull (Get-Col $r 'PasswordLastSetUtc')) -File $f.Name
                $adSams[([string]$r.SamAccountName).ToLowerInvariant()] = $true
            }
            Add-SourceRun -Source 'AD' -Script '04' -Status 'Used' -Found $f.File -File $f.Name -Accounts ($privileged.Count - $before)
        }
        else { Add-SourceRun -Source 'AD' -Script '04' -Status $f.Status -Found $null -File $f.Name -Accounts 0 }
        $f = Find-SourceFile '04' 'ad-admincount-orphans.csv'
        if ($f.File) {
            $before = $privileged.Count
            foreach ($r in (Read-SourceCsv $f.File.Path)) {
                if (-not $r.SamAccountName -or $adSams.ContainsKey(([string]$r.SamAccountName).ToLowerInvariant())) { continue }
                Add-Privileged -Source 'AD' -Account $r.SamAccountName -Tier0 $false -Enabled ([string]$r.Enabled) -Detail 'adminCount orphan' -KeyName $r.SamAccountName -PwdLastSet (ConvertTo-DateOrNull (Get-Col $r 'PasswordLastSetUtc')) -File $f.Name
                $adSams[([string]$r.SamAccountName).ToLowerInvariant()] = $true
            }
            Add-SourceRun -Source 'AD' -Script '04' -Status 'Used' -Found $f.File -File $f.Name -Accounts ($privileged.Count - $before)
        }
        else { Add-SourceRun -Source 'AD' -Script '04' -Status $f.Status -Found $null -File $f.Name -Accounts 0 }
    }

    # AD service account candidates (script 04), not already listed as privileged
    if ($Sources -notcontains 'ADServiceAccount') { & $skipped 'ADServiceAccount' '04' @('ad-service-account-candidates.csv') }
    else {
        $f = Find-SourceFile '04' 'ad-service-account-candidates.csv'
        if ($f.File) {
            $before = $privileged.Count
            foreach ($r in (Read-SourceCsv $f.File.Path)) {
                if (-not $r.SamAccountName -or $adSams.ContainsKey(([string]$r.SamAccountName).ToLowerInvariant())) { continue }
                Add-Privileged -Source 'AD service account' -Account $r.SamAccountName -Tier0 $false -Enabled ([string]$r.Enabled) -Detail ('Service account candidate: ' + (Get-Col $r 'DetectionReasons')) -KeyName $r.SamAccountName -PwdLastSet (ConvertTo-DateOrNull (Get-Col $r 'PasswordLastSetUtc')) -File $f.Name
            }
            Add-SourceRun -Source 'AD service account' -Script '04' -Status 'Used' -Found $f.File -File $f.Name -Accounts ($privileged.Count - $before)
        }
        else { Add-SourceRun -Source 'AD service account' -Script '04' -Status $f.Status -Found $null -File $f.Name -Accounts 0 }
    }

    # AD delegation: every user holding delegated rights (script 18)
    if ($Sources -notcontains 'ADDelegation') { & $skipped 'ADDelegation' '18' @('ad-delegation-effective-users.csv') }
    else {
        $f = Find-SourceFile '18' 'ad-delegation-effective-users.csv'
        if ($f.File) {
            $before = $privileged.Count
            foreach ($r in (Read-SourceCsv $f.File.Path)) {
                if (-not $r.SamAccountName) { continue }
                $sev = Get-Col $r 'HighestSeverity'
                Add-Privileged -Source 'AD delegation' -Account $r.SamAccountName -Tier0 ($sev -eq 'Critical') -Enabled ([string]$r.Enabled) -Detail ("{0} rights: {1} via {2}" -f $sev, (Get-Col $r 'Rights'), (Get-Col $r 'Via')) -KeyName $r.SamAccountName -File $f.Name
            }
            Add-SourceRun -Source 'AD delegation' -Script '18' -Status 'Used' -Found $f.File -File $f.Name -Accounts ($privileged.Count - $before)
        }
        else { Add-SourceRun -Source 'AD delegation' -Script '18' -Status $f.Status -Found $null -File $f.Name -Accounts 0 }
    }

    # Entra (script 02): effective principals preferred, classic privileged-users otherwise
    if ($Sources -notcontains 'Entra') { & $skipped 'Entra' '02' @('privileged-principals-effective.csv', 'privileged-users.csv') }
    else {
        $new = Find-SourceFile '02' 'privileged-principals-effective.csv'
        $old = Find-SourceFile '02' 'privileged-users.csv'
        $pick = Select-Preferred $new $old
        $before = $privileged.Count
        if ($pick -eq 'New') {
            $users = [ordered]@{}
            foreach ($r in (Read-SourceCsv $new.File.Path)) {
                if ((Get-Col $r 'PrincipalType') -ne 'user') { continue }
                $name = $(if ($r.Upn) { [string]$r.Upn } else { [string]$r.PrincipalName })
                if (-not $name) { continue }
                if (-not $users.Contains($name)) { $users[$name] = [pscustomobject]@{ Tier0 = $false; Enabled = (Get-Col $r 'AccountEnabled'); Roles = [System.Collections.Generic.List[string]]::new() } }
                if ((Get-Col $r 'Tier0') -eq 'True') { $users[$name].Tier0 = $true }
                $via = Get-Col $r 'ViaGroup'
                $lbl = '{0} [{1}]{2}' -f (Get-Col $r 'Role'), (Get-Col $r 'AssignmentState'), $(if ($via) { " [via group $via]" } else { '' })
                if (-not $users[$name].Roles.Contains($lbl)) { $users[$name].Roles.Add($lbl) }
            }
            foreach ($n in $users.Keys) { Add-Privileged -Source 'Entra' -Account $n -Tier0 $users[$n].Tier0 -Enabled $users[$n].Enabled -Detail (($users[$n].Roles | Sort-Object) -join '; ') -KeyName $n -File $new.Name }
            Add-SourceRun -Source 'Entra' -Script '02' -Status 'Used' -Found $new.File -File $new.Name -Accounts ($privileged.Count - $before)
            Add-SourceRun -Source 'Entra' -Script '02' -Status $(if ($old.File) { 'Skipped (newer file used)' } else { $old.Status }) -Found $old.File -File $old.Name -Accounts ''
        }
        elseif ($pick -eq 'Old') {
            foreach ($r in (Read-SourceCsv $old.File.Path)) {
                if (-not $r.UserPrincipalName) { continue }
                Add-Privileged -Source 'Entra' -Account $r.UserPrincipalName -Tier0 ("$($r.HoldsTier0Role)" -eq 'True') -Enabled ([string]$r.AccountEnabled) -Detail ([string]$r.Roles + $(if ("$($r.SyncedFromOnPrem)" -eq 'True') { ' [synced from AD]' } else { '' })) -KeyName $r.UserPrincipalName -File $old.Name
            }
            Add-SourceRun -Source 'Entra' -Script '02' -Status $(if ($new.File) { 'Skipped (older run)' } else { $new.Status }) -Found $new.File -File $new.Name -Accounts ''
            Add-SourceRun -Source 'Entra' -Script '02' -Status 'Used' -Found $old.File -File $old.Name -Accounts ($privileged.Count - $before)
        }
        else {
            Add-SourceRun -Source 'Entra' -Script '02' -Status $new.Status -Found $null -File $new.Name -Accounts 0
            Add-SourceRun -Source 'Entra' -Script '02' -Status $old.Status -Found $null -File $old.Name -Accounts 0
        }
    }

    # Azure (script 11): effective users preferred; else direct assignments + eligible assignments
    if ($Sources -notcontains 'Azure') { & $skipped 'Azure' '11' @('azure-effective-users.csv', 'azure-role-assignments.csv', 'azure-eligible-assignments.csv') }
    else {
        $new = Find-SourceFile '11' 'azure-effective-users.csv'
        $old = Find-SourceFile '11' 'azure-role-assignments.csv'
        $elig = Find-SourceFile '11' 'azure-eligible-assignments.csv'
        $pick = Select-Preferred $new $old
        $users = [ordered]@{}
        function Add-AzureRole { param([string]$Name, [string]$Label, [bool]$Broad) if (-not $users.Contains($Name)) { $users[$Name] = [pscustomobject]@{ Roles = [System.Collections.Generic.List[string]]::new(); Broad = $false } }; if (-not $users[$Name].Roles.Contains($Label)) { $users[$Name].Roles.Add($Label) }; if ($Broad) { $users[$Name].Broad = $true } }
        $before = $privileged.Count
        if ($pick -eq 'New') {
            foreach ($r in (Read-SourceCsv $new.File.Path)) {
                if ((Get-Col $r 'IsPrivilegedRole') -ne 'True') { continue }
                $pt = Get-Col $r 'PrincipalType'
                if ($pt -and $pt -ne 'User') { continue }
                $name = Get-Col $r 'Upn'
                if (-not $name) { continue }
                $lvl = Get-AzureScopeLevel (Get-Col $r 'Scope')
                $via = Get-Col $r 'ViaGroup'
                Add-AzureRole -Name $name -Label ('{0} at {1} ({2}{3})' -f (Get-Col $r 'RoleName'), $lvl, (Get-Col $r 'AssignmentState'), $(if ($via) { ", via group $via" } else { '' })) -Broad ($lvl -in @('Root', 'ManagementGroup', 'Subscription'))
            }
            foreach ($n in $users.Keys) { Add-Privileged -Source 'Azure' -Account $n -Tier0 $users[$n].Broad -Enabled '' -Detail (($users[$n].Roles | Sort-Object) -join '; ') -KeyName $n -File $new.Name }
            Add-SourceRun -Source 'Azure' -Script '11' -Status 'Used' -Found $new.File -File $new.Name -Accounts ($privileged.Count - $before)
            foreach ($o in @($old, $elig)) { Add-SourceRun -Source 'Azure' -Script '11' -Status $(if ($o.File) { 'Skipped (newer file used)' } else { $o.Status }) -Found $o.File -File $o.Name -Accounts '' }
        }
        elseif ($pick -eq 'Old') {
            foreach ($r in (Read-SourceCsv $old.File.Path | Where-Object { "$($_.IsPrivilegedRole)" -eq 'True' -and "$($_.PrincipalType)" -eq 'User' })) {
                $name = $(if ($r.PrincipalUPN) { [string]$r.PrincipalUPN } else { [string]$r.PrincipalName })
                if (-not $name) { continue }
                Add-AzureRole -Name $name -Label ('{0} at {1}' -f $r.RoleName, $r.ScopeLevel) -Broad ("$($r.Flags)" -match 'PrivilegedAtBroadScope')
            }
            $fromOld = $users.Count
            Add-SourceRun -Source 'Azure' -Script '11' -Status $(if ($new.File) { 'Skipped (older run)' } else { $new.Status }) -Found $new.File -File $new.Name -Accounts ''
            if ($elig.File) {
                foreach ($r in (Read-SourceCsv $elig.File.Path | Where-Object { "$($_.PrincipalType)" -eq 'User' -and $AzurePrivilegedRoleNames -contains "$($_.RoleName)" })) {
                    $name = $(if ($r.PrincipalUPN) { [string]$r.PrincipalUPN } else { [string]$r.PrincipalName })
                    if (-not $name) { continue }
                    $lvl = $(if ($r.ScopeLevel) { [string]$r.ScopeLevel } else { Get-AzureScopeLevel ([string]$r.Scope) })
                    Add-AzureRole -Name $name -Label ('{0} at {1} (eligible)' -f $r.RoleName, $lvl) -Broad ($lvl -in @('Root', 'ManagementGroup', 'Subscription'))
                }
            }
            foreach ($n in $users.Keys) { Add-Privileged -Source 'Azure' -Account $n -Tier0 $users[$n].Broad -Enabled '' -Detail (($users[$n].Roles | Sort-Object) -join '; ') -KeyName $n -File $old.Name }
            Add-SourceRun -Source 'Azure' -Script '11' -Status 'Used' -Found $old.File -File $old.Name -Accounts $fromOld
            Add-SourceRun -Source 'Azure' -Script '11' -Status $(if ($elig.File) { 'Used' } else { $elig.Status }) -Found $elig.File -File $elig.Name -Accounts $(if ($elig.File) { $users.Count - $fromOld } else { 0 })
        }
        else { foreach ($o in @($new, $old, $elig)) { Add-SourceRun -Source 'Azure' -Script '11' -Status $o.Status -Found $null -File $o.Name -Accounts 0 } }
    }

    # AWS (script 17): effective admins preferred, else IAM users with admin-level policies
    if ($Sources -notcontains 'AWS') { & $skipped 'AWS' '17' @('aws-effective-admins.csv', 'aws-iam-users.csv') }
    else {
        $new = Find-SourceFile '17' 'aws-effective-admins.csv'
        $old = Find-SourceFile '17' 'aws-iam-users.csv'
        $pick = Select-Preferred $new $old
        $before = $privileged.Count
        if ($pick -eq 'New') {
            $seen = [ordered]@{}
            foreach ($r in (Read-SourceCsv $new.File.Path)) {
                $pn = Get-Col $r 'PrincipalName'; $acct = Get-Col $r 'AccountId'
                if (-not $pn) { continue }
                $k = "$acct|$pn"
                if (-not $seen.Contains($k)) { $seen[$k] = [pscustomobject]@{ Name = $pn; Account = $acct; Type = (Get-Col $r 'PrincipalType'); Via = [System.Collections.Generic.List[string]]::new() } }
                $v = ('{0}: {1}' -f (Get-Col $r 'Via'), (Get-Col $r 'Evidence')).Trim(': ')
                if ($v -and -not $seen[$k].Via.Contains($v)) { $seen[$k].Via.Add($v) }
            }
            foreach ($k in $seen.Keys) { $x = $seen[$k]; Add-Privileged -Source 'AWS' -Account ('{0} (account {1})' -f $x.Name, $x.Account) -Tier0 $true -Enabled '' -Detail ("{0} in account {1}: {2}" -f $x.Type, $x.Account, ($x.Via -join '; ')) -KeyName $x.Name -Hint $x.Account -File $new.Name }
            Add-SourceRun -Source 'AWS' -Script '17' -Status 'Used' -Found $new.File -File $new.Name -Accounts ($privileged.Count - $before)
            Add-SourceRun -Source 'AWS' -Script '17' -Status $(if ($old.File) { 'Skipped (newer file used)' } else { $old.Status }) -Found $old.File -File $old.Name -Accounts ''
        }
        elseif ($pick -eq 'Old') {
            foreach ($r in (Read-SourceCsv $old.File.Path | Where-Object { "$($_.Flags)" -match 'AdminAccess' })) {
                Add-Privileged -Source 'AWS' -Account ('{0} (account {1})' -f $r.UserName, $r.AccountId) -Tier0 $true -Enabled '' -Detail ("account {0}: {1}" -f $r.AccountId, $r.AttachedPolicies) -KeyName $r.UserName -Hint ([string]$r.AccountId) -File $old.Name
            }
            Add-SourceRun -Source 'AWS' -Script '17' -Status $(if ($new.File) { 'Skipped (older run)' } else { $new.Status }) -Found $new.File -File $new.Name -Accounts ''
            Add-SourceRun -Source 'AWS' -Script '17' -Status 'Used' -Found $old.File -File $old.Name -Accounts ($privileged.Count - $before)
        }
        else { foreach ($o in @($new, $old)) { Add-SourceRun -Source 'AWS' -Script '17' -Status $o.Status -Found $null -File $o.Name -Accounts 0 } }
    }
    foreach ($s in @($sourceLabels.Values)) { $n = @($privileged | Where-Object Source -eq $s).Count; if ($n) { Write-RunLog ("{0}: {1} privileged accounts" -f $s, $n) } }

    # ---- 3. Match ----
    $coverage = foreach ($p in $privileged) {
        $hits = @(); $method = ''; $vaulted = 'False'
        foreach ($k in $p.Keys) { if ($byFull.ContainsKey($k.Full)) { $hits = @($byFull[$k.Full]); $method = 'Exact'; $vaulted = 'True' } }
        if (-not $hits.Count) {
            foreach ($k in $p.Keys) { if ($k.Short -and $byShort.ContainsKey($k.Short)) { $hits = @($byShort[$k.Short]); $method = 'Name only (domain / suffix ignored)'; $vaulted = 'Unconfirmed' } }
        }
        # Same name in several places (e.g. one IAM user name in two AWS accounts): prefer vault entries whose address carries the hint
        if ($hits.Count -and $p.Hint) {
            $narrow = @($hits | Where-Object { $_.Address -and $_.Address -like "*$($p.Hint)*" })
            if ($narrow.Count) { $hits = $narrow; $method += ' + address' }
            elseif (@($hits | Where-Object { $_.Address }).Count) { $method += ' (address differs: check)'; $vaulted = 'Unconfirmed' }
        }
        foreach ($h in $hits) { $h.Matched = $true }
        $first = $hits | Select-Object -First 1
        $verified = $(if ($first) { ConvertTo-DateOrNull $first.LastVerified } else { $null })
        $changed = $(if ($first) { ConvertTo-DateOrNull $first.LastChanged } else { $null })
        [pscustomobject][ordered]@{
            Source = $p.Source; Account = $p.Account; Tier0 = $p.Tier0; Enabled = $p.Enabled; Vaulted = $vaulted
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
                    $(if ($first -and $PamLastVerifiedColumn -and -not $first.LastVerified) { 'VaultNeverVerified' })
                    $(if ($verified -and ($now - $verified).TotalDays -gt $VerifiedMaxDays) { "VaultVerificationOld(>${VerifiedMaxDays}d)" })
                    $(if ($changed -and $p.PwdLastSet -and ($p.PwdLastSet - $changed).TotalDays -gt 1) { 'PasswordChangedOutsideVault' })
                ) | Where-Object { $_ }) -join '; '
            PrivilegedVia = $p.Detail
            PamLastChanged = $(if ($first) { $first.LastChanged } else { '' })
            PwdLastSetUtc = $(if ($p.PwdLastSet) { $p.PwdLastSet.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            SourceFile = $p.File
        }
    }
    $vOrder = @{ 'False' = 0; 'Unconfirmed' = 1; 'True' = 2 }
    $coverage = @($coverage | Sort-Object @{ Expression = { $vOrder[$_.Vaulted] } }, @{ Expression = 'Tier0'; Descending = $true }, Source, Account)
    Export-Dataset -Name 'privileged-vault-coverage' -Rows $coverage -Note 'One row per privileged account per source; the same person can appear under several sources. Vaulted = Unconfirmed: name-only match, check it'
    $unmatched = @($pamEntries | Where-Object { -not $_.Matched } | ForEach-Object {
            [pscustomobject][ordered]@{ PamAccount = $_.Account; PamAddress = $_.Address; PamPlatform = $_.Platform; PamSafe = $_.Safe; PamLastVerified = $_.LastVerified
                Note = 'Matches no privileged account: no longer privileged, renamed, deleted, a non-human or local account, or its source not run' } })
    Export-Dataset -Name 'pam-entries-unmatched' -Rows $unmatched
    Export-Dataset -Name 'source-runs' -Rows $sourceRows -Note 'Which earlier run and file each privileged list came from. Not run = script never ran here; NotFound = script ran but did not write this file'

    # ---- 4. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'PAM vault entries' $pamEntries.Count
    foreach ($key in @('AD', 'ADServiceAccount', 'ADDelegation', 'Entra', 'Azure', 'AWS')) {
        $src = $sourceLabels[$key]
        $sr = @($sourceRows | Where-Object Source -eq $src)
        if (-not @($sr | Where-Object { $_.Status -eq 'Used' }).Count) { Add-Metric -Metric "$src privileged accounts" -Value '' -Note (Join-Values ($sr | ForEach-Object { "$($_.File): $($_.Status)" })); continue }
        $rows = @($coverage | Where-Object Source -eq $src)
        $enabled = @($rows | Where-Object { "$($_.Enabled)" -ne 'False' })
        $v = @($enabled | Where-Object { $_.Vaulted -eq 'True' }).Count
        $u = @($enabled | Where-Object { $_.Vaulted -eq 'Unconfirmed' }).Count
        Add-Metric -Metric "$src privileged accounts (enabled)" -Value $enabled.Count -Note (Join-Values ($sr | Where-Object { $_.Status -eq 'Used' } | ForEach-Object { $_.File }))
        Add-Metric -Metric "$src privileged accounts vaulted" -Value $v -Note $(if ($enabled.Count) { '{0}% ({1} more unconfirmed)' -f [math]::Round(100.0 * $v / $enabled.Count, 1), $u } else { '' })
    }
    Add-Metric -Metric 'Tier 0 accounts not vaulted (enabled)' -Value @($coverage | Where-Object { $_.Flags -match 'Tier0NotVaulted' }).Count -Note 'AD Domain / Enterprise / Schema Admins and Administrators, AD Critical delegations, Entra Tier 0 roles, Azure broad-scope privileged roles, AWS admins'
    Add-Metric -Metric 'Unconfirmed (name-only) matches' -Value @($coverage | Where-Object { $_.Vaulted -eq 'Unconfirmed' }).Count -Note 'Not counted as vaulted'
    Add-Metric -Metric 'Matches to check' -Value @($coverage | Where-Object { $_.Flags -match 'CheckMatch' }).Count -Note 'Name-only matches, or same name with a different address'
    if ($PamLastVerifiedColumn) { Add-Metric "Vaulted accounts not verified in $VerifiedMaxDays days" @($coverage | Where-Object { $_.Flags -match 'VaultVerificationOld|VaultNeverVerified' }).Count }
    if ($PamLastChangedColumn) { Add-Metric -Metric 'AD passwords changed outside the vault' -Value @($coverage | Where-Object { $_.Flags -match 'PasswordChangedOutsideVault' }).Count -Note 'AD pwdLastSet more than a day after the vault last changed it' }
    Add-Metric 'Vault entries matching no privileged account' $unmatched.Count
    $missing = @($sourceRows | Where-Object { $_.Status -in @('Not run', 'NotFound') })
    Add-Metric -Metric 'Source files not run / not found' -Value $missing.Count -Note (($missing | ForEach-Object { "$($_.File) (script $($_.Script)): $($_.Status)" }) -join ', ')
    Export-Dataset -Name 'summary' -Rows $summary
    $script:ManifestExtra = @{ PamExportFile = (Split-Path $PamExportCsv -Leaf); PamExportSha256 = $pamHash; EvidenceRoot = $EvidenceRoot }
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName '' -Parameters @{ PamExportCsv = (Split-Path $PamExportCsv -Leaf); EvidenceRoot = $EvidenceRoot; PamAccountColumn = $PamAccountColumn; PamAddressColumn = $PamAddressColumn; PamPlatformColumn = $PamPlatformColumn; PamSafeColumn = $PamSafeColumn; PamLastVerifiedColumn = $PamLastVerifiedColumn; PamLastChangedColumn = $PamLastChangedColumn; VerifiedMaxDays = $VerifiedMaxDays; Sources = $Sources }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
