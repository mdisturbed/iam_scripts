<#
.SYNOPSIS
    Read-only comparison of HR lifecycle dates against AD (and optionally Entra) account state.

.DESCRIPTION
    Measures how well joiner/leaver processing tracks HR:
      - Joiner lag: account created vs HR hire date (negative = created before start, i.e. pre-provisioned)
      - Leaver lag: account disabled vs HR termination date (disable time approximated from the
        replication metadata of userAccountControl - the last time that attribute changed)
      - Terminated in HR but still ENABLED in AD
      - Logon / sign-in AFTER the termination date (AD lastLogonTimestamp, optional Entra signInActivity)
      - Active in HR with no AD account
      - Enabled AD users with no HR match (orphan candidates)
      - Summary: counts, median / 90th percentile / max lags, % disabled within the SLA

    INPUT: an HR export CSV that YOU supply (from the HR system of record). Column names are configurable.
    The HR file contains personal data - handle and store it per your data-handling rules.

    READ-ONLY. Uses only Get-AD* cmdlets and (optionally) Graph GET requests.

    Output: <OutputRoot>\06-JmlTiming\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\06-Compare-JmlTiming.ps1 -HrCsvPath .\hr-export.csv
.EXAMPLE
    .\06-Compare-JmlTiming.ps1 -HrCsvPath .\hr-export.csv -HrDateFormat 'MM/dd/yyyy' -TerminatedStatusValues 'Terminated','T' -IncludeEntraSignIn

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module.
              -IncludeEntraSignIn also needs Microsoft.Graph.Authentication and scopes
              User.Read.All + AuditLog.Read.All (Entra ID P1 for signInActivity).
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [Parameter(Mandatory)]
    [string]$HrCsvPath,
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                               # OU holding people accounts (blank = whole domain)

    # HR column mapping
    [string]$HrIdColumn = 'EmployeeId',
    [string]$HrStatusColumn = 'EmploymentStatus',
    [string]$HrHireDateColumn = 'HireDate',
    [string]$HrTermDateColumn = 'TerminationDate',
    [string]$HrDateFormat = '',                             # e.g. 'yyyy-MM-dd' or 'MM/dd/yyyy'; blank = invariant parse
    [string[]]$TerminatedStatusValues = @('Terminated', 'Inactive'),

    # Matching
    [string]$AdMatchAttribute = 'employeeID',               # AD attribute holding the HR id
    [string[]]$ExcludeNamePatterns = @('svc*', 'sa-*', 'sa_*', 'adm*', '*admin*', 'test*'),

    # Thresholds
    [int]$LeaverSlaDays = 1,
    [switch]$SkipDisableTimestamp,                          # skip per-user replication metadata (faster)

    # Optional Entra sign-in check
    [switch]$IncludeEntraSignIn,
    [ValidateSet('Delegated', 'AppCertificate')]
    [string]$AuthMode = 'Delegated',
    [string]$TenantId = 'tenant-id-redacted',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = ''
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '06-JmlTiming'
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
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $script:RunFolder 'run-manifest.json') -Encoding UTF8
    $script:Datasets | Export-Csv -Path (Join-Path $script:RunFolder 'dataset-status.csv') -NoTypeInformation -Encoding UTF8
}

function Join-Values { param($Values) if ($null -eq $Values) { return '' } return (@($Values) | Where-Object { $null -ne $_ -and "$_" -ne '' }) -join '; ' }

# Splat for every AD cmdlet so -Server is honoured consistently.
$script:AdParams = @{}
if ($Server) { $script:AdParams['Server'] = $Server }
#endregion

function ConvertTo-HrDate {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $out = [datetime]::MinValue
    if ($HrDateFormat) {
        if ([datetime]::TryParseExact($Value.Trim(), $HrDateFormat, $inv, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$out)) { return $out }
    }
    elseif ([datetime]::TryParse($Value.Trim(), $inv, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$out)) { return $out }
    $script:DateParseErrors++
    return $null
}

function Get-Percentile {
    param([double[]]$Values, [double]$P)
    $v = @($Values | Sort-Object)
    if ($v.Count -eq 0) { return '' }
    $rank = [math]::Ceiling(($P / 100) * $v.Count) - 1
    return $v[[math]::Max(0, [int]$rank)]
}

function Invoke-GraphGetLite {
    # GET-only Graph helper used for the optional Entra check.
    param([string]$Uri)
    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $attempt = 0; $resp = $null
        while (-not $resp) {
            try { $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop }
            catch {
                $attempt++; $status = $null; try { $status = [int]$_.Exception.Response.StatusCode } catch { }
                if (($status -eq 429 -or $status -ge 500) -and $attempt -le 6) { Start-Sleep -Seconds ([int][math]::Min(120, [math]::Pow(2, $attempt))) } else { throw }
            }
        }
        foreach ($i in @($resp.value)) { if ($null -ne $i) { $results.Add($i) } }
        $next = $null
        if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $next = $resp.'@odata.nextLink' }
    }
    return , $results
}

$domainName = ''
$script:DateParseErrors = 0
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot
    $now = $script:RunStartUtc

    # ---- HR input ----
    if (-not (Test-Path $HrCsvPath)) { throw "HR file not found: $HrCsvPath" }
    $hr = @(Import-Csv -Path $HrCsvPath)
    foreach ($col in @($HrIdColumn, $HrStatusColumn, $HrHireDateColumn, $HrTermDateColumn)) {
        if ($hr.Count -and -not ($hr[0].PSObject.Properties.Name -contains $col)) { throw "HR file has no column '$col'. Columns found: $($hr[0].PSObject.Properties.Name -join ', ')" }
    }
    $hrHash = (Get-FileHash -Path $HrCsvPath -Algorithm SHA256).Hash
    Write-RunLog ("HR file: {0} rows, SHA256 {1}" -f $hr.Count, $hrHash)
    $hrById = @{}
    foreach ($h in $hr) {
        $id = "$($h.$HrIdColumn)".Trim()
        if (-not $id) { continue }
        if ($hrById.ContainsKey($id)) { Write-RunLog ("Duplicate HR id {0}; keeping the row with the latest hire date." -f $id) 'WARN' }
        $rec = [pscustomobject]@{
            Id = $id
            Status = "$($h.$HrStatusColumn)".Trim()
            Hire = ConvertTo-HrDate $h.$HrHireDateColumn
            Term = ConvertTo-HrDate $h.$HrTermDateColumn
        }
        $rec | Add-Member -NotePropertyName IsTerminated -NotePropertyValue (($TerminatedStatusValues -contains $rec.Status) -or ($rec.Term -and $rec.Term -le $now.ToLocalTime()))
        if (-not $hrById.ContainsKey($id) -or ($rec.Hire -and $hrById[$id].Hire -and $rec.Hire -gt $hrById[$id].Hire)) { $hrById[$id] = $rec }
    }

    # ---- AD users ----
    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    $props = @('sAMAccountName', 'userPrincipalName', 'enabled', 'whenCreated', 'lastLogonTimestamp', 'objectGUID', $AdMatchAttribute)
    $adUsers = @(Get-ADUser -Filter * -Properties $props @p)
    Write-RunLog ("{0} AD user accounts read" -f $adUsers.Count)
    $adById = @{}
    foreach ($u in $adUsers) {
        $id = "$($u.$AdMatchAttribute)".Trim()
        if ($id) {
            if (-not $adById.ContainsKey($id)) { $adById[$id] = [System.Collections.Generic.List[object]]::new() }
            $adById[$id].Add($u)
        }
    }

    # ---- Optional Entra sign-in data ----
    $entraByGuid = @{}
    $entraStatus = 'Deferred'
    if ($IncludeEntraSignIn) {
        try {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            if ($AuthMode -eq 'AppCertificate') { Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop }
            else {
                $c = @{ Scopes = @('User.Read.All', 'AuditLog.Read.All'); NoWelcome = $true; ErrorAction = 'Stop' }
                if ($TenantId -and $TenantId -ne 'tenant-id-redacted') { $c.TenantId = $TenantId }
                Connect-MgGraph @c
            }
            $eu = Invoke-GraphGetLite 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,accountEnabled,onPremisesImmutableId,signInActivity&$top=999'
            foreach ($x in $eu) { if ($x.onPremisesImmutableId) { $entraByGuid[$x.onPremisesImmutableId] = $x } }
            $entraStatus = 'Completed'
            Write-RunLog ("Entra: {0} synced users with sign-in data" -f $entraByGuid.Count)
        }
        catch { $entraStatus = 'Blocked'; Write-RunLog ("Entra sign-in check unavailable: {0}" -f $_.Exception.Message) 'WARN' }
    }

    # ---- 1. Matched people ----
    $matched = [System.Collections.Generic.List[object]]::new()
    $hrNoAccount = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $hrById.Keys) {
        $h = $hrById[$id]
        if (-not $adById.ContainsKey($id)) {
            if (-not $h.IsTerminated) { $hrNoAccount.Add([pscustomobject][ordered]@{ HrId = $id; HrStatus = $h.Status; HireDate = $(if ($h.Hire) { $h.Hire.ToString('yyyy-MM-dd') } else { '' }); Note = 'Active in HR, no AD account with matching ' + $AdMatchAttribute }) }
            continue
        }
        foreach ($u in $adById[$id]) {
            $created = $(if ($u.whenCreated) { ([datetime]$u.whenCreated).ToUniversalTime() } else { $null })
            $lastLogon = $(if ($u.lastLogonTimestamp) { [datetime]::FromFileTimeUtc([int64]$u.lastLogonTimestamp) } else { $null })
            $disabledAt = $null
            if (-not $u.Enabled -and -not $SkipDisableTimestamp) {
                try {
                    $md = Get-ADReplicationAttributeMetadata -Object $u.DistinguishedName -Properties userAccountControl @script:AdParams | Select-Object -First 1
                    if ($md) { $disabledAt = ([datetime]$md.LastOriginatingChangeTime).ToUniversalTime() }
                }
                catch { }
            }
            $termUtc = $(if ($h.Term) { $h.Term.ToUniversalTime() } else { $null })
            $hireUtc = $(if ($h.Hire) { $h.Hire.ToUniversalTime() } else { $null })
            $entra = $null
            if ($entraByGuid.Count) { $entra = $entraByGuid[[Convert]::ToBase64String($u.ObjectGUID.ToByteArray())] }
            $entraLast = $null
            if ($entra -and $entra.signInActivity) {
                $cands = @($entra.signInActivity.lastSuccessfulSignInDateTime, $entra.signInActivity.lastSignInDateTime) | Where-Object { $_ }
                if ($cands) { $entraLast = ($cands | ForEach-Object { ([datetime]$_).ToUniversalTime() } | Sort-Object -Descending | Select-Object -First 1) }
            }
            $disableLag = $(if ($h.IsTerminated -and $termUtc -and $disabledAt) { [math]::Round(($disabledAt - $termUtc).TotalDays, 1) } else { '' })
            $flags = @()
            if ($h.IsTerminated -and $u.Enabled) { $flags += 'TerminatedButEnabled' }
            if ($h.IsTerminated -and $termUtc -and $lastLogon -and $lastLogon -gt $termUtc.AddDays(1)) { $flags += 'ADLogonAfterTermination' }
            if ($h.IsTerminated -and $termUtc -and $entraLast -and $entraLast -gt $termUtc.AddDays(1)) { $flags += 'EntraSignInAfterTermination' }
            if ($disableLag -ne '' -and $disableLag -gt $LeaverSlaDays) { $flags += "DisabledAfterSLA(${LeaverSlaDays}d)" }
            if (-not $h.IsTerminated -and -not $u.Enabled) { $flags += 'ActiveInHrButDisabled' }
            if ($adById[$id].Count -gt 1) { $flags += 'MultipleAccountsSameHrId' }
            $matched.Add([pscustomobject][ordered]@{
                HrId                 = $id
                HrStatus             = $h.Status
                IsTerminated         = $h.IsTerminated
                HireDate             = $(if ($h.Hire) { $h.Hire.ToString('yyyy-MM-dd') } else { '' })
                TerminationDate      = $(if ($h.Term) { $h.Term.ToString('yyyy-MM-dd') } else { '' })
                SamAccountName       = $u.SamAccountName
                Enabled              = $u.Enabled
                AccountCreatedUtc    = $(if ($created) { $created.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                CreateLagDays        = $(if ($created -and $hireUtc) { [math]::Round(($created - $hireUtc).TotalDays, 1) } else { '' })
                DisabledAtUtcApprox  = $(if ($disabledAt) { $disabledAt.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                DisableLagDays       = $disableLag
                ADLastLogonUtc       = $(if ($lastLogon) { $lastLogon.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                EntraLastSignInUtc   = $(if ($entraLast) { $entraLast.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                EntraEnabled         = $(if ($entra) { $entra.accountEnabled } else { '' })
                Flags                = Join-Values $flags
            })
        }
    }
    Export-Dataset -Name 'jml-matched' -Rows $matched -Note 'DisabledAtUtcApprox = last change of userAccountControl; can be later than the real disable if UAC changed again'
    Export-Dataset -Name 'jml-terminated-still-enabled' -Rows @($matched | Where-Object { $_.Flags -match 'TerminatedButEnabled' })
    Export-Dataset -Name 'jml-activity-after-termination' -Rows @($matched | Where-Object { $_.Flags -match 'AfterTermination' })
    Export-Dataset -Name 'jml-hr-active-no-account' -Rows $hrNoAccount

    # ---- 2. Orphan candidates: enabled AD users with no HR match ----
    $orphans = foreach ($u in $adUsers) {
        if (-not $u.Enabled) { continue }
        $sam = $u.SamAccountName
        if (@($ExcludeNamePatterns | Where-Object { $sam -like $_ }).Count) { continue }
        $id = "$($u.$AdMatchAttribute)".Trim()
        if ($id -and $hrById.ContainsKey($id)) { continue }
        $lastLogon = $(if ($u.lastLogonTimestamp) { [datetime]::FromFileTimeUtc([int64]$u.lastLogonTimestamp) } else { $null })
        [pscustomobject][ordered]@{
            SamAccountName    = $sam
            UserPrincipalName = $u.UserPrincipalName
            MatchValue        = $id
            Reason            = $(if ($id) { "$AdMatchAttribute not found in HR file" } else { "$AdMatchAttribute is empty" })
            WhenCreated       = $u.whenCreated
            LastLogonUtc      = $(if ($lastLogon) { $lastLogon.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            DistinguishedName = $u.DistinguishedName
        }
    }
    Export-Dataset -Name 'jml-ad-orphan-candidates' -Rows $orphans -Note ('Excludes name patterns: ' + ($ExcludeNamePatterns -join ', '))
    if (-not $IncludeEntraSignIn) { Set-DatasetStatus -Name 'entra-signin-check' -Status 'Deferred' -Note 'Run with -IncludeEntraSignIn to add Entra sign-in after termination' }
    elseif ($entraStatus -ne 'Completed') { Set-DatasetStatus -Name 'entra-signin-check' -Status 'Blocked' -Note 'Graph connection or signInActivity unavailable; see run.log' }

    # ---- 3. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $joinerLags = @($matched | Where-Object { $_.CreateLagDays -ne '' -and -not $_.IsTerminated } | ForEach-Object { [double]$_.CreateLagDays })
    $leaverLags = @($matched | Where-Object { $_.DisableLagDays -ne '' } | ForEach-Object { [double]$_.DisableLagDays })
    $terminated = @($matched | Where-Object IsTerminated)
    Add-Metric 'HR records' $hrById.Count "SHA256 of HR file: $hrHash"
    Add-Metric 'HR date values that failed to parse' $script:DateParseErrors $(if ($script:DateParseErrors) { 'Set -HrDateFormat' } else { '' })
    Add-Metric 'AD accounts matched to HR' $matched.Count
    Add-Metric 'Active HR records with no AD account' $hrNoAccount.Count
    Add-Metric 'Enabled AD accounts with no HR match (orphan candidates)' @($orphans).Count
    Add-Metric 'Joiner lag days - median' (Get-Percentile $joinerLags 50) 'Account created minus hire date; negative = pre-provisioned'
    Add-Metric 'Joiner lag days - 90th percentile' (Get-Percentile $joinerLags 90)
    Add-Metric 'Terminated (HR) with matched account' $terminated.Count
    Add-Metric 'Terminated but still enabled' @($terminated | Where-Object Enabled).Count
    Add-Metric 'Leaver disable lag days - median' (Get-Percentile $leaverLags 50) 'Approximate - see DisabledAtUtcApprox note'
    Add-Metric 'Leaver disable lag days - 90th percentile' (Get-Percentile $leaverLags 90)
    Add-Metric 'Leaver disable lag days - max' $(if ($leaverLags.Count) { ($leaverLags | Measure-Object -Maximum).Maximum } else { '' })
    $within = @($leaverLags | Where-Object { $_ -le $LeaverSlaDays }).Count
    Add-Metric "Leavers disabled within $LeaverSlaDays day(s) (%)" $(if ($leaverLags.Count) { [math]::Round(100 * $within / $leaverLags.Count, 1) } else { '' })
    Add-Metric 'AD logon after termination' @($matched | Where-Object { $_.Flags -match 'ADLogonAfterTermination' }).Count 'lastLogonTimestamp replicates every ~9-14 days; treat as indicative'
    if ($entraStatus -eq 'Completed') { Add-Metric 'Entra sign-in after termination' @($matched | Where-Object { $_.Flags -match 'EntraSignInAfterTermination' }).Count }
    Add-Metric 'HR ids mapped to more than one AD account' @($adById.Keys | Where-Object { $adById[$_].Count -gt 1 }).Count
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ HrCsvPath = (Split-Path $HrCsvPath -Leaf); AdMatchAttribute = $AdMatchAttribute; TerminatedStatusValues = $TerminatedStatusValues; LeaverSlaDays = $LeaverSlaDays; IncludeEntraSignIn = [bool]$IncludeEntraSignIn; SkipDisableTimestamp = [bool]$SkipDisableTimestamp }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
