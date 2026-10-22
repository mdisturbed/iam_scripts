<#
.SYNOPSIS
    Read-only comparison of HR lifecycle dates against AD (and optionally Entra) account state.

.DESCRIPTION
    Measures how well joiner/mover/leaver processing tracks HR:
      - Joiner lag: account created vs HR hire date (negative = created before start, i.e. pre-provisioned)
      - Leaver lag: account disabled vs HR termination date (disable time approximated from the
        replication metadata of userAccountControl - the last time that attribute changed)
      - Terminated in HR but still ENABLED in AD; terminated and disabled but still in groups;
        terminated and still holding Microsoft 365 licences (with -IncludeEntraSignIn)
      - Logon / sign-in AFTER the termination date (AD lastLogonTimestamp, optional Entra signInActivity)
      - Rehires: a hire date later than the termination date is treated as active, not terminated
      - Active in HR with no AD account
      - Enabled AD users with no HR match (orphan candidates)
      - Admin / service / test accounts (the -ExcludeNamePatterns names) linked back to their human
        owner, flagging enabled secondary accounts whose owner has left
      - Optional movers: department / title / manager in HR vs AD
      - Optional cloud-only Entra member users with no HR record
      - Summary: counts, median / 90th percentile / max lags, % disabled within the SLA

    Matching: HR id to the AD attribute in -AdMatchAttribute (employeeID by default). When that AD
    attribute is blank, the AD account is matched on -FallbackMatch attributes (UPN, then mail)
    against the HR UPN / mail columns if the HR file has them. MatchMethod shows which was used.

    INPUT: an HR export CSV that YOU supply (from the HR system of record). Column names are configurable.
    The HR file contains personal data - handle and store it per your data-handling rules.

    READ-ONLY. Uses only Get-AD* cmdlets and (optionally) Graph GET requests.

    Output: <OutputRoot>\06-JmlTiming\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\06-Compare-JmlTiming.ps1 -HrCsvPath .\hr-export.csv
.EXAMPLE
    .\06-Compare-JmlTiming.ps1 -HrCsvPath .\hr-export.csv -HrDateFormat 'MM/dd/yyyy' -TerminatedStatusValues 'Terminated','T' -IncludeEntraSignIn
.EXAMPLE
    .\06-Compare-JmlTiming.ps1 -HrCsvPath .\hr-export.csv -HrDepartmentColumn Department -HrTitleColumn JobTitle -HrManagerColumn ManagerId -OwnerLinkAttribute extensionAttribute7

.NOTES
    Version : 1.1.0
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
    [string]$HrUpnColumn = 'UserPrincipalName',             # used for fallback matching when present in the file
    [string]$HrMailColumn = 'Email',                        # used for fallback matching when present in the file
    [string]$HrDepartmentColumn = '',                       # mover check; blank = skip
    [string]$HrTitleColumn = '',                            # mover check; blank = skip
    [string]$HrManagerColumn = '',                          # mover check (manager's HR id, UPN, mail or sAMAccountName); blank = skip

    # Matching
    [string]$AdMatchAttribute = 'employeeID',               # AD attribute holding the HR id
    [string[]]$FallbackMatch = @('userPrincipalName', 'mail'),   # AD attributes tried when AdMatchAttribute is blank; @() = off
    [string[]]$ExcludeNamePatterns = @('svc*', 'sa-*', 'sa_*', 'adm*', '*admin*', 'test*'),
    [string]$OwnerLinkAttribute = '',                       # AD attribute on secondary accounts naming the owner (HR id, sAMAccountName, UPN or DN)
    [ValidateSet('objectGUID', 'mS-DS-ConsistencyGuid')]
    [string]$AnchorAttribute = 'objectGUID',                # Entra Connect source anchor (for -IncludeEntraSignIn)

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

function Format-Utc { param($Date) if ($Date) { return $Date.ToString('yyyy-MM-ddTHH:mm:ssZ') } return '' }
function ConvertTo-UtcDate { param($Value) if ($Value) { return ([datetime]$Value).ToUniversalTime() } return $null }
function Get-Key { param($Value) return "$Value".Trim().ToLowerInvariant() }

function Get-NameStem {
    # adm-jsmith -> jsmith, jsmith_adm -> jsmith, a-jsmith -> jsmith: strips the literal part of the matched pattern.
    param([string]$Sam, [string]$Pattern)
    $s = $Sam.ToLowerInvariant()
    $lit = $Pattern.ToLowerInvariant().Trim('*')
    if (-not $lit -or $lit -match '[\*\?\[]') { return '' }
    if ($Pattern.EndsWith('*') -and -not $Pattern.StartsWith('*') -and $s.StartsWith($lit)) { $s = $s.Substring($lit.Length) }
    elseif ($Pattern.StartsWith('*') -and -not $Pattern.EndsWith('*') -and $s.EndsWith($lit)) { $s = $s.Substring(0, $s.Length - $lit.Length) }
    else { $i = $s.IndexOf($lit); if ($i -ge 0) { $s = $s.Remove($i, $lit.Length) } }
    return $s.Trim('-', '_', '.', ' ')
}

$domainName = ''
$script:DateParseErrors = 0
$script:DisableMetaErrors = 0
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot
    $now = $script:RunStartUtc
    $FallbackMatch = @($FallbackMatch | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    # ---- HR input ----
    if (-not (Test-Path $HrCsvPath)) { throw "HR file not found: $HrCsvPath" }
    $hr = @(Import-Csv -Path $HrCsvPath)
    $hrCols = $(if ($hr.Count) { @($hr[0].PSObject.Properties.Name) } else { @() })
    $moverCols = @($HrDepartmentColumn, $HrTitleColumn, $HrManagerColumn | Where-Object { $_ })
    foreach ($col in @($HrIdColumn, $HrStatusColumn, $HrHireDateColumn, $HrTermDateColumn) + $moverCols) {
        if ($hr.Count -and -not ($hrCols -contains $col)) { throw "HR file has no column '$col'. Columns found: $($hrCols -join ', ')" }
    }
    $hasUpn = ($HrUpnColumn -and $hrCols -contains $HrUpnColumn)
    $hasMail = ($HrMailColumn -and $hrCols -contains $HrMailColumn)
    if ($FallbackMatch.Count -and -not ($hasUpn -or $hasMail)) { Write-RunLog ("HR file has neither '{0}' nor '{1}'; fallback matching on {2} is off." -f $HrUpnColumn, $HrMailColumn, ($FallbackMatch -join ', ')) 'WARN' }
    $hrHash = (Get-FileHash -Path $HrCsvPath -Algorithm SHA256).Hash
    Write-RunLog ("HR file: {0} rows, SHA256 {1}" -f $hr.Count, $hrHash)
    $hrById = @{}
    $nowLocal = $now.ToLocalTime()
    foreach ($h in $hr) {
        $id = "$($h.$HrIdColumn)".Trim()
        if (-not $id) { continue }
        if ($hrById.ContainsKey($id)) { Write-RunLog ("Duplicate HR id {0}; keeping the row with the latest hire date." -f $id) 'WARN' }
        $rec = [pscustomobject]@{
            Id = $id
            Status = "$($h.$HrStatusColumn)".Trim()
            Hire = ConvertTo-HrDate $h.$HrHireDateColumn
            Term = ConvertTo-HrDate $h.$HrTermDateColumn
            Upn = $(if ($hasUpn) { Get-Key $h.$HrUpnColumn } else { '' })
            Mail = $(if ($hasMail) { Get-Key $h.$HrMailColumn } else { '' })
            Department = $(if ($HrDepartmentColumn) { "$($h.$HrDepartmentColumn)".Trim() } else { '' })
            Title = $(if ($HrTitleColumn) { "$($h.$HrTitleColumn)".Trim() } else { '' })
            Manager = $(if ($HrManagerColumn) { "$($h.$HrManagerColumn)".Trim() } else { '' })
        }
        # A termination date only counts when it has passed and is not followed by a later (re)hire date.
        $statusTerm = ($TerminatedStatusValues -contains $rec.Status)
        $dateTerm = [bool]($rec.Term -and $rec.Term -le $nowLocal -and (-not $rec.Hire -or $rec.Term -ge $rec.Hire))
        $rec | Add-Member -NotePropertyName IsTerminated -NotePropertyValue ($statusTerm -or $dateTerm)
        $rec | Add-Member -NotePropertyName HrRehire -NotePropertyValue ([bool]($rec.Hire -and $rec.Term -and $rec.Hire -gt $rec.Term))
        if (-not $hrById.ContainsKey($id) -or ($rec.Hire -and $hrById[$id].Hire -and $rec.Hire -gt $hrById[$id].Hire)) { $hrById[$id] = $rec }
    }
    $hrByKey = @{}
    foreach ($rec in $hrById.Values) { foreach ($k in @($rec.Upn, $rec.Mail)) { if ($k -and -not $hrByKey.ContainsKey($k)) { $hrByKey[$k] = $rec } } }

    # ---- AD users ----
    $p = @{} + $script:AdParams
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    $props = @('sAMAccountName', 'userPrincipalName', 'mail', 'displayName', 'enabled', 'whenCreated', 'lastLogonTimestamp', 'objectGUID', 'mS-DS-ConsistencyGuid', 'memberOf', 'adminCount', 'manager', 'department', 'title', $AdMatchAttribute) + @($FallbackMatch)
    if ($OwnerLinkAttribute) { $props += $OwnerLinkAttribute }
    $props = @($props | Select-Object -Unique)
    $adUsers = @(Get-ADUser -Filter * -Properties $props @p)
    Write-RunLog ("{0} AD user accounts read" -f $adUsers.Count)
    $adById = @{}
    $adByDn = @{}; $adBySam = @{}; $adByUpn = @{}
    $adByFallback = @{}
    foreach ($u in $adUsers) {
        $adByDn[(Get-Key $u.DistinguishedName)] = $u
        $adBySam[(Get-Key $u.SamAccountName)] = $u
        if ($u.UserPrincipalName) { $adByUpn[(Get-Key $u.UserPrincipalName)] = $u }
        $id = "$($u.$AdMatchAttribute)".Trim()
        if ($id) {
            if (-not $adById.ContainsKey($id)) { $adById[$id] = [System.Collections.Generic.List[object]]::new() }
            $adById[$id].Add($u)
        }
        else {
            foreach ($a in $FallbackMatch) {
                $k = Get-Key $u.$a
                if (-not $k) { continue }
                if (-not $adByFallback.ContainsKey($k)) { $adByFallback[$k] = [System.Collections.Generic.List[object]]::new() }
                $adByFallback[$k].Add([pscustomobject]@{ User = $u; Attribute = $a })
            }
        }
    }
    function Test-ExcludedName { param([string]$Sam) foreach ($pt in $ExcludeNamePatterns) { if ($Sam -like $pt) { return $pt } } return '' }

    # ---- Optional Entra data ----
    $entraByAnchor = @{}
    $entraAll = @()
    $entraStatus = 'Deferred'
    $signInAvailable = $false
    if ($IncludeEntraSignIn) {
        try {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            if ($AuthMode -eq 'AppCertificate') { Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop }
            else {
                $c = @{ Scopes = @('User.Read.All', 'AuditLog.Read.All'); NoWelcome = $true; ErrorAction = 'Stop' }
                if ($TenantId -and $TenantId -ne 'tenant-id-redacted') { $c.TenantId = $TenantId }
                Connect-MgGraph @c
            }
            $sel = 'id,userPrincipalName,mail,displayName,employeeId,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,onPremisesImmutableId,assignedLicenses,signInSessionsValidFromDateTime'
            try {
                $eu = Invoke-GraphGetLite ("https://graph.microsoft.com/v1.0/users?`$select={0},signInActivity&`$top=999" -f $sel)
                $signInAvailable = $true
            }
            catch {
                Write-RunLog ("signInActivity not readable ({0}); continuing with licences and session data only." -f $_.Exception.Message) 'WARN'
                $eu = Invoke-GraphGetLite ("https://graph.microsoft.com/v1.0/users?`$select={0}&`$top=999" -f $sel)
            }
            $entraAll = @($eu)
            foreach ($x in $entraAll) {
                if (-not $x.onPremisesImmutableId) { continue }
                if ($entraByAnchor.ContainsKey($x.onPremisesImmutableId)) { Write-RunLog ("Two Entra users share onPremisesImmutableId {0}; the first is kept." -f $x.onPremisesImmutableId) 'WARN'; continue }
                $entraByAnchor[$x.onPremisesImmutableId] = $x
            }
            $entraStatus = 'Completed'
            Write-RunLog ("Entra: {0} users read, {1} with a source anchor; signInActivity {2}" -f $entraAll.Count, $entraByAnchor.Count, $(if ($signInAvailable) { 'available' } else { 'unavailable' }))
        }
        catch { $entraStatus = 'Blocked'; Write-RunLog ("Entra sign-in check unavailable: {0}" -f $_.Exception.Message) 'WARN' }
    }
    function Get-EntraTwin {
        # Entra Connect behaviour: mS-DS-ConsistencyGuid when set, otherwise objectGUID.
        param($U)
        if (-not $entraByAnchor.Count) { return $null }
        $bytes = $null
        if ($AnchorAttribute -eq 'mS-DS-ConsistencyGuid' -and $U.'mS-DS-ConsistencyGuid') { $bytes = [byte[]]$U.'mS-DS-ConsistencyGuid' }
        if (-not $bytes -and $U.ObjectGUID) { $bytes = $U.ObjectGUID.ToByteArray() }
        if (-not $bytes) { return $null }
        $k = [Convert]::ToBase64String($bytes)
        if ($entraByAnchor.ContainsKey($k)) { return $entraByAnchor[$k] }
        return $null
    }
    function Get-EntraSignIn {
        # Last successful sign-in when Entra reports it; otherwise the newest of interactive and
        # non-interactive (lastSignInDateTime also counts failed attempts).
        param($E)
        $r = [pscustomobject]@{ Last = $null; NonInteractive = $null }
        if (-not $E -or -not $E.signInActivity) { return $r }
        $r.NonInteractive = ConvertTo-UtcDate $E.signInActivity.lastNonInteractiveSignInDateTime
        $succ = ConvertTo-UtcDate $E.signInActivity.lastSuccessfulSignInDateTime
        if ($succ) { $r.Last = $succ }
        else { $r.Last = @((ConvertTo-UtcDate $E.signInActivity.lastSignInDateTime), $r.NonInteractive | Where-Object { $_ }) | Sort-Object -Descending | Select-Object -First 1 }
        return $r
    }

    # ---- 1. Pair HR records with AD accounts ----
    $pairs = [System.Collections.Generic.List[object]]::new()
    $hrNoAccount = [System.Collections.Generic.List[object]]::new()
    $matchedSam = @{}
    foreach ($id in $hrById.Keys) {
        $h = $hrById[$id]
        $users = @(); $method = $AdMatchAttribute
        if ($adById.ContainsKey($id)) { $users = @($adById[$id]) }
        else {
            foreach ($k in @($h.Upn, $h.Mail)) {
                if ($k -and $adByFallback.ContainsKey($k)) {
                    $hit = @($adByFallback[$k] | Where-Object { -not $matchedSam.ContainsKey($_.User.SamAccountName) })
                    if ($hit.Count) { $seen = @{}; $users = @($hit | ForEach-Object { if (-not $seen.ContainsKey($_.User.SamAccountName)) { $seen[$_.User.SamAccountName] = $true; $_.User } }); $method = 'Fallback:' + (@($hit | ForEach-Object { $_.Attribute } | Select-Object -Unique) -join '+'); break }
                }
            }
        }
        if (-not $users.Count) {
            if (-not $h.IsTerminated) { $hrNoAccount.Add([pscustomobject][ordered]@{ HrId = $id; HrStatus = $h.Status; HireDate = $(if ($h.Hire) { $h.Hire.ToString('yyyy-MM-dd') } else { '' }); Note = 'Active in HR, no AD account with matching ' + $AdMatchAttribute + $(if ($FallbackMatch.Count -and ($hasUpn -or $hasMail)) { ' or ' + ($FallbackMatch -join ' / ') } else { '' }) }) }
            continue
        }
        foreach ($u in $users) { $matchedSam[$u.SamAccountName] = $true }
        $pairs.Add([pscustomobject]@{ Id = $id; Hr = $h; Users = $users; Method = $method })
    }

    $matched = [System.Collections.Generic.List[object]]::new()
    $movers = [System.Collections.Generic.List[object]]::new()
    $metaError = ''
    foreach ($pair in $pairs) {
        $id = $pair.Id; $h = $pair.Hr
        foreach ($u in $pair.Users) {
            $created = $(if ($u.whenCreated) { ([datetime]$u.whenCreated).ToUniversalTime() } else { $null })
            $lastLogon = $(if ($u.lastLogonTimestamp) { [datetime]::FromFileTimeUtc([int64]$u.lastLogonTimestamp) } else { $null })
            $disabledAt = $null
            if (-not $u.Enabled -and -not $SkipDisableTimestamp) {
                try {
                    $md = Get-ADReplicationAttributeMetadata -Object $u.DistinguishedName -Properties userAccountControl @script:AdParams | Select-Object -First 1
                    if ($md) { $disabledAt = ([datetime]$md.LastOriginatingChangeTime).ToUniversalTime() }
                }
                catch {
                    $script:DisableMetaErrors++
                    if (-not $metaError) { $metaError = $_.Exception.Message; Write-RunLog ("Replication metadata unreadable for {0}: {1} (further failures counted, not logged)" -f $u.SamAccountName, $metaError) 'WARN' }
                }
            }
            $termUtc = $(if ($h.Term) { $h.Term.ToUniversalTime() } else { $null })
            $hireUtc = $(if ($h.Hire) { $h.Hire.ToUniversalTime() } else { $null })
            $entra = Get-EntraTwin $u
            $si = Get-EntraSignIn $entra
            $entraLast = $si.Last
            $memberOfCount = @($u.memberOf | Where-Object { $_ }).Count
            $licCount = $(if ($entra) { @($entra.assignedLicenses | Where-Object { $_ }).Count } else { '' })
            $disableLag = $(if ($h.IsTerminated -and $termUtc -and $disabledAt) { [math]::Round(($disabledAt - $termUtc).TotalDays, 1) } else { '' })
            $flags = @()
            if ($h.IsTerminated -and $u.Enabled) { $flags += 'TerminatedButEnabled' }
            if ($h.IsTerminated -and $termUtc -and $lastLogon -and $lastLogon -gt $termUtc.AddDays(1)) { $flags += 'ADLogonAfterTermination' }
            if ($h.IsTerminated -and $termUtc -and $entraLast -and $entraLast -gt $termUtc.AddDays(1)) { $flags += 'EntraSignInAfterTermination' }
            if ($disableLag -ne '' -and $disableLag -gt $LeaverSlaDays) { $flags += "DisabledAfterSLA(${LeaverSlaDays}d)" }
            if (-not $h.IsTerminated -and -not $u.Enabled) { $flags += 'ActiveInHrButDisabled' }
            if ($pair.Users.Count -gt 1) { $flags += 'MultipleAccountsSameHrId' }
            if ($h.IsTerminated -and -not $u.Enabled -and $memberOfCount -gt 0) { $flags += 'DisabledButStillInGroups' }
            if ($h.IsTerminated -and $licCount -ne '' -and $licCount -gt 0) { $flags += 'TerminatedStillLicensed' }
            if ($h.HrRehire) { $flags += 'HrRehire' }
            $matched.Add([pscustomobject][ordered]@{
                HrId                 = $id
                HrStatus             = $h.Status
                IsTerminated         = $h.IsTerminated
                HireDate             = $(if ($h.Hire) { $h.Hire.ToString('yyyy-MM-dd') } else { '' })
                TerminationDate      = $(if ($h.Term) { $h.Term.ToString('yyyy-MM-dd') } else { '' })
                SamAccountName       = $u.SamAccountName
                Enabled              = $u.Enabled
                AccountCreatedUtc    = Format-Utc $created
                CreateLagDays        = $(if ($created -and $hireUtc) { [math]::Round(($created - $hireUtc).TotalDays, 1) } else { '' })
                DisabledAtUtcApprox  = Format-Utc $disabledAt
                DisableLagDays       = $disableLag
                ADLastLogonUtc       = Format-Utc $lastLogon
                EntraLastSignInUtc   = Format-Utc $entraLast
                EntraEnabled         = $(if ($entra) { $entra.accountEnabled } else { '' })
                Flags                = Join-Values $flags
                HrRehire             = $h.HrRehire
                MatchMethod          = $pair.Method
                MemberOfCount        = $memberOfCount
                AdminCount           = $(if ("$($u.adminCount)" -eq '1') { 1 } else { 0 })
                AssignedLicenseCount = $licCount
                SignInSessionsValidFromUtc = $(if ($entra) { Format-Utc (ConvertTo-UtcDate $entra.signInSessionsValidFromDateTime) } else { '' })
                LastNonInteractiveSignInUtc = Format-Utc $si.NonInteractive
            })

            # Movers: HR department / title / manager vs AD (active people only)
            if ($moverCols.Count -and -not $h.IsTerminated) {
                if ($HrDepartmentColumn -and (Get-Key $h.Department) -ne (Get-Key $u.department)) { $movers.Add([pscustomobject][ordered]@{ HrId = $id; SamAccountName = $u.SamAccountName; Attribute = 'Department'; HrValue = $h.Department; AdValue = "$($u.department)"; Note = '' }) }
                if ($HrTitleColumn -and (Get-Key $h.Title) -ne (Get-Key $u.title)) { $movers.Add([pscustomobject][ordered]@{ HrId = $id; SamAccountName = $u.SamAccountName; Attribute = 'Title'; HrValue = $h.Title; AdValue = "$($u.title)"; Note = '' }) }
                if ($HrManagerColumn) {
                    $mgr = $null
                    if ($u.manager) {
                        $mk = Get-Key $u.manager
                        if ($adByDn.ContainsKey($mk)) { $mgr = $adByDn[$mk] }
                        else { try { $mgr = Get-ADUser -Identity $u.manager -Properties sAMAccountName, userPrincipalName, mail, displayName, $AdMatchAttribute @script:AdParams } catch { $mgr = $null } }
                    }
                    $mgrKeys = @()
                    if ($mgr) { $mgrKeys = @($mgr.$AdMatchAttribute, $mgr.SamAccountName, $mgr.UserPrincipalName, $mgr.mail, $mgr.displayName | ForEach-Object { Get-Key $_ } | Where-Object { $_ }) }
                    $hk = Get-Key $h.Manager
                    if (($hk -or $u.manager) -and -not ($hk -and $mgrKeys -contains $hk)) {
                        $movers.Add([pscustomobject][ordered]@{ HrId = $id; SamAccountName = $u.SamAccountName; Attribute = 'Manager'; HrValue = $h.Manager
                                AdValue = $(if ($mgr) { '{0} ({1})' -f $mgr.SamAccountName, $mgr.$AdMatchAttribute } elseif ($u.manager) { "$($u.manager)" } else { '' })
                                Note = $(if ($u.manager -and -not $mgr) { 'AD manager not resolvable' } else { '' }) })
                    }
                }
            }
        }
    }
    $metaNote = 'DisabledAtUtcApprox = last change of userAccountControl; can be later than the real disable if UAC changed again'
    if ($script:DisableMetaErrors) { $metaNote += ("; replication metadata unreadable for {0} disabled account(s), their DisableLagDays is blank (first error: {1})" -f $script:DisableMetaErrors, $metaError) }
    Export-Dataset -Name 'jml-matched' -Rows $matched -Note $metaNote
    Export-Dataset -Name 'jml-terminated-still-enabled' -Rows @($matched | Where-Object { $_.Flags -match 'TerminatedButEnabled' })
    Export-Dataset -Name 'jml-activity-after-termination' -Rows @($matched | Where-Object { $_.Flags -match 'AfterTermination' })
    Export-Dataset -Name 'jml-hr-active-no-account' -Rows $hrNoAccount

    # ---- 2. Orphan candidates: enabled AD users with no HR match ----
    $orphans = foreach ($u in $adUsers) {
        if (-not $u.Enabled) { continue }
        $sam = $u.SamAccountName
        if (Test-ExcludedName $sam) { continue }
        if ($matchedSam.ContainsKey($sam)) { continue }
        $id = "$($u.$AdMatchAttribute)".Trim()
        if ($id -and $hrById.ContainsKey($id)) { continue }
        $lastLogon = $(if ($u.lastLogonTimestamp) { [datetime]::FromFileTimeUtc([int64]$u.lastLogonTimestamp) } else { $null })
        [pscustomobject][ordered]@{
            SamAccountName    = $sam
            UserPrincipalName = $u.UserPrincipalName
            MatchValue        = $id
            Reason            = $(if ($id) { "$AdMatchAttribute not found in HR file" } else { "$AdMatchAttribute is empty" + $(if ($FallbackMatch.Count -and ($hasUpn -or $hasMail)) { ' and no HR match on ' + ($FallbackMatch -join ' / ') } else { '' }) })
            WhenCreated       = $u.whenCreated
            LastLogonUtc      = $(if ($lastLogon) { $lastLogon.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
            DistinguishedName = $u.DistinguishedName
        }
    }
    Export-Dataset -Name 'jml-ad-orphan-candidates' -Rows $orphans -Note ('Excludes name patterns: ' + ($ExcludeNamePatterns -join ', ') + '; those accounts are in secondary-accounts')

    # ---- 3. Secondary (admin / service / test) accounts linked to their owner ----
    function Get-OwnerHr {
        # Resolves an AD user (the owner) to its HR record.
        param($Owner)
        if (-not $Owner) { return $null }
        $oid = "$($Owner.$AdMatchAttribute)".Trim()
        if ($oid -and $hrById.ContainsKey($oid)) { return $hrById[$oid] }
        foreach ($k in @((Get-Key $Owner.UserPrincipalName), (Get-Key $Owner.mail))) { if ($k -and $hrByKey.ContainsKey($k)) { return $hrByKey[$k] } }
        return $null
    }
    $secondary = foreach ($u in $adUsers) {
        $pt = Test-ExcludedName $u.SamAccountName
        if (-not $pt) { continue }
        $ownerHr = $null; $ownerSam = ''; $method = ''
        $id = "$($u.$AdMatchAttribute)".Trim()
        if ($id -and $hrById.ContainsKey($id)) { $ownerHr = $hrById[$id]; $method = $AdMatchAttribute }
        if (-not $ownerHr -and $OwnerLinkAttribute -and "$($u.$OwnerLinkAttribute)".Trim()) {
            $v = "$($u.$OwnerLinkAttribute)".Trim(); $vk = Get-Key $v
            if ($hrById.ContainsKey($v)) { $ownerHr = $hrById[$v] }
            else {
                $o = $null
                foreach ($map in @($adBySam, $adByUpn, $adByDn)) { if ($map.ContainsKey($vk)) { $o = $map[$vk]; break } }
                if ($o) { $ownerHr = Get-OwnerHr $o; $ownerSam = $o.SamAccountName }
                elseif ($hrByKey.ContainsKey($vk)) { $ownerHr = $hrByKey[$vk] }
            }
            if ($ownerHr) { $method = $OwnerLinkAttribute }
        }
        if (-not $ownerHr) {
            $stem = Get-NameStem -Sam $u.SamAccountName -Pattern $pt
            if ($stem -and $adBySam.ContainsKey($stem) -and -not (Test-ExcludedName $stem)) {
                $o = $adBySam[$stem]; $oh = Get-OwnerHr $o
                if ($oh) { $ownerHr = $oh; $ownerSam = $o.SamAccountName; $method = "name stem ($stem)" }
            }
        }
        if (-not $ownerHr -and $u.manager) {
            $mk = Get-Key $u.manager
            if ($adByDn.ContainsKey($mk)) { $o = $adByDn[$mk]; $oh = Get-OwnerHr $o; if ($oh) { $ownerHr = $oh; $ownerSam = $o.SamAccountName; $method = 'manager (check: may be the line manager)' } }
        }
        if ($ownerHr -and -not $ownerSam -and $adById.ContainsKey($ownerHr.Id)) { $ownerSam = (@($adById[$ownerHr.Id] | Where-Object { -not (Test-ExcludedName $_.SamAccountName) }) + @($adById[$ownerHr.Id]) | Select-Object -First 1).SamAccountName }
        $lastLogon = $(if ($u.lastLogonTimestamp) { [datetime]::FromFileTimeUtc([int64]$u.lastLogonTimestamp) } else { $null })
        $flags = @()
        if ($ownerHr -and $ownerHr.IsTerminated -and $u.Enabled) { $flags += 'OwnerTerminatedSecondaryEnabled' }
        if (-not $ownerHr) { $flags += 'NoOwnerLink' }
        if ("$($u.adminCount)" -eq '1') { $flags += 'AdminCount' }
        [pscustomobject][ordered]@{
            SamAccountName       = $u.SamAccountName
            Enabled              = $u.Enabled
            MatchedPattern       = $pt
            LinkedOwner          = $(if ($ownerHr) { $ownerHr.Id } else { '' })
            OwnerSamAccountName  = $ownerSam
            LinkMethod           = $method
            OwnerHrStatus        = $(if ($ownerHr) { $ownerHr.Status } else { '' })
            OwnerTerminated      = $(if ($ownerHr) { $ownerHr.IsTerminated } else { '' })
            OwnerTerminationDate = $(if ($ownerHr -and $ownerHr.Term) { $ownerHr.Term.ToString('yyyy-MM-dd') } else { '' })
            LastLogonUtc         = Format-Utc $lastLogon
            Flags                = Join-Values $flags
            DistinguishedName    = $u.DistinguishedName
        }
    }
    $secondary = @($secondary | Sort-Object @{ Expression = { $_.Flags -match 'OwnerTerminated' }; Descending = $true }, SamAccountName)
    Export-Dataset -Name 'secondary-accounts' -Rows $secondary -Note ('Accounts matching -ExcludeNamePatterns, linked to an owner by ' + (@($AdMatchAttribute, $OwnerLinkAttribute | Where-Object { $_ }) -join ' / ') + ' / name stem / manager')

    # ---- 4. Movers ----
    if (-not $moverCols.Count) { Set-DatasetStatus -Name 'mover-mismatches' -Status 'Deferred' -Note 'Pass -HrDepartmentColumn / -HrTitleColumn / -HrManagerColumn to compare HR with AD' }
    else { Export-Dataset -Name 'mover-mismatches' -Rows $movers -Note ('Active HR people only; compared case-insensitively: ' + ($moverCols -join ', ')) }

    # ---- 5. Entra ----
    $cloudNotInHr = @()
    if (-not $IncludeEntraSignIn) {
        Set-DatasetStatus -Name 'entra-signin-check' -Status 'Deferred' -Note 'Run with -IncludeEntraSignIn to add Entra sign-in after termination'
        Set-DatasetStatus -Name 'cloud-only-users-not-in-hr' -Status 'Deferred' -Note 'Run with -IncludeEntraSignIn'
    }
    elseif ($entraStatus -ne 'Completed') {
        Set-DatasetStatus -Name 'entra-signin-check' -Status 'Blocked' -Note 'Graph connection or users unavailable; see run.log'
        Set-DatasetStatus -Name 'cloud-only-users-not-in-hr' -Status 'Blocked' -Note 'Graph connection or users unavailable; see run.log'
    }
    else {
        if (-not $signInAvailable) { Set-DatasetStatus -Name 'entra-signin-check' -Status 'EvidenceUnavailable' -Note 'signInActivity not readable (AuditLog.Read.All / Entra ID P1); licences and sessions were still read' }
        $cloudNotInHr = @(foreach ($e in $entraAll) {
                if ("$($e.onPremisesSyncEnabled)" -eq 'True') { continue }
                if ($e.userType -eq 'Guest') { continue }
                $eid = "$($e.employeeId)".Trim()
                if ($eid -and $hrById.ContainsKey($eid)) { continue }
                if (@((Get-Key $e.userPrincipalName), (Get-Key $e.mail) | Where-Object { $_ -and $hrByKey.ContainsKey($_) }).Count) { continue }
                $si = Get-EntraSignIn $e
                [pscustomobject][ordered]@{
                    UserPrincipalName           = $e.userPrincipalName
                    DisplayName                 = $e.displayName
                    Mail                        = $e.mail
                    EmployeeId                  = $eid
                    AccountEnabled              = $e.accountEnabled
                    CreatedUtc                  = Format-Utc (ConvertTo-UtcDate $e.createdDateTime)
                    LastSignInUtc               = Format-Utc $si.Last
                    LastNonInteractiveSignInUtc = Format-Utc $si.NonInteractive
                    AssignedLicenseCount        = @($e.assignedLicenses | Where-Object { $_ }).Count
                    Note                        = $(if (-not $signInAvailable) { 'Sign-in data unavailable' } elseif ($eid) { 'employeeId not in HR file' } else { 'No employeeId; UPN / mail not in HR file' })
                }
            })
        Export-Dataset -Name 'cloud-only-users-not-in-hr' -Rows $cloudNotInHr -Note 'Member users not synced from AD (guests excluded); break-glass and service identities are expected here'
    }

    # ---- 6. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $joinerLags = @($matched | Where-Object { "$($_.CreateLagDays)" -ne '' -and -not $_.IsTerminated } | ForEach-Object { [double]$_.CreateLagDays })
    $leaverLags = @($matched | Where-Object { "$($_.DisableLagDays)" -ne '' } | ForEach-Object { [double]$_.DisableLagDays })
    $terminated = @($matched | Where-Object IsTerminated)
    Add-Metric -Metric 'HR records' -Value $hrById.Count -Note "SHA256 of HR file: $hrHash"
    Add-Metric -Metric 'HR date values that failed to parse' -Value $script:DateParseErrors -Note $(if ($script:DateParseErrors) { 'Set -HrDateFormat' } else { '' })
    Add-Metric -Metric 'HR records that are rehires (hire date after termination date)' -Value @($hrById.Values | Where-Object HrRehire).Count -Note 'Treated as active unless the status says terminated'
    Add-Metric 'AD accounts matched to HR' $matched.Count
    Add-Metric -Metric 'AD accounts matched by fallback (UPN / mail)' -Value @($matched | Where-Object { $_.MatchMethod -like 'Fallback*' }).Count -Note ("{0} was blank on these accounts" -f $AdMatchAttribute)
    Add-Metric 'Active HR records with no AD account' $hrNoAccount.Count
    Add-Metric 'Enabled AD accounts with no HR match (orphan candidates)' @($orphans).Count
    Add-Metric -Metric 'Joiner lag days - median' -Value (Get-Percentile $joinerLags 50) -Note 'Account created minus hire date; negative = pre-provisioned'
    Add-Metric 'Joiner lag days - 90th percentile' (Get-Percentile $joinerLags 90)
    Add-Metric 'Terminated (HR) with matched account' $terminated.Count
    Add-Metric 'Terminated but still enabled' @($terminated | Where-Object Enabled).Count
    Add-Metric -Metric 'Terminated, disabled, still in groups' -Value @($matched | Where-Object { $_.Flags -match 'DisabledButStillInGroups' }).Count -Note 'Group memberships kept after disable can be restored with the account'
    Add-Metric -Metric 'Leaver disable lag days - median' -Value (Get-Percentile $leaverLags 50) -Note 'Approximate - see DisabledAtUtcApprox note'
    Add-Metric 'Leaver disable lag days - 90th percentile' (Get-Percentile $leaverLags 90)
    Add-Metric 'Leaver disable lag days - max' $(if ($leaverLags.Count) { ($leaverLags | Measure-Object -Maximum).Maximum } else { '' })
    $within = @($leaverLags | Where-Object { $_ -le $LeaverSlaDays }).Count
    Add-Metric "Leavers disabled within $LeaverSlaDays day(s) (%)" $(if ($leaverLags.Count) { [math]::Round(100 * $within / $leaverLags.Count, 1) } else { '' })
    Add-Metric -Metric 'Disable timestamps unreadable (replication metadata)' -Value $script:DisableMetaErrors -Note $(if ($script:DisableMetaErrors) { 'Leaver lag is incomplete; see run.log' } elseif ($SkipDisableTimestamp) { 'Skipped (-SkipDisableTimestamp)' } else { '' })
    Add-Metric -Metric 'AD logon after termination' -Value @($matched | Where-Object { $_.Flags -match 'ADLogonAfterTermination' }).Count -Note 'lastLogonTimestamp replicates every ~9-14 days; treat as indicative'
    if ($entraStatus -eq 'Completed') {
        if ($signInAvailable) { Add-Metric -Metric 'Entra sign-in after termination' -Value @($matched | Where-Object { $_.Flags -match 'EntraSignInAfterTermination' }).Count -Note 'Uses last successful sign-in where Entra reports it' }
        Add-Metric 'Terminated and still licensed in Entra' @($matched | Where-Object { $_.Flags -match 'TerminatedStillLicensed' }).Count
        Add-Metric 'Cloud-only member users not in HR' @($cloudNotInHr).Count
    }
    Add-Metric 'HR ids mapped to more than one AD account' @($pairs | Where-Object { $_.Users.Count -gt 1 }).Count
    Add-Metric 'Secondary (admin / service / test) accounts' @($secondary).Count
    Add-Metric -Metric 'Secondary accounts enabled whose owner has left' -Value @($secondary | Where-Object { $_.Flags -match 'OwnerTerminatedSecondaryEnabled' }).Count -Note 'Leaver process missed the admin / secondary account'
    Add-Metric -Metric 'Secondary accounts with no owner link' -Value @($secondary | Where-Object { $_.Flags -match 'NoOwnerLink' }).Count -Note 'Set -OwnerLinkAttribute if an attribute names the owner'
    if ($moverCols.Count) { Add-Metric -Metric 'Mover mismatches (HR vs AD)' -Value $movers.Count -Note ($moverCols -join ', ') }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ HrCsvPath = (Split-Path $HrCsvPath -Leaf); AdMatchAttribute = $AdMatchAttribute; FallbackMatch = $FallbackMatch; TerminatedStatusValues = $TerminatedStatusValues; LeaverSlaDays = $LeaverSlaDays; IncludeEntraSignIn = [bool]$IncludeEntraSignIn; SkipDisableTimestamp = [bool]$SkipDisableTimestamp; AnchorAttribute = $AnchorAttribute; OwnerLinkAttribute = $OwnerLinkAttribute; ExcludeNamePatterns = $ExcludeNamePatterns; MoverColumns = $moverCols }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
