<#
.SYNOPSIS
    Read-only measurement of legacy authentication on domain controllers: NTLM (v1 and v2) and
    Kerberos tickets issued with weak encryption (RC4 / DES).

.DESCRIPTION
    Shows what would break - and who is still exposed - before NTLM is restricted or RC4 is
    disabled. Reads the Security event log on each domain controller for a time window and
    aggregates:

      - NTLM logons (4624 with AuthenticationPackageName = NTLM), split by NTLM V1 / V2, by
        account, source workstation and IP
      - NTLM credential validations (4776) by account and workstation
      - Kerberos TGT (4768) and service ticket (4769) requests using RC4 or DES, by account,
        service and IP
      - Per-DC read status (events found, window actually covered, errors)
      - A summary of headline metrics

    Security logs often roll over in hours on busy DCs. The per-DC file shows the oldest event
    actually read, so the window covered is explicit. For longer history, query the SIEM.

    READ-ONLY. Uses only Get-WinEvent and Get-AD* cmdlets.

    Output: <OutputRoot>\19-DcAuthProtocols\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\19-Get-DcAuthProtocolUsage.ps1 -Hours 24
.EXAMPLE
    .\19-Get-DcAuthProtocolUsage.ps1 -DomainControllers dc01.contoso.local,dc02.contoso.local -Hours 4 -MaxEventsPerQuery 20000

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x on Windows, RSAT ActiveDirectory module (to list DCs)
    Access  : membership of Event Log Readers on the domain controllers (or equivalent), and
              remote event log access (RPC) from the run host
    Auditing: 4624 / 4776 need "Audit Logon" / "Audit Credential Validation"; 4768 / 4769 need
              "Audit Kerberos Authentication Service" / "Service Ticket Operations". If auditing is
              off, the counts are zero - check dc-read-status before concluding there is no usage.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # used only to find DCs
    [string[]]$DomainControllers = @(),                     # blank = every DC in the domain
    [ValidateRange(1, 720)]
    [int]$Hours = 24,
    [int]$MaxEventsPerQuery = 50000,
    [switch]$SkipKerberos,
    [switch]$SkipNtlmValidation                             # skip 4776 (often very high volume)
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '19-DcAuthProtocols'
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

$EncTypes = @{ '0x1' = 'DES-CBC-CRC'; '0x3' = 'DES-CBC-MD5'; '0x17' = 'RC4-HMAC'; '0x18' = 'RC4-HMAC-EXP' }

function ConvertFrom-EventXml {
    # Returns a hashtable of EventData Name -> value.
    param($EventRecord)
    $h = @{}
    try {
        $x = [xml]$EventRecord.ToXml()
        foreach ($d in $x.Event.EventData.Data) { $h[$d.Name] = "$($d.'#text')" }
    }
    catch { }
    return $h
}

function Get-DcEvents {
    param([string]$Computer, [string]$XPath, [string]$Label)
    try {
        return @(Get-WinEvent -ComputerName $Computer -LogName Security -FilterXPath $XPath -MaxEvents $MaxEventsPerQuery -ErrorAction Stop)
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') { return @() }
        throw ("{0}: {1}" -f $Label, $_.Exception.Message)
    }
}

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if (-not $DomainControllers.Count) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domainName = (Get-ADDomain @script:AdParams).DNSRoot
        $DomainControllers = @(Get-ADDomainController -Filter * @script:AdParams | ForEach-Object { $_.HostName })
    }
    Write-RunLog ("{0} domain controller(s); window {1} hours" -f $DomainControllers.Count, $Hours)
    $ms = [int64]$Hours * 3600 * 1000
    $time = "TimeCreated[timediff(@SystemTime) <= $ms]"
    $queries = [ordered]@{
        'NTLM-Logon'      = "*[System[(EventID=4624) and $time]] and *[EventData[Data[@Name='AuthenticationPackageName']='NTLM']]"
    }
    if (-not $SkipNtlmValidation) { $queries['NTLM-Validation'] = "*[System[(EventID=4776) and $time]]" }
    if (-not $SkipKerberos) {
        $enc = ($EncTypes.Keys | ForEach-Object { "Data[@Name='TicketEncryptionType']='$_'" }) -join ' or '
        $queries['Kerberos-TGT-Weak'] = "*[System[(EventID=4768) and $time]] and *[EventData[$enc]]"
        $queries['Kerberos-TGS-Weak'] = "*[System[(EventID=4769) and $time]] and *[EventData[$enc]]"
    }

    $statusRows = [System.Collections.Generic.List[object]]::new()
    $ntlmAgg = @{}; $valAgg = @{}; $kerbAgg = @{}
    function Add-Agg {
        param([hashtable]$Table, [string]$Key, [hashtable]$Fields, [datetime]$When)
        if (-not $Table.ContainsKey($Key)) { $Table[$Key] = @{ Fields = $Fields; Count = 0; First = $When; Last = $When; DCs = [System.Collections.Generic.HashSet[string]]::new() } }
        $e = $Table[$Key]; $e.Count++
        if ($When -lt $e.First) { $e.First = $When }
        if ($When -gt $e.Last) { $e.Last = $When }
    }

    foreach ($dc in $DomainControllers) {
        # Where this DC's Security log actually starts, so the covered window is explicit.
        $logStart = $null
        try { $logStart = (Get-WinEvent -ComputerName $dc -LogName Security -MaxEvents 1 -Oldest -ErrorAction Stop | Select-Object -First 1).TimeCreated.ToUniversalTime() } catch { }
        $windowStart = $script:RunStartUtc.AddHours(-$Hours)
        $covered = $(if ($logStart) { [math]::Round(($script:RunStartUtc - $(if ($logStart -gt $windowStart) { $logStart } else { $windowStart })).TotalHours, 1) } else { '' })
        foreach ($q in $queries.Keys) {
            $events = @()
            $err = ''
            try { $events = Get-DcEvents -Computer $dc -XPath $queries[$q] -Label $q } catch { $err = $_.Exception.Message; Write-RunLog ("{0} {1}" -f $dc, $err) 'WARN' }
            $oldest = $(if ($events.Count) { ($events | Measure-Object -Property TimeCreated -Minimum).Minimum.ToUniversalTime() } else { $null })
            $statusRows.Add([pscustomobject][ordered]@{
                DomainController = $dc
                Query            = $q
                Status           = $(if ($err) { 'Blocked' } else { 'Completed' })
                EventsRead       = $events.Count
                CappedAtMax      = ($events.Count -ge $MaxEventsPerQuery)
                OldestMatchUtc   = $(if ($oldest) { $oldest.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                LogStartsUtc     = $(if ($logStart) { $logStart.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'unknown' })
                HoursCovered     = $(if ($err) { '' } else { $covered })
                Error            = $err
            })
            foreach ($ev in $events) {
                $d = ConvertFrom-EventXml $ev
                $when = $ev.TimeCreated.ToUniversalTime()
                switch ($q) {
                    'NTLM-Logon' {
                        $ver = $(if ($d['LmPackageName']) { $d['LmPackageName'] } else { 'NTLM' })
                        $k = '{0}|{1}\{2}|{3}|{4}' -f $ver, $d['TargetDomainName'], $d['TargetUserName'], $d['WorkstationName'], $d['IpAddress']
                        Add-Agg $ntlmAgg $k @{ NtlmVersion = $ver; Account = "$($d['TargetDomainName'])\$($d['TargetUserName'])"; SourceWorkstation = $d['WorkstationName']; SourceIp = $d['IpAddress']; LogonType = $d['LogonType'] } $when
                        $ntlmAgg[$k].DCs.Add($dc) | Out-Null
                    }
                    'NTLM-Validation' {
                        $k = '{0}|{1}|{2}' -f $d['TargetUserName'], $d['Workstation'], $d['Status']
                        Add-Agg $valAgg $k @{ Account = $d['TargetUserName']; SourceWorkstation = $d['Workstation']; Status = $d['Status'] } $when
                        $valAgg[$k].DCs.Add($dc) | Out-Null
                    }
                    default {
                        $encName = $(if ($EncTypes.ContainsKey($d['TicketEncryptionType'])) { $EncTypes[$d['TicketEncryptionType']] } else { $d['TicketEncryptionType'] })
                        $svc = $(if ($q -eq 'Kerberos-TGT-Weak') { 'krbtgt (TGT)' } else { $d['ServiceName'] })
                        $ip = ($d['IpAddress'] -replace '^::ffff:', '')
                        $k = '{0}|{1}|{2}|{3}' -f $d['TargetUserName'], $svc, $encName, $ip
                        Add-Agg $kerbAgg $k @{ RequestType = $(if ($q -eq 'Kerberos-TGT-Weak') { 'TGT' } else { 'ServiceTicket' }); Account = $d['TargetUserName']; Service = $svc; Encryption = $encName; ClientIp = $ip } $when
                        $kerbAgg[$k].DCs.Add($dc) | Out-Null
                    }
                }
            }
        }
    }
    Export-Dataset -Name 'dc-read-status' -Rows $statusRows -Note 'Check HoursCovered: Security logs may hold less than the requested window'

    function ConvertFrom-Agg {
        param([hashtable]$Table)
        foreach ($k in $Table.Keys) {
            $e = $Table[$k]
            $o = [ordered]@{}
            foreach ($f in $e.Fields.Keys) { $o[$f] = $e.Fields[$f] }
            $o['Count'] = $e.Count
            $o['FirstSeenUtc'] = $e.First.ToString('yyyy-MM-ddTHH:mm:ssZ')
            $o['LastSeenUtc'] = $e.Last.ToString('yyyy-MM-ddTHH:mm:ssZ')
            $o['DomainControllers'] = Join-Values @($e.DCs)
            [pscustomobject]$o
        }
    }
    $ntlmRows = @(ConvertFrom-Agg $ntlmAgg | Sort-Object @{ Expression = { $_.NtlmVersion -ne 'NTLM V1' } }, @{ Expression = 'Count'; Descending = $true })
    Export-Dataset -Name 'ntlm-logons' -Rows $ntlmRows -Note 'NTLM V1 rows first - those are the urgent ones'
    if ($SkipNtlmValidation) { Set-DatasetStatus -Name 'ntlm-validations' -Status 'Deferred' -Note '-SkipNtlmValidation' }
    else { Export-Dataset -Name 'ntlm-validations' -Rows @(ConvertFrom-Agg $valAgg | Sort-Object Count -Descending) -Note 'Status 0x0 = success; 0xC000006A = bad password; 0xC0000064 = unknown user' }
    $kerbRows = @()
    if ($SkipKerberos) { Set-DatasetStatus -Name 'kerberos-weak-encryption' -Status 'Deferred' -Note '-SkipKerberos' }
    else { $kerbRows = @(ConvertFrom-Agg $kerbAgg | Sort-Object Count -Descending); Export-Dataset -Name 'kerberos-weak-encryption' -Rows $kerbRows -Note 'RC4 / DES tickets; check the account or service msDS-SupportedEncryptionTypes' }

    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Domain controllers queried' $DomainControllers.Count
    Add-Metric 'DC queries blocked' @($statusRows | Where-Object Status -eq 'Blocked').Count 'Usually Event Log Readers / RPC access'
    Add-Metric 'DC queries capped at MaxEventsPerQuery' @($statusRows | Where-Object CappedAtMax).Count 'Counts are a lower bound; shorten -Hours'
    $cov = @($statusRows | Where-Object { $_.HoursCovered -ne '' } | ForEach-Object { [double]$_.HoursCovered })
    Add-Metric 'Shortest window actually covered (hours)' $(if ($cov.Count) { ($cov | Measure-Object -Minimum).Minimum } else { 'unknown' }) "Requested: $Hours; limited by Security log size on each DC"
    $v1 = @($ntlmRows | Where-Object NtlmVersion -eq 'NTLM V1')
    Add-Metric 'NTLM V1 logons' ($v1 | Measure-Object Count -Sum).Sum 'Should be zero'
    Add-Metric 'Accounts using NTLM V1' @($v1 | Select-Object -ExpandProperty Account -Unique).Count
    Add-Metric 'Sources using NTLM V1' @($v1 | ForEach-Object { if ($_.SourceWorkstation) { $_.SourceWorkstation } else { $_.SourceIp } } | Select-Object -Unique).Count
    Add-Metric 'NTLM logons (all versions)' ($ntlmRows | Measure-Object Count -Sum).Sum
    Add-Metric 'Accounts using NTLM' @($ntlmRows | Select-Object -ExpandProperty Account -Unique).Count
    if (-not $SkipKerberos) {
        Add-Metric 'Weak-encryption Kerberos tickets' ($kerbRows | Measure-Object Count -Sum).Sum
        Add-Metric 'Services receiving RC4/DES tickets' @($kerbRows | Where-Object RequestType -eq 'ServiceTicket' | Select-Object -ExpandProperty Service -Unique).Count
        Add-Metric 'Accounts getting RC4/DES TGTs' @($kerbRows | Where-Object RequestType -eq 'TGT' | Select-Object -ExpandProperty Account -Unique).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ DomainControllers = $DomainControllers; Hours = $Hours; MaxEventsPerQuery = $MaxEventsPerQuery; SkipKerberos = [bool]$SkipKerberos; SkipNtlmValidation = [bool]$SkipNtlmValidation }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
