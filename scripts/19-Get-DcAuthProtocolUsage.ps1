<#
.SYNOPSIS
    Read-only measurement of legacy authentication on domain controllers: NTLM (v1 and v2) and
    Kerberos tickets issued with weak encryption (RC4 / DES).

.DESCRIPTION
    Shows what would break - and who is still exposed - before NTLM is restricted or RC4 is
    disabled. Reads the Security and NTLM Operational event logs on each domain controller for a
    time window, reads account encryption settings from AD, and aggregates:

      - NTLM logons (4624 with AuthenticationPackageName = NTLM), split by NTLM V1 / V2 / LM, by
        account, source workstation (with its operating system from AD) and IP
      - NTLM credential validations (4776) by account and workstation
      - NTLM audit events (NTLM Operational log, 8004) by account, client and target server -
        the server each NTLM logon was for, which 4624 on a DC does not show
      - Failed NTLM logons (4625) and failed Kerberos pre-authentication (4771)
      - Kerberos TGT (4768) and service ticket (4769) requests using RC4 or DES, by account,
        service and IP, including the newer encryption-type fields where the DC logs them
      - Kerberos TGTs issued without pre-authentication (4768, PreAuthType 0: AS-REP roastable)
      - Accounts whose msDS-SupportedEncryptionTypes allows only RC4/DES, and service accounts
        whose password predates AES keys in the domain, joined to the RC4 ticket events
      - Per-DC read status (events found, window actually covered, errors)
      - A summary of headline metrics

    Security logs often roll over in hours on busy DCs. The per-DC file shows the oldest event
    actually read, so the window covered is explicit. For longer history, query the SIEM.
    A missing NTLM audit log is reported as evidence unavailable, never as "no NTLM".

    READ-ONLY. Uses only Get-WinEvent and Get-AD* cmdlets.

    Output: <OutputRoot>\19-DcAuthProtocols\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER Hours
    Window to read, 1-720. 24 is the default; 168 gives a week where the logs hold that much.

.PARAMETER SkipFailures
    Skip the failed-logon queries (4625 NTLM, 4771 Kerberos pre-authentication).

.PARAMETER SkipNtlmAudit
    Skip the NTLM Operational log (8004).

.PARAMETER SkipAdAccounts
    Skip the AD read of account encryption settings (accounts-rc4-or-no-aes) and the source
    workstation operating system lookup.

.EXAMPLE
    .\19-Get-DcAuthProtocolUsage.ps1 -Hours 24
.EXAMPLE
    .\19-Get-DcAuthProtocolUsage.ps1 -Hours 168 -MaxEventsPerQuery 200000
.EXAMPLE
    .\19-Get-DcAuthProtocolUsage.ps1 -DomainControllers dc01.contoso.local,dc02.contoso.local -Hours 4 -SkipFailures

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x on Windows, RSAT ActiveDirectory module (to list DCs, read
              account encryption settings and workstation operating systems)
    Access  : membership of Event Log Readers on the domain controllers (or equivalent), and
              remote event log access (RPC) from the run host; domain read for the AD part
    Auditing: 4624 / 4625 / 4776 need "Audit Logon" / "Audit Credential Validation"; 4768 / 4769 /
              4771 need "Audit Kerberos Authentication Service" / "Service Ticket Operations".
              8004 needs "Network security: Restrict NTLM: Audit NTLM authentication in this
              domain" set on the DCs. If auditing is off, the counts are zero - check
              dc-read-status and dataset-status before concluding there is no usage.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # used to find DCs and read AD
    [string[]]$DomainControllers = @(),                     # blank = every DC in the domain
    [ValidateRange(1, 720)]
    [int]$Hours = 24,
    [int]$MaxEventsPerQuery = 50000,
    [switch]$SkipKerberos,
    [switch]$SkipNtlmValidation,                            # skip 4776 (often very high volume)
    [switch]$SkipNtlmAudit,                                 # skip NTLM Operational 8004
    [switch]$SkipFailures,                                  # skip 4625 / 4771
    [switch]$SkipAdAccounts                                 # skip the AD encryption-settings read and OS lookup
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '19-DcAuthProtocols'
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

$EncTypes = @{ '0x1' = 'DES-CBC-CRC'; '0x3' = 'DES-CBC-MD5'; '0x17' = 'RC4-HMAC'; '0x18' = 'RC4-HMAC-EXP' }
$NtlmLog = 'Microsoft-Windows-NTLM/Operational'

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
    param([string]$Computer, [string]$XPath, [string]$Label, [string]$LogName = 'Security', [int]$Max = $MaxEventsPerQuery)
    try {
        return @(Get-WinEvent -ComputerName $Computer -LogName $LogName -FilterXPath $XPath -MaxEvents $Max -ErrorAction Stop)
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') { return @() }
        throw ("{0}: {1}" -f $Label, $_.Exception.Message)
    }
}

function Get-EncTypeText {
    # Decodes an msDS-SupportedEncryptionTypes style bitmask (int or '0x..' string).
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '' -or "$Value" -eq '-') { return '' }
    $n = 0
    try { if ("$Value" -match '^0x[0-9a-fA-F]+$') { $n = [Convert]::ToInt32("$Value".Substring(2), 16) } else { $n = [int]"$Value" } } catch { return "$Value" }
    $names = @()
    if ($n -band 0x1) { $names += 'DES-CBC-CRC' }
    if ($n -band 0x2) { $names += 'DES-CBC-MD5' }
    if ($n -band 0x4) { $names += 'RC4-HMAC' }
    if ($n -band 0x8) { $names += 'AES128' }
    if ($n -band 0x10) { $names += 'AES256' }
    if ($n -band 0x20) { $names += 'AES256-SK' }
    if (-not $names.Count) { return ('0x{0:X} (none set)' -f $n) }
    return ($names -join ', ')
}

function ConvertTo-LdapValue { param([string]$Value) return ($Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace "`0", '\00') }

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    $adAvailable = $false
    $domain = $null
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain @script:AdParams
        $domainName = $domain.DNSRoot
        $adAvailable = $true
    }
    catch {
        if (-not $DomainControllers.Count) { throw }
        Write-RunLog ("ActiveDirectory not available ({0}); account checks and workstation OS lookup skipped" -f $_.Exception.Message) 'WARN'
    }
    if (-not $DomainControllers.Count) { $DomainControllers = @(Get-ADDomainController -Filter * @script:AdParams | ForEach-Object { $_.HostName }) }
    if (-not $domainName -and $DomainControllers.Count -and "$($DomainControllers[0])" -match '^[^.]+\.(.+)$') { $domainName = $Matches[1] }
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
        $queries['Kerberos-TGT-NoPreAuth'] = "*[System[(EventID=4768) and $time]] and *[EventData[Data[@Name='PreAuthType']='0']]"
    }
    if (-not $SkipFailures) {
        $queries['NTLM-Failed'] = "*[System[(EventID=4625) and $time]] and *[EventData[Data[@Name='AuthenticationPackageName']='NTLM']]"
        if (-not $SkipKerberos) { $queries['Kerberos-PreAuth-Failed'] = "*[System[(EventID=4771) and $time]]" }
    }

    $statusRows = [System.Collections.Generic.List[object]]::new()
    $ntlmAgg = @{}; $valAgg = @{}; $kerbAgg = @{}; $noPreAuthAgg = @{}; $ntlmFailAgg = @{}; $preAuthFailAgg = @{}; $auditAgg = @{}
    $auditUnavailable = [System.Collections.Generic.List[string]]::new(); $auditBlocked = [System.Collections.Generic.List[string]]::new()
    function Add-Agg {
        param([hashtable]$Table, [string]$Key, $Fields, [datetime]$When, $Extra = $null)
        if (-not $Table.ContainsKey($Key)) { $Table[$Key] = @{ Fields = $Fields; Extra = $Extra; Count = 0; First = $When; Last = $When; DCs = [System.Collections.Generic.HashSet[string]]::new() } }
        $e = $Table[$Key]; $e.Count++
        if ($When -lt $e.First) { $e.First = $When }
        if ($When -gt $e.Last) { $e.Last = $When; if ($Extra) { $e.Extra = $Extra } }
    }
    function Get-CoveredHours {
        # Hours actually covered: from the later of window start, log start and (when capped) the oldest event read.
        param($LogStart, $Oldest, [bool]$Capped)
        $windowStart = $script:RunStartUtc.AddHours(-$Hours)
        $start = $windowStart
        if ($LogStart -and $LogStart -gt $start) { $start = $LogStart }
        if ($Capped -and $Oldest -and $Oldest -gt $start) { $start = $Oldest }
        if (-not $LogStart -and -not ($Capped -and $Oldest)) { return '' }
        return [math]::Round(($script:RunStartUtc - $start).TotalHours, 1)
    }

    foreach ($dc in $DomainControllers) {
        # Where this DC's Security log actually starts, so the covered window is explicit.
        $logStart = $null
        try { $logStart = (Get-WinEvent -ComputerName $dc -LogName Security -MaxEvents 1 -Oldest -ErrorAction Stop | Select-Object -First 1).TimeCreated.ToUniversalTime() } catch { }
        foreach ($q in $queries.Keys) {
            $events = @()
            $err = ''
            try { $events = Get-DcEvents -Computer $dc -XPath $queries[$q] -Label $q } catch { $err = $_.Exception.Message; Write-RunLog ("{0} {1}" -f $dc, $err) 'WARN' }
            $oldest = $(if ($events.Count) { ($events | Measure-Object -Property TimeCreated -Minimum).Minimum.ToUniversalTime() } else { $null })
            $capped = ($events.Count -ge $MaxEventsPerQuery)
            $statusRows.Add([pscustomobject][ordered]@{
                DomainController = $dc
                Query            = $q
                Status           = $(if ($err) { 'Blocked' } else { 'Completed' })
                EventsRead       = $events.Count
                CappedAtMax      = $capped
                OldestMatchUtc   = $(if ($oldest) { $oldest.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                LogStartsUtc     = $(if ($logStart) { $logStart.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'unknown' })
                HoursCovered     = $(if ($err) { '' } else { Get-CoveredHours -LogStart $logStart -Oldest $oldest -Capped $capped })
                Error            = $err
            })
            foreach ($ev in $events) {
                $d = ConvertFrom-EventXml $ev
                $when = $ev.TimeCreated.ToUniversalTime()
                switch ($q) {
                    'NTLM-Logon' {
                        $lm = "$($d['LmPackageName'])".Trim()
                        $ver = $(if (-not $lm) { 'NTLM' } elseif ($lm -eq '-') { 'NTLM (anonymous/unknown)' } else { $lm })
                        $k = '{0}|{1}\{2}|{3}|{4}' -f $ver, $d['TargetDomainName'], $d['TargetUserName'], $d['WorkstationName'], $d['IpAddress']
                        Add-Agg -Table $ntlmAgg -Key $k -Fields ([ordered]@{ Account = "$($d['TargetDomainName'])\$($d['TargetUserName'])"; SourceIp = $d['IpAddress']; LogonType = $d['LogonType']; NtlmVersion = $ver; SourceWorkstation = $d['WorkstationName'] }) -When $when -Extra ([ordered]@{ Weak = ($ver -eq 'NTLM V1' -or $ver -match '^LM') })
                        $ntlmAgg[$k].DCs.Add($dc) | Out-Null
                    }
                    'NTLM-Validation' {
                        $k = '{0}|{1}|{2}' -f $d['TargetUserName'], $d['Workstation'], $d['Status']
                        Add-Agg -Table $valAgg -Key $k -Fields ([ordered]@{ Account = $d['TargetUserName']; SourceWorkstation = $d['Workstation']; Status = $d['Status'] }) -When $when
                        $valAgg[$k].DCs.Add($dc) | Out-Null
                    }
                    'NTLM-Failed' {
                        $k = '{0}\{1}|{2}|{3}|{4}|{5}' -f $d['TargetDomainName'], $d['TargetUserName'], $d['WorkstationName'], $d['IpAddress'], $d['Status'], $d['SubStatus']
                        Add-Agg -Table $ntlmFailAgg -Key $k -Fields ([ordered]@{ Account = "$($d['TargetDomainName'])\$($d['TargetUserName'])"; SourceWorkstation = $d['WorkstationName']; SourceIp = $d['IpAddress']; Status = $d['Status']; SubStatus = $d['SubStatus']; LmPackageName = $d['LmPackageName'] }) -When $when
                        $ntlmFailAgg[$k].DCs.Add($dc) | Out-Null
                    }
                    'Kerberos-PreAuth-Failed' {
                        $ip = ("$($d['IpAddress'])" -replace '^::ffff:', '')
                        $k = '{0}|{1}|{2}' -f $d['TargetUserName'], $ip, $d['Status']
                        Add-Agg -Table $preAuthFailAgg -Key $k -Fields ([ordered]@{ Account = $d['TargetUserName']; ClientIp = $ip; Status = $d['Status']; PreAuthType = $d['PreAuthType']; Service = $d['ServiceName'] }) -When $when
                        $preAuthFailAgg[$k].DCs.Add($dc) | Out-Null
                    }
                    'Kerberos-TGT-NoPreAuth' {
                        $ip = ("$($d['IpAddress'])" -replace '^::ffff:', '')
                        $encName = $(if ($EncTypes.ContainsKey($d['TicketEncryptionType'])) { $EncTypes[$d['TicketEncryptionType']] } else { $d['TicketEncryptionType'] })
                        $k = '{0}|{1}' -f $d['TargetUserName'], $ip
                        Add-Agg -Table $noPreAuthAgg -Key $k -Fields ([ordered]@{ Account = $d['TargetUserName']; ClientIp = $ip; Encryption = $encName }) -When $when
                        $noPreAuthAgg[$k].DCs.Add($dc) | Out-Null
                    }
                    default {
                        $encName = $(if ($EncTypes.ContainsKey($d['TicketEncryptionType'])) { $EncTypes[$d['TicketEncryptionType']] } else { $d['TicketEncryptionType'] })
                        $svc = $(if ($q -eq 'Kerberos-TGT-Weak') { 'krbtgt (TGT)' } else { $d['ServiceName'] })
                        $ip = ("$($d['IpAddress'])" -replace '^::ffff:', '')
                        $k = '{0}|{1}|{2}|{3}' -f $d['TargetUserName'], $svc, $encName, $ip
                        # Newer DCs log the encryption types each party supports; blank on older builds.
                        $extra = [ordered]@{ AccountSupportedEncryptionTypes = $d['AccountSupportedEncryptionTypes']; ServiceSupportedEncryptionTypes = $d['ServiceSupportedEncryptionTypes']; SessionKeyEncryptionType = $d['SessionKeyEncryptionType'] }
                        Add-Agg -Table $kerbAgg -Key $k -Fields ([ordered]@{ Account = $d['TargetUserName']; RequestType = $(if ($q -eq 'Kerberos-TGT-Weak') { 'TGT' } else { 'ServiceTicket' }); Service = $svc; ClientIp = $ip; Encryption = $encName }) -When $when -Extra $extra
                        $kerbAgg[$k].DCs.Add($dc) | Out-Null
                    }
                }
            }
        }

        # ---- NTLM Operational log (8004): only meaningful when NTLM auditing is enabled on the DC ----
        if (-not $SkipNtlmAudit) {
            $state = ''; $err = ''; $events = @(); $nLogStart = $null
            try {
                $cfg = Get-WinEvent -ListLog $NtlmLog -ComputerName $dc -ErrorAction Stop
                if (-not $cfg.IsEnabled) { $state = 'LogDisabled' } elseif (-not $cfg.RecordCount) { $state = 'LogEmpty' } else { $state = 'Enabled' }
            }
            catch { $state = 'Error'; $err = $_.Exception.Message }
            if ($state -eq 'Enabled') {
                try {
                    try { $nLogStart = (Get-WinEvent -ComputerName $dc -LogName $NtlmLog -MaxEvents 1 -Oldest -ErrorAction Stop | Select-Object -First 1).TimeCreated.ToUniversalTime() } catch { }
                    $events = Get-DcEvents -Computer $dc -LogName $NtlmLog -XPath "*[System[(EventID=8004) and $time]]" -Label 'NTLM-Audit-8004'
                    if ($events.Count -eq 0 -and @(Get-DcEvents -Computer $dc -LogName $NtlmLog -XPath '*[System[(EventID=8004)]]' -Label 'NTLM-Audit-8004' -Max 1).Count -eq 0) { $state = 'No8004' }
                }
                catch { $state = 'Error'; $err = $_.Exception.Message }
            }
            if ($state -eq 'Error') { $auditBlocked.Add($dc); Write-RunLog ("{0} NTLM-Audit-8004: {1}" -f $dc, $err) 'WARN' }
            elseif ($state -ne 'Enabled') { $auditUnavailable.Add($dc); $err = ("NTLM auditing not enabled on {0} ({1})" -f $dc, $state); Write-RunLog $err 'WARN' }
            $oldest = $(if ($events.Count) { ($events | Measure-Object -Property TimeCreated -Minimum).Minimum.ToUniversalTime() } else { $null })
            $capped = ($events.Count -ge $MaxEventsPerQuery)
            $statusRows.Add([pscustomobject][ordered]@{
                DomainController = $dc
                Query            = 'NTLM-Audit-8004'
                Status           = $(if ($state -eq 'Enabled') { 'Completed' } elseif ($state -eq 'Error') { 'Blocked' } else { 'EvidenceUnavailable' })
                EventsRead       = $events.Count
                CappedAtMax      = $capped
                OldestMatchUtc   = $(if ($oldest) { $oldest.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                LogStartsUtc     = $(if ($nLogStart) { $nLogStart.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'unknown' })
                HoursCovered     = $(if ($state -eq 'Enabled') { Get-CoveredHours -LogStart $nLogStart -Oldest $oldest -Capped $capped } else { '' })
                Error            = $err
            })
            foreach ($ev in $events) {
                $d = ConvertFrom-EventXml $ev
                $k = '{0}\{1}|{2}|{3}' -f $d['DomainName'], $d['UserName'], $d['WorkstationName'], $d['SChannelName']
                Add-Agg -Table $auditAgg -Key $k -Fields ([ordered]@{ Account = "$($d['DomainName'])\$($d['UserName'])"; ClientWorkstation = $d['WorkstationName']; TargetServer = $d['SChannelName'] }) -When $ev.TimeCreated.ToUniversalTime()
                $auditAgg[$k].DCs.Add($dc) | Out-Null
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
            if ($e.Extra) { foreach ($f in $e.Extra.Keys) { $o[$f] = $e.Extra[$f] } }
            [pscustomobject]$o
        }
    }
    function Get-QueryState {
        # Completed / Partial / Blocked for a dataset, from the per-DC rows of the queries feeding it.
        param([string[]]$Query, [string]$Note)
        $rows = @($statusRows | Where-Object { $Query -contains $_.Query })
        $bad = @($rows | Where-Object Status -ne 'Completed')
        if ($rows.Count -and $bad.Count -eq $rows.Count) { return @{ Status = 'Blocked'; Note = ("No DC readable for {0}; see dc-read-status. {1}" -f ($Query -join '/'), $Note) } }
        if ($bad.Count) { return @{ Status = 'Partial'; Note = ("Not read on: {0}. {1}" -f (Join-Values ($bad | ForEach-Object { $_.DomainController } | Select-Object -Unique)), $Note) } }
        return @{ Status = 'Completed'; Note = $Note }
    }

    # Source workstation operating system from AD (cached per name)
    $osCache = @{}
    function Get-SourceOs {
        param([string]$Name)
        if (-not $adAvailable -or $SkipAdAccounts) { return '' }
        $n = "$Name".Trim()
        if (-not $n -or $n -eq '-') { return '' }
        $key = $n.ToLowerInvariant()
        if ($osCache.ContainsKey($key)) { return $osCache[$key] }
        $v = ''
        try {
            $c = @(Get-ADComputer -LDAPFilter ("(sAMAccountName={0}`$)" -f (ConvertTo-LdapValue $n)) -Properties operatingSystem, operatingSystemVersion @script:AdParams | Select-Object -First 1)
            $v = $(if ($c.Count -and $c[0].operatingSystem) { ("{0} {1}" -f $c[0].operatingSystem, $c[0].operatingSystemVersion).Trim() } elseif ($c.Count) { 'InAD (no OS recorded)' } else { 'NotFoundInAD' })
        }
        catch { $v = 'LookupFailed' }
        $osCache[$key] = $v
        return $v
    }

    $ntlmRows = @(ConvertFrom-Agg $ntlmAgg | Sort-Object @{ Expression = { -not $_.Weak } }, @{ Expression = 'Count'; Descending = $true })
    foreach ($r in $ntlmRows) { $r | Add-Member -NotePropertyName SourceOS -NotePropertyValue (Get-SourceOs $r.SourceWorkstation) }
    $st = Get-QueryState 'NTLM-Logon' 'NTLM V1 and LM rows (Weak = True) first - those are the urgent ones'
    Export-Dataset -Name 'ntlm-logons' -Rows $ntlmRows -Status $st.Status -Note $st.Note
    if ($SkipNtlmValidation) { Set-DatasetStatus -Name 'ntlm-validations' -Status 'Deferred' -Note '-SkipNtlmValidation' }
    else { $st = Get-QueryState 'NTLM-Validation' 'Status 0x0 = success; 0xC000006A = bad password; 0xC0000064 = unknown user'; Export-Dataset -Name 'ntlm-validations' -Rows @(ConvertFrom-Agg $valAgg | Sort-Object Count -Descending) -Status $st.Status -Note $st.Note }

    $auditRows = @()
    if ($SkipNtlmAudit) { Set-DatasetStatus -Name 'ntlm-dc-audit-8004' -Status 'Deferred' -Note '-SkipNtlmAudit' }
    elseif (($auditUnavailable.Count + $auditBlocked.Count) -ge $DomainControllers.Count) {
        $why = @()
        if ($auditUnavailable.Count) { $why += ("NTLM auditing not enabled on {0}" -f ($auditUnavailable -join ', ')) }
        if ($auditBlocked.Count) { $why += ("NTLM log not readable on {0}" -f ($auditBlocked -join ', ')) }
        Set-DatasetStatus -Name 'ntlm-dc-audit-8004' -Status $(if ($auditUnavailable.Count) { 'EvidenceUnavailable' } else { 'Blocked' }) -Note ((Join-Values $why) + '. Not a "no NTLM" result.')
    }
    else {
        $auditRows = @(ConvertFrom-Agg $auditAgg | Sort-Object Count -Descending)
        $why = @()
        if ($auditUnavailable.Count) { $why += ("NTLM auditing not enabled on {0}" -f ($auditUnavailable -join ', ')) }
        if ($auditBlocked.Count) { $why += ("NTLM log not readable on {0}" -f ($auditBlocked -join ', ')) }
        Export-Dataset -Name 'ntlm-dc-audit-8004' -Rows $auditRows -Status $(if ($why.Count) { 'Partial' } else { 'Completed' }) -Note $(if ($why.Count) { Join-Values $why } else { 'TargetServer = the server the NTLM logon was for' })
    }

    if ($SkipFailures) {
        Set-DatasetStatus -Name 'ntlm-failed-logons' -Status 'Deferred' -Note '-SkipFailures'
        Set-DatasetStatus -Name 'kerberos-preauth-failures' -Status 'Deferred' -Note '-SkipFailures'
    }
    else {
        $st = Get-QueryState 'NTLM-Failed' 'Status/SubStatus 0xC000006A = bad password; 0xC0000064 = unknown user; 0xC0000234 = locked out'
        Export-Dataset -Name 'ntlm-failed-logons' -Rows @(ConvertFrom-Agg $ntlmFailAgg | Sort-Object Count -Descending) -Status $st.Status -Note $st.Note
        if ($SkipKerberos) { Set-DatasetStatus -Name 'kerberos-preauth-failures' -Status 'Deferred' -Note '-SkipKerberos' }
        else { $st = Get-QueryState 'Kerberos-PreAuth-Failed' 'Status 0x18 = bad password; 0x12 = account disabled/locked; 0x25 = clock skew'; Export-Dataset -Name 'kerberos-preauth-failures' -Rows @(ConvertFrom-Agg $preAuthFailAgg | Sort-Object Count -Descending) -Status $st.Status -Note $st.Note }
    }

    $kerbRows = @(); $noPreAuthRows = @()
    if ($SkipKerberos) {
        Set-DatasetStatus -Name 'kerberos-weak-encryption' -Status 'Deferred' -Note '-SkipKerberos'
        Set-DatasetStatus -Name 'kerberos-tgt-no-preauth' -Status 'Deferred' -Note '-SkipKerberos'
    }
    else {
        $kerbRows = @(ConvertFrom-Agg $kerbAgg | Sort-Object Count -Descending)
        $st = Get-QueryState 'Kerberos-TGT-Weak', 'Kerberos-TGS-Weak' 'RC4 / DES tickets; check the account or service msDS-SupportedEncryptionTypes'
        Export-Dataset -Name 'kerberos-weak-encryption' -Rows $kerbRows -Status $st.Status -Note $st.Note
        $noPreAuthRows = @(ConvertFrom-Agg $noPreAuthAgg | Sort-Object Count -Descending)
        $st = Get-QueryState 'Kerberos-TGT-NoPreAuth' 'TGTs issued without pre-authentication (DONT_REQ_PREAUTH): AS-REP roastable accounts'
        Export-Dataset -Name 'kerberos-tgt-no-preauth' -Rows $noPreAuthRows -Status $st.Status -Note $st.Note
    }

    # ---- AD: accounts that can only do RC4/DES, or whose password predates AES keys ----
    $acctRows = @()
    if ($SkipAdAccounts) { Set-DatasetStatus -Name 'accounts-rc4-or-no-aes' -Status 'Deferred' -Note '-SkipAdAccounts' }
    elseif (-not $adAvailable) { Set-DatasetStatus -Name 'accounts-rc4-or-no-aes' -Status 'EvidenceUnavailable' -Note 'ActiveDirectory module or domain not reachable from the run host' }
    else {
        try {
            $seen = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($r in $kerbRows) {
                foreach ($n in @($r.Account, $(if ($r.RequestType -eq 'ServiceTicket') { $r.Service } else { '' }))) {
                    $s = ("$n" -replace '@.*$', '').Trim().ToLowerInvariant()
                    if ($s) { [void]$seen.Add($s); [void]$seen.Add($s.TrimEnd('$')) }
                }
            }
            $byDn = [ordered]@{}
            $weakFilter = '(&(objectClass=user)(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.804:=7)(!(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.804:=24)))'
            foreach ($o in @(Get-ADObject -LDAPFilter $weakFilter -Properties sAMAccountName, objectClass, 'msDS-SupportedEncryptionTypes', userAccountControl, servicePrincipalName, pwdLastSet @script:AdParams)) {
                $byDn[$o.DistinguishedName] = @{ Obj = $o; Reasons = [System.Collections.Generic.List[string]]::new() }
                $byDn[$o.DistinguishedName].Reasons.Add('Rc4OrDesOnly')
            }
            $heuristicNote = ''
            $rodc = $null
            try { $rodc = Get-ADGroup -Identity ("{0}-521" -f $domain.DomainSID.Value) -Properties whenCreated @script:AdParams } catch { }
            if ($rodc -and $rodc.whenCreated) {
                $cut = ([datetime]$rodc.whenCreated).ToUniversalTime()
                $heuristicNote = ("PasswordPredatesAes = SPN user whose password was last set before {0} (creation of Read-only Domain Controllers, a proxy for when AES keys started being generated)" -f $cut.ToString('yyyy-MM-dd'))
                foreach ($u in @(Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName, pwdLastSet, 'msDS-SupportedEncryptionTypes', userAccountControl, objectClass @script:AdParams)) {
                    $pls = 0; try { $pls = [int64]"$($u.pwdLastSet)" } catch { }
                    if ($pls -le 0) { continue }
                    if ([datetime]::FromFileTimeUtc($pls) -ge $cut) { continue }
                    if (-not $byDn.Contains($u.DistinguishedName)) { $byDn[$u.DistinguishedName] = @{ Obj = $u; Reasons = [System.Collections.Generic.List[string]]::new() } }
                    $byDn[$u.DistinguishedName].Reasons.Add('PasswordPredatesAes')
                }
            }
            else { $heuristicNote = 'Read-only Domain Controllers group not found: password-age check not applied' }
            $acctRows = foreach ($dn in $byDn.Keys) {
                $o = $byDn[$dn].Obj
                $set = $o.'msDS-SupportedEncryptionTypes'
                $uac = 0; try { $uac = [int]"$($o.userAccountControl)" } catch { }
                $pls = 0; try { $pls = [int64]"$($o.pwdLastSet)" } catch { }
                $sam = "$($o.sAMAccountName)"
                [pscustomobject][ordered]@{
                    SamAccountName           = $sam
                    ObjectClass              = "$(@($o.objectClass)[-1])"
                    Enabled                  = -not ($uac -band 2)
                    SupportedEncryptionTypes = $(if ($null -ne $set -and "$set" -ne '') { '0x{0:X}' -f [int]"$set" } else { '(not set)' })
                    EncryptionTypesDecoded   = $(if ($null -ne $set -and "$set" -ne '') { Get-EncTypeText $set } else { 'Domain default' })
                    HasSpn                   = [bool](@($o.servicePrincipalName | Where-Object { $_ }).Count)
                    PwdLastSetUtc            = $(if ($pls -gt 0) { [datetime]::FromFileTimeUtc($pls).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                    Reason                   = Join-Values $byDn[$dn].Reasons
                    SeenInRc4Events          = $(if ($SkipKerberos) { 'not checked' } else { $seen.Contains($sam.ToLowerInvariant()) -or $seen.Contains($sam.TrimEnd('$').ToLowerInvariant()) })
                    DistinguishedName        = $dn
                }
            }
            Export-Dataset -Name 'accounts-rc4-or-no-aes' -Rows @($acctRows | Sort-Object @{ Expression = { "$($_.SeenInRc4Events)" -ne 'True' } }, SamAccountName) -Note $heuristicNote
        }
        catch {
            Set-DatasetStatus -Name 'accounts-rc4-or-no-aes' -Status 'Blocked' -Note ("AD read failed: {0}" -f $_.Exception.Message)
        }
    }

    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Domain controllers queried' $DomainControllers.Count
    Add-Metric -Metric 'DC queries blocked' -Value @($statusRows | Where-Object Status -eq 'Blocked').Count -Note 'Usually Event Log Readers / RPC access'
    Add-Metric -Metric 'DC queries capped at MaxEventsPerQuery' -Value @($statusRows | Where-Object CappedAtMax).Count -Note 'Counts are a lower bound; shorten -Hours'
    $cov = @($statusRows | Where-Object { $_.HoursCovered -ne '' } | ForEach-Object { [double]$_.HoursCovered })
    Add-Metric -Metric 'Shortest window actually covered (hours)' -Value $(if ($cov.Count) { ($cov | Measure-Object -Minimum).Minimum } else { 'unknown' }) -Note "Requested: $Hours; limited by log size on each DC (and by -MaxEventsPerQuery when capped)"
    $v1 = @($ntlmRows | Where-Object Weak)
    Add-Metric -Metric 'NTLM V1 logons' -Value ($v1 | Measure-Object Count -Sum).Sum -Note 'Includes LM; should be zero'
    Add-Metric -Metric 'Accounts using NTLM V1' -Value @($v1 | Select-Object -ExpandProperty Account -Unique).Count -Note 'Includes LM'
    Add-Metric -Metric 'Sources using NTLM V1' -Value @($v1 | ForEach-Object { if ($_.SourceWorkstation) { $_.SourceWorkstation } else { $_.SourceIp } } | Select-Object -Unique).Count -Note 'Includes LM'
    Add-Metric 'NTLM logons (all versions)' ($ntlmRows | Measure-Object Count -Sum).Sum
    Add-Metric 'Accounts using NTLM' @($ntlmRows | Select-Object -ExpandProperty Account -Unique).Count
    if (-not $SkipNtlmAudit) {
        Add-Metric -Metric 'NTLM audit (8004): servers receiving NTLM' -Value $(if ($auditUnavailable.Count + $auditBlocked.Count -ge $DomainControllers.Count) { 'not available' } else { @($auditRows | Select-Object -ExpandProperty TargetServer -Unique).Count }) -Note $(if ($auditUnavailable.Count) { "NTLM auditing not enabled on $($auditUnavailable -join ', ')" } else { '' })
    }
    if (-not $SkipFailures) {
        Add-Metric 'Failed NTLM logons' (@(ConvertFrom-Agg $ntlmFailAgg) | Measure-Object Count -Sum).Sum
        if (-not $SkipKerberos) { Add-Metric 'Failed Kerberos pre-authentications' (@(ConvertFrom-Agg $preAuthFailAgg) | Measure-Object Count -Sum).Sum }
    }
    if (-not $SkipKerberos) {
        Add-Metric 'Weak-encryption Kerberos tickets' ($kerbRows | Measure-Object Count -Sum).Sum
        Add-Metric 'Services receiving RC4/DES tickets' @($kerbRows | Where-Object RequestType -eq 'ServiceTicket' | Select-Object -ExpandProperty Service -Unique).Count
        Add-Metric 'Accounts getting RC4/DES TGTs' @($kerbRows | Where-Object RequestType -eq 'TGT' | Select-Object -ExpandProperty Account -Unique).Count
        Add-Metric -Metric 'Accounts getting TGTs without pre-authentication' -Value @($noPreAuthRows | Select-Object -ExpandProperty Account -Unique).Count -Note 'AS-REP roastable'
    }
    if (-not $SkipAdAccounts -and $adAvailable) {
        Add-Metric -Metric 'Accounts allowing only RC4/DES' -Value @($acctRows | Where-Object { $_.Reason -match 'Rc4OrDesOnly' }).Count -Note 'msDS-SupportedEncryptionTypes without AES bits'
        Add-Metric -Metric 'Service accounts with a password older than AES keys' -Value @($acctRows | Where-Object { $_.Reason -match 'PasswordPredatesAes' }).Count -Note 'Heuristic; a password reset creates AES keys'
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ DomainControllers = $DomainControllers; Hours = $Hours; MaxEventsPerQuery = $MaxEventsPerQuery; SkipKerberos = [bool]$SkipKerberos; SkipNtlmValidation = [bool]$SkipNtlmValidation; SkipNtlmAudit = [bool]$SkipNtlmAudit; SkipFailures = [bool]$SkipFailures; SkipAdAccounts = [bool]$SkipAdAccounts }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
