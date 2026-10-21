<#
.SYNOPSIS
    Read-only inventory of every attribute the AD schema allows on users (and optionally groups and
    computers), with how many objects actually have a value in each.

.DESCRIPTION
    Answers "what is really populated in this directory, and what isn't" before attributes are
    chosen to drive roles, sync rules or lifecycle automation.

    1. Reads the schema and works out every attribute the class can hold: the class itself, every
       class it inherits from (user -> organizationalPerson -> person -> top) and every auxiliary
       class attached anywhere in that chain (for example Exchange's mail classes). Attributes that
       are never populated still appear, with 0.
    2. Reads every object of that class once, in batches of attributes, and counts per attribute:
       objects with a value, total values (multi-valued), distinct values and the longest value.
    3. Large binary attributes (photos, certificates, other octet strings) are counted with a
       presence-only query, so their content is never downloaded.

    Per attribute it also reports: data type, single- or multi-valued, mandatory, the class that
    brings it in, global catalog (partial attribute set), linked (forward / back link), system-only,
    not replicated, and confidential.

    Not counted, and reported as such:
      - constructed attributes (computed on read, not stored; MS-ADTS 2.2.10 FLAG_ATTR_IS_CONSTRUCTED)
      - base-only attributes (a search across many objects that asks for them fails; MS-ADTS 2.2.9 fBASEONLY)
      - security descriptors (nTSecurityDescriptor; present on every object)

    Confidential attributes (MS-ADTS 2.2.9 fCONFIDENTIAL) are only returned to accounts with the
    extended read right, so a count of 0 there means "empty or not readable by the run account" and
    is marked that way. Not-replicated attributes (lastLogon, badPwdCount, logonCount ...) hold a
    per-DC value: the count reflects the DC queried.

    No values are written unless -SampleValueCount is set: directory-wide values are personal data.

    READ-ONLY. Uses only Get-AD* cmdlets.

    Output: <OutputRoot>\23-ADAttributePopulation\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER ObjectClass
    Which classes to inventory: user (default), group, computer, or several.

.PARAMETER EnabledOnly
    Users and computers: only enabled accounts.

.PARAMETER SampleValueCount
    Most common values to show per attribute (0 = none, the default). Only for attributes you know
    hold no personal data; samples come from at most -DistinctValueCap distinct values.

.PARAMETER DistinctValueCap
    Stop counting distinct values for an attribute above this many (reported as "<cap>+"). Bounds memory.

.PARAMETER BatchSize
    Attributes requested per pass over the objects. Smaller = more passes but lighter requests.

.PARAMETER SkipPresenceQueries
    Don't run the presence-only queries for binary attributes (faster; those show as Not counted).

.EXAMPLE
    .\23-Get-ADAttributePopulation.ps1 -Server DC1.contoso.local
.EXAMPLE
    .\23-Get-ADAttributePopulation.ps1 -Server DC1.contoso.local -ObjectClass user,group,computer -EnabledOnly
.EXAMPLE
    .\23-Get-ADAttributePopulation.ps1 -SearchBase 'OU=People,DC=contoso,DC=local'

.NOTES
    Version : 1.0.1
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, read access to the domain and schema
              (any authenticated user by default).
    Load    : reads every attribute of every object of each class (one pass per batch). Run off-peak
              in large domains; -SearchBase or -ObjectClass user alone keeps it lighter.
    Sources : searchFlags and systemFlags bits from [MS-ADTS] 2.2.9 and 2.2.10; attribute syntaxes from
              the Active Directory syntax table (attributeSyntax 2.5.5.x).
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # e.g. 'dc01.contoso.local'
    [string]$SearchBase = '',                               # blank = whole domain
    [ValidateSet('user', 'group', 'computer')]
    [string[]]$ObjectClass = @('user'),
    [switch]$EnabledOnly,
    [ValidateRange(0, 20)]
    [int]$SampleValueCount = 0,
    [ValidateRange(10, 100000)]
    [int]$DistinctValueCap = 1000,
    [ValidateRange(10, 500)]
    [int]$BatchSize = 100,
    [switch]$SkipPresenceQueries
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '23-ADAttributePopulation'
$ScriptVersion = '1.0.1'

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

# ---- Script-specific constants ([MS-ADTS] 2.2.9 / 2.2.10; attribute syntax table) ----
$FLAG_ATTR_NOT_REPLICATED = 0x1
$FLAG_ATTR_IS_CONSTRUCTED = 0x4
$fCONFIDENTIAL            = 0x80
$fBASEONLY                = 0x800
# Attribute syntaxes are 2.5.5.<n>; keyed by <n> so the source holds no dotted quads.
$SyntaxPrefix = '2.5.5.'
$SyntaxNames = @{
    1 = 'DN'; 2 = 'OID'; 3 = 'Case-sensitive string'; 4 = 'Case-insensitive string'; 5 = 'Printable / IA5 string'
    6 = 'Numeric string'; 7 = 'DN with binary'; 8 = 'Boolean'; 9 = 'Integer'; 10 = 'Octet string (binary)'; 11 = 'Time'
    12 = 'Unicode string'; 13 = 'Presentation address'; 14 = 'DN with string'; 15 = 'Security descriptor'; 16 = 'Large integer'; 17 = 'SID'
}
$SYNTAX_OCTET_STRING = 10
$SYNTAX_SECURITY_DESCRIPTOR = 15
function Get-SyntaxNumber { param([string]$Syntax) if ($Syntax.StartsWith($SyntaxPrefix)) { $n = 0; if ([int]::TryParse($Syntax.Substring($SyntaxPrefix.Length), [ref]$n)) { return $n } } return -1 }
$ClassFilters = @{
    user     = '(&(objectCategory=person)(objectClass=user))'
    group    = '(objectClass=group)'
    computer = '(objectClass=computer)'
}
$DisabledClause = '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'

function ConvertTo-ValueText {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($Value -is [byte[]]) { return [Convert]::ToBase64String($Value) }
    return [string]$Value
}

function Get-FlagValue { param($Value) if ($null -eq $Value -or "$Value" -eq '') { return 0 } return [int64]"$Value" }

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainName = (Get-ADDomain @script:AdParams).DNSRoot
    $rootDse = Get-ADRootDSE @script:AdParams
    $schemaNC = [string]$rootDse.schemaNamingContext
    Write-RunLog "Domain: $domainName  Schema: $schemaNC"

    # ---- 1. Schema: classes and attributes ----
    Write-RunLog 'Reading schema classes...'
    $classProps = 'lDAPDisplayName', 'governsID', 'subClassOf', 'auxiliaryClass', 'systemAuxiliaryClass', 'mayContain', 'systemMayContain', 'mustContain', 'systemMustContain', 'objectClassCategory'
    $classes = @{}; $classByOid = @{}
    foreach ($c in @(Get-ADObject -SearchBase $schemaNC -LDAPFilter '(objectClass=classSchema)' -Properties $classProps @script:AdParams)) {
        $classes[[string]$c.lDAPDisplayName] = $c
        if ($c.governsID) { $classByOid[[string]$c.governsID] = [string]$c.lDAPDisplayName }
    }
    Write-RunLog 'Reading schema attributes...'
    $attrProps = 'lDAPDisplayName', 'attributeID', 'attributeSyntax', 'isSingleValued', 'searchFlags', 'systemFlags', 'isMemberOfPartialAttributeSet', 'linkID', 'systemOnly', 'rangeUpper', 'isDefunct'
    $attributes = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $attrByOid = @{}
    foreach ($a in @(Get-ADObject -SearchBase $schemaNC -LDAPFilter '(objectClass=attributeSchema)' -Properties $attrProps @script:AdParams)) {
        if ("$($a.isDefunct)" -eq 'True') { continue }
        $attributes[[string]$a.lDAPDisplayName] = $a
        if ($a.attributeID) { $attrByOid[[string]$a.attributeID] = [string]$a.lDAPDisplayName }
    }
    Write-RunLog ("Schema: {0} classes, {1} attributes" -f $classes.Count, $attributes.Count)

    # Schema values may come back as OIDs or names; resolve either way.
    function Resolve-ClassName { param([string]$Value) if ($classes.ContainsKey($Value)) { return $Value } if ($classByOid.ContainsKey($Value)) { return $classByOid[$Value] } return $Value }
    function Resolve-AttrName { param([string]$Value) if ($attributes.ContainsKey($Value)) { return $attributes[$Value].lDAPDisplayName } if ($attrByOid.ContainsKey($Value)) { return $attrByOid[$Value] } return $Value }

    $populationRows = [System.Collections.Generic.List[object]]::new()
    $closureRows    = [System.Collections.Generic.List[object]]::new()
    $summary        = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }

    foreach ($cls in $ObjectClass) {
        Write-RunLog "==== $cls ===="
        if (-not $classes.ContainsKey($cls)) { Set-DatasetStatus -Name "attribute-population-$cls" -Status 'EvidenceUnavailable' -Note "class $cls not found in schema"; continue }

        # ---- 2. Class closure: superclasses + auxiliary classes (recursively) ----
        $seen = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
        $queue = [System.Collections.Generic.Queue[object]]::new()
        $queue.Enqueue(@($cls, 'Structural (this class)'))
        while ($queue.Count) {
            $item = $queue.Dequeue(); $name = [string]$item[0]; $how = [string]$item[1]
            if ($seen.ContainsKey($name)) { continue }
            $seen[$name] = $how
            if (-not $classes.ContainsKey($name)) { continue }
            $c = $classes[$name]
            $sup = Resolve-ClassName ([string]$c.subClassOf)
            if ($sup -and $sup -ne $name) { $queue.Enqueue(@($sup, "Inherited (superclass of $name)")) }
            foreach ($aux in @(@($c.auxiliaryClass) + @($c.systemAuxiliaryClass) | Where-Object { $_ })) { $queue.Enqueue(@((Resolve-ClassName ([string]$aux)), "Auxiliary (attached to $name)")) }
        }

        $allowed = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $seen.Keys) {
            if (-not $classes.ContainsKey($name)) { continue }
            $c = $classes[$name]
            $must = @(@($c.mustContain) + @($c.systemMustContain) | Where-Object { $_ } | ForEach-Object { Resolve-AttrName ([string]$_) })
            $may  = @(@($c.mayContain) + @($c.systemMayContain) | Where-Object { $_ } | ForEach-Object { Resolve-AttrName ([string]$_) })
            foreach ($n in $must) { if (-not $allowed.ContainsKey($n)) { $allowed[$n] = [pscustomobject]@{ DefinedBy = $name; Mandatory = $true } } else { $allowed[$n].Mandatory = $true } }
            foreach ($n in $may) { if (-not $allowed.ContainsKey($n)) { $allowed[$n] = [pscustomobject]@{ DefinedBy = $name; Mandatory = $false } } }
            $closureRows.Add([pscustomobject][ordered]@{ ObjectClass = $cls; SchemaClass = $name; HowIncluded = $seen[$name]; Attributes = ($must.Count + $may.Count) })
        }
        Write-RunLog ("{0}: {1} classes in closure, {2} attributes allowed" -f $cls, $seen.Count, $allowed.Count)

        # ---- 3. Plan: what can be read in bulk, what needs a presence query, what is not counted ----
        $plan = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $allowed.Keys) {
            $a = $null
            if ($attributes.ContainsKey($n)) { $a = $attributes[$n] }
            $syntax = if ($a) { [string]$a.attributeSyntax } else { '' }
            $syntaxNo = Get-SyntaxNumber $syntax
            $sys = if ($a) { Get-FlagValue $a.systemFlags } else { 0 }
            $sf  = if ($a) { Get-FlagValue $a.searchFlags } else { 0 }
            $link = if ($a -and "$($a.linkID)" -ne '') { [int]"$($a.linkID)" } else { $null }
            $method = if (-not $a) { 'Unknown' }
                      elseif ($sys -band $FLAG_ATTR_IS_CONSTRUCTED) { 'Constructed' }
                      elseif ($sf -band $fBASEONLY) { 'BaseOnly' }
                      elseif ($syntaxNo -eq $SYNTAX_SECURITY_DESCRIPTOR) { 'SecurityDescriptor' }
                      elseif ($syntaxNo -eq $SYNTAX_OCTET_STRING) { 'Presence' }
                      else { 'Bulk' }
            $plan[$n] = [pscustomobject]@{
                Name         = $(if ($a) { [string]$a.lDAPDisplayName } else { $n })
                Method       = $method
                Syntax       = $(if ($SyntaxNames.ContainsKey($syntaxNo)) { $SyntaxNames[$syntaxNo] } else { $syntax })
                SingleValued = $(if ($a) { "$($a.isSingleValued)" -eq 'True' } else { $null })
                Confidential = [bool]($sf -band $fCONFIDENTIAL)
                NotReplicated = [bool]($sys -band $FLAG_ATTR_NOT_REPLICATED)
                InGlobalCatalog = $(if ($a) { "$($a.isMemberOfPartialAttributeSet)" -eq 'True' } else { $null })
                Linked       = $(if ($null -eq $link) { '' } elseif ($link % 2 -eq 0) { 'Forward link' } else { 'Back link' })
                SystemOnly   = $(if ($a) { "$($a.systemOnly)" -eq 'True' } else { $null })
                Populated = 0; TotalValues = 0; MaxLength = 0; Overflow = $false; ReadError = ''
                Values = [System.Collections.Generic.Dictionary[string, int]]::new([StringComparer]::Ordinal)
            }
        }

        $filter = $ClassFilters[$cls]
        if ($EnabledOnly -and $cls -in 'user', 'computer') { $filter = "(&$filter$DisabledClause)" }
        $p = @{} + $script:AdParams
        if ($SearchBase) { $p['SearchBase'] = $SearchBase }

        # ---- 4. Bulk passes ----
        $bulk = @($plan.Values | Where-Object Method -eq 'Bulk' | ForEach-Object { $_.Name } | Sort-Object)
        $objectCount = $null
        $batches = [math]::Ceiling($bulk.Count / [double]$BatchSize)
        for ($b = 0; $b -lt $batches; $b++) {
            $chunk = @($bulk[($b * $BatchSize)..([math]::Min($bulk.Count, ($b + 1) * $BatchSize) - 1)])
            Write-RunLog ("{0}: pass {1} of {2} ({3} attributes)" -f $cls, ($b + 1), $batches, $chunk.Count)
            $want = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($n in $chunk) { $want[$n] = $plan[$n] }
            $seenThisPass = 0
            try {
                Get-ADObject -LDAPFilter $filter -Properties $chunk -ResultPageSize 500 @p | ForEach-Object {
                    $seenThisPass++
                    $obj = $_
                    $names = if ($null -ne $obj.PropertyNames) { $obj.PropertyNames } else { $obj.PSObject.Properties.Name }
                    foreach ($pn in $names) {
                        if (-not $want.ContainsKey($pn)) { continue }
                        $entry = $want[$pn]
                        $vals = @($obj.$pn | Where-Object { $null -ne $_ -and "$_" -ne '' })
                        if (-not $vals.Count) { continue }
                        $entry.Populated++
                        $entry.TotalValues += $vals.Count
                        foreach ($v in $vals) {
                            $t = ConvertTo-ValueText $v
                            if ($t.Length -gt $entry.MaxLength) { $entry.MaxLength = $t.Length }
                            if ($entry.Values.ContainsKey($t)) { $entry.Values[$t]++ }
                            elseif ($entry.Values.Count -lt $DistinctValueCap) { $entry.Values[$t] = 1 }
                            else { $entry.Overflow = $true }
                        }
                    }
                }
                if ($null -eq $objectCount) { $objectCount = $seenThisPass }
            }
            catch {
                $msg = $_.Exception.Message
                Write-RunLog ("{0}: pass {1} failed ({2}); counting this batch one attribute at a time" -f $cls, ($b + 1), $msg) 'WARN'
                foreach ($n in $chunk) {
                    try {
                        $c = 0
                        Get-ADObject -LDAPFilter "(&$filter($n=*))" -ResultPageSize 500 @p | ForEach-Object { $c++ }
                        $plan[$n].Populated = $c
                        $plan[$n].ReadError = 'Counted by presence query (bulk read failed): no value statistics'
                    }
                    catch { $plan[$n].ReadError = "Read failed: $($_.Exception.Message)" }
                }
            }
        }
        if ($null -eq $objectCount) {
            $objectCount = 0
            Get-ADObject -LDAPFilter $filter -ResultPageSize 500 @p | ForEach-Object { $objectCount++ }
        }
        Write-RunLog ("{0}: {1} objects" -f $cls, $objectCount)

        # ---- 5. Presence-only counts for binary attributes ----
        $presence = @($plan.Values | Where-Object Method -eq 'Presence')
        if ($SkipPresenceQueries) { foreach ($e in $presence) { $e.ReadError = 'Not counted (-SkipPresenceQueries)' } }
        else {
            Write-RunLog ("{0}: {1} binary attributes counted by presence only" -f $cls, $presence.Count)
            foreach ($e in $presence) {
                try {
                    $c = 0
                    Get-ADObject -LDAPFilter "(&$filter($($e.Name)=*))" -ResultPageSize 500 @p | ForEach-Object { $c++ }
                    $e.Populated = $c
                }
                catch { $e.ReadError = "Read failed: $($_.Exception.Message)" }
            }
        }

        # ---- 6. Rows ----
        foreach ($e in ($plan.Values | Sort-Object Name)) {
            $status = switch ($e.Method) {
                'Constructed'        { 'Not counted (constructed: computed on read)' }
                'BaseOnly'           { 'Not counted (base-only: not returned by searches)' }
                'SecurityDescriptor' { 'Not counted (security descriptor)' }
                'Unknown'            { 'Not counted (defunct or not in schema)' }
                default {
                    if ($e.ReadError -like 'Read failed*' -or $e.ReadError -like 'Not counted*') { $e.ReadError -replace '^Read failed.*', 'Read failed' }
                    elseif ($e.Populated -gt 0) { 'Populated' }
                    elseif ($e.Confidential) { 'Empty or not readable (confidential)' }
                    else { 'Empty' }
                }
            }
            $counted = ($e.Method -in 'Bulk', 'Presence') -and $status -notlike 'Not counted*' -and $status -ne 'Read failed'
            $notes = @()
            if ($e.NotReplicated) { $notes += 'Per-DC value (not replicated): count is from the DC queried' }
            if ($e.Method -eq 'Presence' -and $counted) { $notes += 'Binary: counted by presence only' }
            if ($e.ReadError -and $e.ReadError -notlike 'Not counted*') { $notes += $e.ReadError }
            $distinct = if ($e.Method -ne 'Bulk' -or -not $counted -or $e.ReadError) { '' } elseif ($e.Overflow) { "$DistinctValueCap+" } else { $e.Values.Count }
            $row = [ordered]@{
                ObjectClass      = $cls
                Attribute        = $e.Name
                Status           = $status
                Populated        = $(if ($counted) { $e.Populated } else { '' })
                Objects          = $objectCount
                PercentPopulated = $(if ($counted -and $objectCount) { [math]::Round(100.0 * $e.Populated / $objectCount, 1) } else { '' })
                TotalValues      = $(if ($counted -and $e.Method -eq 'Bulk' -and -not $e.ReadError) { $e.TotalValues } else { '' })
                DistinctValues   = $distinct
                MaxLength        = $(if ($counted -and $e.Method -eq 'Bulk' -and -not $e.ReadError) { $e.MaxLength } else { '' })
                Syntax           = $e.Syntax
                SingleValued     = $e.SingleValued
                Mandatory        = $allowed[$e.Name].Mandatory
                DefinedBy        = $allowed[$e.Name].DefinedBy
                InGlobalCatalog  = $e.InGlobalCatalog
                Linked           = $e.Linked
                SystemOnly       = $e.SystemOnly
                Confidential     = $e.Confidential
                Note             = ($notes -join '; ')
            }
            if ($SampleValueCount -gt 0) {
                $row['SampleValues'] = $(if ($e.Method -eq 'Bulk' -and $e.Values.Count) {
                        (($e.Values.GetEnumerator() | Sort-Object -Property @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key'; Descending = $false } |
                            Select-Object -First $SampleValueCount | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value }) -join ' | ')
                    } else { '' })
            }
            $populationRows.Add([pscustomobject]$row)
        }

        $mine = @($populationRows | Where-Object ObjectClass -eq $cls)
        $countedRows = @($mine | Where-Object { $_.Populated -isnot [string] })   # '' = not counted; never compare with -ne '' (0 -ne '' is False)
        Add-Metric "$cls objects scanned" $objectCount $(if ($EnabledOnly -and $cls -in 'user', 'computer') { 'Enabled only' } else { '' })
        Add-Metric "$cls attributes allowed by schema" $mine.Count ("{0} classes in closure" -f $seen.Count)
        Add-Metric "$cls attributes populated on at least one object" @($countedRows | Where-Object { $_.Populated -gt 0 }).Count
        Add-Metric "$cls attributes populated on every object" @($countedRows | Where-Object { $objectCount -gt 0 -and $_.Populated -eq $objectCount }).Count
        Add-Metric "$cls attributes never populated" @($countedRows | Where-Object { $_.Populated -eq 0 }).Count 'Includes confidential attributes that may only be unreadable'
        Add-Metric "$cls confidential attributes" @($mine | Where-Object Confidential).Count
        Add-Metric "$cls attributes not counted" @($mine | Where-Object { $_.Populated -is [string] }).Count 'Constructed, base-only, security descriptor, skipped or read failed'
    }

    Export-Dataset -Name 'attribute-population' -Rows $populationRows -Note 'One row per class and attribute; Populated = objects with at least one value'
    Export-Dataset -Name 'schema-class-closure' -Rows $closureRows -Note 'Classes whose attributes apply: the class, its superclasses and auxiliary classes'
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ SearchBase = $SearchBase; ObjectClass = $ObjectClass; EnabledOnly = [bool]$EnabledOnly; SampleValueCount = $SampleValueCount; DistinctValueCap = $DistinctValueCap; BatchSize = $BatchSize; SkipPresenceQueries = [bool]$SkipPresenceQueries }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
