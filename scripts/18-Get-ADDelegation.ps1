<#
.SYNOPSIS
    Read-only review of delegated permissions (ACLs) on the AD objects that matter most: the
    domain root, AdminSDHolder, the Domain Controllers OU, every OU, and the protected groups.

.DESCRIPTION
    Group membership (script 04) is only half of privileged access. Accounts and groups that hold
    dangerous rights through ACLs - full control, reset password, write members, DCSync - are
    effectively administrators too, and are often forgotten. This script reads the explicit
    (non-inherited) access control entries on each target and exports:

      - One row per risky delegation held by a non-default trustee: target, tier, trustee,
        right (FullControl, ModifyPermissions, TakeOwnership, WriteAllProperties, ResetPassword,
        WriteMembers, WriteSPN, WriteKeyCredential, WriteRBCD, AllExtendedRights, DCSync,
        ReadLAPSPassword, CreateObjects ...), object type it applies to, and severity
      - Object owners that are not a default administrative principal
      - One row per trustee with all rights summarised (the "who can do what" view)
      - A summary of headline metrics

    Default trustees (SYSTEM, Domain/Enterprise Admins, Administrators, domain controllers,
    SELF, CREATOR OWNER, Key Admins, Authenticated Users read, etc.) are excluded so the output
    shows delegations someone made. Builtin operator groups are included and marked.

    GUIDs are resolved from this forest's schema and extended rights, so forest-specific
    attributes (for example the LAPS password attribute) are named correctly.

    READ-ONLY. Uses only Get-AD* cmdlets. Nothing in the directory is changed.

    Output: <OutputRoot>\18-ADDelegation\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\18-Get-ADDelegation.ps1
.EXAMPLE
    .\18-Get-ADDelegation.ps1 -Server dc01.contoso.local -SkipOUs
.EXAMPLE
    .\18-Get-ADDelegation.ps1 -AdditionalTargets 'CN=Group1,OU=Groups,DC=contoso,DC=local' -IncludeInherited

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account
              (authenticated users can read DACLs on most objects; the SACL is not read)
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # e.g. 'dc01.contoso.local'
    [switch]$SkipOUs,                                       # only Tier 0 targets
    [string[]]$AdditionalTargets = @(),                     # extra DNs to review
    [switch]$IncludeInherited,                              # also report inherited ACEs (noisy)
    [switch]$IncludeLowSeverity                             # include CreateObjects / delete-child rows
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '18-ADDelegation'
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

# ActiveDirectoryRights flag values (System.DirectoryServices.ActiveDirectoryRights), as integers so
# the script does not depend on the enum type being loaded.
$Rights = @{ CreateChild = 1; DeleteChild = 2; Self = 8; WriteProperty = 32; ExtendedRight = 256; Delete = 65536
    GenericWrite = 131112; WriteDacl = 262144; WriteOwner = 524288; GenericAll = 983551 }

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain @script:AdParams
    $domainName = $domain.DNSRoot
    $dSid = $domain.DomainSID.Value
    $root = Get-ADRootDSE @script:AdParams
    $forestSid = $dSid
    try { $forestSid = (Get-ADDomain -Identity (Get-ADForest @script:AdParams).RootDomain @script:AdParams).DomainSID.Value } catch { }

    # ---- GUID maps from this forest ----
    Write-RunLog 'Reading schema and extended-rights GUIDs...'
    # Schema (attributes / classes) and extended rights are kept apart: some GUIDs are shared
    # (e.g. 'member' and Self-Membership, 'servicePrincipalName' and Validated-SPN).
    $schemaName = @{}; $rightName = @{}
    foreach ($s in @(Get-ADObject -SearchBase $root.schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties lDAPDisplayName, schemaIDGUID @script:AdParams)) {
        $schemaName[([guid]::new([byte[]]$s.schemaIDGUID)).ToString()] = $s.lDAPDisplayName
    }
    foreach ($e in @(Get-ADObject -SearchBase ("CN=Extended-Rights,{0}" -f $root.configurationNamingContext) -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGuid @script:AdParams)) {
        if ($e.rightsGuid) { $rightName["$($e.rightsGuid)".ToLowerInvariant()] = $e.name }
    }
    Write-RunLog ("{0} schema and {1} extended-right GUIDs mapped" -f $schemaName.Count, $rightName.Count)
    function Get-GuidName {
        # -Kind Schema for property / class GUIDs, Right for extended rights and validated writes
        param([guid]$Guid, [ValidateSet('Schema', 'Right')][string]$Kind = 'Schema')
        if ($Guid -eq [guid]::Empty) { return '' }
        $k = $Guid.ToString()
        $first = $(if ($Kind -eq 'Right') { $rightName } else { $schemaName }); $second = $(if ($Kind -eq 'Right') { $schemaName } else { $rightName })
        if ($first.ContainsKey($k)) { return $first[$k] }
        if ($second.ContainsKey($k)) { return $second[$k] }
        return $k
    }

    # ---- Default trustees ----
    $defaultSids = @{
        'S-1-5-18' = 'SYSTEM'; 'S-1-5-32-544' = 'Administrators'; 'S-1-5-9' = 'Enterprise Domain Controllers'
        'S-1-3-0' = 'CREATOR OWNER'; 'S-1-5-10' = 'SELF'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-1-0' = 'Everyone'
        'S-1-5-32-554' = 'Pre-Windows 2000 Compatible Access'; 'S-1-5-32-560' = 'Windows Authorization Access Group'
        'S-1-5-32-561' = 'Terminal Server License Servers'; 'S-1-5-20' = 'NETWORK SERVICE'
        "$dSid-512" = 'Domain Admins'; "$forestSid-519" = 'Enterprise Admins'; "$forestSid-518" = 'Schema Admins'
        "$dSid-516" = 'Domain Controllers'; "$dSid-521" = 'Read-only Domain Controllers'; "$forestSid-498" = 'Enterprise Read-only Domain Controllers'
        "$dSid-526" = 'Key Admins'; "$forestSid-527" = 'Enterprise Key Admins'; "$dSid-517" = 'Cert Publishers'
    }
    $builtinOperators = @{ 'S-1-5-32-548' = 'Account Operators'; 'S-1-5-32-549' = 'Server Operators'; 'S-1-5-32-550' = 'Print Operators'; 'S-1-5-32-551' = 'Backup Operators' }

    $sidNameCache = @{}
    function Resolve-Sid {
        param([string]$Sid)
        if ($sidNameCache.ContainsKey($Sid)) { return $sidNameCache[$Sid] }
        if ($builtinOperators.ContainsKey($Sid)) { return "BUILTIN\$($builtinOperators[$Sid])" }
        if ($defaultSids.ContainsKey($Sid)) { return $defaultSids[$Sid] }
        $n = $Sid
        try { $n = ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value }
        catch {
            try { $o = Get-ADObject -LDAPFilter "(objectSid=$Sid)" -Properties sAMAccountName @script:AdParams | Select-Object -First 1; if ($o) { $n = "$($domain.NetBIOSName)\$($o.sAMAccountName)" } else { $n = "$Sid (unresolved)" } } catch { $n = "$Sid (unresolved)" }
        }
        $sidNameCache[$Sid] = $n
        return $n
    }

    # ---- Targets ----
    $targets = [System.Collections.Generic.List[object]]::new()
    $targets.Add([pscustomobject]@{ DN = $domain.DistinguishedName; Kind = 'DomainRoot'; Tier = 'Tier0' })
    $targets.Add([pscustomobject]@{ DN = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"; Kind = 'AdminSDHolder'; Tier = 'Tier0' })
    $targets.Add([pscustomobject]@{ DN = $domain.DomainControllersContainer; Kind = 'DomainControllersOU'; Tier = 'Tier0' })
    foreach ($sid in "$dSid-512", "$forestSid-519", "$forestSid-518", 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-551') {
        try { $g = Get-ADGroup -Identity $sid @script:AdParams; $targets.Add([pscustomobject]@{ DN = $g.DistinguishedName; Kind = "ProtectedGroup:$($g.Name)"; Tier = 'Tier0' }) } catch { }
    }
    if (-not $SkipOUs) {
        foreach ($ou in @(Get-ADOrganizationalUnit -Filter * @script:AdParams)) {
            if ($ou.DistinguishedName -eq $domain.DomainControllersContainer) { continue }
            $targets.Add([pscustomobject]@{ DN = $ou.DistinguishedName; Kind = 'OU'; Tier = 'OU' })
        }
    }
    foreach ($t in $AdditionalTargets) { $targets.Add([pscustomobject]@{ DN = $t; Kind = 'Additional'; Tier = 'Additional' }) }
    Write-RunLog ("{0} targets to review" -f $targets.Count)

    $rows = [System.Collections.Generic.List[object]]::new()
    $ownerRows = [System.Collections.Generic.List[object]]::new()
    $unreadable = 0
    $named = @{
        'member' = 'WriteMembers'; 'servicePrincipalName' = 'WriteSPN'; 'msDS-KeyCredentialLink' = 'WriteKeyCredential'
        'msDS-AllowedToActOnBehalfOfOtherIdentity' = 'WriteRBCD'; 'userAccountControl' = 'WriteUserAccountControl'
        'scriptPath' = 'WriteScriptPath'; 'gPLink' = 'WriteGPLink'; 'msDS-AllowedToDelegateTo' = 'WriteConstrainedDelegation'
        'userPassword' = 'WritePasswordAttribute'; 'unicodePwd' = 'WritePasswordAttribute'
    }
    $lapsAttrs = @('ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-EncryptedDSRMPassword')

    foreach ($t in $targets) {
        $obj = $null
        try { $obj = Get-ADObject -Identity $t.DN -Properties nTSecurityDescriptor @script:AdParams } catch { $unreadable++; Write-RunLog ("Cannot read {0}: {1}" -f $t.DN, $_.Exception.Message) 'WARN'; continue }
        $sd = $obj.nTSecurityDescriptor
        if (-not $sd) { $unreadable++; continue }

        # Owner
        try {
            $ownerSid = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if (-not $defaultSids.ContainsKey($ownerSid)) {
                $ownerRows.Add([pscustomobject][ordered]@{ Target = $t.DN; TargetKind = $t.Kind; Tier = $t.Tier; Owner = Resolve-Sid $ownerSid; OwnerSid = $ownerSid; Severity = $(if ($t.Tier -eq 'Tier0') { 'Critical' } else { 'High' }); Note = 'Owner can rewrite permissions on this object' })
            }
        }
        catch { }

        foreach ($ace in $sd.GetAccessRules($true, [bool]$IncludeInherited, [System.Security.Principal.SecurityIdentifier])) {
            if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
            $sid = $ace.IdentityReference.Value
            if ($defaultSids.ContainsKey($sid)) { continue }
            $r = [int]$ace.ActiveDirectoryRights
            $objType = Get-GuidName $ace.ObjectType -Kind Schema
            $rightType = Get-GuidName $ace.ObjectType -Kind Right
            $inhType = Get-GuidName $ace.InheritedObjectType -Kind Schema
            $found = @()
            if (($r -band $Rights.GenericAll) -eq $Rights.GenericAll) { $found += 'FullControl' }
            else {
                if ($r -band $Rights.WriteDacl) { $found += 'ModifyPermissions' }
                if ($r -band $Rights.WriteOwner) { $found += 'TakeOwnership' }
                if (($r -band $Rights.GenericWrite) -eq $Rights.GenericWrite) { $found += 'WriteAllProperties' }
                elseif ($r -band $Rights.WriteProperty) {
                    if (-not $objType) { $found += 'WriteAllProperties' }
                    elseif ($named.ContainsKey($objType)) { $found += $named[$objType] }
                }
                if ($r -band $Rights.ExtendedRight) {
                    switch -Regex ($rightType) {
                        '^$' { $found += 'AllExtendedRights' }
                        '^User-Force-Change-Password$' { $found += 'ResetPassword' }
                        '^DS-Replication-Get-Changes-All$' { $found += 'DCSync' }
                        '^DS-Replication-Get-Changes-In-Filtered-Set$' { $found += 'DCSync' }
                        default { if ($lapsAttrs -contains $objType) { $found += 'ReadLAPSPassword' } }
                    }
                }
                if ($r -band $Rights.Self) {
                    if ($rightType -eq 'Self-Membership') { $found += 'AddSelfToGroup' }
                    elseif ($rightType -eq 'Validated-SPN') { $found += 'WriteSPN' }
                }
                if ($IncludeLowSeverity -and (($r -band $Rights.CreateChild) -or ($r -band $Rights.DeleteChild) -or ($r -band $Rights.Delete))) { $found += 'CreateOrDeleteObjects' }
            }
            if (-not $found.Count) { continue }
            $isOperator = $builtinOperators.ContainsKey($sid)
            foreach ($f in ($found | Select-Object -Unique)) {
                $sev = 'Medium'
                if ($f -in @('DCSync') -or ($t.Tier -eq 'Tier0' -and $f -ne 'CreateOrDeleteObjects')) { $sev = 'Critical' }
                elseif ($f -in @('FullControl', 'ModifyPermissions', 'TakeOwnership', 'ResetPassword', 'WriteAllProperties', 'AllExtendedRights', 'WriteKeyCredential', 'WriteRBCD', 'ReadLAPSPassword', 'WriteMembers', 'WriteGPLink')) { $sev = 'High' }
                elseif ($f -eq 'CreateOrDeleteObjects') { $sev = 'Low' }
                $rows.Add([pscustomobject][ordered]@{
                    Target            = $t.DN
                    TargetKind        = $t.Kind
                    Tier              = $t.Tier
                    Trustee           = Resolve-Sid $sid
                    TrusteeSid        = $sid
                    TrusteeIsBuiltinOperator = $isOperator
                    Right             = $f
                    AppliesTo         = $(if ($f -in @('ResetPassword', 'DCSync', 'AddSelfToGroup', 'WriteSPN') -and $rightType) { $rightType } else { $objType })
                    AppliesToObjects  = $(if ($inhType) { $inhType } else { 'All' })
                    Inherited         = $ace.IsInherited
                    Severity          = $sev
                    RawRights         = "$($ace.ActiveDirectoryRights)"
                })
            }
        }
    }
    $rows = @($rows | Sort-Object @{ Expression = { @{ Critical = 0; High = 1; Medium = 2; Low = 3 }[$_.Severity] } }, Target, Trustee)
    Export-Dataset -Name 'ad-delegations' -Rows $rows -Note $(if ($IncludeInherited) { 'Explicit and inherited ACEs' } else { 'Explicit ACEs only; inherited rights appear at the OU where they were set' })
    Export-Dataset -Name 'ad-nondefault-owners' -Rows $ownerRows

    $trusteeRows = $rows | Group-Object TrusteeSid | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject][ordered]@{
            Trustee         = $g[0].Trustee
            TrusteeSid      = $_.Name
            BuiltinOperator = $g[0].TrusteeIsBuiltinOperator
            HighestSeverity = ($g | Sort-Object @{ Expression = { @{ Critical = 0; High = 1; Medium = 2; Low = 3 }[$_.Severity] } } | Select-Object -First 1).Severity
            Rights          = Join-Values ($g | Select-Object -ExpandProperty Right -Unique)
            Tier0Targets    = @($g | Where-Object Tier -eq 'Tier0' | Select-Object -ExpandProperty Target -Unique).Count
            OUTargets       = @($g | Where-Object Tier -eq 'OU' | Select-Object -ExpandProperty Target -Unique).Count
            DelegationRows  = $g.Count
        }
    } | Sort-Object @{ Expression = { @{ Critical = 0; High = 1; Medium = 2; Low = 3 }[$_.HighestSeverity] } }, @{ Expression = 'DelegationRows'; Descending = $true }
    Export-Dataset -Name 'ad-delegation-by-trustee' -Rows $trusteeRows -Note 'Expand group trustees with script 04 or 05 to see who actually holds these rights'

    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Targets reviewed' ($targets.Count - $unreadable)
    Add-Metric 'Targets that could not be read' $unreadable
    Add-Metric 'Delegation rows' $rows.Count
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') { Add-Metric "Severity: $s" @($rows | Where-Object Severity -eq $s).Count }
    Add-Metric 'Non-default trustees with DCSync' @($rows | Where-Object Right -eq 'DCSync' | Select-Object -ExpandProperty TrusteeSid -Unique).Count 'Can read every password hash in the domain'
    Add-Metric 'Non-default trustees with rights on Tier 0 objects' @($rows | Where-Object Tier -eq 'Tier0' | Select-Object -ExpandProperty TrusteeSid -Unique).Count
    Add-Metric 'Trustees able to reset passwords in OUs' @($rows | Where-Object { $_.Tier -eq 'OU' -and $_.Right -in @('ResetPassword', 'FullControl', 'AllExtendedRights') } | Select-Object -ExpandProperty TrusteeSid -Unique).Count
    Add-Metric 'Trustees able to read LAPS passwords' @($rows | Where-Object Right -eq 'ReadLAPSPassword' | Select-Object -ExpandProperty TrusteeSid -Unique).Count
    Add-Metric 'Objects with a non-default owner' $ownerRows.Count
    Add-Metric 'Rows held by builtin operator groups' @($rows | Where-Object TrusteeIsBuiltinOperator).Count 'Account/Server/Backup Operators should normally be empty'
    Add-Metric 'Unresolved trustees (deleted accounts)' @($rows | Where-Object { $_.Trustee -like '*(unresolved)' } | Select-Object -ExpandProperty TrusteeSid -Unique).Count 'Orphaned ACEs - safe clean-up'
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ SkipOUs = [bool]$SkipOUs; AdditionalTargets = $AdditionalTargets; IncludeInherited = [bool]$IncludeInherited; IncludeLowSeverity = [bool]$IncludeLowSeverity }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
