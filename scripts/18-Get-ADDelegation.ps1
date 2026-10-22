<#
.SYNOPSIS
    Read-only review of delegated permissions (ACLs) in AD: who holds dangerous rights on the
    domain, OUs, protected groups, GPOs and individual (admin) accounts, and which real user
    accounts end up holding them through group membership.

.DESCRIPTION
    Group membership (script 04) is only half of privileged access. Accounts and groups that hold
    dangerous rights through ACLs - full control, reset password, write members, DCSync, GPO edit -
    are effectively administrators too, and are often forgotten. This script reads the explicit
    (non-inherited) access control entries and reports:

      Targets
        - Tier 0: the domain root, AdminSDHolder, the Domain Controllers OU, the protected groups,
          protected accounts (adminCount=1) and GPOs linked to the domain or the DC OU
        - every OU
        - every other GPO (edit rights on a GPO = control of everything it applies to)
        - individual accounts (-ObjectAclScope): by default admin-like accounts - protected
          accounts, names matching -AdminNamePatterns and members of -AdditionalPrivilegedGroups;
          'All' checks every user, group and computer (slow in large domains)

      Datasets
        - ad-delegations: one row per risky right held by a non-default trustee (target, tier,
          trustee and its type / category, right, object type it applies to, severity)
        - ad-nondefault-owners: objects owned by a non-default principal (an owner can rewrite the
          object's permissions)
        - ad-delegation-by-trustee: every trustee with its rights summarised and how many user
          accounts actually hold them
        - ad-delegation-effective-users: every user account that holds a right, directly or through
          nested groups, flagged when it does not look like an admin account
          (RegularAccountWithElevatedRights)
        - summary

    Default trustees (SYSTEM, Domain/Enterprise Admins, Administrators, domain controllers, SELF,
    CREATOR OWNER, Key Admins, Authenticated Users read, etc.) are excluded. Product-installed
    trustees are kept but labelled so they can be filtered: Exchange groups (a known escalation
    path), the Entra Connect sync account (DCSync is expected there) and builtin operator groups.

    On protected accounts, rights copied from AdminSDHolder are not repeated (they are reported once,
    on AdminSDHolder). GPO permissions are read from the GPO object in AD; SYSVOL file permissions are
    not read.

    GUIDs are resolved from this forest's schema and extended rights, so forest-specific
    attributes (for example the LAPS password attribute) are named correctly.

    READ-ONLY. Uses only Get-AD* cmdlets. Nothing in the directory is changed.

    Output: <OutputRoot>\18-ADDelegation\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER ObjectAclScope
    Individual accounts to check: Privileged (default: protected, admin-named and listed-group
    accounts), All (every user, group and computer), None.

.PARAMETER AdminNamePatterns
    sAMAccountName wildcards that mark an admin account. Used to choose accounts to check and to
    tell admin accounts from regular ones among the effective holders. Set to the naming standard.

.PARAMETER AdditionalPrivilegedGroups
    Custom admin groups (name or DN) whose members are also checked as privileged accounts.

.EXAMPLE
    .\18-Get-ADDelegation.ps1 -Server dc01.contoso.local
.EXAMPLE
    .\18-Get-ADDelegation.ps1 -AdminNamePatterns 'adm-*','*-a' -AdditionalPrivilegedGroups 'Server Admins','Helpdesk Tier 1'
.EXAMPLE
    .\18-Get-ADDelegation.ps1 -ObjectAclScope All -IncludeInherited

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x, RSAT ActiveDirectory module, a standard domain account
              (authenticated users can read DACLs on most objects; the SACL is not read)
    Load    : tells the SOC first - ACL reads across the directory look like reconnaissance.
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$Server = '',                                   # e.g. 'dc01.contoso.local'
    [switch]$SkipOUs,                                       # skip the per-OU review
    [switch]$SkipGPOs,                                      # skip GPO permissions
    [ValidateSet('Privileged', 'All', 'None')]
    [string]$ObjectAclScope = 'Privileged',
    [string[]]$AdminNamePatterns = @('adm*', '*adm', '*-adm*', '*_adm*', 'a-*', 'a_*', 'da-*', '*admin*'),
    [string[]]$AdditionalPrivilegedGroups = @(),
    [string[]]$AdditionalTargets = @(),                     # extra DNs to review
    [switch]$SkipMemberExpansion,                           # don't expand group trustees to users
    [switch]$IncludeInherited,                              # also report inherited ACEs (noisy)
    [switch]$IncludeLowSeverity                             # include CreateObjects / delete-child rows
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '18-ADDelegation'
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

# ActiveDirectoryRights flag values (System.DirectoryServices.ActiveDirectoryRights), as integers so
# the script does not depend on the enum type being loaded.
$Rights = @{ CreateChild = 1; DeleteChild = 2; Self = 8; WriteProperty = 32; ExtendedRight = 256; Delete = 65536
    GenericWrite = 131112; WriteDacl = 262144; WriteOwner = 524288; GenericAll = 983551 }
$SeverityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
$InChain = '1.2.840.113556.1.4.1941'      # LDAP_MATCHING_RULE_IN_CHAIN: transitive group membership

$domainName = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain @script:AdParams
    $domainName = $domain.DNSRoot
    $domainDN = $domain.DistinguishedName
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

    # ---- Default trustees and labels ----
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
    $exchangeGroups = @('Exchange Windows Permissions', 'Exchange Trusted Subsystem', 'Organization Management', 'Exchange Servers', 'Exchange Enterprise Servers', 'Exchange Domain Servers', 'Public Folder Management', 'Recipient Management')
    $syncPatterns = @('MSOL_*', 'AAD_*', 'ADSync*', 'Sync_*', 'ADSyncAdmins', 'ADSyncOperators')

    $trusteeCache = @{}
    function Get-TrusteeInfo {
        # Name, type (User / Group / Computer / Builtin / WellKnown / Unresolved), category, DN and sAMAccountName for a SID.
        param([string]$Sid)
        if ($trusteeCache.ContainsKey($Sid)) { return $trusteeCache[$Sid] }
        $info = [pscustomobject]@{ Name = $Sid; Type = 'Unresolved'; Category = 'Custom'; DN = ''; Sam = '' }
        if ($defaultSids.ContainsKey($Sid)) { $info.Name = $defaultSids[$Sid]; $info.Type = 'WellKnown'; $info.Category = 'Default' }
        else {
            $o = $null
            try { $o = Get-ADObject -LDAPFilter "(objectSid=$Sid)" -Properties sAMAccountName, objectClass, distinguishedName @script:AdParams | Select-Object -First 1 } catch { }
            if ($o) {
                $info.Sam = [string]$o.sAMAccountName; $info.DN = [string]$o.DistinguishedName
                $info.Name = $(if ($Sid -like 'S-1-5-32-*') { "BUILTIN\$($o.sAMAccountName)" } else { "$($domain.NetBIOSName)\$($o.sAMAccountName)" })
                $cls = @($o.objectClass)[-1]
                $info.Type = $(if ($Sid -like 'S-1-5-32-*') { 'Builtin' } elseif ($cls -eq 'computer') { 'Computer' } elseif ($cls -eq 'group') { 'Group' } elseif ($cls -in 'user', 'inetOrgPerson', 'msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount') { 'User' } else { [string]$cls })
            }
            else {
                try { $info.Name = ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value; $info.Type = 'WellKnown' }
                catch { $info.Name = "$Sid (unresolved)" }
            }
            if ($builtinOperators.ContainsKey($Sid)) { $info.Category = 'Builtin operator'; if ($info.Name -like 'S-1-*') { $info.Name = "BUILTIN\$($builtinOperators[$Sid])" }; $info.Type = 'Builtin' }
            elseif ($exchangeGroups -contains $info.Sam) { $info.Category = 'Exchange (product default)' }
            elseif (@($syncPatterns | Where-Object { $info.Sam -like $_ }).Count) { $info.Category = 'Entra Connect (sync account)' }
        }
        $trusteeCache[$Sid] = $info
        return $info
    }

    function Test-AdminName { param([string]$Sam) return [bool](@($AdminNamePatterns | Where-Object { $Sam -like $_ }).Count) }

    $rows = [System.Collections.Generic.List[object]]::new()
    $ownerRows = [System.Collections.Generic.List[object]]::new()
    $named = @{
        'member' = 'WriteMembers'; 'servicePrincipalName' = 'WriteSPN'; 'msDS-KeyCredentialLink' = 'WriteKeyCredential'
        'msDS-AllowedToActOnBehalfOfOtherIdentity' = 'WriteRBCD'; 'userAccountControl' = 'WriteUserAccountControl'
        'scriptPath' = 'WriteScriptPath'; 'gPLink' = 'WriteGPLink'; 'msDS-AllowedToDelegateTo' = 'WriteConstrainedDelegation'
        'userPassword' = 'WritePasswordAttribute'; 'unicodePwd' = 'WritePasswordAttribute'; 'gPCFileSysPath' = 'WriteGPOPath'
    }
    $lapsAttrs = @('ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-EncryptedDSRMPassword')
    $bigRights = @('FullControl', 'ModifyPermissions', 'TakeOwnership', 'ResetPassword', 'WriteAllProperties', 'AllExtendedRights', 'WriteKeyCredential', 'WriteRBCD', 'ReadLAPSPassword', 'WriteMembers', 'WriteGPLink', 'WriteGPOPath', 'WriteScriptPath')

    function Add-AclRows {
        # Classifies the risky allow-ACEs on one security descriptor and adds rows. $Skip = ACE keys to ignore.
        param($Target, $Sd, [hashtable]$Skip = @{})
        try {
            $ownerSid = $Sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if (-not $defaultSids.ContainsKey($ownerSid)) {
                $ti = Get-TrusteeInfo $ownerSid
                $ownerRows.Add([pscustomobject][ordered]@{ Target = $Target.DN; TargetKind = $Target.Kind; Tier = $Target.Tier; Owner = $ti.Name; OwnerType = $ti.Type; OwnerSid = $ownerSid
                    Severity = $(if ($Target.Tier -eq 'Tier0') { 'Critical' } else { 'High' }); Note = 'Owner can rewrite permissions on this object' })
            }
        }
        catch { }
        foreach ($ace in $Sd.GetAccessRules($true, [bool]$IncludeInherited, [System.Security.Principal.SecurityIdentifier])) {
            if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
            $sid = $ace.IdentityReference.Value
            if ($defaultSids.ContainsKey($sid)) { continue }
            $r = [int]$ace.ActiveDirectoryRights
            if ($Skip.Count -and $Skip.ContainsKey(('{0}|{1}|{2}|{3}' -f $sid, $r, $ace.ObjectType, $ace.InheritedObjectType))) { continue }
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
            $ti = Get-TrusteeInfo $sid
            foreach ($f in ($found | Select-Object -Unique)) {
                $sev = 'Medium'
                if ($f -eq 'DCSync' -or ($Target.Tier -eq 'Tier0' -and $f -ne 'CreateOrDeleteObjects')) { $sev = 'Critical' }
                elseif ($bigRights -contains $f) { $sev = 'High' }
                elseif ($f -eq 'CreateOrDeleteObjects') { $sev = 'Low' }
                $rows.Add([pscustomobject][ordered]@{
                    Target            = $Target.DN
                    TargetKind        = $Target.Kind
                    Tier              = $Target.Tier
                    Trustee           = $ti.Name
                    TrusteeType       = $ti.Type
                    TrusteeCategory   = $ti.Category
                    TrusteeSid        = $sid
                    TrusteeIsBuiltinOperator = $builtinOperators.ContainsKey($sid)
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

    # ---- 1. Directory targets (domain, AdminSDHolder, DC OU, protected groups, OUs) ----
    $targets = [System.Collections.Generic.List[object]]::new()
    $targets.Add([pscustomobject]@{ DN = $domainDN; Kind = 'DomainRoot'; Tier = 'Tier0' })
    $targets.Add([pscustomobject]@{ DN = "CN=AdminSDHolder,CN=System,$domainDN"; Kind = 'AdminSDHolder'; Tier = 'Tier0' })
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
    Write-RunLog ("{0} directory targets to review" -f $targets.Count)

    $unreadable = 0
    $tier0GpoGuids = @{}
    $adminSdHolderKeys = @{}
    foreach ($t in $targets) {
        $obj = $null
        try { $obj = Get-ADObject -Identity $t.DN -Properties nTSecurityDescriptor, gPLink @script:AdParams } catch { $unreadable++; Write-RunLog ("Cannot read {0}: {1}" -f $t.DN, $_.Exception.Message) 'WARN'; continue }
        if ($t.Kind -in 'DomainRoot', 'DomainControllersOU' -and $obj.gPLink) {
            foreach ($m in [regex]::Matches([string]$obj.gPLink, '\{([0-9a-fA-F-]{36})\}')) { $tier0GpoGuids[$m.Groups[1].Value.ToLowerInvariant()] = $t.Kind }
        }
        $sd = $obj.nTSecurityDescriptor
        if (-not $sd) { $unreadable++; continue }
        if ($t.Kind -eq 'AdminSDHolder') {
            foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) { $adminSdHolderKeys[('{0}|{1}|{2}|{3}' -f $ace.IdentityReference.Value, [int]$ace.ActiveDirectoryRights, $ace.ObjectType, $ace.InheritedObjectType)] = $true }
        }
        Add-AclRows -Target $t -Sd $sd
    }

    # ---- 2. GPOs ----
    $gpoCount = 0
    if ($SkipGPOs) { Write-RunLog 'GPOs skipped (-SkipGPOs).' 'WARN' }
    else {
        try {
            $gpos = @(Get-ADObject -SearchBase "CN=Policies,CN=System,$domainDN" -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName, name, nTSecurityDescriptor @script:AdParams)
            foreach ($g in $gpos) {
                $guid = ([string]$g.Name).Trim('{', '}').ToLowerInvariant()
                $linked = $tier0GpoGuids.ContainsKey($guid)
                $t = [pscustomobject]@{ DN = $g.DistinguishedName; Kind = $(if ($linked) { "GPO (linked to $($tier0GpoGuids[$guid])): $($g.displayName)" } else { "GPO: $($g.displayName)" }); Tier = $(if ($linked) { 'Tier0' } else { 'GPO' }) }
                if ($g.nTSecurityDescriptor) { Add-AclRows -Target $t -Sd $g.nTSecurityDescriptor; $gpoCount++ } else { $unreadable++ }
            }
            Write-RunLog ("{0} GPOs reviewed ({1} linked to the domain root or DC OU)" -f $gpoCount, $tier0GpoGuids.Count)
        }
        catch { Write-RunLog ("GPOs not readable: {0}" -f $_.Exception.Message) 'WARN' }
    }

    # ---- 3. Individual accounts ----
    $objectCount = 0
    $objectScanNote = $ObjectAclScope
    if ($ObjectAclScope -ne 'None') {
      try {
        $objs = @{}
        $props = @('nTSecurityDescriptor', 'sAMAccountName', 'objectClass', 'adminCount')
        if ($ObjectAclScope -eq 'All') {
            Write-RunLog 'Reading permissions on every user, group and computer (this can take a long time)...'
            foreach ($o in @(Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=group))' -Properties $props -ResultPageSize 500 @script:AdParams)) { $objs[$o.DistinguishedName] = $o }
        }
        else {
            Write-RunLog 'Reading permissions on admin-like accounts (protected, admin-named, listed groups)...'
            foreach ($o in @(Get-ADObject -LDAPFilter '(&(adminCount=1)(|(objectClass=user)(objectClass=group)))' -Properties $props @script:AdParams)) { $objs[$o.DistinguishedName] = $o }
            if ($AdminNamePatterns.Count) {
                $f = '(&(objectCategory=person)(objectClass=user)(|' + (($AdminNamePatterns | ForEach-Object { "(sAMAccountName=$($_ -replace '[()\\]', ''))" }) -join '') + '))'
                foreach ($o in @(Get-ADObject -LDAPFilter $f -Properties $props @script:AdParams)) { $objs[$o.DistinguishedName] = $o }
            }
            foreach ($gName in $AdditionalPrivilegedGroups) {
                try {
                    $g = Get-ADGroup -Identity $gName @script:AdParams
                    foreach ($o in @(Get-ADObject -LDAPFilter "(memberOf:$InChain`:=$($g.DistinguishedName))" -Properties $props @script:AdParams)) { $objs[$o.DistinguishedName] = $o }
                }
                catch { Write-RunLog ("Group '{0}' not found: {1}" -f $gName, $_.Exception.Message) 'WARN' }
            }
        }
        foreach ($o in $objs.Values) {
            $sd = $o.nTSecurityDescriptor
            if (-not $sd) { $unreadable++; continue }
            $cls = @($o.objectClass)[-1]
            $protected = "$($o.adminCount)" -eq '1'
            $t = [pscustomobject]@{ DN = $o.DistinguishedName; Kind = ("{0}: {1}" -f $(if ($cls -eq 'group') { 'Group' } elseif ($cls -eq 'computer') { 'Computer' } else { 'Account' }), $o.sAMAccountName)
                Tier = $(if ($protected) { 'Tier0' } elseif ($ObjectAclScope -eq 'All' -and -not (Test-AdminName ([string]$o.sAMAccountName))) { 'Object' } else { 'PrivilegedAccount' }) }
            Add-AclRows -Target $t -Sd $sd -Skip $(if ($protected) { $adminSdHolderKeys } else { @{} })
            $objectCount++
        }
        Write-RunLog ("{0} individual objects reviewed ({1})" -f $objectCount, $ObjectAclScope)
      }
      catch {
        $objectScanNote = "$ObjectAclScope - stopped early: $($_.Exception.Message)"
        Write-RunLog ("Individual account review stopped early: {0}" -f $_.Exception.Message) 'WARN'
      }
    }

    $rows = @($rows | Sort-Object @{ Expression = { $SeverityOrder[$_.Severity] } }, Target, Trustee)
    Export-Dataset -Name 'ad-delegations' -Rows $rows -Note $(if ($IncludeInherited) { 'Explicit and inherited ACEs' } else { 'Explicit ACEs only; inherited rights appear where they were set' })
    Export-Dataset -Name 'ad-nondefault-owners' -Rows $ownerRows

    # ---- 4. Effective holders: expand group trustees to user accounts ----
    $holders = @{}      # user DN -> holder record
    $trusteeUsers = @{} # trustee SID -> user count
    $bySid = $rows | Group-Object TrusteeSid
    foreach ($grp in $bySid) {
        $sid = $grp.Name; $ti = Get-TrusteeInfo $sid
        $users = @()
        if ($ti.Type -eq 'User' -and $ti.DN) {
            try { $users = @(Get-ADObject -Identity $ti.DN -Properties sAMAccountName, userAccountControl, adminCount, lastLogonTimestamp, objectClass @script:AdParams) } catch { }
        }
        elseif ($ti.Type -in 'Group', 'Builtin' -and $ti.DN -and -not $SkipMemberExpansion) {
            try { $users = @(Get-ADObject -LDAPFilter "(&(objectCategory=person)(objectClass=user)(memberOf:$InChain`:=$($ti.DN)))" -Properties sAMAccountName, userAccountControl, adminCount, lastLogonTimestamp, objectClass @script:AdParams) }
            catch { Write-RunLog ("Members of {0} not readable: {1}" -f $ti.Name, $_.Exception.Message) 'WARN' }
        }
        $trusteeUsers[$sid] = $users.Count
        foreach ($u in $users) {
            $dn = [string]$u.DistinguishedName
            if (-not $holders.ContainsKey($dn)) {
                $llt = $null; try { if ($u.lastLogonTimestamp) { $llt = [datetime]::FromFileTimeUtc([int64]"$($u.lastLogonTimestamp)") } } catch { }
                $uac = 0; try { $uac = [int]"$($u.userAccountControl)" } catch { }
                $holders[$dn] = [pscustomobject]@{ Sam = [string]$u.sAMAccountName; DN = $dn; Enabled = -not ($uac -band 2); AdminCount = ("$($u.adminCount)" -eq '1')
                    LastLogon = $llt; Rights = [System.Collections.Generic.HashSet[string]]::new(); Via = [System.Collections.Generic.HashSet[string]]::new()
                    Targets = [System.Collections.Generic.HashSet[string]]::new(); Sev = 3; Tier0 = $false; Direct = $false }
            }
            $h = $holders[$dn]
            foreach ($row in $grp.Group) {
                [void]$h.Rights.Add($row.Right); [void]$h.Targets.Add($row.Target)
                if ($SeverityOrder[$row.Severity] -lt $h.Sev) { $h.Sev = $SeverityOrder[$row.Severity] }
                if ($row.Tier -eq 'Tier0') { $h.Tier0 = $true }
            }
            if ($ti.Type -eq 'User') { $h.Direct = $true; [void]$h.Via.Add('(granted directly)') } else { [void]$h.Via.Add($ti.Name) }
        }
    }
    $sevName = @{ 0 = 'Critical'; 1 = 'High'; 2 = 'Medium'; 3 = 'Low' }
    $now = (Get-Date).ToUniversalTime()
    $effective = @($holders.Values | ForEach-Object {
            $looksAdmin = Test-AdminName $_.Sam
            [pscustomobject][ordered]@{
                SamAccountName = $_.Sam; Enabled = $_.Enabled; LooksLikeAdminAccount = $looksAdmin; AdminCount = $_.AdminCount
                LastLogonUtc = $_.LastLogon; HighestSeverity = $sevName[$_.Sev]; HoldsTier0Rights = $_.Tier0
                Rights = (($_.Rights | Sort-Object) -join '; '); Via = (($_.Via | Sort-Object) -join '; '); Targets = $_.Targets.Count
                Flags = (@(
                        $(if ($_.Enabled -and -not $looksAdmin -and $_.Sev -le 1) { 'RegularAccountWithElevatedRights' })
                        $(if ($_.Direct) { 'DirectGrant' })
                        $(if (-not $_.Enabled) { 'Disabled' })
                        $(if ($_.Enabled -and (-not $_.LastLogon -or ($now - $_.LastLogon).TotalDays -gt 90)) { 'NoLogon90d' })
                    ) | Where-Object { $_ }) -join '; '
                DistinguishedName = $_.DN
            }
        } | Sort-Object @{ Expression = { $SeverityOrder[$_.HighestSeverity] } }, @{ Expression = 'LooksLikeAdminAccount'; Descending = $false }, SamAccountName)
    if ($SkipMemberExpansion) { Set-DatasetStatus -Name 'ad-delegation-effective-users' -Status 'Deferred' -Note 'Group trustees not expanded (-SkipMemberExpansion); direct user grants only' }
    else { Export-Dataset -Name 'ad-delegation-effective-users' -Rows $effective -Note 'Every user account holding a right, directly or through nested groups (primary-group membership not included)' }

    $trusteeRows = $rows | Group-Object TrusteeSid | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject][ordered]@{
            Trustee         = $g[0].Trustee
            TrusteeType     = $g[0].TrusteeType
            TrusteeCategory = $g[0].TrusteeCategory
            TrusteeSid      = $_.Name
            BuiltinOperator = $g[0].TrusteeIsBuiltinOperator
            HighestSeverity = ($g | Sort-Object @{ Expression = { $SeverityOrder[$_.Severity] } } | Select-Object -First 1).Severity
            Rights          = Join-Values ($g | Select-Object -ExpandProperty Right -Unique)
            Tier0Targets    = @($g | Where-Object Tier -eq 'Tier0' | Select-Object -ExpandProperty Target -Unique).Count
            OUTargets       = @($g | Where-Object Tier -eq 'OU' | Select-Object -ExpandProperty Target -Unique).Count
            GPOTargets      = @($g | Where-Object { $_.TargetKind -like 'GPO*' } | Select-Object -ExpandProperty Target -Unique).Count
            AccountTargets  = @($g | Where-Object { $_.Tier -in 'PrivilegedAccount', 'Object' -or $_.TargetKind -like 'Account:*' } | Select-Object -ExpandProperty Target -Unique).Count
            EffectiveUsers  = $(if ($trusteeUsers.ContainsKey($_.Name)) { $trusteeUsers[$_.Name] } else { '' })
            DelegationRows  = $g.Count
        }
    } | Sort-Object @{ Expression = { $SeverityOrder[$_.HighestSeverity] } }, @{ Expression = 'DelegationRows'; Descending = $true }
    Export-Dataset -Name 'ad-delegation-by-trustee' -Rows $trusteeRows -Note 'TrusteeCategory separates product defaults (Exchange, Entra Connect) and builtin operators from custom delegations'

    # ---- 5. Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    $custom = @($rows | Where-Object TrusteeCategory -eq 'Custom')
    Add-Metric 'Directory targets reviewed' ($targets.Count)
    Add-Metric 'GPOs reviewed' $gpoCount $(if ($tier0GpoGuids.Count) { "$($tier0GpoGuids.Count) linked to the domain root or DC OU (Tier 0)" } else { '' })
    Add-Metric 'Individual accounts reviewed' $objectCount $objectScanNote
    Add-Metric 'Objects that could not be read' $unreadable
    Add-Metric 'Delegation rows' $rows.Count
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') { Add-Metric "Severity: $s" @($rows | Where-Object Severity -eq $s).Count }
    Add-Metric 'Rows held by custom trustees' $custom.Count 'Excludes Exchange, Entra Connect and builtin operator rows'
    Add-Metric 'Rows held by product defaults' @($rows | Where-Object { $_.TrusteeCategory -like 'Exchange*' -or $_.TrusteeCategory -like 'Entra Connect*' }).Count 'Exchange groups and the Entra Connect sync account'
    Add-Metric 'Non-default trustees with DCSync' @($rows | Where-Object Right -eq 'DCSync' | Select-Object -ExpandProperty TrusteeSid -Unique).Count 'Can read every password hash in the domain (expected only for the Entra Connect sync account)'
    Add-Metric 'Non-default trustees with rights on Tier 0 objects' @($rows | Where-Object Tier -eq 'Tier0' | Select-Object -ExpandProperty TrusteeSid -Unique).Count
    Add-Metric 'Trustees that can edit a GPO' @($rows | Where-Object { $_.TargetKind -like 'GPO*' } | Select-Object -ExpandProperty TrusteeSid -Unique).Count
    Add-Metric 'Rights granted on individual accounts' @($rows | Where-Object { $_.TargetKind -like 'Account:*' -or $_.TargetKind -like 'Group:*' -or $_.TargetKind -like 'Computer:*' }).Count 'Explicit permissions on single objects (excluding copies of AdminSDHolder)'
    Add-Metric 'Rights granted directly to user accounts' @($rows | Where-Object TrusteeType -eq 'User').Count 'Good practice is to grant to groups'
    Add-Metric 'Trustees able to reset passwords in OUs' @($rows | Where-Object { $_.Tier -eq 'OU' -and $_.Right -in @('ResetPassword', 'FullControl', 'AllExtendedRights') } | Select-Object -ExpandProperty TrusteeSid -Unique).Count
    Add-Metric 'Trustees able to read LAPS passwords' @($rows | Where-Object Right -eq 'ReadLAPSPassword' | Select-Object -ExpandProperty TrusteeSid -Unique).Count
    Add-Metric 'Objects with a non-default owner' $ownerRows.Count
    Add-Metric 'Rows held by builtin operator groups' @($rows | Where-Object TrusteeIsBuiltinOperator).Count 'Account/Server/Backup Operators should normally be empty'
    Add-Metric 'Unresolved trustees (deleted accounts)' @($rows | Where-Object { $_.Trustee -like '*(unresolved)' } | Select-Object -ExpandProperty TrusteeSid -Unique).Count 'Orphaned ACEs - safe clean-up'
    if (-not $SkipMemberExpansion) {
        Add-Metric 'User accounts holding delegated rights' $effective.Count 'Directly or through nested groups'
        Add-Metric 'Regular (non-admin-named) enabled accounts with High or Critical rights' @($effective | Where-Object { $_.Flags -match 'RegularAccountWithElevatedRights' }).Count ("Admin naming used: {0}" -f ($AdminNamePatterns -join ', '))
        Add-Metric 'User accounts holding Tier 0 rights' @($effective | Where-Object HoldsTier0Rights).Count
        Add-Metric 'Enabled holders with no logon in 90 days' @($effective | Where-Object { $_.Flags -match 'NoLogon90d' }).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName $domainName -Parameters @{ SkipOUs = [bool]$SkipOUs; SkipGPOs = [bool]$SkipGPOs; ObjectAclScope = $ObjectAclScope; AdminNamePatterns = $AdminNamePatterns; AdditionalPrivilegedGroups = $AdditionalPrivilegedGroups; AdditionalTargets = $AdditionalTargets; SkipMemberExpansion = [bool]$SkipMemberExpansion; IncludeInherited = [bool]$IncludeInherited; IncludeLowSeverity = [bool]$IncludeLowSeverity }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
