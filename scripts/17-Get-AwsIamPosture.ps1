<#
.SYNOPSIS
    Read-only discovery of AWS identity posture: IAM users, access keys, roles and trusts,
    IAM Identity Center permission sets and assignments, and IAM Access Analyzer findings.

.DESCRIPTION
    Covers the AWS side of privileged and non-human identity sprawl. For each account in scope:
      - Account summary: root MFA, root access keys, password policy, SAML providers
      - IAM users: console access, MFA, groups, attached / inline policies, last password use,
        and flags (console without MFA, administrator access, inactive)
      - Access keys: age, last used date and service, flags (old, unused, never used)
      - IAM roles: trust policy principals (cross-account, wildcard, SAML federation, service),
        attached administrator policies, last used, flags
      - IAM Access Analyzer external-access findings (active), where an analyzer exists
    Once per run (from the Identity Center management or delegated admin account):
      - Permission sets: session duration, managed / inline policies, admin flag
      - Account assignments: which users and groups get which permission set in which account

    Multi-account: use -AllOrganizationAccounts (or -AccountIds) with -AssumeRoleName to read
    each account through a read-only role deployed to every account (for example by StackSet).

    READ-ONLY. Uses only Get-* AWS cmdlets. Use-STSRole is used only to obtain temporary
    credentials for the read-only role; it changes nothing.

    Output: <OutputRoot>\17-AwsIamPosture\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.EXAMPLE
    .\17-Get-AwsIamPosture.ps1 -ProfileName audit
.EXAMPLE
    .\17-Get-AwsIamPosture.ps1 -ProfileName org-audit -AllOrganizationAccounts -AssumeRoleName IAMDiscoveryReadOnly -IncludeIdentityCenter
.EXAMPLE
    .\17-Get-AwsIamPosture.ps1 -AccountIds 111111111111,222222222222 -AssumeRoleName IAMDiscoveryReadOnly -SkipAccessAnalyzer

.NOTES
    Version : 1.0.0
    Requires: PowerShell 5.1 or 7.x and AWS Tools for PowerShell modules:
              AWS.Tools.Common, AWS.Tools.SecurityToken, AWS.Tools.IdentityManagement
              (+ AWS.Tools.Organizations for -AllOrganizationAccounts,
                 AWS.Tools.SSOAdmin and AWS.Tools.IdentityStore for -IncludeIdentityCenter,
                 AWS.Tools.AccessAnalyzer unless -SkipAccessAnalyzer)
    AWS     : SecurityAudit + ViewOnlyAccess managed policies (or equivalent read) in each account;
              IAM Identity Center read in the management / delegated admin account
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$ProfileName = '',                           # AWS credential profile (blank = default chain)
    [string]$Region = 'us-east-1',
    [string[]]$AccountIds = @(),                         # extra accounts to read via -AssumeRoleName
    [switch]$AllOrganizationAccounts,
    [string]$AssumeRoleName = '',                        # read-only role in each member account
    [switch]$IncludeIdentityCenter,
    [string]$IdentityCenterRegion = '',                  # blank = -Region
    [switch]$SkipAccessAnalyzer,
    [int]$KeyAgeDays = 90,
    [int]$StaleDays = 90
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '17-AwsIamPosture'
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

function Format-Utc { param($Value) if ($Value -and ([datetime]$Value).Year -gt 1900) { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } return '' }
function Get-Age { param($Value) if ($Value -and ([datetime]$Value).Year -gt 1900) { return [int]($script:RunStartUtc - ([datetime]$Value).ToUniversalTime()).TotalDays } return $null }

function Get-TrustPrincipals {
    # Parses a URL-encoded trust policy into principal entries.
    param([string]$Document)
    $out = [System.Collections.Generic.List[object]]::new()
    if (-not $Document) { return , $out }
    $json = $null
    try { $json = [uri]::UnescapeDataString($Document) | ConvertFrom-Json } catch { return , $out }
    foreach ($st in @($json.Statement)) {
        if ("$($st.Effect)" -ne 'Allow') { continue }
        $hasCondition = [bool]$st.Condition
        $p = $st.Principal
        if ("$p" -eq '*') { $out.Add([pscustomobject]@{ Type = 'AWS'; Value = '*'; HasCondition = $hasCondition }); continue }
        foreach ($kind in 'AWS', 'Federated', 'Service') {
            if ($p -and $p.PSObject.Properties.Name -contains $kind) {
                foreach ($v in @($p.$kind)) { $out.Add([pscustomobject]@{ Type = $kind; Value = "$v"; HasCondition = $hasCondition }) }
            }
        }
    }
    return , $out
}

function Test-AdminPolicy { param($PolicyNames) return [bool](@($PolicyNames | Where-Object { $_ -in @('AdministratorAccess', 'IAMFullAccess', 'PowerUserAccess') }).Count) }

$callerAccount = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    foreach ($m in 'AWS.Tools.Common', 'AWS.Tools.SecurityToken', 'AWS.Tools.IdentityManagement') {
        if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module $m not found. Install it (Install-Module $m -Scope CurrentUser) if your policy allows." }
        Import-Module $m -ErrorAction Stop
    }
    $base = @{ Region = $Region }
    if ($ProfileName) { $base['ProfileName'] = $ProfileName }
    $me = Get-STSCallerIdentity @base
    $callerAccount = "$($me.Account)"
    Write-RunLog ("Signed in to AWS account {0} as {1}" -f $callerAccount, $me.Arn)
    $script:ManifestExtra = @{ AwsCallerAccount = $callerAccount; AwsCallerArn = "$($me.Arn)"; AwsRegion = $Region }

    # ---- Accounts in scope ----
    $accounts = [System.Collections.Generic.List[object]]::new()
    $accounts.Add([pscustomobject]@{ Id = $callerAccount; Name = '(signed-in account)'; Status = 'ACTIVE' })
    if ($AllOrganizationAccounts) {
        Import-Module AWS.Tools.Organizations -ErrorAction Stop
        foreach ($a in (Get-ORGAccountList @base)) {
            if ("$($a.Id)" -eq $callerAccount) { $accounts[0].Name = $a.Name; continue }
            $accounts.Add([pscustomobject]@{ Id = "$($a.Id)"; Name = $a.Name; Status = "$($a.Status)" })
        }
    }
    foreach ($id in $AccountIds) { if (-not ($accounts | Where-Object Id -eq $id)) { $accounts.Add([pscustomobject]@{ Id = $id; Name = ''; Status = 'ACTIVE' }) } }
    if ($accounts.Count -gt 1 -and -not $AssumeRoleName) { throw 'Reading other accounts needs -AssumeRoleName (the read-only role deployed in each account).' }
    Write-RunLog ("{0} account(s) in scope" -f $accounts.Count)

    $acctRows = [System.Collections.Generic.List[object]]::new()
    $userRows = [System.Collections.Generic.List[object]]::new()
    $keyRows = [System.Collections.Generic.List[object]]::new()
    $roleRows = [System.Collections.Generic.List[object]]::new()
    $aaRows = [System.Collections.Generic.List[object]]::new()
    $samlRows = [System.Collections.Generic.List[object]]::new()
    $aaUnavailable = 0
    $accountCreds = @{}

    foreach ($acct in $accounts) {
        if ($acct.Status -ne 'ACTIVE') { $acctRows.Add([pscustomobject][ordered]@{ AccountId = $acct.Id; AccountName = $acct.Name; ReadStatus = "Skipped ($($acct.Status))"; RootMfaEnabled = ''; RootAccessKeysPresent = ''; IamUsers = ''; IamRoles = ''; PasswordPolicy = '' }); continue }
        $p = @{ Region = $Region }
        if ($acct.Id -eq $callerAccount) { if ($ProfileName) { $p['ProfileName'] = $ProfileName } }
        else {
            try {
                $sts = Use-STSRole -RoleArn ("arn:aws:iam::{0}:role/{1}" -f $acct.Id, $AssumeRoleName) -RoleSessionName 'iam-discovery-readonly' @base
                $p['Credential'] = $sts.Credentials
            }
            catch {
                $acctRows.Add([pscustomobject][ordered]@{ AccountId = $acct.Id; AccountName = $acct.Name; ReadStatus = "Blocked: $($_.Exception.Message)"; RootMfaEnabled = ''; RootAccessKeysPresent = ''; IamUsers = ''; IamRoles = ''; PasswordPolicy = '' })
                Write-RunLog ("Account {0}: cannot assume role ({1})" -f $acct.Id, $_.Exception.Message) 'WARN'
                continue
            }
        }
        $accountCreds[$acct.Id] = $p
        Write-RunLog ("Reading account {0} {1}" -f $acct.Id, $acct.Name)

        try {
            # Account summary and password policy
            $sum = Get-IAMAccountSummary @p
            $pp = 'None'
            try { $ppo = Get-IAMAccountPasswordPolicy @p; $pp = "MinLength=$($ppo.MinimumPasswordLength); MaxAge=$($ppo.MaxPasswordAge); Reuse=$($ppo.PasswordReusePrevention)" } catch { }
            $acctRows.Add([pscustomobject][ordered]@{
                AccountId             = $acct.Id
                AccountName           = $acct.Name
                ReadStatus            = 'Completed'
                RootMfaEnabled        = ([int]$sum['AccountMFAEnabled'] -eq 1)
                RootAccessKeysPresent = ([int]$sum['AccountAccessKeysPresent'] -eq 1)
                IamUsers              = $sum['Users']
                IamRoles              = $sum['Roles']
                PasswordPolicy        = $pp
            })
            foreach ($s in @(Get-IAMSAMLProviderList @p)) { $samlRows.Add([pscustomobject][ordered]@{ AccountId = $acct.Id; ProviderArn = $s.Arn; ValidUntilUtc = Format-Utc $s.ValidUntil; CreatedUtc = Format-Utc $s.CreateDate }) }

            # Users and keys
            foreach ($u in @(Get-IAMUserList @p)) {
                $console = $true
                try { $null = Get-IAMLoginProfile -UserName $u.UserName @p } catch { $console = $false }
                $mfa = @(Get-IAMMFADevice -UserName $u.UserName @p).Count
                $groups = @(Get-IAMGroupForUser -UserName $u.UserName @p | ForEach-Object { $_.GroupName })
                $policies = @(Get-IAMAttachedUserPolicyList -UserName $u.UserName @p | ForEach-Object { $_.PolicyName })
                foreach ($gName in $groups) { $policies += @(Get-IAMAttachedGroupPolicyList -GroupName $gName @p | ForEach-Object { $_.PolicyName }) }
                $policies = @($policies | Select-Object -Unique)
                $inline = @(Get-IAMUserPolicyList -UserName $u.UserName @p)
                $lastKeyUse = $null
                foreach ($k in @(Get-IAMAccessKey -UserName $u.UserName @p)) {
                    $lu = Get-IAMAccessKeyLastUsed -AccessKeyId $k.AccessKeyId @p
                    $used = $lu.AccessKeyLastUsed.LastUsedDate
                    $usedAge = Get-Age $used
                    if ($null -ne $usedAge -and ($null -eq $lastKeyUse -or $used -gt $lastKeyUse)) { $lastKeyUse = $used }
                    $age = Get-Age $k.CreateDate
                    $kf = @()
                    if ("$($k.Status)" -eq 'Active') {
                        if ($age -gt $KeyAgeDays) { $kf += "OlderThan${KeyAgeDays}d" }
                        if ($null -eq $usedAge) { $kf += 'NeverUsed' } elseif ($usedAge -gt $StaleDays) { $kf += "Unused${StaleDays}d" }
                    }
                    $keyRows.Add([pscustomobject][ordered]@{
                        AccountId       = $acct.Id
                        UserName        = $u.UserName
                        AccessKeyId     = ('{0}...{1}' -f "$($k.AccessKeyId)".Substring(0, [math]::Min(4, "$($k.AccessKeyId)".Length)), "$($k.AccessKeyId)".Substring([math]::Max(0, "$($k.AccessKeyId)".Length - 4)))
                        Status          = $k.Status
                        CreatedUtc      = Format-Utc $k.CreateDate
                        AgeDays         = $age
                        LastUsedUtc     = Format-Utc $used
                        LastUsedService = $lu.AccessKeyLastUsed.ServiceName
                        Flags           = Join-Values $kf
                    })
                }
                $pwdAge = Get-Age $u.PasswordLastUsed
                $lastActivity = @($(if ($null -ne $pwdAge) { $pwdAge }), $(if ($lastKeyUse) { Get-Age $lastKeyUse }) | Where-Object { $null -ne $_ } | Measure-Object -Minimum).Minimum
                $uf = @()
                if ($console -and $mfa -eq 0) { $uf += 'ConsoleWithoutMFA' }
                if (Test-AdminPolicy $policies) { $uf += 'AdminAccess' }
                if ($inline.Count) { $uf += 'InlinePolicies' }
                if ($null -eq $lastActivity) { $uf += 'NeverUsed' } elseif ($lastActivity -gt $StaleDays) { $uf += "Inactive${StaleDays}d" }
                $userRows.Add([pscustomobject][ordered]@{
                    AccountId          = $acct.Id
                    UserName           = $u.UserName
                    CreatedUtc         = Format-Utc $u.CreateDate
                    ConsoleAccess      = $console
                    MfaDevices         = $mfa
                    PasswordLastUsedUtc = Format-Utc $u.PasswordLastUsed
                    KeyLastUsedUtc     = Format-Utc $lastKeyUse
                    DaysSinceActivity  = $lastActivity
                    Groups             = Join-Values $groups
                    AttachedPolicies   = Join-Values $policies
                    InlinePolicies     = Join-Values $inline
                    Flags              = Join-Values $uf
                })
            }

            # Roles
            foreach ($r in @(Get-IAMRoleList @p)) {
                $isServiceLinked = "$($r.Path)" -like '/aws-service-role/*'
                $detail = $null
                try { $detail = Get-IAMRole -RoleName $r.RoleName @p } catch { }
                $lastUsed = $(if ($detail -and $detail.RoleLastUsed) { $detail.RoleLastUsed.LastUsedDate } else { $null })
                $principals = Get-TrustPrincipals $r.AssumeRolePolicyDocument
                $policies = @(Get-IAMAttachedRolePolicyList -RoleName $r.RoleName @p | ForEach-Object { $_.PolicyName })
                $rf = @()
                $crossAccounts = @()
                foreach ($pr in $principals) {
                    if ($pr.Type -eq 'AWS') {
                        if ($pr.Value -eq '*') { $rf += $(if ($pr.HasCondition) { 'WildcardPrincipalWithCondition' } else { 'WildcardPrincipal' }) }
                        elseif ($pr.Value -match '(\d{12})' -and $Matches[1] -ne $acct.Id) {
                            $crossAccounts += $Matches[1]
                            if (-not $pr.HasCondition) { $rf += 'CrossAccountNoCondition' }
                        }
                    }
                    if ($pr.Type -eq 'Federated' -and $pr.Value -match 'saml-provider') { $rf += 'SamlFederated' }
                    elseif ($pr.Type -eq 'Federated') { $rf += 'WebIdentityFederated' }
                }
                if ($crossAccounts.Count) { $rf += 'CrossAccountTrust' }
                if (Test-AdminPolicy $policies) { $rf += 'AdminAccess' }
                $luAge = Get-Age $lastUsed
                if (-not $isServiceLinked) { if ($null -eq $luAge) { $rf += 'NeverUsed' } elseif ($luAge -gt $StaleDays) { $rf += "Unused${StaleDays}d" } }
                $roleRows.Add([pscustomobject][ordered]@{
                    AccountId          = $acct.Id
                    RoleName           = $r.RoleName
                    Path               = $r.Path
                    ServiceLinked      = $isServiceLinked
                    CreatedUtc         = Format-Utc $r.CreateDate
                    LastUsedUtc        = Format-Utc $lastUsed
                    TrustedPrincipals  = Join-Values ($principals | ForEach-Object { '{0}:{1}' -f $_.Type, $_.Value })
                    CrossAccountIds    = Join-Values ($crossAccounts | Select-Object -Unique)
                    AttachedPolicies   = Join-Values $policies
                    Flags              = Join-Values ($rf | Select-Object -Unique)
                })
            }

            # Access Analyzer (external access)
            if (-not $SkipAccessAnalyzer) {
                try {
                    Import-Module AWS.Tools.AccessAnalyzer -ErrorAction Stop
                    $analyzers = @(Get-IAMAAAnalyzerList @p | Where-Object { "$($_.Type)" -in @('ACCOUNT', 'ORGANIZATION') })
                    if (-not $analyzers.Count) { $aaUnavailable++ }
                    foreach ($an in $analyzers) {
                        foreach ($f in @(Get-IAMAAFindingList -AnalyzerArn $an.Arn @p)) {
                            if ("$($f.Status)" -ne 'ACTIVE') { continue }
                            $aaRows.Add([pscustomobject][ordered]@{
                                AccountId    = $acct.Id
                                Analyzer     = $an.Name
                                ResourceType = $f.ResourceType
                                Resource     = $f.Resource
                                Principal    = $(if ($f.Principal) { Join-Values ($f.Principal.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) } else { '' })
                                IsPublic     = $f.IsPublic
                                Actions      = Join-Values $f.Action
                                UpdatedUtc   = Format-Utc $f.UpdatedAt
                            })
                        }
                    }
                }
                catch { $aaUnavailable++; Write-RunLog ("Account {0}: Access Analyzer unreadable ({1})" -f $acct.Id, $_.Exception.Message) 'WARN' }
            }
        }
        catch {
            Write-RunLog ("Account {0}: read failed ({1})" -f $acct.Id, $_.Exception.Message) 'WARN'
            $acctRows.Add([pscustomobject][ordered]@{ AccountId = $acct.Id; AccountName = $acct.Name; ReadStatus = "Blocked: $($_.Exception.Message)"; RootMfaEnabled = ''; RootAccessKeysPresent = ''; IamUsers = ''; IamRoles = ''; PasswordPolicy = '' })
        }
    }

    Export-Dataset -Name 'aws-accounts' -Rows $acctRows
    Export-Dataset -Name 'aws-iam-users' -Rows $userRows
    Export-Dataset -Name 'aws-access-keys' -Rows $keyRows -Note 'Key IDs are truncated'
    Export-Dataset -Name 'aws-iam-roles' -Rows $roleRows
    Export-Dataset -Name 'aws-saml-providers' -Rows $samlRows
    if ($SkipAccessAnalyzer) { Set-DatasetStatus -Name 'aws-access-analyzer-findings' -Status 'Deferred' -Note '-SkipAccessAnalyzer' }
    else { Export-Dataset -Name 'aws-access-analyzer-findings' -Rows $aaRows -Note $(if ($aaUnavailable) { "$aaUnavailable account(s) had no external-access analyzer in $Region or could not be read" } else { '' }) }

    # ---- Identity Center ----
    $psRows = [System.Collections.Generic.List[object]]::new()
    $asgRows = [System.Collections.Generic.List[object]]::new()
    if (-not $IncludeIdentityCenter) {
        foreach ($n in 'aws-identity-center-permission-sets', 'aws-identity-center-assignments') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note 'Run with -IncludeIdentityCenter' }
    }
    else {
        try {
            Import-Module AWS.Tools.SSOAdmin, AWS.Tools.IdentityStore -ErrorAction Stop
            $icp = @{} + $accountCreds[$callerAccount]
            if ($IdentityCenterRegion) { $icp['Region'] = $IdentityCenterRegion }
            $inst = @(Get-SSOADMNInstanceList @icp) | Select-Object -First 1
            if (-not $inst) { throw 'No IAM Identity Center instance visible from this account/region.' }
            $nameCache = @{}
            function Get-PrincipalName {
                param([string]$Type, [string]$Id)
                $k = "$Type|$Id"
                if ($nameCache.ContainsKey($k)) { return $nameCache[$k] }
                $n = $Id
                try { $n = $(if ($Type -eq 'GROUP') { (Get-IDSGroup -IdentityStoreId $inst.IdentityStoreId -GroupId $Id @icp).DisplayName } else { (Get-IDSUser -IdentityStoreId $inst.IdentityStoreId -UserId $Id @icp).UserName }) } catch { }
                $nameCache[$k] = $n
                return $n
            }
            foreach ($psArn in @(Get-SSOADMNPermissionSetList -InstanceArn $inst.InstanceArn @icp)) {
                $ps = Get-SSOADMNPermissionSet -InstanceArn $inst.InstanceArn -PermissionSetArn $psArn @icp
                $managed = @(Get-SSOADMNManagedPoliciesInPermissionSetList -InstanceArn $inst.InstanceArn -PermissionSetArn $psArn @icp | ForEach-Object { $_.Name })
                $inline = ''
                try { $inline = "$(Get-SSOADMNInlinePolicyForPermissionSet -InstanceArn $inst.InstanceArn -PermissionSetArn $psArn @icp)" } catch { }
                $inlineWildcard = ($inline -match '"Action"\s*:\s*"\*"' -or $inline -match '"Action"\s*:\s*\[\s*"\*"')
                $isAdmin = (Test-AdminPolicy $managed) -or $inlineWildcard
                $acctIds = @(Get-SSOADMNAccountsForProvisionedPermissionSetList -InstanceArn $inst.InstanceArn -PermissionSetArn $psArn @icp)
                $count = 0
                foreach ($aid in $acctIds) {
                    foreach ($a in @(Get-SSOADMNAccountAssignmentList -InstanceArn $inst.InstanceArn -AccountId $aid -PermissionSetArn $psArn @icp)) {
                        $count++
                        $asgRows.Add([pscustomobject][ordered]@{
                            PermissionSet  = $ps.Name
                            IsAdminSet     = $isAdmin
                            AccountId      = $aid
                            AccountName    = (@($accounts | Where-Object Id -eq "$aid") | Select-Object -First 1 -ExpandProperty Name)
                            PrincipalType  = $a.PrincipalType
                            PrincipalName  = Get-PrincipalName "$($a.PrincipalType)" "$($a.PrincipalId)"
                            Flags          = Join-Values @($(if ("$($a.PrincipalType)" -eq 'USER') { 'DirectUserAssignment' }), $(if ($isAdmin) { 'AdminPermissionSet' }))
                        })
                    }
                }
                $psRows.Add([pscustomobject][ordered]@{
                    PermissionSet    = $ps.Name
                    Description      = $ps.Description
                    SessionDuration  = $ps.SessionDuration
                    ManagedPolicies  = Join-Values $managed
                    HasInlinePolicy  = [bool]$inline
                    InlineWildcard   = $inlineWildcard
                    IsAdminSet       = $isAdmin
                    ProvisionedAccounts = $acctIds.Count
                    Assignments      = $count
                })
            }
            Export-Dataset -Name 'aws-identity-center-permission-sets' -Rows $psRows
            Export-Dataset -Name 'aws-identity-center-assignments' -Rows $asgRows
        }
        catch {
            foreach ($n in 'aws-identity-center-permission-sets', 'aws-identity-center-assignments') { Set-DatasetStatus -Name $n -Status 'Blocked' -Note $_.Exception.Message }
        }
    }

    # ---- Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric 'Accounts in scope' $accounts.Count
    Add-Metric 'Accounts read' @($acctRows | Where-Object ReadStatus -eq 'Completed').Count
    Add-Metric 'Accounts that could not be read' @($acctRows | Where-Object { $_.ReadStatus -like 'Blocked*' }).Count
    Add-Metric 'Accounts with root MFA OFF' @($acctRows | Where-Object { $_.RootMfaEnabled -eq $false }).Count 'Critical'
    Add-Metric 'Accounts with root access keys' @($acctRows | Where-Object { $_.RootAccessKeysPresent -eq $true }).Count 'Critical'
    Add-Metric 'IAM users' $userRows.Count 'Long-lived identities; Identity Center is preferred for people'
    Add-Metric 'IAM users with console access but no MFA' @($userRows | Where-Object { $_.Flags -match 'ConsoleWithoutMFA' }).Count
    Add-Metric 'IAM users with admin-level policies' @($userRows | Where-Object { $_.Flags -match 'AdminAccess' }).Count
    Add-Metric "IAM users inactive over $StaleDays days or never used" @($userRows | Where-Object { $_.Flags -match 'Inactive|NeverUsed' }).Count
    Add-Metric 'Active access keys' @($keyRows | Where-Object Status -eq 'Active').Count
    Add-Metric "Active keys older than $KeyAgeDays days" @($keyRows | Where-Object { $_.Flags -match 'OlderThan' }).Count
    Add-Metric 'Active keys never used or unused' @($keyRows | Where-Object { $_.Flags -match 'NeverUsed|Unused' }).Count
    $custRoles = @($roleRows | Where-Object { -not $_.ServiceLinked })
    Add-Metric 'IAM roles (excluding service-linked)' $custRoles.Count
    Add-Metric 'Roles trusting other AWS accounts' @($custRoles | Where-Object { $_.Flags -match 'CrossAccountTrust' }).Count
    Add-Metric 'Cross-account trusts with no condition' @($custRoles | Where-Object { $_.Flags -match 'CrossAccountNoCondition' }).Count 'No ExternalId / source condition'
    Add-Metric 'Roles trusting a wildcard principal' @($custRoles | Where-Object { $_.Flags -match 'WildcardPrincipal' }).Count
    Add-Metric 'SAML-federated roles' @($custRoles | Where-Object { $_.Flags -match 'SamlFederated' }).Count 'Direct IdP-to-IAM federation (outside Identity Center)'
    Add-Metric 'Roles with admin-level policies' @($custRoles | Where-Object { $_.Flags -match 'AdminAccess' }).Count
    Add-Metric "Roles unused over $StaleDays days or never used" @($custRoles | Where-Object { $_.Flags -match 'Unused|NeverUsed' }).Count
    if (-not $SkipAccessAnalyzer) {
        Add-Metric 'Active external-access findings' $aaRows.Count
        Add-Metric 'Public findings' @($aaRows | Where-Object IsPublic).Count
    }
    if ($IncludeIdentityCenter -and $psRows.Count) {
        Add-Metric 'Identity Center permission sets' $psRows.Count
        Add-Metric 'Admin-level permission sets' @($psRows | Where-Object IsAdminSet).Count
        Add-Metric 'Identity Center assignments' $asgRows.Count
        Add-Metric 'Assignments made directly to users' @($asgRows | Where-Object { $_.Flags -match 'DirectUserAssignment' }).Count 'Best practice: assign to groups'
        Add-Metric 'Admin permission set assignments' @($asgRows | Where-Object IsAdminSet).Count
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName '' -Parameters @{ ProfileName = $ProfileName; Region = $Region; AccountIds = $AccountIds; AllOrganizationAccounts = [bool]$AllOrganizationAccounts; AssumeRoleName = $AssumeRoleName; IncludeIdentityCenter = [bool]$IncludeIdentityCenter; SkipAccessAnalyzer = [bool]$SkipAccessAnalyzer; KeyAgeDays = $KeyAgeDays; StaleDays = $StaleDays }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
