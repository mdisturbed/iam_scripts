<#
.SYNOPSIS
    Read-only discovery of AWS identity posture: IAM users, access keys and other credentials, who
    is admin-equivalent through which policy, roles and their trusts (cross-account, external,
    OIDC), organization guardrails, IAM Identity Center permission sets and the people behind each
    assignment, and IAM Access Analyzer findings.

.DESCRIPTION
    Covers the AWS side of privileged and non-human identity sprawl. For each account in scope:
      - Account summary: root MFA, root access keys, password policy, SAML and OIDC providers, and
        (with -UseExistingCredentialReport) root last-used dates from the existing credential report
      - IAM users: console access, MFA, groups, attached / inline policies, permissions boundary,
        signing certificates and service-specific credentials, last activity, flags
      - Access keys: age, last used date and service, flags (old, unused, never used)
      - Admin-equivalent principals: every user and role that is admin-equivalent, and the exact
        path (direct policy, inline policy, group policy) and policy statement evidence. Policy
        documents are read once per account with GetAccountAuthorizationDetails.
      - Group memberships
      - IAM roles: trust policy principals (cross-account in or outside the organization, wildcard,
        SAML federation, OIDC with wildcard or missing subject, service), admin policies, last used
      - IAM Access Analyzer active findings: external access and unused access, per region
    Once per run:
      - Organization service / resource control policies and their targets, and delegated
        administrators (from the management or a delegated administrator account)
      - Identity Center permission sets (managed, customer managed and inline policies, boundary,
        admin flag), account assignments, and assignments expanded to the users in each group

    Multi-account: use -AllOrganizationAccounts (or -AccountIds) with -AssumeRoleName to read
    each account through a read-only role deployed to every account (for example by StackSet).

    A failed read is never reported as "none": console access, password policy and role last use
    show Unknown when the read fails; only NoSuchEntity means "not set".

    READ-ONLY. Uses only Get-* AWS cmdlets. Use-STSRole is used only to obtain temporary
    credentials for the read-only role; it changes nothing. The credential report is only read if
    one already exists; it is never generated.

    Output: <OutputRoot>\17-AwsIamPosture\<yyyyMMdd-HHmmssZ>\*.csv + run-manifest.json + run.log

.PARAMETER Regions
    Regions to read Access Analyzer findings from. Default: -Region only.

.PARAMETER SkipIdentityCenter
    Skip Identity Center. It is read by default when AWS.Tools.SSOAdmin and AWS.Tools.IdentityStore
    are installed; otherwise the datasets are Deferred.

.PARAMETER IncludeIdentityCenter
    Kept for compatibility; Identity Center is read by default.

.PARAMETER SkipPolicyAnalysis
    Skip the policy-document analysis (aws-effective-admins, aws-group-memberships).

.PARAMETER UseExistingCredentialReport
    Read the account's existing credential report for root last-used dates. Nothing is generated;
    when no current report exists the columns say so.

.EXAMPLE
    .\17-Get-AwsIamPosture.ps1 -ProfileName audit
.EXAMPLE
    .\17-Get-AwsIamPosture.ps1 -ProfileName org-audit -AllOrganizationAccounts -AssumeRoleName IAMDiscoveryReadOnly -Regions us-east-1,us-west-2
.EXAMPLE
    .\17-Get-AwsIamPosture.ps1 -AccountIds 111111111111,222222222222 -AssumeRoleName IAMDiscoveryReadOnly -SkipAccessAnalyzer -SkipIdentityCenter

.NOTES
    Version : 1.1.0
    Requires: PowerShell 5.1 or 7.x and AWS Tools for PowerShell modules:
              AWS.Tools.Common, AWS.Tools.SecurityToken, AWS.Tools.IdentityManagement
              (+ AWS.Tools.Organizations for -AllOrganizationAccounts, trust classification and
                 organization policies,
                 AWS.Tools.SSOAdmin and AWS.Tools.IdentityStore for Identity Center,
                 AWS.Tools.AccessAnalyzer unless -SkipAccessAnalyzer)
    AWS     : SecurityAudit + ViewOnlyAccess managed policies (or equivalent read) in each account,
              including iam:GetAccountAuthorizationDetails; IAM Identity Center and identity store
              read, and Organizations read, in the management / delegated admin account
#>
[CmdletBinding()]
param(
    # ---------------- CONFIG: edit here or pass as parameters ----------------
    [string]$OutputRoot = '',
    [string]$ProfileName = '',                           # AWS credential profile (blank = default chain)
    [string]$Region = 'us-east-1',
    [string[]]$Regions = @(),                            # Access Analyzer regions (blank = -Region)
    [string[]]$AccountIds = @(),                         # extra accounts to read via -AssumeRoleName
    [switch]$AllOrganizationAccounts,
    [string]$AssumeRoleName = '',                        # read-only role in each member account
    [switch]$SkipIdentityCenter,
    [switch]$IncludeIdentityCenter,                      # no-op: Identity Center is read by default
    [string]$IdentityCenterRegion = '',                  # blank = -Region
    [switch]$SkipAccessAnalyzer,
    [switch]$SkipPolicyAnalysis,
    [switch]$UseExistingCredentialReport,
    [int]$KeyAgeDays = 90,
    [int]$StaleDays = 90
    # -------------------------------------------------------------------------
)

$ErrorActionPreference = 'Stop'
$ScriptName    = '17-AwsIamPosture'
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

function Test-AwsError {
    # True when an AWS exception carries the given error code (for example NoSuchEntity).
    param($ErrorRecord, [string]$Code)
    $c = ''
    try { $c = "$($ErrorRecord.Exception.ErrorCode)" } catch { }
    if ($c -eq $Code) { return $true }
    return ("$($ErrorRecord.Exception.Message)" -match [regex]::Escape($Code))
}

function ConvertFrom-PolicyDocument {
    param($Document)
    if ($null -eq $Document -or "$Document" -eq '') { return $null }
    if ($Document -isnot [string]) { return $Document }
    try { return ([uri]::UnescapeDataString($Document) | ConvertFrom-Json) } catch { return $null }
}

# Actions that let a principal grant itself more access when allowed on Resource '*'.
$EscalationActions = @(
    'iam:createpolicyversion', 'iam:setdefaultpolicyversion', 'iam:attachuserpolicy', 'iam:attachgrouppolicy',
    'iam:attachrolepolicy', 'iam:putuserpolicy', 'iam:putgrouppolicy', 'iam:putrolepolicy', 'iam:createaccesskey',
    'iam:createloginprofile', 'iam:updateloginprofile', 'iam:addusertogroup', 'iam:updateassumerolepolicy',
    'iam:putuserpermissionsboundary', 'iam:deleteuserpermissionsboundary', 'iam:putrolepermissionsboundary', 'iam:deleterolepermissionsboundary'
)
$ComputeCreateActions = @('ec2:runinstances', 'lambda:createfunction', 'lambda:updatefunctionconfiguration', 'ecs:runtask', 'ecs:registertaskdefinition', 'glue:createdevendpoint', 'cloudformation:createstack', 'sagemaker:createnotebookinstance', 'codebuild:createproject', 'datapipeline:createpipeline')

function Get-PolicyRisk {
    # Returns why a policy document is admin-equivalent: full wildcard, iam:*, privilege-escalation
    # actions on '*', iam:PassRole with a compute create on '*', sts:AssumeRole on '*', or a broad
    # Allow + NotAction on '*'.
    param($Doc)
    $why = [System.Collections.Generic.List[string]]::new()
    if (-not $Doc) { return $why.ToArray() }
    $acts = [System.Collections.Generic.List[string]]::new()
    foreach ($st in @($Doc.Statement)) {
        if (-not $st -or "$($st.Effect)" -ne 'Allow') { continue }
        $res = @($st.Resource | ForEach-Object { "$_" })
        $resStar = ($res -contains '*')
        if ($st.PSObject.Properties.Name -contains 'NotAction' -and $st.NotAction) {
            if ($resStar -and -not $why.Contains('Allow with NotAction on *')) { $why.Add('Allow with NotAction on *') }
            continue
        }
        if (-not $resStar) { continue }
        foreach ($a in @($st.Action)) { if ($a) { $acts.Add("$a".ToLowerInvariant()) } }
    }
    if ($acts.Contains('*') -or $acts.Contains('*:*')) { $why.Add('Action * on Resource *') }
    elseif ($acts.Contains('iam:*')) { $why.Add('iam:* on Resource *') }
    $esc = @($EscalationActions | Where-Object { $op = $_; @($acts | Where-Object { $op -like $_ }).Count })
    if ($esc.Count -and -not $acts.Contains('*') -and -not $acts.Contains('iam:*')) { $why.Add('Privilege escalation on *: ' + ($esc -join ',')) }
    $pass = @($acts | Where-Object { 'iam:passrole' -like $_ }).Count -gt 0
    $compute = @($ComputeCreateActions | Where-Object { $op = $_; @($acts | Where-Object { $op -like $_ }).Count })
    if ($pass -and $compute.Count -and -not $acts.Contains('*')) { $why.Add('iam:PassRole + ' + ($compute -join ',') + ' on *') }
    if (@($acts | Where-Object { 'sts:assumerole' -like $_ -and $_ -ne '*' }).Count) { $why.Add('sts:AssumeRole on *') }
    return $why.ToArray()
}

function Get-OidcTrustIssue {
    # For roles trusted by an OIDC provider: flags a 'sub' condition that is a wildcard, or no 'sub'
    # condition at all (any repository / workload of that provider can assume the role).
    param([string]$Document)
    $out = @()
    $json = ConvertFrom-PolicyDocument $Document
    if (-not $json) { return $out }
    foreach ($st in @($json.Statement)) {
        if ("$($st.Effect)" -ne 'Allow' -or -not $st.Principal -or -not ($st.Principal.PSObject.Properties.Name -contains 'Federated')) { continue }
        foreach ($fed in @($st.Principal.Federated)) {
            if ("$fed" -match 'saml-provider') { continue }
            $idpHost = ("$fed" -replace '^arn:aws:iam::\d{12}:oidc-provider/', '')
            $subValues = @()
            if ($st.Condition) {
                foreach ($op in $st.Condition.PSObject.Properties) {
                    foreach ($kv in $op.Value.PSObject.Properties) { if ($kv.Name -match ':sub$') { $subValues += @($kv.Value | ForEach-Object { "$_" }) } }
                }
            }
            if (-not $subValues.Count) { $out += "OidcNoSubjectCondition($idpHost)" }
            elseif (@($subValues | Where-Object { $_ -eq '*' -or $_ -match ':\*$' -or $_ -match '^[^:]*\*' }).Count) { $out += "OidcWildcardSubject($idpHost)" }
        }
    }
    return $out
}

$callerAccount = ''
try {
    Write-RunLog ("{0} v{1} starting. Output: {2}" -f $ScriptName, $ScriptVersion, $script:RunFolder)
    if ($IncludeIdentityCenter) { Write-RunLog '-IncludeIdentityCenter is no longer needed: Identity Center is read by default (use -SkipIdentityCenter to turn it off).' }
    foreach ($m in 'AWS.Tools.Common', 'AWS.Tools.SecurityToken', 'AWS.Tools.IdentityManagement') {
        if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module $m not found. Install it (Install-Module $m -Scope CurrentUser) if your policy allows." }
        Import-Module $m -ErrorAction Stop
    }
    $aaRegions = @($Regions | Where-Object { $_ })
    if (-not $aaRegions.Count) { $aaRegions = @($Region) }
    $base = @{ Region = $Region }
    if ($ProfileName) { $base['ProfileName'] = $ProfileName }
    $me = Get-STSCallerIdentity @base
    $callerAccount = "$($me.Account)"
    Write-RunLog ("Signed in to AWS account {0} as {1}" -f $callerAccount, $me.Arn)
    $script:ManifestExtra = @{ AwsCallerAccount = $callerAccount; AwsCallerArn = "$($me.Arn)"; AwsRegion = $Region; AccessAnalyzerRegions = $aaRegions }

    # ---- Accounts in scope ----
    $accounts = [System.Collections.Generic.List[object]]::new()
    $accounts.Add([pscustomobject]@{ Id = $callerAccount; Name = '(signed-in account)'; Status = 'ACTIVE' })
    $orgAccountIds = @{}
    $orgAvailable = [bool](Get-Module -ListAvailable -Name AWS.Tools.Organizations)
    if ($AllOrganizationAccounts) {
        Import-Module AWS.Tools.Organizations -ErrorAction Stop
        foreach ($a in (Get-ORGAccountList @base)) {
            $orgAccountIds["$($a.Id)"] = $true
            if ("$($a.Id)" -eq $callerAccount) { $accounts[0].Name = $a.Name; continue }
            $accounts.Add([pscustomobject]@{ Id = "$($a.Id)"; Name = $a.Name; Status = "$($a.Status)" })
        }
    }
    elseif ($orgAvailable) {
        # Only used to tell in-organization trusts from external ones; failure is fine.
        try { Import-Module AWS.Tools.Organizations -ErrorAction Stop; foreach ($a in (Get-ORGAccountList @base)) { $orgAccountIds["$($a.Id)"] = $true } }
        catch { Write-RunLog ("Organization account list not readable ({0}); cross-account trusts are not classified in / outside the organization" -f $_.Exception.Message) 'WARN' }
    }
    foreach ($id in $AccountIds) { if (-not ($accounts | Where-Object Id -eq $id)) { $accounts.Add([pscustomobject]@{ Id = $id; Name = ''; Status = 'ACTIVE' }) } }
    if ($accounts.Count -gt 1 -and -not $AssumeRoleName) { throw 'Reading other accounts needs -AssumeRoleName (the read-only role deployed in each account).' }
    Write-RunLog ("{0} account(s) in scope" -f $accounts.Count)

    $acctRows = [System.Collections.Generic.List[object]]::new()
    $userRows = [System.Collections.Generic.List[object]]::new()
    $keyRows = [System.Collections.Generic.List[object]]::new()
    $roleRows = [System.Collections.Generic.List[object]]::new()
    $aaRows = [System.Collections.Generic.List[object]]::new()
    $unusedRows = [System.Collections.Generic.List[object]]::new()
    $samlRows = [System.Collections.Generic.List[object]]::new()
    $oidcRows = [System.Collections.Generic.List[object]]::new()
    $adminRows = [System.Collections.Generic.List[object]]::new()
    $gmRows = [System.Collections.Generic.List[object]]::new()
    $aaUnavailable = 0; $aaErrors = 0; $aaNoUnused = 0
    $aaModule = [bool](Get-Module -ListAvailable -Name AWS.Tools.AccessAnalyzer)
    $policyFailures = [System.Collections.Generic.List[string]]::new()
    $oidcFailures = 0
    $accountCreds = @{}
    $blankAcct = { param($Id, $Name, $Status) [pscustomobject][ordered]@{ AccountId = $Id; AccountName = $Name; ReadStatus = $Status; RootMfaEnabled = ''; RootAccessKeysPresent = ''; IamUsers = ''; IamRoles = ''; PasswordPolicy = ''; RootPasswordLastUsedUtc = ''; RootAccessKeyLastUsedUtc = ''; CredentialReportUtc = '' } }

    foreach ($acct in $accounts) {
        if ($acct.Status -ne 'ACTIVE') { $acctRows.Add((& $blankAcct $acct.Id $acct.Name "Skipped ($($acct.Status))")); continue }
        $p = @{ Region = $Region }
        if ($acct.Id -eq $callerAccount) { if ($ProfileName) { $p['ProfileName'] = $ProfileName } }
        else {
            try {
                $sts = Use-STSRole -RoleArn ("arn:aws:iam::{0}:role/{1}" -f $acct.Id, $AssumeRoleName) -RoleSessionName 'iam-discovery-readonly' @base
                $p['Credential'] = $sts.Credentials
            }
            catch {
                $acctRows.Add((& $blankAcct $acct.Id $acct.Name "Blocked: $($_.Exception.Message)"))
                Write-RunLog ("Account {0}: cannot assume role ({1})" -f $acct.Id, $_.Exception.Message) 'WARN'
                continue
            }
        }
        $accountCreds[$acct.Id] = $p
        Write-RunLog ("Reading account {0} {1}" -f $acct.Id, $acct.Name)

        try {
            # Account summary and password policy (NoSuchEntity = no policy; anything else = unknown)
            $sum = Get-IAMAccountSummary @p
            $pp = 'None'
            try { $ppo = Get-IAMAccountPasswordPolicy @p; $pp = "MinLength=$($ppo.MinimumPasswordLength); MaxAge=$($ppo.MaxPasswordAge); Reuse=$($ppo.PasswordReusePrevention)" }
            catch { if (-not (Test-AwsError $_ 'NoSuchEntity')) { $pp = "Unknown (error: $($_.Exception.Message))" } }
            $rootPwd = ''; $rootKey = ''; $repUtc = ''
            if ($UseExistingCredentialReport) {
                try {
                    $rep = Get-IAMCredentialReport @p
                    $text = ''
                    if ($rep.Content) { $sr = [System.IO.StreamReader]::new($rep.Content); $text = $sr.ReadToEnd(); $sr.Dispose() }
                    $repUtc = Format-Utc $rep.GeneratedTime
                    $root = @($text | ConvertFrom-Csv | Where-Object { $_.user -eq '<root_account>' }) | Select-Object -First 1
                    if ($root) {
                        $rootPwd = "$($root.password_last_used)"
                        $rootKey = (@("$($root.access_key_1_last_used_date)", "$($root.access_key_2_last_used_date)") | Where-Object { $_ -and $_ -ne 'N/A' } | Sort-Object -Descending | Select-Object -First 1)
                        if (-not $rootKey) { $rootKey = 'N/A' }
                    }
                }
                catch { $repUtc = "Unavailable: $($_.Exception.Message)"; Write-RunLog ("Account {0}: no current credential report ({1}); this script does not generate one" -f $acct.Id, $_.Exception.Message) 'WARN' }
            }
            $acctRows.Add([pscustomobject][ordered]@{
                AccountId                = $acct.Id
                AccountName              = $acct.Name
                ReadStatus               = 'Completed'
                RootMfaEnabled           = ([int]$sum['AccountMFAEnabled'] -eq 1)
                RootAccessKeysPresent    = ([int]$sum['AccountAccessKeysPresent'] -eq 1)
                IamUsers                 = $sum['Users']
                IamRoles                 = $sum['Roles']
                PasswordPolicy           = $pp
                RootPasswordLastUsedUtc  = $rootPwd
                RootAccessKeyLastUsedUtc = $rootKey
                CredentialReportUtc      = $repUtc
            })
            foreach ($s in @(Get-IAMSAMLProviderList @p)) { $samlRows.Add([pscustomobject][ordered]@{ AccountId = $acct.Id; ProviderArn = $s.Arn; ValidUntilUtc = Format-Utc $s.ValidUntil; CreatedUtc = Format-Utc $s.CreateDate }) }

            # Policy documents for every user, group, role and managed policy (one paged call)
            $auth = $null
            if (-not $SkipPolicyAnalysis) {
                try {
                    $auth = @{ Users = @{}; Groups = @{}; Roles = @{}; Policies = @{} }
                    $marker = $null; $guard = 0
                    do {
                        $guard++
                        $ad = @{ Filter = @('User', 'Group', 'Role', 'LocalManagedPolicy', 'AWSManagedPolicy'); Select = '*' }
                        if ($marker) { $ad['Marker'] = $marker }
                        $pages = @(Get-IAMAccountAuthorizationDetail @ad @p)
                        foreach ($pg in $pages) {
                            foreach ($x in @($pg.UserDetailList)) { if ($x) { $auth.Users["$($x.UserName)"] = $x } }
                            foreach ($x in @($pg.GroupDetailList)) { if ($x) { $auth.Groups["$($x.GroupName)"] = $x } }
                            foreach ($x in @($pg.RoleDetailList)) { if ($x) { $auth.Roles["$($x.RoleName)"] = $x } }
                            foreach ($x in @($pg.Policies)) { if ($x -and ($x.AttachmentCount -gt 0 -or "$($x.Arn)" -notmatch '^arn:aws:iam::aws:')) { $auth.Policies["$($x.Arn)"] = $x } }
                        }
                        $last = $(if ($pages.Count) { $pages[-1] } else { $null })
                        $marker = $(if ($last -and $last.IsTruncated -and $last.Marker) { $last.Marker } else { $null })
                    } while ($marker -and $guard -lt 500)
                }
                catch { $auth = $null; $policyFailures.Add($acct.Id); Write-RunLog ("Account {0}: authorization details unreadable ({1})" -f $acct.Id, $_.Exception.Message) 'WARN' }
            }
            $policyRiskCache = @{}
            $managedRisk = {
                param($Arn, $Name)
                if ($policyRiskCache.ContainsKey($Arn)) { return , $policyRiskCache[$Arn] }
                $r = @()
                $pol = $auth.Policies[$Arn]
                if ($pol) {
                    $ver = @($pol.PolicyVersionList | Where-Object { "$($_.IsDefaultVersion)" -eq 'True' -or $_.VersionId -eq $pol.DefaultVersionId }) | Select-Object -First 1
                    if ($ver) { $r = @(Get-PolicyRisk (ConvertFrom-PolicyDocument $ver.Document)) }
                }
                elseif (Test-AdminPolicy @($Name)) { $r = @("AWS managed policy $Name (document not read)") }
                $policyRiskCache[$Arn] = $r
                return , $r
            }
            $addAdmin = { param($Type, $Name, $Via, $Evidence, $Boundary) $adminRows.Add([pscustomobject][ordered]@{ AccountId = $acct.Id; PrincipalType = $Type; PrincipalName = $Name; Via = $Via; Evidence = ((@($Evidence) -join '; ') + $(if ($Boundary) { " (permissions boundary: $Boundary - may limit this)" } else { '' })) }) }
            $groupRisk = @{}
            if ($auth) {
                foreach ($g in $auth.Groups.Values) {
                    $list = [System.Collections.Generic.List[object]]::new()
                    foreach ($ap in @($g.AttachedManagedPolicies)) { if ($ap) { $r = & $managedRisk "$($ap.PolicyArn)" "$($ap.PolicyName)"; if (@($r).Count) { $list.Add([pscustomobject]@{ Via = "policy $($ap.PolicyName)"; Evidence = $r }) } } }
                    foreach ($ip in @($g.GroupPolicyList)) { if ($ip) { $r = @(Get-PolicyRisk (ConvertFrom-PolicyDocument $ip.PolicyDocument)); if ($r.Count) { $list.Add([pscustomobject]@{ Via = "inline policy $($ip.PolicyName)"; Evidence = $r }) } } }
                    $groupRisk["$($g.GroupName)"] = $list
                }
            }

            # Users and keys
            foreach ($u in @(Get-IAMUserList @p)) {
                $console = $true
                try { $null = Get-IAMLoginProfile -UserName $u.UserName @p }
                catch { $console = $(if (Test-AwsError $_ 'NoSuchEntity') { $false } else { 'Unknown' }) }
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
                $certs = ''; $ssc = ''
                try { $certs = @(Get-IAMSigningCertificate -UserName $u.UserName @p | Where-Object { "$($_.Status)" -eq 'Active' }).Count } catch { $certs = 'Unknown' }
                try { $ssc = @(Get-IAMServiceSpecificCredentialList -UserName $u.UserName @p | Where-Object { "$($_.Status)" -eq 'Active' }).Count } catch { $ssc = 'Unknown' }
                $ud = $(if ($auth) { $auth.Users["$($u.UserName)"] } else { $null })
                $boundary = $(if ($ud -and $ud.PermissionsBoundary) { "$($ud.PermissionsBoundary.PermissionsBoundaryArn)" } else { '' })
                $adminHit = $false
                if ($ud) {
                    foreach ($ap in @($ud.AttachedManagedPolicies)) { if ($ap) { $r = & $managedRisk "$($ap.PolicyArn)" "$($ap.PolicyName)"; if (@($r).Count) { $adminHit = $true; & $addAdmin 'User' $u.UserName "Direct policy $($ap.PolicyName)" $r $boundary } } }
                    foreach ($ip in @($ud.UserPolicyList)) { if ($ip) { $r = @(Get-PolicyRisk (ConvertFrom-PolicyDocument $ip.PolicyDocument)); if ($r.Count) { $adminHit = $true; & $addAdmin 'User' $u.UserName "Inline policy $($ip.PolicyName)" $r $boundary } } }
                    foreach ($gName in @($ud.GroupList)) { foreach ($gr in @($groupRisk["$gName"])) { if ($gr) { $adminHit = $true; & $addAdmin 'User' $u.UserName "Group $gName $($gr.Via)" $gr.Evidence $boundary } } }
                }
                $pwdAge = Get-Age $u.PasswordLastUsed
                $lastActivity = @($(if ($null -ne $pwdAge) { $pwdAge }), $(if ($lastKeyUse) { Get-Age $lastKeyUse }) | Where-Object { $null -ne $_ } | Measure-Object -Minimum).Minimum
                $uf = @()
                if ($console -eq $true -and $mfa -eq 0) { $uf += 'ConsoleWithoutMFA' }
                if ("$console" -eq 'Unknown') { $uf += 'ConsoleAccessUnknown' }
                if ((Test-AdminPolicy $policies) -or $adminHit) { $uf += 'AdminAccess' }
                if ($inline.Count) { $uf += 'InlinePolicies' }
                if ($null -eq $lastActivity) { $uf += 'NeverUsed' } elseif ($lastActivity -gt $StaleDays) { $uf += "Inactive${StaleDays}d" }
                if ("$certs" -ne 'Unknown' -and $certs -gt 0) { $uf += 'SigningCertificate' }
                if ("$ssc" -ne 'Unknown' -and $ssc -gt 0) { $uf += 'ServiceSpecificCredential' }
                $userRows.Add([pscustomobject][ordered]@{
                    AccountId           = $acct.Id
                    UserName            = $u.UserName
                    CreatedUtc          = Format-Utc $u.CreateDate
                    ConsoleAccess       = $console
                    MfaDevices          = $mfa
                    PasswordLastUsedUtc = Format-Utc $u.PasswordLastUsed
                    KeyLastUsedUtc      = Format-Utc $lastKeyUse
                    DaysSinceActivity   = $lastActivity
                    Groups              = Join-Values $groups
                    AttachedPolicies    = Join-Values $policies
                    InlinePolicies      = Join-Values $inline
                    Flags               = Join-Values $uf
                    PermissionsBoundary = $boundary
                    SigningCertificates = $certs
                    ServiceSpecificCredentials = $ssc
                    AdminEquivalent     = $(if ($auth) { $adminHit } else { 'Unknown' })
                })
                foreach ($gName in $groups) {
                    $gd = $(if ($auth) { $auth.Groups["$gName"] } else { $null })
                    $gmRows.Add([pscustomobject][ordered]@{ AccountId = $acct.Id; GroupName = $gName; UserName = $u.UserName; GroupAttachedPolicies = $(if ($gd) { Join-Values (@($gd.AttachedManagedPolicies) | ForEach-Object { $_.PolicyName }) } else { '' }); GroupInlinePolicies = $(if ($gd) { Join-Values (@($gd.GroupPolicyList) | ForEach-Object { $_.PolicyName }) } else { '' }); GroupIsAdminEquivalent = $(if ($auth) { [bool](@($groupRisk["$gName"]).Count) } else { 'Unknown' }) })
                }
            }

            # OIDC providers
            $oidcHosts = @{}
            try {
                foreach ($op in @(Get-IAMOpenIDConnectProviderList @p)) {
                    $arn = "$($op.Arn)"
                    $o = $null
                    try { $o = Get-IAMOpenIDConnectProvider -OpenIDConnectProviderArn $arn @p } catch { $oidcFailures++ }
                    $idpHostName = ($arn -replace '^arn:aws:iam::\d{12}:oidc-provider/', '')
                    $oidcHosts[$idpHostName] = 0
                    $oidcRows.Add([pscustomobject][ordered]@{ AccountId = $acct.Id; Url = $(if ($o) { "$($o.Url)" } else { $idpHostName }); ClientIds = $(if ($o) { Join-Values $o.ClientIDList } else { 'Unknown' }); Thumbprints = $(if ($o) { @($o.ThumbprintList).Count } else { '' }); CreatedUtc = $(if ($o) { Format-Utc $o.CreateDate } else { '' }); RolesTrusting = 0; RolesWithSubjectIssue = 0 })
                }
            }
            catch { $oidcFailures++; Write-RunLog ("Account {0}: OIDC providers unreadable ({1})" -f $acct.Id, $_.Exception.Message) 'WARN' }

            # Roles
            foreach ($r in @(Get-IAMRoleList @p)) {
                $isServiceLinked = "$($r.Path)" -like '/aws-service-role/*'
                $detail = $null; $detailRead = $true
                try { $detail = Get-IAMRole -RoleName $r.RoleName @p } catch { $detailRead = $false; Write-RunLog ("Role {0} in {1}: details unreadable ({2})" -f $r.RoleName, $acct.Id, $_.Exception.Message) 'WARN' }
                $lastUsed = $(if ($detail -and $detail.RoleLastUsed) { $detail.RoleLastUsed.LastUsedDate } else { $null })
                $principals = Get-TrustPrincipals $r.AssumeRolePolicyDocument
                $policies = @(Get-IAMAttachedRolePolicyList -RoleName $r.RoleName @p | ForEach-Object { $_.PolicyName })
                $rf = @()
                $crossAccounts = @(); $externalAccounts = @()
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
                if ($crossAccounts.Count) {
                    $rf += 'CrossAccountTrust'
                    if ($orgAccountIds.Count) {
                        $externalAccounts = @($crossAccounts | Where-Object { -not $orgAccountIds.ContainsKey($_) } | Select-Object -Unique)
                        if ($externalAccounts.Count) { $rf += 'ExternalAccountTrust' } else { $rf += 'InOrgAccountTrust' }
                    }
                }
                $oidcIssues = @()
                if (@($principals | Where-Object { $_.Type -eq 'Federated' -and $_.Value -notmatch 'saml-provider' }).Count) {
                    $oidcIssues = @(Get-OidcTrustIssue $r.AssumeRolePolicyDocument)
                    foreach ($pr in @($principals | Where-Object { $_.Type -eq 'Federated' -and $_.Value -notmatch 'saml-provider' })) {
                        $h = ("$($pr.Value)" -replace '^arn:aws:iam::\d{12}:oidc-provider/', '')
                        foreach ($orow in @($oidcRows | Where-Object { $_.AccountId -eq $acct.Id -and ($_.Url -eq $h -or $_.Url -eq "https://$h") })) { $orow.RolesTrusting++; if ($oidcIssues.Count) { $orow.RolesWithSubjectIssue++ } }
                    }
                    foreach ($oi in $oidcIssues) { $rf += ($oi -replace '\(.*$', '') }
                }
                $rd = $(if ($auth) { $auth.Roles["$($r.RoleName)"] } else { $null })
                $boundary = $(if ($rd -and $rd.PermissionsBoundary) { "$($rd.PermissionsBoundary.PermissionsBoundaryArn)" } elseif ($detail -and $detail.PermissionsBoundary) { "$($detail.PermissionsBoundary.PermissionsBoundaryArn)" } else { '' })
                $adminHit = $false
                if ($rd -and -not $isServiceLinked) {
                    foreach ($ap in @($rd.AttachedManagedPolicies)) { if ($ap) { $x = & $managedRisk "$($ap.PolicyArn)" "$($ap.PolicyName)"; if (@($x).Count) { $adminHit = $true; & $addAdmin 'Role' $r.RoleName "Direct policy $($ap.PolicyName)" $x $boundary } } }
                    foreach ($ip in @($rd.RolePolicyList)) { if ($ip) { $x = @(Get-PolicyRisk (ConvertFrom-PolicyDocument $ip.PolicyDocument)); if ($x.Count) { $adminHit = $true; & $addAdmin 'Role' $r.RoleName "Inline policy $($ip.PolicyName)" $x $boundary } } }
                }
                if ((Test-AdminPolicy $policies) -or $adminHit) { $rf += 'AdminAccess' }
                $luAge = Get-Age $lastUsed
                if (-not $isServiceLinked) {
                    if (-not $detailRead) { $rf += 'LastUsedUnknown' }
                    elseif ($null -eq $luAge) { $rf += 'NeverUsed' }
                    elseif ($luAge -gt $StaleDays) { $rf += "Unused${StaleDays}d" }
                }
                $roleRows.Add([pscustomobject][ordered]@{
                    AccountId          = $acct.Id
                    RoleName           = $r.RoleName
                    Path               = $r.Path
                    ServiceLinked      = $isServiceLinked
                    CreatedUtc         = Format-Utc $r.CreateDate
                    LastUsedUtc        = $(if ($detailRead) { Format-Utc $lastUsed } else { 'Unknown' })
                    TrustedPrincipals  = Join-Values ($principals | ForEach-Object { '{0}:{1}' -f $_.Type, $_.Value })
                    CrossAccountIds    = Join-Values ($crossAccounts | Select-Object -Unique)
                    AttachedPolicies   = Join-Values $policies
                    Flags              = Join-Values ($rf | Select-Object -Unique)
                    PermissionsBoundary = $boundary
                    ExternalAccountIds = Join-Values $externalAccounts
                    OidcTrustIssues    = Join-Values $oidcIssues
                    AdminEquivalent    = $(if ($auth) { $adminHit } else { 'Unknown' })
                })
            }

            # Access Analyzer: external access (v1 findings) and unused access (v2 findings), per region
            if (-not $SkipAccessAnalyzer -and $aaModule) {
                foreach ($rg in $aaRegions) {
                    $pr = @{} + $p
                    $pr['Region'] = $rg
                    try {
                        Import-Module AWS.Tools.AccessAnalyzer -ErrorAction Stop
                        $allAnalyzers = @(Get-IAMAAAnalyzerList @pr)
                        $analyzers = @($allAnalyzers | Where-Object { "$($_.Type)" -in @('ACCOUNT', 'ORGANIZATION') })
                        if (-not $analyzers.Count) { $aaUnavailable++ }
                        if (-not @($allAnalyzers | Where-Object { "$($_.Type)" -match 'UNUSED_ACCESS' }).Count) { $aaNoUnused++ }
                        foreach ($an in $analyzers) {
                            foreach ($f in @(Get-IAMAAFindingList -AnalyzerArn $an.Arn @pr)) {
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
                                    Region       = $rg
                                })
                            }
                        }
                        foreach ($an in @($allAnalyzers | Where-Object { "$($_.Type)" -match 'UNUSED_ACCESS' })) {
                            foreach ($f in @(Get-IAMAAFindingsV2List -AnalyzerArn $an.Arn @pr)) {
                                if ("$($f.Status)" -ne 'ACTIVE') { continue }
                                $unusedRows.Add([pscustomobject][ordered]@{ AccountId = $acct.Id; Region = $rg; Analyzer = $an.Name; FindingType = "$($f.FindingType)"; ResourceType = "$($f.ResourceType)"; Resource = "$($f.Resource)"; Status = "$($f.Status)"; UpdatedUtc = Format-Utc $f.UpdatedAt })
                            }
                        }
                    }
                    catch { $aaErrors++; Write-RunLog ("Account {0} region {1}: Access Analyzer unreadable ({2})" -f $acct.Id, $rg, $_.Exception.Message) 'WARN' }
                }
            }
        }
        catch {
            Write-RunLog ("Account {0}: read failed ({1})" -f $acct.Id, $_.Exception.Message) 'WARN'
            $acctRows.Add((& $blankAcct $acct.Id $acct.Name "Blocked: $($_.Exception.Message)"))
        }
    }

    Export-Dataset -Name 'aws-accounts' -Rows $acctRows -Note $(if ($UseExistingCredentialReport) { 'Root last-used values from the existing credential report (not regenerated)' } else { 'Run with -UseExistingCredentialReport for root last-used values' })
    Export-Dataset -Name 'aws-iam-users' -Rows $userRows -Note 'ConsoleAccess Unknown = login profile could not be read (not "no console")'
    Export-Dataset -Name 'aws-access-keys' -Rows $keyRows -Note 'Key IDs are truncated'
    Export-Dataset -Name 'aws-iam-roles' -Rows $roleRows -Note $(if ($orgAccountIds.Count) { 'ExternalAccountTrust = trusted account is outside the AWS Organization' } else { 'Organization account list not read: cross-account trusts not classified in / outside the organization' })
    Export-Dataset -Name 'aws-saml-providers' -Rows $samlRows
    Export-Dataset -Name 'aws-oidc-providers' -Rows $oidcRows -Status $(if ($oidcFailures) { 'Partial' } else { 'Completed' }) -Note 'RolesWithSubjectIssue = roles trusting this provider with no or a wildcard sub condition'
    if ($SkipPolicyAnalysis) {
        foreach ($n in 'aws-effective-admins', 'aws-group-memberships') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note '-SkipPolicyAnalysis' }
    }
    else {
        $paStatus = $(if ($policyFailures.Count) { 'Partial' } else { 'Completed' })
        $paNote = $(if ($policyFailures.Count) { "Authorization details unreadable in: $($policyFailures -join ', ') (no rows for those accounts is not evidence of none)" } else { '' })
        Export-Dataset -Name 'aws-effective-admins' -Rows $adminRows -Status $paStatus -Note ((@($paNote, 'Admin-equivalent = *:*, iam:*, privilege-escalation actions, PassRole + compute create, sts:AssumeRole on *, or broad Allow NotAction; service-linked roles excluded') | Where-Object { $_ }) -join '; ')
        Export-Dataset -Name 'aws-group-memberships' -Rows $gmRows -Status $paStatus -Note $paNote
    }
    if ($SkipAccessAnalyzer) { foreach ($n in 'aws-access-analyzer-findings', 'aws-unused-access-findings') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note '-SkipAccessAnalyzer' } }
    elseif (-not $aaModule) { foreach ($n in 'aws-access-analyzer-findings', 'aws-unused-access-findings') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note 'Module AWS.Tools.AccessAnalyzer not installed' } }
    else {
        $aaStatus = $(if ($aaErrors -or $aaUnavailable) { 'Partial' } else { 'Completed' })
        $aaNote = "Regions: $($aaRegions -join ', ')"
        if ($aaErrors) { $aaNote += "; $aaErrors account/region pair(s) could not be read (see run.log)" }
        if ($aaUnavailable) { $aaNote += "; $aaUnavailable account/region pair(s) have no external-access analyzer (no evidence there, not zero findings)" }
        Export-Dataset -Name 'aws-access-analyzer-findings' -Rows $aaRows -Status $aaStatus -Note $aaNote
        $uNote = "Active findings from unused-access analyzers; regions: $($aaRegions -join ', ')"
        if ($aaErrors) { $uNote += "; $aaErrors account/region pair(s) could not be read" }
        if ($aaNoUnused) { $uNote += "; $aaNoUnused account/region pair(s) have no unused-access analyzer" }
        Export-Dataset -Name 'aws-unused-access-findings' -Rows $unusedRows -Status $(if ($aaErrors -or $aaNoUnused) { 'Partial' } else { 'Completed' }) -Note $uNote
    }

    # ---- Organization guardrails (management or delegated admin account only) ----
    $orgPolRows = [System.Collections.Generic.List[object]]::new()
    $delegRows = @()
    if (-not $orgAvailable) { foreach ($n in 'aws-org-policies', 'aws-org-delegated-admins') { Set-DatasetStatus -Name $n -Status 'Deferred' -Note 'Module AWS.Tools.Organizations not installed' } }
    else {
        $orgPolFailed = @()
        foreach ($ptype in 'SERVICE_CONTROL_POLICY', 'RESOURCE_CONTROL_POLICY') {
            try {
                foreach ($pol in @(Get-ORGPolicyList -Filter $ptype @base)) {
                    $targets = @()
                    try { $targets = @(Get-ORGTargetForPolicy -PolicyId $pol.Id @base) } catch { $targets = $null }
                    $orgPolRows.Add([pscustomobject][ordered]@{ PolicyType = $ptype; PolicyName = "$($pol.Name)"; PolicyId = "$($pol.Id)"; AwsManaged = $pol.AwsManaged; Description = "$($pol.Description)"; TargetCount = $(if ($null -ne $targets) { $targets.Count } else { 'Unknown' }); Targets = $(if ($null -ne $targets) { Join-Values ($targets | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Type }) } else { 'Unknown (targets not readable)' }) })
                }
            }
            catch { $orgPolFailed += "$ptype : $($_.Exception.Message)" }
        }
        if ($orgPolFailed.Count -eq 2) { Set-DatasetStatus -Name 'aws-org-policies' -Status 'EvidenceUnavailable' -Note ('Organization policies readable only from the management or delegated administrator account: ' + ($orgPolFailed -join ' | ')) }
        else { Export-Dataset -Name 'aws-org-policies' -Rows $orgPolRows -Status $(if ($orgPolFailed.Count) { 'Partial' } else { 'Completed' }) -Note ($(if ($orgPolFailed.Count) { ($orgPolFailed -join ' | ') + '; ' } else { '' }) + 'FullAWSAccess alone attached everywhere = no SCP guardrail') }
        try {
            $delegRows = @(Get-ORGDelegatedAdministratorList @base | ForEach-Object { [pscustomobject][ordered]@{ AccountId = "$($_.Id)"; Name = "$($_.Name)"; Email = "$($_.Email)"; Status = "$($_.Status)"; DelegationEnabledUtc = Format-Utc $_.DelegationEnabledDate } })
            Export-Dataset -Name 'aws-org-delegated-admins' -Rows $delegRows -Note 'Member accounts delegated to administer an AWS service for the whole organization'
        }
        catch { Set-DatasetStatus -Name 'aws-org-delegated-admins' -Status 'EvidenceUnavailable' -Note ("Readable only from the management account: {0}" -f $_.Exception.Message) }
    }

    # ---- Identity Center ----
    $psRows = [System.Collections.Generic.List[object]]::new()
    $asgRows = [System.Collections.Generic.List[object]]::new()
    $icEffRows = [System.Collections.Generic.List[object]]::new()
    $icNames = 'aws-identity-center-permission-sets', 'aws-identity-center-assignments', 'aws-identity-center-effective-users'
    $icAvailable = [bool](Get-Module -ListAvailable -Name AWS.Tools.SSOAdmin) -and [bool](Get-Module -ListAvailable -Name AWS.Tools.IdentityStore)
    if ($SkipIdentityCenter) { foreach ($n in $icNames) { Set-DatasetStatus -Name $n -Status 'Deferred' -Note '-SkipIdentityCenter' } }
    elseif (-not $icAvailable) { foreach ($n in $icNames) { Set-DatasetStatus -Name $n -Status 'Deferred' -Note 'Modules AWS.Tools.SSOAdmin and AWS.Tools.IdentityStore not installed' } }
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
            $memberCache = @{}
            function Get-IcGroupMember {
                param([string]$GroupId)
                if ($memberCache.ContainsKey($GroupId)) { return $memberCache[$GroupId] }
                $m = $null
                try { $m = @(Get-IDSGroupMembershipList -IdentityStoreId $inst.IdentityStoreId -GroupId $GroupId @icp | ForEach-Object { "$($_.MemberId.UserId)" } | Where-Object { $_ }) }
                catch { $script:IcMemberFailures++; Write-RunLog ("Identity Center group {0} members unreadable: {1}" -f $GroupId, $_.Exception.Message) 'WARN' }
                $memberCache[$GroupId] = $m
                return $m
            }
            $script:IcMemberFailures = 0
            foreach ($psArn in @(Get-SSOADMNPermissionSetList -InstanceArn $inst.InstanceArn @icp)) {
                $ps = Get-SSOADMNPermissionSet -InstanceArn $inst.InstanceArn -PermissionSetArn $psArn @icp
                $managed = @(Get-SSOADMNManagedPoliciesInPermissionSetList -InstanceArn $inst.InstanceArn -PermissionSetArn $psArn @icp | ForEach-Object { $_.Name })
                $inline = ''
                try { $inline = "$(Get-SSOADMNInlinePolicyForPermissionSet -InstanceArn $inst.InstanceArn -PermissionSetArn $psArn @icp)" } catch { }
                $inlineWildcard = ($inline -match '"Action"\s*:\s*"\*"' -or $inline -match '"Action"\s*:\s*\[\s*"\*"')
                $inlineRisk = @(Get-PolicyRisk (ConvertFrom-PolicyDocument $inline))
                $isAdmin = (Test-AdminPolicy $managed) -or $inlineWildcard -or [bool]$inlineRisk.Count
                $cmp = ''; $pb = ''
                try { $cmp = Join-Values (@(Get-SSOADMNCustomerManagedPolicyReferencesInPermissionSetList -InstanceArn $inst.InstanceArn -PermissionSetArn $psArn @icp) | ForEach-Object { '{0}{1}' -f $(if ($_.Path -and $_.Path -ne '/') { $_.Path } else { '' }), $_.Name }) } catch { $cmp = 'Unknown' }
                try {
                    $b = Get-SSOADMNPermissionsBoundaryForPermissionSet -InstanceArn $inst.InstanceArn -PermissionSetArn $psArn @icp
                    $pb = $(if ($b.ManagedPolicyArn) { "$($b.ManagedPolicyArn)" } elseif ($b.CustomerManagedPolicyReference) { "$($b.CustomerManagedPolicyReference.Name)" } else { '' })
                }
                catch { $pb = $(if (Test-AwsError $_ 'ResourceNotFoundException') { '' } else { 'Unknown' }) }
                $acctIds = @(Get-SSOADMNAccountsForProvisionedPermissionSetList -InstanceArn $inst.InstanceArn -PermissionSetArn $psArn @icp)
                $count = 0
                foreach ($aid in $acctIds) {
                    $aName = (@($accounts | Where-Object Id -eq "$aid") | Select-Object -First 1 -ExpandProperty Name)
                    foreach ($a in @(Get-SSOADMNAccountAssignmentList -InstanceArn $inst.InstanceArn -AccountId $aid -PermissionSetArn $psArn @icp)) {
                        $count++
                        $pName = Get-PrincipalName "$($a.PrincipalType)" "$($a.PrincipalId)"
                        $asgRows.Add([pscustomobject][ordered]@{
                            PermissionSet  = $ps.Name
                            IsAdminSet     = $isAdmin
                            AccountId      = $aid
                            AccountName    = $aName
                            PrincipalType  = $a.PrincipalType
                            PrincipalName  = $pName
                            Flags          = Join-Values @($(if ("$($a.PrincipalType)" -eq 'USER') { 'DirectUserAssignment' }), $(if ($isAdmin) { 'AdminPermissionSet' }))
                        })
                        if ("$($a.PrincipalType)" -eq 'GROUP') {
                            $mem = Get-IcGroupMember "$($a.PrincipalId)"
                            if ($null -eq $mem) { continue }
                            foreach ($uid in $mem) { $icEffRows.Add([pscustomobject][ordered]@{ PermissionSet = $ps.Name; IsAdminSet = $isAdmin; AccountId = $aid; AccountName = $aName; UserName = (Get-PrincipalName 'USER' $uid); UserId = $uid; Via = "Group $pName"; GroupName = $pName }) }
                        }
                        else { $icEffRows.Add([pscustomobject][ordered]@{ PermissionSet = $ps.Name; IsAdminSet = $isAdmin; AccountId = $aid; AccountName = $aName; UserName = $pName; UserId = "$($a.PrincipalId)"; Via = 'Direct'; GroupName = '' }) }
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
                    CustomerManagedPolicies = $cmp
                    PermissionsBoundary = $pb
                    InlineRisk       = Join-Values $inlineRisk
                })
            }
            Export-Dataset -Name 'aws-identity-center-permission-sets' -Rows $psRows
            Export-Dataset -Name 'aws-identity-center-assignments' -Rows $asgRows
            Export-Dataset -Name 'aws-identity-center-effective-users' -Rows $icEffRows -Status $(if ($script:IcMemberFailures) { 'Partial' } else { 'Completed' }) -Note $(if ($script:IcMemberFailures) { "$($script:IcMemberFailures) group(s) could not be expanded; see run.log" } else { 'Group assignments expanded to their member users' })
        }
        catch {
            foreach ($n in $icNames) { Set-DatasetStatus -Name $n -Status 'Blocked' -Note $_.Exception.Message }
        }
    }

    # ---- Summary ----
    $summary = [System.Collections.Generic.List[object]]::new()
    function Add-Metric { param($Metric, $Value, $Note = '') $summary.Add([pscustomobject][ordered]@{ Metric = $Metric; Value = $Value; Note = $Note }) }
    Add-Metric -Metric 'Accounts in scope' $accounts.Count
    Add-Metric -Metric 'Accounts read' @($acctRows | Where-Object ReadStatus -eq 'Completed').Count
    Add-Metric -Metric 'Accounts that could not be read' @($acctRows | Where-Object { $_.ReadStatus -like 'Blocked*' }).Count
    Add-Metric -Metric 'Accounts with root MFA OFF' @($acctRows | Where-Object { $_.RootMfaEnabled -eq $false }).Count 'Critical'
    Add-Metric -Metric 'Accounts with root access keys' @($acctRows | Where-Object { $_.RootAccessKeysPresent -eq $true }).Count 'Critical'
    Add-Metric -Metric 'Accounts with password policy unknown' @($acctRows | Where-Object { "$($_.PasswordPolicy)" -like 'Unknown*' }).Count 'Read failed - not the same as no policy'
    Add-Metric -Metric 'IAM users' $userRows.Count 'Long-lived identities; Identity Center is preferred for people'
    Add-Metric -Metric 'IAM users with console access but no MFA' @($userRows | Where-Object { $_.Flags -match 'ConsoleWithoutMFA' }).Count
    Add-Metric -Metric 'IAM users whose console access could not be read' @($userRows | Where-Object { "$($_.ConsoleAccess)" -eq 'Unknown' }).Count
    Add-Metric -Metric 'IAM users with admin-level policies' @($userRows | Where-Object { $_.Flags -match 'AdminAccess' }).Count
    Add-Metric -Metric "IAM users inactive over $StaleDays days or never used" @($userRows | Where-Object { $_.Flags -match 'Inactive|NeverUsed' }).Count
    Add-Metric -Metric 'Active access keys' @($keyRows | Where-Object Status -eq 'Active').Count
    Add-Metric -Metric "Active keys older than $KeyAgeDays days" @($keyRows | Where-Object { $_.Flags -match 'OlderThan' }).Count
    Add-Metric -Metric 'Active keys never used or unused' @($keyRows | Where-Object { $_.Flags -match 'NeverUsed|Unused' }).Count
    $custRoles = @($roleRows | Where-Object { -not $_.ServiceLinked })
    Add-Metric -Metric 'IAM roles (excluding service-linked)' $custRoles.Count
    Add-Metric -Metric 'Roles trusting other AWS accounts' @($custRoles | Where-Object { $_.Flags -match 'CrossAccountTrust' }).Count
    Add-Metric -Metric 'Roles trusting accounts outside the organization' @($custRoles | Where-Object { $_.Flags -match 'ExternalAccountTrust' }).Count $(if ($orgAccountIds.Count) { '' } else { 'Organization account list not read - not classified' })
    Add-Metric -Metric 'Cross-account trusts with no condition' @($custRoles | Where-Object { $_.Flags -match 'CrossAccountNoCondition' }).Count 'No ExternalId / source condition'
    Add-Metric -Metric 'Roles trusting a wildcard principal' @($custRoles | Where-Object { $_.Flags -match 'WildcardPrincipal' }).Count
    Add-Metric -Metric 'Roles trusting OIDC with a wildcard or missing subject' @($custRoles | Where-Object { $_.Flags -match 'OidcWildcardSubject|OidcNoSubjectCondition' }).Count 'Any repository / workload of that provider can assume the role'
    Add-Metric -Metric 'SAML-federated roles' @($custRoles | Where-Object { $_.Flags -match 'SamlFederated' }).Count 'Direct IdP-to-IAM federation (outside Identity Center)'
    Add-Metric -Metric 'Roles with admin-level policies' @($custRoles | Where-Object { $_.Flags -match 'AdminAccess' }).Count
    Add-Metric -Metric "Roles unused over $StaleDays days or never used" @($custRoles | Where-Object { $_.Flags -match 'Unused|NeverUsed' }).Count
    Add-Metric -Metric 'Roles whose last use could not be read' @($custRoles | Where-Object { $_.Flags -match 'LastUsedUnknown' }).Count
    if (-not $SkipPolicyAnalysis) {
        Add-Metric -Metric 'Admin-equivalent IAM users (any path)' @($adminRows | Where-Object PrincipalType -eq 'User' | ForEach-Object { "$($_.AccountId)|$($_.PrincipalName)" } | Select-Object -Unique).Count 'Direct, inline or group policies'
        Add-Metric -Metric 'Admin-equivalent IAM roles' @($adminRows | Where-Object PrincipalType -eq 'Role' | ForEach-Object { "$($_.AccountId)|$($_.PrincipalName)" } | Select-Object -Unique).Count
        Add-Metric -Metric 'Accounts whose policies could not be analysed' $policyFailures.Count
    }
    Add-Metric -Metric 'OIDC identity providers' $oidcRows.Count
    Add-Metric -Metric 'IAM users with signing certificates or service-specific credentials' @($userRows | Where-Object { $_.Flags -match 'SigningCertificate|ServiceSpecificCredential' }).Count 'Long-lived credentials besides access keys'
    if (-not $SkipAccessAnalyzer) {
        Add-Metric -Metric 'Active external-access findings' $aaRows.Count
        Add-Metric -Metric 'Public findings' @($aaRows | Where-Object IsPublic).Count
        Add-Metric -Metric 'Active unused-access findings' $unusedRows.Count
    }
    if ($orgPolRows.Count) { Add-Metric -Metric 'Service / resource control policies' $orgPolRows.Count }
    if ($psRows.Count) {
        Add-Metric -Metric 'Identity Center permission sets' $psRows.Count
        Add-Metric -Metric 'Admin-level permission sets' @($psRows | Where-Object IsAdminSet).Count
        Add-Metric -Metric 'Identity Center assignments' $asgRows.Count
        Add-Metric -Metric 'Assignments made directly to users' @($asgRows | Where-Object { $_.Flags -match 'DirectUserAssignment' }).Count 'Best practice: assign to groups'
        Add-Metric -Metric 'Admin permission set assignments' @($asgRows | Where-Object IsAdminSet).Count
        Add-Metric -Metric 'Distinct Identity Center users with an admin permission set' @($icEffRows | Where-Object IsAdminSet | Select-Object -ExpandProperty UserId -Unique).Count 'Groups expanded to members'
    }
    Export-Dataset -Name 'summary' -Rows $summary
}
catch {
    Write-RunLog ("Fatal: {0}" -f $_.Exception.Message) 'ERROR'
    throw
}
finally {
    Write-RunManifest -DomainName '' -Parameters @{ ProfileName = $ProfileName; Region = $Region; Regions = $Regions; AccountIds = $AccountIds; AllOrganizationAccounts = [bool]$AllOrganizationAccounts; AssumeRoleName = $AssumeRoleName; IncludeIdentityCenter = [bool]$IncludeIdentityCenter; SkipIdentityCenter = [bool]$SkipIdentityCenter; SkipAccessAnalyzer = [bool]$SkipAccessAnalyzer; SkipPolicyAnalysis = [bool]$SkipPolicyAnalysis; UseExistingCredentialReport = [bool]$UseExistingCredentialReport; KeyAgeDays = $KeyAgeDays; StaleDays = $StaleDays }
    Write-RunLog ("Finished. Evidence folder: {0}" -f $script:RunFolder)
}
