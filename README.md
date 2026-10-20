# IAM Discovery Scripts

Read-only PowerShell scripts that collect evidence for an identity and access management (IAM) gap analysis across **Microsoft Entra ID**, **on-premises Active Directory**, **Intune**, **Exchange Online / SharePoint**, **Azure** and **AWS**.

Each script measures one gap, writes timestamped CSVs plus a run manifest, and can be rerun after remediation to show progress against the same baseline. The output is designed to stand up as audit evidence (for example in a HITRUST, NIST or CIS assessment): every run records who ran it, from where, when, with which permissions, and a SHA-256 hash of every file it produced.

> **Nothing in these scripts changes anything.** Graph calls go through one function that only sends HTTP `GET`; Azure Resource Manager calls go through one function that only sends `GET`; AD, Exchange, SharePoint, event log and AWS work uses only `Get-*` cmdlets. [`tools/Test-ReadOnly.ps1`](tools/Test-ReadOnly.ps1) proves this statically, without running anything, so a reviewer can confirm it in seconds.

> **Test status:** every script is **mock-tested** (see [Testing](#testing)). Before handing a script to others, run it once yourself in the target environment and check it against known answers using the [pilot runbook](docs/pilot-runbook.md).

---

## Contents

- [What it measures](#what-it-measures)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [Prerequisites](#prerequisites)
- [Authentication](#authentication)
- [Common parameters](#common-parameters)
- [The scripts](#the-scripts)
  - Entra: [01 MFA coverage](#01---mfa-coverage) · [02 Privileged access](#02---entra-privileged-access) · [03 Apps and consents](#03---apps-and-consents) · [10 Guests](#10---guest-access) · [21 Identity risk](#21---identity-risk) · [22 PIM role settings](#22---pim-role-settings)
  - AD: [04 Privileged and service accounts](#04---ad-privileged-and-service-accounts) · [05 Group nesting](#05---ad-group-nesting) · [07 Role mining](#07---role-mining) · [18 Delegation and ACLs](#18---ad-delegation) · [19 NTLM / Kerberos usage](#19---dc-authentication-protocols)
  - Hybrid: [08 Extension attributes](#08---extension-attribute-inventory) · [12 Stale accounts](#12---stale-accounts) · [13 Sync scope](#13---hybrid-sync-scope)
  - Devices: [16 Device posture](#16---device-posture)
  - Microsoft 365: [09 Mail forwarding and sharing](#09---mail-forwarding-and-external-sharing)
  - Azure: [11 Azure RBAC](#11---azure-rbac)
  - AWS: [17 AWS IAM posture](#17---aws-iam-posture)
  - Governance: [20 Access review coverage](#20---governance-coverage)
  - Lifecycle and governance: [06 JML timing](#06---jml-timing) · [14 IGA reconciliation](#14---iga-reconciliation) · [15 Rule-managed access](#15---rule-managed-access)
- [Output and evidence](#output-and-evidence)
- [Dataset statuses](#dataset-statuses)
- [Read-only guarantee](#read-only-guarantee)
- [Handling the output](#handling-the-output)
- [Locked-down environments](#locked-down-environments)
- [Using the results](#using-the-results)
- [Troubleshooting](#troubleshooting)
- [Design choices](#design-choices)
- [Testing](#testing)
- [Version history](#version-history)

---

## What it measures

| # | Script | Question it answers | Source | Version |
|---|--------|--------------------|--------|---------|
| 01 | [`01-Get-MfaCoverage.ps1`](scripts/01-Get-MfaCoverage.ps1) | Is MFA actually enforced everywhere, or only registered? | Entra | 1.0.1 |
| 02 | [`02-Get-PrivilegedAccess.ps1`](scripts/02-Get-PrivilegedAccess.ps1) | Who holds Entra admin roles, how, and are those accounts well managed? | Entra | 1.0.1 |
| 03 | [`03-Get-AppsAndConsents.ps1`](scripts/03-Get-AppsAndConsents.ps1) | Which apps can reach our data, and are they governed? | Entra | 1.0.1 |
| 04 | [`04-Get-ADPrivilegedAndServiceAccounts.ps1`](scripts/04-Get-ADPrivilegedAndServiceAccounts.ps1) | Who has admin rights on-prem (including via nesting), and where are the service accounts? | AD | 1.0.1 |
| 05 | [`05-Get-ADGroupNesting.ps1`](scripts/05-Get-ADGroupNesting.ps1) | How deep and messy is group nesting, and how healthy are groups? | AD | 1.0.1 |
| 06 | [`06-Compare-JmlTiming.ps1`](scripts/06-Compare-JmlTiming.ps1) | How quickly are joiners provisioned and leavers disabled, compared with HR? | AD + HR file (+ Entra) | 1.0.1 |
| 07 | [`07-Get-RoleMiningCandidates.ps1`](scripts/07-Get-RoleMiningCandidates.ps1) | Which groups do people in the same department or job code share, and is the HR data clean enough to drive roles? | AD | 1.0.0 |
| 08 | [`08-Get-ExtensionAttributeInventory.ps1`](scripts/08-Get-ExtensionAttributeInventory.ps1) | Which custom / extension attributes are free to carry new data? | AD (+ Entra) | 1.0.0 |
| 09 | [`09-Get-MailForwardingAndSharing.ps1`](scripts/09-Get-MailForwardingAndSharing.ps1) | Is mail being forwarded out, and how open is SharePoint / OneDrive sharing? | Exchange Online + SharePoint | 1.0.0 |
| 10 | [`10-Get-GuestAccess.ps1`](scripts/10-Get-GuestAccess.ps1) | How many guests are there, are they used, and what can they reach? | Entra | 1.0.0 |
| 11 | [`11-Get-AzureRbac.ps1`](scripts/11-Get-AzureRbac.ps1) | Who has access to Azure resources, at what scope, and to deleted principals? | Azure + Entra | 1.0.0 |
| 12 | [`12-Get-StaleAccounts.ps1`](scripts/12-Get-StaleAccounts.ps1) | Which identities are really unused once AD and Entra activity are combined? | AD + Entra | 1.0.0 |
| 13 | [`13-Get-HybridSyncScope.ps1`](scripts/13-Get-HybridSyncScope.ps1) | What actually syncs from AD to Entra, and where do they disagree? | AD + Entra | 1.0.0 |
| 14 | [`14-Compare-IgaToDirectory.ps1`](scripts/14-Compare-IgaToDirectory.ps1) | Where does the IGA platform's view of accounts and group access differ from AD? | AD + IGA export | 1.0.0 |
| 15 | [`15-Test-RuleManagedAccess.ps1`](scripts/15-Test-RuleManagedAccess.ps1) | Are applied roles, HR-expected roles and actual group membership in step? | AD + role files | 1.0.0 |
| 16 | [`16-Get-DevicePosture.ps1`](scripts/16-Get-DevicePosture.ps1) | Are devices joined, managed and compliant, and does Conditional Access rely on it? | Entra + Intune | 1.0.0 |
| 17 | [`17-Get-AwsIamPosture.ps1`](scripts/17-Get-AwsIamPosture.ps1) | Which AWS users, keys, roles, trusts and permission sets exist, and which are risky? | AWS | 1.0.0 |
| 18 | [`18-Get-ADDelegation.ps1`](scripts/18-Get-ADDelegation.ps1) | Who has dangerous rights through AD permissions (ACLs), not group membership? | AD | 1.0.0 |
| 19 | [`19-Get-DcAuthProtocolUsage.ps1`](scripts/19-Get-DcAuthProtocolUsage.ps1) | Who still uses NTLM (v1 especially) or RC4/DES Kerberos? | DC event logs | 1.0.0 |
| 20 | [`20-Get-GovernanceCoverage.ps1`](scripts/20-Get-GovernanceCoverage.ps1) | What share of apps, groups and roles is actually covered by access reviews? | Entra ID Governance | 1.0.0 |
| 21 | [`21-Get-IdentityRisk.ps1`](scripts/21-Get-IdentityRisk.ps1) | Who is at risk right now, and does Conditional Access act on risk? | Entra ID Protection | 1.0.0 |
| 22 | [`22-Get-PimRoleSettings.ps1`](scripts/22-Get-PimRoleSettings.ps1) | What does it actually take to activate each admin role? | Entra PIM | 1.0.0 |

The scripts gather facts. They do not score maturity or recommend fixes; that interpretation belongs in the analysis that uses the evidence.

## Repository layout

```
iam_scripts/
├── README.md                     this file
├── CHANGELOG.md                  version history
├── .gitignore                    blocks evidence, keys and data exports from being committed
├── scripts/                      the twenty-two discovery scripts (self-contained, run independently)
├── tools/
│   └── Test-ReadOnly.ps1         static proof that the scripts cannot write anything
├── examples/                     placeholder input templates for scripts 06, 14 and 15
│   ├── hr.example.csv
│   ├── iga-accounts.example.csv
│   ├── iga-assignments.example.csv
│   ├── role-definitions.example.csv
│   └── rule-map.example.csv
└── docs/
    ├── permissions.md            roles, scopes, licences and modules per script
    ├── outputs.md                every output file and column, with reading notes
    └── pilot-runbook.md          how to verify each script in the real environment before handover
```

## Quick start

```powershell
# 1. Prove the scripts are read-only (AST scan only - nothing executes)
.\tools\Test-ReadOnly.ps1

# 2. Entra, signing in as yourself
.\scripts\01-Get-MfaCoverage.ps1   -OutputRoot D:\Evidence
.\scripts\02-Get-PrivilegedAccess.ps1 -OutputRoot D:\Evidence
.\scripts\03-Get-AppsAndConsents.ps1  -OutputRoot D:\Evidence
.\scripts\10-Get-GuestAccess.ps1      -OutputRoot D:\Evidence

# 3. On-prem AD, from a management host with RSAT
.\scripts\04-Get-ADPrivilegedAndServiceAccounts.ps1 -Server dc01.contoso.local -OutputRoot D:\Evidence
.\scripts\05-Get-ADGroupNesting.ps1                 -Server dc01.contoso.local -OutputRoot D:\Evidence
.\scripts\07-Get-RoleMiningCandidates.ps1           -GroupingAttributes department,extensionAttribute5 -OutputRoot D:\Evidence

# 4. Hybrid (AD + Entra)
.\scripts\08-Get-ExtensionAttributeInventory.ps1 -IncludeEntra -OutputRoot D:\Evidence
.\scripts\12-Get-StaleAccounts.ps1               -IncludeComputers -OutputRoot D:\Evidence
.\scripts\13-Get-HybridSyncScope.ps1             -IncludeGroups -OutputRoot D:\Evidence

# 5. Microsoft 365, Azure, devices, governance
.\scripts\09-Get-MailForwardingAndSharing.ps1 -OutputRoot D:\Evidence
.\scripts\11-Get-AzureRbac.ps1                -OutputRoot D:\Evidence
.\scripts\16-Get-DevicePosture.ps1            -OutputRoot D:\Evidence
.\scripts\20-Get-GovernanceCoverage.ps1       -IncludeDecisionStats -OutputRoot D:\Evidence
.\scripts\21-Get-IdentityRisk.ps1             -OutputRoot D:\Evidence
.\scripts\22-Get-PimRoleSettings.ps1          -OutputRoot D:\Evidence

# 6. AD permissions and legacy authentication
.\scripts\18-Get-ADDelegation.ps1             -OutputRoot D:\Evidence
.\scripts\19-Get-DcAuthProtocolUsage.ps1      -Hours 24 -OutputRoot D:\Evidence

# 7. AWS (credential profile, or a read-only role in every account)
.\scripts\17-Get-AwsIamPosture.ps1 -ProfileName audit -AllOrganizationAccounts -AssumeRoleName IAMDiscoveryReadOnly -IncludeIdentityCenter -OutputRoot D:\Evidence

# 8. Need input files (templates in .\examples)
.\scripts\06-Compare-JmlTiming.ps1        -HrCsvPath .\hr-export.csv -OutputRoot D:\Evidence
.\scripts\14-Compare-IgaToDirectory.ps1   -AccountsCsv .\iga-accounts.csv -AssignmentsCsv .\iga-assignments.csv -OutputRoot D:\Evidence
.\scripts\15-Test-RuleManagedAccess.ps1   -RoleDefinitionCsv .\roles.csv -RuleMapCsv .\rule-map.csv -OutputRoot D:\Evidence

# Full help for any script
Get-Help .\scripts\07-Get-RoleMiningCandidates.ps1 -Full
```

Start with `summary.csv` in each run folder.

## Prerequisites

### PowerShell and modules

| Need | Scripts | Notes |
|------|---------|-------|
| PowerShell 5.1 or 7.x | All | Written for both; tested on 7.4 |
| `Microsoft.Graph.Authentication` | 01, 02, 03, 10, 11, 12, 13, 16, 20, 21, 22; 06 / 08 / 09 optionally | The only Graph module needed; all calls are raw `GET` requests |
| RSAT `ActiveDirectory` | 04, 05, 06, 07, 08, 12, 13, 14, 15, 18, 19 | Read access with a standard domain account is normally enough |
| `ExchangeOnlineManagement` v3 | 09 | Uses `Get-EXOMailbox` / `Get-EXORecipient` |
| `Microsoft.Online.SharePoint.PowerShell` | 09 with `-IncludeSiteSharing` | Windows PowerShell 5.1 |
| `Az.Accounts` | 11 | Only `Connect-AzAccount`, `Get-AzContext` and `Invoke-AzRestMethod -Method GET` |
| AWS Tools for PowerShell | 17 | `AWS.Tools.Common`, `.SecurityToken`, `.IdentityManagement`; plus `.Organizations`, `.SSOAdmin`, `.IdentityStore`, `.AccessAnalyzer` for the optional parts |
| Windows + remote event log access | 19 | `Get-WinEvent` against each DC (RPC) |

```powershell
# If policy allows installing modules:
Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement, Az.Accounts -Scope CurrentUser
Install-Module AWS.Tools.Common, AWS.Tools.SecurityToken, AWS.Tools.IdentityManagement, AWS.Tools.Organizations, AWS.Tools.SSOAdmin, AWS.Tools.IdentityStore, AWS.Tools.AccessAnalyzer -Scope CurrentUser
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

If installs are blocked, Azure Cloud Shell in the tenant includes the Graph, Exchange and Az modules (but not RSAT).

### Access and licences

| Need | Scripts |
|------|---------|
| Entra **Global Reader** (preferred) | 01, 02, 03, 10, 12, 13, 16, 20, 22, 08 / 09 Graph parts |
| Entra **Security Reader** (or Global Reader) | 21 |
| Intune **Read Only Operator** (or Global Reader) | 16 |
| Exchange: Global Reader or View-Only Organization Management | 09 |
| Azure **Reader** at the root management group, or on each subscription | 11 |
| AWS **SecurityAudit + ViewOnlyAccess** in each account (role deployed by StackSet); IAM Identity Center read | 17 |
| **Event Log Readers** on domain controllers | 19 |
| Entra ID P1 | Sign-in activity (01, 02, 03, 06, 10, 12) |
| Entra ID P2 / ID Governance | PIM eligibility (02, 11), access reviews (20), risk data (21), PIM settings (22) |

Scope-by-scope detail is in [docs/permissions.md](docs/permissions.md). Missing access doesn't crash a script; the affected dataset is marked `Blocked` or `EvidenceUnavailable`.

## Authentication

Every script that uses Graph, Exchange or Azure supports two modes through `-AuthMode`:

| Mode | When to use | Parameters |
|------|-------------|------------|
| `Delegated` (default) | You sign in interactively; results are limited to what your role can read | none |
| `AppCertificate` | A dedicated read-only app registration with a certificate; suits repeatable runs | `-TenantId`, `-ClientId`, `-CertificateThumbprint` (09 also needs `-ExchangeOrganization contoso.onmicrosoft.com`) |

Each Graph script requests only the read scopes it needs and logs a warning if the token is missing any of them, or if it carries write scopes from an earlier consent. The scripts still only send `GET`. App-only setup is in [docs/permissions.md](docs/permissions.md#app-registration-for-app-only-mode-optional).

## Common parameters

| Parameter | Scripts | Default | Purpose |
|-----------|---------|---------|---------|
| `-OutputRoot` | All | `scripts\output` | Where run folders are written. Point this at the approved evidence location. |
| `-Server` | AD scripts | session default DC | Domain controller or domain to query, e.g. `dc01.contoso.local` |
| `-SearchBase` | Most AD scripts | whole domain | Limit to an OU, e.g. `OU=People,DC=contoso,DC=local` |
| `-AuthMode`, `-TenantId`, `-ClientId`, `-CertificateThumbprint` | Graph / Exchange / Azure scripts | Delegated | See [Authentication](#authentication) |

## The scripts

Each section lists what the script collects, its own parameters (beyond the [common ones](#common-parameters)), and which file to open first. Every output file and column is described in [docs/outputs.md](docs/outputs.md).

### 01 - MFA coverage

Measures whether MFA is actually enforced, not just registered.

**Collects:** every Conditional Access policy flattened with names resolved; one row per exclusion and the transitive members of excluded groups; MFA registration for every user (registered vs capable, SMS/voice, phone-only); successful single-factor sign-ins over a lookback window, with legacy authentication flagged.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SignInLookbackDays` | `7` | Days of sign-in logs to read (1-30) |
| `-MaxSignInRecords` | `50000` | Safety cap; output marked TRUNCATED if reached |
| `-SkipSignIns` | off | Skip the sign-in query |
| `-SkipExcludedGroupMembers` | off | Skip expanding excluded groups |

**Start with:** `summary.csv`, then `ca-exclusions.csv` and `signins-singlefactor-success.csv`.

### 02 - Entra privileged access

Shows who holds directory roles, how (directly, through a group, permanently or just-in-time), and whether those accounts are well managed.

**Collects:** active and eligible (PIM) role assignments; members of role-holding groups; role-assignable groups and owners; one row per privileged user with sync source, last sign-in, MFA registration, Tier 0 role and flags. Falls back to plain role assignments if PIM isn't licensed.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-StaleDays` | `90` | Days without sign-in before a privileged user is flagged |

**Start with:** `summary.csv`, then `privileged-users.csv` sorted by `Flags`. The Tier 0 role list is at the top of the script.

### 03 - Apps and consents

The first version of the "where is my data going" map: which non-human identities are *authorised* to reach data, and how well they're governed.

**Collects:** tenant consent settings; app registrations with owners and one row per secret/certificate; service principals classified as this tenant, third party, managed identity or Microsoft; application permissions flagged DataAccess / PrivilegeEscalation; delegated grants (admin vs user consent); a per-app "data movers" summary ranked for review.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-CredentialWarningDays` | `30` | Credentials expiring within this window are flagged |
| `-LongLivedSecretDays` | `730` | Secrets with a longer lifetime are flagged |
| `-StaleDays` | `90` | Apps with no sign-in in this window are flagged |
| `-IncludeMicrosoftApps` | off | Include Microsoft first-party clients |
| `-SkipSignInActivity` | off | Skip the service-principal sign-in report (Graph beta) |

**Start with:** `app-risk-summary.csv`. `TriageScore` only orders the list for review.

### 04 - AD privileged and service accounts

Finds every account with admin rights on-prem, including rights gained through nested groups, and finds likely service accounts.

**Collects:** membership of every protected group with the full nesting path; one row per privileged account with hygiene flags (stale, password never expires, Kerberoastable, pre-auth disabled, delegation, nested-only); service-account candidates with the detection reasons; `adminCount=1` leftovers.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ServiceNamePatterns` | `svc*`, `sa-*`, `sa_*`, … | Name patterns that indicate a service account |
| `-AdditionalPrivilegedGroups` | none | Custom admin groups to expand |
| `-StaleDays` | `90` | Days without logon before flagging |
| `-PasswordAgeWarningDays` | `365` | Passwords older than this are flagged |

**Start with:** `summary.csv`, then `ad-privileged-accounts.csv`.

### 05 - AD group nesting

Builds the full group-in-group graph in memory and reports structure and hygiene for every group.

**Collects:** one row per group with member counts, depth below (`DepthDown`) and above (`DepthUp`), and flags (empty, no owner, mail-enabled security, deep or circular nesting, naming-convention miss); one row per circular loop.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-DeepNestingThreshold` | `3` | Groups nested at least this deep are flagged |
| `-NamingConventionRegex` | none | e.g. `'^(RB|APP)-'` |

**Start with:** `summary.csv`, then `ad-groups.csv` filtered on `Flags`.

### 06 - JML timing

Compares HR lifecycle dates with account state to show how well joiners and leavers are processed.

**Collects:** joiner lag (account created vs hire date); leaver lag (disabled vs termination date); terminated-but-enabled; logon or sign-in after termination; active HR records with no account; enabled accounts with no HR match; median, 90th percentile and maximum lags.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-HrCsvPath` | required | HR export ([template](examples/hr.example.csv)) |
| `-HrIdColumn`, `-HrStatusColumn`, `-HrHireDateColumn`, `-HrTermDateColumn` | `EmployeeId`, `EmploymentStatus`, `HireDate`, `TerminationDate` | Map the export's column names |
| `-HrDateFormat` | invariant parse | e.g. `'MM/dd/yyyy'` |
| `-TerminatedStatusValues` | `Terminated`, `Inactive` | Status values that mean "left" |
| `-AdMatchAttribute` | `employeeID` | AD attribute holding the HR id |
| `-LeaverSlaDays` | `1` | Allowed days between termination and disable |
| `-IncludeEntraSignIn` | off | Add Entra sign-in after termination |

**Start with:** `summary.csv`, then `jml-terminated-still-enabled.csv`.

### 07 - Role mining

Supports the move to RBAC (birthright → department roles → job-code roles). For each value of each grouping attribute, it measures how many people in that population hold each group.

**Collects:**
- **Attribute quality:** blank %, distinct values, and values spelled more than one way (`IT` vs `I.T.`, `Finance` vs `finance`). Rule-based roles only work on clean attributes, and this shows whether the data can carry them.
- **Populations:** the size of each department or job-code group.
- **Birthright candidates:** groups held by almost everyone (default 90%+).
- **Role candidates:** groups held by most of one population (default 80%+), with lift against the overall rate.
- **Outliers:** people missing a group their peers have, and people holding a group that is rare in their population and overall. These are questions for managers, not findings.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-GroupingAttributes` | `department`, `title` | Attributes that define populations; add the job-code attribute |
| `-MinPopulation` | `5` | Smaller populations are listed but not mined |
| `-RoleThreshold` | `0.8` | Share of a population that makes a group a role candidate |
| `-CommonThreshold` | `0.5` | Minimum share to appear in `role-candidates.csv` |
| `-BirthrightThreshold` | `0.9` | Share of all users that makes a group a birthright candidate |
| `-OutlierThreshold` | `0.1` | "Rare" for uncommon-access outliers |
| `-ExcludeNamePatterns` | service/admin patterns | Accounts left out of mining |
| `-ExcludeGroupRegex` | none | Groups left out, e.g. `'^(All Staff|Everyone)'` |
| `-ExpandNested` | off | Count access through nested groups too |
| `-NormalizeValues` | off | Treat `IT` and `it ` as one population once variants are confirmed cosmetic |
| `-IncludeDisabled`, `-IncludeDistributionGroups`, `-SkipOutliers` | off | |

**Start with:** `attribute-quality.csv` and `attribute-value-variants.csv` (fix the data first), then `birthright-candidates.csv` and `role-candidates.csv`.

### 08 - Extension attribute inventory

Before choosing an attribute to carry new data (for example the roles applied by the JML automation), find out which are already in use.

**Collects:** for AD users (and optionally groups), `extensionAttribute1-15` plus any listed attributes, with populated count and %, distinct values, maximum length, format hints (List, Date, Number, Email, LowCardinality, UniquePerObject) and top values; status `InUse`, `Rare`, `Unused` or `NotInSchema`. With `-IncludeEntra`: cloud-only users' `onPremisesExtensionAttributes`, directory (schema) extensions registered by apps, and optionally custom security attribute definitions.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AdditionalAttributes` | `employeeType`, `employeeNumber`, `division`, `departmentNumber`, `info` | Extra attributes to profile |
| `-IncludeCloudExtensionAttributes` | off | Add `msDS-cloudExtensionAttribute1-20` |
| `-IncludeGroups` | off | Profile groups as well as users |
| `-SampleValueCount` | `3` | Top values shown; `0` suppresses them if values could be personal data |
| `-IncludeEntra` | off | Add the Entra datasets |
| `-CountExtensionUsage` | off | Count users holding each directory extension |
| `-IncludeCustomSecurityAttributes` | off | Needs `CustomSecAttributeDefinition.Read.All` and Attribute Definition Reader |

**Start with:** `summary.csv` (lists unused attributes by name), then `ad-attribute-usage.csv`. *Unused* doesn't prove nothing reads an attribute: check Entra Connect sync rules, Exchange (extensionAttribute1-15 are Exchange custom attributes) and any app that reads AD.

### 09 - Mail forwarding and external sharing

The human side of "where is my data going" (script 03 covers apps).

**Collects:** accepted domains; mailboxes with forwarding set, flagged external; inbox rules that forward or redirect (flagged external) and rules that delete or bury mail in RSS Feeds / Deleted Items / Archive / Conversation History (`ForwardAndHide` is a common sign of a compromised mailbox); transport rules that redirect, copy or BCC; remote domains allowing auto-forward; outbound spam policy forwarding mode; SharePoint tenant sharing settings; optionally per-site sharing capability.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ExchangeOrganization` | none | e.g. `contoso.onmicrosoft.com`; required for app-only Exchange sign-in |
| `-MaxMailboxes` | `0` (all) | Limit the inbox-rule scan (one call per mailbox) |
| `-SkipInboxRules` | off | Skip inbox rules (fast pass) |
| `-SkipSharePointSettings` | off | Skip the Graph SharePoint settings |
| `-IncludeSiteSharing` | off | Read every site's sharing capability (needs `-SharePointAdminUrl`) |
| `-SharePointAdminUrl` | none | e.g. `https://contoso-admin.sharepoint.com` |
| `-IncludeOneDrive` | off | Include OneDrive sites in the site scan |

**Start with:** `summary.csv`, then `exo-inbox-rules.csv` filtered on `ForwardAndHide` and `ExternalForward`.

### 10 - Guest access

Guests are often the largest pool of stale access.

**Collects:** external collaboration settings (who can invite, guest permission level, default cross-tenant access, partner policy count); one row per guest with home domain, invitation state, last sign-in, group/role/app counts, sponsors and flags (`PendingInvitation`, `PendingOverNd`, `NeverSignedIn`, `NoSignInNd`, `Disabled`, `HoldsDirectoryRole`, `NoSponsor`); one row per home domain.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-StaleDays` | `90` | Days without sign-in before flagging |
| `-PendingDays` | `30` | Pending invitations older than this are flagged |
| `-SkipMemberships` | off | Fast pass: no per-guest group/app calls |
| `-IncludeSponsors` | off | Read each guest's sponsors |

**Start with:** `summary.csv`, then `guests.csv` filtered on enabled guests that are stale or never signed in.

### 11 - Azure RBAC

Entra roles control the tenant; Azure RBAC controls the resources.

**Collects:** visible management groups and subscriptions; every role assignment at management group, subscription, resource group and resource scope (de-duplicated, principal resolved via Graph); eligible PIM assignments where licensed; custom roles flagged when they contain `*` or authorization-write actions; classic administrators. Assignment flags: `DirectUserAssignment`, `GuestPrincipal`, `OrphanedPrincipal`, `PrivilegedAtBroadScope`, `ServicePrincipalPrivileged`, `CustomRoleRisky`.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SubscriptionId` | all visible | Limit to listed subscriptions |
| `-SkipManagementGroups` | off | Skip management-group scopes |
| `-SkipEligible` | off | Skip PIM eligibility |
| `-SkipPrincipalResolution` | off | Don't call Graph; principals show as IDs |

**Start with:** `summary.csv`, then `azure-role-assignments.csv` filtered on `OrphanedPrincipal` (safe clean-up) and `PrivilegedAtBroadScope`. Subscriptions you can't read are counted in the summary and logged; they are not silently skipped.

### 12 - Stale accounts

A user can look stale in AD while signing in to Microsoft 365 every day, or the reverse. This joins AD and Entra and uses the newest activity from either side.

**Collects:** one row per identity (Hybrid, ADOnly, CloudOnly) with enabled state on each side, AD last logon, Entra interactive / non-interactive / successful sign-in, newest activity, activity bucket (0-30 … 365+, Never) and flags (`NeverUsed`, `Stale`, `EnabledMismatch`, `CreatedButNeverUsed`, `PasswordNeverExpires`, `Guest`); optionally stale computer accounts.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AnchorAttribute` | `objectGUID` | Use `mS-DS-ConsistencyGuid` if Entra Connect anchors on it |
| `-StaleDays` | `90` | Threshold for `Stale` |
| `-NewAccountGraceDays` | `30` | New accounts aren't flagged as never used until this old |
| `-EnabledOnly` | off | Only identities enabled on at least one side |
| `-IncludeComputers` | off | Add stale AD computer accounts |

**Start with:** `summary.csv`; the "Stale in AD but active in Entra" line shows how many accounts an AD-only check would have wrongly flagged.

### 13 - Hybrid sync scope

Any provisioning design that writes to AD depends on knowing what reaches Entra.

**Collects:** tenant sync status (on/off, last sync, last password-hash sync, optional feature flags); per-OU coverage with inferred scope (`InScope`, `OutOfScope`, `Partial - investigate`); enabled AD users not in Entra; synced Entra users with no AD match (orphaned, or from another domain); cloud-only users that look like duplicates of AD users; provisioning errors; optionally the same for groups (matched on SID).

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AnchorAttribute` | `objectGUID` | As in script 12 |
| `-IncludeGroups` | off | Add group coverage and orphans |
| `-IncludeSyncFeatures` | off | Read sync feature flags (`OnPremDirectorySynchronization.Read.All`) |
| `-SyncStaleHours` | `24` | Warn if the last sync is older |

**Start with:** `summary.csv`, then `sync-ou-coverage-users.csv` rows marked Partial. Scope is inferred from results, not read from the Entra Connect configuration. Run once per domain in a multi-domain forest.

### 14 - IGA reconciliation

Shows where the IGA platform's view differs from AD. Run it before JML moves to a new platform, to document what the current IGA does and doesn't control. Inputs are CSV exports you supply; nothing connects to the IGA.

**Collects:**
- an input profile (rows, systems and status values seen) to confirm the column mapping
- AD accounts the IGA doesn't know, with service/admin patterns marked separately
- IGA accounts missing from AD
- status mismatches, where `IgaInactive_ADEnabled` is the highest risk

With an assignments export it also collects:
- governed groups, with counts of members in both, AD-only and IGA-only
- memberships granted outside the IGA
- IGA assignments not present in AD
- AD security groups the IGA never assigns

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AccountsCsv` | required | One row per account per system ([template](examples/iga-accounts.example.csv)) |
| `-AssignmentsCsv` | none | One row per account per group ([template](examples/iga-assignments.example.csv)) |
| `-SystemName` | `Active Directory` | Value identifying AD rows; wildcards allowed |
| `-Acct*Column`, `-Asg*Column` | see templates | Map the export's column names |
| `-ActiveStatusValues` / `-InactiveStatusValues` | `Active`, `Enabled` / `Disabled`, `Inactive`, `Terminated`, `Deleted`, `Expired`, `Removed`, `Revoked` | Status mapping |
| `-AdAccountKey` | `sAMAccountName` | Or `userPrincipalName` |
| `-AdGroupKey` | `Name` | Or `sAMAccountName`, `DistinguishedName` |
| `-ServiceNamePatterns` | service/admin patterns | Marked separately in the unmanaged list |
| `-GroupSearchBase` | whole domain | Limit the group scope |

**Start with:** `iga-input-profile.csv` (check the mapping), then `summary.csv` and `account-status-mismatch.csv`. Compares direct membership; access the IGA grants through nesting appears as "not in AD" for the parent group.

### 15 - Rule-managed access

A drift check for rule-based access once roles are in place. It assumes each role maps to groups (role definition file), the JML automation records applied roles on the user in an attribute, and rule-managed groups are identifiable.

**Collects:**
- **Role-definition check:** groups that don't exist, groups not tagged as rule-managed, tagged groups that no role uses, and roles in the rule map that aren't defined.
- **Per-user reconciliation:**
  - applied roles, and HR-expected roles if a rule map is supplied
  - `RolesToAdd` / `RolesToRemove`, which show a mover that wasn't processed
  - unknown role codes
  - `MissingGroups`: groups required by an applied role that the user isn't in
  - `ExtraRuleGroups`: rule-managed groups the user is in that no applied role justifies
- **Drift detail:** one row per difference.

Run it on a schedule after go-live and the output becomes ongoing evidence that rule-based access is working.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-RoleDefinitionCsv` | required | `RoleCode,GroupName` ([template](examples/role-definitions.example.csv)) |
| `-RuleMapCsv` | none | `Attribute,Value,RoleCode`; `*,*` for everyone ([template](examples/rule-map.example.csv)) |
| `-AppliedRolesAttribute` | `extensionAttribute10` | Attribute holding applied roles; pick one with script 08 |
| `-Separator` | `;` | Separator inside that attribute |
| `-RuleManagedGroupRegex` | none | Identify rule-managed groups by name, e.g. `'^RB-'` |
| `-GroupTagAttribute` / `-GroupTagValues` | none / `Birthright`, `Department`, `JobCode` | Or identify them by an attribute on the group |
| `-OnlyDrift` | off | Write only users with differences |
| `-IncludeDisabled`, `-ExcludeNamePatterns` | | |

If neither a regex nor a tag is given, the groups in the role definition file are treated as rule-managed.

**Start with:** `role-definition-check.csv` (fix any issues first), then `summary.csv` and `drift-detail.csv`.

### 16 - Device posture

Zero Trust device controls only work if devices are registered, managed and evaluated.

**Collects:**
- **Entra device objects:** join type (Entra joined, hybrid joined, registered), managed, compliant and last sign-in, with flags for stale, unmanaged and non-compliant devices.
- **Intune managed devices:** compliance state, last check-in, encryption, jailbreak status, and whether each has a matching Entra object.
- **Compliance policies:** each policy and its assignments, plus the tenant setting that decides whether a device with *no* policy counts as compliant.
- **Conditional Access policies that depend on devices:** those requiring a compliant or hybrid-joined device, using device filters, or targeting platforms.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-StaleDays` | `90` | Entra devices with no sign-in in this window are flagged |
| `-CheckInStaleDays` | `30` | Intune devices not checked in for this long are flagged |
| `-SkipIntune` | off | Entra devices and CA only |

**Start with:** `summary.csv`. The "devices with no policy treated as compliant" line matters: if it's True, an unassigned device passes a require-compliant-device control.

### 17 - AWS IAM posture

The AWS side of privileged and non-human identity sprawl.

**Collects, per account:**
- **Account summary:** root MFA, root access keys, password policy and SAML providers.
- **IAM users:** console access, MFA, groups and policies, and last activity.
- **Access keys:** age and last use, with key IDs truncated.
- **IAM roles:** trust principals, flagged when they are cross-account (with or without a condition), wildcard, SAML-federated or web-identity; plus admin policies and last use.
- **Access Analyzer:** active external-access findings.

**Collects from Identity Center:** permission sets (session length, managed and inline policies, admin flag), and every account assignment with the user or group resolved by name.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ProfileName` | default credential chain | AWS credential profile |
| `-Region` | `us-east-1` | Region for regional APIs (Access Analyzer, Identity Center) |
| `-AllOrganizationAccounts` | off | Read every account in the Organization |
| `-AccountIds` | none | Read specific extra accounts |
| `-AssumeRoleName` | none | Read-only role deployed in each account (needed for other accounts) |
| `-IncludeIdentityCenter` | off | Permission sets and assignments |
| `-IdentityCenterRegion` | `-Region` | Region where Identity Center lives |
| `-SkipAccessAnalyzer` | off | Skip Access Analyzer findings |
| `-KeyAgeDays` / `-StaleDays` | `90` / `90` | Key age and inactivity thresholds |

**Start with:** `summary.csv` (root MFA and root keys first), then `aws-iam-roles.csv` filtered on `CrossAccountNoCondition` and `WildcardPrincipal`. `Use-STSRole` is used only to get temporary credentials for the read-only role.

### 18 - AD delegation

Group membership (script 04) is only half of privileged access. Accounts and groups holding dangerous rights through **ACLs** are effectively admins too, and they're often forgotten.

**Collects:** explicit permissions on the domain root, AdminSDHolder, the Domain Controllers OU, every OU and the protected groups, held by **non-default** trustees. The rights reported are:
- full control, modify permissions, take ownership and write all properties
- reset password, write members, write SPN, write key credential (shadow credentials) and write RBCD
- all extended rights, DCSync and read LAPS password

Each row has a severity: Critical on Tier 0 objects or for DCSync. The script also lists objects with a non-default owner, and gives a per-trustee summary. GUIDs are resolved from this forest's schema, so forest-specific attributes like the LAPS password are named correctly.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SkipOUs` | off | Tier 0 targets only |
| `-AdditionalTargets` | none | Extra DNs to review |
| `-IncludeInherited` | off | Also report inherited ACEs (noisy) |
| `-IncludeLowSeverity` | off | Include create / delete child object rights |

**Start with:** `summary.csv`, then `ad-delegations.csv` sorted by severity. Expand group trustees with script 04 or 05 to see who actually holds the rights.

### 19 - DC authentication protocols

Shows what would break, and who is still exposed, before NTLM is restricted or RC4 is disabled.

**Collects** from each domain controller's Security log over a time window:
- **NTLM logons (4624):** split into NTLM V1 and V2, by account, workstation and IP.
- **NTLM credential validations (4776).**
- **Kerberos tickets with weak encryption:** TGTs (4768) and service tickets (4769) issued with RC4 or DES, by account, service and IP.
- **Per-DC read status:** including where each Security log actually starts.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-DomainControllers` | all DCs | Limit to listed DCs |
| `-Hours` | `24` | Window to read (1-720) |
| `-MaxEventsPerQuery` | `50000` | Safety cap per DC per query |
| `-SkipKerberos` / `-SkipNtlmValidation` | off | Skip parts (4776 is often high-volume) |

**Start with:** `dc-read-status.csv` (was every DC readable, and how much log did it hold?), then `ntlm-logons.csv`, where NTLM V1 rows are listed first. If auditing isn't enabled the counts are zero, so check the status file before concluding there's no usage. For longer history, query the SIEM.

### 20 - Governance coverage

Answers "what share of the things that should be certified actually are?"

**Collects:**
- **Access review definitions:** target, reviewers, recurrence, auto-apply setting and the latest instance.
- **Decision statistics** (optional): approved, denied and not reviewed counts, completion %, and how many decisions failed to apply.
- **Coverage list:** every enterprise app requiring assignment, role-assignable group, group containing guests and Tier 0 directory role, each marked Covered or NotCovered by a recurring review. Your own in-scope application list can be checked too.
- **Access packages:** approval, expiration and built-in review settings.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-IncludeDecisionStats` | off | Read decisions on each review's latest instance |
| `-SkipGuestGroups` | off | Skip finding groups that contain guests (one call per guest) |
| `-InScopeAppsCsv` | none | CSV with `AppName` and/or `AppId` columns: the certification scope list |

**Start with:** `summary.csv` (coverage % by type), then `review-coverage.csv` filtered on `Covered = False`.

### 21 - Identity risk

**Collects:**
- **Users currently at risk:** flagged when they hold a directory role or when their risk has been left open for 30+ days.
- **Risk detections:** over a lookback window, with an aggregate by detection type.
- **Risky service principals:** marked `EvidenceUnavailable` without Workload Identities Premium.
- **Conditional Access policies that act on user or sign-in risk.**

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-DetectionLookbackDays` | `30` | Days of detections (1-90) |
| `-IncludeRemediated` | off | Include remediated / dismissed users |
| `-SkipServicePrincipals` | off | Skip workload identity risk |

**Start with:** `summary.csv`, then `risky-users.csv`, where risky admins are listed first. Legacy Identity Protection risk policies (outside CA) aren't exposed by Graph; check the portal if CA shows none.

### 22 - PIM role settings

PIM only reduces risk if activation is hard enough. For every directory role this exports what activation requires:
- maximum duration
- MFA, justification and ticket number
- approval and the approvers
- authentication context

It also shows whether eligible or active assignments can be permanent, with assignment counts. Tier 0 roles are flagged when activation has no approval, has no MFA or authentication context, lasts longer than the threshold, or permanent assignment is allowed.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-MaxActivationHours` | `8` | Longer Tier 0 activation is flagged |
| `-OnlyAssignedRoles` | off | Skip roles nobody holds |

**Start with:** `pim-role-settings.csv`, with Tier 0 roles listed first. Covers directory roles only; PIM for Groups and Azure resource roles are configured per group or scope.

## Output and evidence

```
<OutputRoot>\
  07-RoleMining\
    20261020-140501Z\
      attribute-quality.csv      data files (one per dataset)
      role-candidates.csv
      ...
      summary.csv                headline metrics for the status report
      dataset-status.csv         one row per dataset: status, rows, SHA-256, note
      run-manifest.json          who / where / when / scopes / parameters / datasets
      run.log                    timestamped log of the run
```

- All timestamps are UTC, ISO 8601, independent of the run machine's regional settings.
- `run-manifest.json` records the Windows account and machine, the Graph account and app, the scopes in the token, the Azure / Exchange connection where used, the parameters, and every dataset with its row count and SHA-256.
- Each run gets a new folder, so reruns never overwrite earlier evidence. Compare `summary.csv` across runs to show change.
- Scripts that read an input file (06, 14, 15) record its SHA-256, so you can prove which export was used without storing it with the results.

## Dataset statuses

| Status | Meaning | What to do |
|--------|---------|------------|
| `Completed` | Data collected. Zero rows is still Completed. | Nothing |
| `Blocked` | Permission denied or the call failed | Fix access, rerun |
| `Deferred` | Skipped on purpose by a switch, or an optional input wasn't supplied | Rerun with the switch or input when ready |
| `EvidenceUnavailable` | The tenant can't produce it (e.g. licence not present) | Record as a finding |

## Read-only guarantee

1. **One Graph entry point.** All Graph traffic goes through `Invoke-GraphGet`, which calls `Invoke-MgGraphRequest -Method GET`.
2. **One Azure entry point.** All ARM traffic in script 11 goes through `Invoke-ArmGet`, which calls `Invoke-AzRestMethod -Method GET`.
3. **Read cmdlets only** for AD (`Get-AD*`), Exchange (`Get-EXO*`, `Get-InboxRule`, `Get-TransportRule`, …), SharePoint (`Get-SPOSite`), event logs (`Get-WinEvent`) and AWS (`Get-IAM*`, `Get-SSOADMN*`, `Get-ORG*`, …). In script 17, `Use-STSRole` only obtains temporary credentials for a read-only role; it's the one non-`Get` command on the checker's allowlist.
4. **Read scopes only** are requested at sign-in.
5. **Static proof.** [`tools/Test-ReadOnly.ps1`](tools/Test-ReadOnly.ps1) parses each script with the PowerShell AST, without running it, and fails on:
   - any state-changing verb (`New-`, `Set-`, `Remove-`, `Add-`, `Update-`, `Enable-`, `Disable-`, `Grant-`, `Revoke-`, …) outside a short allowlist of commands that only write the local evidence folder
   - any `Invoke-MgGraphRequest` or `Invoke-AzRestMethod` without `-Method GET`
   - `Invoke-RestMethod`, `Invoke-WebRequest`, `Invoke-Expression`, `Invoke-Command`, `Start-Process`

```powershell
.\tools\Test-ReadOnly.ps1                                         # all scripts
.\tools\Test-ReadOnly.ps1 -Path .\scripts\11-Get-AzureRbac.ps1    # one script
```

Exit code `0` means pass. Run it again after any edit.

## Handling the output

The CSVs contain identity data (names, UPNs, sign-in activity, group membership, mail forwarding targets), and scripts 06, 14 and 15 read HR or IGA exports. Treat every run folder as sensitive:

- Store output only in the approved evidence location, **never in this repository**. `.gitignore` excludes `output/` and all CSV, JSON and log files; only the placeholder templates in `examples/` are allowed.
- Follow the environment's retention rule and delete local copies once evidence is filed.
- Use `-SampleValueCount 0` with script 08 if attribute values could be personal data.
- Do not paste raw output into tools that aren't approved for that data.

## Locked-down environments

If USB and downloads are blocked, bring the scripts in by whatever route policy allows, in this order:

1. **The organization's own code repository**, with review. This also records what was run.
2. **Paste or retype** into an editor on the work machine. Each script is self-contained, with configuration at the top.

`Test-ReadOnly.ps1` gives the approver a quick way to confirm nothing writes anything. If module installs are blocked, Azure Cloud Shell includes the Graph, Exchange and Az modules.

## Using the results

A suggested order for a discovery pass, matched to the three common gaps and the move to rule-based access:

| Goal | Scripts |
|------|---------|
| MFA coverage | 01 |
| Privileged and service account sprawl | 02, 04, 11, 17, 18, 22 |
| "Where is my data going" | 03, 09, 10 |
| Stale and orphaned identities | 12, 13, 06, 10 |
| Devices and Conditional Access | 16, 01, 21 |
| AD attack paths and legacy protocols | 18, 19, 04 |
| AWS identity | 17 |
| Certification coverage and PIM hardening | 20, 22 |
| Current lifecycle and governance baseline | 06, 14 |
| Groups and RBAC design | 05, 07, 08 |
| After rule-based access goes live | 15 (scheduled), 06 and 12 (rerun) |

1. Run `Test-ReadOnly.ps1` and share the result with whoever approves the run.
2. Pilot each script yourself using the [pilot runbook](docs/pilot-runbook.md).
3. Collect each `summary.csv` into the status update, plus `dataset-status.csv` for anything `Blocked` or `EvidenceUnavailable`.
4. After remediation, rerun with the same parameters and compare summaries.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Module ... not found` | Module missing | Install it, or run from Azure Cloud Shell |
| Dataset `Blocked` with 403 / `Authorization_RequestDenied` | Role or scope missing | Compare `ScopesInToken` in `run-manifest.json` with [docs/permissions.md](docs/permissions.md) |
| Dataset `EvidenceUnavailable` mentioning a licence | Tenant lacks Entra ID P1/P2 | Record as a finding |
| Script 01 note says TRUNCATED | Hit `-MaxSignInRecords` | Shorter lookback or higher cap |
| Repeated `HTTP 429` warnings | Throttling | Handled with back-off; large tenants take longer |
| Script 06: `HR file has no column ...` | Column names differ | Map with `-HrIdColumn` and so on |
| Script 06: date values failed to parse | Date format not recognized | Set `-HrDateFormat` |
| Script 07: almost no populations meet the minimum | Attribute values inconsistent or too granular | Read `attribute-value-variants.csv`; try `-NormalizeValues` or a lower `-MinPopulation` |
| Script 08: `Bulk read failed ... retrying per attribute` | An attribute isn't in the schema | Informational; it shows as `NotInSchema` |
| Script 09: `exo-inbox-rules` slow | One call per mailbox | `-MaxMailboxes 500` for a sample, or `-SkipInboxRules` |
| Script 11: "Scopes that could not be read" above 0 | No Reader on some subscriptions | Request Reader at the root management group |
| Scripts 12 / 13: few AD users matched to Entra | Entra Connect anchors on a different attribute | `-AnchorAttribute 'mS-DS-ConsistencyGuid'` |
| Script 14: `No account rows match System` | `-SystemName` doesn't match the export | Check "Systems seen" in `iga-input-profile.csv` |
| Script 14: many `UnmappedIgaStatus` rows | Status values not in the lists | Extend `-ActiveStatusValues` / `-InactiveStatusValues` |
| Script 15: everyone shows drift | Applied-roles attribute not yet populated, or wrong attribute | Check `-AppliedRolesAttribute` with script 08 |
| Script 16: Intune datasets `Blocked` | No Intune read role / scope | Intune Read Only Operator, `DeviceManagementManagedDevices.Read.All` |
| Script 17: an account shows `Blocked: AccessDenied` | Read-only role missing or not trusted from the run account | Deploy the role (StackSet) and allow the run account to assume it |
| Script 17: no Access Analyzer findings | No external-access analyzer in that region | Create one (outside this script), or set `-Region` |
| Script 18: many `(unresolved)` trustees | Deleted accounts or groups still in ACLs | These are clean-up items; confirm the SID is gone |
| Script 19: all counts zero | Auditing not enabled, or log rolled over | Check `dc-read-status.csv` (`LogStartsUtc`) and audit policy; use the SIEM |
| Script 19: DC rows `Blocked` | Not in Event Log Readers, or RPC blocked | Request Event Log Readers on DCs; check firewall to DCs |
| Scripts 20-22: datasets `EvidenceUnavailable` | No Entra ID P2 / ID Governance | Record as a finding |
| Execution policy blocks a script | Local policy | `Unblock-File`, or follow the approved signing process |

## Design choices

- **One file per area, no shared module.** Each script can be reviewed, approved, transferred or retyped on its own. The helper block at the top of each script is intentionally identical across scripts of the same kind.
- **Minimal dependencies.** Only the modules listed under [Prerequisites](#prerequisites); no Graph SDK sub-modules, no Az.Resources.
- **Configuration at the top.** Every environment-specific value is a parameter with a placeholder default (`contoso.local`, `tenant-id-redacted`). Nothing environment-specific is stored in the repository.
- **Paging and throttling handled.** Graph and ARM requests follow every page and back off on `429` and `5xx`.
- **Case-sensitive where it matters.** Attribute values are counted exactly as stored, so `Finance` and `finance` appear as separate values instead of being silently merged.
- **Facts, not conclusions.** Flags and triage scores are sorting aids; scoring and recommendations belong in the analysis.

## Testing

Before release, every script was:

- parse-checked and linted with PSScriptAnalyzer (no errors or warnings outside documented exclusions)
- checked with `Test-ReadOnly.ps1`, including negative tests confirming it catches write cmdlets (AD, Exchange, Azure), non-GET Graph calls and non-GET ARM calls
- run end to end on PowerShell 7.4 against mocked Graph, AD (including ACLs), Intune, Exchange Online, SharePoint, Azure Resource Manager, AWS and domain controller event log responses using placeholder data, including paging, missing licences, permission failures, deleted principals, circular nesting, case variants, expired credentials, missing schema attributes, accounts that can't be assumed, unreadable DCs and every optional switch

Results were checked against the values the mock data should produce, not only for "no errors". This caught and fixed real defects before release (see [CHANGELOG.md](CHANGELOG.md)).

**The scripts have not yet been run against a live environment.** Use the [pilot runbook](docs/pilot-runbook.md) to verify each one before handing it to others.

## Version history

See [CHANGELOG.md](CHANGELOG.md).
