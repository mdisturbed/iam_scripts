# Getting started

Everything needed before the first run: modules, access, sign-in, the parameters every script shares, and getting the scripts onto a locked-down machine.

- [Prerequisites](#prerequisites)
- [Authentication](#authentication)
- [Common parameters](#common-parameters)
- [Run everything](#run-everything)
- [Locked-down environments](#locked-down-environments)

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

Scope-by-scope detail is in [permissions.md](permissions.md). Missing access doesn't crash a script; the affected dataset is marked `Blocked` or `EvidenceUnavailable`.

## Authentication

Every script that uses Graph, Exchange or Azure supports two modes through `-AuthMode`:

| Mode | When to use | Parameters |
|------|-------------|------------|
| `Delegated` (default) | You sign in interactively; results are limited to what your role can read | none |
| `AppCertificate` | A dedicated read-only app registration with a certificate; suits repeatable runs | `-TenantId`, `-ClientId`, `-CertificateThumbprint` (09 also needs `-ExchangeOrganization contoso.onmicrosoft.com`) |

Each Graph script requests only the read scopes it needs and logs a warning if the token is missing any of them, or if it carries write scopes from an earlier consent. The scripts still only send `GET`. App-only setup is in [permissions.md](permissions.md#app-registration-for-app-only-mode-optional).

## Common parameters

| Parameter | Scripts | Default | Purpose |
|-----------|---------|---------|---------|
| `-OutputRoot` | All | `scripts\output` | Where run folders are written. Point this at the approved evidence location. |
| `-Server` | AD scripts | session default DC | Domain controller or domain to query, e.g. `dc01.contoso.local` |
| `-SearchBase` | Most AD scripts | whole domain | Limit to an OU, e.g. `OU=People,DC=contoso,DC=local` |
| `-AuthMode`, `-TenantId`, `-ClientId`, `-CertificateThumbprint` | Graph / Exchange / Azure scripts | Delegated | See [Authentication](getting-started.md#authentication) |

## Run everything

Every script with typical parameters. Point `-OutputRoot` at the approved evidence location.

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

## Locked-down environments

If USB and downloads are blocked, bring the scripts in by whatever route policy allows, in this order:

1. **The organization's own code repository**, with review. This also records what was run.
2. **Paste or retype** into an editor on the work machine. Each script is self-contained, with configuration at the top.

`Test-ReadOnly.ps1` gives the approver a quick way to confirm nothing writes anything. If module installs are blocked, Azure Cloud Shell includes the Graph, Exchange and Az modules.

[← Back to README](../README.md)
