# Permissions

Everything here is read-only. Ask for the narrowest option that works and, where PIM is in use, make roles eligible rather than permanent.

## Summary by script

| Script | Entra role | Graph scopes | Other access | Modules |
|--------|-----------|--------------|--------------|---------|
| 01 MFA coverage | Global Reader | Policy.Read.All, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All | | Graph Auth |
| 02 Privileged access | Global Reader | RoleManagement.Read.Directory, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All | | Graph Auth |
| 03 Apps and consents | Global Reader | Application.Read.All, Directory.Read.All, Policy.Read.All, AuditLog.Read.All | | Graph Auth |
| 04 AD privileged / service | | | Domain read | RSAT AD |
| 05 AD group nesting | | | Domain read | RSAT AD |
| 06 JML timing | (Global Reader with `-IncludeEntraSignIn`) | (User.Read.All, AuditLog.Read.All) | Domain read; read of replication metadata | RSAT AD (+ Graph Auth) |
| 07 Role mining | | | Domain read | RSAT AD |
| 08 Extension attributes | (Global Reader with `-IncludeEntra`) | (Directory.Read.All, Application.Read.All; + CustomSecAttributeDefinition.Read.All) | Domain read; (Attribute Definition Reader for custom security attributes) | RSAT AD (+ Graph Auth) |
| 09 Mail and sharing | Global Reader | SharePointTenantSettings.Read.All | Exchange: Global Reader or View-Only Organization Management; (SharePoint Administrator or Global Reader for `-IncludeSiteSharing`) | ExchangeOnlineManagement, Graph Auth (+ SPO module) |
| 10 Guests | Global Reader | User.Read.All, Directory.Read.All, AuditLog.Read.All, Policy.Read.All | | Graph Auth |
| 11 Azure RBAC | Global Reader | Directory.Read.All | Azure **Reader** at root management group (or each subscription) | Az.Accounts, Graph Auth |
| 12 Stale accounts | Global Reader | User.Read.All, AuditLog.Read.All | Domain read | RSAT AD, Graph Auth |
| 13 Sync scope | Global Reader | User.Read.All, Group.Read.All, Organization.Read.All (+ OnPremDirectorySynchronization.Read.All) | Domain read | RSAT AD, Graph Auth |
| 14 IGA reconciliation | | | Domain read; IGA exports supplied by the IGA owner | RSAT AD |
| 15 Rule-managed access | | | Domain read; role files | RSAT AD |
| 16 Device posture | Global Reader (or Intune Read Only Operator + Global Reader) | Device.Read.All, Policy.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All | | Graph Auth |
| 17 AWS IAM posture | | | AWS SecurityAudit + ViewOnlyAccess in each account (read-only role); IAM Identity Center read | AWS.Tools.* |
| 18 AD delegation | | | Domain read (DACLs are readable by authenticated users on most objects) | RSAT AD |
| 19 DC auth protocols | | | **Event Log Readers** on domain controllers; RPC to DCs; audit policy enabled | RSAT AD, Windows |
| 20 Governance coverage | Global Reader | AccessReview.Read.All, EntitlementManagement.Read.All, Application.Read.All, Group.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory | | Graph Auth |
| 21 Identity risk | Security Reader or Global Reader | IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All, Policy.Read.All, RoleManagement.Read.Directory (+ IdentityRiskyServicePrincipal.Read.All) | | Graph Auth |
| 22 PIM role settings | Global Reader | RoleManagementPolicy.Read.Directory, RoleManagement.Read.Directory | | Graph Auth |
| 23 AD attribute population | | | Domain and schema read | RSAT AD |

Items in brackets apply only when the matching optional switch is used.

## Entra directory role (for the operator)

| Option | Covers | Notes |
|--------|--------|-------|
| **Global Reader** (preferred) | All Entra and Graph parts | Read across users, groups, apps, CA, roles, logs and tenant settings; also covers Exchange Online read |
| Security Reader + Reports Reader | Most of 01-03, 10 | Fallback if Global Reader is refused; some datasets may be `Blocked` |

## Graph scopes

Delegated sign-in (as yourself through Microsoft Graph PowerShell) needs an admin to consent to the read scopes once. App-only (certificate) needs the same names granted as **application** permissions on a dedicated read-only app registration.

All scopes used anywhere in the repository:

| Scope | Used by |
|-------|---------|
| `Directory.Read.All` | 01, 02, 03, 08, 10, 11 |
| `Device.Read.All` | 16 |
| `DeviceManagementManagedDevices.Read.All` | 16 |
| `DeviceManagementConfiguration.Read.All` | 16 |
| `AccessReview.Read.All` | 20 |
| `EntitlementManagement.Read.All` | 20 |
| `GroupMember.Read.All` | 20 |
| `IdentityRiskyUser.Read.All` | 21 |
| `IdentityRiskEvent.Read.All` | 21 |
| `IdentityRiskyServicePrincipal.Read.All` | 21 (optional; needs Workload Identities Premium) |
| `RoleManagementPolicy.Read.Directory` | 22 |
| `User.Read.All` | 06, 10, 12, 13 |
| `Group.Read.All` | 13, 20 |
| `Policy.Read.All` | 01, 03, 10, 16, 21 |
| `AuditLog.Read.All` | 01, 02, 03, 06, 10, 12 |
| `UserAuthenticationMethod.Read.All` | 01, 02 |
| `RoleManagement.Read.Directory` | 02, 20, 21, 22 |
| `Application.Read.All` | 03, 08, 20 |
| `Organization.Read.All` | 13 |
| `SharePointTenantSettings.Read.All` | 09 |
| `CustomSecAttributeDefinition.Read.All` | 08 (`-IncludeCustomSecurityAttributes` only) |
| `OnPremDirectorySynchronization.Read.All` | 13 (`-IncludeSyncFeatures` only) |

## Licence-dependent data

| Data | Needs | If missing |
|------|-------|-----------|
| Sign-in logs, `signInActivity`, registration details | Entra ID P1 | Dataset marked `EvidenceUnavailable` / `Blocked`, or activity columns left blank with a note |
| PIM eligible assignments (Entra roles and Azure resources) | Entra ID P2 / ID Governance | Scripts 02 and 11 continue; eligibility marked `EvidenceUnavailable` |
| Access reviews, entitlement management (20), PIM settings (22) | Entra ID P2 / ID Governance | Dataset marked `EvidenceUnavailable` / `Blocked` |
| Risky users and detections (21) | Entra ID P2 for full detail | Limited data on P1 |
| Risky service principals (21) | Workload Identities Premium | Dataset marked `EvidenceUnavailable` |
| Service-principal sign-in activity | Entra ID P1 (Graph beta report) | `LastSignInUtc` left blank |
| Custom security attributes | Entra ID P1 | Dataset marked `Blocked` |

## Active Directory

| Need | Detail |
|------|--------|
| Account | A standard domain user is normally enough to read users, groups, computers and `adminCount` |
| Module | RSAT `ActiveDirectory` |
| Host | An approved management host. Scripts 05, 07, 08, 12 and 13 read every user or group once, so run them off-peak in large domains |
| Replication metadata (06) | `Get-ADReplicationAttributeMetadata` is readable by authenticated users by default; use `-SkipDisableTimestamp` if restricted |
| Multi-domain forest | Run AD scripts once per domain with `-Server` pointing at that domain |

## Exchange Online (script 09)

| Need | Detail |
|------|--------|
| Role | Global Reader, or Exchange **View-Only Organization Management** |
| Module | `ExchangeOnlineManagement` v3 |
| App-only | Exchange.ManageAsApp application permission plus an Exchange role assigned to the app's service principal; run with `-AuthMode AppCertificate -ExchangeOrganization contoso.onmicrosoft.com -ClientId ... -CertificateThumbprint ...` |

## Azure (script 11)

| Need | Detail |
|------|--------|
| Role | **Reader** at the Tenant Root Group (management group), or on each subscription in scope. Reader includes `Microsoft.Authorization/*/read`, which covers role assignments and definitions |
| PIM for Azure resources | Readable with Reader where licensed |
| Module | `Az.Accounts` only |

## AWS (script 17)

| Need | Detail |
|------|--------|
| Run identity | An AWS principal in the management (or delegated admin) account, from a credential profile (`-ProfileName`) or the default chain, e.g. IAM Identity Center SSO |
| Member accounts | A read-only role with the same name in every account (`-AssumeRoleName`), typically deployed by CloudFormation StackSet, with **SecurityAudit** and **ViewOnlyAccess** attached and a trust that allows the run identity to assume it |
| Organizations | `organizations:ListAccounts` in the management / delegated admin account for `-AllOrganizationAccounts` |
| Identity Center | `sso:List*`, `sso:Describe*`, `sso:Get*` and `identitystore:Describe*` (included in SecurityAudit / ViewOnlyAccess in most cases) in the account that hosts Identity Center |
| Access Analyzer | An existing external-access analyzer (account or organization) in `-Region`; the script does not create one |
| Modules | `AWS.Tools.Common`, `AWS.Tools.SecurityToken`, `AWS.Tools.IdentityManagement`; plus `AWS.Tools.Organizations`, `AWS.Tools.SSOAdmin`, `AWS.Tools.IdentityStore`, `AWS.Tools.AccessAnalyzer` for optional parts |

## Domain controller event logs (script 19)

| Need | Detail |
|------|--------|
| Group | **Event Log Readers** (builtin) on the domain - membership lets the account read the Security log on DCs |
| Network | Remote event log (RPC / dynamic ports) from the run host to each DC |
| Audit policy | Audit Logon (4624), Audit Credential Validation (4776), Audit Kerberos Authentication Service (4768) and Kerberos Service Ticket Operations (4769) set to Success on DCs |
| Alternative | If logs are centralized, run the equivalent query in the SIEM instead; the script documents the event IDs and fields used |

## App registration for app-only mode (optional)

If the client prefers a dedicated identity over delegated access:

1. Create a single-tenant app registration, e.g. `App1-IAM-Discovery-ReadOnly`, with an owner.
2. Add only the read **application** permissions for the scripts you'll run (table above) and grant admin consent.
3. Upload a certificate (no client secret). Keep the private key in the user certificate store of the run host.
4. For script 11, assign the app's service principal **Reader** at the root management group. For script 09, add `Exchange.ManageAsApp` and an Exchange view-only role.
5. Run with `-AuthMode AppCertificate -TenantId ... -ClientId ... -CertificateThumbprint ...`.
6. Disable or delete the app when discovery ends. It is itself a privileged non-human identity, and script 03 will report it.
