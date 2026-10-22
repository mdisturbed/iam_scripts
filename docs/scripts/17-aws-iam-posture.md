# 17 - AWS IAM posture

**Script:** [`17-Get-AwsIamPosture.ps1`](../../scripts/17-Get-AwsIamPosture.ps1) · **Version:** 1.1.0 · **Source:** AWS

> Which AWS users, keys, roles, trusts and permission sets exist, who is admin-equivalent and through which policy, and which people sit behind each Identity Center assignment?

The AWS side of privileged and non-human identity sprawl.

**Collects, per account:**
- **Account summary:** root MFA, root access keys, password policy, SAML and OIDC providers, and (with `-UseExistingCredentialReport`) root password / key last use from the existing credential report.
- **IAM users:** console access, MFA, groups and policies, permissions boundary, signing certificates, service-specific credentials and last activity.
- **Access keys:** age and last use, with key IDs truncated.
- **Admin-equivalent principals:** every user and role that can act as an administrator, with the path (direct policy, inline policy, group policy) and the statement that makes it so: `*` on `*`, `iam:*`, privilege-escalation actions on `*` (for example `iam:PutUserPolicy`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`), `iam:PassRole` with a compute create action, `sts:AssumeRole` on `*`, or a broad Allow + NotAction. Policy documents come from one paged `GetAccountAuthorizationDetails` call per account.
- **Group memberships.**
- **IAM roles:** trust principals, flagged when they are cross-account (in or outside the organization, with or without a condition), wildcard, SAML-federated, web-identity, or OIDC with a wildcard or missing `sub` condition; plus admin policies, permissions boundary and last use.
- **Access Analyzer:** active external-access and unused-access findings in every region in `-Regions`.

**Collects once per run:** organization service and resource control policies with their targets and delegated administrators (management or delegated administrator account only); Identity Center permission sets (session length, managed, customer managed and inline policies, permissions boundary, admin flag), every account assignment with the user or group resolved by name, and group assignments expanded to the member users.

A failed read is never reported as "none": console access, password policy and role last use show `Unknown` when the read fails; only `NoSuchEntity` means not set.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ProfileName` | default credential chain | AWS credential profile |
| `-Region` | `us-east-1` | Region for regional APIs (Identity Center, and Access Analyzer when `-Regions` is blank) |
| `-Regions` | `-Region` | Regions to read Access Analyzer findings from |
| `-AllOrganizationAccounts` | off | Read every account in the Organization |
| `-AccountIds` | none | Read specific extra accounts |
| `-AssumeRoleName` | none | Read-only role deployed in each account (needed for other accounts) |
| `-SkipIdentityCenter` | off | Skip Identity Center. It runs by default when AWS.Tools.SSOAdmin and AWS.Tools.IdentityStore are installed; otherwise its datasets are `Deferred` |
| `-IncludeIdentityCenter` | off | Kept for compatibility; has no effect |
| `-IdentityCenterRegion` | `-Region` | Region where Identity Center lives |
| `-SkipAccessAnalyzer` | off | Skip Access Analyzer findings |
| `-SkipPolicyAnalysis` | off | Skip policy-document analysis (`aws-effective-admins`, `aws-group-memberships`) |
| `-UseExistingCredentialReport` | off | Read the existing credential report for root last use (never generates one) |
| `-KeyAgeDays` / `-StaleDays` | `90` / `90` | Key age and inactivity thresholds |

**Open first:** `summary.csv` (root MFA and root keys first), then `aws-effective-admins.csv`, then `aws-iam-roles.csv` filtered on `ExternalAccountTrust`, `CrossAccountNoCondition`, `WildcardPrincipal` and `OidcWildcardSubject`. `Use-STSRole` is used only to get temporary credentials for the read-only role.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `aws-accounts.csv` | Account | `ReadStatus`, `RootMfaEnabled`, `RootAccessKeysPresent`, `PasswordPolicy` (`None` = no policy, `Unknown (error ...)` = not readable), `RootPasswordLastUsedUtc`, `RootAccessKeyLastUsedUtc`, `CredentialReportUtc` |
| `aws-iam-users.csv` | IAM user | `ConsoleAccess` (True / False / Unknown), `MfaDevices`, `AttachedPolicies`, `InlinePolicies`, `DaysSinceActivity`, `Flags`, `PermissionsBoundary`, `SigningCertificates`, `ServiceSpecificCredentials`, `AdminEquivalent` |
| `aws-access-keys.csv` | Access key | `AgeDays`, `LastUsedUtc`, `LastUsedService`, `Flags` (key ID truncated) |
| `aws-effective-admins.csv` | Admin-equivalent path for a user or role | `AccountId`, `PrincipalType`, `PrincipalName`, `Via` (Direct policy X / Inline policy Y / Group G policy X), `Evidence` |
| `aws-group-memberships.csv` | User in a group | `GroupName`, `UserName`, `GroupAttachedPolicies`, `GroupInlinePolicies`, `GroupIsAdminEquivalent` |
| `aws-iam-roles.csv` | IAM role | `TrustedPrincipals`, `CrossAccountIds`, `AttachedPolicies`, `LastUsedUtc` (Unknown when unreadable), `Flags`, `PermissionsBoundary`, `ExternalAccountIds`, `OidcTrustIssues`, `AdminEquivalent` |
| `aws-saml-providers.csv` | SAML provider | `ValidUntilUtc` |
| `aws-oidc-providers.csv` | OIDC provider | `Url`, `ClientIds`, `RolesTrusting`, `RolesWithSubjectIssue` |
| `aws-access-analyzer-findings.csv` | Active external-access finding | `ResourceType`, `Resource`, `Principal`, `IsPublic`, `Region` |
| `aws-unused-access-findings.csv` | Active unused-access finding | `Region`, `FindingType`, `ResourceType`, `Resource` |
| `aws-org-policies.csv` | Service or resource control policy | `PolicyType`, `PolicyName`, `AwsManaged`, `TargetCount`, `Targets` |
| `aws-org-delegated-admins.csv` | Delegated administrator account | `AccountId`, `Name`, `DelegationEnabledUtc` |
| `aws-identity-center-permission-sets.csv` | Permission set | `SessionDuration`, `ManagedPolicies`, `InlineWildcard`, `IsAdminSet`, `CustomerManagedPolicies`, `PermissionsBoundary`, `InlineRisk` |
| `aws-identity-center-assignments.csv` | Assignment | `PermissionSet`, `AccountId`, `PrincipalType`, `PrincipalName`, `Flags` |
| `aws-identity-center-effective-users.csv` | User holding a permission set in an account | `PermissionSet`, `IsAdminSet`, `AccountId`, `UserName`, `Via` (Direct / Group G), `GroupName` |

**Reading it:** `aws-effective-admins.csv` is the list to review: each row is one path to admin-equivalent access, so a user can appear more than once. A permissions boundary is shown in `Evidence` because it may cap what the policy grants; check it before downgrading the finding. Service-linked roles are left out. `AdminAccess` on users and roles means AdministratorAccess, IAMFullAccess or PowerUserAccess is attached, or the policy analysis found an admin-equivalent path.

`CrossAccountNoCondition` trusts another account without an ExternalId or source condition; `ExternalAccountTrust` means that account is outside the AWS Organization (classification needs the Organizations account list). `OidcWildcardSubject` / `OidcNoSubjectCondition` mean any repository or workload of that identity provider can assume the role.

A dataset marked `Partial` had at least one account, region or group it could not read; the note says which. In the Access Analyzer files, an account / region with no analyzer has no evidence, which is not the same as no findings.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | AWS SecurityAudit + ViewOnlyAccess in each account (read-only role), which include `iam:GetAccountAuthorizationDetails`, `iam:ListOpenIDConnectProviders`, `iam:ListSigningCertificates`, `iam:ListServiceSpecificCredentials` and `access-analyzer:ListFindings`; `iam:GetCredentialReport` for `-UseExistingCredentialReport`; IAM Identity Center and identity store read (`identitystore:ListGroupMemberships`); Organizations read (`organizations:ListPolicies`, `ListTargetsForPolicy`, `ListDelegatedAdministrators`) in the management account | AWS.Tools.* |

Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Root MFA status in one account's IAM dashboard; one known cross-account role's trust policy.

Usually tuned on first run: `-Region`, `-IdentityCenterRegion`, `-AssumeRoleName`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 17: an account shows `Blocked: AccessDenied` | Read-only role missing or not trusted from the run account | Deploy the role (StackSet) and allow the run account to assume it |
| Script 17: no Access Analyzer findings | No external-access analyzer in that region | Create one (outside this script), or set `-Regions`; the dataset is `Partial` and the note counts the account / region pairs without an analyzer |
| `aws-effective-admins` is `Partial` | `iam:GetAccountAuthorizationDetails` denied in some accounts | Add it to the read-only role (it is in SecurityAudit) |
| `aws-org-policies` is `EvidenceUnavailable` | Run account is not the management or a delegated administrator account | Run from the management account, or accept the gap |
| Identity Center datasets `Deferred` | AWS.Tools.SSOAdmin / AWS.Tools.IdentityStore not installed | Install them, or run with `-SkipIdentityCenter` |
| `CredentialReportUtc` shows `Unavailable` | No current credential report exists | Generate one in the IAM console when policy allows; this script only reads it |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 16 Device posture](16-device-posture.md) · [All scripts](README.md) · [18 AD delegation →](18-ad-delegation.md)
