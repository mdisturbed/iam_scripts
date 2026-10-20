# 17 - AWS IAM posture

**Script:** [`17-Get-AwsIamPosture.ps1`](../../scripts/17-Get-AwsIamPosture.ps1) · **Version:** 1.0.0 · **Source:** AWS

> Which AWS users, keys, roles, trusts and permission sets exist, and which are risky?

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

**Open first:** `summary.csv` (root MFA and root keys first), then `aws-iam-roles.csv` filtered on `CrossAccountNoCondition` and `WildcardPrincipal`. `Use-STSRole` is used only to get temporary credentials for the read-only role.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `aws-accounts.csv` | Account | `ReadStatus`, `RootMfaEnabled`, `RootAccessKeysPresent`, `PasswordPolicy` |
| `aws-iam-users.csv` | IAM user | `ConsoleAccess`, `MfaDevices`, `AttachedPolicies`, `InlinePolicies`, `DaysSinceActivity`, `Flags` |
| `aws-access-keys.csv` | Access key | `AgeDays`, `LastUsedUtc`, `LastUsedService`, `Flags` (key ID truncated) |
| `aws-iam-roles.csv` | IAM role | `TrustedPrincipals`, `CrossAccountIds`, `AttachedPolicies`, `LastUsedUtc`, `Flags` |
| `aws-saml-providers.csv` | SAML provider | `ValidUntilUtc` |
| `aws-access-analyzer-findings.csv` | Active external-access finding | `ResourceType`, `Resource`, `Principal`, `IsPublic` |
| `aws-identity-center-permission-sets.csv` | Permission set | `SessionDuration`, `ManagedPolicies`, `InlineWildcard`, `IsAdminSet` |
| `aws-identity-center-assignments.csv` | Assignment | `PermissionSet`, `AccountId`, `PrincipalType`, `PrincipalName`, `Flags` |

**Reading it:** `AdminAccess` means AdministratorAccess, IAMFullAccess or PowerUserAccess is attached directly or through a group. `CrossAccountNoCondition` trusts another account without an ExternalId or source condition.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | AWS SecurityAudit + ViewOnlyAccess in each account (read-only role); IAM Identity Center read | AWS.Tools.* |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Root MFA status in one account's IAM dashboard; one known cross-account role's trust policy.

Usually tuned on first run: `-Region`, `-IdentityCenterRegion`, `-AssumeRoleName`. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 17: an account shows `Blocked: AccessDenied` | Read-only role missing or not trusted from the run account | Deploy the role (StackSet) and allow the run account to assume it |
| Script 17: no Access Analyzer findings | No external-access analyzer in that region | Create one (outside this script), or set `-Region` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 16 Device posture](16-device-posture.md) · [All scripts](README.md) · [18 AD delegation →](18-ad-delegation.md)
