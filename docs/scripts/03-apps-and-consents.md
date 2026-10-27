# 03 - Apps and consents

**Script:** [`03-Get-AppsAndConsents.ps1`](../../scripts/03-Get-AppsAndConsents.ps1) · **Version:** 1.1.1 · **Source:** Entra

> Which apps can reach our data, who owns and can use them, and are they governed?

The first version of the "where is my data going" map: which non-human identities are *authorised* to reach data, which of them hold directory roles or Tier 0-equivalent permissions, and how well they're governed.

**Collects:**
- **Tenant consent settings:** user consent policy (legacy, Microsoft-recommended, low-risk or custom), app registration by users, admin-consent workflow.
- **App registrations:** owners by name with guest / disabled owners marked (all owners, not only the first 20), one row per secret or certificate, federated identity credentials, and configuration risks (http or wildcard redirect URIs, implicit grant, fallback public client).
- **App management policies:** the tenant default and custom policies that restrict secrets and certificates.
- **Service principals:** classified as this tenant, third party, managed identity or Microsoft, plus one row per secret or certificate held directly on a service principal. Credentials are read for *every* service principal, including Microsoft first-party ones: a credential added to a first-party or multi-tenant service principal is a known persistence technique.
- **Permissions:** application permissions flagged DataAccess / PrivilegeEscalation, with Tier 0-equivalent permissions marked; delegated grants (admin vs user consent).
- **Assignments:** for every enterprise app that requires assignment, how many users, groups and service principals are assigned, with group names.
- **Directory roles held by service principals:** active, eligible, via a role-holding group or PIM for Groups, joined into the per-app summary.
- **Per-app "data movers" summary** ranked for review.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-CredentialWarningDays` | `30` | Credentials expiring within this window are flagged |
| `-LongLivedSecretDays` | `730` | Secrets with a longer lifetime are flagged |
| `-StaleDays` | `90` | Apps with no sign-in in this window are flagged |
| `-IncludeMicrosoftApps` | off | Include Microsoft first-party clients in permissions, owners and assignments (their credentials are always read) |
| `-SkipSignInActivity` | off | Skip the service-principal sign-in report (Graph beta) |
| `-MaxAssignmentsPerApp` | `5000` | Cap on assignments read per app; the app's row is marked `Truncated` if reached |
| `-SkipAppAssignments` | off | Do not read who is assigned to each app |
| `-SkipPrivilegeJoin` | off | Do not read directory role holders; `HoldsDirectoryRole` is left blank |

**Open first:** `app-risk-summary.csv`, then `service-principal-credentials.csv` filtered on `Severity = High`. `TriageScore` only orders the list for review.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `tenant-consent-settings.csv` | Setting | User consent policy, app registration by users, admin-consent workflow |
| `app-registrations.csv` | App registration | `OwnerCount`, `Owners` (with `[Guest]` / `[Disabled]`), credential counts, `HasExpiredCredential`, `HasLongLivedSecret`, `NextExpiryDays`, `OwnerGuestCount`, `OwnerDisabledCount`, `OwnerReadStatus`, `FederatedCredentials`, `FederatedCredentialFlags`, `ConfigRisks` |
| `app-credentials.csv` | Secret or certificate on an app registration | `EndUtc`, `DaysToExpiry`, `LifetimeDays`, `Status` |
| `federated-credentials.csv` | Federated identity credential | `Issuer`, `Subject`, `Audiences`, `Flags` (SubjectWildcard, BroadGitHubSubject, GitHubPullRequestSubject, NoSubject) |
| `app-config-risks.csv` | Risky app setting | `Setting`, `Value`, `Risk` (HttpRedirectNonLocalhost, WildcardRedirect, ImplicitAccessToken, ImplicitIdToken, FallbackPublicClient) |
| `app-management-policies.csv` | Restriction in the tenant default or a custom policy | `PolicyType`, `IsEnabled`, `Target`, `RestrictionType`, `State`, `MaxLifetime`, `AppliesTo` |
| `service-principals.csv` | Service principal | `OwnerClass` (ThisTenant/ThirdParty/ManagedIdentity/Microsoft), `Publisher`, `LastSignInUtc`, `SpCredentialCount`, `SpCredentialFlags` |
| `service-principal-credentials.csv` | Secret or certificate on a service principal (all, incl. Microsoft) | `OwnerClass`, `IsMicrosoft`, `IsMultiTenant`, `CredentialType`, `Usage`, `EndUtc`, `Expired`, `DaysToExpiry`, `Flag`, `Severity` |
| `app-permissions-application.csv` | App role granted to a client | `Permission`, `RiskCategory` (DataAccess / PrivilegeEscalation), `Tier0Equivalent` |
| `app-permissions-delegated.csv` | Delegated grant | `ConsentType` (Admin/User), `ConsentedBy`, `Scopes`, `HighRiskScopes`, `Tier0EquivalentScopes` |
| `app-assignments.csv` | App that requires assignment | `Users`, `Groups`, `ServicePrincipals`, `Total`, `GroupNames`, `Status` |
| `app-risk-summary.csv` | App holding permissions, a directory role or a high-severity credential | high-risk permissions, owners, last sign-in, `Flags`, `TriageScore`, `HoldsDirectoryRole`, `DirectoryRoles`, `HoldsTier0Role`, `RolePaths`, `Tier0EquivalentPermissions`, `Owners`, `SpCredentialFlags` |

**Reading it:**
- `app-risk-summary.csv` is the first draft of the "where is my data going" map. `TriageScore` only orders the list for review; it is not a risk rating. It shows what each app is *authorised* to reach, not what it actually moved.
- **Tier 0-equivalent** permissions let the app make itself or anyone Global Administrator in one step: `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All` and the PIM ReadWrite permissions. Treat these apps as Tier 0.
- **Service principal credentials:** `CredentialOnFirstPartySp` (High) is a secret or certificate on a Microsoft service principal - there is no normal reason for one. `CredentialOnMultiTenantSp` is a credential added in this tenant to a third-party app. `SamlSigningCertificate` and `ManagedIdentityCredential` are expected.
- **Owners:** `OwnerIsGuest` and `OwnerDisabled` in `Flags` mean someone outside the organisation, or a leaver's account, controls the app. `OwnerUnresolved` means the owners could not be read; it is not the same as `NoOwner`.
- **Federated credentials:** `BroadGitHubSubject` (for example `repo:org/*`) lets any repository or branch matching the pattern sign in as the app.
- **Assignments** count direct assignments; groups are not expanded here.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | Application.Read.All, Directory.Read.All, Policy.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup | - | Graph Auth |

Eligible role assignments and PIM for Groups need Entra ID P2; without it those role paths are marked `EvidenceUnavailable` in the `app-risk-summary` note and the active assignments are still used. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One known app registration's secret expiry date; one third-party app's granted permissions in Enterprise apps > Permissions; one app with assignment required shows the same user and group counts as Enterprise apps > Users and groups.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `federated-credentials` or `app-assignments` Partial | Some apps could not be read (403) | Check the run account's role; the unreadable apps are marked in the rows |
| `app-risk-summary` Partial, `HoldsDirectoryRole` blank | Role assignments not readable | Add RoleManagement.Read.Directory, or run as Global Reader |
| `app-management-policies` Blocked | Policy.Read.All missing | Add the scope |
| An app row says `Truncated at 5000` | More assignments than `-MaxAssignmentsPerApp` | Raise the cap |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 02 Entra privileged access](02-entra-privileged-access.md) · [All scripts](README.md) · [04 AD privileged and service accounts →](04-ad-privileged-and-service-accounts.md)
