# 03 - Apps and consents

**Script:** [`03-Get-AppsAndConsents.ps1`](../../scripts/03-Get-AppsAndConsents.ps1) · **Version:** 1.0.1 · **Source:** Entra

> Which apps can reach our data, and are they governed?

The first version of the "where is my data going" map: which non-human identities are *authorised* to reach data, and how well they're governed.

**Collects:** tenant consent settings; app registrations with owners and one row per secret/certificate; service principals classified as this tenant, third party, managed identity or Microsoft; application permissions flagged DataAccess / PrivilegeEscalation; delegated grants (admin vs user consent); a per-app "data movers" summary ranked for review.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-CredentialWarningDays` | `30` | Credentials expiring within this window are flagged |
| `-LongLivedSecretDays` | `730` | Secrets with a longer lifetime are flagged |
| `-StaleDays` | `90` | Apps with no sign-in in this window are flagged |
| `-IncludeMicrosoftApps` | off | Include Microsoft first-party clients |
| `-SkipSignInActivity` | off | Skip the service-principal sign-in report (Graph beta) |

**Open first:** `app-risk-summary.csv`. `TriageScore` only orders the list for review.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `tenant-consent-settings.csv` | Setting | User consent policy, app registration by users, admin-consent workflow |
| `app-registrations.csv` | App registration | `OwnerCount`, credential counts, `HasExpiredCredential`, `HasLongLivedSecret`, `NextExpiryDays` |
| `app-credentials.csv` | Secret or certificate | `EndUtc`, `DaysToExpiry`, `LifetimeDays`, `Status` |
| `service-principals.csv` | Service principal | `OwnerClass` (ThisTenant/ThirdParty/ManagedIdentity/Microsoft), `Publisher`, `LastSignInUtc` |
| `app-permissions-application.csv` | App role granted to a client | `Permission`, `RiskCategory` (DataAccess / PrivilegeEscalation) |
| `app-permissions-delegated.csv` | Delegated grant | `ConsentType` (Admin/User), `ConsentedBy`, `Scopes`, `HighRiskScopes` |
| `app-risk-summary.csv` | Non-Microsoft app holding permissions | high-risk permissions, owners, last sign-in, `Flags`, `TriageScore` |

**Reading it:** `app-risk-summary.csv` is the first draft of the "where is my data going" map. `TriageScore` only orders the list for review; it is not a risk rating. It shows what each app is *authorised* to reach, not what it actually moved.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | Application.Read.All, Directory.Read.All, Policy.Read.All, AuditLog.Read.All | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One known app registration's secret expiry date; one third-party app's granted permissions in Enterprise apps > Permissions.

See the [pilot runbook](../pilot-runbook.md).

---

[← 02 Entra privileged access](02-entra-privileged-access.md) · [All scripts](README.md) · [04 AD privileged and service accounts →](04-ad-privileged-and-service-accounts.md)
