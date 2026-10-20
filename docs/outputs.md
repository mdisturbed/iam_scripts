# Output reference

Every run folder also contains `summary.csv` (headline metrics), `dataset-status.csv`, `run-manifest.json` and `run.log`. All timestamps are UTC, ISO 8601.

## 01-MfaCoverage

| File | One row per | Key columns |
|------|-------------|-------------|
| `ca-policies.csv` | CA policy | `State`, `RequiresMfa`, `BlocksLegacyAuth`, include/exclude scope resolved to names, `ClientAppTypes`, `SessionControls` |
| `ca-exclusions.csv` | Exclusion on a policy | `PolicyName`, `ExclusionType` (User/Group/Role/GuestOrExternal), `DisplayName` |
| `ca-excluded-group-members.csv` | Member of an excluded group (transitive) | `GroupName`, `ExcludedFromPolicies`, `MemberUPN`, `AccountEnabled` |
| `mfa-registration.csv` | User | `IsMfaRegistered`, `IsMfaCapable`, `MethodsRegistered`, `HasSmsOrVoice`, `HasPhoneMethodOnly`, `IsAdmin` |
| `signins-singlefactor-success.csv` | User + app + client | `IsLegacyAuth`, `SignInCount`, first/last seen, `CaStatuses` |

**Reading it:** registered is not the same as enforced. A user can be registered and still sign in with a password if no enabled policy requires MFA for that sign-in; the single-factor file shows where that actually happened.

## 02-PrivilegedAccess

| File | One row per | Key columns |
|------|-------------|-------------|
| `role-assignments-active.csv` | Active assignment | `RoleName`, `IsTier0Role`, `PrincipalType`, `AssignmentType`, `IsPermanent`, `MemberType` |
| `role-assignments-eligible.csv` | Eligible assignment | `IsPermanentlyEligible` |
| `role-group-members.csv` | Member of a role-holding group | `RolesGranted`, `MemberUPN` |
| `role-assignable-groups.csv` | Role-assignable group | `HoldsRoles`, `OwnerCount`, `SyncedFromOnPrem` |
| `privileged-users.csv` | Privileged user | `SyncedFromOnPrem`, `LastSignInUtc`, `IsMfaRegistered`, `HoldsTier0Role`, `Roles`, `Flags` |

Tier 0 roles are listed at the top of the script and can be extended.

## 03-AppsAndConsents

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

## 04-ADPrivilegedAndServiceAccounts

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-privileged-membership.csv` | Member found while expanding a protected group | `PrivilegedGroup`, `Depth`, `NestingPath` |
| `ad-privileged-accounts.csv` | Privileged account | `PrivilegedVia`, `Flags` (stale, never-expiring or old password, Kerberoastable, pre-auth disabled, delegation, nested-only) |
| `ad-service-account-candidates.csv` | Candidate service account | `DetectionReasons`, `IsPrivileged`, `Stale`, `PasswordAgeDays`, `HasManagedBy` |
| `ad-admincount-orphans.csv` | Account with adminCount=1 no longer in a protected group | hygiene columns |

**Reading it:** service accounts are candidates found by heuristics (SPN, never-expiring password, name pattern, description, gMSA). Confirm with owners before reporting a count as fact.

## 05-ADGroupNesting

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-groups.csv` | Group | `DirectMembers`, `DirectGroupMembers`, `DepthDown`, `DepthUp`, `CycleId`, `Flags` |
| `ad-circular-nesting.csv` | Nesting loop | `Groups` |

`DepthDown` counts levels of groups nested inside a group; `DepthUp` counts levels of groups it sits inside.

## 06-JmlTiming

| File | One row per | Key columns |
|------|-------------|-------------|
| `jml-matched.csv` | AD account matched to an HR record | `CreateLagDays`, `DisableLagDays`, `ADLastLogonUtc`, `EntraLastSignInUtc`, `Flags` |
| `jml-terminated-still-enabled.csv` | Terminated person with an enabled account | |
| `jml-activity-after-termination.csv` | Logon or sign-in more than a day after termination | |
| `jml-hr-active-no-account.csv` | Active HR record with no AD account | |
| `jml-ad-orphan-candidates.csv` | Enabled AD account with no HR match | `Reason` |

**Caveats:** disable time is approximated from the last change to `userAccountControl`, so it can be later than the real disable. `lastLogonTimestamp` replicates on a 9-14 day cycle, so AD logon-after-termination is indicative; the Entra sign-in check is more precise.
