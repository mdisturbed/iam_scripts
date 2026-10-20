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

## 07-RoleMining

| File | One row per | Key columns |
|------|-------------|-------------|
| `attribute-quality.csv` | Grouping attribute | `BlankPct`, `DistinctRawValues`, `DistinctNormalizedValues`, `ValuesWithSpellingVariants`, `PopulationsMeetingMin` |
| `attribute-value-variants.csv` | Normalised value | `VariantCount`, `Variants` (each raw spelling with its count) |
| `populations.csv` | Attribute value | `Users`, `MeetsMinPopulation` |
| `birthright-candidates.csv` | Group held by almost everyone | `Holders`, `PctOfAllUsers` |
| `role-candidates.csv` | Group held by at least `-CommonThreshold` of a population | `PctInPopulation`, `PctOfAllUsers`, `Lift`, `Classification` (BirthrightCandidate / RoleCandidate / Common) |
| `outliers.csv` | User + group | `Type` (MissingRoleCandidate / UncommonAccess) |

**Reading it:** fix the attribute data before designing roles. A `VariantCount` above 1 means the same department or job code is spelled more than one way, which splits populations and breaks rule-based assignment. `Lift` near 1 means a group is common everywhere, not specific to that population, so it's more likely birthright than a department role.

## 08-ExtensionAttributes

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-attribute-usage.csv` | Object type + attribute | `Populated`, `PopulatedPct`, `DistinctValues`, `MaxLength`, `FormatHints`, `SampleValues`, `Status` (InUse / Rare / Unused / NotInSchema) |
| `entra-cloudonly-extension-usage.csv` | extensionAttribute1-15 on cloud-only users | as above |
| `entra-directory-extensions.csv` | Schema extension registered by an app | `ExtensionName`, `DataType`, `TargetObjects`, `OwningApp`, `UsersWithValue` |
| `entra-custom-security-attributes.csv` | Custom security attribute definition | `AttributeSet`, `Name`, `Type`, `IsCollection` |

**Reading it:** *Unused* means no object holds a value today. Before claiming an attribute, confirm no Entra Connect sync rule, Exchange feature or application reads it.

## 09-MailAndSharing

| File | One row per | Key columns |
|------|-------------|-------------|
| `exo-accepted-domains.csv` | Accepted domain | used to decide internal vs external |
| `exo-mailbox-forwarding.csv` | Mailbox with forwarding set | `ForwardingSmtpAddress`, `ForwardingAddressResolved`, `DeliverToMailboxAndForward`, `IsExternal` |
| `exo-inbox-rules.csv` | Inbox rule that forwards, redirects, deletes or buries mail | `ExternalTargets`, `MoveToFolder`, `DeleteMessage`, `Flags` (ExternalForward / InternalForward / DeletesOrBuriesMail / ForwardAndHide) |
| `exo-transport-rules.csv` | Transport rule that redirects, copies or BCCs | `ExternalTargets`, `State`, `Mode` |
| `exo-remote-domains.csv` | Remote domain | `AutoForwardEnabled` |
| `exo-outbound-spam-policies.csv` | Outbound spam policy | `AutoForwardingMode` |
| `spo-tenant-sharing-settings.csv` | Tenant sharing setting | `Setting`, `Value` |
| `spo-site-sharing.csv` | Site | `SharingCapability`, `AnyoneLinksAllowed`, `ExternalSharingAllowed` |

**Reading it:** review `ForwardAndHide` rules first; forwarding mail externally while hiding replies is a classic sign of a compromised mailbox. External forwarding only works if both the outbound spam policy and the remote domain allow it, so read those two files together.

## 10-GuestAccess

| File | One row per | Key columns |
|------|-------------|-------------|
| `external-collaboration-settings.csv` | Setting | Who can invite, guest access level, cross-tenant defaults |
| `guests.csv` | Guest | `HomeDomain`, `InvitationState`, `LastSignInUtc`, `GroupCount`, `DirectoryRoles`, `AppAssignments`, `Sponsors`, `Flags` |
| `guests-by-domain.csv` | Home domain | `Guests`, `PendingInvitation`, `NeverSignedIn`, `Stale` |

## 11-AzureRbac

| File | One row per | Key columns |
|------|-------------|-------------|
| `azure-management-groups.csv` | Management group | |
| `azure-subscriptions.csv` | Subscription in scope | `State` |
| `azure-role-assignments.csv` | Role assignment | `Scope`, `ScopeLevel`, `RoleName`, `RoleType`, `IsPrivilegedRole`, `PrincipalType`, `PrincipalName`, `Flags` |
| `azure-eligible-assignments.csv` | PIM eligible assignment | `RoleName`, `PrincipalName`, `EndUtc` |
| `azure-custom-roles.csv` | Custom role | `Actions`, `Risky`, `AssignmentCount` |
| `azure-classic-administrators.csv` | Classic co-administrator | |

**Reading it:** `OrphanedPrincipal` rows point at deleted identities and are the safest clean-up. `PrivilegedAtBroadScope` rows are the highest-impact standing access. Check the summary's "Scopes that could not be read" before treating counts as complete.

## 12-StaleAccounts

| File | One row per | Key columns |
|------|-------------|-------------|
| `identity-activity.csv` | Identity (AD and/or Entra) | `Source` (Hybrid / ADOnly / CloudOnly), `ADEnabled`, `EntraEnabled`, `ADLastLogonUtc`, `EntraLast*Utc`, `NewestActivityUtc`, `NewestActivitySource`, `ActivityBucket`, `Flags` |
| `ad-computers.csv` | Computer account (`-IncludeComputers`) | `LastLogonUtc`, `PasswordLastSetUtc`, `Stale` |

**Reading it:** `NewestActivityUtc` is the newer of AD and Entra. `EnabledMismatch` means disabled on one side and enabled on the other, often a leaver disabled on-prem whose cloud object hasn't synced yet, or the reverse.

## 13-HybridSyncScope

| File | One row per | Key columns |
|------|-------------|-------------|
| `sync-tenant-status.csv` | Setting | last sync, last password-hash sync, feature flags |
| `sync-ou-coverage-users.csv` | OU holding users | `Users`, `SyncedUsers`, `SyncedPct`, `InferredScope` |
| `ad-users-not-in-entra.csv` | Enabled AD user with no Entra twin | `ParentOU`, `Note` |
| `entra-synced-without-ad-match.csv` | Synced Entra user with no AD match here | `Classification` (OtherDomain / OrphanedSyncedObject / NoMatchInThisDomain) |
| `cloud-only-possible-duplicates.csv` | Cloud-only user resembling an AD user | `MatchesADAccounts`, `MatchStrength` (Strong / NameOnly) |
| `user-provisioning-errors.csv` | Provisioning error | `Category`, `PropertyCausingError`, `Value` |
| `sync-ou-coverage-groups.csv` | OU holding groups (`-IncludeGroups`) | as for users |
| `entra-synced-groups-without-ad-match.csv` | Synced Entra group with no AD match here | `Classification` |

**Reading it:** scope is inferred from results. An OU at 100% is in scope, 0% is out of scope, and anything in between has an explanation to find: an attribute filter, sync errors, or objects created after the last sync.

## 14-IgaReconciliation

| File | One row per | Key columns |
|------|-------------|-------------|
| `iga-input-profile.csv` | Input fact | rows read, SHA-256, systems seen, status values and how each was mapped |
| `accounts-ad-not-in-iga.csv` | AD account the IGA doesn't know | `Enabled`, `Classification` (UnmanagedEnabled / UnmanagedDisabled / ServiceOrAdminPattern) |
| `accounts-iga-not-in-ad.csv` | IGA account with no AD account | `IgaStatus`, `IgaStatusClass` |
| `account-status-mismatch.csv` | Account whose status differs | `MismatchType` (IgaInactive_ADEnabled / IgaActive_ADDisabled / UnmappedIgaStatus) |
| `governed-groups.csv` | Group referenced by an IGA assignment | `IgaAssignments`, `ADUserMembers`, `InBoth`, `ADOnly`, `IgaOnly` |
| `memberships-outside-iga.csv` | AD membership with no IGA assignment | |
| `assignments-not-in-ad.csv` | IGA assignment not present in AD | `Finding` (NotProvisioned / AccountMissingInAD / GroupMissingInAD) |
| `ungoverned-groups.csv` | Security group with users that no IGA assignment references | `UserMembers` |

**Reading it:** check `iga-input-profile.csv` first. If a status value maps to `Unknown`, extend the status lists and rerun before trusting mismatches.

## 15-RuleManagedAccess

| File | One row per | Key columns |
|------|-------------|-------------|
| `role-definition-check.csv` | Role-group mapping, untagged or unused rule group, or undefined rule-map role | `Issue` (GroupNotFound / GroupNotTaggedRuleManaged / TaggedButNotInAnyRole / RoleInMapNotDefined) |
| `user-reconciliation.csv` | User | `AppliedRoles`, `ExpectedRoles`, `RolesToAdd`, `RolesToRemove`, `UnknownRoles`, `MissingGroups`, `ExtraRuleGroups`, `Issues`, `Status` |
| `drift-detail.csv` | Difference | `Type` (MissingGroup / ExtraRuleGroup / RoleToAdd / RoleToRemove) |

**Reading it:** `RolesToAdd` / `RolesToRemove` mean the user's HR attributes changed but the applied roles didn't, which is a mover the automation didn't process. `ExtraRuleGroups` means someone was added to a rule-managed group by hand, or kept it from an old role.
