# 20 - Governance coverage

**Script:** [`20-Get-GovernanceCoverage.ps1`](../../scripts/20-Get-GovernanceCoverage.ps1) · **Version:** 1.1.0 · **Source:** Entra ID Governance

> What share of apps, groups and privileged roles is actually covered by access reviews, what do access packages grant, and are joiner / mover / leaver workflows in place?

Answers "what share of the things that should be certified actually are?"

**Collects:**
- **Access review definitions:** target, which members are reviewed (all or guests only), reviewers and reviewer type, recurrence, auto-apply setting and the latest instance. Self-reviews and manager reviews without a fallback reviewer are flagged.
- **Decision statistics** (optional): approved, denied and not reviewed counts, completion %, and how many decisions failed to apply.
- **Coverage list:** every enterprise app requiring assignment, role-assignable group, group holding a directory role, group containing guests, and every directory role that has holders (active, eligible, via group or PIM for Groups; Tier 0 marked), each marked Covered or NotCovered by a recurring review. Your own in-scope application list can be checked too.
- **Access packages:** approval, expiration and built-in review settings, assignment counts, incompatible packages, and one row per resource role each package grants.
- **Lifecycle workflows:** category (joiner / mover / leaver), enabled and scheduled state, and tasks.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-IncludeDecisionStats` | off | Read decisions on each review's latest instance |
| `-SkipGuestGroups` | off | Skip finding groups that contain guests (one call per guest) |
| `-InScopeAppsCsv` | none | CSV with `AppName` and/or `AppId` columns: the certification scope list |
| `-SkipAccessPackageAssignments` | off | Do not count assignments per access package |
| `-SkipLifecycleWorkflows` | off | Do not read lifecycle workflows |

**Open first:** `summary.csv` (coverage % by type, Tier 0 coverage), then `review-coverage.csv` filtered on `Covered = False`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `access-review-definitions.csv` | Access review | `TargetType` (Application, DirectoryRole, Group, AllGroups, AllM365Groups, GroupsFiltered, AzureResource, AccessPackage), `TargetName`, `Recurrence`, `Reviewers`, `AutoApplyResults`, latest instance, `CoversMembers`, `ReviewerType`, `Flags` (SelfReview, ManagerNoFallback, GuestsOnly, FilteredGroupScope), `ScopeQuery`, `InstancesRead` |
| `access-review-latest-decisions.csv` | Review's latest instance | `Approved`, `Denied`, `NotReviewed`, `CompletionPct`, `ApplyFailed` |
| `review-coverage.csv` | Target that should be reviewed | `TargetType`, `WhyInScope`, `Covered`, `CoveredBy`, `CoversMembers` (All / GuestsOnly), `Tier0`, `CoverageNote` |
| `access-packages.csv` | Access package | `AnyApprovalRequired`, `AnyReviewConfigured`, `AnyNoExpiration`, `ResourceRoles`, `AssignmentsDelivered`, `AssignmentsTotal`, `IncompatiblePackages`, `DetailStatus` |
| `access-package-resources.csv` | Resource role granted by a package | `ResourceName`, `ResourceOriginSystem` (AadGroup, AadApplication, SharePointOnline), `Role`, `Scope` |
| `lifecycle-workflows.csv` | Lifecycle workflow | `Category`, `IsEnabled`, `IsSchedulingEnabled`, `TaskCount`, `Tasks` |

**Reading it:**
- `Covered` means a recurring, not-completed review targets the item and reviews **all** of its members. A guest-only review counts only for groups that are in scope because they contain guests; elsewhere the row shows `CoversMembers = GuestsOnly` and a note that member access is not certified.
- "All groups" reviews only count for the groups their filter matches: a review over all Microsoft 365 groups does not cover security groups (role-assignable groups are security groups). A review with any other filter is listed in `CoverageNote` as "may be covered" and needs a manual check.
- `SelfReview` means users attest their own access. `ManagerNoFallback` means users without a manager are not reviewed by anyone.
- Directory roles in scope are the roles that have at least one effective holder; `Tier0` marks the roles in the shared Tier 0 list and the groups holding them.
- Azure resource reviews are listed (`TargetType = AzureResource`) but not part of the coverage list; see [11 Azure RBAC](11-azure-rbac.md).
- If access reviews cannot be read, `review-coverage.csv` still lists the targets, with `Covered` blank.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | AccessReview.Read.All, EntitlementManagement.Read.All, Application.Read.All, Group.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory, Directory.Read.All, LifecycleWorkflows.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Number of access reviews in Identity Governance; one app you know is reviewed shows `Covered`; one access package's resources match its Resource roles page.

Usually tuned on first run: `-InScopeAppsCsv` once the certification scope list exists. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scripts 20-22: datasets `EvidenceUnavailable` | No Entra ID P2 / ID Governance | Record as a finding |
| `access-review-definitions` Partial | Some review instances not readable | See `InstancesRead`; check the run account's role |
| `review-coverage` Partial: role holders unreadable | RoleManagement.Read.Directory missing | Add the scope; until then only the Tier 0 roles are listed |
| `lifecycle-workflows` Blocked | LifecycleWorkflows.Read.All missing | Add the scope, or `-SkipLifecycleWorkflows` |
| `access-packages` `DetailStatus` shows unreadable | No catalog read access for that package | Global Reader or a catalog reader role |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 19 DC authentication protocols](19-dc-authentication-protocols.md) · [All scripts](README.md) · [21 Identity risk →](21-identity-risk.md)
