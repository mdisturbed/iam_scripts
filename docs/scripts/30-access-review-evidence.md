# 30 - Access review evidence

**Script:** [`30-Get-AccessReviewEvidence.ps1`](../../scripts/30-Get-AccessReviewEvidence.ps1) · **Version:** 1.0.0 · **Source:** Entra ID Governance

> For each access review that ran, who reviewed what, what did they decide and why, and were the removals actually applied?

The access-review evidence package. [20 Governance coverage](20-governance-coverage.md) answers "is it reviewed at all?": which apps, groups and roles have a recurring review, plus decision counts for each review's latest instance. This script answers "what happened in the reviews that ran?": one row per decision, for every instance in the window, with the reviewer, the reason and the apply result, and a list of the decisions that need follow-up. Use 20 for coverage KPIs and this one as audit evidence.

**Collects:** access review definitions (optionally filtered by ID or name) and their instances that ended in the window. For each instance: the stages of a multi-stage review and the decisions made in each stage; the final decisions (paged in full) with decision, recommendation, justification, reviewer, review time, who applied it, when, and the apply result; and the reviewers who were actually contacted. Each principal is joined to the effective privileged set (any directory role path: active, eligible, via group or PIM for Groups) to mark `IsPrivileged` and `IsTier0`. Personal data is kept to what evidence needs: names and UPNs of principals and reviewers. No IP addresses.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SinceDays` | `180` | Instances whose end date (or start date, when there is none) falls within this many days |
| `-DefinitionIds` | all | Only these access review definition IDs |
| `-DefinitionNameLike` | all | Only definitions whose name matches any of these wildcards, for example `'*Group1*'` (case-insensitive) |
| `-IncludeInProgress` | off | Also include running instances (InProgress, Starting, Completing, AutoReviewing, AutoReviewed, Applying), flagged `InProgress`. By default only `Completed` and `Applied` instances are included |
| `-SkipPrivilegeJoin` | off | Do not read directory role holders; `IsPrivileged` / `IsTier0` are blank and `PrivilegedApprovedWithoutReview` is not evaluated |

**Open first:** `summary.csv` (instances, % reviewed, denies applied / not applied, exceptions by type), then `review-exceptions.csv` filtered on `ExceptionType` = `DenyNotApplied` and `PrivilegedApprovedWithoutReview`.

Common parameters (`-OutputRoot`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `review-instances.csv` | Review instance in the window | `DefinitionId`, `DefinitionName`, `ScopeSummary` (target type and name, "(guests only)" when guest-scoped), `ReviewerType` (per stage for multi-stage), `InstanceId`, `Status`, `StartUtc`, `EndUtc`, `Stages`, `Decisions`, `Approve`, `Deny`, `NotReviewed`, `DontKnow`, `Reviewed%`, `DeniesApplied`, `DeniesNotApplied`, `AutoApplyEnabled`, `DefaultDecision`, `JustificationRequired`, `RecommendationsEnabled`, `ContactedReviewers`, `Flags`, `EvidenceStatus` (Completed / Partial / Blocked), `EvidenceNote`, `ContactedReviewerUpns` |
| `review-decisions.csv` | Decision (per stage, and the final outcome) | `DefinitionName`, `InstanceId`, `Stage`, `PrincipalType`, `PrincipalName`, `PrincipalUpn`, `ResourceType`, `ResourceName`, `Decision`, `Recommendation`, `Justification` (max 500 characters), `ReviewedBy`, `ReviewedByUpn`, `ReviewedUtc`, `AppliedBy`, `AppliedUtc`, `ApplyResult`, `IsPrivileged`, `IsTier0`, `Flags`, `ApplyDescription`, `DefinitionId`, `DecisionId`, `PrincipalId`, `ReviewedById` |
| `review-exceptions.csv` | Decision or instance needing follow-up | `ExceptionType`, `DefinitionName`, `InstanceId`, `InstanceStatus`, `Stage`, `PrincipalType`, `PrincipalName`, `PrincipalUpn`, `ResourceName`, `Decision`, `Recommendation`, `ReviewedBy`, `ReviewedByUpn`, `ReviewedUtc`, `ApplyResult`, `IsPrivileged`, `IsTier0`, `Detail`, `InstanceEndUtc`, `DefinitionId`, `DecisionId` |

Exception types:

| ExceptionType | Raised when |
|---------------|-------------|
| `NotReviewed` | Final decision is `NotReviewed` |
| `DenyNotApplied` | Instance is Completed or Applied, final decision is `Deny`, and `ApplyResult` is not `AppliedSuccessfully` / `AppliedSuccessfullyButObjectNotFound` |
| `SelfReview` | The reviewer's ID is the principal's ID |
| `ApprovedWithoutJustification` | The definition requires justification on approval and an approval has none |
| `DecidedAgainstRecommendation` | Reviewer chose `Approve` or `Deny` and the recommendation was the opposite. `Detail` says whether recommendations were shown |
| `PrivilegedApprovedWithoutReview` | A privileged principal was `NotReviewed` and kept access: default decision `Approve` or `None`, or `Recommendation` when the recommendation was not `Deny` |
| `InstanceNoReviewersContacted` | The instance's contacted reviewers list is empty |
| `InstanceOverdue` | Instance is still running after its end date. Raised even without `-IncludeInProgress`; the summary says how many are missing from `review-instances.csv` |

Flags on instances: `InProgress`, `InstanceOverdue`, `ManualApply` (auto-apply off), `DeniesNotApplied`, `InstanceNoReviewersContacted`, `DecisionsUnreadable`, `StagesUnreadable`, `StageDecisionsUnreadable`, `ContactedReviewersUnreadable`, `InstancesUnreadable`. Flags on decisions: the exception types above, plus `InProgress` and `AppliedButObjectNotFound`.

**Reading it:**
- `Stage` is the stage number for a decision made in a stage of a multi-stage review, `Final` for the instance's outcome, and blank for a single-stage review. Counts and `Reviewed%` use the final decisions only, so no decision is counted twice. Reviewer checks (self-review, justification, against recommendation) use the stage decisions when they exist, because that is where each reviewer acted; outcome checks (not reviewed, deny not applied) use the final decision.
- `DenyNotApplied` is the removal that did not happen. With auto-apply off (`ManualApply`), an admin had to apply the results; `ApplyResult = New` means nobody did. `AppliedWithUnknownFailure` and `ApplyNotSupported` need a manual removal and a ticket.
- `AppliedSuccessfullyButObjectNotFound` counts as applied: the principal or the access was already gone.
- A `NotReviewed` decision with `DefaultDecision = Approve` or `None` means the access stayed without anyone looking at it. For a privileged principal that is `PrivilegedApprovedWithoutReview`; Tier 0 is noted in `Detail`.
- `DecidedAgainstRecommendation` is not wrong in itself: the recommendation only reflects sign-in activity. It is the list to sample for reviewer reasoning.
- The instances list only supports filtering on status, so every instance of each definition is read and the date window is applied on the client. Instances older than the window are not read for decisions.
- A failed read is never reported as zero. If an instance's decisions can't be read (for example HTTP 403), that instance shows `EvidenceStatus = Partial`, its counts are blank, the run carries on, and the three datasets are `Partial`. If the definitions can't be read, all three datasets are `EvidenceUnavailable` (no Entra ID P2 / ID Governance) or `Blocked` (permission).
- Justifications are free text written by reviewers. They are cut to 500 characters, with line breaks removed; check them before sharing the file outside the audit team.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | AccessReview.Read.All, Directory.Read.All, RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup | - | Graph Auth |

Licence: access reviews need Entra ID P2 / ID Governance. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: one completed review's decision counts match its Results page in Identity Governance; one denied user shows the same apply result as the portal.

Usually tuned on first run: `-SinceDays` to the audit period, and `-DefinitionNameLike` to the reviews in scope. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| All datasets `EvidenceUnavailable` | No Entra ID P2 / ID Governance | Record as a finding |
| All datasets `Blocked` | AccessReview.Read.All missing or not consented | Add the scope; Global Reader can read reviews |
| An instance `Partial` with `DecisionsUnreadable` | That review's decisions were refused (HTTP 403) | Check the run account's role; re-run for that definition with `-DefinitionIds` |
| `PrivilegedApprovedWithoutReview` count blank | Role holders not readable | Add RoleManagement.Read.Directory, or accept and note it |
| No instances found | Window too short, or reviews still running | Raise `-SinceDays`, or add `-IncludeInProgress` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 29 Pilot outcome](29-pilot-outcome.md) · [All scripts](README.md)
