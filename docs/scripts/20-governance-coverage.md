# 20 - Governance coverage

**Script:** [`20-Get-GovernanceCoverage.ps1`](../../scripts/20-Get-GovernanceCoverage.ps1) · **Version:** 1.0.0 · **Source:** Entra ID Governance

> What share of apps, groups and roles is actually covered by access reviews?

Answers "what share of the things that should be certified actually are?"

**Collects:**
- **Access review definitions:** target, reviewers, recurrence, auto-apply setting and the latest instance.
- **Decision statistics** (optional): approved, denied and not reviewed counts, completion %, and how many decisions failed to apply.
- **Coverage list:** every enterprise app requiring assignment, role-assignable group, group containing guests and Tier 0 directory role, each marked Covered or NotCovered by a recurring review. Your own in-scope application list can be checked too.
- **Access packages:** approval, expiration and built-in review settings.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-IncludeDecisionStats` | off | Read decisions on each review's latest instance |
| `-SkipGuestGroups` | off | Skip finding groups that contain guests (one call per guest) |
| `-InScopeAppsCsv` | none | CSV with `AppName` and/or `AppId` columns: the certification scope list |

**Open first:** `summary.csv` (coverage % by type), then `review-coverage.csv` filtered on `Covered = False`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `access-review-definitions.csv` | Access review | `TargetType`, `TargetName`, `Recurrence`, `Reviewers`, `AutoApplyResults`, latest instance |
| `access-review-latest-decisions.csv` | Review's latest instance | `Approved`, `Denied`, `NotReviewed`, `CompletionPct`, `ApplyFailed` |
| `review-coverage.csv` | Target that should be reviewed | `TargetType`, `WhyInScope`, `Covered`, `CoveredBy` |
| `access-packages.csv` | Access package | `AnyApprovalRequired`, `AnyReviewConfigured`, `AnyNoExpiration` |

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | AccessReview.Read.All, EntitlementManagement.Read.All, Application.Read.All, Group.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory | - | Graph Auth |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Number of access reviews in Identity Governance; one app you know is reviewed shows `Covered`.

Usually tuned on first run: `-InScopeAppsCsv` once the certification scope list exists. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scripts 20-22: datasets `EvidenceUnavailable` | No Entra ID P2 / ID Governance | Record as a finding |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 19 DC authentication protocols](19-dc-authentication-protocols.md) · [All scripts](README.md) · [21 Identity risk →](21-identity-risk.md)
