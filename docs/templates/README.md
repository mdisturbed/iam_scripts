# Registers and templates

The scripts produce evidence. These templates hold the decisions people make about that evidence: which tests prove a change, who accepted which risk, what is still open, and who owns what. Copy a template into the engagement's evidence location and fill it there. Never commit a filled copy to this repository.

| Template | Use it for | Columns that matter most |
|---|---|---|
| [Pilot test cases](../../examples/pilot-test-cases.example.csv) | Expected and adverse test cases for an MFA or Conditional Access pilot. It is also the input to [29 - Pilot outcome](../scripts/29-pilot-outcome.md), which marks each case Pass, Fail or NoEvidence from sign-in logs | `CaseType`, `ExpectedPolicyResult`, `ExpectedSignIn`, `NotBeforeUtc` |
| [Exception register](../../examples/exception-register.example.csv) | Accepted exceptions and residual risk: who is excluded from a control, why, what compensates, who accepted it and when it expires | `ResidualRisk`, `RiskOwner`, `ApprovedBy`, `ExpiresUtc`, `EvidenceRunFolder` |
| [Readiness checklist](../../examples/readiness-checklist.example.csv) | The ten pre-project prerequisites, each closed with evidence or formally waived (reason, who waived, when). The pre-project gate passes only when every row is Closed or Waived | `Status`, `Evidence`, `WaiverReason`, `WaivedBy`, `WaivedOnUtc` |
| [Status register](../../examples/status-register.example.csv) | One line per deliverable item with its evidence state (Completed, Partial, Blocked, Deferred, EvidenceUnavailable). Blocked and deferred items always carry an owner, rationale, risk, disposition and recommended follow-on, so they are never presented as implemented | `EvidenceState`, `Rationale`, `Owner`, `Risk`, `Disposition`, `RecommendedFollowOn` |
| [Deliverable acceptance log](../../examples/deliverable-acceptance-log.example.csv) | Each deliverable submission: to whom, when, the review due date (5 business days unless agreed otherwise), and the outcome: Accepted, CommentsReceived or DeemedAccepted (no written rejection by the due date) | `SubmittedOnUtc`, `ReviewDueUtc`, `Decision`, `CommentsReceived` |
| [Ownership matrix](../../examples/ownership-matrix.example.csv) | Who owns, operates and reviews each control, policy and process after handover | `BusinessOwner`, `TechnicalOwner`, `Operator`, `Runbook` |
| [Population exclusions](../../examples/population-exclusions.example.csv) | Approved exclusions from the human-workforce population used as the denominator for every KPI. Input to [27 - Identity population](../scripts/27-identity-population.md) | `Reason`, `ApprovedBy`, `ExpiresUtc` |
| [Findings review workbook](../../templates/findings-review.template.xlsx) | One row per finding, reviewed in order by the Identity Engineer, Identity Architect, Zero Trust Architect and the client decision authority. Stage, Waiting on and Disposition are calculated. Rows from [New-FindingDrafts](../engagement-kit.md#findings-pipeline) paste straight into the Review Trail sheet; its CSV export ([example](../../examples/findings-review.example.csv)) feeds the dashboard | `Observed severity`, `Architect severity`, `Alignment`, `Client decision`, `Stage` |
| [Finding rules](../../examples/finding-rules.psd1) | Which summary metric of which script drafts a finding, with its default severity, HITRUST CSF reference, Zero Trust pillar and principle, and recommendation. Input to [New-FindingDrafts](../engagement-kit.md#findings-pipeline); tune thresholds per engagement, never change a RuleId | `RuleId`, `Metric`, `Condition`, `Threshold`, `Severity` |
| [Runbook](runbook-template.md) | Operating a control after handover: scope, prerequisites, procedure, validation, rollback, operations, knowledge transfer | Sections 4 to 8 tie each step to a script run |

## How they connect

```
Baseline run (01-30)  ->  change approved  ->  pilot test cases  ->  29 Pass/Fail
        |                                                               |
   28 snapshot  <------------- rollback proof (drift = Unchanged) ------+
        |
Compare-RunFolders (before / after)  ->  exception register  ->  status register
        |
Get-KpiSummary (27 denominators)  ->  New-EvidencePackage (per-deliverable status)
        |
New-FindingDrafts (finding rules)  ->  findings review workbook  ->  New-EngagementDashboard
```

`tools\New-Engagement.ps1` copies every template here into a new engagement folder (`registers\`, `config\`, `templates\`), so a new engagement starts from the same set. See [Engagement kit](../engagement-kit.md).

Fill the registers with role names or identity IDs as the engagement's data-handling rules allow. Keep personal data out of anything that leaves the approved evidence location.

[← Back to README](../../README.md)
