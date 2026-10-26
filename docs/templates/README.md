# Registers and templates

The scripts produce evidence. These templates hold the decisions people make about that evidence: which tests prove a change, who accepted which risk, what is still open, and who owns what. Copy a template into the engagement's evidence location and fill it there. Never commit a filled copy to this repository.

| Template | Use it for | Columns that matter most |
|---|---|---|
| [Pilot test cases](../../examples/pilot-test-cases.example.csv) | Expected and adverse test cases for an MFA or Conditional Access pilot. It is also the input to [29 - Pilot outcome](../scripts/29-pilot-outcome.md), which marks each case Pass, Fail or NoEvidence from sign-in logs | `CaseType`, `ExpectedPolicyResult`, `ExpectedSignIn`, `NotBeforeUtc` |
| [Exception register](../../examples/exception-register.example.csv) | Accepted exceptions and residual risk: who is excluded from a control, why, what compensates, who accepted it and when it expires | `ResidualRisk`, `RiskOwner`, `ApprovedBy`, `ExpiresUtc`, `EvidenceRunFolder` |
| [Status register](../../examples/status-register.example.csv) | One line per deliverable item in one of the four states (Completed, Blocked, Deferred, EvidenceUnavailable) with a reason. Deferred items always carry an owner, a target treatment and a target date | `Status`, `StatusReason`, `Owner`, `TargetTreatment`, `TargetDateUtc` |
| [Ownership matrix](../../examples/ownership-matrix.example.csv) | Who owns, operates and reviews each control, policy and process after handover | `BusinessOwner`, `TechnicalOwner`, `Operator`, `Runbook` |
| [Population exclusions](../../examples/population-exclusions.example.csv) | Approved exclusions from the human-workforce population used as the denominator for every KPI. Input to [27 - Identity population](../scripts/27-identity-population.md) | `Reason`, `ApprovedBy`, `ExpiresUtc` |
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
```

Fill the registers with role names or identity IDs as the engagement's data-handling rules allow. Keep personal data out of anything that leaves the approved evidence location.

[← Back to README](../../README.md)
