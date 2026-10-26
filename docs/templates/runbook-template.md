# Runbook: <control or process name>

| Field | Value |
|---|---|
| Runbook ID | RB-000 |
| Version | 0.1 (draft) |
| Owner | Role (from the [ownership matrix](../../examples/ownership-matrix.example.csv)) |
| Operator | Role |
| Last reviewed | yyyy-mm-dd |
| Related change records | REQ0000000 |

## 1. Purpose

One or two sentences: what this control or process does and why it exists.

## 2. Scope

- **In scope:** which users, groups, apps, policies or systems.
- **Out of scope:** what this runbook does not cover.
- **Exceptions:** IDs from the exception register, never names.

## 3. Prerequisites

| Need | Detail |
|---|---|
| Role | Least-privileged role needed (for example, Conditional Access Administrator activated through PIM) |
| Access | Portals, modules, approval in the change calendar |
| Evidence folder | Where run folders go |

## 4. Before the change

1. Confirm the change record is approved and inside its window.
2. Take the baseline: run the read-only evidence script(s) and keep the run folder.
   ```powershell
   .\scripts\28-Export-CaPolicySnapshot.ps1 -OutputRoot $ev
   ```
3. Record the baseline run folder in the change record.

## 5. Procedure

Numbered steps. One action per step. Say what you should see after each step.

1. ...
2. ...

## 6. Validation

| Test ID | Case type | What is tested | Expected result | Evidence |
|---|---|---|---|---|
| TC-01 | Expected | ... | ... | `29-PilotOutcome` run folder |
| TC-02 | Adverse | ... | ... | `29-PilotOutcome` run folder |

Pass criteria: every case `Pass` in `pilot-test-results.csv`; no rows in `pilot-scope-leak.csv`.

## 7. Rollback

- **Trigger:** what makes you roll back (for example, any adverse case fails, or helpdesk volume above an agreed level).
- **Steps:** numbered, the exact reverse of section 5.
- **Proof of rollback:** rerun the snapshot with `-BaselineRunFolder <section 4 run>`; every changed object must show `Unchanged`.

## 8. After the change

1. Rerun the evidence script and compare with the baseline:
   ```powershell
   .\tools\Compare-RunFolders.ps1 -BeforeRunFolder <before> -AfterRunFolder <after> -OutputRoot $ev
   ```
2. Attach the run folders and the comparison to the change record.
3. Update the status register: Completed, Blocked, Deferred or EvidenceUnavailable, with a reason.

## 9. Operations

| Task | Frequency | How | Evidence |
|---|---|---|---|
| Review exceptions | Per exception register cadence | ... | ... |
| Recheck configuration drift | Monthly | Snapshot with `-BaselineRunFolder` | `ca-policy-drift.csv` |

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| ... | ... | ... |

## 11. Knowledge transfer

- Walkthrough held with: roles, date.
- Questions raised and answers.
- Sign-off: role, date.

[← Back to templates](README.md)
