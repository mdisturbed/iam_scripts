# Jira finding template

One finding = one Jira issue. Every finding carries the same sections, so the architect can triage it, the owner can fix it, and an assessor can trace it back to evidence without asking.

- [Issue fields](#issue-fields)
- [Description template](#description-template) (copy this)
- [Severity guide](#severity-guide)
- [Worked example](#worked-example)
- [Rules for evidence in Jira](#rules-for-evidence-in-jira)

## Issue fields

| Field | Value |
|-------|-------|
| **Summary** | `[Area] What is wrong - scale` e.g. `[Entra PIM] Global Administrator activates without approval - 7 eligible admins` |
| **Issue type** | Finding (or Task with label `finding` if no Finding type exists) |
| **Priority** | From severity: Critical → Highest, High → High, Medium → Medium, Low → Low |
| **Labels** | `iam-discovery`, the area (`entra`, `ad`, `aws`, `azure`, `m365`, `iga`, `jml`), the gap (`mfa`, `privileged-access`, `service-accounts`, `data-flow`, `rbac`, `stale-accounts`), `script-NN` |
| **Components** | Platform owner team, if the project uses components |
| **Assignee** | Engineer who logged it, until the architect triages |
| **Linked issues** | Related findings ("relates to"); remediation tickets and change records ("is fixed by") |

Statuses that work well: `Draft` → `Triaged` (architect agreed severity and owner) → `Remediation planned` → `Remediated` → `Verified` (rerun shows the fix) → `Closed`. Use `Accepted risk` for findings that won't be fixed, with the approver named in a comment.

## Description template

Paste into the issue description. Jira Cloud converts the Markdown as you paste; delete any line that doesn't apply rather than leaving it blank.

```markdown
## Finding
<One sentence: what is wrong, where, and how many. Lead with the number.>

## Severity
**<Critical | High | Medium | Low>** - <one line: why this rating (likelihood x impact)>

## Scope
- Platform / system: <Entra ID | AD | Intune | Exchange Online | Azure | AWS | IGA | ...>
- Affected objects: <count> <type> (e.g. 12 enabled user accounts)
- Examples: <2-3 placeholders or IDs only, e.g. User1, Group1, App1 - full list in evidence>
- Tier: <Tier 0 | Tier 1 | Tier 2 | n/a>

## Current state vs expected state
| | |
| --- | --- |
| **Current** | <what the data shows> |
| **Expected** | <the standard, policy or baseline it should meet> |

## Evidence
- Script: <NN-ScriptName.ps1> v<version>
- Run folder: <OutputRoot>\<NN-Name>\<yyyyMMdd-HHmmssZ>
- Dataset(s): <file.csv> - filter: <column = value>
- SHA-256 (from dataset-status.csv): <hash>
- Run by: <run account from run-manifest.json> | Data as of: <UTC timestamp>
- Dataset status: <Completed | Blocked | EvidenceUnavailable | Deferred>
- Verified against: <known-answer check, e.g. "GA count matches Entra portal"> | Not yet verified
- Evidence location: <link to approved evidence store - no raw exports in Jira>

## Why it matters
<1-3 sentences: what an attacker or failure could do, in this environment's terms.>

## Framework mapping
- Zero Trust (CISA ZTMM): <Identity | Devices | Networks | Applications & Workloads | Data> - <current maturity: Traditional | Initial | Advanced | Optimal>
- HITRUST CSF: <domain / requirement reference>
- NIST SP 800-53: <control, e.g. AC-2(3), IA-2(1)>
- CIS Controls v8: <safeguard, e.g. 5.3, 6.5>

## Possible options (for architect review)
1. <option> - effort: <S | M | L>, dependency: <...>
2. <option> - effort: <S | M | L>, dependency: <...>

## Remediation
- Proposed owner: <team / role>
- Approver: <role>
- Change ticket: <link once raised>
- Target date: <date, once agreed>

## Closure criteria
- Rerun: `<script> <same parameters>`
- Pass when: <metric in summary.csv> = <target value> (was <current value> on <date>)

## Notes / open questions
- <anything unconfirmed, who to ask>
```

## Severity guide

Use the highest row that applies. When unsure, log it one level down and let the architect raise it at triage.

| Severity | Use when | Typical examples from the scripts |
|----------|----------|------------------------------------|
| **Critical** | Direct path to tenant / domain / account takeover, or active compromise indicators | Non-default DCSync rights (18); root account with no MFA or access keys (17); permanent Global Admin without MFA (02, 22); at-risk admin (21); external forwarding + hiding inbox rule (09) |
| **High** | Privilege or data exposure that needs one more step, or broad control gaps | Tier 0 PIM activation without approval (22); app with high-risk application permissions and no owner (03); successful legacy-auth sign-ins (01); terminated users still enabled (06); NTLM v1 in use (19) |
| **Medium** | Weakens control coverage or hygiene; exploit needs several conditions | CA exclusions without documented approval (01); stale enabled accounts (12); guests never signed in (10); deep or circular nesting (05); attribute values inconsistent for RBAC (07) |
| **Low** | Hygiene and documentation gaps with little direct risk | Groups without owners or descriptions (05); unassigned compliance policies (16); unused extension attributes not documented (08) |

## Worked example

**Summary:** `[Entra PIM] Tier 0 roles activate without approval or MFA - 2 roles`

**Labels:** `iam-discovery`, `entra`, `privileged-access`, `script-22`

```markdown
## Finding
2 of 14 Tier 0 directory roles (Global Administrator, Privileged Role Administrator) can be activated in PIM without approval and without MFA or an authentication context.

## Severity
**High** - eligible admins can self-activate full tenant control for up to 10 hours with only a password; mitigated only by the sign-in CA policy.

## Scope
- Platform / system: Entra ID (PIM for directory roles)
- Affected objects: 2 role settings; 7 eligible assignments across them
- Examples: Global Administrator, Privileged Role Administrator
- Tier: Tier 0

## Current state vs expected state
| | |
| --- | --- |
| **Current** | Approval: off. MFA on activation: off. Auth context: none. Max activation: 10 h. Permanent eligibility allowed. |
| **Expected** | Approval required; authentication context requiring phishing-resistant MFA; max activation 4-8 h; eligibility expires. |

## Evidence
- Script: 22-Get-PimRoleSettings.ps1 v1.0.0
- Run folder: D:\Evidence\22-PimRoleSettings\20261021-140501Z
- Dataset(s): pim-role-settings.csv - filter: Flags contains Tier0NoApproval
- SHA-256 (from dataset-status.csv): <hash>
- Run by: admin1@contoso.local | Data as of: 2026-10-21T14:05:01Z
- Dataset status: Completed
- Verified against: Global Administrator settings in PIM > Entra roles > Settings match
- Evidence location: <evidence store link>

## Why it matters
A phished password for any of the 7 eligible admins is enough to activate Global Administrator; nothing stops or alerts on the activation.

## Framework mapping
- Zero Trust (CISA ZTMM): Identity - Initial
- HITRUST CSF: 01.c Privilege Management
- NIST SP 800-53: AC-2(7), AC-6(5), IA-2(1)
- CIS Controls v8: 5.4, 6.5

## Possible options (for architect review)
1. Require approval + authentication context (phishing-resistant MFA) on all Tier 0 roles - effort: S, dependency: approver group, CA auth-context policy
2. Same, plus cap activation at 4 h and require ticket number - effort: S, dependency: change process wording

## Remediation
- Proposed owner: IAM engineering
- Approver: IAM Manager
- Change ticket: <link>
- Target date: <date>

## Closure criteria
- Rerun: `.\scripts\22-Get-PimRoleSettings.ps1 -OutputRoot D:\Evidence`
- Pass when: "Tier 0 roles activatable without approval" = 0 and "Tier 0 roles without MFA or auth context on activation" = 0 (were 1 and 1 on 2026-10-21)

## Notes / open questions
- Who should be in the approver group? Confirm with the architect.
```

## Rules for evidence in Jira

- **Never attach raw CSV exports** to a Jira issue. They contain identity data and Jira is not the evidence store. Link to the approved evidence location and quote counts.
- In the issue, name objects only as far as needed to act on the finding, and put full lists in the evidence store.
- Copy the SHA-256 from `dataset-status.csv` so the issue stays tied to the exact file, even if the evidence is moved.
- Closure always means a **rerun with the same parameters**, recorded in a comment with the new run folder.
- Framework references above are examples; confirm the exact HITRUST requirement IDs against the CSF version the organization is assessed on.
