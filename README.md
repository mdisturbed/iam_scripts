# IAM Discovery Scripts

Read-only PowerShell scripts that collect evidence for an identity and access management (IAM) gap analysis across **Microsoft Entra ID**, **on-premises Active Directory**, **Intune**, **Exchange Online / SharePoint**, **Azure** and **AWS**.

Each script measures one gap, writes timestamped CSVs plus a run manifest, and can be rerun after remediation to show progress against the same baseline. The output is designed to stand up as audit evidence (for example in a HITRUST, NIST or CIS assessment): every run records who ran it, from where, when, with which permissions, and a SHA-256 hash of every file it produced.

> **Nothing in these scripts changes anything.** Graph calls go through one function that only sends HTTP `GET`; Azure Resource Manager calls go through one function that only sends `GET`; AD, Exchange, SharePoint, event log and AWS work uses only `Get-*` cmdlets. [`tools/Test-ReadOnly.ps1`](tools/Test-ReadOnly.ps1) proves this statically, without running anything, so a reviewer can confirm it in seconds.

> **Test status:** every script is **mock-tested** (see [Testing](docs/design-and-testing.md#testing)). Before handing a script to others, run it once yourself in the target environment and check it against known answers using the [pilot runbook](docs/pilot-runbook.md).

---

## Contents

- [The scripts](#the-scripts)
- [Quick start](#quick-start)
- [Read-only guarantee](#read-only-guarantee)
- [Using the results](#using-the-results)
- [Documentation](#documentation)
- [Repository layout](#repository-layout)
- [Author](#author) · [License](#license)

## The scripts

Each links to its page: what it collects, parameters, output files, permissions, pilot check and troubleshooting.

| # | Script | Question it answers | Source |
|---|--------|--------------------|--------|
| 01 | [MFA coverage](docs/scripts/01-mfa-coverage.md) | Is MFA actually enforced everywhere, how strong is it, and who is left out? | Entra |
| 02 | [Entra privileged access](docs/scripts/02-entra-privileged-access.md) | Who really holds Entra admin roles, down to the account, and are those accounts well managed? | Entra |
| 03 | [Apps and consents](docs/scripts/03-apps-and-consents.md) | Which apps can reach our data, who owns and can use them, and are they governed? | Entra |
| 04 | [AD privileged and service accounts](docs/scripts/04-ad-privileged-and-service-accounts.md) | Who has admin rights on-prem (including via nesting and primary group), which accounts carry risky settings, and where are the service accounts? | AD |
| 05 | [AD group nesting](docs/scripts/05-ad-group-nesting.md) | How deep and messy is group nesting, which accounts does each group really reach, and how healthy are groups and their owners? | AD |
| 06 | [JML timing](docs/scripts/06-jml-timing.md) | How quickly are joiners provisioned and leavers disabled, and which leavers and their admin accounts still hold access? | AD + HR file (+ Entra) |
| 07 | [Role mining](docs/scripts/07-role-mining.md) | Which groups do people in the same department or job code share, who has far more access than their peers, and is the HR data clean enough to drive roles? | AD |
| 08 | [Extension attribute inventory](docs/scripts/08-extension-attribute-inventory.md) | Which custom / extension attributes are free to carry new data, and does anything already read them? | AD (+ Entra) |
| 09 | [Mail forwarding and external sharing](docs/scripts/09-mail-forwarding-and-external-sharing.md) | Is mail being forwarded out, who can read or send as other mailboxes, and how open is SharePoint / OneDrive sharing? | Exchange Online + SharePoint |
| 10 | [Guest access](docs/scripts/10-guest-access.md) | How many guests and external accounts are there, are they used, what can they reach, and which partner tenants do we trust? | Entra |
| 11 | [Azure RBAC](docs/scripts/11-azure-rbac.md) | Who actually holds access to Azure resources (groups expanded), at what scope, permanently or just-in-time, and through which other paths? | Azure + Entra |
| 12 | [Stale accounts](docs/scripts/12-stale-accounts.md) | Which identities are really unused once AD and Entra activity are combined, and what do the stale ones still hold? | AD + Entra |
| 13 | [Hybrid sync scope](docs/scripts/13-hybrid-sync-scope.md) | What actually syncs from AD to Entra, where do they disagree, and which on-prem admins reach the cloud? | AD + Entra |
| 14 | [IGA reconciliation](docs/scripts/14-iga-reconciliation.md) | Where does the IGA platform's view of accounts and group access differ from AD, including access through nested groups and leavers who still hold groups? | AD + IGA export |
| 15 | [Rule-managed access](docs/scripts/15-rule-managed-access.md) | Are applied roles, HR-expected roles and actual group membership in step, and who is in a rule-managed group who shouldn't be? | AD + role files |
| 16 | [Device posture](docs/scripts/16-device-posture.md) | Are devices joined, managed, compliant and backed up, who can join them, and which accounts does device-based CA exempt? | Entra + Intune |
| 17 | [AWS IAM posture](docs/scripts/17-aws-iam-posture.md) | Which AWS identities exist, who is admin-equivalent and through which policy, and which people sit behind each Identity Center assignment? | AWS |
| 18 | [AD delegation](docs/scripts/18-ad-delegation.md) | Who has dangerous rights through AD permissions, and which real accounts end up holding them? | AD |
| 19 | [DC authentication protocols](docs/scripts/19-dc-authentication-protocols.md) | Who still uses NTLM (v1 and LM especially) or RC4/DES Kerberos, against which servers, and which accounts can't do AES? | DC event logs + AD |
| 20 | [Governance coverage](docs/scripts/20-governance-coverage.md) | What share of apps, groups and privileged roles is actually covered by access reviews, what do access packages grant, and are joiner / mover / leaver workflows in place? | Entra ID Governance |
| 21 | [Identity risk](docs/scripts/21-identity-risk.md) | Who is at risk right now, and does Conditional Access act on risk for everyone? | Entra ID Protection |
| 22 | [PIM role settings](docs/scripts/22-pim-role-settings.md) | What does it actually take to activate each admin role or privileged group, and who approves it? | Entra PIM |
| 23 | [AD attribute population](docs/scripts/23-ad-attribute-population.md) | Which attributes does the schema allow, how many objects actually have a value in each, and where are values duplicated? | AD |
| 24 | [CA report-only impact](docs/scripts/24-ca-reportonly-impact.md) | What does each Conditional Access policy do to real sign-ins, who would a report-only policy block or challenge, and which sign-ins does no enforced policy cover? | Entra sign-in logs |
| 25 | [Purview classification and DLP](docs/scripts/25-purview-classification.md) | What can classify and protect regulated data, what is switched on, who is excluded, who can see or bypass it, and how much tagged content exists? | Microsoft Purview |
| 26 | [PAM vault coverage](docs/scripts/26-pam-vault-coverage.md) | Which privileged, service and delegated accounts are managed in the PAM vault, which are not, and which vault entries are stale? | PAM export + 02/04/11/17/18 |
| 27 | [Identity population](docs/scripts/27-identity-population.md) | Who exactly is in scope, how many of each kind of identity are there, and who was excluded and why? The denominators for every KPI | AD + Entra (+ HR file) |
| 28 | [CA policy snapshot](docs/scripts/28-ca-policy-snapshot.md) | What exactly is the Conditional Access configuration right now, and what changed since the last snapshot? The baseline and rollback proof for a change | Entra |
| 29 | [Pilot outcome](docs/scripts/29-pilot-outcome.md) | Did each pilot test case, expected and adverse, give the result it should, and which sign-in proves it? | Entra sign-in logs + test-case file |
| 30 | [Access review evidence](docs/scripts/30-access-review-evidence.md) | For each access review that ran, who reviewed what, what did they decide and why, and were removals applied? | Entra ID Governance |
| 31 | [Licence inventory](docs/scripts/31-licence-inventory.md) | Which Microsoft licences and service plans does the tenant actually have, how many are assigned, and which licence-dependent evidence could not be collected? | Entra (+ evidence folder) |

The scripts gather facts. They do not score maturity or recommend fixes; that interpretation belongs in the analysis that uses the evidence.

## Quick start

Needs PowerShell 5.1 or 7.x, plus the modules for the scripts you run ([prerequisites](docs/getting-started.md#prerequisites)).

```powershell
# 1. Prove the scripts are read-only (AST scan only - nothing executes)
.\tools\Test-ReadOnly.ps1

# 2. Run a script, signing in as yourself; output goes to a new timestamped folder
.\scripts\02-Get-PrivilegedAccess.ps1 -OutputRoot D:\Evidence

# 3. On-prem AD from a management host with RSAT
.\scripts\04-Get-ADPrivilegedAndServiceAccounts.ps1 -Server dc01.contoso.local -OutputRoot D:\Evidence

# Full help for any script
Get-Help .\scripts\07-Get-RoleMiningCandidates.ps1 -Full
```

Open `summary.csv` in the run folder first. Every script with typical parameters is in [Getting started](docs/getting-started.md#run-everything).

**Prefer a menu?** The launcher shows which scripts this machine can run, lets you tick them, runs them with the DC and evidence folder filled in, and can finish with a one-page HTML report (counts only, no names):

```powershell
.\tools\Start-Discovery.ps1 -Server dc01.contoso.local -OutputRoot D:\Evidence -Report
.\tools\New-DiscoveryReport.ps1 -OutputRoot D:\Evidence        # rebuild the report any time
```

See [Launcher and report](docs/getting-started.md#launcher-and-report).

## Read-only guarantee

1. **One Graph entry point.** All Graph traffic goes through `Invoke-GraphGet`, which calls `Invoke-MgGraphRequest -Method GET`.
2. **One Azure entry point.** All ARM traffic in script 11 goes through `Invoke-ArmGet`, which calls `Invoke-AzRestMethod -Method GET`.
3. **Read cmdlets only** for AD (`Get-AD*`), Exchange (`Get-EXO*`, `Get-InboxRule`, `Get-TransportRule`, …), SharePoint (`Get-SPOSite`), event logs (`Get-WinEvent`) and AWS (`Get-IAM*`, `Get-SSOADMN*`, `Get-ORG*`, …). In script 17, `Use-STSRole` only obtains temporary credentials for a read-only role; it's the one non-`Get` command on the checker's allowlist.
4. **Read scopes only** are requested at sign-in.
5. **Static proof.** [`tools/Test-ReadOnly.ps1`](tools/Test-ReadOnly.ps1) parses each script with the PowerShell AST, without running it, and fails on:
   - any state-changing verb (`New-`, `Set-`, `Remove-`, `Add-`, `Update-`, `Enable-`, `Disable-`, `Grant-`, `Revoke-`, …) outside a short allowlist of commands that only write the local evidence folder
   - any `Invoke-MgGraphRequest` or `Invoke-AzRestMethod` without `-Method GET`
   - `Invoke-RestMethod`, `Invoke-WebRequest`, `Invoke-Expression`, `Invoke-Command`, `Start-Process`

```powershell
.\tools\Test-ReadOnly.ps1                                         # all scripts
.\tools\Test-ReadOnly.ps1 -Path .\scripts\11-Get-AzureRbac.ps1    # one script
```

Exit code `0` means pass. Run it again after any edit.

## Using the results

A suggested order for a discovery pass, matched to the three common gaps and the move to rule-based access:

| Goal | Scripts |
|------|---------|
| MFA coverage | 01, 24 |
| Privileged and service account sprawl | 02, 04, 11, 17, 18, 22, 26 |
| "Where is my data going" | 03, 09, 10, 25 |
| Stale and orphaned identities | 12, 13, 06, 10 |
| Devices and Conditional Access | 16, 01, 21, 24 |
| AD attack paths and legacy protocols | 18, 19, 04 |
| AWS identity | 17 |
| Certification coverage and PIM hardening | 20, 22 |
| Current lifecycle and governance baseline | 06, 14 |
| Groups and RBAC design | 05, 07, 08, 23 |
| After rule-based access goes live | 15 (scheduled), 06 and 12 (rerun) |
| KPI denominators | 27 |
| Conditional Access change: baseline, pilot, rollback | 28, 24, 29, then 28 with `-BaselineRunFolder` |
| Access-review evidence | 20, 30 |
| Licence confirmation for a readiness gate | 31 (with `-EvidenceRoot` after the other runs) |

1. Run `Test-ReadOnly.ps1` and share the result with whoever approves the run.
2. Pilot each script yourself using the [pilot runbook](docs/pilot-runbook.md).
3. Build the HTML report with `tools/New-DiscoveryReport.ps1` for the status update: headline metrics, change since the previous run, and every `Blocked` or `EvidenceUnavailable` dataset.
4. Log each finding in Jira with the [finding template](docs/jira-finding-template.md); `tools/New-FindingEvidence.ps1` pre-fills the Evidence and Closure sections from the run folder.
5. After remediation, rerun with the same parameters and compare the two run folders with `tools/Compare-RunFolders.ps1`; that rerun and the comparison are the finding's closure evidence.

### Running a staged identity programme

For work that moves through gates (baseline, pilot, staged change, operational handover, final evidence), three tools turn run folders into gate evidence. See [Evidence tools](docs/evidence-tools.md).

| Need | Use |
|------|-----|
| One agreed population to divide by | 27, with the [population exclusions](examples/population-exclusions.example.csv) the approver signs |
| Pilot passes, rollback proven | [Pilot test cases](examples/pilot-test-cases.example.csv) → 29; 28 before the change and again with `-BaselineRunFolder` after rollback |
| Before / after evidence for an approved change | `tools/Compare-RunFolders.ps1` |
| KPIs with validated denominators | `tools/Get-KpiSummary.ps1` with a [KPI definition file](examples/kpi-definitions.example.psd1) |
| Evidence intake log and per-deliverable status | `tools/New-EvidencePackage.ps1` with a [deliverable map](examples/deliverable-map.example.psd1) |
| Readiness prerequisites, exceptions, status, acceptance, ownership, runbooks | [Registers and templates](docs/templates/README.md) |

### Running an engagement

The [engagement kit](docs/engagement-kit.md) packages the whole workflow so it runs the same way at every client: one engagement folder, an access request generated from the script catalog, the readiness checklist, baseline runs, evidence package, KPIs, draft findings reviewed in a workbook, and a one-page dashboard.

```powershell
.\tools\New-Engagement.ps1 -Path D:\Engagements\Programme1 -Name 'Identity programme'        # folder, registers, config, workbook
.\tools\Start-Engagement.ps1 -EngagementPath D:\Engagements\Programme1 -Server dc01.contoso.local   # menu for every step
```

| Need | Use |
|------|-----|
| What to ask the client for: roles, Graph permissions, other access, input files, licences | `tools/New-AccessRequest.ps1` |
| Draft findings from the latest runs, with stable IDs and evidence notes | `tools/New-FindingDrafts.ps1` with [finding rules](examples/finding-rules.psd1) |
| Engineer, architect, Zero Trust and client review of each finding | [Findings review workbook](templates/findings-review.template.xlsx) |
| Where the engagement stands, on one page | `tools/New-EngagementDashboard.ps1` |

> **Contributing?** Read [CONTRIBUTING.md](CONTRIBUTING.md) and run `.\tools\guardrail\Install-Guardrail.ps1` once after cloning. See [Guardrail](docs/guardrail.md).

## Documentation

| Page | Covers |
|------|--------|
| [Getting started](docs/getting-started.md) | Modules, access and licences, sign-in modes, common parameters, every script with typical parameters, locked-down hosts |
| [Script reference](docs/scripts/README.md) | One page per script |
| [Permissions](docs/permissions.md) | Roles, scopes, licences and modules per script; app-only setup |
| [Output and evidence](docs/outputs.md) | Run folder, manifest, dataset statuses, handling the files |
| [Pilot runbook](docs/pilot-runbook.md) | Moving a script from mock-tested to pilot-verified before handover |
| [Evidence tools](docs/evidence-tools.md) | Before / after comparison, KPIs with validated denominators, evidence intake log and per-deliverable package |
| [Engagement kit](docs/engagement-kit.md) | Running an engagement end to end: engagement folder, access request, findings pipeline and review workbook, dashboard, reuse at the next client |
| [Registers and templates](docs/templates/README.md) | Pilot test cases, exception register, status register, ownership matrix, findings review workbook, finding rules, runbook template |
| [Jira finding template](docs/jira-finding-template.md) | Logging findings with evidence and closure criteria |
| [Troubleshooting](docs/troubleshooting.md) | Symptoms, causes and fixes |
| [Design and testing](docs/design-and-testing.md) | Design choices and how the scripts were tested |
| [Guardrail](docs/guardrail.md) | What keeps identifying information and secrets out of this repo; one-time setup per machine |
| [Changelog](CHANGELOG.md) | Version history |

## Repository layout

```
iam_scripts/
├── README.md                     this file
├── CHANGELOG.md                  version history
├── LICENSE                       MIT
├── CONTRIBUTING.md               rules for changing this repo (read before contributing)
├── .gitignore                    blocks evidence, keys and data exports from being committed
├── .githooks/                    pre-commit and commit-msg guardrail hooks
├── .github/workflows/            guardrail CI on every push (backstop for the hooks)
├── scripts/                      the thirty-one discovery scripts (self-contained, run independently)
├── tools/
│   ├── Test-ReadOnly.ps1         static proof that the scripts cannot write anything
│   ├── Start-Discovery.ps1       launcher: readiness check, pick list, runs scripts, run summary
│   ├── New-DiscoveryReport.ps1   one-page HTML report from the evidence folder (counts only)
│   ├── discovery-catalog.psd1    script list, what each needs and the access it requires (launcher, report, access request)
│   ├── New-FindingEvidence.ps1   pre-fills a Jira finding's Scope, Evidence and Closure from a run folder
│   ├── Compare-RunFolders.ps1    before / after evidence: two runs of the same script, row and metric changes
│   ├── Get-KpiSummary.ps1        KPIs from the latest runs, divided by the script 27 population
│   ├── New-EvidencePackage.ps1   evidence intake log, hash re-check and per-deliverable status
│   ├── New-Engagement.ps1        creates an engagement folder: evidence, registers, config, findings, workbook, README
│   ├── Start-Engagement.ps1      text menu for one engagement folder (every step of the kit)
│   ├── New-AccessRequest.ps1     client access request (roles, permissions, inputs, licences) from the catalog
│   ├── New-FindingDrafts.ps1     draft findings from summary metrics, with a ledger of stable finding IDs
│   ├── New-EngagementDashboard.ps1  one-page HTML dashboard: runs, KPIs, readiness, findings, open items
│   ├── build_findings_review.py  builds the findings review workbook template (Python 3, openpyxl)
│   └── guardrail/                blocks identifying info and secrets from being committed (docs/guardrail.md)
├── examples/                     placeholder inputs and registers (never commit a filled copy)
│   ├── hr.example.csv, iga-*.example.csv, role-definitions / rule-map   inputs for 06, 14, 15
│   ├── pam-accounts.example.csv               input for 26
│   ├── population-exclusions.example.csv      input for 27
│   ├── pilot-test-cases.example.csv           input for 29
│   ├── kpi-definitions.example.psd1           input for Get-KpiSummary
│   ├── deliverable-map.example.psd1           input for New-EvidencePackage
│   ├── finding-rules.psd1                     input for New-FindingDrafts
│   ├── findings-review.example.csv            Review Trail export, input for New-EngagementDashboard
│   └── readiness checklist, exception / status register, acceptance log, ownership matrix
├── templates/
│   └── findings-review.template.xlsx          blank findings review workbook (pinned by SHA-256 in the guardrail)
└── docs/
    ├── getting-started.md        modules, access, sign-in, common parameters, locked-down hosts
    ├── scripts/                  one page per script: parameters, outputs, permissions, pilot check
    ├── permissions.md            roles, scopes, licences and modules per script
    ├── outputs.md                run folder, dataset statuses, handling the output
    ├── pilot-runbook.md          how to verify each script in the real environment before handover
    ├── jira-finding-template.md  how to log each finding in Jira: fields, description template, severity guide
    ├── evidence-tools.md         before / after, KPIs, evidence package
    ├── engagement-kit.md         running an engagement end to end with the kit
    ├── templates/                registers and runbook template
    ├── troubleshooting.md        symptoms, causes and fixes
    ├── guardrail.md              no identifying info in the repo: rules, placeholders, setup
    └── design-and-testing.md     why the scripts are built this way, and how they were tested
```

## Author

Written and maintained by Jay Klinkowsky ([jay@everydayidentity.tech](mailto:jay@everydayidentity.tech)). Issues and pull requests are welcome; for anything else, email. <!-- guardrail:allow public author contact, intentional -->

## License

[MIT](LICENSE). Provided as is, without warranty. Review the scripts and run `tools/Test-ReadOnly.ps1` before using them in your environment.
