# Engagement kit

**Tools:** [`New-Engagement.ps1`](../tools/New-Engagement.ps1), [`Start-Engagement.ps1`](../tools/Start-Engagement.ps1), [`New-AccessRequest.ps1`](../tools/New-AccessRequest.ps1), [`New-FindingDrafts.ps1`](../tools/New-FindingDrafts.ps1), [`New-EngagementDashboard.ps1`](../tools/New-EngagementDashboard.ps1) · **Version:** 1.0.0 · **Template:** [`templates/findings-review.template.xlsx`](../templates/findings-review.template.xlsx)

> One way to run an identity discovery engagement from start to finish, the same way at every client.

The kit wraps the discovery scripts and the evidence tools in a repeatable workflow:

1. set up an engagement folder
2. ask the client for exactly the access the scripts need
3. close the readiness checklist
4. run the baseline
5. package the evidence and compute the KPIs
6. turn the results into draft findings and review them in a workbook
7. show where everything stands on one page

Every tool in the kit is local. None connects to anything or changes anything outside its own output: each passes [`Test-ReadOnly.ps1`](../tools/Test-ReadOnly.ps1). They work in Windows PowerShell 5.1 and PowerShell 7.

- [End-to-end flow](#end-to-end-flow)
- [The engagement folder](#the-engagement-folder)
- [Tools](#tools)
- [Findings pipeline](#findings-pipeline)
- [How the pieces connect](#how-the-pieces-connect)
- [Reusing the kit at the next client](#reusing-the-kit-at-the-next-client)
- [What never goes in this repository](#what-never-goes-in-this-repository)

## End-to-end flow

```powershell
# 1. Create the engagement folder (outside this repository, in the approved evidence location)
.\tools\New-Engagement.ps1 -Path D:\Engagements\Programme1 -Name 'Identity programme'

# 2. Open the menu; every step below is one option
.\tools\Start-Engagement.ps1 -EngagementPath D:\Engagements\Programme1 -Server dc01.contoso.local
```

| Step | Menu | What you do | Tool |
|---|---|---|---|
| 1. Access request | 1 | Send the request to the client: roles, Graph permissions, other access, input files, licences | `New-AccessRequest.ps1` |
| 2. Readiness | 2 | Work `registers\readiness-checklist.csv` until every row is Closed or Waived; check what this machine can run | `Start-Discovery.ps1 -ListOnly` |
| 3. Baseline runs | 3 | Run 31 first (licences), then the rest as access allows. Record every dataset that is not Completed in `registers\status-register.csv` | `Start-Discovery.ps1` |
| 4. Evidence package | 4 | Intake log, hash re-check, per-deliverable status | `New-EvidencePackage.ps1` |
| 5. KPIs | 5 | KPI values over the script 27 denominators | `Get-KpiSummary.ps1` |
| 6. Findings | 8 | Draft findings from the latest runs; paste them into the review workbook; each role reviews in turn | `New-FindingDrafts.ps1` + workbook |
| 7. Dashboard | 6 | One page for the status meeting | `New-EngagementDashboard.ps1` |

Repeat steps 3 to 7 after each collection round, each change, and before each gate. The engagement folder's `README.md` lists the same steps with the exact commands for that folder (menu option 7 shows it).

## The engagement folder

`New-Engagement.ps1` creates:

| Folder | Holds |
|---|---|
| `evidence\` | Run folders of the scripts and the evidence tools. Never edit a file inside a run folder. Move a failed or abandoned run into `evidence\_aborted\` (or `<script folder>\_aborted\`); every tool ignores `_aborted` |
| `registers\` | Working copies of the registers and input templates from `examples\`, with `.example` dropped: readiness checklist, status register, exception register, deliverable acceptance log, ownership matrix, population exclusions, pilot test cases, and the input templates for HR, PAM, IGA and role files |
| `config\` | `kpi-definitions.psd1`, `deliverable-map.psd1`, `finding-rules.psd1` (agree the first two with the programme owner), `engagement.psd1` (name and date) |
| `findings\` | Evidence notes (`F-xx.md`), `finding-ledger.csv`, and `findings-review.csv` (the Review Trail export for the dashboard). Keep the working copy of the workbook here too |
| `templates\` | `findings-review.xlsx`, the blank review workbook |
| `reports\` | Access requests, finding drafts and dashboards |

The copied registers hold placeholder rows (`contoso`, `Role1`, `User1`). Replace them with the engagement's own values.

## Tools

### New-Engagement

| Parameter | Default | Purpose |
|---|---|---|
| `-Path` | required | The engagement folder. Refused if it is inside this repository |
| `-Name` | required | Engagement name for the README and the dashboard title |
| `-Force` | off | Use a folder that already has files in it. Only adds what is missing; never overwrites a file, so filled registers are safe |

Without `-Force`, a folder with anything in it is refused.

### Start-Engagement

A text menu for one engagement folder. It only calls the other tools with that folder's paths.

| Option | Runs |
|---|---|
| 1 Access request | `New-AccessRequest.ps1 -OutputRoot reports` |
| 2 Readiness check | `Start-Discovery.ps1 -ListOnly -Server <dc> -OutputRoot evidence` |
| 3 Run discovery scripts | `Start-Discovery.ps1 -Server <dc> -OutputRoot evidence` (pick list) |
| 4 Evidence package | `New-EvidencePackage.ps1 -EvidenceRoot evidence -DeliverableMapPath config\deliverable-map.psd1` |
| 5 KPI summary | `Get-KpiSummary.ps1 -EvidenceRoot evidence -KpiDefinitionPath config\kpi-definitions.psd1` |
| 6 Dashboard | `New-EngagementDashboard.ps1` with evidence, `registers\readiness-checklist.csv`, `registers\status-register.csv` and `findings\findings-review.csv` when present |
| 7 Show README | The engagement README, in the console |
| 8 Draft findings | `New-FindingDrafts.ps1 -EvidenceRoot evidence -RulesPath config\finding-rules.psd1 -LedgerPath findings\finding-ledger.csv -ReviewTrailCsv findings\findings-review.csv` |
| D | Set the domain controller |
| Q | Quit |

| Parameter | Default | Purpose |
|---|---|---|
| `-EngagementPath` | required | The engagement folder |
| `-Server` | session value | Domain controller for the AD scripts. Asked for once and kept in `$global:IamEngagementServer` for the PowerShell window |
| `-AuthMode` | `Delegated` | Sign-in mode for the access request |
| `-Option` | menu | Run these options and exit, e.g. `-Option 5,8,6`. Option 3 needs the pick list, so it is skipped here |

### New-AccessRequest

Builds the access request from the discovery catalog ([`tools/discovery-catalog.psd1`](../tools/discovery-catalog.psd1)), so it always matches the scripts.

| Parameter | Default | Purpose |
|---|---|---|
| `-Select` | every script | Script numbers, e.g. `-Select 01,02,04` |
| `-AuthMode` | `Delegated` | `Delegated` words the Graph permissions as delegated, consented for the operator's sign-in. `AppCertificate` words them as application permissions on a read-only app registration and adds the app-only steps (certificate, Exchange.ManageAsApp, Azure Reader for the app) |
| `-Format` | `Markdown`, `Csv`, `Html` | One or more |
| `-Title` | `Access request: read-only identity discovery` | Heading |
| `-OutputRoot` | `tools\output` | Use the engagement's `reports\` |

Sections:

1. **Entra directory roles**, deduplicated, with the scripts that need each.
2. **Microsoft Graph permissions**, deduplicated, all read-only. Permissions needed only with an optional switch are marked as such. `DeviceLocalCredential.ReadBasic.All` and `BitlockerKey.ReadBasic.All` are marked *metadata only, never secrets*.
3. **Other access**: Active Directory, domain controller event logs, Exchange, Purview, Azure, AWS, the SOC notice for 18, and the run order for 26.
4. **Input files**, with the template in `examples\` and empty *Client owner* and *Due* columns.
5. **Licence dependencies.**
6. **Read-only statement**, with the result of `Test-ReadOnly.ps1` for the selected scripts.

Output: `<OutputRoot>\New-AccessRequest\<timestamp>Z\` with `access-request.md` (paste into a ticket), `access-request.html` (open, copy into an email, or print to PDF), one CSV per section, and the usual `run-manifest.json`, `dataset-status.csv` (SHA-256 of every file) and `run.log`.

### New-FindingDrafts

See [Findings pipeline](#findings-pipeline).

### New-EngagementDashboard

One self-contained HTML page: no external files, fonts or scripts, light and dark by the browser's setting, and it prints cleanly.

| Parameter | Default | Purpose |
|---|---|---|
| `-EvidenceRoot` | none | Latest run of each script: dataset counts by status, run age, version. Also the latest `Get-KpiSummary` run (its `kpi-summary.csv` is hash-checked) |
| `-ReadinessCsv` | none | Readiness checklist: Closed / Waived / In progress / Open counts and the items still open |
| `-FindingsCsv` | none | Review Trail CSV export: findings by stage, severity and client decision, and the list. A blank Stage is worked out the way the workbook does it |
| `-StatusRegisterCsv` | none | Status register: every item not Completed, with rationale, owner, risk and disposition |
| `-Title` | `Engagement dashboard` | Heading |
| `-StaleAfterDays` | `30` | Latest runs older than this are marked |
| `-OutputRoot` | `-EvidenceRoot` | Use the engagement's `reports\` |

Every input is optional; a section without its input says *Not provided*. Tiles: scripts run, datasets blocked, KPIs meeting target, readiness closed or waived, findings decided, evidence items not completed.

**Counts and statuses only.** From run folders it reads `run-manifest.json` and `dataset-status.csv`, never the data files, so the page holds no account names. The registers are shown as written, so keep names out of them. Every value is HTML-encoded.

Output: `<OutputRoot>\New-EngagementDashboard\<timestamp>Z\engagement-dashboard.html`, `summary.csv` (the headline numbers), manifest and log.

## Findings pipeline

```
discovery runs  ->  New-FindingDrafts  ->  finding-drafts.csv  ->  Review Trail (workbook)  ->  CSV export  ->  dashboard
                        |                                               |
                  finding-ledger.csv (stable IDs)              Engineer -> Architect -> Zero Trust Architect -> Client
                  findings\F-xx.md (evidence notes)
```

1. Run the scripts (step 3). New results, including scripts that were blocked on access and run later, are picked up on the next pass.
2. Run **New-FindingDrafts** (menu option 8). It writes the evidence note for every new finding into `findings\` and a `finding-drafts.csv` with the new findings only.
3. Open the working copy of the workbook, go to the **Review Trail** sheet, select the first empty row's **ID** cell and paste the rows of `finding-drafts.csv` (without the header). The columns are in the Engineer column order, so they land in the right place.
4. Each role completes its own column group in order: Identity Architect (severity, root cause, solution, effort, gate), Zero Trust Architect (pillar, principle, maturity, alignment), then the client decision authority (decision). *Stage*, *Waiting on* and *Disposition* update on their own.
5. Export the Review Trail sheet to `findings\findings-review.csv` (File > Save a copy > CSV) for the dashboard. The tool skips the section-title row above the headers.

### Rules

[`examples/finding-rules.psd1`](../examples/finding-rules.psd1) holds one rule per candidate finding (91 rules across scripts 01 to 31). Each names a script's run folder, a `summary.csv` metric, a condition and a threshold, plus the draft text: finding, observed severity, HITRUST CSF reference, Zero Trust pillar and principle, and an initial recommendation. `New-Engagement` copies it to `config\finding-rules.psd1` so thresholds can be tuned per engagement. Keep every `RuleId`: the ledger depends on it.

A rule is evaluated only when its evidence is usable. No run gives **NoRun**. A missing or blank metric, a metric that says the read failed, a rule dataset that is Blocked, EvidenceUnavailable or Deferred, or a `summary.csv` that no longer matches its SHA-256 gives **NotEvaluable**. Nothing is ever drafted from evidence that is not there.

### Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-EvidenceRoot` | required | Folder holding the run folders |
| `-RulesPath` | `examples\finding-rules.psd1` | Rule file |
| `-LedgerPath` | `<EvidenceRoot>\findings\finding-ledger.csv` | Finding ledger; created when missing |
| `-FindingsFolder` | the ledger's folder | Where the evidence notes go |
| `-ReviewTrailCsv` | none | Review Trail export. IDs already in the workbook are never reused |
| `-IdPrefix` | `F-` | Finding ID prefix |
| `-StartNumber` | `1` | First number when the ledger (and `-ReviewTrailCsv`) is empty |
| `-ToolsRoot` | this tool's folder | Where `New-FindingEvidence.ps1` is |
| `-OutputRoot` | `-EvidenceRoot` | Use the engagement's `reports\` |

Output: `<OutputRoot>\New-FindingDrafts\<timestamp>Z\` with:

- `finding-drafts.csv`: new findings only, in the Review Trail Engineer columns. *Source and filter* starts with the rule ID, e.g. `[R-13-01] 13 summary.csv: Matched pairs: AD disabled but Entra enabled > 0`.
- `finding-evaluation.csv`: every rule with its value and result (New, Existing, NotTriggered, NotEvaluable, NoRun) and the reason.
- A copy of the ledger, plus `summary.csv`, the manifest and the log.

### The ledger

`finding-ledger.csv` maps each rule to its finding ID: `RuleId, FindingId, FirstSeenUtc, RunFolder, Value`.

- A rule that fires again in a later run keeps its ID. It is reported as **Existing** and not drafted again, because it is already in the workbook.
- New IDs continue from the highest ID in the ledger and in `-ReviewTrailCsv`. An ID that already has an evidence note in the findings folder (`F-xx.md`, e.g. a finding raised by hand) is skipped.
- **Findings raised by hand before the tool was used:** seed the ledger with a CSV of `RuleId,FindingId` rows, e.g. `R-13-01,F-07`. That rule then reuses F-07, and new IDs start above it.
- An evidence note that already exists is never overwritten. Notes are written by [`New-FindingEvidence.ps1`](../tools/New-FindingEvidence.ps1): scope (when the rule has a dataset filter), evidence with SHA-256, and closure with the rerun command and the target value.

## How the pieces connect

| From | To | How |
|---|---|---|
| Discovery catalog (`Roles`, `Scopes`, `OptionalScopes`, `OtherAccess`, `Inputs`, `Licence`) | Access request | `New-AccessRequest` reads the catalog. The catalog's `Scopes` match each script's `$RequiredScopes`; change both together, and update [permissions.md](permissions.md) |
| Run folders | Evidence package, KPIs, finding drafts, dashboard | Each tool reads the latest run per script and re-checks hashes |
| `config\deliverable-map.psd1`, `config\kpi-definitions.psd1` | Evidence package, KPIs | Their SHA-256 goes in each tool's run manifest |
| `config\finding-rules.psd1` + ledger | Finding drafts | Rules decide what is drafted; the ledger keeps IDs stable |
| Finding drafts | Review workbook | Paste into the Review Trail |
| Review Trail export, readiness checklist, status register | Dashboard | `-FindingsCsv`, `-ReadinessCsv`, `-StatusRegisterCsv` |

**Review workbook stages:** *Draft* (Engineer section only), *Architect reviewed* (Architect severity set), *With client* (Zero Trust alignment set), *Closed* (client decision set). The client decision sets the disposition:

- **Accept and remediate:** remediation backlog
- **Accept risk:** exception register
- **Defer:** status register
- **Reject:** the rationale is recorded

The blank workbook is [`templates/findings-review.template.xlsx`](../templates/findings-review.template.xlsx). It is built by [`tools/build_findings_review.py`](../tools/build_findings_review.py) (Python 3 with openpyxl): `python tools/build_findings_review.py --out findings-review.xlsx`.

**Gaps sheet:** the workbook also has a **Gaps** tab for everything that is a gap but not a counted finding. Each gap has a type:

- **Control:** a theme grouping findings.
- **Capability:** a missing or unused process or tool, often raised in a meeting.
- **Evidence:** not assessed yet.
- **Coverage:** no script measures it.
- **Decision:** waiting on a decision.

Gaps link to findings by ID and are counted on the Summary sheet. Keep them in a Markdown table ([example](../examples/gap-register.example.md)) and build the tab with `--gaps gap-register.md`, or fill the tab directly.

## Reusing the kit at the next client

1. Pull the latest `iam_scripts` and run `.\tools\Test-ReadOnly.ps1`.
2. `New-Engagement.ps1` to a new folder in that client's approved evidence location.
3. Tune `config\` for the programme: deliverables, KPIs and targets, and finding thresholds. The defaults are a starting point, not a standard.
4. Send the access request (option 1), selecting only the scripts in scope.
5. Run the flow above.

Nothing from one engagement folder is needed at the next. Start each one empty.

## What never goes in this repository

- Any engagement folder, or anything from one: run folders, filled registers, filled workbooks, finding drafts, evidence notes, ledgers, dashboards, access requests filled in for a client.
- Client names, tenant or domain names, hostnames, real IDs or people's names, in any file, comment or commit message. See [Guardrail](guardrail.md).
- Changes to `templates/findings-review.template.xlsx` that hold data. The template is a binary file pinned by SHA-256 in [`tools/guardrail/allowed-binaries.txt`](../tools/guardrail/allowed-binaries.txt). To change it:
  1. Rebuild it with the generator.
  2. Unzip it and search the XML for anything identifying.
  3. Update the hash in the same commit.

[← Back to README](../README.md)
