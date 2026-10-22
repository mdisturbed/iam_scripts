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
| 01 | [MFA coverage](docs/scripts/01-mfa-coverage.md) | Is MFA actually enforced everywhere, or only registered? | Entra |
| 02 | [Entra privileged access](docs/scripts/02-entra-privileged-access.md) | Who holds Entra admin roles, how, and are those accounts well managed? | Entra |
| 03 | [Apps and consents](docs/scripts/03-apps-and-consents.md) | Which apps can reach our data, and are they governed? | Entra |
| 04 | [AD privileged and service accounts](docs/scripts/04-ad-privileged-and-service-accounts.md) | Who has admin rights on-prem (including via nesting), and where are the service accounts? | AD |
| 05 | [AD group nesting](docs/scripts/05-ad-group-nesting.md) | How deep and messy is group nesting, and how healthy are groups? | AD |
| 06 | [JML timing](docs/scripts/06-jml-timing.md) | How quickly are joiners provisioned and leavers disabled, compared with HR? | AD + HR file (+ Entra) |
| 07 | [Role mining](docs/scripts/07-role-mining.md) | Which groups do people in the same department or job code share, and is the HR data clean enough to drive roles? | AD |
| 08 | [Extension attribute inventory](docs/scripts/08-extension-attribute-inventory.md) | Which custom / extension attributes are free to carry new data? | AD (+ Entra) |
| 09 | [Mail forwarding and external sharing](docs/scripts/09-mail-forwarding-and-external-sharing.md) | Is mail being forwarded out, and how open is SharePoint / OneDrive sharing? | Exchange Online + SharePoint |
| 10 | [Guest access](docs/scripts/10-guest-access.md) | How many guests are there, are they used, and what can they reach? | Entra |
| 11 | [Azure RBAC](docs/scripts/11-azure-rbac.md) | Who has access to Azure resources, at what scope, and to deleted principals? | Azure + Entra |
| 12 | [Stale accounts](docs/scripts/12-stale-accounts.md) | Which identities are really unused once AD and Entra activity are combined? | AD + Entra |
| 13 | [Hybrid sync scope](docs/scripts/13-hybrid-sync-scope.md) | What actually syncs from AD to Entra, and where do they disagree? | AD + Entra |
| 14 | [IGA reconciliation](docs/scripts/14-iga-reconciliation.md) | Where does the IGA platform's view of accounts and group access differ from AD? | AD + IGA export |
| 15 | [Rule-managed access](docs/scripts/15-rule-managed-access.md) | Are applied roles, HR-expected roles and actual group membership in step? | AD + role files |
| 16 | [Device posture](docs/scripts/16-device-posture.md) | Are devices joined, managed and compliant, and does Conditional Access rely on it? | Entra + Intune |
| 17 | [AWS IAM posture](docs/scripts/17-aws-iam-posture.md) | Which AWS users, keys, roles, trusts and permission sets exist, and which are risky? | AWS |
| 18 | [AD delegation](docs/scripts/18-ad-delegation.md) | Who has dangerous rights through AD permissions, and which real accounts end up holding them? | AD |
| 19 | [DC authentication protocols](docs/scripts/19-dc-authentication-protocols.md) | Who still uses NTLM (v1 especially) or RC4/DES Kerberos? | DC event logs |
| 20 | [Governance coverage](docs/scripts/20-governance-coverage.md) | What share of apps, groups and roles is actually covered by access reviews? | Entra ID Governance |
| 21 | [Identity risk](docs/scripts/21-identity-risk.md) | Who is at risk right now, and does Conditional Access act on risk? | Entra ID Protection |
| 22 | [PIM role settings](docs/scripts/22-pim-role-settings.md) | What does it actually take to activate each admin role? | Entra PIM |
| 23 | [AD attribute population](docs/scripts/23-ad-attribute-population.md) | Which attributes does the schema allow, and how many objects actually have a value in each? | AD |
| 24 | [CA report-only impact](docs/scripts/24-ca-reportonly-impact.md) | Who would a report-only Conditional Access policy block or challenge if it were switched on? | Entra sign-in logs |
| 25 | [Purview classification and DLP](docs/scripts/25-purview-classification.md) | What can classify regulated data, what is switched on, and how much tagged content exists where? | Microsoft Purview |
| 26 | [PAM vault coverage](docs/scripts/26-pam-vault-coverage.md) | Which privileged accounts are managed in the PAM vault, and which are not? | PAM export + 02/04/11/17 |

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

1. Run `Test-ReadOnly.ps1` and share the result with whoever approves the run.
2. Pilot each script yourself using the [pilot runbook](docs/pilot-runbook.md).
3. Build the HTML report with `tools/New-DiscoveryReport.ps1` for the status update: headline metrics, change since the previous run, and every `Blocked` or `EvidenceUnavailable` dataset.
4. Log each finding in Jira with the [finding template](docs/jira-finding-template.md); `tools/New-FindingEvidence.ps1` pre-fills the Evidence and Closure sections from the run folder.
5. After remediation, rerun with the same parameters and compare summaries; that rerun is the finding's closure evidence.

> **Contributing?** Read [CONTRIBUTING.md](CONTRIBUTING.md) and run `.\tools\guardrail\Install-Guardrail.ps1` once after cloning. See [Guardrail](docs/guardrail.md).

## Documentation

| Page | Covers |
|------|--------|
| [Getting started](docs/getting-started.md) | Modules, access and licences, sign-in modes, common parameters, every script with typical parameters, locked-down hosts |
| [Script reference](docs/scripts/README.md) | One page per script |
| [Permissions](docs/permissions.md) | Roles, scopes, licences and modules per script; app-only setup |
| [Output and evidence](docs/outputs.md) | Run folder, manifest, dataset statuses, handling the files |
| [Pilot runbook](docs/pilot-runbook.md) | Moving a script from mock-tested to pilot-verified before handover |
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
├── scripts/                      the twenty-six discovery scripts (self-contained, run independently)
├── tools/
│   ├── Test-ReadOnly.ps1         static proof that the scripts cannot write anything
│   ├── Start-Discovery.ps1       launcher: readiness check, pick list, runs scripts, run summary
│   ├── New-DiscoveryReport.ps1   one-page HTML report from the evidence folder (counts only)
│   ├── discovery-catalog.psd1    script list and what each needs, shared by the two above
│   ├── New-FindingEvidence.ps1   pre-fills a Jira finding's Scope, Evidence and Closure from a run folder
│   └── guardrail/                blocks identifying info and secrets from being committed (docs/guardrail.md)
├── examples/                     placeholder input templates for scripts 06, 14, 15 and 26
│   ├── hr.example.csv
│   ├── iga-accounts.example.csv
│   ├── iga-assignments.example.csv
│   ├── pam-accounts.example.csv
│   ├── role-definitions.example.csv
│   └── rule-map.example.csv
└── docs/
    ├── getting-started.md        modules, access, sign-in, common parameters, locked-down hosts
    ├── scripts/                  one page per script: parameters, outputs, permissions, pilot check
    ├── permissions.md            roles, scopes, licences and modules per script
    ├── outputs.md                run folder, dataset statuses, handling the output
    ├── pilot-runbook.md          how to verify each script in the real environment before handover
    ├── jira-finding-template.md  how to log each finding in Jira: fields, description template, severity guide
    ├── troubleshooting.md        symptoms, causes and fixes
    ├── guardrail.md              no identifying info in the repo: rules, placeholders, setup
    └── design-and-testing.md     why the scripts are built this way, and how they were tested
```

## Author

Written and maintained by Jay Klinkowsky ([jay@everydayidentity.tech](mailto:jay@everydayidentity.tech)). Issues and pull requests are welcome; for anything else, email. <!-- guardrail:allow public author contact, intentional -->

## License

[MIT](LICENSE). Provided as is, without warranty. Review the scripts and run `tools/Test-ReadOnly.ps1` before using them in your environment.
