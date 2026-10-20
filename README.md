# IAM Discovery Scripts

Read-only PowerShell scripts that collect evidence for an identity and access management (IAM) gap analysis across **Microsoft Entra ID** and **on-premises Active Directory**.

Each script measures one gap, writes timestamped CSVs plus a run manifest, and can be rerun after remediation to show progress against the same baseline. The output is designed to stand up as audit evidence (for example in a HITRUST, NIST or CIS assessment): every run records who ran it, from where, when, with which permissions, and a SHA-256 hash of every file it produced.

> **Nothing in these scripts changes the directory.** Graph calls go through a single function that only sends HTTP `GET`. AD work uses only `Get-AD*` cmdlets. [`tools/Test-ReadOnly.ps1`](tools/Test-ReadOnly.ps1) proves this statically, without running anything, so a reviewer can confirm it in seconds.

---

## Contents

- [What it measures](#what-it-measures)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [Prerequisites](#prerequisites)
- [Authentication](#authentication)
- [The scripts](#the-scripts)
  - [01 - MFA coverage](#01---mfa-coverage)
  - [02 - Entra privileged access](#02---entra-privileged-access)
  - [03 - Apps and consents](#03---apps-and-consents)
  - [04 - AD privileged and service accounts](#04---ad-privileged-and-service-accounts)
  - [05 - AD group nesting](#05---ad-group-nesting)
  - [06 - JML timing](#06---jml-timing)
- [Output and evidence](#output-and-evidence)
- [Dataset statuses](#dataset-statuses)
- [Read-only guarantee](#read-only-guarantee)
- [Handling the output](#handling-the-output)
- [Locked-down environments](#locked-down-environments)
- [Using the results](#using-the-results)
- [Troubleshooting](#troubleshooting)
- [Design choices](#design-choices)
- [Testing](#testing)
- [Version history](#version-history)

---

## What it measures

| # | Script | Gap it measures | Source |
|---|--------|-----------------|--------|
| 01 | [`01-Get-MfaCoverage.ps1`](scripts/01-Get-MfaCoverage.ps1) | Inconsistent MFA coverage: Conditional Access policies and exclusions, MFA registration, single-factor and legacy-auth sign-ins | Entra |
| 02 | [`02-Get-PrivilegedAccess.ps1`](scripts/02-Get-PrivilegedAccess.ps1) | Privileged account sprawl in the cloud: active vs eligible roles, permanent assignments, role-holding groups, privileged-user hygiene | Entra |
| 03 | [`03-Get-AppsAndConsents.ps1`](scripts/03-Get-AppsAndConsents.ps1) | "Where is my data going": apps, service principals, application and delegated permissions, consent settings, credential hygiene | Entra |
| 04 | [`04-Get-ADPrivilegedAndServiceAccounts.ps1`](scripts/04-Get-ADPrivilegedAndServiceAccounts.ps1) | Privileged and service-account sprawl on-prem, including indirect admin rights through nesting | AD |
| 05 | [`05-Get-ADGroupNesting.ps1`](scripts/05-Get-ADGroupNesting.ps1) | Nested groups and group hygiene; the baseline for RBAC role mining | AD |
| 06 | [`06-Compare-JmlTiming.ps1`](scripts/06-Compare-JmlTiming.ps1) | Manual joiner/mover/leaver (JML) processes: joiner and leaver lag against HR, terminated-but-enabled accounts, orphans | AD + HR file (+ Entra, optional) |

The scripts gather facts. They do not score maturity or recommend fixes; that interpretation belongs in the analysis that uses the evidence.

## Repository layout

```
iam_scripts/
├── README.md                  this file
├── CHANGELOG.md               version history
├── .gitignore                 blocks evidence, keys and data exports from being committed
├── scripts/                   the six discovery scripts (self-contained, run independently)
├── tools/
│   └── Test-ReadOnly.ps1      static proof that the scripts cannot write to AD or Entra
└── docs/
    ├── permissions.md         roles, Graph scopes, licences and AD access needed
    └── outputs.md             every output file and column, with reading notes
```

## Quick start

```powershell
# 1. Confirm the scripts are read-only (AST scan only - nothing executes)
.\tools\Test-ReadOnly.ps1

# 2. Entra discovery, signing in as yourself
.\scripts\01-Get-MfaCoverage.ps1
.\scripts\02-Get-PrivilegedAccess.ps1
.\scripts\03-Get-AppsAndConsents.ps1

# 3. On-prem AD discovery
.\scripts\04-Get-ADPrivilegedAndServiceAccounts.ps1 -Server dc01.contoso.local
.\scripts\05-Get-ADGroupNesting.ps1 -Server dc01.contoso.local

# 4. JML timing against an HR export you supply
.\scripts\06-Compare-JmlTiming.ps1 -HrCsvPath .\hr-export.csv

# Full help for any script
Get-Help .\scripts\03-Get-AppsAndConsents.ps1 -Full
```

Results land in `scripts\output\<script>\<timestamp>Z\`. Start with `summary.csv` in each run folder.

## Prerequisites

| Need | Scripts | Detail |
|------|---------|--------|
| PowerShell 5.1 or 7.x | All | Written for both; tested on 7.4 |
| `Microsoft.Graph.Authentication` module | 01, 02, 03, (06 with `-IncludeEntraSignIn`) | The only Graph module required; all calls are raw `GET` requests |
| RSAT `ActiveDirectory` module | 04, 05, 06 | A standard domain account is normally enough to read |
| Entra directory role | 01, 02, 03 | **Global Reader** preferred; Security Reader + Reports Reader as a fallback |
| Graph read scopes | 01, 02, 03, 06 | Admin consent once; see [docs/permissions.md](docs/permissions.md) |
| Entra ID P1 | Sign-in data, registration details | Without it, those datasets are marked `EvidenceUnavailable` |
| Entra ID P2 / ID Governance | PIM eligibility (02) | Without it, script 02 falls back to plain role assignments |
| HR export CSV | 06 | See [HR file format](#hr-file-format) |

Install the modules if policy allows:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
# RSAT on Windows 10/11:
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

If module installs are blocked, Azure Cloud Shell in the tenant includes the Graph modules.

## Authentication

Graph scripts (01-03, and 06 with `-IncludeEntraSignIn`) support two modes, chosen with `-AuthMode`.

| Mode | When to use | Command |
|------|-------------|---------|
| `Delegated` (default) | You sign in interactively; data is limited to what your role can read | `.\scripts\01-Get-MfaCoverage.ps1` |
| `AppCertificate` | A dedicated read-only app registration with a certificate; suits repeatable or scheduled runs | `.\scripts\01-Get-MfaCoverage.ps1 -AuthMode AppCertificate -TenantId tenant-id-redacted -ClientId <app-id> -CertificateThumbprint <thumbprint>` |

Each script requests only the read scopes it needs and logs a warning if the token is missing any of them, or if it carries write scopes from an earlier consent (the script still only sends `GET`). Setup steps for app-only mode are in [docs/permissions.md](docs/permissions.md#app-registration-for-app-only-mode-optional).

## The scripts

Every script shares these parameters:

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-OutputRoot` | `scripts\output` | Where run folders are written |

Graph scripts also share `-AuthMode`, `-TenantId`, `-ClientId` and `-CertificateThumbprint` (see [Authentication](#authentication)). AD scripts share `-Server` (a domain controller or domain, blank for the session default) and, where relevant, `-SearchBase` (an OU, blank for the whole domain).

### 01 - MFA coverage

Measures whether MFA is actually enforced, not just registered.

**Collects**
- Every Conditional Access policy, flattened, with included and excluded users, groups, roles and apps resolved to names
- One row per exclusion, and the transitive members of every excluded group
- MFA registration for every user: registered vs capable, methods, SMS/voice, phone-only
- Successful single-factor sign-ins over a lookback window, aggregated by user, app and client, with legacy authentication flagged

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-SignInLookbackDays` | `7` | Days of sign-in logs to read (1-30) |
| `-MaxSignInRecords` | `50000` | Safety cap; the output is marked TRUNCATED if reached |
| `-SkipSignIns` | off | Skip the sign-in query (marked `Deferred`) |
| `-SkipExcludedGroupMembers` | off | Skip expanding excluded groups |

**Scopes:** `Policy.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`

**Start with:** `summary.csv`, then `ca-exclusions.csv` and `signins-singlefactor-success.csv`.

### 02 - Entra privileged access

Shows who holds directory roles, how (directly, through a group, permanently or just-in-time), and whether those accounts are well managed.

**Collects**
- Active role assignments, marked permanent or time-bound, direct or through a group
- Eligible (PIM) assignments
- Members of every role-holding group, expanded transitively
- Role-assignable groups and their owners
- One row per privileged user: sync source, last sign-in, MFA registration, Tier 0 role, and flags

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-StaleDays` | `90` | Days without sign-in before a privileged user is flagged |

**Scopes:** `RoleManagement.Read.Directory`, `Directory.Read.All`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`

The Tier 0 role list is a table at the top of the script and can be extended.

**Start with:** `summary.csv`, then `privileged-users.csv` sorted by `Flags`.

### 03 - Apps and consents

Builds the first version of the "where is my data going" map: which non-human identities are *authorised* to reach data, and how well they are governed.

**Collects**
- Tenant consent settings: whether users can consent to apps, whether the admin-consent workflow is on
- App registrations with owners, plus one row per secret or certificate with expiry status
- Service principals classified as this tenant, third party, managed identity or Microsoft
- Application permissions granted to each client, flagged as DataAccess or PrivilegeEscalation
- Delegated grants, admin vs user consent, with high-risk scopes flagged
- A per-app summary ranked for review (the "data movers" list)

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-CredentialWarningDays` | `30` | Credentials expiring within this window are flagged |
| `-LongLivedSecretDays` | `730` | Secrets with a longer lifetime are flagged |
| `-StaleDays` | `90` | Apps with no sign-in in this window are flagged |
| `-IncludeMicrosoftApps` | off | Include Microsoft first-party clients (numerous; rarely the question) |
| `-SkipSignInActivity` | off | Skip the service-principal sign-in report |

**Scopes:** `Application.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`

The high-risk permission list is a table at the top of the script and can be extended. Service-principal last sign-in uses a Graph **beta** report (still a `GET`).

**Start with:** `app-risk-summary.csv`. `TriageScore` only orders the list for review; it is not a risk rating, and the file shows what apps *can* reach, not what they moved.

### 04 - AD privileged and service accounts

Finds every account with admin rights on-prem, including rights gained indirectly through nested groups, and finds likely service accounts.

**Collects**
- Membership of every protected group (Domain Admins, Enterprise Admins, Schema Admins, Administrators, the Operators groups, DnsAdmins and any you add), expanded with the full nesting path
- One row per privileged account with hygiene flags: stale, password never expires, old password, SPN on a privileged user (Kerberoastable), pre-auth disabled, delegation, privileged only through nesting
- Service-account candidates from several detections (SPN, never-expiring password, name pattern, description, gMSA/sMSA), with the reasons listed
- Accounts with `adminCount=1` that are no longer in any protected group
- Circular nesting under privileged groups is detected and logged

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ServiceNamePatterns` | `svc*`, `svc-*`, `svc_*`, `sa-*`, `sa_*`, `*_svc`, `*-svc`, `srv-*` | Name patterns that indicate a service account |
| `-AdditionalPrivilegedGroups` | none | Custom admin groups to expand, e.g. `'Group1','Group2'` |
| `-StaleDays` | `90` | Days without logon before an enabled account is flagged |
| `-PasswordAgeWarningDays` | `365` | Passwords older than this are flagged |

**Start with:** `summary.csv`, then `ad-privileged-accounts.csv`. Service accounts are candidates found by heuristics; confirm with owners before reporting a count as fact.

### 05 - AD group nesting

Builds the full group-in-group graph in memory and reports structure and hygiene for every group.

**Collects**
- One row per group: type, scope, direct member counts, nesting depth below (`DepthDown`) and above (`DepthUp`), and flags (empty, no owner, no description, mail-enabled security group, deep nesting, circular nesting, naming-convention miss)
- One row per circular nesting loop

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-DeepNestingThreshold` | `3` | Groups nested at least this deep are flagged |
| `-NamingConventionRegex` | none | Regex a well-named group should match, e.g. `'^(RB|APP)-'` |

Reads every group once; run off-peak in large domains. Groups with 5,000 or more members are flagged `MemberListTruncated` because of the AD Web Services read limit.

**Start with:** `summary.csv`, then `ad-groups.csv` filtered on `Flags`.

### 06 - JML timing

Compares HR lifecycle dates with account state to show how well joiners and leavers are processed.

**Collects**
- Joiner lag: account created vs hire date (negative = pre-provisioned)
- Leaver lag: account disabled vs termination date
- Terminated in HR but still enabled
- Logon or sign-in after the termination date (AD, and Entra with `-IncludeEntraSignIn`)
- Active HR records with no AD account
- Enabled AD accounts with no HR match (orphan candidates)
- Summary with median, 90th percentile and maximum lags, and the percentage of leavers disabled within the SLA

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-HrCsvPath` | required | Path to the HR export |
| `-HrIdColumn` | `EmployeeId` | HR column holding the person's id |
| `-HrStatusColumn` | `EmploymentStatus` | HR column holding employment status |
| `-HrHireDateColumn` | `HireDate` | HR column holding the hire date |
| `-HrTermDateColumn` | `TerminationDate` | HR column holding the termination date |
| `-HrDateFormat` | invariant parse | Exact date format, e.g. `'MM/dd/yyyy'` |
| `-TerminatedStatusValues` | `Terminated`, `Inactive` | Status values that mean "left" |
| `-AdMatchAttribute` | `employeeID` | AD attribute holding the HR id |
| `-ExcludeNamePatterns` | `svc*`, `sa-*`, `sa_*`, `adm*`, `*admin*`, `test*` | Accounts excluded from the orphan list |
| `-LeaverSlaDays` | `1` | Days allowed between termination and disable |
| `-SkipDisableTimestamp` | off | Skip per-user replication metadata (faster, no leaver lag) |
| `-IncludeEntraSignIn` | off | Add Entra sign-in after termination (needs Graph) |

#### HR file format

Any CSV with one row per person. Only these four columns are read; rename them with the parameters above if the export differs.

```csv
EmployeeId,EmploymentStatus,HireDate,TerminationDate
1001,Active,2026-01-07,
1002,Terminated,2020-01-01,2026-09-30
```

**Caveats:** disable time is approximated from the last change to `userAccountControl`, so it can be later than the real disable if that attribute changed again. `lastLogonTimestamp` replicates on a 9-14 day cycle, so AD logon-after-termination is indicative; the Entra check is more precise.

**Start with:** `summary.csv`, then `jml-terminated-still-enabled.csv`.

## Output and evidence

```
scripts\output\
  01-MfaCoverage\
    20261020-140501Z\
      ca-policies.csv            data files (one per dataset)
      ca-exclusions.csv
      ...
      summary.csv                headline metrics for the status report
      dataset-status.csv         one row per dataset: status, rows, SHA-256, note
      run-manifest.json          who / where / when / scopes / parameters / datasets
      run.log                    timestamped log of the run
```

- All timestamps are UTC, ISO 8601, so files are independent of the regional settings of the machine that ran them.
- `run-manifest.json` records the Windows account and machine, the Graph account and app, the scopes in the token, the parameters used, and every dataset with its row count and SHA-256 hash.
- Each run gets a new folder, so reruns never overwrite earlier evidence. Compare `summary.csv` across runs to show change over time.

Every output file and column is described in [docs/outputs.md](docs/outputs.md).

## Dataset statuses

Every dataset ends in exactly one state, so missing evidence is visible rather than silent:

| Status | Meaning | What to do |
|--------|---------|------------|
| `Completed` | Data collected. Zero rows is still Completed. | Nothing |
| `Blocked` | Permission denied or the call failed | Fix access, rerun |
| `Deferred` | Skipped on purpose by a switch | Rerun without the switch when ready |
| `EvidenceUnavailable` | The tenant cannot produce it (e.g. licence not present) | Record as a finding |

## Read-only guarantee

The scripts are built so a reviewer can verify they change nothing:

1. **One Graph entry point.** All Graph traffic goes through `Invoke-GraphGet`, which calls `Invoke-MgGraphRequest -Method GET`. There is no other way the scripts talk to Graph.
2. **Read cmdlets only for AD.** Only `Get-AD*` cmdlets are used.
3. **Read scopes only.** The delegated sign-in requests read scopes only.
4. **Static proof.** [`tools/Test-ReadOnly.ps1`](tools/Test-ReadOnly.ps1) parses each script with the PowerShell AST, without running it, and fails if it finds:
   - any command with a state-changing verb (`New-`, `Set-`, `Remove-`, `Add-`, `Update-`, `Enable-`, `Disable-`, `Grant-`, `Revoke-`, `Move-`, `Reset-` and so on), outside a short allowlist of commands that only write to the local evidence folder
   - any `Invoke-MgGraphRequest` without `-Method GET`
   - `Invoke-RestMethod`, `Invoke-WebRequest`, `Invoke-Expression`, `Invoke-Command`, `Start-Process`

```powershell
.\tools\Test-ReadOnly.ps1                                      # all scripts
.\tools\Test-ReadOnly.ps1 -Path .\scripts\03-Get-AppsAndConsents.ps1
```

Exit code `0` means pass. Run it again after any edit.

## Handling the output

The CSVs contain identity data (names, UPNs, sign-in activity, group membership), and script 06 reads HR data. Treat every run folder as sensitive:

- Store output only in the location approved for evidence, **never in this repository**. `.gitignore` excludes `output/` and all CSV, JSON and log files as a safeguard.
- Follow the environment's retention rule and delete local copies once evidence is filed.
- Do not paste raw output into tools that are not approved for that data.
- The HR file's SHA-256 is recorded in the summary, so you can prove which export was used without keeping it alongside the results.

## Locked-down environments

If USB and downloads are blocked, bring the scripts in by whatever route policy allows, in this order:

1. **The organization's own code repository**, with review. This also gives a record of what was run.
2. **Paste or retype** into an editor on the work machine. Each script is self-contained, with configuration at the top.

`Test-ReadOnly.ps1` gives the approver a quick way to confirm nothing writes to the directory. If module installs are blocked, Azure Cloud Shell in the tenant includes the Graph modules.

## Using the results

A suggested order for a first discovery pass:

1. Run `Test-ReadOnly.ps1` and share the result with whoever approves the run.
2. Run 01, 02 and 03 once read access is granted. They answer the MFA, privileged-access and data-flow questions.
3. Run 04 and 05 from an approved management host.
4. Run 06 once an HR export is available.
5. Collect each `summary.csv` into the status update, with the `dataset-status.csv` for anything `Blocked` or `EvidenceUnavailable`.
6. After remediation, rerun the same scripts with the same parameters and compare summaries to show measured progress.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Module Microsoft.Graph.Authentication not found` | Module missing | Install it, or run from Azure Cloud Shell |
| Dataset `Blocked` with 403 / `Authorization_RequestDenied` | Role or scope missing | Check `ScopesInToken` in `run-manifest.json` against [docs/permissions.md](docs/permissions.md) |
| Dataset `EvidenceUnavailable` mentioning a licence | Tenant lacks Entra ID P1/P2 | Record as a finding; nothing to fix in the script |
| `signins-singlefactor-success` note says TRUNCATED | Hit `-MaxSignInRecords` | Shorter `-SignInLookbackDays` or a higher cap |
| `role-assignments-eligible` is `EvidenceUnavailable` | No PIM licence | Expected; active assignments still collected |
| Repeated `HTTP 429` warnings | Graph throttling | Handled automatically with back-off; large tenants just take longer |
| `HR file has no column ...` | Column names differ | Map them with `-HrIdColumn`, `-HrStatusColumn` and so on |
| "HR date values that failed to parse" above zero | Date format not recognized | Set `-HrDateFormat` |
| Many orphan candidates in script 06 | Service/admin accounts or a different match attribute | Extend `-ExcludeNamePatterns`, check `-AdMatchAttribute` |
| `Group ... not found; skipped` in script 04 | Group doesn't exist in this domain (e.g. forest-root groups in a child domain) | Informational |
| Execution policy blocks the script | Local policy | `Unblock-File` on the scripts, or follow the approved signing process |

## Design choices

- **One file per area, no shared module.** Each script can be reviewed, approved, transferred or retyped on its own. The helper block at the top of each script is intentionally identical across scripts.
- **Minimal dependencies.** Graph scripts need only `Microsoft.Graph.Authentication`; AD scripts need only RSAT.
- **Configuration at the top.** Every environment-specific value is a parameter with a placeholder default (`contoso.local`, `tenant-id-redacted`). Nothing environment-specific is stored in the repository.
- **Throttling and paging handled.** Graph requests follow every page and back off on `429` and `5xx`, so large tenants don't produce silently incomplete results.
- **Facts, not conclusions.** Flags and triage scores are sorting aids. Scoring, maturity and recommendations belong in the analysis.

## Testing

Before release, every script was:

- parse-checked and linted with PSScriptAnalyzer (no errors or warnings outside documented exclusions)
- checked with `Test-ReadOnly.ps1`, including a negative test that confirmed it catches a write cmdlet and a non-GET Graph call
- run end to end on PowerShell 7.4 against mocked Graph and AD responses using placeholder data, covering paging, missing licences, unresolved objects, circular nesting and expired credentials

The scripts have **not yet been run against a live tenant**. Expect to tune naming patterns and thresholds on the first run, and report anything unexpected so the scripts can be corrected.

## Version history

See [CHANGELOG.md](CHANGELOG.md).
