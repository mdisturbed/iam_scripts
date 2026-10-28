# Changelog

All notable changes to these scripts are recorded here. Each script also carries its own `$ScriptVersion`, which is written to every run manifest, so evidence can always be tied to the exact code that produced it.

## 1.10.0 - 2026-10-28

Engagement kit. Packages the engagement workflow so it runs the same way at every client: engagement folder, access request, readiness, baseline runs, evidence package, KPIs, draft findings, review workbook and a one-page dashboard. Every new tool is local, reads run folders and registers only, writes only its own output, and passes `Test-ReadOnly.ps1`. See `docs/engagement-kit.md`.

### Added
- `tools/New-Engagement.ps1` (1.0.0): creates an engagement folder (`evidence`, `registers`, `config`, `findings`, `templates`, `reports`) with working copies of every register, input template, KPI definition, deliverable map, finding rule file and the review workbook, plus a README with the run order and exact commands for that folder. Refuses a non-empty folder unless `-Force`, and with `-Force` never overwrites a file. Refuses a folder inside the repository.
- `tools/Start-Engagement.ps1` (1.0.0): text menu for an engagement folder (access request, readiness check, discovery runs, evidence package, KPIs, dashboard, README, draft findings). Remembers the domain controller for the session. `-Option` runs options unattended.
- `tools/New-AccessRequest.ps1` (1.0.0): client-ready access request from the discovery catalog for the selected scripts, in Markdown, HTML and CSV. Covers:
  - Entra roles and Graph permissions, deduplicated, worded for delegated or app-only sign-in; optional-switch permissions are marked, and `DeviceLocalCredential.ReadBasic.All` and `BitlockerKey.ReadBasic.All` are marked metadata only, never secrets
  - other access, including the SOC notice for 18 and the app-only steps
  - input files with templates and a client-owner column
  - licence dependencies
  - a read-only statement with the `Test-ReadOnly.ps1` result
- `tools/New-FindingDrafts.ps1` (1.0.0) and `examples/finding-rules.psd1` (90 rules across scripts 01 to 31): draft engineer findings from summary metrics of the latest runs.
  - Never drafts from Blocked, EvidenceUnavailable or Deferred evidence, from a missing or blank metric, or from a `summary.csv` that fails its hash check.
  - A ledger (`finding-ledger.csv`) keeps finding IDs stable across runs; it can be seeded for findings raised by hand, and `-ReviewTrailCsv` keeps IDs already in the workbook from being reused; an ID that already has an evidence note is skipped. Values written with a decimal comma (`54,1`) are read as numbers.
  - Writes an evidence note per new finding through `New-FindingEvidence.ps1`.
  - `finding-drafts.csv` has the new findings only, in the Review Trail Engineer column order, so the rows paste straight into the workbook; `finding-evaluation.csv` records every rule's result and reason.
- `tools/New-EngagementDashboard.ps1` (1.0.0): one self-contained HTML page (no external resources, light and dark, prints cleanly) with:
  - discovery runs: dataset statuses per script and run age; `_aborted` folders are ignored
  - KPIs from the latest `Get-KpiSummary` run, hash-checked
  - the readiness checklist
  - findings by stage, severity and client decision, from the Review Trail export
  - status register items not completed

  Counts and statuses only; every value HTML-encoded.
- `templates/findings-review.template.xlsx`: blank findings review workbook (Engineer, Architect, Zero Trust Architect and client sections; calculated Stage, Waiting on and Disposition). Built by `tools/build_findings_review.py`.
- `examples/findings-review.example.csv`: Review Trail CSV export with two placeholder rows, the input for the dashboard.
- `docs/engagement-kit.md`.

### Changed
- `tools/discovery-catalog.psd1`: every script now carries its access requirements: `Roles`, `OptionalRoles` (where a switch needs one), `Scopes` (exactly the script's default `$RequiredScopes`), `OptionalScopes` (opt-in switches), `OtherAccess`, `Inputs` (with template names) and `Licence`. `Start-Discovery.ps1` and `New-DiscoveryReport.ps1` are unchanged and still read it.
- Guardrail: a blocked file type is now allowed only when `tools/guardrail/allowed-binaries.txt` lists its path with the SHA-256 of its exact content (`PinnedBinariesFile` in `rules.psd1`).
  - Changed content at a pinned path fails as `pinned-binary-changed`.
  - An unlisted `.xlsx` still fails as `blocked-file-type`.
  - An unreadable list line fails closed.
  - `Test-Guardrail.ps1` covers all of these.
  - `.gitignore` allows only `templates/*.template.xlsx`.
- README, `docs/getting-started.md`, `docs/permissions.md`, `docs/templates/README.md` and `docs/guardrail.md` point to the kit.

### Notes
- Mock-tested on PowerShell 7.4 with fake engagement folders. Not yet run on Windows PowerShell 5.1; run each new tool once there before handover.

## 1.9.3 - 2026-10-27

Readiness and acceptance evidence, mapped from the SOW acceptance criteria and assumptions.

### Added
- `31-Get-LicenceInventory.ps1` (1.0.0): subscribed SKUs (enabled, suspended, warning, assigned, available), every service plan with its provisioning status, and a capability check (Entra ID P1 / P2, ID Governance, Workload Identities, Intune, Defender for Identity and Office 365, Purview information protection, DLP, insider risk and communication compliance, Exchange, SharePoint) using plan names from Microsoft's service plan reference. With `-EvidenceRoot`, lists every dataset in the latest runs that came back EvidenceUnavailable. Signs in with `Directory.Read.All` by default; `-GraphScope LicenseAssignment.Read.All` is the least-privileged option.
- `examples/readiness-checklist.example.csv`: the ten pre-project prerequisites, each closed with evidence or formally waived (reason, approver, date).
- `examples/deliverable-acceptance-log.example.csv`: submission, review due date (5 business days by default), decision (Accepted, CommentsReceived, DeemedAccepted), comments and resubmission.

### Changed
- `examples/status-register.example.csv`: columns now match the acceptance criteria for blocked and deferred items: `EvidenceState`, `Rationale`, `Owner`, `Risk`, `Disposition`, `RecommendedFollowOn` (replacing `Status`, `StatusReason`, `TargetTreatment`).

## 1.9.2 - 2026-10-27

### Fixed
- All Graph scripts (01, 02, 03, 08, 09, 10, 11, 12, 13, 16, 20, 21, 22, 24, 27, 28, 29, 30): `Invoke-GraphGet` now retries client-side timeouts, not just 429 and 5xx. A request that hits the Graph client timeout (`HttpClient.Timeout`, a canceled or timed-out request) or returns HTTP 408 or 504 is retried with the same back-off, up to 6 times, with a WARN line each time. Before, one slow sign-in query made the whole dataset Blocked.

### Changed
- `01-Get-MfaCoverage.ps1` 1.1.2, `24-Get-CaReportOnlyImpact.ps1` 1.1.1, `29-Test-PilotOutcome.ps1` 1.0.1: sign-in reads over a lookback window are now split into time slices (new `-SignInSliceHours`, default 24, range 1-168). Each slice is one query with `createdDateTime ge <start> and createdDateTime lt <end>`. Slices do not overlap and together cover exactly the lookback. This applies to 01 (interactive and non-interactive single-factor), 24 (all sign-in reads) and 29 (the `-CheckScopeLeak` read; per-user reads are unchanged).
- Slices are read newest first. In 01 and 29 the window ends at the run start, so both 01 sign-in datasets cover the same window. `-MaxSignInRecords` counts across all slices. When it is reached, the note gives the window actually covered (earliest sign-in read up to the run time).
- If a slice still fails after retries, the other slices are kept and the dataset is marked Partial. The note lists the missing windows in UTC. If every slice fails, the dataset is Blocked or EvidenceUnavailable as before. A 400, 401, 403 or 404 stops the read at once, since every slice would fail the same way.
- 24 adds the `SignInSlicesNotRead` flag and a *Sign-in slices not read* summary row (blank, with the reason, when the sign-ins could not be read at all).
- Slice boundaries in the filter are formatted with the invariant culture, so the query is the same on any regional setting.
- Other Graph scripts get a patch version bump for the retry change only.
- Sign-in slices end with `createdDateTime lt <end>`. Graph documents only `eq`, `le` and `ge` for that property, so if `lt` is rejected the read switches to `le` once and drops sign-ins that appear in two adjacent slices (matched by sign-in id).

## 1.9.1 - 2026-10-27

### Fixed
- `01-Get-MfaCoverage.ps1` 1.1.1: `signins-singlefactor-success` was always Blocked with "Bad Request". The filter uses `authenticationRequirement`, which exists only on the beta sign-in resource, so the v1.0 endpoint rejected it. The query now goes to beta (the non-interactive query already did). Rerun 01 to fill this dataset.

## 1.9.0 - 2026-10-26

Gate evidence release. Closes the gaps found when the scripts were mapped to the deliverables and success criteria of a staged identity programme (baseline, pilot, staged change, operational readiness, final evidence). Everything stays read-only.

### Added
- `27-Get-IdentityPopulation.ps1` (1.0.0): one agreed in-scope identity population from AD, Entra and an optional HR export. Every identity is classified (human workforce, admin, service, break-glass, guest, external member, resource, test, unclassified) with the rule that matched. Writes `population-denominators.csv`, the standard denominators every KPI divides by, with written definitions an approver can sign. Approved exclusions come from a file with approver and expiry; expired ones are not applied. Also writes the HR vs AD vs Entra reconciliation.
- `28-Export-CaPolicySnapshot.ps1` (1.0.0): Conditional Access policies, named locations, authentication strengths, the authentication methods policy and security defaults as raw JSON plus flattened CSV, with a canonical per-policy hash. With `-BaselineRunFolder`, per-object drift with the changed paths. The baseline's own hashes are checked first. This is the pre-change baseline and the rollback proof (after a rollback every policy shows `Unchanged`).
- `29-Test-PilotOutcome.ps1` (1.0.0): marks each expected and adverse pilot test case Pass, Fail, NoEvidence or Blocked from the sign-in logs, citing the sign-in (correlation ID) used as evidence. It can also check pilot-group membership and list users outside the pilot that a pilot policy enforced on (scope leak).
- `30-Get-AccessReviewEvidence.ps1` (1.0.0): one row per access-review decision (reviewer, decision, justification, recommendation, apply result, stage) for reviews in a window, and the exceptions to follow up: not reviewed, deny not applied, self-review, approved without a required justification, decided against recommendation, privileged left unreviewed, no reviewers contacted, overdue.
- `tools/Compare-RunFolders.ps1`: before/after evidence from two runs of the same script. Gives row-level adds, removes and changes, plus metric deltas. Both folders are hash-checked first.
- `tools/Get-KpiSummary.ps1`: KPIs from the latest runs, divided by the script 27 population. Every value carries its source runs and hashes. Nothing is computed from Blocked or EvidenceUnavailable data. Values are marked Partial when the numerator and denominator come from runs far apart.
- `tools/New-EvidencePackage.ps1`: evidence intake log, re-verification of every dataset hash, a status per deliverable from a deliverable map, `evidence-index.md`, and an optional verified package copy.
- Examples: `population-exclusions`, `pilot-test-cases`, `kpi-definitions`, `deliverable-map`, exception register, status register, ownership matrix. Docs: `docs/evidence-tools.md`, `docs/templates/` (registers and a runbook template).
- Catalog entries for 27-30, so the launcher and report show them.

### Notes
- The new scripts and tools were mock-tested end to end on PowerShell 7.4. PSScriptAnalyzer was not run for this release; run it before handover.

## 1.8.0 - 2026-10-22

Depth release. Every script was reviewed for places where it stopped at a group, a role or a fixed list instead of resolving to the real accounts, and for places where a failed read was reported as a finding or as "none". Earlier evidence from the scripts listed under Fixed should be rerun.

### Fixed (earlier output could be wrong)
- 04: `Enabled`, `PasswordNeverExpires`, `KerberosPreAuthDisabled` and the delegation columns were computed from the wrong variable (PowerShell names are case-insensitive, so a local value overwrote the flag table). Root-domain groups (Enterprise / Schema / Enterprise Key Admins) came back empty in a child domain; loops were detected by name instead of DN.
- 11: any principal lookup failure, including access denied and throttling, was flagged `OrphanedPrincipal` and summarised as safe to clean up. Only a real 404 does that now; others are `PrincipalNotVerified`.
- 20: a review scoped to groups counted every group as covered, including role-assignable groups, even when the review was M365-only or guests-only.
- 02: after one failed user lookup the last-sign-in check was switched off for all later admins and failed users were dropped. Tier 0 is matched by role template ID, not by name.
- 01: an unreadable Conditional Access read reported "no groups are excluded"; email-only users counted as phone-only.
- 06: rehires were treated as leavers; 0-day lags were dropped from the statistics.
- 12, 13: synced users with an empty `mS-DS-ConsistencyGuid` were reported as AD-only or unsynced (Entra Connect falls back to `objectGUID`); duplicate anchors overwrote each other.
- 16: a failed compliance assignment read showed `Unassigned`; exclusion targets counted as assignments.
- 17: access denied on a login profile read as "no console access" (hiding console users without MFA); a failed role read flagged `NeverUsed`; a failed password-policy read showed `None`.
- 19: covered hours overstated when a query hit the event cap; anonymous NTLM shown as version `-`; blank domain in the manifest with `-DomainControllers`.
- 22: `ActiveAssignments` included eligible users who were activated at the time.
- 25: DLP rules written with `AdvancedRule` showed zero sensitive information types.
- 26: every AD account was treated as Tier 0; a name-only match counted as vaulted (now `Unconfirmed`).
- 07, 14, 15: groups keyed by name, so same-named groups merged.

### Changed: deeper by default
- Entra (01, 02, 03, 10, 20, 21, 22, 24) share one "effective privileged principal" set: active and eligible role assignments, groups that hold roles expanded to their members, PIM for Groups eligible members and owners, and owners of role-holding groups. One Tier 0 list for all.
- 01 1.1.0: method strength (phishing-resistant / Authenticator / phone / email), privileged join, excluded roles resolved to holders, authentication methods policy and security defaults, named locations, auth strength combinations, optional non-interactive single-factor sign-ins.
- 02 1.1.0: `privileged-principals-effective`, privileged service principals with owners and credentials, custom role definitions with risky actions, administrative units, PIM self-activations, phishing-resistant MFA for admins, `-BreakGlassUpns`.
- 03 1.1.0: credentials on every service principal (including Microsoft and multi-tenant), wider high-risk and Tier 0-equivalent permission list, directory roles held by apps, federated credentials, redirect URI / implicit grant risks, app management policies, owner detail, who is assigned to each app.
- 04 1.1.0: more privileged groups with a Tier column, primary-group members, foreign principals translated, admin naming and product labels, domain-wide risk flags (`ad-account-risk-flags`: delegation, pre-auth off, password not required, reversible encryption, DES, old non-expiring passwords, SIDHistory, shadow-credential indicator, kerberoastable users), krbtgt / RID-500 / Seamless SSO key age, gMSA password readers. `IsPrivileged` now means Tier 0.
- 05 1.1.0: the real users and computers each group reaches, whether it reaches a privileged group and how, owner health, all-members-disabled, full membership for very large groups, out-of-scope edges counted.
- 06 1.1.0: secondary (admin / service) accounts tied to their owner and flagged when the owner has left, fallback matching on UPN / mail, leavers still in groups or licensed, cloud-only users not in HR, optional mover check.
- 07 1.1.0: nested membership on by default (`-DirectOnly` to turn off; `-ExpandNested` is a no-op), excluded and unpopulated accounts listed instead of dropped, layered keys (`-LayeredAttributes`), per-user access load against peers, primary group counted.
- 08 1.1.0: users, groups, computers and contacts by default; which dynamic groups, administrative units and CA device filters read each attribute; Entra device extension attributes; custom security attribute holders; multi-valued attributes counted correctly.
- 09 1.1.0: mailbox delegation (FullAccess, SendAs, SendOnBehalf, groups expanded), hidden inbox rules, room and equipment mailboxes, risky transport rules, outbound connectors, application access policies and RBAC for Applications, per-site sharing detail on by default, optional external users per site.
- 10 1.1.0: external members as well as guests, transitive groups, privileged guests, objects guests own, app names, sponsors on by default, per-partner cross-tenant settings.
- 11 1.1.0: `azure-effective-users` (groups expanded, active and eligible), management-group custom roles, dataActions in the risk test and a wider privileged role list, Key Vault access policies, Lighthouse delegations, deny assignments, managed identities, management-group hierarchy, conditions.
- 12 1.1.0: what stale accounts still hold (groups, adminCount, SPN, licences, Entra roles), new flags (stale but privileged / licensed, disabled but licensed, never logged on, old non-expiring password, service account with no owner), computers on by default, managed service accounts, unmatched synced users listed, optional precise last logon.
- 13 1.1.0: privileged AD accounts that sync to Entra and those that also hold Entra roles, sync service accounts, matched-pair mismatches, hybrid-joined device coverage, group provisioning errors, disabled accounts listed.
- 14 1.1.0: access through nested groups, non-user members of governed groups, leavers still in groups, duplicate and blank keys reported; group key defaults to `sAMAccountName`.
- 15 1.1.0: every unexpected member of a rule-managed group (disabled, out of scope, excluded, nested, computer, foreign); disabled users evaluated by default (`-EnabledOnly` to narrow; `-IncludeDisabled` is a no-op); rule attributes checked against the schema.
- 16 1.1.0: device registration policy, ownership and management detail, CA device exclusions resolved to users, enrollment restrictions, app protection policies, LAPS and BitLocker coverage (metadata only), compliance grace periods.
- 17 1.1.0: `aws-effective-admins` from full policy documents (inline, group and customer-managed, privilege escalation patterns), group memberships, Identity Center groups expanded to people (on by default when the modules exist), OIDC providers and wildcard subjects, in-org vs external trusts, SCPs and delegated administrators, unused-access findings, multiple regions, existing credential report.
- 19 1.1.0: NTLM operational log (8004) with target servers, failed NTLM and Kerberos pre-auth, TGTs without pre-auth, accounts limited to RC4 / DES or without AES keys, source workstation OS.
- 20 1.1.0: review scope parsed properly, self-review and guests-only flags, coverage base from the effective privileged set, what access packages grant and how many hold them, lifecycle workflows.
- 21 1.1.0: privileged flag from the effective set, risky users who can't self-remediate, risk policy exclusions resolved, service principal risk detections, optional risk history.
- 22 1.1.0: PIM for Groups settings, approvers resolved and checked against eligibility, authentication context checked against Conditional Access, notification settings, PIM alerts, flags on every held role.
- 23 1.2.0: duplicates on attributes that should be unique (`attribute-duplicates`), population by enabled / disabled and by `-BreakdownAttribute`, contacts and gMSAs by default (gMSAs no longer counted under computer).
- 24 1.1.0: real covered window reported when sign-ins are capped, sign-ins no enforced policy covers, optional service principal sign-ins, privileged flag on impact rows.
- 25 1.1.0: who is excluded from each policy, adaptive scopes, Purview role holders, eDiscovery admins, label super users (Windows PowerShell 5.1), label encryption and override settings, custom types in Content Explorer, optional Activity explorer totals, retention.
- 26 1.1.0: also checks service accounts, adminCount orphans and delegated-rights holders (18), prefers the new effective files from 02, 11 and 17, flags old vault verification and passwords changed outside the vault.

### Added
- Dataset status `Partial`: data collected but part of the source could not be read; the note says what. The launcher and report (1.0.1) count and show it.
- New Graph scopes, all read-only: `PrivilegedEligibilitySchedule.Read.AzureADGroup`, `RoleManagementPolicy.Read.AzureADGroup`, `RoleManagementAlert.Read.Directory`, `LifecycleWorkflows.Read.All`, `CustomSecAttributeAssignment.Read.All`, `DeviceLocalCredential.ReadBasic.All`, `BitlockerKey.ReadBasic.All`, `DeviceManagementServiceConfig.Read.All`, `DeviceManagementApps.Read.All`, plus existing scopes used by more scripts. See [permissions](docs/permissions.md).

## 1.7.0 - 2026-10-22

### Changed
- `18-Get-ADDelegation.ps1` 1.1.0: now also reviews GPO permissions (GPOs linked to the domain root or DC OU are Tier 0) and explicit permissions on individual accounts (`-ObjectAclScope`: admin-like accounts by default, or `All`); rights copied from AdminSDHolder onto protected accounts are not repeated. Group trustees are expanded through nested groups to the user accounts that actually hold each right (`ad-delegation-effective-users.csv`), with regular (non-admin-named) accounts holding High or Critical rights flagged. Trustees are labelled Exchange (product default), Entra Connect (sync account), Builtin operator or Custom. New parameters: `-ObjectAclScope`, `-AdminNamePatterns`, `-AdditionalPrivilegedGroups`, `-SkipGPOs`, `-SkipMemberExpansion`. A failed account search no longer stops the run.

## 1.6.0 - 2026-10-21

Closes the gaps found when aligning the scripts to the engagement scope (Conditional Access staging, Purview classification evidence, PAM coverage).

### Added
- `24-Get-CaReportOnlyImpact.ps1` (1.0.0): per Conditional Access policy, what it did or would have done to real sign-ins: every result count, users a report-only policy would block or interrupt, top apps, and one row per policy, user and app to work through before enforcing. Sends `Prefer: include-unknown-enum-members` (required for report-only results); reports policies deleted since the sign-ins; optional non-interactive sign-ins (beta).
- `25-Get-PurviewClassification.ps1` (1.0.0): sensitivity labels and label policies, auto-labeling policies and rules, DLP policies (mode: on / simulation / off) and rules (sensitive information types, actions), sensitive information types with custom ones flagged, and optional Content Explorer totals per tag and workload. Totals come from response metadata only: no item names, paths or senders are kept; locations are summarised, never listed.
- `26-Compare-PamVaultCoverage.ps1` (1.0.0): privileged accounts from the latest runs of 02, 04, 11 and 17 checked against a PAM vault export: vaulted or not, Tier 0 not vaulted, name-only matches to check, AWS account-aware matching, vault entries matching no privileged account, and SHA-256 of every input.
- `examples/pam-accounts.example.csv`; script pages, permissions (Purview section), pilot checks, tuning and sign-off rows; catalog entries for the launcher and report.

### Changed
- `23-Get-ADAttributePopulation.ps1` 1.1.0: inventories users, groups and computers by default (`-ObjectClass user` to narrow).

## 1.5.1 - 2026-10-21

### Changed
- `23-Get-ADAttributePopulation.ps1` 1.0.1: attribute syntax codes are built from a prefix and number instead of written out in full, so the source no longer trips the guardrail's IP address rule. No change in behavior or output.

## 1.5.0 - 2026-10-21

### Added
- `23-Get-ADAttributePopulation.ps1` (1.0.0): every attribute the schema allows on users (and optionally groups and computers), resolved through superclasses and auxiliary classes, with populated count and %, total and distinct values, longest value, syntax, single/multi-valued, mandatory, defining class, global catalog, link type, system-only and confidential. Binary attributes counted by presence only; constructed, base-only and security-descriptor attributes reported as not counted; confidential zeros marked as possibly unreadable. No values written unless `-SampleValueCount` is set. Flag values from [MS-ADTS] 2.2.9 and 2.2.10.
- Catalog entry for the launcher and report (shows as Check first: heavy read), script page, permissions, pilot check, tuning and sign-off rows.

## 1.4.0 - 2026-10-21

Launcher and report; no discovery-script changes.

### Added
- `tools/Start-Discovery.ps1` (1.0.0): readiness check for every script on this machine (AD module and DC, Graph / Exchange / Azure / AWS modules, input files), pick list (Out-GridView or console), runs the picks with `-Server` and `-OutputRoot`, asks for required input files and for SOC confirmation before 18, then a run summary (Completed / Partial / Failed / Skipped with the run folder). Unattended with `-Select` and `-ScriptParameters`.
- `tools/New-DiscoveryReport.ps1` (1.0.0): one self-contained HTML page from the evidence folder: headline tiles, coverage of all 22 scripts with pilot status, summary metrics with change since the previous run, dataset statuses. Built from summaries only (counts, no names); run details only with `-IncludeRunDetails`.
- `tools/discovery-catalog.psd1`: script list and what each needs, shared by the two tools.
- Docs: launcher and report section and an Entra-joined devices section in `docs/getting-started.md`; troubleshooting rows.

### Changed
- `tools/Test-ReadOnly.ps1` 1.3.0: `Read` added to the read-only verbs (`Read-Host` reads keyboard input).

## 1.3.1 - 2026-10-20

Repository guardrail; no script changes.

### Added
- `tools/guardrail/`: scanner (`Invoke-Guardrail.ps1`), rules (`rules.psd1`), Microsoft-published ID allowlist (`known-public-ids.txt`), private denylist template, one-time setup (`Install-Guardrail.ps1`) and a self-test (`Test-Guardrail.ps1`) that proves every rule fires and the placeholders pass.
- `.githooks/pre-commit` and `.githooks/commit-msg`: scan staged files and the commit message; fail closed.
- `.github/workflows/guardrail.yml`: self-test, full tree + commit message / author scan with the `GUARDRAIL_DENYLIST` secret, and gitleaks over the full history on every push and pull request.
- `docs/guardrail.md` and `CONTRIBUTING.md`.

### Changed
- `.gitignore`: also ignores the private denylist, `*.local.psd1`, `.env`, credential XML and more data / archive types.

## 1.3.0 - 2026-10-20

Documentation restructure; no script changes.

### Changed
- README is now a short front door: script table, quick start, read-only guarantee, using the results, and a documentation index.
- `docs/scripts/`: one page per script (collects, parameters, output files, permissions, pilot check, troubleshooting), with an index and previous / next links.
- `docs/getting-started.md`: prerequisites, authentication, common parameters, every script with typical parameters, locked-down environments.
- `docs/outputs.md`: now covers the run folder, dataset statuses and handling the output; per-script output tables moved to the script pages.
- `docs/troubleshooting.md` and `docs/design-and-testing.md`: moved out of the README.

## 1.2.1 - 2026-10-20

### Added
- `LICENSE` (MIT) and an Author section in the README.
- `tools/New-FindingEvidence.ps1` 1.0.0: reads a run folder and prints the finding's Scope count, Evidence (with SHA-256) and Closure criteria (exact rerun command and metric), to console, file or clipboard.
- `docs/jira-finding-template.md`: Jira issue fields, description template, severity guide with examples from the scripts, worked example and evidence rules.

## 1.2.0 - 2026-10-20

Fills the gaps found when mapping the discovery access matrix against the scripts.

### Added
- `16-Get-DevicePosture.ps1` (1.0.0): Entra device join / management / compliance, Intune compliance and check-in, compliance policy assignment and the no-policy setting, CA policies that rely on device state.
- `17-Get-AwsIamPosture.ps1` (1.0.0): AWS root MFA and keys, IAM users and access keys, role trusts (cross-account, wildcard, SAML), Access Analyzer external-access findings, IAM Identity Center permission sets and assignments; multi-account through a read-only role.
- `18-Get-ADDelegation.ps1` (1.0.0): dangerous ACL rights on the domain root, AdminSDHolder, DC OU, OUs and protected groups held by non-default trustees (incl. DCSync, reset password, write members, shadow credentials, RBCD, LAPS read), non-default owners, per-trustee view.
- `19-Get-DcAuthProtocolUsage.ps1` (1.0.0): NTLM v1 / v2 logons, NTLM validations and RC4 / DES Kerberos tickets from DC Security logs, with the window each DC's log actually covers.
- `20-Get-GovernanceCoverage.ps1` (1.0.0): access review definitions and decision statistics, coverage of apps / groups / Tier 0 roles, optional in-scope application list, access packages.
- `21-Get-IdentityRisk.ps1` (1.0.0): risky users (admins first), risk detections, risky service principals, CA risk policies.
- `22-Get-PimRoleSettings.ps1` (1.0.0): PIM activation requirements and permanent-assignment settings per directory role, with Tier 0 flags.
- Docs: README sections, permissions (AWS and event log sections), outputs, pilot runbook checks and sign-off rows for 16-22.

### Changed
- `tools/Test-ReadOnly.ps1` 1.2.0: `Use-STSRole` added to the allowlist (returns temporary credentials for a read-only AWS role; changes nothing).

### Found and fixed during testing (before release)
- 18: schema and extended-right GUID lookups were shared, but some GUIDs are identical (`member` / Self-Membership, `servicePrincipalName` / Validated-SPN), which would have mislabeled write-members rights. Now kept separate.
- 18: builtin operator groups were reported as unresolved trustees.
- 19: covered window is now taken from where each DC's Security log starts, not from the oldest matching event.
- 20: decision apply failures with "Failure" in the result were not counted.

## 1.1.0 - 2026-10-20

### Added
- `07-Get-RoleMiningCandidates.ps1` (1.0.0): role mining by department / job code, with attribute quality and spelling-variant detection, birthright and role candidates, and outliers.
- `08-Get-ExtensionAttributeInventory.ps1` (1.0.0): usage and format of AD extension and custom attributes, Entra cloud-only extension attributes, directory (schema) extensions and custom security attribute definitions.
- `09-Get-MailForwardingAndSharing.ps1` (1.0.0): mailbox forwarding, forwarding / hiding inbox rules, transport rules, remote domain and outbound spam forwarding settings, SharePoint tenant and site sharing.
- `10-Get-GuestAccess.ps1` (1.0.0): external collaboration settings, per-guest activity / access / sponsors, guests by home domain.
- `11-Get-AzureRbac.ps1` (1.0.0): Azure role assignments across management groups and subscriptions, PIM eligibility, custom roles, classic administrators.
- `12-Get-StaleAccounts.ps1` (1.0.0): combined AD + Entra activity per identity, activity buckets, optional stale computers.
- `13-Get-HybridSyncScope.ps1` (1.0.0): sync status, inferred OU scope, unsynced users, orphaned synced objects, cloud-only duplicates, provisioning errors, optional groups.
- `14-Compare-IgaToDirectory.ps1` (1.0.0): reconciliation of IGA account and assignment exports against AD.
- `15-Test-RuleManagedAccess.ps1` (1.0.0): drift between applied roles, HR-expected roles and actual rule-managed group membership.
- `examples/`: placeholder input templates for scripts 06, 14 and 15.
- `docs/pilot-runbook.md`: per-script known-answer checks, tuning guide, problem reporting and sign-off table for moving scripts from mock-tested to pilot-verified.
- `tools/Test-ReadOnly.ps1` 1.1.0: also fails on `Invoke-AzRestMethod` without `-Method GET`.

### Fixed (scripts 01-06 -> 1.0.1)
- **02, 03: owner counts were always 1.** Wrapping the paged Graph helper's result in `@()` produced a one-element array, so `OwnerCount` on role-assignable groups (02) and service principals without an app registration (03) was wrong, and the `NoOwner` flag never fired for those service principals.
- All Graph and AD scripts: the run manifest can now record extra connection details (used by 09 and 11). Identical helper change in every script, so all are bumped to 1.0.1.

### Changed
- README rewritten to cover all 15 scripts, with per-script parameters, a goal-to-script map and an expanded troubleshooting table.
- `docs/permissions.md`: per-script summary, every scope used, Exchange and Azure sections.
- `docs/outputs.md`: output reference for scripts 07-15.
- `.gitignore`: allows only `examples/*.example.csv`; all other CSV, JSON and log files stay blocked.

## 1.0.0 - 2026-10-20

Initial release.

### Added
- `01-Get-MfaCoverage.ps1`: Conditional Access policies and exclusions, excluded-group members, MFA registration, successful single-factor and legacy-auth sign-ins.
- `02-Get-PrivilegedAccess.ps1`: active and eligible Entra role assignments, role-holding group members, role-assignable groups, per-user privileged hygiene. Falls back when PIM is not licensed.
- `03-Get-AppsAndConsents.ps1`: consent settings, app registrations and credentials, service principals, application and delegated permissions, per-app "data movers" summary.
- `04-Get-ADPrivilegedAndServiceAccounts.ps1`: protected-group membership with nesting paths, privileged-account hygiene, service-account candidates, adminCount leftovers.
- `05-Get-ADGroupNesting.ps1`: full group graph with nesting depth, circular-nesting detection and hygiene flags.
- `06-Compare-JmlTiming.ps1`: joiner and leaver lag against an HR export, terminated-but-enabled, activity after termination, orphan candidates; optional Entra sign-in check.
- `tools/Test-ReadOnly.ps1`: static AST check that the scripts contain no state-changing commands and that every Graph call is GET.
- Evidence output for every run: timestamped folder, UTC ISO 8601 dates, `run-manifest.json`, `dataset-status.csv` with SHA-256 per file, `run.log`.
- `docs/permissions.md` and `docs/outputs.md`.
