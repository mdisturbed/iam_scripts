# 25 - Purview classification and DLP

**Script:** [`25-Get-PurviewClassification.ps1`](../../scripts/25-Get-PurviewClassification.ps1) · **Version:** 1.1.0 · **Source:** Microsoft Purview (Security & Compliance PowerShell)

> What can classify and protect regulated data, what is actually switched on, who is excluded from it, who can see or bypass it, and how much tagged content exists where?

Evidence for "review classification and discovery": the labels, auto-labeling and DLP configuration that exist, their **mode** (on, simulation, off), the sensitive information types they look for, the people and places excluded, the people who can view, export or decrypt protected content, and optional item and activity counts. It enforces nothing and changes nothing.

**Collects:** sensitivity labels (parent, priority, enabled, content types, encryption rights and do-not-forward, site and group privacy / guest access); label policies (labels published, mode, locations, mandatory and default label, downgrade justification, excluded locations, every setting); auto-labeling policies (mode, label applied, locations) and their rules (sensitive information types); DLP policies (mode, workloads, locations) and rules (sensitive information types, including rules kept in `AdvancedRule`, actions, user override settings); every excluded location and rule exception, resolved to recipient type and group member count where possible; adaptive scopes; every sensitive information type with custom ones flagged; members of role groups that can view, export, classify or decrypt protected content, eDiscovery administrators, and AIP super users; retention policies and labels; optionally Content Explorer item counts per sensitive information type or label per workload (custom SITs added automatically) and Activity Explorer counts per user of DLP overrides and label downgrades.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-IncludeContentExplorer` | off | Add item counts per tag and workload (custom SITs are added to the list automatically) |
| `-ContentExplorerSits` | SSN, ICD-10-CM, ICD-9-CM, DEA number, ITIN, credit card | Sensitive information types to count; names must match the tenant exactly |
| `-ContentExplorerLabels` | off | Also count items for every sensitivity label |
| `-Workloads` | `EXO`, `ODB`, `SPO`, `Teams` | Content Explorer workloads |
| `-SkipRoleHolders` | off | Skip role group members, eDiscovery administrators and AIP super users |
| `-IncludeActivityExplorer` | off | Add per-user counts of DLP matches, overrides / undos and label downgrades / removals |
| `-ActivityDays` | `30` | Activity Explorer window (1 to 30 days) |
| `-ActivityMaxPages` | `20` | Stop after this many pages of 5000 events (the dataset is then `Partial`) |
| `-AuthMode`, `-Organization`, `-ClientId`, `-CertificateThumbprint` | Delegated | App-only: `-AuthMode AppCertificate -Organization contoso.onmicrosoft.com …` |

**Open first:** `summary.csv` (how many DLP and auto-labeling policies are on vs. in simulation), then `policy-exclusions.csv` (who and what is outside the policies), `purview-role-holders.csv`, and `purview-dlp-rules.csv` / `purview-autolabel-rules.csv` to see which sensitive information types are actually covered.

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `purview-sensitivity-labels.csv` | Label | `DisplayName`, `ParentLabel`, `Priority`, `Disabled`, `ContentType`, `EncryptionEnabled`, `EncryptionDoNotForward`, `EncryptionRightsDefinitions`, `SiteAndGroupPrivacy`, `SiteAndGroupAllowGuests` |
| `purview-label-policies.csv` | Label policy | `Labels`, `Mode`, `ExchangeLocation`, `ModernGroupLocation`, `MandatoryLabeling`, `DefaultLabelId`, `RequireDowngradeJustification`, `ExchangeLocationException`, `ModernGroupLocationException`, `AllSettings` |
| `purview-autolabel-policies.csv` | Auto-labeling policy | `Mode` (On / Simulation / Off), `AppliesLabel`, locations |
| `purview-autolabel-rules.csv` | Auto-labeling rule | `Policy`, `SensitiveInfoTypes`, `Workload` |
| `purview-dlp-policies.csv` | DLP policy | `Mode`, `Workload`, `ExchangeLocation` … `EndpointDlpLocation` |
| `purview-dlp-rules.csv` | DLP rule | `Policy`, `SensitiveInfoTypes`, `Actions` (BlockAccess, NotifyUser, IncidentReport, Alert, Encrypt), `NotifyAllowOverride`, `NotifyOverrideRequirements`, `UsesAdvancedRule` |
| `policy-exclusions.csv` | Excluded location or rule exception | `Policy`, `PolicyType`, `Location` (for example `ExchangeLocationException`, `ExceptIfSentToMemberOf`), `ExcludedValue`, `ResolvedType`, `MemberCount`, `Note` |
| `purview-adaptive-scopes.csv` | Adaptive scope | `LocationType`, `Query` |
| `purview-sensitive-info-types.csv` | Sensitive information type | `Publisher`, `Custom`, `Type`, `RecommendedConfidence` |
| `purview-role-holders.csv` | Member of a sensitive role group | `RoleGroup`, `MatchingRoles`, `Member`, `MemberType`, `Address`, `Note` |
| `purview-ediscovery-admins.csv` | eDiscovery Administrator | `Name`, `Address` |
| `purview-aip-super-users.csv` | AIP super user or group | `Feature` (Enabled / Disabled), `SuperUser`, `Source` |
| `purview-retention-policies.csv` | Retention policy | `Enabled`, `Mode`, `Workload`, `AdaptiveScopes` |
| `purview-retention-labels.csv` | Retention label | `RetentionAction`, `RetentionDuration`, `IsRecordLabel` |
| `purview-content-explorer-counts.csv` | Tag + workload | `TagType`, `TagName`, `Workload`, `ItemCount`, `Note` |
| `purview-activity-summary.csv` | User with matching activity | `Events`, `DlpMatches`, `DlpOverridesOrUndos`, `LabelDowngrades`, `LabelRemovals`, `Workloads`, `FirstUtc`, `LastUtc` |

**Reading it:**
- **Content Explorer counts are totals only.** For each tag and workload the script requests one record and keeps only the total from the response metadata; item names, paths and senders are never read into the output.
- **Activity Explorer output is counts per user only.** Events are aggregated in memory; file names, paths and content are never written. `DlpOverridesOrUndos` counts `DLPRuleUndo` events and DLP matches that carry an override or justification value.
- Locations in the policy files are shown as `All` or *N specific*. Exclusions are listed in full in `policy-exclusions.csv`, because each one is a gap to review. Recipients and groups are resolved (type, member count) only when Exchange Online recipient cmdlets are loaded in the same session; otherwise `ResolvedType` is `Unresolved` with a note.
- `purview-role-holders.csv` lists role groups whose roles include eDiscovery / case management, review, export, RMS decrypt, Content Explorer / data classification, information protection, DLP or compliance administration. A member that is itself a group is marked; its members are not expanded.
- AIP super users are read only in Windows PowerShell 5.1 with the AIPService module (the dataset is `Deferred` otherwise).
- A sensitive information type in `-ContentExplorerSits` that the tenant doesn't have is reported as *not found* rather than queried; check exact names in `purview-sensitive-info-types.csv`.
- The Security & Compliance session is left open. Close it with `Disconnect-ExchangeOnline` when finished.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader (maps to Purview Global Reader) | | Purview: Global Reader role group (covers role groups, eDiscovery administrators, adaptive scopes and retention); for Content Explorer counts also **Information Protection Readers** and **Content Explorer List viewer** (not Content viewer); for `-IncludeActivityExplorer` a role group with Activity explorer access; for AIP super users, Global Reader or Azure Information Protection administrator | ExchangeOnlineManagement v3 (+ AIPService on Windows PowerShell 5.1, optional) |

Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: the number of DLP policies and their modes match **Purview > Data loss prevention > Policies**, and one label's priority matches **Information protection > Sensitivity labels**.

Usually tuned on first run: `-ContentExplorerSits` to the organization's own list. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 25: a dataset EvidenceUnavailable with "not recognized" | That cmdlet isn't available to the account or tenant | Check Purview role group membership; record as a finding if the feature isn't licensed |
| Script 25: `purview-content-explorer-counts` Blocked | Missing Content Explorer roles | Information Protection Readers and Content Explorer List viewer |
| Script 25: a SIT shows *not found in this tenant* | Name differs from the tenant's | Copy the exact name from `purview-sensitive-info-types.csv` |
| `policy-exclusions` shows `Unresolved` for every recipient | Exchange Online cmdlets not loaded in the same session | Run `Connect-ExchangeOnline` before the script in the same session, or resolve the names by hand |
| `purview-role-holders` `Partial` | Members of some role groups could not be read | See the `Note` column and run.log |
| `purview-aip-super-users` `Deferred` | AIPService module missing, PowerShell 7, or AppCertificate mode | Re-run in Windows PowerShell 5.1 with AIPService installed, signed in interactively |
| `purview-activity-summary` `Blocked` | No Activity explorer access | Add the account to a role group with Activity explorer access |
| `purview-activity-summary` `Partial` | Stopped at `-ActivityMaxPages` | Raise `-ActivityMaxPages` or shorten `-ActivityDays` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 24 CA report-only impact](24-ca-reportonly-impact.md) · [All scripts](README.md) · [26 PAM vault coverage →](26-pam-vault-coverage.md)
