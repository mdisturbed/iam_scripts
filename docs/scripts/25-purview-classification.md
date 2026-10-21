# 25 - Purview classification and DLP

**Script:** [`25-Get-PurviewClassification.ps1`](../../scripts/25-Get-PurviewClassification.ps1) · **Version:** 1.0.0 · **Source:** Microsoft Purview (Security & Compliance PowerShell)

> What can classify regulated data, what is actually switched on, and how much tagged content exists where?

Evidence for "review classification and discovery": the labels, auto-labeling and DLP configuration that exist, their **mode** (on, simulation, off), the sensitive information types they look for, and optional item counts. It enforces nothing and changes nothing.

**Collects:** sensitivity labels (parent, priority, enabled, content types); label policies (labels published, mode, locations, mandatory and default label); auto-labeling policies (mode, label applied, locations) and their rules (sensitive information types); DLP policies (mode, workloads, locations) and rules (sensitive information types, actions); every sensitive information type with custom ones flagged; optionally Content Explorer item counts per sensitive information type or label per workload.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-IncludeContentExplorer` | off | Add item counts per tag and workload |
| `-ContentExplorerSits` | SSN, ICD-10-CM, ICD-9-CM, DEA number, ITIN, credit card | Sensitive information types to count; names must match the tenant exactly |
| `-ContentExplorerLabels` | off | Also count items for every sensitivity label |
| `-Workloads` | `EXO`, `ODB`, `SPO`, `Teams` | Content Explorer workloads |
| `-AuthMode`, `-Organization`, `-ClientId`, `-CertificateThumbprint` | Delegated | App-only: `-AuthMode AppCertificate -Organization contoso.onmicrosoft.com …` |

**Open first:** `summary.csv` (how many DLP and auto-labeling policies are on vs. in simulation), then `purview-dlp-rules.csv` and `purview-autolabel-rules.csv` to see which sensitive information types are actually covered.

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `purview-sensitivity-labels.csv` | Label | `DisplayName`, `ParentLabel`, `Priority`, `Disabled`, `ContentType` |
| `purview-label-policies.csv` | Label policy | `Labels`, `Mode`, `ExchangeLocation`, `ModernGroupLocation`, `MandatoryLabeling`, `DefaultLabelId` |
| `purview-autolabel-policies.csv` | Auto-labeling policy | `Mode` (On / Simulation / Off), `AppliesLabel`, locations |
| `purview-autolabel-rules.csv` | Auto-labeling rule | `Policy`, `SensitiveInfoTypes`, `Workload` |
| `purview-dlp-policies.csv` | DLP policy | `Mode`, `Workload`, `ExchangeLocation` … `EndpointDlpLocation` |
| `purview-dlp-rules.csv` | DLP rule | `Policy`, `SensitiveInfoTypes`, `Actions` (BlockAccess, NotifyUser, IncidentReport, Alert, Encrypt) |
| `purview-sensitive-info-types.csv` | Sensitive information type | `Publisher`, `Custom`, `Type`, `RecommendedConfidence` |
| `purview-content-explorer-counts.csv` | Tag + workload | `TagType`, `TagName`, `Workload`, `ItemCount`, `Note` |

**Reading it:**
- **Content Explorer counts are totals only.** For each tag and workload the script requests one record and keeps only the total from the response metadata; item names, paths and senders are never read into the output.
- Locations are shown as `All` or *N specific*; sites, mailboxes and users are never listed.
- A sensitive information type in `-ContentExplorerSits` that the tenant doesn't have is reported as *not found* rather than queried; check exact names in `purview-sensitive-info-types.csv`.
- The Security & Compliance session is left open. Close it with `Disconnect-ExchangeOnline` when finished.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader (maps to Purview Global Reader) | | Purview: Global Reader role group; for Content Explorer counts also **Information Protection Readers** and **Content Explorer List viewer** (not Content viewer) | ExchangeOnlineManagement v3 |

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

General issues: [troubleshooting](../troubleshooting.md).

---

[← 24 CA report-only impact](24-ca-reportonly-impact.md) · [All scripts](README.md) · [26 PAM vault coverage →](26-pam-vault-coverage.md)
