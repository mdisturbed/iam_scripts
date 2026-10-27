# 31 - Licence inventory

**Script:** [`31-Get-LicenceInventory.ps1`](../../scripts/31-Get-LicenceInventory.ps1) · **Version:** 1.0.0 · **Source:** Entra subscribed SKUs (+ earlier run folders)

> Which Microsoft licences and service plans does the tenant actually have, how many are assigned, and which licence-dependent evidence could not be collected?

This is the licence-confirmation evidence for a readiness gate. Other scripts mark a dataset `EvidenceUnavailable` when a feature looks unlicensed. This script reads the subscriptions themselves, so a licence gap is confirmed from the tenant's own SKUs rather than inferred from a failed read. Run it first, before the project starts. After the discovery pass, run it again with `-EvidenceRoot` to list every dataset that other runs could not collect.

**Collects:** every subscribed SKU with its prepaid units (enabled, suspended, warning, locked out), consumed units and service plans. Each capability in the capability map is then marked present or absent from those service plans. With `-EvidenceRoot`, the latest run of every other script under that folder is read and each `EvidenceUnavailable` dataset is listed.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-EvidenceRoot` | none | Evidence folder holding the other scripts' run folders (`NN-Name\yyyyMMdd-HHmmssZ`), usually the `-OutputRoot` they were run with. Adds `licence-gaps-observed.csv` |
| `-CapabilityMap` | built-in map (below) | Capability label -> array of service plan names. Replaces the default map. Pass an `[ordered]` hashtable to keep your order. Plan names are matched case-insensitively |
| `-GraphScope` | `Directory.Read.All` | Delegated scope requested at sign-in. The default is already consented wherever the other Graph scripts run. `LicenseAssignment.Read.All` is least privileged but needs its own consent; `Organization.Read.All` also works |

```powershell
.\scripts\31-Get-LicenceInventory.ps1 -OutputRoot D:\Evidence                               # before the project
.\scripts\31-Get-LicenceInventory.ps1 -EvidenceRoot D:\Evidence -OutputRoot D:\Evidence     # after the pass
.\scripts\31-Get-LicenceInventory.ps1 -CapabilityMap ([ordered]@{ 'Entra ID P2' = @('AAD_PREMIUM_P2'); 'Intune' = @('INTUNE_A') })
```

**Open first:** `summary.csv` (*Capabilities absent* lists them by name, and *SKUs suspended* / *SKUs in warning* show subscriptions at risk), then `licence-capabilities.csv` filtered on `Present = False`. With `-EvidenceRoot`, `licence-gaps-observed.csv` lists the evidence that is missing.

Common parameters (`-OutputRoot`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `licence-skus.csv` | Subscribed SKU | `SkuPartNumber`, `SkuId`, `CapabilityStatus` (Enabled / Warning / Suspended / Deleted / LockedOut), `Enabled`, `Suspended`, `Warning`, `LockedOut`, `Consumed`, `Available` (Enabled - Consumed), `ServicePlanCount`, `Flags` |
| `licence-service-plans.csv` | SKU and service plan | `SkuPartNumber`, `ServicePlanName`, `ServicePlanId`, `ProvisioningStatus` (Success / Disabled / Error / PendingInput / PendingActivation / PendingProvisioning), `AppliesTo` (User / Company), `Capability` (from the map; blank when unmapped) |
| `licence-capabilities.csv` | Capability in the map | `Capability`, `MappedPlans`, `Present` (True / False), `ProvisioningStatuses`, `ViaSkus`, `EnabledUnits`, `ConsumedUnits`, `Note` |
| `licence-gaps-observed.csv` | `EvidenceUnavailable` dataset in another script's latest run | `Script`, `RunFolder`, `Dataset`, `Note` |

Without `-EvidenceRoot`, `licence-gaps-observed` is `Deferred`.

**Summary metrics:** *Subscribed SKUs*, *SKUs suspended*, *SKUs in warning*, *SKUs locked out*, *SKUs over-assigned* (the note lists the SKUs), *Capabilities present* and *Capabilities absent* (the note lists the names), and with `-EvidenceRoot` *Script runs scanned* and *Datasets EvidenceUnavailable in latest runs* (the note lists the scripts).

**Reading it:**
- **Present** means at least one SKU whose `capabilityStatus` is `Enabled` or `Warning` carries one of the capability's service plans with `provisioningStatus` `Success`. A plan on a suspended, deleted or locked-out SKU, or a plan that is `Disabled` or `PendingActivation`, doesn't count. `ViaSkus` still lists it with its status (for example `SKU1 (Success, SKU Suspended)`), and `Note` says why the capability is absent.
- **EnabledUnits and ConsumedUnits** add up `Enabled` and `Consumed` of the SKUs that make the capability present, each SKU counted once. They show how many seats carry the capability, not how many users have that plan switched on: an admin can disable one service plan in a user's licence, and this script doesn't read per-user assignments.
- **Flags** on a SKU: `Suspended` (capabilityStatus Suspended, or suspended units), `Warning` (expired, in the grace period before suspension), `LockedOut`, `Deleted`, `OverAssigned` (Consumed > Enabled, which is common while units are in warning or suspended), `NoneAssigned` (enabled units, none assigned) and `CompanyLevel` (a tenant-wide SKU, which isn't assigned to users).
- **A Warning SKU still counts as present**, because its units keep working during the grace period. When a capability comes only from SKUs in warning, `Note` says so: the capability is at risk.
- **licence-gaps-observed** reads `dataset-status.csv` of the latest run folder (by name) that has a `run-manifest.json`, for each `NN-Name` folder under `-EvidenceRoot`. Folders named `_aborted`, folders that are not run folders, and this script's own runs are skipped. A run folder without a readable `dataset-status.csv` makes the dataset `Partial` and is named in the note. Compare each row with `licence-capabilities.csv`: a gap whose capability is absent is a confirmed licence gap, and a gap whose capability is present points to a permission or configuration problem instead.
- **No tenant naming.** The SKU read also returns the account name and subscription IDs. They are not written to any file.
- **Never zero for a failed read.** If the SKU read fails, the three licence datasets are `Blocked` and the summary values are blank, not 0.

### Default capability map

Every service plan name below was checked against Microsoft's [Product names and service plan identifiers for licensing](https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference) (reference last updated August 2026), using the friendly name Microsoft gives each plan. `_GOV`, `_EDU` and similar names are the same service in the government and education SKUs. <!-- guardrail:allow Microsoft docs URL, not a user profile path -->

| Capability | Service plans |
|------------|---------------|
| Entra ID P1 | `AAD_PREMIUM` |
| Entra ID P2 | `AAD_PREMIUM_P2` |
| Entra ID Governance | `Entra_Identity_Governance` |
| Workload Identities Premium | `AAD_WRKLDID_P1`, `AAD_WRKLDID_P2` |
| Intune | `INTUNE_A`, `INTUNE_A_GOV`, `INTUNE_A_VL`, `INTUNE_EDU`, `INTUNE_SMBIZ` |
| Defender for Identity | `ATA` |
| Defender for Office 365 Plan 1 | `ATP_ENTERPRISE`, `ATP_ENTERPRISE_GOV` |
| Defender for Office 365 Plan 2 | `THREAT_INTELLIGENCE`, `THREAT_INTELLIGENCE_GOV` |
| Purview Information Protection Standard | `MIP_S_CLP1` (Information Protection for Office 365 - Standard) |
| Purview Information Protection Premium | `MIP_S_CLP2` (Information Protection for Office 365 - Premium) |
| Azure Rights Management | `RMS_S_ENTERPRISE`, `RMS_S_ENTERPRISE_GOV` |
| Azure Information Protection Premium P1 | `RMS_S_PREMIUM`, `RMS_S_PREMIUM_GOV` |
| Azure Information Protection Premium P2 | `RMS_S_PREMIUM2`, `RMS_S_PREMIUM2_GOV` |
| Purview DLP for Teams | `COMMUNICATIONS_DLP` (Microsoft Communications DLP) |
| Purview Endpoint DLP | `MICROSOFTENDPOINTDLP` |
| Purview DLP add-on | `BPOS_S_DlpAddOn` (Data Loss Prevention, in Business Premium and the F5 add-ons) |
| Purview Insider Risk Management | `INSIDER_RISK` |
| Purview Communication Compliance | `MICROSOFT_COMMUNICATION_COMPLIANCE` |
| Exchange Online | `EXCHANGE_S_STANDARD`, `EXCHANGE_S_ENTERPRISE`, `EXCHANGE_S_DESKLESS`, `EXCHANGE_S_ESSENTIALS`, `EXCHANGE_L_STANDARD`, `EXCHANGE_B_STANDARD`, `EXCHANGE_S_STANDARD_MIDMARKET`, `EXCHANGE_S_STANDARD_GOV`, `EXCHANGE_S_ENTERPRISE_GOV`, `EXCHANGE_S_DESKLESS_GOV` |
| SharePoint Online | `SHAREPOINTSTANDARD`, `SHAREPOINTENTERPRISE`, `SHAREPOINTDESKLESS`, `SHAREPOINTENTERPRISE_MIDMARKET`, `SHAREPOINTSTANDARD_EDU`, `SHAREPOINTENTERPRISE_EDU`, `SHAREPOINTENTERPRISE_GOV`, `SHAREPOINTDESKLESS_GOV` |

Left out on purpose:
- **DLP for Exchange Online and SharePoint.** Microsoft doesn't list it as its own service plan; it comes with the Exchange Online and SharePoint plans. Use the Exchange Online and SharePoint Online rows, and script 25 for the DLP policies themselves.
- `COMMUNICATIONS_COMPLIANCE` and `INSIDER_RISK_MANAGEMENT`: the reference marks them *RETIRED* in current Microsoft 365 E5 SKUs. The current plans are `MICROSOFT_COMMUNICATION_COMPLIANCE` and `INSIDER_RISK`.
- `INTUNE_O365` (Mobile Device Management for Office 365, the basic MDM in Office 365 SKUs), `EXCHANGE_S_FOUNDATION` (no mailbox), `SHAREPOINTWAC` (Office for the web) and the `*_FOR_AGENTS` plans. None of them provides the capability on its own.

Microsoft adds and renames service plans. When a new SKU arrives, check `licence-service-plans.csv` for plans with a blank `Capability` and extend the map with `-CapabilityMap`, using only names from Microsoft's reference.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader or Directory Readers | Directory.Read.All by default (already consented for the other Graph scripts); `-GraphScope LicenseAssignment.Read.All` is the least-privileged option and needs its own consent | Read access to the evidence folder for `-EvidenceRoot` | Graph Auth |

No licence is needed: every tenant can read its own subscriptions. A failed SKU read is therefore always `Blocked`, never `EvidenceUnavailable`. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm two things. Each SKU's `Enabled` and `Consumed` in `licence-skus.csv` should match **Microsoft 365 admin center > Billing > Licenses** (available and assigned licences for that product). And one capability you know is licensed, such as Entra ID P1, should show `Present = True`.

Usually tuned on first run: `-CapabilityMap`, if the readiness gate needs a capability the default map doesn't cover. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 31: licence datasets Blocked (403) | Token has none of LicenseAssignment.Read.All, Organization.Read.All or Directory.Read.All, or the account has no directory read role | Run with the default `-GraphScope Directory.Read.All`, or consent the scope you chose; Global Reader or Directory Readers |
| Script 31: capability absent though the product was bought | SKU suspended or in a state other than Enabled / Warning, plan `Disabled` or `PendingActivation`, or the plan name isn't in the map | Check `ViaSkus` and `Note`; for a new plan name, check `licence-service-plans.csv` and extend `-CapabilityMap` |
| Script 31: `licence-gaps-observed` Blocked | `-EvidenceRoot` missing or not readable | Point it at the folder that holds the `NN-Name` folders |
| Script 31: `licence-gaps-observed` Partial | A latest run folder has no readable `dataset-status.csv` (run stopped early) | Rerun that script, or move the broken run folder into an `_aborted` folder |
| Script 31: a script's gaps are missing | Its run folder has no `run-manifest.json`, or the folder name isn't `yyyyMMdd-HHmmssZ` | Only complete run folders are read; rerun that script |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 30 Access review evidence](30-access-review-evidence.md) · [All scripts](README.md)
