# Troubleshooting

General issues first; script-specific issues follow, and also appear on each script page.

## General

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Module ... not found` | Module missing | Install it, or run from Azure Cloud Shell |
| Dataset `Blocked` with 403 / `Authorization_RequestDenied` | Role or scope missing | Compare `ScopesInToken` in `run-manifest.json` with [permissions.md](permissions.md) |
| Dataset `EvidenceUnavailable` mentioning a licence | Tenant lacks Entra ID P1/P2 | Record as a finding |
| Repeated `HTTP 429` warnings | Throttling | Handled with back-off; large tenants take longer |
| Execution policy blocks a script | Local policy | `Unblock-File`, or follow the approved signing process |

## By script

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 01 note says TRUNCATED | Hit `-MaxSignInRecords` | Shorter lookback or higher cap |
| Script 06: `HR file has no column ...` | Column names differ | Map with `-HrIdColumn` and so on |
| Script 06: date values failed to parse | Date format not recognized | Set `-HrDateFormat` |
| Script 07: almost no populations meet the minimum | Attribute values inconsistent or too granular | Read `attribute-value-variants.csv`; try `-NormalizeValues` or a lower `-MinPopulation` |
| Script 08: `Bulk read failed ... retrying per attribute` | An attribute isn't in the schema | Informational; it shows as `NotInSchema` |
| Script 09: `exo-inbox-rules` slow | One call per mailbox | `-MaxMailboxes 500` for a sample, or `-SkipInboxRules` |
| Script 11: "Scopes that could not be read" above 0 | No Reader on some subscriptions | Request Reader at the root management group |
| Scripts 12 / 13: few AD users matched to Entra | Entra Connect anchors on a different attribute | `-AnchorAttribute 'mS-DS-ConsistencyGuid'` |
| Script 14: `No account rows match System` | `-SystemName` doesn't match the export | Check "Systems seen" in `iga-input-profile.csv` |
| Script 14: many `UnmappedIgaStatus` rows | Status values not in the lists | Extend `-ActiveStatusValues` / `-InactiveStatusValues` |
| Script 15: everyone shows drift | Applied-roles attribute not yet populated, or wrong attribute | Check `-AppliedRolesAttribute` with script 08 |
| Script 16: Intune datasets `Blocked` | No Intune read role / scope | Intune Read Only Operator, `DeviceManagementManagedDevices.Read.All` |
| Script 17: an account shows `Blocked: AccessDenied` | Read-only role missing or not trusted from the run account | Deploy the role (StackSet) and allow the run account to assume it |
| Script 17: no Access Analyzer findings | No external-access analyzer in that region | Create one (outside this script), or set `-Region` |
| Script 18: many `(unresolved)` trustees | Deleted accounts or groups still in ACLs | These are clean-up items; confirm the SID is gone |
| Script 19: all counts zero | Auditing not enabled, or log rolled over | Check `dc-read-status.csv` (`LogStartsUtc`) and audit policy; use the SIEM |
| Script 19: DC rows `Blocked` | Not in Event Log Readers, or RPC blocked | Request Event Log Readers on DCs; check firewall to DCs |
| Scripts 20-22: datasets `EvidenceUnavailable` | No Entra ID P2 / ID Governance | Record as a finding |

[← Back to README](../README.md)
