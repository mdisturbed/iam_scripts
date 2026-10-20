# 19 - DC authentication protocols

**Script:** [`19-Get-DcAuthProtocolUsage.ps1`](../../scripts/19-Get-DcAuthProtocolUsage.ps1) · **Version:** 1.0.0 · **Source:** DC event logs

> Who still uses NTLM (v1 especially) or RC4/DES Kerberos?

Shows what would break, and who is still exposed, before NTLM is restricted or RC4 is disabled.

**Collects** from each domain controller's Security log over a time window:
- **NTLM logons (4624):** split into NTLM V1 and V2, by account, workstation and IP.
- **NTLM credential validations (4776).**
- **Kerberos tickets with weak encryption:** TGTs (4768) and service tickets (4769) issued with RC4 or DES, by account, service and IP.
- **Per-DC read status:** including where each Security log actually starts.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-DomainControllers` | all DCs | Limit to listed DCs |
| `-Hours` | `24` | Window to read (1-720) |
| `-MaxEventsPerQuery` | `50000` | Safety cap per DC per query |
| `-SkipKerberos` / `-SkipNtlmValidation` | off | Skip parts (4776 is often high-volume) |

**Open first:** `dc-read-status.csv` (was every DC readable, and how much log did it hold?), then `ntlm-logons.csv`, where NTLM V1 rows are listed first. If auditing isn't enabled the counts are zero, so check the status file before concluding there's no usage. For longer history, query the SIEM.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `dc-read-status.csv` | DC + query | `Status`, `EventsRead`, `CappedAtMax`, `LogStartsUtc`, `HoursCovered` |
| `ntlm-logons.csv` | NTLM version + account + source | `NtlmVersion`, `Account`, `SourceWorkstation`, `SourceIp`, `Count`, first / last seen |
| `ntlm-validations.csv` | Account + workstation + status | `Count`, `Status` |
| `kerberos-weak-encryption.csv` | Account + service + encryption + client | `RequestType`, `Encryption`, `Count` |

**Reading it:** NTLM V1 should be zero. RC4 service tickets usually point at a service account whose `msDS-SupportedEncryptionTypes` doesn't allow AES, or a password never reset since AES keys were introduced.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | **Event Log Readers** on domain controllers; RPC to DCs; audit policy enabled | RSAT AD, Windows |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: `LogStartsUtc` matches the oldest event in Event Viewer on one DC; one known NTLM application server appears.

Usually tuned on first run: `-Hours` to fit how much Security log the DCs hold. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 19: all counts zero | Auditing not enabled, or log rolled over | Check `dc-read-status.csv` (`LogStartsUtc`) and audit policy; use the SIEM |
| Script 19: DC rows `Blocked` | Not in Event Log Readers, or RPC blocked | Request Event Log Readers on DCs; check firewall to DCs |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 18 AD delegation](18-ad-delegation.md) · [All scripts](README.md) · [20 Governance coverage →](20-governance-coverage.md)
