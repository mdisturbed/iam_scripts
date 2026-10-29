# 19 - DC authentication protocols

**Script:** [`19-Get-DcAuthProtocolUsage.ps1`](../../scripts/19-Get-DcAuthProtocolUsage.ps1) · **Version:** 1.1.1 · **Source:** DC event logs + AD

> Who still uses NTLM (v1 and LM especially) or RC4/DES Kerberos, against which servers, and which accounts can't do AES?

Shows what would break, and who is still exposed, before NTLM is restricted or RC4 is disabled.

**Collects** from each domain controller over a time window:
- **NTLM logons (4624):** split into NTLM V1, LM, V2 and anonymous/unknown, by account, workstation (with its operating system from AD) and IP. V1 and LM are both marked `Weak`.
- **NTLM credential validations (4776).**
- **NTLM audit (NTLM Operational log, 8004):** account, client and the target server each NTLM logon was for, which 4624 on a DC doesn't show. Needs NTLM auditing enabled on the DCs.
- **Failed logons:** NTLM failures (4625) and Kerberos pre-authentication failures (4771).
- **Kerberos tickets with weak encryption:** TGTs (4768) and service tickets (4769) issued with RC4 or DES, by account, service and IP, with the newer encryption-type fields where the DC logs them.
- **TGTs issued without pre-authentication** (4768, PreAuthType 0): AS-REP roastable accounts.
- **Per-DC read status:** including where each log actually starts.

And from AD:
- **Accounts that can't do AES:** users and computers whose `msDS-SupportedEncryptionTypes` allows only RC4/DES, and user accounts with an SPN whose password was last set before the domain's Read-only Domain Controllers group was created. That group appears when the domain is first prepared for Windows Server 2008, the same point AES keys start being generated, so it is a proxy for "this password has no AES keys". Each row says whether the account also appears in the RC4 ticket events.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-DomainControllers` | all DCs | Limit to listed DCs |
| `-Hours` | `24` | Window to read (1-720). Use `168` for a week if the logs hold that much |
| `-MaxEventsPerQuery` | `50000` | Safety cap per DC per query |
| `-SkipKerberos` / `-SkipNtlmValidation` | off | Skip parts (4776 is often high-volume) |
| `-SkipNtlmAudit` | off | Skip the NTLM Operational log (8004) |
| `-SkipFailures` | off | Skip 4625 and 4771 |
| `-SkipAdAccounts` | off | Skip the AD encryption-settings read and the workstation OS lookup |

**Open first:** `dc-read-status.csv` and `dataset-status.csv` (was every DC readable, was NTLM auditing on, and how much log did each DC hold?), then `ntlm-logons.csv`, where weak (V1 and LM) rows are listed first, and `accounts-rc4-or-no-aes.csv`. If auditing isn't enabled the counts are zero, so check the status files before concluding there's no usage. For longer history, query the SIEM.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `dc-read-status.csv` | DC + query | `Status` (Completed / Blocked / EvidenceUnavailable), `EventsRead`, `CappedAtMax`, `LogStartsUtc`, `HoursCovered` |
| `ntlm-logons.csv` | NTLM version + account + source | `NtlmVersion`, `Account`, `SourceWorkstation`, `SourceIp`, `Count`, first / last seen, `Weak`, `SourceOS` |
| `ntlm-validations.csv` | Account + workstation + status | `Count`, `Status` |
| `ntlm-dc-audit-8004.csv` | Account + client + target server | `Account`, `ClientWorkstation`, `TargetServer`, `Count` |
| `ntlm-failed-logons.csv` | Account + source + status | `Status`, `SubStatus`, `LmPackageName`, `Count` |
| `kerberos-preauth-failures.csv` | Account + client + status | `Status`, `PreAuthType`, `Count` |
| `kerberos-weak-encryption.csv` | Account + service + encryption + client | `RequestType`, `Encryption`, `Count`, `AccountSupportedEncryptionTypes`, `ServiceSupportedEncryptionTypes`, `SessionKeyEncryptionType` |
| `kerberos-tgt-no-preauth.csv` | Account + client | `Encryption`, `Count` |
| `accounts-rc4-or-no-aes.csv` | Account | `SupportedEncryptionTypes`, `EncryptionTypesDecoded`, `HasSpn`, `PwdLastSetUtc`, `Reason` (Rc4OrDesOnly / PasswordPredatesAes), `SeenInRc4Events` |

Event datasets are marked `Partial` in `dataset-status.csv` when some DCs couldn't be read, and `Blocked` when none could. `ntlm-dc-audit-8004` is `EvidenceUnavailable` with the note "NTLM auditing not enabled on <dc>" when the NTLM Operational log is disabled, empty, or has never logged 8004 on that DC; that is not a "no NTLM" result.

`HoursCovered` is the window actually read: it starts at the later of the requested window, the oldest event in the log and, when a query hit `-MaxEventsPerQuery`, the oldest event returned.

**Reading it:** NTLM V1 and LM should be zero. `SourceOS` shows whether a weak source is an old system that can't be fixed in place. `TargetServer` in the 8004 data tells you which servers need NTLM kept (or fixed) before it's restricted. RC4 service tickets usually point at a service account whose `msDS-SupportedEncryptionTypes` doesn't allow AES, or a password never reset since AES keys were introduced; `accounts-rc4-or-no-aes.csv` lists both, and `SeenInRc4Events = True` rows are already getting RC4 tickets. `kerberos-tgt-no-preauth.csv` rows should be fixed (require pre-authentication) regardless of encryption.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | **Event Log Readers** on domain controllers; RPC to DCs; audit policy enabled (and NTLM auditing for 8004); domain read | RSAT AD, Windows |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: `LogStartsUtc` matches the oldest event in Event Viewer on one DC; one known NTLM application server appears (as `TargetServer` in the 8004 data if auditing is on); one service account you know has an old password appears in `accounts-rc4-or-no-aes.csv`.

Usually tuned on first run: `-Hours` to fit how much Security log the DCs hold. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 19: event datasets `Blocked`, summary counts blank ("Not assessed") | No DC event log could be read: not in Event Log Readers, or RPC / remote event log blocked | Request Event Log Readers on the DCs; check firewall (RPC, remote event log management) from the run host. Before 1.1.1 the summary showed 0 here |
| Script 19: all counts zero | Auditing not enabled, or log rolled over | Check `dc-read-status.csv` (`LogStartsUtc`) and audit policy; use the SIEM |
| Script 19: DC rows `Blocked` | Not in Event Log Readers, or RPC blocked | Request Event Log Readers on DCs; check firewall to DCs |
| Script 19: `ntlm-dc-audit-8004` is `EvidenceUnavailable` | NTLM auditing is off on the DCs | Set "Network security: Restrict NTLM: Audit NTLM authentication in this domain" (audit only) on the DCs, wait, and rerun |
| Script 19: `HoursCovered` far below `-Hours` with `CappedAtMax = True` | The query hit `-MaxEventsPerQuery` | Raise the cap or shorten `-Hours`; counts are a lower bound |
| Script 19: `accounts-rc4-or-no-aes` `EvidenceUnavailable` or `Blocked` | No RSAT AD on the run host, or AD read refused | Run from a host with RSAT and domain read, or use `-SkipAdAccounts` |
| Script 19: `SourceOS` shows `NotFoundInAD` | Workstation name isn't a computer in this domain (non-Windows device, other domain, or deleted) | Look up the `SourceIp` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 18 AD delegation](18-ad-delegation.md) · [All scripts](README.md) · [20 Governance coverage →](20-governance-coverage.md)
