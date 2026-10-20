# 09 - Mail forwarding and external sharing

**Script:** [`09-Get-MailForwardingAndSharing.ps1`](../../scripts/09-Get-MailForwardingAndSharing.ps1) · **Version:** 1.0.0 · **Source:** Exchange Online + SharePoint

> Is mail being forwarded out, and how open is SharePoint / OneDrive sharing?

The human side of "where is my data going" (script 03 covers apps).

**Collects:** accepted domains; mailboxes with forwarding set, flagged external; inbox rules that forward or redirect (flagged external) and rules that delete or bury mail in RSS Feeds / Deleted Items / Archive / Conversation History (`ForwardAndHide` is a common sign of a compromised mailbox); transport rules that redirect, copy or BCC; remote domains allowing auto-forward; outbound spam policy forwarding mode; SharePoint tenant sharing settings; optionally per-site sharing capability.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ExchangeOrganization` | none | e.g. `contoso.onmicrosoft.com`; required for app-only Exchange sign-in |
| `-MaxMailboxes` | `0` (all) | Limit the inbox-rule scan (one call per mailbox) |
| `-SkipInboxRules` | off | Skip inbox rules (fast pass) |
| `-SkipSharePointSettings` | off | Skip the Graph SharePoint settings |
| `-IncludeSiteSharing` | off | Read every site's sharing capability (needs `-SharePointAdminUrl`) |
| `-SharePointAdminUrl` | none | e.g. `https://contoso-admin.sharepoint.com` |
| `-IncludeOneDrive` | off | Include OneDrive sites in the site scan |

**Open first:** `summary.csv`, then `exo-inbox-rules.csv` filtered on `ForwardAndHide` and `ExternalForward`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `exo-accepted-domains.csv` | Accepted domain | used to decide internal vs external |
| `exo-mailbox-forwarding.csv` | Mailbox with forwarding set | `ForwardingSmtpAddress`, `ForwardingAddressResolved`, `DeliverToMailboxAndForward`, `IsExternal` |
| `exo-inbox-rules.csv` | Inbox rule that forwards, redirects, deletes or buries mail | `ExternalTargets`, `MoveToFolder`, `DeleteMessage`, `Flags` (ExternalForward / InternalForward / DeletesOrBuriesMail / ForwardAndHide) |
| `exo-transport-rules.csv` | Transport rule that redirects, copies or BCCs | `ExternalTargets`, `State`, `Mode` |
| `exo-remote-domains.csv` | Remote domain | `AutoForwardEnabled` |
| `exo-outbound-spam-policies.csv` | Outbound spam policy | `AutoForwardingMode` |
| `spo-tenant-sharing-settings.csv` | Tenant sharing setting | `Setting`, `Value` |
| `spo-site-sharing.csv` | Site | `SharingCapability`, `AnyoneLinksAllowed`, `ExternalSharingAllowed` |

**Reading it:** review `ForwardAndHide` rules first; forwarding mail externally while hiding replies is a classic sign of a compromised mailbox. External forwarding only works if both the outbound spam policy and the remote domain allow it, so read those two files together.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | SharePointTenantSettings.Read.All | Exchange: Global Reader or View-Only Organization Management; (SharePoint Administrator or Global Reader for `-IncludeSiteSharing`) | ExchangeOnlineManagement, Graph Auth (+ SPO module) |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One known forwarding mailbox or inbox rule (if any); tenant sharing level in the SharePoint admin center.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 09: `exo-inbox-rules` slow | One call per mailbox | `-MaxMailboxes 500` for a sample, or `-SkipInboxRules` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 08 Extension attribute inventory](08-extension-attribute-inventory.md) · [All scripts](README.md) · [10 Guest access →](10-guest-access.md)
