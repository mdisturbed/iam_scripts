# 09 - Mail forwarding and external sharing

**Script:** [`09-Get-MailForwardingAndSharing.ps1`](../../scripts/09-Get-MailForwardingAndSharing.ps1) · **Version:** 1.1.0 · **Source:** Exchange Online + SharePoint

> Is mail being forwarded out, who can read or send as other mailboxes, and how open is SharePoint / OneDrive sharing?

The human side of "where is my data going" (script 03 covers app consents), plus the mailbox delegation and app mailbox access that let one identity act on another's mail.

**Collects:** accepted domains; mailboxes (user, shared, room, equipment) with forwarding set, flagged external; inbox rules, hidden rules included, that forward or redirect (flagged external) and rules that delete or bury mail in RSS Feeds / Deleted Items / Archive / Conversation History (`ForwardAndHide` is a common sign of a compromised mailbox); mailboxes whose rules or permissions could not be read; FullAccess, SendAs and SendOnBehalf delegation with group trustees expanded to their nested members; transport rules that redirect, copy or BCC, and rules that weaken protection (route through a connector, SCL -1, strip encryption, set filtering-bypass headers); outbound connectors; remote domains allowing auto-forward; outbound spam policy forwarding mode; application access policies and RBAC for Applications role assignments; SharePoint tenant sharing settings; per-site sharing capability, domain restrictions, default link type and link / guest expiry; optionally external users per site.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ExchangeOrganization` | none | e.g. `contoso.onmicrosoft.com`; required for app-only Exchange sign-in |
| `-MaxMailboxes` | `0` (all) | Limit the inbox-rule scan to the first N user / shared mailboxes Exchange returns (one call per mailbox); the dataset note records the limit |
| `-SkipInboxRules` | off | Skip inbox rules (fast pass) |
| `-SkipDelegation` | off | Skip FullAccess / SendAs / SendOnBehalf (one permission call per mailbox) |
| `-SkipSharePointSettings` | off | Skip the Graph SharePoint settings |
| `-SkipSiteSharing` | off | Skip the per-site sharing read. It runs by default when the SharePoint Online module is installed; without the module the dataset is `Deferred` |
| `-IncludeSiteSharing` | off | Kept for compatibility; has no effect (site sharing runs by default) |
| `-SharePointAdminUrl` | derived | e.g. `https://contoso-admin.sharepoint.com`; when blank it is derived from the initial `*.onmicrosoft.com` domain |
| `-IncludeOneDrive` | off | Include OneDrive sites in the site scan |
| `-IncludeExternalUsers` | off | List external users on every site that allows external sharing (pages of 50 per site) |

**Open first:** `summary.csv`, then `exo-inbox-rules.csv` filtered on `ForwardAndHide` and `ExternalForward`, then `mailbox-delegation.csv` filtered on `Right` = `FullAccess` / `SendAs`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `exo-accepted-domains.csv` | Accepted domain | used to decide internal vs external |
| `exo-mailbox-forwarding.csv` | Mailbox with forwarding set (user, shared, room, equipment) | `ForwardingSmtpAddress`, `ForwardingAddressResolved`, `DeliverToMailboxAndForward`, `IsExternal` |
| `exo-inbox-rules.csv` | Inbox rule (hidden rules included) that forwards, redirects, deletes or buries mail | `ExternalTargets`, `MoveToFolder`, `DeleteMessage`, `Flags` (ExternalForward / InternalForward / DeletesOrBuriesMail / ForwardAndHide). `Partial` when any mailbox could not be read |
| `mailbox-delegation.csv` | Mailbox right held by a trustee; group trustees get one row for the group and one per member | `Mailbox`, `MailboxType`, `Trustee`, `TrusteeType`, `Right` (FullAccess / SendAs / SendOnBehalf), `IsInherited`, `ViaGroup` (group path, blank for a direct grant) |
| `mailbox-read-errors.csv` | Mailbox whose inbox rules or permissions could not be read | `Mailbox`, `Error`, `Source` |
| `exo-transport-rules.csv` | Transport rule that redirects, copies or BCCs | `ExternalTargets`, `State`, `Mode` |
| `transport-rules-risky.csv` | Transport rule that weakens protection | `RiskReasons` (RoutesViaOutboundConnector / BypassSpamFiltering(SCL-1) / RemovesMessageEncryption / RemovesAttachmentEncryption / SetsBypassHeader), `RouteMessageOutboundConnector`, `SetSCL`, `SetHeaderName` |
| `outbound-connectors.csv` | Outbound connector | `Enabled`, `ConnectorType`, `SmartHosts`, `RecipientDomains`, `TlsSettings`, `IsTransportRuleScoped`, `Flags` |
| `exo-remote-domains.csv` | Remote domain | `AutoForwardEnabled` |
| `exo-outbound-spam-policies.csv` | Outbound spam policy | `AutoForwardingMode` |
| `application-access-policies.csv` | Application access policy | `AppId`, `AccessRight` (RestrictAccess / DenyAccess), `ScopeName` |
| `app-rbac-role-assignments.csv` | Exchange application role granted to a service principal (RBAC for Applications) | `App`, `Role`, `CustomResourceScope`, `Flags` (OrganizationWide) |
| `spo-tenant-sharing-settings.csv` | Tenant sharing setting | `Setting`, `Value` |
| `spo-site-sharing.csv` | Site | `SharingCapability`, `AnyoneLinksAllowed`, `ExternalSharingAllowed`, `SharingDomainRestrictionMode`, `SharingAllowedDomainList`, `SharingBlockedDomainList`, `DefaultSharingLinkType`, `AnonymousLinkExpirationInDays`, `ExternalUserExpirationInDays`, `DetailRead` |
| `spo-external-users.csv` | External user on a site (`-IncludeExternalUsers`) | `SiteUrl`, `Email`, `AcceptedAs`, `WhenCreated`, `InvitedBy` |

**Reading it:** review `ForwardAndHide` rules first; forwarding mail externally while hiding replies is a classic sign of a compromised mailbox. External forwarding only works if both the outbound spam policy and the remote domain allow it, so read those two files together. A mailbox listed in `mailbox-read-errors.csv` was not checked, so its absence from the rule and delegation files proves nothing.

In `mailbox-delegation.csv`, filter `ViaGroup` non-blank to see the accounts that hold a right only through a group; `TrusteeType` `Unresolved (SID only ...)` is usually a deleted account still on the ACL. Built-in Exchange and system trustees (SELF, Organization Management, Exchange Servers and similar) and Deny entries are left out. SendAs rows on a recipient that is not a scanned mailbox (for example a distribution group) show `MailboxType` = `Recipient (not a scanned mailbox)`.

An app with Graph `Mail.Read` / `Mail.ReadWrite` application permission (script 03) can read every mailbox unless an application access policy or an RBAC for Applications scope limits it; `OrganizationWide` in `app-rbac-role-assignments.csv` means no scope.

`spo-site-sharing.csv` reads each site by URL, because the site list leaves the sharing properties at default values. `DetailRead` = `False` means only the list values were available for that site (the dataset is then `Partial`). An `AnonymousLinkExpirationInDays` / `ExternalUserExpirationInDays` of `0` means the site follows the tenant setting.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | SharePointTenantSettings.Read.All | Exchange: Global Reader or View-Only Organization Management (covers mailbox / recipient permissions, connectors, application access policies and role assignments); SharePoint Administrator or Global Reader for per-site sharing and `-IncludeExternalUsers` | ExchangeOnlineManagement, Graph Auth, SPO module (optional; per-site sharing is `Deferred` without it) |

Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One known forwarding mailbox or inbox rule (if any); one known shared mailbox's FullAccess members in the Exchange admin center; tenant sharing level in the SharePoint admin center.

See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 09: `exo-inbox-rules` slow | One call per mailbox | `-MaxMailboxes 500` for a sample, or `-SkipInboxRules` |
| `mailbox-delegation` slow | One permission call per mailbox, plus group expansion | `-SkipDelegation` for a fast pass |
| `exo-inbox-rules` or `mailbox-delegation` is `Partial` | Some mailboxes could not be read, or a group trustee could not be expanded | See `mailbox-read-errors.csv` and run.log; re-run with an account that has View-Only Organization Management |
| `spo-site-sharing` is `Deferred` | SharePoint Online module not installed | Install `Microsoft.Online.SharePoint.PowerShell` (Windows PowerShell 5.1) or accept the tenant-level settings only |
| `spo-site-sharing` is `Blocked`: could not derive the admin URL | No `*.onmicrosoft.com` accepted domain visible | Pass `-SharePointAdminUrl https://contoso-admin.sharepoint.com` |
| `spo-site-sharing` is `Partial` | Some sites could not be read by URL | Check run.log; the account needs SharePoint Administrator or Global Reader |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 08 Extension attribute inventory](08-extension-attribute-inventory.md) · [All scripts](README.md) · [10 Guest access →](10-guest-access.md)
