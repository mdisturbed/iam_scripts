# 04 - AD privileged and service accounts

**Script:** [`04-Get-ADPrivilegedAndServiceAccounts.ps1`](../../scripts/04-Get-ADPrivilegedAndServiceAccounts.ps1) · **Version:** 1.1.0 · **Source:** AD

> Who has admin rights on-prem (including via nesting and primary group), which accounts carry risky settings, and where are the service accounts?

Finds every account with admin rights on-prem, down to the real accounts, including rights gained through nested groups, primary-group membership, cross-domain members and foreign principals. Then checks every user and computer account in the domain for risky settings, the age of the domain secrets, who can read gMSA passwords, and likely service accounts.

**Groups expanded** (each row carries a `Tier`):
- **Tier0:** Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account / Server / Print / Backup Operators, Group Policy Creator Owners, Key Admins, Enterprise Key Admins, Domain Controllers, Read-only Domain Controllers, Enterprise Read-only Domain Controllers, Cert Publishers, Cryptographic Operators, Hyper-V Administrators, DnsAdmins, the Exchange groups (Organization Management, Exchange Windows Permissions, Exchange Trusted Subsystem) when present, and any `-AdditionalPrivilegedGroups`
- **Tier1-access:** Remote Desktop Users, Remote Management Users, DHCP Administrators (logon or service rights, not domain admin)
- **Info:** Event Log Readers (low); Protected Users (membership reported, used for the `InProtectedUsers` column, never counted as privileged)

Forest-root groups (Schema Admins, Enterprise Admins, Enterprise Key Admins, Enterprise Read-only Domain Controllers) are read from the root domain, and every member is read from a DC of the domain that owns it, so a run in a child domain sees them. Accounts whose `primaryGroupID` is a privileged group's RID are added (they are not in `member`). Foreign security principals are translated to `DOMAIN\name`.

**Collects:** membership with the full nesting path; one row per privileged account with hygiene flags, tier, admin naming, product-default category and delegation protection; risky account settings domain-wide; secret ages; gMSA password readers; service-account candidates; `adminCount=1` leftovers.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ServiceNamePatterns` | `svc*`, `sa-*`, `sa_*`, … | Name patterns that indicate a service account |
| `-AdditionalPrivilegedGroups` | none | Custom admin groups to expand (Tier0) |
| `-AdminNamePatterns` | `adm*`, `*adm`, `*-adm*`, `*_adm*`, `a-*`, `a_*`, `da-*`, `*admin*` | Admin naming standard (`IsAdminNamed`). Set to the organization's convention |
| `-StaleDays` | `90` | Days without logon before flagging |
| `-PasswordAgeWarningDays` (alias `-PasswordAgeDays`) | `365` | Passwords older than this are flagged; also the age for `PasswordNeverExpiresAndOld` |
| `-SkipRiskFlags` | off | Skip the domain-wide risky-setting queries |

`-SearchBase` limits only the service-account name / description / SPN detections; every other section is domain-wide.

**Open first:** `summary.csv`, then `ad-privileged-accounts.csv` filtered on `Tier` = `Tier0`, then `ad-account-risk-flags.csv` filtered on `IsPrivileged` = `True`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-privileged-membership.csv` | Member found while expanding a privileged group | `PrivilegedGroup`, `MemberClass`, `Depth`, `NestingPath` (ends in `(primaryGroupID)` for primary-group members), `Tier` |
| `ad-privileged-accounts.csv` | Account in a privileged group (any tier except Protected Users) | `PrivilegedVia`, `Flags` (stale, never-expiring or old password, Kerberoastable, pre-auth disabled, delegation, nested-only, ForeignPrincipal, WellKnownPrincipal), then at the end `Tier`, `IsAdminNamed`, `Category`, `InProtectedUsers`, `AccountNotDelegated`, `SIDHistoryPresent`, `msDS-SupportedEncryptionTypes` |
| `ad-account-risk-flags.csv` | Account and risky setting, every user and computer in the domain | `SamAccountName`, `ObjectClass`, `Enabled`, `Flag`, `Detail`, `IsPrivileged` (Tier 0), `IsAdminNamed`, `Category`, `PwdLastSetUtc`, `LastLogonUtc` |
| `ad-domain-secrets-age.csv` | krbtgt, RODC `krbtgt_*`, built-in Administrator (RID 500), `AZUREADSSOACC$` | `Kind`, `Enabled`, `PwdLastSetUtc`, `AgeDays`, `LastLogonUtc` |
| `ad-gmsa-password-readers.csv` | gMSA and principal that can retrieve its password | `GmsaSamAccountName`, `GrantedTo`, `Principal`, `PrincipalClass`, `PrincipalEnabled`, `Via` (direct, or member of the granted group at any depth), `IsPrivileged`, `Status` |
| `ad-service-account-candidates.csv` | Candidate service account | `DetectionReasons`, `IsPrivileged` (Tier 0), `Stale`, `PasswordAgeDays`, `HasManagedBy` |
| `ad-admincount-orphans.csv` | User, computer or group with adminCount=1 no longer in a Tier 0 group | `ObjectClass`, hygiene columns (blank for groups) |

**Risk flags** (`Flag` column): `UnconstrainedDelegation` (domain controllers listed separately as `UnconstrainedDelegation-DomainController`), `ProtocolTransition` (read-only DCs listed as `ProtocolTransition-DomainController`), `ConstrainedDelegation` (targets in `Detail`), `ResourceBasedDelegation` (presence only), `PreAuthNotRequired`, `PasswordNotRequired`, `ReversibleEncryption`, `DesOnly`, `PasswordNeverExpiresAndOld`, `SIDHistory` (same-domain SIDs and privileged RIDs marked), `KeyCredentialOnUser` (shadow-credentials indicator, presence only), `Kerberoastable` (user accounts with an SPN; AES support from `msDS-SupportedEncryptionTypes` in `Detail`), `SensitiveNotDelegatedMissing` (enabled Tier 0 user accounts without "Account is sensitive and cannot be delegated" and not in Protected Users). All checks are server-side LDAP filters.

**Category:** `Builtin` (RID 500 / 501 / 502, krbtgt), `Domain controller`, `Entra Connect (sync account)` (`MSOL_*`, `AAD_*`, `ADSync*`, `Sync_*`), `Exchange (product default)`, `Managed service account`, `Foreign principal`, `Custom`.

**Reading it:**
- `Tier0` is what counts as "privileged" in the summary, `IsPrivileged` and the service-account and orphan checks. `Tier1-access` and `Info` rows are there to be read, not counted as admins.
- A Tier 0 account with `IsAdminNamed = False` and `Category = Custom` is a day-to-day-looking account with admin rights.
- `Domain Users` (or Domain Computers) nested in a privileged group is logged and the dataset marked Partial: every account is then effectively privileged, and those members are not listed one by one.
- Service accounts are candidates found by heuristics (SPN, never-expiring password, name pattern, description, gMSA). Confirm with owners before reporting a count as fact.
- `KeyCredentialOnUser` is also written by Windows Hello for Business key trust; confirm the source before calling it shadow credentials.
- A dataset marked **Partial** in `dataset-status.csv` had a read gap (a domain, group, member or query that could not be read); the `Note` and `run.log` say which. A failed check shows `Read failed` in the summary, never 0.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read; in a child domain, read of the forest root domain | RSAT AD |

`msDS-KeyCredentialLink` and gMSA password-reader lists may not be readable by every account; empty results there are labelled "not readable or none". Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Domain Admins membership in ADUC, including a nested group if one exists; one account whose primary group is Domain Admins (if any) appears with `(primaryGroupID)`; the krbtgt age matches `Get-ADUser krbtgt -Properties PasswordLastSet`.

Usually tuned on first run: service / admin account name patterns (`-ServiceNamePatterns`, `-AdminNamePatterns`). See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 04: `Forest root domain ... not readable` | Run from a child domain without access to a root DC | Allow the run account to reach a root-domain DC (ADWS, TCP 9389); root groups are otherwise missing and the membership datasets are Partial |
| Script 04: `Could not read CN=...` for a member | Member in a domain or forest that can't be reached, or a deleted object | The member is listed as `unresolved (read failed)`; check the trust or clean up the membership |
| Script 04: foreign principals show `(not translated)` | The run machine can't resolve the SID (trust down, or not a Windows host) | Translate the SID in the trusted forest; the SID is in `SamAccountName` |
| Script 04: `Risk check '...' failed` | That LDAP query was refused (permissions or timeout) | Shows `Read failed` in the summary; rerun later or with `-SkipRiskFlags` to skip all |
| Script 04: `ad-gmsa-password-readers` Blocked | The run account can't read gMSA objects | Run with an account that can read `CN=Managed Service Accounts` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 03 Apps and consents](03-apps-and-consents.md) · [All scripts](README.md) · [05 AD group nesting →](05-ad-group-nesting.md)
