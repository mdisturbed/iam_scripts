# 12 - Stale accounts

**Script:** [`12-Get-StaleAccounts.ps1`](../../scripts/12-Get-StaleAccounts.ps1) · **Version:** 1.1.0 · **Source:** AD + Entra

> Which identities are really unused once AD and Entra activity are combined, and what do the stale ones still hold?

A user can look stale in AD while signing in to Microsoft 365 every day, or the reverse. This joins AD and Entra, uses the newest activity from either side, and shows what each stale identity still holds: privileged group membership (adminCount), Entra directory roles, licences, SPNs and a password that never expires.

**Collects:** one row per identity (Hybrid, ADOnly, CloudOnly) with enabled state on each side, AD last logon, Entra interactive / non-interactive / successful sign-in, newest activity, activity bucket (0-30 … 365+, Never), category (`Admin`, `Service`, `Sync`, `Guest`, `User`), password last set, group count, adminCount, SPN, manager, admin naming, licence count, Entra roles (active and eligible, including through role-assignable groups), session revocation time and flags; synced Entra users with no AD match in this scope; Entra users sharing one source anchor; stale computer accounts; managed service accounts (gMSA / sMSA).

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AnchorAttribute` | `objectGUID` | Use `mS-DS-ConsistencyGuid` if Entra Connect anchors on it; an empty value falls back to `objectGUID`, as Entra Connect does |
| `-StaleDays` | `90` | Threshold for `Stale` and `NeverLoggedOn` |
| `-NewAccountGraceDays` | `30` | New accounts aren't flagged as never used until this old |
| `-PasswordAgeDays` | `365` | Threshold for `PasswordNeverExpiresOld` |
| `-EnabledOnly` | off | Only identities enabled on at least one side |
| `-SkipComputers` | off | Leave out AD computer accounts (included by default) |
| `-IncludeComputers` | off | Accepted for older command lines; has no effect |
| `-SkipEntraRoles` | off | Don't read Entra role assignments (`HoldsEntraRole` stays blank) |
| `-PreciseLastLogon` | off | Read `lastLogon` from every domain controller for the stale candidates only and use the newest. One query per candidate per DC: run it once the candidate list is small |
| `-AdminNamePatterns` | `adm*`, `*adm`, `*-adm*`, `*_adm*`, `a-*`, `a_*`, `da-*`, `*admin*` | Sets `IsAdminNamed` and the `Admin` category |
| `-ServiceNamePatterns` | `svc*`, `*-svc*`, `*_svc*`, `sa-*`, `sa_*` | Service naming for the `Service` category and `ServiceAccountNoOwner` |

Computer accounts are included by default; earlier versions needed `-IncludeComputers`.

**Open first:** `summary.csv`; the "Stale in AD but active in Entra" line shows how many accounts an AD-only check would have wrongly flagged, and "Stale or never used but privileged" is the first clean-up list.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `identity-activity.csv` | Identity (AD and/or Entra) | `Source` (Hybrid / ADOnly / CloudOnly), `ADEnabled`, `EntraEnabled`, `ADLastLogonUtc`, `EntraLast*Utc`, `NewestActivityUtc`, `NewestActivitySource`, `ActivityBucket`, `Flags`, `PwdLastSetUtc`, `PasswordNeverExpires`, `MemberOfCount`, `AdminCount`, `HasSPN`, `Manager`, `IsAdminNamed`, `Category`, `AssignedLicenseCount`, `HoldsEntraRole`, `EntraRoles`, `SignInSessionsValidFromUtc`, `ADLastLogonPrecise` |
| `entra-synced-unmatched.csv` | Synced Entra user with no AD match in this scope | `OnPremisesDomainName`, `OnPremisesSamAccountName`, `OnPremisesImmutableId`, `NewestEntraActivityUtc`, `AssignedLicenseCount`, `Reason` |
| `duplicate-anchors.csv` | Entra user sharing an `onPremisesImmutableId` with another | `OnPremisesImmutableId`, `UserPrincipalName`, `UsedForMatch`, `SharedBy` |
| `ad-computers.csv` | Computer account | `LastLogonUtc`, `PasswordLastSetUtc`, `Stale` |
| `ad-managed-service-accounts.csv` | gMSA / sMSA | `Type`, `LastLogonUtc`, `PasswordLastSetUtc`, `PrincipalsAllowedToRetrievePresent`, `Stale`, `Flags` (Stale, NoPrincipalAllowedToRetrieve, EntraConnectSync) |

`identity-activity.csv` flags: `NeverUsed`, `Stale(>nd)`, `EnabledMismatch`, `CreatedButNeverUsed`, `PasswordNeverExpires`, `Guest`, `NoActivityData`, `StaleButPrivileged` (stale or never used, with adminCount = 1 or an Entra role), `StaleButLicensed`, `DisabledButLicensed` (disabled in Entra, licence still assigned), `NeverLoggedOn` (no AD logon, created more than `-StaleDays` ago), `PasswordNeverExpiresOld`, `ServiceAccountNoOwner` (SPN or service name, no `manager` or `managedBy`).

**Reading it:**
- `NewestActivityUtc` is the newer of AD and Entra. `EnabledMismatch` means disabled on one side and enabled on the other, often a leaver disabled on-prem whose cloud object hasn't synced yet, or the reverse.
- `HoldsEntraRole` is `True`, `False`, `Unknown (Partial)` (some role data, such as eligible assignments or a role group's members, couldn't be read) or `EvidenceUnavailable` (role assignments couldn't be read at all). Only `False` means no role was found. `EntraRoles` lists each role as Active or Eligible, and the group it comes through.
- `ADLastLogonPrecise` is `True` when the AD date came from the per-DC `lastLogon` read, or `NoDcLogon` when no DC had a logon for a candidate.
- An Entra user in `duplicate-anchors.csv` with `UsedForMatch = False` was not joined to AD; it is also listed in `entra-synced-unmatched.csv`.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| Global Reader | User.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, GroupMember.Read.All | Domain read | RSAT AD, Graph Auth |

`signInActivity` needs Entra ID P1; eligible (PIM) role assignments need Entra ID P2. RoleManagement.Read.Directory and GroupMember.Read.All aren't needed with `-SkipEntraRoles`. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One account you know is active on both sides shows `0-30`; one disabled leaver shows as stale or disabled; one Entra admin shows `HoldsEntraRole = True` with the right role.

Usually tuned on first run: `-AnchorAttribute` if Entra Connect uses `mS-DS-ConsistencyGuid`; `-AdminNamePatterns` and `-ServiceNamePatterns` to your naming. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scripts 12 / 13: few AD users matched to Entra | Entra Connect anchors on a different attribute | `-AnchorAttribute 'mS-DS-ConsistencyGuid'` |
| Script 12: `HoldsEntraRole` is `EvidenceUnavailable` | RoleManagement.Read.Directory not consented, or no directory reader role | Consent the scope; the summary line "Entra role evidence" shows the error |
| Script 12: `HoldsEntraRole` is `Unknown (Partial)` | No Entra ID P2 (eligible roles) or GroupMember.Read.All missing (role groups) | See "Entra role evidence" in the summary; active direct assignments are still shown |
| Script 12: `lastLogon not readable on <DC>` | A DC is unreachable during `-PreciseLastLogon` | Precise values come from the DCs that answered; the summary note lists the unreachable ones |
| Script 12: `ad-managed-service-accounts` Blocked | No rights to read managed service accounts | Domain read is enough on most domains; check the run.log error |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 11 Azure RBAC](11-azure-rbac.md) · [All scripts](README.md) · [13 Hybrid sync scope →](13-hybrid-sync-scope.md)
