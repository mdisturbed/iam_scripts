# 34 - Privileged register

**Script:** [`34-Get-PrivilegedRegister.ps1`](../../scripts/34-Get-PrivilegedRegister.ps1) · **Version:** 1.0.0 · **Source:** earlier runs of 02, 04, 11, 17, 18, 22, 26, 27 (+ attestation file)

> Which privileged accounts and roles exist, who owns each one and why, is it vaulted, and which privilege is unmanaged?

The privileged identity register. It has one row per privileged account (AD, Entra, Azure, AWS and workload identities), one row per privileged role or group, and a worksheet for owners to confirm owner and purpose. An account counts as managed only with an attested owner, an attested purpose, and either a vault or eligible-only (just-in-time) access. Connects to nothing.

**Collects:** privileged Entra users and workload identities (02), AD protected-group members, adminCount leftovers and privileged service accounts (04), users holding High or Critical AD delegated rights (18), Azure privileged role holders (11), AWS admins (17), PIM activation settings per role (22), vault coverage (26), and the identity population (27). 27 joins a person's AD and Entra accounts into one row, gives the category, and links an admin account to its owner through the HR id. Every source is optional except 02 or 04, and every one that's missing or unusable is named.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-EvidenceRoot` | `-OutputRoot` | Folder holding the earlier runs |
| `-AttestationCsv` | (none) | Owner and purpose answers ([template](../../examples/privileged-attestation.example.csv)) |
| `-NoPamPlatform` | off | No PAM vault exists: accounts without other vault evidence show `NotVaulted (no PAM platform)` instead of `Unknown` |
| `-IncludeServiceAccountCandidates` | off | Also list AD service account candidates with no privilege |
| `-IncludeComputerAccounts` | off | Also list computer accounts in privileged groups (domain controllers and similar) |
| `-AdminAffixPatterns` | `adm-`, `-adm`, `a-`, `da-` and similar | Regular expressions removed from an admin account name to find the person's own account |
| `-DelegationSeverities` | `Critical`, `High` | Which 18 delegation severities count as privilege |
| `-AllowHashMismatch` | off | Use a source file that changed after its run |

**Open first:** `summary.csv` (managed vs unmanaged, and why), then `privileged-register.csv` filtered on `Managed` = False, then `privileged-roles.csv`.

```powershell
# First run: produces the attestation worksheet
.\scripts\34-Get-PrivilegedRegister.ps1 -OutputRoot D:\Evidence -NoPamPlatform
# After owners answer: save the worksheet as registers\privileged-attestation.csv and rerun
.\scripts\34-Get-PrivilegedRegister.ps1 -OutputRoot D:\Evidence -NoPamPlatform -AttestationCsv D:\Engagement\registers\privileged-attestation.csv
```

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `privileged-register.csv` | Privileged identity | `Identity`, `DisplayName`, `SamAccountName`, `IdentityType`, `Category`, `Platforms`, `Privilege`, `Tier0`, `AssignmentModel`, `Enabled`, `LastActivityUtc`, `Owner`, `SuggestedOwner`, `SuggestedOwnerSource`, `Purpose`, `SuggestedPurpose`, `VaultStatus`, `VaultSource`, `Attestation`, `AttestedBy`, `AttestedOnUtc`, `ReviewByUtc`, `Managed`, `UnmanagedReasons`, `EvidenceState`, `EvidenceSources`, `Flags` |
| `privileged-roles.csv` | Privileged role or group | `Platform`, `Role`, `Scope`, `Tier0`, `Holders`, `StandingHolders`, `EligibleHolders`, `ActivationControls`, `Owner`, `Purpose`, `Attestation`, `Flags`, `EvidenceState`, `EvidenceSource` |
| `privileged-attestation-worksheet.csv` | Identity or role to attest | `Identity`, `IdentityType`, `Platforms`, `Privilege`, `Tier0`, `AssignmentModel`, `SuggestedOwner`, `SuggestedOwnerSource`, `SuggestedPurpose`, `Owner`, `Purpose`, `AttestedBy`, `AttestedOnUtc`, `ReviewByUtc`, `VaultStatus`, `Notes`, `CurrentState` |
| `source-runs.csv` | Source dataset read | `Script`, `Dataset`, `RunFolder`, `SourceStatus`, `HashCheck`, `UsedAs` |

`IdentityType`: Break-glass account, Admin account, Regular user account, Service account, Workload identity (service principal), Managed identity, Built-in account, Guest or external, Test account, Shared or resource account, AWS principal, Unclassified.

`AssignmentModel`: Standing, Eligible only (just in time), Mixed (standing and eligible), None (residual adminCount only). AD group membership is always standing.

`VaultStatus`, in this order of precedence: the attestation's `VaultStatus` (only values starting with `Vaulted` or `Sealed`, for example *Sealed (break-glass procedure)*, count as protected; anything else, such as *Not vaulted*, is shown but counts as not vaulted); script 26's match (`Vaulted`, `Unconfirmed (name-only match)`, `NotVaulted`); `NotVaulted (no PAM platform)` with `-NoPamPlatform`; otherwise `Unknown`. Workload identities show `N/A (workload identity)`: their credential lives on the app (see script 03).

`Attestation`: `Attested`, `Pending` (no row), `NotApproved` (no `AttestedBy`), `Expired` (`ReviewByUtc` passed).

`UnmanagedReasons`: No attested owner; No attested purpose; Attestation expired; Standing access not vaulted; Residual adminCount.

Flags: `Tier0StandingNotVaulted`, `PrivilegeOnRegularAccount`, `RegularAccountWithElevatedRights`, `PrivilegedGuest`, `NoOwnerFound`, `PermanentActiveRole`, `NotMfaRegistered`, `Tier0WithoutPhishResistantMfa`, `PrivilegedSyncedFromAD`, `NoRecentSignIn`, `ServiceAccountCandidate`, `AdminCountOrphan`, `PasswordNeverExpires`, `SpnOnPrivilegedUser`, `PreAuthDisabled`, `UnconstrainedDelegation`, `NoOwner`, `SecretOnServicePrincipal`, `ExpiredCredential`, `Disabled`.

**Reading it:**
- **Suggested values never count.** `SuggestedOwner` comes from app owners in the directory, the workforce account with the same HR id (27), or a name match after removing admin prefixes and suffixes (*confirm*). `SuggestedPurpose` comes from the AD description or the app name. Only `Owner` and `Purpose` from an attestation with `AttestedBy` count.
- **The attestation loop:** send `privileged-attestation-worksheet.csv` to the owners (or walk through it with the account and platform owners). Collect `Owner`, `Purpose`, `AttestedBy`, `AttestedOnUtc` and optionally `ReviewByUtc` and `VaultStatus`, save it as CSV, and rerun with `-AttestationCsv`. Identity can be a UPN, sAMAccountName, `DOMAIN\name` or the display name of a workload identity; roles use `role:<Platform>:<Role>`, as the worksheet writes them.
- **One person, one row** only when 27 has run, because it joins AD to Entra on the source anchor. Without 27, an admin's AD account and its synced Entra account are separate rows.
- **Evidence state** per row is the worst status of the source datasets that row came from. A source that ran but was Blocked (for example 18 without domain controller access) makes the register Partial, because privileged accounts from that source are missing. A source that never ran is noted, not counted as Partial.
- **Computer accounts** in privileged groups (domain controllers) are left out by default and counted in the summary.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| none | none | Read access to the evidence folder (earlier runs); the attestation file, if used | none |

## Pilot check

Your own admin account shows with the right roles and groups, and your workforce account is the `SuggestedOwner`. The number of Domain Admins members in `privileged-roles.csv` matches **Active Directory Users and Computers**. One attestation row you enter changes that identity's `Attestation` to `Attested` on the next run.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 34: `Needs at least script 02 ... or script 04` | Neither source has a usable run | Run 02 and 04 into the same evidence folder |
| Script 34: every `VaultStatus` is `Unknown` | No 26 run and no `-NoPamPlatform` | Run 26 with the vault export, or pass `-NoPamPlatform` when there's no vault |
| Script 34: the same admin appears twice | No usable 27 run | Run 27 so AD and Entra accounts are joined |
| Script 34: an attestation isn't applied | `AttestedBy` blank (`NotApproved`), `ReviewByUtc` passed (`Expired`), or the `Identity` doesn't match | Use the `Identity` value from the worksheet |
| Script 34: register Partial with *ran but is Blocked* | A source script couldn't read its system | Fix access and rerun that script, then rerun 34 |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 33 CA policy analysis](33-ca-policy-analysis.md) · [All scripts](README.md)
