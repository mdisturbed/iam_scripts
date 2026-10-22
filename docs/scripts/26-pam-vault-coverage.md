# 26 - PAM vault coverage

**Script:** [`26-Compare-PamVaultCoverage.ps1`](../../scripts/26-Compare-PamVaultCoverage.ps1) · **Version:** 1.1.0 · **Source:** PAM export + earlier runs of 02, 04, 11, 17, 18

> Which privileged accounts are managed in the PAM vault, and which are not?

"PAM coverage and residual risk" in numbers: every privileged account the other scripts found, down to the user accounts behind groups and delegations, checked against the vault's own account export. Connects to nothing; reads CSV files only.

**Collects:** privileged accounts from the latest run of 04 (AD protected-group members, adminCount leftovers and service-account candidates), 18 (users holding AD delegated rights), 02 (Entra role holders, including through groups and eligible assignments), 11 (Azure privileged roles held by users, including through groups and eligible assignments) and 17 (AWS admins) in the evidence folder; for each: Tier 0, enabled, vaulted (True / False / Unconfirmed), how it matched, and the vault entry (address, platform, safe, last verified, last changed). Also vault entries that match no privileged account, vault verification age, AD passwords changed outside the vault, and which run and file each list came from (with SHA-256).

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-PamExportCsv` | required | Vault account export ([template](../../examples/pam-accounts.example.csv)) |
| `-EvidenceRoot` | `-OutputRoot` | Folder holding the earlier runs |
| `-PamAccountColumn` | `UserName` | Account name column (UPN, DOMAIN\name or name) |
| `-PamAddressColumn`, `-PamPlatformColumn`, `-PamSafeColumn`, `-PamLastVerifiedColumn`, `-PamLastChangedColumn` | `Address`, `PlatformId`, `SafeName`, (none), (none) | Map the export's columns; blank if absent |
| `-VerifiedMaxDays` | `90` | Flag vaulted accounts whose last verification is older |
| `-Sources` | `AD`, `ADServiceAccount`, `ADDelegation`, `Entra`, `Azure`, `AWS` | Which privileged lists to check |
| `-AzurePrivilegedRoleNames` | the script 11 list (Owner, User Access Administrator, Contributor …) | Privileged Azure roles, used only for `azure-eligible-assignments.csv` |

**Open first:** `summary.csv` (vaulted % per source, Tier 0 not vaulted), then `privileged-vault-coverage.csv` filtered on `Flags` = `Tier0NotVaulted`, then rows with `Vaulted` = `Unconfirmed`.

## Sources

| Source | Script | Files (preferred first) | Tier 0 when |
|--------|--------|-------------------------|-------------|
| `AD` | 04 | `ad-privileged-accounts.csv`, `ad-admincount-orphans.csv` | Member (direct or nested) of Domain Admins, Enterprise Admins, Schema Admins or Administrators, or a `Tier` column says `Tier0`. Operator groups and adminCount leftovers are privileged but not Tier 0 |
| `AD service account` | 04 | `ad-service-account-candidates.csv` | Never (accounts already in the AD list are skipped) |
| `AD delegation` | 18 | `ad-delegation-effective-users.csv` | Highest severity is Critical |
| `Entra` | 02 | `privileged-principals-effective.csv` (users), else `privileged-users.csv` | The role is Tier 0 |
| `Azure` | 11 | `azure-effective-users.csv`, else `azure-role-assignments.csv` + `azure-eligible-assignments.csv` | Privileged role at root, management group or subscription |
| `AWS` | 17 | `aws-effective-admins.csv`, else `aws-iam-users.csv` (AdminAccess) | Always |

The newer file is used when it is present and not older than the classic one. A missing file doesn't stop the run: `source-runs.csv` shows `Not run` (the script never ran in this evidence folder) or `NotFound` (it ran, but an older version didn't write that file).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `privileged-vault-coverage.csv` | Privileged account per source | `Source`, `Account`, `Tier0`, `Enabled`, `Vaulted` (True / False / Unconfirmed), `MatchMethod`, `VaultEntries`, `PamAddress`, `PamPlatform`, `PamSafe`, `PamLastVerified`, `Flags`, `PrivilegedVia`, `PamLastChanged`, `PwdLastSetUtc`, `SourceFile` |
| `pam-entries-unmatched.csv` | Vault entry matching no privileged account | `PamAccount`, `PamAddress`, `PamPlatform`, `PamSafe` |
| `source-runs.csv` | Source file | `Status` (Used / Not run / NotFound / Skipped), `RunFolder`, `File`, `Sha256`, `Accounts` |

Flags: `Tier0NotVaulted`, `NotVaulted`, `CheckMatch`, `MultipleVaultEntries`, `Disabled`, `VaultNeverVerified`, `VaultVerificationOld(>nd)`, `PasswordChangedOutsideVault`.

**Reading it:**
- Matching is case-insensitive: exact first (UPN or sAMAccountName), then name only (DOMAIN\ and @suffix removed). A name-only match is `Vaulted = Unconfirmed` with `CheckMatch`, and isn't counted as vaulted in the summary. A vault that stores `CONTOSO\name` while AD reports `name` gives Unconfirmed: review a few and they are usually right.
- The same IAM user name in two AWS accounts is matched to the vault entry whose address carries that account ID; when the address points elsewhere the match is Unconfirmed.
- `PasswordChangedOutsideVault` (needs `-PamLastChangedColumn`) means AD `pwdLastSet` is more than a day newer than the vault's last change: someone reset the password outside the vault, so the vaulted credential may be stale.
- `VaultVerificationOld` / `VaultNeverVerified` (needs `-PamLastVerifiedColumn`): the vault hasn't confirmed the credential works recently.
- The same person can appear under several sources (AD admin account, AD delegation, Entra role, Azure Owner); each privileged identity is listed where it was found.
- An unmatched vault entry isn't necessarily wrong: it may be a local, application or break-glass account, or its source script hasn't been run.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Read access to the evidence folder; a PAM account export from the PAM team (account names and vault structure only, never passwords) | none |

## Pilot check

Before handing this script to others, confirm: one account you know is vaulted shows `Vaulted = True` with the right safe, and one you know is not shows `NotVaulted`.

Usually tuned on first run: the `-Pam*Column` mappings to the export's headers. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 26: `PAM export has no column ...` | Export headers differ | Map with `-PamAccountColumn` and the other column parameters; the error lists the columns |
| Script 26: a source shows `Not run` | That script hasn't run into this evidence folder | Run it (02, 04, 11, 17 or 18) first, or point `-EvidenceRoot` at the right folder |
| Script 26: a file shows `NotFound` | The script ran in an older version that didn't write it | Re-run the current version of that script; the classic file is used meanwhile |
| Script 26: many `Unconfirmed` rows | Vault stores DOMAIN\name while the directory uses the bare name | Review a few; usually correct |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 25 Purview classification and DLP](25-purview-classification.md) · [All scripts](README.md)
