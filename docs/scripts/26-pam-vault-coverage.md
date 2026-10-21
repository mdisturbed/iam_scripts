# 26 - PAM vault coverage

**Script:** [`26-Compare-PamVaultCoverage.ps1`](../../scripts/26-Compare-PamVaultCoverage.ps1) · **Version:** 1.0.0 · **Source:** PAM export + earlier runs of 02, 04, 11, 17

> Which privileged accounts are managed in the PAM vault, and which are not?

"PAM coverage and residual risk" in numbers: every privileged account the other scripts found, checked against the vault's own account export. Connects to nothing; reads CSV files only.

**Collects:** privileged accounts from the latest run of 04 (AD protected groups), 02 (Entra role holders), 11 (Azure privileged roles held by users) and 17 (AWS IAM users with admin access) in the evidence folder; for each: Tier 0, enabled, vaulted or not, how it matched, and the vault entry (address, platform, safe, last verified). Also vault entries that match no privileged account, and which run and file each list came from (with SHA-256).

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-PamExportCsv` | required | Vault account export ([template](../../examples/pam-accounts.example.csv)) |
| `-EvidenceRoot` | `-OutputRoot` | Folder holding the earlier runs |
| `-PamAccountColumn` | `UserName` | Account name column (UPN, DOMAIN\name or name) |
| `-PamAddressColumn`, `-PamPlatformColumn`, `-PamSafeColumn`, `-PamLastVerifiedColumn` | `Address`, `PlatformId`, `SafeName`, (none) | Map the export's columns; blank if absent |
| `-Sources` | `AD`, `Entra`, `Azure`, `AWS` | Which privileged lists to check |

**Open first:** `summary.csv` (vaulted % per source, Tier 0 not vaulted), then `privileged-vault-coverage.csv` filtered on `Flags` = `Tier0NotVaulted`.

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `privileged-vault-coverage.csv` | Privileged account per source | `Source`, `Account`, `Tier0`, `Enabled`, `Vaulted`, `MatchMethod`, `VaultEntries`, `PamAddress`, `PamPlatform`, `PamSafe`, `PamLastVerified`, `Flags` (Tier0NotVaulted, NotVaulted, CheckMatch, MultipleVaultEntries, Disabled), `PrivilegedVia` |
| `pam-entries-unmatched.csv` | Vault entry matching no privileged account | `PamAccount`, `PamAddress`, `PamPlatform`, `PamSafe` |
| `source-runs.csv` | Source list | `Status` (Used / Not run / Skipped), `RunFolder`, `File`, `Sha256`, `Accounts` |

**Reading it:**
- Matching is case-insensitive: exact first (UPN or sAMAccountName), then name only (DOMAIN\ and @suffix removed). Name-only matches are flagged `CheckMatch`.
- The same IAM user name in two AWS accounts is matched to the vault entry whose address carries that account ID.
- The same person can appear under several sources (AD admin account, Entra role, Azure Owner); each privileged identity is listed where it was found.
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
| Script 26: a source shows `Not run` | That script hasn't run into this evidence folder | Run it (02, 04, 11 or 17) first, or point `-EvidenceRoot` at the right folder |
| Script 26: many `CheckMatch` rows | Vault stores DOMAIN\name while the directory uses the bare name | Review a few; usually correct |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 25 Purview classification and DLP](25-purview-classification.md) · [All scripts](README.md)
