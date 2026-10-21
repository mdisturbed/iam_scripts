# Output and evidence

What every run writes, what the dataset statuses mean, and how to handle the files. Per-script output files and columns are on each [script page](scripts/README.md).

## Run folder

```
<OutputRoot>\
  07-RoleMining\
    20261020-140501Z\
      attribute-quality.csv      data files (one per dataset)
      role-candidates.csv
      ...
      summary.csv                headline metrics for the status report
      dataset-status.csv         one row per dataset: status, rows, SHA-256, note
      run-manifest.json          who / where / when / scopes / parameters / datasets
      run.log                    timestamped log of the run
```

- All timestamps are UTC, ISO 8601, independent of the run machine's regional settings.
- `run-manifest.json` records the Windows account and machine, the Graph account and app, the scopes in the token, the Azure / Exchange connection where used, the parameters, and every dataset with its row count and SHA-256.
- Each run gets a new folder, so reruns never overwrite earlier evidence. Compare `summary.csv` across runs to show change.
- Scripts that read an input file (06, 14, 15) record its SHA-256, so you can prove which export was used without storing it with the results.

## Dataset statuses

| Status | Meaning | What to do |
|--------|---------|------------|
| `Completed` | Data collected. Zero rows is still Completed. | Nothing |
| `Blocked` | Permission denied or the call failed | Fix access, rerun |
| `Deferred` | Skipped on purpose by a switch, or an optional input wasn't supplied | Rerun with the switch or input when ready |
| `EvidenceUnavailable` | The tenant can't produce it (e.g. licence not present) | Record as a finding |

## Handling the output

The CSVs contain identity data (names, UPNs, sign-in activity, group membership, mail forwarding targets), and scripts 06, 14 and 15 read HR or IGA exports. Treat every run folder as sensitive:

- Store output only in the approved evidence location, **never in this repository**. `.gitignore` excludes `output/` and all CSV, JSON and log files; only the placeholder templates in `examples/` are allowed.
- Follow the environment's retention rule and delete local copies once evidence is filed.
- Use `-SampleValueCount 0` with script 08 if attribute values could be personal data.
- Do not paste raw output into tools that aren't approved for that data.

## Output files by script

- [01 MFA coverage](scripts/01-mfa-coverage.md#output): `ca-policies.csv`, `ca-exclusions.csv`, `ca-excluded-group-members.csv`, `mfa-registration.csv`, `signins-singlefactor-success.csv`
- [02 Entra privileged access](scripts/02-entra-privileged-access.md#output): `role-assignments-active.csv`, `role-assignments-eligible.csv`, `role-group-members.csv`, `role-assignable-groups.csv`, `privileged-users.csv`
- [03 Apps and consents](scripts/03-apps-and-consents.md#output): `tenant-consent-settings.csv`, `app-registrations.csv`, `app-credentials.csv`, `service-principals.csv`, `app-permissions-application.csv`, `app-permissions-delegated.csv`, `app-risk-summary.csv`
- [04 AD privileged and service accounts](scripts/04-ad-privileged-and-service-accounts.md#output): `ad-privileged-membership.csv`, `ad-privileged-accounts.csv`, `ad-service-account-candidates.csv`, `ad-admincount-orphans.csv`
- [05 AD group nesting](scripts/05-ad-group-nesting.md#output): `ad-groups.csv`, `ad-circular-nesting.csv`
- [06 JML timing](scripts/06-jml-timing.md#output): `jml-matched.csv`, `jml-terminated-still-enabled.csv`, `jml-activity-after-termination.csv`, `jml-hr-active-no-account.csv`, `jml-ad-orphan-candidates.csv`
- [07 Role mining](scripts/07-role-mining.md#output): `attribute-quality.csv`, `attribute-value-variants.csv`, `populations.csv`, `birthright-candidates.csv`, `role-candidates.csv`, `outliers.csv`
- [08 Extension attribute inventory](scripts/08-extension-attribute-inventory.md#output): `ad-attribute-usage.csv`, `entra-cloudonly-extension-usage.csv`, `entra-directory-extensions.csv`, `entra-custom-security-attributes.csv`
- [09 Mail forwarding and external sharing](scripts/09-mail-forwarding-and-external-sharing.md#output): `exo-accepted-domains.csv`, `exo-mailbox-forwarding.csv`, `exo-inbox-rules.csv`, `exo-transport-rules.csv`, `exo-remote-domains.csv`, `exo-outbound-spam-policies.csv`, `spo-tenant-sharing-settings.csv`, `spo-site-sharing.csv`
- [10 Guest access](scripts/10-guest-access.md#output): `external-collaboration-settings.csv`, `guests.csv`, `guests-by-domain.csv`
- [11 Azure RBAC](scripts/11-azure-rbac.md#output): `azure-management-groups.csv`, `azure-subscriptions.csv`, `azure-role-assignments.csv`, `azure-eligible-assignments.csv`, `azure-custom-roles.csv`, `azure-classic-administrators.csv`
- [12 Stale accounts](scripts/12-stale-accounts.md#output): `identity-activity.csv`, `ad-computers.csv`
- [13 Hybrid sync scope](scripts/13-hybrid-sync-scope.md#output): `sync-tenant-status.csv`, `sync-ou-coverage-users.csv`, `ad-users-not-in-entra.csv`, `entra-synced-without-ad-match.csv`, `cloud-only-possible-duplicates.csv`, `user-provisioning-errors.csv`, `sync-ou-coverage-groups.csv`, `entra-synced-groups-without-ad-match.csv`
- [14 IGA reconciliation](scripts/14-iga-reconciliation.md#output): `iga-input-profile.csv`, `accounts-ad-not-in-iga.csv`, `accounts-iga-not-in-ad.csv`, `account-status-mismatch.csv`, `governed-groups.csv`, `memberships-outside-iga.csv`, `assignments-not-in-ad.csv`, `ungoverned-groups.csv`
- [15 Rule-managed access](scripts/15-rule-managed-access.md#output): `role-definition-check.csv`, `user-reconciliation.csv`, `drift-detail.csv`
- [16 Device posture](scripts/16-device-posture.md#output): `entra-devices.csv`, `intune-devices.csv`, `compliance-policies.csv`, `ca-device-requirements.csv`
- [17 AWS IAM posture](scripts/17-aws-iam-posture.md#output): `aws-accounts.csv`, `aws-iam-users.csv`, `aws-access-keys.csv`, `aws-iam-roles.csv`, `aws-saml-providers.csv`, `aws-access-analyzer-findings.csv`, `aws-identity-center-permission-sets.csv`, `aws-identity-center-assignments.csv`
- [18 AD delegation](scripts/18-ad-delegation.md#output): `ad-delegations.csv`, `ad-nondefault-owners.csv`, `ad-delegation-by-trustee.csv`
- [19 DC authentication protocols](scripts/19-dc-authentication-protocols.md#output): `dc-read-status.csv`, `ntlm-logons.csv`, `ntlm-validations.csv`, `kerberos-weak-encryption.csv`
- [20 Governance coverage](scripts/20-governance-coverage.md#output): `access-review-definitions.csv`, `access-review-latest-decisions.csv`, `review-coverage.csv`, `access-packages.csv`
- [21 Identity risk](scripts/21-identity-risk.md#output): `risky-users.csv`, `risk-detections.csv`, `risk-detections-by-type.csv`, `risky-service-principals.csv`, `ca-risk-policies.csv`
- [22 PIM role settings](scripts/22-pim-role-settings.md#output): `pim-role-settings.csv`
- [23 AD attribute population](scripts/23-ad-attribute-population.md#output): `attribute-population.csv`, `schema-class-closure.csv`
- [24 CA report-only impact](scripts/24-ca-reportonly-impact.md#output): `ca-policy-results.csv`, `ca-reportonly-impact.csv`
- [25 Purview classification and DLP](scripts/25-purview-classification.md#output): `purview-sensitivity-labels.csv`, `purview-label-policies.csv`, `purview-autolabel-policies.csv`, `purview-autolabel-rules.csv`, `purview-dlp-policies.csv`, `purview-dlp-rules.csv`, `purview-sensitive-info-types.csv`, `purview-content-explorer-counts.csv`
- [26 PAM vault coverage](scripts/26-pam-vault-coverage.md#output): `privileged-vault-coverage.csv`, `pam-entries-unmatched.csv`, `source-runs.csv`

[← Back to README](../README.md)
