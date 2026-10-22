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
| `Partial` | Data collected, but part of the source could not be read (one domain, some groups, some mailboxes). The dataset Note says what is missing | Read the note; fix access for the missing part and rerun, or record the gap |
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

- [01 MFA coverage](scripts/01-mfa-coverage.md#output): `ca-policies.csv`, `ca-exclusions.csv`, `ca-excluded-group-members.csv`, `ca-excluded-role-holders.csv`, `mfa-registration.csv`, `auth-methods-policy.csv`, `signins-singlefactor-success.csv`, `signins-noninteractive-singlefactor.csv`
- [02 Entra privileged access](scripts/02-entra-privileged-access.md#output): `role-assignments-active.csv`, `role-assignments-eligible.csv`, `role-group-members.csv`, `role-assignable-groups.csv`, `privileged-principals-effective.csv`, `privileged-users.csv`, `privileged-service-principals.csv`, `custom-role-definitions.csv`, `administrative-units.csv`, `pim-activations.csv`
- [03 Apps and consents](scripts/03-apps-and-consents.md#output): `tenant-consent-settings.csv`, `app-registrations.csv`, `app-credentials.csv`, `federated-credentials.csv`, `app-config-risks.csv`, `app-management-policies.csv`, `service-principal-credentials.csv`, `service-principals.csv`, `app-permissions-application.csv`, `app-assignments.csv`, `app-permissions-delegated.csv`, `app-risk-summary.csv`
- [04 AD privileged and service accounts](scripts/04-ad-privileged-and-service-accounts.md#output): `ad-privileged-membership.csv`, `ad-privileged-accounts.csv`, `ad-service-account-candidates.csv`, `ad-admincount-orphans.csv`, `ad-account-risk-flags.csv`, `ad-domain-secrets-age.csv`, `ad-gmsa-password-readers.csv`
- [05 AD group nesting](scripts/05-ad-group-nesting.md#output): `ad-groups.csv`, `ad-circular-nesting.csv`, `ad-group-edges.csv`, `ad-group-reach.csv`
- [06 JML timing](scripts/06-jml-timing.md#output): `jml-matched.csv`, `jml-terminated-still-enabled.csv`, `jml-activity-after-termination.csv`, `jml-hr-active-no-account.csv`, `jml-ad-orphan-candidates.csv`, `secondary-accounts.csv`, `mover-mismatches.csv`, `entra-signin-check.csv`, `cloud-only-users-not-in-hr.csv`
- [07 Role mining](scripts/07-role-mining.md#output): `excluded-accounts.csv`, `no-population-users.csv`, `birthright-candidates.csv`, `attribute-quality.csv`, `attribute-value-variants.csv`, `populations.csv`, `role-candidates.csv`, `outliers.csv`, `access-load.csv`
- [08 Extension attribute inventory](scripts/08-extension-attribute-inventory.md#output): `entra-cloudonly-extension-usage.csv`, `entra-device-extension-usage.csv`, `entra-directory-extensions.csv`, `entra-custom-security-attributes.csv`, `attribute-consumers.csv`, `ad-attribute-usage.csv`
- [09 Mail forwarding and external sharing](scripts/09-mail-forwarding-and-external-sharing.md#output): `exo-accepted-domains.csv`, `exo-mailbox-forwarding.csv`, `exo-inbox-rules.csv`, `mailbox-delegation.csv`, `mailbox-read-errors.csv`, `exo-transport-rules.csv`, `transport-rules-risky.csv`, `outbound-connectors.csv`, `exo-remote-domains.csv`, `exo-outbound-spam-policies.csv`, `application-access-policies.csv`, `app-rbac-role-assignments.csv`, `spo-tenant-sharing-settings.csv`, `spo-site-sharing.csv`, `spo-external-users.csv`
- [10 Guest access](scripts/10-guest-access.md#output): `external-collaboration-settings.csv`, `cross-tenant-partners.csv`, `guests.csv`, `guest-group-memberships.csv`, `guest-owned-objects.csv`, `privileged-guests.csv`, `guests-by-domain.csv`
- [11 Azure RBAC](scripts/11-azure-rbac.md#output): `azure-management-groups.csv`, `azure-subscriptions.csv`, `azure-role-assignments.csv`, `azure-eligible-assignments.csv`, `azure-effective-users.csv`, `azure-custom-roles.csv`, `azure-classic-administrators.csv`, `keyvaults.csv`, `keyvault-access-policies.csv`, `lighthouse-delegations.csv`, `azure-deny-assignments.csv`, `managed-identities.csv`
- [12 Stale accounts](scripts/12-stale-accounts.md#output): `identity-activity.csv`, `entra-synced-unmatched.csv`, `duplicate-anchors.csv`, `ad-computers.csv`, `ad-managed-service-accounts.csv`
- [13 Hybrid sync scope](scripts/13-hybrid-sync-scope.md#output): `sync-tenant-status.csv`, `sync-ou-coverage-users.csv`, `ad-users-not-in-entra.csv`, `duplicate-anchors.csv`, `entra-synced-without-ad-match.csv`, `matched-pair-mismatches.csv`, `cloud-only-possible-duplicates.csv`, `user-provisioning-errors.csv`, `sync-ou-coverage-groups.csv`, `entra-synced-groups-without-ad-match.csv`, `group-provisioning-errors.csv`, `privileged-ad-accounts-synced.csv`, `sync-service-accounts.csv`, `device-sync-coverage.csv`
- [14 IGA reconciliation](scripts/14-iga-reconciliation.md#output): `iga-input-profile.csv`, `accounts-ad-not-in-iga.csv`, `accounts-iga-not-in-ad.csv`, `account-status-mismatch.csv`, `governed-groups.csv`, `memberships-outside-iga.csv`, `nested-memberships-outside-iga.csv`, `governed-group-nonuser-members.csv`, `assignments-not-in-ad.csv`, `ungoverned-groups.csv`, `inactive-but-still-member.csv`, `duplicate-keys.csv`
- [15 Rule-managed access](scripts/15-rule-managed-access.md#output): `role-definition-check.csv`, `user-reconciliation.csv`, `drift-detail.csv`, `rule-group-unexpected-members.csv`
- [16 Device posture](scripts/16-device-posture.md#output): `entra-devices.csv`, `laps-bitlocker-coverage.csv`, `device-registration-policy.csv`, `intune-devices.csv`, `compliance-policies.csv`, `enrollment-restrictions.csv`, `app-protection-policies.csv`, `device-ca-exclusions.csv`, `ca-device-requirements.csv`
- [17 AWS IAM posture](scripts/17-aws-iam-posture.md#output): `aws-accounts.csv`, `aws-iam-users.csv`, `aws-access-keys.csv`, `aws-iam-roles.csv`, `aws-saml-providers.csv`, `aws-oidc-providers.csv`, `aws-effective-admins.csv`, `aws-group-memberships.csv`, `aws-access-analyzer-findings.csv`, `aws-unused-access-findings.csv`, `aws-org-policies.csv`, `aws-org-delegated-admins.csv`, `aws-identity-center-permission-sets.csv`, `aws-identity-center-assignments.csv`, `aws-identity-center-effective-users.csv`
- [18 AD delegation](scripts/18-ad-delegation.md#output): `ad-delegations.csv`, `ad-nondefault-owners.csv`, `ad-delegation-effective-users.csv`, `ad-delegation-by-trustee.csv`
- [19 DC authentication protocols](scripts/19-dc-authentication-protocols.md#output): `dc-read-status.csv`, `ntlm-logons.csv`, `ntlm-validations.csv`, `ntlm-dc-audit-8004.csv`, `ntlm-failed-logons.csv`, `kerberos-preauth-failures.csv`, `kerberos-weak-encryption.csv`, `kerberos-tgt-no-preauth.csv`, `accounts-rc4-or-no-aes.csv`
- [20 Governance coverage](scripts/20-governance-coverage.md#output): `access-review-definitions.csv`, `access-review-latest-decisions.csv`, `review-coverage.csv`, `access-packages.csv`, `access-package-resources.csv`, `lifecycle-workflows.csv`
- [21 Identity risk](scripts/21-identity-risk.md#output): `risky-users.csv`, `risk-detections.csv`, `risk-detections-by-type.csv`, `risky-service-principals.csv`, `service-principal-risk-detections.csv`, `ca-risk-policies.csv`, `risk-policy-exclusions.csv`, `risky-user-history.csv`
- [22 PIM role settings](scripts/22-pim-role-settings.md#output): `pim-role-settings.csv`, `pim-group-settings.csv`, `pim-alerts.csv`
- [23 AD attribute population](scripts/23-ad-attribute-population.md#output): `attribute-population.csv`, `schema-class-closure.csv`, `attribute-duplicates.csv`, `attribute-population-breakdown.csv`
- [24 CA report-only impact](scripts/24-ca-reportonly-impact.md#output): `ca-policy-results.csv`, `ca-reportonly-impact.csv`, `no-enforced-policy-signins.csv`
- [25 Purview classification and DLP](scripts/25-purview-classification.md#output): `purview-sensitivity-labels.csv`, `purview-label-policies.csv`, `purview-autolabel-policies.csv`, `purview-autolabel-rules.csv`, `purview-dlp-policies.csv`, `purview-dlp-rules.csv`, `policy-exclusions.csv`, `purview-adaptive-scopes.csv`, `purview-sensitive-info-types.csv`, `purview-role-holders.csv`, `purview-ediscovery-admins.csv`, `purview-aip-super-users.csv`, `purview-retention-policies.csv`, `purview-retention-labels.csv`, `purview-content-explorer-counts.csv`, `purview-activity-summary.csv`
- [26 PAM vault coverage](scripts/26-pam-vault-coverage.md#output): `privileged-vault-coverage.csv`, `pam-entries-unmatched.csv`, `source-runs.csv`

[← Back to README](../README.md)
