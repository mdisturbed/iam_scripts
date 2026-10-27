# Script reference

One page per script: what it collects, parameters, output files, permissions, pilot check and troubleshooting.

| # | Page | Question it answers | Source | Version |
|---|------|--------------------|--------|---------|
| 01 | [MFA coverage](01-mfa-coverage.md) | Is MFA actually enforced everywhere, how strong is it, and who is left out? | Entra | 1.1.2 |
| 02 | [Entra privileged access](02-entra-privileged-access.md) | Who really holds Entra admin roles, down to the account, and are those accounts well managed? | Entra | 1.1.1 |
| 03 | [Apps and consents](03-apps-and-consents.md) | Which apps can reach our data, who owns and can use them, and are they governed? | Entra | 1.1.1 |
| 04 | [AD privileged and service accounts](04-ad-privileged-and-service-accounts.md) | Who has admin rights on-prem (including via nesting and primary group), which accounts carry risky settings, and where are the service accounts? | AD | 1.1.0 |
| 05 | [AD group nesting](05-ad-group-nesting.md) | How deep and messy is group nesting, which accounts does each group really reach, and how healthy are groups and their owners? | AD | 1.1.0 |
| 06 | [JML timing](06-jml-timing.md) | How quickly are joiners provisioned and leavers disabled, and which leavers and their admin accounts still hold access? | AD + HR file (+ Entra) | 1.1.0 |
| 07 | [Role mining](07-role-mining.md) | Which groups do people in the same department or job code share, who has far more access than their peers, and is the HR data clean enough to drive roles? | AD | 1.1.0 |
| 08 | [Extension attribute inventory](08-extension-attribute-inventory.md) | Which custom / extension attributes are free to carry new data, and does anything already read them? | AD (+ Entra) | 1.1.1 |
| 09 | [Mail forwarding and external sharing](09-mail-forwarding-and-external-sharing.md) | Is mail being forwarded out, who can read or send as other mailboxes, and how open is SharePoint / OneDrive sharing? | Exchange Online + SharePoint | 1.1.1 |
| 10 | [Guest access](10-guest-access.md) | How many guests and external accounts are there, are they used, what can they reach, and which partner tenants do we trust? | Entra | 1.1.1 |
| 11 | [Azure RBAC](11-azure-rbac.md) | Who actually holds access to Azure resources (groups expanded), at what scope, permanently or just-in-time, and through which other paths? | Azure + Entra | 1.1.1 |
| 12 | [Stale accounts](12-stale-accounts.md) | Which identities are really unused once AD and Entra activity are combined, and what do the stale ones still hold? | AD + Entra | 1.1.1 |
| 13 | [Hybrid sync scope](13-hybrid-sync-scope.md) | What actually syncs from AD to Entra, where do they disagree, and which on-prem admins reach the cloud? | AD + Entra | 1.1.1 |
| 14 | [IGA reconciliation](14-iga-reconciliation.md) | Where does the IGA platform's view of accounts and group access differ from AD, including access through nested groups and leavers who still hold groups? | AD + IGA export | 1.1.0 |
| 15 | [Rule-managed access](15-rule-managed-access.md) | Are applied roles, HR-expected roles and actual group membership in step, and who is in a rule-managed group who shouldn't be? | AD + role files | 1.1.0 |
| 16 | [Device posture](16-device-posture.md) | Are devices joined, managed, compliant and backed up, who can join them, and which accounts does device-based CA exempt? | Entra + Intune | 1.1.1 |
| 17 | [AWS IAM posture](17-aws-iam-posture.md) | Which AWS identities exist, who is admin-equivalent and through which policy, and which people sit behind each Identity Center assignment? | AWS | 1.1.0 |
| 18 | [AD delegation](18-ad-delegation.md) | Who has dangerous rights through AD permissions, and which real accounts end up holding them? | AD | 1.1.0 |
| 19 | [DC authentication protocols](19-dc-authentication-protocols.md) | Who still uses NTLM (v1 and LM especially) or RC4/DES Kerberos, against which servers, and which accounts can't do AES? | DC event logs + AD | 1.1.0 |
| 20 | [Governance coverage](20-governance-coverage.md) | What share of apps, groups and privileged roles is actually covered by access reviews, what do access packages grant, and are joiner / mover / leaver workflows in place? | Entra ID Governance | 1.1.1 |
| 21 | [Identity risk](21-identity-risk.md) | Who is at risk right now, and does Conditional Access act on risk for everyone? | Entra ID Protection | 1.1.1 |
| 22 | [PIM role settings](22-pim-role-settings.md) | What does it actually take to activate each admin role or privileged group, and who approves it? | Entra PIM | 1.1.1 |
| 23 | [AD attribute population](23-ad-attribute-population.md) | Which attributes does the schema allow, how many objects actually have a value in each, and where are values duplicated? | AD | 1.2.0 |
| 24 | [CA report-only impact](24-ca-reportonly-impact.md) | What does each Conditional Access policy do to real sign-ins, who would a report-only policy block or challenge, and which sign-ins does no enforced policy cover? | Entra sign-in logs | 1.1.1 |
| 25 | [Purview classification and DLP](25-purview-classification.md) | What can classify and protect regulated data, what is switched on, who is excluded, who can see or bypass it, and how much tagged content exists? | Microsoft Purview | 1.1.0 |
| 26 | [PAM vault coverage](26-pam-vault-coverage.md) | Which privileged, service and delegated accounts are managed in the PAM vault, which are not, and which vault entries are stale? | PAM export + 02/04/11/17/18 | 1.1.0 |
| 27 | [Identity population](27-identity-population.md) | Who exactly is in scope, how many of each kind of identity are there, and who was excluded and why? | AD + Entra (+ HR file) | 1.0.1 |
| 28 | [CA policy snapshot](28-ca-policy-snapshot.md) | What exactly is the Conditional Access configuration right now, and what changed since the last snapshot? | Entra | 1.0.1 |
| 29 | [Pilot outcome](29-pilot-outcome.md) | Did each pilot test case, expected and adverse, give the result it should, and which sign-in proves it? | Entra sign-in logs + test-case file | 1.0.1 |
| 30 | [Access review evidence](30-access-review-evidence.md) | For each access review that ran, who reviewed what, what did they decide and why, and were removals applied? | Entra ID Governance | 1.0.1 |

[← Back to README](../../README.md)
