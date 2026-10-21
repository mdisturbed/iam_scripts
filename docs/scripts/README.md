# Script reference

One page per script: what it collects, parameters, output files, permissions, pilot check and troubleshooting.

| # | Page | Question it answers | Source | Version |
|---|------|--------------------|--------|---------|
| 01 | [MFA coverage](01-mfa-coverage.md) | Is MFA actually enforced everywhere, or only registered? | Entra | 1.0.1 |
| 02 | [Entra privileged access](02-entra-privileged-access.md) | Who holds Entra admin roles, how, and are those accounts well managed? | Entra | 1.0.1 |
| 03 | [Apps and consents](03-apps-and-consents.md) | Which apps can reach our data, and are they governed? | Entra | 1.0.1 |
| 04 | [AD privileged and service accounts](04-ad-privileged-and-service-accounts.md) | Who has admin rights on-prem (including via nesting), and where are the service accounts? | AD | 1.0.1 |
| 05 | [AD group nesting](05-ad-group-nesting.md) | How deep and messy is group nesting, and how healthy are groups? | AD | 1.0.1 |
| 06 | [JML timing](06-jml-timing.md) | How quickly are joiners provisioned and leavers disabled, compared with HR? | AD + HR file (+ Entra) | 1.0.1 |
| 07 | [Role mining](07-role-mining.md) | Which groups do people in the same department or job code share, and is the HR data clean enough to drive roles? | AD | 1.0.0 |
| 08 | [Extension attribute inventory](08-extension-attribute-inventory.md) | Which custom / extension attributes are free to carry new data? | AD (+ Entra) | 1.0.0 |
| 09 | [Mail forwarding and external sharing](09-mail-forwarding-and-external-sharing.md) | Is mail being forwarded out, and how open is SharePoint / OneDrive sharing? | Exchange Online + SharePoint | 1.0.0 |
| 10 | [Guest access](10-guest-access.md) | How many guests are there, are they used, and what can they reach? | Entra | 1.0.0 |
| 11 | [Azure RBAC](11-azure-rbac.md) | Who has access to Azure resources, at what scope, and to deleted principals? | Azure + Entra | 1.0.0 |
| 12 | [Stale accounts](12-stale-accounts.md) | Which identities are really unused once AD and Entra activity are combined? | AD + Entra | 1.0.0 |
| 13 | [Hybrid sync scope](13-hybrid-sync-scope.md) | What actually syncs from AD to Entra, and where do they disagree? | AD + Entra | 1.0.0 |
| 14 | [IGA reconciliation](14-iga-reconciliation.md) | Where does the IGA platform's view of accounts and group access differ from AD? | AD + IGA export | 1.0.0 |
| 15 | [Rule-managed access](15-rule-managed-access.md) | Are applied roles, HR-expected roles and actual group membership in step? | AD + role files | 1.0.0 |
| 16 | [Device posture](16-device-posture.md) | Are devices joined, managed and compliant, and does Conditional Access rely on it? | Entra + Intune | 1.0.0 |
| 17 | [AWS IAM posture](17-aws-iam-posture.md) | Which AWS users, keys, roles, trusts and permission sets exist, and which are risky? | AWS | 1.0.0 |
| 18 | [AD delegation](18-ad-delegation.md) | Who has dangerous rights through AD permissions (ACLs), not group membership? | AD | 1.0.0 |
| 19 | [DC authentication protocols](19-dc-authentication-protocols.md) | Who still uses NTLM (v1 especially) or RC4/DES Kerberos? | DC event logs | 1.0.0 |
| 20 | [Governance coverage](20-governance-coverage.md) | What share of apps, groups and roles is actually covered by access reviews? | Entra ID Governance | 1.0.0 |
| 21 | [Identity risk](21-identity-risk.md) | Who is at risk right now, and does Conditional Access act on risk? | Entra ID Protection | 1.0.0 |
| 22 | [PIM role settings](22-pim-role-settings.md) | What does it actually take to activate each admin role? | Entra PIM | 1.0.0 |
| 23 | [AD attribute population](23-ad-attribute-population.md) | Which attributes does the schema allow, and how many objects actually have a value in each? | AD | 1.0.1 |

[← Back to README](../../README.md)
