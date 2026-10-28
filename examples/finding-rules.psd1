@{
    # =====================================================================
    # Finding rules for tools/New-FindingDrafts.ps1: which summary metric of which script signals a gap worth
    # a draft engineer finding. Copy this file into the engagement's config folder to tune it; keep RuleIds.
    #
    # Each rule:
    #   RuleId          'R-NN-xx', stable forever: the finding ledger maps it to the finding ID (F-xx), so a
    #                   rule that fires again in a later run keeps its finding ID. Never reuse a retired RuleId
    #   Script          run folder name of the script ($ScriptName), e.g. '13-HybridSyncScope'
    #   Metric          summary.csv metric name, exact. '*' stands for a number the script fills in from a
    #                   parameter (e.g. 'Enabled privileged accounts with no logon in * days'); every other character is literal; case ignored
    #   Condition       GreaterThan | LessThan | NotEqual | Equals, compared with Threshold (numbers compared as
    #                   numbers, anything else as text, ignoring case)
    #   Threshold       the value the metric is compared with
    #   Finding         one line, generic: what was observed
    #   Population      optional: another metric in the same summary.csv, shown as the denominator
    #   Severity        default observed severity (Critical / High / Medium / Low, as on the workbook's
    #                   Definitions sheet); the Identity Architect confirms or adjusts it
    #   HitrustCsf      HITRUST CSF control reference
    #   ZtPillar        CISA Zero Trust Maturity Model pillar (the workbook's list)
    #   ZtPrinciple     Verify explicitly | Use least privilege | Assume breach
    #   Recommendation  generic initial recommendation; the Architect owns the solution
    #   Dataset         optional: the dataset the metric is computed from. The rule is evaluated only when this
    #                   dataset (or summary, when not set) is Completed or Partial: never from Blocked,
    #                   EvidenceUnavailable or Deferred evidence
    #   FilterColumn / FilterValue / FilterMode
    #                   optional: the evidence note also counts the dataset rows matching this filter
    #                   (FilterMode Like, Equals, Match or Contains, as in New-FindingEvidence.ps1)
    #
    # Severity scale: Critical = reaches Tier 0 or leaves a leaver or an admin with no second factor;
    # High = privileged access outside the intended model, or a gap affecting many accounts;
    # Medium = hygiene gap with limited reach or partly covered by another control; Low = housekeeping.
    #
    # HITRUST CSF references used: 01.b User Registration; 01.c Privilege Management; 01.d User Password
    # Management; 01.e Review of User Access Rights; 01.j User Authentication for External Connections;
    # 01.p Secure Log-on Procedures; 01.q User Identification and Authentication; 01.v Information Access
    # Restriction; 02.i Removal of Access Rights; 05.i Identification of Risks Related to External Parties;
    # 06.d Data Protection and Privacy of Covered Information; 09.ab Monitoring System Use; 09.c Segregation of Duties.
    # =====================================================================
    Rules = @(
        @{ RuleId = 'R-01-01'; Script = '01-MfaCoverage'; Metric = 'Admins not MFA registered'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Admin accounts not registered for MFA'
           Population = 'Member users in registration report'
           Severity = 'Critical'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Register MFA for every admin account now and enforce it with Conditional Access for all admin roles'
           Dataset = 'mfa-registration' }
        @{ RuleId = 'R-01-02'; Script = '01-MfaCoverage'; Metric = 'Privileged users (effective set) not MFA registered'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Privileged users (including group and PIM paths) not registered for MFA'
           Population = 'Member users in registration report'
           Severity = 'Critical'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Register MFA for every privileged user and block privileged role use without it'
           Dataset = 'mfa-registration' }
        @{ RuleId = 'R-01-03'; Script = '01-MfaCoverage'; Metric = 'Tier 0 users without phishing-resistant method'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Tier 0 users without a phishing-resistant MFA method'
           Severity = 'High'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Register FIDO2 or Windows Hello for Business for Tier 0 users and require a phishing-resistant authentication strength'
           Dataset = 'mfa-registration' }
        @{ RuleId = 'R-01-04'; Script = '01-MfaCoverage'; Metric = 'Members MFA registered (%)'; Condition = 'LessThan'; Threshold = 98
           Finding = 'MFA registration of member users below target'
           Population = 'Member users in registration report'
           Severity = 'High'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Run a registration campaign with a deadline and close the gap with a Conditional Access registration policy'
           Dataset = 'mfa-registration' }
        @{ RuleId = 'R-01-05'; Script = '01-MfaCoverage'; Metric = 'Distinct users using legacy auth successfully'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Users signing in successfully with legacy authentication'
           Severity = 'High'; HitrustCsf = '01.p Secure Log-on Procedures'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Block legacy authentication with Conditional Access after moving the remaining clients to modern authentication'
           Dataset = 'signins-singlefactor-success' }
        @{ RuleId = 'R-01-06'; Script = '01-MfaCoverage'; Metric = 'Enabled policies blocking legacy auth'; Condition = 'Equals'; Threshold = 0
           Finding = 'No enabled Conditional Access policy blocks legacy authentication'
           Population = 'CA policies enabled'
           Severity = 'High'; HitrustCsf = '01.p Secure Log-on Procedures'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Create a policy that blocks legacy authentication, pilot it in report-only mode, then enable it'
           Dataset = 'ca-policies' }
        @{ RuleId = 'R-02-01'; Script = '02-PrivilegedAccess'; Metric = 'Privileged users not MFA registered'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Privileged users not registered for MFA'
           Population = 'Distinct privileged users'
           Severity = 'Critical'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Register MFA for every privileged user and require it on role activation'
           Dataset = 'privileged-users'; FilterColumn = 'Flags'; FilterValue = 'NotMfaRegistered'; FilterMode = 'Contains' }
        @{ RuleId = 'R-02-02'; Script = '02-PrivilegedAccess'; Metric = 'Tier 0 users without phishing-resistant MFA'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Tier 0 role holders without phishing-resistant MFA'
           Population = 'Privileged users holding a Tier 0 role'
           Severity = 'High'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Require a phishing-resistant authentication strength for every Tier 0 role'
           Dataset = 'privileged-users'; FilterColumn = 'Flags'; FilterValue = 'Tier0WithoutPhishResistantMfa'; FilterMode = 'Contains' }
        @{ RuleId = 'R-02-03'; Script = '02-PrivilegedAccess'; Metric = 'Active assignments that are permanent'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Permanent active Entra role assignments (no just-in-time activation)'
           Population = 'Active role assignments'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Convert permanent assignments to PIM-eligible, keeping only the break-glass accounts permanent'
           Dataset = 'role-assignments-active' }
        @{ RuleId = 'R-02-04'; Script = '02-PrivilegedAccess'; Metric = 'Privileged users synced from on-prem'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Entra privileged roles held by accounts synced from on-premises AD'
           Population = 'Distinct privileged users'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Move Entra admin roles to cloud-only admin accounts so an AD compromise cannot reach the tenant'
           Dataset = 'privileged-users' }
        @{ RuleId = 'R-02-05'; Script = '02-PrivilegedAccess'; Metric = 'Privileged guest users'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Guest accounts holding Entra privileged roles'
           Population = 'Distinct privileged users'
           Severity = 'High'; HitrustCsf = '05.i Identification of Risks Related to External Parties'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove privileged roles from guests, or replace them with internal accounts under the same controls as staff admins'
           Dataset = 'privileged-users'; FilterColumn = 'Flags'; FilterValue = 'Guest'; FilterMode = 'Contains' }
        @{ RuleId = 'R-02-06'; Script = '02-PrivilegedAccess'; Metric = 'Privileged users reached as owner of a role-holding group'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Owners of role-holding groups can add themselves to a privileged role'
           Population = 'Distinct privileged users'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove group owners from role-holding groups or make the groups role-assignable with PIM for Groups'
           Dataset = 'privileged-users' }
        @{ RuleId = 'R-03-01'; Script = '03-AppsAndConsents'; Metric = 'Application-permission grants that are Tier 0-equivalent'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Applications holding application permissions equivalent to tenant control'
           Population = 'Application-permission grants (non-Microsoft clients)'
           Severity = 'Critical'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Applications and workloads'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove or narrow each Tier 0-equivalent permission, and manage the remaining apps as Tier 0 assets with named owners'
           Dataset = 'app-permissions-application' }
        @{ RuleId = 'R-03-02'; Script = '03-AppsAndConsents'; Metric = 'Credentials on Microsoft first-party service principals'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Credentials added to Microsoft first-party service principals'
           Severity = 'High'; HitrustCsf = '01.d User Password Management'; ZtPillar = 'Applications and workloads'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Investigate each credential, remove it, and alert on any credential added to a first-party service principal'
           Dataset = 'service-principal-credentials' }
        @{ RuleId = 'R-03-03'; Script = '03-AppsAndConsents'; Metric = 'Application-permission grants that are high-risk'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Applications holding high-risk application permissions'
           Population = 'Application-permission grants (non-Microsoft clients)'
           Severity = 'High'; HitrustCsf = '01.v Information Access Restriction'; ZtPillar = 'Applications and workloads'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Review each high-risk grant with its owner and replace it with the narrowest permission that works'
           Dataset = 'app-permissions-application' }
        @{ RuleId = 'R-03-04'; Script = '03-AppsAndConsents'; Metric = 'App registrations with no owner'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'App registrations with no owner'
           Population = 'App registrations'
           Severity = 'Medium'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Applications and workloads'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Assign at least two owners to every app registration and disable or remove those nobody claims'
           Dataset = 'app-registrations' }
        @{ RuleId = 'R-03-05'; Script = '03-AppsAndConsents'; Metric = 'Secrets with lifetime over * days'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Long-lived client secrets on app registrations'
           Population = 'App registrations'
           Severity = 'Medium'; HitrustCsf = '01.d User Password Management'; ZtPillar = 'Applications and workloads'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Replace long-lived secrets with certificates or managed identities and set an app management policy that limits secret lifetime'
           Dataset = 'app-credentials' }
        @{ RuleId = 'R-04-01'; Script = '04-ADPrivilegedAndServiceAccounts'; Metric = 'Privileged user accounts with an SPN (Kerberoastable)'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Tier 0 accounts with a service principal name (Kerberoastable)'
           Population = 'Distinct privileged accounts'
           Severity = 'Critical'; HitrustCsf = '01.d User Password Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Remove SPNs from Tier 0 accounts; run services as gMSAs outside Tier 0'
           Dataset = 'ad-privileged-accounts' }
        @{ RuleId = 'R-04-02'; Script = '04-ADPrivilegedAndServiceAccounts'; Metric = 'Privileged accounts with password never expires'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Tier 0 accounts with passwords that never expire'
           Population = 'Distinct privileged accounts'
           Severity = 'High'; HitrustCsf = '01.d User Password Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Clear PasswordNeverExpires on Tier 0 accounts and rotate their passwords, or vault and rotate them through PAM'
           Dataset = 'ad-privileged-accounts' }
        @{ RuleId = 'R-04-03'; Script = '04-ADPrivilegedAndServiceAccounts'; Metric = 'Enabled privileged accounts with no logon in * days'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Enabled Tier 0 accounts with no recent logon'
           Population = 'Privileged accounts enabled'
           Severity = 'High'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Disable unused Tier 0 accounts after owner confirmation and remove them from privileged groups'
           Dataset = 'ad-privileged-accounts' }
        @{ RuleId = 'R-04-04'; Script = '04-ADPrivilegedAndServiceAccounts'; Metric = 'Service-account candidates that are privileged'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Service accounts with Tier 0 rights'
           Population = 'Service-account candidates'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove Tier 0 membership from service accounts, delegate only the rights each service needs, and vault the rest'
           Dataset = 'ad-service-account-candidates' }
        @{ RuleId = 'R-04-05'; Script = '04-ADPrivilegedAndServiceAccounts'; Metric = 'Foreign security principals in privileged groups'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Accounts from other domains or forests in privileged AD groups'
           Population = 'Distinct privileged accounts'
           Severity = 'High'; HitrustCsf = '05.i Identification of Risks Related to External Parties'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove foreign principals from privileged groups or document the trust and its compensating controls'
           Dataset = 'ad-privileged-accounts' }
        @{ RuleId = 'R-04-06'; Script = '04-ADPrivilegedAndServiceAccounts'; Metric = 'Tier 0 accounts with SID history'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Tier 0 accounts carrying SID history'
           Population = 'Distinct privileged accounts'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Clear SID history after migration is confirmed complete'
           Dataset = 'ad-privileged-accounts' }
        @{ RuleId = 'R-05-01'; Script = '05-ADGroupNesting'; Metric = 'Groups nested into a privileged built-in group'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Groups nested into privileged built-in AD groups'
           Population = 'Groups'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove nested groups from privileged built-in groups and grant membership directly to named admin accounts'
           Dataset = 'ad-group-reach' }
        @{ RuleId = 'R-05-02'; Script = '05-ADGroupNesting'; Metric = 'Groups with no managedBy owner'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Security groups with no accountable owner'
           Population = 'Groups'
           Severity = 'Low'; HitrustCsf = '01.e Review of User Access Rights'; ZtPillar = 'Governance'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Make the owner mandatory in the group request process and assign owners to existing groups'
           Dataset = 'ad-groups' }
        @{ RuleId = 'R-05-03'; Script = '05-ADGroupNesting'; Metric = 'Circular nesting loops'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Circular group nesting'
           Population = 'Groups'
           Severity = 'Low'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Break each loop by removing one nesting link after checking who loses access'
           Dataset = 'ad-circular-nesting' }
        @{ RuleId = 'R-06-01'; Script = '06-JmlTiming'; Metric = 'Terminated but still enabled'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Leavers (terminated in HR) whose AD account is still enabled'
           Population = 'Terminated (HR) with matched account'
           Severity = 'Critical'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Disable the accounts now, then automate disablement from the HR termination event'
           Dataset = 'jml-terminated-still-enabled' }
        @{ RuleId = 'R-06-02'; Script = '06-JmlTiming'; Metric = 'Secondary accounts enabled whose owner has left'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Admin, service or test accounts still enabled after their owner left'
           Population = 'Secondary (admin / service / test) accounts'
           Severity = 'Critical'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Disable or reassign each account and link every secondary account to an owner so leaver processing reaches it'
           Dataset = 'secondary-accounts' }
        @{ RuleId = 'R-06-03'; Script = '06-JmlTiming'; Metric = 'Leavers disabled within * day(s) (%)'; Condition = 'LessThan'; Threshold = 95
           Finding = 'Leavers not disabled within the agreed service level'
           Population = 'Terminated (HR) with matched account'
           Severity = 'High'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Automation and orchestration'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Drive disablement from the HR termination event and alert on leavers still enabled after the service level'
           Dataset = 'jml-matched' }
        @{ RuleId = 'R-09-01'; Script = '09-MailAndSharing'; Metric = 'Mailboxes forwarding externally'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Mailboxes forwarding mail to external addresses'
           Population = 'Mailboxes checked'
           Severity = 'High'; HitrustCsf = '06.d Data Protection and Privacy of Covered Information'; ZtPillar = 'Data'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Confirm each forward with its owner, remove the unapproved ones, and block external auto-forwarding by default'
           Dataset = 'exo-mailbox-forwarding' }
        @{ RuleId = 'R-09-02'; Script = '09-MailAndSharing'; Metric = 'Inbox rules that forward AND hide'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Inbox rules that forward mail and hide it from the mailbox owner'
           Population = 'Mailboxes checked'
           Severity = 'High'; HitrustCsf = '09.ab Monitoring System Use'; ZtPillar = 'Data'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Treat each as a possible compromise: investigate the mailbox, remove the rule and reset the account credentials'
           Dataset = 'exo-inbox-rules' }
        @{ RuleId = 'R-09-03'; Script = '09-MailAndSharing'; Metric = 'Remote domains allowing auto-forward'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Remote domains that allow automatic forwarding'
           Severity = 'Medium'; HitrustCsf = '06.d Data Protection and Privacy of Covered Information'; ZtPillar = 'Data'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Disable auto-forward on remote domains and allow it only for approved partner domains'
           Dataset = 'exo-remote-domains' }
        @{ RuleId = 'R-09-04'; Script = '09-MailAndSharing'; Metric = 'Sites allowing Anyone links'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'SharePoint and OneDrive sites that allow Anyone (anonymous) links'
           Population = 'Sites checked'
           Severity = 'Medium'; HitrustCsf = '01.v Information Access Restriction'; ZtPillar = 'Data'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Restrict Anyone links to approved sites and set a link expiry'
           Dataset = 'spo-site-sharing' }
        @{ RuleId = 'R-10-01'; Script = '10-GuestAccess'; Metric = 'Guests with a Tier 0 role path'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Guest accounts with a path to a Tier 0 role'
           Population = 'Guests'
           Severity = 'Critical'; HitrustCsf = '05.i Identification of Risks Related to External Parties'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove every Tier 0 role path from guests now'
           Dataset = 'privileged-guests' }
        @{ RuleId = 'R-10-02'; Script = '10-GuestAccess'; Metric = 'Guests holding a directory role'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Guest accounts holding Entra directory roles'
           Population = 'Guests'
           Severity = 'High'; HitrustCsf = '05.i Identification of Risks Related to External Parties'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove directory roles from guests, or replace them with internal accounts under staff admin controls'
           Dataset = 'privileged-guests' }
        @{ RuleId = 'R-10-03'; Script = '10-GuestAccess'; Metric = 'Enabled guests that are stale or never signed in'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Enabled guest accounts that are unused or never signed in'
           Population = 'Guests'
           Severity = 'Medium'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Disable and later remove unused guests, and add a recurring guest access review'
           Dataset = 'guests'; FilterColumn = 'Flags'; FilterValue = 'NeverSignedIn|NoSignIn'; FilterMode = 'Match' }
        @{ RuleId = 'R-10-04'; Script = '10-GuestAccess'; Metric = 'Partner tenants trusting external MFA'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Partner tenants whose MFA is trusted without a review of their controls'
           Severity = 'Medium'; HitrustCsf = '01.j User Authentication for External Connections'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Trust partner MFA only for partners whose controls are confirmed; otherwise require MFA in this tenant'
           Dataset = 'cross-tenant-partners' }
        @{ RuleId = 'R-11-01'; Script = '11-AzureRbac'; Metric = 'Permanent privileged assignments'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Permanent privileged Azure role assignments'
           Population = 'Role assignments'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Applications and workloads'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Move privileged Azure roles to PIM-eligible assignments with approval for Owner and User Access Administrator'
           Dataset = 'azure-role-assignments' }
        @{ RuleId = 'R-11-02'; Script = '11-AzureRbac'; Metric = 'Privileged roles at broad scope'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Privileged Azure roles assigned at root, management group or subscription scope'
           Population = 'Role assignments'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Applications and workloads'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Assign privileged roles at the narrowest scope that works and keep root and management group roles to break-glass and platform teams'
           Dataset = 'azure-role-assignments' }
        @{ RuleId = 'R-11-03'; Script = '11-AzureRbac'; Metric = 'Classic administrators'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Classic subscription administrators still assigned'
           Severity = 'Medium'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Applications and workloads'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove classic administrators and replace them with Azure RBAC roles'
           Dataset = 'azure-classic-administrators' }
        @{ RuleId = 'R-11-04'; Script = '11-AzureRbac'; Metric = 'Assignments to orphaned principals'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Azure role assignments to deleted principals'
           Population = 'Role assignments'
           Severity = 'Low'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Applications and workloads'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove assignments whose principal no longer exists'
           Dataset = 'azure-role-assignments' }
        @{ RuleId = 'R-12-01'; Script = '12-StaleAccounts'; Metric = 'Stale or never used but privileged (adminCount or Entra role)'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Privileged identities that are stale or never used'
           Population = 'Identities'
           Severity = 'High'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Disable stale privileged identities after owner confirmation and remove their roles'
           Dataset = 'identity-activity'; FilterColumn = 'Flags'; FilterValue = 'StaleButPrivileged'; FilterMode = 'Contains' }
        @{ RuleId = 'R-12-02'; Script = '12-StaleAccounts'; Metric = 'Enabled identities stale over * days or never used'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Enabled identities with no recent activity in AD or Entra'
           Population = 'Identities'
           Severity = 'Medium'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Disable stale identities in batches with owner confirmation, then automate the stale-account process'
           Dataset = 'identity-activity' }
        @{ RuleId = 'R-12-03'; Script = '12-StaleAccounts'; Metric = 'Password never expires and older than * days'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Accounts with non-expiring passwords that have not been changed for a long time'
           Population = 'Identities'
           Severity = 'Medium'; HitrustCsf = '01.d User Password Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Rotate these passwords, clear PasswordNeverExpires where possible and vault the service accounts'
           Dataset = 'identity-activity'; FilterColumn = 'Flags'; FilterValue = 'PasswordNeverExpiresOld'; FilterMode = 'Contains' }
        @{ RuleId = 'R-13-01'; Script = '13-HybridSyncScope'; Metric = 'Matched pairs: AD disabled but Entra enabled'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Accounts disabled in AD but still enabled in Entra'
           Population = 'AD users with an Entra twin'
           Severity = 'High'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Fix the sync of the enabled state and disable the Entra accounts now'
           Dataset = 'matched-pair-mismatches' }
        @{ RuleId = 'R-13-02'; Script = '13-HybridSyncScope'; Metric = 'Synced on-prem admins that also hold an Entra role'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'On-premises admin accounts synced to Entra that also hold Entra roles'
           Population = 'Privileged AD accounts synced to Entra'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Separate the tiers: cloud-only accounts for Entra roles, and keep on-premises admin accounts out of sync scope'
           Dataset = 'privileged-ad-accounts-synced' }
        @{ RuleId = 'R-13-03'; Script = '13-HybridSyncScope'; Metric = 'Users with provisioning errors'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Users with directory sync provisioning errors'
           Population = 'AD users'
           Severity = 'Low'; HitrustCsf = '01.b User Registration'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Resolve the conflicting attributes and monitor sync errors'
           Dataset = 'user-provisioning-errors' }
        @{ RuleId = 'R-14-01'; Script = '14-IgaReconciliation'; Metric = 'IGA inactive but AD enabled'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Accounts inactive in the IGA platform but still enabled in AD'
           Population = 'IGA accounts for this system'
           Severity = 'High'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Governance'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Disable the AD accounts and fix the IGA connector so deprovisioning reaches AD'
           Dataset = 'account-status-mismatch' }
        @{ RuleId = 'R-16-01'; Script = '16-DevicePosture'; Metric = 'Enabled devices unmanaged'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Enabled devices that are not managed'
           Population = 'Entra device objects'
           Severity = 'Medium'; HitrustCsf = '01.v Information Access Restriction'; ZtPillar = 'Devices'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Enrol corporate devices in device management and require a compliant or hybrid-joined device for sensitive apps'
           Dataset = 'entra-devices' }
        @{ RuleId = 'R-16-02'; Script = '16-DevicePosture'; Metric = 'Intune devices not encrypted'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Managed devices without disk encryption'
           Population = 'Intune managed devices'
           Severity = 'High'; HitrustCsf = '06.d Data Protection and Privacy of Covered Information'; ZtPillar = 'Devices'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Enforce disk encryption through compliance policy and remediate the listed devices'
           Dataset = 'intune-devices' }
        @{ RuleId = 'R-16-03'; Script = '16-DevicePosture'; Metric = 'Intune devices with a reported threat'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Managed devices reporting an active threat'
           Population = 'Intune managed devices'
           Severity = 'High'; HitrustCsf = '09.ab Monitoring System Use'; ZtPillar = 'Devices'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Investigate each device with the security team and block access from devices above the allowed threat level'
           Dataset = 'intune-devices' }
        @{ RuleId = 'R-16-04'; Script = '16-DevicePosture'; Metric = 'CA policies requiring a compliant device (enabled)'; Condition = 'Equals'; Threshold = 0
           Finding = 'No enabled Conditional Access policy requires a compliant device'
           Severity = 'Medium'; HitrustCsf = '01.v Information Access Restriction'; ZtPillar = 'Devices'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Pilot a policy requiring a compliant or hybrid-joined device for administrators and sensitive apps, then widen it'
           Dataset = 'ca-device-requirements' }
        @{ RuleId = 'R-17-01'; Script = '17-AwsIamPosture'; Metric = 'Accounts with root MFA OFF'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'AWS accounts whose root user has no MFA'
           Population = 'Accounts read'
           Severity = 'Critical'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Enable hardware MFA on every root user and store the credentials under break-glass controls'
           Dataset = 'aws-accounts' }
        @{ RuleId = 'R-17-02'; Script = '17-AwsIamPosture'; Metric = 'Accounts with root access keys'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'AWS accounts with root user access keys'
           Population = 'Accounts read'
           Severity = 'Critical'; HitrustCsf = '01.d User Password Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Delete root access keys and use roles for automation'
           Dataset = 'aws-accounts' }
        @{ RuleId = 'R-17-03'; Script = '17-AwsIamPosture'; Metric = 'IAM users with console access but no MFA'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'AWS IAM users with console access and no MFA'
           Population = 'IAM users'
           Severity = 'High'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Move people to IAM Identity Center; until then require MFA for every IAM user with console access'
           Dataset = 'aws-iam-users'; FilterColumn = 'Flags'; FilterValue = 'ConsoleWithoutMFA'; FilterMode = 'Contains' }
        @{ RuleId = 'R-17-04'; Script = '17-AwsIamPosture'; Metric = 'Roles trusting accounts outside the organization'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'AWS roles that can be assumed from accounts outside the organization'
           Population = 'IAM roles (excluding service-linked)'
           Severity = 'High'; HitrustCsf = '05.i Identification of Risks Related to External Parties'; ZtPillar = 'Applications and workloads'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Confirm each external trust with its owner, add an external ID or conditions, and remove the rest'
           Dataset = 'aws-iam-roles' }
        @{ RuleId = 'R-17-05'; Script = '17-AwsIamPosture'; Metric = 'Active keys older than * days'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Active AWS access keys older than the rotation period'
           Population = 'Active access keys'
           Severity = 'Medium'; HitrustCsf = '01.d User Password Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Rotate or remove old keys and replace long-lived keys with roles'
           Dataset = 'aws-access-keys' }
        @{ RuleId = 'R-18-01'; Script = '18-ADDelegation'; Metric = 'Non-default trustees with DCSync'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Non-default accounts or groups that can replicate directory secrets (DCSync)'
           Severity = 'Critical'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Remove replication rights from every non-default trustee at once and alert on replication requests from non-DCs'
           Dataset = 'ad-delegations' }
        @{ RuleId = 'R-18-02'; Script = '18-ADDelegation'; Metric = 'Non-default trustees with rights on Tier 0 objects'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Non-default trustees with rights on Tier 0 AD objects'
           Severity = 'Critical'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove the rights or move the trustee into Tier 0 with Tier 0 controls'
           Dataset = 'ad-delegations' }
        @{ RuleId = 'R-18-03'; Script = '18-ADDelegation'; Metric = 'Regular (non-admin-named) enabled accounts with High or Critical rights'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Everyday user accounts holding high-impact AD delegations'
           Population = 'User accounts holding delegated rights'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Move the rights to separate admin accounts or groups and remove them from everyday accounts'
           Dataset = 'ad-delegation-effective-users' }
        @{ RuleId = 'R-18-04'; Script = '18-ADDelegation'; Metric = 'Unresolved trustees (deleted accounts)'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'AD permissions granted to deleted accounts'
           Severity = 'Low'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove the orphaned access control entries'
           Dataset = 'ad-delegations' }
        @{ RuleId = 'R-19-01'; Script = '19-DcAuthProtocols'; Metric = 'NTLM V1 logons'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'NTLMv1 or LM authentication still in use against domain controllers'
           Population = 'NTLM logons (all versions)'
           Severity = 'High'; HitrustCsf = '01.p Secure Log-on Procedures'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Find and fix the sources, then set LAN Manager authentication level to refuse NTLMv1 and LM'
           Dataset = 'ntlm-logons' }
        @{ RuleId = 'R-19-02'; Script = '19-DcAuthProtocols'; Metric = 'Accounts getting TGTs without pre-authentication'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Accounts that get Kerberos tickets without pre-authentication (AS-REP roastable)'
           Severity = 'High'; HitrustCsf = '01.d User Password Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Turn Kerberos pre-authentication back on for every listed account'
           Dataset = 'kerberos-tgt-no-preauth' }
        @{ RuleId = 'R-19-03'; Script = '19-DcAuthProtocols'; Metric = 'Services receiving RC4/DES tickets'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Services still receiving RC4 or DES Kerberos tickets'
           Severity = 'Medium'; HitrustCsf = '01.p Secure Log-on Procedures'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Enable AES on the service accounts, reset their passwords and phase out RC4'
           Dataset = 'kerberos-weak-encryption' }
        @{ RuleId = 'R-20-01'; Script = '20-GovernanceCoverage'; Metric = 'Tier 0 roles and groups covered (%)'; Condition = 'LessThan'; Threshold = 100
           Finding = 'Tier 0 roles and groups not covered by access reviews'
           Severity = 'High'; HitrustCsf = '01.e Review of User Access Rights'; ZtPillar = 'Governance'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Add recurring access reviews for every Tier 0 role and role-assignable group'
           Dataset = 'review-coverage' }
        @{ RuleId = 'R-20-02'; Script = '20-GovernanceCoverage'; Metric = 'Application targets covered (%)'; Condition = 'LessThan'; Threshold = 80
           Finding = 'Applications not covered by access reviews'
           Population = 'Application targets in scope'
           Severity = 'Medium'; HitrustCsf = '01.e Review of User Access Rights'; ZtPillar = 'Governance'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Add recurring reviews for the in-scope applications, starting with those holding sensitive data'
           Dataset = 'review-coverage' }
        @{ RuleId = 'R-20-03'; Script = '20-GovernanceCoverage'; Metric = 'Self-reviews'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Access reviews where users attest their own access'
           Population = 'Access review definitions'
           Severity = 'Medium'; HitrustCsf = '09.c Segregation of Duties'; ZtPillar = 'Governance'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Change the reviewers to managers or resource owners with a fallback reviewer'
           Dataset = 'access-review-definitions' }
        @{ RuleId = 'R-20-04'; Script = '20-GovernanceCoverage'; Metric = 'Enabled leaver workflows'; Condition = 'Equals'; Threshold = 0
           Finding = 'No enabled leaver lifecycle workflow'
           Severity = 'Medium'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Automation and orchestration'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Automate leaver steps from the HR event (disable, remove access, revoke sessions) with a lifecycle workflow or the IGA platform'
           Dataset = 'lifecycle-workflows' }
        @{ RuleId = 'R-21-01'; Script = '21-IdentityRisk'; Metric = 'At-risk users holding a Tier 0 role'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Tier 0 role holders currently flagged at risk'
           Population = 'Users currently at risk'
           Severity = 'Critical'; HitrustCsf = '09.ab Monitoring System Use'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Investigate now: confirm or dismiss the risk, reset credentials and revoke sessions'
           Dataset = 'risky-users' }
        @{ RuleId = 'R-21-02'; Script = '21-IdentityRisk'; Metric = 'At-risk users holding a directory role'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Privileged users currently flagged at risk'
           Population = 'Users currently at risk'
           Severity = 'High'; HitrustCsf = '09.ab Monitoring System Use'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Investigate each user, remediate the risk and require remediation before role activation'
           Dataset = 'risky-users' }
        @{ RuleId = 'R-21-03'; Script = '21-IdentityRisk'; Metric = 'CA policies using user risk (enabled)'; Condition = 'Equals'; Threshold = 0
           Finding = 'No enabled Conditional Access policy acts on user risk'
           Severity = 'Medium'; HitrustCsf = '09.ab Monitoring System Use'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Add a user-risk policy that requires a secure password change at high risk, piloted in report-only mode'
           Dataset = 'ca-risk-policies' }
        @{ RuleId = 'R-21-04'; Script = '21-IdentityRisk'; Metric = 'Privileged accounts excluded from an enabled risk policy'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Privileged accounts excluded from risk-based Conditional Access'
           Severity = 'High'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Remove privileged accounts from risk-policy exclusions, keeping only the break-glass accounts'
           Dataset = 'risk-policy-exclusions' }
        @{ RuleId = 'R-22-01'; Script = '22-PimRoleSettings'; Metric = 'Tier 0 roles without MFA or auth context on activation'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Tier 0 roles that can be activated without MFA or an authentication context'
           Population = 'Tier 0 roles reported'
           Severity = 'Critical'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Require MFA or an authentication context enforced by Conditional Access on every Tier 0 role activation'
           Dataset = 'pim-role-settings'; FilterColumn = 'Flags'; FilterValue = 'Tier0NoMfaOrAuthContext'; FilterMode = 'Contains' }
        @{ RuleId = 'R-22-02'; Script = '22-PimRoleSettings'; Metric = 'Tier 0 roles activatable without approval'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Tier 0 roles that can be activated without approval'
           Population = 'Tier 0 roles reported'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Require approval for Tier 0 role activation, with at least two approvers who are not eligible themselves'
           Dataset = 'pim-role-settings' }
        @{ RuleId = 'R-22-03'; Script = '22-PimRoleSettings'; Metric = 'Tier 0 roles allowing permanent active assignment'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Tier 0 roles that allow permanent active assignment'
           Population = 'Tier 0 roles reported'
           Severity = 'High'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Disallow permanent active assignment for Tier 0 roles, except for break-glass accounts'
           Dataset = 'pim-role-settings' }
        @{ RuleId = 'R-22-04'; Script = '22-PimRoleSettings'; Metric = 'Roles where an approver is also eligible'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Privileged roles where an approver can also activate the role'
           Population = 'Roles reported'
           Severity = 'Medium'; HitrustCsf = '09.c Segregation of Duties'; ZtPillar = 'Governance'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Use approvers who are not eligible for the role they approve'
           Dataset = 'pim-role-settings' }
        @{ RuleId = 'R-24-01'; Script = '24-CaReportOnlyImpact'; Metric = 'Tier 0 users signing in with no enforced policy'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Tier 0 users signing in with no enforced Conditional Access policy'
           Population = 'Users / principals signing in with no enforced policy'
           Severity = 'Critical'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Bring every Tier 0 sign-in under an enforced policy requiring phishing-resistant MFA'
           Dataset = 'no-enforced-policy-signins' }
        @{ RuleId = 'R-24-02'; Script = '24-CaReportOnlyImpact'; Metric = 'Privileged users signing in with no enforced policy'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Privileged users signing in with no enforced Conditional Access policy'
           Population = 'Users / principals signing in with no enforced policy'
           Severity = 'High'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Target an enforced policy at all privileged roles'
           Dataset = 'no-enforced-policy-signins' }
        @{ RuleId = 'R-24-03'; Script = '24-CaReportOnlyImpact'; Metric = 'Users / principals signing in with no enforced policy'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Users signing in with no enforced Conditional Access policy'
           Severity = 'Medium'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Close the gaps with a baseline policy for all users and apps, staged through report-only mode'
           Dataset = 'no-enforced-policy-signins' }
        @{ RuleId = 'R-26-01'; Script = '26-PamVaultCoverage'; Metric = 'Tier 0 accounts not vaulted (enabled)'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Enabled Tier 0 accounts not managed in the PAM vault'
           Population = 'PAM vault entries'
           Severity = 'Critical'; HitrustCsf = '01.c Privilege Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Onboard every Tier 0 account to the vault with credential rotation and session control'
           Dataset = 'privileged-vault-coverage' }
        @{ RuleId = 'R-26-02'; Script = '26-PamVaultCoverage'; Metric = 'AD passwords changed outside the vault'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Vaulted AD accounts whose password was changed outside the vault'
           Population = 'PAM vault entries'
           Severity = 'High'; HitrustCsf = '01.d User Password Management'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Find who changed each password, reconcile the vault, and alert on password changes not made by the vault'
           Dataset = 'privileged-vault-coverage' }
        @{ RuleId = 'R-26-03'; Script = '26-PamVaultCoverage'; Metric = 'Vault entries matching no privileged account'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Vault entries that match no current privileged account'
           Population = 'PAM vault entries'
           Severity = 'Low'; HitrustCsf = '01.e Review of User Access Rights'; ZtPillar = 'Governance'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Remove or correct stale vault entries'
           Dataset = 'pam-entries-unmatched' }
        @{ RuleId = 'R-27-01'; Script = '27-IdentityPopulation'; Metric = 'Reconciliation: HrTerminatedAdEnabled'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Workers terminated in HR whose AD account is still enabled'
           Severity = 'Critical'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Disable the accounts now, then automate disablement from the HR termination event'
           Dataset = 'population-reconciliation' }
        @{ RuleId = 'R-27-02'; Script = '27-IdentityPopulation'; Metric = 'Reconciliation: HrTerminatedEntraEnabled'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Workers terminated in HR whose Entra account is still enabled'
           Severity = 'Critical'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Identity'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Disable the accounts and revoke their sessions, then automate disablement from the HR termination event'
           Dataset = 'population-reconciliation' }
        @{ RuleId = 'R-27-03'; Script = '27-IdentityPopulation'; Metric = 'Unclassified (enabled, no HR match, no pattern)'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Enabled accounts with no HR record and no recognised account type'
           Population = 'Identities'
           Severity = 'Medium'; HitrustCsf = '01.b User Registration'; ZtPillar = 'Identity'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Assign an owner and type to each account, or disable it; require an owner and type at creation'
           Dataset = 'identity-population' }
        @{ RuleId = 'R-29-01'; Script = '29-PilotOutcome'; Metric = 'Test cases failed'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Pilot test cases that did not give the expected result'
           Population = 'Test cases'
           Severity = 'High'; HitrustCsf = '01.q User Identification and Authentication'; ZtPillar = 'Identity'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Fix the policy or the test case, rerun the pilot and do not widen the change until every case passes' }
        @{ RuleId = 'R-30-01'; Script = '30-AccessReviewEvidence'; Metric = 'Denies not applied'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Access removed in a review but not applied'
           Population = 'Decisions'
           Severity = 'High'; HitrustCsf = '02.i Removal of Access Rights'; ZtPillar = 'Governance'; ZtPrinciple = 'Assume breach'
           Recommendation = 'Apply the outstanding denies and turn on auto-apply for the reviews'
           Dataset = 'review-instances' }
        @{ RuleId = 'R-30-02'; Script = '30-AccessReviewEvidence'; Metric = 'Exceptions: PrivilegedApprovedWithoutReview'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Privileged access approved without a reviewer decision'
           Population = 'Decisions'
           Severity = 'High'; HitrustCsf = '01.e Review of User Access Rights'; ZtPillar = 'Governance'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Require an explicit reviewer decision for privileged access; never let it default to approve'
           Dataset = 'review-exceptions' }
        @{ RuleId = 'R-30-03'; Script = '30-AccessReviewEvidence'; Metric = 'Exceptions: SelfReview'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Access review decisions made by the person whose access was reviewed'
           Population = 'Decisions'
           Severity = 'Medium'; HitrustCsf = '09.c Segregation of Duties'; ZtPillar = 'Governance'; ZtPrinciple = 'Use least privilege'
           Recommendation = 'Change the reviewers so nobody reviews their own access'
           Dataset = 'review-exceptions' }
        @{ RuleId = 'R-31-01'; Script = '31-LicenceInventory'; Metric = 'Datasets EvidenceUnavailable in latest runs'; Condition = 'GreaterThan'; Threshold = 0
           Finding = 'Evidence the tenant cannot produce, mostly for lack of a licence'
           Population = 'Script runs scanned'
           Severity = 'Low'; HitrustCsf = '09.ab Monitoring System Use'; ZtPillar = 'Governance'; ZtPrinciple = 'Verify explicitly'
           Recommendation = 'Record each gap in the status register with its risk, and decide per gap whether to license, compensate or accept' }
    )
}
