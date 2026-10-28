@{
    # =====================================================================
    # Catalog of the discovery scripts, shared by Start-Discovery.ps1, New-DiscoveryReport.ps1,
    # New-AccessRequest.ps1 and New-EngagementDashboard.ps1.
    #
    # Needs: what a script must have to run (used by the launcher's readiness check).
    #   AD        RSAT ActiveDirectory module and a reachable domain controller (-Server)
    #   Graph     Microsoft.Graph.Authentication; sign-in with read scopes at run time
    #   Exchange  ExchangeOnlineManagement; Exchange view-only role at run time
    #   Azure     Az.Accounts; Azure Reader at run time
    #   AWS       AWS.Tools.* modules and a credential profile / read-only role
    #   EventLog  Event Log Readers on the domain controllers
    #   InputFile export files passed as mandatory parameters (the launcher prompts for them)
    # Optional: needs used only with an optional switch.
    #
    # Access requirements (used by New-AccessRequest.ps1; keep in step with docs/permissions.md):
    #   Roles           least Entra directory roles for a default run
    #   OptionalRoles   roles needed only with an optional switch
    #   Scopes          Microsoft Graph read scopes a default run requests. These must match the script's
    #                   $RequiredScopes exactly (scopes added unless a -Skip... switch is used count as default)
    #   OptionalScopes  Graph scopes requested only with an opt-in switch or parameter (named in docs/permissions.md)
    #   OtherAccess     access outside Entra roles and Graph scopes: AD, Exchange, Azure, AWS, event logs, notices
    #   Inputs          files or values the client supplies: Name, Parameter, Template (file in examples\), Required
    #   Licence         licence the full output depends on ('' = none). Missing licences give
    #                   EvidenceUnavailable datasets, never a failed run
    # =====================================================================
    Scripts = @(
        @{ Number = '01'; Title = 'MFA coverage';                         Area = 'Entra';      Needs = @('Graph')
           Roles = @('Global Reader')
           Scopes = @('Policy.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
           OptionalScopes = @()
           OtherAccess = @()
           Inputs = @()
           Licence = 'Entra ID P1 (sign-in logs and registration details)' }
        @{ Number = '02'; Title = 'Entra privileged access';              Area = 'Entra';      Needs = @('Graph')
           Roles = @('Global Reader')
           Scopes = @('RoleManagement.Read.Directory', 'Directory.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
           OptionalScopes = @('Policy.Read.All')
           OtherAccess = @()
           Inputs = @( @{ Name = 'Break-glass account UPNs'; Parameter = '-BreakGlassUpns'; Template = ''; Required = $false } )
           Licence = 'Entra ID P2 or ID Governance for PIM eligibility (the script continues without it)' }
        @{ Number = '03'; Title = 'Apps and consents';                    Area = 'Entra';      Needs = @('Graph')
           Roles = @('Global Reader')
           Scopes = @('Application.Read.All', 'Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
           OptionalScopes = @()
           OtherAccess = @()
           Inputs = @()
           Licence = 'Entra ID P1 for service-principal sign-in activity' }
        @{ Number = '04'; Title = 'AD privileged and service accounts';   Area = 'AD';         Needs = @('AD')
           Roles = @(); Scopes = @(); OptionalScopes = @()
           OtherAccess = @('Domain read (a standard domain user is normally enough)', 'Read of the forest root domain when run in a child domain')
           Inputs = @(); Licence = '' }
        @{ Number = '05'; Title = 'AD group nesting';                     Area = 'AD';         Needs = @('AD')
           Roles = @(); Scopes = @(); OptionalScopes = @()
           OtherAccess = @('Domain read (a standard domain user is normally enough)', 'Read of the forest root domain when run in a child domain')
           Inputs = @(); Licence = '' }
        @{ Number = '06'; Title = 'JML timing';                           Area = 'Lifecycle';  Needs = @('AD', 'InputFile'); Optional = @('Graph')
           Roles = @(); OptionalRoles = @('Global Reader')
           Scopes = @(); OptionalScopes = @('User.Read.All', 'AuditLog.Read.All')
           OtherAccess = @('Domain read (a standard domain user is normally enough)', 'Read of AD replication metadata')
           Inputs = @( @{ Name = 'HR export'; Parameter = '-HrCsvPath'; Template = 'hr.example.csv'; Required = $true } )
           Licence = 'Entra ID P1 for sign-in activity (with -IncludeEntraSignIn)' }
        @{ Number = '07'; Title = 'Role mining';                          Area = 'AD';         Needs = @('AD')
           Roles = @(); Scopes = @(); OptionalScopes = @()
           OtherAccess = @('Domain read (a standard domain user is normally enough)')
           Inputs = @(); Licence = '' }
        @{ Number = '08'; Title = 'Extension attribute inventory';        Area = 'Hybrid';     Needs = @('AD');                Optional = @('Graph')
           Roles = @(); OptionalRoles = @('Global Reader', 'Attribute Definition Reader', 'Attribute Assignment Reader')
           Scopes = @(); OptionalScopes = @('Directory.Read.All', 'Application.Read.All', 'Policy.Read.All', 'CustomSecAttributeDefinition.Read.All', 'CustomSecAttributeAssignment.Read.All')
           OtherAccess = @('Domain read (a standard domain user is normally enough)')
           Inputs = @()
           Licence = 'Entra ID P1 for custom security attributes (with -IncludeCustomSecurityAttributes)' }
        @{ Number = '09'; Title = 'Mail forwarding and external sharing'; Area = 'M365';       Needs = @('Exchange', 'Graph')
           Roles = @('Global Reader')
           Scopes = @('SharePointTenantSettings.Read.All'); OptionalScopes = @()
           OtherAccess = @('Exchange View-Only Organization Management (or Global Reader)', 'SharePoint Administrator or Global Reader for per-site sharing (when the SharePoint Online module is installed)')
           Inputs = @(); Licence = '' }
        @{ Number = '10'; Title = 'Guest access';                         Area = 'Entra';      Needs = @('Graph')
           Roles = @('Global Reader')
           Scopes = @('User.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
           OptionalScopes = @()
           OtherAccess = @()
           Inputs = @()
           Licence = 'Entra ID P1 for sign-in activity' }
        @{ Number = '11'; Title = 'Azure RBAC';                           Area = 'Azure';      Needs = @('Azure', 'Graph')
           Roles = @('Global Reader')
           Scopes = @('Directory.Read.All'); OptionalScopes = @()
           OtherAccess = @('Azure Reader at root management group (or on each subscription in scope)')
           Inputs = @()
           Licence = 'Entra ID P2 for PIM eligibility on Azure resources (the script continues without it)' }
        @{ Number = '12'; Title = 'Stale accounts';                       Area = 'Hybrid';     Needs = @('AD', 'Graph')
           Roles = @('Global Reader')
           Scopes = @('User.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All'); OptionalScopes = @()
           OtherAccess = @('Domain read (a standard domain user is normally enough)')
           Inputs = @()
           Licence = 'Entra ID P1 for sign-in activity' }
        @{ Number = '13'; Title = 'Hybrid sync scope';                    Area = 'Hybrid';     Needs = @('AD', 'Graph')
           Roles = @('Global Reader')
           Scopes = @('User.Read.All', 'Group.Read.All', 'Organization.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All', 'Device.Read.All')
           OptionalScopes = @('OnPremDirectorySynchronization.Read.All')
           OtherAccess = @('Domain read (a standard domain user is normally enough)')
           Inputs = @(); Licence = '' }
        @{ Number = '14'; Title = 'IGA reconciliation';                   Area = 'Lifecycle';  Needs = @('AD', 'InputFile')
           Roles = @(); Scopes = @(); OptionalScopes = @()
           OtherAccess = @('Domain read (a standard domain user is normally enough)')
           Inputs = @(
               @{ Name = 'IGA account export'; Parameter = '-AccountsCsv'; Template = 'iga-accounts.example.csv'; Required = $true }
               @{ Name = 'IGA assignment export'; Parameter = '-AssignmentsCsv'; Template = 'iga-assignments.example.csv'; Required = $false }
           )
           Licence = '' }
        @{ Number = '15'; Title = 'Rule-managed access';                  Area = 'Lifecycle';  Needs = @('AD', 'InputFile')
           Roles = @(); Scopes = @(); OptionalScopes = @()
           OtherAccess = @('Domain read (a standard domain user is normally enough)', 'Schema read (falls back to probing each attribute)')
           Inputs = @(
               @{ Name = 'Role definitions'; Parameter = '-RoleDefinitionCsv'; Template = 'role-definitions.example.csv'; Required = $true }
               @{ Name = 'Rule map'; Parameter = '-RuleMapCsv'; Template = 'rule-map.example.csv'; Required = $false }
           )
           Licence = '' }
        @{ Number = '16'; Title = 'Device posture';                       Area = 'Devices';    Needs = @('Graph')
           Roles = @('Global Reader')
           Scopes = @('Device.Read.All', 'Policy.Read.All', 'Directory.Read.All', 'DeviceLocalCredential.ReadBasic.All', 'BitlockerKey.ReadBasic.All', 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All', 'DeviceManagementApps.Read.All')
           OptionalScopes = @()
           OtherAccess = @('Intune Read Only Operator (only if Global Reader does not cover Intune in the tenant)')
           Inputs = @()
           Licence = 'Microsoft Intune for the managed-device datasets' }
        @{ Number = '17'; Title = 'AWS IAM posture';                      Area = 'AWS';        Needs = @('AWS')
           Roles = @(); Scopes = @(); OptionalScopes = @()
           OtherAccess = @('AWS read-only role with SecurityAudit and ViewOnlyAccess in each account', 'AWS IAM Identity Center read in the account that hosts it', 'AWS Organizations ListAccounts in the management (or delegated admin) account')
           Inputs = @(); Licence = '' }
        @{ Number = '18'; Title = 'AD delegation';                        Area = 'AD';         Needs = @('AD'); Note = 'Tell the SOC before running: ACL reads look like reconnaissance.'
           Roles = @(); Scopes = @(); OptionalScopes = @()
           OtherAccess = @('Domain read (DACLs are readable by authenticated users on most objects)', 'SOC notified before the run (ACL reads look like reconnaissance)')
           Inputs = @(); Licence = '' }
        @{ Number = '19'; Title = 'DC authentication protocols';          Area = 'AD';         Needs = @('AD', 'EventLog')
           Roles = @(); Scopes = @(); OptionalScopes = @()
           OtherAccess = @('Event Log Readers on DCs', 'Remote event log (RPC) from the run host to each DC', 'DC audit policy: logon, credential validation and Kerberos events set to Success; NTLM auditing for event 8004', 'Domain read (a standard domain user is normally enough)')
           Inputs = @(); Licence = '' }
        @{ Number = '20'; Title = 'Governance coverage';                  Area = 'Entra';      Needs = @('Graph')
           Roles = @('Global Reader')
           Scopes = @('AccessReview.Read.All', 'EntitlementManagement.Read.All', 'Application.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory', 'Directory.Read.All', 'LifecycleWorkflows.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
           OptionalScopes = @()
           OtherAccess = @()
           Inputs = @()
           Licence = 'Entra ID P2 or ID Governance (access reviews, entitlement management, lifecycle workflows)' }
        @{ Number = '21'; Title = 'Identity risk';                        Area = 'Entra';      Needs = @('Graph')
           Roles = @('Security Reader')
           Scopes = @('IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'Directory.Read.All', 'AuditLog.Read.All', 'IdentityRiskyServicePrincipal.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
           OptionalScopes = @()
           OtherAccess = @()
           Inputs = @()
           Licence = 'Entra ID P2 for full risk detail; Workload Identities Premium for risky service principals' }
        @{ Number = '22'; Title = 'PIM role settings';                    Area = 'Entra';      Needs = @('Graph')
           Roles = @('Global Reader')
           Scopes = @('RoleManagementPolicy.Read.Directory', 'RoleManagement.Read.Directory', 'Directory.Read.All', 'Policy.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'RoleManagementPolicy.Read.AzureADGroup', 'RoleManagementAlert.Read.Directory')
           OptionalScopes = @()
           OtherAccess = @()
           Inputs = @()
           Licence = 'Entra ID P2 or ID Governance (PIM)' }
        @{ Number = '23'; Title = 'AD attribute population';              Area = 'AD';         Needs = @('AD'); Note = 'Heavy: reads every attribute of every object. Run off-peak.'
           Roles = @(); Scopes = @(); OptionalScopes = @()
           OtherAccess = @('Domain read (a standard domain user is normally enough)', 'Schema read')
           Inputs = @(); Licence = '' }
        @{ Number = '24'; Title = 'CA report-only impact';                Area = 'Entra';      Needs = @('Graph')
           Roles = @('Global Reader')
           Scopes = @('Policy.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'Directory.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
           OptionalScopes = @()
           OtherAccess = @()
           Inputs = @()
           Licence = 'Entra ID P1 (sign-in logs, Conditional Access)' }
        @{ Number = '25'; Title = 'Purview classification and DLP';       Area = 'Data protection'; Needs = @('Exchange')
           Roles = @('Global Reader')
           Scopes = @(); OptionalScopes = @()
           OtherAccess = @('Purview Global Reader role group', 'Information Protection Readers and Content Explorer List viewer (with -IncludeContentExplorer)', 'A Purview role group with Activity explorer access (with -IncludeActivityExplorer)')
           Inputs = @()
           Licence = 'Microsoft Purview information protection and DLP service plans for the features measured' }
        @{ Number = '26'; Title = 'PAM vault coverage';                   Area = 'Privileged access'; Needs = @('InputFile'); Note = 'Run after 02, 04, 11, 17 and 18 into the same evidence folder.'
           Roles = @(); Scopes = @(); OptionalScopes = @()
           OtherAccess = @('Earlier runs of 02, 04, 11, 17 and 18 in the same evidence folder')
           Inputs = @( @{ Name = 'PAM vault account export (no secrets)'; Parameter = '-PamExportCsv'; Template = 'pam-accounts.example.csv'; Required = $true } )
           Licence = '' }
        @{ Number = '27'; Title = 'Identity population';                  Area = 'Hybrid';     Needs = @('AD', 'Graph');       Optional = @('InputFile'); Note = 'The denominators for every KPI. Pass the HR export and approved exclusions when you have them.'
           Roles = @('Global Reader')
           Scopes = @('User.Read.All'); OptionalScopes = @()
           OtherAccess = @('Domain read (a standard domain user is normally enough)')
           Inputs = @(
               @{ Name = 'HR export'; Parameter = '-HrCsvPath'; Template = 'hr.example.csv'; Required = $false }
               @{ Name = 'Approved population exclusions'; Parameter = '-ExclusionsCsv'; Template = 'population-exclusions.example.csv'; Required = $false }
               @{ Name = 'Break-glass account UPNs'; Parameter = '-BreakGlassUpns'; Template = ''; Required = $false }
           )
           Licence = '' }
        @{ Number = '28'; Title = 'CA policy snapshot';                   Area = 'Entra';      Needs = @('Graph'); Note = 'Take one before every Conditional Access change; pass it as -BaselineRunFolder afterwards.'
           Roles = @('Global Reader')
           Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Application.Read.All'); OptionalScopes = @()
           OtherAccess = @()
           Inputs = @()
           Licence = 'Entra ID P1 (Conditional Access)' }
        @{ Number = '29'; Title = 'Pilot outcome';                        Area = 'Entra';      Needs = @('Graph', 'InputFile'); Note = 'Needs a test-case file. Run after the test users have signed in.'
           Roles = @('Global Reader')
           Scopes = @('AuditLog.Read.All', 'Policy.Read.All', 'Directory.Read.All'); OptionalScopes = @('GroupMember.Read.All')
           OtherAccess = @()
           Inputs = @( @{ Name = 'Pilot test cases'; Parameter = '-TestCaseCsv'; Template = 'pilot-test-cases.example.csv'; Required = $true } )
           Licence = 'Entra ID P1 (sign-in logs)' }
        @{ Number = '30'; Title = 'Access review evidence';               Area = 'Entra';      Needs = @('Graph')
           Roles = @('Global Reader')
           Scopes = @('AccessReview.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup'); OptionalScopes = @()
           OtherAccess = @()
           Inputs = @()
           Licence = 'Entra ID P2 or ID Governance (access reviews)' }
        @{ Number = '31'; Title = 'Licence inventory';                    Area = 'Entra';      Needs = @('Graph'); Note = 'Run first to confirm licences; rerun with -EvidenceRoot after the pass to list licence-dependent gaps.'
           Roles = @('Global Reader')
           Scopes = @('Directory.Read.All'); OptionalScopes = @('LicenseAssignment.Read.All', 'Organization.Read.All')
           OtherAccess = @()
           Inputs = @()
           Licence = '' }
    )
}
