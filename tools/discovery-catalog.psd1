@{
    # =====================================================================
    # Catalog of the discovery scripts, shared by Start-Discovery.ps1 and New-DiscoveryReport.ps1.
    # Needs: what a script must have to run.
    #   AD        RSAT ActiveDirectory module and a reachable domain controller (-Server)
    #   Graph     Microsoft.Graph.Authentication; sign-in with read scopes at run time
    #   Exchange  ExchangeOnlineManagement; Exchange view-only role at run time
    #   Azure     Az.Accounts; Azure Reader at run time
    #   AWS       AWS.Tools.* modules and a credential profile / read-only role
    #   EventLog  Event Log Readers on the domain controllers
    #   InputFile export files passed as mandatory parameters (the launcher prompts for them)
    # Optional: needs used only with an optional switch.
    # =====================================================================
    Scripts = @(
        @{ Number = '01'; Title = 'MFA coverage';                         Area = 'Entra';      Needs = @('Graph') }
        @{ Number = '02'; Title = 'Entra privileged access';              Area = 'Entra';      Needs = @('Graph') }
        @{ Number = '03'; Title = 'Apps and consents';                    Area = 'Entra';      Needs = @('Graph') }
        @{ Number = '04'; Title = 'AD privileged and service accounts';   Area = 'AD';         Needs = @('AD') }
        @{ Number = '05'; Title = 'AD group nesting';                     Area = 'AD';         Needs = @('AD') }
        @{ Number = '06'; Title = 'JML timing';                           Area = 'Lifecycle';  Needs = @('AD', 'InputFile'); Optional = @('Graph') }
        @{ Number = '07'; Title = 'Role mining';                          Area = 'AD';         Needs = @('AD') }
        @{ Number = '08'; Title = 'Extension attribute inventory';        Area = 'Hybrid';     Needs = @('AD');                Optional = @('Graph') }
        @{ Number = '09'; Title = 'Mail forwarding and external sharing'; Area = 'M365';       Needs = @('Exchange', 'Graph') }
        @{ Number = '10'; Title = 'Guest access';                         Area = 'Entra';      Needs = @('Graph') }
        @{ Number = '11'; Title = 'Azure RBAC';                           Area = 'Azure';      Needs = @('Azure', 'Graph') }
        @{ Number = '12'; Title = 'Stale accounts';                       Area = 'Hybrid';     Needs = @('AD', 'Graph') }
        @{ Number = '13'; Title = 'Hybrid sync scope';                    Area = 'Hybrid';     Needs = @('AD', 'Graph') }
        @{ Number = '14'; Title = 'IGA reconciliation';                   Area = 'Lifecycle';  Needs = @('AD', 'InputFile') }
        @{ Number = '15'; Title = 'Rule-managed access';                  Area = 'Lifecycle';  Needs = @('AD', 'InputFile') }
        @{ Number = '16'; Title = 'Device posture';                       Area = 'Devices';    Needs = @('Graph') }
        @{ Number = '17'; Title = 'AWS IAM posture';                      Area = 'AWS';        Needs = @('AWS') }
        @{ Number = '18'; Title = 'AD delegation';                        Area = 'AD';         Needs = @('AD'); Note = 'Tell the SOC before running: ACL reads look like reconnaissance.' }
        @{ Number = '19'; Title = 'DC authentication protocols';          Area = 'AD';         Needs = @('AD', 'EventLog') }
        @{ Number = '20'; Title = 'Governance coverage';                  Area = 'Entra';      Needs = @('Graph') }
        @{ Number = '21'; Title = 'Identity risk';                        Area = 'Entra';      Needs = @('Graph') }
        @{ Number = '22'; Title = 'PIM role settings';                    Area = 'Entra';      Needs = @('Graph') }
        @{ Number = '23'; Title = 'AD attribute population';              Area = 'AD';         Needs = @('AD'); Note = 'Heavy: reads every attribute of every object. Run off-peak.' }
        @{ Number = '24'; Title = 'CA report-only impact';                Area = 'Entra';      Needs = @('Graph') }
        @{ Number = '25'; Title = 'Purview classification and DLP';       Area = 'Data protection'; Needs = @('Exchange') }
        @{ Number = '26'; Title = 'PAM vault coverage';                   Area = 'Privileged access'; Needs = @('InputFile'); Note = 'Run after 02, 04, 11, 17 and 18 into the same evidence folder.' }
        @{ Number = '27'; Title = 'Identity population';                  Area = 'Hybrid';     Needs = @('AD', 'Graph');       Optional = @('InputFile'); Note = 'The denominators for every KPI. Pass the HR export and approved exclusions when you have them.' }
        @{ Number = '28'; Title = 'CA policy snapshot';                   Area = 'Entra';      Needs = @('Graph'); Note = 'Take one before every Conditional Access change; pass it as -BaselineRunFolder afterwards.' }
        @{ Number = '29'; Title = 'Pilot outcome';                        Area = 'Entra';      Needs = @('Graph', 'InputFile'); Note = 'Needs a test-case file. Run after the test users have signed in.' }
        @{ Number = '30'; Title = 'Access review evidence';               Area = 'Entra';      Needs = @('Graph') }
    )
}
