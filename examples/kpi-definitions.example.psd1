@{
    # =====================================================================
    # KPI definitions for tools/Get-KpiSummary.ps1. Copy this file, agree the definitions with the
    # programme owner, and keep the signed-off copy with the evidence (its SHA-256 is in the run manifest).
    #
    # Each KPI:
    #   Id, Name, Description
    #   Direction   HigherIsBetter | LowerIsBetter
    #   Target      percent (optional); MeetsTarget is blank without it
    #   Numerator / Denominator, one of:
    #     @{ Script = 'NN'; Metric = '<exact summary.csv metric name>' }            a count, not a (%) metric
    #     @{ Script = 'NN'; Dataset = '<dataset>'; FilterColumn = '<col>'; FilterValue = '<v>'; FilterMode = 'Equals' }
    #         FilterMode: Equals (default, case-insensitive), NotEquals, Like, Contains, Match (regex)
    #         Filters = @( @{ Column = ''; Value = ''; Mode = '' }, ... )  every filter must match
    #         CountDistinct = '<col>'  count distinct non-blank values instead of rows
    #         No filter = every row of the dataset
    #     @{ Population = '<exact population name>' }                              from 27-IdentityPopulation
    #   Script is the run folder prefix ('01') or the full folder name ('01-MfaCoverage').
    #
    # Population names (exact, from population-denominators.csv of script 27):
    #   Entra users (all), Entra members enabled, Entra guests, Human workforce enabled (Entra),
    #   Human workforce enabled (AD), AD users enabled, AD service accounts enabled, AD admin accounts enabled,
    #   Entra admin accounts enabled, Break-glass accounts, HR active workers, HR active with AD account,
    #   HR active with Entra account, Approved exclusions
    #
    # [needs 27] = run 27-IdentityPopulation into the same evidence folder first, or the KPI is NotRun.
    # Runs more than -MaxRunSpreadDays apart make the KPI Partial: run the sources in the same window.
    # =====================================================================
    Kpis = @(
        # [needs 27] Members (not guests) whose account is enabled and MFA registered, over the agreed human
        # workforce. mfa-registration also lists service and shared accounts that are members; if 27 excludes
        # them, a numerator over 100% of the denominator shows up as Partial with a note.
        @{
            Id          = 'MFA-01'
            Name        = 'MFA registration coverage of the human workforce'
            Description = 'Enabled member users registered for MFA, over Human workforce enabled (Entra)'
            Direction   = 'HigherIsBetter'
            Target      = 98
            Numerator   = @{ Script = '01'; Dataset = 'mfa-registration'; Filters = @(
                    @{ Column = 'UserType'; Value = 'member' }
                    @{ Column = 'AccountEnabled'; Value = 'True' }
                    @{ Column = 'IsMfaRegistered'; Value = 'True' }) }
            Denominator = @{ Population = 'Human workforce enabled (Entra)' }
        }
        # Same KPI without 27: both sides from one dataset, so no denominator contract. Use until 27 is agreed.
        @{
            Id          = 'MFA-01a'
            Name        = 'MFA registration of enabled members (no population file)'
            Description = 'Enabled member users registered for MFA, over all enabled member users in the registration report'
            Direction   = 'HigherIsBetter'
            Target      = 98
            Numerator   = @{ Script = '01'; Dataset = 'mfa-registration'; Filters = @(
                    @{ Column = 'UserType'; Value = 'member' }
                    @{ Column = 'AccountEnabled'; Value = 'True' }
                    @{ Column = 'IsMfaRegistered'; Value = 'True' }) }
            Denominator = @{ Script = '01'; Dataset = 'mfa-registration'; Filters = @(
                    @{ Column = 'UserType'; Value = 'member' }
                    @{ Column = 'AccountEnabled'; Value = 'True' }) }
        }
        # Enabled privileged users (effective set from 02) with a phishing-resistant method registered.
        @{
            Id          = 'MFA-02'
            Name        = 'Phishing-resistant MFA for privileged users'
            Description = 'Enabled users in the effective privileged set with a phishing-resistant method (FIDO2, Windows Hello, certificate)'
            Direction   = 'HigherIsBetter'
            Target      = 100
            Numerator   = @{ Script = '02'; Dataset = 'privileged-users'; Filters = @(
                    @{ Column = 'AccountEnabled'; Value = 'True' }
                    @{ Column = 'PhishResistantMfa'; Value = 'True' }) }
            Denominator = @{ Script = '02'; Dataset = 'privileged-users'; FilterColumn = 'AccountEnabled'; FilterValue = 'True' }
        }
        # Tier 0 holders from the registration report of 01 (needs 01 run without -SkipPrivilegeJoin).
        @{
            Id          = 'MFA-03'
            Name        = 'Phishing-resistant MFA for Tier 0 users'
            Description = 'Users holding a Tier 0 role with a phishing-resistant method registered'
            Direction   = 'HigherIsBetter'
            Target      = 100
            Numerator   = @{ Script = '01'; Dataset = 'mfa-registration'; Filters = @(
                    @{ Column = 'IsTier0'; Value = 'True' }
                    @{ Column = 'PhishResistant'; Value = 'True' }) }
            Denominator = @{ Script = '01'; Dataset = 'mfa-registration'; FilterColumn = 'IsTier0'; FilterValue = 'True' }
        }
        # Enabled privileged accounts (all sources) confirmed in the vault. Unconfirmed name-only matches do not count.
        @{
            Id          = 'PAM-01'
            Name        = 'Privileged accounts vaulted'
            Description = 'Enabled privileged accounts from 02, 04, 11, 17 and 18 with an exact vault match'
            Direction   = 'HigherIsBetter'
            Target      = 90
            Numerator   = @{ Script = '26'; Dataset = 'privileged-vault-coverage'; Filters = @(
                    @{ Column = 'Enabled'; Value = 'False'; Mode = 'NotEquals' }
                    @{ Column = 'Vaulted'; Value = 'True' }) }
            Denominator = @{ Script = '26'; Dataset = 'privileged-vault-coverage'; FilterColumn = 'Enabled'; FilterValue = 'False'; FilterMode = 'NotEquals' }
        }
        # Same idea from summary metrics, for one source (metric names are "<source> privileged accounts ...").
        @{
            Id          = 'PAM-02'
            Name        = 'Entra privileged accounts vaulted'
            Description = 'From summary.csv of 26'
            Direction   = 'HigherIsBetter'
            Target      = 100
            Numerator   = @{ Script = '26'; Metric = 'Entra privileged accounts vaulted' }
            Denominator = @{ Script = '26'; Metric = 'Entra privileged accounts (enabled)' }
        }
        # [needs 27] Enabled AD accounts stale over the 12 threshold (default 90 days) or never used, over enabled AD users.
        @{
            Id          = 'LCM-01'
            Name        = 'Stale enabled AD accounts'
            Description = 'Enabled AD accounts with no activity on either side for StaleDays, or never used, over AD users enabled'
            Direction   = 'LowerIsBetter'
            Target      = 2
            Numerator   = @{ Script = '12'; Dataset = 'identity-activity'; Filters = @(
                    @{ Column = 'ADEnabled'; Value = 'True' }
                    @{ Column = 'Flags'; Value = 'Stale\(|NeverUsed'; Mode = 'Match' }) }
            Denominator = @{ Population = 'AD users enabled' }
        }
        # [needs 27] HR active workers who have an Entra account (both sides from 27).
        @{
            Id          = 'LCM-02'
            Name        = 'HR active workers with an Entra account'
            Description = 'Joiner completeness: active workers in the HR export matched to an Entra account'
            Direction   = 'HigherIsBetter'
            Target      = 99
            Numerator   = @{ Population = 'HR active with Entra account' }
            Denominator = @{ Population = 'HR active workers' }
        }
        # Access review coverage of the in-scope targets from 20 (apps, groups, roles).
        @{
            Id          = 'GOV-01'
            Name        = 'Access review coverage'
            Description = 'In-scope applications, groups and directory roles covered by a recurring access review'
            Direction   = 'HigherIsBetter'
            Target      = 80
            Numerator   = @{ Script = '20'; Dataset = 'review-coverage'; FilterColumn = 'Covered'; FilterValue = 'True' }
            Denominator = @{ Script = '20'; Dataset = 'review-coverage' }
        }
        @{
            Id          = 'GOV-02'
            Name        = 'Access review coverage of Tier 0 roles and groups'
            Description = 'Tier 0 roles and role-assignable groups covered by a recurring access review'
            Direction   = 'HigherIsBetter'
            Target      = 100
            Numerator   = @{ Script = '20'; Dataset = 'review-coverage'; Filters = @(
                    @{ Column = 'Tier0'; Value = 'True' }
                    @{ Column = 'Covered'; Value = 'True' }) }
            Denominator = @{ Script = '20'; Dataset = 'review-coverage'; FilterColumn = 'Tier0'; FilterValue = 'True' }
        }
        # Deny decisions from 30 that were applied. Stage blank = single-stage review, Final = outcome of a
        # multi-stage review; stage-by-stage rows are left out so a decision is not counted twice.
        # In-progress instances are included, so run 30 after the review period ends.
        @{
            Id          = 'GOV-03'
            Name        = 'Access review deny decisions applied'
            Description = 'Final deny decisions applied successfully, over all final deny decisions in the review window'
            Direction   = 'HigherIsBetter'
            Target      = 100
            Numerator   = @{ Script = '30'; Dataset = 'review-decisions'; Filters = @(
                    @{ Column = 'Stage'; Value = '^(Final)?$'; Mode = 'Match' }
                    @{ Column = 'Decision'; Value = 'Deny' }
                    @{ Column = 'ApplyResult'; Value = '^AppliedSuccessfully'; Mode = 'Match' }) }
            Denominator = @{ Script = '30'; Dataset = 'review-decisions'; Filters = @(
                    @{ Column = 'Stage'; Value = '^(Final)?$'; Mode = 'Match' }
                    @{ Column = 'Decision'; Value = 'Deny' }) }
        }
        # Conditional Access pilot: test cases passed, over every test case (NoEvidence counts as not passed).
        @{
            Id          = 'CA-01'
            Name        = 'Conditional Access pilot test cases passed'
            Description = 'Rows of pilot-test-results with Outcome Pass, over all test cases'
            Direction   = 'HigherIsBetter'
            Target      = 100
            Numerator   = @{ Script = '29'; Dataset = 'pilot-test-results'; FilterColumn = 'Outcome'; FilterValue = 'Pass' }
            Denominator = @{ Script = '29'; Dataset = 'pilot-test-results' }
        }
    )
}
