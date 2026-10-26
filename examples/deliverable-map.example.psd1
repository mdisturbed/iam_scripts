@{
    # =====================================================================
    # Deliverable map for tools/New-EvidencePackage.ps1: which runs and datasets make up each deliverable
    # of a staged identity programme. Copy it, rename the deliverables to the programme's own, and keep
    # the agreed copy with the evidence (its SHA-256 is in the tool's run manifest).
    #
    # Each deliverable:
    #   Id, Deliverable, Gate, Description (optional)
    #   Requires = @( @{ Script = 'NN' or a folder name; Datasets = @('dataset' or 'file.ext', ...); Run = 'yyyyMMdd-HHmmssZ' } )
    #     Script    run folder prefix ('01') or full folder name ('Compare-RunFolders')
    #     Datasets  dataset names from dataset-status.csv, or file names with extension (use file names for
    #               the JSON files of 28). Leave out to require every dataset of the run except summary.
    #     Run       optional: pin a specific run (a frozen baseline). Default: the latest run.
    #
    # Status per deliverable: Completed only when every required dataset is Completed and its file still
    # matches its SHA-256; otherwise the most serious of HashMismatch, NotRun, Blocked, EvidenceUnavailable,
    # Deferred, Partial, with the dataset named in the Note.
    # =====================================================================
    Deliverables = @(
        @{
            Id          = 'D00'
            Deliverable = 'Readiness and access record (frozen baseline set)'
            Gate        = 'G0'
            Description = 'The access granted for discovery, shown by a first run of each read-only script. Start-Discovery readiness is console only, so the frozen first runs are the record. Pin them with Run = once agreed.'
            Requires    = @(
                @{ Script = '01'; Datasets = @('ca-policies', 'mfa-registration') }      # Run = '20261020-140501Z' to freeze
                @{ Script = '02'; Datasets = @('role-assignments-active', 'privileged-users') }
                @{ Script = '04'; Datasets = @('ad-privileged-accounts') }
                @{ Script = '12'; Datasets = @('identity-activity') }
            )
        }
        @{
            Id          = 'D01'
            Deliverable = 'Identity baseline and gap assessment'
            Gate        = 'G1'
            Description = 'Current state across Entra, AD, hybrid sync, lifecycle and governance, with the agreed population every KPI divides by.'
            Requires    = @(
                @{ Script = '01'; Datasets = @('ca-policies', 'ca-exclusions', 'mfa-registration', 'auth-methods-policy') }
                @{ Script = '02'; Datasets = @('role-assignments-active', 'role-assignments-eligible', 'privileged-users', 'privileged-service-principals') }
                @{ Script = '03'; Datasets = @('app-registrations', 'app-credentials', 'app-permissions-application', 'app-risk-summary') }
                @{ Script = '04'; Datasets = @('ad-privileged-accounts', 'ad-service-account-candidates', 'ad-account-risk-flags') }
                @{ Script = '05'; Datasets = @('ad-groups', 'ad-circular-nesting') }
                @{ Script = '06'; Datasets = @('jml-matched', 'jml-terminated-still-enabled', 'jml-hr-active-no-account') }
                @{ Script = '10'; Datasets = @('guests', 'privileged-guests') }
                @{ Script = '12'; Datasets = @('identity-activity') }
                @{ Script = '13'; Datasets = @('sync-ou-coverage-users', 'ad-users-not-in-entra', 'matched-pair-mismatches') }
                @{ Script = '20'; Datasets = @('access-review-definitions', 'review-coverage') }
                @{ Script = '22'; Datasets = @('pim-role-settings') }
                @{ Script = '27'; Datasets = @('population-denominators', 'identity-population', 'population-exclusions') }
            )
        }
        @{
            Id          = 'D02'
            Deliverable = 'MFA and Conditional Access design and pilot evidence'
            Gate        = 'G2'
            Description = 'Baseline policy snapshot, report-only impact, pilot test results against the agreed test cases.'
            Requires    = @(
                @{ Script = '01'; Datasets = @('ca-policies', 'ca-exclusions', 'mfa-registration') }
                @{ Script = '24'; Datasets = @('ca-policy-results', 'ca-reportonly-impact') }
                @{ Script = '28'; Datasets = @('ca-policies.json', 'ca-policies.csv', 'named-locations.json', 'authentication-strengths.json', 'authentication-methods-policy.json') }
                @{ Script = '29'; Datasets = @('pilot-test-results') }
            )
        }
        @{
            Id          = 'D03'
            Deliverable = 'Privileged access quick-win baseline'
            Gate        = 'G2'
            Description = 'Privileged accounts in Entra and AD and how many are vaulted.'
            Requires    = @(
                @{ Script = '02'; Datasets = @('privileged-users', 'privileged-principals-effective') }
                @{ Script = '04'; Datasets = @('ad-privileged-accounts', 'ad-admincount-orphans', 'ad-service-account-candidates') }
                @{ Script = '26'; Datasets = @('privileged-vault-coverage', 'pam-entries-unmatched', 'source-runs') }
            )
        }
        @{
            Id          = 'D04'
            Deliverable = 'Joiner-mover-leaver pilot design baseline'
            Gate        = 'G2'
            Description = 'HR to directory timing, IGA reconciliation and rule-managed access before the lifecycle pilot.'
            Requires    = @(
                @{ Script = '06'; Datasets = @('jml-matched', 'jml-terminated-still-enabled', 'mover-mismatches') }
                @{ Script = '14'; Datasets = @('accounts-ad-not-in-iga', 'accounts-iga-not-in-ad', 'memberships-outside-iga') }
                @{ Script = '15'; Datasets = @('user-reconciliation', 'drift-detail') }
            )
        }
        @{
            Id          = 'D05'
            Deliverable = 'Change before / after and rollback evidence'
            Gate        = 'G3'
            Description = 'Policy drift against the pre-change snapshot (Unchanged after a rollback) and the before / after comparison of the approved change.'
            Requires    = @(
                @{ Script = '28'; Datasets = @('ca-policy-drift.csv') }
                @{ Script = 'Compare-RunFolders'; Datasets = @('run-diff-summary', 'run-diff-rows', 'metric-diff', 'input-verification') }
            )
        }
        @{
            Id          = 'D06'
            Deliverable = 'Access review evidence package'
            Gate        = 'G4'
            Description = 'Review coverage, and every instance, decision and exception in the review window.'
            Requires    = @(
                @{ Script = '20'; Datasets = @('access-review-definitions', 'review-coverage') }
                @{ Script = '30'; Datasets = @('review-instances', 'review-decisions', 'review-exceptions') }
            )
        }
        @{
            Id          = 'D07'
            Deliverable = 'KPI draft'
            Gate        = 'G4'
            Description = 'KPIs computed with validated denominators, each traced to its run and SHA-256.'
            Requires    = @(
                @{ Script = 'Get-KpiSummary'; Datasets = @('kpi-summary') }
                @{ Script = '27'; Datasets = @('population-denominators') }
            )
        }
        @{
            Id          = 'D08'
            Deliverable = 'Final evidence package'
            Gate        = 'G5'
            Description = 'Latest runs of everything above, re-verified. Build it with -CopyTo once every deliverable above is Completed or its gaps are accepted.'
            Requires    = @(
                @{ Script = '01'; Datasets = @('mfa-registration', 'ca-policies') }
                @{ Script = '02'; Datasets = @('privileged-users') }
                @{ Script = '12'; Datasets = @('identity-activity') }
                @{ Script = '20'; Datasets = @('review-coverage') }
                @{ Script = '26'; Datasets = @('privileged-vault-coverage') }
                @{ Script = '27'; Datasets = @('population-denominators') }
                @{ Script = '28'; Datasets = @('ca-policies.json', 'ca-policy-drift.csv') }
                @{ Script = '29'; Datasets = @('pilot-test-results') }
                @{ Script = '30'; Datasets = @('review-decisions', 'review-exceptions') }
                @{ Script = 'Compare-RunFolders'; Datasets = @('run-diff-summary') }
                @{ Script = 'Get-KpiSummary'; Datasets = @('kpi-summary') }
            )
        }
    )
}
