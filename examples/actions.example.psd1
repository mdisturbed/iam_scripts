@{
    # =====================================================================
    # Engagement actions: buttons on the console's "Engagement actions" tab (Start-EngagementConsole.ps1)
    # and entries under option A of Start-Engagement.ps1.
    #
    # Copy to <engagement>\config\actions.psd1 (the console's "Edit actions file" does this) and list the
    # scripts that belong to this engagement only. The kit's own tools are already on the other tabs.
    #
    #   Name         button title
    #   Description  one line under the title
    #   Script       path to a .ps1. Relative paths are under the iam_scripts folder; tokens and %ENVVARS% work
    #   Arguments    named parameters: @{ ParameterName = 'value' }. Tokens and %ENVVARS% work in values
    #   Switches     switch parameters to add, e.g. @('WhatIf')
    #
    # Tokens: {EngagementPath} {Evidence} {Registers} {Config} {Findings} {Reports} {Kit} {Server}
    #
    # Each action runs in its own PowerShell window with the command line shown at the top.
    # =====================================================================
    Actions = @(
        @{
            Name        = 'Compare two runs (example)'
            Description = 'Before / after for one script: pick the run folders when asked.'
            Script      = 'tools\Compare-RunFolders.ps1'
            Arguments   = @{ OutputRoot = '{Reports}' }
        }
        # A script kept outside the kit, e.g. in a private working repository:
        # @{
        #     Name        = 'Run summaries'
        #     Description = 'Headline counts for the latest runs.'
        #     Script      = '%USERPROFILE%\working-notes\scripts\Get-RunSummaries.ps1'
        #     Arguments   = @{ EvidenceRoot = '{Evidence}' }
        # }
    )
}
