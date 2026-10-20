# Design and testing

## Design choices

- **One file per area, no shared module.** Each script can be reviewed, approved, transferred or retyped on its own. The helper block at the top of each script is intentionally identical across scripts of the same kind.
- **Minimal dependencies.** Only the modules listed under [Prerequisites](getting-started.md#prerequisites); no Graph SDK sub-modules, no Az.Resources.
- **Configuration at the top.** Every environment-specific value is a parameter with a placeholder default (`contoso.local`, `tenant-id-redacted`). Nothing environment-specific is stored in the repository.
- **Paging and throttling handled.** Graph and ARM requests follow every page and back off on `429` and `5xx`.
- **Case-sensitive where it matters.** Attribute values are counted exactly as stored, so `Finance` and `finance` appear as separate values instead of being silently merged.
- **Facts, not conclusions.** Flags and triage scores are sorting aids; scoring and recommendations belong in the analysis.

## Testing

Before release, every script was:

- parse-checked and linted with PSScriptAnalyzer (no errors or warnings outside documented exclusions)
- checked with `Test-ReadOnly.ps1`, including negative tests confirming it catches write cmdlets (AD, Exchange, Azure), non-GET Graph calls and non-GET ARM calls
- run end to end on PowerShell 7.4 against mocked Graph, AD (including ACLs), Intune, Exchange Online, SharePoint, Azure Resource Manager, AWS and domain controller event log responses using placeholder data, including paging, missing licences, permission failures, deleted principals, circular nesting, case variants, expired credentials, missing schema attributes, accounts that can't be assumed, unreadable DCs and every optional switch

Results were checked against the values the mock data should produce, not only for "no errors". This caught and fixed real defects before release (see [CHANGELOG.md](../CHANGELOG.md)).

**The scripts have not yet been run against a live environment.** Use the [pilot runbook](pilot-runbook.md) to verify each one before handing it to others.

[← Back to README](../README.md)
