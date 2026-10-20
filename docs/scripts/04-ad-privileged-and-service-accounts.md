# 04 - AD privileged and service accounts

**Script:** [`04-Get-ADPrivilegedAndServiceAccounts.ps1`](../../scripts/04-Get-ADPrivilegedAndServiceAccounts.ps1) · **Version:** 1.0.1 · **Source:** AD

> Who has admin rights on-prem (including via nesting), and where are the service accounts?

Finds every account with admin rights on-prem, including rights gained through nested groups, and finds likely service accounts.

**Collects:** membership of every protected group with the full nesting path; one row per privileged account with hygiene flags (stale, password never expires, Kerberoastable, pre-auth disabled, delegation, nested-only); service-account candidates with the detection reasons; `adminCount=1` leftovers.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ServiceNamePatterns` | `svc*`, `sa-*`, `sa_*`, … | Name patterns that indicate a service account |
| `-AdditionalPrivilegedGroups` | none | Custom admin groups to expand |
| `-StaleDays` | `90` | Days without logon before flagging |
| `-PasswordAgeWarningDays` | `365` | Passwords older than this are flagged |

**Open first:** `summary.csv`, then `ad-privileged-accounts.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-privileged-membership.csv` | Member found while expanding a protected group | `PrivilegedGroup`, `Depth`, `NestingPath` |
| `ad-privileged-accounts.csv` | Privileged account | `PrivilegedVia`, `Flags` (stale, never-expiring or old password, Kerberoastable, pre-auth disabled, delegation, nested-only) |
| `ad-service-account-candidates.csv` | Candidate service account | `DetectionReasons`, `IsPrivileged`, `Stale`, `PasswordAgeDays`, `HasManagedBy` |
| `ad-admincount-orphans.csv` | Account with adminCount=1 no longer in a protected group | hygiene columns |

**Reading it:** service accounts are candidates found by heuristics (SPN, never-expiring password, name pattern, description, gMSA). Confirm with owners before reporting a count as fact.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read | RSAT AD |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Domain Admins membership in ADUC, including a nested group if one exists.

Usually tuned on first run: Service / admin account name patterns (`-ServiceNamePatterns`, `-ExcludeNamePatterns`). See the [pilot runbook](../pilot-runbook.md).

---

[← 03 Apps and consents](03-apps-and-consents.md) · [All scripts](README.md) · [05 AD group nesting →](05-ad-group-nesting.md)
