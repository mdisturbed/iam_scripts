# 05 - AD group nesting

**Script:** [`05-Get-ADGroupNesting.ps1`](../../scripts/05-Get-ADGroupNesting.ps1) · **Version:** 1.0.1 · **Source:** AD

> How deep and messy is group nesting, and how healthy are groups?

Builds the full group-in-group graph in memory and reports structure and hygiene for every group.

**Collects:** one row per group with member counts, depth below (`DepthDown`) and above (`DepthUp`), and flags (empty, no owner, mail-enabled security, deep or circular nesting, naming-convention miss); one row per circular loop.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-DeepNestingThreshold` | `3` | Groups nested at least this deep are flagged |
| `-NamingConventionRegex` | none | e.g. `'^(RB|APP)-'` |

**Open first:** `summary.csv`, then `ad-groups.csv` filtered on `Flags`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-groups.csv` | Group | `DirectMembers`, `DirectGroupMembers`, `DepthDown`, `DepthUp`, `CycleId`, `Flags` |
| `ad-circular-nesting.csv` | Nesting loop | `Groups` |

`DepthDown` counts levels of groups nested inside a group; `DepthUp` counts levels of groups it sits inside.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read | RSAT AD |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: Total group count (`(Get-ADGroup -Filter *).Count`); one known nested group's `DepthDown`.

Usually tuned on first run: `-NamingConventionRegex` once a convention is agreed. See the [pilot runbook](../pilot-runbook.md).

---

[← 04 AD privileged and service accounts](04-ad-privileged-and-service-accounts.md) · [All scripts](README.md) · [06 JML timing →](06-jml-timing.md)
