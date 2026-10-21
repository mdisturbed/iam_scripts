# 23 - AD attribute population

**Script:** [`23-Get-ADAttributePopulation.ps1`](../../scripts/23-Get-ADAttributePopulation.ps1) · **Version:** 1.1.0 · **Source:** AD (schema + objects)

> Which attributes does the schema allow on users, groups and computers, and how many objects actually have a value in each?

Where 08 profiles the spare attributes you might claim, this inventories **every** attribute the schema allows, so you can see what is really populated, how consistently, and what is never used, before choosing attributes to drive roles, sync rules or lifecycle automation.

**How it works:**
1. Reads the schema and resolves everything the class can hold: the class, every class it inherits from (`user` → `organizationalPerson` → `person` → `top`) and every auxiliary class attached anywhere in that chain (Exchange's mail classes, for example). Attributes nobody uses still appear, with 0.
2. Reads every object once per batch of attributes and counts, per attribute: objects with a value, total values, distinct values and the longest value.
3. Counts large binary attributes (photos, certificates, other octet strings) with a presence-only query, so their content is never downloaded.

**Not counted** (and reported as such): constructed attributes (computed on read), base-only attributes (a search across many objects that requests them fails), and security descriptors.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ObjectClass` | `user`, `group`, `computer` | Any of the three; `-ObjectClass user` alone is lighter |
| `-EnabledOnly` | off | Users and computers: enabled accounts only |
| `-SampleValueCount` | `0` | Most common values per attribute. Off by default: directory-wide values are personal data |
| `-DistinctValueCap` | `1000` | Stop counting distinct values above this (shown as `1000+`) |
| `-BatchSize` | `100` | Attributes requested per pass over the objects |
| `-SkipPresenceQueries` | off | Skip the binary-attribute presence counts (faster) |

**Open first:** `summary.csv`, then `attribute-population.csv` filtered on `ObjectClass`, sorted by `PercentPopulated`. Good starting views:
- `Status = Populated` and `PercentPopulated` between 1 and 95: partly populated, so check whether it should be complete (department, title, manager, employeeID).
- `DistinctValues` low relative to `Populated`: code-like values (job code, cost center, location) that could drive roles.
- `Status = Empty` and `SystemOnly = False`: never used; candidate for new data (cross-check with [08](08-extension-attribute-inventory.md) and Entra Connect sync rules first).

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `attribute-population.csv` | Object class + attribute allowed by the schema | `Status`, `Populated`, `Objects`, `PercentPopulated`, `TotalValues`, `DistinctValues`, `MaxLength`, `Syntax`, `SingleValued`, `Mandatory`, `DefinedBy` (class that brings it in), `InGlobalCatalog`, `Linked` (forward / back link), `SystemOnly`, `Confidential`, `Note`, (`SampleValues`) |
| `schema-class-closure.csv` | Schema class whose attributes apply | `ObjectClass`, `SchemaClass`, `HowIncluded` (structural / inherited / auxiliary), `Attributes` |

**Status values:** `Populated`, `Empty`, `Empty or not readable (confidential)`, `Not counted (constructed …)`, `Not counted (base-only …)`, `Not counted (security descriptor)`, `Not counted (defunct or not in schema)`, `Not counted (-SkipPresenceQueries)`, `Read failed`.

**Reading it:**
- **Confidential** attributes are returned only to accounts with the extended read right, so 0 means "empty *or* not readable by the run account", never "unused".
- **Not-replicated** attributes (`lastLogon`, `badPwdCount`, `logonCount` …) hold a per-DC value; the `Note` column says so. Use `lastLogonTimestamp` for activity.
- **Back links** (`memberOf`, `directReports`) are maintained by AD from the forward link; their population mirrors `member` / `manager`.
- If one batch can't be read, that batch falls back to presence counts (populated count only, no value statistics) and the `Note` says so.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| - | - | Domain read and schema read (any authenticated user by default) | RSAT AD |

Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: `user objects scanned` matches `(Get-ADUser -Filter * -Server <DC>).Count`, and one attribute you know is fully populated (e.g. `sAMAccountName`) shows 100%.

Usually tuned on first run: `-ObjectClass user`, `-EnabledOnly`, `-SearchBase` to limit load. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 23: `pass N failed ... counting this batch one attribute at a time` | One attribute in the batch can't be returned by a search | Informational; that batch is counted by presence. Lower `-BatchSize` to narrow it down |
| Script 23: takes a long time | Every attribute of every object is read once per batch | Run off-peak; `-SearchBase`, `-EnabledOnly`, `-ObjectClass user` alone, or `-SkipPresenceQueries` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 22 PIM role settings](22-pim-role-settings.md) · [All scripts](README.md) · [24 CA report-only impact →](24-ca-reportonly-impact.md)
