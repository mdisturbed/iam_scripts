# 08 - Extension attribute inventory

**Script:** [`08-Get-ExtensionAttributeInventory.ps1`](../../scripts/08-Get-ExtensionAttributeInventory.ps1) · **Version:** 1.0.0 · **Source:** AD (+ Entra)

> Which custom / extension attributes are free to carry new data?

Before choosing an attribute to carry new data (for example the roles applied by the JML automation), find out which are already in use.

**Collects:** for AD users (and optionally groups), `extensionAttribute1-15` plus any listed attributes, with populated count and %, distinct values, maximum length, format hints (List, Date, Number, Email, LowCardinality, UniquePerObject) and top values; status `InUse`, `Rare`, `Unused` or `NotInSchema`. With `-IncludeEntra`: cloud-only users' `onPremisesExtensionAttributes`, directory (schema) extensions registered by apps, and optionally custom security attribute definitions.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-AdditionalAttributes` | `employeeType`, `employeeNumber`, `division`, `departmentNumber`, `info` | Extra attributes to profile |
| `-IncludeCloudExtensionAttributes` | off | Add `msDS-cloudExtensionAttribute1-20` |
| `-IncludeGroups` | off | Profile groups as well as users |
| `-SampleValueCount` | `3` | Top values shown; `0` suppresses them if values could be personal data |
| `-IncludeEntra` | off | Add the Entra datasets |
| `-CountExtensionUsage` | off | Count users holding each directory extension |
| `-IncludeCustomSecurityAttributes` | off | Needs `CustomSecAttributeDefinition.Read.All` and Attribute Definition Reader |

**Open first:** `summary.csv` (lists unused attributes by name), then `ad-attribute-usage.csv`. *Unused* doesn't prove nothing reads an attribute: check Entra Connect sync rules, Exchange (extensionAttribute1-15 are Exchange custom attributes) and any app that reads AD.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-attribute-usage.csv` | Object type + attribute | `Populated`, `PopulatedPct`, `DistinctValues`, `MaxLength`, `FormatHints`, `SampleValues`, `Status` (InUse / Rare / Unused / NotInSchema) |
| `entra-cloudonly-extension-usage.csv` | extensionAttribute1-15 on cloud-only users | as above |
| `entra-directory-extensions.csv` | Schema extension registered by an app | `ExtensionName`, `DataType`, `TargetObjects`, `OwningApp`, `UsersWithValue` |
| `entra-custom-security-attributes.csv` | Custom security attribute definition | `AttributeSet`, `Name`, `Type`, `IsCollection` |

**Reading it:** *Unused* means no object holds a value today. Before claiming an attribute, confirm no Entra Connect sync rule, Exchange feature or application reads it.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| (Global Reader with `-IncludeEntra`) | (Directory.Read.All, Application.Read.All; + CustomSecAttributeDefinition.Read.All) | Domain read; (Attribute Definition Reader for custom security attributes) | RSAT AD (+ Graph Auth) |

Brackets mean only with the matching optional switch. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One attribute you know is in use shows `InUse`, with a plausible count.

Usually tuned on first run: `-AdditionalAttributes`, `-SampleValueCount 0` if values are sensitive. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 08: `Bulk read failed ... retrying per attribute` | An attribute isn't in the schema | Informational; it shows as `NotInSchema` |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 07 Role mining](07-role-mining.md) · [All scripts](README.md) · [09 Mail forwarding and external sharing →](09-mail-forwarding-and-external-sharing.md)
