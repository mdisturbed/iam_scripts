# 08 - Extension attribute inventory

**Script:** [`08-Get-ExtensionAttributeInventory.ps1`](../../scripts/08-Get-ExtensionAttributeInventory.ps1) · **Version:** 1.1.0 · **Source:** AD (+ Entra)

> Which custom / extension attributes are free to carry new data, and does anything already read them?

Before choosing an attribute to carry new data (for example the roles applied by the JML automation), find out which are already in use, on which object types, and which Entra rules already read them.

**Collects:** for AD users, groups, computers and contacts, `extensionAttribute1-15` plus any listed attributes, with populated count and %, distinct values, maximum length, values per object, format hints (MultiValued, List, Date, Number, Email, LowCardinality, UniquePerObject) and top values; status `InUse`, `Rare`, `Unused`, `NotInSchema` or `Unreadable`. With `-IncludeEntra`: cloud-only users' `onPremisesExtensionAttributes`, Entra device `extensionAttributes`, directory (schema) extensions registered by apps, optionally custom security attribute definitions with how many users hold each, and the **consumers** of each attribute: dynamic group and dynamic administrative unit membership rules and Conditional Access device filters.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-Classes` | `User`, `Group`, `Computer`, `Contact` | AD object classes to profile |
| `-AdditionalAttributes` | `employeeType`, `employeeNumber`, `division`, `departmentNumber`, `info` | Extra attributes to profile |
| `-IncludeCloudExtensionAttributes` | off | Add `msDS-cloudExtensionAttribute1-20` |
| `-IncludeGroups` | off | Accepted for older command lines; groups are in `-Classes` by default |
| `-SampleValueCount` | `3` | Top values shown; `0` suppresses them if values could be personal data |
| `-IncludeEntra` | off | Add the Entra datasets and the consumer check |
| `-CountExtensionUsage` | off | Count users holding each directory extension |
| `-IncludeCustomSecurityAttributes` | off | Definitions and holder counts; needs `CustomSecAttributeDefinition.Read.All` + `CustomSecAttributeAssignment.Read.All` and the Attribute Definition Reader / Attribute Assignment Reader roles |

Groups, computers and contacts are profiled by default; earlier versions profiled users only (groups with `-IncludeGroups`). User rows keep the same columns and values for single-valued attributes.

**Open first:** `summary.csv` (lists unused attributes by name, and unused attributes a rule already reads), then `ad-attribute-usage.csv` and `attribute-consumers.csv`.

Common parameters (`-OutputRoot`, `-Server`, `-SearchBase`, `-AuthMode` …) are in [Getting started](../getting-started.md#common-parameters).

## Output

Each run folder also has `summary.csv`, `dataset-status.csv`, `run-manifest.json` and `run.log` ([run folder layout](../outputs.md#run-folder)).

| File | One row per | Key columns |
|------|-------------|-------------|
| `ad-attribute-usage.csv` | Object type + attribute | `Populated`, `PopulatedPct`, `DistinctValues`, `MaxLength`, `FormatHints`, `SampleValues`, `Status` (InUse / Rare / Unused / NotInSchema / Unreadable), `MaxValuesPerObject`, `KnownConsumers` |
| `entra-cloudonly-extension-usage.csv` | extensionAttribute1-15 on cloud-only users | as above (without the last two columns) |
| `entra-device-extension-usage.csv` | extensionAttribute1-15 on Entra devices | as `ad-attribute-usage.csv` |
| `entra-directory-extensions.csv` | Schema extension registered by an app | `ExtensionName`, `DataType`, `TargetObjects`, `OwningApp`, `UsersWithValue`, `KnownConsumers` |
| `entra-custom-security-attributes.csv` | Custom security attribute definition | `AttributeSet`, `Name`, `Type`, `IsCollection`, `UsersWithValue`, `HolderEvidence` |
| `attribute-consumers.csv` | Rule that reads an attribute | `Attribute`, `ConsumerType` (DynamicGroup / DynamicAdministrativeUnit / ConditionalAccessDeviceFilter), `ConsumerName`, `Rule` (excerpt), `Target` (user / device), `ConsumerState`, `ConsumerId` |

**Reading it:**
- *Unused* means no object holds a value today. `KnownConsumers` counts the Entra rules that read the attribute (user attributes for AD users and directory extensions, device attributes for Entra devices). A rule that reads an unused attribute means it isn't free: the summary lists those.
- `KnownConsumers` is blank when the consumer check didn't run, `Unknown` when it couldn't be read, and `Unknown (Partial)` when part of it couldn't be read and no consumer was found.
- AD `extensionAttribute1-15` on users sync to Entra `onPremisesExtensionAttributes`, so a rule on `user.extensionAttribute5` or `user.onPremisesExtensionAttributes.extensionAttribute5` reads the AD value. Entra device `extensionAttributes` are set in Entra, not synced from AD computers.
- Multi-valued attributes (`proxyAddresses`, for example) are counted per value: `Populated` is objects with at least one value, `DistinctValues` and samples count individual values, and `MaxValuesPerObject` shows the largest number on one object.
- **Not covered:** Exchange address lists, email address policies and dynamic distribution groups (extensionAttribute1-15 are Exchange custom attributes 1-15; reading them needs Exchange), Entra Connect sync rules, and applications that read AD. Confirm none of them reads an attribute before claiming it.

## Permissions

| Entra role | Graph scopes | Other access | Modules |
|-----------|--------------|--------------|---------|
| (Global Reader with `-IncludeEntra`) | (Directory.Read.All, Application.Read.All, Policy.Read.All; + CustomSecAttributeDefinition.Read.All, CustomSecAttributeAssignment.Read.All) | Domain read; (Attribute Definition Reader and Attribute Assignment Reader for custom security attributes) | RSAT AD (+ Graph Auth) |

Brackets mean only with the matching optional switch. Policy.Read.All is for the Conditional Access device filters. Full detail: [permissions](../permissions.md).

## Pilot check

Before handing this script to others, confirm: One attribute you know is in use shows `InUse`, with a plausible count; one dynamic group you know of appears in `attribute-consumers.csv`.

Usually tuned on first run: `-AdditionalAttributes`, `-SampleValueCount 0` if values are sensitive. See the [pilot runbook](../pilot-runbook.md).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Script 08: `Bulk read failed ... retrying per attribute` | An attribute isn't in the schema (for that class) | Informational; it shows as `NotInSchema` |
| Script 08: a class shows `Unreadable` and the dataset note says PARTIAL | No read access to that object class or OU | Fix access or drop the class with `-Classes`; unreadable rows are not evidence of Unused |
| Script 08: `attribute-consumers` Blocked or PARTIAL | Directory.Read.All or Policy.Read.All missing | Consent the scope; `KnownConsumers` shows `Unknown` until then |
| Script 08: `UsersWithValue` = `EvidenceUnavailable` for custom security attributes | No CustomSecAttributeAssignment.Read.All or Attribute Assignment Reader role | Grant both, or read the definitions only |
| Script 08: `extensionProperties of app ... not readable` | Access to one app denied | The dataset note says PARTIAL and lists the apps |

General issues: [troubleshooting](../troubleshooting.md).

---

[← 07 Role mining](07-role-mining.md) · [All scripts](README.md) · [09 Mail forwarding and external sharing →](09-mail-forwarding-and-external-sharing.md)
