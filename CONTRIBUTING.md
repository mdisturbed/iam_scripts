# Contributing

Issues and pull requests are welcome. These rules apply to every change.

## Keep it anonymous

Nothing in this repo may identify an employer, client, tenant, server or person. Read `docs/guardrail.md`.

- Never write real environment values into a tracked file: domain names, DNs, tenant / app / object IDs,
  group or OU names, hostnames, IPs, email addresses, ticket numbers, people's names, file shares. Use the
  placeholders in `docs/guardrail.md`. Real values come from parameters at run time.
- When porting a script from a work environment, sanitize it first: turn every environment value into a
  parameter or placeholder, and strip comments that name people, tickets, agencies, or dates tied to an incident.
- Commit messages follow the same rule. Describe the change, not the environment.

## Before you commit

- Run `.\tools\guardrail\Install-Guardrail.ps1` once after cloning; it turns on the hooks.
- Before every commit, run `.\tools\guardrail\Invoke-Guardrail.ps1 -Mode Staged`. Never use `--no-verify`.
  Never add `guardrail:allow` to keep a real value.
- Never put a real org's name in `denylist.example.txt` or any other tracked file. The real list lives only in
  `tools/guardrail/denylist.local.txt` (gitignored) and the `GUARDRAIL_DENYLIST` repo secret.
- Changing a guardrail rule means updating `Test-Guardrail.ps1` in the same commit, and the self-test must pass.
- Discovery scripts stay read-only: run `.\tools\Test-ReadOnly.ps1` after any script edit.
