# Guardrail: no identifying information in this repo

These scripts are meant to be run anywhere, so nothing committed here may identify an employer, a client,
a tenant, a server or a person. The guardrail checks that on every commit and every push. It **fails closed**:
if a check cannot run, the commit or build fails rather than letting it through.

## The three layers

1. **pre-commit hook** scans exactly what is staged (the staged blob, not your working copy).
2. **commit-msg hook** scans the commit message. Ticket numbers, hosts and names in messages stay in history too.
3. **GitHub Actions** (`.github/workflows/guardrail.yml`) runs on every push and pull request:
   - the self-test
   - a scan of every file plus every commit message and author
   - gitleaks over the full history

   This is the backstop for `git commit --no-verify`.

## What it blocks

Rules live in [`tools/guardrail/rules.psd1`](../tools/guardrail/rules.psd1).

- **Secrets**: private keys, Entra client secrets, JWTs, GitHub and AWS tokens, storage and SAS keys,
  a quoted password assigned to a variable, or a quoted string passed to `ConvertTo-SecureString -AsPlainText`.
- **Identifiers**: GUIDs (tenant, app, object), real `DC=` components, email addresses, `.gov` / `.local` /
  `.corp` / `onmicrosoft.com` / `sharepoint.com` names, IPv4 addresses, UNC paths, domain SIDs, ServiceNow
  ticket numbers, phone numbers, SSN-shaped numbers, user profile paths.
- **AI attribution**: AI assistant names, co-author trailers and session links, in files and commit messages.
- **Files**:
  - data, key and archive types (`.csv`, `.xlsx`, `.pfx`, `.pem`, `.log`, `.zip`, ...)
  - `*cred*.xml`, `*.local.psd1` and `.env`
  - binaries, and anything over 1 MB

  Only `examples/*.example.csv` is allowed, and its contents are still scanned.
- **Your private denylist**: org names, hostnames, group prefixes and people. The generic rules can't know these.

Microsoft-published IDs that are the same in every tenant (built-in role template IDs, guest access levels,
Microsoft's own tenant IDs) are listed with their source in
[`tools/guardrail/known-public-ids.txt`](../tools/guardrail/known-public-ids.txt) and pass the GUID rule.
Add one there only with a Microsoft source link.

Findings print **masked** (`abc*********`), and denylist hits print `(hidden)`, so a CI log never repeats the
value it caught.

## Placeholders

The guardrail lets these through, and they read as obviously fake.

| Kind | Use |
|---|---|
| Domain / DN | `DC=contoso,DC=com`, `contoso.com`, `contoso.local`, `example.com` |
| Email | `user@contoso.com`, `admin1@contoso.local` |
| SharePoint / tenant | `https://contoso-admin.sharepoint.com`, `contoso.onmicrosoft.com` |
| GUID | `00000000-0000-0000-0000-000000000000` (or `...0001`, `...0002` for lists) |
| Ticket | `INC0123456`, `REQ0000000`, `RITM1234567` |
| Server / share | `\\server\share`, `\\fileserver\share` |
| IP | `192.0.2.10` (192.0.2.x, 198.51.100.x and 203.0.113.x are documentation ranges) |
| Phone | `555-0100` to `555-0199` |
| User profile path | `C:\Users\username\...` |
| Secret | never a value; read it at run time (`Import-Clixml`, SecretManagement, Key Vault) |

Real values a script needs at run time come from parameters. Don't put them in defaults.

## Setup (once per machine)

```powershell
git clone https://github.com/mdisturbed/iam_scripts
cd iam_scripts
.\tools\guardrail\Install-Guardrail.ps1      # Windows PowerShell 5.1 or PowerShell 7
```

This:
- turns on the hooks (`git config core.hooksPath .githooks`)
- creates `tools/guardrail/denylist.local.txt` from the example
- confirms git ignores that file
- scans the repo

Then edit `denylist.local.txt`: add one regex per line for every org name, domain, hostname, group prefix and
person you work with.

**Add the same list to GitHub** so CI checks it too:
1. Open the repo's **Settings > Secrets and variables > Actions > New repository secret**.
2. Name it `GUARDRAIL_DENYLIST`.
3. Paste the list as the value, one regex per line.

## False positives

Add `guardrail:allow <reason>` to the line, in a `#` comment in PowerShell or `<!-- -->` in Markdown:

```powershell
$build = '10.0.17763.1'   # guardrail:allow OS build number, not an IP
```

Every allow shows up in review. Never use one to keep a real value.

## If CI fails

Something identifying reached GitHub. Even in a private repo, it stays in history.

1. Replace the value with a placeholder and commit.
2. If it was a **secret**, rotate it now. A secret that has been pushed is burned, even in a private repo.
3. Rewrite history to remove it (`git filter-repo --replace-text`), force-push, and have every other clone re-clone.

## Run it by hand

```powershell
.\tools\guardrail\Invoke-Guardrail.ps1 -Mode Staged    # what you are about to commit
.\tools\guardrail\Invoke-Guardrail.ps1 -Mode All       # whole repo + commit messages and authors
.\tools\guardrail\Test-Guardrail.ps1                   # self-test: every rule fires, placeholders pass
```

To add a rule:
1. Add it to `rules.psd1`.
2. Add a bad sample for it to `Test-Guardrail.ps1`. The self-test is how each rule keeps proving it works.
