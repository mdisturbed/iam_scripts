# Permissions

Everything here is read-only. Ask for the narrowest option that works and, where PIM is in use, make roles eligible rather than permanent.

## Entra directory role (for the operator)

| Option | Covers | Notes |
|--------|--------|-------|
| **Global Reader** (preferred) | Scripts 01, 02, 03 | Read across users, groups, apps, CA, roles and logs |
| Security Reader + Reports Reader | Most of 01-03 | Fallback if Global Reader is refused; some app details may be Blocked |

## Graph scopes

Delegated (signing in as yourself through Microsoft Graph PowerShell) needs an admin to consent to these read scopes once. App-only (certificate) needs the same names granted as **application** permissions on a dedicated read-only app registration.

| Scope | 01 MFA | 02 Privileged | 03 Apps | 06 JML (`-IncludeEntraSignIn`) |
|-------|:-----:|:------------:|:------:|:------------------------------:|
| `Directory.Read.All` | X | X | X | |
| `Policy.Read.All` | X | | X | |
| `AuditLog.Read.All` | X | X | X | X |
| `UserAuthenticationMethod.Read.All` | X | X | | |
| `RoleManagement.Read.Directory` | | X | | |
| `Application.Read.All` | | | X | |
| `User.Read.All` | | | | X |

## Licence-dependent data

| Data | Needs | If missing |
|------|-------|-----------|
| Sign-in logs, `signInActivity`, registration details | Entra ID P1 | Dataset marked `EvidenceUnavailable` or `Blocked` |
| PIM eligible assignments, assignment schedules | Entra ID P2 / ID Governance | Script 02 falls back to plain role assignments; eligible marked `EvidenceUnavailable` |
| Service-principal sign-in activity | Entra ID P1 (Graph beta report) | `LastSignInUtc` left blank |

## Active Directory

| Need | Detail |
|------|--------|
| Account | Standard domain user is normally enough to read users, groups and `adminCount`. |
| Module | RSAT `ActiveDirectory` |
| Host | An approved management host; scripts 05 and 06 read every group or user once, so run them off-peak in large domains |
| Replication metadata (script 06) | `Get-ADReplicationAttributeMetadata` is readable by authenticated users by default; use `-SkipDisableTimestamp` if it is restricted |

## App registration for app-only mode (optional)

If the client prefers a dedicated identity over delegated access:

1. Create a single-tenant app registration, e.g. `App1-IAM-Discovery-ReadOnly`, with an owner.
2. Add the application permissions above (read scopes only) and grant admin consent.
3. Upload a certificate (no client secret). Keep the private key in the user certificate store of the run host.
4. Run with `-AuthMode AppCertificate -TenantId ... -ClientId ... -CertificateThumbprint ...`.
5. Disable or delete the app when discovery ends; it is itself a privileged non-human identity.
