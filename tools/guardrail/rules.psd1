@{
    # =====================================================================
    # Guardrail rules - what may never be committed to this repo.
    # Each rule: Id, Description, Pattern (.NET regex), optional Allow (regex tested against the matched value;
    # a match that also matches Allow is a safe placeholder and is not reported).
    # Keep org-specific words (names, hostnames, agency names) OUT of this file: they go in the local denylist
    # (tools/guardrail/denylist.local.txt, gitignored) and the GUARDRAIL_DENYLIST repo secret for CI.
    # Patterns are case-sensitive unless they start with (?i).
    # =====================================================================

    BlockedExtensions = @('.csv', '.tsv', '.xlsx', '.xls', '.xlsm', '.pfx', '.p12', '.pem', '.key', '.cer', '.crt',
                          '.kdbx', '.log', '.bak', '.zip', '.7z', '.evtx', '.ldf', '.dmp', '.ost', '.pst')
    BlockedNamePatterns = @('(?i)cred.*\.xml$', '(?i)\.local\.psd1$', '(?i)secrets?\.', '(?i)\.env$', '(?i)denylist\.local')
    # Placeholder input templates (examples/*.example.csv) are the only data files allowed; their CONTENT is still scanned
    AllowedNamePatterns = @('(?i)(^|/)examples/[^/]+\.example\.(csv|json)$')
    MaxFileBytes = 1048576

    Rules = @(
        # ---------------- Secrets ----------------
        @{ Id = 'secret-private-key';    Description = 'Private key block'
           Pattern = '-----BEGIN [A-Z ]*PRIVATE KEY-----' }
        @{ Id = 'secret-entra-client-secret'; Description = 'Entra app client secret value'
           Pattern = '(?<![A-Za-z0-9_~.-])[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}' }
        @{ Id = 'secret-jwt';            Description = 'JWT / bearer token'
           Pattern = 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' }
        @{ Id = 'secret-github-token';   Description = 'GitHub token'
           Pattern = '\bgh[pousr]_[A-Za-z0-9]{36,}' }
        @{ Id = 'secret-aws-key';        Description = 'AWS access key'
           Pattern = '\bAKIA[0-9A-Z]{16}\b' }
        @{ Id = 'secret-connection-key'; Description = 'Storage / SAS / service bus key'
           Pattern = '(?i)\b(AccountKey|SharedAccessKey|sig)=[A-Za-z0-9%+/=]{20,}' }
        @{ Id = 'secret-plaintext-securestring'; Description = 'Literal password turned into a SecureString'
           Pattern = '(?i)ConvertTo-SecureString\s+["''][^"''$%]+["'']\s+-AsPlainText' }
        @{ Id = 'secret-assignment';     Description = 'Password / secret / key assigned a literal value'
           Pattern = '(?i)\b(password|passwd|pwd|secret|client_?secret|api_?key|access_?token)\s*[:=]\s*["''][^"''\s$%{(<]{6,}["'']'
           Allow   = '(?i)["''](placeholder|changeme|redacted|xxxxxx+)["'']' }

        # ---------------- Identifiers ----------------
        @{ Id = 'id-guid';               Description = 'GUID (tenant ID, client ID, object ID, command ID)'
           Pattern = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
           # all one digit (00000000-..., 11111111-...) or the public Microsoft first-party app IDs (00000003-0000-0000-c000-...)
           Allow   = '^(([0-9a-fA-F])\2{7}-\2{4}-\2{4}-\2{4}-\2{12}|00000000-0000-0000-0000-0000000000\d\d|0000000[0-9a-fA-F]-0000-0000-c000-000000000000)$' }
           # plus every GUID in known-public-ids.txt (Microsoft built-in role template IDs and similar)
        @{ Id = 'id-distinguished-name'; Description = 'Real domain component in a DN (DC=...)'
           Pattern = '(?i)\bDC=[A-Za-z0-9-]+'
           Allow   = '(?i)^DC=(example|contoso|fabrikam|domain|corp|com|org|net|local|test)$' }
        @{ Id = 'id-email';              Description = 'Email address'
           Pattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b'
           Allow   = '(?i)(@((.+\.)?(example|contoso|fabrikam)(-[a-z0-9]+)?\.[a-z.]+|users\.noreply\.github\.com)$)' }
        @{ Id = 'ai-attribution';        Description = 'AI assistant name or attribution (co-author trailer, session link)'
           Pattern = '(?i)\bcl[a]ude\b|\banthr[o]pic\b' }
        @{ Id = 'id-internal-domain';    Description = 'Internal or government domain name'
           Pattern = '(?i)\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(gov|mil|local|corp|internal|intranet|lan|onmicrosoft\.com|onmicrosoft\.us|sharepoint\.com)\b(?!\.?[A-Za-z0-9])'
           Allow   = '(?i)^((.+\.)?(example|contoso|fabrikam)(-[a-z0-9]+)?\.[a-z.]+|graph\.microsoft\.us)$' }
        @{ Id = 'id-ipv4';               Description = 'IPv4 address'
           Pattern = '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
           Allow   = '^(0\.0\.\d+\.\d+|127\.0\.0\.1|255\.255\.255\.\d+|192\.0\.2\.\d+|198\.51\.100\.\d+|203\.0\.113\.\d+)$' }
        @{ Id = 'id-unc-path';           Description = 'UNC path to a real server'
           Pattern = '\\\\[A-Za-z0-9._-]{2,}\\[A-Za-z0-9$._-]+'
           Allow   = '(?i)^\\\\(server|fileserver|example|contoso|localhost|\?)\\' }
        @{ Id = 'id-domain-sid';         Description = 'Domain SID'
           Pattern = '\bS-1-5-21-\d{6,}-\d{6,}-\d{6,}(-\d+)?\b' }
        @{ Id = 'id-ticket-number';      Description = 'Real ServiceNow ticket number'
           Pattern = '\b(INC|REQ|RITM|CHG|TASK|SCTASK|PRB)\d{7}\b'
           Allow   = '^(INC|REQ|RITM|CHG|TASK|SCTASK|PRB)(0000000|0123456|1234567)$' }
        @{ Id = 'id-us-phone';           Description = 'Phone number'
           Pattern = '(?<!\d)\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)'
           Allow   = '555[-. ]01\d\d$' }
        @{ Id = 'id-ssn';                Description = 'SSN-shaped number'
           Pattern = '(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)' }
        @{ Id = 'id-user-profile-path';  Description = 'Path that names a real user profile'
           Pattern = '(?i)(C:\\Users\\|/Users/|/home/)[A-Za-z0-9._-]+'
           Allow   = '(?i)(\\|/)(Public|Default|user|username|you|runner|example)$' }
    )
}
