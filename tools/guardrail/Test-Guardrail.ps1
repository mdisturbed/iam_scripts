<#
.SYNOPSIS
    Self-test for the guardrail: plants one bad value per rule in a temp folder and confirms each is caught,
    then confirms a file full of approved placeholders passes, and that a pinned binary (allowed-binaries.txt)
    passes only at its listed SHA-256. Runs in CI on every push.
    Bad samples are built by joining fragments so this file itself never contains a real-looking value.
.EXAMPLE
    pwsh tools/guardrail/Test-Guardrail.ps1
#>
$ErrorActionPreference = 'Stop'
$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$scanner = Join-Path $here 'Invoke-Guardrail.ps1'
$psExe   = (Get-Process -Id $PID).Path
$tmp     = Join-Path ([IO.Path]::GetTempPath()) ("guardrail-test-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null

$bad = [ordered]@{
    'secret-private-key'            = '-----BEGIN ' + 'RSA PRIVATE KEY-----'
    'secret-entra-client-secret'    = '$s = "abc' + '8Q~' + ('Zq9' * 11) + '"'
    'secret-jwt'                    = 'Bearer eyJ' + 'hbGciOiJIUzI1' + '.eyJ' + 'zdWIiOiIxMjM0' + '.Sfl' + 'KxwRJSMeKKF2QT4'
    'secret-github-token'           = 'ghp' + '_' + ('a1B2' * 9)
    'secret-aws-key'                = 'AKI' + 'AIOSFODNN7EXAMPLE'
    'secret-connection-key'         = 'Account' + 'Key=' + ('k9' * 15)
    'secret-plaintext-securestring' = 'ConvertTo-SecureString "Hunt' + 'er2abc" -AsPlainText -Force'
    'secret-assignment'             = '$password = "Sup' + 'erS3cret!"'
    'id-guid'                       = '$tenantId = "3f2b' + '9c1d-1a2b-4c3d-8e9f-0a1b2c3d4e5f"'
    'id-distinguished-name'         = '$ou = "OU=Users,DC=' + 'acme,DC=com"'
    'id-email'                      = 'Send-MailMessage -To jdoe' + '@acme.com'
    'id-internal-domain'            = 'Enter-PSSession srv01.acme' + '.local'
    'id-ipv4'                       = '$dc = "10.' + '20.30.40"'
    'id-unc-path'                   = '$share = "\\' + '\fs01\hr$"'
    'id-domain-sid'                 = 'S-1-5-21-' + '1234567-2345678-3456789-1105'
    'id-ticket-number'              = '# per INC' + '4815162'
    'id-us-phone'                   = 'call 401' + '-555-1234'
    'id-ssn'                        = 'ssn 078' + '-05-1120'
    'ai-attribution'                = 'Co-Authored-By: Cla' + 'ude <noreply@anthr' + 'opic.com>'
    'id-user-profile-path'          = 'C:\Users\' + 'jdoe\Desktop\out.txt'
    'denylist-1'                    = 'Invoke-Command -ComputerName ACME' + 'CORP-APP01'
}
$blockedFiles = [ordered]@{ 'blocked-file-type' = 'export.csv'; 'blocked-file-name' = 'graph.cred.xml' }

$clean = @'
$ou       = "OU=Users,DC=contoso,DC=com"
$mail     = "user@contoso.com"
$tenantId = "00000000-0000-0000-0000-000000000000"   # set in settings.local.psd1
$graphApp = "00000003-0000-0000-c000-000000000000"   # Microsoft Graph, public
$ticket   = "INC0123456"
if ($ticket -notmatch '^(INC|REQ|RITM)\d{7}$') { }
$share    = "\\server\share"
$ip       = "192.0.2.10"
$path     = "C:\Users\username\Documents"
$param    = "%param-ticketNumber%"
$password = $cred.GetNetworkCredential().Password
$version  = "7.4.6"
$phone    = "401-555-0123"
$build    = "10.0.17763.1"   # guardrail:allow OS build number, not an IP
'@

$failures = 0
try {
    $env:GUARDRAIL_DENYLIST = 'acmecorp'
    $i = 0
    foreach ($rule in $bad.Keys) {
        $i++; $f = Join-Path $tmp ("bad$i.ps1"); Set-Content -Path $f -Value $bad[$rule]
        $out = & $psExe -NoProfile -File $scanner -Mode Files -Path $f 2>&1 | Out-String
        if ($LASTEXITCODE -eq 1 -and $out -match [regex]::Escape($rule)) { Write-Host "  caught   $rule" -ForegroundColor Green }
        else { Write-Host "  MISSED   $rule (exit $LASTEXITCODE)`n$out" -ForegroundColor Red; $failures++ }
    }
    foreach ($rule in $blockedFiles.Keys) {
        $f = Join-Path $tmp $blockedFiles[$rule]; Set-Content -Path $f -Value 'x'
        $out = & $psExe -NoProfile -File $scanner -Mode Files -Path $f 2>&1 | Out-String
        if ($LASTEXITCODE -eq 1 -and $out -match [regex]::Escape($rule)) { Write-Host "  caught   $rule" -ForegroundColor Green }
        else { Write-Host "  MISSED   $rule (exit $LASTEXITCODE)`n$out" -ForegroundColor Red; $failures++ }
    }
    # ---- pinned binaries (allowed-binaries.txt): exact content passes, changed content or an unlisted binary fails ----
    $root = Join-Path $tmp 'pinroot'; New-Item -ItemType Directory -Path (Join-Path $root 'templates') -Force | Out-Null
    $pinnedFile = Join-Path (Join-Path $root 'templates') 'sample.template.xlsx'
    [IO.File]::WriteAllBytes($pinnedFile, [byte[]](0x50, 0x4B, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03))
    $sha = (Get-FileHash -LiteralPath $pinnedFile -Algorithm SHA256).Hash
    $list = Join-Path $tmp 'allowed-binaries.txt'
    Set-Content -Path $list -Value @('# test list', "$sha  templates/sample.template.xlsx  # self-test")
    $pinArgs = @('-NoProfile', '-File', $scanner, '-Mode', 'Files', '-AllowedBinariesPath', $list, '-RootPath', $root, '-Path')
    $out = & $psExe @pinArgs $pinnedFile 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Write-Host '  passed   pinned binary at its listed SHA-256' -ForegroundColor Green }
    else { Write-Host "  FALSE POSITIVE on pinned binary (exit $LASTEXITCODE)`n$out" -ForegroundColor Red; $failures++ }
    [IO.File]::WriteAllBytes($pinnedFile, [byte[]](0x50, 0x4B, 0x03, 0x04, 0x00, 0x01, 0x02, 0x04))
    $out = & $psExe @pinArgs $pinnedFile 2>&1 | Out-String
    if ($LASTEXITCODE -eq 1 -and $out -match 'pinned-binary-changed') { Write-Host '  caught   pinned-binary-changed (same path, different content)' -ForegroundColor Green }
    else { Write-Host "  MISSED   pinned-binary-changed (exit $LASTEXITCODE)`n$out" -ForegroundColor Red; $failures++ }
    $unlisted = Join-Path (Join-Path $root 'templates') 'other.xlsx'
    [IO.File]::WriteAllBytes($unlisted, [byte[]](0x50, 0x4B, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03))
    $out = & $psExe @pinArgs $unlisted 2>&1 | Out-String
    if ($LASTEXITCODE -eq 1 -and $out -match 'blocked-file-type') { Write-Host '  caught   blocked-file-type (unlisted .xlsx, same content as a pinned file)' -ForegroundColor Green }
    else { Write-Host "  MISSED   unlisted .xlsx (exit $LASTEXITCODE)`n$out" -ForegroundColor Red; $failures++ }
    Set-Content -Path $list -Value 'not-a-hash  templates/sample.template.xlsx'
    $out = & $psExe @pinArgs $pinnedFile 2>&1 | Out-String
    if ($LASTEXITCODE -eq 2) { Write-Host '  caught   unreadable allowed-binaries line (fails closed)' -ForegroundColor Green }
    else { Write-Host "  MISSED   unreadable allowed-binaries line (exit $LASTEXITCODE)`n$out" -ForegroundColor Red; $failures++ }

    $f = Join-Path $tmp 'clean.ps1'; Set-Content -Path $f -Value $clean
    $out = & $psExe -NoProfile -File $scanner -Mode Files -Path $f 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Write-Host '  passed   placeholders file is clean' -ForegroundColor Green }
    else { Write-Host "  FALSE POSITIVE on placeholders (exit $LASTEXITCODE)`n$out" -ForegroundColor Red; $failures++ }
}
finally {
    Remove-Item -Recurse -Force $tmp
    Remove-Item Env:\GUARDRAIL_DENYLIST -ErrorAction SilentlyContinue
}

if ($failures) { Write-Host "guardrail self-test: $failures failure(s)" -ForegroundColor Red; exit 1 }
Write-Host 'guardrail self-test: all rules fire, placeholders pass, pinned binaries hold' -ForegroundColor Green
exit 0
