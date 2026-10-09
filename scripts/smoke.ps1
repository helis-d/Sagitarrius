# Sagitarrius release smoke test (PowerShell 5.1+ and 7, no real secrets).
# Usage:
#   scripts\smoke.ps1 <archive> <SHA256SUMS.txt>      # verify + extract + test
#   scripts\smoke.ps1 -Binary <sagitarrius-bin>       # test an existing binary
# Throwaway vault dir + throwaway master password. Prints PASS/FAIL per
# step; exits non-zero on any failure.
param(
    [string]$Binary = "",
    [Parameter(Position = 0)][string]$Archive = "",
    [Parameter(Position = 1)][string]$Sums = ""
)
$ErrorActionPreference = 'Stop'

$script:Pass = 0
$script:Fail = 0
function Pass-Step([string]$Name) { $script:Pass++; Write-Output "PASS: $Name" }
function Fail-Step([string]$Name) { $script:Fail++; Write-Output "FAIL: $Name" }

# Runs the binary with stderr to a temp file (never console): on
# PowerShell 5.1 a native command's stderr becomes a terminating error
# under 'Stop', so direct `2>&1` cannot be used for assertions.
# Returns @{ Code = <int>; Out = <stdout string>; Err = <stderr string> }.
function Invoke-Bin {
    param([string[]]$Arguments)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $errFile = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString() + '.err')
        $out = & $script:Bin @Arguments 2> $errFile
        $code = $LASTEXITCODE
        $err = ''
        if (Test-Path -LiteralPath $errFile) {
            $err = (Get-Content -LiteralPath $errFile -Raw)
            if ($null -eq $err) { $err = '' }
            Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
        }
    } finally {
        $ErrorActionPreference = $old
    }
    return @{ Code = $code; Out = "$out".Trim(); Err = "$err".Trim() }
}

$Work = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $Work | Out-Null
try {
    $env:SAGITARRIUS_VAULT_DIR = Join-Path $Work 'vault'
    $env:SAGITARRIUS_PASSWORD = 'smoke-test-password-01'
    $Name = 'SMOKEKEY01'
    $Value = '0123456789abcdef' # 16 chars; only its LENGTH is asserted/printed

    $script:Bin = $Binary
    if ([string]::IsNullOrEmpty($script:Bin)) {
        if ([string]::IsNullOrEmpty($Archive) -or [string]::IsNullOrEmpty($Sums)) {
            Write-Output 'FAIL: usage: smoke.ps1 <archive> <SHA256SUMS.txt> OR smoke.ps1 -Binary <bin>'; exit 1
        }
        # 1. Checksum: archive listed in SHA256SUMS.txt and matching.
        $base = Split-Path $Archive -Leaf
        $line = Select-String -LiteralPath $Sums -SimpleMatch $base | Select-Object -First 1
        if ($null -eq $line) { Fail-Step 'archive listed in sums'; exit 1 }
        $want = ($line.Line -split '\s+')[0]
        $got = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLower()
        if ($got -eq $want.ToLower()) { Pass-Step 'archive checksum' } else { Fail-Step 'archive checksum'; exit 1 }
        # 2. Extract; --version works.
        $pkg = Join-Path $Work 'pkg'
        if ($Archive -like '*.zip') {
            Expand-Archive -LiteralPath $Archive -DestinationPath $pkg -Force
        } else {
            Fail-Step 'unknown archive type (expected .zip on Windows)'; exit 1
        }
        $found = Get-ChildItem $pkg -Recurse -Filter 'sagitarrius.exe' | Select-Object -First 1
        if ($null -eq $found) { Fail-Step 'extracted binary found'; exit 1 }
        $script:Bin = $found.FullName
    }
    $r = Invoke-Bin @('--version')
    if ($r.Code -eq 0) { Pass-Step 'version runs' } else { Fail-Step 'version runs'; exit 1 }

    # 3. init; add; list shows the name, never the value.
    $r = Invoke-Bin @('init')
    if ($r.Code -eq 0) { Pass-Step 'init' } else { Fail-Step 'init'; exit 1 }
    $r = Invoke-Bin @('add', $Name, $Value)
    if ($r.Code -eq 0) { Pass-Step 'add' } else { Fail-Step 'add'; exit 1 }
    $r = Invoke-Bin @('list')
    if ($r.Out -match [regex]::Escape($Name)) { Pass-Step 'list shows name' } else { Fail-Step 'list shows name'; exit 1 }
    if ($r.Out -match [regex]::Escape($Value)) { Fail-Step 'list leaks value'; exit 1 } else { Pass-Step 'list hides value' }

    # 4. run injects the secret; assert LENGTH only (value never printed).
    # Inner PowerShell via single-quoted script (no outer expansion).
    $r = Invoke-Bin @('run', '--secret', $Name, '--', 'powershell', '-NoProfile', '-Command', 'Write-Output $env:SMOKEKEY01.Length')
    if (($r.Code -eq 0) -and ($r.Out -eq '16')) { Pass-Step 'run injects (length 16)' } else { Fail-Step "run injects (got '$($r.Out)')"; exit 1 }

    # 5. run without --secret: usage error, exit 2.
    $r = Invoke-Bin @('run', '--', 'cmd', '/c', 'exit', '0')
    if ($r.Code -eq 2) { Pass-Step 'run-no-secret exit 2' } else { Fail-Step 'run-no-secret exit code'; exit 1 }

    # 6. exists present/absent; wrong password.
    $r = Invoke-Bin @('exists', $Name)
    if ($r.Code -eq 0) { Pass-Step 'exists present' } else { Fail-Step 'exists present'; exit 1 }
    $r = Invoke-Bin @('exists', 'MISSING')
    if ($r.Code -eq 1) { Pass-Step 'exists absent exit 1' } else { Fail-Step 'exists absent exit code'; exit 1 }
    $env:SAGITARRIUS_PASSWORD = 'definitely-wrong-pw'
    $r = Invoke-Bin @('get', $Name)
    if ($r.Code -eq 2) { Pass-Step 'wrong password exit 2' } else { Fail-Step 'wrong password exit code'; exit 1 }
    $env:SAGITARRIUS_PASSWORD = 'smoke-test-password-01'

    # 7. export without --plaintext fails (exit 2 per docs).
    $r = Invoke-Bin @('export')
    if ($r.Code -eq 2) { Pass-Step 'export-no-flag exit 2' } else { Fail-Step 'export-no-flag exit code'; exit 1 }

    # 8. backup create --to, backup verify --from.
    $offline = Join-Path $Work 'offline'
    $r = Invoke-Bin @('backup', 'create', '--to', $offline)
    if ($r.Code -eq 0) { Pass-Step 'backup create' } else { Fail-Step 'backup create'; exit 1 }
    $bid = (Get-ChildItem $offline -Directory | Select-Object -First 1).Name
    $r = Invoke-Bin @('backup', 'verify', $bid, '--from', $offline)
    if ($r.Code -eq 0) { Pass-Step 'backup verify' } else { Fail-Step 'backup verify'; exit 1 }

    # 9. Dangerous name: add allowed, run refused with exit 2.
    #    (Before tampering: tampering breaks the vault for later writes.)
    $r = Invoke-Bin @('add', 'LD_PRELOAD', 'x')
    if ($r.Code -eq 0) { Pass-Step 'add LD_PRELOAD allowed' } else { Fail-Step 'add LD_PRELOAD'; exit 1 }
    $r = Invoke-Bin @('run', '--secret', 'LD_PRELOAD', '--', 'cmd', '/c', 'exit', '0')
    if ($r.Code -eq 2) { Pass-Step 'run LD_PRELOAD refused exit 2' } else { Fail-Step 'run LD_PRELOAD exit code'; exit 1 }

    # 10. Tamper: rename one record inside vault.json; next command fails
    #     with exit 2 and an integrity message. LAST: vault stays tampered.
    $vaultPath = Join-Path $env:SAGITARRIUS_VAULT_DIR 'vault.json'
    $j = Get-Content -LiteralPath $vaultPath -Raw | ConvertFrom-Json
    $j.records[0].name += '-tampered'
    $j | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $vaultPath -NoNewline
    $r = Invoke-Bin @('get', $Name)
    if ($r.Code -eq 2) { Pass-Step 'tampered vault exit 2' } else { Fail-Step 'tampered exit code'; exit 1 }
    if ($r.Err -match 'integrity') { Pass-Step 'tampered message mentions integrity' } else { Fail-Step 'tampered message mentions integrity'; exit 1 }
}
finally {
    Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
    Remove-Item Env:\SAGITARRIUS_VAULT_DIR -ErrorAction SilentlyContinue
    Remove-Item Env:\SAGITARRIUS_PASSWORD -ErrorAction SilentlyContinue
}

Write-Output '----'
Write-Output ("PASS=$script:Pass FAIL=$script:Fail")
if ($script:Fail -ne 0) { exit 1 }
