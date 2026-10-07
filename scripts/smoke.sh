#!/usr/bin/env bash
# Sagitarrius release smoke test (POSIX sh/bash, no network, no real secrets).
# Usage:
#   scripts/smoke.sh <archive> <SHA256SUMS.txt>          # verify + extract + test
#   scripts/smoke.sh --binary <sagitarrius-bin>          # test an existing binary
# Uses a throwaway vault dir and a throwaway master password. Prints
# PASS/FAIL per step; exits non-zero on any failure.
set -euo pipefail

BIN=""
if [ "${1:-}" = "--binary" ]; then
    BIN="$2"
else
    ARCHIVE="${1:?usage: smoke.sh <archive> <SHA256SUMS.txt> OR smoke.sh --binary <bin>}"
    SUMS="${2:?usage: smoke.sh <archive> <SHA256SUMS.txt> OR smoke.sh --binary <bin>}"
fi

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

export SAGITARRIUS_VAULT_DIR="$WORK/vault"
export SAGITARRIUS_PASSWORD="smoke-test-password-01"
NAME="SMOKEKEY01"
VALUE="0123456789abcdef" # 16 chars; only its LENGTH is ever asserted/printed

if [ -z "$BIN" ]; then
    # 1. Checksum: the archive must be listed in SHA256SUMS.txt and match.
    base="$(basename "$ARCHIVE")"
    if ! grep -q " $base\$" "$SUMS"; then
        echo "FAIL: $base not listed in $SUMS"; exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$SUMS")" 2>/dev/null | grep -q "$base: OK") \
            && pass "archive checksum" || { fail "archive checksum"; exit 1; }
    else
        (cd "$(dirname "$ARCHIVE")" && shasum -a 256 -c "$(basename "$SUMS")" 2>/dev/null | grep -q "$base: OK") \
            && pass "archive checksum" || { fail "archive checksum"; exit 1; }
    fi
    # 2. Extract; --version works.
    mkdir -p "$WORK/pkg"
    case "$ARCHIVE" in
        *.tar.gz) tar -xzf "$ARCHIVE" -C "$WORK/pkg" ;;
        *.zip) unzip -q "$ARCHIVE" -d "$WORK/pkg" ;;
        *) echo "FAIL: unknown archive type"; exit 1 ;;
    esac
    BIN="$(find "$WORK/pkg" -name 'sagitarrius*' -type f | head -n 1)"
    [ -x "$BIN" ] || { fail "extracted binary not executable"; exit 1; }
    "$BIN" --version >/dev/null && pass "version runs" || { fail "version runs"; exit 1; }
else
    "$BIN" --version >/dev/null && pass "version runs" || { fail "version runs"; exit 1; }
fi

# 3. init; add; list shows the name, never the value.
"$BIN" init >/dev/null 2>&1 && pass "init" || { fail "init"; exit 1; }
"$BIN" add "$NAME" "$VALUE" >/dev/null 2>&1 && pass "add" || { fail "add"; exit 1; }
OUT="$("$BIN" list 2>/dev/null)"
case "$OUT" in
    *"$NAME"*) pass "list shows name" ;;
    *) fail "list shows name"; exit 1 ;;
esac
case "$OUT" in
    *"$VALUE"*) fail "list leaks value"; exit 1 ;;
    *) pass "list hides value" ;;
esac

# 4. run injects the secret; assert LENGTH only (value never printed).
LEN="$("$BIN" run --secret "$NAME" -- sh -c 'printf %s "${#SMOKEKEY01}"' 2>/dev/null)"
[ "$LEN" = "16" ] && pass "run injects (length 16)" || { fail "run injects (got '$LEN')"; exit 1; }

# 5. run without --secret: usage error, exit 2.
if "$BIN" run -- sh -c 'exit 0' >/dev/null 2>&1; then fail "run-no-secret must fail"; exit 1; else
    [ "$?" = "2" ] && pass "run-no-secret exit 2" || { fail "run-no-secret exit code"; exit 1; }
fi

# 6. exists present/absent; wrong password.
"$BIN" exists "$NAME" >/dev/null 2>&1 && pass "exists present" || { fail "exists present"; exit 1; }
if "$BIN" exists MISSING >/dev/null 2>&1; then fail "exists absent"; exit 1; else
    [ "$?" = "1" ] && pass "exists absent exit 1" || { fail "exists absent exit code"; exit 1; }
fi
if SAGITARRIUS_PASSWORD=definitely-wrong-pw "$BIN" get "$NAME" >/dev/null 2>&1; then
    fail "wrong password must fail"; exit 1;
else
    [ "$?" = "2" ] && pass "wrong password exit 2" || { fail "wrong password exit code"; exit 1; }
fi

# 7. export without --plaintext fails (exit 2 per docs).
if "$BIN" export >/dev/null 2>&1; then fail "export-no-flag must fail"; exit 1; else
    [ "$?" = "2" ] && pass "export-no-flag exit 2" || { fail "export-no-flag exit code"; exit 1; }
fi

# 8. backup create --to, backup verify --from.
"$BIN" backup create --to "$WORK/offline" >/dev/null 2>&1 && pass "backup create" || { fail "backup create"; exit 1; }
BID="$(ls "$WORK/offline")"
"$BIN" backup verify "$BID" --from "$WORK/offline" >/dev/null 2>&1 && pass "backup verify" || { fail "backup verify"; exit 1; }

# 9. Dangerous name: add allowed, run refused with exit 2.
#    (Before tampering: the tamper step below breaks the vault for writes.)
"$BIN" add LD_PRELOAD x >/dev/null 2>&1 && pass "add LD_PRELOAD allowed" || { fail "add LD_PRELOAD"; exit 1; }
if "$BIN" run --secret LD_PRELOAD -- true >/dev/null 2>&1; then
    fail "run LD_PRELOAD must be refused"; exit 1;
else
    [ "$?" = "2" ] && pass "run LD_PRELOAD refused exit 2" || { fail "run LD_PRELOAD exit code"; exit 1; }
fi

# 10. Tamper: rename one record inside vault.json; next command must fail
#     with exit 2 and an integrity message. LAST: the vault stays tampered
#     afterwards by design.
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "FAIL: need python3 or python for the tamper step"; exit 1
fi
"$PY" - "$WORK/vault/vault.json" <<'EOF'
import json, sys
p = sys.argv[1]
with open(p) as f:
    v = json.load(f)
v["records"][0]["name"] += "-tampered"
with open(p, "w") as f:
    json.dump(v, f)
EOF
if OUT2="$("$BIN" get "$NAME" 2>&1)"; then fail "tampered vault must fail"; exit 1; else
    [ "$?" = "2" ] && pass "tampered vault exit 2" || { fail "tampered exit code"; exit 1; }
fi
case "$OUT2" in
    *integrity*) pass "tampered message mentions integrity" ;;
    *) fail "tampered message mentions integrity"; exit 1 ;;
esac

echo "----"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = "0" ]
