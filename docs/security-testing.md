# Security testing

## Automated today

- `cargo test`: crypto round-trips + tamper matrix (key/nonce/AAD/header),
  KDF bounds, payload caps, envelope wraps, chunked files (tamper/truncate/
  wrong-key), migration + verification, snapshot/restore + rollback
  tripwire, recovery create/verify/reset, scoped `run`, export gating,
  lockdown, hostile `.env` inputs.
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo fmt --check`
- CI (`.github/workflows/ci.yml`): fmt + clippy + full tests on
  Ubuntu/Windows/macOS, plus `cargo audit` for RustSec advisories.

## Attacker-controlled surfaces (review checklist)

`vault.json` bytes, snapshot/backup bytes, `.env` imports, recovery codes,
file-container bytes, CLI argv, environment, child environments. Each has
caps, authenticated parsing, and fail-closed errors — see
[threat-model.md](threat-model.md).

## Fuzzing (next step, not yet wired)

Highest-value targets, in order:

1. `Vault::unlock` / header probe (arbitrary JSON, truncated, huge fields)
2. v3 record decryption (wrong AAD/kind confusion)
3. `.env` parser (`import_env`)
4. file-container reader (`files::read_all`)
5. recovery-code parser

Suggested setup: `cargo fuzz` with libfuzzer + address sanitizer, seed
corpus from `tests/` fixtures, run on a schedule (not per-PR; Argon2 makes
unlock targets slow — gate KDF-heavy paths behind a test-only fast-params
hook before fuzzing `unlock` end-to-end). Property of interest for every
target: **no panic, no hang beyond caps, deterministic fail-closed error**.

Until the harness lands, `tests/security.rs` carries hostile-input cases
(malformed JSON, unknown versions, bad base64, absurd KDF numbers,
oversized fields) as ordinary regression tests.
