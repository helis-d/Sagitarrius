# Changelog

## 0.2.1 — hardening patch (no format break)

- Fixed: `migrate` wiped the password before re-opening the migrated
  vault, failing every real v2→v3 migration. Password lifetime corrected
  (verify with the original, zeroize after) + real CLI migration test from
  a committed v2 fixture.
- Fixed: streaming `file put` truncated inputs at 64 KiB
  (`Vec::zeroize()` clears length — reused I/O buffers are arrays now).
- Snapshots/backups are complete containers: manifest + vault + every
  referenced file container, with cross-reference verification. Missing or
  corrupt containers fail closed; restores re-verify live state.
- `backup verify/restore --from DIR` for external/offline copies.
- True streaming file encryption (bounded memory), staged container
  install, symlink refusal, extra-file rejection, strict id checks.
- Lockdown scope pinned: decrypting/mutating commands refused (incl.
  snapshot delete, backup prune); `status/list/search/exists` stay.
- `audit` reports missing file containers; KDF/recovery/backup notices.
- Hostile-input, lockdown, disaster-recovery and ransomware-simulation
  integration tests.
- OS keystore wrapping explicitly deferred (documented, no fake claims).

- New vault format v3: random VMK, Argon2id password/recovery wraps,
  per-record AES-GCM keys via HKDF, typed records
  (secret/password/credential/note/document/file). New vaults are v3;
  `migrate` upgrades v2 explicitly (snapshots first, verifies after).
- Password change re-wraps the VMK instead of re-encrypting the vault.
- `run` requires `--secret NAME` (repeatable): the whole vault is never
  exposed to a child by default.
- `export` requires `--plaintext`; warns and lists skipped names.
- Snapshots, backups (`--to`, `prune`), recovery kit
  (`create`/`verify`/`reset-password`), chunked encrypted files
  (`file put/get`), `status`, `lockdown`.
- Rollback detection: generation counter + trusted `state.json`.
- `--password-stdin` flag; `SAGITARRIUS_PASSWORD` documented test-only.
- Terminal-safe name rendering; audit duplicate groups (O(n)).
- CI: Ubuntu/Windows/macOS matrix + `cargo audit`.

## 0.1.0 — initial local-first secret manager

- Argon2id + AES-256-GCM single-file vault, atomic writes, advisory lock.
- 16 CLI commands, import/export, audit, security test suite.
