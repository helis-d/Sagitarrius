# Changelog

## 0.2.0 — vault v3: VMK envelope + resilience

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
