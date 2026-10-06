# PROGRESS.md — session evidence log

## 2026-10-05 — session start (v0.3.0 Phase 1)

- Base verified: `8330f85` (v0.2.1), clean tree, branch `v030-phase1`
  created for Phase 1 work (no direct commits to `main`).
- Protocol files created: AGENTS.md (backlog F1–F9), PLAN.md, PROGRESS.md,
  DECISIONS.md.
- Pre-checks for F7: all test passwords already ≥ 12 chars
  (`correct horse battery staple`, `s3cret-master-pw`,
  `disaster-test-password`, `brand-new-master-pw-123`, `new-after-loss`;
  `definitely-wrong` is a deliberate auth-failure probe, no policy applies).
- Pre-checks for F9: only `stable` toolchain installed; MSRV probe pending.

## F1 DONE — manifest MAC (vault metadata integrity)

- TDD: 5 unit tests written first, failed on missing `manifest_mac`
  field (`cargo test` E0609), then implemented → all pass.
- Impl: `hmac 0.12` direct dep (mandated by the inline F1 spec
  "HMAC-SHA256"; already transitive via hkdf, same family — recorded, not
  counted as the session escalation); HKDF key with new label
  `SAGITARRIUS/v3/manifest`; length-prefixed canonical encoding
  (`manifest-v1` domain, vault_id, be64 generation, records sorted by id
  with (id, name, kind, created, updated, nonce)); verify-after-unlock
  (constant-time via `hmac::verify_slice`), recompute-on-write; legacy
  accept + upgrade; strip-rejection via `state.json:has_manifest_mac`.
- Fixture `tests/fixtures/v3-nomac.json` (v0.2.1-style, no MAC) emitted by
  a temporary in-crate test (since removed).
- CLI test `manifest_mac_legacy_upgrade_and_strip_rejection`: legacy opens,
  first write adds MAC, stripped MAC refused ("stripped"). PASS.
- Gates: `cargo fmt --check` clean, `clippy -D warnings` clean.
- Names stay plaintext: DECISIONS.md D01 + SECURITY.md.

## F2 DONE — write caps pre-write, higher read caps

- TDD: `read_caps_open_oversized_for_shrinking` +
  `migrate_rejects_oversized_entry_before_writing` failed first, then green.
- READ_* caps at 4x (file 40MiB, value 4MiB, name 1KiB, count 400k) for
  unlock/storage-read; strict MAX_* enforced on all write paths
  (add/edit/gen/import/file/migrate) + `write_vault_atomic` refuses
  oversize output before touching disk (nothing modified, clear message).
- CLI test `write_cap_enforced_before_writing` (stdin path — Windows argv
  caps at ~32KiB, os error 206): refused + old data intact. PASS.

## F3 DONE — shell quoting rules

- Single-quote when possible (no `'`, newline, CR), else double-quote with
  exactly `\ " $ ` newline (+CR); importer unescapes all six (legacy
  `\t`/`\'` kept compatible).
- Tests: `export_quotes_special_values` (4 styles), deterministic
  xorshift property test (300 adversarial values, 2 Argon2 runs — a naive
  per-value vault would burn 600 KDF ops), unix `sh`-sourcing test
  (newline values excluded: shells can't represent them; our importer can).
- docs/commands.md export row updated.

## F4/F5 DONE — dangerous names + NUL

- `is_dangerous_name` (D02): POSIX safe, `[A-Za-z0-9_][A-Za-z0-9_.-]*`
  portable, everything else dangerous. NUL always refused (no OS carries
  it in env).
- `run --secret <dangerous>` errors naming the secret (never the value)
  unless `--allow-dangerous-env`; `import` skips + warns unless
  `--allow-dangerous` (`import_env` now returns dangerous names too).
- `search` rejects NUL queries; add/gen/rename/import reject NUL via
  structural validation (NUL-containing `.env` keys skip).
- Tests: unit `import_dangerous_names_need_opt_in` (incl. NUL + portable
  dash names), CLI `dangerous_names_need_opt_in` (import warn names secret
  not value, run refusal, opt-in injection). PASS.
- docs/commands.md import/run rows updated.

## F6 DONE — exit codes 0/1/2

- New `Usage` error variant (exit 2); `main` maps it, everything else 1;
  child codes pass through. Reclassified: empty/NUL search, unknown
  `--kind`, file-kind via `add`, run no-command/no-secret/NUL/dangerous,
  missing `--plaintext`, bad `gen` length, invalid secret names
  (validate_secret_name; `EmptySecretName` variant removed as dead).
  Operational failures (auth, not-found, lockdown, stale) stay 1;
  `exists`/`search`-no-match/`audit` Ok(1) semantics unchanged.
- `--help` gained an exit-code legend (`after_help`); docs/commands.md
  exit-codes section rewritten. CLI test `exit_codes_usage_vs_operational`
  covers both sides. PASS.

## F7 DONE — min password length 12

- `input::check_new_password` (char-count, Usage error) enforced in
  `init`, `passwd`, `recovery reset-password` AFTER confirmation — covers
  terminal/pipe/stdin/env uniformly; no bypass switch exists. Unlock paths
  never gated (legacy short passwords keep opening).
- CLI test `short_master_passwords_rejected` (env path, exit 2, no vault
  created, old password survives failed rotation). PASS.

## F8 DONE — BOM, inline comments, trailing text

- `parse_env_value` rewritten: quote-aware closing scan (escape-aware for
  `"`), trailing text must be blank/comment else entry skipped (D04);
  unquoted `#` comments only after whitespace; BOM stripped per import.
- Unit test `import_bom_comments_and_trailing_text` (failed first, then
  green; also caught my own count mistake: 6 valid, not 5).
- docs/commands.md import row documents the exact rules.

## F10 DONE — missing-state warning + MAC error message

- `state::verify_generation`: state file missing + generation > 1 →
  stderr warning ("no trusted state... freshness cannot be confirmed") +
  adopt (still works). `status` already showed "UNKNOWN (no trusted
  state yet)".
- New `ManifestIntegrity` error variant: MAC failure says "vault metadata
  failed integrity check" + points at snapshot restore (was generic
  "invalid vault format").
- CLI test `missing_state_warns_mac_failure_explains` covers both. PASS.

## F9 DONE — real MSRV 1.85 + CI

- Probed locally: `cargo +1.75 check --locked` FAILS (locked
  `zeroize_derive 1.5.0` manifest needs `edition2024`, supported since
  Cargo 1.85) → 1.75 impossible without dep surgery. `cargo +1.85 check
  --locked --all-targets` + `cargo +1.85 build --locked` PASS.
- `rust-version` set to `1.85` (was a fictional 1.75).
- CI: new `msrv` job (toolchain 1.85, locked check); `audit` job kept.

## cargo audit — run for real (2026-10-05)

- `cargo install cargo-audit --locked` FAILED locally (C: disk full,
  os error 112 unpacking aws-lc-sys). Freed 2.2 GiB via `cargo clean`
  (target/ is regenerable), then used the official prebuilt
  `cargo-audit-x86_64-pc-windows-msvc-v0.22.2` release binary instead.
- Verbatim output (`cargo-audit 0.22.2`):
  `Fetching advisory database ... Loaded 1290 security advisories ...
  Updating crates.io index ... Scanning Cargo.lock for vulnerabilities
  (115 crate dependencies)` → exit code **0** = no reported
  vulnerabilities in the locked tree.

## Final gates (reopened Phase 1 complete)

- `cargo fmt --check`: clean.
- `cargo clippy --all-targets --all-features -- -D warnings`: clean on
  stable 1.99.0 (the reviewer's `manual_strip` at vault.rs:996 does not
  reproduce — likely line drift; gates are green either way).
- `cargo test -j 2`: **113/113 green from actual output** (58 unit + 36
  cli + 3 disaster + 15 security + 1 placeholder), incl. all pre-existing
  tests unregressed. (Full parallel link OOMs this box: C: was at 0 bytes
  free; freed 2.2 GiB via `cargo clean`, declined to touch 3.7 GiB of
  foreign VS-installer temp, ran serial instead.)
- Branch `v030-phase1` pushed (no direct commit to `main`).
- Unix-only tests (sh-source, 2 symlink, unix dangerous-env block)
  compile out on Windows; covered by Linux/macOS CI matrix.

## F11 DONE — unicode names, empty env, export --force, dir perms, menu text

- `validate_secret_name` rejects C1 (U+0080–009F), bidi (U+202A–202E,
  U+2066–2069), zero-width (U+200B–200D, U+2060, U+FEFF); ordinary Unicode
  letters still accepted; unlock never checks names (legacy opens).
  Unit test covers all classes + legacy-open.
- Empty `SAGITARRIUS_PASSWORD`/`SAGITARRIUS_NEW_PASSWORD` treated as unset
  (falls through to interactive); CLI test with piped passwords.
- `export <path>` refuses existing destinations without new `--force`.
  CLI test covers refuse + force paths.
- `ensure_dir_perms`: pre-existing non-empty dirs keep permissions;
  only created/empty dirs get 0700 (unix test with 0755 + marker file).
- Banner passwd line fixed (no longer claims env is required).
