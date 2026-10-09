# PROGRESS.md — session evidence log

## T3 - PARTIAL - 2026-10-09
- CI on branch push: run 37655810115 (`check` ubuntu/windows/macos +
  `msrv` + `audit`, all success) covered the pre-T1 tree; a fresh CI run
  was triggered by pushing this session's commits — conclusion pending at
  write time (see T8 note).
- Release `workflow_dispatch`: NOT VERIFIED — `gh` is not authenticated on
  this box and dispatch needs auth. The workflow file itself was linted
  (actionlint clean) and its Windows packaging path was executed by hand
  (zip + SHA256 + smoke run, see T4 evidence in the prior session log).
- Publish job: by construction it runs only on `refs/tags/v`; no tag was
  created or pushed this session (verified: `git tag` empty locally, no
  tag push commands issued). `gh release list` could not be queried
  without auth — human to confirm zero new releases.
- Discrepancies: none. Open questions: release-dispatch run (handoff below).

## T6 - DONE - 2026-10-07
- Change (`24d378a`): version 0.3.0; Cargo.lock minimal (only `version=4`
  header + sagitarrius line — the v3→v4 header rewrite is cargo's own doing
  on this toolchain, parseable since 1.78, MSRV unaffected); CHANGELOG 0.3.0
  section grouped by behavior incl. all mandated breaking items;
  downgrade documented in CHANGELOG + vault-and-crypto.md; stale strings
  swept (only true hits left).
- U-4 compatibility matrix from real runs (0.2.1 release binary built from
  worktree @8330f85): 0.2.1 vault → 0.3.0 opens + first write adds MAC;
  0.3.0 MAC vault → 0.2.1 reads fine (serde ignores the field); 0.2.1
  write silently drops the MAC (0.3.0 then refuses as stripped until
  explicit restore). Back-up-before-upgrade documented.
- Evidence: `cargo build --locked` ok; `cargo test --locked -j 2` 119/119.
- Discrepancies: none. Open questions: none.

## T7 - DONE - 2026-10-07
- Change (`24d378a`): keywords (5), categories, homepage, documentation in
  Cargo.toml; rust-version stays 1.85.
- Evidence: `cargo package --locked --list --allow-dirty` (75 files, no
  target/, no secrets; largest asset 150 KiB banner); `cargo publish
  --dry-run --locked --allow-dirty` → "Packaged 75 files, 586.9KiB
  (228.6KiB compressed)", verify-compile ok, "aborting upload due to dry
  run". No exclude list needed.
- Name report (crates.io API, read-only): `sagitarrius` does NOT exist
  (available; nothing reserved); near-collision `sagittarius 0.3.1` exists
  (different spelling) — user-confusion risk noted, no action possible.
- Discrepancies: none. Open questions: none.

## T5 - DONE - 2026-10-07
- Content was merged to main earlier; this task verified + adjusted it:
- Content was merged to main earlier; this task verified + adjusted it:
  reporting = GitHub Private Vulnerability Reporting + literal
  `SECURITY_CONTACT_TODO` (SECURITY.md:6-16); replay claim now states the
  precondition inline (SECURITY.md:23-25, threat-model.md:14-16) with the
  both-files-replaced case in out-of-scope (SECURITY.md:44-45,
  threat-model.md:34-35); zeroization/hardening/review/recommendations
  sections present (SECURITY.md:157-196); release-security.md notes
  artifacts exist per-run but nothing published.
- Traceability (U-5 resolved): `cargo tree -e features -i argon2` shows
  alloc/default/password-hash/rand — NO `zeroize` feature, and even with
  it only small intermediaries (argon2-0.5.3 lib.rs:322-323,501-504)
  are wiped, never the 64 MiB block memory. Zeroized: DerivedKey +
  ZeroizeOnDrop (crypto.rs:44-45), VaultMasterKey (envelope.rs:33-34),
  password Strings on all paths, plaintext buffers post-crypto,
  run name/value copies, recovery codes. mlock/VirtualLock/core-dump:
  zero hits repo-wide. No superlatives in either file.
- Human action: enable Settings -> Security -> Private vulnerability
  reporting. No response-time statement added (no approval).
- Discrepancies: F-9's "missing qualification" was already fixed on main;
  only the inline precondition needed tightening.
- Open questions: none.

## T2 - DONE - 2026-10-07
- Changes (`8e90580`, `dba364c`): ci.yml gets top-level
  `permissions: contents: read`, `concurrency` cancel-in-progress,
  `--locked` on clippy/test; release.yml gets `macos-13` →
  `macos-15-intel`, `draft: true` + `fail_on_unmatched_files: true`,
  checksums via `cd dist && sha256sum -- *.tar.gz *.zip` (self-excluding),
  top-level read permissions; new `.github/dependabot.yml` (actions+cargo
  weekly, grouped minor/patch, no auto-merge).
- Action SHAs resolved live, not invented: checkout v4
  `11d5960a…`, upload-artifact v4 `ea165f8d…`, download-artifact v4
  `d3f86a10…` (all `refs/tags/v4`, no `^{}` = lightweight tags, SHA IS the
  commit); dtolnay has no version tags → pinned master HEAD `7e38f4b4…`
  with `toolchain: stable`/`1.85` inputs preserving selection semantics;
  softprops v2 `3bb12739…` (lightweight). Version comments on every use.
- Runner labels: macos-13 retired (deprecation from Sep 2025 per
  actions/runner-images#13045); Intel successor is `macos-15-intel`
  (macOS 15, until Aug 2027); macos-14 itself retires 2026-11-02 with
  October brownouts (changelog 2026-10-01) but we never used it.
  aarch64-linux stays omitted (documented, needs cross toolchain).
- Evidence: `actionlint 1.7.12` on both files → exit 0, no findings.
- Discrepancies: none vs F-5 (all confirmed pre-change).
- Open questions: attestation proposal left for DECISIONS (escalation item).

## T1 - DONE - 2026-10-07
- Change: `src/banner.rs` `logo_is_pure_ascii` — vacuous `!LOGO_ART.is_empty()`
  replaced with content guards (`#`/`=`/`@` raster language) via a local
  binding (no `#[allow]`).
- Evidence: `cargo fmt --check` exit 0; `cargo clippy --locked
  --all-targets --all-features -- -D warnings` exit 0 (rustc 1.99.0);
  banner tests 2/2 pass.
- Discrepancies: F-3's clippy failure does not reproduce on this toolchain
  (fixed anyway — the new assertions are strictly stronger).
- Open questions: none.

## T0 baseline — release/v0.3.0-blockers from main@7b6a5b7 (2026-10-07)

- Env: rustc/cargo 1.99.0 stable (active, `rustup update stable` = unchanged),
  Windows x64, gh 2.97.0 present but NOT authenticated, actionlint absent.
  Branch `release/v0.3.0-blockers` created from `origin/main`; tree was
  line-ending noise only (reverted, nothing lost).
- Gates: `fmt --check` PASS; `clippy --locked --all-targets --all-features
  -- -D warnings` PASS (F-3 does NOT reproduce on 1.99.0 — see discrepancy);
  `cargo test --locked -j 2` **119/119** (59+41+3+15+1);
  `cargo-audit 0.22.2` exit 0 (1294 advisories, 115 crates).
- Discrepancies vs prompt: F-3 clippy failure absent here (lint behavior
  differs on 1.99.0; fixing anyway per T1). F-1 count 124 vs local 119 =
  platform-gated tests only (`#[cfg(unix)]` at cli.rs:222,624 +
  security.rs:282,302 + vault.rs:1592 → +5 on Linux; 119+5=124 ✓).
  F-5/F-6/F-7 confirmed as-is (no dependabot.yml, no scripts/, draft flag
  missing, checksum globs `./*`, mutable action tags, no top-level
  permissions). macos-13 label present (U-1/U-2 open).

## Context summary (≤10 lines, read-first pass)

- v0.2.1+Phase1 tree: v3 VMK envelope + manifest MAC, snapshots/backups as
  complete containers, recovery wraps, scoped run, lockdown, typed records.
- Surprise 1: F-3's clippy failure does not reproduce on stable 1.99.0.
- Surprise 2: test-count gap (124 vs 119) is exactly the unix-gated tests.
- Surprise 3: release.yml lacks `draft:true` although PROGRESS claimed it.
- Surprise 4: checksum job globs `./*` (includes SHA256SUMS.txt itself).
- CI check matrix already covers ubuntu+windows+macos (U-6 evidence source).

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

## F6 DONE — exit codes 0/1/2 (REVISED: see "exit-code revision" below)

- New `Usage` error variant; `main` maps errors to exit codes; child codes
  pass through. `--help` gained an exit-code legend (`after_help`);
  docs/commands.md exit-codes section rewritten. CLI test
  `exit_codes_usage_vs_operational` covers both sides. PASS.

## Exit-code revision (supersedes the F6 entry above; see DECISIONS.md D03b)

- `1` ONLY for clean negatives (`exists` absent, `search` no match,
  `audit` findings — all `Ok(1)`, never `Err`).
- `2` for EVERY `Err` (auth, not-found, corruption, lockdown, stale, I/O,
  usage). `--help` legend + docs rewritten; `get_missing` test updated
  1 → 2; CLI test extended (wrong password, no vault, lockdown → 2).

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

## Cross-platform + P1 review gaps (this session, branch v030-phase1)

- §8 fixed: `run --allow-dangerous-env` now actually injects OS-legal
  non-POSIX names (was silently skipped after the opt-in check); invalid
  OS names (NUL/`=`) still refused. Denylist split into ELF/Mach-O/shell
  groups with platform docs. Tests run `/usr/bin/env` (unix) and
  `cmd /c set` (windows) — the old `sh -c env` dropped space-names.
- §21 fixed: strip check moved before forward-heal; `has_manifest_mac`
  monotonic. Regression test (strip + forged-high generation refused,
  state not downgraded).
- §22 fixed: `recovery verify`/`reset-password` enforce trusted-state
  generation + strip checks after unwrap; verify-fail stays Ok(1),
  integrity refusal is Err (exit 2). Regression test (stale + stripped).
- §23: `VaultV2::serialize` enforces write caps pre-encrypt; §24: V2
  import arm uses the denylist (was metachars-only) + fixture-driven test.
- §6: default vs custom dir policy (`platform::is_custom_dir`), docs.
- Release: `release.yml` matrix (linux/win/macos x64 + mac arm64),
  tar.gz/zip packaging, SHA256SUMS job, draft publish on tags. Locally
  verified on Windows: release build + zip + sha256 + smoke run
  (init works; 1.8MB exe / 707KB zip).
- Docs: README/installation 1.85+, per-OS install blocks, vault-location
  table (§19), PowerShell quoting note, stale-claim sweep (F6 section,
  "no backups", run/export wording, banner text untouched).
- CI: `--locked` added to clippy/test; audit + msrv kept.
- Gates from real output: fmt clean, clippy `-D warnings` clean,
  `cargo test --locked -j 2` → **119/119** (59 unit + 41 cli + 3 disaster
  + 15 security + 1 placeholder).

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

## T4 - DONE (scripts+Windows run) / NEEDS HUMAN RUN (Linux/macOS)
- `scripts/smoke.sh` (bash `set -euo pipefail`) + `scripts/smoke.ps1`
  (5.1-safe via an Invoke-Bin stderr-file helper — plain `2>&1` aborts
  under `$ErrorActionPreference='Stop'`). Steps: checksum, version, init,
  add, list-hides-value, run-length-only, run-no-secret→2, exists 0/1,
  wrong-password→2, export-no-flag→2, backup create/verify, LD_PRELOAD
  add-allowed/run-refused→2, tamper→exit-2+integrity. Trap/finally cleanup,
  lengths only, never values.
- Evidence: `smoke.ps1` vs local release zip → **18/18 PASS, exit 0**.
  `smoke.sh` NOT RUN here (no Linux/macOS box) — handoff below.
  One-liner added to docs/development.md. `.gitattributes` forces LF for
  `*.sh` (CRLF shebangs break Unix exec).
- Discrepancies: none. Open questions: none.

## T8 - PARTIAL - 2026-10-09
- Fresh clone of the branch: fmt exit 0, clippy `-D warnings` exit 0,
  `cargo test --locked` **119/119** (59+41+3+15+1), `cargo audit` exit 0
  (1296 advisories, 115 crates), `cargo +1.85 check --locked --all-targets`
  exit 0. Test counts copied from real output above.
- Draft PR: NOT CREATED — `gh` unauthenticated (handoff below). Do not merge.
- Discrepancies: none. Open questions: PR creation + release dispatch.
