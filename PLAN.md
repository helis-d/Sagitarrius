# PLAN.md — v0.3.0 launch-ready

Base: v0.2.1 (`8330f85`). Work branch: `v030-phase1` (Phase 1), then
feature branches per phase. Never commit to `main` directly.

## Phase 1 — Trust: fix all findings (current)

Order: F1 → F9 (AGENTS.md). Per finding: failing regression test first,
minimal fix, evidence in PROGRESS.md.

## Phase 1 reopen — evidence-based review gaps (done, same branch)

- [x] F4b loader/shell-startup denylist (+ D02b, portable /usr/bin/env test)
- [x] F5b NUL in values (add/edit/import/run/file-paths)
- [x] F6b exit 1 = clean negatives only, every error = 2 (D03 superseded)
- [x] F10 missing-state warning + ManifestIntegrity message
- [x] F11 unicode names, empty-env-as-unset, export --force, dir chmod rule,
  passwd menu text
- [x] cargo audit run for real (clean: 1290 advisories, 115 crates, exit 0)
- [x] clippy green on stable 1.99.0; full suite 113/113 from real output

- [x] F1 manifest MAC (HKDF `SAGITARRIUS/v3/manifest`, length-prefixed
  encoding, verify-after-unlock, recompute-on-write, legacy upgrade path,
  strip-rejection via trusted state, names-encryption decision)
- [x] F2 write caps pre-write + higher read caps (open-and-shrink)
- [x] F3 shell quoting rules + round-trip + property test + sh-source test
- [x] F4 dangerous names (`--allow-dangerous-env` / `--allow-dangerous`)
- [x] F5 NUL rejection everywhere; run errors name secrets only
- [x] F6 exit codes 0/1/2 + `--help` and docs
- [x] F7 min length 12 on init/passwd/recovery-reset (env/stdin included)
- [x] F8 BOM strip, inline comments, trailing text after quote
- [x] F9 real MSRV (verified build) + MSRV CI job + audit job kept

Exit: gates green, every finding tested, 93 existing tests unregressed,
v0.2.1-fixture migration test.

## Privacy Station — PS-01 credential broker (current)

Branch: `privacy-station/proposal`. Separate `sagitarrius-broker` binary;
main CLI stays network-free (verified: `cargo tree -e normal --bin sagitarrius`
shows no ureq/url/hyper/reqwest).

### Stage list

- [x] Phase A: repo state, ureq 3.4.2 API verification, main-binary network-free proof
- [x] Phase B: `src/broker/policy.rs` — pure default-deny matcher, JSON schema, 5 unit tests
- [x] Phase C: `src/broker/request.rs` — strict schema, deny-unknown-fields, timestamp ±500s, 2 unit tests
- [x] Phase D: `src/lib.rs` + `src/main.rs` split; `src/broker/mod.rs`; feature `broker-http`
- [x] Phase E: `src/broker/http.rs` — `locked_agent()`, `validate_target()`, `redact_ureq_error()`, 6 unit tests
- [x] Phase F: `src/broker/respond.rs` — allowlist filter + envelopes, 3 unit tests;
  `src/broker/audit.rs` — redacted JSONL writer, fail-closed, 1 unit test
- [x] Phase G: `src/broker/main.rs` — CLI wiring, password-on-stdin, vault unlock,
  credential resolution, bounded read, audit-before-output
- [x] Phase H: `tests/broker.rs` — 23 integration tests covering 17 security scenarios
- [x] Phase I: remaining docs (`product-vision`, `threat-model`, `mvp-spec`, `testing-strategy`, `roadmap`)
- [x] Phase J: commit all broker code
- [x] Remediation: pinned DNS/SSRF enforcement, constrained response schema, genuine broker-process tests, tightened policy/request/audit semantics, JSON deviation record, policy-trust-boundary decision, broker CI coverage, MSRV-compatible dependency pins (policy-trust approval still needs-human)

### Acceptance criteria

- [x] `cargo fmt --check` passes
- [x] `cargo clippy --locked --all-targets --all-features -- -D warnings` passes
- [x] `cargo test --locked` passes (70 + 41 + 15 + 23 + 3 + 1 = 153 tests)
- [x] Main binary has no HTTP deps in tree
- [x] All docs written
- [x] Committed
- [ ] Remediation acceptance report in `PROGRESS.md` (including unresolved policy-trust boundary)

## Phase 2 — Core value features

Each designed in DECISIONS.md with 5 lines of example usage before coding:
`.sagitarrius.toml` mapping, `add --from-file`/stdin, keyfile 2nd factor
(format change = human approval), `rotate-report`, `get --clip`, `doctor`,
completions + man page.

## Phase 3 — Distribution and trust assets

cargo-dist, checksums, signed releases, crates.io metadata,
Homebrew/scoop/winget drafts, CI matrix+MSRV+audit, cargo-fuzz bounded
runs, SECURITY.md refresh, CHANGELOG/CONTRIBUTING/templates/CODE_OF_CONDUCT.

## Phase 4 — Launch drafts (`docs/launch/`, unpublished)

README first screen, demo.sh + asciinema recipe, Show HN pack,
direnv/mise guides, honest comparison table.
