# PLAN.md — v0.3.0 launch-ready

Base: v0.2.1 (`8330f85`). Work branch: `v030-phase1` (Phase 1), then
feature branches per phase. Never commit to `main` directly.

## Phase 1 — Trust: fix all findings (current)

Order: F1 → F9 (AGENTS.md). Per finding: failing regression test first,
minimal fix, evidence in PROGRESS.md.

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
