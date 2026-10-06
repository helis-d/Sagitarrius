# AGENTS.md — Sagitarrius maintainer protocol

## Roles

- Agent (this session) owns execution. Human owns the decisions in
  DECISIONS.md marked `needs-human`, plus the escalation list below.

## Session protocol

1. Read AGENTS.md, PLAN.md, PROGRESS.md, DECISIONS.md first. If PLAN.md is
   missing, create it from this backlog before writing code.
2. Prefer reading code over assuming. Read a module fully (and its tests)
   before editing it.
3. Keep context small; delegate large independent investigations.
4. End of session: update PLAN.md / PROGRESS.md / DECISIONS.md so a fresh
   session continues with zero verbal context.

## Definition of done

A claim is done only with: code + test + docs + evidence in PROGRESS.md
(command and output) + green gates. "Probably works" is not done.

## Gates (CI-equivalent, run locally)

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Backlog — Phase 1 (v0.3.0 trust hardening, in order)

- F1: manifest MAC over vault metadata (HKDF key, new info label,
  canonical length-prefixed encoding of vault_id + generation + every
  record's (id, name, kind, created_at, updated_at, nonce) sorted by id).
  Verify after unlock, fail closed. Recompute on every write. Legacy v3
  without MAC: accept, upgrade on next write, reject stripped MAC
  afterwards (via trusted state). Evaluate encrypting names; record the
  decision.
- F2: enforce write caps before writing (nothing modified on failure, clear
  message); read limits higher than write limits so oversized vaults still
  open and can shrink.
- F3: export quoting — single-quote when possible, else double-quote with
  escapes for `\ " $ ` newline. Import round-trips. Property test (no new
  deps) + sh-sourcing test (unix).
- F4: `run` refuses dangerous names unless `--allow-dangerous-env`;
  import warns and skips them unless `--allow-dangerous`.
- F5: reject NUL at every entry point; `run` errors name the secret, never
  the value.
- F6: exit codes 0/1/2 across all commands; documented in `--help` + docs.
- F7: minimum password length 12 on init/passwd/recovery-reset (applies to
  env/stdin too); no bypass env var.
- F8: import strips BOM, supports dotenv inline comments, handles text
  after a closing quote.
- F9: set real MSRV (verify by building with that toolchain), MSRV CI job,
  keep cargo-audit CI job.

## Backlog — Phase 2 (features, each designed in DECISIONS.md first)

Project mapping `.sagitarrius.toml`; `add --from-file`/stdin PEM values;
keyfile second factor (format change needs human approval); `rotate-report`;
`get --clip`; `doctor`; shell completions + man page.

## Backlog — Phase 3 (distribution)

cargo-dist (Linux/macOS/Windows), checksums, signed releases, crates.io
metadata, Homebrew/scoop/winget drafts; CI matrix + MSRV + audit;
cargo-fuzz targets with bounded runs recorded; SECURITY.md refresh;
CHANGELOG/CONTRIBUTING/templates/CODE_OF_CONDUCT; Windows runner check.

## Backlog — Phase 4 (launch drafts in docs/launch/, unpublished)

README first screen, demo.sh + asciinema recipe, Show HN pack, direnv/mise
guides, honest comparison table.

## Escalate (ask human first)

On-disk format change beyond F1; adding a dependency; changing a public
flag/command; license/name/branding; publishing anything; contacting third
parties; deleting any data path. At most one escalation per session.

## Forbidden

Real secrets/vaults in tests; network calls from the binary; force-push;
committing to main directly; skipping hooks/gates; weakening a test to
pass; marketing claims outside the SECURITY.md threat model.
