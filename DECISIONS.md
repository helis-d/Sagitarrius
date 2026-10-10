# DECISIONS.md — Sagitarrius design record

## PS-01 — Privacy Station broker architecture (needs-human)

Single batched escalation for the Privacy Station MVP (details in
`docs/privacy-station/architecture.md`, research in
`docs/privacy-station/competitive-analysis.md`):
1. Option A (separate `sagitarrius-broker` binary, main CLI stays
   network-free)? Recommended: yes.
2. New deps `ureq` + `url` for the broker binary only? Recommended: yes.
3. New surfaces (broker CLI, policy TOML, request/response JSON, audit
   JSONL)? Recommended: yes as specified.
4. No vault-format change, no main-CLI changes — confirmation only.
Rejected: Option B (two new auth boundaries for an MVP), Option C
(breaks the no-network invariant for convenience), hyper/reqwest (heavier
async stacks), standing broker tokens in v1 (per-call password instead).

Conventions: each entry has status (`decided` | `needs-human`), the
decision, and why. Security-sensitive choices reference the mechanism.

## D01 — F1: names stay plaintext (decided)

Record names remain plaintext metadata. Encrypting them would force a full
vault decrypt for `list`/`search` (the read-mostly operations), enlarging
plaintext exposure — the opposite of the record-level design goal.
Tampering/swap/removal of names is covered by the manifest MAC (present =
verified, fail closed). Documented in SECURITY.md.

## D02 — F4: dangerous-name rule (decided)

- SAFE (always): POSIX identifiers `[A-Za-z_][A-Za-z0-9_]*`.
- PORTABLE (warned, allowed): `[A-Za-z0-9_][A-Za-z0-9_.-]*`
  (e.g. `github-token`; common dotenv style).
- DANGEROUS (refused): anything else — whitespace, shell metacharacters
  (`$ ` " ' \ | & ; < > ( ) * ? ! ~ #`), `=`, leading `-`, control chars.
- `run --secret <dangerous>` errors unless `--allow-dangerous-env`;
  `import` skips + warns unless `--allow-dangerous`.
  (Portable-but-non-POSIX names import silently; `audit` flags them.)

## D02b — loader/shell-startup denylist (decided, extends D02)

Most denylisted names (`PATH`, `IFS`, `LD_PRELOAD`, ...) are valid POSIX
identifiers, so the metacharacter rule misses them. Explicit exact-match
denylist + `DYLD_` prefix, enforced exactly like dangerous names in `run`
and `import`. Rationale: injecting `LD_PRELOAD` executes attacker code in
the child; `BASH_ENV`/`ENV`/`IFS`/`PATH` hijack every spawned shell.

## D03 — F6: exit-code split (SUPERSEDED by D03b below)

Original split (0 ok / 1 operational / 2 usage) replaced: scripts cannot
separate "negative" from "error" when both share code 1.

## D03b — exit codes: negatives vs failures (decided, supersedes D03)

- `0` success.
- `1` ONLY for clean negatives: `exists` absent, `search` no matches,
  `audit` findings. These return `Ok(1)`, never `Err`.
- `2` for every `Err`: auth, not-found, corruption, lockdown, stale, I/O,
  usage. `main` maps all errors to 2; `run` child codes pass through.
- Pre-approved by the reopened Phase 1 order (public-behavior change).

## D04 — F8: trailing text after closing quote (decided)

`KEY="val" <ws>` → value `val`. `KEY="val" # comment` → value `val`.
Any other trailing text → entry skipped + counted (ambiguous input must
not become a secret silently).

## D05 — F1 strip-rejection via trusted state (decided)

`state.json` gains `has_manifest_mac` per vault id. Unlock of a MAC-less
v3 file when state says MAC'd → refuse (stripped MAC). Legacy files adopted
with `false`, flipped on first write. Attacker replacing vault+state
together remains the documented offline-backup case.

## Pre-approved by the Phase 1 mandate (no escalation needed)

F4/F6 flag and exit-code behavior changes and the F1 format addition are
ordered inline by the human — treated as approved, recorded here.

## D06 — F1: `hmac` crate promotion (decided, not counted as escalation)

F1's inline spec mandates HMAC-SHA256. `hmac 0.12` was already in
Cargo.lock (transitive via `hkdf`); promoting it to a direct dependency is
the only sane implementation — no hand-rolled MAC. Recorded here instead
of spending the session's single escalation.

## D07 — build provenance attestation (PROPOSAL ONLY, needs human approval)

Not implemented. Proposed diff for `.github/workflows/release.yml` when
approved: add `actions/attest-build-provenance` step after packaging in
the `build` job (subject = the archive), with job-level
`permissions: { id-token: write, attestations: write, contents: read }`.
Rejected alternative: doing it silently now — it changes the release
trust story (keyless Sigstore identity tied to this repo) and needs a
human to understand what attestation does and does not prove. No code
changed for this item.
