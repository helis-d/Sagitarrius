# DECISIONS.md — Sagitarrius design record

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
- `run --secret <dangerous>` errors unless `--allow-dangerous-env`.
- `import` skips + warns on dangerous names unless `--allow-dangerous`
  (portable-but-non-POSIX names import with a warning either way).

## D03 — F6: exit-code split (decided)

- `0` success (incl. `exists` absent? No: `exists` keeps 0/1 presence
  semantics — 1 there means "absent", not failure).
- `1` operational failure: auth, not-found, validation, lockdown, stale.
- `2` usage error: bad flags/values, empty query, unknown `--kind`,
  missing `--secret`/`--plaintext`, invalid names at entry.
- Child exit propagation in `run` unchanged. `search` no-match stays 1.
- Pre-approved by the Phase 1 order (public-behavior change).

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
