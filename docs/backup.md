# Snapshots & backups

## Container format (v1)

Snapshots and backups share one complete container — vault *plus* every
referenced file container, so a File record can never outlive its bytes:

```text
<base>/<id>/
  manifest.json            inventory + hashes (never plaintext secrets)
  vault.json               encrypted vault bytes
  files/<file-id>/         one encrypted container per File record
    manifest.json
    chunk-00000000 ...
```

`manifest.json` holds `{format, archive_format: 1, kind, id, vault_id,
generation, vault_format, created_at, vault_sha256, files[], verified}`.
Unknown `archive_format` values are rejected, never reinterpreted.
Pre-container snapshots (`<id>.json` + `<id>.meta.json`, vault bytes only)
are still listed/verified/restored and labeled *legacy*.

## Concepts

- **Snapshot**: fast local history (`snapshots/`). Cheap, automatic safety
  net before restores/migrations. Same-disk = history, not protection.
- **Backup**: same encrypted format, aimed at **separate/offline media**
  (`backups/` locally, or any directory via `--to`). Only an offline copy
  survives ransomware that can write to your disk.

Both are byte copies (always encrypted) + a manifest
`{id, vault_id, generation, format_version, created_at, sha256, verified}`.

## Commands

```bash
sagitarrius snapshot create
sagitarrius snapshot list
sagitarrius snapshot verify [id]     # full unlock proof (needs password)
sagitarrius snapshot restore <id>    # snapshots current first, then replaces
sagitarrius snapshot delete <id>

sagitarrius backup create [--to <dir>]
sagitarrius backup list              # local backups only (external may be offline)
sagitarrius backup verify [id] [--from <dir>]
sagitarrius backup restore <id> [--from <dir>]
sagitarrius backup prune --keep 5
```

Verification is whole-object: manifest → vault hash → full unlock →
record/file cross-check → every chunk authenticated + hashed. Anything
missing or mismatched fails the backup; restores additionally re-verify the
live state afterward and keep a `pre-restore-*` copy. A restore whose
pre-state is already destroyed still proceeds (nothing to preserve) after
successful verification.

Every restore: verifies the copy (hash + full unlock) *before* touching the
live vault, snapshots the present as `pre-restore-*`, replaces atomically,
re-verifies live, adopts the restored generation as trusted.

## Rollback detection

v3 headers carry a `generation` counter (bumped per write). `state.json`
remembers the newest seen `(vault_id, generation)`:

- header older than trusted → **refuse** ("possible rollback").
- header newer → adopt (a state write was lost).
- different vault id → adopt (fresh vault / swap, not a rollback).
- v2 files have no counter: rollback protection reports UNAVAILABLE.

Replacing vault **and** state together is locally undetectable — offline
backups are the answer, and `status` shows when the last verified copy was
taken.

## Retention

Backups: `prune --keep N` (newest N survive). Snapshots: manual `delete`.
No silent auto-deletion anywhere — destructive automation is exactly what a
resilience layer must not do.
