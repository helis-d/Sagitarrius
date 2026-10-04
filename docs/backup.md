# Snapshots & backups

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
sagitarrius backup verify [id]
sagitarrius backup restore <id>
sagitarrius backup prune --keep 5
```

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
