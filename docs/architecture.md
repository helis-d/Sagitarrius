# Architecture (v3)

## Key hierarchy

```text
              random VMK (32 bytes, never derived)
                         |
          +--------------+--------------+
          |                             |
     password wrap                 recovery wrap (optional)
     Argon2id -> KEK               Argon2id -> KEK
     AES-256-GCM                   AES-256-GCM
```

- The VMK is generated once per vault (`rand`, CSPRNG) and never derived
  from anything. Password change re-wraps the same VMK — O(1), records
  untouched.
- Each wrap's AAD binds magic, format version, vault id, wrap kind, KDF
  params and salt (all immutable for the wrap's life). The mutable
  generation counter is intentionally excluded: recovery wraps could not
  otherwise survive ordinary writes.
- Record keys: `HKDF-SHA256(VMK, salt=vault_id, info="SAGITARRIUS/v3/record/<record-id>")`.
  File keys: same scheme with `"SAGITARRIUS/v3/file/<file-id>"`.
  One key per purpose, always.

## Vault file (format v3)

```json
{
  "header": {
    "magic": "SAGITARRIUS", "version": 3,
    "vault_id": "<base64>",
    "generation": 12,
    "kdf": "argon2id",
    "wraps": [ { "kind": "password"|"recovery", "kdf_params": {...},
                 "salt": "<b64>", "nonce": "<b64>", "wrapped": "<b64>" } ]
  },
  "records": [
    { "id": "<b64>", "name": "...", "kind": "secret|password|credential|note|document|file",
      "created_at": 0, "updated_at": 0,
      "nonce": "<b64>", "ciphertext": "<b64(JSON payload)>" }
  ]
}
```

- Record plaintext metadata: name, kind, timestamps only. Values, usernames
  and file contents are always ciphertext.
- Record AAD binds `vault_id | record_id | kind | version`. The mutable
  generation is *not* in record AAD (else every write would invalidate every
  record); freshness comes from the trusted state file + snapshots.
- v2 files (`version <= 2`, whole-payload AES-GCM) still open read/write in
  place. `migrate` converts them explicitly (with pre-migration snapshot +
  re-unlock verification). New vaults are always v3.

## Files

`<vault_dir>/files/<hex-id>/`: `manifest.json` (version, nonce prefix,
chunk count, size, SHA-256, filename) + `chunk-00000000…` ciphertexts.
64 KiB chunks, nonce = 32-bit random prefix || 64-bit counter, per-chunk AAD
binds vault id, file id, index, total and version. Hash mismatch, missing
chunks or reordered chunks all fail closed.

## Local state

| Path | Content | Secrets? |
|---|---|---|
| `vault.json` | encrypted vault | ciphertext only |
| `state.json` | `{vault_id, generation}` anti-rollback reference | no |
| `snapshots/<id>/` | complete container: manifest + vault + file containers | ciphertext only |
| `backups/<id>/` | same layout, local or `--to` external | ciphertext only |
| `files/<id>/` | chunked containers (64 KiB, streaming) | ciphertext only |
| `lockdown` | flag file | no |

## What the code deliberately does NOT do

- No OS keystore wrapping yet (trait point reserved; password+recovery only).
- No whole-vault single-blob for files (chunked instead).
- `list`/`search` show names (plaintext metadata by design); values never do.
