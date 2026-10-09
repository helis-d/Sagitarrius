# Vault & cryptography

> v3 (current) uses a VMK envelope + per-record keys. v2 files
> (whole-payload AES-GCM) still open; `migrate` upgrades them. Full design:
> [architecture.md](architecture.md).
>
> Version notes: 0.3.0 adds the manifest MAC (additive header field) and
> upgrades MAC-less v3 vaults on first write. Downgrade reads with 0.2.1
> work, but a 0.2.1 write drops the MAC — 0.3.0 then refuses the file as
> stripped until an explicit restore. Back up before upgrading.

## Vault location

| Platform | Default data location |
|---|---|
| Windows | OS application-data directory (`%APPDATA%`-based) |
| Linux | `$XDG_DATA_HOME` or `$HOME/.local/share` |
| macOS | `~/Library/Application Support` |

Sagitarrius derives the exact application-specific path through the
platform abstraction (`directories::ProjectDirs`), it is not hardcoded:
today that resolves to `%APPDATA%\sagitarrius\data\vault.json` on Windows,
`$XDG_DATA_HOME/sagitarrius/vault.json` (fallback
`~/.local/share/sagitarrius/vault.json`) on Linux, and
`~/Library/Application Support/sagitarrius/vault.json` on macOS.

Override with `SAGITARRIUS_VAULT_DIR=/some/dir` (handy for tests and
portable installs). Explicitly overridden directories are never
re-permissioned; the managed default directory is tightened to `0700`
(unix) when Sagitarrius creates it or finds it empty.

The vault itself is a single JSON file: a plaintext header plus encrypted
records. No plaintext secret is ever written to disk.

## Cryptography

```
Master password
      │
      ▼
   Argon2id  (m=64MiB, t=3, p=4, 16-byte random salt)
      │
      ▼
   256-bit key
      │
      ▼
 AES-256-GCM  (fresh 12-byte nonce per write; header as AAD)
      │
      ▼
   vault.json
```

- **Why Argon2id?** It is the current recommendation from OWASP and the
  Argon2 authors for password-based key derivation.
- **Why AES-256-GCM?** It is hardware-accelerated on virtually every modern
  CPU (AES-NI / ARMv8 crypto) and extremely well-audited. ChaCha20-Poly1305
  is only preferable where AES acceleration is unavailable.
- The header (magic, version, KDF params, salt) is authenticated as GCM
  additional data. Any modification to the header fails decryption.
- A fresh random nonce is generated for every write.
- The derived key is zeroized on drop; decrypted plaintext buffers are wiped
  after use.
- No cryptographic primitive is hand-rolled.

## Writes, locking, concurrency

- Updates are written to a fresh temp file in the same directory (`0600` on
  Unix), `fsync`ed, then `rename`d over the destination. A crash leaves
  either the old or the new vault intact. Crash safety is not backup:
  use `snapshot create` / `backup create --to <dir>` (see
  [backup.md](backup.md)).
- Mutating commands take an exclusive advisory lock next to the vault, so
  there is a single writer at a time. Reads are lock-free.
- On Unix the vault file is `0600` and the directory `0700`. On Windows we
  rely on the ACL of `%APPDATA%`.

## `SAGITARRIUS_PASSWORD`

For scripting and automated tests, `SAGITARRIUS_PASSWORD` supplies the
master password non-interactively, and `SAGITARRIUS_NEW_PASSWORD` supplies
the new password for `passwd`. **This is not safer than typing it** —
environment variables are visible to `ps`, `/proc`, and child processes.
Do not use them with a real master password.

## Full threat model

See [SECURITY.md](../SECURITY.md). The short version: Sagitarrius protects
a stolen vault file at rest. It cannot protect a compromised machine, a weak
master password, or secrets you paste into shell history — and there is no
password recovery by design.
