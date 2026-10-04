# Vault & cryptography

## Vault location

| OS | Path |
|---|---|
| Linux | `$XDG_DATA_HOME/sagitarrius/vault.json` (fallback `~/.local/share/sagitarrius/vault.json`) |
| macOS | `~/Library/Application Support/sagitarrius/vault.json` |
| Windows | `%APPDATA%\sagitarrius\data\vault.json` |

Override with `SAGITARRIUS_VAULT_DIR=/some/dir` (handy for tests and
portable installs). The vault is a single JSON file: a plaintext header
(magic, version, KDF params, salt) plus base64 nonce and ciphertext. No
plaintext secret is ever written to disk.

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
  either the old or the new vault intact. No backups are kept.
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
