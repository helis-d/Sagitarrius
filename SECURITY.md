# Security

Sagitarrius is a small local tool. This document describes exactly what it
protects against and what it does not.

## Reporting a vulnerability

Please open a private security advisory on the project's GitHub repository,
or email the maintainers directly. Do not open a public issue for
vulnerabilities that could affect users.

## Threat model

Sagitarrius protects an encrypted vault file **at rest** against an attacker
who obtains a copy of that file but does not control the machine where it
was created or read.

### In scope

- Loss or theft of a disk, backup, or synced copy of `vault.json`.
- Silent tampering with the vault file.
- Accidental disclosure of values through command output.
- Partial or torn writes if the process is interrupted mid-update.

### Out of scope

- A compromised machine. A keylogger, rootkit, debugger, or hostile root
  user can recover both the master password and the plaintext.
- Brute-force resistance against weak master passwords. Argon2id raises the
  cost of each guess; it does not eliminate the risk.
- Exposure through shell history, `ps`, `/proc`, or `argv` when a secret is
  passed as a command-line argument.
- Any process that can read the environment of a child spawned by
  `sagitarrius run`. The child (and anything that can inspect it) has full
  access to every injected secret.
- Physical coercion, rubber-hose cryptanalysis, or legal compulsion.
- Password recovery. There is no recovery path by design.

## Cryptographic design

- **KDF:** Argon2id
  - m_cost = 65536 KiB (64 MiB)
  - t_cost = 3
  - p_cost = 4
  - 16-byte salt, generated with `rand::thread_rng()` (CSPRNG).
- **AEAD:** AES-256-GCM
  - 12-byte nonce, freshly generated for every encryption operation.
  - 16-byte authentication tag (appended by `aes-gcm`).
  - The vault header (magic, version, KDF identifier, KDF parameters, salt)
    is passed as additional authenticated data. Any tampering with the
    header invalidates the tag.
- **No primitive is hand-rolled.** All primitives are provided by the
  `argon2` and `aes-gcm` crates.

## Master password model

- The master password is never stored, logged, printed, or sent over a
  network.
- It is read without echoing (`rpassword` when stdin is a TTY).
- It is used only to derive a 256-bit key via Argon2id.
- The derived key is held in a `Zeroize` + `ZeroizeOnDrop` wrapper for the
  lifetime of a single command.
- `SAGITARRIUS_PASSWORD` exists for scripting and tests. It is **insecure**;
  it is visible to `ps`, `/proc`, and every child process. Never use it
  with a real master password.

## Vault storage

- The vault is a single JSON file with a base64-encoded ciphertext and
  nonce, and a plaintext header (version, KDF params, salt).
- No plaintext secret is ever written to disk. Temporary files contain only
  already-encrypted bytes.
- On Unix, the vault file is created with mode `0600` and the containing
  directory with `0700`.
- On Windows, Sagitarrius does not manage ACLs; the vault inherits the
  permissions of `%APPDATA%`.

## Atomic writes

Updates are written to a fresh temp file in the same directory, `chmod`ed
and `fsync`ed before being `rename`d over the destination. A crash at any
point leaves either the old or the new vault intact. No backups are kept.

## Concurrency

Mutating commands take an exclusive advisory lock on a lock file next to
the vault (`fs2`'s `lock_exclusive`). Reads are lock-free and may observe
either the prior or the new vault. The lock is released when the process
exits, so a crash cannot leave a permanent lock — but the OS may report a
stale lock on some filesystems, in which case rerun the command.

## Secret exposure risks

- `sagitarrius add <name> "<value>"` places the value in `argv`, which is
  visible to `ps` and may be recorded in shell history. **Prefer
  interactive input.**
- `sagitarrius run -- <cmd>` exports every valid-named secret into the
  child's environment. Any process that can read the child's environment
  can read every secret. This is the intended behaviour but is a real
  disclosure surface.
- `sagitarrius get <name>` prints the value to stdout. Redirect carefully,
  avoid screen sharing, and remember that shell redirections and pipelines
  can copy the value elsewhere.

## Failure modes

- Wrong password, tampered ciphertext, tampered nonce, or truncated payload:
  the command exits non-zero and prints
  `invalid master password or corrupted vault`. No partial plaintext is
  produced.
- Tampered or malformed header (bad magic, unknown KDF id, bad base64,
  out-of-range KDF params or salt/nonce lengths): the command exits non-zero
  and prints `invalid vault format`. KDF params are bounds-checked *before*
  Argon2 runs, so a forged header cannot force excessive memory allocation.
- Vault from a future version: `unsupported vault version: N`.
- Missing vault: `Sagitarrius has not been initialized. Run: sagitarrius init`.
- The binary never panics on attacker-controlled input in normal operation.

## What we do not claim

We do not claim "military-grade", "unhackable", "100% secure", or similar.
Sagitarrius cannot protect a machine that is already compromised, and it
cannot protect you from yourself.
