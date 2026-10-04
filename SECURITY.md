# Security

Sagitarrius is a small local tool. This document describes exactly what it
protects against and what it does not.

## Reporting a vulnerability

Please open a private security advisory on the project's GitHub repository,
or email the maintainers directly. Do not open a public issue for
vulnerabilities that could affect users.

## Threat model

Sagitarrius protects encrypted vault data **at rest** and provides
**verifiable recovery** from corruption and destructive filesystem events.
Full statement: [docs/threat-model.md](docs/threat-model.md).

### In scope

- Loss or theft of a disk, backup, or synced copy of `vault.json`.
- Silent tampering with the vault file, snapshots, backups, or file
  containers (all authenticated; failures are closed, never partial).
- Replay of an older-but-authentic vault (generation counter + trusted
  state refuse stale files; v2 files report rollback protection
  as unavailable).
- Ransomware-like modification of accessible storage: detected via
  integrity/generation signals; recovery via verified snapshots and
  *offline* backups. Same-disk copies are history, not protection.
- Accidental disclosure of values through command output (values never in
  list/search/audit; names are terminal-escaped).
- Child-process over-exposure: `run` injects only `--secret` names and
  strips password helpers.
- Partial or torn writes if the process is interrupted mid-update.

### Out of scope

- A compromised machine. A keylogger, rootkit, debugger, or hostile root
  user can recover both the master password and the plaintext.
- Brute-force resistance against weak master passwords. Argon2id raises the
  cost of each guess; it does not eliminate it.
- Exposure through shell history, `ps`, `/proc`, or `argv` when a secret is
  passed as a command-line argument.
- A child process intentionally given a secret: it can leak it by design.
- An attacker replacing **both** `vault.json` **and** `state.json`
  consistently (locally indistinguishable — offline backups defeat this).
- Forensic remnants of old ciphertext on disk; swap/pagefile disclosure.
- Physical coercion, rubber-hose cryptanalysis, or legal compulsion.
- Password recovery *without* a recovery kit. With a kit
  (`recovery create`), password *reset* is supported — nothing ever stores
  the password itself.

## Cryptographic design (v3; v2 files use whole-payload AES-GCM)

- **Vault Master Key:** 32 random bytes, never derived. Password and
  recovery code each derive a wrapping KEK (Argon2id) that unwraps the VMK.
- **KDF:** Argon2id (m=64 MiB, t=3, p=4; per-wrap 16-byte salt).
  Header KDF params are bounds-checked *before* derivation.
- **Records:** AES-256-GCM under `HKDF(VMK, "SAGITARRIUS/v3/record/<id>")`,
  fresh 96-bit nonce per record write; AAD binds vault id, record id, kind,
  version. `get` decrypts exactly one record.
- **Files:** 64 KiB chunks, nonce = 32-bit random prefix || 64-bit counter;
  per-chunk AAD + SHA-256 cross-check.
- **Wraps:** AES-256-GCM; AAD binds magic, version, vault id, wrap kind,
  KDF params, salt.
- **No primitive is hand-rolled.** `argon2`, `aes-gcm`, `hkdf`, `sha2`.

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
