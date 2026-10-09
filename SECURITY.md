# Security

Sagitarrius is a small local tool. This document describes exactly what it
protects against and what it does not.

## Reporting a vulnerability

Please use GitHub Private Vulnerability Reporting on the project's
repository (Security tab → Report a vulnerability). Do not open a public
issue for vulnerabilities that could affect users.

If private reporting is unavailable to you, contact: `SECURITY_CONTACT_TODO`
(the maintainer will replace this placeholder with a real address; until
then use private reporting only).

Human action: enable Settings → Security → Private vulnerability reporting
on the repository.

## Threat model

Sagitarrius protects encrypted vault data **at rest** and provides
**verifiable recovery** from corruption and destructive filesystem events.
Full statement: [docs/threat-model.md](docs/threat-model.md).

### In scope

- Loss or theft of a disk, backup, or synced copy of `vault.json`.
- Silent tampering with the vault file, snapshots, backups, or file
  containers (all authenticated; failures are closed, never partial).
- Replay of an older-but-authentic vault — refused by the generation
  counter compared against trusted `state.json`, but ONLY while that state
  file exists and is not itself attacker-writable (see out-of-scope item
  below); v2 files report rollback protection as unavailable.
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
- **Manifest MAC:** HMAC-SHA256 under an HKDF-derived manifest key over a
  canonical length-prefixed encoding of vault id, generation and every
  record's (id, name, kind, timestamps, nonce). Verified after every
  unlock; recomputed on every write. Record names stay plaintext by design
  (listing without full decryption); set-membership tampering is what the
  MAC covers.
- **No primitive is hand-rolled.** `argon2`, `aes-gcm`, `hkdf`, `hmac`,
  `sha2`.

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
point leaves either the old or the new vault intact. Crash safety is not
backup: snapshots (`snapshot create`) and offline backups
(`backup create --to <dir>`) are separate, explicit operations.

## Lockdown

`lockdown` writes a flag file that makes every decrypting or mutating
command fail closed; only `status`, `list`, `search`, `exists` and `menu`
keep working until `lockdown --off`. It stops the CLI (own mistakes,
malware driving the CLI) — anyone with raw filesystem access can remove
the flag, so it is not an OS-level boundary and is documented as such.

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
- `sagitarrius run --secret A --secret B -- <cmd>` exports only the named
  secrets into the child's environment. Any process that can read the
  child's environment can read those secrets — that scoping is the whole
  point, but the residual surface is real. Without `--secret` the command
  refuses rather than exposing the vault.
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

## What is zeroized

Best-effort memory hygiene, not a guarantee (see next section):

- Derived keys and the VMK wipe on drop (`ZeroizeOnDrop` on `DerivedKey`
  in `src/crypto.rs` and `VaultMasterKey` in `src/envelope.rs`).
- Master-password `String`s are wiped after use in every command
  (`password.zeroize()` on both success and unlock-failure paths).
- Decrypted plaintext buffers are wiped after encrypt/decrypt in the
  vault layer; `run` wipes its name/value copies after `Command::env`.
- Recovery codes and temp secret pairs are wiped after use.

## Hardening not implemented

- The Argon2id memory blocks (64 MiB per derivation) are NOT wiped: the
  `argon2` crate's `zeroize` feature is not enabled in our build
  (verified: `cargo tree -e features -i argon2` lists only
  alloc/default/password-hash/rand), and even with it only small
  intermediaries are wiped, never the block memory itself.
- No page locking (`mlock`/`VirtualLock`), no swap avoidance, no
  core-dump suppression anywhere in the codebase.
- Allocator copies, `serde` intermediate `String`s, and the child
  process environment are outside wiping.
- Treat unlocked plaintext as recoverable by anyone who can read process
  memory, swap, or crash dumps on the machine.

## Independent review wanted

No independent cryptographic review has been performed. If you can review
applied Rust cryptography (AEAD usage, KDF parameterization, envelope
key hierarchy, backup/restore integrity logic), please report findings via
private vulnerability reporting above. Honest, specific findings are
welcome; vague assurances are not.

## Recommendations

- Use a long passphrase (12+ characters enforced for new passwords).
- Keep offline backups (`backup create --to <offline-dir>`) and verify
  them (`backup verify`).
- Rotate secrets after any suspected compromise of the machine.
- Do not store your most critical secrets here until an independent
  review exists.

## What we do not claim

We do not claim "military-grade", "unhackable", "100% secure", or similar.
Sagitarrius cannot protect a machine that is already compromised, and it
cannot protect you from yourself.
