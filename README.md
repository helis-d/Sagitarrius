# Sagitarrius

<img src="assets/sagitarrius-logo.svg" width="120" alt="Sagitarrius logo">

**Your secrets. Your machine. Your terminal.**

A tiny, local-first CLI secret manager for developers. No account, no cloud,
no network, no telemetry — one encrypted file on your own disk.

```
sagitarrius init
sagitarrius add OPENAI_API_KEY
sagitarrius list
sagitarrius get OPENAI_API_KEY
sagitarrius run -- cargo test
```

## Why

You have a handful of API keys and tokens. You do not want a cloud password
manager, a browser extension, a daemon, or a `.env` file checked into the
wrong repo. You want a small Unix-flavoured tool that stores your secrets
encrypted on your machine and hands them back to your terminal.

That is all Sagitarrius does.

## Install

From source (Rust 1.75+):

```bash
git clone https://github.com/sagitarrius/sagitarrius
cd sagitarrius
cargo build --release
./target/release/sagitarrius --help
```

Or, once published:

```bash
cargo install --path .
```

## Quick start

```bash
sagitarrius init
# Create master password:
# Confirm master password:
# Vault initialized successfully.

sagitarrius add OPENAI_API_KEY
# Master password:
# Enter secret value:
# Confirm secret value:
# Secret "OPENAI_API_KEY" added successfully.

sagitarrius add DATABASE_URL
sagitarrius add GITHUB_TOKEN

sagitarrius list
# Stored secrets:
#
# DATABASE_URL
# GITHUB_TOKEN
# OPENAI_API_KEY
#
# 3 secrets

sagitarrius get OPENAI_API_KEY
# sk-...
```

Because `get` prints only the value to stdout, it composes:

```bash
export OPENAI_API_KEY="$(sagitarrius get OPENAI_API_KEY)"
```

## Commands

| Command | Description |
|---|---|
| `init` | Create the vault. Refuses to overwrite. |
| `passwd` | Change vault master password safely. |
| `add <name> [value]` | Add a secret. Interactive entry is preferred. |
| `gen <name> [--length L] [--no-symbols]` | Generate a cryptographically secure random secret. |
| `get <name>` | Print only the value to stdout. |
| `info <name>` | Display metadata (created/updated timestamp, character length). |
| `list` | List secret **names**. Values are never shown. |
| `remove <name>` | Delete after a `[y/N]` confirmation. |
| `edit <name>` | Replace an existing secret's value. |
| `rename <old> <new>` | Rename without overwriting. |
| `exists <name>` | Exit 0 if present, 1 otherwise. Silent. |
| `search <query>` | Search **names** for a substring. |
| `import <file> [--overwrite]` | Import secrets from a `.env` file. |
| `export [file]` | Export secrets formatted in `.env` format. |
| `audit` | Health check for weak passwords, duplicates, or invalid env names. |
| `run -- <cmd> ...` | Run a child process with every valid-named secret in its env. |

Exit codes:

- `0` — success
- `1` — general / user error (missing secret, wrong password, etc.)
- Any other code — propagated from `sagitarrius run`'s child process

### `add`

```bash
sagitarrius add openai              # interactive, no echo
sagitarrius add openai "sk-example" # value on the CLI
```

> **Warning:** passing a secret as a command-line argument may expose it
> through shell history, `ps`, or process listings. Prefer interactive input.

### `run`

```bash
sagitarrius add OPENAI_API_KEY
sagitarrius add DATABASE_URL
sagitarrius run -- python app.py    # os.getenv("OPENAI_API_KEY")
```

How names map to environment variables:

- **Only names that are valid POSIX environment variable identifiers**
  (`[A-Za-z_][A-Za-z0-9_]*`) are injected. Names like `openai-key` or
  `foo.bar` are skipped with a warning on stderr.
- Existing environment variables with the same name are shadowed for the
  child only. Your shell is untouched.
- Nothing is written to disk. No `.env` file is created.
- The child process has full access to every injected value. Sagitarrius
  cannot prevent the child (or anything that can read its environment)
  from leaking secrets — that is the caller's responsibility.

## Vault location

| OS | Path |
|---|---|
| Linux | `$XDG_DATA_HOME/sagitarrius/vault.json` (fallback `~/.local/share/sagitarrius/vault.json`) |
| macOS | `~/Library/Application Support/sagitarrius/vault.json` |
| Windows | `%APPDATA%\sagitarrius\data\vault.json` |

Override with `SAGITARRIUS_VAULT_DIR=/some/dir`.

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
- The derived key is zeroized on drop.
- No cryptographic primitive is hand-rolled.

## Security model

**Protects against**

- Theft of the vault file (disk, backups, cloud-synced folders).
- Tampering with the vault file — any modification fails authentication.
- Accidental disclosure of values via `list`, `search`, `exists`.
- Partial writes if the process is interrupted.

**Does not protect against**

- A compromised machine. Malware, keyloggers, rootkits, root users, and
  debuggers can recover both your password and your plaintext while the
  process runs.
- A weak master password. Argon2id raises the cost of brute force; it
  cannot eliminate it.
- Shell-history or `ps` exposure when you pass secrets on the command line.
- Any process that can read the environment of a child spawned by
  `sagitarrius run`.
- Password recovery. There is none. If you lose the password, the vault is
  gone.

See [SECURITY.md](SECURITY.md) for the full threat model.

## `SAGITARRIUS_PASSWORD`

For scripting and automated tests, `SAGITARRIUS_PASSWORD` supplies the
master password non-interactively. **This is not safer than typing it** —
environment variables are visible to `ps`, `/proc`, and child processes.
Do not use it with a real master password.

## Development

```bash
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

Project layout:

```
src/
├── main.rs         entry point
├── cli.rs          clap definitions
├── commands/       one file per subcommand
├── crypto.rs       Argon2id + AES-256-GCM
├── vault.rs        on-disk format, CRUD
├── storage.rs      atomic writes, file locking
├── platform.rs     OS-specific paths
├── input.rs        terminal / pipe input
└── error.rs        error types
tests/
├── cli.rs          end-to-end CLI tests
├── security.rs     tamper / leak / permission tests
└── vault.rs        placeholder for in-crate vault tests
```

## Building releases

```bash
# Native
cargo build --release

# Cross-compile (requires the appropriate target installed via rustup)
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
                 x86_64-apple-darwin aarch64-apple-darwin \
                 x86_64-pc-windows-gnu

cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-pc-windows-gnu
```

Release profile uses LTO, one codegen unit, and stripped symbols, producing
a small single-file executable.

## Limitations

- No password recovery.
- No cloud sync, no team sharing, no browser integration. These are
  explicitly out of scope.
- Single-writer at a time. Concurrent mutations are serialized via an
  advisory file lock; the second writer waits.
- `run` only injects secrets whose names are valid environment variable
  identifiers. Names with dashes or dots are skipped with a warning.
- OS-level file permission guarantees are only as strong as the platform
  provides. On Windows we rely on the ACL of `%APPDATA%`.

## Contributing

Bug reports and small, focused pull requests are welcome. Please run
`cargo fmt`, `cargo clippy -D warnings`, and `cargo test` before opening a
PR.

## License

MIT — see [LICENSE](LICENSE).
