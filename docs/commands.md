# Command reference

Run `sagitarrius` with no arguments (or `sagitarrius menu`) to see the
launch menu. Run `sagitarrius <command> --help` for flags of one command.
Global flag: `--password-stdin` reads the master password from stdin
instead of the terminal or env vars (prefer it over `SAGITARRIUS_PASSWORD`
in scripts).

## Exit codes

- `0` — success.
- `1` — clean negative result only: `exists` for an absent secret,
  `search` with no matches, `audit` with findings.
- `2` — every failure: wrong password, missing secret, corrupt or missing
  vault, lockdown refusal, stale generation, I/O errors, and all usage
  errors (bad flags/values, empty query, unknown `--kind`, missing
  `--secret`/`--plaintext`, invalid names). Clap parse errors also exit 2.
- Any other code — propagated from `sagitarrius run`'s child process.

## Vault

| Command | Description |
|---|---|
| `init` | Create the vault. Refuses to overwrite an existing one. |
| `passwd` | Change the master password. The new password comes from `SAGITARRIUS_NEW_PASSWORD`, or from an interactive prompt when that is unset. |

## Secrets

| Command | Description |
|---|---|
| `add <name> [value] [--kind K] [--username U]` | Add a typed record (`secret` default; `password`, `note`, `credential`, `document`). Without `value` you are prompted twice (preferred). |
| `gen <name> [--length L] [--no-symbols]` | Generate a random secret and store it (default length 32, max 4096). |
| `get <name> [--json]` | Print only the value to stdout — composable with pipes. `--json` prints the full record (for credentials/files). |
| `info <name>` | Show kind, metadata: character length, valid-env-name flag, timestamps. Never shows the value. |
| `list` | List secret **names**. Values are never shown. |
| `search <query>` | Search **names** for a substring. Exits 1 when nothing matches. |
| `exists <name>` | Exit 0 if present, 1 otherwise. Silent — made for scripts. |
| `edit <name>` | Replace an existing secret's value (double prompt). |
| `rename <old> <new>` | Rename without overwriting. |
| `remove <name> [-y/--yes]` | Delete after a `[y/N]` confirmation (`-y` skips it, for scripts). Also drops the file container for file records. |

### `add` in detail

```bash
sagitarrius add openai              # interactive, no echo
sagitarrius add openai "sk-example" # value on the CLI
```

> **Warning:** passing a secret as a command-line argument may expose it
> through shell history, `ps`, or process listings. Prefer interactive input.

Names must not be empty and must not contain `=`, newlines, or control
characters. Values must not be empty (whitespace-only counts as empty).

## Bulk operations

| Command | Description |
|---|---|
| `import <file> [--overwrite] [--allow-dangerous]` | Import secrets from a `.env` file. A UTF-8 BOM is stripped. `#` starts an inline comment only outside quotes and after whitespace (`a#b` stays). Text after a closing quote must be blank or a comment, else the entry is skipped. Without `--overwrite`, existing names are skipped and counted. Lines without `=`, empty keys/values, over-long entries, and control-char names are skipped and counted. Names with spaces/shell metacharacters are skipped with a warning unless `--allow-dangerous`. |
| `export --plaintext [--force] [file]` | Export secrets in `.env` format — to stdout, or to a file (written atomically with `0600` permissions on Unix; symlinks at the destination are refused). `--plaintext` is **required**: decrypting to disk must be deliberate. An existing destination file is never overwritten without `--force`. Quoting is shell-safe: single quotes when possible, else double quotes escaping `\ " $ ` and newline — sourceable by POSIX `sh`, and re-import round-trips byte-for-byte. Only single-value kinds and valid env names export; the rest are listed as skipped. |
| `audit` | Health check: short values (< 8 chars, rough signal only), duplicate values (grouped), invalid env names. Exits 1 when issues are found. |

## Resilience

| Command | Description |
|---|---|
| `migrate` | Upgrade a v2 vault to v3 (snapshots first, verifies after). No-op on v3. |
| `snapshot create/list/verify/delete` + `restore <id>` | Encrypted local history. Restores verify first, snapshot the present, then replace. |
| `backup create [--to DIR]/list/verify/restore/prune` | Same format aimed at offline media. `--to` writes anywhere; `list` covers local backups, `verify`/`restore` accept `--from DIR`. |
| `recovery create/verify/reset-password` | Recovery code kit for a lost master password (v3 only). |
| `file put <path> [--name N]` / `file get <name> <dest>` | Encrypted files (64 KiB chunks, hash-verified). Removed with `remove`. |
| `status` | Passwordless health lines: format, trusted generation, recovery, snapshots, backups, lockdown. |
| `lockdown [--off]` | Refuse all decryption until released. Stops the CLI, not filesystem attackers. |

## `run` in detail

```bash
sagitarrius add OPENAI_API_KEY
sagitarrius add DATABASE_URL
sagitarrius run --secret OPENAI_API_KEY -- python app.py   # os.getenv(...)
```

Only `--secret` names are injected — the default is nothing, never the
whole vault. Repeat `--secret` for more than one. Loader and shell-startup
names (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `DYLD_*`, `BASH_ENV`,
`ENV`, `SHELLOPTS`, `BASHOPTS`, `PS4`, `IFS`, `PATH`) and names with
whitespace or shell metacharacters are refused unless
`--allow-dangerous-env`; NUL is always refused. Errors name the secret,
never the value.

How names map to environment variables:

- **Only names that are valid POSIX environment variable identifiers**
  (`[A-Za-z_][A-Za-z0-9_]*`) are injected. Names like `openai-key` or
  `foo.bar` are skipped with a warning on stderr.
- Existing environment variables with the same name are shadowed for the
  child only. Your shell is untouched.
- Nothing is written to disk. No `.env` file is created.
- `SAGITARRIUS_PASSWORD` / `SAGITARRIUS_NEW_PASSWORD` are stripped from the
  child's environment.
- The child process has full access to every injected value. Sagitarrius
  cannot prevent the child (or anything that can read its environment)
  from leaking secrets — that is the caller's responsibility.
