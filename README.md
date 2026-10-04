# Sagitarrius

![Sagitarrius banner](assets/sagitarrius-banner.jpg)

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

## Install

From source (Rust 1.75+):

```bash
git clone https://github.com/helis-d/Sagitarrius.git
cd Sagitarrius
cargo install --path . --force
```

Details: [docs/installation.md](docs/installation.md).

## Quick start

```bash
sagitarrius init       # create the vault (asks for a master password)
sagitarrius add OPENAI_API_KEY   # asks twice, input is hidden
sagitarrius list       # names only — values are never shown
sagitarrius get OPENAI_API_KEY   # prints only the value (pipe-friendly)
```

Because `get` prints only the value, it composes:

```bash
export OPENAI_API_KEY="$(sagitarrius get OPENAI_API_KEY)"
```

## Commands

| Command | Description |
|---|---|
| `menu` | Show the launch menu |
| `init` / `passwd` | Create the vault / change the master password |
| `add` / `gen` / `edit` | Add, generate, or replace a secret |
| `get` / `info` | Print a value / show metadata (never the value) |
| `list` / `search` / `exists` | Browse names (values are never shown) |
| `rename` / `remove` | Rename without overwriting / delete with confirmation |
| `import` / `export` | Bulk move secrets in `.env` format |
| `audit` | Health check: short values, duplicates, bad names |
| `run -- <cmd>` | Run a command with secrets in its environment |

Full reference: [docs/commands.md](docs/commands.md).

## Security in 30 seconds

- Vault lives at `%APPDATA%\sagitarrius\data\vault.json` on Windows
  ([all platforms](docs/vault-and-crypto.md)); encrypted with
  Argon2id + AES-256-GCM.
- Protects a **stolen vault file**. Does **not** protect a compromised
  machine, a weak master password, or shell-history leaks — and there is
  **no password recovery**.
- Full model: [SECURITY.md](SECURITY.md) · details:
  [docs/vault-and-crypto.md](docs/vault-and-crypto.md).

## Docs

- [Installation](docs/installation.md) · [Commands](docs/commands.md) ·
  [Vault & crypto](docs/vault-and-crypto.md) ·
  [Development](docs/development.md)

## License

MIT — see [LICENSE](LICENSE).
