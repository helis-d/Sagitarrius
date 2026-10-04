# Installation

Requirements: **Rust 1.75+** (via [rustup](https://rustup.rs)) and git.

## From source (recommended)

```bash
git clone https://github.com/helis-d/Sagitarrius.git
cd Sagitarrius
cargo install --path . --force
```

After this, `sagitarrius` works in any terminal. Verify with a bare run —
it shows the logo and the menu without touching anything:

```bash
sagitarrius
```

## From a release binary

No Rust needed. Take `sagitarrius.exe` (or the `sagitarrius` binary for your
OS) from a release build (`cargo build --release` produces a single file
under `target/release/`), put it somewhere on your `PATH`, and run:

```bash
sagitarrius --help
```

## Updating

There is no auto-update. Rebuild and reinstall:

```bash
cd Sagitarrius
git pull
cargo install --path . --force
```

Updating only replaces the executable. Your vault
(`vault.json`, see [vault-and-crypto.md](vault-and-crypto.md)) and your
master password are untouched. Back up `vault.json` before upgrading, just
in case.

## Uninstalling

```bash
cargo uninstall sagitarrius
```

This removes the binary only. Delete the vault directory yourself if you
want your secrets gone (see the location table in
[vault-and-crypto.md](vault-and-crypto.md)).
