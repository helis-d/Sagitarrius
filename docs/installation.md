# Installation

Requirements for source builds: **Rust 1.85+** (via [rustup](https://rustup.rs)) and git.

Supported platforms and architectures:

| OS | Architectures | Release artifact |
|---|---|---|
| Windows 10/11 | x86_64 | `sagitarrius-windows-x86_64.zip` |
| Linux (glibc) | x86_64 | `sagitarrius-linux-x86_64.tar.gz` |
| macOS 13+ | x86_64 (Intel) | `sagitarrius-macos-x86_64.tar.gz` |
| macOS 14+ | aarch64 (Apple Silicon) | `sagitarrius-macos-aarch64.tar.gz` |

(Linux ARM64 is not built yet — see the note in `.github/workflows/release.yml`.)

## From a release binary (no Rust needed)

1. Download the archive for your OS/arch from GitHub Releases plus
   `SHA256SUMS.txt`, and verify the checksum.
2. Unpack the single `sagitarrius` (or `sagitarrius.exe`) binary.

### Windows (PowerShell)

```powershell
Expand-Archive sagitarrius-windows-x86_64.zip C:\Tools\sagitarrius
$env:PATH += ";C:\Tools\sagitarrius"   # or set it permanently in Settings
sagitarrius --help
```

### Linux

```bash
tar -xzf sagitarrius-linux-x86_64.tar.gz
sudo install -m 0755 sagitarrius-linux-x86_64/sagitarrius /usr/local/bin/
sagitarrius --help
```

### macOS

```bash
tar -xzf sagitarrius-macos-aarch64.tar.gz   # or -x86_64 on Intel
sudo install -m 0755 sagitarrius-macos-*/sagitarrius /usr/local/bin/
sagitarrius --help
```

## From source (any supported OS)

```bash
git clone https://github.com/helis-d/Sagitarrius.git
cd Sagitarrius
cargo install --path . --force
```

After either method, `sagitarrius` works in any terminal. Verify with a
bare run — it shows the logo and the menu without touching anything:

```bash
sagitarrius
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
