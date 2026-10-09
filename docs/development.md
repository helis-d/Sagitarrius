# Development

```bash
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

Run all four before opening a pull request. Bug reports and small, focused
pull requests are welcome. Release smoke tests live in `scripts/`
(`smoke.sh` for POSIX, `smoke.ps1` for Windows) — see their headers.

## Project layout

```
src/
├── main.rs         entry point
├── cli.rs          clap definitions
├── banner.rs       launch menu ASCII-ART (rasterized from assets/sagitarrius-logo.svg)
├── commands/       one file per subcommand (+ snapshot/backup/recovery/file/...)
├── crypto.rs       Argon2id + AES-256-GCM (+ nonce-explicit variants)
├── envelope.rs     VMK, wraps, HKDF sub-keys, recovery codes
├── vault.rs        v2 format + unified Vault facade + migration
├── vault_v3.rs     v3 envelope format, typed records
├── files.rs        chunked authenticated file containers
├── state.rs        trusted generation state (rollback detection)
├── storage.rs      atomic writes, file locking
├── platform.rs     OS-specific paths
├── input.rs        terminal / pipe input
└── error.rs        error types
assets/
├── sagitarrius-logo.svg    the logo
└── sagitarrius-banner.jpg  README banner
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

The release profile uses LTO, one codegen unit, and stripped symbols,
producing a small single-file executable.

## Out of scope (by design)

- No password recovery without a kit, no cloud sync, no team sharing, no browser integration.
- `run` only injects valid POSIX env names; the rest are skipped with a warning.
- File permission guarantees are only as strong as the platform provides.
