//! Vault lockdown: refuse all decryption until explicitly released.
//!
//! Enabling writes a flag file; every secret-decrypting or mutating command
//! checks it first and fails closed. It preserves all data and recovery
//! material — it deletes nothing.
//!
//! Honest scope: this stops *the CLI* (mistakes, malware driving the CLI).
//! Anyone with raw filesystem access can remove the flag file, so lockdown
//! is not a defense against a filesystem-level attacker. It is documented
//! as such.

use crate::error::Result;
use crate::storage;

pub fn run(off: bool) -> Result<i32> {
    if off {
        storage::set_lockdown(false)?;
        eprintln!("Lockdown released. Decryption commands work again.");
    } else {
        storage::set_lockdown(true)?;
        eprintln!(
            "Lockdown ENABLED: decryption and all mutations are refused.\n\
             Only `status`, `list`, `search`, `exists` and `menu` still work.\n\
             (On v2 vaults, migrate for the full effect.)\n\
             Release with `sagitarrius lockdown --off`."
        );
    }
    Ok(0)
}
