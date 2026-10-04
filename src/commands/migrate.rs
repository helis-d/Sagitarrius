//! Explicit v2 -> v3 migration.
//!
//! Never silent, never destructive without a safety net:
//!
//! 1. snapshot the current (v2) vault,
//! 2. convert names/values/timestamps in memory (kinds become `Secret`),
//! 3. verify the result by re-unlocking it,
//! 4. only then replace `vault.json` and adopt the new generation.
//!
//! Already-v3 vaults are left alone.

use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run() -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let _lock = VaultLock::acquire()?;
    let data = storage::read_vault()?;

    let mut password = input::master_password("Master password: ")?;
    let vault = match Vault::unlock(&password, &data) {
        Ok(v) => v,
        Err(e) => {
            password.zeroize();
            return Err(e);
        }
    };
    if vault.is_v3() {
        password.zeroize();
        eprintln!("Vault is already format v3. Nothing to do.");
        return Ok(0);
    }
    if !matches!(vault, Vault::V2(_)) {
        password.zeroize();
        return Err(SagitarriusError::InvalidVaultFormat);
    }

    // Safety net first: the old vault stays recoverable whatever happens.
    let pre = crate::commands::snapshot::store_copy(&storage::snapshots_dir()?, "pre-migrate")?;

    let migrated = crate::vault::migrate_v2_to_v3(&password, &data)?;
    password.zeroize();
    storage::write_vault_atomic(&migrated)?;

    let live = storage::read_vault()?;
    let vault = Vault::unlock(&password, &live)?;
    password.zeroize();
    if !vault.is_v3() {
        return Err(SagitarriusError::Other(
            "migration verification failed: live vault is not v3".into(),
        ));
    }
    crate::state::store_generation(&vault)?;
    eprintln!(
        "Migrated to vault format v3 (VMK envelope, per-record keys). \
         Pre-migration copy kept as snapshot {pre}."
    );
    Ok(0)
}
