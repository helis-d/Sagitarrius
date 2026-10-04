use crate::error::Result;
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run(old: String, new: String) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let _lock = VaultLock::acquire()?;
    let mut data = storage::read_vault()?;

    let mut password = input::master_password("Master password: ")?;
    let mut vault = match Vault::unlock(&password, &data) {
        Ok(v) => v,
        Err(e) => {
            password.zeroize();
            data.zeroize();
            return Err(e);
        }
    };
    password.zeroize();
    data.zeroize();
    crate::state::verify_generation(&vault)?;

    vault.rename(&old, &new)?;
    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;
    crate::state::store_generation(&vault)?;

    eprintln!("Secret {old:?} renamed to {new:?}.");
    Ok(0)
}
