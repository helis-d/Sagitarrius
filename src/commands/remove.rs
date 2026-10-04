use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run(name: String, yes: bool) -> Result<i32> {
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

    if !vault.exists(&name) {
        return Err(SagitarriusError::SecretNotFound(name));
    }

    if !yes && !input::confirm(&format!("Remove secret {name:?}? [y/N] "))? {
        eprintln!("Cancelled.");
        return Ok(0);
    }

    vault.remove(&name);
    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;

    eprintln!("Secret {name:?} removed.");
    Ok(0)
}
