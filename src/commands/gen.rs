use crate::crypto;
use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run(name: String, length: usize, no_symbols: bool) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    /// Upper bound to avoid accidental/OOM allocations (`vec![0u8; N]`).
    const MAX_GENERATED_SECRET_LEN: usize = 4096;
    crate::vault::validate_secret_name(&name)?;
    if length == 0 {
        return Err(SagitarriusError::Usage(
            "generated secret length must be greater than 0".into(),
        ));
    }
    if length > MAX_GENERATED_SECRET_LEN {
        return Err(SagitarriusError::Usage(format!(
            "generated secret length must be at most {MAX_GENERATED_SECRET_LEN}"
        )));
    }

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

    if vault.exists(&name) {
        return Err(SagitarriusError::SecretAlreadyExists(name));
    }

    let mut secret_val = crypto::random_secret(length, !no_symbols);
    vault.set(&name, &secret_val);
    secret_val.zeroize();

    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;
    crate::state::store_generation(&vault)?;

    eprintln!("Generated random secret for {name:?} ({length} chars) and saved to vault.");
    Ok(0)
}
