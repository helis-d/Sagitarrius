use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run(name: String) -> Result<i32> {
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

    if !vault.exists(&name) {
        return Err(SagitarriusError::SecretNotFound(name));
    }

    let mut v1 = input::read_secret("Enter new secret value: ")?;
    let mut v2 = input::read_secret("Confirm new secret value: ")?;

    if v1.trim().is_empty() {
        v1.zeroize();
        v2.zeroize();
        return Err(SagitarriusError::EmptySecretValue);
    }
    if v1.contains('\0') {
        v1.zeroize();
        v2.zeroize();
        return Err(SagitarriusError::Usage(format!(
            "secret {name:?} contains a NUL byte and cannot be stored"
        )));
    }
    if v1.len() > crate::vault::MAX_SECRET_VALUE_LEN {
        v1.zeroize();
        v2.zeroize();
        return Err(SagitarriusError::Other(format!(
            "secret value must be at most {} bytes",
            crate::vault::MAX_SECRET_VALUE_LEN
        )));
    }
    if v1 != v2 {
        v1.zeroize();
        v2.zeroize();
        return Err(SagitarriusError::ValuesMismatch);
    }
    v2.zeroize();

    vault.set(&name, &v1);
    v1.zeroize();

    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;
    crate::state::store_generation(&vault)?;

    eprintln!("Secret {name:?} updated.");
    Ok(0)
}
