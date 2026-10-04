use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run(name: String, value: Option<String>) -> Result<i32> {
    crate::vault::validate_secret_name(&name)?;

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

    if vault.exists(&name) {
        return Err(SagitarriusError::SecretAlreadyExists(name));
    }

    let (mut v1, mut v2) = match value {
        Some(v) => {
            eprintln!(
                "Warning: passing a secret on the command line may expose it through \
                 shell history or process listings. Prefer interactive input."
            );
            (v.clone(), v)
        }
        None => {
            let v1 = input::read_secret("Enter secret value: ")?;
            let v2 = input::read_secret("Confirm secret value: ")?;
            (v1, v2)
        }
    };

    if v1.trim().is_empty() {
        v1.zeroize();
        v2.zeroize();
        return Err(SagitarriusError::EmptySecretValue);
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

    if vault.names().len() >= crate::vault::MAX_SECRETS {
        v1.zeroize();
        return Err(SagitarriusError::Other(format!(
            "vault already holds {} secrets",
            crate::vault::MAX_SECRETS
        )));
    }
    vault.set(&name, &v1);
    v1.zeroize();

    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;

    eprintln!("Secret {name:?} added successfully.");
    Ok(0)
}
