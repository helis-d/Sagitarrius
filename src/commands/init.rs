use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::platform;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run() -> Result<i32> {
    let _lock = VaultLock::acquire()?;

    if storage::vault_exists()? {
        let path = platform::vault_path()?;
        return Err(SagitarriusError::VaultExists(path.display().to_string()));
    }

    let mut pw1 = input::master_password("Create master password: ")?;
    if pw1.is_empty() {
        pw1.zeroize();
        return Err(SagitarriusError::EmptyPassword);
    }

    // Skip confirmation only when the password came from the environment
    // (non-interactive test / scripting mode). An empty env value is treated
    // as unset so we fall through to the interactive confirm path (which will
    // then fail on EmptyPassword rather than silently succeeding).
    let mut pw2 = if matches!(
        std::env::var("SAGITARRIUS_PASSWORD"),
        Ok(ref v) if !v.is_empty()
    ) {
        pw1.clone()
    } else {
        input::read_secret("Confirm master password: ")?
    };

    if pw1 != pw2 {
        pw1.zeroize();
        pw2.zeroize();
        return Err(SagitarriusError::PasswordMismatch);
    }
    pw2.zeroize();

    let vault = Vault::create(&pw1)?;
    pw1.zeroize();

    let data = vault.serialize()?;
    storage::write_vault_atomic(&data)?;

    eprintln!("Vault initialized successfully.");
    Ok(0)
}
