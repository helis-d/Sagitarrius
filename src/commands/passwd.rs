use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run() -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let _lock = VaultLock::acquire()?;
    let mut data = storage::read_vault()?;

    let mut old_pw = input::master_password("Current master password: ")?;
    let mut vault = match Vault::unlock(&old_pw, &data) {
        Ok(v) => v,
        Err(e) => {
            old_pw.zeroize();
            data.zeroize();
            return Err(e);
        }
    };
    old_pw.zeroize();
    data.zeroize();
    crate::state::verify_generation(&vault)?;

    // Empty SAGITARRIUS_NEW_PASSWORD counts as unset (falls through to the
    // interactive prompt) instead of erroring: no silent empty passwords,
    // no surprising failures in wrappers that always export the variable.
    let new_from_env = matches!(
        std::env::var("SAGITARRIUS_NEW_PASSWORD"),
        Ok(ref v) if !v.is_empty()
    );
    let mut new_pw1 = if new_from_env {
        // Safe: just matched non-empty above.
        std::env::var("SAGITARRIUS_NEW_PASSWORD").unwrap_or_default()
    } else {
        input::read_secret("Enter new master password: ")?
    };
    if new_pw1.is_empty() {
        new_pw1.zeroize();
        return Err(SagitarriusError::EmptyPassword);
    }

    let mut new_pw2 = if new_from_env {
        new_pw1.clone()
    } else {
        input::read_secret("Confirm new master password: ")?
    };

    if new_pw1 != new_pw2 {
        new_pw1.zeroize();
        new_pw2.zeroize();
        return Err(SagitarriusError::PasswordMismatch);
    }
    new_pw2.zeroize();

    if let Err(e) = input::check_new_password(&new_pw1) {
        new_pw1.zeroize();
        return Err(e);
    }

    vault.change_password(&new_pw1)?;
    new_pw1.zeroize();

    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;
    crate::state::store_generation(&vault)?;

    eprintln!("Master password changed successfully.");
    Ok(0)
}
