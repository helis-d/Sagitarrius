use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run() -> Result<i32> {
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

    let mut new_pw1 = match std::env::var("SAGITARRIUS_NEW_PASSWORD") {
        Ok(nw) if !nw.is_empty() => nw,
        Ok(_) => {
            return Err(SagitarriusError::EmptyPassword);
        }
        Err(_) => input::read_secret("Enter new master password: ")?,
    };
    if new_pw1.is_empty() {
        new_pw1.zeroize();
        return Err(SagitarriusError::EmptyPassword);
    }

    let mut new_pw2 = if std::env::var("SAGITARRIUS_NEW_PASSWORD").is_ok() {
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

    vault.change_password(&new_pw1)?;
    new_pw1.zeroize();

    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;

    eprintln!("Master password changed successfully.");
    Ok(0)
}
