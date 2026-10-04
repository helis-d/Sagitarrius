use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage;
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run(name: String) -> Result<i32> {
    let mut data = storage::read_vault()?;

    let mut password = input::master_password("Master password: ")?;
    let vault = match Vault::unlock(&password, &data) {
        Ok(v) => v,
        Err(e) => {
            password.zeroize();
            data.zeroize();
            return Err(e);
        }
    };
    password.zeroize();
    data.zeroize();

    match vault.get(&name) {
        Some(value) => {
            // The ONLY thing we print to stdout. No prefix, no suffix.
            println!("{value}");
            Ok(0)
        }
        None => Err(SagitarriusError::SecretNotFound(name)),
    }
}
