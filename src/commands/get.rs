use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage;
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run(name: String, json: bool) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
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
    crate::state::verify_generation(&vault)?;

    if json {
        // Full record (needed for credential/file kinds). Still only this
        // record — nothing else leaves the vault.
        return match vault.get_payload(&name) {
            Some(payload) => {
                let mut out = serde_json::to_string(&payload)?;
                println!("{out}");
                out.zeroize();
                Ok(0)
            }
            None => Err(SagitarriusError::SecretNotFound(name)),
        };
    }

    match vault.get(&name) {
        Some(value) => {
            // The ONLY thing we print to stdout. No prefix, no suffix.
            println!("{value}");
            Ok(0)
        }
        None => Err(SagitarriusError::SecretNotFound(name)),
    }
}
