use crate::error::Result;
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
    crate::state::verify_generation(&vault)?;

    Ok(if vault.exists(&name) { 0 } else { 1 })
}
