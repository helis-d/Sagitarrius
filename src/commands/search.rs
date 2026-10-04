use crate::error::Result;
use crate::input;
use crate::storage;
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run(query: String) -> Result<i32> {
    if query.is_empty() {
        return Err(crate::error::SagitarriusError::Other(
            "search query must not be empty".into(),
        ));
    }
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

    let matches = vault.search(&query);
    if matches.is_empty() {
        return Ok(1);
    }
    for m in matches {
        println!("{}", crate::vault::escape_name(m));
    }
    Ok(0)
}
