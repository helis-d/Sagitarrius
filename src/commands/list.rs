use crate::error::Result;
use crate::input;
use crate::storage;
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run() -> Result<i32> {
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

    let names = vault.names();
    // Header / footer to stderr; the actual names to stdout so the command
    // is pipeline-friendly:
    //     sagitarrius list | grep -i api
    eprintln!("Stored secrets:");
    eprintln!();
    for n in &names {
        println!("{n}");
    }
    eprintln!();
    eprintln!(
        "{} secret{}",
        names.len(),
        if names.len() == 1 { "" } else { "s" }
    );
    Ok(0)
}
