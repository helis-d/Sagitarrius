use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage;
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run(name: String) -> Result<i32> {
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

    match vault.info(&name) {
        Some(info) => {
            println!("Secret Info:");
            println!(
                "  Name:              {}",
                crate::vault::escape_name(&info.name)
            );
            println!("  Length:            {} characters", info.length);
            println!("  Valid POSIX Env:   {}", info.is_valid_env_name);
            println!("  Created At:        {}", format_timestamp(info.created_at));
            println!("  Updated At:        {}", format_timestamp(info.updated_at));
            Ok(0)
        }
        None => Err(SagitarriusError::SecretNotFound(name)),
    }
}

fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        "Unknown".to_string()
    } else {
        format!("{ts} (Unix Epoch)")
    }
}
