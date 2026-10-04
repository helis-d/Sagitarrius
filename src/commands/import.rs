use crate::error::Result;
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use std::fs;
use zeroize::Zeroize;

pub fn run(path: String, overwrite: bool) -> Result<i32> {
    // Bound memory use before reading an attacker-influenced file.
    let import_meta = fs::metadata(&path)?;
    if import_meta.len() > crate::vault::MAX_IMPORT_FILE_SIZE {
        return Err(crate::error::SagitarriusError::Other(format!(
            "import file too large ({} bytes, max {})",
            import_meta.len(),
            crate::vault::MAX_IMPORT_FILE_SIZE
        )));
    }
    let mut env_content = fs::read_to_string(&path)?;
    // read_to_string follows symlinks; cap the in-memory size as well in case
    // the file grew between metadata and read.
    if env_content.len() as u64 > crate::vault::MAX_IMPORT_FILE_SIZE * 2 {
        env_content.zeroize();
        return Err(crate::error::SagitarriusError::Other(format!(
            "import file too large (max {})",
            crate::vault::MAX_IMPORT_FILE_SIZE
        )));
    }

    let _lock = VaultLock::acquire()?;
    let mut data = storage::read_vault()?;

    let mut password = input::master_password("Master password: ")?;
    let mut vault = match Vault::unlock(&password, &data) {
        Ok(v) => v,
        Err(e) => {
            password.zeroize();
            env_content.zeroize();
            data.zeroize();
            return Err(e);
        }
    };
    password.zeroize();
    data.zeroize();

    let (added, skipped) = vault.import_env(&env_content, overwrite);
    env_content.zeroize();

    if added > 0 {
        let out = vault.serialize()?;
        storage::write_vault_atomic(&out)?;
    }

    eprintln!("Import complete: {added} secret(s) added/updated, {skipped} skipped.");
    Ok(0)
}
