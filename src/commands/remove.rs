use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run(name: String, yes: bool) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let _lock = VaultLock::acquire()?;
    let mut data = storage::read_vault()?;

    let mut password = input::master_password("Master password: ")?;
    let mut vault = match Vault::unlock(&password, &data) {
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

    if !vault.exists(&name) {
        return Err(SagitarriusError::SecretNotFound(name));
    }

    if !yes && !input::confirm(&format!("Remove secret {name:?}? [y/N] "))? {
        eprintln!("Cancelled.");
        return Ok(0);
    }

    // File records own an on-disk container: drop it with the record so no
    // orphaned ciphertext lingers.
    let file_id = match vault.get_payload(&name) {
        Some(crate::vault_v3::RecordPayload::File { file_id, .. }) => Some(file_id),
        _ => None,
    };
    vault.remove(&name);
    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;
    crate::state::store_generation(&vault)?;
    if let Some(fid) = file_id {
        if let Err(e) = crate::files::remove(&storage::files_dir()?, &fid) {
            eprintln!("Warning: record removed but file container cleanup failed: {e}");
        }
    }

    eprintln!("Secret {name:?} removed.");
    Ok(0)
}
