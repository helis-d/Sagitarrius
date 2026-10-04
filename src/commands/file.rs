//! Encrypted file records: chunked authenticated containers on disk +
//! a `File` record holding identity and integrity metadata.
//!
//! `file put` encrypts in 64 KiB chunks (random per-file nonce prefix +
//! counter, per-chunk AAD, SHA-256 cross-check). `file get` verifies before
//! writing the destination atomically and refuses symlink destinations.

use crate::envelope::VaultMasterKey;
use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use crate::vault_v3::RecordPayload;
use std::path::PathBuf;
use zeroize::Zeroize;

fn v3_parts(vault: &Vault) -> Result<(&VaultMasterKey, &str)> {
    match vault {
        Vault::V3(v) => Ok((&v.vmk, &v.header.vault_id)),
        Vault::V2(_) => Err(SagitarriusError::Other(
            "file records need vault format v3; run `sagitarrius migrate` first".into(),
        )),
    }
}

pub fn put(path: String, name: Option<String>) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let src = PathBuf::from(&path);
    let name = name.unwrap_or_else(|| {
        src.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into())
    });
    crate::vault::validate_secret_name(&name)?;

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

    if vault.exists(&name) {
        return Err(SagitarriusError::SecretAlreadyExists(name));
    }
    let (vmk, vault_id) = v3_parts(&vault)?;
    let files_dir = storage::files_dir()?;
    let filename = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (file_id, size, sha256, chunks) = crate::files::put(vmk, vault_id, &files_dir, &src)?;
    let payload = RecordPayload::File {
        file_id: file_id.clone(),
        filename,
        size,
        sha256,
        chunks,
    };
    if let Err(e) = vault.set_typed(&name, payload) {
        let _ = crate::files::remove(&files_dir, &file_id);
        return Err(e);
    }
    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;
    crate::state::store_generation(&vault)?;
    eprintln!("File stored as {name:?} ({size} bytes, {chunks} chunks).");
    Ok(0)
}

pub fn get(name: String, dest: String) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let dest = PathBuf::from(&dest);
    let data = storage::read_vault()?;
    let mut password = input::master_password("Master password: ")?;
    let vault = match Vault::unlock(&password, &data) {
        Ok(v) => v,
        Err(e) => {
            password.zeroize();
            return Err(e);
        }
    };
    password.zeroize();
    crate::state::verify_generation(&vault)?;

    let Some(payload) = vault.get_payload(&name) else {
        return Err(SagitarriusError::SecretNotFound(name));
    };
    let crate::vault_v3::RecordPayload::File { file_id, size, .. } = payload else {
        return Err(SagitarriusError::Other(format!(
            "{name:?} is not a file record (use `sagitarrius get`)"
        )));
    };
    let (vmk, vault_id) = v3_parts(&vault)?;
    let wrote = crate::files::get_to(vmk, vault_id, &storage::files_dir()?, &file_id, &dest)?;
    eprintln!("Wrote {wrote} bytes (verified, {size} expected).");
    Ok(0)
}
