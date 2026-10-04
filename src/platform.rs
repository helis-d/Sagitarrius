//! OS-appropriate vault locations.
//!
//! `SAGITARRIUS_VAULT_DIR` overrides the default (useful for tests and
//! portable installs).

use crate::error::{Result, SagitarriusError};
use directories::ProjectDirs;
use std::path::PathBuf;

pub fn vault_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("SAGITARRIUS_VAULT_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let dirs = ProjectDirs::from("dev", "sagitarrius", "sagitarrius")
        .ok_or_else(|| SagitarriusError::Other("could not determine data directory".into()))?;
    Ok(dirs.data_dir().to_path_buf())
}

pub fn vault_path() -> Result<PathBuf> {
    Ok(vault_dir()?.join("vault.json"))
}

pub fn lock_path() -> Result<PathBuf> {
    Ok(vault_dir()?.join(".vault.lock"))
}
