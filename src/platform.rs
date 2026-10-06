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
    default_vault_dir()
}

/// True when the operator explicitly overrode the vault location via
/// `SAGITARRIUS_VAULT_DIR`. Custom directories are never chmodded: they may
/// be shared or deliberately arranged, and Sagitarrius must not re-permission
/// user-chosen paths.
pub fn is_custom_dir() -> bool {
    matches!(std::env::var("SAGITARRIUS_VAULT_DIR"), Ok(ref d) if !d.is_empty())
}

fn default_vault_dir() -> Result<PathBuf> {
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
