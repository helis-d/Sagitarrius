//! Trusted generation state: rollback detection for v3 vaults.
//!
//! AES-GCM proves a vault file is *authentic*, not *current*: an attacker
//! can always replay yesterday's genuine vault. The v3 header therefore
//! carries a `generation` counter (bumped on every mutating write, AAD-bound
//! into every key wrap), and this module keeps the newest generation ever
//! seen in a *separate* state file next to the vault:
//!
//! ```text
//! header.generation < state.generation  ->  STALE, refuse (possible rollback)
//! header.generation > state.generation  ->  heal forward (state write lost)
//! header.generation == state.generation ->  current, proceed
//! ```
//!
//! Honest limitation: an attacker who replaces *both* the vault and the
//! state file consistently is indistinguishable locally. That is what
//! offline backups are for (see `backup`). v2 vaults have no generation;
//! they report "rollback protection unavailable".

use crate::error::{Result, SagitarriusError};
use crate::vault::Vault;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct TrustedState {
    vault_id: String,
    generation: u64,
    /// True once a manifest MAC has been observed for this vault id.
    /// A MAC-less v3 file arriving afterwards is a stripped MAC: refuse.
    #[serde(default)]
    has_manifest_mac: bool,
}

fn state_path() -> Result<std::path::PathBuf> {
    Ok(crate::platform::vault_dir()?.join("state.json"))
}

/// Verify the opened vault against trusted state. No-op for v2.
pub fn verify_generation(vault: &Vault) -> Result<()> {
    if !vault.is_v3() {
        return Ok(());
    }
    let path = state_path()?;
    if !path.exists() {
        // First contact: adopt the current file as trusted.
        return store_generation(vault);
    }
    let raw = std::fs::read(&path)?;
    let state: TrustedState =
        serde_json::from_slice(&raw).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    if state.vault_id != vault.vault_id() {
        // A different vault lives here now (fresh init, restore, or swap):
        // adopt it rather than bricking the user.
        return store_generation(vault);
    }
    if vault.generation() < state.generation {
        return Err(SagitarriusError::Other(format!(
            "vault generation {} is older than trusted generation {} for this vault id — \
             refusing: possible rollback to a stale vault. Restore explicitly with \
             `sagitarrius snapshot restore <id>` or `sagitarrius backup restore <id>`",
            vault.generation(),
            state.generation
        )));
    }
    if vault.generation() > state.generation {
        // Forward heal: a previous state write was lost (crash between the
        // vault rename and the state update). The vault itself is authentic.
        return store_generation(vault);
    }
    if state.has_manifest_mac && vault.is_v3() && !vault.has_manifest_mac() {
        // The vault used to carry a manifest MAC and now does not: someone
        // stripped it (downgrading metadata-integrity to legacy-accept).
        // Fail closed; the way back is an explicit restore.
        return Err(SagitarriusError::Other(
            "vault manifest MAC is missing but trusted state records one — \
             refusing: possible metadata-tamper (stripped manifest MAC). \
             Restore explicitly with `sagitarrius snapshot restore <id>` or \
             `sagitarrius backup restore <id>`"
                .into(),
        ));
    }
    Ok(())
}

/// Persist the vault's current (vault_id, generation) as trusted. Call after
/// every successful mutating write and after restores. No-op for v2.
pub fn store_generation(vault: &Vault) -> Result<()> {
    if !vault.is_v3() {
        return Ok(());
    }
    let state = TrustedState {
        vault_id: vault.vault_id(),
        generation: vault.generation(),
        has_manifest_mac: vault.has_manifest_mac(),
    };
    let bytes = serde_json::to_vec_pretty(&state)?;
    crate::storage::write_state_atomic(&bytes)
}
