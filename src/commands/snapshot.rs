//! Encrypted snapshots: versioned local history of the vault file.
//!
//! A snapshot is a byte copy of `vault.json` (still encrypted) plus a JSON
//! manifest. Copies never decrypt anything, so `create`/`list` need no
//! password; `verify`/`restore` do. Every restore first snapshots the current
//! vault, so a bad restore is itself recoverable.

use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage;
use crate::vault::Vault;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub vault_id: String,
    pub generation: u64,
    pub format_version: u32,
    pub created_at: u64,
    pub sha256: String, // of the snapshot bytes
    pub verified: bool,
}

pub fn new_id(prefix: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut r = [0u8; 3];
    rand::thread_rng().fill_bytes(&mut r);
    format!(
        "{prefix}-{now}-{r:02x}{r2:02x}{r3:02x}",
        r = r[0],
        r2 = r[1],
        r3 = r[2]
    )
}

fn sha_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn meta_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.meta.json"))
}

fn data_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

fn check_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(SagitarriusError::Other("invalid snapshot id".into()));
    }
    Ok(())
}

/// Describe the current vault file without decrypting it.
fn describe_current() -> Result<(Vec<u8>, String, u64, u32)> {
    let bytes = storage::read_vault()?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    let h = &v["header"];
    let vault_id = h["vault_id"].as_str().unwrap_or("v2-legacy").to_string();
    let generation = h["generation"].as_u64().unwrap_or(0);
    let version = h["version"].as_u64().unwrap_or(0) as u32;
    Ok((bytes, vault_id, generation, version))
}

/// Store an encrypted copy + manifest into `dir`. Returns the snapshot id.
pub(crate) fn store_copy(dir: &Path, prefix: &str) -> Result<String> {
    std::fs::create_dir_all(dir)?;
    let (bytes, vault_id, generation, version) = describe_current()?;
    let id = new_id(prefix);
    storage::write_file_atomic(&data_path(dir, &id), &bytes)?;
    let manifest = Manifest {
        id: id.clone(),
        vault_id,
        generation,
        format_version: version,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        sha256: sha_hex(&bytes),
        verified: false,
    };
    let mbytes = serde_json::to_vec_pretty(&manifest)?;
    storage::write_file_atomic(&meta_path(dir, &id), &mbytes)?;
    Ok(id)
}

pub(crate) fn read_manifest(dir: &Path, id: &str) -> Result<Manifest> {
    check_id(id)?;
    let raw = std::fs::read(meta_path(dir, id))?;
    serde_json::from_slice(&raw).map_err(|_| SagitarriusError::InvalidVaultFormat)
}

pub(crate) fn list_entries(dir: &Path) -> Result<Vec<Manifest>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(id) = name.strip_suffix(".meta.json") {
            if let Ok(m) = read_manifest(dir, id) {
                out.push(m);
            }
        }
    }
    out.sort_by_key(|m| (m.created_at, m.id.clone()));
    Ok(out)
}

/// Verify bytes against their manifest (hash + openability with password).
fn verify_bytes(id: &str, bytes: &[u8], manifest: &Manifest, password: &str) -> Result<()> {
    if sha_hex(bytes) != manifest.sha256 {
        return Err(SagitarriusError::Other(format!(
            "snapshot {id}: sha256 mismatch — file corrupted or replaced"
        )));
    }
    // Full unlock proves the copy is a usable vault, not just intact bytes.
    let vault = Vault::unlock(password, bytes)?;
    // Cross-check identity: a manifest swapped onto foreign bytes must fail.
    if vault.vault_id() != manifest.vault_id && manifest.vault_id != "v2-legacy" {
        return Err(SagitarriusError::Other(format!(
            "snapshot {id}: vault id mismatch — manifest does not belong to these bytes"
        )));
    }
    let _ = vault;
    Ok(())
}

pub fn create() -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let dir = storage::snapshots_dir()?;
    let id = store_copy(&dir, "snap")?;
    eprintln!("Snapshot {id} recorded (encrypted; verify with `snapshot verify {id}`).");
    Ok(0)
}

pub fn list() -> Result<i32> {
    let dir = storage::snapshots_dir()?;
    let entries = list_entries(&dir)?;
    if entries.is_empty() {
        eprintln!("No snapshots. Create one with `sagitarrius snapshot create`.");
        return Ok(0);
    }
    for m in entries {
        println!(
            "{}  gen={} vault={} v{} {} {}",
            m.id,
            m.generation,
            &m.vault_id[..m.vault_id.len().min(12)],
            m.format_version,
            m.created_at,
            if m.verified { "verified" } else { "unverified" }
        );
    }
    Ok(0)
}

pub fn verify(id: Option<String>) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let dir = storage::snapshots_dir()?;
    let ids: Vec<String> = match id {
        Some(id) => vec![id],
        None => list_entries(&dir)?.iter().map(|m| m.id.clone()).collect(),
    };
    if ids.is_empty() {
        eprintln!("No snapshots to verify.");
        return Ok(0);
    }
    let mut password = input::master_password("Master password: ")?;
    let mut failed = 0;
    for id in ids {
        let manifest = read_manifest(&dir, &id)?;
        let bytes = std::fs::read(data_path(&dir, &id))?;
        match verify_bytes(&id, &bytes, &manifest, &password) {
            Ok(()) => {
                eprintln!("Snapshot {id}: OK");
                // Mark verified in the manifest (best effort).
                let mut m = manifest;
                m.verified = true;
                if let Ok(mbytes) = serde_json::to_vec_pretty(&m) {
                    let _ = storage::write_file_atomic(&meta_path(&dir, &id), &mbytes);
                }
            }
            Err(e) => {
                eprintln!("Snapshot {id}: FAILED ({e})");
                failed += 1;
            }
        }
    }
    password.zeroize();
    Ok(if failed == 0 { 0 } else { 1 })
}

pub fn restore(id: String) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let dir = storage::snapshots_dir()?;
    let manifest = read_manifest(&dir, &id)?;
    let bytes = std::fs::read(data_path(&dir, &id))?;

    // The snapshot may predate a `passwd`: ask for the password that opens
    // *it*, not necessarily today's.
    let mut password =
        input::master_password("Master password for this snapshot (possibly an older one): ")?;
    // The copy must open BEFORE it touches the live vault.
    verify_bytes(&id, &bytes, &manifest, &password)?;

    // Safety net: snapshot the present first.
    let _lock = storage::VaultLock::acquire()?;
    let pre = store_copy(&dir, "pre-restore")?;
    storage::write_vault_atomic(&bytes)?;

    // Adopt the restored generation as trusted, then re-verify live.
    let live = storage::read_vault()?;
    let vault = Vault::unlock(&password, &live)?;
    password.zeroize();
    crate::state::store_generation(&vault)?;
    eprintln!(
        "Restored snapshot {id} (gen {}). Pre-restore state kept as {pre}.",
        manifest.generation
    );
    Ok(0)
}

pub fn delete(id: String) -> Result<i32> {
    check_id(&id)?;
    let dir = storage::snapshots_dir()?;
    let _ = std::fs::remove_file(data_path(&dir, &id));
    let _ = std::fs::remove_file(meta_path(&dir, &id));
    eprintln!("Snapshot {id} deleted (if it existed).");
    Ok(0)
}
