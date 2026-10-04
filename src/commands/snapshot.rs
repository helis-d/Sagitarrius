//! Encrypted snapshots: fast local history of the complete vault state.
//!
//! Snapshots use the shared [`crate::archive`] container
//! (`<id>/{manifest.json, vault.json, files/...}`), so a snapshot always
//! carries every file container — a File record can never survive while its
//! bytes are lost. Creation needs no password (everything copied is already
//! ciphertext); `verify`/`restore` do.
//!
//! Pre-v3-layout snapshots (`<id>.json` + `<id>.meta.json`, vault bytes
//! only) are still listed, verified and restored — labeled legacy — but new
//! snapshots always use the complete layout.

use crate::archive;
use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage;
use crate::vault::Vault;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Legacy manifest (vault-bytes-only layout, pre-container-format).
#[derive(Debug, Serialize, Deserialize)]
struct LegacyManifest {
    id: String,
    vault_id: String,
    generation: u64,
    format_version: u32,
    created_at: u64,
    sha256: String,
    verified: bool,
}

fn legacy_data(dir: &std::path::Path, id: &str) -> std::path::PathBuf {
    dir.join(format!("{id}.json"))
}

fn legacy_meta(dir: &std::path::Path, id: &str) -> std::path::PathBuf {
    dir.join(format!("{id}.meta.json"))
}

fn has_legacy(dir: &std::path::Path, id: &str) -> bool {
    legacy_data(dir, id).exists() && legacy_meta(dir, id).exists()
}

fn has_archive(dir: &std::path::Path, id: &str) -> bool {
    dir.join(id).join("manifest.json").exists()
}

pub fn create() -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let dir = storage::snapshots_dir()?;
    let id = archive::create_archive(&dir, "snapshot", "snap")?;
    eprintln!("Snapshot {id} recorded (complete: vault + file containers; verify with `snapshot verify {id}`).");
    Ok(0)
}

pub fn list() -> Result<i32> {
    let dir = storage::snapshots_dir()?;
    struct Row {
        id: String,
        gen: String,
        created: u64,
        state: String,
    }
    let mut rows: Vec<Row> = archive::list_archives(&dir)?
        .iter()
        .map(|m| Row {
            id: m.id.clone(),
            gen: m.generation.to_string(),
            created: m.created_at,
            state: if m.verified {
                "verified".into()
            } else {
                "unverified".into()
            },
        })
        .collect();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".meta.json") {
                if has_archive(&dir, id) {
                    continue;
                }
                if let Ok(raw) = std::fs::read(legacy_meta(&dir, id)) {
                    if let Ok(m) = serde_json::from_slice::<LegacyManifest>(&raw) {
                        rows.push(Row {
                            id: m.id,
                            gen: m.generation.to_string(),
                            created: m.created_at,
                            state: "legacy vault-only".into(),
                        });
                    }
                }
            }
        }
    }
    if rows.is_empty() {
        eprintln!("No snapshots. Create one with `sagitarrius snapshot create`.");
        return Ok(0);
    }
    rows.sort_by_key(|r| (r.created, r.id.clone()));
    for r in rows {
        println!("{}  gen={} {} {}", r.id, r.gen, r.created, r.state);
    }
    Ok(0)
}

fn verify_legacy(dir: &std::path::Path, id: &str, password: &str) -> Result<()> {
    let raw = std::fs::read(legacy_meta(dir, id))?;
    let m: LegacyManifest =
        serde_json::from_slice(&raw).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    let bytes = std::fs::read(legacy_data(dir, id))?;
    let mut h = sha2::Sha256::new();
    use sha2::Digest;
    h.update(&bytes);
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if hex != m.sha256 {
        return Err(SagitarriusError::Other(format!(
            "snapshot {id}: sha256 mismatch"
        )));
    }
    let vault = Vault::unlock(password, &bytes)?;
    if vault.vault_id() != m.vault_id && m.vault_id != "v2-legacy" {
        return Err(SagitarriusError::Other(format!(
            "snapshot {id}: vault id mismatch"
        )));
    }
    eprintln!("note: {id} is a legacy vault-only snapshot (no file containers covered)");
    Ok(())
}

pub fn verify(id: Option<String>) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let dir = storage::snapshots_dir()?;
    let ids: Vec<String> = match id {
        Some(id) => vec![id],
        None => archive::list_archives(&dir)?
            .iter()
            .map(|m| m.id.clone())
            .collect(),
    };
    // Legacy ids verify too when explicitly named.
    if ids.is_empty() {
        eprintln!("No snapshots to verify.");
        return Ok(0);
    }
    let mut password = input::master_password("Master password: ")?;
    let mut failed = 0;
    for id in &ids {
        let res = if has_archive(&dir, id) {
            match archive::verify_archive(&dir, id, &password) {
                Ok(m) => {
                    // Mark verified (best effort).
                    let mut m = m;
                    m.verified = true;
                    if let Ok(b) = serde_json::to_vec_pretty(&m) {
                        let _ = storage::write_file_atomic(&dir.join(id).join("manifest.json"), &b);
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else if has_legacy(&dir, id) {
            verify_legacy(&dir, id, &password)
        } else {
            Err(SagitarriusError::Other(format!("snapshot {id} not found")))
        };
        match res {
            Ok(()) => eprintln!("Snapshot {id}: OK"),
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
    archive::check_id(&id)?;
    let dir = storage::snapshots_dir()?;
    // The snapshot may predate a `passwd`: ask for the password that opens
    // *it*, not necessarily today's.
    let mut password =
        input::master_password("Master password for this snapshot (possibly an older one): ")?;

    if has_archive(&dir, &id) {
        let manifest = archive::read_manifest(&dir, &id)?;
        archive::verify_archive(&dir, &id, &password)?;
        let _lock = storage::VaultLock::acquire()?;
        let pre = archive::try_preserve_current()?;
        archive::install_archive(&dir, &manifest)?;
        let live = storage::read_vault()?;
        let vault = Vault::unlock(&password, &live)?;
        password.zeroize();
        // Post-install proof: references AND containers of the live state.
        verify_live_complete(&vault)?;
        crate::state::store_generation(&vault)?;
        eprintln!(
            "Restored snapshot {id} (gen {}).{}",
            manifest.generation,
            match &pre {
                Some(p) => format!(" Pre-restore state kept as {p}."),
                None => String::new(),
            }
        );
        return Ok(0);
    }
    if has_legacy(&dir, &id) {
        verify_legacy(&dir, &id, &password)?;
        let _lock = storage::VaultLock::acquire()?;
        let pre = archive::create_archive(&dir, "snapshot", "pre-restore")?;
        let bytes = std::fs::read(legacy_data(&dir, &id))?;
        storage::write_vault_atomic(&bytes)?;
        let live = storage::read_vault()?;
        let vault = Vault::unlock(&password, &live)?;
        password.zeroize();
        crate::state::store_generation(&vault)?;
        eprintln!("Restored legacy snapshot {id}. Pre-restore state kept as {pre}.");
        return Ok(0);
    }
    password.zeroize();
    Err(SagitarriusError::Other(format!("snapshot {id} not found")))
}

/// Post-restore proof on the LIVE state: every File record resolves to a
/// verified container. Restores that fail here keep their pre-restore copy.
pub(crate) fn verify_live_complete(vault: &Vault) -> Result<()> {
    for name in vault.names() {
        if let Some(crate::vault_v3::RecordPayload::File { file_id, .. }) = vault.get_payload(name)
        {
            let (vmk, vault_id) = match vault {
                Vault::V3(v) => (&v.vmk, v.header.vault_id.clone()),
                Vault::V2(_) => {
                    return Err(SagitarriusError::Other(
                        "file record in v2 vault (unexpected)".into(),
                    ))
                }
            };
            crate::files::verify(vmk, &vault_id, &storage::files_dir()?, &file_id).map_err(
                |e| {
                    SagitarriusError::Other(format!(
                        "restored vault references unverifiable file container for {name:?}: {e}"
                    ))
                },
            )?;
        }
    }
    Ok(())
}

pub fn delete(id: String) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    archive::check_id(&id)?;
    let dir = storage::snapshots_dir()?;
    if has_archive(&dir, &id) {
        std::fs::remove_dir_all(dir.join(&id))?;
    } else if has_legacy(&dir, &id) {
        let _ = std::fs::remove_file(legacy_data(&dir, &id));
        let _ = std::fs::remove_file(legacy_meta(&dir, &id));
    }
    eprintln!("Snapshot {id} deleted (if it existed).");
    Ok(0)
}
