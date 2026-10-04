//! Complete backup objects: vault + every referenced file container.
//!
//! Layout (format version 1 — bump on any change, reject unknown):
//!
//! ```text
//! <base>/<id>/
//!   manifest.json            full inventory + hashes (no plaintext secrets)
//!   vault.json               encrypted vault bytes
//!   files/<file-id>/        one encrypted container per File record
//!     manifest.json
//!     chunk-00000000 ...
//! ```
//!
//! Snapshots (local history) and backups (offline-bound) share this layout
//! and these routines; only the base directory differs. Creation needs no
//! password (everything copied is already ciphertext); verification and
//! restore do. A backup is complete or it does not exist: any missing or
//! mismatched object fails the whole operation closed.

use crate::error::{Result, SagitarriusError};
use crate::vault::Vault;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Backup container format version. Unknown versions are rejected, never
/// reinterpreted.
pub const ARCHIVE_FORMAT: u32 = 1;
const ARCHIVE_MAGIC: &str = "sagitarrius-backup";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRef {
    pub file_id: String,
    pub size: u64,
    pub sha256: String,
    pub chunks: u64,
    /// sha256(manifest bytes || chunk bytes in index order).
    pub container_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub format: String,
    pub archive_format: u32,
    pub kind: String, // "snapshot" | "backup"
    pub id: String,
    pub vault_id: String,
    pub generation: u64,
    pub vault_format: u32,
    pub created_at: u64,
    pub vault_sha256: String,
    pub files: Vec<FileRef>,
    pub verified: bool,
}

pub fn new_id(prefix: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut r = [0u8; 3];
    rand::thread_rng().fill_bytes(&mut r);
    format!("{prefix}-{now}-{:02x}{:02x}{:02x}", r[0], r[1], r[2])
}

pub fn check_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(SagitarriusError::Other("invalid archive id".into()));
    }
    Ok(())
}

fn sha_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn archive_dir(base: &Path, id: &str) -> PathBuf {
    base.join(id)
}

/// Refuse symlinks anywhere inside copied trees: a planted link could make
/// verification read (or restore write) outside the container.
fn ensure_no_symlink(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(SagitarriusError::Other(format!(
            "refusing symlink inside backup object: {}",
            path.display()
        )));
    }
    Ok(())
}

fn copy_dir_clean(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        ensure_no_symlink(&from)?;
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir_clean(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

fn hash_container(dir: &Path, chunks: u64) -> Result<String> {
    let mut h = Sha256::new();
    let mbytes = std::fs::read(dir.join("manifest.json"))?;
    if mbytes.len() > 64 * 1024 {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    h.update(&mbytes);
    for index in 0..chunks {
        let name = format!("chunk-{index:08}");
        let p = dir.join(&name);
        ensure_no_symlink(&p)?;
        let ct = std::fs::read(&p)?;
        if ct.len() > crate::files::FILE_CHUNK_SIZE + 32 {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        h.update(&ct);
    }
    // No extra files allowed: anything unexpected fails the container.
    let mut seen = chunks as usize + 1; // chunks + manifest
    for entry in std::fs::read_dir(dir)? {
        let _ = entry?;
        seen -= 1;
    }
    if seen != 0 {
        return Err(SagitarriusError::Other(
            "file container has unexpected extra files".into(),
        ));
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Create a complete archive of the current state. Fails closed when any
/// referenced file container is missing or inconsistent.
pub fn create_archive(base: &Path, kind: &str, prefix: &str) -> Result<String> {
    let vault_bytes = crate::storage::read_vault()?;
    // Structural parse first (cheap, no key): version/vault_id/generation.
    let v: serde_json::Value =
        serde_json::from_slice(&vault_bytes).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    let vault_id = v["header"]["vault_id"].as_str().unwrap_or("v2-legacy");
    let generation = v["header"]["generation"].as_u64().unwrap_or(0);
    let vault_format = v["header"]["version"].as_u64().unwrap_or(0) as u32;
    if vault_format != 2 && vault_format != 3 {
        return Err(SagitarriusError::UnsupportedVersion(vault_format));
    }

    let id = new_id(prefix);
    let tmp = base.join(format!(".tmp-{id}"));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    // Best effort cleanup on failure: never leave a half-written object that
    // looks complete.
    let build = || -> Result<ArchiveManifest> {
        std::fs::write(tmp.join("vault.json"), &vault_bytes)?;
        let mut refs = Vec::new();
        // Inventory every live container. Orphans (interrupted puts) are
        // faithfully inventoried; verify-time cross-check against the vault
        // decides what matters. Missing containers fail below.
        let files_dir = crate::storage::files_dir()?;
        if files_dir.exists() {
            for entry in std::fs::read_dir(&files_dir)? {
                let entry = entry?;
                let fid = entry.file_name().to_string_lossy().into_owned();
                if fid.len() != 32 || !fid.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue; // stray directory: not our container, ignore at rest
                }
                let cdir = entry.path();
                ensure_no_symlink(&cdir)?;
                let mbytes = std::fs::read(cdir.join("manifest.json"))?;
                let m: serde_json::Value = serde_json::from_slice(&mbytes)
                    .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
                let chunks = m["chunks"]
                    .as_u64()
                    .ok_or(SagitarriusError::InvalidVaultFormat)?;
                let container_sha = hash_container(&cdir, chunks)?;
                copy_dir_clean(&cdir, &tmp.join("files").join(&fid))?;
                refs.push(FileRef {
                    file_id: fid,
                    size: m["size"].as_u64().unwrap_or(0),
                    sha256: m["sha256"].as_str().unwrap_or("").to_string(),
                    chunks,
                    container_sha256: container_sha,
                });
            }
        }
        Ok(ArchiveManifest {
            format: ARCHIVE_MAGIC.into(),
            archive_format: ARCHIVE_FORMAT,
            kind: kind.into(),
            id: id.clone(),
            vault_id: vault_id.into(),
            generation,
            vault_format,
            created_at: now_ts(),
            vault_sha256: sha_hex(&vault_bytes),
            files: refs,
            verified: false,
        })
    };
    let manifest = match build() {
        Ok(m) => m,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(e);
        }
    };
    let mbytes = serde_json::to_vec_pretty(&manifest)?;
    std::fs::write(tmp.join("manifest.json"), &mbytes)?;
    std::fs::rename(&tmp, archive_dir(base, &id))?;
    Ok(id)
}

/// Best-effort pre-restore safety net. Returns the snapshot id, or None
/// when there is nothing worth preserving: no vault file at all, or a vault
/// file so destroyed it does not even parse (a ransomware-garbled vault
/// must not block its own replacement — the verified backup is the way
/// back, and it was checked before anything was touched).
pub fn try_preserve_current() -> Result<Option<String>> {
    if !crate::storage::vault_exists()? {
        eprintln!("note: no live vault present, nothing to preserve");
        return Ok(None);
    }
    let raw = crate::storage::read_vault()?;
    if serde_json::from_slice::<serde_json::Value>(&raw).is_err() {
        eprintln!("note: live vault is unparseable (destroyed?), nothing to preserve");
        return Ok(None);
    }
    Ok(Some(create_archive(
        &crate::storage::snapshots_dir()?,
        "snapshot",
        "pre-restore",
    )?))
}

pub fn read_manifest(base: &Path, id: &str) -> Result<ArchiveManifest> {
    check_id(id)?;
    let raw = std::fs::read(archive_dir(base, id).join("manifest.json"))?;
    if raw.len() > 1024 * 1024 {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let m: ArchiveManifest =
        serde_json::from_slice(&raw).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    if m.format != ARCHIVE_MAGIC || m.id != id {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    if m.archive_format != ARCHIVE_FORMAT {
        return Err(SagitarriusError::UnsupportedVersion(m.archive_format));
    }
    Ok(m)
}

pub fn list_archives(base: &Path) -> Result<Vec<ArchiveManifest>> {
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(base)? {
        let entry = entry?;
        if !entry.path().is_dir() || entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        if let Ok(m) = read_manifest(base, &id) {
            out.push(m);
        }
    }
    out.sort_by_key(|m| (m.created_at, m.id.clone()));
    Ok(out)
}

/// Full verification: manifest -> vault bytes -> unlock -> record/file
/// cross-check -> every container (chunks + hash). Reports VERIFIED only
/// when the entire recoverable state is valid.
pub fn verify_archive(base: &Path, id: &str, password: &str) -> Result<ArchiveManifest> {
    let manifest = read_manifest(base, id)?;
    let dir = archive_dir(base, id);
    let vault_bytes = std::fs::read(dir.join("vault.json"))?;
    if sha_hex(&vault_bytes) != manifest.vault_sha256 {
        return Err(SagitarriusError::Other(format!(
            "{id}: vault bytes hash mismatch"
        )));
    }
    let vault = Vault::unlock(password, &vault_bytes)?;
    if vault.vault_id() != manifest.vault_id && manifest.vault_id != "v2-legacy" {
        return Err(SagitarriusError::Other(format!("{id}: vault id mismatch")));
    }
    // Every File record must have a matching, valid container. Manifest
    // containers unreferenced by the vault (interrupted puts) are tolerated
    // with a warning: the dangerous direction is a MISSING container.
    let mut expected: std::collections::BTreeMap<String, (String, u64, String, u64)> =
        std::collections::BTreeMap::new();
    for name in vault.names() {
        if let Some(crate::vault_v3::RecordPayload::File {
            file_id,
            size,
            sha256,
            chunks,
            ..
        }) = vault.get_payload(name)
        {
            expected.insert(file_id, (name.to_string(), size, sha256, chunks));
        }
    }
    let mut orphans = 0;
    for fr in &manifest.files {
        if !expected.contains_key(&fr.file_id) {
            orphans += 1;
            continue;
        }
        let (_, size, sha, chunks) = &expected[&fr.file_id];
        if *size != fr.size || *sha != fr.sha256 || *chunks != fr.chunks {
            return Err(SagitarriusError::Other(format!(
                "{id}: container {} metadata mismatch vs vault record",
                fr.file_id
            )));
        }
        // Full cryptographic check of the archived container.
        verify_archived_container(&dir, &vault, fr)?;
    }
    // Now the other direction: every vault reference must exist.
    let mut missing = Vec::new();
    for (fid, (name, _, _, _)) in &expected {
        if !manifest.files.iter().any(|fr| &fr.file_id == fid) {
            missing.push(format!("{name} -> {fid}"));
        }
    }
    if !missing.is_empty() {
        return Err(SagitarriusError::Other(format!(
            "{id}: backup is INCOMPLETE, {} referenced container(s) missing: {}",
            missing.len(),
            missing.join(", ")
        )));
    }
    if orphans > 0 {
        eprintln!(
            "warning: {id} holds {orphans} unreferenced container(s) (interrupted puts); ignored"
        );
    }
    Ok(manifest)
}

fn verify_archived_container(archive: &Path, vault: &Vault, fr: &FileRef) -> Result<()> {
    let cdir = archive.join("files").join(&fr.file_id);
    let mbytes = std::fs::read(cdir.join("manifest.json"))?;
    let m: serde_json::Value =
        serde_json::from_slice(&mbytes).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    if m["file_id"] != fr.file_id.as_str()
        || m["chunks"].as_u64() != Some(fr.chunks)
        || m["size"].as_u64() != Some(fr.size)
        || m["sha256"] != fr.sha256.as_str()
    {
        return Err(SagitarriusError::Other(format!(
            "container {} manifest mismatch",
            fr.file_id
        )));
    }
    if hash_container(&cdir, fr.chunks)? != fr.container_sha256 {
        return Err(SagitarriusError::Other(format!(
            "container {} content mismatch",
            fr.file_id
        )));
    }
    // Authenticate every chunk under the vault key (proves recoverability,
    // not just intact copying). Streaming: plaintext is hashed and dropped.
    let (vmk, vault_id) = match vault {
        Vault::V3(v) => (&v.vmk, v.header.vault_id.clone()),
        Vault::V2(_) => return Ok(()), // v2 archives carry no files by construction
    };
    crate::files::verify(vmk, &vault_id, &archive.join("files"), &fr.file_id)?;
    Ok(())
}

/// Install a verified archive as the live state: vault bytes + the exact
/// container set (stale live containers for unreferenced ids are removed so
/// no orphaned ciphertext lingers, and no foreign container survives).
/// Caller must verify first, snapshot the present first, and re-verify
/// after; this function only performs the file operations. Not atomic across
/// vault + containers (documented): an interruption can leave extra
/// containers, never a new vault with holes — containers land first.
pub fn install_archive(base: &Path, manifest: &ArchiveManifest) -> Result<()> {
    let dir = archive_dir(base, &manifest.id);
    let vault_bytes = std::fs::read(dir.join("vault.json"))?;
    if sha_hex(&vault_bytes) != manifest.vault_sha256 {
        return Err(SagitarriusError::Other(
            "archive vault bytes changed".into(),
        ));
    }
    // Containers first (vault last, so an interruption leaves the old vault
    // with extra-but-harmless containers rather than a new vault with holes).
    let live_files = crate::storage::files_dir()?;
    std::fs::create_dir_all(&live_files)?;
    let mut wanted: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for fr in &manifest.files {
        wanted.insert(fr.file_id.clone());
        let src = dir.join("files").join(&fr.file_id);
        ensure_no_symlink(&src)?;
        let stage = live_files.join(format!(".stage-{}", fr.file_id));
        let _ = std::fs::remove_dir_all(&stage);
        copy_dir_clean(&src, &stage)?;
        let dest = live_files.join(&fr.file_id);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::rename(&stage, &dest)?;
    }
    // Drop live containers the restored vault does not reference.
    if live_files.exists() {
        for entry in std::fs::read_dir(&live_files)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".stage-") || name.starts_with(".tmp-") {
                let _ = std::fs::remove_dir_all(entry.path());
                continue;
            }
            if !wanted.contains(&name) {
                std::fs::remove_dir_all(entry.path())?;
            }
        }
    }
    crate::storage::write_vault_atomic(&vault_bytes)?;
    Ok(())
}
