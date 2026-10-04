//! Encrypted backups: complete recoverable state aimed at offline media.
//!
//! Same container as snapshots (`<id>/{manifest.json, vault.json,
//! files/...}`) — every backup carries all referenced file containers, and
//! verification covers all of them. A backup on the *same* writable disk is
//! version history, not ransomware protection: use `--to` an external or
//! offline destination and `verify` regularly. The CLI cannot make a
//! filesystem immutable; it makes safe copies easy and verification routine.

use crate::archive;
use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage;
use crate::vault::Vault;
use std::path::PathBuf;
use zeroize::Zeroize;

fn local_dir() -> Result<PathBuf> {
    storage::backups_dir()
}

pub fn create(to: Option<String>) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let dir = match to {
        Some(d) => PathBuf::from(&d),
        None => local_dir()?,
    };
    let id = archive::create_archive(&dir, "backup", "backup")?;
    eprintln!(
        "Backup {id} written (complete: vault + file containers). Verify it with `backup verify {id}` — \
         ideally after moving it offline."
    );
    Ok(0)
}

pub fn list() -> Result<i32> {
    // External destinations are not enumerated (they may be offline).
    let all = archive::list_archives(&local_dir()?)?;
    if all.is_empty() {
        eprintln!("No local backups. Create one with `sagitarrius backup create`.");
        return Ok(0);
    }
    for m in all {
        println!(
            "{}  gen={} vault={} v{} {} {} ({} file container(s))",
            m.id,
            m.generation,
            &m.vault_id[..m.vault_id.len().min(12)],
            m.vault_format,
            m.created_at,
            if m.verified { "verified" } else { "unverified" },
            m.files.len()
        );
    }
    Ok(0)
}

pub fn verify(id: Option<String>, from: Option<String>) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let dir = match from {
        Some(d) => PathBuf::from(&d),
        None => local_dir()?,
    };
    let ids: Vec<String> = match id {
        Some(id) => vec![id],
        None => archive::list_archives(&dir)?
            .iter()
            .map(|m| m.id.clone())
            .collect(),
    };
    if ids.is_empty() {
        eprintln!("No backups to verify.");
        return Ok(0);
    }
    let mut password = input::master_password("Master password: ")?;
    let mut failed = 0;
    for id in &ids {
        match archive::verify_archive(&dir, id, &password) {
            Ok(m) => {
                eprintln!(
                    "Backup {id}: OK (vault + {} file container(s))",
                    m.files.len()
                );
                let mut m = m;
                m.verified = true;
                if let Ok(b) = serde_json::to_vec_pretty(&m) {
                    let _ = storage::write_file_atomic(&dir.join(id).join("manifest.json"), &b);
                }
            }
            Err(e) => {
                eprintln!("Backup {id}: FAILED ({e})");
                failed += 1;
            }
        }
    }
    password.zeroize();
    Ok(if failed == 0 { 0 } else { 1 })
}

pub fn restore(id: String, from: Option<String>) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    archive::check_id(&id)?;
    let dir = match from {
        Some(d) => PathBuf::from(&d),
        None => local_dir()?,
    };
    // The backup may predate a `passwd`: ask for the password that opens it.
    let mut password =
        input::master_password("Master password for this backup (possibly an older one): ")?;
    let manifest = archive::read_manifest(&dir, &id)?;
    archive::verify_archive(&dir, &id, &password)?;

    let _lock = storage::VaultLock::acquire()?;
    let pre = archive::try_preserve_current()?;
    archive::install_archive(&dir, &manifest)?;

    let live = storage::read_vault()?;
    let vault = match Vault::unlock(&password, &live) {
        Ok(v) => v,
        Err(e) => {
            password.zeroize();
            return Err(e);
        }
    };
    password.zeroize();
    // Post-install proof on the LIVE state (references + containers).
    crate::commands::snapshot::verify_live_complete(&vault).map_err(|e| {
        let kept = pre
            .as_deref()
            .map(|p| format!("pre-restore kept as {p}"))
            .unwrap_or_else(|| "no live state existed to preserve".to_string());
        SagitarriusError::Other(format!("restored state incomplete, {kept}: {e}"))
    })?;
    crate::state::store_generation(&vault)?;
    eprintln!(
        "Restored backup {id} (gen {}, {} file container(s)).{}",
        manifest.generation,
        manifest.files.len(),
        match &pre {
            Some(p) => format!(" Pre-restore state kept as snapshot {p}."),
            None => String::new(),
        }
    );
    Ok(0)
}

pub fn prune(keep: usize) -> Result<i32> {
    // Deleting backups destroys recovery options: gate on lockdown too.
    crate::storage::ensure_unlocked()?;
    let dir = local_dir()?;
    let mut entries = archive::list_archives(&dir)?;
    if entries.len() <= keep {
        eprintln!("{} backup(s), keeping all (keep={keep}).", entries.len());
        return Ok(0);
    }
    entries.sort_by_key(|m| (m.created_at, m.id.clone()));
    for m in entries.iter().take(entries.len() - keep) {
        std::fs::remove_dir_all(dir.join(&m.id))?;
        eprintln!("Deleted backup {}.", m.id);
    }
    Ok(0)
}
