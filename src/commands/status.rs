//! Concise security status. Every line reflects a real local check:
//! nothing here is estimated, scored, or theater.
//!
//! `status` never asks for the password and never decrypts: integrity *proof*
//! needs the key, so integrity is reported as unknown-without-unlock and the
//! command points at `snapshot verify`. Everything else (generation vs.
//! trusted state, recovery presence, backup/snapshot inventory, lockdown)
//! is readable from authenticated metadata.

use crate::error::Result;
use crate::storage;

pub fn run() -> Result<i32> {
    let vault_path = crate::platform::vault_path()?;
    if !vault_path.exists() {
        println!("Vault:            NOT INITIALIZED (run `sagitarrius init`)");
        return Ok(1);
    }
    let bytes = storage::read_vault()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    let version = v["header"]["version"].as_u64().unwrap_or(0);
    let vault_id = v["header"]["vault_id"].as_str().unwrap_or("v2-legacy");
    let generation = v["header"]["generation"].as_u64().unwrap_or(0);
    let has_recovery = v["header"]["wraps"]
        .as_array()
        .map(|w| w.iter().any(|e| e["kind"] == "recovery"))
        .unwrap_or(false);

    // Trusted state comparison (metadata only, no decryption).
    let state_path = crate::platform::vault_dir()?.join("state.json");
    let rollback = if version == 3 {
        if !state_path.exists() {
            "UNKNOWN (no trusted state yet)".to_string()
        } else {
            match std::fs::read(&state_path)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            {
                Some(s)
                    if s["vault_id"] == vault_id
                        && s["generation"].as_u64().unwrap_or(0) == generation =>
                {
                    format!("CURRENT (gen {generation})")
                }
                Some(s) if s["vault_id"] != vault_id => {
                    "UNKNOWN (different vault id than trusted state)".to_string()
                }
                Some(s) => format!(
                    "STALE? header gen {generation} vs trusted {}",
                    s["generation"].as_u64().unwrap_or(0)
                ),
                None => "UNKNOWN (unreadable state file)".to_string(),
            }
        }
    } else {
        "UNAVAILABLE (v2 format — run `migrate`)".to_string()
    };

    let snapshots = crate::archive::list_archives(&storage::snapshots_dir()?)?;
    let backups = crate::archive::list_archives(&storage::backups_dir()?)?;
    let snap_line = match snapshots.iter().max_by_key(|m| m.created_at) {
        Some(m) => format!(
            "{} present, latest {} ({})",
            snapshots.len(),
            m.id,
            if m.verified { "verified" } else { "unverified" }
        ),
        None => "none".to_string(),
    };
    let backup_line = match backups.iter().max_by_key(|m| m.created_at) {
        Some(m) => format!(
            "{} local, latest {} ({})",
            backups.len(),
            m.id,
            if m.verified { "verified" } else { "unverified" }
        ),
        None => "none".to_string(),
    };
    let locked = storage::is_locked_down()?;

    println!("Vault integrity:  UNKNOWN WITHOUT UNLOCK (run `snapshot verify` for proof)");
    println!("Format:           v{version}");
    println!("Trusted state:    {rollback}");
    println!(
        "Recovery:         {}",
        if has_recovery {
            "READY (recovery wrap present)"
        } else if version == 3 {
            "MISSING (run `recovery create`)"
        } else {
            "UNAVAILABLE (v2 format — run `migrate`)"
        }
    );
    println!("Snapshots:        {snap_line}");
    println!(
        "Backups:          {backup_line} (same-disk copies are history, not ransomware protection)"
    );
    println!(
        "Lockdown:         {}",
        if locked {
            "ENABLED (decryption refused)"
        } else {
            "off"
        }
    );
    Ok(0)
}
