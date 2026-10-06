//! Filesystem operations for the vault: locking and atomic writes.

use crate::error::{Result, SagitarriusError};
use crate::platform;
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Exclusive advisory lock on a lock file next to the vault. Held for the
/// duration of a mutating command. Released automatically on drop.
///
/// The lock is on a separate file (`vault.lock`), not the vault itself, so
/// the vault can be atomically replaced via `rename` without invalidating
/// the lock.
pub struct VaultLock {
    file: File,
    #[allow(dead_code)]
    path: PathBuf,
}

impl VaultLock {
    pub fn acquire() -> Result<Self> {
        let dir = platform::vault_dir()?;
        ensure_dir_perms(&dir)?;
        let path = platform::lock_path()?;
        let mut opts = OpenOptions::new();
        opts.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        #[cfg(unix)]
        tighten_file_permissions(&path)?;
        file.lock_exclusive()
            .map_err(|e| SagitarriusError::Other(format!("could not acquire vault lock: {e}")))?;
        Ok(Self { file, path })
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub fn vault_exists() -> Result<bool> {
    Ok(platform::vault_path()?.exists())
}

/// Directory holding encrypted snapshots (`<id>.json` + `<id>.meta.json`).
pub fn snapshots_dir() -> Result<PathBuf> {
    Ok(platform::vault_dir()?.join("snapshots"))
}

/// Directory holding encrypted backups (same layout as snapshots).
pub fn backups_dir() -> Result<PathBuf> {
    Ok(platform::vault_dir()?.join("backups"))
}

/// Directory holding encrypted file containers (`<hex-id>/` each).
pub fn files_dir() -> Result<PathBuf> {
    Ok(platform::vault_dir()?.join("files"))
}

/// Presence of this file means the vault is in lockdown: decryption
/// operations are refused until `lockdown --off`.
pub fn lockdown_path() -> Result<PathBuf> {
    Ok(platform::vault_dir()?.join("lockdown"))
}

pub fn is_locked_down() -> Result<bool> {
    Ok(lockdown_path()?.exists())
}

pub fn set_lockdown(on: bool) -> Result<()> {
    let path = lockdown_path()?;
    if on {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_file_atomic(&path, b"locked\n")?;
    } else if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Refuse when the vault is in lockdown. Call at the top of every command
/// that decrypts secrets or mutates the vault.
pub fn ensure_unlocked() -> Result<()> {
    if is_locked_down()? {
        return Err(SagitarriusError::Other(
            "vault is in lockdown: decryption is disabled until `sagitarrius lockdown --off`"
                .into(),
        ));
    }
    Ok(())
}

pub fn read_vault() -> Result<Vec<u8>> {
    use crate::vault::READ_MAX_VAULT_FILE_SIZE;
    let path = platform::vault_path()?;
    if !path.exists() {
        return Err(SagitarriusError::NotInitialized);
    }
    let meta = fs::metadata(&path)?;
    if meta.len() > READ_MAX_VAULT_FILE_SIZE {
        return Err(SagitarriusError::Other(format!(
            "vault file too large ({} bytes, max {READ_MAX_VAULT_FILE_SIZE})",
            meta.len()
        )));
    }
    Ok(fs::read(path)?)
}

/// Write `data` atomically to the vault path.
///
/// Steps:
/// 1. Write to a fresh temp file in the same directory.
/// 2. Set restrictive permissions *before* writing the payload.
/// 3. Flush + `sync_all`.
/// 4. `rename` over the destination.
/// 5. Best-effort `sync` the containing directory.
///
/// A crash at any point leaves either the old or the new vault intact.
pub fn write_vault_atomic(data: &[u8]) -> Result<()> {
    // Write-side cap, checked BEFORE anything is modified: an oversized
    // vault errors here with the file untouched (read caps stay higher so
    // the vault can still be opened and shrunk).
    use crate::vault::MAX_VAULT_FILE_SIZE;
    if data.len() as u64 > MAX_VAULT_FILE_SIZE {
        return Err(SagitarriusError::Other(format!(
            "vault too large to write ({} bytes, max {MAX_VAULT_FILE_SIZE}); remove or shrink secrets first",
            data.len()
        )));
    }
    let path = platform::vault_path()?;
    let dir = path
        .parent()
        .ok_or_else(|| SagitarriusError::Other("vault path has no parent".into()))?;
    ensure_dir_perms(dir)?;

    let unique = format!(
        ".vault-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let tmp_path = dir.join(unique);

    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp_path)?;
        if let Err(e) = f.write_all(data).and_then(|_| f.sync_all()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }
    }

    if let Err(e) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    // A pre-existing vault (created by an older version or copied in by hand)
    // may have looser permissions. Tighten to 0600 best-effort.
    #[cfg(unix)]
    let _ = tighten_file_permissions(&path);

    // Best-effort durability of the rename itself.
    #[cfg(unix)]
    if let Ok(dirf) = File::open(dir) {
        let _ = dirf.sync_all();
    }

    Ok(())
}

#[cfg(unix)]
fn tighten_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path)?;
    let mut perms = meta.permissions();
    if perms.mode() & 0o077 != 0 {
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Generic atomic file write: temp file (0600 on unix) in the destination
/// directory + fsync + rename + tighten. Used for snapshots, backups, state
/// and exported plaintext — never follow a destination symlink for the data:
/// `rename` replaces the link itself.
pub fn write_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| SagitarriusError::Other("path has no parent".into()))?;
    ensure_dir_perms(dir)?;

    let unique = format!(
        ".tmp-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let tmp_path = dir.join(unique);

    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp_path)?;
        if let Err(e) = f.write_all(data).and_then(|_| f.sync_all()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    #[cfg(unix)]
    let _ = tighten_file_permissions(path);
    #[cfg(unix)]
    if let Ok(dirf) = File::open(dir) {
        let _ = dirf.sync_all();
    }

    Ok(())
}

/// Persist trusted generation state (no secrets inside; still 0600).
pub fn write_state_atomic(data: &[u8]) -> Result<()> {
    let path = platform::vault_dir()?.join("state.json");
    write_file_atomic(&path, data)
}

/// Create `dir` if missing and protect it — with a conservative split:
///
/// 1. Sagitarrius-managed default directory: always tightened to 0700 on
///    unix (only tightening, never widening). An old default dir with
///    weakened permissions is thereby repaired when safe.
/// 2. Explicitly user-selected custom directory (`SAGITARRIUS_VAULT_DIR`):
///    never chmodded. A pre-existing non-empty custom dir keeps its
///    permissions verbatim; a missing/empty one is created (inheriting the
///    parent's defaults) but not re-permissioned either.
///
/// Nothing here ever recursively chmods user content — only the single
/// directory level Sagitarrius itself manages.
fn ensure_dir_perms(dir: &Path) -> Result<()> {
    let custom = crate::platform::is_custom_dir();
    let pre_existing_nonempty = dir.exists()
        && fs::read_dir(dir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
    fs::create_dir_all(dir)?;
    if custom && pre_existing_nonempty {
        return Ok(());
    }
    set_dir_permissions(dir)?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_permissions(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(dir)?;
    let mut perms = meta.permissions();
    // Only tighten; do not widen.
    if perms.mode() & 0o077 != 0 {
        perms.set_mode(0o700);
        fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_dir: &Path) -> Result<()> {
    // On Windows we rely on the ACL of %APPDATA%\Sagitarrius.
    Ok(())
}

#[cfg(test)]
mod tests {
    // Storage is exercised via `tests/vault.rs` (integration) which uses
    // isolated processes and environment-scoped vault directories.
}
