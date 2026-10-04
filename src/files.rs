//! Chunked authenticated file containers with bounded memory.
//!
//! streaming model (never a whole file in RAM):
//!
//! ```text
//! put:    read 64 KiB -> hash -> encrypt -> write chunk -> repeat
//! get:    read chunk -> authenticate/decrypt -> write temp -> rename
//! verify: read chunk -> authenticate/decrypt -> hash -> drop
//! ```
//!
//! Each file gets a random 32-bit nonce prefix; chunk `i` uses nonce
//! `prefix || be64(i)` (unique per (file key, chunk) by construction).
//! Per-chunk AAD binds vault id, file id, index, total and version, so
//! reordering, truncation, duplication or cross-file swaps fail closed.
//! A SHA-256 over the plaintext cross-checks the stream end to end.
//!
//! Containers live under `<vault_dir>/files/<hex-id>/` as `manifest.json`
//! plus `chunk-00000000…`. Staging goes through `.stage-<id>` + rename, so
//! an interrupted `put` leaves no partial container behind.

use crate::crypto::{self};
use crate::envelope::{VaultMasterKey, LABEL_FILE};
use crate::error::{Result, SagitarriusError};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const FILE_CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;
/// Manifest cap: metadata only, never content.
const MAX_MANIFEST_SIZE: usize = 64 * 1024;
const CONTAINER_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    version: u32,
    file_id: String,      // hex
    nonce_prefix: String, // base64(4 bytes)
    chunks: u64,
    size: u64,
    sha256: String, // hex of plaintext
    filename: String,
}

fn file_key(vmk: &VaultMasterKey, vault_id_b64: &str, file_id_hex: &str) -> crypto::DerivedKey {
    let salt = B64.decode(vault_id_b64).unwrap_or_default();
    let info = format!("{LABEL_FILE}/{file_id_hex}");
    vmk.derive_subkey(&salt, &info)
}

fn chunk_aad(vault_id: &str, file_id: &str, index: u64, total: u64) -> Vec<u8> {
    format!("SAGITARRIUS/v3/file-chunk|{vault_id}|{file_id}|{index}/{total}|{CONTAINER_VERSION}")
        .into_bytes()
}

fn chunk_nonce(prefix: &[u8; 4], index: u64) -> [u8; crypto::NONCE_LEN] {
    let mut n = [0u8; crypto::NONCE_LEN];
    n[..4].copy_from_slice(prefix);
    n[4..].copy_from_slice(&index.to_be_bytes());
    n
}

fn container_dir(files_dir: &Path, file_id_hex: &str) -> PathBuf {
    files_dir.join(file_id_hex)
}

/// file_id values travel in paths: strict hex, fixed length, no separators.
pub fn check_file_id(file_id_hex: &str) -> Result<()> {
    if file_id_hex.len() != 32 || !file_id_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SagitarriusError::Other("invalid file id".into()));
    }
    Ok(())
}

/// Refuse symlinks anywhere a container is read or written: a planted link
/// could redirect reads outside the container (or writes outside the dest).
fn ensure_no_symlink(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(SagitarriusError::Other(format!(
            "refusing symlink in file container path: {}",
            path.display()
        )));
    }
    Ok(())
}

fn chunk_name(index: u64) -> String {
    format!("chunk-{index:08}")
}

fn read_manifest(dir: &Path) -> Result<Manifest> {
    let mp = dir.join("manifest.json");
    ensure_no_symlink(&mp)?;
    let mbytes = std::fs::read(&mp)?;
    if mbytes.len() > MAX_MANIFEST_SIZE {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let m: Manifest =
        serde_json::from_slice(&mbytes).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    if m.version != CONTAINER_VERSION {
        return Err(SagitarriusError::UnsupportedVersion(m.version));
    }
    check_file_id(&m.file_id)?;
    if m.size > MAX_FILE_SIZE {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    // chunks=0 is impossible (even empty files store one empty chunk); the
    // upper bound follows from MAX_FILE_SIZE.
    let max_chunks = MAX_FILE_SIZE.div_ceil(FILE_CHUNK_SIZE as u64) + 1;
    if m.chunks == 0 || m.chunks > max_chunks {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    if m.sha256.len() != 64 || !m.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    Ok(m)
}

/// Encrypt `src` into a new container, streaming 64 KiB at a time.
/// Returns (file_id_hex, size, sha256_hex, chunks).
pub fn put(
    vmk: &VaultMasterKey,
    vault_id_b64: &str,
    files_dir: &Path,
    src: &Path,
) -> Result<(String, u64, String, u64)> {
    ensure_no_symlink(src)?;
    let meta = std::fs::metadata(src)?;
    if !meta.is_file() {
        return Err(SagitarriusError::Other(format!(
            "not a file: {}",
            src.display()
        )));
    }
    if meta.len() > MAX_FILE_SIZE {
        return Err(SagitarriusError::Other(format!(
            "file too large ({} bytes, max {MAX_FILE_SIZE})",
            meta.len()
        )));
    }
    let mut id_raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id_raw);
    let file_id: String = id_raw.iter().map(|b| format!("{b:02x}")).collect();
    let mut prefix = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut prefix);

    // Stream: hash incrementally to learn size/digest, then encrypt chunk by
    // chunk. Two passes over the source, O(chunk) memory either way.
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    {
        let mut f = std::fs::File::open(src)?;
        // Fixed-size array: `Vec::zeroize()` clears the length (documented
        // zeroize behavior), which would make the next `read` see an empty
        // buffer and stop after one chunk. Arrays wipe in place.
        let mut buf = [0u8; FILE_CHUNK_SIZE];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
            if size > MAX_FILE_SIZE {
                return Err(SagitarriusError::Other(format!(
                    "file too large (max {MAX_FILE_SIZE} bytes)"
                )));
            }
            buf.zeroize();
        }
    }
    let total = size.div_ceil(FILE_CHUNK_SIZE as u64).max(1);
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let key = file_key(vmk, vault_id_b64, &file_id);
    let stage = files_dir.join(format!(".stage-{file_id}"));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage)?;
    let stream = || -> Result<()> {
        let mut f = std::fs::File::open(src)?;
        // See above: fixed array, never a reused zeroized Vec.
        let mut buf = [0u8; FILE_CHUNK_SIZE];
        for index in 0..total {
            let mut chunk = Vec::new();
            while chunk.len() < FILE_CHUNK_SIZE {
                let want = (FILE_CHUNK_SIZE - chunk.len()).min(buf.len());
                let n = f.read(&mut buf[..want])?;
                if n == 0 {
                    break;
                }
                chunk.extend_from_slice(&buf[..n]);
                buf[..n].zeroize();
            }
            if (index as usize) < (total as usize) - 1 && chunk.len() != FILE_CHUNK_SIZE {
                return Err(SagitarriusError::Other(
                    "source file shrank during read".into(),
                ));
            }
            let aad = chunk_aad(vault_id_b64, &file_id, index, total);
            let ct = crypto::encrypt_with_nonce(&key, &chunk, &aad, &chunk_nonce(&prefix, index))?;
            chunk.zeroize();
            std::fs::write(stage.join(chunk_name(index)), ct)?;
        }
        // Empty source: exactly one empty (authenticated) chunk.
        if total == 1 && size == 0 && !stage.join(chunk_name(0)).exists() {
            let aad = chunk_aad(vault_id_b64, &file_id, 0, 1);
            let ct = crypto::encrypt_with_nonce(&key, &[], &aad, &chunk_nonce(&prefix, 0))?;
            std::fs::write(stage.join(chunk_name(0)), ct)?;
        }
        Ok(())
    };
    if let Err(e) = stream() {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(e);
    }

    let filename = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let manifest = Manifest {
        version: CONTAINER_VERSION,
        file_id: file_id.clone(),
        nonce_prefix: B64.encode(prefix),
        chunks: total,
        size,
        sha256: digest.clone(),
        filename,
    };
    let mbytes = serde_json::to_vec_pretty(&manifest)?;
    std::fs::write(stage.join("manifest.json"), &mbytes)?;
    std::fs::rename(&stage, container_dir(files_dir, &file_id))?;

    Ok((file_id, size, digest, total))
}

/// Stream-decrypt a container, verifying hash + size. With `collect`,
/// returns the plaintext (bounded by MAX_FILE_SIZE); otherwise drops it and
/// returns size + filename. Rejects unexpected extra files in the container.
fn stream_decrypt(
    vmk: &VaultMasterKey,
    vault_id_b64: &str,
    dir: &Path,
    manifest: &Manifest,
    collect: bool,
) -> Result<(Vec<u8>, u64, String)> {
    // Self-contained container: exactly chunks + manifest.json, nothing else.
    // (A planted extra file is not silently ignored.)
    let mut entries = 0usize;
    for entry in std::fs::read_dir(dir)? {
        entry?;
        entries += 1;
    }
    if entries != manifest.chunks as usize + 1 {
        return Err(SagitarriusError::Other(
            "file container has unexpected files".into(),
        ));
    }
    let prefix_raw = B64
        .decode(&manifest.nonce_prefix)
        .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    if prefix_raw.len() != 4 {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&prefix_raw);
    let key = file_key(vmk, vault_id_b64, &manifest.file_id);
    let mut hasher = Sha256::new();
    let mut out = if collect {
        Vec::with_capacity(manifest.size.min(MAX_FILE_SIZE) as usize)
    } else {
        Vec::new()
    };
    let mut written = 0u64;
    for index in 0..manifest.chunks {
        let p = dir.join(chunk_name(index));
        ensure_no_symlink(&p)?;
        let ct = std::fs::read(&p)?;
        if ct.len() > FILE_CHUNK_SIZE + 32 {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        let aad = chunk_aad(vault_id_b64, &manifest.file_id, index, manifest.chunks);
        let mut pt = crypto::decrypt_with_nonce(&key, &chunk_nonce(&prefix, index), &ct, &aad)?;
        hasher.update(&pt);
        written += pt.len() as u64;
        if collect {
            if out.len() as u64 + pt.len() as u64 > MAX_FILE_SIZE {
                pt.zeroize();
                out.zeroize();
                return Err(SagitarriusError::InvalidVaultFormat);
            }
            out.extend_from_slice(&pt);
        }
        pt.zeroize();
    }
    if written != manifest.size {
        out.zeroize();
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if digest != manifest.sha256 {
        out.zeroize();
        return Err(SagitarriusError::Other(
            "file integrity check failed (sha256 mismatch)".into(),
        ));
    }
    let filename = manifest.filename.clone();
    Ok((out, written, filename))
}

/// Decrypt + write to `dest` atomically (0600 on unix), streaming through a
/// temp file. Verifies hash first (hash-then-write would need two passes;
/// instead stream to temp, verify, then rename — no plaintext leftover on
/// failure).
pub fn get_to(
    vmk: &VaultMasterKey,
    vault_id_b64: &str,
    files_dir: &Path,
    file_id_hex: &str,
    dest: &Path,
) -> Result<u64> {
    check_file_id(file_id_hex)?;
    if let Ok(meta) = std::fs::symlink_metadata(dest) {
        if meta.file_type().is_symlink() {
            return Err(SagitarriusError::Other(format!(
                "refusing to write through symlink: {}",
                dest.display()
            )));
        }
    }
    let dir = container_dir(files_dir, file_id_hex);
    ensure_no_symlink(&dir)?;
    let manifest = read_manifest(&dir)?;
    if manifest.file_id != file_id_hex {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let key = file_key(vmk, vault_id_b64, file_id_hex);
    let prefix_raw = B64
        .decode(&manifest.nonce_prefix)
        .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    if prefix_raw.len() != 4 {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&prefix_raw);

    let parent = dest
        .parent()
        .ok_or_else(|| SagitarriusError::Other("destination has no parent directory".into()))?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".tmp-get-{}-{}.part",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    // Count check first (cheap): exact container contents expected.
    let mut entries = 0usize;
    for entry in std::fs::read_dir(&dir)? {
        entry?;
        entries += 1;
    }
    if entries != manifest.chunks as usize + 1 {
        return Err(SagitarriusError::Other(
            "file container has unexpected files".into(),
        ));
    }
    let result = (|| -> Result<u64> {
        let mut out = std::fs::File::create(&tmp)?;
        let mut hasher = Sha256::new();
        let mut written = 0u64;
        for index in 0..manifest.chunks {
            let p = dir.join(chunk_name(index));
            ensure_no_symlink(&p)?;
            let ct = std::fs::read(&p)?;
            if ct.len() > FILE_CHUNK_SIZE + 32 {
                return Err(SagitarriusError::InvalidVaultFormat);
            }
            let aad = chunk_aad(vault_id_b64, file_id_hex, index, manifest.chunks);
            let mut pt = crypto::decrypt_with_nonce(&key, &chunk_nonce(&prefix, index), &ct, &aad)?;
            hasher.update(&pt);
            out.write_all(&pt)?;
            written += pt.len() as u64;
            pt.zeroize();
        }
        out.sync_all()?;
        drop(out);
        if written != manifest.size {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if digest != manifest.sha256 {
            return Err(SagitarriusError::Other(
                "file integrity check failed (sha256 mismatch)".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp)?.permissions();
            if perms.mode() & 0o077 != 0 {
                perms.set_mode(0o600);
                std::fs::set_permissions(&tmp, perms)?;
            }
        }
        std::fs::rename(&tmp, dest)?;
        Ok(written)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Remove a container entirely.
pub fn remove(files_dir: &Path, file_id_hex: &str) -> Result<()> {
    check_file_id(file_id_hex)?;
    let dir = container_dir(files_dir, file_id_hex);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

/// Structural verify: decrypt every chunk, check hash, drop plaintext.
/// Returns the verified size.
pub fn verify(
    vmk: &VaultMasterKey,
    vault_id_b64: &str,
    files_dir: &Path,
    file_id_hex: &str,
) -> Result<u64> {
    check_file_id(file_id_hex)?;
    let dir = container_dir(files_dir, file_id_hex);
    ensure_no_symlink(&dir)?;
    let manifest = read_manifest(&dir)?;
    if manifest.file_id != file_id_hex {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let (_, written, _) = stream_decrypt(vmk, vault_id_b64, &dir, &manifest, false)?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::VaultMasterKey;

    fn vmk() -> VaultMasterKey {
        VaultMasterKey::generate()
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &payload).unwrap();
        let k = vmk();
        let (id, size, sha, chunks) = put(&k, "dmF1bHQtaWQ=", dir.path(), &src).unwrap();
        assert_eq!(size, payload.len() as u64);
        assert!(chunks >= 3);
        let dest = dir.path().join("out.bin");
        assert_eq!(
            get_to(&k, "dmF1bHQtaWQ=", dir.path(), &id, &dest).unwrap(),
            size
        );
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
        let _ = sha;
    }

    #[test]
    fn empty_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("empty.bin");
        std::fs::write(&src, b"").unwrap();
        let k = vmk();
        let (id, size, _, chunks) = put(&k, "dmF1bHQtaWQ=", dir.path(), &src).unwrap();
        assert_eq!((size, chunks), (0, 1));
        let dest = dir.path().join("out.bin");
        assert_eq!(
            get_to(&k, "dmF1bHQtaWQ=", dir.path(), &id, &dest).unwrap(),
            0
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"");
    }

    #[test]
    fn wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        std::fs::write(&src, b"hello").unwrap();
        let (id, _, _, _) = put(&vmk(), "dmF1bHQtaWQ=", dir.path(), &src).unwrap();
        assert!(verify(&vmk(), "dmF1bHQtaWQ=", dir.path(), &id).is_err());
    }

    #[test]
    fn wrong_vault_id_fails() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        std::fs::write(&src, b"hello").unwrap();
        let k = vmk();
        let (id, _, _, _) = put(&k, "dmF1bHQtaWQ=", dir.path(), &src).unwrap();
        assert!(verify(&k, "ZGlmZmVyZW50", dir.path(), &id).is_err());
    }

    #[test]
    fn tampered_chunk_fails() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        std::fs::write(&src, b"hello world, tamper me").unwrap();
        let k = vmk();
        let (id, _, _, _) = put(&k, "dmF1bHQtaWQ=", dir.path(), &src).unwrap();
        let cdir = dir.path().join(&id);
        let p = cdir.join("chunk-00000000");
        let mut ct = std::fs::read(&p).unwrap();
        ct[0] ^= 1;
        std::fs::write(&p, ct).unwrap();
        assert!(verify(&k, "dmF1bHQtaWQ=", dir.path(), &id).is_err());
    }

    #[test]
    fn truncated_container_fails() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        std::fs::write(&src, vec![7u8; 100_000]).unwrap();
        let k = vmk();
        let (id, _, _, _) = put(&k, "dmF1bHQtaWQ=", dir.path(), &src).unwrap();
        std::fs::remove_file(dir.path().join(&id).join("chunk-00000001")).unwrap();
        assert!(verify(&k, "dmF1bHQtaWQ=", dir.path(), &id).is_err());
    }

    #[test]
    fn extra_file_in_container_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        std::fs::write(&src, b"data").unwrap();
        let k = vmk();
        let (id, _, _, _) = put(&k, "dmF1bHQtaWQ=", dir.path(), &src).unwrap();
        // Planted extra file: every read path must refuse the container.
        std::fs::write(dir.path().join(&id).join("evil.bin"), b"planted").unwrap();
        assert!(verify(&k, "dmF1bHQtaWQ=", dir.path(), &id).is_err());
        let dest = dir.path().join("out.bin");
        assert!(get_to(&k, "dmF1bHQtaWQ=", dir.path(), &id, &dest).is_err());
    }

    #[test]
    fn bad_file_id_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let k = vmk();
        assert!(verify(&k, "dmF1bHQtaWQ=", dir.path(), "../escape").is_err());
        assert!(verify(&k, "dmF1bHQtaWQ=", dir.path(), "zz").is_err());
        assert!(remove(dir.path(), "not-hex-at-all-00000000000000000").is_err());
    }
}
