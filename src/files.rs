//! Chunked authenticated file containers.
//!
//! Large files are never a single AES-GCM message. Each file gets:
//!
//! * a random 32-bit nonce prefix + per-chunk 64-bit big-endian counter as
//!   the 96-bit GCM nonce (unique per (file key, chunk) by construction),
//! * per-chunk AAD binding vault id, file id, chunk index, chunk total and
//!   format version,
//! * a manifest with size + SHA-256 of the plaintext for end-to-end check.
//!
//! Tampering with a chunk, the count, the order (index is in the nonce *and*
//! the AAD) or truncation fails authentication or the hash check.
//! Containers live under `<vault_dir>/files/<hex-id>/`.

use crate::crypto::{self};
use crate::envelope::{VaultMasterKey, LABEL_FILE};
use crate::error::{Result, SagitarriusError};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const FILE_CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;
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

/// Encrypt `src` into a new container. Returns (file_id_hex, size, sha256_hex, chunks).
pub fn put(
    vmk: &VaultMasterKey,
    vault_id_b64: &str,
    files_dir: &Path,
    src: &Path,
) -> Result<(String, u64, String, u64)> {
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

    let data = std::fs::read(src)?;
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(SagitarriusError::Other(format!(
            "file too large (max {MAX_FILE_SIZE} bytes)"
        )));
    }
    let total = data.len().div_ceil(FILE_CHUNK_SIZE).max(1) as u64;
    let key = file_key(vmk, vault_id_b64, &file_id);
    let dir = container_dir(files_dir, &file_id);
    std::fs::create_dir_all(&dir)?;

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();
    let sha_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();

    let mut offset = 0usize;
    for index in 0..total {
        let end = (offset + FILE_CHUNK_SIZE).min(data.len());
        // Empty files produce one empty chunk: still authenticated.
        let chunk = if data.is_empty() {
            &[][..]
        } else {
            &data[offset..end]
        };
        let aad = chunk_aad(vault_id_b64, &file_id, index, total);
        let ct = crypto::encrypt_with_nonce(&key, chunk, &aad, &chunk_nonce(&prefix, index))?;
        std::fs::write(dir.join(chunk_name(index)), ct)?;
        offset = end;
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
        size: data.len() as u64,
        sha256: sha_hex.clone(),
        filename,
    };
    let mbytes = serde_json::to_vec_pretty(&manifest)?;
    crate::storage::write_file_atomic(&dir.join("manifest.json"), &mbytes)?;

    Ok((file_id, data.len() as u64, sha_hex, total))
}

fn chunk_name(index: u64) -> String {
    format!("chunk-{index:08}")
}

/// Decrypt a container fully in memory (bounded by MAX_FILE_SIZE) and return
/// plaintext after hash verification.
pub fn read_all(
    vmk: &VaultMasterKey,
    vault_id_b64: &str,
    files_dir: &Path,
    file_id_hex: &str,
) -> Result<(Vec<u8>, String)> {
    let dir = container_dir(files_dir, file_id_hex);
    let mbytes = std::fs::read(dir.join("manifest.json"))?;
    let manifest: Manifest =
        serde_json::from_slice(&mbytes).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    if manifest.version != CONTAINER_VERSION || manifest.file_id != file_id_hex {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    if manifest.size > MAX_FILE_SIZE || manifest.chunks == 0 || manifest.chunks > 1024 * 64 {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let prefix_raw = B64
        .decode(&manifest.nonce_prefix)
        .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    if prefix_raw.len() != 4 {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&prefix_raw);

    let key = file_key(vmk, vault_id_b64, file_id_hex);
    let mut out = Vec::with_capacity(manifest.size as usize);
    for index in 0..manifest.chunks {
        let ct = std::fs::read(dir.join(chunk_name(index)))?;
        if ct.len() > FILE_CHUNK_SIZE + 32 {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        let aad = chunk_aad(vault_id_b64, file_id_hex, index, manifest.chunks);
        let mut pt = crypto::decrypt_with_nonce(&key, &chunk_nonce(&prefix, index), &ct, &aad)?;
        out.extend_from_slice(&pt);
        pt.zeroize();
    }
    if out.len() as u64 != manifest.size {
        out.zeroize();
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let mut hasher = Sha256::new();
    hasher.update(&out);
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
    Ok((out, manifest.filename))
}

/// Decrypt + write to `dest` atomically (0600 on unix). Verifies hash first.
pub fn get_to(
    vmk: &VaultMasterKey,
    vault_id_b64: &str,
    files_dir: &Path,
    file_id_hex: &str,
    dest: &Path,
) -> Result<u64> {
    let (mut data, _) = read_all(vmk, vault_id_b64, files_dir, file_id_hex)?;
    let size = data.len() as u64;
    // Refuse symlink destinations for plaintext.
    if let Ok(meta) = std::fs::symlink_metadata(dest) {
        if meta.file_type().is_symlink() {
            data.zeroize();
            return Err(SagitarriusError::Other(format!(
                "refusing to write through symlink: {}",
                dest.display()
            )));
        }
    }
    if let Err(e) = crate::storage::write_file_atomic(dest, &data) {
        data.zeroize();
        return Err(e);
    }
    data.zeroize();
    Ok(size)
}

/// Remove a container entirely.
pub fn remove(files_dir: &Path, file_id_hex: &str) -> Result<()> {
    if file_id_hex.len() != 32 || !file_id_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SagitarriusError::Other("invalid file id".into()));
    }
    let dir = container_dir(files_dir, file_id_hex);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    Ok(())
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
        let (back, _) = read_all(&k, "dmF1bHQtaWQ=", dir.path(), &id).unwrap();
        assert_eq!(back, payload);
        let _ = sha;
    }

    #[test]
    fn wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        std::fs::write(&src, b"hello").unwrap();
        let (id, _, _, _) = put(&vmk(), "dmF1bHQtaWQ=", dir.path(), &src).unwrap();
        assert!(read_all(&vmk(), "dmF1bHQtaWQ=", dir.path(), &id).is_err());
    }

    #[test]
    fn wrong_vault_id_fails() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        std::fs::write(&src, b"hello").unwrap();
        let k = vmk();
        let (id, _, _, _) = put(&k, "dmF1bHQtaWQ=", dir.path(), &src).unwrap();
        assert!(read_all(&k, "ZGlmZmVyZW50", dir.path(), &id).is_err());
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
        assert!(read_all(&k, "dmF1bHQtaWQ=", dir.path(), &id).is_err());
    }

    #[test]
    fn truncated_container_fails() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        std::fs::write(&src, vec![7u8; 100_000]).unwrap();
        let k = vmk();
        let (id, _, _, _) = put(&k, "dmF1bHQtaWQ=", dir.path(), &src).unwrap();
        std::fs::remove_file(dir.path().join(&id).join("chunk-00000001")).unwrap();
        assert!(read_all(&k, "dmF1bHQtaWQ=", dir.path(), &id).is_err());
    }
}
