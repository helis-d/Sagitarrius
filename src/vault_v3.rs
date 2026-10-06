//! Vault format v3: envelope encryption with per-record keys.
//!
//! ```text
//!              random VMK (32 bytes)
//!                         |
//!          +--------------+--------------+
//!          |                             |
//!     password wrap                 recovery wrap (optional)
//!     Argon2id KEK                  Argon2id KEK
//! ```
//!
//! Each record is encrypted separately under
//! `HKDF(VMK, vault_id, "SAGITARRIUS/v3/record" || record_id)` with AAD
//! binding vault id, record id, kind and format version. `get` therefore
//! decrypts exactly one record instead of the whole vault.
//!
//! The header (including the generation counter) is plaintext and AAD-bound
//! into every *wrap*; record AAD binds the immutable vault id, never the
//! mutable generation (else every write would invalidate every record).
//! Rollback (old-but-authentic file) is detected against the trusted state
//! file, not by crypto — see `state.rs`.

use crate::crypto::{self, DerivedKey, KdfParams, NONCE_LEN, SALT_LEN};
use crate::envelope::{self, VaultMasterKey, LABEL_RECORD};
use crate::error::{Result, SagitarriusError};
use crate::vault::{
    validate_kdf_params, READ_MAX_SECRETS, READ_MAX_SECRET_NAME_LEN, READ_MAX_SECRET_VALUE_LEN,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

pub const FORMAT_VERSION_V3: u32 = 3;
pub const WRAP_KIND_PASSWORD: &str = "password";
pub const WRAP_KIND_RECOVERY: &str = "recovery";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapEntry {
    pub kind: String,
    pub kdf_params: KdfParams,
    pub salt: String,    // base64
    pub nonce: String,   // base64
    pub wrapped: String, // base64 (wrapped VMK)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderV3 {
    pub magic: String,
    pub version: u32,
    pub vault_id: String, // base64(16 random bytes), immutable
    pub generation: u64,  // bumped on every mutating write
    pub kdf: String,
    pub wraps: Vec<WrapEntry>,
    /// HMAC-SHA256 over the canonical manifest encoding (see below).
    /// `None` on pre-F1 files: accepted as legacy, added on next write.
    #[serde(default)]
    pub manifest_mac: Option<String>, // base64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFileV3 {
    pub header: HeaderV3,
    pub records: Vec<StoredRecord>,
}

/// Typed record kinds. Stored as lowercase strings on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordKind {
    Secret,
    Password,
    Credential,
    Note,
    Document,
    File,
}

impl RecordKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordKind::Secret => "secret",
            RecordKind::Password => "password",
            RecordKind::Credential => "credential",
            RecordKind::Note => "note",
            RecordKind::Document => "document",
            RecordKind::File => "file",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "secret" => Some(RecordKind::Secret),
            "password" => Some(RecordKind::Password),
            "credential" => Some(RecordKind::Credential),
            "note" => Some(RecordKind::Note),
            "document" => Some(RecordKind::Document),
            "file" => Some(RecordKind::File),
            _ => None,
        }
    }
}

/// Decrypted record payload. File payloads reference a chunked container on
/// disk (see `files.rs`); the container holds the bytes, the record holds
/// identity + integrity metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecordPayload {
    Secret {
        value: String,
    },
    Password {
        value: String,
    },
    Note {
        value: String,
    },
    Document {
        value: String,
    },
    Credential {
        username: String,
        password: String,
    },
    File {
        file_id: String,
        filename: String,
        size: u64,
        sha256: String,
        chunks: u64,
    },
}

impl RecordPayload {
    /// Plain value for single-string kinds. Credential/File need dedicated
    /// handling (export skips them with a warning).
    pub fn single_value(&self) -> Option<&str> {
        match self {
            RecordPayload::Secret { value }
            | RecordPayload::Password { value }
            | RecordPayload::Note { value }
            | RecordPayload::Document { value } => Some(value),
            RecordPayload::Credential { .. } | RecordPayload::File { .. } => None,
        }
    }

    pub fn kind(&self) -> RecordKind {
        match self {
            RecordPayload::Secret { .. } => RecordKind::Secret,
            RecordPayload::Password { .. } => RecordKind::Password,
            RecordPayload::Credential { .. } => RecordKind::Credential,
            RecordPayload::Note { .. } => RecordKind::Note,
            RecordPayload::Document { .. } => RecordKind::Document,
            RecordPayload::File { .. } => RecordKind::File,
        }
    }

    /// Character length for `info` (file size for File records).
    pub fn display_len(&self) -> usize {
        match self {
            RecordPayload::Secret { value }
            | RecordPayload::Password { value }
            | RecordPayload::Note { value }
            | RecordPayload::Document { value } => value.chars().count(),
            RecordPayload::Credential { username, password } => {
                username.chars().count() + 1 + password.chars().count()
            }
            RecordPayload::File { size, .. } => *size as usize,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRecord {
    pub id: String, // base64(16 random bytes)
    pub name: String,
    pub kind: String, // RecordKind as string (kept denormalized for AAD + ls)
    pub created_at: u64,
    pub updated_at: u64,
    pub nonce: String,      // base64
    pub ciphertext: String, // base64(JSON RecordPayload)
}

pub struct VaultV3 {
    pub(crate) header: HeaderV3,
    pub(crate) vmk: VaultMasterKey,
    pub(crate) records: Vec<StoredRecord>,
}

impl Drop for VaultV3 {
    fn drop(&mut self) {
        // VMK wipes itself; nothing else plaintext is retained (records stay
        // encrypted in memory).
    }
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn random_id() -> [u8; 16] {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn record_aad(vault_id: &str, record_id: &str, kind: &str) -> Vec<u8> {
    format!("SAGITARRIUS/v3/record|{vault_id}|{record_id}|{kind}|3").into_bytes()
}

/// Canonical manifest encoding for the header MAC. Length-prefixed fields
/// (u64 big-endian length + bytes) for every variable-length value;
/// fixed-size integers as raw big-endian. Records sorted by id bytes so
/// encoding is order-independent. Versioned by the `manifest-v1` domain.
fn manifest_canonical(vault_id: &str, generation: u64, records: &[StoredRecord]) -> Vec<u8> {
    fn field(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(b);
    }
    let mut out = b"SAGITARRIUS/manifest-v1".to_vec();
    field(&mut out, vault_id.as_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    let mut sorted: Vec<&StoredRecord> = records.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    for r in sorted {
        field(&mut out, r.id.as_bytes());
        field(&mut out, r.name.as_bytes());
        field(&mut out, r.kind.as_bytes());
        out.extend_from_slice(&r.created_at.to_be_bytes());
        out.extend_from_slice(&r.updated_at.to_be_bytes());
        field(&mut out, r.nonce.as_bytes());
    }
    out
}

/// Compute the manifest MAC under the VMK-derived manifest key.
fn compute_manifest_mac(
    vmk: &VaultMasterKey,
    vault_id: &str,
    generation: u64,
    records: &[StoredRecord],
) -> String {
    use base64::{engine::general_purpose::STANDARD as B64m, Engine};
    let key = envelope::manifest_key(vmk, vault_id);
    let msg = manifest_canonical(vault_id, generation, records);
    let tag = envelope::compute_mac(&key, &msg);
    B64m.encode(&tag)
}

/// Verify the stored manifest MAC (constant-time). Absent MAC = legacy file,
/// accepted here; stripping detection lives in trusted state (see state.rs).
fn verify_manifest_mac(
    vmk: &VaultMasterKey,
    header: &HeaderV3,
    records: &[StoredRecord],
) -> Result<()> {
    let Some(stored_b64) = &header.manifest_mac else {
        return Ok(());
    };
    let stored = B64
        .decode(stored_b64)
        .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    let key = envelope::manifest_key(vmk, &header.vault_id);
    let msg = manifest_canonical(&header.vault_id, header.generation, records);
    envelope::verify_mac(&key, &msg, &stored)
}

fn record_key(vmk: &VaultMasterKey, vault_id_b64: &str, record_id_b64: &str) -> DerivedKey {
    let salt = B64.decode(vault_id_b64).unwrap_or_default();
    let info = format!("{LABEL_RECORD}/{record_id_b64}");
    vmk.derive_subkey(&salt, &info)
}

fn encrypt_record(
    vmk: &VaultMasterKey,
    vault_id: &str,
    record_id: &str,
    kind: &str,
    payload: &RecordPayload,
) -> Result<(String, String)> {
    let mut plain = serde_json::to_vec(payload)?;
    let key = record_key(vmk, vault_id, record_id);
    let aad = record_aad(vault_id, record_id, kind);
    let (nonce, ct) = crypto::encrypt(&key, &plain, &aad)?;
    plain.zeroize();
    Ok((B64.encode(nonce), B64.encode(&ct)))
}

fn decrypt_record(
    vmk: &VaultMasterKey,
    vault_id: &str,
    rec: &StoredRecord,
) -> Result<RecordPayload> {
    let nonce = B64
        .decode(&rec.nonce)
        .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    if nonce.len() != NONCE_LEN {
        return Err(SagitarriusError::InvalidPassword);
    }
    let ct = B64
        .decode(&rec.ciphertext)
        .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    let key = record_key(vmk, vault_id, &rec.id);
    let aad = record_aad(vault_id, &rec.id, &rec.kind);
    let mut plain = crypto::decrypt(&key, &nonce, &ct, &aad)?;
    let payload: RecordPayload =
        serde_json::from_slice(&plain).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    plain.zeroize();
    // The stored kind label must agree with the decrypted payload.
    if payload.kind().as_str() != rec.kind {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    Ok(payload)
}

fn make_password_wrap(vault_id: &str, password: &str, vmk: &VaultMasterKey) -> Result<WrapEntry> {
    let params = KdfParams::default();
    let salt = crypto::random_salt();
    let mut kek = crypto::derive_key(password, &salt, params)?;
    let salt_b64 = B64.encode(salt);
    let aad = envelope::wrap_aad(vault_id, WRAP_KIND_PASSWORD, params, &salt_b64);
    let (nonce, wrapped) = envelope::wrap_vmk(&kek, vmk, &aad)?;
    kek.zeroize();
    Ok(WrapEntry {
        kind: WRAP_KIND_PASSWORD.into(),
        kdf_params: params,
        salt: salt_b64,
        nonce: B64.encode(nonce),
        wrapped: B64.encode(&wrapped),
    })
}

fn find_wrap<'a>(header: &'a HeaderV3, kind: &str) -> Result<&'a WrapEntry> {
    header
        .wraps
        .iter()
        .find(|w| w.kind == kind)
        .ok_or(SagitarriusError::InvalidVaultFormat)
}

fn unwrap_with_secret(header: &HeaderV3, kind: &str, secret: &str) -> Result<VaultMasterKey> {
    let wrap = find_wrap(header, kind)?;
    validate_kdf_params(wrap.kdf_params)?;
    let salt = B64
        .decode(&wrap.salt)
        .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    if salt.len() != SALT_LEN {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    let mut kek = crypto::derive_key(secret, &salt, wrap.kdf_params)?;
    let nonce = B64
        .decode(&wrap.nonce)
        .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    let wrapped = B64
        .decode(&wrap.wrapped)
        .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
    let aad = envelope::wrap_aad(&header.vault_id, kind, wrap.kdf_params, &wrap.salt);
    let vmk = envelope::unwrap_vmk(&kek, &nonce, &wrapped, &aad)?;
    kek.zeroize();
    Ok(vmk)
}

impl VaultV3 {
    /// Brand-new v3 vault. Generation starts at 0; the first `serialize`
    /// bumps it to 1.
    pub fn create(password: &str) -> Result<Self> {
        if password.is_empty() {
            return Err(SagitarriusError::EmptyPassword);
        }
        let vault_id = B64.encode(random_id());
        let vmk = VaultMasterKey::generate();
        let pw_wrap = make_password_wrap(&vault_id, password, &vmk)?;
        Ok(Self {
            header: HeaderV3 {
                magic: crate::vault::MAGIC.into(),
                version: FORMAT_VERSION_V3,
                vault_id,
                generation: 0,
                kdf: "argon2id".into(),
                wraps: vec![pw_wrap],
                // No MAC yet: the first serialize() computes it. (A header
                // without MAC is exactly what legacy files look like.)
                manifest_mac: None,
            },
            vmk,
            records: Vec::new(),
        })
    }

    /// Open: validate header, unwrap VMK via the password wrap, validate
    /// payload bounds. Records stay encrypted until individually requested.
    pub fn unlock(password: &str, file_bytes: &[u8]) -> Result<Self> {
        let file: VaultFileV3 =
            serde_json::from_slice(file_bytes).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
        if file.header.magic != crate::vault::MAGIC {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        if file.header.version != FORMAT_VERSION_V3 {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        if file.header.kdf != "argon2id" {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        if B64.decode(&file.header.vault_id).is_err() {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        if file.records.len() > READ_MAX_SECRETS {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        for rec in &file.records {
            if rec.name.len() > READ_MAX_SECRET_NAME_LEN
                || rec.ciphertext.len() > READ_MAX_SECRET_VALUE_LEN * 2
            {
                return Err(SagitarriusError::InvalidVaultFormat);
            }
            if RecordKind::parse(&rec.kind).is_none() {
                return Err(SagitarriusError::InvalidVaultFormat);
            }
        }
        let vmk = unwrap_with_secret(&file.header, WRAP_KIND_PASSWORD, password)?;
        let vault = Self {
            header: file.header,
            vmk,
            records: file.records,
        };
        // Metadata membership proof: any added/removed/renamed record, or a
        // tampered generation counter, fails here — fail closed.
        verify_manifest_mac(&vault.vmk, &vault.header, &vault.records)?;
        Ok(vault)
    }

    /// Open with a recovery code instead of the password. Used by
    /// `recovery verify` and `recovery reset-password`; the recovery wrap
    /// KDF params are bounds-checked before derivation, like password wraps.
    pub(crate) fn unlock_with_recovery(file_bytes: &[u8], code_raw: &[u8; 32]) -> Result<Self> {
        let file: VaultFileV3 =
            serde_json::from_slice(file_bytes).map_err(|_| SagitarriusError::InvalidVaultFormat)?;
        if file.header.magic != crate::vault::MAGIC {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        if file.header.version != FORMAT_VERSION_V3 {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        let hex: String = code_raw.iter().map(|b| format!("{b:02x}")).collect();
        let vmk = unwrap_with_secret(&file.header, WRAP_KIND_RECOVERY, &hex)?;
        let vault = Self {
            header: file.header,
            vmk,
            records: file.records,
        };
        verify_manifest_mac(&vault.vmk, &vault.header, &vault.records)?;
        Ok(vault)
    }

    pub fn has_recovery(&self) -> bool {
        self.header
            .wraps
            .iter()
            .any(|w| w.kind == WRAP_KIND_RECOVERY)
    }

    /// Change password = re-wrap the same VMK. Records are untouched, so
    /// rotation is O(1) instead of re-encrypting the vault.
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        if new_password.is_empty() {
            return Err(SagitarriusError::EmptyPassword);
        }
        let wrap = make_password_wrap(&self.header.vault_id, new_password, &self.vmk)?;
        if let Some(slot) = self
            .header
            .wraps
            .iter_mut()
            .find(|w| w.kind == WRAP_KIND_PASSWORD)
        {
            *slot = wrap;
        } else {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        Ok(())
    }

    /// Add a recovery wrap. The code itself is never stored.
    pub fn add_recovery(&mut self, code_raw: &[u8; 32]) -> Result<()> {
        if self.has_recovery() {
            return Err(SagitarriusError::Other(
                "a recovery wrap already exists; remove it first".into(),
            ));
        }
        // Recovery KEK via Argon2id over the code; hex form is only UI.
        let hex: String = code_raw.iter().map(|b| format!("{b:02x}")).collect();
        let params = KdfParams::default();
        let salt = crypto::random_salt();
        let mut kek = crypto::derive_key(&hex, &salt, params)?;
        let salt_b64 = B64.encode(salt);
        let aad = envelope::wrap_aad(&self.header.vault_id, WRAP_KIND_RECOVERY, params, &salt_b64);
        let (nonce, wrapped) = envelope::wrap_vmk(&kek, &self.vmk, &aad)?;
        kek.zeroize();
        self.header.wraps.push(WrapEntry {
            kind: WRAP_KIND_RECOVERY.into(),
            kdf_params: params,
            salt: salt_b64,
            nonce: B64.encode(nonce),
            wrapped: B64.encode(&wrapped),
        });
        Ok(())
    }

    /// Password reset via recovery code: unwrap VMK with the code, then
    /// install a fresh password wrap. Old password becomes useless.
    pub fn reset_password_via_recovery(
        &mut self,
        code_raw: &[u8; 32],
        new_password: &str,
    ) -> Result<()> {
        if new_password.is_empty() {
            return Err(SagitarriusError::EmptyPassword);
        }
        let hex: String = code_raw.iter().map(|b| format!("{b:02x}")).collect();
        let vmk = unwrap_with_secret(&self.header, WRAP_KIND_RECOVERY, &hex)?;
        if vmk.as_bytes() != self.vmk.as_bytes() {
            return Err(SagitarriusError::InvalidPassword);
        }
        let wrap = make_password_wrap(&self.header.vault_id, new_password, &vmk)?;
        if let Some(slot) = self
            .header
            .wraps
            .iter_mut()
            .find(|w| w.kind == WRAP_KIND_PASSWORD)
        {
            *slot = wrap;
            Ok(())
        } else {
            Err(SagitarriusError::InvalidVaultFormat)
        }
    }

    pub fn find_index(&self, name: &str) -> Option<usize> {
        self.records.iter().position(|r| r.name == name)
    }

    pub fn get_payload(&self, name: &str) -> Option<RecordPayload> {
        let idx = self.find_index(name)?;
        decrypt_record(&self.vmk, &self.header.vault_id, &self.records[idx]).ok()
    }

    pub fn set_payload(&mut self, name: &str, payload: RecordPayload) -> Result<()> {
        let kind = payload.kind().as_str().to_string();
        let id = B64.encode(random_id());
        let (nonce, ct) = encrypt_record(&self.vmk, &self.header.vault_id, &id, &kind, &payload)?;
        let now = now_ts();
        if let Some(idx) = self.find_index(name) {
            let created = self.records[idx].created_at;
            self.records[idx] = StoredRecord {
                id,
                name: name.into(),
                kind,
                created_at: created,
                updated_at: now,
                nonce,
                ciphertext: ct,
            };
        } else {
            self.records.push(StoredRecord {
                id,
                name: name.into(),
                kind,
                created_at: now,
                updated_at: now,
                nonce,
                ciphertext: ct,
            });
        }
        Ok(())
    }

    /// Import one legacy (v2) entry preserving its timestamps. Used only by
    /// migration, which pre-validates names through the v2 parse. Enforces
    /// write caps: an oversized legacy entry fails migration loudly instead
    /// of producing a vault that violates write limits.
    pub(crate) fn import_legacy_entry(
        &mut self,
        name: &str,
        value: &str,
        created_at: u64,
        updated_at: u64,
    ) -> Result<()> {
        use crate::vault::{MAX_SECRET_NAME_LEN, MAX_SECRET_VALUE_LEN};
        if name.len() > MAX_SECRET_NAME_LEN || value.len() > MAX_SECRET_VALUE_LEN {
            return Err(SagitarriusError::Other(format!(
                "secret {name:?} is too large to migrate (name ≤ {MAX_SECRET_NAME_LEN}B, value ≤ {MAX_SECRET_VALUE_LEN}B); shrink it first"
            )));
        }
        let kind = RecordKind::Secret.as_str().to_string();
        let id = B64.encode(random_id());
        let payload = RecordPayload::Secret {
            value: value.into(),
        };
        let (nonce, ct) = encrypt_record(&self.vmk, &self.header.vault_id, &id, &kind, &payload)?;
        self.records.push(StoredRecord {
            id,
            name: name.into(),
            kind,
            created_at,
            updated_at,
            nonce,
            ciphertext: ct,
        });
        Ok(())
    }

    /// Serialize with a bumped generation. Records already carry their own
    /// ciphertexts; only the header (generation) changes. The manifest MAC
    /// is recomputed on every write, so it always covers the latest state.
    pub fn serialize(&mut self) -> Result<Vec<u8>> {
        self.header.generation = self.header.generation.saturating_add(1);
        self.header.manifest_mac = Some(compute_manifest_mac(
            &self.vmk,
            &self.header.vault_id,
            self.header.generation,
            &self.records,
        ));
        let file = VaultFileV3 {
            header: self.header.clone(),
            records: self.records.clone(),
        };
        Ok(serde_json::to_vec_pretty(&file)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "test-master-password";

    #[test]
    fn v3_create_unlock_roundtrip() {
        let mut v = VaultV3::create(PW).unwrap();
        v.set_payload(
            "API_KEY",
            RecordPayload::Secret {
                value: "sk-123".into(),
            },
        )
        .unwrap();
        let bytes = v.serialize().unwrap();
        let v2 = VaultV3::unlock(PW, &bytes).unwrap();
        assert_eq!(
            v2.get_payload("API_KEY"),
            Some(RecordPayload::Secret {
                value: "sk-123".into()
            })
        );
        // Generation bumped exactly once by the single serialize.
        assert_eq!(v2.header.generation, 1);
    }

    #[test]
    fn v3_wrong_password_fails() {
        let mut v = VaultV3::create(PW).unwrap();
        let bytes = v.serialize().unwrap();
        assert!(VaultV3::unlock("wrong", &bytes).is_err());
    }

    #[test]
    fn v3_password_rotation_keeps_records() {
        let mut v = VaultV3::create(PW).unwrap();
        v.set_payload(
            "K",
            RecordPayload::Note {
                value: "hello".into(),
            },
        )
        .unwrap();
        v.change_password("brand-new-pw").unwrap();
        let bytes = v.serialize().unwrap();
        assert!(VaultV3::unlock(PW, &bytes).is_err());
        let v2 = VaultV3::unlock("brand-new-pw", &bytes).unwrap();
        assert_eq!(
            v2.get_payload("K"),
            Some(RecordPayload::Note {
                value: "hello".into()
            })
        );
    }

    #[test]
    fn v3_typed_credential_roundtrip() {
        let mut v = VaultV3::create(PW).unwrap();
        v.set_payload(
            "DB",
            RecordPayload::Credential {
                username: "admin".into(),
                password: "s3cret".into(),
            },
        )
        .unwrap();
        let bytes = v.serialize().unwrap();
        let v2 = VaultV3::unlock(PW, &bytes).unwrap();
        assert_eq!(
            v2.get_payload("DB"),
            Some(RecordPayload::Credential {
                username: "admin".into(),
                password: "s3cret".into()
            })
        );
    }

    #[test]
    fn v3_tampered_record_fails() {
        let mut v = VaultV3::create(PW).unwrap();
        v.set_payload("K", RecordPayload::Secret { value: "v".into() })
            .unwrap();
        let bytes = v.serialize().unwrap();
        let mut file: VaultFileV3 = serde_json::from_slice(&bytes).unwrap();
        file.records[0].ciphertext = B64.encode(b"forged-ciphertext-payload!!");
        let evil = serde_json::to_vec(&file).unwrap();
        let v2 = VaultV3::unlock(PW, &evil).unwrap();
        assert!(v2.get_payload("K").is_none());
    }

    #[test]
    fn v3_recovery_cycle() {
        let mut v = VaultV3::create(PW).unwrap();
        v.set_payload("K", RecordPayload::Secret { value: "v".into() })
            .unwrap();
        let (code_text, code_raw) = envelope::generate_recovery_code();
        assert_eq!(envelope::parse_recovery_code(&code_text).unwrap(), code_raw);
        v.add_recovery(&code_raw).unwrap();
        assert!(v.has_recovery());
        let bytes = v.serialize().unwrap();
        // Code verification = header-only unwrap against these bytes.
        VaultV3::unlock_with_recovery(&bytes, &code_raw).unwrap();
        assert!(VaultV3::unlock_with_recovery(&bytes, &[9u8; 32]).is_err());
        v.reset_password_via_recovery(&code_raw, "new-pw-after-loss")
            .unwrap();
        let bytes = v.serialize().unwrap();
        assert!(VaultV3::unlock(PW, &bytes).is_err());
        let v2 = VaultV3::unlock("new-pw-after-loss", &bytes).unwrap();
        assert_eq!(
            v2.get_payload("K"),
            Some(RecordPayload::Secret { value: "v".into() })
        );
        // Recovery still works after the reset.
        VaultV3::unlock_with_recovery(&bytes, &code_raw).unwrap();
    }

    #[test]
    fn manifest_mac_present_after_write() {
        let mut v = VaultV3::create(PW).unwrap();
        v.set_payload("K", RecordPayload::Secret { value: "v".into() })
            .unwrap();
        let bytes = v.serialize().unwrap();
        let file: VaultFileV3 = serde_json::from_slice(&bytes).unwrap();
        assert!(file.header.manifest_mac.is_some());
        // Untouched file opens.
        VaultV3::unlock(PW, &bytes).unwrap();
    }

    #[test]
    fn manifest_mac_rejects_renamed_record() {
        let mut v = VaultV3::create(PW).unwrap();
        v.set_payload("K", RecordPayload::Secret { value: "v".into() })
            .unwrap();
        let bytes = v.serialize().unwrap();
        let mut file: VaultFileV3 = serde_json::from_slice(&bytes).unwrap();
        file.records[0].name = "K-RENAMED".into();
        let evil = serde_json::to_vec(&file).unwrap();
        assert!(VaultV3::unlock(PW, &evil).is_err());
    }

    #[test]
    fn manifest_mac_rejects_removed_record() {
        let mut v = VaultV3::create(PW).unwrap();
        v.set_payload("A", RecordPayload::Secret { value: "1".into() })
            .unwrap();
        v.set_payload("B", RecordPayload::Secret { value: "2".into() })
            .unwrap();
        let bytes = v.serialize().unwrap();
        let mut file: VaultFileV3 = serde_json::from_slice(&bytes).unwrap();
        file.records.pop();
        let evil = serde_json::to_vec(&file).unwrap();
        assert!(VaultV3::unlock(PW, &evil).is_err());
    }

    #[test]
    fn manifest_mac_rejects_bumped_generation() {
        let mut v = VaultV3::create(PW).unwrap();
        let bytes = v.serialize().unwrap();
        let mut file: VaultFileV3 = serde_json::from_slice(&bytes).unwrap();
        file.header.generation += 100;
        let evil = serde_json::to_vec(&file).unwrap();
        assert!(VaultV3::unlock(PW, &evil).is_err());
    }

    #[test]
    fn manifest_mac_legacy_upgrade() {
        // A v3 file without a MAC (pre-F1 / v0.2.1) opens fine...
        let mut v = VaultV3::create(PW).unwrap();
        v.set_payload("K", RecordPayload::Secret { value: "v".into() })
            .unwrap();
        let bytes = v.serialize().unwrap();
        let mut file: VaultFileV3 = serde_json::from_slice(&bytes).unwrap();
        file.header.manifest_mac = None;
        let legacy = serde_json::to_vec(&file).unwrap();
        let mut reopened = VaultV3::unlock(PW, &legacy).unwrap();
        assert_eq!(
            reopened.get_payload("K"),
            Some(RecordPayload::Secret { value: "v".into() })
        );
        // ...and the next write upgrades it with a MAC.
        let upgraded = reopened.serialize().unwrap();
        let file: VaultFileV3 = serde_json::from_slice(&upgraded).unwrap();
        assert!(file.header.manifest_mac.is_some());
        VaultV3::unlock(PW, &upgraded).unwrap();
    }
}
