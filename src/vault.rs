//! Versioned on-disk vault format.
//!
//! The file is JSON. The plaintext payload is a JSON document
//! `{"secrets":{...}}`. The header is bound to the ciphertext via AEAD
//! additional data, so any modification to the header is detected.

use crate::crypto::{self, DerivedKey, KdfParams, NONCE_LEN, SALT_LEN};
use crate::error::{Result, SagitarriusError};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

pub const MAGIC: &str = "SAGITARRIUS";
pub const FORMAT_VERSION: u32 = 2;

/// Generous DoS caps: normal vaults are KBs. These only reject absurd inputs
/// (GB files, MB-long single values) that would OOM the process.
pub const MAX_VAULT_FILE_SIZE: u64 = 10 * 1024 * 1024;
pub const MAX_IMPORT_FILE_SIZE: u64 = 1024 * 1024;
pub const MAX_SECRET_VALUE_LEN: usize = 1024 * 1024;
pub const MAX_SECRET_NAME_LEN: usize = 256;
pub const MAX_SECRETS: usize = 100_000;

/// Read-time caps are 4x the write caps: an oversized vault still OPENS
/// (bounded DoS protection only), so it can be inspected and shrunk.
/// Writes always enforce the strict MAX_* limits first.
pub const READ_MAX_VAULT_FILE_SIZE: u64 = 40 * 1024 * 1024;
pub const READ_MAX_SECRET_VALUE_LEN: usize = 4 * 1024 * 1024;
pub const READ_MAX_SECRET_NAME_LEN: usize = 1024;
pub const READ_MAX_SECRETS: usize = 400_000;

/// Hard bounds for attacker-controlled KDF parameters in the vault header.
/// Checked **before** running Argon2: a tampered header claiming gigabytes
/// of RAM or thousands of threads must fail fast instead of exhausting the
/// machine and only then failing GCM authentication.
/// Defaults (m=64MiB, t=3, p=4) sit comfortably inside these bounds.
pub const MAX_KDF_M_COST: u32 = 256 * 1024; // KiB = 256 MiB
pub const MAX_KDF_T_COST: u32 = 10;
pub const MAX_KDF_P_COST: u32 = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEntry {
    pub value: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub magic: String,
    pub version: u32,
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub salt: String, // base64
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFile {
    pub header: VaultHeader,
    pub nonce: String,      // base64
    pub ciphertext: String, // base64
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Payload {
    secrets: BTreeMap<String, SecretEntry>,
}

#[derive(Debug, Deserialize)]
struct PayloadV1 {
    secrets: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SecretInfo {
    pub name: String,
    pub length: usize,
    pub created_at: u64,
    pub updated_at: u64,
    pub is_valid_env_name: bool,
}

#[derive(Debug, Default)]
pub struct AuditReport {
    pub total_secrets: usize,
    pub invalid_env_names: Vec<String>,
    /// One entry per shared value; each holds the 2+ names using it.
    pub duplicate_groups: Vec<Vec<String>>,
    pub weak_secrets: Vec<String>,
    /// Non-failing observations (missing recovery, no backups, ...).
    pub notices: Vec<String>,
}

pub struct VaultV2 {
    header: VaultHeader,
    key: DerivedKey,
    payload: Payload,
}

impl Drop for VaultV2 {
    fn drop(&mut self) {
        // Best-effort: wipe plaintext secrets from memory. `DerivedKey`
        // already zeroizes itself via `ZeroizeOnDrop`.
        for entry in self.payload.secrets.values_mut() {
            entry.value.zeroize();
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl VaultV2 {
    /// Decrypt and parse an existing vault file.
    pub fn unlock(password: &str, file_bytes: &[u8]) -> Result<Self> {
        let file: VaultFile =
            serde_json::from_slice(file_bytes).map_err(|_| SagitarriusError::InvalidVaultFormat)?;

        if file.header.magic != MAGIC {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        if file.header.version > FORMAT_VERSION {
            return Err(SagitarriusError::UnsupportedVersion(file.header.version));
        }
        if file.header.kdf != "argon2id" {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
        // The header is attacker-controlled until GCM verifies it, and GCM
        // verification happens only AFTER key derivation. Clamp KDF params
        // first so a tampered header cannot force multi-GB Argon2 allocations.
        validate_kdf_params(file.header.kdf_params)?;

        let salt = B64
            .decode(&file.header.salt)
            .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
        if salt.len() != SALT_LEN {
            return Err(SagitarriusError::InvalidVaultFormat);
        }

        let nonce = B64
            .decode(&file.nonce)
            .map_err(|_| SagitarriusError::InvalidVaultFormat)?;
        if nonce.len() != NONCE_LEN {
            return Err(SagitarriusError::InvalidVaultFormat);
        }

        let ciphertext = B64
            .decode(&file.ciphertext)
            .map_err(|_| SagitarriusError::InvalidVaultFormat)?;

        let key = crypto::derive_key(password, &salt, file.header.kdf_params)?;
        let aad = header_aad(&file.header)?;
        let mut plaintext = crypto::decrypt(&key, &nonce, &ciphertext, &aad)?;

        let payload_res: Result<Payload> = (|| {
            if let Ok(v2) = serde_json::from_slice::<Payload>(&plaintext) {
                return Ok(v2);
            }
            if let Ok(v1) = serde_json::from_slice::<PayloadV1>(&plaintext) {
                let now = current_timestamp();
                let mut secrets = BTreeMap::new();
                for (k, v) in v1.secrets {
                    secrets.insert(
                        k,
                        SecretEntry {
                            value: v,
                            created_at: now,
                            updated_at: now,
                        },
                    );
                }
                return Ok(Payload { secrets });
            }
            Err(SagitarriusError::InvalidVaultFormat)
        })();
        // Plaintext JSON must not linger in memory.
        plaintext.zeroize();

        let payload = payload_res?;

        // The decrypted payload is also attacker-influenced (a foreign or
        // hand-crafted vault). Enforce resource caps so a 10M-entry payload
        // or a 1GB "value" cannot OOM the process. Deliberately lenient about
        // name *content* here: vaults written by older versions may contain
        // names that current write paths reject, and refusing to open them
        // would lock users out of their own data.
        validate_payload(&payload)?;

        let mut header = file.header;
        header.version = FORMAT_VERSION;

        Ok(Self {
            header,
            key,
            payload,
        })
    }

    /// Change the master password of the vault.
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        let new_salt = crypto::random_salt();
        let new_key = crypto::derive_key(new_password, &new_salt, self.header.kdf_params)?;
        self.header.salt = B64.encode(new_salt);
        self.key = new_key;
        Ok(())
    }

    /// Encrypt with a fresh nonce and return the JSON file bytes.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let aad = header_aad(&self.header)?;
        let mut plaintext = serde_json::to_vec(&self.payload)?;
        let (nonce, ciphertext) = crypto::encrypt(&self.key, &plaintext, &aad)?;
        plaintext.zeroize();

        let file = VaultFile {
            header: self.header.clone(),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(&ciphertext),
        };
        Ok(serde_json::to_vec_pretty(&file)?)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.payload.secrets.get(name).map(|s| s.value.as_str())
    }

    #[allow(dead_code)]
    pub fn get_entry(&self, name: &str) -> Option<&SecretEntry> {
        self.payload.secrets.get(name)
    }

    pub fn set(&mut self, name: &str, value: &str) {
        // Low-level setter: callers (add/edit/gen/import) validate first.
        // The assert documents the invariant in debug builds without risking
        // release-mode breakage on legacy data.
        debug_assert!(validate_secret_name(name).is_ok());
        debug_assert!(value.len() <= MAX_SECRET_VALUE_LEN);
        let now = current_timestamp();
        if let Some(entry) = self.payload.secrets.get_mut(name) {
            entry.value.zeroize();
            entry.value = value.into();
            entry.updated_at = now;
        } else {
            self.payload.secrets.insert(
                name.into(),
                SecretEntry {
                    value: value.into(),
                    created_at: now,
                    updated_at: now,
                },
            );
        }
    }

    pub fn remove(&mut self, name: &str) -> bool {
        if let Some(mut entry) = self.payload.secrets.remove(name) {
            entry.value.zeroize();
            true
        } else {
            false
        }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.payload.secrets.contains_key(name)
    }

    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        validate_secret_name(old)?;
        validate_secret_name(new)?;
        if !self.payload.secrets.contains_key(old) {
            return Err(SagitarriusError::SecretNotFound(old.into()));
        }
        if self.payload.secrets.contains_key(new) {
            return Err(SagitarriusError::SecretAlreadyExists(new.into()));
        }
        let mut entry = self.payload.secrets.remove(old).unwrap();
        entry.updated_at = current_timestamp();
        self.payload.secrets.insert(new.into(), entry);
        Ok(())
    }

    pub fn names(&self) -> Vec<&str> {
        self.payload.secrets.keys().map(|s| s.as_str()).collect()
    }

    pub fn search(&self, query: &str) -> Vec<&str> {
        self.payload
            .secrets
            .keys()
            .filter(|k| k.contains(query))
            .map(|s| s.as_str())
            .collect()
    }

    pub fn info(&self, name: &str) -> Option<SecretInfo> {
        self.payload.secrets.get(name).map(|entry| SecretInfo {
            name: name.into(),
            length: entry.value.chars().count(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
            is_valid_env_name: is_valid_env_name(name),
        })
    }

    pub fn import_env(
        &mut self,
        env_text: &str,
        overwrite: bool,
        allow_dangerous: bool,
    ) -> (usize, usize, Vec<String>) {
        let mut added = 0;
        let mut skipped = 0;
        let mut dangerous = Vec::new();
        // Strip a UTF-8 BOM so the first key is not poisoned by it.
        let env_text = env_text.strip_prefix('\u{FEFF}').unwrap_or(env_text);

        for line in env_text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line).trim();
            let Some((k, v)) = line.split_once('=') else {
                // Previously silently ignored; count so the summary is honest.
                skipped += 1;
                continue;
            };
            let key = k.trim();
            let val_trimmed = v.trim();

            let Some(val) = parse_env_value(val_trimmed) else {
                skipped += 1;
                continue;
            };

            // Reject garbage that would spoof .env/terminal output or bypass
            // the EmptySecretValue rule enforced by `add`/`edit`.
            if key.is_empty() || val.is_empty() {
                skipped += 1;
                continue;
            }
            if key.len() > MAX_SECRET_NAME_LEN || val.len() > MAX_SECRET_VALUE_LEN {
                skipped += 1;
                continue;
            }
            if validate_secret_name(key).is_err() {
                skipped += 1;
                continue;
            }
            // Dangerous names (spaces, shell metacharacters, ...) are only
            // imported with explicit opt-in; otherwise skip loudly.
            if !allow_dangerous && is_dangerous_name(key) {
                skipped += 1;
                dangerous.push(key.to_string());
                continue;
            }

            if !overwrite && self.exists(key) {
                skipped += 1;
            } else {
                if self.payload.secrets.len() >= MAX_SECRETS && !self.exists(key) {
                    skipped += 1;
                    continue;
                }
                self.set(key, &val);
                added += 1;
            }
        }
        (added, skipped, dangerous)
    }

    /// Exported `.env` text plus the names that were skipped because they
    /// are not valid POSIX environment variable identifiers.
    pub fn export_env(&self) -> (String, Vec<String>) {
        let mut out = String::new();
        let mut skipped = Vec::new();
        for (k, entry) in &self.payload.secrets {
            if is_valid_env_name(k) {
                out.push_str(&format!("{k}={}\n", escape_env_value(&entry.value)));
            } else {
                skipped.push(k.clone());
            }
        }
        (out, skipped)
    }

    pub fn audit(&self) -> AuditReport {
        let mut report = AuditReport {
            total_secrets: self.payload.secrets.len(),
            ..Default::default()
        };

        let mut seen_values: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

        for (name, entry) in &self.payload.secrets {
            if !is_valid_env_name(name) {
                report.invalid_env_names.push(name.clone());
            }

            // Character count (not byte length) so multi-byte values are
            // measured the way users see them.
            if entry.value.chars().count() < 8 {
                report.weak_secrets.push(name.clone());
            }

            seen_values
                .entry(entry.value.as_str())
                .or_default()
                .push(name.as_str());
        }

        // Grouped (O(n)), not pairwise (O(n²)): 10k identical values used to
        // mean ~50M pairs and gigabytes of report. BTreeMap keeps output
        // deterministic.
        for (_val, names) in seen_values {
            if names.len() > 1 {
                report
                    .duplicate_groups
                    .push(names.iter().map(|s| s.to_string()).collect());
            }
        }

        report
    }
}

/// Unified vault handle. New vaults are always v3 (VMK envelope +
/// per-record encryption); v2 files open read/write in place until an
/// explicit `migrate` converts them.
pub enum Vault {
    V2(VaultV2),
    V3(crate::vault_v3::VaultV3),
}

impl Vault {
    /// Create a brand-new v3 vault.
    pub fn create(password: &str) -> Result<Self> {
        Ok(Vault::V3(crate::vault_v3::VaultV3::create(password)?))
    }

    /// Open either format. The version probe reads only the header envelope;
    /// v2 files keep the v2 code path (whole-payload decrypt, as before).
    /// A known-magic header with a future version fails here as
    /// `UnsupportedVersion` instead of falling into the wrong parser.
    pub fn unlock(password: &str, file_bytes: &[u8]) -> Result<Self> {
        if is_v3_bytes(file_bytes) {
            return Ok(Vault::V3(crate::vault_v3::VaultV3::unlock(
                password, file_bytes,
            )?));
        }
        if let Some(v) = probed_version(file_bytes) {
            if v > crate::vault_v3::FORMAT_VERSION_V3 {
                return Err(SagitarriusError::UnsupportedVersion(v));
            }
        }
        Ok(Vault::V2(VaultV2::unlock(password, file_bytes)?))
    }

    pub fn is_v3(&self) -> bool {
        matches!(self, Vault::V3(_))
    }

    /// Stable vault identity for snapshots/state. v2 files predate vault ids;
    /// they report a fixed legacy marker (no rollback tracking).
    pub fn vault_id(&self) -> String {
        match self {
            Vault::V2(_) => "v2-legacy".into(),
            Vault::V3(v) => v.header.vault_id.clone(),
        }
    }

    pub fn generation(&self) -> u64 {
        match self {
            Vault::V2(_) => 0,
            Vault::V3(v) => v.header.generation,
        }
    }

    /// On-disk format version (2 or 3).
    pub fn format_version(&self) -> u32 {
        match self {
            Vault::V2(_) => FORMAT_VERSION,
            Vault::V3(v) => v.header.version,
        }
    }

    /// KDF params guarding the password wrap/entry, if any.
    pub fn password_kdf_params(&self) -> Option<KdfParams> {
        match self {
            Vault::V2(v) => Some(v.header.kdf_params),
            Vault::V3(v) => v
                .header
                .wraps
                .iter()
                .find(|w| w.kind == crate::vault_v3::WRAP_KIND_PASSWORD)
                .map(|w| w.kdf_params),
        }
    }

    pub fn has_recovery(&self) -> bool {
        match self {
            Vault::V2(_) => false,
            Vault::V3(v) => v.has_recovery(),
        }
    }

    /// Whether the loaded file carries a manifest MAC (v3 only).
    pub fn has_manifest_mac(&self) -> bool {
        match self {
            Vault::V2(_) => false,
            Vault::V3(v) => v.header.manifest_mac.is_some(),
        }
    }

    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        match self {
            Vault::V2(v) => v.change_password(new_password),
            Vault::V3(v) => v.change_password(new_password),
        }
    }

    pub fn serialize(&mut self) -> Result<Vec<u8>> {
        match self {
            Vault::V2(v) => v.serialize(),
            Vault::V3(v) => v.serialize(),
        }
    }

    /// Single-string value for Secret/Password/Note/Document kinds.
    /// v3 decrypts exactly one record; v2 serves from its unlocked payload.
    pub fn get(&self, name: &str) -> Option<String> {
        match self {
            Vault::V2(v) => v.get(name).map(|s| s.to_string()),
            Vault::V3(v) => v
                .get_payload(name)
                .and_then(|p| p.single_value().map(|s| s.to_string())),
        }
    }

    pub fn get_payload(&self, name: &str) -> Option<crate::vault_v3::RecordPayload> {
        match self {
            Vault::V2(v) => v.get(name).map(|s| crate::vault_v3::RecordPayload::Secret {
                value: s.to_string(),
            }),
            Vault::V3(v) => v.get_payload(name),
        }
    }

    /// Store a plain string as a `Secret` record (v3) / entry (v2).
    pub fn set(&mut self, name: &str, value: &str) {
        match self {
            Vault::V2(v) => v.set(name, value),
            Vault::V3(v) => {
                let _ = v.set_payload(
                    name,
                    crate::vault_v3::RecordPayload::Secret {
                        value: value.into(),
                    },
                );
            }
        }
    }

    pub fn set_typed(&mut self, name: &str, payload: crate::vault_v3::RecordPayload) -> Result<()> {
        match self {
            Vault::V2(v) => {
                let Some(value) = payload.single_value() else {
                    return Err(SagitarriusError::Other(
                        "this record kind needs vault format v3; run `sagitarrius migrate` first"
                            .into(),
                    ));
                };
                v.set(name, value);
                Ok(())
            }
            Vault::V3(v) => v.set_payload(name, payload),
        }
    }

    pub fn remove(&mut self, name: &str) -> bool {
        match self {
            Vault::V2(v) => v.remove(name),
            Vault::V3(v) => {
                if let Some(idx) = v.find_index(name) {
                    v.records.remove(idx);
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn exists(&self, name: &str) -> bool {
        match self {
            Vault::V2(v) => v.exists(name),
            Vault::V3(v) => v.find_index(name).is_some(),
        }
    }

    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        validate_secret_name(old)?;
        validate_secret_name(new)?;
        match self {
            Vault::V2(v) => v.rename(old, new),
            Vault::V3(v) => {
                if v.find_index(old).is_none() {
                    return Err(SagitarriusError::SecretNotFound(old.into()));
                }
                if v.find_index(new).is_some() {
                    return Err(SagitarriusError::SecretAlreadyExists(new.into()));
                }
                let idx = v.find_index(old).unwrap();
                v.records[idx].name = new.into();
                Ok(())
            }
        }
    }

    pub fn names(&self) -> Vec<&str> {
        match self {
            Vault::V2(v) => v.names(),
            Vault::V3(v) => v.records.iter().map(|r| r.name.as_str()).collect(),
        }
    }

    pub fn search(&self, query: &str) -> Vec<&str> {
        match self {
            Vault::V2(v) => v.search(query),
            Vault::V3(v) => v
                .records
                .iter()
                .filter(|r| r.name.contains(query))
                .map(|r| r.name.as_str())
                .collect(),
        }
    }

    pub fn info(&self, name: &str) -> Option<SecretInfo> {
        match self {
            Vault::V2(v) => v.info(name),
            Vault::V3(v) => {
                let rec = v.records.iter().find(|r| r.name == name)?;
                let len = v.get_payload(name)?.display_len();
                Some(SecretInfo {
                    name: name.into(),
                    length: len,
                    created_at: rec.created_at,
                    updated_at: rec.updated_at,
                    is_valid_env_name: is_valid_env_name(name),
                })
            }
        }
    }

    pub fn import_env(
        &mut self,
        env_text: &str,
        overwrite: bool,
        allow_dangerous: bool,
    ) -> (usize, usize, Vec<String>) {
        // Shared parser lives on V2; route through a scratch V2 view is
        // wasteful, so v3 validates inline with identical rules.
        match self {
            Vault::V2(v) => v.import_env(env_text, overwrite, allow_dangerous),
            Vault::V3(v) => {
                let mut added = 0;
                let mut skipped = 0;
                let mut dangerous = Vec::new();
                let env_text = env_text.strip_prefix('\u{FEFF}').unwrap_or(env_text);
                for line in env_text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let line = line.strip_prefix("export ").unwrap_or(line).trim();
                    let Some((k, val)) = line.split_once('=') else {
                        skipped += 1;
                        continue;
                    };
                    let key = k.trim();
                    let Some(val) = parse_env_value(val.trim()) else {
                        skipped += 1;
                        continue;
                    };
                    if key.is_empty()
                        || val.is_empty()
                        || key.len() > MAX_SECRET_NAME_LEN
                        || val.len() > MAX_SECRET_VALUE_LEN
                        || validate_secret_name(key).is_err()
                    {
                        skipped += 1;
                        continue;
                    }
                    if !allow_dangerous && is_dangerous_name(key) {
                        skipped += 1;
                        dangerous.push(key.to_string());
                        continue;
                    }
                    if !overwrite && v.find_index(key).is_some() {
                        skipped += 1;
                    } else {
                        if v.records.len() >= MAX_SECRETS && v.find_index(key).is_none() {
                            skipped += 1;
                            continue;
                        }
                        let _ = v.set_payload(
                            key,
                            crate::vault_v3::RecordPayload::Secret { value: val },
                        );
                        added += 1;
                    }
                }
                (added, skipped, dangerous)
            }
        }
    }

    pub fn export_env(&self) -> (String, Vec<String>) {
        match self {
            Vault::V2(v) => v.export_env(),
            Vault::V3(v) => {
                let mut out = String::new();
                let mut skipped = Vec::new();
                for rec in &v.records {
                    match v
                        .get_payload(&rec.name)
                        .and_then(|p| p.single_value().map(|s| s.to_string()))
                    {
                        Some(value) if is_valid_env_name(&rec.name) => {
                            out.push_str(&format!(
                                "{n}={}\n",
                                escape_env_value(&value),
                                n = rec.name
                            ));
                        }
                        _ => skipped.push(rec.name.clone()),
                    }
                }
                (out, skipped)
            }
        }
    }

    pub fn audit(&self) -> AuditReport {
        match self {
            Vault::V2(v) => v.audit(),
            Vault::V3(v) => {
                let mut report = AuditReport {
                    total_secrets: v.records.len(),
                    ..Default::default()
                };
                // Owned keys (one extra copy per secret, wiped below): the
                // decrypted values are temporaries and cannot back borrows.
                let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
                for rec in &v.records {
                    if !is_valid_env_name(&rec.name) {
                        report.invalid_env_names.push(rec.name.clone());
                    }
                    // Credential passwords join the analysis (never printed).
                    let val: Option<String> = v.get_payload(&rec.name).and_then(|p| match p {
                        crate::vault_v3::RecordPayload::Credential { password, .. } => {
                            Some(password)
                        }
                        crate::vault_v3::RecordPayload::Secret { value }
                        | crate::vault_v3::RecordPayload::Password { value }
                        | crate::vault_v3::RecordPayload::Note { value }
                        | crate::vault_v3::RecordPayload::Document { value } => Some(value),
                        crate::vault_v3::RecordPayload::File { .. } => None,
                    });
                    if let Some(val) = val {
                        if val.chars().count() < 8 {
                            report.weak_secrets.push(rec.name.clone());
                        }
                        seen.entry(val).or_default().push(rec.name.clone());
                    }
                }
                for (mut val, names) in seen {
                    if names.len() > 1 {
                        report.duplicate_groups.push(names);
                    }
                    val.zeroize();
                }
                report
            }
        }
    }

    pub fn add_recovery(&mut self, code_raw: &[u8; 32]) -> Result<()> {
        match self {
            Vault::V2(_) => Err(SagitarriusError::Other(
                "recovery needs vault format v3; run `sagitarrius migrate` first".into(),
            )),
            Vault::V3(v) => v.add_recovery(code_raw),
        }
    }

    pub fn reset_password_via_recovery(
        &mut self,
        code_raw: &[u8; 32],
        new_password: &str,
    ) -> Result<()> {
        match self {
            Vault::V2(_) => Err(SagitarriusError::Other(
                "recovery needs vault format v3; run `sagitarrius migrate` first".into(),
            )),
            Vault::V3(v) => v.reset_password_via_recovery(code_raw, new_password),
        }
    }
}

/// Best-effort (magic, version) read for dispatch. Garbage returns None and
/// falls through to the v2 parser, which fails closed on its own.
fn probed_envelope(file_bytes: &[u8]) -> Option<(String, u32)> {
    #[derive(Deserialize)]
    struct Probe {
        header: ProbeHeader,
    }
    #[derive(Deserialize)]
    struct ProbeHeader {
        magic: String,
        version: u32,
    }
    serde_json::from_slice::<Probe>(file_bytes)
        .ok()
        .map(|p| (p.header.magic, p.header.version))
}

/// True when the file envelope declares v3. Only the tiny header envelope is
/// inspected — no decryption, no allocation beyond the parse.
fn is_v3_bytes(file_bytes: &[u8]) -> bool {
    matches!(
        probed_envelope(file_bytes),
        Some((magic, v))
            if magic == MAGIC && v == crate::vault_v3::FORMAT_VERSION_V3
    )
}

fn probed_version(file_bytes: &[u8]) -> Option<u32> {
    probed_envelope(file_bytes).and_then(|(magic, v)| if magic == MAGIC { Some(v) } else { None })
}

/// Convert a v2 vault file (bytes + password) into v3 bytes. Names, values
/// and timestamps are preserved; kinds default to `Secret`. The caller is
/// responsible for snapshotting the old file first and verifying the result
/// (re-unlock) before replacing anything.
pub fn migrate_v2_to_v3(password: &str, v2_bytes: &[u8]) -> Result<Vec<u8>> {
    let old = VaultV2::unlock(password, v2_bytes)?;
    let mut fresh = crate::vault_v3::VaultV3::create(password)?;
    for (name, entry) in &old.payload.secrets {
        fresh.import_legacy_entry(name, &entry.value, entry.created_at, entry.updated_at)?;
    }
    // Verify before handing back: the migrated vault must open cleanly.
    let mut bytes = fresh.serialize()?;
    let check = crate::vault_v3::VaultV3::unlock(password, &bytes)?;
    for (name, entry) in &old.payload.secrets {
        match check.get_payload(name) {
            Some(crate::vault_v3::RecordPayload::Secret { value }) if value == entry.value => {}
            _ => {
                bytes.zeroize();
                return Err(SagitarriusError::Other(
                    "migration verification failed".into(),
                ));
            }
        }
    }
    Ok(bytes)
}

fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Portable dotenv-style names: safe in `.env` files and most shells, but
/// not valid POSIX identifiers (e.g. `github-token`). Imported with at most
/// a warning; `run` skips them with a warning (never injects).
pub(crate) fn is_portable_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Dangerous names (D02): anything outside the portable set — whitespace,
/// shell metacharacters, `=`, leading `-`, control chars (incl. NUL).
/// `run` refuses these unless `--allow-dangerous-env`; `import` skips them
/// unless `--allow-dangerous`. NUL is refused unconditionally (no OS can
/// carry it in an env var).
pub(crate) fn is_dangerous_name(name: &str) -> bool {
    if name.contains('\0') {
        return true;
    }
    if is_valid_env_name(name) || is_portable_name(name) {
        return false;
    }
    true
}

/// Structural validation for secret names. Deliberately permissive about
/// dashes/dots (existing vaults and tests use `github-token`), but rejects
/// what would spoof terminal/`.env` output or break the format:
/// empty, over-long, `=`, newlines/NUL and other ASCII control codes.
pub(crate) fn validate_secret_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(SagitarriusError::Usage(
            "secret name must not be empty".into(),
        ));
    }
    if name.len() > MAX_SECRET_NAME_LEN {
        return Err(SagitarriusError::Usage(format!(
            "secret name must be at most {MAX_SECRET_NAME_LEN} bytes"
        )));
    }
    if name.contains('=')
        || name.contains('\n')
        || name.contains('\r')
        || name.contains('\0')
        || name.chars().any(|c| c.is_ascii_control())
    {
        return Err(SagitarriusError::Usage(format!(
            "invalid secret name {name:?}: must not contain '=', newlines or control characters"
        )));
    }
    Ok(())
}

/// Bounds-check KDF parameters from the (still unauthenticated) header.
/// Must run before `derive_key`: Argon2 allocates per these numbers, so a
/// tampered `m_cost` in the gigabytes would DoS the machine before GCM gets
/// a chance to reject the forgery.
pub(crate) fn validate_kdf_params(p: KdfParams) -> Result<()> {
    // Lower bounds keep Argon2 itself from rejecting with a confusing error;
    // the argon2 crate enforces m >= 8*p on top of this.
    const MIN_M_COST: u32 = 8 * 1024;
    if p.m_cost < MIN_M_COST
        || p.m_cost > MAX_KDF_M_COST
        || p.t_cost == 0
        || p.t_cost > MAX_KDF_T_COST
        || p.p_cost == 0
        || p.p_cost > MAX_KDF_P_COST
    {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    Ok(())
}

/// Resource caps for a decrypted payload. Uses READ caps (above write
/// limits): an oversized vault still opens so it can be inspected and
/// shrunk. Only sizes/counts — never name content, so vaults written by
/// older versions always stay openable.
fn validate_payload(payload: &Payload) -> Result<()> {
    if payload.secrets.len() > READ_MAX_SECRETS {
        return Err(SagitarriusError::InvalidVaultFormat);
    }
    for (name, entry) in &payload.secrets {
        if name.len() > READ_MAX_SECRET_NAME_LEN || entry.value.len() > READ_MAX_SECRET_VALUE_LEN {
            return Err(SagitarriusError::InvalidVaultFormat);
        }
    }
    Ok(())
}

/// Terminal-safe rendering of secret names. Current write paths reject
/// control characters, but vaults written by older versions may contain
/// them — never emit raw ESC/C0 bytes to the terminal.
pub(crate) fn escape_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:X}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Values that only contain these characters are written raw so simple
/// `.env` files stay human-friendly (`FOO=bar`). Anything else (spaces,
/// `#`, newlines, quotes, `=`, non-ASCII, ...) is double-quoted with escapes
/// so `export` -> `import` round-trips byte-for-byte.
fn env_value_needs_quotes(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    !v.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '_' | '-' | '.' | '/' | ':' | ',' | '+' | '@' | '%')
    })
}

fn escape_env_value(v: &str) -> String {
    if !env_value_needs_quotes(v) {
        return v.to_string();
    }
    // Single quotes when possible: everything inside is literal, both for
    // shells and for our importer. Possible unless the value itself holds a
    // single quote or a line break (line-based .env cannot hold those raw).
    if !v.contains('\'') && !v.contains('\n') && !v.contains('\r') {
        return format!("'{v}'");
    }
    // Otherwise double quotes with exactly the shell-portable escapes:
    // backslash, double quote, dollar, backtick, newline (+ CR, same reason).
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Parse a raw (already trimmed) value. Returns `None` when the entry must
/// be skipped: ambiguous trailing text after a closing quote is never
/// guessed at (D04) — it is counted as skipped instead.
fn parse_env_value(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('"') {
        // Double-quoted: the value ends at the first UNESCAPED quote.
        let mut inner = String::new();
        let mut tail = String::new();
        let mut closed = false;
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            if closed {
                tail.push(c);
                continue;
            }
            if c == '\\' {
                // Preserve the pair; the shared unescaper interprets it.
                inner.push('\\');
                if let Some(n) = chars.next() {
                    inner.push(n);
                }
            } else if c == '"' {
                closed = true;
            } else {
                inner.push(c);
            }
        }
        if !closed {
            // Unclosed quote: legacy behavior — the whole thing is literal.
            return Some(raw.to_string());
        }
        let tail = tail.trim();
        if !tail.is_empty() && !tail.starts_with('#') {
            return None;
        }
        return Some(unescape_double_quoted(&inner));
    }
    if let Some(rest) = raw.strip_prefix('\'') {
        // Single quotes have no escapes: value ends at the next quote.
        match rest.find('\'') {
            Some(end) => {
                let tail = rest[end + 1..].trim();
                if !tail.is_empty() && !tail.starts_with('#') {
                    return None;
                }
                return Some(rest[..end].to_string());
            }
            None => return Some(raw.to_string()), // unclosed: legacy literal
        }
    }
    // Unquoted: dotenv inline comment = '#' at the start or after whitespace.
    Some(strip_inline_comment(raw))
}

/// Cut `value # comment` down to `value`. A `#` glued to text (`a#b`)
/// stays — only whitespace-separated comments count.
fn strip_inline_comment(v: &str) -> String {
    let mut prev_ws = false;
    for (off, c) in v.char_indices() {
        if c == '#' && (off == 0 || prev_ws) {
            return v[..off].trim_end().to_string();
        }
        prev_ws = c == ' ' || c == '\t';
    }
    v.to_string()
}

fn unescape_double_quoted(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('$') => out.push('$'),
            Some('`') => out.push('`'),
            // Legacy compat: older exports emitted \t and accepted \'.
            Some('t') => out.push('\t'),
            Some('\'') => out.push('\''),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Canonical serialization of the header, used as AEAD additional data.
/// Uses `serde_json::to_vec`, which produces compact JSON in field
/// declaration order — a deterministic encoding for our fixed struct.
///
/// WARNING: the byte-exact output is part of the vault format. Any change
/// (field order, new field, pretty-print, different escaping) invalidates
/// existing vaults (decrypt fails as `InvalidPassword`). The
/// `header_aad_stability` test below pins the encoding; update the format
/// version and add migration instead of changing this function.
fn header_aad(header: &VaultHeader) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(header)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery staple";

    fn round_trip(mutate: impl FnOnce(&mut Vault)) -> Vault {
        let mut v = Vault::create(PW).unwrap();
        mutate(&mut v);
        let bytes = v.serialize().unwrap();
        Vault::unlock(PW, &bytes).unwrap()
    }

    #[test]
    fn create_and_unlock_empty() {
        let mut v = Vault::create(PW).unwrap();
        let bytes = v.serialize().unwrap();
        let v = Vault::unlock(PW, &bytes).unwrap();
        assert_eq!(v.names().len(), 0);
    }

    #[test]
    fn crud() {
        let mut v = round_trip(|v| {
            v.set("openai", "sk-test-123");
            v.set("github", "gh-token");
        });
        assert_eq!(v.get("openai").as_deref(), Some("sk-test-123"));
        assert_eq!(v.get("github").as_deref(), Some("gh-token"));

        v.rename("openai", "OPENAI_API_KEY").unwrap();
        assert!(!v.exists("openai"));
        assert_eq!(v.get("OPENAI_API_KEY").as_deref(), Some("sk-test-123"));

        assert!(v.rename("OPENAI_API_KEY", "github").is_err());

        v.set("x", "1");
        v.set("y", "2");
        assert!(v.remove("x"));
        assert!(!v.remove("x"));

        let matches = v.search("git");
        assert_eq!(matches, vec!["github"]);
    }

    #[test]
    fn wrong_password_fails() {
        let mut v = Vault::create(PW).unwrap();
        let bytes = v.serialize().unwrap();
        assert!(Vault::unlock("wrong", &bytes).is_err());
    }

    #[test]
    fn change_password_works() {
        let mut v = Vault::create(PW).unwrap();
        v.set("k", "v");
        v.change_password("new-pw-123").unwrap();
        let bytes = v.serialize().unwrap();

        assert!(Vault::unlock(PW, &bytes).is_err());
        let unlocked = Vault::unlock("new-pw-123", &bytes).unwrap();
        assert_eq!(unlocked.get("k").as_deref(), Some("v"));
    }

    #[test]
    fn import_export_env() {
        let mut v = Vault::create(PW).unwrap();
        let env_content = "FOO=bar\nBAR=\"baz\"\n# comment\nexport QUX='val'\n";
        let (added, skipped, _) = v.import_env(env_content, false, false);
        assert_eq!(added, 3);
        assert_eq!(skipped, 0);

        assert_eq!(v.get("FOO").as_deref(), Some("bar"));
        assert_eq!(v.get("BAR").as_deref(), Some("baz"));
        assert_eq!(v.get("QUX").as_deref(), Some("val"));

        let (exported, skipped) = v.export_env();
        assert!(exported.contains("FOO=bar"));
        assert!(skipped.is_empty());
    }

    #[test]
    fn audit_detects_issues() {
        let mut v = Vault::create(PW).unwrap();
        v.set("invalid-name", "value12345");
        v.set("SHORT", "123");
        v.set("DUP1", "samevalue123");
        v.set("DUP2", "samevalue123");

        let report = v.audit();
        assert_eq!(report.total_secrets, 4);
        assert!(report
            .invalid_env_names
            .contains(&"invalid-name".to_string()));
        assert!(report.weak_secrets.contains(&"SHORT".to_string()));
        assert_eq!(report.duplicate_groups.len(), 1);
        let mut group = report.duplicate_groups[0].clone();
        group.sort();
        assert_eq!(group, vec!["DUP1".to_string(), "DUP2".to_string()]);
    }

    #[test]
    fn header_aad_stability() {
        // Golden vector: byte-exact AAD must never change for FORMAT_VERSION 2.
        // If this fails, existing vaults would stop decrypting.
        let header = VaultHeader {
            magic: MAGIC.into(),
            version: 2,
            kdf: "argon2id".into(),
            kdf_params: KdfParams {
                m_cost: 65536,
                t_cost: 3,
                p_cost: 4,
            },
            salt: B64.encode([7u8; 16]),
        };
        let aad = header_aad(&header).unwrap();
        let s = String::from_utf8(aad).unwrap();
        assert_eq!(
            s,
            format!(
                "{{\"magic\":\"SAGITARRIUS\",\"version\":2,\"kdf\":\"argon2id\",\
                 \"kdf_params\":{{\"m_cost\":65536,\"t_cost\":3,\"p_cost\":4}},\
                 \"salt\":\"{}\"}}",
                B64.encode([7u8; 16])
            )
        );
    }

    #[test]
    fn import_bom_comments_and_trailing_text() {
        let mut v = Vault::create(PW).unwrap();
        // BOM stripped; inline comments only outside quotes and only after
        // whitespace; trailing text after a closing quote skips the entry.
        let text = "\u{FEFF}BOMMED=1\nA=2 # comment\nB=\"x # y\"\nC=nospace#kept\n\
            D=\"v\" \nE=\"v\" # c\nF=\"v\" garbage\nG='w' junk\n";
        let (added, skipped, _) = v.import_env(text, false, false);
        assert_eq!((added, skipped), (6, 2));
        assert_eq!(v.get("BOMMED").as_deref(), Some("1"));
        assert_eq!(v.get("A").as_deref(), Some("2"));
        assert_eq!(v.get("B").as_deref(), Some("x # y"));
        assert_eq!(v.get("C").as_deref(), Some("nospace#kept"));
        assert_eq!(v.get("D").as_deref(), Some("v"));
        assert_eq!(v.get("E").as_deref(), Some("v"));
        assert!(v.get("F").is_none());
        assert!(v.get("G").is_none());
    }

    #[test]
    fn import_rejects_garbage_and_empty() {
        let mut v = Vault::create(PW).unwrap();
        // no '=', empty key, empty value, control chars, over-long handled
        let (added, skipped, _) = v.import_env("NOEQUALS\n=novalue\nEMPTY=\n", false, false);
        assert_eq!(added, 0);
        assert_eq!(skipped, 3);
        // '=' in name would corrupt .env output; must be skipped
        let (added, _, _) = v.import_env("A=B=C\n", false, false);
        assert_eq!(added, 1);
        assert_eq!(v.get("A").as_deref(), Some("B=C"));
    }

    #[test]
    fn import_dangerous_names_need_opt_in() {
        let mut v = Vault::create(PW).unwrap();
        // Space + shell metacharacters: skipped with the name reported...
        let (added, skipped, dangerous) =
            v.import_env("EVIL NAME=x\nFINE=1\nA;B=2\n", false, false);
        assert_eq!((added, skipped), (1, 2));
        assert_eq!(dangerous.len(), 2);
        assert!(v.get("FINE").is_some());
        assert!(v.get("EVIL NAME").is_none());
        // ...unless explicitly allowed.
        let (added, _, dangerous) = v.import_env("EVIL NAME=x\n", true, true);
        assert_eq!(added, 1);
        assert!(dangerous.is_empty());
        assert_eq!(v.get("EVIL NAME").as_deref(), Some("x"));
        // Portable-but-not-POSIX names (dashes) never needed the flag.
        let (added, _, dangerous) = v.import_env("ok-name=1\n", false, false);
        assert_eq!(added, 1);
        assert!(dangerous.is_empty());
        // NUL is rejected at the structural layer (never importable).
        let (added, skipped, _) = v.import_env("A\x00B=x\n", false, true);
        assert_eq!((added, skipped), (0, 1));
    }

    #[test]
    fn rename_rejects_bad_names() {
        let mut v = Vault::create(PW).unwrap();
        v.set("a", "1");
        assert!(v.rename("a", "").is_err());
        assert!(v.rename("a", "x\ny").is_err());
        assert!(v.rename("a", "x=y").is_err());
    }

    #[test]
    fn export_quotes_special_values() {
        let mut v = Vault::create(PW).unwrap();
        v.set("SPACED", "hello world #hash=eq");
        v.set("QUOTED", "she said \"hi\"");
        v.set("DOLLAR", "costs $5 and `tick`");
        v.set("MULTILINE", "line1\nline2");
        v.set("bad-name", "kept-in-vault");
        let (out, skipped) = v.export_env();
        // Single quotes whenever possible...
        assert!(out.contains("SPACED='hello world #hash=eq'"));
        assert!(out.contains("QUOTED='she said \"hi\"'"));
        assert!(out.contains("DOLLAR='costs $5 and `tick`'"));
        // ...double quotes with escapes only when single quotes cannot hold it.
        assert!(out.contains("MULTILINE=\"line1\\nline2\""));
        assert!(!out.contains("bad-name="));
        assert_eq!(skipped, vec!["bad-name".to_string()]);
        let mut v2 = Vault::create(PW).unwrap();
        let (added, _, _) = v2.import_env(&out, false, false);
        assert_eq!(added, 4);
        assert_eq!(v2.get("SPACED").as_deref(), Some("hello world #hash=eq"));
        assert_eq!(v2.get("QUOTED").as_deref(), Some("she said \"hi\""));
        assert_eq!(v2.get("DOLLAR").as_deref(), Some("costs $5 and `tick`"));
        assert_eq!(v2.get("MULTILINE").as_deref(), Some("line1\nline2"));
    }

    /// Deterministic xorshift64* — a property test without new dependencies.
    /// Fixed seed, 300 adversarial values through the real export/import
    /// path. One vault holds all values (a Vault::create per value would
    /// burn 600 Argon2 runs); names stay distinct so each value is checked.
    #[test]
    fn export_import_roundtrip_property() {
        let alphabet: Vec<char> = "abZ019 _-./:@%+,='#\"\\$`!&;<>|(){}[]^~?\t\n\r"
            .chars()
            .collect();
        let mut state: u64 = 0x243F_6A88_85A3_08D3;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut values = Vec::new();
        for _ in 0..300 {
            let len = 1 + (next() % 48) as usize;
            values.push(
                (0..len)
                    .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                    .collect::<String>(),
            );
        }
        let mut v = Vault::create(PW).unwrap();
        for (i, value) in values.iter().enumerate() {
            v.set(&format!("PROP_{i}"), value);
        }
        let (out, skipped) = v.export_env();
        assert!(skipped.is_empty());
        let mut v2 = Vault::create(PW).unwrap();
        let (added, skipped, _) = v2.import_env(&out, false, false);
        assert_eq!((added, skipped), (300, 0));
        for (i, value) in values.iter().enumerate() {
            let name = format!("PROP_{i}");
            assert_eq!(
                v2.get(&name).as_deref(),
                Some(value.as_str()),
                "no round-trip for {value:?}"
            );
        }
    }

    /// The exported file must be sourceable by POSIX sh with identical
    /// values. Shells cannot represent newlines portably, so newline values
    /// are excluded here (they round-trip through our own importer, tested
    /// above) — everything else must survive `. file` byte-for-byte.
    #[cfg(unix)]
    #[test]
    fn export_sources_cleanly_in_sh() {
        use std::io::Write;
        let values = [
            "plain",
            "hello world",
            "a=b",
            "hash#tag",
            "dollar$home",
            "back`tick",
            "say \"hi\"",
            "it's",
            "back\\slash",
            "semi;colon",
            "pipe|line",
            "star*quest",
            "tab\there",
            "trail ",
            " lead",
            "uni-héllo",
        ];
        let mut v = Vault::create(PW).unwrap();
        for (i, val) in values.iter().enumerate() {
            v.set(&format!("SH_{i}"), val);
        }
        let (out, _) = v.export_env();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(out.as_bytes()).unwrap();
        let path = f.path().to_str().unwrap().to_string();
        for (i, want) in values.iter().enumerate() {
            let script = format!(". \"{path}\"; printf '%s' \"$SH_{i}\"");
            let got = std::process::Command::new("sh")
                .args(["-c", &script])
                .output()
                .expect("sh must exist on unix CI");
            assert!(got.status.success());
            assert_eq!(
                String::from_utf8_lossy(&got.stdout).as_ref(),
                *want,
                "sh round-trip failed for {want:?}"
            );
        }
    }

    #[test]
    fn migrate_v2_bytes_to_v3() {
        use base64::{engine::general_purpose::STANDARD as B64t, Engine};
        // Hand-build a genuine v2 vault file (the old format): header +
        // whole-payload AES-GCM, one entry with fixed timestamps.
        let params = crate::crypto::KdfParams::default();
        let salt = [11u8; crate::crypto::SALT_LEN];
        let key = crate::crypto::derive_key(PW, &salt, params).unwrap();
        let header = VaultHeader {
            magic: MAGIC.into(),
            version: FORMAT_VERSION,
            kdf: "argon2id".into(),
            kdf_params: params,
            salt: B64t.encode(salt),
        };
        let payload = serde_json::json!({"secrets": {
            "LEGACY": {"value": "old-secret", "created_at": 111, "updated_at": 222}
        }});
        let aad = serde_json::to_vec(&header).unwrap();
        let plain = serde_json::to_vec(&payload).unwrap();
        let (nonce, ct) = crate::crypto::encrypt(&key, &plain, &aad).unwrap();
        let file = VaultFile {
            header,
            nonce: B64t.encode(nonce),
            ciphertext: B64t.encode(&ct),
        };
        let v2bytes = serde_json::to_vec_pretty(&file).unwrap();
        // Sanity: facade sees v2.
        assert!(!Vault::unlock(PW, &v2bytes).unwrap().is_v3());

        let v3bytes = migrate_v2_to_v3(PW, &v2bytes).unwrap();
        let v = Vault::unlock(PW, &v3bytes).unwrap();
        assert!(v.is_v3());
        assert_eq!(v.get("LEGACY").as_deref(), Some("old-secret"));
        // Timestamps preserved across the migration.
        let info = v.info("LEGACY").unwrap();
        assert_eq!((info.created_at, info.updated_at), (111, 222));
    }

    #[test]
    fn migrate_rejects_oversized_entry_before_writing() {
        use base64::{engine::general_purpose::STANDARD as B64m, Engine};
        // A v2 entry over the write cap must fail migration with a clear
        // error — never produce a vault that cannot be opened.
        let params = crate::crypto::KdfParams::default();
        let salt = [13u8; crate::crypto::SALT_LEN];
        let key = crate::crypto::derive_key(PW, &salt, params).unwrap();
        let header = VaultHeader {
            magic: MAGIC.into(),
            version: FORMAT_VERSION,
            kdf: "argon2id".into(),
            kdf_params: params,
            salt: B64m.encode(salt),
        };
        let big = "y".repeat(MAX_SECRET_VALUE_LEN + 1);
        let payload = serde_json::json!({"secrets": {"BIG": {"value": big, "created_at": 1, "updated_at": 1}}});
        let aad = serde_json::to_vec(&header).unwrap();
        let plain = serde_json::to_vec(&payload).unwrap();
        let (nonce, ct) = crate::crypto::encrypt(&key, &plain, &aad).unwrap();
        let file = VaultFile {
            header,
            nonce: B64m.encode(nonce),
            ciphertext: B64m.encode(&ct),
        };
        let v2bytes = serde_json::to_vec_pretty(&file).unwrap();
        let err = migrate_v2_to_v3(PW, &v2bytes).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn kdf_params_out_of_bounds_rejected() {
        let mut v = Vault::create(PW).unwrap();
        let bytes = v.serialize().unwrap();
        // Tamper with the v3 password wrap's KDF params: must fail fast,
        // before any Argon2 allocation (wrap AAD won't match either).
        let mut file: crate::vault_v3::VaultFileV3 = serde_json::from_slice(&bytes).unwrap();
        file.header.wraps[0].kdf_params.m_cost = 4 * 1024 * 1024;
        let evil = serde_json::to_vec(&file).unwrap();
        assert!(Vault::unlock(PW, &evil).is_err());
        // Zero time cost is equally invalid.
        file.header.wraps[0].kdf_params.m_cost = 65536;
        file.header.wraps[0].kdf_params.t_cost = 0;
        let evil = serde_json::to_vec(&file).unwrap();
        assert!(Vault::unlock(PW, &evil).is_err());
        // Sane params still open.
        assert!(Vault::unlock(PW, &bytes).is_ok());
    }

    #[test]
    fn oversized_payload_rejected() {
        // Unlock-time gate uses READ caps: absurd sizes fail closed...
        let mut absurd = Payload::default();
        absurd.secrets.insert(
            "k".into(),
            SecretEntry {
                value: "x".repeat(READ_MAX_SECRET_VALUE_LEN + 1),
                created_at: 0,
                updated_at: 0,
            },
        );
        assert!(validate_payload(&absurd).is_err());

        let mut too_many = Payload::default();
        for i in 0..(READ_MAX_SECRETS + 1) {
            too_many.secrets.insert(
                format!("k{i}"),
                SecretEntry {
                    value: "v".into(),
                    created_at: 0,
                    updated_at: 0,
                },
            );
        }
        assert!(validate_payload(&too_many).is_err());
    }

    #[test]
    fn read_caps_open_oversized_for_shrinking() {
        // Between write cap and read cap: opens fine (shrinkable).
        let mut big = Payload::default();
        big.secrets.insert(
            "k".into(),
            SecretEntry {
                value: "x".repeat(MAX_SECRET_VALUE_LEN + 1),
                created_at: 0,
                updated_at: 0,
            },
        );
        assert!(validate_payload(&big).is_ok());

        let sane = Payload::default();
        assert!(validate_payload(&sane).is_ok());
    }
}
