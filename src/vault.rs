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
    pub duplicate_values: Vec<(String, String)>,
    pub weak_secrets: Vec<String>,
}

pub struct Vault {
    header: VaultHeader,
    key: DerivedKey,
    payload: Payload,
}

impl Drop for Vault {
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

impl Vault {
    /// Create a brand new in-memory vault with an empty secret store.
    pub fn create(password: &str) -> Result<Self> {
        let salt = crypto::random_salt();
        let params = KdfParams::default();
        let key = crypto::derive_key(password, &salt, params)?;
        let header = VaultHeader {
            magic: MAGIC.into(),
            version: FORMAT_VERSION,
            kdf: "argon2id".into(),
            kdf_params: params,
            salt: B64.encode(salt),
        };
        Ok(Self {
            header,
            key,
            payload: Payload::default(),
        })
    }

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

    pub fn secrets(&self) -> BTreeMap<String, String> {
        self.payload
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), v.value.clone()))
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

    pub fn import_env(&mut self, env_text: &str, overwrite: bool) -> (usize, usize) {
        let mut added = 0;
        let mut skipped = 0;

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

            let val = parse_env_value(val_trimmed);

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
        (added, skipped)
    }

    pub fn export_env(&self) -> String {
        let mut out = String::new();
        for (k, entry) in &self.payload.secrets {
            if is_valid_env_name(k) {
                out.push_str(&format!("{k}={}\n", escape_env_value(&entry.value)));
            }
        }
        out
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

        for (_val, names) in seen_values {
            if names.len() > 1 {
                for i in 0..names.len() {
                    for j in (i + 1)..names.len() {
                        report
                            .duplicate_values
                            .push((names[i].to_string(), names[j].to_string()));
                    }
                }
            }
        }

        report
    }
}

fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Structural validation for secret names. Deliberately permissive about
/// dashes/dots (existing vaults and tests use `github-token`), but rejects
/// what would spoof terminal/`.env` output or break the format:
/// empty, over-long, `=`, newlines/NUL and other ASCII control codes.
pub(crate) fn validate_secret_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(SagitarriusError::EmptySecretName);
    }
    if name.len() > MAX_SECRET_NAME_LEN {
        return Err(SagitarriusError::Other(format!(
            "secret name must be at most {MAX_SECRET_NAME_LEN} bytes"
        )));
    }
    if name.contains('=')
        || name.contains('\n')
        || name.contains('\r')
        || name.contains('\0')
        || name.chars().any(|c| c.is_ascii_control())
    {
        return Err(SagitarriusError::Other(format!(
            "invalid secret name {name:?}: must not contain '=', newlines or control characters"
        )));
    }
    Ok(())
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
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn parse_env_value(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        unescape_double_quoted(&raw[1..raw.len() - 1])
    } else if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        // Single-quoted: literal, no escape processing (shell-like).
        raw[1..raw.len() - 1].to_string()
    } else {
        raw.to_string()
    }
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
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
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
        let v = Vault::create(PW).unwrap();
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
        assert_eq!(v.get("openai"), Some("sk-test-123"));
        assert_eq!(v.get("github"), Some("gh-token"));

        v.rename("openai", "OPENAI_API_KEY").unwrap();
        assert!(!v.exists("openai"));
        assert_eq!(v.get("OPENAI_API_KEY"), Some("sk-test-123"));

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
        let v = Vault::create(PW).unwrap();
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
        assert_eq!(unlocked.get("k"), Some("v"));
    }

    #[test]
    fn import_export_env() {
        let mut v = Vault::create(PW).unwrap();
        let env_content = "FOO=bar\nBAR=\"baz\"\n# comment\nexport QUX='val'\n";
        let (added, skipped) = v.import_env(env_content, false);
        assert_eq!(added, 3);
        assert_eq!(skipped, 0);

        assert_eq!(v.get("FOO"), Some("bar"));
        assert_eq!(v.get("BAR"), Some("baz"));
        assert_eq!(v.get("QUX"), Some("val"));

        let exported = v.export_env();
        assert!(exported.contains("FOO=bar"));
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
        assert_eq!(report.duplicate_values.len(), 1);
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
    fn import_rejects_garbage_and_empty() {
        let mut v = Vault::create(PW).unwrap();
        // no '=', empty key, empty value, control chars, over-long handled
        let (added, skipped) = v.import_env("NOEQUALS\n=novalue\nEMPTY=\n", false);
        assert_eq!(added, 0);
        assert_eq!(skipped, 3);
        // '=' in name would corrupt .env output; must be skipped
        let (added, _) = v.import_env("A=B=C\n", false);
        assert_eq!(added, 1);
        assert_eq!(v.get("A"), Some("B=C"));
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
        let out = v.export_env();
        assert!(out.contains("SPACED=\"hello world #hash=eq\""));
        let mut v2 = Vault::create(PW).unwrap();
        let (added, _) = v2.import_env(&out, false);
        assert_eq!(added, 1);
        assert_eq!(v2.get("SPACED"), Some("hello world #hash=eq"));
    }
}
