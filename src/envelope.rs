//! Envelope encryption: a random Vault Master Key (VMK) wrapped by one or
//! more Key-Encryption Keys (password, recovery, ...).
//!
//! ```text
//!              random VMK (32 bytes, never derived)
//!                         |
//!          +--------------+--------------+
//!          |              |              |
//!     password wrap  recovery wrap   (future: device wrap)
//!     Argon2id KEK    Argon2id KEK
//! ```
//!
//! Record/file keys come from HKDF-SHA256 over the VMK with explicit domain
//! separation labels, so one key is never reused for unrelated purposes.
//! Wraps are AES-256-GCM; the wrap AAD binds magic, format version, vault
//! id, wrap kind, KDF params and salt — all immutable for the wrap's life.
//! (The mutable generation counter is intentionally *not* in wrap AAD:
//! recovery wraps could not otherwise survive ordinary writes.)

use crate::crypto::{self, DerivedKey, KdfParams, KEY_LEN};
use crate::error::{Result, SagitarriusError};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separation labels. One VMK, many purposes — never one key twice.
pub const LABEL_RECORD: &str = "SAGITARRIUS/v3/record";
pub const LABEL_FILE: &str = "SAGITARRIUS/v3/file";
pub const LABEL_MANIFEST: &str = "SAGITARRIUS/v3/manifest";

/// The Vault Master Key: randomly generated, never derived from anything.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultMasterKey([u8; KEY_LEN]);

impl VaultMasterKey {
    pub fn generate() -> Self {
        let mut b = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut b);
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// HKDF-SHA256(VMK, salt, info) -> 32-byte sub-key with domain separation.
    pub fn derive_subkey(&self, salt: &[u8], info: &str) -> DerivedKey {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut out = [0u8; KEY_LEN];
        hk.expand(info.as_bytes(), &mut out)
            .expect("hkdf expand with fixed 32-byte output cannot fail");
        let key = DerivedKey::from_bytes(out);
        out.zeroize();
        key
    }
}

/// Manifest authentication key: HKDF(VMK, salt=vault_id, info=LABEL_MANIFEST).
pub fn manifest_key(vmk: &VaultMasterKey, vault_id_b64: &str) -> DerivedKey {
    let salt = base64_decode_or_empty(vault_id_b64);
    vmk.derive_subkey(&salt, LABEL_MANIFEST)
}

fn base64_decode_or_empty(s: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    B64.decode(s).unwrap_or_default()
}

/// HMAC-SHA256 over `message` under `key`. Constant-time verification via
/// [`verify_mac`].
pub fn compute_mac(key: &DerivedKey, message: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC takes any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time MAC check. Failure collapses to `InvalidVaultFormat`
/// (metadata tamper, not a password error — wrong passwords already fail at
/// the wrap unwrap step before this runs).
pub fn verify_mac(key: &DerivedKey, message: &[u8], tag: &[u8]) -> Result<()> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC takes any key length");
    mac.update(message);
    mac.verify_slice(tag)
        .map_err(|_| SagitarriusError::InvalidVaultFormat)
}
/// Wrap (encrypt) the VMK under a KEK. Returns (nonce, wrapped).
pub fn wrap_vmk(
    kek: &DerivedKey,
    vmk: &VaultMasterKey,
    aad: &[u8],
) -> Result<([u8; crypto::NONCE_LEN], Vec<u8>)> {
    crypto::encrypt(kek, vmk.as_bytes(), aad)
}

/// Unwrap (decrypt) the VMK. Any failure collapses to `InvalidPassword`,
/// exactly like vault decryption: wrong secret vs. tampered wrap is not
/// distinguished.
pub fn unwrap_vmk(
    kek: &DerivedKey,
    nonce: &[u8],
    wrapped: &[u8],
    aad: &[u8],
) -> Result<VaultMasterKey> {
    let mut raw = crypto::decrypt(kek, nonce, wrapped, aad)?;
    if raw.len() != KEY_LEN {
        raw.zeroize();
        return Err(SagitarriusError::InvalidPassword);
    }
    let mut b = [0u8; KEY_LEN];
    b.copy_from_slice(&raw);
    raw.zeroize();
    Ok(VaultMasterKey(b))
}

/// Canonical wrap AAD: every immutable parameter of the wrap.
pub fn wrap_aad(vault_id_b64: &str, kind: &str, params: KdfParams, salt_b64: &str) -> Vec<u8> {
    format!(
        "SAGITARRIUS/v3/wrap|{vault_id_b64}|{kind}|{}|{}|{}|{salt_b64}",
        params.m_cost, params.t_cost, params.p_cost
    )
    .into_bytes()
}

/// Generate a recovery code: 256 bits, hex in 16 groups of 4 for reliable
/// transcription. The code itself is never stored — only its Argon2id wrap.
pub fn generate_recovery_code() -> (String, [u8; 32]) {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let grouped: Vec<String> = hex
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    (grouped.join("-"), raw)
}

/// Parse a recovery code back to bytes. Accepts dashes/spaces/case
/// variations; rejects anything that is not 64 hex digits.
pub fn parse_recovery_code(s: &str) -> Result<[u8; 32]> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if clean.len() != 64 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SagitarriusError::Other(
            "invalid recovery code: expected 64 hex digits".into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in clean.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk)
            .map_err(|_| SagitarriusError::Other("invalid recovery code".into()))?;
        out[i] = u8::from_str_radix(hex, 16)
            .map_err(|_| SagitarriusError::Other("invalid recovery code".into()))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        KdfParams {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn wrap_roundtrip() {
        let salt = crypto::random_salt();
        let kek = crypto::derive_key("pw", &salt, test_params()).unwrap();
        let vmk = VaultMasterKey::generate();
        let aad = wrap_aad("vault-id", "password", test_params(), "salt");
        let (nonce, wrapped) = wrap_vmk(&kek, &vmk, &aad).unwrap();
        let back = unwrap_vmk(&kek, &nonce, &wrapped, &aad).unwrap();
        assert_eq!(back.as_bytes(), vmk.as_bytes());
    }

    #[test]
    fn wrong_kek_fails() {
        let salt = crypto::random_salt();
        let k1 = crypto::derive_key("a", &salt, test_params()).unwrap();
        let k2 = crypto::derive_key("b", &salt, test_params()).unwrap();
        let vmk = VaultMasterKey::generate();
        let aad = wrap_aad("vault-id", "password", test_params(), "salt");
        let (nonce, wrapped) = wrap_vmk(&k1, &vmk, &aad).unwrap();
        assert!(unwrap_vmk(&k2, &nonce, &wrapped, &aad).is_err());
    }

    #[test]
    fn tampered_wrap_aad_fails() {
        let salt = crypto::random_salt();
        let kek = crypto::derive_key("pw", &salt, test_params()).unwrap();
        let vmk = VaultMasterKey::generate();
        let aad = wrap_aad("vault-id", "password", test_params(), "salt");
        let (nonce, wrapped) = wrap_vmk(&kek, &vmk, &aad).unwrap();
        let bad = wrap_aad("other-vault", "password", test_params(), "salt");
        assert!(unwrap_vmk(&kek, &nonce, &wrapped, &bad).is_err());
    }

    #[test]
    fn subkeys_differ_by_domain() {
        let vmk = VaultMasterKey::generate();
        let r = vmk.derive_subkey(b"salt", LABEL_RECORD);
        let f = vmk.derive_subkey(b"salt", LABEL_FILE);
        assert_ne!(r.as_bytes(), f.as_bytes());
        let r2 = vmk.derive_subkey(b"salt", LABEL_RECORD);
        assert_eq!(r.as_bytes(), r2.as_bytes());
    }

    #[test]
    fn recovery_code_roundtrip() {
        let (text, raw) = generate_recovery_code();
        assert_eq!(text.len(), 64 + 15); // 16 groups + 15 dashes
        assert_eq!(parse_recovery_code(&text).unwrap(), raw);
        // Case/space tolerant.
        assert_eq!(
            parse_recovery_code(&text.to_uppercase().replace('-', " ")).unwrap(),
            raw
        );
        assert!(parse_recovery_code("too-short").is_err());
    }
}
