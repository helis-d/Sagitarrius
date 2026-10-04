//! Cryptographic primitives: Argon2id KDF and AES-256-GCM AEAD.
//!
//! Design decisions:
//!
//! * **Argon2id** is used as the password-based KDF. Its parameters
//!   (m=64MiB, t=3, p=4) match the OWASP 2023 recommendation.
//! * **AES-256-GCM** is used for authenticated encryption. It is
//!   hardware-accelerated on virtually every modern CPU (AES-NI / ARMv8
//!   crypto) and extremely well-audited. ChaCha20-Poly1305 would be the
//!   better choice only on platforms without AES acceleration.
//! * The header (KDF params, salt, magic, version) is bound to the
//!   ciphertext via AEAD additional authenticated data. Any tampering
//!   with the header fails authentication.

use crate::error::{Result, SagitarriusError};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{Rng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // OWASP 2023 recommendation for Argon2id.
        Self {
            m_cost: 64 * 1024, // 64 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey([u8; KEY_LEN]);

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Cryptographically secure random salt.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Cryptographically secure random nonce. A fresh nonce is used for every
/// encryption operation, so nonce reuse is impossible unless the RNG is
/// catastrophically broken.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Cryptographically secure random password / secret generator.
///
/// Uses rejection-free uniform sampling (`gen_range`) so every character in
/// the charset is equally likely (no `% len` modulo bias).
pub fn random_secret(length: usize, include_symbols: bool) -> String {
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

    let charset = if include_symbols {
        [ALPHA, SYMBOLS].concat()
    } else {
        ALPHA.to_vec()
    };
    debug_assert!(!charset.is_empty());

    let mut rng = rand::thread_rng();
    let mut result = Vec::with_capacity(length);
    for _ in 0..length {
        // `gen_range` is uniform over the range (rejection sampling
        // internally), unlike `byte % len`.
        let idx: usize = rng.gen_range(0..charset.len());
        result.push(charset[idx]);
    }

    String::from_utf8(result).unwrap_or_default()
}

pub fn derive_key(password: &str, salt: &[u8], params: KdfParams) -> Result<DerivedKey> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|e| SagitarriusError::Other(format!("invalid kdf params: {e}")))?,
    );
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| SagitarriusError::Other(format!("kdf failure: {e}")))?;
    Ok(DerivedKey(key))
}

pub fn encrypt(
    key: &DerivedKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SagitarriusError::Other("encryption failed".into()))?;
    Ok((nonce_bytes, ct))
}

/// Any failure mode (wrong key, tampered ciphertext, tampered AAD,
/// truncated data) collapses to `InvalidPassword` so that we never reveal
/// which internal check failed.
pub fn decrypt(key: &DerivedKey, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(SagitarriusError::InvalidPassword);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SagitarriusError::InvalidPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        // Deliberately weak for tests only.
        KdfParams {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn kdf_deterministic() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key("hunter2", &salt, fast_params()).unwrap();
        let b = derive_key("hunter2", &salt, fast_params()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn kdf_salt_matters() {
        let a = derive_key("hunter2", &[1u8; SALT_LEN], fast_params()).unwrap();
        let b = derive_key("hunter2", &[2u8; SALT_LEN], fast_params()).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn kdf_password_matters() {
        let salt = [3u8; SALT_LEN];
        let a = derive_key("a", &salt, fast_params()).unwrap();
        let b = derive_key("b", &salt, fast_params()).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn roundtrip() {
        let key = derive_key("pw", &[0u8; SALT_LEN], fast_params()).unwrap();
        let aad = b"header";
        let (nonce, ct) = encrypt(&key, b"hello world", aad).unwrap();
        let pt = decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = derive_key("a", &[0u8; SALT_LEN], fast_params()).unwrap();
        let k2 = derive_key("b", &[0u8; SALT_LEN], fast_params()).unwrap();
        let (nonce, ct) = encrypt(&k1, b"x", b"").unwrap();
        assert!(decrypt(&k2, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let k = derive_key("p", &[0u8; SALT_LEN], fast_params()).unwrap();
        let (nonce, mut ct) = encrypt(&k, b"hello", b"").unwrap();
        ct[0] ^= 1;
        assert!(decrypt(&k, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let k = derive_key("p", &[0u8; SALT_LEN], fast_params()).unwrap();
        let (mut nonce, ct) = encrypt(&k, b"hello", b"").unwrap();
        nonce[0] ^= 1;
        assert!(decrypt(&k, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn tampered_aad_fails() {
        let k = derive_key("p", &[0u8; SALT_LEN], fast_params()).unwrap();
        let (nonce, ct) = encrypt(&k, b"hello", b"aad-1").unwrap();
        assert!(decrypt(&k, &nonce, &ct, b"aad-2").is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let k = derive_key("p", &[0u8; SALT_LEN], fast_params()).unwrap();
        let (nonce, ct) = encrypt(&k, b"hello", b"").unwrap();
        assert!(decrypt(&k, &nonce, &ct[..ct.len() / 2], b"").is_err());
    }

    #[test]
    fn salts_differ() {
        assert_ne!(random_salt(), random_salt());
    }

    #[test]
    fn nonces_differ() {
        assert_ne!(random_nonce(), random_nonce());
    }
}
