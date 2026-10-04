//! Recovery kit: survive a lost master password.
//!
//! `recovery create` generates a random 256-bit recovery code, stores only
//! its Argon2id *wrap* of the VMK in the vault header, and prints the code
//! exactly once. The code is never written to disk by Sagitarrius — write it
//! on paper, store it offline and apart from the vault. Anyone holding the
//! code AND the vault file can reset the password, so treat it like a key.
//!
//! `verify` checks a code without changing anything. `reset-password`
//! installs a fresh password wrap using only the code: the old password
//! stops working, the recovery wrap keeps working, records are untouched.

use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use zeroize::Zeroize;

fn read_code() -> Result<[u8; 32]> {
    let mut code = input::read_secret("Recovery code: ")?;
    let raw = crate::envelope::parse_recovery_code(&code);
    code.zeroize();
    raw
}

pub fn create() -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let _lock = VaultLock::acquire()?;
    let mut data = storage::read_vault()?;

    let mut password = input::master_password("Master password: ")?;
    let mut vault = match Vault::unlock(&password, &data) {
        Ok(v) => v,
        Err(e) => {
            password.zeroize();
            data.zeroize();
            return Err(e);
        }
    };
    password.zeroize();
    data.zeroize();
    crate::state::verify_generation(&vault)?;

    if vault.has_recovery() {
        return Err(SagitarriusError::Other(
            "a recovery wrap already exists on this vault".into(),
        ));
    }

    let (code_text, code_raw) = crate::envelope::generate_recovery_code();
    vault.add_recovery(&code_raw)?;
    let mut code_raw = code_raw;
    code_raw.zeroize();

    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;
    crate::state::store_generation(&vault)?;

    eprintln!("Recovery wrap stored. NOW WRITE THIS DOWN — it is shown ONCE,");
    eprintln!("never again, and never stored on this machine:");
    eprintln!();
    println!("{code_text}");
    eprintln!();
    eprintln!(
        "Keep it offline and AWAY from the vault file. Anyone with this code \
         AND a copy of vault.json can set a new master password. Check it \
         with `sagitarrius recovery verify`."
    );
    Ok(0)
}

pub fn verify() -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let data = storage::read_vault()?;
    let mut raw = read_code()?;
    // Header-only: no password involved. Success proves the code unwraps the
    // VMK of *this* vault file.
    let ok = crate::vault_v3::VaultV3::unlock_with_recovery(&data, &raw).map(|_| ());
    raw.zeroize();
    match ok {
        Ok(()) => {
            eprintln!("Recovery code is VALID for this vault.");
            Ok(0)
        }
        Err(e) => {
            eprintln!("Recovery code FAILED: {e}");
            Ok(1)
        }
    }
}

pub fn reset_password() -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    let _lock = VaultLock::acquire()?;
    let data = storage::read_vault()?;

    let mut raw = read_code()?;
    let mut vault = match crate::vault_v3::VaultV3::unlock_with_recovery(&data, &raw) {
        Ok(v) => Vault::V3(v),
        Err(e) => {
            raw.zeroize();
            return Err(e);
        }
    };

    let mut new1 = input::read_secret("Enter NEW master password: ")?;
    if new1.trim().is_empty() {
        new1.zeroize();
        raw.zeroize();
        return Err(SagitarriusError::EmptyPassword);
    }
    let mut new2 = input::read_secret("Confirm NEW master password: ")?;
    if new1 != new2 {
        new1.zeroize();
        new2.zeroize();
        raw.zeroize();
        return Err(SagitarriusError::PasswordMismatch);
    }
    new2.zeroize();

    vault.reset_password_via_recovery(&raw, &new1)?;
    raw.zeroize();
    new1.zeroize();

    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;
    crate::state::store_generation(&vault)?;
    eprintln!(
        "Master password reset. The old password no longer works; the recovery code still does."
    );
    Ok(0)
}
