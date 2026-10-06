use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage::{self, VaultLock};
use crate::vault::Vault;
use crate::vault_v3::RecordPayload;
use zeroize::Zeroize;

pub fn run(
    name: String,
    value: Option<String>,
    kind: String,
    username: Option<String>,
) -> Result<i32> {
    crate::vault::validate_secret_name(&name)?;
    crate::storage::ensure_unlocked()?;
    let kind = crate::vault_v3::RecordKind::parse(&kind).ok_or_else(|| {
        SagitarriusError::Usage(
            "unknown --kind (expected secret|password|note|credential|document)".into(),
        )
    })?;
    if kind == crate::vault_v3::RecordKind::File {
        return Err(SagitarriusError::Usage(
            "file records are created with `sagitarrius file put <path>`".into(),
        ));
    }

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

    if vault.exists(&name) {
        return Err(SagitarriusError::SecretAlreadyExists(name));
    }

    let (mut v1, mut v2) = match value {
        Some(v) => {
            eprintln!(
                "Warning: passing a secret on the command line may expose it through \
                 shell history or process listings. Prefer interactive input."
            );
            (v.clone(), v)
        }
        None => {
            let v1 = input::read_secret("Enter secret value: ")?;
            let v2 = input::read_secret("Confirm secret value: ")?;
            (v1, v2)
        }
    };

    if v1.trim().is_empty() {
        v1.zeroize();
        v2.zeroize();
        return Err(SagitarriusError::EmptySecretValue);
    }
    if v1.contains('\0') {
        v1.zeroize();
        v2.zeroize();
        return Err(SagitarriusError::Usage(format!(
            "secret {name:?} contains a NUL byte and cannot be stored"
        )));
    }
    if v1.len() > crate::vault::MAX_SECRET_VALUE_LEN {
        v1.zeroize();
        v2.zeroize();
        return Err(SagitarriusError::Other(format!(
            "secret value must be at most {} bytes",
            crate::vault::MAX_SECRET_VALUE_LEN
        )));
    }
    if v1 != v2 {
        v1.zeroize();
        v2.zeroize();
        return Err(SagitarriusError::ValuesMismatch);
    }
    v2.zeroize();

    if vault.names().len() >= crate::vault::MAX_SECRETS {
        v1.zeroize();
        return Err(SagitarriusError::Other(format!(
            "vault already holds {} secrets",
            crate::vault::MAX_SECRETS
        )));
    }

    // Credential records pair a (non-secret) username with the secret value.
    let mut username = username;
    if kind == crate::vault_v3::RecordKind::Credential && username.is_none() {
        let mut u = input::read_line("Username: ")?;
        if u.trim().is_empty() {
            u.zeroize();
            v1.zeroize();
            return Err(SagitarriusError::Other("username must not be empty".into()));
        }
        username = Some(u);
    }
    let payload = match kind {
        crate::vault_v3::RecordKind::Secret => RecordPayload::Secret { value: v1.clone() },
        crate::vault_v3::RecordKind::Password => RecordPayload::Password { value: v1.clone() },
        crate::vault_v3::RecordKind::Note => RecordPayload::Note { value: v1.clone() },
        crate::vault_v3::RecordKind::Document => RecordPayload::Document { value: v1.clone() },
        crate::vault_v3::RecordKind::Credential => RecordPayload::Credential {
            username: username.clone().unwrap_or_default(),
            password: v1.clone(),
        },
        crate::vault_v3::RecordKind::File => unreachable!("rejected above"),
    };
    v1.zeroize();
    vault.set_typed(&name, payload)?;
    if let Some(mut u) = username {
        u.zeroize();
    }

    let out = vault.serialize()?;
    storage::write_vault_atomic(&out)?;
    crate::state::store_generation(&vault)?;

    eprintln!("Secret {name:?} added successfully.");
    Ok(0)
}
