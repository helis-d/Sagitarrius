use thiserror::Error;

#[derive(Error, Debug)]
pub enum SagitarriusError {
    #[error("Sagitarrius has not been initialized.\nRun: sagitarrius init")]
    NotInitialized,

    #[error("vault already exists at {0}")]
    VaultExists(String),

    #[error("invalid master password or corrupted vault")]
    InvalidPassword,

    #[error("invalid vault format")]
    InvalidVaultFormat,

    #[error(
        "vault metadata failed integrity check (manifest MAC mismatch); \
         the record set or generation was modified outside Sagitarrius. \
         Restore from a verified snapshot or backup"
    )]
    ManifestIntegrity,

    #[error("unsupported vault version: {0}")]
    UnsupportedVersion(u32),

    #[error("secret {0:?} not found")]
    SecretNotFound(String),

    #[error("secret {0:?} already exists")]
    SecretAlreadyExists(String),

    #[error("secret value must not be empty")]
    EmptySecretValue,

    #[error("passwords do not match")]
    PasswordMismatch,

    #[error("secret values do not match")]
    ValuesMismatch,

    #[error("master password must not be empty")]
    EmptyPassword,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),

    /// CLI usage errors: bad flags, bad values, missing required selections.
    /// Like every other failure, these exit 2 (see `main`); clean negative
    /// results (`exists` absent, `search` no match, `audit` findings) return
    /// `Ok(1)` instead and never pass through here.
    #[error("{0}")]
    Usage(String),
}

pub type Result<T> = std::result::Result<T, SagitarriusError>;
