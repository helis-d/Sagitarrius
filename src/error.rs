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

    #[error("unsupported vault version: {0}")]
    UnsupportedVersion(u32),

    #[error("secret {0:?} not found")]
    SecretNotFound(String),

    #[error("secret {0:?} already exists")]
    SecretAlreadyExists(String),

    #[error("secret name must not be empty")]
    EmptySecretName,

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
}

pub type Result<T> = std::result::Result<T, SagitarriusError>;
