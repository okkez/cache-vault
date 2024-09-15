use thiserror::Error;

#[derive(Error, Debug)]
pub enum CacheVaultError {
    #[error("keyring error")]
    Keyring(#[from] keyring::Error),

    #[error("crypt error")]
    ChaCha20(#[from] chacha20poly1305::Error),

    #[error("base32 decode error")]
    Decode,

    #[error("sqlx error")]
    SqlxError(#[from] sqlx::Error),

    #[error("migrate error")]
    MigrateError(#[from] sqlx::migrate::MigrateError),

    #[error("convert bytes to utf8 string error")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error("Unknown error")]
    Unknown(String),

    #[error("anyhow error with context")]
    AnyhowError(#[from] anyhow::Error),
}
