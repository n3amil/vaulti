use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Wrong master password / backup code, or the data was tampered with.
    /// Deliberately not distinguished.
    #[error("decryption failed (wrong password/backup code or corrupted data)")]
    Decrypt,
    #[error("invalid backup code format")]
    InvalidBackupCode,
    #[error("unsupported vault format version {0}")]
    UnsupportedFormat(u32),
    #[error("invalid KDF parameters: {0}")]
    Kdf(String),
    #[error("malformed vault: {0}")]
    Malformed(String),
    #[error("collection not found")]
    CollectionNotFound,
    #[error("entry not found")]
    EntryNotFound,
    #[error("randomness unavailable: {0}")]
    Random(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
