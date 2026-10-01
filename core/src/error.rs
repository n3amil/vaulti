use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Wrong master password / backup code, or the data was tampered with.
    /// Deliberately not distinguished.
    #[error("decryption failed (wrong password/backup code or corrupted data)")]
    Decrypt,
    #[error("invalid backup code format")]
    InvalidBackupCode,
    #[error("invalid signature")]
    BadSignature,
    #[error("not allowed: {0}")]
    NotAllowed(String),
    #[error("unsupported vault format version {0}")]
    UnsupportedFormat(u32),
    #[error("invalid KDF parameters: {0}")]
    Kdf(String),
    #[error("malformed data: {0}")]
    Malformed(String),
    #[error("collection not found")]
    CollectionNotFound,
    #[error("entry not found")]
    EntryNotFound,
    #[error("contact not found")]
    ContactNotFound,
    #[error("this vault was copied from another device; finish pairing first")]
    NeedsDeviceSetup,
    #[error("randomness unavailable: {0}")]
    Random(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
