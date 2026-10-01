//! Encrypted backups: all readable collections and entries in one file,
//! protected by a backup password (Argon2id + XChaCha20-Poly1305).
//!
//! The backup holds only data (collection names and entries), not keys,
//! devices or contacts, so it can be imported into any vault, e.g. a new
//! one after losing all devices.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{derive_key, open, random_salt, seal, KdfParams, Sealed};
use crate::error::{Error, Result};

pub const FORMAT: &str = "vaulti-backup";
pub const VERSION: u32 = 1;
const AAD: &[u8] = b"vaulti/backup/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFile {
    pub format: String,
    pub version: u32,
    pub created_at: u64,
    pub kdf: KdfParams,
    #[serde(with = "crate::b64")]
    pub salt: Vec<u8>,
    pub sealed: Sealed,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupData {
    pub exported_at: u64,
    pub collections: Vec<BackupCollection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCollection {
    pub name: String,
    pub entries: Vec<BackupEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupEntry {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    pub created_at: u64,
}

impl BackupEntry {
    /// Same login (ignores notes and timestamps).
    pub(crate) fn same_as(&self, other: &BackupEntry) -> bool {
        self.title == other.title
            && self.username == other.username
            && self.password == other.password
            && self.url == other.url
    }
}

/// What an import did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    pub collections_created: usize,
    pub entries_added: usize,
    pub entries_skipped: usize,
}

pub fn seal_backup(data: &BackupData, password: &str, kdf: KdfParams) -> Result<BackupFile> {
    let salt = random_salt()?;
    let key = derive_key(password.as_bytes(), &salt, &kdf)?;
    let plain = Zeroizing::new(serde_json::to_vec(data)?);
    Ok(BackupFile {
        format: FORMAT.into(),
        version: VERSION,
        created_at: data.exported_at,
        kdf,
        salt,
        sealed: seal(&key, &plain, AAD)?,
    })
}

pub fn open_backup(file: &BackupFile, password: &str) -> Result<BackupData> {
    if file.format != FORMAT {
        return Err(Error::Malformed("not a Vaulti backup".into()));
    }
    if file.version != VERSION {
        return Err(Error::UnsupportedFormat(file.version));
    }
    let key = derive_key(password.as_bytes(), &file.salt, &file.kdf)?;
    let plain = open(&key, &file.sealed, AAD)?;
    Ok(serde_json::from_slice(&plain)?)
}

/// Serialized form for writing to disk.
pub fn to_bytes(file: &BackupFile) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(file)?)
}

pub fn from_bytes(bytes: &[u8]) -> Result<BackupFile> {
    serde_json::from_slice(bytes).map_err(|_| Error::Malformed("not a Vaulti backup file".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BackupData {
        BackupData {
            exported_at: 1,
            collections: vec![BackupCollection {
                name: "Personal".into(),
                entries: vec![BackupEntry {
                    title: "GitHub".into(),
                    username: Some("me".into()),
                    password: "pw".into(),
                    url: None,
                    notes: None,
                    totp: Some("JBSWY3DPEHPK3PXP".into()),
                    created_at: 1,
                }],
            }],
        }
    }

    #[test]
    fn roundtrip_and_wrong_password() {
        let f = seal_backup(&sample(), "backup pw", KdfParams::insecure_fast()).unwrap();
        let bytes = to_bytes(&f).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("GitHub"), "contents are encrypted");
        let back = open_backup(&from_bytes(&bytes).unwrap(), "backup pw").unwrap();
        assert_eq!(back.collections[0].entries, sample().collections[0].entries);
        assert!(matches!(open_backup(&f, "wrong"), Err(Error::Decrypt)));
    }

    #[test]
    fn rejects_other_files() {
        assert!(from_bytes(b"{\"hello\": 1}").is_err());
        let mut f = seal_backup(&sample(), "pw", KdfParams::insecure_fast()).unwrap();
        f.format = "something".into();
        assert!(open_backup(&f, "pw").is_err());
    }
}
