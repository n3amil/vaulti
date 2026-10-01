//! Vault format and the unlocked in-memory vault.
//!
//! Key hierarchy:
//! ```text
//! root key (random) ──wrapped by── Argon2id(master password)  [password slot]
//!                   └─wrapped by── Argon2id(backup code)      [recovery slot]
//! root key ─wraps─▶ identity secret keys (ed25519 + x25519, for sharing later)
//! root key ─wraps─▶ collection key ─encrypts─▶ collection data
//! ```
//! Changing the password or rotating the backup code only rewraps the root
//! key; nothing else is re-encrypted.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, derive_key, open, random_salt, seal, KdfParams, Key, Sealed, KEY_LEN};
use crate::error::{Error, Result};
use crate::model::{now, Collection, Entry, EntryInput};
use crate::recovery::BackupCode;

pub const FORMAT_VERSION: u32 = 1;
pub const DEFAULT_COLLECTION: &str = "Personal";

/// What is written to disk. Everything secret is inside a `Sealed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub format: u32,
    pub vault_id: Uuid,
    pub kdf: KdfParams,
    pub password_slot: KeySlot,
    pub recovery_slot: KeySlot,
    pub identity_public: IdentityPublic,
    pub identity_secret: Sealed,
    pub collections: Vec<CollectionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    #[serde(with = "crate::b64")]
    pub salt: Vec<u8>,
    pub wrapped_root: Sealed,
}

/// Public half of the user's identity. Will be shared with other users so
/// they can wrap collection keys for us.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPublic {
    #[serde(with = "crate::b64")]
    pub signing: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub encryption: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionRecord {
    pub id: Uuid,
    pub wrapped_key: Sealed,
    pub data: Sealed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CollectionData {
    name: String,
    entries: Vec<Entry>,
    updated_at: u64,
}

struct OpenCollection {
    key: Key,
    wrapped_key: Sealed,
    inner: Collection,
}

/// An unlocked vault. Holds the root key in memory until dropped.
pub struct Vault {
    vault_id: Uuid,
    kdf: KdfParams,
    password_slot: KeySlot,
    recovery_slot: KeySlot,
    identity_public: IdentityPublic,
    identity_secret: Sealed,
    root: Key,
    collections: Vec<OpenCollection>,
}

fn aad(vault_id: &Uuid, purpose: &str) -> Vec<u8> {
    format!("vaulti/v{FORMAT_VERSION}/{vault_id}/{purpose}").into_bytes()
}

const AAD_PASSWORD: &str = "slot/password";
const AAD_RECOVERY: &str = "slot/recovery";
const AAD_IDENTITY: &str = "identity";

fn aad_ckey(vault_id: &Uuid, cid: &Uuid) -> Vec<u8> {
    aad(vault_id, &format!("collection/{cid}/key"))
}

fn aad_cdata(vault_id: &Uuid, cid: &Uuid) -> Vec<u8> {
    aad(vault_id, &format!("collection/{cid}/data"))
}

fn make_slot(secret: &[u8], root: &Key, kdf: &KdfParams, aad: &[u8]) -> Result<KeySlot> {
    let salt = random_salt()?;
    let kek = derive_key(secret, &salt, kdf)?;
    let wrapped_root = seal(&kek, root.as_bytes(), aad)?;
    Ok(KeySlot { salt, wrapped_root })
}

fn open_slot(secret: &[u8], slot: &KeySlot, kdf: &KdfParams, aad: &[u8]) -> Result<Key> {
    let kek = derive_key(secret, &slot.salt, kdf)?;
    let raw = open(&kek, &slot.wrapped_root, aad)?;
    Key::from_bytes(&raw)
}

impl Vault {
    /// Creates a new vault. The returned backup code must be shown to the
    /// user exactly once; it is not stored anywhere.
    pub fn create(password: &str, kdf: KdfParams) -> Result<(Self, BackupCode)> {
        let vault_id = Uuid::new_v4();
        let root = Key::random()?;
        let code = BackupCode::generate()?;

        let password_slot = make_slot(password.as_bytes(), &root, &kdf, &aad(&vault_id, AAD_PASSWORD))?;
        let recovery_slot = make_slot(code.as_bytes(), &root, &kdf, &aad(&vault_id, AAD_RECOVERY))?;

        // Identity keys: 32 random bytes each for ed25519 (signing) and
        // x25519 (key agreement), stored as signing || encryption.
        let mut secret = Zeroizing::new([0u8; 2 * KEY_LEN]);
        crypto::fill_random(secret.as_mut())?;
        let sk_sign: [u8; KEY_LEN] = secret[..KEY_LEN].try_into().expect("len");
        let sk_enc: [u8; KEY_LEN] = secret[KEY_LEN..].try_into().expect("len");
        let identity_public = IdentityPublic {
            signing: ed25519_dalek::SigningKey::from_bytes(&sk_sign).verifying_key().to_bytes().to_vec(),
            encryption: x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(sk_enc)).to_bytes().to_vec(),
        };
        let identity_secret = seal(&root, secret.as_ref(), &aad(&vault_id, AAD_IDENTITY))?;

        let mut vault = Self {
            vault_id,
            kdf,
            password_slot,
            recovery_slot,
            identity_public,
            identity_secret,
            root,
            collections: Vec::new(),
        };
        vault.create_collection(DEFAULT_COLLECTION)?;
        Ok((vault, code))
    }

    pub fn unlock(file: VaultFile, password: &str) -> Result<Self> {
        check_format(&file)?;
        let root = open_slot(password.as_bytes(), &file.password_slot, &file.kdf, &aad(&file.vault_id, AAD_PASSWORD))?;
        Self::from_file(file, root)
    }

    /// Unlocks with the backup code only. Callers should follow up with
    /// [`change_password`](Self::change_password) and
    /// [`rotate_backup_code`](Self::rotate_backup_code); [`recover`](Self::recover) does all three.
    pub fn unlock_with_backup_code(file: VaultFile, code: &BackupCode) -> Result<Self> {
        check_format(&file)?;
        let root = open_slot(code.as_bytes(), &file.recovery_slot, &file.kdf, &aad(&file.vault_id, AAD_RECOVERY))?;
        Self::from_file(file, root)
    }

    /// Unlocks with the backup code, sets a new master password and issues a
    /// fresh backup code. The old code stops working once the vault is saved.
    pub fn recover(file: VaultFile, code: &BackupCode, new_password: &str) -> Result<(Self, BackupCode)> {
        let mut vault = Self::unlock_with_backup_code(file, code)?;
        vault.change_password(new_password)?;
        let new_code = vault.rotate_backup_code()?;
        Ok((vault, new_code))
    }

    fn from_file(file: VaultFile, root: Key) -> Result<Self> {
        // Verify the identity blob decrypts: catches a corrupted vault early.
        open(&root, &file.identity_secret, &aad(&file.vault_id, AAD_IDENTITY))?;

        let mut collections = Vec::with_capacity(file.collections.len());
        for rec in file.collections {
            let key = Key::from_bytes(&open(&root, &rec.wrapped_key, &aad_ckey(&file.vault_id, &rec.id))?)?;
            let plain = open(&key, &rec.data, &aad_cdata(&file.vault_id, &rec.id))?;
            let data: CollectionData = serde_json::from_slice(&plain)?;
            collections.push(OpenCollection {
                key,
                wrapped_key: rec.wrapped_key,
                inner: Collection { id: rec.id, name: data.name, entries: data.entries, updated_at: data.updated_at },
            });
        }
        Ok(Self {
            vault_id: file.vault_id,
            kdf: file.kdf,
            password_slot: file.password_slot,
            recovery_slot: file.recovery_slot,
            identity_public: file.identity_public,
            identity_secret: file.identity_secret,
            root,
            collections,
        })
    }

    /// Re-encrypts all collections (fresh nonces) into the on-disk format.
    pub fn to_file(&self) -> Result<VaultFile> {
        let mut records = Vec::with_capacity(self.collections.len());
        for c in &self.collections {
            let data = CollectionData {
                name: c.inner.name.clone(),
                entries: c.inner.entries.clone(),
                updated_at: c.inner.updated_at,
            };
            let plain = Zeroizing::new(serde_json::to_vec(&data)?);
            records.push(CollectionRecord {
                id: c.inner.id,
                wrapped_key: c.wrapped_key.clone(),
                data: seal(&c.key, &plain, &aad_cdata(&self.vault_id, &c.inner.id))?,
            });
        }
        Ok(VaultFile {
            format: FORMAT_VERSION,
            vault_id: self.vault_id,
            kdf: self.kdf,
            password_slot: self.password_slot.clone(),
            recovery_slot: self.recovery_slot.clone(),
            identity_public: self.identity_public.clone(),
            identity_secret: self.identity_secret.clone(),
            collections: records,
        })
    }

    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        self.password_slot =
            make_slot(new_password.as_bytes(), &self.root, &self.kdf, &aad(&self.vault_id, AAD_PASSWORD))?;
        Ok(())
    }

    /// Issues a new backup code; the previous one is invalidated on save.
    pub fn rotate_backup_code(&mut self) -> Result<BackupCode> {
        let code = BackupCode::generate()?;
        self.recovery_slot = make_slot(code.as_bytes(), &self.root, &self.kdf, &aad(&self.vault_id, AAD_RECOVERY))?;
        Ok(code)
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    pub fn identity_public(&self) -> &IdentityPublic {
        &self.identity_public
    }

    // --- collections -----------------------------------------------------

    pub fn collections(&self) -> impl Iterator<Item = &Collection> {
        self.collections.iter().map(|c| &c.inner)
    }

    pub fn collection(&self, id: Uuid) -> Option<&Collection> {
        self.collections().find(|c| c.id == id)
    }

    fn collection_mut(&mut self, id: Uuid) -> Result<&mut Collection> {
        self.collections.iter_mut().map(|c| &mut c.inner).find(|c| c.id == id).ok_or(Error::CollectionNotFound)
    }

    pub fn create_collection(&mut self, name: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let key = Key::random()?;
        let wrapped_key = seal(&self.root, key.as_bytes(), &aad_ckey(&self.vault_id, &id))?;
        self.collections.push(OpenCollection {
            key,
            wrapped_key,
            inner: Collection { id, name: name.to_string(), entries: Vec::new(), updated_at: now() },
        });
        Ok(id)
    }

    pub fn rename_collection(&mut self, id: Uuid, name: &str) -> Result<()> {
        let c = self.collection_mut(id)?;
        c.name = name.to_string();
        c.updated_at = now();
        Ok(())
    }

    /// Deletes a collection including all its entries.
    pub fn delete_collection(&mut self, id: Uuid) -> Result<Collection> {
        let pos = self.collections.iter().position(|c| c.inner.id == id).ok_or(Error::CollectionNotFound)?;
        Ok(self.collections.remove(pos).inner)
    }

    // --- entries ---------------------------------------------------------

    /// All entries with the collection they belong to.
    pub fn entries(&self) -> impl Iterator<Item = (&Collection, &Entry)> {
        self.collections().flat_map(|c| c.entries.iter().map(move |e| (c, e)))
    }

    pub fn entry(&self, id: Uuid) -> Option<(&Collection, &Entry)> {
        self.entries().find(|(_, e)| e.id == id)
    }

    /// Case-insensitive substring match on title, username and url.
    pub fn search(&self, query: &str) -> Vec<(&Collection, &Entry)> {
        let q = query.to_lowercase();
        let hit = |s: &Option<String>| s.as_deref().is_some_and(|v| v.to_lowercase().contains(&q));
        self.entries().filter(|(_, e)| e.title.to_lowercase().contains(&q) || hit(&e.username) || hit(&e.url)).collect()
    }

    pub fn add_entry(&mut self, collection: Uuid, input: EntryInput) -> Result<Uuid> {
        let ts = now();
        let entry = Entry {
            id: Uuid::new_v4(),
            title: input.title,
            username: input.username,
            password: input.password,
            url: input.url,
            notes: input.notes,
            created_at: ts,
            updated_at: ts,
        };
        let id = entry.id;
        let c = self.collection_mut(collection)?;
        c.entries.push(entry);
        c.updated_at = ts;
        Ok(id)
    }

    pub fn update_entry(&mut self, id: Uuid, input: EntryInput) -> Result<()> {
        let ts = now();
        let c = self
            .collections
            .iter_mut()
            .map(|c| &mut c.inner)
            .find(|c| c.entries.iter().any(|e| e.id == id))
            .ok_or(Error::EntryNotFound)?;
        let e = c.entries.iter_mut().find(|e| e.id == id).expect("checked above");
        e.title = input.title;
        e.username = input.username;
        e.password = input.password;
        e.url = input.url;
        e.notes = input.notes;
        e.updated_at = ts;
        c.updated_at = ts;
        Ok(())
    }

    pub fn remove_entry(&mut self, id: Uuid) -> Result<Entry> {
        for c in self.collections.iter_mut().map(|c| &mut c.inner) {
            if let Some(pos) = c.entries.iter().position(|e| e.id == id) {
                c.updated_at = now();
                return Ok(c.entries.remove(pos));
            }
        }
        Err(Error::EntryNotFound)
    }
}

fn check_format(file: &VaultFile) -> Result<()> {
    if file.format != FORMAT_VERSION {
        return Err(Error::UnsupportedFormat(file.format));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf() -> KdfParams {
        KdfParams::insecure_fast()
    }

    fn sample() -> EntryInput {
        EntryInput {
            title: "GitHub".into(),
            username: Some("dude".into()),
            password: "hunter2".into(),
            url: Some("https://github.com".into()),
            notes: None,
        }
    }

    /// Simulates save + load through JSON.
    fn roundtrip(v: &Vault) -> VaultFile {
        let json = serde_json::to_string(&v.to_file().unwrap()).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn create_and_unlock() {
        let (mut v, _code) = Vault::create("correct horse", kdf()).unwrap();
        let personal = v.collections().next().unwrap().id;
        let eid = v.add_entry(personal, sample()).unwrap();

        let v2 = Vault::unlock(roundtrip(&v), "correct horse").unwrap();
        let (c, e) = v2.entry(eid).unwrap();
        assert_eq!(c.name, DEFAULT_COLLECTION);
        assert_eq!(e.password, "hunter2");
        assert_eq!(v2.identity_public(), v.identity_public());
    }

    #[test]
    fn wrong_password_fails() {
        let (v, _) = Vault::create("correct horse", kdf()).unwrap();
        assert!(matches!(Vault::unlock(roundtrip(&v), "wrong"), Err(Error::Decrypt)));
    }

    #[test]
    fn recover_with_backup_code_rotates_code_and_password() {
        let (mut v, code) = Vault::create("old password", kdf()).unwrap();
        let personal = v.collections().next().unwrap().id;
        let eid = v.add_entry(personal, sample()).unwrap();
        let file = roundtrip(&v);

        let parsed = BackupCode::parse(&code.display()).unwrap();
        let (recovered, new_code) = Vault::recover(file, &parsed, "new password").unwrap();
        assert_eq!(recovered.entry(eid).unwrap().1.password, "hunter2");
        let file = roundtrip(&recovered);

        assert!(Vault::unlock(file.clone(), "old password").is_err());
        assert!(Vault::unlock(file.clone(), "new password").is_ok());
        assert!(Vault::recover(file.clone(), &code, "x").is_err(), "old code must be invalid");
        assert!(Vault::recover(file, &new_code, "x").is_ok());
    }

    #[test]
    fn change_password_keeps_backup_code() {
        let (mut v, code) = Vault::create("one", kdf()).unwrap();
        v.change_password("two").unwrap();
        let file = roundtrip(&v);
        assert!(Vault::unlock(file.clone(), "one").is_err());
        assert!(Vault::unlock(file.clone(), "two").is_ok());
        assert!(Vault::recover(file, &code, "three").is_ok());
    }

    #[test]
    fn swapped_collection_blobs_are_rejected() {
        let (mut v, _) = Vault::create("pw", kdf()).unwrap();
        v.create_collection("Work").unwrap();
        let mut file = roundtrip(&v);
        let (a, b) = (file.collections[0].data.clone(), file.collections[1].data.clone());
        file.collections[0].data = b;
        file.collections[1].data = a;
        assert!(matches!(Vault::unlock(file, "pw"), Err(Error::Decrypt)));
    }

    #[test]
    fn entry_crud_and_search() {
        let (mut v, _) = Vault::create("pw", kdf()).unwrap();
        let work = v.create_collection("Work").unwrap();
        let id = v.add_entry(work, sample()).unwrap();
        assert_eq!(v.search("git").len(), 1);
        assert_eq!(v.search("DUDE").len(), 1);
        assert!(v.search("gitlab").is_empty());

        v.update_entry(id, EntryInput { title: "GitLab".into(), ..sample() }).unwrap();
        assert_eq!(v.search("gitlab").len(), 1);

        v.remove_entry(id).unwrap();
        assert!(v.entry(id).is_none());
        assert!(matches!(v.remove_entry(id), Err(Error::EntryNotFound)));
    }
}
