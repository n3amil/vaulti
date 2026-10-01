//! Format v1 (single-user, pre-sync) vault files, kept only for migration.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{open, KdfParams, Key, Sealed};
use crate::error::Result;
use crate::model::Entry;
use crate::vault::KeySlot;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileV1 {
    pub format: u32,
    pub vault_id: Uuid,
    pub kdf: KdfParams,
    pub password_slot: KeySlot,
    pub recovery_slot: KeySlot,
    pub identity_public: crate::identity::IdentityPublic,
    pub identity_secret: Sealed,
    pub collections: Vec<RecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordV1 {
    pub id: Uuid,
    pub wrapped_key: Sealed,
    pub data: Sealed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataV1 {
    name: String,
    entries: Vec<Entry>,
}

pub struct CollectionV1 {
    pub id: Uuid,
    pub key: Key,
    pub name: String,
    pub entries: Vec<Entry>,
}

fn aad(vault_id: &Uuid, purpose: &str) -> Vec<u8> {
    format!("vaulti/v1/{vault_id}/{purpose}").into_bytes()
}

pub fn open_collections(file: &FileV1, root: &Key) -> Result<Vec<CollectionV1>> {
    file.collections
        .iter()
        .map(|rec| {
            let key = Key::from_bytes(&open(
                root,
                &rec.wrapped_key,
                &aad(&file.vault_id, &format!("collection/{}/key", rec.id)),
            )?)?;
            let plain = open(&key, &rec.data, &aad(&file.vault_id, &format!("collection/{}/data", rec.id)))?;
            let data: DataV1 = serde_json::from_slice(&plain)?;
            Ok(CollectionV1 { id: rec.id, key, name: data.name, entries: data.entries })
        })
        .collect()
}
