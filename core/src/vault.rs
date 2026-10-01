//! Vault format and the unlocked in-memory vault.
//!
//! Key hierarchy:
//! ```text
//! root key (random) ──wrapped by── Argon2id(master password)  [password slot]
//!                   └─wrapped by── Argon2id(backup code)      [recovery slot]
//! root key ─seals─▶ identity secret (ed25519 + x25519), account doc, device key
//! identity (x25519) ─opens─▶ collection key (one KeyWrap per member)
//! collection key ─seals─▶ collection doc (meta + signed entries)
//! ```
//! All devices of a user share the root key and identity. Collection keys
//! are wrapped per member, so sharing a collection = adding a KeyWrap and a
//! member to the owner-signed meta.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::account::{AccountDoc, Contact, ContactCard, Device, Lww};
use crate::collection::{
    aad_body, aad_key, sign_entry, sign_meta, CollectionDoc, CollectionRecord, EntryData, EntryVersion, KeyWrap,
    Member, Meta, Role,
};
use crate::crypto::{derive_key, fill_random, open, random_salt, seal, KdfParams, Key, Sealed};
use crate::error::{Error, Result};
use crate::identity::{device_node_id, Identity, IdentityPublic, UserId};
use crate::legacy::{self, FileV1};
use crate::model::{now, Collection, DeviceView, Entry, EntryInput};
use crate::recovery::BackupCode;
use crate::stamp::{Clock, Stamp};

pub const FORMAT_VERSION: u32 = 2;
pub const DEFAULT_COLLECTION: &str = "Personal";
const DEFAULT_PROFILE_NAME: &str = "Me";
const DEFAULT_DEVICE_NAME: &str = "This device";

/// On-disk vault. Accepts the legacy v1 format on load.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VaultFile {
    Current(Box<FileV2>),
    Legacy(Box<FileV1>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileV2 {
    pub format: u32,
    /// Same on all of a user's devices.
    pub vault_id: Uuid,
    pub slots: Slots,
    pub identity_public: IdentityPublic,
    pub identity_secret: Sealed,
    /// `AccountDoc`, sealed with the root key.
    pub account: Sealed,
    pub collections: Vec<CollectionRecord>,
    /// Absent in a copy sent to a newly paired device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<DeviceLocal>,
}

/// Key slots, synced between own devices (one master password, one backup code).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slots {
    pub kdf: KdfParams,
    pub password: KeySlot,
    pub recovery: KeySlot,
    pub stamp: Stamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    #[serde(with = "crate::b64")]
    pub salt: Vec<u8>,
    pub wrapped_root: Sealed,
}

/// Never leaves the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceLocal {
    pub device_id: Uuid,
    /// iroh endpoint secret key, sealed with the root key.
    pub device_secret: Sealed,
    pub clock: Clock,
}

/// Who is on the other end of a sync connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peer {
    OwnDevice,
    Contact(UserId),
}

/// Sent to a peer during sync. State-based: each side sends everything the
/// peer may see, the receiver merges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMessage {
    pub card: ContactCard,
    /// Only between own devices.
    pub own: Option<OwnState>,
    pub collections: Vec<CollectionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnState {
    pub slots: Slots,
    pub account: Sealed,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SyncReport {
    pub changed: bool,
    pub new_collections: usize,
    pub entries_updated: usize,
    pub rejected: usize,
}

struct OpenCollection {
    owner: IdentityPublic,
    keys: Vec<KeyWrap>,
    key: Key,
    doc: CollectionDoc,
    view: Collection,
}

/// An unlocked vault. Holds the root key in memory until dropped.
pub struct Vault {
    vault_id: Uuid,
    slots: Slots,
    identity: Identity,
    identity_public: IdentityPublic,
    identity_secret: Sealed,
    root: Key,
    account: AccountDoc,
    collections: Vec<OpenCollection>,
    device_id: Uuid,
    device_secret: Zeroizing<[u8; 32]>,
    clock: Clock,
}

// Slot/identity labels kept from v1 so migrated slots stay valid.
fn aad(vault_id: &Uuid, purpose: &str) -> Vec<u8> {
    format!("vaulti/v1/{vault_id}/{purpose}").into_bytes()
}

const AAD_PASSWORD: &str = "slot/password";
const AAD_RECOVERY: &str = "slot/recovery";
const AAD_IDENTITY: &str = "identity";
const AAD_ACCOUNT: &str = "account";

fn aad_device(vault_id: &Uuid, device_id: &Uuid) -> Vec<u8> {
    aad(vault_id, &format!("device/{device_id}"))
}

fn make_slot(secret: &[u8], root: &Key, kdf: &KdfParams, aad: &[u8]) -> Result<KeySlot> {
    let salt = random_salt()?;
    let kek = derive_key(secret, &salt, kdf)?;
    Ok(KeySlot { salt, wrapped_root: seal(&kek, root.as_bytes(), aad)? })
}

fn open_slot(secret: &[u8], slot: &KeySlot, kdf: &KdfParams, aad: &[u8]) -> Result<Key> {
    let kek = derive_key(secret, &slot.salt, kdf)?;
    Key::from_bytes(&open(&kek, &slot.wrapped_root, aad)?)
}

fn random_device_secret() -> Result<Zeroizing<[u8; 32]>> {
    let mut s = Zeroizing::new([0u8; 32]);
    fill_random(s.as_mut())?;
    Ok(s)
}

enum SlotKind {
    Password,
    Recovery,
}

/// Device-specific setup when opening a vault copied from another device.
struct NewDevice {
    secret: Zeroizing<[u8; 32]>,
    name: String,
}

impl Vault {
    // --- lifecycle -----------------------------------------------------------

    /// Creates a new vault. The returned backup code must be shown to the
    /// user exactly once; it is not stored anywhere.
    pub fn create(password: &str, kdf: KdfParams) -> Result<(Self, BackupCode)> {
        let vault_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let mut clock = Clock::new(device_id);
        let root = Key::random()?;
        let code = BackupCode::generate()?;
        let slots = Slots {
            kdf,
            password: make_slot(password.as_bytes(), &root, &kdf, &aad(&vault_id, AAD_PASSWORD))?,
            recovery: make_slot(code.as_bytes(), &root, &kdf, &aad(&vault_id, AAD_RECOVERY))?,
            stamp: clock.tick(),
        };
        let identity = Identity::generate()?;
        let identity_secret = seal(&root, &identity.secret_bytes(), &aad(&vault_id, AAD_IDENTITY))?;
        let account = AccountDoc::new(DEFAULT_PROFILE_NAME.into(), clock.tick());

        let mut vault = Self {
            vault_id,
            slots,
            identity_public: identity.public(),
            identity,
            identity_secret,
            root,
            account,
            collections: Vec::new(),
            device_id,
            device_secret: random_device_secret()?,
            clock,
        };
        vault.register_this_device(DEFAULT_DEVICE_NAME);
        vault.create_collection(DEFAULT_COLLECTION)?;
        Ok((vault, code))
    }

    pub fn unlock(file: VaultFile, password: &str) -> Result<Self> {
        Self::open_any(file, password.as_bytes(), SlotKind::Password, None)
    }

    /// Unlocks with the backup code only. Follow up with
    /// [`change_password`](Self::change_password) and
    /// [`rotate_backup_code`](Self::rotate_backup_code); [`recover`](Self::recover) does all three.
    pub fn unlock_with_backup_code(file: VaultFile, code: &BackupCode) -> Result<Self> {
        Self::open_any(file, code.as_bytes(), SlotKind::Recovery, None)
    }

    /// Unlocks with the backup code, sets a new master password and issues a
    /// fresh backup code. The old code stops working once the vault is saved.
    pub fn recover(file: VaultFile, code: &BackupCode, new_password: &str) -> Result<(Self, BackupCode)> {
        let mut vault = Self::unlock_with_backup_code(file, code)?;
        vault.change_password(new_password)?;
        let new_code = vault.rotate_backup_code()?;
        Ok((vault, new_code))
    }

    /// Opens a vault received from another of the user's devices during
    /// pairing. `device_secret` is the iroh key this device paired with.
    pub fn unlock_new_device(file: FileV2, password: &str, device_secret: [u8; 32], device_name: &str) -> Result<Self> {
        let new = NewDevice { secret: Zeroizing::new(device_secret), name: device_name.to_string() };
        Self::open_any(VaultFile::Current(Box::new(file)), password.as_bytes(), SlotKind::Password, Some(new))
    }

    fn open_any(file: VaultFile, secret: &[u8], kind: SlotKind, new: Option<NewDevice>) -> Result<Self> {
        match file {
            VaultFile::Current(f) => {
                if f.format != FORMAT_VERSION {
                    return Err(Error::UnsupportedFormat(f.format));
                }
                let (slot, label) = match kind {
                    SlotKind::Password => (&f.slots.password, AAD_PASSWORD),
                    SlotKind::Recovery => (&f.slots.recovery, AAD_RECOVERY),
                };
                let root = open_slot(secret, slot, &f.slots.kdf, &aad(&f.vault_id, label))?;
                Self::from_v2(*f, root, new)
            }
            VaultFile::Legacy(f) => {
                if f.format != 1 {
                    return Err(Error::UnsupportedFormat(f.format));
                }
                let (slot, label) = match kind {
                    SlotKind::Password => (&f.password_slot, AAD_PASSWORD),
                    SlotKind::Recovery => (&f.recovery_slot, AAD_RECOVERY),
                };
                let root = open_slot(secret, slot, &f.kdf, &aad(&f.vault_id, label))?;
                Self::migrate_v1(*f, root)
            }
        }
    }

    fn from_v2(f: FileV2, root: Key, new: Option<NewDevice>) -> Result<Self> {
        let identity = Identity::from_secret_bytes(&open(&root, &f.identity_secret, &aad(&f.vault_id, AAD_IDENTITY))?)?;
        if identity.public() != f.identity_public {
            return Err(Error::Malformed("identity mismatch".into()));
        }
        let account: AccountDoc = serde_json::from_slice(&open(&root, &f.account, &aad(&f.vault_id, AAD_ACCOUNT))?)?;

        let (device_id, device_secret, clock, new_name) = match (f.local, new) {
            (_, Some(n)) => {
                let id = Uuid::new_v4();
                (id, n.secret, Clock::new(id), Some(n.name))
            }
            (Some(local), None) => {
                let raw = open(&root, &local.device_secret, &aad_device(&f.vault_id, &local.device_id))?;
                let secret: [u8; 32] = raw[..].try_into().map_err(|_| Error::Malformed("device key".into()))?;
                (local.device_id, Zeroizing::new(secret), local.clock, None)
            }
            (None, None) => return Err(Error::NeedsDeviceSetup),
        };

        let mut vault = Self {
            vault_id: f.vault_id,
            slots: f.slots,
            identity_public: f.identity_public,
            identity,
            identity_secret: f.identity_secret,
            root,
            account,
            collections: Vec::new(),
            device_id,
            device_secret,
            clock,
        };
        for rec in f.collections {
            match vault.open_record(rec) {
                Ok(oc) => vault.collections.push(oc),
                // No key for us (e.g. removed from a shared collection): drop it.
                Err(Error::NotAllowed(_)) => {}
                // Our key is there but the data doesn't decrypt: corruption, don't silently lose it.
                Err(e) => return Err(e),
            }
        }
        if let Some(name) = new_name {
            vault.register_this_device(&name);
        }
        Ok(vault)
    }

    fn migrate_v1(f: FileV1, root: Key) -> Result<Self> {
        let old = legacy::open_collections(&f, &root)?;
        let identity = Identity::from_secret_bytes(&open(&root, &f.identity_secret, &aad(&f.vault_id, AAD_IDENTITY))?)?;
        let device_id = Uuid::new_v4();
        let mut clock = Clock::new(device_id);
        let mut vault = Self {
            vault_id: f.vault_id,
            slots: Slots { kdf: f.kdf, password: f.password_slot, recovery: f.recovery_slot, stamp: clock.tick() },
            identity_public: identity.public(),
            identity,
            identity_secret: f.identity_secret,
            root,
            account: AccountDoc::new(DEFAULT_PROFILE_NAME.into(), clock.tick()),
            collections: Vec::new(),
            device_id,
            device_secret: random_device_secret()?,
            clock,
        };
        vault.register_this_device(DEFAULT_DEVICE_NAME);
        for c in old {
            vault.insert_new_collection(c.id, c.key, &c.name)?;
            for e in c.entries {
                let data = EntryData {
                    title: e.title,
                    username: e.username,
                    password: e.password,
                    url: e.url,
                    notes: e.notes,
                    created_at: e.created_at,
                };
                vault.put_entry(c.id, e.id, Some(data))?;
            }
        }
        Ok(vault)
    }

    pub fn to_file(&self) -> Result<VaultFile> {
        let mut f = self.file_for_new_device()?;
        f.local = Some(DeviceLocal {
            device_id: self.device_id,
            device_secret: seal(&self.root, self.device_secret.as_ref(), &aad_device(&self.vault_id, &self.device_id))?,
            clock: self.clock,
        });
        Ok(VaultFile::Current(Box::new(f)))
    }

    /// Copy of the vault for a device being paired (no device-local data).
    pub fn file_for_new_device(&self) -> Result<FileV2> {
        Ok(FileV2 {
            format: FORMAT_VERSION,
            vault_id: self.vault_id,
            slots: self.slots.clone(),
            identity_public: self.identity_public.clone(),
            identity_secret: self.identity_secret.clone(),
            account: self.seal_account()?,
            collections: self.collections.iter().map(|c| self.record(c)).collect::<Result<_>>()?,
            local: None,
        })
    }

    fn seal_account(&self) -> Result<Sealed> {
        let plain = Zeroizing::new(serde_json::to_vec(&self.account)?);
        seal(&self.root, &plain, &aad(&self.vault_id, AAD_ACCOUNT))
    }

    fn record(&self, c: &OpenCollection) -> Result<CollectionRecord> {
        let plain = Zeroizing::new(serde_json::to_vec(&c.doc)?);
        Ok(CollectionRecord {
            id: c.view.id,
            owner: c.owner.clone(),
            keys: c.keys.clone(),
            body: seal(&c.key, &plain, &aad_body(&c.view.id))?,
        })
    }

    fn open_record(&self, rec: CollectionRecord) -> Result<OpenCollection> {
        let me = self.user_id();
        let wrap = rec.keys.iter().find(|w| w.recipient == me).ok_or(Error::NotAllowed("no key for us".into()))?;
        let key = Key::from_bytes(&self.identity.open_box(&wrap.sealed, &aad_key(&rec.id))?)?;
        let doc: CollectionDoc = serde_json::from_slice(&open(&key, &rec.body, &aad_body(&rec.id))?)?;
        let view = build_view(rec.id, &rec.owner, &doc, &me);
        Ok(OpenCollection { owner: rec.owner, keys: rec.keys, key, doc, view })
    }

    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        self.slots.password =
            make_slot(new_password.as_bytes(), &self.root, &self.slots.kdf, &aad(&self.vault_id, AAD_PASSWORD))?;
        self.slots.stamp = self.clock.tick();
        Ok(())
    }

    /// Issues a new backup code; the previous one is invalidated on save.
    pub fn rotate_backup_code(&mut self) -> Result<BackupCode> {
        let code = BackupCode::generate()?;
        self.slots.recovery =
            make_slot(code.as_bytes(), &self.root, &self.slots.kdf, &aad(&self.vault_id, AAD_RECOVERY))?;
        self.slots.stamp = self.clock.tick();
        Ok(code)
    }

    // --- identity, profile, devices --------------------------------------------

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    pub fn identity_public(&self) -> &IdentityPublic {
        &self.identity_public
    }

    pub fn user_id(&self) -> UserId {
        self.identity_public.user_id()
    }

    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    /// Secret key for this device's iroh endpoint.
    pub fn device_secret(&self) -> [u8; 32] {
        *self.device_secret
    }

    pub fn node_id(&self) -> String {
        device_node_id(&self.device_secret)
    }

    pub fn profile_name(&self) -> &str {
        &self.account.profile_name.value
    }

    pub fn set_profile_name(&mut self, name: &str) {
        self.account.profile_name = Lww::new(name.trim().to_string(), self.clock.tick());
    }

    fn register_this_device(&mut self, name: &str) {
        let id = self.node_id();
        self.add_device(&id, name);
    }

    /// Adds (or renames/restores) one of the user's devices by endpoint id.
    pub fn add_device(&mut self, node_id: &str, name: &str) {
        let stamp = self.clock.tick();
        self.account
            .devices
            .insert(node_id.to_string(), Lww::new(Device { name: name.trim().to_string(), removed: false }, stamp));
    }

    pub fn remove_device(&mut self, node_id: &str) -> Result<()> {
        if node_id == self.node_id() {
            return Err(Error::NotAllowed("can't remove this device".into()));
        }
        let name =
            self.account.devices.get(node_id).ok_or(Error::Malformed("unknown device".into()))?.value.name.clone();
        let stamp = self.clock.tick();
        self.account.devices.insert(node_id.to_string(), Lww::new(Device { name, removed: true }, stamp));
        Ok(())
    }

    pub fn devices(&self) -> Vec<DeviceView> {
        let me = self.node_id();
        self.account
            .active_devices()
            .map(|(id, d)| DeviceView { node_id: id.clone(), name: d.name.clone(), this_device: *id == me })
            .collect()
    }

    // --- contacts ----------------------------------------------------------------

    /// Our current contact card (name, identity, active devices).
    pub fn my_card(&self) -> ContactCard {
        let mut devices: Vec<String> = self.account.active_devices().map(|(id, _)| id.clone()).collect();
        devices.sort();
        // Deterministic stamp: only changes when name or devices change.
        let stamp = self
            .account
            .devices
            .values()
            .map(|d| d.stamp)
            .chain([self.account.profile_name.stamp])
            .max()
            .unwrap_or(Stamp::ZERO);
        ContactCard::new(&self.identity, self.profile_name().to_string(), devices, stamp)
    }

    pub fn add_contact(&mut self, card: ContactCard) -> Result<UserId> {
        card.verify()?;
        let uid = card.identity.user_id();
        if uid == self.user_id() {
            return Err(Error::NotAllowed("that's your own card".into()));
        }
        let removed = Lww::new(false, self.clock.tick());
        match self.account.contacts.get_mut(&uid) {
            Some(c) => {
                c.removed = removed;
                if card.stamp >= c.card.stamp {
                    c.card = card;
                }
            }
            None => {
                self.account.contacts.insert(uid.clone(), Contact { card, removed });
            }
        }
        Ok(uid)
    }

    pub fn remove_contact(&mut self, uid: &UserId) -> Result<()> {
        let stamp = self.clock.tick();
        let c = self.account.contacts.get_mut(uid).ok_or(Error::ContactNotFound)?;
        c.removed = Lww::new(true, stamp);
        Ok(())
    }

    pub fn contacts(&self) -> impl Iterator<Item = &ContactCard> {
        self.account.active_contacts().map(|c| &c.card)
    }

    pub fn contact(&self, uid: &UserId) -> Option<&ContactCard> {
        self.account.contact(uid).map(|c| &c.card)
    }

    // --- collections -------------------------------------------------------------

    /// Visible (not deleted) collections.
    pub fn collections(&self) -> impl Iterator<Item = &Collection> {
        self.collections.iter().filter(|c| !c.doc.meta.meta.deleted).map(|c| &c.view)
    }

    pub fn collection(&self, id: Uuid) -> Option<&Collection> {
        self.collections().find(|c| c.id == id)
    }

    fn open_mut(&mut self, id: Uuid) -> Result<&mut OpenCollection> {
        self.collections
            .iter_mut()
            .find(|c| c.view.id == id && !c.doc.meta.meta.deleted)
            .ok_or(Error::CollectionNotFound)
    }

    fn me_as_member(&self, role: Role) -> Member {
        Member { identity: self.identity_public.clone(), name: self.profile_name().to_string(), role }
    }

    fn insert_new_collection(&mut self, id: Uuid, key: Key, name: &str) -> Result<()> {
        let meta = Meta {
            name: name.to_string(),
            deleted: false,
            members: vec![self.me_as_member(Role::Owner)],
            stamp: self.clock.tick(),
        };
        let doc = CollectionDoc { meta: sign_meta(&self.identity, &id, meta), entries: Default::default() };
        let keys = vec![KeyWrap {
            recipient: self.user_id(),
            sealed: self.identity_public.seal_to(key.as_bytes(), &aad_key(&id))?,
        }];
        let view = build_view(id, &self.identity_public, &doc, &self.user_id());
        self.collections.push(OpenCollection { owner: self.identity_public.clone(), keys, key, doc, view });
        Ok(())
    }

    pub fn create_collection(&mut self, name: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        self.insert_new_collection(id, Key::random()?, name)?;
        Ok(id)
    }

    /// Owner-only change of the signed meta.
    fn update_meta(&mut self, id: Uuid, f: impl FnOnce(&mut Meta) -> Result<()>) -> Result<()> {
        let me = self.user_id();
        let c = self
            .collections
            .iter()
            .find(|c| c.view.id == id && !c.doc.meta.meta.deleted)
            .ok_or(Error::CollectionNotFound)?;
        if c.owner.user_id() != me {
            return Err(Error::NotAllowed("only the owner can change this collection".into()));
        }
        let mut meta = c.doc.meta.meta.clone();
        f(&mut meta)?;
        meta.stamp = self.clock.tick();
        let signed = sign_meta(&self.identity, &id, meta);
        let oc = self.open_mut(id)?;
        oc.doc.meta = signed;
        let members: Vec<UserId> = oc.doc.meta.meta.members.iter().map(|m| m.identity.user_id()).collect();
        oc.keys.retain(|k| members.contains(&k.recipient));
        oc.view = build_view(id, &oc.owner, &oc.doc, &me);
        Ok(())
    }

    pub fn rename_collection(&mut self, id: Uuid, name: &str) -> Result<()> {
        let name = name.to_string();
        self.update_meta(id, |m| {
            m.name = name;
            Ok(())
        })
    }

    /// Deletes a collection for all members (owner only).
    pub fn delete_collection(&mut self, id: Uuid) -> Result<Collection> {
        let view = self.collection(id).cloned().ok_or(Error::CollectionNotFound)?;
        self.update_meta(id, |m| {
            m.deleted = true;
            Ok(())
        })?;
        Ok(view)
    }

    /// Shares a collection with a contact (owner only). Also used to change a member's role.
    pub fn share_collection(&mut self, id: Uuid, with: &UserId, role: Role) -> Result<()> {
        if role == Role::Owner {
            return Err(Error::NotAllowed("a collection has exactly one owner".into()));
        }
        let card = self.contact(with).cloned().ok_or(Error::ContactNotFound)?;
        self.update_meta(id, |m| {
            m.members.retain(|x| x.identity != card.identity);
            m.members.push(Member { identity: card.identity.clone(), name: card.name.clone(), role });
            Ok(())
        })?;
        let oc = self.open_mut(id)?;
        if !oc.keys.iter().any(|k| &k.recipient == with) {
            let sealed = card.identity.seal_to(oc.key.as_bytes(), &aad_key(&id))?;
            oc.keys.push(KeyWrap { recipient: with.clone(), sealed });
        }
        Ok(())
    }

    /// Removes a member (owner only). They keep what they already synced.
    pub fn unshare_collection(&mut self, id: Uuid, member: &UserId) -> Result<()> {
        if *member == self.user_id() {
            return Err(Error::NotAllowed("the owner can't be removed".into()));
        }
        let member = member.clone();
        self.update_meta(id, |m| {
            let before = m.members.len();
            m.members.retain(|x| x.identity.user_id() != member);
            if m.members.len() == before {
                return Err(Error::ContactNotFound);
            }
            Ok(())
        })
    }

    // --- entries -----------------------------------------------------------------

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

    fn put_entry(&mut self, cid: Uuid, eid: Uuid, data: Option<EntryData>) -> Result<()> {
        let me = self.user_id();
        if !self.collection(cid).ok_or(Error::CollectionNotFound)?.can_write() {
            return Err(Error::NotAllowed("you can only view this collection".into()));
        }
        let version = EntryVersion { stamp: self.clock.tick(), author: me.clone(), data };
        let signed = sign_entry(&self.identity, &cid, &eid, version);
        let oc = self.open_mut(cid)?;
        oc.doc.entries.insert(eid, signed);
        oc.view = build_view(cid, &oc.owner, &oc.doc, &me);
        Ok(())
    }

    pub fn add_entry(&mut self, collection: Uuid, input: EntryInput) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let data = EntryData {
            title: input.title,
            username: input.username,
            password: input.password,
            url: input.url,
            notes: input.notes,
            created_at: now(),
        };
        self.put_entry(collection, id, Some(data))?;
        Ok(id)
    }

    pub fn update_entry(&mut self, id: Uuid, input: EntryInput) -> Result<()> {
        let (c, e) = self.entry(id).ok_or(Error::EntryNotFound)?;
        let (cid, created_at) = (c.id, e.created_at);
        let data = EntryData {
            title: input.title,
            username: input.username,
            password: input.password,
            url: input.url,
            notes: input.notes,
            created_at,
        };
        self.put_entry(cid, id, Some(data))
    }

    pub fn remove_entry(&mut self, id: Uuid) -> Result<Entry> {
        let (c, e) = self.entry(id).ok_or(Error::EntryNotFound)?;
        let (cid, old) = (c.id, e.clone());
        self.put_entry(cid, id, None)?;
        Ok(old)
    }

    // --- sync ----------------------------------------------------------------------

    /// Classifies a remote iroh endpoint id; `None` = not someone we sync with.
    pub fn classify_peer(&self, node_id: &str) -> Option<Peer> {
        if node_id == self.node_id() {
            return None;
        }
        if self.account.active_devices().any(|(id, _)| id == node_id) {
            return Some(Peer::OwnDevice);
        }
        self.account
            .active_contacts()
            .find(|c| c.card.devices.iter().any(|d| d == node_id))
            .map(|c| Peer::Contact(c.card.identity.user_id()))
    }

    /// Endpoints to dial: our other devices and all contacts' devices.
    pub fn sync_targets(&self) -> Vec<(String, Peer)> {
        let me = self.node_id();
        let own =
            self.account.active_devices().filter(|(id, _)| **id != me).map(|(id, _)| (id.clone(), Peer::OwnDevice));
        let contacts = self.account.active_contacts().flat_map(|c| {
            let uid = c.card.identity.user_id();
            c.card.devices.iter().map(move |d| (d.clone(), Peer::Contact(uid.clone())))
        });
        own.chain(contacts).collect()
    }

    pub fn sync_message(&self, peer: &Peer) -> Result<SyncMessage> {
        let collections = self
            .collections
            .iter()
            .filter(|c| match peer {
                Peer::OwnDevice => true,
                Peer::Contact(uid) => c.doc.meta.meta.member(uid).is_some(),
            })
            .map(|c| self.record(c))
            .collect::<Result<_>>()?;
        let own = match peer {
            Peer::OwnDevice => Some(OwnState { slots: self.slots.clone(), account: self.seal_account()? }),
            Peer::Contact(_) => None,
        };
        Ok(SyncMessage { card: self.my_card(), own, collections })
    }

    pub fn apply_sync(&mut self, peer: &Peer, msg: SyncMessage) -> Result<SyncReport> {
        msg.card.verify()?;
        let mut report = SyncReport::default();
        match peer {
            Peer::OwnDevice => {
                if msg.card.identity != self.identity_public {
                    return Err(Error::NotAllowed("device belongs to another user".into()));
                }
                let own = msg.own.ok_or(Error::Malformed("missing own-device state".into()))?;
                if own.slots.stamp > self.slots.stamp {
                    self.clock.observe(own.slots.stamp);
                    self.slots = own.slots;
                    report.changed = true;
                }
                let other: AccountDoc =
                    serde_json::from_slice(&open(&self.root, &own.account, &aad(&self.vault_id, AAD_ACCOUNT))?)?;
                report.changed |= self.account.merge(other);
            }
            Peer::Contact(uid) => {
                if msg.card.identity.user_id() != *uid {
                    return Err(Error::NotAllowed("card does not match peer".into()));
                }
                report.changed |= self.account.update_card(msg.card);
            }
        }

        let me = self.user_id();
        for rec in msg.collections {
            let pos = self.collections.iter().position(|c| c.view.id == rec.id);
            match pos {
                Some(i) => {
                    let oc = &mut self.collections[i];
                    if rec.owner != oc.owner {
                        report.rejected += 1;
                        continue;
                    }
                    let Ok(plain) = open(&oc.key, &rec.body, &aad_body(&rec.id)) else {
                        report.rejected += 1;
                        continue;
                    };
                    let incoming: CollectionDoc = serde_json::from_slice(&plain)?;
                    let stats = oc.doc.merge(&rec.id, &oc.owner, incoming);
                    for k in rec.keys {
                        if !oc.keys.iter().any(|x| x.recipient == k.recipient) {
                            oc.keys.push(k);
                        }
                    }
                    let members: Vec<UserId> = oc.doc.meta.meta.members.iter().map(|m| m.identity.user_id()).collect();
                    oc.keys.retain(|k| members.contains(&k.recipient));
                    report.rejected += stats.rejected;
                    report.entries_updated += stats.entries_updated;
                    if stats.changed() {
                        report.changed = true;
                        oc.view = build_view(rec.id, &oc.owner, &oc.doc, &me);
                        let max = oc.doc.max_stamp();
                        self.clock.observe(max);
                    }
                }
                None => {
                    let owner_ok =
                        rec.owner == self.identity_public || self.account.contact(&rec.owner.user_id()).is_some();
                    let cid = rec.id;
                    let opened = if owner_ok { self.open_record(rec).ok() } else { None };
                    match opened {
                        Some(oc) if oc.doc.verify_all(&cid, &oc.owner).is_ok() && oc.view.my_role.is_some() => {
                            self.clock.observe(oc.doc.max_stamp());
                            self.collections.push(oc);
                            report.new_collections += 1;
                            report.changed = true;
                        }
                        _ => report.rejected += 1,
                    }
                }
            }
        }
        Ok(report)
    }
}

fn build_view(id: Uuid, owner: &IdentityPublic, doc: &CollectionDoc, me: &UserId) -> Collection {
    let meta = &doc.meta.meta;
    let entries: Vec<Entry> = doc
        .entries
        .iter()
        .filter_map(|(eid, e)| {
            let d = e.version.data.as_ref()?;
            Some(Entry {
                id: *eid,
                title: d.title.clone(),
                username: d.username.clone(),
                password: d.password.clone(),
                url: d.url.clone(),
                notes: d.notes.clone(),
                created_at: d.created_at,
                updated_at: e.version.stamp.secs(),
            })
        })
        .collect();
    Collection {
        id,
        name: meta.name.clone(),
        updated_at: doc.max_stamp().secs(),
        entries,
        owner: owner.user_id(),
        members: meta.members.clone(),
        my_role: meta.member(me).map(|m| m.role),
    }
}

#[cfg(test)]
mod tests;
