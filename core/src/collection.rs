//! Shared collection documents (a state-based CRDT).
//!
//! A collection has one owner. The owner signs the [`Meta`] (name, member
//! list, roles); every entry version is signed by its author. Merging keeps,
//! per entry, the version with the highest [`Stamp`] whose signature is valid
//! and whose author is a writer in the (merged) member list. Deletions are
//! tombstones (`data: None`) so they win over stale copies.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;
use crate::identity::{Identity, IdentityPublic, SealedBox, UserId};
use crate::stamp::Stamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Editor,
    Viewer,
}

impl Role {
    pub fn can_write(self) -> bool {
        !matches!(self, Role::Viewer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub identity: IdentityPublic,
    pub name: String,
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    pub deleted: bool,
    pub members: Vec<Member>,
    pub stamp: Stamp,
}

impl Meta {
    pub fn member(&self, user: &UserId) -> Option<&Member> {
        self.members.iter().find(|m| &m.identity.user_id() == user)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMeta {
    pub meta: Meta,
    #[serde(with = "crate::b64")]
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryData {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryVersion {
    pub stamp: Stamp,
    pub author: UserId,
    /// `None` = deleted.
    pub data: Option<EntryData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEntry {
    pub version: EntryVersion,
    #[serde(with = "crate::b64")]
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionDoc {
    pub meta: SignedMeta,
    pub entries: BTreeMap<Uuid, SignedEntry>,
}

/// Collection key encrypted to one member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyWrap {
    pub recipient: UserId,
    pub sealed: SealedBox,
}

/// What is stored on disk and sent over the wire for a collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionRecord {
    pub id: Uuid,
    pub owner: IdentityPublic,
    pub keys: Vec<KeyWrap>,
    /// `CollectionDoc` as JSON, sealed with the collection key.
    pub body: crate::crypto::Sealed,
}

pub(crate) fn aad_key(cid: &Uuid) -> Vec<u8> {
    format!("vaulti/collection/{cid}/key").into_bytes()
}

pub(crate) fn aad_body(cid: &Uuid) -> Vec<u8> {
    format!("vaulti/collection/{cid}/body").into_bytes()
}

fn meta_msg(cid: &Uuid, meta: &Meta) -> Vec<u8> {
    serde_json::to_vec(&("vaulti/meta/v1", cid, meta)).expect("serializable")
}

fn entry_msg(cid: &Uuid, eid: &Uuid, v: &EntryVersion) -> Vec<u8> {
    serde_json::to_vec(&("vaulti/entry/v1", cid, eid, v)).expect("serializable")
}

pub fn sign_meta(owner: &Identity, cid: &Uuid, meta: Meta) -> SignedMeta {
    let sig = owner.sign(&meta_msg(cid, &meta));
    SignedMeta { meta, sig }
}

pub fn sign_entry(author: &Identity, cid: &Uuid, eid: &Uuid, version: EntryVersion) -> SignedEntry {
    let sig = author.sign(&entry_msg(cid, eid, &version));
    SignedEntry { version, sig }
}

pub fn verify_meta(cid: &Uuid, owner: &IdentityPublic, m: &SignedMeta) -> Result<()> {
    owner.verify(&meta_msg(cid, &m.meta), &m.sig)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeStats {
    pub meta_updated: bool,
    pub entries_updated: usize,
    pub rejected: usize,
}

impl MergeStats {
    pub fn changed(&self) -> bool {
        self.meta_updated || self.entries_updated > 0
    }
}

impl CollectionDoc {
    /// Checks the owner signature on meta and every entry against the
    /// member list. Used when a collection is seen for the first time.
    pub fn verify_all(&self, cid: &Uuid, owner: &IdentityPublic) -> Result<()> {
        verify_meta(cid, owner, &self.meta)?;
        for (eid, e) in &self.entries {
            self.check_entry(cid, eid, e)?;
        }
        Ok(())
    }

    fn check_entry(&self, cid: &Uuid, eid: &Uuid, e: &SignedEntry) -> Result<()> {
        let author = self
            .meta
            .meta
            .member(&e.version.author)
            .filter(|m| m.role.can_write())
            .ok_or(crate::Error::NotAllowed("entry author is not a writer".into()))?;
        author.identity.verify(&entry_msg(cid, eid, &e.version), &e.sig)
    }

    pub fn merge(&mut self, cid: &Uuid, owner: &IdentityPublic, other: CollectionDoc) -> MergeStats {
        let mut stats = MergeStats::default();
        if other.meta.meta.stamp > self.meta.meta.stamp {
            if verify_meta(cid, owner, &other.meta).is_ok() {
                self.meta = other.meta;
                stats.meta_updated = true;
            } else {
                stats.rejected += 1;
            }
        }
        for (eid, incoming) in other.entries {
            if self.entries.get(&eid).is_some_and(|cur| cur.version.stamp >= incoming.version.stamp) {
                continue;
            }
            if self.check_entry(cid, &eid, &incoming).is_ok() {
                self.entries.insert(eid, incoming);
                stats.entries_updated += 1;
            } else {
                stats.rejected += 1;
            }
        }
        stats
    }

    pub fn max_stamp(&self) -> Stamp {
        self.entries.values().map(|e| e.version.stamp).chain([self.meta.meta.stamp]).max().unwrap_or(Stamp::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stamp::Clock;

    fn member(id: &Identity, role: Role) -> Member {
        Member { identity: id.public(), name: "x".into(), role }
    }

    fn data(title: &str) -> Option<EntryData> {
        Some(EntryData {
            title: title.into(),
            username: None,
            password: "pw".into(),
            url: None,
            notes: None,
            created_at: 0,
        })
    }

    struct Fixture {
        cid: Uuid,
        owner: Identity,
        editor: Identity,
        viewer: Identity,
        clock: Clock,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                cid: Uuid::new_v4(),
                owner: Identity::generate().unwrap(),
                editor: Identity::generate().unwrap(),
                viewer: Identity::generate().unwrap(),
                clock: Clock::new(Uuid::new_v4()),
            }
        }

        fn doc(&mut self) -> CollectionDoc {
            let meta = Meta {
                name: "Team".into(),
                deleted: false,
                members: vec![
                    member(&self.owner, Role::Owner),
                    member(&self.editor, Role::Editor),
                    member(&self.viewer, Role::Viewer),
                ],
                stamp: self.clock.tick(),
            };
            CollectionDoc { meta: sign_meta(&self.owner, &self.cid, meta), entries: BTreeMap::new() }
        }

        fn entry(&mut self, author: &Identity, title: &str) -> SignedEntry {
            let v = EntryVersion { stamp: self.clock.tick(), author: author.public().user_id(), data: data(title) };
            sign_entry(author, &self.cid, &Uuid::nil(), v)
        }
    }

    #[test]
    fn newer_entry_wins_both_directions() {
        let mut f = Fixture::new();
        let mut a = f.doc();
        let mut b = a.clone();
        let old = f.entry(&f.owner.clone_for_test(), "old");
        let new = f.entry(&f.editor.clone_for_test(), "new");
        a.entries.insert(Uuid::nil(), old.clone());
        b.entries.insert(Uuid::nil(), new.clone());

        let (a2, b2) = (a.clone(), b.clone());
        assert_eq!(a.merge(&f.cid, &f.owner.public(), b2).entries_updated, 1);
        assert_eq!(b.merge(&f.cid, &f.owner.public(), a2).entries_updated, 0);
        for d in [&a, &b] {
            assert_eq!(d.entries[&Uuid::nil()].version.data.as_ref().unwrap().title, "new");
        }
    }

    #[test]
    fn viewer_and_outsider_writes_are_rejected() {
        let mut f = Fixture::new();
        let mut doc = f.doc();
        let outsider = Identity::generate().unwrap();
        for author in [f.viewer.clone_for_test(), outsider] {
            let mut incoming = doc.clone();
            incoming.entries.insert(Uuid::nil(), f.entry(&author, "evil"));
            let s = doc.merge(&f.cid, &f.owner.public(), incoming);
            assert_eq!((s.entries_updated, s.rejected), (0, 1));
        }
    }

    #[test]
    fn forged_signature_and_meta_from_non_owner_rejected() {
        let mut f = Fixture::new();
        let mut doc = f.doc();
        let mut e = f.entry(&f.editor.clone_for_test(), "ok");
        e.version.data.as_mut().unwrap().password = "tampered".into();
        let mut incoming = doc.clone();
        incoming.entries.insert(Uuid::nil(), e);
        assert_eq!(doc.merge(&f.cid, &f.owner.public(), incoming).rejected, 1);

        // Editor tries to make themselves owner.
        let mut meta = doc.meta.meta.clone();
        meta.stamp = f.clock.tick();
        meta.members.retain(|m| m.role != Role::Viewer);
        let forged = CollectionDoc { meta: sign_meta(&f.editor, &f.cid, meta), entries: BTreeMap::new() };
        let s = doc.merge(&f.cid, &f.owner.public(), forged);
        assert!(!s.meta_updated);
        assert_eq!(doc.meta.meta.members.len(), 3);
    }

    #[test]
    fn tombstone_beats_older_version() {
        let mut f = Fixture::new();
        let mut doc = f.doc();
        let live = f.entry(&f.owner.clone_for_test(), "x");
        doc.entries.insert(Uuid::nil(), live.clone());
        let v = EntryVersion { stamp: f.clock.tick(), author: f.owner.public().user_id(), data: None };
        let mut del = doc.clone();
        del.entries.insert(Uuid::nil(), sign_entry(&f.owner, &f.cid, &Uuid::nil(), v));
        doc.merge(&f.cid, &f.owner.public(), del);
        let mut stale = doc.clone();
        stale.entries.insert(Uuid::nil(), live);
        doc.merge(&f.cid, &f.owner.public(), stale);
        assert!(doc.entries[&Uuid::nil()].version.data.is_none());
    }

    impl Identity {
        fn clone_for_test(&self) -> Identity {
            Identity::from_secret_bytes(&self.secret_bytes()).unwrap()
        }
    }
}
