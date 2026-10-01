use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::collection::{Member, Role};
use crate::identity::UserId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub totp: Option<String>,
    /// Set for entries in the trash.
    #[serde(default)]
    pub trashed_at: Option<u64>,
}

/// An earlier version of an entry, from its history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    /// Identifies this version within the entry (from its unique stamp).
    pub id: String,
    /// When this version was saved (unix seconds).
    pub changed_at: u64,
    pub author_name: String,
    pub by_me: bool,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
}

/// Fields a user can set when adding or editing an entry.
#[derive(Debug, Clone, Default)]
pub struct EntryInput {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    /// Validated with [`crate::totp::Totp::parse`] when saved.
    pub totp: Option<String>,
}

/// Decrypted, read-only view of a collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub id: Uuid,
    pub name: String,
    pub entries: Vec<Entry>,
    /// Entries in the trash, restorable until purged.
    #[serde(default)]
    pub trash: Vec<Entry>,
    pub updated_at: u64,
    pub owner: UserId,
    pub members: Vec<Member>,
    /// Our role; `None` if we were removed from a shared collection.
    pub my_role: Option<Role>,
}

impl Collection {
    pub fn is_shared(&self) -> bool {
        self.members.len() > 1
    }

    pub fn can_write(&self) -> bool {
        self.my_role.is_some_and(Role::can_write)
    }

    pub fn is_owner(&self) -> bool {
        self.my_role == Some(Role::Owner)
    }
}

/// One of the user's own devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceView {
    pub node_id: String,
    pub name: String,
    pub this_device: bool,
}

pub fn now() -> u64 {
    crate::clock::since_epoch().map(|d| d.as_secs()).unwrap_or(0)
}
