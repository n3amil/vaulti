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
}

/// Fields a user can set when adding or editing an entry.
#[derive(Debug, Clone, Default)]
pub struct EntryInput {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
}

/// Decrypted, read-only view of a collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub id: Uuid,
    pub name: String,
    pub entries: Vec<Entry>,
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

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
