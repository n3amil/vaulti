//! Vaulti core: vault format, crypto, recovery, sharing and the sync merge
//! logic. No networking here; transport lives in `vaulti-sync`.
//!
//! The key hierarchy is documented in [`vault`].

pub mod account;
mod b64;
pub mod backup;
pub mod collection;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod identity;
mod legacy;
pub mod model;
pub mod recovery;
pub mod stamp;
pub mod store;
pub mod totp;
pub mod vault;

pub use account::ContactCard;
pub use collection::{Member, Role};
pub use crypto::KdfParams;
pub use error::{Error, Result};
pub use identity::{IdentityPublic, UserId};
pub use model::{Collection, DeviceView, Entry, EntryInput};
pub use recovery::BackupCode;
pub use vault::{FileV2, Peer, SyncMessage, SyncReport, Vault, VaultFile};
