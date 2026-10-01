//! Vaulti core: vault format, crypto and recovery.
//!
//! P2P sync (iroh) and collection sharing build on top of this; the key
//! hierarchy is documented in [`vault`].

mod b64;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod model;
pub mod recovery;
pub mod store;
pub mod vault;

pub use crypto::KdfParams;
pub use error::{Error, Result};
pub use model::{Collection, Entry, EntryInput};
pub use recovery::BackupCode;
pub use vault::{Vault, VaultFile};
