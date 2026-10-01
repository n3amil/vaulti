//! Per-user state synced between the user's own devices: profile name,
//! paired devices and contacts. Last-writer-wins per item.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::{Identity, IdentityPublic, UserId};
use crate::stamp::Stamp;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lww<T> {
    pub value: T,
    pub stamp: Stamp,
}

impl<T> Lww<T> {
    pub fn new(value: T, stamp: Stamp) -> Self {
        Self { value, stamp }
    }

    /// Returns true if `other` won.
    fn merge(&mut self, other: Lww<T>) -> bool {
        if other.stamp > self.stamp {
            *self = other;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub removed: bool,
}

/// Signed, shareable description of a user and their devices. Exchanged
/// out of band to become contacts, and refreshed automatically on sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactCard {
    pub name: String,
    pub identity: IdentityPublic,
    /// Hex iroh endpoint ids of the user's devices.
    pub devices: Vec<String>,
    pub stamp: Stamp,
    #[serde(with = "crate::b64")]
    pub sig: Vec<u8>,
}

const CARD_PREFIX: &str = "vaulti-contact:";

fn card_msg(name: &str, identity: &IdentityPublic, devices: &[String], stamp: &Stamp) -> Vec<u8> {
    serde_json::to_vec(&("vaulti/card/v1", name, identity, devices, stamp)).expect("serializable")
}

impl ContactCard {
    pub fn new(identity: &Identity, name: String, devices: Vec<String>, stamp: Stamp) -> Self {
        let public = identity.public();
        let sig = identity.sign(&card_msg(&name, &public, &devices, &stamp));
        Self { name, identity: public, devices, stamp, sig }
    }

    pub fn verify(&self) -> Result<()> {
        self.identity.verify(&card_msg(&self.name, &self.identity, &self.devices, &self.stamp), &self.sig)
    }

    pub fn encode(&self) -> String {
        format!("{CARD_PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).expect("serializable")))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let raw = s.trim().strip_prefix(CARD_PREFIX).ok_or(Error::Malformed("not a vaulti contact card".into()))?;
        let bytes = URL_SAFE_NO_PAD.decode(raw.trim()).map_err(|_| Error::Malformed("bad contact card".into()))?;
        let card: ContactCard = serde_json::from_slice(&bytes)?;
        card.verify()?;
        Ok(card)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub card: ContactCard,
    pub removed: Lww<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDoc {
    pub profile_name: Lww<String>,
    /// Keyed by hex endpoint id.
    pub devices: BTreeMap<String, Lww<Device>>,
    pub contacts: BTreeMap<UserId, Contact>,
}

impl AccountDoc {
    pub fn new(profile_name: String, stamp: Stamp) -> Self {
        Self { profile_name: Lww::new(profile_name, stamp), devices: BTreeMap::new(), contacts: BTreeMap::new() }
    }

    pub fn active_devices(&self) -> impl Iterator<Item = (&String, &Device)> {
        self.devices.iter().filter(|(_, d)| !d.value.removed).map(|(id, d)| (id, &d.value))
    }

    pub fn active_contacts(&self) -> impl Iterator<Item = &Contact> {
        self.contacts.values().filter(|c| !c.removed.value)
    }

    pub fn contact(&self, user: &UserId) -> Option<&Contact> {
        self.contacts.get(user).filter(|c| !c.removed.value)
    }

    /// Stores a newer card for a contact we already have (removed or not).
    pub fn update_card(&mut self, card: ContactCard) -> bool {
        match self.contacts.get_mut(&card.identity.user_id()) {
            Some(c) if card.stamp > c.card.stamp && card.identity == c.card.identity => {
                c.card = card;
                true
            }
            _ => false,
        }
    }

    pub fn merge(&mut self, other: AccountDoc) -> bool {
        let mut changed = self.profile_name.merge(other.profile_name);
        for (id, d) in other.devices {
            match self.devices.get_mut(&id) {
                Some(cur) => changed |= cur.merge(d),
                None => {
                    self.devices.insert(id, d);
                    changed = true;
                }
            }
        }
        for (uid, c) in other.contacts {
            if c.card.verify().is_err() || c.card.identity.user_id() != uid {
                continue;
            }
            match self.contacts.get_mut(&uid) {
                Some(cur) => {
                    changed |= cur.removed.merge(c.removed);
                    if c.card.stamp > cur.card.stamp && c.card.identity == cur.card.identity {
                        cur.card = c.card;
                        changed = true;
                    }
                }
                None => {
                    self.contacts.insert(uid, c);
                    changed = true;
                }
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stamp::Clock;
    use uuid::Uuid;

    #[test]
    fn card_roundtrip_and_tamper() {
        let id = Identity::generate().unwrap();
        let mut clock = Clock::new(Uuid::new_v4());
        let card = ContactCard::new(&id, "Alice".into(), vec!["ab".repeat(32)], clock.tick());
        let decoded = ContactCard::decode(&card.encode()).unwrap();
        assert_eq!(decoded, card);

        let mut forged = card.clone();
        forged.devices.push("cd".repeat(32));
        let s = format!("{CARD_PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap()));
        assert!(ContactCard::decode(&s).is_err());
    }

    #[test]
    fn devices_merge_lww() {
        let mut clock = Clock::new(Uuid::new_v4());
        let mut a = AccountDoc::new("me".into(), clock.tick());
        let mut b = a.clone();
        a.devices.insert("d1".into(), Lww::new(Device { name: "laptop".into(), removed: false }, clock.tick()));
        b.devices.insert("d2".into(), Lww::new(Device { name: "phone".into(), removed: false }, clock.tick()));
        let mut b_removes = a.clone();
        b_removes
            .devices
            .get_mut("d1")
            .unwrap()
            .merge(Lww::new(Device { name: "laptop".into(), removed: true }, clock.tick()));
        assert!(a.merge(b));
        assert!(a.merge(b_removes));
        assert_eq!(a.active_devices().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), vec!["d2"]);
    }
}
