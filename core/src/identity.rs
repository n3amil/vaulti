//! User identity: an ed25519 key (signing) and an x25519 key (receiving
//! collection keys). All devices of one user share the same identity.

use data_encoding::HEXLOWER;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{self, fill_random, Key, Sealed, KEY_LEN};
use crate::error::{Error, Result};

/// Stable user id: lowercase hex of the ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub String);

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityPublic {
    #[serde(with = "crate::b64")]
    pub signing: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub encryption: Vec<u8>,
}

/// Collection key (or anything small) encrypted to an x25519 public key:
/// ephemeral ECDH + HKDF-SHA256 + XChaCha20-Poly1305.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBox {
    #[serde(with = "crate::b64")]
    pub ephemeral: Vec<u8>,
    pub sealed: Sealed,
}

fn box_key(shared: &[u8; 32], ephemeral: &[u8], recipient: &[u8]) -> Result<Key> {
    let salt = [ephemeral, recipient].concat();
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(b"vaulti/sealbox/v1", out.as_mut())
        .map_err(|_| Error::Malformed("hkdf".into()))?;
    Key::from_bytes(out.as_ref())
}

fn arr32(b: &[u8], what: &str) -> Result<[u8; 32]> {
    b.try_into().map_err(|_| Error::Malformed(format!("{what} has wrong length")))
}

impl IdentityPublic {
    pub fn user_id(&self) -> UserId {
        UserId(HEXLOWER.encode(&self.signing))
    }

    /// Short code users can compare out of band, e.g. `3F9A 11C2 7B04 E8D1`.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest([&self.signing[..], &self.encryption[..]].concat());
        let hex = data_encoding::HEXUPPER.encode(&digest[..8]);
        hex.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).expect("hex")).collect::<Vec<_>>().join(" ")
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&arr32(&self.signing, "signing key")?).map_err(|_| Error::BadSignature)?;
        let sig = Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
        vk.verify(msg, &sig).map_err(|_| Error::BadSignature)
    }

    pub fn seal_to(&self, plaintext: &[u8], aad: &[u8]) -> Result<SealedBox> {
        let recipient = XPublic::from(arr32(&self.encryption, "encryption key")?);
        let mut eph_bytes = Zeroizing::new([0u8; 32]);
        fill_random(eph_bytes.as_mut())?;
        let eph = StaticSecret::from(*eph_bytes);
        let eph_pub = XPublic::from(&eph);
        let shared = Zeroizing::new(eph.diffie_hellman(&recipient).to_bytes());
        let key = box_key(&shared, eph_pub.as_bytes(), recipient.as_bytes())?;
        Ok(SealedBox { ephemeral: eph_pub.as_bytes().to_vec(), sealed: crypto::seal(&key, plaintext, aad)? })
    }
}

pub struct Identity {
    signing: SigningKey,
    encryption: StaticSecret,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; 64]);
        fill_random(secret.as_mut())?;
        Self::from_secret_bytes(secret.as_ref())
    }

    /// `signing (32) || encryption (32)`
    pub fn from_secret_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 64 {
            return Err(Error::Malformed("identity secret has wrong length".into()));
        }
        Ok(Self {
            signing: SigningKey::from_bytes(&arr32(&b[..32], "signing secret")?),
            encryption: StaticSecret::from(arr32(&b[32..], "encryption secret")?),
        })
    }

    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new([&self.signing.to_bytes()[..], &self.encryption.to_bytes()[..]].concat())
    }

    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            signing: self.signing.verifying_key().to_bytes().to_vec(),
            encryption: XPublic::from(&self.encryption).to_bytes().to_vec(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing.sign(msg).to_bytes().to_vec()
    }

    pub fn open_box(&self, b: &SealedBox, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let eph = XPublic::from(arr32(&b.ephemeral, "ephemeral key")?);
        let shared = Zeroizing::new(self.encryption.diffie_hellman(&eph).to_bytes());
        let me = XPublic::from(&self.encryption);
        let key = box_key(&shared, eph.as_bytes(), me.as_bytes())?;
        crypto::open(&key, &b.sealed, aad)
    }
}

/// Hex public key of a device's iroh endpoint (ed25519), derived from its secret.
pub fn device_node_id(device_secret: &[u8; 32]) -> String {
    HEXLOWER.encode(SigningKey::from_bytes(device_secret).verifying_key().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let id = Identity::generate().unwrap();
        let sig = id.sign(b"msg");
        id.public().verify(b"msg", &sig).unwrap();
        assert!(id.public().verify(b"other", &sig).is_err());
        let other = Identity::generate().unwrap();
        assert!(other.public().verify(b"msg", &sig).is_err());
    }

    #[test]
    fn sealed_box_roundtrip_and_wrong_recipient() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let b = bob.public().seal_to(b"collection key", b"aad").unwrap();
        assert_eq!(&bob.open_box(&b, b"aad").unwrap()[..], b"collection key");
        assert!(bob.open_box(&b, b"other").is_err());
        assert!(alice.open_box(&b, b"aad").is_err());
    }

    #[test]
    fn secret_roundtrip() {
        let id = Identity::generate().unwrap();
        let again = Identity::from_secret_bytes(&id.secret_bytes()).unwrap();
        assert_eq!(id.public(), again.public());
        assert_eq!(id.public().user_id().0.len(), 64);
        assert_eq!(id.public().fingerprint().len(), 19);
    }
}
