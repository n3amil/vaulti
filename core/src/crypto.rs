//! Low-level primitives: random bytes, Argon2id key derivation and
//! XChaCha20-Poly1305 authenticated encryption.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// A 256-bit symmetric key, wiped from memory on drop.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    pub fn random() -> Result<Self> {
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        fill_random(k.as_mut())?;
        Ok(Self(k))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::Malformed("key has wrong length".into()))?;
        Ok(Self(Zeroizing::new(arr)))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::Random(e.to_string()))
}

pub fn random_salt() -> Result<Vec<u8>> {
    let mut s = vec![0u8; SALT_LEN];
    fill_random(&mut s)?;
    Ok(s)
}

/// Argon2id cost parameters, stored in the vault header so they can be
/// raised later without breaking existing vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes: ~0.5s on a laptop, acceptable on mid-range phones.
    fn default() -> Self {
        Self { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 1 }
    }
}

impl KdfParams {
    /// Very cheap parameters. Only for tests.
    pub fn insecure_fast() -> Self {
        Self { m_cost_kib: 8, t_cost: 1, p_cost: 1 }
    }
}

pub fn derive_key(secret: &[u8], salt: &[u8], params: &KdfParams) -> Result<Key> {
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(secret, salt, out.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(Key(out))
}

/// Nonce + ciphertext. `aad` binds the ciphertext to its context so blobs
/// can't be swapped between slots/collections undetected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "crate::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub ct: Vec<u8>,
}

pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let mut nonce = vec![0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad }).map_err(|_| Error::Decrypt)?;
    Ok(Sealed { nonce, ct })
}

pub fn open(key: &Key, sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.nonce.len() != NONCE_LEN {
        return Err(Error::Malformed("bad nonce length".into()));
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(XNonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let k = Key::random().unwrap();
        let s = seal(&k, b"hello", b"ctx").unwrap();
        assert_eq!(&open(&k, &s, b"ctx").unwrap()[..], b"hello");
    }

    #[test]
    fn wrong_aad_or_key_fails() {
        let k = Key::random().unwrap();
        let s = seal(&k, b"hello", b"ctx").unwrap();
        assert!(matches!(open(&k, &s, b"other"), Err(Error::Decrypt)));
        let k2 = Key::random().unwrap();
        assert!(matches!(open(&k2, &s, b"ctx"), Err(Error::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let k = Key::random().unwrap();
        let mut s = seal(&k, b"hello", b"ctx").unwrap();
        s.ct[0] ^= 1;
        assert!(matches!(open(&k, &s, b"ctx"), Err(Error::Decrypt)));
    }

    #[test]
    fn kdf_is_deterministic_and_salted() {
        let p = KdfParams::insecure_fast();
        let a = derive_key(b"pw", b"saltsaltsaltsalt", &p).unwrap();
        let b = derive_key(b"pw", b"saltsaltsaltsalt", &p).unwrap();
        let c = derive_key(b"pw", b"othersaltothersa", &p).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }
}
