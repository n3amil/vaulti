//! Time-based one-time passwords (RFC 6238).
//!
//! Accepts what services hand out: an `otpauth://totp/...` URI (from the QR
//! code) or a bare base32 secret (any case, spaces and `=` padding allowed).

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

fn bad(msg: &str) -> Error {
    Error::Malformed(format!("TOTP: {msg}"))
}

fn percent_decode(s: &str) -> String {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_secret(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        s.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-').map(|c| c.to_ascii_uppercase()).collect(),
    );
    if cleaned.is_empty() {
        return Err(bad("empty secret"));
    }
    let secret = BASE32_NOPAD.decode(cleaned.as_bytes()).map_err(|_| bad("secret is not valid base32"))?;
    Ok(Zeroizing::new(secret))
}

impl Totp {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let Some(rest) = input.strip_prefix("otpauth://") else {
            return Ok(Self {
                secret: decode_secret(input)?,
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                issuer: None,
                account: None,
            });
        };
        let rest = rest.strip_prefix("totp/").ok_or_else(|| bad("only time-based (totp) codes are supported"))?;
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label);
        let (mut issuer, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_string()), Some(a.trim().to_string())),
            None => (None, Some(label.trim().to_string()).filter(|a| !a.is_empty())),
        };
        let (mut secret, mut algorithm, mut digits, mut period) = (None, Algorithm::Sha1, 6, 30);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v);
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_secret(&v)?),
                "issuer" if !v.trim().is_empty() => issuer = Some(v.trim().to_string()),
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(bad("unsupported algorithm")),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| bad("invalid digits"))?,
                "period" => period = v.parse().map_err(|_| bad("invalid period"))?,
                _ => {}
            }
        }
        if !(6..=8).contains(&digits) {
            return Err(bad("digits must be 6 to 8"));
        }
        if !(1..=300).contains(&period) {
            return Err(bad("period must be 1 to 300 seconds"));
        }
        Ok(Self {
            secret: secret.ok_or_else(|| bad("the link has no secret"))?,
            algorithm,
            digits,
            period,
            issuer,
            account,
        })
    }

    fn hmac(&self, msg: &[u8]) -> Vec<u8> {
        macro_rules! mac {
            ($h:ty) => {{
                let mut m = Hmac::<$h>::new_from_slice(&self.secret).expect("HMAC takes any key length");
                m.update(msg);
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self.algorithm {
            Algorithm::Sha1 => mac!(sha1::Sha1),
            Algorithm::Sha256 => mac!(sha2::Sha256),
            Algorithm::Sha512 => mac!(sha2::Sha512),
        }
    }

    /// The code valid at unix time `secs`.
    pub fn code_at(&self, secs: u64) -> String {
        let counter = secs / self.period;
        let h = self.hmac(&counter.to_be_bytes());
        let offset = (h[h.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([h[offset] & 0x7f, h[offset + 1], h[offset + 2], h[offset + 3]]);
        let code = bin % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// Current code and seconds until it changes.
    pub fn now(&self) -> (String, u64) {
        let secs = crate::clock::since_epoch().map(|d| d.as_secs()).unwrap_or(0);
        (self.code_at(secs), self.period - secs % self.period)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc(secret: &[u8], alg: &str) -> Totp {
        let b32 = BASE32_NOPAD.encode(secret);
        Totp::parse(&format!("otpauth://totp/Test?secret={b32}&algorithm={alg}&digits=8&period=30")).unwrap()
    }

    /// RFC 6238 Appendix B test vectors.
    #[test]
    fn rfc6238_vectors() {
        let sha1 = rfc(b"12345678901234567890", "SHA1");
        let sha256 = rfc(b"12345678901234567890123456789012", "SHA256");
        let sha512 = rfc(b"1234567890123456789012345678901234567890123456789012345678901234", "SHA512");
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, a, b, c) in cases {
            assert_eq!(sha1.code_at(t), a, "sha1 @{t}");
            assert_eq!(sha256.code_at(t), b, "sha256 @{t}");
            assert_eq!(sha512.code_at(t), c, "sha512 @{t}");
        }
    }

    #[test]
    fn parses_uri_labels_and_defaults() {
        let t =
            Totp::parse("otpauth://totp/ACME%20Co:jo%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co").unwrap();
        assert_eq!(t.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(t.account.as_deref(), Some("jo@example.com"));
        assert_eq!((t.digits, t.period, t.algorithm), (6, 30, Algorithm::Sha1));
        assert_eq!(t.code_at(0).len(), 6);
    }

    #[test]
    fn bare_secret_is_lenient() {
        let a = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        let b = Totp::parse("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(a.code_at(1_700_000_000), b.code_at(1_700_000_000));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Totp::parse("").is_err());
        assert!(Totp::parse("not base32 !!").is_err());
        assert!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").is_err());
        assert!(Totp::parse("otpauth://totp/x?issuer=a").is_err());
        assert!(Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4").is_err());
    }

    #[test]
    fn countdown_in_range() {
        let (code, left) = Totp::parse("JBSWY3DPEHPK3PXP").unwrap().now();
        assert_eq!(code.len(), 6);
        assert!((1..=30).contains(&left));
    }
}
