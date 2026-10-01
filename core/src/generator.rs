//! Random password generator (uniform, rejection sampling).

use zeroize::Zeroizing;

use crate::crypto::fill_random;
use crate::error::{Error, Result};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";

#[derive(Debug, Clone, Copy)]
pub struct PasswordSpec {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PasswordSpec {
    fn default() -> Self {
        Self { length: 20, lower: true, upper: true, digits: true, symbols: true }
    }
}

fn random_index(n: usize) -> Result<usize> {
    // Rejection sampling to avoid modulo bias.
    let n = n as u32;
    let limit = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        fill_random(&mut b)?;
        let v = u32::from_le_bytes(b);
        if v < limit {
            return Ok((v % n) as usize);
        }
    }
}

/// Generates a password containing at least one char of every enabled class.
pub fn generate(spec: PasswordSpec) -> Result<Zeroizing<String>> {
    let classes: Vec<&[u8]> =
        [(spec.lower, LOWER), (spec.upper, UPPER), (spec.digits, DIGITS), (spec.symbols, SYMBOLS)]
            .into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, s)| s.as_bytes())
            .collect();
    if classes.is_empty() || spec.length < classes.len() {
        return Err(Error::Malformed("password spec: no classes or length too short".into()));
    }
    let alphabet: Vec<u8> = classes.concat();

    loop {
        let mut out = Zeroizing::new(String::with_capacity(spec.length));
        for _ in 0..spec.length {
            out.push(alphabet[random_index(alphabet.len())?] as char);
        }
        if classes.iter().all(|cls| out.bytes().any(|b| cls.contains(&b))) {
            return Ok(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_classes() {
        let p = generate(PasswordSpec { length: 12, symbols: false, ..Default::default() }).unwrap();
        assert_eq!(p.len(), 12);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn rejects_impossible_spec() {
        let none = PasswordSpec { lower: false, upper: false, digits: false, symbols: false, length: 10 };
        assert!(generate(none).is_err());
        assert!(generate(PasswordSpec { length: 2, ..Default::default() }).is_err());
    }
}
