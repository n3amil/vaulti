//! Password and passphrase generator (uniform, rejection sampling).
//!
//! Passphrases use the EFF large wordlist, <https://www.eff.org/dice>,
//! licensed CC BY 3.0 US, with the 4 hyphenated words removed (7772 words,
//! ~12.9 bits per word) so any separator, including `-`, splits unambiguously.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::fill_random;
use crate::error::{Error, Result};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
/// Characters easily confused when reading or typing a password.
const AMBIGUOUS: &str = "0O1lI|";

const WORDLIST: &str = include_str!("wordlist/eff_large.txt");

pub const MIN_LENGTH: usize = 4;
pub const MAX_LENGTH: usize = 128;
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordSpec {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Leave out 0 O 1 l I |
    pub avoid_ambiguous: bool,
}

impl Default for PasswordSpec {
    fn default() -> Self {
        Self { length: 20, lower: true, upper: true, digits: true, symbols: true, avoid_ambiguous: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PassphraseSpec {
    pub words: usize,
    /// Anything up to 3 characters: "-", " ", "#", "" ...
    pub separator: String,
    pub capitalize: bool,
    /// Append a random digit to one random word.
    pub include_number: bool,
}

impl Default for PassphraseSpec {
    fn default() -> Self {
        Self { words: 5, separator: "-".into(), capitalize: false, include_number: false }
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

fn classes(spec: &PasswordSpec) -> Vec<Vec<u8>> {
    [(spec.lower, LOWER), (spec.upper, UPPER), (spec.digits, DIGITS), (spec.symbols, SYMBOLS)]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, s)| s.bytes().filter(|b| !(spec.avoid_ambiguous && AMBIGUOUS.as_bytes().contains(b))).collect())
        .collect()
}

/// Generates a password containing at least one char of every enabled class.
pub fn generate(spec: PasswordSpec) -> Result<Zeroizing<String>> {
    let classes = classes(&spec);
    if classes.is_empty() {
        return Err(Error::Malformed("choose at least one character type".into()));
    }
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&spec.length) || spec.length < classes.len() {
        return Err(Error::Malformed(format!("length must be between {MIN_LENGTH} and {MAX_LENGTH}")));
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

fn words() -> impl Iterator<Item = &'static str> {
    WORDLIST.lines()
}

pub fn generate_passphrase(spec: &PassphraseSpec) -> Result<Zeroizing<String>> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&spec.words) {
        return Err(Error::Malformed(format!("use between {MIN_WORDS} and {MAX_WORDS} words")));
    }
    if spec.separator.chars().count() > 3 {
        return Err(Error::Malformed("separator can be at most 3 characters".into()));
    }
    let list: Vec<&str> = words().collect();
    let number_at = if spec.include_number { Some(random_index(spec.words)?) } else { None };
    let mut parts: Vec<Zeroizing<String>> = Vec::with_capacity(spec.words);
    for i in 0..spec.words {
        let w = list[random_index(list.len())?];
        let mut word = Zeroizing::new(if spec.capitalize {
            let mut c = w.chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
        } else {
            w.to_string()
        });
        if number_at == Some(i) {
            word.push(char::from(b'0' + random_index(10)? as u8));
        }
        parts.push(word);
    }
    let joined = parts.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(&spec.separator);
    Ok(Zeroizing::new(joined))
}

/// Approximate entropy in bits of what `generate` produces with this spec.
pub fn password_entropy(spec: &PasswordSpec) -> f64 {
    let n: usize = classes(spec).iter().map(Vec::len).sum();
    if n == 0 {
        return 0.0;
    }
    spec.length as f64 * (n as f64).log2()
}

/// Entropy in bits of a passphrase with this spec (the word choice dominates).
pub fn passphrase_entropy(spec: &PassphraseSpec) -> f64 {
    let per_word = (words().count() as f64).log2();
    let number = if spec.include_number { (10.0f64).log2() + (spec.words as f64).log2() } else { 0.0 };
    spec.words as f64 * per_word + number
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
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn single_class_and_ambiguous_filter() {
        for _ in 0..50 {
            let p = generate(PasswordSpec {
                length: 30,
                lower: false,
                upper: false,
                digits: true,
                symbols: false,
                avoid_ambiguous: true,
            })
            .unwrap();
            assert!(p.chars().all(|c| c.is_ascii_digit() && c != '0' && c != '1'), "{}", &*p);
        }
        let p = generate(PasswordSpec { length: 64, avoid_ambiguous: true, ..Default::default() }).unwrap();
        assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
    }

    #[test]
    fn rejects_impossible_spec() {
        let none = PasswordSpec { lower: false, upper: false, digits: false, symbols: false, ..Default::default() };
        assert!(generate(none).is_err());
        assert!(generate(PasswordSpec { length: 3, ..Default::default() }).is_err());
        assert!(generate(PasswordSpec { length: 129, ..Default::default() }).is_err());
    }

    #[test]
    fn wordlist_has_only_plain_words() {
        assert_eq!(words().count(), 7772);
        assert!(words().all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase())));
    }

    #[test]
    fn passphrase_shape() {
        let spec = PassphraseSpec { words: 6, separator: ".".into(), capitalize: true, include_number: true };
        let p = generate_passphrase(&spec).unwrap();
        let parts: Vec<&str> = p.split('.').collect();
        assert_eq!(parts.len(), 6);
        assert!(parts.iter().all(|w| w.chars().next().unwrap().is_ascii_uppercase()));
        assert_eq!(p.chars().filter(|c| c.is_ascii_digit()).count(), 1);

        let plain = generate_passphrase(&PassphraseSpec::default()).unwrap();
        assert_eq!(plain.split('-').count(), 5);
        for sep in [" ", "#", "", "+++"] {
            let p =
                generate_passphrase(&PassphraseSpec { words: 4, separator: sep.into(), ..Default::default() }).unwrap();
            if !sep.is_empty() {
                assert_eq!(p.split(sep).count(), 4, "{sep:?}");
            }
            assert!(p.chars().all(|c| c.is_ascii_lowercase() || sep.contains(c)));
        }
        assert!(generate_passphrase(&PassphraseSpec { words: 2, ..Default::default() }).is_err());
        assert!(generate_passphrase(&PassphraseSpec { separator: "----".into(), ..Default::default() }).is_err());
    }

    #[test]
    fn entropy_estimates() {
        let e = password_entropy(&PasswordSpec::default());
        assert!((e - 20.0 * 86f64.log2()).abs() < 0.01, "{e}");
        let p = passphrase_entropy(&PassphraseSpec::default());
        assert!((p - 5.0 * 7772f64.log2()).abs() < 0.01, "{p}");
    }
}
