//! Backup codes: 160 random bits shown to the user once, e.g.
//! `K7QM-3XPA-9TRD-...` (8 groups of 4, RFC 4648 base32).

use data_encoding::BASE32_NOPAD;
use zeroize::Zeroizing;

use crate::crypto::fill_random;
use crate::error::{Error, Result};

const CODE_BYTES: usize = 20; // 160 bits -> exactly 32 base32 chars
const GROUP: usize = 4;

pub struct BackupCode(Zeroizing<Vec<u8>>);

impl BackupCode {
    pub fn generate() -> Result<Self> {
        let mut b = Zeroizing::new(vec![0u8; CODE_BYTES]);
        fill_random(&mut b)?;
        Ok(Self(b))
    }

    /// Accepts any case, with or without dashes/spaces. Digits that base32
    /// never uses are read as their look-alike letters (0→O, 1→I, 8→B).
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| match c.to_ascii_uppercase() {
                    '0' => 'O',
                    '1' => 'I',
                    '8' => 'B',
                    c => c,
                })
                .collect(),
        );
        let bytes = BASE32_NOPAD.decode(cleaned.as_bytes()).map_err(|_| Error::InvalidBackupCode)?;
        if bytes.len() != CODE_BYTES {
            return Err(Error::InvalidBackupCode);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Human-readable form for display/printing.
    pub fn display(&self) -> Zeroizing<String> {
        let raw = BASE32_NOPAD.encode(&self.0);
        let groups: Vec<&str> =
            raw.as_bytes().chunks(GROUP).map(|c| std::str::from_utf8(c).expect("base32 is ascii")).collect();
        Zeroizing::new(groups.join("-"))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for BackupCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupCode(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_parse_roundtrip() {
        let c = BackupCode::generate().unwrap();
        let shown = c.display();
        assert_eq!(shown.len(), 32 + 7);
        let p = BackupCode::parse(&shown).unwrap();
        assert_eq!(p.as_bytes(), c.as_bytes());
    }

    #[test]
    fn parse_is_lenient_about_formatting() {
        let c = BackupCode::generate().unwrap();
        let sloppy = c.display().replace('-', " ").to_lowercase();
        assert_eq!(BackupCode::parse(&sloppy).unwrap().as_bytes(), c.as_bytes());
    }

    #[test]
    fn parse_accepts_lookalike_digits() {
        let c = BackupCode::generate().unwrap();
        let typo = c.display().replace('O', "0").replace('I', "1").replace('B', "8");
        assert_eq!(BackupCode::parse(&typo).unwrap().as_bytes(), c.as_bytes());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(BackupCode::parse("not-a-code").is_err());
        assert!(BackupCode::parse("AAAA").is_err());
    }
}
