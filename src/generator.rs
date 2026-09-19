use zeroize::Zeroizing;

use crate::errors::{Error, Result};

pub const DEFAULT_LENGTH: usize = 20;
pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/~";

// Ambiguous characters removed when `exclude_ambiguous` is set.
const AMBIGUOUS: &[u8] = b"0O1lI|`'\"`";

#[derive(Clone, Debug)]
pub struct GenOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        Self {
            length: DEFAULT_LENGTH,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        }
    }
}

impl GenOptions {
    pub fn validate(&self) -> Result<()> {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&self.length) {
            return Err(Error::InvalidFormat("invalid password length"));
        }
        if !(self.lowercase || self.uppercase || self.digits || self.symbols) {
            return Err(Error::InvalidFormat(
                "at least one character class must be enabled",
            ));
        }
        Ok(())
    }

    fn alphabet(&self, class: &[u8]) -> Vec<u8> {
        if self.exclude_ambiguous {
            class
                .iter()
                .copied()
                .filter(|c| !AMBIGUOUS.contains(c))
                .collect()
        } else {
            class.to_vec()
        }
    }
}

fn pick_uniform(set: &[u8]) -> Result<u8> {
    debug_assert!(!set.is_empty(), "empty character set");
    // Rejection sampling: n = 2^8, usable = floor(256 / len) * len to avoid
    // modulo bias (modular reduction over the full byte range leaks bias).
    let len = set.len();
    let usable: usize = (1 << 8) - ((1 << 8) % len);
    loop {
        let mut byte = [0u8; 1];
        getrandom::getrandom(&mut byte)?;
        let v = byte[0] as usize;
        if v < usable {
            return Ok(set[v % len]);
        }
    }
}

pub fn generate(options: &GenOptions) -> Result<Zeroizing<String>> {
    options.validate()?;

    let mut classes: Vec<Vec<u8>> = Vec::new();
    if options.lowercase {
        classes.push(options.alphabet(LOWERCASE));
    }
    if options.uppercase {
        classes.push(options.alphabet(UPPERCASE));
    }
    if options.digits {
        classes.push(options.alphabet(DIGITS));
    }
    if options.symbols {
        classes.push(options.alphabet(SYMBOLS));
    }
    classes.retain(|c| !c.is_empty());
    if classes.is_empty() {
        return Err(Error::InvalidFormat(
            "character set too small after ambiguity removal",
        ));
    }

    let pool: Vec<u8> = classes.iter().flatten().copied().collect();
    let mut out = Vec::with_capacity(options.length);

    // Guarantee at least one character from each enabled class.
    for class in &classes {
        out.push(pick_uniform(class)?);
    }
    while out.len() < options.length {
        out.push(pick_uniform(&pool)?);
    }

    // Fisher-Yates shuffle for unbiased final ordering.
    for i in (1..out.len()).rev() {
        let j = {
            let mut byte = [0u8; 1];
            getrandom::getrandom(&mut byte)?;
            byte[0] as usize % (i + 1)
        };
        out.swap(i, j);
    }

    Ok(Zeroizing::new(
        String::from_utf8(out).map_err(|_| Error::Crypto)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_length_and_char_classes() {
        let options = GenOptions::default();
        let pw = generate(&options).unwrap();
        assert_eq!(pw.len(), DEFAULT_LENGTH);
        assert!(
            pw.bytes().any(|c| LOWERCASE.contains(&c))
                && pw.bytes().any(|c| UPPERCASE.contains(&c))
                && pw.bytes().any(|c| DIGITS.contains(&c))
                && pw.bytes().any(|c| SYMBOLS.contains(&c))
        );
    }

    #[test]
    fn ambiguous_chars_excluded() {
        let options = GenOptions {
            exclude_ambiguous: true,
            ..Default::default()
        };
        let pw = generate(&options).unwrap();
        assert!(pw.bytes().all(|c| !AMBIGUOUS.contains(&c)));
    }

    #[test]
    fn classes_without_symbols() {
        let options = GenOptions {
            symbols: false,
            length: 16,
            ..Default::default()
        };
        let pw = generate(&options).unwrap();
        assert_eq!(pw.len(), 16);
        assert!(pw.bytes().all(|c| !SYMBOLS.contains(&c)));
    }

    #[test]
    fn rejects_bad_length() {
        let options = GenOptions {
            length: MIN_LENGTH - 1,
            ..Default::default()
        };
        assert!(generate(&options).is_err());
        let options = GenOptions {
            length: MAX_LENGTH + 1,
            ..Default::default()
        };
        assert!(generate(&options).is_err());
    }

    #[test]
    fn rejects_no_classes() {
        let options = GenOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(generate(&options).is_err());
    }

    #[test]
    fn generation_is_random() {
        let options = GenOptions::default();
        let a = generate(&options).unwrap();
        let b = generate(&options).unwrap();
        assert_ne!(&*a, &*b);
    }
}
