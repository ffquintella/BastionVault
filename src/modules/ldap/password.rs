//! Password generator.
//!
//! Phase 1 ships a built-in 24-char alphanumeric + symbol generator
//! that satisfies the AD complexity rule (at least three of the four
//! character classes) by construction: every output contains at
//! least one lowercase, one uppercase, one digit, and one symbol.
//! Operator-supplied generator policies (`sys/policies/password/*`)
//! are spec'd as a follow-up; the field on `LdapConfig.password_policy`
//! is persisted today but ignored at generation time until that
//! subsystem ships.

use rand::{seq::SliceRandom, RngExt};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT: &[u8] = b"0123456789";
const SYMBOL: &[u8] = b"!@#$%^&*-_=+";

pub const DEFAULT_LENGTH: usize = 24;

/// Generate a fresh password with the engine's built-in policy.
/// Length is the `len` argument, capped at 256 for sanity (AD's
/// hard ceiling is 256; OpenLDAP has no hard cap but anything
/// longer makes operator typo-recovery painful).
pub fn generate(len: usize) -> String {
    let len = len.clamp(12, 256);
    let mut rng = rand::rng();

    // Seed the buffer with one of each required class so the AD
    // complexity rule is structurally satisfied before we fill the
    // rest from the union pool. The final byte order is shuffled
    // so the position of the seeded class isn't predictable.
    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    bytes.push(LOWER[rng.random_range(0..LOWER.len())]);
    bytes.push(UPPER[rng.random_range(0..UPPER.len())]);
    bytes.push(DIGIT[rng.random_range(0..DIGIT.len())]);
    bytes.push(SYMBOL[rng.random_range(0..SYMBOL.len())]);

    // Union pool for the rest.
    let mut union_pool: Vec<u8> = Vec::with_capacity(LOWER.len() + UPPER.len() + DIGIT.len() + SYMBOL.len());
    union_pool.extend_from_slice(LOWER);
    union_pool.extend_from_slice(UPPER);
    union_pool.extend_from_slice(DIGIT);
    union_pool.extend_from_slice(SYMBOL);

    while bytes.len() < len {
        bytes.push(union_pool[rng.random_range(0..union_pool.len())]);
    }
    bytes.shuffle(&mut rng);

    // The character set is ASCII by construction so this is always
    // valid UTF-8 — `from_utf8_unchecked` would be safe here, but
    // the cost of `String::from_utf8` is one length check.
    String::from_utf8(bytes).expect("password bytes are ASCII by construction")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_class(s: &str, cls: &[u8]) -> bool {
        s.as_bytes().iter().any(|b| cls.contains(b))
    }

    #[test]
    fn output_satisfies_ad_complexity_rule() {
        // 1000 generations should each carry at least one of every
        // class — a structural guarantee, not a probabilistic one.
        for _ in 0..1000 {
            let p = generate(DEFAULT_LENGTH);
            assert!(has_class(&p, LOWER), "missing lowercase: {p}");
            assert!(has_class(&p, UPPER), "missing uppercase: {p}");
            assert!(has_class(&p, DIGIT), "missing digit: {p}");
            assert!(has_class(&p, SYMBOL), "missing symbol: {p}");
            assert_eq!(p.len(), DEFAULT_LENGTH);
        }
    }

    #[test]
    fn length_clamps_low() {
        // Below the floor we still seed every class, so length must
        // grow to at least 4 — but the spec says no shorter than 12.
        let p = generate(4);
        assert!(p.len() >= 12);
    }

    #[test]
    fn distinct_calls_distinct() {
        let a = generate(DEFAULT_LENGTH);
        let b = generate(DEFAULT_LENGTH);
        assert_ne!(a, b);
    }
}
