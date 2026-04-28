//! HOTP (RFC 4226) and TOTP (RFC 6238).
//!
//! Implemented on top of `hmac` + `sha1` / `sha2`. The construction
//! is fixed by the RFC; we don't invent crypto here, only stitch the
//! standard primitives together.
//!
//! HOTP(K, C) = Truncate(HMAC-Hash(K, C)) mod 10^d
//! TOTP(K, T) = HOTP(K, floor((T - T0) / X))   with T0 = 0, X = period.

use hmac::{digest::KeyInit, Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use super::policy::Algorithm;

pub mod otpauth;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// RFC 4226 §5.3 dynamic truncation. Returns the digit-bounded code
/// for the supplied counter. `digits` must be 6 or 8 — the policy
/// validator rejects anything else before reaching here.
pub fn hotp(key: &[u8], counter: u64, algo: Algorithm, digits: u32) -> String {
    let counter_be = counter.to_be_bytes();
    let mac = match algo {
        Algorithm::Sha1 => {
            let mut m = <HmacSha1 as KeyInit>::new_from_slice(key)
                .expect("hmac accepts any key length");
            m.update(&counter_be);
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut m = <HmacSha256 as KeyInit>::new_from_slice(key)
                .expect("hmac accepts any key length");
            m.update(&counter_be);
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut m = <HmacSha512 as KeyInit>::new_from_slice(key)
                .expect("hmac accepts any key length");
            m.update(&counter_be);
            m.finalize().into_bytes().to_vec()
        }
    };

    // RFC 4226 §5.3: low-nibble of the last byte selects the offset.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin_code = ((mac[offset] & 0x7f) as u32) << 24
        | (mac[offset + 1] as u32) << 16
        | (mac[offset + 2] as u32) << 8
        | (mac[offset + 3] as u32);

    let modulus = 10_u32.pow(digits);
    let code = bin_code % modulus;
    format!("{:0width$}", code, width = digits as usize)
}

/// Step counter for `(now_secs, period)`. Wrapped in a function so
/// callers cannot get the off-by-one wrong relative to the validate
/// path — both paths come through here.
pub fn step_for(now_secs: u64, period: u64) -> u64 {
    now_secs / period
}

/// Generate the current TOTP code at `now_secs`.
pub fn totp(key: &[u8], now_secs: u64, algo: Algorithm, digits: u32, period: u64) -> String {
    hotp(key, step_for(now_secs, period), algo, digits)
}

/// Constant-time string comparison. Wraps `subtle::ConstantTimeEq` so
/// the validator cannot be timed for the matching prefix.
pub fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D test vectors. Secret = ASCII
    /// "12345678901234567890" (20 bytes), SHA1, 6 digits.
    #[test]
    fn rfc4226_appendix_d() {
        let key = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp(key, counter as u64, Algorithm::Sha1, 6);
            assert_eq!(&got, want, "HOTP(K, {counter}) mismatch");
        }
    }

    /// RFC 6238 Appendix B test vectors (8-digit). The RFC defines
    /// distinct seeds per algorithm:
    ///   * SHA1   — 20 ASCII bytes "12345678901234567890"
    ///   * SHA256 — 32 ASCII bytes "12345678901234567890123456789012"
    ///   * SHA512 — 64 ASCII bytes "1234567890" repeated to 64 bytes.
    #[test]
    fn rfc6238_appendix_b() {
        let key_sha1 = b"12345678901234567890".to_vec();
        let key_sha256 = b"12345678901234567890123456789012".to_vec();
        let key_sha512 =
            b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();

        // Selected (T, expected) per algo from Appendix B.
        let cases: &[(u64, Algorithm, &[u8], &str)] = &[
            (59, Algorithm::Sha1, &key_sha1, "94287082"),
            (1111111109, Algorithm::Sha1, &key_sha1, "07081804"),
            (1111111111, Algorithm::Sha1, &key_sha1, "14050471"),
            (1234567890, Algorithm::Sha1, &key_sha1, "89005924"),
            (2000000000, Algorithm::Sha1, &key_sha1, "69279037"),
            (59, Algorithm::Sha256, &key_sha256, "46119246"),
            (1111111109, Algorithm::Sha256, &key_sha256, "68084774"),
            (1234567890, Algorithm::Sha256, &key_sha256, "91819424"),
            (59, Algorithm::Sha512, &key_sha512, "90693936"),
            (1111111109, Algorithm::Sha512, &key_sha512, "25091201"),
        ];

        for (t, algo, key, want) in cases {
            let got = totp(key, *t, *algo, 8, 30);
            assert_eq!(&got, want, "TOTP({:?}, T={}) mismatch", algo, t);
        }
    }

    #[test]
    fn ct_eq_matches_string_eq() {
        assert!(ct_eq("123456", "123456"));
        assert!(!ct_eq("123456", "123457"));
        assert!(!ct_eq("123456", "1234567"));
    }
}
