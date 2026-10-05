//! Server-side TOTP for `form`-mode launches (`features/web-application-connect.md`
//! §3: "compute TOTP now (never the seed)").
//!
//! HOTP (RFC 4226) / TOTP (RFC 6238), stitched from the RustCrypto `hmac`,
//! `sha1` and `sha2` primitives exactly as `bv-engine-totp` does — the
//! construction is fixed by the RFCs and checked against their published test
//! vectors below. Nothing here is a new scheme. The second copy exists only
//! because an engine may not depend on another engine; folding both into a
//! Tier-0 crate is a recorded follow-up.
//!
//! Every buffer derived from the seed (the decoded key, the MAC output, the
//! code itself) is `Zeroizing`.

use hmac::{digest::KeyInit, Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Shortest seed accepted, in bytes. 80 bits is what most authenticator
/// enrolments issue (a 16-character base32 secret).
pub const MIN_SEED_BYTES: usize = 10;
pub const MAX_SEED_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

/// Code parameters. They describe the *target application's* enrolment, so
/// they live on the profile's credential source, not in the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpParams {
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self { algorithm: TotpAlgorithm::Sha1, digits: 6, period: 30 }
    }
}

impl TotpParams {
    /// Strictly parse `credential_source.totp`. Absent means the RFC 6238
    /// defaults (SHA1, 6 digits, 30 s), which is what nearly every web login
    /// uses.
    pub fn parse(v: Option<&Value>) -> Result<Self, String> {
        let Some(v) = v else { return Ok(Self::default()) };
        let obj = v.as_object().ok_or("credential_source.totp must be an object")?;
        if let Some(k) = obj.keys().find(|k| !matches!(k.as_str(), "algorithm" | "digits" | "period")) {
            return Err(format!("credential_source.totp.{k} is not a field this server understands"));
        }
        let mut p = Self::default();
        if let Some(a) = obj.get("algorithm") {
            p.algorithm = match a.as_str() {
                Some("SHA1") => TotpAlgorithm::Sha1,
                Some("SHA256") => TotpAlgorithm::Sha256,
                Some("SHA512") => TotpAlgorithm::Sha512,
                _ => return Err("credential_source.totp.algorithm must be SHA1, SHA256 or SHA512".into()),
            };
        }
        if let Some(d) = obj.get("digits") {
            p.digits = match d.as_u64() {
                Some(6) => 6,
                Some(8) => 8,
                _ => return Err("credential_source.totp.digits must be 6 or 8".into()),
            };
        }
        if let Some(s) = obj.get("period") {
            p.period = match s.as_u64() {
                Some(30) => 30,
                Some(60) => 60,
                _ => return Err("credential_source.totp.period must be 30 or 60".into()),
            };
        }
        Ok(p)
    }
}

/// A code and the instant (unix seconds) its time step ends.
pub struct TotpCode {
    pub code: Zeroizing<String>,
    pub valid_until: u64,
}

/// Decode a base32 (RFC 4648) seed. Tolerates whitespace, lower case and
/// `=` padding, like the TOTP engine. The error never echoes the input.
pub fn decode_seed(raw: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        raw.chars().filter(|c| !c.is_whitespace() && *c != '=').map(|c| c.to_ascii_uppercase()).collect(),
    );
    let key = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .map(Zeroizing::new)
        .ok_or("the TOTP seed is not valid base32 (RFC 4648)")?;
    // The decoded length is not reported: it is a fact about the seed.
    if !(MIN_SEED_BYTES..=MAX_SEED_BYTES).contains(&key.len()) {
        return Err(format!("the TOTP seed must decode to {MIN_SEED_BYTES}..={MAX_SEED_BYTES} bytes"));
    }
    Ok(key)
}

/// Copy a MAC output into a `Zeroizing` buffer and scrub the original, so no
/// un-zeroized copy of it outlives this function.
fn take_and_scrub(mut out: impl AsMut<[u8]>) -> Zeroizing<Vec<u8>> {
    let bytes = out.as_mut();
    let copy = Zeroizing::new(bytes.to_vec());
    bytes.zeroize();
    copy
}

fn mac(key: &[u8], counter: u64, algorithm: TotpAlgorithm) -> Zeroizing<Vec<u8>> {
    let msg = counter.to_be_bytes();
    // `new_from_slice` accepts any key length for HMAC; the `expect`s cannot fire.
    match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
            m.update(&msg);
            take_and_scrub(m.finalize().into_bytes())
        }
        TotpAlgorithm::Sha256 => {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
            m.update(&msg);
            take_and_scrub(m.finalize().into_bytes())
        }
        TotpAlgorithm::Sha512 => {
            let mut m = <Hmac<Sha512> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
            m.update(&msg);
            take_and_scrub(m.finalize().into_bytes())
        }
    }
}

/// RFC 4226 §5.3 HOTP with dynamic truncation.
pub fn hotp(key: &[u8], counter: u64, algorithm: TotpAlgorithm, digits: u32) -> Zeroizing<String> {
    let mac = mac(key, counter, algorithm);
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = ((mac[offset] & 0x7f) as u32) << 24
        | (mac[offset + 1] as u32) << 16
        | (mac[offset + 2] as u32) << 8
        | (mac[offset + 3] as u32);
    let code = bin % 10_u32.pow(digits);
    Zeroizing::new(format!("{:0width$}", code, width = digits as usize))
}

/// RFC 6238 TOTP at `now_secs` (T0 = 0).
pub fn code_at(key: &[u8], params: TotpParams, now_secs: u64) -> TotpCode {
    let step = now_secs / params.period;
    TotpCode { code: hotp(key, step, params.algorithm, params.digits), valid_until: (step + 1) * params.period }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc4226_appendix_d() {
        let key = b"12345678901234567890";
        let want = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
        for (c, w) in want.iter().enumerate() {
            assert_eq!(hotp(key, c as u64, TotpAlgorithm::Sha1, 6).as_str(), *w);
        }
    }

    #[test]
    fn rfc6238_appendix_b() {
        let k1 = b"12345678901234567890".as_slice();
        let k256 = b"12345678901234567890123456789012".as_slice();
        let k512 = b"1234567890123456789012345678901234567890123456789012345678901234".as_slice();
        let cases: &[(u64, TotpAlgorithm, &[u8], &str)] = &[
            (59, TotpAlgorithm::Sha1, k1, "94287082"),
            (1111111109, TotpAlgorithm::Sha1, k1, "07081804"),
            (2000000000, TotpAlgorithm::Sha1, k1, "69279037"),
            (59, TotpAlgorithm::Sha256, k256, "46119246"),
            (1234567890, TotpAlgorithm::Sha256, k256, "91819424"),
            (59, TotpAlgorithm::Sha512, k512, "90693936"),
            (1111111109, TotpAlgorithm::Sha512, k512, "25091201"),
        ];
        for (t, a, k, want) in cases {
            let p = TotpParams { algorithm: *a, digits: 8, period: 30 };
            let c = code_at(k, p, *t);
            assert_eq!(c.code.as_str(), *want, "T={t} {a:?}");
            assert_eq!(c.valid_until % 30, 0);
            assert!(c.valid_until > *t && c.valid_until - t <= 30);
        }
    }

    #[test]
    fn seed_decoding_is_tolerant_of_format_and_strict_on_content() {
        // "12345678901234567890" in base32, spaced and lower-cased.
        let k = decode_seed("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(k.as_slice(), b"12345678901234567890");
        assert!(decode_seed("GEZDGNBVGY3TQOJQ====").is_ok());
        assert!(decode_seed("not base32!").is_err());
        // 5 bytes is below the floor.
        assert!(decode_seed("GEZDGNBV").is_err());
        let msg = decode_seed("SECRETVALUE1!").err().unwrap();
        assert!(!msg.contains("SECRETVALUE1"), "errors must not echo the seed");
        // Nor its decoded length: "GEZDGNBV" is 5 bytes.
        assert!(!decode_seed("GEZDGNBV").err().unwrap().contains('5'));
    }

    #[test]
    fn params_parse_strictly() {
        assert_eq!(TotpParams::parse(None).unwrap(), TotpParams::default());
        let p = TotpParams::parse(Some(&json!({ "algorithm": "SHA256", "digits": 8, "period": 60 }))).unwrap();
        assert_eq!(p, TotpParams { algorithm: TotpAlgorithm::Sha256, digits: 8, period: 60 });
        for bad in [
            json!({ "digits": 7 }),
            json!({ "period": 45 }),
            json!({ "algorithm": "sha1" }),
            json!({ "skew": 1 }),
            json!("SHA1"),
        ] {
            assert!(TotpParams::parse(Some(&bad)).is_err(), "{bad}");
        }
    }
}
