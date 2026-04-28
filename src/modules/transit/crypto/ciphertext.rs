//! `bvault:vN:[pqc:<algo>:]<base64>` framer + parser.
//!
//! The wire format encodes algorithm + key version directly so a
//! decrypt path can refuse a payload produced under a different
//! algorithm even if both happened to live at the same key name
//! across a destructive type change. Two shapes today:
//!
//! ```text
//! bvault:v3:<base64(nonce || ct || tag)>            # symmetric AEAD
//! bvault:v3:pqc:ml-kem-768:<base64(...)>            # PQC KEM datakey wrap
//! bvault:v3:pqc:ml-dsa-65:<base64(sig)>             # PQC signature
//! ```
//!
//! Vault's prefix is `vault:vN:`; we use `bvault:vN:` to namespace
//! cleanly and to make the source of a stored blob obvious to an
//! incident responder. The `pqc:<algo>:` tag is mandatory for any
//! PQC payload — the framer rejects an unrecognised algo at parse
//! time so an algorithm rename never silently accepts old material.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::errors::RvError;

const PREFIX: &str = "bvault:v";
const PQC_TAG: &str = "pqc";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framed {
    pub version: u32,
    /// `Some("ml-kem-768")` etc. for PQC payloads, `None` for the
    /// classical Vault-shape symmetric framing.
    pub pqc_algo: Option<String>,
    pub bytes: Vec<u8>,
}

pub fn build(version: u32, pqc_algo: Option<&str>, bytes: &[u8]) -> String {
    let b64 = B64.encode(bytes);
    match pqc_algo {
        Some(a) => format!("{PREFIX}{version}:{PQC_TAG}:{a}:{b64}"),
        None => format!("{PREFIX}{version}:{b64}"),
    }
}

pub fn parse(s: &str) -> Result<Framed, RvError> {
    let rest = s
        .strip_prefix(PREFIX)
        .ok_or_else(|| RvError::ErrString(format!("not a bvault ciphertext: missing `{PREFIX}` prefix")))?;

    let (version_str, rest) = rest
        .split_once(':')
        .ok_or_else(|| RvError::ErrString("malformed ciphertext: missing version separator".into()))?;
    let version: u32 = version_str
        .parse()
        .map_err(|e| RvError::ErrString(format!("malformed ciphertext: bad version `{version_str}` ({e})")))?;
    if version == 0 {
        return Err(RvError::ErrString("ciphertext version must be >= 1".into()));
    }

    // Look for the PQC tag. We split only the FIRST two `:` so the
    // base64 body (which may contain `:`-free characters but a
    // poorly-formed wrapper might not) can't be re-interpreted as a
    // tag fragment.
    let (pqc_algo, body_b64) = if let Some(after_tag) = rest.strip_prefix(&format!("{PQC_TAG}:")) {
        let (algo, body) = after_tag
            .split_once(':')
            .ok_or_else(|| RvError::ErrString("malformed pqc ciphertext: missing algo separator".into()))?;
        if !is_known_pqc_algo(algo) {
            return Err(RvError::ErrString(format!(
                "unknown pqc algo tag `{algo}` in ciphertext"
            )));
        }
        (Some(algo.to_string()), body)
    } else {
        (None, rest)
    };

    let bytes = B64
        .decode(body_b64)
        .map_err(|e| RvError::ErrString(format!("malformed ciphertext: base64 decode failed ({e})")))?;
    Ok(Framed {
        version,
        pqc_algo,
        bytes,
    })
}

fn is_known_pqc_algo(s: &str) -> bool {
    matches!(
        s,
        "ml-kem-768"
            | "ml-dsa-44"
            | "ml-dsa-65"
            | "ml-dsa-87"
            // Hybrid wire tags. Recognised by the framer regardless of
            // build-feature so a payload produced by a `transit_pqc_hybrid`
            // build doesn't surface a confusing "unknown algo" parse
            // error on a build that simply can't handle it — the
            // matching path handler will refuse it later with a clear
            // "feature not enabled" message.
            | "hybrid-ed25519+ml-dsa-65"
            | "hybrid-x25519+ml-kem-768"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_classical() {
        let bytes = b"hello world".to_vec();
        let s = build(7, None, &bytes);
        let f = parse(&s).unwrap();
        assert_eq!(f.version, 7);
        assert!(f.pqc_algo.is_none());
        assert_eq!(f.bytes, bytes);
    }

    #[test]
    fn round_trip_pqc() {
        let bytes = vec![1, 2, 3, 4];
        let s = build(2, Some("ml-kem-768"), &bytes);
        assert!(s.contains(":pqc:ml-kem-768:"));
        let f = parse(&s).unwrap();
        assert_eq!(f.version, 2);
        assert_eq!(f.pqc_algo.as_deref(), Some("ml-kem-768"));
        assert_eq!(f.bytes, bytes);
    }

    #[test]
    fn missing_prefix_rejected() {
        assert!(parse("vault:v1:AAA=").is_err());
    }

    #[test]
    fn bad_version_rejected() {
        assert!(parse("bvault:v0:AAA=").is_err());
        assert!(parse("bvault:vabc:AAA=").is_err());
    }

    #[test]
    fn unknown_pqc_algo_rejected() {
        assert!(parse("bvault:v1:pqc:rot13:AAA=").is_err());
    }
}
