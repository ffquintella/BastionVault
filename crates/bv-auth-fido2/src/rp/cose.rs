//! COSE_Key parsing.
//!
//! The credentialPublicKey inside authenticatorData is a CBOR-encoded
//! COSE_Key (RFC 8152 §7). We only need to parse two algorithms:
//!
//! * **ES256** (alg = -7): EC2 key (kty = 2) over P-256 (crv = 1) with
//!   coordinates `x` (-2) and `y` (-3) as 32-byte big-endian unsigned ints.
//! * **EdDSA** (alg = -8): OKP key (kty = 1) over Ed25519 (crv = 6) with
//!   public key `x` (-2) as 32 bytes.
//!
//! Anything else is rejected. We deliberately do not handle RSA — passkey
//! authenticators don't ship RSA in practice and pulling `rsa` here just
//! to be thorough is not worth it.

use ciborium::value::Value as CborValue;

use super::errors::RpError;

#[derive(Debug)]
pub enum PublicKey {
    Es256 {
        verifying_key: p256::ecdsa::VerifyingKey,
    },
    Ed25519 {
        verifying_key: ed25519_dalek::VerifyingKey,
    },
}

/// Parse a COSE_Key CBOR blob into a verifier-ready public key.
pub fn parse_public_key(cbor: &[u8]) -> Result<PublicKey, RpError> {
    let val: CborValue = ciborium::de::from_reader(cbor)
        .map_err(|e| RpError::Cbor(format!("COSE_Key: {e}")))?;
    let map = match val {
        CborValue::Map(m) => m,
        _ => return Err(RpError::BadCoseKey("not a CBOR map".into())),
    };

    // COSE label keys are integers; collect everything we care about.
    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    for (k, v) in map {
        let label = match k {
            CborValue::Integer(i) => i128::from(i),
            _ => continue,
        };
        match (label, v) {
            (1, CborValue::Integer(i)) => kty = Some(i128::from(i) as i64),
            (3, CborValue::Integer(i)) => alg = Some(i128::from(i) as i64),
            (-1, CborValue::Integer(i)) => crv = Some(i128::from(i) as i64),
            (-2, CborValue::Bytes(b)) => x = Some(b),
            (-3, CborValue::Bytes(b)) => y = Some(b),
            _ => {}
        }
    }

    let alg = alg.ok_or_else(|| RpError::BadCoseKey("missing alg".into()))?;
    match alg {
        -7 => {
            // ES256 / ECDSA over P-256.
            if kty != Some(2) {
                return Err(RpError::BadCoseKey(format!(
                    "ES256 expects kty=2 (EC2), got {kty:?}"
                )));
            }
            if crv != Some(1) {
                return Err(RpError::BadCoseKey(format!(
                    "ES256 expects crv=1 (P-256), got {crv:?}"
                )));
            }
            let x = x.ok_or_else(|| RpError::BadCoseKey("missing x".into()))?;
            let y = y.ok_or_else(|| RpError::BadCoseKey("missing y".into()))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(RpError::BadCoseKey(format!(
                    "P-256 coordinates must be 32 bytes (got x={}, y={})",
                    x.len(),
                    y.len()
                )));
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04); // uncompressed marker
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|e| RpError::BadCoseKey(format!("invalid P-256 point: {e}")))?;
            Ok(PublicKey::Es256 { verifying_key })
        }
        -8 => {
            // EdDSA / Ed25519 (OKP).
            if kty != Some(1) {
                return Err(RpError::BadCoseKey(format!(
                    "EdDSA expects kty=1 (OKP), got {kty:?}"
                )));
            }
            if crv != Some(6) {
                return Err(RpError::BadCoseKey(format!(
                    "EdDSA expects crv=6 (Ed25519), got {crv:?}"
                )));
            }
            let x = x.ok_or_else(|| RpError::BadCoseKey("missing x".into()))?;
            let bytes: [u8; 32] = x
                .as_slice()
                .try_into()
                .map_err(|_| RpError::BadCoseKey("Ed25519 key must be 32 bytes".into()))?;
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|e| RpError::BadCoseKey(format!("invalid Ed25519 key: {e}")))?;
            Ok(PublicKey::Ed25519 { verifying_key })
        }
        other => Err(RpError::UnsupportedAlg(other)),
    }
}
