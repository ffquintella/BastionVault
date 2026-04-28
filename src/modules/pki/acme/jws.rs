//! JWS request envelope parsing + verification — RFC 7515 / RFC 8555 §6.
//!
//! ACME requests come wrapped in a flattened-JSON JWS envelope:
//!
//! ```json
//! {
//!   "protected": "<base64url(header)>",
//!   "payload":   "<base64url(body)> | \"\"",
//!   "signature": "<base64url(sig)>"
//! }
//! ```
//!
//! Where `protected` decodes to a JSON object containing at minimum
//! `alg`, `nonce`, `url`, and **either** `jwk` (only on first request,
//! e.g. `new-account`) **or** `kid` (an account URL the server issued).
//!
//! This module supports `RS256`, `ES256`, and `EdDSA` — the three
//! algorithms RFC 8555 §6.2 says servers MUST handle. Other algorithms
//! are refused with a clear `JwsError::UnsupportedAlg`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::errors::RvError;

#[derive(Debug, thiserror::Error)]
pub enum JwsError {
    #[error("malformed envelope: {0}")]
    Malformed(&'static str),
    #[error("unsupported alg `{0}`; expected RS256, ES256, or EdDSA")]
    UnsupportedAlg(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("envelope must carry exactly one of `jwk` or `kid`, not both")]
    KeyAmbiguity,
}

impl From<JwsError> for RvError {
    fn from(e: JwsError) -> Self {
        RvError::ErrString(format!("acme jws: {e}"))
    }
}

/// Flattened JSON JWS envelope as it arrives over the wire.
#[derive(Debug, Clone, Deserialize)]
pub struct JwsEnvelope {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

/// Decoded protected header. RFC 8555 §6.2 says the four required
/// fields are `alg`, `nonce`, `url`, and exactly one of `jwk` / `kid`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectedHeader {
    pub alg: String,
    pub nonce: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Successful verification result. Carries the parsed protected
/// header (so the handler can check `nonce` / `url`), the decoded
/// payload bytes (which may be `b""` for POST-as-GET), and the
/// canonical key thumbprint of the account key — used to identify
/// the calling account on subsequent requests.
pub struct Verified {
    pub header: ProtectedHeader,
    pub payload: Vec<u8>,
    /// Account key as a JWK (caller may need to persist on
    /// new-account, or look up via `kid` for replay).
    pub jwk: Value,
    /// RFC 7638 canonical key thumbprint, base64url(SHA-256(JWK)).
    /// Used as the account identifier in storage.
    pub thumbprint: String,
}

/// Verify a JWS envelope. Caller must supply `account_jwk_lookup`
/// for envelopes that carry only `kid` (no `jwk`); the closure maps
/// the kid → JWK persisted at `new-account` time. Caller may also
/// pass `Some(jwk)` directly to short-circuit the lookup (used by
/// `key-change`'s inner JWS).
pub fn verify(
    envelope: &JwsEnvelope,
    account_jwk_lookup: impl FnOnce(&str) -> Option<Value>,
) -> Result<Verified, JwsError> {
    let header_bytes = B64
        .decode(envelope.protected.as_bytes())
        .map_err(|_| JwsError::Malformed("protected is not base64url"))?;
    let header: ProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| JwsError::Malformed("protected is not valid JSON"))?;

    let jwk = match (header.jwk.as_ref(), header.kid.as_ref()) {
        (Some(j), None) => j.clone(),
        (None, Some(kid)) => account_jwk_lookup(kid)
            .ok_or(JwsError::Malformed("kid does not resolve to a known account"))?,
        (None, None) => return Err(JwsError::Malformed("missing both jwk and kid")),
        (Some(_), Some(_)) => return Err(JwsError::KeyAmbiguity),
    };

    let signature = B64
        .decode(envelope.signature.as_bytes())
        .map_err(|_| JwsError::Malformed("signature is not base64url"))?;
    let payload = B64
        .decode(envelope.payload.as_bytes())
        .map_err(|_| JwsError::Malformed("payload is not base64url"))?;

    // Signing input is the ASCII string `protected || "." || payload`
    // — both still in their base64url-encoded form. RFC 7515 §5.1.
    let signing_input = format!("{}.{}", envelope.protected, envelope.payload);

    match header.alg.as_str() {
        "RS256" => verify_rs256(&jwk, signing_input.as_bytes(), &signature)?,
        "ES256" => verify_es256(&jwk, signing_input.as_bytes(), &signature)?,
        "EdDSA" => verify_eddsa(&jwk, signing_input.as_bytes(), &signature)?,
        other => return Err(JwsError::UnsupportedAlg(other.to_string())),
    }

    let thumbprint = jwk_thumbprint(&jwk)?;
    Ok(Verified {
        header,
        payload,
        jwk,
        thumbprint,
    })
}

// ── Algorithm-specific verifiers ─────────────────────────────────

fn verify_rs256(jwk: &Value, msg: &[u8], sig: &[u8]) -> Result<(), JwsError> {
    use rsa::{pkcs1v15::VerifyingKey, signature::Verifier, BigUint, RsaPublicKey};
    use sha2_saml::Sha256 as Sha256Saml;

    let n = jwk_b64_field(jwk, "n").ok_or(JwsError::Malformed("rsa jwk missing `n`"))?;
    let e = jwk_b64_field(jwk, "e").ok_or(JwsError::Malformed("rsa jwk missing `e`"))?;

    let pk = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
        .map_err(|_| JwsError::Malformed("rsa jwk components rejected"))?;
    let verifier: VerifyingKey<Sha256Saml> = VerifyingKey::new(pk);
    let parsed = ::rsa::pkcs1v15::Signature::try_from(sig)
        .map_err(|_| JwsError::Malformed("rs256 signature parse"))?;
    verifier.verify(msg, &parsed).map_err(|_| JwsError::BadSignature)
}

fn verify_es256(jwk: &Value, msg: &[u8], sig: &[u8]) -> Result<(), JwsError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::EncodedPoint;

    let x = jwk_b64_field(jwk, "x").ok_or(JwsError::Malformed("ec jwk missing `x`"))?;
    let y = jwk_b64_field(jwk, "y").ok_or(JwsError::Malformed("ec jwk missing `y`"))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(JwsError::Malformed("ec jwk x/y must be 32 bytes"));
    }
    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    let point = EncodedPoint::from_bytes(&uncompressed)
        .map_err(|_| JwsError::Malformed("ec jwk point invalid"))?;
    let vk = VerifyingKey::from_encoded_point(&point)
        .map_err(|_| JwsError::Malformed("ec jwk public key invalid"))?;

    // ES256 signatures are 64-byte raw r||s, exactly what `Signature::from_slice` wants.
    let parsed = Signature::from_slice(sig).map_err(|_| JwsError::Malformed("es256 signature parse"))?;
    vk.verify(msg, &parsed).map_err(|_| JwsError::BadSignature)
}

fn verify_eddsa(jwk: &Value, msg: &[u8], sig: &[u8]) -> Result<(), JwsError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let crv = jwk
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or(JwsError::Malformed("okp jwk missing `crv`"))?;
    if crv != "Ed25519" {
        return Err(JwsError::Malformed("EdDSA only supports Ed25519 curve"));
    }
    let x = jwk_b64_field(jwk, "x").ok_or(JwsError::Malformed("okp jwk missing `x`"))?;
    let pk_arr: [u8; 32] = x.as_slice().try_into().map_err(|_| JwsError::Malformed("ed25519 pubkey must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| JwsError::Malformed("ed25519 pubkey invalid"))?;
    let sig_arr: [u8; 64] = sig.try_into().map_err(|_| JwsError::Malformed("ed25519 signature must be 64 bytes"))?;
    let parsed = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &parsed).map_err(|_| JwsError::BadSignature)
}

// ── JWK helpers ──────────────────────────────────────────────────

fn jwk_b64_field(jwk: &Value, name: &str) -> Option<Vec<u8>> {
    let s = jwk.get(name)?.as_str()?;
    B64.decode(s.as_bytes()).ok()
}

/// RFC 7638 — canonical JWK SHA-256 thumbprint, base64url-encoded.
/// Only the algorithm-required fields are included, in lexicographic
/// order; everything else is stripped before hashing.
pub fn jwk_thumbprint(jwk: &Value) -> Result<String, JwsError> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or(JwsError::Malformed("jwk missing `kty`"))?;
    let canonical = match kty {
        "RSA" => {
            let e = field_str(jwk, "e")?;
            let n = field_str(jwk, "n")?;
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        "EC" => {
            let crv = field_str(jwk, "crv")?;
            let x = field_str(jwk, "x")?;
            let y = field_str(jwk, "y")?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        "OKP" => {
            let crv = field_str(jwk, "crv")?;
            let x = field_str(jwk, "x")?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        other => return Err(JwsError::UnsupportedAlg(format!("jwk kty `{other}`"))),
    };
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    Ok(B64.encode(h.finalize()))
}

fn field_str(jwk: &Value, name: &str) -> Result<String, JwsError> {
    Ok(jwk
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| JwsError::Malformed("jwk field missing"))?
        .to_string())
}

/// RFC 8555 §8.1 — keyAuthorization is `<token> || "." || base64url(SHA-256(JWK_thumbprint))`.
/// Wait, the RFC has it as `token || "." || base64url(SHA-256(jwk))` — i.e. the
/// thumbprint *is* the SHA-256 of the canonical JWK. So if we already have the
/// thumbprint string, the keyAuthorization is just `"<token>.<thumbprint>"`.
pub fn key_authorization(token: &str, thumbprint: &str) -> String {
    format!("{token}.{thumbprint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7638 §3.1 reference vector. The example RSA key in the
    /// spec produces a known thumbprint we pin against here.
    #[test]
    fn rfc7638_rsa_thumbprint_reference() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        });
        let tp = jwk_thumbprint(&jwk).unwrap();
        assert_eq!(tp, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn key_authorization_rfc8555_shape() {
        let ka = key_authorization("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA", "x");
        assert_eq!(
            ka,
            "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.x"
        );
    }

    #[test]
    fn unsupported_alg_rejected() {
        let env = JwsEnvelope {
            protected: B64.encode(serde_json::to_vec(&serde_json::json!({
                "alg": "HS256",
                "nonce": "x",
                "url": "x",
                "jwk": { "kty": "oct" }
            })).unwrap()),
            payload: String::new(),
            signature: String::new(),
        };
        let r = verify(&env, |_| None);
        assert!(matches!(r, Err(JwsError::UnsupportedAlg(_))));
    }

    #[test]
    fn missing_both_jwk_and_kid_rejected() {
        let env = JwsEnvelope {
            protected: B64.encode(serde_json::to_vec(&serde_json::json!({
                "alg": "RS256",
                "nonce": "x",
                "url": "x"
            })).unwrap()),
            payload: String::new(),
            signature: String::new(),
        };
        assert!(matches!(verify(&env, |_| None), Err(JwsError::Malformed(_))));
    }

    /// EdDSA round-trip: sign + verify our own JWS with a freshly
    /// generated Ed25519 key. Confirms the verifier path works
    /// against a real signature, not just a structural check.
    #[test]
    fn eddsa_round_trip() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let pk_b64 = B64.encode(vk.as_bytes());

        let protected_obj = serde_json::json!({
            "alg": "EdDSA",
            "nonce": "n",
            "url": "u",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": pk_b64,
            }
        });
        let protected_b64 = B64.encode(serde_json::to_vec(&protected_obj).unwrap());
        let payload_b64 = B64.encode(b"{\"hello\":\"world\"}");
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig = sk.sign(signing_input.as_bytes());
        let env = JwsEnvelope {
            protected: protected_b64,
            payload: payload_b64,
            signature: B64.encode(sig.to_bytes()),
        };
        let v = verify(&env, |_| None).unwrap();
        assert_eq!(v.payload, b"{\"hello\":\"world\"}");
        assert_eq!(v.header.alg, "EdDSA");
        assert!(!v.thumbprint.is_empty());
    }
}
