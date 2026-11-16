//! JWS compact serialisation (RFC 7515) with RS256 only. Signing is the
//! key ring's; this module only encodes. `verify_rs256` is a reference
//! check against a published JWKS, for relying parties written against
//! this crate and for the tests: it checks the signature and nothing else.

use aws_lc_rs::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use serde_json::{Map, Value};

use crate::{errors::RvError, provider::federation::keys::SigningKey};

/// `header.payload.signature`, signed by `key`.
pub fn encode_rs256(key: &SigningKey, typ: &str, claims: &Map<String, Value>) -> Result<String, RvError> {
    let mut header = Map::new();
    header.insert("alg".into(), key.alg.clone().into());
    header.insert("kid".into(), key.kid.clone().into());
    header.insert("typ".into(), typ.into());
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&Value::Object(header))?),
        B64URL.encode(serde_json::to_vec(&Value::Object(claims.clone()))?)
    );
    let signature = key.sign(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", B64URL.encode(signature)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtError {
    Malformed,
    UnsupportedAlgorithm,
    UnknownKey,
    BadSignature,
}

fn segment(s: &str) -> Result<Map<String, Value>, JwtError> {
    let bytes = B64URL.decode(s).map_err(|_| JwtError::Malformed)?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(JwtError::Malformed),
    }
}

/// Header and claims of `token` if an RS256 key of `jwks` with its `kid`
/// signed it. Claims (`iss`, `aud`, `exp`, `nonce`) are the caller's to check.
pub fn verify_rs256(token: &str, jwks: &Value) -> Result<(Map<String, Value>, Map<String, Value>), JwtError> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(JwtError::Malformed);
    };
    let header = segment(h)?;
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err(JwtError::UnsupportedAlgorithm);
    }
    let kid = header.get("kid").and_then(Value::as_str).ok_or(JwtError::UnknownKey)?;
    let jwk = jwks
        .get("keys")
        .and_then(Value::as_array)
        .and_then(|keys| keys.iter().find(|k| k.get("kid").and_then(Value::as_str) == Some(kid)))
        .ok_or(JwtError::UnknownKey)?;
    let component = |name: &str| {
        jwk.get(name).and_then(Value::as_str).and_then(|v| B64URL.decode(v).ok()).ok_or(JwtError::UnknownKey)
    };
    let public = RsaPublicKeyComponents { n: component("n")?, e: component("e")? };
    let signature = B64URL.decode(s).map_err(|_| JwtError::Malformed)?;
    public
        .verify(&RSA_PKCS1_2048_8192_SHA256, format!("{h}.{p}").as_bytes(), &signature)
        .map_err(|_| JwtError::BadSignature)?;
    Ok((header, segment(p)?))
}
