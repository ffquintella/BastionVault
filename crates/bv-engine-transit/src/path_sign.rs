//! `/v1/transit/sign/:name` and `/v1/transit/verify/:name`.
//!
//! Phase 2 / Phase 3: Ed25519 (classical) and ML-DSA-44/65/87 (PQC).
//! The wire format embeds the algorithm so a verifier (or the engine
//! itself) can reject a signature presented against the wrong key
//! type even if the key name happens to match.

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    crypto::{ciphertext, ed25519, ml_dsa},
    keytype::KeyType,
    TransitBackend, TransitBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const SIGN_HELP: &str = "Sign a base64 message under the latest version of the named asymmetric signing key. Returns a `bvault:vN[:pqc:<algo>]:<base64>` signature.";
const VERIFY_HELP: &str = "Verify a `bvault:vN[:pqc:<algo>]:<base64>` signature against a message.";

impl TransitBackend {
    pub fn sign_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"sign/(?P<name>\w[\w-]*\w)",
            fields: {
                "name":  { field_type: FieldType::Str, required: true, description: "Key name." },
                "input": { field_type: FieldType::Str, default: "", description: "Base64-encoded message." }
            },
            operations: [{op: Operation::Write, handler: h.handle_sign}],
            help: SIGN_HELP
        })
    }

    pub fn verify_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"verify/(?P<name>\w[\w-]*\w)",
            fields: {
                "name":      { field_type: FieldType::Str, required: true, description: "Key name." },
                "input":     { field_type: FieldType::Str, default: "", description: "Base64-encoded message." },
                "signature": { field_type: FieldType::Str, default: "", description: "`bvault:vN[:pqc:<algo>]:<base64>` signature." }
            },
            operations: [{op: Operation::Write, handler: h.handle_verify}],
            help: VERIFY_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl TransitBackendInner {
    pub async fn handle_sign(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let input_b64 = take_str(req, "input");
        let input = B64
            .decode(input_b64.as_bytes())
            .map_err(|e| RvError::ErrString(format!("input: not base64 ({e})")))?;

        let p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        if !p.key_type.supports_sign() {
            return Err(RvError::ErrString(format!(
                "{} keys do not support /sign",
                p.key_type.as_str()
            )));
        }
        let v = p.latest().ok_or_else(|| RvError::ErrString("key has no versions".into()))?;

        let sig = match p.key_type {
            KeyType::Ed25519 => ed25519::sign(&v.material, &input)?,
            KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => {
                ml_dsa::sign(p.key_type, &v.material, &input)?
            }
            #[cfg(feature = "transit_pqc_hybrid")]
            KeyType::HybridEd25519MlDsa65 => {
                super::crypto::hybrid::sign_composite(&v.material, &input)?
            }
            _ => unreachable!("supports_sign() guarded above"),
        };
        let wire = ciphertext::build(v.version, p.key_type.pqc_wire_tag(), &sig);
        let mut data = Map::new();
        data.insert("signature".into(), Value::String(wire));
        data.insert("key_version".into(), Value::Number(v.version.into()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_verify(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let input_b64 = take_str(req, "input");
        let sig_str = take_str(req, "signature");
        let input = B64
            .decode(input_b64.as_bytes())
            .map_err(|e| RvError::ErrString(format!("input: not base64 ({e})")))?;

        let framed = ciphertext::parse(&sig_str)?;
        let p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;

        // Algorithm-tag agreement: a signature framed as PQC must
        // match the key's PQC tag exactly. A classical signature
        // against a PQC key (or vice versa) is refused before any
        // crypto runs.
        let key_tag = p.key_type.pqc_wire_tag();
        if framed.pqc_algo.as_deref() != key_tag {
            return Err(RvError::ErrString(format!(
                "signature algorithm mismatch: ciphertext tagged {:?}, key is {}",
                framed.pqc_algo,
                p.key_type.as_str()
            )));
        }

        let v = p
            .version_for_decrypt(framed.version)
            .map_err(RvError::ErrString)?;
        let valid = match p.key_type {
            KeyType::Ed25519 => ed25519::verify(&v.pk, &input, &framed.bytes)?,
            KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => {
                ml_dsa::verify(p.key_type, &v.material, &input, &framed.bytes)?
            }
            #[cfg(feature = "transit_pqc_hybrid")]
            KeyType::HybridEd25519MlDsa65 => {
                super::crypto::hybrid::verify_composite(&v.pk, &input, &framed.bytes)?
            }
            _ => {
                return Err(RvError::ErrString(format!(
                    "{} keys do not support /verify",
                    p.key_type.as_str()
                )))
            }
        };
        let mut data = Map::new();
        data.insert("valid".into(), Value::Bool(valid));
        Ok(Some(Response::data_response(Some(data))))
    }
}

fn take_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}
