//! `/v1/transit/datakey/plaintext/:name` and `/wrapped/:name`.
//!
//! ML-KEM-768 KEM-based datakey generation. The semantic:
//!
//!   * Engine encapsulates against the parent's public key.
//!   * The shared secret feeds HKDF-SHA-256 → 32-byte AES-shaped key.
//!   * `wrapped` returns base64 of the KEM ciphertext (recipient
//!     decapsulates with the matching secret key to recover the
//!     same 32-byte key).
//!   * `plaintext` additionally returns the derived datakey itself.
//!
//! Symmetric and signing keys are refused — datakey only makes
//! sense for KEM key types.

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    crypto::{ciphertext, ml_kem},
    keytype::KeyType,
    TransitBackend, TransitBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const HELP: &str = "Generate a fresh datakey wrapped under the named asymmetric key. The `plaintext` variant additionally returns the unwrapped key.";

impl TransitBackend {
    pub fn datakey_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"datakey/(?P<plaintext_or_wrapped>plaintext|wrapped)/(?P<name>\w[\w-]*\w)",
            fields: {
                "plaintext_or_wrapped": { field_type: FieldType::Str, required: true, description: "`plaintext` or `wrapped`." },
                "name": { field_type: FieldType::Str, required: true, description: "Key name." }
            },
            operations: [{op: Operation::Write, handler: h.handle_datakey}],
            help: HELP
        })
    }
}

#[maybe_async::maybe_async]
impl TransitBackendInner {
    pub async fn handle_datakey(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mode = take_str(req, "plaintext_or_wrapped");
        let name = take_str(req, "name");

        let p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        if !p.key_type.supports_datakey() {
            return Err(RvError::ErrString(format!(
                "{} keys do not support /datakey; this engine ships KEM-based datakey only (ml-kem-768)",
                p.key_type.as_str()
            )));
        }
        let v = p.latest().ok_or_else(|| RvError::ErrString("key has no versions".into()))?;

        let (plaintext_dk, kem_ct) = match p.key_type {
            KeyType::MlKem768 => ml_kem::encapsulate_datakey(&v.pk)?,
            #[cfg(feature = "transit_pqc_hybrid")]
            KeyType::HybridX25519MlKem768 => {
                super::crypto::hybrid::encapsulate_hybrid_datakey(&v.pk)?
            }
            _ => unreachable!("supports_datakey() guarded above"),
        };
        let wrapped = ciphertext::build(v.version, p.key_type.pqc_wire_tag(), &kem_ct);

        let mut data = Map::new();
        data.insert("ciphertext".into(), Value::String(wrapped));
        data.insert("key_version".into(), Value::Number(v.version.into()));
        if mode == "plaintext" {
            data.insert("plaintext".into(), Value::String(B64.encode(&plaintext_dk)));
        } else if mode != "wrapped" {
            return Err(RvError::ErrString(format!(
                "datakey mode must be `plaintext` or `wrapped`, got `{mode}`"
            )));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Unwrap a previously-issued datakey. Not in the original Vault
    /// surface — Vault expects the application to use the datakey
    /// directly. We expose this as `/v1/transit/decrypt/:name` only
    /// for symmetric keys; for KEM unwraps the application reaches
    /// out to the engine via this helper because there is no other
    /// way to recover the derived 32-byte key from the wrapped form.
    pub async fn handle_datakey_unwrap(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let ct_str = take_str(req, "ciphertext");
        let framed = ciphertext::parse(&ct_str)?;
        let p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        if !p.key_type.supports_datakey() {
            return Err(RvError::ErrString(format!(
                "{} keys do not support datakey unwrap",
                p.key_type.as_str()
            )));
        }
        if framed.pqc_algo.as_deref() != p.key_type.pqc_wire_tag() {
            return Err(RvError::ErrString(format!(
                "datakey algorithm mismatch: ciphertext tagged {:?}, key is {}",
                framed.pqc_algo,
                p.key_type.as_str()
            )));
        }
        let v = p
            .version_for_decrypt(framed.version)
            .map_err(RvError::ErrString)?;
        let dk = match p.key_type {
            KeyType::MlKem768 => ml_kem::decapsulate_datakey(&v.material, &framed.bytes)?,
            #[cfg(feature = "transit_pqc_hybrid")]
            KeyType::HybridX25519MlKem768 => {
                super::crypto::hybrid::decapsulate_hybrid_datakey(&v.material, &framed.bytes)?
            }
            _ => unreachable!("supports_datakey() guarded above"),
        };
        let mut data = Map::new();
        data.insert("plaintext".into(), Value::String(B64.encode(&dk)));
        Ok(Some(Response::data_response(Some(data))))
    }
}

impl TransitBackend {
    pub fn datakey_unwrap_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"datakey/unwrap/(?P<name>\w[\w-]*\w)",
            fields: {
                "name":       { field_type: FieldType::Str, required: true, description: "Key name." },
                "ciphertext": { field_type: FieldType::Str, default: "", description: "Previously-issued wrapped datakey." }
            },
            operations: [{op: Operation::Write, handler: h.handle_datakey_unwrap}],
            help: "Recover the 32-byte derived datakey from a wrapped form. KEM keys only."
        })
    }
}

fn take_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}
