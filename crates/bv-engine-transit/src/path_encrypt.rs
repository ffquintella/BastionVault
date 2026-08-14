//! `/v1/transit/encrypt/:name`, `/decrypt/:name`, `/rewrap/:name`.
//!
//! Symmetric AEAD only on these paths (Vault parity); ML-KEM
//! encrypt-of-arbitrary-data flows through `/datakey` instead.

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    crypto::{ciphertext, derive, sym},
    TransitBackend, TransitBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const ENCRYPT_HELP: &str = "Encrypt base64 plaintext under the latest version of the named symmetric AEAD key. Returns `bvault:vN:<base64>`.";
const DECRYPT_HELP: &str = "Decrypt a `bvault:vN:<base64>` ciphertext. Tries the embedded version against this key.";
const REWRAP_HELP: &str = "Decrypt and re-encrypt a ciphertext under the latest key version. The plaintext never leaves the engine.";

impl TransitBackend {
    pub fn encrypt_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"encrypt/(?P<name>\w[\w-]*\w)",
            fields: {
                "name":      { field_type: FieldType::Str, required: true, description: "Key name." },
                "plaintext": { field_type: FieldType::Str, default: "", description: "Base64-encoded plaintext." },
                "context":   { field_type: FieldType::Str, default: "", description: "Optional base64-encoded AAD bound to the ciphertext." }
            },
            operations: [{op: Operation::Write, handler: h.handle_encrypt}],
            help: ENCRYPT_HELP
        })
    }

    pub fn decrypt_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"decrypt/(?P<name>\w[\w-]*\w)",
            fields: {
                "name":       { field_type: FieldType::Str, required: true, description: "Key name." },
                "ciphertext": { field_type: FieldType::Str, default: "", description: "`bvault:vN:<base64>` ciphertext." },
                "context":    { field_type: FieldType::Str, default: "", description: "Optional base64-encoded AAD; must match encrypt." }
            },
            operations: [{op: Operation::Write, handler: h.handle_decrypt}],
            help: DECRYPT_HELP
        })
    }

    pub fn rewrap_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"rewrap/(?P<name>\w[\w-]*\w)",
            fields: {
                "name":       { field_type: FieldType::Str, required: true, description: "Key name." },
                "ciphertext": { field_type: FieldType::Str, default: "", description: "`bvault:vN:<base64>` ciphertext to re-encrypt under the latest version." },
                "context":    { field_type: FieldType::Str, default: "", description: "Optional base64-encoded AAD; must match encrypt." }
            },
            operations: [{op: Operation::Write, handler: h.handle_rewrap}],
            help: REWRAP_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl TransitBackendInner {
    pub async fn handle_encrypt(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let plaintext_b64 = take_str(req, "plaintext");
        let aad_b64 = take_str(req, "context");

        let plaintext = B64
            .decode(plaintext_b64.as_bytes())
            .map_err(|e| RvError::ErrString(format!("plaintext: not base64 ({e})")))?;
        let aad = if aad_b64.is_empty() {
            Vec::new()
        } else {
            B64.decode(aad_b64.as_bytes())
                .map_err(|e| RvError::ErrString(format!("context: not base64 ({e})")))?
        };

        let p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        if !p.key_type.supports_encrypt() {
            return Err(RvError::ErrString(format!(
                "{} keys do not support /encrypt; use /sign or /datakey as appropriate",
                p.key_type.as_str()
            )));
        }
        if !p.key_type.is_symmetric_aead() {
            return Err(RvError::ErrString(format!(
                "/encrypt is symmetric-AEAD only; {} keys must use /datakey",
                p.key_type.as_str()
            )));
        }

        let v = p.latest().ok_or_else(|| RvError::ErrString("key has no versions".into()))?;
        let blob = encrypt_with_modes(&p, &v.material, &plaintext, &aad)?;
        let wire = ciphertext::build(v.version, None, &blob);

        let mut data = Map::new();
        data.insert("ciphertext".into(), Value::String(wire));
        data.insert("key_version".into(), Value::Number(v.version.into()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_decrypt(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let ct_str = take_str(req, "ciphertext");
        let aad_b64 = take_str(req, "context");

        let framed = ciphertext::parse(&ct_str)?;
        if framed.pqc_algo.is_some() {
            return Err(RvError::ErrString(
                "/decrypt is symmetric only; pqc-tagged ciphertexts go through /datakey unwrap".into(),
            ));
        }
        let aad = if aad_b64.is_empty() {
            Vec::new()
        } else {
            B64.decode(aad_b64.as_bytes())
                .map_err(|e| RvError::ErrString(format!("context: not base64 ({e})")))?
        };

        let p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        let v = p
            .version_for_decrypt(framed.version)
            .map_err(RvError::ErrString)?;
        let pt = decrypt_with_modes(&p, &v.material, &framed.bytes, &aad)?;

        let mut data = Map::new();
        data.insert("plaintext".into(), Value::String(B64.encode(&pt)));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_rewrap(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let ct_str = take_str(req, "ciphertext");
        let aad_b64 = take_str(req, "context");

        let framed = ciphertext::parse(&ct_str)?;
        if framed.pqc_algo.is_some() {
            return Err(RvError::ErrString(
                "/rewrap is symmetric only; pqc-tagged ciphertexts go through /datakey unwrap".into(),
            ));
        }
        let aad = if aad_b64.is_empty() {
            Vec::new()
        } else {
            B64.decode(aad_b64.as_bytes())
                .map_err(|e| RvError::ErrString(format!("context: not base64 ({e})")))?
        };

        let p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        let v_old = p
            .version_for_decrypt(framed.version)
            .map_err(RvError::ErrString)?;
        let pt = decrypt_with_modes(&p, &v_old.material, &framed.bytes, &aad)?;
        let v_new = p
            .latest()
            .ok_or_else(|| RvError::ErrString("key has no versions".into()))?;
        let blob = encrypt_with_modes(&p, &v_new.material, &pt, &aad)?;
        let wire = ciphertext::build(v_new.version, None, &blob);

        let mut data = Map::new();
        data.insert("ciphertext".into(), Value::String(wire));
        data.insert("key_version".into(), Value::Number(v_new.version.into()));
        Ok(Some(Response::data_response(Some(data))))
    }
}

/// Apply derived / convergent modes (if configured) and run the
/// underlying AEAD encrypt. `aad` is the caller-supplied `context`
/// (already base64-decoded). The same value is fed to subkey
/// derivation AND used as AEAD AAD so a tampered context fails the
/// AEAD tag check at decrypt time, not just the subkey lookup.
fn encrypt_with_modes(
    p: &super::policy::KeyPolicy,
    parent_key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, RvError> {
    if !p.derived {
        return sym::aead_encrypt(p.key_type, parent_key, plaintext, aad);
    }
    let subkey = derive::subkey(parent_key, aad)?;
    if p.convergent_encryption {
        // Bind the deterministic nonce to the plaintext under the
        // *parent* key, not the subkey — same plaintext + same
        // context across two derived keys with the same parent
        // would otherwise produce the same nonce, which is fine
        // (both branches of the parent-derived structure observe
        // the same convergence) but binding to the parent makes
        // the property auditable from a single value.
        let nonce = derive::convergent_nonce(parent_key, aad, plaintext)?;
        return sym::aead_encrypt_with_nonce(p.key_type, &subkey, &nonce, plaintext, aad);
    }
    sym::aead_encrypt(p.key_type, &subkey, plaintext, aad)
}

fn decrypt_with_modes(
    p: &super::policy::KeyPolicy,
    parent_key: &[u8],
    blob: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, RvError> {
    if !p.derived {
        return sym::aead_decrypt(p.key_type, parent_key, blob, aad);
    }
    let subkey = derive::subkey(parent_key, aad)?;
    sym::aead_decrypt(p.key_type, &subkey, blob, aad)
}

fn take_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}
