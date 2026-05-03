//! Routes for the managed key store — Phase L1.
//!
//! - `LIST   /v1/pki/keys`                        → `{"keys": [<id>, ...]}`
//! - `WRITE  /v1/pki/keys/generate/internal`      → generate, do not return private
//! - `WRITE  /v1/pki/keys/generate/exported`      → generate, return PKCS#8 private once
//! - `WRITE  /v1/pki/keys/import`                 → import a PEM private key
//! - `READ   /v1/pki/key/<key_ref>`               → metadata + public key
//! - `DELETE /v1/pki/key/<key_ref>`               → remove (refuses if referenced)
//!
//! `<key_ref>` is either the UUID returned at create time or the
//! optional name supplied via the `name` field.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{
    crypto::KeyAlgorithm,
    keys::{self, KeyEntry, KeySource},
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn keys_list_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"keys/?$",
            operations: [{op: Operation::List, handler: r.list_keys}],
            help: "List managed key IDs."
        })
    }

    pub fn keys_generate_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"keys/generate/(?P<exported>internal|exported)$",
            fields: {
                "exported": { field_type: FieldType::Str, required: true, description: "internal | exported." },
                "key_type": { field_type: FieldType::Str, default: "ec", description: "rsa | ec | ed25519 | ml-dsa-44 | ml-dsa-65 | ml-dsa-87." },
                "key_bits": { field_type: FieldType::Int, default: 0, description: "Key size in bits (0 = default)." },
                "name": { field_type: FieldType::Str, default: "", description: "Optional human-friendly alias for this key." }
            },
            operations: [{op: Operation::Write, handler: r.generate_key}],
            help: "Generate and persist a managed private key."
        })
    }

    pub fn keys_import_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"keys/import$",
            fields: {
                "private_key": { field_type: FieldType::Str, required: true, description: "PEM-encoded private key (PKCS#8 or BV PQC envelope)." },
                "name": { field_type: FieldType::Str, default: "", description: "Optional human-friendly alias for this key." }
            },
            operations: [{op: Operation::Write, handler: r.import_key}],
            help: "Import an externally-generated private key into the managed key store."
        })
    }

    pub fn key_path(&self) -> Path {
        let rr = self.inner.clone();
        let rd = self.inner.clone();
        new_path!({
            pattern: r"key/(?P<key_ref>[\w\-]+)$",
            fields: {
                "key_ref": { field_type: FieldType::Str, required: true, description: "Managed key ID (UUID) or name." },
                "force": { field_type: FieldType::Bool, default: false, description: "Drop the key even if it has outstanding issuer / cert references. The issuer's own private-key copy is preserved." }
            },
            operations: [
                {op: Operation::Read, handler: rr.read_key},
                {op: Operation::Delete, handler: rd.delete_key}
            ],
            help: "Read or delete a managed key."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn list_keys(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let ids = keys::list_keys(req).await?;
        Ok(Some(Response::list_response(&ids)))
    }

    pub async fn generate_key(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let exported = req
            .get_data("exported")?
            .as_str()
            .unwrap_or("")
            .to_string();
        let exported_flag = match exported.as_str() {
            "exported" => true,
            "internal" => false,
            _ => return Err(RvError::ErrRequestFieldInvalid),
        };

        let key_type = req
            .get_data_or_default("key_type")?
            .as_str()
            .unwrap_or("ec")
            .to_string();
        let key_bits = req
            .get_data_or_default("key_bits")?
            .as_u64()
            .unwrap_or(0) as u32;
        let alg = KeyAlgorithm::from_role(&key_type, key_bits)?;
        let name = req
            .get_data_or_default("name")?
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();

        let (entry, signer) =
            keys::generate_managed_key(req, alg, &name, exported_flag).await?;

        let mut data = entry_to_data(&entry);
        if exported_flag {
            // `exported` mode returns the caller-facing PKCS#8 PEM once.
            // The same material is also kept under the barrier so future
            // phases (key reuse, issuer-bound generation) can reload it.
            let pkcs8 = signer.to_pkcs8_pem()?;
            data.insert("private_key".into(), json!(pkcs8));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn import_key(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pem = req
            .get_data("private_key")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .trim()
            .to_string();
        if pem.is_empty() {
            return Err(RvError::ErrRequestFieldInvalid);
        }
        let name = req
            .get_data_or_default("name")?
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();

        let (entry, _signer) = keys::import_managed_key(req, &pem, &name).await?;
        Ok(Some(Response::data_response(Some(entry_to_data(&entry)))))
    }

    pub async fn read_key(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let key_ref = req
            .get_data("key_ref")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let entry = match keys::load_key(req, &key_ref).await? {
            Some(e) => e,
            None => return Ok(None),
        };
        let refs = keys::load_refs(req, &entry.id).await?;

        let mut data = entry_to_data(&entry);
        // Reference summary so the operator can see at a glance whether
        // a key is in use before attempting to delete it. The actual
        // sets stay internal; the response just carries counts.
        data.insert("issuer_ref_count".into(), json!(refs.issuer_ids.len()));
        data.insert("cert_ref_count".into(), json!(refs.cert_serials.len()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn delete_key(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let key_ref = req
            .get_data("key_ref")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        // `force` is optional and Delete callers may omit a body entirely;
        // treat "no body / no field" as `force = false` instead of bubbling
        // ErrRequestNoData up to the operator.
        let force = req
            .get_data_or_default("force")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if force {
            keys::force_delete_key(req, &key_ref).await?;
        } else {
            keys::delete_key(req, &key_ref).await?;
        }
        Ok(None)
    }
}

fn entry_to_data(entry: &KeyEntry) -> Map<String, Value> {
    let mut data: Map<String, Value> = Map::new();
    data.insert("key_id".into(), json!(entry.id));
    if !entry.name.is_empty() {
        data.insert("name".into(), json!(entry.name));
    }
    data.insert("key_type".into(), json!(entry.key_type));
    if entry.key_bits > 0 {
        data.insert("key_bits".into(), json!(entry.key_bits));
    }
    data.insert("public_key".into(), json!(entry.public_key_pem));
    data.insert("source".into(), json!(entry.source.as_str()));
    data.insert("exported".into(), json!(entry.exported));
    data.insert("created_at".into(), json!(entry.created_at_unix));
    let _ = KeySource::Generated; // keep import alive when source enum gains variants
    data
}
