//! `pki/root/generate/{exported|internal}` — generate a self-signed root CA.
//!
//! Phase 1 supports root generation only. `sign-intermediate`, `intermediate/*`,
//! and `set-signed` are exposed as stub endpoints that return
//! `ErrLogicalOperationUnsupported` — the route surface stays Vault-shaped so
//! clients see a clear "not implemented" rather than a 404 mismatch.

use std::{collections::HashMap, sync::Arc, time::Duration};

use humantime::parse_duration;
use serde_json::{json, Map, Value};

use super::{
    crypto::{KeyAlgorithm, Signer},
    storage::{self, CaMetadata, CrlConfig, CrlState, KEY_CA_CERT, KEY_CA_KEY, KEY_CA_META, KEY_CONFIG_CRL, KEY_CRL_STATE},
    x509, x509_pqc,
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const DEFAULT_ROOT_TTL: Duration = Duration::from_secs(10 * 365 * 24 * 3600); // ~10y

impl PkiBackend {
    pub fn root_generate_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"root/generate/(?P<exported>internal|exported)",
            fields: {
                "exported": { field_type: FieldType::Str, required: true, description: "internal | exported." },
                "common_name": { field_type: FieldType::Str, required: true, description: "Subject Common Name." },
                "organization": { field_type: FieldType::Str, default: "", description: "Subject Organization." },
                "key_type": { field_type: FieldType::Str, default: "ec", description: "rsa | ec | ed25519 | ml-dsa-44 | ml-dsa-65 | ml-dsa-87." },
                "key_bits": { field_type: FieldType::Int, default: 0, description: "Key size (0 = default)." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Validity duration (e.g. 8760h)." }
            },
            operations: [{op: Operation::Write, handler: r.generate_root}],
            help: "Generate a self-signed root CA."
        })
    }

    /// Stubs for the not-yet-implemented signing paths.
    pub fn root_sign_intermediate_stub(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"root/sign-intermediate$",
            operations: [{op: Operation::Write, handler: r.unsupported}],
            help: "(Phase 2) Sign an intermediate CA CSR."
        })
    }

    pub fn intermediate_generate_stub(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"intermediate/generate/(?P<exported>internal|exported)",
            operations: [{op: Operation::Write, handler: r.unsupported}],
            help: "(Phase 2) Generate an intermediate CA CSR."
        })
    }

    pub fn intermediate_set_signed_stub(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"intermediate/set-signed$",
            operations: [{op: Operation::Write, handler: r.unsupported}],
            help: "(Phase 2) Install a signed intermediate."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn generate_root(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if storage::get_string(req, KEY_CA_CERT).await?.is_some() {
            return Err(RvError::ErrPkiCaNotConfig);
        }

        let exported = req.get_data("exported")?.as_str().unwrap_or("").to_string();
        let common_name = req.get_data("common_name")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let organization = req.get_data_or_default("organization")?.as_str().unwrap_or("").to_string();
        let key_type = req.get_data_or_default("key_type")?.as_str().unwrap_or("ec").to_string();
        let key_bits = req.get_data_or_default("key_bits")?.as_u64().unwrap_or(0) as u32;
        let alg = KeyAlgorithm::from_role(&key_type, key_bits)?;

        let ttl_str = req.get_data_or_default("ttl")?.as_str().unwrap_or("").to_string();
        let ttl = if ttl_str.is_empty() {
            DEFAULT_ROOT_TTL
        } else {
            parse_duration(&ttl_str).map_err(|_| RvError::ErrRequestFieldInvalid)?
        };

        // Dispatch on algorithm class. Classical (RSA/EC/Ed25519) goes
        // through rcgen; PQC (ML-DSA) through the manual x509-cert builder
        // in `x509_pqc`; composite (Phase 3 preview) through `x509_composite`.
        // Either way the result is the same shape: (PEM cert, serial bytes,
        // PEM private key).
        let signer = Signer::generate(alg)?;
        let (cert_pem, serial_bytes) = match &signer {
            Signer::Classical(cs) => {
                let (cert, serial) = x509::build_root_ca(&common_name, &organization, ttl, cs)?;
                (cert.pem(), serial)
            }
            Signer::MlDsa(ml) => x509_pqc::build_root_ca(&common_name, &organization, ttl, ml)?,
            #[cfg(feature = "pki_pqc_composite")]
            Signer::Composite(c) => {
                super::x509_composite::build_root_ca(&common_name, &organization, ttl, c)?
            }
        };
        let key_pem = signer.to_storage_pem();

        // Persist CA cert + key (barrier-encrypted at the storage layer) +
        // metadata + initial CRL state.
        storage::put_string(req, KEY_CA_CERT, &cert_pem).await?;
        storage::put_string(req, KEY_CA_KEY, &key_pem).await?;

        let serial_hex = storage::serial_to_hex(&serial_bytes);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let meta = CaMetadata {
            key_type: alg.as_str().to_string(),
            key_bits: alg.key_bits(),
            common_name: common_name.clone(),
            serial_hex,
            created_at_unix: now,
            not_after_unix: (now as i64) + (ttl.as_secs() as i64),
        };
        storage::put_json(req, KEY_CA_META, &meta).await?;

        // Seed CRL state if absent so revoke can append immediately.
        if storage::get_json::<CrlState>(req, KEY_CRL_STATE).await?.is_none() {
            storage::put_json(req, KEY_CRL_STATE, &CrlState::default()).await?;
        }
        if storage::get_json::<CrlConfig>(req, KEY_CONFIG_CRL).await?.is_none() {
            storage::put_json(req, KEY_CONFIG_CRL, &CrlConfig::default()).await?;
        }

        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(cert_pem));
        data.insert("issuing_ca".into(), json!(cert_pem));
        data.insert("expiration".into(), json!(meta.not_after_unix));
        if exported == "exported" {
            data.insert("private_key".into(), json!(key_pem));
            data.insert("private_key_type".into(), json!(alg.as_str()));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn unsupported(&self, _b: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Err(RvError::ErrLogicalOperationUnsupported)
    }
}
