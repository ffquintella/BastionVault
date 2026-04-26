//! Intermediate-CA lifecycle — Phase 5.
//!
//! Two-mount workflow:
//!
//! 1. On the *intermediate* mount, operator runs
//!    `pki/intermediate/generate/{exported|internal}`. The engine generates
//!    a keypair, writes it to `ca/pending/key`, and returns a CSR. In
//!    `internal` mode the private key is *not* echoed; in `exported` mode
//!    it is, for offline workflows that cannot read the engine's storage.
//! 2. Operator takes the CSR to a root mount (or an offline root) and
//!    calls `pki/root/sign-intermediate` to get a signed intermediate cert.
//! 3. Back on the intermediate mount, `pki/intermediate/set-signed` with
//!    the signed cert installs it as `ca/cert`, promotes
//!    `ca/pending/key` → `ca/key`, and the mount can now issue leaves.
//!
//! Until step 3 lands, the intermediate mount has no `ca/cert` and `issue`
//! calls fail with `ErrPkiCaNotConfig` — the right behaviour.

use std::{collections::HashMap, sync::Arc, time::Duration};

use humantime::parse_duration;
use serde_json::{json, Map, Value};
use x509_cert::der::Decode;

use super::{
    crypto::{KeyAlgorithm, Signer},
    storage::{
        self, CaKind, CaMetadata, CrlConfig, CrlState, PendingIntermediate, KEY_CA_CERT, KEY_CA_KEY,
        KEY_CA_META, KEY_CA_PENDING_CSR, KEY_CA_PENDING_KEY, KEY_CA_PENDING_META, KEY_CONFIG_CRL,
        KEY_CRL_STATE,
    },
    x509,
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const DEFAULT_INTERMEDIATE_TTL: Duration = Duration::from_secs(5 * 365 * 24 * 3600); // ~5y

impl PkiBackend {
    pub fn intermediate_generate_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"intermediate/generate/(?P<exported>internal|exported)",
            fields: {
                "exported": { field_type: FieldType::Str, required: true, description: "internal | exported." },
                "common_name": { field_type: FieldType::Str, required: true, description: "Subject CN for the intermediate." },
                "organization": { field_type: FieldType::Str, default: "", description: "Subject Organization." },
                "key_type": { field_type: FieldType::Str, default: "ec", description: "rsa | ec | ed25519." },
                "key_bits": { field_type: FieldType::Int, default: 0, description: "Key size (0 = default)." }
            },
            operations: [{op: Operation::Write, handler: r.generate_intermediate}],
            help: "Generate an intermediate-CA keypair and emit its CSR for signing by an upstream root."
        })
    }

    pub fn intermediate_set_signed_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"intermediate/set-signed$",
            fields: {
                "certificate": { field_type: FieldType::Str, required: true, description: "PEM of the signed intermediate cert (from the upstream CA)." }
            },
            operations: [{op: Operation::Write, handler: r.set_signed_intermediate}],
            help: "Install a signed intermediate cert produced from this mount's pending CSR."
        })
    }

    pub fn root_sign_intermediate_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"root/sign-intermediate$",
            fields: {
                "csr": { field_type: FieldType::Str, required: true, description: "PEM- or DER-encoded PKCS#10 CSR for the intermediate." },
                "common_name": { field_type: FieldType::Str, default: "", description: "Override CN; defaults to the CSR's CN." },
                "organization": { field_type: FieldType::Str, default: "", description: "Subject Organization." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Lifetime of the intermediate (default 5y)." },
                "max_path_length": { field_type: FieldType::Int, default: -1, description: "BasicConstraints pathLenConstraint; negative = unconstrained." }
            },
            operations: [{op: Operation::Write, handler: r.sign_intermediate}],
            help: "Sign an intermediate-CA CSR with this mount's CA."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn generate_intermediate(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        // Refuse if the mount is already active *or* if there's a pending
        // generation that hasn't been resolved by `set-signed`. Operators
        // who want to abandon an in-flight pending cert should delete the
        // mount; we don't expose a `cancel` knob in Phase 5.
        if storage::get_string(req, KEY_CA_CERT).await?.is_some() {
            return Err(RvError::ErrPkiCaNotConfig);
        }
        if storage::get_string(req, KEY_CA_PENDING_KEY).await?.is_some() {
            return Err(RvError::ErrPkiCaNotConfig);
        }

        let exported = req.get_data("exported")?.as_str().unwrap_or("").to_string();
        let common_name = req.get_data("common_name")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let organization = req.get_data_or_default("organization")?.as_str().unwrap_or("").to_string();
        let key_type = req.get_data_or_default("key_type")?.as_str().unwrap_or("ec").to_string();
        let key_bits = req.get_data_or_default("key_bits")?.as_u64().unwrap_or(0) as u32;
        let alg = KeyAlgorithm::from_role(&key_type, key_bits)?;

        let signer = Signer::generate(alg)?;
        // Phase 5 limits intermediate generation to classical algorithms,
        // matching the sign-handler limitation. PQC intermediates land
        // alongside PQC CSR support.
        let Signer::Classical(classical) = &signer else {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        };

        let csr = x509::build_intermediate_csr(&common_name, &organization, classical)?;
        let csr_pem = csr.pem().map_err(super::crypto::rcgen_err)?;

        let key_pem = signer.to_storage_pem();
        storage::put_string(req, KEY_CA_PENDING_KEY, &key_pem).await?;
        storage::put_string(req, KEY_CA_PENDING_CSR, &csr_pem).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        storage::put_json(
            req,
            KEY_CA_PENDING_META,
            &PendingIntermediate {
                key_type: alg.as_str().to_string(),
                key_bits: alg.key_bits(),
                common_name: common_name.clone(),
                created_at_unix: now,
            },
        )
        .await?;

        let mut data: Map<String, Value> = Map::new();
        data.insert("csr".into(), json!(csr_pem));
        if exported == "exported" {
            data.insert("private_key".into(), json!(key_pem));
            data.insert("private_key_type".into(), json!(alg.as_str()));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn set_signed_intermediate(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pending_key = storage::get_string(req, KEY_CA_PENDING_KEY)
            .await?
            .ok_or(RvError::ErrPkiCaKeyNotFound)?;
        let pending_meta: PendingIntermediate = storage::get_json(req, KEY_CA_PENDING_META)
            .await?
            .ok_or(RvError::ErrPkiCaKeyNotFound)?;

        let signed_pem = req.get_data("certificate")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();

        // Validate: the cert's SubjectPublicKeyInfo must match the pending
        // keypair's public key. This is the defence against an operator
        // accidentally installing the wrong signed cert.
        let signer = Signer::from_storage_pem(&pending_key)?;
        let Signer::Classical(classical) = &signer else {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        };
        let cert_der = super::csr::decode_pem_or_der(&signed_pem)?;
        let cert = x509_cert::Certificate::from_der(&cert_der)
            .map_err(|_| RvError::ErrPkiCertChainIncorrect)?;
        let cert_pk_bits = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        // Compare raw public key bytes via rcgen's PublicKeyData trait.
        use rcgen::PublicKeyData;
        if cert_pk_bits != classical.key_pair().der_bytes() {
            return Err(RvError::ErrPkiCertKeyMismatch);
        }

        // Promote pending → active.
        storage::put_string(req, KEY_CA_CERT, &signed_pem).await?;
        storage::put_string(req, KEY_CA_KEY, &pending_key).await?;

        // CA metadata + CRL state.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let not_after_unix = cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs() as i64;
        let serial_hex = storage::serial_to_hex(cert.tbs_certificate.serial_number.as_bytes());
        storage::put_json(
            req,
            KEY_CA_META,
            &CaMetadata {
                key_type: pending_meta.key_type,
                key_bits: pending_meta.key_bits,
                common_name: pending_meta.common_name,
                serial_hex,
                created_at_unix: now,
                not_after_unix,
                ca_kind: CaKind::Intermediate,
            },
        )
        .await?;
        if storage::get_json::<CrlState>(req, KEY_CRL_STATE).await?.is_none() {
            storage::put_json(req, KEY_CRL_STATE, &CrlState::default()).await?;
        }
        if storage::get_json::<CrlConfig>(req, KEY_CONFIG_CRL).await?.is_none() {
            storage::put_json(req, KEY_CONFIG_CRL, &CrlConfig::default()).await?;
        }

        // Clear pending state so a future `intermediate/generate` can run
        // (after first deleting `ca/cert` + `ca/key` — Phase 5 doesn't
        // expose that, but a DELETE on `pki/config/ca` would). For now,
        // clearing the pending records keeps storage tidy.
        req.storage_delete(KEY_CA_PENDING_KEY).await?;
        req.storage_delete(KEY_CA_PENDING_CSR).await?;
        req.storage_delete(KEY_CA_PENDING_META).await?;

        let mut data: Map<String, Value> = Map::new();
        data.insert("imported_issuers".into(), json!([]));
        data.insert("imported_keys".into(), json!([]));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn sign_intermediate(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let csr_input = req.get_data("csr")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let parsed = super::csr::parse_and_verify(&csr_input)?;

        let common_name = {
            let override_cn = req.get_data_or_default("common_name")?.as_str().unwrap_or("").to_string();
            if !override_cn.is_empty() {
                override_cn
            } else {
                parsed.common_name.clone().ok_or(RvError::ErrPkiDataInvalid)?
            }
        };
        let organization = req.get_data_or_default("organization")?.as_str().unwrap_or("").to_string();

        let ttl_str = req.get_data_or_default("ttl")?.as_str().unwrap_or("").to_string();
        let ttl = if ttl_str.is_empty() {
            DEFAULT_INTERMEDIATE_TTL
        } else {
            parse_duration(&ttl_str).map_err(|_| RvError::ErrRequestFieldInvalid)?
        };

        let max_path_length = req.get_data_or_default("max_path_length")?.as_i64().unwrap_or(-1);
        let path_len: Option<u8> = if max_path_length < 0 { None } else { Some(max_path_length.min(255) as u8) };

        let ca_cert_pem = storage::get_string(req, KEY_CA_CERT).await?
            .ok_or(RvError::ErrPkiCaNotConfig)?;
        let ca_key_pem = storage::get_string(req, KEY_CA_KEY).await?
            .ok_or(RvError::ErrPkiCaKeyNotFound)?;
        let ca_signer = Signer::from_storage_pem(&ca_key_pem)?;
        let Signer::Classical(ca_classical) = &ca_signer else {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        };

        let (cert, _serial) = x509::build_intermediate_ca(
            &common_name,
            &organization,
            ttl,
            &parsed.spki_der,
            ca_classical,
            &ca_cert_pem,
            path_len,
        )?;
        let cert_pem = cert.pem();

        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(cert_pem));
        data.insert("issuing_ca".into(), json!(ca_cert_pem));
        Ok(Some(Response::data_response(Some(data))))
    }
}
