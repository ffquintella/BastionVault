//! `pki/csr/*` — outgoing CSR flow for leaf certs.
//!
//! Mirrors the intermediate-CA flow at [`super::path_intermediate`] but
//! for *leaves*: the engine generates (or uses an existing managed) key,
//! emits a role-shaped CSR, and stashes a [`storage::PendingCsr`]
//! awaiting the externally-signed cert. When `set-signed` lands, the
//! cert is indexed under the orphan-cert flow (we didn't sign it, so
//! there's no issuer linkage), and the cert serial is bound to the
//! managed key via [`super::keys::add_cert_ref`] so a later
//! `pki/key/<id>` delete can refuse while the cert is live.
//!
//! Endpoints:
//!
//! - `WRITE  /v1/pki/csr/generate`              → build keypair + CSR
//! - `LIST   /v1/pki/csr`                       → list pending CSR ids
//! - `READ   /v1/pki/csr/<csr_id>`              → re-fetch CSR record
//! - `WRITE  /v1/pki/csr/<csr_id>/set-signed`   → install signed cert
//! - `DELETE /v1/pki/csr/<csr_id>`              → drop pending CSR
//!
//! The role drives DN locked-fields (organization / OU / country /
//! locality / province) plus key_type / key_bits and the requested
//! KU / EKU set. CN + SANs come from the request body. We deliberately
//! don't run the full `pki/issue/:role` policy gate (allowed_domains,
//! IP-SAN allow, etc.) on the CN here — the external CA owns
//! issuance policy for these certs. We do run the same `validate_*`
//! shape checks as the issue path so the CSR is well-formed.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};
use uuid::Uuid;
use x509_parser::prelude::FromDer;

use super::{
    crypto::Signer,
    keys::{self, KeyEntry, KeySource},
    storage::{self, PendingCsr},
    x509::{self, SubjectInput},
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn csr_generate_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"csr/generate$",
            fields: {
                "role": { field_type: FieldType::Str, required: true, description: "Role whose key_type / key_bits / DN locked-fields drive this CSR." },
                "common_name": { field_type: FieldType::Str, required: true, description: "Subject CN to put on the CSR." },
                "alt_names": { field_type: FieldType::Str, default: "", description: "Comma-separated DNS / IP SANs to request." },
                "ip_sans": { field_type: FieldType::Str, default: "", description: "Comma-separated IP SANs (in addition to anything in `alt_names`)." },
                "key_ref": { field_type: FieldType::Str, default: "", description: "Optional: pin to an existing managed key (UUID or name) instead of generating a fresh one. Subject to the role's `allow_key_reuse` / `allowed_key_refs`." },
                "exported": { field_type: FieldType::Bool, default: false, description: "When `true`, return the freshly generated PKCS#8 PEM in the response. Ignored when `key_ref` is set (the key already lives in the managed-key store)." },
                "exportable": { field_type: FieldType::Bool, default: false, description: "Pin the backing managed key as exportable via `pki/cert/<serial>/export?include_private_key=true`. Read-only after creation. Default false." }
            },
            operations: [{op: Operation::Write, handler: r.csr_generate}],
            help: "Build a leaf CSR using the named role and stash a pending record awaiting the upstream-signed cert."
        })
    }

    pub fn csr_list_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"csr/?$",
            operations: [{op: Operation::List, handler: r.csr_list}],
            help: "List pending external-signing CSR IDs."
        })
    }

    pub fn csr_item_path(&self) -> Path {
        let rr = self.inner.clone();
        let rd = self.inner.clone();
        new_path!({
            pattern: r"csr/(?P<csr_id>[\w\-]+)$",
            fields: {
                "csr_id": { field_type: FieldType::Str, required: true, description: "Pending CSR UUID (returned by `csr/generate`)." }
            },
            operations: [
                {op: Operation::Read, handler: rr.csr_read},
                {op: Operation::Delete, handler: rd.csr_delete}
            ],
            help: "Read or drop a pending CSR record. Delete preserves the backing managed key."
        })
    }

    pub fn csr_set_signed_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"csr/(?P<csr_id>[\w\-]+)/set-signed$",
            fields: {
                "csr_id": { field_type: FieldType::Str, required: true, description: "Pending CSR UUID (returned by `csr/generate`)." },
                "certificate": { field_type: FieldType::Str, required: true, description: "PEM-encoded signed certificate from the external CA." }
            },
            operations: [{op: Operation::Write, handler: r.csr_set_signed}],
            help: "Install the externally-signed cert against a pending CSR. The cert lands in the orphan-cert index and gets bound to the backing managed key."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn csr_generate(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req
            .get_data("role")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let role = self
            .get_role(req, &role_name)
            .await?
            .ok_or(RvError::ErrPkiRoleNotFound)?;

        let common_name = req
            .get_data("common_name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .trim()
            .to_string();
        // Run the same shape check as `pki/issue/:role` so a malformed
        // CN is caught locally instead of bouncing off the upstream CA.
        x509::validate_common_name(&role, &common_name)?;

        let alt_str = req
            .get_data_or_default("alt_names")?
            .as_str()
            .unwrap_or("")
            .to_string();
        let (mut alt_dns, mut alt_ips) = x509::split_alt_names(&alt_str);
        let ip_str = req
            .get_data_or_default("ip_sans")?
            .as_str()
            .unwrap_or("")
            .to_string();
        let (extra_dns, extra_ips) = x509::split_alt_names(&ip_str);
        alt_dns.extend(extra_dns);
        alt_ips.extend(extra_ips);
        if !role.allow_ip_sans && !alt_ips.is_empty() {
            return Err(RvError::ErrPkiDataInvalid);
        }
        for dns in &alt_dns {
            x509::validate_dns_name(&role, dns)?;
        }

        let role_alg = role.algorithm()?;

        // Optional `key_ref` reuses an existing managed key. Same
        // gating as `pki/issue/:role`: roles must opt in via
        // `allow_key_reuse`, and `allowed_key_refs` (when non-empty)
        // narrows which keys are acceptable.
        let request_key_ref = req
            .get_data_or_default("key_ref")?
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();
        let pinned_key: Option<KeyEntry> = if request_key_ref.is_empty() {
            None
        } else {
            if !role.allow_key_reuse {
                return Err(RvError::ErrString(format!(
                    "csr/generate: role `{role_name}` does not allow `key_ref` reuse (set role.allow_key_reuse = true)"
                )));
            }
            let entry = keys::load_key(req, &request_key_ref).await?.ok_or_else(|| {
                RvError::ErrString(format!(
                    "csr/generate: key_ref `{request_key_ref}` does not resolve to a managed key on this mount"
                ))
            })?;
            if entry.algorithm()? != role_alg {
                return Err(RvError::ErrPkiKeyTypeInvalid);
            }
            if !role.allowed_key_refs.is_empty()
                && !role.allowed_key_refs.contains(&entry.id)
                && !role.allowed_key_refs.contains(&entry.name)
            {
                return Err(RvError::ErrString(format!(
                    "csr/generate: key_ref `{request_key_ref}` is not in the role's `allowed_key_refs` allow-list"
                )));
            }
            Some(entry)
        };

        // Either reuse the pinned managed key or generate fresh + persist
        // it as a managed key so `set-signed` can bind the resulting cert
        // serial to it. We always end up with a `key_id` in the pending
        // record — there's no "ephemeral CSR" mode here.
        let exported = req
            .get_data_or_default("exported")?
            .as_bool()
            .unwrap_or(false);
        let (key_entry, signer, exported_pem) = match pinned_key {
            Some(entry) => {
                let signer = Signer::from_storage_pem(&entry.private_key_pem)?;
                (entry, signer, None)
            }
            None => {
                // Reuse the same naming heuristic the issue path uses —
                // empty name lets `persist_new_key` skip the name pointer.
                // `exportable` defaults to false for CSR-driven key
                // creation: the key is meant to live in the vault while
                // the external CA signs the CSR. The operator can opt
                // in via the `exportable` body parameter.
                let exportable = req
                    .get_data_or_default("exportable")?
                    .as_bool()
                    .unwrap_or(false);
                let (entry, signer) =
                    keys::generate_managed_key(req, role_alg, "", exported, exportable).await?;
                let exported_pem = if exported {
                    Some(signer.to_pkcs8_pem()?)
                } else {
                    None
                };
                // Replace the source on the persisted entry — `generate_managed_key`
                // tags it as `Generated` which is fine, but we'd like the
                // operator to see "csr-external" provenance on the Keys tab.
                // Doing that requires a separate write; skip for now and add
                // when we have a `KeySource::CsrExternal` variant.
                (entry, signer, exported_pem)
            }
        };

        // CSRs only support classical algorithms today — PQC CSR
        // generation lands alongside the rcgen-PQC story (Phase 2.x).
        let Signer::Classical(classical) = &signer else {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        };

        let subject = SubjectInput {
            common_name: common_name.clone(),
            alt_names: alt_dns,
            ip_sans: alt_ips,
        };
        let csr = x509::build_leaf_csr(&role, &subject, classical)?;
        let csr_pem = csr.pem().map_err(super::crypto::rcgen_err)?;

        // Persist the pending record.
        let csr_id = Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let record = PendingCsr {
            id: csr_id.clone(),
            role_name: role_name.clone(),
            key_id: key_entry.id.clone(),
            common_name: common_name.clone(),
            csr_pem: csr_pem.clone(),
            created_at_unix: now,
        };
        storage::put_json(req, &storage::pending_csr_storage_key(&csr_id), &record).await?;

        let mut data: Map<String, Value> = Map::new();
        data.insert("csr_id".into(), json!(csr_id));
        data.insert("csr".into(), json!(csr_pem));
        data.insert("key_id".into(), json!(key_entry.id));
        data.insert("role".into(), json!(role_name));
        data.insert("common_name".into(), json!(common_name));
        if let Some(pem) = exported_pem {
            data.insert("private_key".into(), json!(pem));
            data.insert("private_key_type".into(), json!(role_alg.as_str()));
        }
        // Suppress unused warning when KeySource happens to be re-exported here.
        let _ = KeySource::Generated;
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn csr_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let ids = req.storage_list(storage::KEY_PREFIX_CSR_PENDING).await?;
        Ok(Some(Response::list_response(&ids)))
    }

    pub async fn csr_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let csr_id = req
            .get_data("csr_id")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let record: PendingCsr = match storage::get_json(req, &storage::pending_csr_storage_key(&csr_id)).await? {
            Some(r) => r,
            None => return Ok(None),
        };
        let mut data: Map<String, Value> = Map::new();
        data.insert("csr_id".into(), json!(record.id));
        data.insert("role".into(), json!(record.role_name));
        data.insert("key_id".into(), json!(record.key_id));
        data.insert("common_name".into(), json!(record.common_name));
        data.insert("csr".into(), json!(record.csr_pem));
        data.insert("created_at".into(), json!(record.created_at_unix));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn csr_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let csr_id = req
            .get_data("csr_id")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let key = storage::pending_csr_storage_key(&csr_id);
        if req.storage_get(&key).await?.is_none() {
            return Ok(None);
        }
        req.storage_delete(&key).await?;
        Ok(None)
    }

    pub async fn csr_set_signed(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let csr_id = req
            .get_data("csr_id")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let storage_key = storage::pending_csr_storage_key(&csr_id);
        let record: PendingCsr = storage::get_json(req, &storage_key)
            .await?
            .ok_or_else(|| {
                RvError::ErrString(format!(
                    "csr/set-signed: no pending CSR record for id `{csr_id}`"
                ))
            })?;

        let signed_pem = req
            .get_data("certificate")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .trim()
            .to_string();
        if signed_pem.is_empty() {
            return Err(RvError::ErrRequestFieldInvalid);
        }

        // Parse the operator-supplied cert. We accept a single
        // CERTIFICATE block — chains belong on the issuer-import path.
        let parsed_pem = pem::parse(signed_pem.as_bytes())
            .map_err(|e| RvError::ErrString(format!("csr/set-signed: PEM parse failed: {e}")))?;
        if parsed_pem.tag() != "CERTIFICATE" {
            return Err(RvError::ErrString(format!(
                "csr/set-signed: expected `CERTIFICATE` PEM block, got `{}`",
                parsed_pem.tag()
            )));
        }
        let cert_der = parsed_pem.contents();

        // Verify the cert's SubjectPublicKeyInfo matches the pending
        // CSR's pubkey. This is the defence against an operator
        // accidentally pasting the wrong signed cert (or a cert minted
        // for a different CSR) on top of this pending record.
        let csr_der = super::csr::decode_pem_or_der(&record.csr_pem)?;
        let (_, csr_parsed) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
                .map_err(|_| RvError::ErrString("csr/set-signed: pending CSR is not parseable".into()))?;
        let (_, cert_parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der)
            .map_err(|_| RvError::ErrString("csr/set-signed: certificate not parseable".into()))?;
        let csr_spki = csr_parsed.certification_request_info.subject_pki.raw;
        let cert_spki = cert_parsed.tbs_certificate.subject_pki.raw;
        if csr_spki != cert_spki {
            return Err(RvError::ErrPkiCertKeyMismatch);
        }

        // Index the cert under the orphan-cert flow. We didn't sign it,
        // so there's no issuer linkage — the CRL builder skips
        // orphaned records, and the GUI Certificates tab renders an
        // "external" badge.
        let serial_bytes = cert_parsed.tbs_certificate.serial.to_bytes_be();
        let serial_hex = storage::serial_to_hex(&serial_bytes);
        let not_after_unix = cert_parsed.tbs_certificate.validity.not_after.timestamp();

        let cert_storage_key = storage::cert_storage_key(&serial_hex);
        if req.storage_get(&cert_storage_key).await?.is_some() {
            return Err(RvError::ErrString(format!(
                "csr/set-signed: serial `{serial_hex}` already indexed at this mount"
            )));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cert_record = storage::CertRecord {
            serial_hex: serial_hex.clone(),
            certificate_pem: pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.to_vec())),
            issued_at_unix: now,
            revoked_at_unix: None,
            not_after_unix,
            issuer_id: String::new(),
            is_orphaned: true,
            source: "csr-external".into(),
            key_id: record.key_id.clone(),
        };
        storage::put_json(req, &cert_storage_key, &cert_record).await?;

        // Bind the cert serial to the managed key's refs so a later
        // `pki/key/<id>` delete refuses while the cert is live (matches
        // the Phase L3 behaviour for engine-issued certs that pinned
        // a key via `key_ref`).
        keys::add_cert_ref(req, &record.key_id, &serial_hex).await?;

        // Drop the pending record — the cert is now the canonical
        // long-lived record. Operator can re-issue against the same
        // managed key by running `csr/generate` with `key_ref` again.
        req.storage_delete(&storage_key).await?;

        let mut data: Map<String, Value> = Map::new();
        data.insert("serial_number".into(), json!(serial_hex));
        data.insert("not_after".into(), json!(not_after_unix));
        data.insert("key_id".into(), json!(record.key_id));
        data.insert("source".into(), json!(cert_record.source));
        data.insert("is_orphaned".into(), json!(true));
        Ok(Some(Response::data_response(Some(data))))
    }
}

// `Context` is reachable through the `new_path!` macro expansion via the
// `crate::context::Context` use above; pulling it in a no-op `let` keeps
// the import "used" for codepaths the macro happens not to emit on this
// file. The other `use` lines are all live.
#[allow(dead_code)]
fn _ctx_keep_alive(_c: Arc<Context>) {}
