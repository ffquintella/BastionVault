//! `pki/cert/:serial`, `pki/ca[/pem]`, `pki/ca_chain` — read-only fetch endpoints.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};
use x509_parser::prelude::FromDer;

use super::{
    issuers,
    path_revoke::rebuild_crl_for_issuer,
    storage::{self, CertRecord, CrlState},
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn fetch_cert_path(&self) -> Path {
        let rr = self.inner.clone();
        let rd = self.inner.clone();
        new_path!({
            pattern: r"cert/(?P<serial>[0-9a-fA-F:\-]+)",
            fields: {
                "serial": { field_type: FieldType::Str, required: true, description: "Cert serial (hex)." },
                "force": { field_type: FieldType::Bool, default: false, description: "Allow deleting an active (non-revoked, non-expired) cert. Required to remove a cert that is still trusted by relying parties." }
            },
            operations: [
                {op: Operation::Read, handler: rr.read_cert},
                {op: Operation::Delete, handler: rd.delete_cert}
            ],
            help: "Fetch or delete a previously issued certificate by serial."
        })
    }

    pub fn fetch_ca_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"ca(/pem)?$",
            operations: [{op: Operation::Read, handler: r.read_ca}],
            help: "Fetch the active CA certificate."
        })
    }

    pub fn fetch_ca_chain_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"ca_chain$",
            operations: [{op: Operation::Read, handler: r.read_ca}],
            help: "Fetch the CA chain (Phase 1: root only)."
        })
    }

    pub fn list_certs_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"certs/?$",
            operations: [{op: Operation::List, handler: r.list_certs}],
            help: "List issued certificate serials."
        })
    }

    /// `pki/certs/import` — index an externally-issued certificate so it
    /// shows up alongside engine-issued certs in `pki/certs` listings and
    /// the GUI Certificates tab. The cert is stored as *orphaned*:
    /// it carries no `issuer_id`, isn't tied to any local key, and the
    /// CRL builder skips it. Useful for migrating cert inventories from
    /// other tools (e.g. XCA leaf certs) without mounting a fake issuer.
    pub fn import_cert_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"certs/import$",
            fields: {
                "certificate": { field_type: FieldType::Str, required: true, description: "PEM-encoded certificate." },
                "source": { field_type: FieldType::Str, default: "", description: "Free-form provenance label (e.g. `xca-import`)." }
            },
            operations: [{op: Operation::Write, handler: r.import_cert}],
            help: "Index an externally-issued certificate (no key, no issuer link)."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn read_cert(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let serial_raw = req.get_data("serial")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let serial_hex = normalize_serial_hex(&serial_raw);
        let key = storage::cert_storage_key(&serial_hex);
        let record: Option<CertRecord> = storage::get_json(req, &key).await?;
        let record = record.ok_or(RvError::ErrPkiCertNotFound)?;

        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(record.certificate_pem));
        data.insert("serial_number".into(), json!(record.serial_hex));
        data.insert("issued_at".into(), json!(record.issued_at_unix));
        if record.not_after_unix > 0 {
            data.insert("not_after".into(), json!(record.not_after_unix));
        }
        if !record.issuer_id.is_empty() {
            data.insert("issuer_id".into(), json!(record.issuer_id));
        }
        if record.is_orphaned {
            data.insert("is_orphaned".into(), json!(true));
        }
        if !record.source.is_empty() {
            data.insert("source".into(), json!(record.source));
        }
        if let Some(t) = record.revoked_at_unix {
            data.insert("revoked_at".into(), json!(t));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Remove a cert record from this mount's cert store.
    ///
    /// An *active* (non-revoked, non-expired) cert can only be deleted
    /// when the caller passes `force=true` — silently dropping a cert
    /// that relying parties may still trust without first revoking it
    /// would weaken the audit trail. Revoked or expired records are
    /// removable without `force`. When the deleted record was on a
    /// per-issuer CRL revoked-list, the entry is pulled and the CRL is
    /// rebuilt so verifiers stop seeing a phantom serial. Managed-key
    /// bindings recorded in `KeyRefs.cert_serials` are cleared on a
    /// best-effort basis so a downstream `DELETE pki/key/<id>` can
    /// succeed once the last referring cert is gone.
    pub async fn delete_cert(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let serial_raw = req.get_data("serial")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let serial_hex = normalize_serial_hex(&serial_raw);
        let force = req
            .get_data_or_default("force")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let cert_key = storage::cert_storage_key(&serial_hex);
        let record: CertRecord = storage::get_json(req, &cert_key).await?
            .ok_or(RvError::ErrPkiCertNotFound)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let expired = record.not_after_unix > 0 && record.not_after_unix <= now;
        let is_active = record.revoked_at_unix.is_none() && !expired;
        if is_active && !force {
            return Err(RvError::ErrString(format!(
                "delete_cert: serial `{serial_hex}` is still active; revoke it first \
                 or pass force=true to drop the record without revoking"
            )));
        }

        // Pull the serial from the issuer's CRL revoked-list (if any) so
        // a future verifier doesn't see a CRL entry pointing at a serial
        // we no longer have a record for. Then rebuild the CRL.
        if !record.issuer_id.is_empty() || record.revoked_at_unix.is_some() {
            let issuer_handle = if record.issuer_id.is_empty() {
                issuers::load_default_issuer(req).await.ok()
            } else {
                issuers::load_issuer(req, &record.issuer_id).await.ok()
            };
            if let Some(issuer) = issuer_handle {
                let crl_state_key = storage::issuer_crl_state_key(&issuer.id);
                let mut state: CrlState = storage::get_json(req, &crl_state_key).await?.unwrap_or_default();
                let before = state.revoked.len();
                state.revoked.retain(|e| e.serial_hex != serial_hex);
                if state.revoked.len() != before {
                    state.crl_number = state.crl_number.saturating_add(1);
                    storage::put_json(req, &crl_state_key, &state).await?;
                    if let Err(e) = rebuild_crl_for_issuer(req, &issuer).await {
                        log::warn!(
                            "pki/cert delete: CRL rebuild for issuer {} failed: {e:?}",
                            issuer.id
                        );
                    }
                }
            }
        }

        // Best-effort: clear the cert→managed-key binding so the key
        // becomes deletable once its last cert is gone.
        if !record.key_id.is_empty() {
            if let Err(e) = super::keys::remove_cert_ref(req, &record.key_id, &serial_hex).await {
                log::warn!(
                    "pki/cert delete: failed to clear key_ref binding for serial {serial_hex} \
                     on key {}: {e:?}",
                    record.key_id,
                );
            }
        }

        req.storage_delete(&cert_key).await?;

        let mut data: Map<String, Value> = Map::new();
        data.insert("serial_number".into(), json!(serial_hex));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn import_cert(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let pem_in = req.get_data("certificate")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .trim()
            .to_string();
        if pem_in.is_empty() {
            return Err(RvError::ErrRequestFieldInvalid);
        }
        let source = req.get_data_or_default("source")?
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();

        // Parse the PEM → DER → x509 to pull serial + NotAfter. We only
        // accept a single CERTIFICATE block; chains belong on the issuer
        // import path.
        let parsed_pem = pem::parse(pem_in.as_bytes())
            .map_err(|e| RvError::ErrString(format!("import_cert: PEM parse failed: {e}")))?;
        if parsed_pem.tag() != "CERTIFICATE" {
            return Err(RvError::ErrString(format!(
                "import_cert: expected `CERTIFICATE` PEM block, got `{}`",
                parsed_pem.tag()
            )));
        }
        let der = parsed_pem.contents();
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(der)
            .map_err(|_| RvError::ErrString("import_cert: certificate not parseable".into()))?;
        let serial_bytes = parsed.tbs_certificate.serial.to_bytes_be();
        let serial_hex = storage::serial_to_hex(&serial_bytes);
        let not_after_unix = parsed.tbs_certificate.validity.not_after.timestamp();

        let key = storage::cert_storage_key(&serial_hex);
        if let Some(_existing) = req.storage_get(&key).await? {
            return Err(RvError::ErrString(format!(
                "import_cert: serial `{serial_hex}` already indexed at this mount"
            )));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let record = CertRecord {
            serial_hex: serial_hex.clone(),
            // Re-emit canonical PEM (single-block, normalized line endings)
            // so `read_cert` round-trips cleanly regardless of how the
            // input was wrapped.
            certificate_pem: pem::encode(&pem::Pem::new("CERTIFICATE", der.to_vec())),
            issued_at_unix: now,
            revoked_at_unix: None,
            not_after_unix,
            issuer_id: String::new(),
            is_orphaned: true,
            source,
            key_id: String::new(),
        };
        storage::put_json(req, &key, &record).await?;

        let mut data: Map<String, Value> = Map::new();
        data.insert("serial_number".into(), json!(serial_hex));
        data.insert("not_after".into(), json!(not_after_unix));
        data.insert("is_orphaned".into(), json!(true));
        if !record.source.is_empty() {
            data.insert("source".into(), json!(record.source));
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn read_ca(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        // Phase 5.2: `pki/ca` returns the *default* issuer's cert, falling
        // back through the migration shim for any pre-5.2 mount.
        let issuer = super::issuers::load_default_issuer(req).await?;
        let mut data: Map<String, Value> = Map::new();
        data.insert("certificate".into(), json!(issuer.cert_pem));
        data.insert("issuer_id".into(), json!(issuer.id));
        data.insert("issuer_name".into(), json!(issuer.name));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn list_certs(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list("certs/").await?;
        Ok(Some(Response::list_response(&keys)))
    }
}

fn normalize_serial_hex(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase()
}
