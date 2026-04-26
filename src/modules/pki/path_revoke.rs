//! `pki/revoke` — revoke an issued cert by serial.
//!
//! Phase 5.2: per-issuer CRL state. The cert's `CertRecord.issuer_id`
//! identifies which issuer signed it; the CRL state for *that* issuer
//! gets the new revocation entry, and only that issuer's CRL is rebuilt.
//! A cert with an empty `issuer_id` (record written before 5.2)
//! transparently routes to the mount default — same behaviour the migration
//! shim leaves things in.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{
    crypto::Signer,
    issuers::{self, IssuerHandle},
    storage::{self, CertRecord, CrlConfig, CrlState, RevokedSerial, KEY_CONFIG_CRL},
    x509::{self, RevokedEntry},
    x509_pqc,
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn revoke_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"revoke$",
            fields: {
                "serial_number": { field_type: FieldType::Str, required: true, description: "Cert serial (hex)." }
            },
            operations: [{op: Operation::Write, handler: r.revoke_cert}],
            help: "Revoke a certificate by serial number."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn revoke_cert(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let serial_raw = req.get_data("serial_number")?.as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let serial_hex: String = serial_raw
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_ascii_lowercase();

        let cert_key = storage::cert_storage_key(&serial_hex);
        let mut record: CertRecord = storage::get_json(req, &cert_key).await?
            .ok_or(RvError::ErrPkiCertNotFound)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Idempotent: re-revoking returns the existing revocation time.
        if record.revoked_at_unix.is_none() {
            record.revoked_at_unix = Some(now);
            storage::put_json(req, &cert_key, &record).await?;

            // Resolve the cert's issuer; pre-5.2 records may have an empty
            // `issuer_id` and route to the mount default.
            let issuer = if record.issuer_id.is_empty() {
                issuers::load_default_issuer(req).await?
            } else {
                issuers::load_issuer(req, &record.issuer_id).await?
            };
            let crl_state_key = storage::issuer_crl_state_key(&issuer.id);
            let mut state: CrlState = storage::get_json(req, &crl_state_key).await?.unwrap_or_default();
            if !state.revoked.iter().any(|e| e.serial_hex == serial_hex) {
                state.revoked.push(RevokedSerial { serial_hex: serial_hex.clone(), revoked_at_unix: now });
            }
            state.crl_number = state.crl_number.saturating_add(1);
            storage::put_json(req, &crl_state_key, &state).await?;

            rebuild_crl_for_issuer(req, &issuer).await?;
        }

        let mut data: Map<String, Value> = Map::new();
        data.insert("revocation_time".into(), json!(record.revoked_at_unix.unwrap_or(now)));
        data.insert("serial_number".into(), json!(serial_hex));
        data.insert("issuer_id".into(), json!(record.issuer_id));
        Ok(Some(Response::data_response(Some(data))))
    }
}

/// Rebuild the CRL for a *specific* issuer. Used by `revoke_cert` (after
/// flipping a cert's `revoked_at_unix`) and by `path_crl::rotate_crl` /
/// `path_crl::read_crl` (which now operate on the default issuer).
#[maybe_async::maybe_async]
pub async fn rebuild_crl_for_issuer(req: &Request, issuer: &IssuerHandle) -> Result<String, RvError> {
    let cfg: CrlConfig = storage::get_json(req, KEY_CONFIG_CRL).await?.unwrap_or_default();
    let crl_state_key = storage::issuer_crl_state_key(&issuer.id);
    let crl_cached_key = storage::issuer_crl_cached_key(&issuer.id);
    let state: CrlState = storage::get_json(req, &crl_state_key).await?.unwrap_or_default();

    let revoked: Vec<RevokedEntry> = state
        .revoked
        .iter()
        .filter_map(|s| {
            hex_to_bytes(&s.serial_hex).map(|bytes| RevokedEntry { serial: bytes, revoked_at_unix: s.revoked_at_unix })
        })
        .collect();

    let crl_number = if state.crl_number == 0 { 1 } else { state.crl_number };
    let pem = match &issuer.signer {
        Signer::Classical(cs) => {
            let crl = x509::build_crl(crl_number, cfg.expiry_seconds.max(60), &revoked, cs, &issuer.cert_pem)?;
            crl.pem().map_err(super::crypto::rcgen_err)?
        }
        Signer::MlDsa(ml) => {
            x509_pqc::build_crl(crl_number, cfg.expiry_seconds.max(60), &revoked, ml, &issuer.cert_pem)?
        }
        #[cfg(feature = "pki_pqc_composite")]
        Signer::Composite(c) => super::x509_composite::build_crl(
            crl_number,
            cfg.expiry_seconds.max(60),
            &revoked,
            c,
            &issuer.cert_pem,
        )?,
    };
    storage::put_string(req, &crl_cached_key, &pem).await?;
    Ok(pem)
}

/// Backwards-compatible wrapper that operates on the mount's default
/// issuer. The Phase 4 tidy job and the existing CRL routes call this.
#[maybe_async::maybe_async]
pub async fn rebuild_crl(req: &Request) -> Result<String, RvError> {
    let issuer = issuers::load_default_issuer(req).await?;
    rebuild_crl_for_issuer(req, &issuer).await
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let high = (bytes[i] as char).to_digit(16)?;
        let low = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
        i += 2;
    }
    Some(out)
}
