//! `pki/revoke` — revoke an issued cert by serial.
//!
//! On revoke we (1) flip the stored `CertRecord.revoked_at_unix`, (2) append
//! the serial to the persistent `CrlState`, and (3) bump `crl_number` and
//! rebuild + cache the CRL. This keeps `GET /v1/pki/crl` cheap and cache-able.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::{
    crypto::Signer,
    storage::{self, CertRecord, CrlConfig, CrlState, RevokedSerial, KEY_CA_CERT, KEY_CA_KEY, KEY_CONFIG_CRL,
              KEY_CRL_CACHED, KEY_CRL_STATE},
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

            let mut state: CrlState = storage::get_json(req, KEY_CRL_STATE).await?.unwrap_or_default();
            if !state.revoked.iter().any(|e| e.serial_hex == serial_hex) {
                state.revoked.push(RevokedSerial { serial_hex: serial_hex.clone(), revoked_at_unix: now });
            }
            state.crl_number = state.crl_number.saturating_add(1);
            storage::put_json(req, KEY_CRL_STATE, &state).await?;

            // Rebuild the CRL eagerly so the next read is a cache hit.
            rebuild_crl(req).await?;
        }

        let mut data: Map<String, Value> = Map::new();
        data.insert("revocation_time".into(), json!(record.revoked_at_unix.unwrap_or(now)));
        data.insert("serial_number".into(), json!(serial_hex));
        Ok(Some(Response::data_response(Some(data))))
    }
}

#[maybe_async::maybe_async]
pub async fn rebuild_crl(req: &Request) -> Result<String, RvError> {
    let ca_cert_pem = storage::get_string(req, KEY_CA_CERT).await?
        .ok_or(RvError::ErrPkiCaNotConfig)?;
    let ca_key_pem = storage::get_string(req, KEY_CA_KEY).await?
        .ok_or(RvError::ErrPkiCaKeyNotFound)?;
    let signer = Signer::from_storage_pem(&ca_key_pem)?;
    let state: CrlState = storage::get_json(req, KEY_CRL_STATE).await?.unwrap_or_default();
    let cfg: CrlConfig = storage::get_json(req, KEY_CONFIG_CRL).await?.unwrap_or_default();

    let revoked: Vec<RevokedEntry> = state
        .revoked
        .iter()
        .filter_map(|s| hex_to_bytes(&s.serial_hex).map(|bytes| RevokedEntry { serial: bytes, revoked_at_unix: s.revoked_at_unix }))
        .collect();

    let crl_number = if state.crl_number == 0 { 1 } else { state.crl_number };
    let pem = match &signer {
        Signer::Classical(cs) => {
            let crl = x509::build_crl(crl_number, cfg.expiry_seconds.max(60), &revoked, cs, &ca_cert_pem)?;
            crl.pem().map_err(super::crypto::rcgen_err)?
        }
        Signer::MlDsa(ml) => {
            x509_pqc::build_crl(crl_number, cfg.expiry_seconds.max(60), &revoked, ml, &ca_cert_pem)?
        }
    };
    storage::put_string(req, KEY_CRL_CACHED, &pem).await?;
    Ok(pem)
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
