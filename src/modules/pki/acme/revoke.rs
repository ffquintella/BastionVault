//! `POST /v1/pki/acme/revoke-cert` — RFC 8555 §7.6.
//!
//! The request payload carries the DER-encoded certificate (base64url)
//! and an optional `reason` integer. We accept the kid-flow (account
//! key) authentication path: the requesting account must own an
//! order whose issued cert matches the supplied DER. Cert-key
//! authentication (where the JWS jwk = the leaf's keypair, which
//! lets a holder revoke even without an account) is left out for v1
//! — operators can always revoke directly via `pki/revoke` with the
//! serial number.
//!
//! A successful revoke flips the cert's `revoked_at_unix`, appends
//! to the issuer's CRL state, and rebuilds the issuer's CRL. Same
//! code path the engine's existing `pki/revoke` uses, so an
//! ACME-revoked cert appears on the same CRL as anything else.

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde_json::{json, Map, Value};
use x509_parser::prelude::FromDer;

use super::{
    jws::JwsEnvelope,
    storage::{ORDER_CERT_SUFFIX, ORDER_PREFIX},
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

use super::super::{
    issuers, path_revoke,
    storage as pki_storage,
    PkiBackend, PkiBackendInner,
};

const HELP: &str = "RFC 8555 §7.6 — revoke a previously-issued certificate.";

impl PkiBackend {
    pub fn acme_revoke_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/revoke-cert$",
            fields: {
                "protected": { field_type: FieldType::Str, required: true, description: "JWS protected header (base64url)." },
                "payload":   { field_type: FieldType::Str, required: true, description: "JWS payload (base64url) carrying { certificate: <b64url DER>, reason?: <int> }." },
                "signature": { field_type: FieldType::Str, required: true, description: "JWS signature (base64url)." }
            },
            operations: [{op: Operation::Write, handler: h.handle_acme_revoke}],
            help: HELP
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn handle_acme_revoke(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        if !cfg.enabled {
            return Err(RvError::ErrString("acme: not enabled on this mount".into()));
        }
        let envelope = parse_envelope(req)?;
        let (account_id, payload) = self
            .verify_kid_jws(req, &envelope, "revoke-cert")
            .await?;

        let payload_json: Value = serde_json::from_slice(&payload)
            .map_err(|e| RvError::ErrString(format!("acme: revoke payload not JSON: {e}")))?;
        let cert_b64 = payload_json
            .get("certificate")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RvError::ErrString("acme: revoke payload missing `certificate`".into()))?;
        let cert_der = B64
            .decode(cert_b64.as_bytes())
            .map_err(|_| RvError::ErrString("acme: revoke certificate not base64url".into()))?;

        // Pull the serial from the DER. We don't need the full
        // x509-parser apparatus — just the serial bytes — but it's
        // the simplest correct extractor and we already depend on
        // it for CSR parsing.
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(&cert_der)
            .map_err(|_| RvError::ErrString("acme: revoke certificate not parseable".into()))?;
        let serial_bytes = parsed.tbs_certificate.serial.to_bytes_be();
        let serial_hex = pki_storage::serial_to_hex(&serial_bytes);

        // Authorisation: the requesting account must own an order
        // whose `cert_id` resolves to the same serial. We walk the
        // account's orders by linear scan — order count per account
        // is small in any sane deployment, and the alternative is a
        // reverse index we'd have to maintain on every finalize.
        let owned = self
            .account_owns_serial(req, &account_id, &serial_hex)
            .await?;
        if !owned {
            return Err(RvError::ErrString(
                "acme: unauthorized — account did not issue this certificate".into(),
            ));
        }

        // Drop into the same plumbing `pki/revoke` uses: flip the
        // cert record, append to CRL state, rebuild the issuer's CRL.
        let cert_key = pki_storage::cert_storage_key(&serial_hex);
        let mut record: pki_storage::CertRecord =
            pki_storage::get_json(req, &cert_key).await?.ok_or_else(|| {
                RvError::ErrString(format!(
                    "acme: cert serial `{serial_hex}` not in engine index (was it issued by this mount?)"
                ))
            })?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if record.revoked_at_unix.is_none() {
            record.revoked_at_unix = Some(now);
            pki_storage::put_json(req, &cert_key, &record).await?;

            let issuer = if record.issuer_id.is_empty() {
                issuers::load_default_issuer(req).await?
            } else {
                issuers::load_issuer(req, &record.issuer_id).await?
            };
            let crl_state_key = pki_storage::issuer_crl_state_key(&issuer.id);
            let mut state: pki_storage::CrlState = pki_storage::get_json(req, &crl_state_key)
                .await?
                .unwrap_or_default();
            if !state.revoked.iter().any(|e| e.serial_hex == serial_hex) {
                state.revoked.push(pki_storage::RevokedSerial {
                    serial_hex: serial_hex.clone(),
                    revoked_at_unix: now,
                });
            }
            state.crl_number = state.crl_number.saturating_add(1);
            pki_storage::put_json(req, &crl_state_key, &state).await?;
            path_revoke::rebuild_crl_for_issuer(req, &issuer).await?;
        }

        // RFC 8555 §7.6: a successful revoke returns 200 with empty
        // body. We still emit a `Replay-Nonce` per §6.5.
        let nonce = self.mint_nonce(req).await?;
        let mut headers = HashMap::new();
        headers.insert("Replay-Nonce".to_string(), nonce);
        headers.insert("Cache-Control".to_string(), "no-store".to_string());
        let mut data = Map::new();
        data.insert("revocation_time".into(), json!(record.revoked_at_unix.unwrap_or(now)));
        data.insert("serial_number".into(), json!(serial_hex));
        Ok(Some(Response {
            data: Some(data),
            headers: Some(headers),
            ..Default::default()
        }))
    }

    /// Walk the account's stored orders and return true if any
    /// order's stashed cert chain encodes a leaf with the supplied
    /// serial. We compare by re-extracting the serial from the
    /// stored leaf rather than indexing by serial — keeps the data
    /// model small and avoids a separate reverse index that needs
    /// invalidation on revoke + tidy.
    async fn account_owns_serial(
        &self,
        req: &Request,
        account_id: &str,
        target_serial_hex: &str,
    ) -> Result<bool, RvError> {
        // Storage backends expose `list` via the request prefix.
        let order_keys = req.storage_list(ORDER_PREFIX).await?;
        for k in order_keys {
            // We only care about top-level order records, not the
            // `<id>/cert` blobs. Prefer the `/cert` blob check —
            // the cert is what carries the serial — but still
            // verify the top-level record is owned by the same
            // account so a mis-routed cert blob can't grant cross-
            // account revoke.
            if k.ends_with(ORDER_CERT_SUFFIX.trim_start_matches('/')) {
                continue;
            }
            let order_id = k.clone();
            let entry = req
                .storage_get(&format!("{ORDER_PREFIX}{order_id}"))
                .await?;
            let order: super::storage::AcmeOrder = match entry {
                Some(e) => match serde_json::from_slice(&e.value) {
                    Ok(o) => o,
                    Err(_) => continue,
                },
                None => continue,
            };
            if order.account_id != account_id {
                continue;
            }
            if order.cert_id.is_empty() {
                continue;
            }
            // Pull the stashed PEM bundle and check the leaf serial.
            let chain = req
                .storage_get(&format!(
                    "{ORDER_PREFIX}{}{ORDER_CERT_SUFFIX}",
                    order.cert_id
                ))
                .await?;
            let pem = match chain {
                Some(e) => match String::from_utf8(e.value) {
                    Ok(s) => s,
                    Err(_) => continue,
                },
                None => continue,
            };
            if let Some(serial) = first_pem_cert_serial(&pem) {
                if serial == target_serial_hex {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

fn parse_envelope(req: &Request) -> Result<JwsEnvelope, RvError> {
    let protected = req
        .get_data("protected")
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();
    let payload = req
        .get_data("payload")
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();
    let signature = req
        .get_data("signature")
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();
    if protected.is_empty() || signature.is_empty() {
        return Err(RvError::ErrString(
            "acme: malformed JWS envelope (missing protected or signature)".into(),
        ));
    }
    Ok(JwsEnvelope {
        protected,
        payload,
        signature,
    })
}

fn first_pem_cert_serial(pem: &str) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut in_block = false;
    let mut acc = String::new();
    for line in pem.lines() {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            acc.clear();
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_block {
            acc.push_str(line.trim());
        }
    }
    let der = STANDARD.decode(acc.as_bytes()).ok()?;
    let (_, c) = x509_parser::certificate::X509Certificate::from_der(&der).ok()?;
    Some(pki_storage::serial_to_hex(&c.tbs_certificate.serial.to_bytes_be()))
}

#[allow(dead_code)]
fn _silence() {
    let _ = StorageEntry {
        key: String::new(),
        value: Vec::new(),
    };
    let _ = Arc::new(());
}
