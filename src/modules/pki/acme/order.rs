//! `POST /v1/pki/acme/new-order`, `POST /v1/pki/acme/order/<id>`,
//! `POST /v1/pki/acme/order/<id>/finalize`, `POST /v1/pki/acme/cert/<id>`.
//!
//! All four endpoints are JWS-authenticated (kid flow) and
//! unauthenticated at the engine layer.
//!
//! `finalize` is the gateway between ACME and the existing PKI engine:
//! it parses the client-supplied CSR, re-checks every identifier
//! against the order's authorisations, then drops into the same
//! `build_leaf_from_spki` path `pki/sign/<role>` already uses with the
//! mount's configured `default_role` + `default_issuer_ref`.

use std::{collections::HashMap, sync::Arc, time::Duration};

use serde_json::{json, Map, Value};

use super::{
    jws::{verify, JwsEnvelope},
    new_object_id,
    storage::{
        AcmeAuthz, AcmeChall, AcmeIdentifier, AcmeOrder, AUTHZ_PREFIX, CHALL_PREFIX,
        ORDER_CERT_SUFFIX, ORDER_PREFIX,
    },
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

use super::super::{
    csr::{self, CsrAlgClass},
    crypto::Signer,
    storage as pki_storage,
    x509, x509_pqc, PkiBackend, PkiBackendInner,
};

const NEW_ORDER_HELP: &str = "RFC 8555 §7.4 — submit a new order for one or more identifiers.";
const ORDER_HELP: &str = "RFC 8555 §7.4 — read order state (POST-as-GET).";
const FINALIZE_HELP: &str = "RFC 8555 §7.4 — submit the CSR to finalize an order whose authorisations are all valid.";
const CERT_HELP: &str = "RFC 8555 §7.4.2 — download the issued certificate chain (POST-as-GET).";

/// Default order expiry — 7 days. RFC 8555 §7.1.2 leaves this to the
/// CA; matches Let's Encrypt's published value.
const ORDER_TTL_SECS: u64 = 7 * 24 * 3600;
/// Default authz expiry. Same shape — the validator window is intentionally
/// long enough that a slow CI/CD cycle won't expire mid-flow.
const AUTHZ_TTL_SECS: u64 = 30 * 24 * 3600;

impl PkiBackend {
    pub fn acme_new_order_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/new-order$",
            fields: {
                "protected": { field_type: FieldType::Str, required: true, description: "JWS protected header (base64url)." },
                "payload":   { field_type: FieldType::Str, default:  "",   description: "JWS payload (base64url)." },
                "signature": { field_type: FieldType::Str, required: true, description: "JWS signature (base64url)." }
            },
            operations: [{op: Operation::Write, handler: h.handle_acme_new_order}],
            help: NEW_ORDER_HELP
        })
    }

    pub fn acme_order_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/order/(?P<id>[A-Za-z0-9_\-]+)$",
            fields: {
                "id":        { field_type: FieldType::Str, required: true, description: "Order id." },
                "protected": { field_type: FieldType::Str, required: true, description: "JWS protected header (base64url)." },
                "payload":   { field_type: FieldType::Str, default:  "",   description: "JWS payload (base64url; empty for POST-as-GET)." },
                "signature": { field_type: FieldType::Str, required: true, description: "JWS signature (base64url)." }
            },
            operations: [{op: Operation::Write, handler: h.handle_acme_order}],
            help: ORDER_HELP
        })
    }

    pub fn acme_finalize_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/order/(?P<id>[A-Za-z0-9_\-]+)/finalize$",
            fields: {
                "id":        { field_type: FieldType::Str, required: true, description: "Order id." },
                "protected": { field_type: FieldType::Str, required: true, description: "JWS protected header (base64url)." },
                "payload":   { field_type: FieldType::Str, required: true, description: "JWS payload (base64url) carrying { csr: <base64url DER> }." },
                "signature": { field_type: FieldType::Str, required: true, description: "JWS signature (base64url)." }
            },
            operations: [{op: Operation::Write, handler: h.handle_acme_finalize}],
            help: FINALIZE_HELP
        })
    }

    pub fn acme_cert_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/cert/(?P<id>[A-Za-z0-9_\-]+)$",
            fields: {
                "id":        { field_type: FieldType::Str, required: true, description: "Order id whose cert to fetch." },
                "protected": { field_type: FieldType::Str, required: true, description: "JWS protected header (base64url)." },
                "payload":   { field_type: FieldType::Str, default:  "",   description: "JWS payload (base64url; empty for POST-as-GET)." },
                "signature": { field_type: FieldType::Str, required: true, description: "JWS signature (base64url)." }
            },
            operations: [{op: Operation::Write, handler: h.handle_acme_cert}],
            help: CERT_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn handle_acme_new_order(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        if !cfg.enabled {
            return Err(RvError::ErrString("acme: not enabled on this mount".into()));
        }

        let envelope = parse_envelope(req)?;
        let (account_id, payload) = self.verify_kid_jws(req, &envelope, "new-order").await?;

        // Per-account rate limit (Phase 6.3). Sliding window per
        // `acme/config`. 0 in either knob disables.
        if cfg.rate_window_secs > 0 && cfg.rate_orders_per_window > 0 {
            self.rate_limit_record(req, &account_id, cfg.rate_window_secs, cfg.rate_orders_per_window)
                .await?;
        }

        // RFC 8555 §7.4: payload is `{ identifiers: [...], notBefore?, notAfter? }`.
        let payload_json: Value = if payload.is_empty() {
            return Err(RvError::ErrString(
                "acme: new-order payload must be a JSON object with identifiers".into(),
            ));
        } else {
            serde_json::from_slice(&payload)
                .map_err(|e| RvError::ErrString(format!("acme: payload not JSON: {e}")))?
        };
        let identifiers = parse_identifiers(&payload_json)?;
        if identifiers.is_empty() {
            return Err(RvError::ErrString("acme: order has no identifiers".into()));
        }

        // For each identifier, mint an authz with a single HTTP-01
        // challenge. DNS-01 lands in Phase 6.2.
        let order_id = new_object_id("ord");
        let mut authz_ids: Vec<String> = Vec::with_capacity(identifiers.len());
        for ident in &identifiers {
            if ident.typ != "dns" {
                return Err(RvError::ErrString(format!(
                    "acme: unsupported identifier type `{}` (only `dns` in v1)",
                    ident.typ
                )));
            }
            let authz_id = new_object_id("az");
            // Mint both an HTTP-01 and a DNS-01 challenge per authz —
            // the client picks which to satisfy. Each gets its own
            // token (RFC 8555 §8.3 / §8.4). The challenge that the
            // client triggers via POST `chall/<id>` runs the
            // matching validator.
            let mut chall_ids = Vec::with_capacity(2);
            for typ in ["http-01", "dns-01"] {
                let chall_id = new_object_id("ch");
                let chall = AcmeChall {
                    status: "pending".into(),
                    typ: typ.into(),
                    token: super::new_nonce(),
                    authz_id: authz_id.clone(),
                    identifier: ident.clone(),
                    validated: String::new(),
                    error: None,
                };
                self.save_chall(req, &chall_id, &chall).await?;
                chall_ids.push(chall_id);
            }
            let authz = AcmeAuthz {
                status: "pending".into(),
                identifier: ident.clone(),
                challenges: chall_ids,
                expires_at_unix: unix_now() + AUTHZ_TTL_SECS,
                account_id: account_id.clone(),
                order_id: order_id.clone(),
            };
            self.save_authz(req, &authz_id, &authz).await?;
            authz_ids.push(authz_id);
        }

        let order = AcmeOrder {
            status: "pending".into(),
            account_id: account_id.clone(),
            identifiers,
            authorizations: authz_ids,
            not_before: String::new(),
            not_after: String::new(),
            cert_id: String::new(),
            expires_at_unix: unix_now() + ORDER_TTL_SECS,
            error: None,
        };
        self.save_order(req, &order_id, &order).await?;

        self.respond_order(req, &order_id, &order, true).await
    }

    pub async fn handle_acme_order(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        if !cfg.enabled {
            return Err(RvError::ErrString("acme: not enabled on this mount".into()));
        }
        let id = req
            .get_data("id")
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();

        let envelope = parse_envelope(req)?;
        let (account_id, _payload) = self
            .verify_kid_jws(req, &envelope, &format!("order/{id}"))
            .await?;

        let mut order = self
            .load_order(req, &id)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("acme: unknown order `{id}`")))?;
        if order.account_id != account_id {
            return Err(RvError::ErrString("acme: order belongs to another account".into()));
        }

        // POST-as-GET: re-evaluate state (a chall validation may have
        // flipped an authz behind the scenes — recompute on read).
        self.refresh_order_state(req, &mut order).await?;
        self.save_order(req, &id, &order).await?;
        self.respond_order(req, &id, &order, false).await
    }

    pub async fn handle_acme_finalize(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        if !cfg.enabled {
            return Err(RvError::ErrString("acme: not enabled on this mount".into()));
        }
        if cfg.default_role.trim().is_empty() {
            return Err(RvError::ErrString(
                "acme: cannot finalize without acme/config.default_role".into(),
            ));
        }
        let id = req
            .get_data("id")
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();

        let envelope = parse_envelope(req)?;
        let (account_id, payload) = self
            .verify_kid_jws(req, &envelope, &format!("order/{id}/finalize"))
            .await?;

        let mut order = self
            .load_order(req, &id)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("acme: unknown order `{id}`")))?;
        if order.account_id != account_id {
            return Err(RvError::ErrString("acme: order belongs to another account".into()));
        }

        // Recompute state — finalize is only valid in the `ready`
        // state, which is reached when every authz is `valid`.
        self.refresh_order_state(req, &mut order).await?;
        if order.status != "ready" {
            return Err(RvError::ErrString(format!(
                "acme: orderNotReady (status = `{}`; all authorisations must be `valid`)",
                order.status
            )));
        }

        // Pull the CSR out of the payload. RFC 8555 §7.4: shape is
        // `{ "csr": "<base64url DER>" }`.
        let payload_json: Value = serde_json::from_slice(&payload)
            .map_err(|e| RvError::ErrString(format!("acme: finalize payload not JSON: {e}")))?;
        let csr_b64 = payload_json
            .get("csr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RvError::ErrString("acme: finalize payload missing `csr`".into()))?;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
        let csr_der = B64
            .decode(csr_b64.as_bytes())
            .map_err(|_| RvError::ErrString("acme: finalize csr not base64url".into()))?;

        // Hand DER directly to the existing CSR parser (it accepts
        // either PEM or DER via `decode_pem_or_der`).
        let parsed = csr::parse_and_verify(
            // The parser expects either a PEM or raw bytes wrapped in a
            // string. Re-encode as PEM because `parse_and_verify` takes
            // `&str` and needs a PEM-style envelope to round-trip.
            &pem_wrap_csr(&csr_der),
        )?;

        // RFC 8555 §7.4: the CSR must NOT request an identifier the
        // order didn't authorise. Compare both ways — the CSR's CN
        // must be in the order, and every order identifier must
        // appear in the CSR's SANs (or as the CSR CN).
        let mut csr_dns: Vec<String> = parsed.requested_dns_sans.clone();
        if let Some(cn) = parsed.common_name.as_deref() {
            if !cn.is_empty() && !csr_dns.iter().any(|d| d == cn) {
                csr_dns.push(cn.to_string());
            }
        }
        let order_dns: Vec<String> = order
            .identifiers
            .iter()
            .filter(|i| i.typ == "dns")
            .map(|i| i.value.clone())
            .collect();
        for d in &csr_dns {
            if !order_dns.contains(d) {
                return Err(RvError::ErrString(format!(
                    "acme: badCSR — identifier `{d}` not authorised on order"
                )));
            }
        }
        for d in &order_dns {
            if !csr_dns.contains(d) {
                return Err(RvError::ErrString(format!(
                    "acme: badCSR — order identifier `{d}` missing from CSR"
                )));
            }
        }

        // Resolve role + issuer the same way `pki/sign/<role>` does.
        let role = self
            .get_role(req, &cfg.default_role)
            .await?
            .ok_or_else(|| RvError::ErrString(format!(
                "acme: configured default_role `{}` not found", cfg.default_role
            )))?;
        let issuer = if !cfg.default_issuer_ref.is_empty() {
            super::super::issuers::load_issuer(req, &cfg.default_issuer_ref).await?
        } else {
            super::super::issuers::load_default_issuer(req).await?
        };
        super::super::issuers::require_issuing(&issuer)?;
        let ca_cert_pem = issuer.cert_pem.clone();
        let ca_signer = issuer.signer;
        let issuer_id = issuer.id.clone();

        let common_name = parsed
            .common_name
            .clone()
            .or_else(|| order_dns.first().cloned())
            .ok_or_else(|| RvError::ErrString("acme: badCSR — no common name".into()))?;
        x509::validate_common_name(&role, &common_name)?;
        let mut alt_dns = csr_dns.clone();
        alt_dns.retain(|d| d != &common_name);
        let subject = x509::SubjectInput {
            common_name: common_name.clone(),
            alt_names: alt_dns,
            ip_sans: parsed.requested_ip_sans.clone(),
        };
        let ttl = role.effective_ttl(None);

        // Same dispatch as `sign_csr_role`. Mixed-class chains rejected.
        let (cert_pem, serial_bytes) = match (&parsed.algorithm_class, &ca_signer) {
            (CsrAlgClass::Classical, Signer::Classical(ca)) => {
                let (cert, serial) =
                    x509::build_leaf_from_spki(&role, &subject, ttl, &parsed.spki_der, ca, &ca_cert_pem)?;
                (cert.pem(), serial)
            }
            (CsrAlgClass::MlDsa(level), Signer::MlDsa(ca_ml)) => x509_pqc::build_leaf_from_pqc_spki(
                &role,
                &subject,
                ttl,
                &parsed.raw_public_key,
                *level,
                ca_ml,
                &ca_cert_pem,
            )?,
            _ => return Err(RvError::ErrPkiKeyTypeInvalid),
        };
        let serial_hex = pki_storage::serial_to_hex(&serial_bytes);

        // Persist into the engine's normal cert index so revoke + CRL
        // pick this leaf up alongside non-ACME issuance.
        let now = unix_now();
        let record = pki_storage::CertRecord {
            serial_hex: serial_hex.clone(),
            certificate_pem: cert_pem.clone(),
            issued_at_unix: now,
            revoked_at_unix: None,
            not_after_unix: (now as i64).saturating_add(ttl.as_secs() as i64),
            issuer_id: issuer_id.clone(),
            is_orphaned: false,
            source: String::new(),
        };
        pki_storage::put_json(req, &pki_storage::cert_storage_key(&serial_hex), &record).await?;

        // Stash the chain at `acme/orders/<id>/cert`. The `cert/<id>`
        // endpoint hands it back as PEM bundle (leaf + issuer).
        let chain_pem = format!("{cert_pem}\n{ca_cert_pem}");
        req.storage_put(&StorageEntry {
            key: format!("{ORDER_PREFIX}{id}{ORDER_CERT_SUFFIX}"),
            value: chain_pem.into_bytes(),
        })
        .await?;

        order.status = "valid".to_string();
        order.cert_id = id.clone();
        self.save_order(req, &id, &order).await?;
        self.respond_order(req, &id, &order, false).await
    }

    pub async fn handle_acme_cert(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        if !cfg.enabled {
            return Err(RvError::ErrString("acme: not enabled on this mount".into()));
        }
        let id = req
            .get_data("id")
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();

        let envelope = parse_envelope(req)?;
        let (account_id, _payload) = self
            .verify_kid_jws(req, &envelope, &format!("cert/{id}"))
            .await?;

        let order = self
            .load_order(req, &id)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("acme: unknown order `{id}`")))?;
        if order.account_id != account_id {
            return Err(RvError::ErrString("acme: order belongs to another account".into()));
        }
        if order.status != "valid" || order.cert_id.is_empty() {
            return Err(RvError::ErrString(
                "acme: order has no certificate yet".into(),
            ));
        }
        let chain = req
            .storage_get(&format!("{ORDER_PREFIX}{id}{ORDER_CERT_SUFFIX}"))
            .await?
            .ok_or_else(|| RvError::ErrString("acme: cert chain missing from storage".into()))?;
        let chain_pem = String::from_utf8(chain.value)
            .map_err(|_| RvError::ErrString("acme: stored cert is not utf-8".into()))?;

        let nonce = self.mint_nonce(req).await?;
        let mut headers = HashMap::new();
        headers.insert("Replay-Nonce".to_string(), nonce);
        headers.insert("Cache-Control".to_string(), "no-store".to_string());
        headers.insert(
            "Content-Type".to_string(),
            "application/pem-certificate-chain".to_string(),
        );
        let mut data = Map::new();
        data.insert("certificate".into(), Value::String(chain_pem));
        Ok(Some(Response {
            data: Some(data),
            headers: Some(headers),
            ..Default::default()
        }))
    }

    /// Append `now` to the per-account rate bucket, prune entries
    /// outside the window, and refuse the call if the result
    /// crosses the `max` threshold. RFC 8555 §6.6 maps over-limit
    /// to `urn:ietf:params:acme:error:rateLimited`; we surface that
    /// shape in the error string.
    pub async fn rate_limit_record(
        &self,
        req: &mut Request,
        account_id: &str,
        window_secs: u64,
        max: u64,
    ) -> Result<(), RvError> {
        use super::storage::{RateBucket, RATE_PREFIX};
        let key = format!("{RATE_PREFIX}{account_id}");
        let mut bucket: RateBucket = match req.storage_get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => RateBucket::default(),
        };
        let now = unix_now();
        let cutoff = now.saturating_sub(window_secs);
        bucket.orders.retain(|t| *t >= cutoff);
        if (bucket.orders.len() as u64) >= max {
            return Err(RvError::ErrString(format!(
                "acme: rateLimited (account `{account_id}` exceeded {max} new-order calls per {window_secs}s window)"
            )));
        }
        bucket.orders.push(now);
        let bytes = serde_json::to_vec(&bucket)?;
        req.storage_put(&StorageEntry { key, value: bytes }).await
    }

    // ── State machine helpers ────────────────────────────────────

    /// Recompute `order.status` from the current state of its
    /// authorisations. Pure function on stored state — no validator
    /// is run here; the chall handler is what flips an authz to
    /// `valid` after a successful HTTP-01 fetch.
    pub async fn refresh_order_state(
        &self,
        req: &Request,
        order: &mut AcmeOrder,
    ) -> Result<(), RvError> {
        if order.status == "valid" || order.status == "invalid" {
            return Ok(());
        }
        let mut all_valid = true;
        let mut any_invalid = false;
        for az_id in &order.authorizations {
            match self.load_authz(req, az_id).await? {
                Some(a) => {
                    if a.status == "invalid" || a.status == "expired" || a.status == "deactivated"
                    {
                        any_invalid = true;
                    }
                    if a.status != "valid" {
                        all_valid = false;
                    }
                }
                None => {
                    any_invalid = true;
                    all_valid = false;
                }
            }
        }
        if any_invalid {
            order.status = "invalid".into();
        } else if all_valid {
            order.status = "ready".into();
        }
        Ok(())
    }

    // ── Storage ──────────────────────────────────────────────────

    pub async fn load_order(&self, req: &Request, id: &str) -> Result<Option<AcmeOrder>, RvError> {
        match req.storage_get(&format!("{ORDER_PREFIX}{id}")).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }
    pub async fn save_order(
        &self,
        req: &mut Request,
        id: &str,
        order: &AcmeOrder,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(order)?;
        req.storage_put(&StorageEntry {
            key: format!("{ORDER_PREFIX}{id}"),
            value: bytes,
        })
        .await
    }
    pub async fn load_authz(&self, req: &Request, id: &str) -> Result<Option<AcmeAuthz>, RvError> {
        match req.storage_get(&format!("{AUTHZ_PREFIX}{id}")).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }
    pub async fn save_authz(
        &self,
        req: &mut Request,
        id: &str,
        authz: &AcmeAuthz,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(authz)?;
        req.storage_put(&StorageEntry {
            key: format!("{AUTHZ_PREFIX}{id}"),
            value: bytes,
        })
        .await
    }
    pub async fn load_chall(&self, req: &Request, id: &str) -> Result<Option<AcmeChall>, RvError> {
        match req.storage_get(&format!("{CHALL_PREFIX}{id}")).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }
    pub async fn save_chall(
        &self,
        req: &mut Request,
        id: &str,
        chall: &AcmeChall,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(chall)?;
        req.storage_put(&StorageEntry {
            key: format!("{CHALL_PREFIX}{id}"),
            value: bytes,
        })
        .await
    }

    // ── JWS / response helpers ───────────────────────────────────

    /// Parse the kid out of the protected header, look up the
    /// account, verify the signature, consume the nonce, and return
    /// `(account_id, payload)`. Used by every protocol endpoint
    /// after `new-account`.
    pub async fn verify_kid_jws(
        &self,
        req: &mut Request,
        envelope: &JwsEnvelope,
        expected_url_tail: &str,
    ) -> Result<(String, Vec<u8>), RvError> {
        // Pre-parse the protected header to read `kid` so we can
        // synchronously load the account JWK before invoking the
        // verifier (the verifier closure is sync).
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
        let header_bytes = B64
            .decode(envelope.protected.as_bytes())
            .map_err(|_| RvError::ErrString("acme: protected not base64url".into()))?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|_| RvError::ErrString("acme: protected not JSON".into()))?;
        let kid = header
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RvError::ErrString("acme: missing kid (use account url)".into()))?
            .to_string();
        // The kid is always the full account URL ending in
        // `/acme/account/<id>`.
        let account_id = kid
            .rsplit('/')
            .next()
            .map(|s| s.to_string())
            .unwrap_or_default();
        if account_id.is_empty() {
            return Err(RvError::ErrString("acme: malformed kid".into()));
        }
        let account = self
            .load_account(req, &account_id)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("acme: unknown account `{account_id}`")))?;
        let stored_jwk = account.jwk.clone();
        let kid_for_lookup = kid.clone();
        let verified = verify(envelope, move |k| {
            if k == kid_for_lookup {
                Some(stored_jwk)
            } else {
                None
            }
        })?;
        // Replay protection.
        if verified.header.nonce.is_empty() {
            return Err(RvError::ErrString("acme: badNonce (missing)".into()));
        }
        if !self.consume_nonce(req, &verified.header.nonce).await? {
            return Err(RvError::ErrString(
                "acme: badNonce (unknown / replayed)".into(),
            ));
        }
        // The JWS-bound url must match the endpoint tail (mirrors
        // the looser check in account.rs — proxies can rewrite the
        // exact path so we anchor on the tail).
        let want = format!("/acme/{expected_url_tail}");
        if !verified.header.url.ends_with(&want) {
            return Err(RvError::ErrString(format!(
                "acme: jws header.url `{}` does not match endpoint `{want}`",
                verified.header.url
            )));
        }
        Ok((account_id, verified.payload))
    }

    async fn respond_order(
        &self,
        req: &mut Request,
        id: &str,
        order: &AcmeOrder,
        _created: bool,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        let base = directory_base(&cfg, req);
        let location = format!("{base}/acme/order/{id}");

        let mut data = Map::new();
        data.insert("status".into(), Value::String(order.status.clone()));
        data.insert(
            "expires".into(),
            Value::String(rfc3339_from_unix(order.expires_at_unix)),
        );
        let identifiers: Vec<Value> = order
            .identifiers
            .iter()
            .map(|i| json!({ "type": i.typ, "value": i.value }))
            .collect();
        data.insert("identifiers".into(), Value::Array(identifiers));
        let auth_urls: Vec<Value> = order
            .authorizations
            .iter()
            .map(|a| Value::String(format!("{base}/acme/authz/{a}")))
            .collect();
        data.insert("authorizations".into(), Value::Array(auth_urls));
        data.insert(
            "finalize".into(),
            Value::String(format!("{base}/acme/order/{id}/finalize")),
        );
        if !order.cert_id.is_empty() {
            data.insert(
                "certificate".into(),
                Value::String(format!("{base}/acme/cert/{}", order.cert_id)),
            );
        }

        let nonce = self.mint_nonce(req).await?;
        let mut headers = HashMap::new();
        headers.insert("Replay-Nonce".to_string(), nonce);
        headers.insert("Cache-Control".to_string(), "no-store".to_string());
        headers.insert("Location".to_string(), location);
        headers.insert(
            "Link".to_string(),
            format!(r#"<{base}/acme/directory>;rel="index""#),
        );
        Ok(Some(Response {
            data: Some(data),
            headers: Some(headers),
            ..Default::default()
        }))
    }
}

// ── Free helpers ─────────────────────────────────────────────────

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

fn parse_identifiers(payload: &Value) -> Result<Vec<AcmeIdentifier>, RvError> {
    let arr = payload
        .get("identifiers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| RvError::ErrString("acme: payload.identifiers missing or not array".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let typ = v
            .get("type")
            .and_then(|t| t.as_str())
            .ok_or_else(|| RvError::ErrString("acme: identifier.type missing".into()))?;
        let value = v
            .get("value")
            .and_then(|t| t.as_str())
            .ok_or_else(|| RvError::ErrString("acme: identifier.value missing".into()))?;
        out.push(AcmeIdentifier {
            typ: typ.to_string(),
            value: value.to_string(),
        });
    }
    Ok(out)
}

fn pem_wrap_csr(der: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let b64 = STANDARD.encode(der);
    let mut wrapped = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap());
        wrapped.push('\n');
    }
    wrapped.push_str("-----END CERTIFICATE REQUEST-----\n");
    wrapped
}

fn directory_base(cfg: &super::storage::AcmeConfig, req: &Request) -> String {
    if !cfg.external_hostname.trim().is_empty() {
        let host = cfg.external_hostname.trim().trim_end_matches('/');
        if host.starts_with("http://") || host.starts_with("https://") {
            format!("{host}/v1/pki")
        } else {
            format!("https://{host}/v1/pki")
        }
    } else {
        let host = req
            .headers
            .as_ref()
            .and_then(|h| h.get("host").or_else(|| h.get("Host")))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "localhost:8200".to_string());
        format!("https://{host}/v1/pki")
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rfc3339_from_unix(t: u64) -> String {
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};
    OffsetDateTime::from_unix_timestamp(t as i64)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| format!("{t}"))
}

#[allow(dead_code)]
fn _silence() {
    let _: Duration = Duration::from_secs(0);
    let _ = Arc::new(());
    let _ = std::marker::PhantomData::<&()>;
    let _ = json!(null);
}
