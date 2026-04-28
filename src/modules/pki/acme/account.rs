//! `POST /v1/pki/acme/new-account` and `POST /v1/pki/acme/account/<id>`.
//!
//! Both unauthenticated at the engine layer. The auth is the JWS
//! envelope that wraps the request body — the account key signs.
//! `new-account` uses an `embed` (`jwk` in the protected header);
//! subsequent calls use `kid` referring to the account URL the
//! server returned on `new-account`.

use std::{collections::HashMap, sync::Arc, time::SystemTime};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde_json::{json, Map, Value};

use super::{
    jws::{verify, JwsEnvelope, Verified},
    new_object_id,
    storage::{AcmeAccount, ACCOUNT_PREFIX},
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

use super::super::{PkiBackend, PkiBackendInner};

const NEW_ACCOUNT_HELP: &str = "RFC 8555 §7.3 — register a new ACME account or fetch the existing one keyed by the JWS account key.";
const ACCOUNT_HELP: &str = "RFC 8555 §7.3.2 — read or update an account by id.";

impl PkiBackend {
    pub fn acme_new_account_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/new-account$",
            fields: {
                "protected": { field_type: FieldType::Str, required: true, description: "JWS protected header (base64url)." },
                "payload":   { field_type: FieldType::Str, default:  "",   description: "JWS payload (base64url; empty for POST-as-GET)." },
                "signature": { field_type: FieldType::Str, required: true, description: "JWS signature (base64url)." }
            },
            operations: [{op: Operation::Write, handler: h.handle_acme_new_account}],
            help: NEW_ACCOUNT_HELP
        })
    }

    pub fn acme_account_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/account/(?P<id>[A-Za-z0-9_\-]+)$",
            fields: {
                "id":        { field_type: FieldType::Str, required: true, description: "Account id (assigned at new-account time)." },
                "protected": { field_type: FieldType::Str, required: true, description: "JWS protected header (base64url)." },
                "payload":   { field_type: FieldType::Str, default:  "",   description: "JWS payload (base64url; empty for POST-as-GET)." },
                "signature": { field_type: FieldType::Str, required: true, description: "JWS signature (base64url)." }
            },
            operations: [{op: Operation::Write, handler: h.handle_acme_account}],
            help: ACCOUNT_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn handle_acme_new_account(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        if !cfg.enabled {
            return Err(RvError::ErrString("acme: not enabled on this mount".into()));
        }

        // Parse the JWS envelope from the request body. The PKI
        // engine's standard request shape is JSON with named fields,
        // so the operator's HTTP-to-engine layer flattens the JSON
        // body into `req.get_data(...)`. ACME's body is itself a
        // 3-field JSON envelope which fits cleanly.
        let envelope = parse_envelope(req)?;

        // For new-account, the JWK is embedded — the lookup
        // closure is never invoked.
        let verified = verify(&envelope, |_kid| None)?;

        // Validate `nonce` (consume from ring) and `url` (must
        // match the request's full URL — for the in-engine model
        // we accept any URL ending in `acme/new-account`, since
        // the HTTP layer doesn't surface the original path verbatim
        // to the engine; clients must still set it for compliance
        // but a strict equality check would over-constrain proxy
        // setups. The header guards against cross-endpoint replay).
        self.check_nonce(req, &verified.header.nonce).await?;
        if !verified.header.url.ends_with("/acme/new-account") {
            return Err(RvError::ErrString(format!(
                "acme: jws header.url `{}` is not new-account",
                verified.header.url
            )));
        }

        // Look up by thumbprint — RFC 8555 §7.3 says repeated
        // new-account with the same key returns the existing record.
        if let Some(existing) = self.load_account(req, &verified.thumbprint).await? {
            return self
                .respond_account(req, &verified.thumbprint, &existing, false)
                .await;
        }

        // Parse the (optional) account-creation payload. The body
        // may be empty (then we accept defaults) or a JSON object
        // with `contact` (URL list) + `termsOfServiceAgreed` (bool)
        // + `onlyReturnExisting` (bool — RFC 8555 §7.3.1).
        let payload: Value = if verified.payload.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&verified.payload)
                .map_err(|e| RvError::ErrString(format!("acme: payload not JSON: {e}")))?
        };

        let only_existing = payload
            .get("onlyReturnExisting")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if only_existing {
            // RFC 8555 §7.3.1 — when this flag is set and no account
            // matches, return `accountDoesNotExist`.
            return Err(RvError::ErrString(
                "acme: accountDoesNotExist (onlyReturnExisting)".into(),
            ));
        }

        // EAB (RFC 8555 §7.3.4). When `eab_required = true` the
        // payload must carry `externalAccountBinding` — an inner
        // flattened JWS HMAC-signed by an operator-distributed key
        // we have on file at `acme/eab/<key_id>`. Otherwise we
        // accept-and-validate when present so the operator can mint
        // EAB-protected accounts opportunistically while keeping the
        // surface generally open.
        let mut consumed_eab_id: Option<String> = None;
        let eab_present = payload.get("externalAccountBinding").is_some();
        if cfg.eab_required && !eab_present {
            return Err(RvError::ErrString(
                "acme: externalAccountBindingRequired".into(),
            ));
        }
        if eab_present {
            let eab_value = payload.get("externalAccountBinding").unwrap().clone();
            // Synchronous lookup: pre-load the kid'd key off
            // `req.storage_get`. Mirrors the JWS-by-kid pattern
            // elsewhere in the module.
            let inner_kid = eab_value
                .get("protected")
                .and_then(|p| p.as_str())
                .and_then(|p| {
                    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
                    let bytes = B64.decode(p.as_bytes()).ok()?;
                    let v: Value = serde_json::from_slice(&bytes).ok()?;
                    v.get("kid")
                        .and_then(|k| k.as_str())
                        .map(|s| s.to_string())
                })
                .ok_or_else(|| {
                    RvError::ErrString("acme: eab inner protected.kid missing".into())
                })?;
            let key_record = self
                .load_eab(req, &inner_kid)
                .await?
                .ok_or_else(|| {
                    RvError::ErrString(format!("acme: eab unknown kid `{inner_kid}`"))
                })?;
            let key_for_lookup = key_record.clone();
            super::eab::verify_eab(
                &eab_value,
                &verified.jwk,
                "new-account",
                move |_k| Some(key_for_lookup),
            )
            .map_err(RvError::ErrString)?;
            consumed_eab_id = Some(key_record.key_id);
        }

        let contact: Vec<String> = payload
            .get("contact")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let terms_agreed = payload
            .get("termsOfServiceAgreed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let account = AcmeAccount {
            status: "valid".to_string(),
            contact,
            jwk: verified.jwk.clone(),
            terms_of_service_agreed: terms_agreed,
            created_at_unix: unix_now(),
        };
        self.save_account(req, &verified.thumbprint, &account).await?;
        // Mark the EAB key consumed only after the account is
        // persisted — order matters: a panic between save_account
        // and save_eab would otherwise leave a stranded key.
        if let Some(id) = consumed_eab_id {
            if let Some(mut k) = self.load_eab(req, &id).await? {
                k.consumed = true;
                let _ = self.save_eab(req, &id, &k).await;
            }
        }
        self.respond_account(req, &verified.thumbprint, &account, true).await
    }

    pub async fn handle_acme_account(
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
        // For the account endpoint the JWS uses `kid`; the verifier
        // resolves it to the persisted JWK.
        let req_for_lookup = std::sync::Arc::new(std::sync::Mutex::new(()));
        let _ = req_for_lookup; // (unused — left for clarity; sync lookup below)

        // Synchronous lookup against the persisted account record:
        // we read the account's stored JWK before invoking `verify`,
        // because the verifier wants a closure (and async storage in
        // a closure here is awkward). The url+id correspondence
        // also gives us an authorisation gate — the kid the client
        // sent must match the path id.
        let account = self
            .load_account(req, &id)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("acme: unknown account `{id}`")))?;
        let stored_jwk = account.jwk.clone();
        let id_for_lookup = id.clone();
        let verified = verify(&envelope, move |kid| {
            // The kid field contains the full account URL ending in
            // `/acme/account/<id>`; we accept any kid whose tail
            // matches our expected id and hand back the persisted
            // JWK. The verifier itself only uses the JWK to verify
            // the signature.
            if kid.ends_with(&format!("/acme/account/{id_for_lookup}")) {
                Some(stored_jwk)
            } else {
                None
            }
        })?;
        self.check_nonce(req, &verified.header.nonce).await?;
        // No thumbprint == id assertion here: after a successful
        // key-change (RFC 8555 §7.3.5) the live JWK on the account
        // record changes while the URL (and hence the id) stays
        // stable. The verifier above already used the persisted JWK
        // to check the signature, so the kid → JWK binding is
        // exactly as strong as the storage record.

        // POST-as-GET (empty payload) → return current state.
        // Otherwise interpret as an update. RFC 8555 §7.3.2 allows
        // updating `contact` and setting `status = "deactivated"`;
        // anything else is rejected.
        let mut updated = account;
        if !verified.payload.is_empty() && verified.payload != b"{}" {
            let update: Value = serde_json::from_slice(&verified.payload)
                .map_err(|e| RvError::ErrString(format!("acme: update payload not JSON: {e}")))?;
            if let Some(contact) = update.get("contact").and_then(|v| v.as_array()) {
                updated.contact = contact
                    .iter()
                    .filter_map(|c| c.as_str().map(String::from))
                    .collect();
            }
            if let Some(status) = update.get("status").and_then(|v| v.as_str()) {
                if status == "deactivated" {
                    updated.status = "deactivated".to_string();
                } else if status != updated.status {
                    return Err(RvError::ErrString(format!(
                        "acme: account status `{status}` not settable (only `deactivated` is allowed)"
                    )));
                }
            }
            self.save_account(req, &id, &updated).await?;
        }

        self.respond_account(req, &id, &updated, false).await
    }

    // ── Helpers ──────────────────────────────────────────────────

    async fn respond_account(
        &self,
        req: &mut Request,
        id: &str,
        account: &AcmeAccount,
        created: bool,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        let base = directory_base(&cfg, req);
        let location = format!("{base}/acme/account/{id}");

        let mut data = Map::new();
        data.insert("status".into(), Value::String(account.status.clone()));
        data.insert(
            "contact".into(),
            Value::Array(account.contact.iter().map(|c| Value::String(c.clone())).collect()),
        );
        data.insert(
            "termsOfServiceAgreed".into(),
            Value::Bool(account.terms_of_service_agreed),
        );
        data.insert(
            "orders".into(),
            Value::String(format!("{base}/acme/account/{id}/orders")),
        );

        let nonce = self.mint_nonce(req).await?;
        let mut headers = HashMap::new();
        headers.insert("Replay-Nonce".to_string(), nonce);
        headers.insert("Cache-Control".to_string(), "no-store".to_string());
        headers.insert("Location".to_string(), location);
        // RFC 8555 §6.5: the directory link is included on every
        // protocol response.
        headers.insert(
            "Link".to_string(),
            format!(r#"<{base}/acme/directory>;rel="index""#),
        );

        let _ = created;
        Ok(Some(Response {
            data: Some(data),
            headers: Some(headers),
            ..Default::default()
        }))
    }

    pub async fn load_account(
        &self,
        req: &Request,
        id: &str,
    ) -> Result<Option<AcmeAccount>, RvError> {
        let key = format!("{ACCOUNT_PREFIX}{id}");
        match req.storage_get(&key).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn save_account(
        &self,
        req: &mut Request,
        id: &str,
        account: &AcmeAccount,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(account)?;
        req.storage_put(&StorageEntry {
            key: format!("{ACCOUNT_PREFIX}{id}"),
            value: bytes,
        })
        .await
    }

    /// Validate the supplied nonce; returns a clear ACME-shaped
    /// error if the nonce is unknown or already consumed. RFC 8555
    /// §6.5 says we must fail with `urn:ietf:params:acme:error:badNonce`
    /// — surfaced here as the error message body.
    async fn check_nonce(&self, req: &mut Request, nonce: &str) -> Result<(), RvError> {
        if nonce.is_empty() {
            return Err(RvError::ErrString(
                "acme: badNonce (missing protected.nonce)".into(),
            ));
        }
        if !self.consume_nonce(req, nonce).await? {
            return Err(RvError::ErrString(
                "acme: badNonce (unknown / already consumed nonce)".into(),
            ));
        }
        Ok(())
    }
}

/// Pull the JWS envelope fields out of the request body. Same
/// shape regardless of which protocol endpoint we're handling.
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

/// Reused from `directory.rs` — the directory's URL builder. Kept
/// inline (not re-exported) to keep the module dependency graph
/// small. If a third file needs it we hoist into a `urls.rs`.
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
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Suppress unused-import warnings under feature combos that don't
// reach the encoder paths.
#[allow(dead_code)]
fn _unused() -> &'static str {
    let _ = B64.encode("x");
    let _ = json!(null);
    let _ = new_object_id("x");
    let _ = std::marker::PhantomData::<Verified>;
    "_"
}
