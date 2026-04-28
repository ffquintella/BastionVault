//! `POST /v1/pki/acme/authz/<id>` and `POST /v1/pki/acme/chall/<id>`.
//!
//! `authz/<id>` is POST-as-GET — the client polls it to learn the
//! challenge URLs and current status.
//!
//! `chall/<id>` is the trigger: the client publishes the
//! keyAuthorization at the challenge URL (`/.well-known/acme-challenge/<token>`
//! for HTTP-01) and POSTs an empty `{}` payload here. The engine
//! then issues an outbound HTTP GET to that URL and compares the
//! body to the expected `<token>.<thumbprint>` keyAuthorization.

use std::{collections::HashMap, sync::Arc, time::Duration};

use serde_json::{json, Map, Value};

use super::{
    jws::{key_authorization, JwsEnvelope},
    storage::{AcmeAuthz, AcmeChall, AUTHZ_PREFIX, CHALL_PREFIX},
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

use super::super::{PkiBackend, PkiBackendInner};

const AUTHZ_HELP: &str = "RFC 8555 §7.5 — read authorization (POST-as-GET).";
const CHALL_HELP: &str = "RFC 8555 §7.5.1 — submit a challenge for validation.";

impl PkiBackend {
    pub fn acme_authz_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/authz/(?P<id>[A-Za-z0-9_\-]+)$",
            fields: {
                "id":        { field_type: FieldType::Str, required: true, description: "Authorization id." },
                "protected": { field_type: FieldType::Str, required: true, description: "JWS protected header (base64url)." },
                "payload":   { field_type: FieldType::Str, default:  "",   description: "JWS payload (base64url; empty for POST-as-GET)." },
                "signature": { field_type: FieldType::Str, required: true, description: "JWS signature (base64url)." }
            },
            operations: [{op: Operation::Write, handler: h.handle_acme_authz}],
            help: AUTHZ_HELP
        })
    }

    pub fn acme_chall_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/chall/(?P<id>[A-Za-z0-9_\-]+)$",
            fields: {
                "id":        { field_type: FieldType::Str, required: true, description: "Challenge id." },
                "protected": { field_type: FieldType::Str, required: true, description: "JWS protected header (base64url)." },
                "payload":   { field_type: FieldType::Str, default:  "",   description: "JWS payload (base64url; usually `{}`)." },
                "signature": { field_type: FieldType::Str, required: true, description: "JWS signature (base64url)." }
            },
            operations: [{op: Operation::Write, handler: h.handle_acme_chall}],
            help: CHALL_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn handle_acme_authz(
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
            .verify_kid_jws(req, &envelope, &format!("authz/{id}"))
            .await?;

        let authz = self
            .load_authz(req, &id)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("acme: unknown authz `{id}`")))?;
        if authz.account_id != account_id {
            return Err(RvError::ErrString("acme: authz belongs to another account".into()));
        }
        self.respond_authz(req, &id, &authz).await
    }

    pub async fn handle_acme_chall(
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
            .verify_kid_jws(req, &envelope, &format!("chall/{id}"))
            .await?;

        let mut chall = self
            .load_chall(req, &id)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("acme: unknown chall `{id}`")))?;
        let mut authz = self
            .load_authz(req, &chall.authz_id)
            .await?
            .ok_or_else(|| {
                RvError::ErrString("acme: chall references unknown authz (corruption)".into())
            })?;
        if authz.account_id != account_id {
            return Err(RvError::ErrString("acme: chall belongs to another account".into()));
        }

        // Already done? Idempotent — just return current state.
        if chall.status == "valid" || chall.status == "invalid" {
            return self.respond_chall(req, &id, &chall, &authz).await;
        }

        // Pull the account JWK so we can compute the expected
        // keyAuthorization for this challenge.
        let account = self
            .load_account(req, &account_id)
            .await?
            .ok_or_else(|| RvError::ErrString("acme: account vanished mid-flow".into()))?;
        let thumbprint = super::jws::jwk_thumbprint(&account.jwk)?;
        let expected = key_authorization(&chall.token, &thumbprint);

        // Run the validator. HTTP-01 + DNS-01 supported; tls-alpn-01
        // is out of scope for v1.
        let result = match chall.typ.as_str() {
            "http-01" => http01_validate(&chall.identifier.value, &chall.token, &expected),
            "dns-01" => super::dns01::dns01_validate(
                &chall.identifier.value,
                &expected,
                &cfg.dns_resolvers,
            ),
            other => Err(format!("unsupported challenge type `{other}`")),
        };

        match result {
            Ok(()) => {
                chall.status = "valid".into();
                chall.validated = rfc3339_now();
                chall.error = None;
                authz.status = "valid".into();
            }
            Err(e) => {
                chall.status = "invalid".into();
                chall.error = Some(json!({
                    "type": "urn:ietf:params:acme:error:incorrectResponse",
                    "detail": e,
                }));
                // RFC 8555 §7.1.4: an authz with all challenges
                // invalid becomes invalid. We only ever attach one
                // challenge per authz today, so a single failure
                // sinks the authz.
                authz.status = "invalid".into();
            }
        }
        self.save_chall(req, &id, &chall).await?;
        self.save_authz(req, &chall.authz_id, &authz).await?;

        // Cascade: if this authz flipped to valid/invalid, the
        // owning order's state machine recomputes on next
        // poll — refresh now so the response after this chall is
        // already consistent.
        if let Some(mut order) = self.load_order(req, &authz.order_id).await? {
            self.refresh_order_state(req, &mut order).await?;
            self.save_order(req, &authz.order_id, &order).await?;
        }

        self.respond_chall(req, &id, &chall, &authz).await
    }

    async fn respond_authz(
        &self,
        req: &mut Request,
        id: &str,
        authz: &AcmeAuthz,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        let base = directory_base(&cfg, req);
        let location = format!("{base}/acme/authz/{id}");

        let mut data = Map::new();
        data.insert("status".into(), Value::String(authz.status.clone()));
        data.insert(
            "expires".into(),
            Value::String(rfc3339_from_unix(authz.expires_at_unix)),
        );
        data.insert(
            "identifier".into(),
            json!({"type": authz.identifier.typ, "value": authz.identifier.value}),
        );
        let mut chall_arr = Vec::with_capacity(authz.challenges.len());
        for ch_id in &authz.challenges {
            if let Some(ch) = self.load_chall(req, ch_id).await? {
                let mut o = Map::new();
                o.insert("type".into(), Value::String(ch.typ.clone()));
                o.insert(
                    "url".into(),
                    Value::String(format!("{base}/acme/chall/{ch_id}")),
                );
                o.insert("status".into(), Value::String(ch.status.clone()));
                o.insert("token".into(), Value::String(ch.token.clone()));
                if !ch.validated.is_empty() {
                    o.insert("validated".into(), Value::String(ch.validated.clone()));
                }
                if let Some(err) = &ch.error {
                    o.insert("error".into(), err.clone());
                }
                chall_arr.push(Value::Object(o));
            }
        }
        data.insert("challenges".into(), Value::Array(chall_arr));

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

    async fn respond_chall(
        &self,
        req: &mut Request,
        id: &str,
        chall: &AcmeChall,
        authz: &AcmeAuthz,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        let base = directory_base(&cfg, req);
        let mut data = Map::new();
        data.insert("type".into(), Value::String(chall.typ.clone()));
        data.insert(
            "url".into(),
            Value::String(format!("{base}/acme/chall/{id}")),
        );
        data.insert("status".into(), Value::String(chall.status.clone()));
        data.insert("token".into(), Value::String(chall.token.clone()));
        if !chall.validated.is_empty() {
            data.insert("validated".into(), Value::String(chall.validated.clone()));
        }
        if let Some(err) = &chall.error {
            data.insert("error".into(), err.clone());
        }
        let nonce = self.mint_nonce(req).await?;
        let mut headers = HashMap::new();
        headers.insert("Replay-Nonce".to_string(), nonce);
        headers.insert("Cache-Control".to_string(), "no-store".to_string());
        headers.insert(
            "Link".to_string(),
            format!(
                r#"<{base}/acme/authz/{}>;rel="up", <{base}/acme/directory>;rel="index""#,
                chall.authz_id
            ),
        );
        let _ = authz;
        Ok(Some(Response {
            data: Some(data),
            headers: Some(headers),
            ..Default::default()
        }))
    }
}

// ── HTTP-01 validator ────────────────────────────────────────────

/// HTTP-01 (RFC 8555 §8.3): GET `http://<domain>/.well-known/acme-challenge/<token>`
/// over plain HTTP, expect a body containing exactly the
/// keyAuthorization. We bound the response size, set a tight
/// timeout, and refuse to follow redirects — every one of those
/// guards is documented in the security section of
/// `features/pki-acme.md`.
fn http01_validate(domain: &str, token: &str, expected: &str) -> Result<(), String> {
    if token.is_empty() {
        return Err("empty token".into());
    }
    let url = format!("http://{domain}/.well-known/acme-challenge/{token}");
    // ureq agent with explicit timeouts and redirect-disable so a
    // misbehaving target can't pull us through 30 redirects to an
    // internal address.
    let agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_global(Some(Duration::from_secs(10)))
        .max_redirects(0)
        .build()
        .new_agent();
    let mut resp = match agent.get(&url).call() {
        Ok(r) => r,
        Err(e) => return Err(format!("fetch failed: {e}")),
    };
    // Cap the body at 4 KiB — the keyAuthorization is ~90 bytes
    // including the dot. A larger body is either misconfigured or
    // an attempt to amplify SSRF.
    let body = match resp.body_mut().with_config().limit(4096).read_to_string() {
        Ok(b) => b,
        Err(e) => return Err(format!("body read failed: {e}")),
    };
    let trimmed = body.trim();
    if trimmed != expected {
        return Err(format!(
            "keyAuthorization mismatch (got {} bytes, wanted {})",
            trimmed.len(),
            expected.len()
        ));
    }
    Ok(())
}

// ── shared helpers (mirror order.rs) ─────────────────────────────

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

fn rfc3339_now() -> String {
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
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
    let _ = AUTHZ_PREFIX;
    let _ = CHALL_PREFIX;
    let _ = StorageEntry {
        key: String::new(),
        value: Vec::new(),
    };
    let _ = Arc::new(());
    let _ = std::marker::PhantomData::<&()>;
}
