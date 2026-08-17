//! `POST /v1/pki/acme/key-change` — RFC 8555 §7.3.5.
//!
//! The outer JWS is signed by the **old** account key (kid flow);
//! its payload is itself a JWS, signed by the **new** account key,
//! whose payload is the JSON object `{ account: <kid>, oldKey: <jwk_of_old> }`.
//! On success, the account record's stored JWK is replaced with the
//! new key. The account id (and account URL) does NOT change — only
//! the live JWK does.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Map, Value};

use super::jws::{jwk_thumbprint, verify, JwsEnvelope};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

use super::super::{PkiBackend, PkiBackendInner};

const HELP: &str = "RFC 8555 §7.3.5 — rotate the account key.";

impl PkiBackend {
    pub fn acme_key_change_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/key-change$",
            fields: {
                "protected": { field_type: FieldType::Str, required: true, description: "Outer JWS protected header (base64url)." },
                "payload":   { field_type: FieldType::Str, required: true, description: "Outer JWS payload — itself a flattened JWS (base64url)." },
                "signature": { field_type: FieldType::Str, required: true, description: "Outer JWS signature (base64url)." }
            },
            operations: [{op: Operation::Write, handler: h.handle_acme_key_change}],
            help: HELP
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn handle_acme_key_change(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        if !cfg.enabled {
            return Err(RvError::ErrString("acme: not enabled on this mount".into()));
        }

        let outer = parse_envelope(req)?;
        // Outer is signed by the OLD account key (kid flow). The
        // verify_kid_jws helper consumes the nonce, asserts the url
        // tail matches `key-change`, and returns the resolved
        // account id + decoded payload (which is itself the inner
        // JWS as raw JSON bytes).
        let (account_id, inner_bytes) = self
            .verify_kid_jws(req, &outer, "key-change")
            .await?;

        // The inner JWS is signed by the NEW key; its protected
        // header carries `jwk` (embedded — the new key isn't yet
        // attached to the account, so kid lookup wouldn't work).
        let inner_value: Value = serde_json::from_slice(&inner_bytes)
            .map_err(|e| RvError::ErrString(format!("acme: key-change inner not JSON: {e}")))?;
        let inner = JwsEnvelope {
            protected: take_str(&inner_value, "protected")?,
            payload: take_str(&inner_value, "payload")?,
            signature: take_str(&inner_value, "signature")?,
        };
        // Pure verification — closure is never invoked because
        // the inner header MUST embed `jwk` per RFC 8555 §7.3.5.
        let inner_verified = verify(&inner, |_kid| None)
            .map_err(|e| RvError::ErrString(format!("acme: key-change inner verify: {e}")))?;
        if inner_verified.header.jwk.is_none() {
            return Err(RvError::ErrString(
                "acme: key-change inner JWS must embed jwk (not kid)".into(),
            ));
        }
        // RFC 8555 §7.3.5: the inner `url` MUST equal the outer `url`.
        // We already pinned the outer to `key-change` in
        // verify_kid_jws; mirror the check on the inner here.
        if !inner_verified.header.url.ends_with("/acme/key-change") {
            return Err(RvError::ErrString(format!(
                "acme: key-change inner url `{}` not key-change",
                inner_verified.header.url
            )));
        }

        // The inner payload is the bound-credentials JSON:
        //   { "account": "<account url>", "oldKey": <old_jwk> }
        let bind: Value = serde_json::from_slice(&inner_verified.payload)
            .map_err(|e| RvError::ErrString(format!("acme: key-change bind not JSON: {e}")))?;
        let bind_account = bind
            .get("account")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RvError::ErrString("acme: key-change.account missing".into()))?;
        let bind_account_id = bind_account
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string();
        if bind_account_id != account_id {
            return Err(RvError::ErrString(
                "acme: key-change inner.account does not match outer kid".into(),
            ));
        }
        let bind_old_key = bind
            .get("oldKey")
            .ok_or_else(|| RvError::ErrString("acme: key-change.oldKey missing".into()))?;

        // Load current account; the bind's `oldKey` MUST equal the
        // currently-stored JWK (compared by canonical thumbprint to
        // be presentation-tolerant).
        let mut account = self
            .load_account(req, &account_id)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("acme: unknown account `{account_id}`")))?;
        let old_tp_stored = jwk_thumbprint(&account.jwk).map_err(RvError::from)?;
        let old_tp_bind = jwk_thumbprint(bind_old_key).map_err(RvError::from)?;
        if old_tp_stored != old_tp_bind {
            return Err(RvError::ErrString(
                "acme: key-change.oldKey does not match the current account key".into(),
            ));
        }

        // Refuse to roll onto a key already attached to a different
        // account — RFC 8555 §7.3.5 calls this out as a server
        // requirement.
        let new_tp = jwk_thumbprint(&inner_verified.jwk).map_err(RvError::from)?;
        if new_tp != old_tp_stored {
            if let Some(_collision) = self.load_account(req, &new_tp).await? {
                return Err(RvError::ErrString(
                    "acme: key-change new key is already in use by another account".into(),
                ));
            }
        }

        // Atomic-from-the-client's-point-of-view swap. The id stays
        // stable; only the stored JWK changes. Subsequent kid
        // lookups continue to resolve `account/<id>` and will verify
        // against the new JWK.
        account.jwk = inner_verified.jwk.clone();
        self.save_account(req, &account_id, &account).await?;

        // RFC 8555 §7.3.5: the response is the (updated) account
        // record. Re-use the same response shape `account/<id>` uses.
        self.respond_account_for_key_change(req, &account_id, &account).await
    }

    async fn respond_account_for_key_change(
        &self,
        req: &mut Request,
        id: &str,
        account: &super::storage::AcmeAccount,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        let base = directory_base(&cfg, req);
        let location = format!("{base}/acme/account/{id}");
        let mut data = Map::new();
        data.insert("status".into(), Value::String(account.status.clone()));
        data.insert(
            "contact".into(),
            Value::Array(
                account
                    .contact
                    .iter()
                    .map(|c| Value::String(c.clone()))
                    .collect(),
            ),
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

fn take_str(v: &Value, name: &str) -> Result<String, RvError> {
    v.get(name)
        .and_then(|x| x.as_str())
        .map(String::from)
        .ok_or_else(|| RvError::ErrString(format!("acme: key-change inner missing `{name}`")))
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

#[allow(dead_code)]
fn _silence() {
    let _ = json!(null);
    let _ = Arc::new(());
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};

    /// Sign a fresh inner JWS with a new Ed25519 key, hand it to the
    /// JWS verifier (the same one `handle_acme_key_change` uses for
    /// the inner envelope), and confirm the structure parses + the
    /// embedded JWK comes back. Doesn't drive the storage path
    /// (that needs a Request); narrows the assertion to the
    /// JWS-shape contract.
    #[test]
    fn key_change_inner_jws_round_trip() {
        let new_sk = SigningKey::from_bytes(&[3u8; 32]);
        let new_vk = new_sk.verifying_key();
        let new_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": B64.encode(new_vk.as_bytes()),
        });
        let inner_protected = serde_json::json!({
            "alg": "EdDSA",
            "jwk": new_jwk,
            "url": "https://example/v1/pki/acme/key-change",
            "nonce": "n",
        });
        let bind = serde_json::json!({
            "account": "https://example/v1/pki/acme/account/old-id",
            "oldKey": { "kty": "OKP", "crv": "Ed25519", "x": "old" },
        });
        let p_b64 = B64.encode(serde_json::to_vec(&inner_protected).unwrap());
        let pl_b64 = B64.encode(serde_json::to_vec(&bind).unwrap());
        let signing_input = format!("{p_b64}.{pl_b64}");
        let sig = new_sk.sign(signing_input.as_bytes());
        let env = JwsEnvelope {
            protected: p_b64,
            payload: pl_b64,
            signature: B64.encode(sig.to_bytes()),
        };
        let v = verify(&env, |_| None).unwrap();
        assert_eq!(v.header.alg, "EdDSA");
        assert!(v.header.jwk.is_some());
    }
}
