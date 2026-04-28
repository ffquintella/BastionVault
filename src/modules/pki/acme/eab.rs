//! External Account Binding (EAB) — RFC 8555 §7.3.4.
//!
//! Operator-facing CRUD on `pki/acme/eab/<key_id>` (Vault-token
//! authenticated). The operator generates a fresh key, distributes
//! `(key_id, key_b64)` to a client team out-of-band, and the client
//! folds it into their `new-account` request as an inner JWS. New-
//! account verifies that inner JWS against the persisted HMAC key
//! before creating the account; consumed keys are marked
//! `consumed = true` (single-use per RFC 8555 §7.3.4).

use std::{collections::HashMap, sync::Arc, time::SystemTime};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde_json::{json, Map, Value};

use super::storage::{EabKey, EAB_PREFIX};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

use super::super::{PkiBackend, PkiBackendInner};

const HELP: &str = r#"
Manage External Account Binding (EAB) HMAC keys for ACME `new-account`.

Operator-facing; the protocol-side validation runs inside `new-account`.

Write a record to mint or replace a key:

  * `key_id`  — operator-chosen identifier the client will reference in
                the inner JWS `kid`. Defaults to a random 144-bit b64url
                value when omitted.
  * `key_b64` — HMAC-SHA-256 key bytes, URL-safe base64 (no pad).
                Defaults to a freshly generated 256-bit key.
  * `comment` — optional audit note (which client got the key, etc.).

The Read response surfaces `key_id`, `key_b64`, `comment`,
`created_at_unix`, and `consumed`. Once consumed, a re-issue requires
writing a new record with a fresh `key_id`.
"#;

impl PkiBackend {
    pub fn acme_eab_path(&self) -> Path {
        let r = self.inner.clone();
        let w = self.inner.clone();
        let d = self.inner.clone();
        new_path!({
            pattern: r"acme/eab/(?P<key_id>[A-Za-z0-9_\-]+)$",
            fields: {
                "key_id":  { field_type: FieldType::Str, required: true, description: "EAB key id (URL-safe; mirrors the inner JWS `kid`)." },
                "key_b64": { field_type: FieldType::Str, default:  "",   description: "URL-safe base64 (no pad) HMAC-SHA-256 key bytes; empty = mint a fresh 256-bit key." },
                "comment": { field_type: FieldType::Str, default:  "",   description: "Optional human-readable note for audit." }
            },
            operations: [
                {op: Operation::Read,   handler: r.handle_acme_eab_read},
                {op: Operation::Write,  handler: w.handle_acme_eab_write},
                {op: Operation::Delete, handler: d.handle_acme_eab_delete}
            ],
            help: HELP
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn handle_acme_eab_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let key_id = req
            .get_data("key_id")
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        let key = self
            .load_eab(req, &key_id)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("acme: eab `{key_id}` not found")))?;
        let mut data = Map::new();
        data.insert("key_id".into(), Value::String(key.key_id));
        data.insert("key_b64".into(), Value::String(key.key_b64));
        data.insert("comment".into(), Value::String(key.comment));
        data.insert(
            "created_at_unix".into(),
            Value::Number(key.created_at_unix.into()),
        );
        data.insert("consumed".into(), Value::Bool(key.consumed));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_acme_eab_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let key_id = req
            .get_data("key_id")
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        let key_b64 = match req
            .get_data("key_b64")
            .ok()
            .and_then(|v| v.as_str().map(String::from))
        {
            Some(s) if !s.is_empty() => {
                B64.decode(s.as_bytes()).map_err(|_| {
                    RvError::ErrString("acme: eab key_b64 not URL-safe base64 (no pad)".into())
                })?;
                s
            }
            _ => {
                use rand::RngExt;
                let mut bytes = [0u8; 32];
                rand::rng().fill(&mut bytes[..]);
                B64.encode(bytes)
            }
        };
        let comment = req
            .get_data("comment")
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        let key = EabKey {
            key_id: key_id.clone(),
            key_b64: key_b64.clone(),
            comment,
            created_at_unix: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            consumed: false,
        };
        self.save_eab(req, &key_id, &key).await?;
        let mut data = Map::new();
        data.insert("key_id".into(), Value::String(key_id));
        data.insert("key_b64".into(), Value::String(key_b64));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_acme_eab_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let key_id = req
            .get_data("key_id")
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        req.storage_delete(&format!("{EAB_PREFIX}{key_id}")).await?;
        Ok(None)
    }

    pub async fn load_eab(
        &self,
        req: &Request,
        key_id: &str,
    ) -> Result<Option<EabKey>, RvError> {
        match req.storage_get(&format!("{EAB_PREFIX}{key_id}")).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }
    pub async fn save_eab(
        &self,
        req: &mut Request,
        key_id: &str,
        key: &EabKey,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(key)?;
        req.storage_put(&StorageEntry {
            key: format!("{EAB_PREFIX}{key_id}"),
            value: bytes,
        })
        .await
    }
}

/// Verify the EAB inner JWS (RFC 8555 §7.3.4):
/// - inner JWS `protected.alg` = `HS256`,
/// - inner JWS `protected.kid` = a key_id we have on file,
/// - inner JWS `protected.url` = the new-account URL (we accept any
///   url ending in `/acme/new-account` for proxy tolerance, mirroring
///   the outer envelope),
/// - inner JWS payload, when decoded, equals the outer envelope's
///   account JWK,
/// - HMAC-SHA-256 over `protected.payload` matches `signature`.
///
/// Returns the matched EAB record on success so the caller can flip
/// `consumed = true` after the account is persisted.
pub fn verify_eab(
    eab_value: &Value,
    expected_account_jwk: &Value,
    expected_url_tail: &str,
    lookup: impl FnOnce(&str) -> Option<EabKey>,
) -> Result<EabKey, String> {
    use hmac::{Hmac, Mac};
    use hmac::digest::KeyInit;
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let protected = eab_value
        .get("protected")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "eab: missing protected".to_string())?;
    let payload = eab_value
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "eab: missing payload".to_string())?;
    let signature = eab_value
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "eab: missing signature".to_string())?;

    let header_bytes = B64
        .decode(protected.as_bytes())
        .map_err(|_| "eab: protected not base64url".to_string())?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| "eab: protected not JSON".to_string())?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "eab: missing protected.alg".to_string())?;
    if alg != "HS256" {
        return Err(format!("eab: alg `{alg}` not HS256"));
    }
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "eab: missing protected.kid".to_string())?;
    let url = header
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "eab: missing protected.url".to_string())?;
    let want = format!("/acme/{expected_url_tail}");
    if !url.ends_with(&want) {
        return Err(format!("eab: protected.url `{url}` not new-account"));
    }

    let key = lookup(kid).ok_or_else(|| format!("eab: unknown kid `{kid}`"))?;
    if key.consumed {
        return Err(format!("eab: key `{kid}` already consumed"));
    }
    let key_bytes = B64
        .decode(key.key_b64.as_bytes())
        .map_err(|_| "eab: stored key_b64 invalid".to_string())?;

    let payload_bytes = B64
        .decode(payload.as_bytes())
        .map_err(|_| "eab: payload not base64url".to_string())?;
    let inner_jwk: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| "eab: payload not JSON".to_string())?;
    if !jwks_equal(&inner_jwk, expected_account_jwk) {
        return Err("eab: payload JWK does not match account JWK".to_string());
    }

    let signing_input = format!("{protected}.{payload}");
    let sig = B64
        .decode(signature.as_bytes())
        .map_err(|_| "eab: signature not base64url".to_string())?;
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&key_bytes)
        .map_err(|_| "eab: hmac key length".to_string())?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&sig)
        .map_err(|_| "eab: signature verify failed".to_string())?;
    Ok(key)
}

/// Equal modulo presentation: serialize each via the canonical
/// thumbprint pre-image. RFC 7638's canonical JSON form is what we
/// need — same fields, lex order, no whitespace. We get it for free
/// by recomputing the thumbprint of each side and comparing those.
fn jwks_equal(a: &Value, b: &Value) -> bool {
    match (
        super::jws::jwk_thumbprint(a),
        super::jws::jwk_thumbprint(b),
    ) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

#[allow(dead_code)]
fn _silence() {
    let _ = json!(null);
    let _: HashMap<String, String> = HashMap::new();
    let _ = Arc::new(());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HMAC sign + verify a hand-built EAB envelope against a JWK
    /// and confirm `verify_eab` walks the full happy path.
    #[test]
    fn eab_round_trip_hs256() {
        use hmac::digest::KeyInit;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        // Pre-shared HMAC key + the account JWK the client will
        // register with.
        let key = [42u8; 32];
        let key_b64 = B64.encode(key);
        let account_jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        });
        let kid = "eab-key-001";
        let inner_protected = json!({
            "alg": "HS256",
            "kid": kid,
            "url": "https://vault.example/v1/pki/acme/new-account",
        });
        let protected_b64 = B64.encode(serde_json::to_vec(&inner_protected).unwrap());
        let payload_b64 = B64.encode(serde_json::to_vec(&account_jwk).unwrap());
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&key).unwrap();
        mac.update(signing_input.as_bytes());
        let sig = B64.encode(mac.finalize().into_bytes());
        let envelope = json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig,
        });

        let stored = EabKey {
            key_id: kid.to_string(),
            key_b64,
            comment: String::new(),
            created_at_unix: 0,
            consumed: false,
        };
        let r = verify_eab(&envelope, &account_jwk, "new-account", |k| {
            assert_eq!(k, kid);
            Some(stored.clone())
        });
        assert!(r.is_ok(), "eab verify failed: {:?}", r.err());
    }

    #[test]
    fn eab_rejects_consumed_key() {
        let stored = EabKey {
            key_id: "x".into(),
            key_b64: B64.encode([0u8; 32]),
            comment: String::new(),
            created_at_unix: 0,
            consumed: true,
        };
        // We don't even need a real signature — the consumed-check
        // fires before HMAC verification.
        let envelope = json!({
            "protected": B64.encode(b"{\"alg\":\"HS256\",\"kid\":\"x\",\"url\":\"https://x/v1/pki/acme/new-account\"}"),
            "payload": B64.encode(b"{}"),
            "signature": B64.encode([0u8; 32]),
        });
        let r = verify_eab(&envelope, &json!({}), "new-account", |_| {
            Some(stored.clone())
        });
        assert!(r.is_err());
        assert!(format!("{}", r.err().unwrap()).contains("consumed"));
    }
}
