//! `GET /v1/pki/acme/directory` and `HEAD /v1/pki/acme/new-nonce`.
//!
//! Both unauthenticated. The directory advertises every other ACME
//! endpoint as an absolute URL — clients use it as the entry point.
//! `new-nonce` returns no body but sets a fresh `Replay-Nonce`
//! header that the client folds into its next signed request.

use std::{collections::HashMap, sync::Arc};

use serde_json::{Map, Value};

use super::{
    new_nonce,
    storage::{AcmeConfig, NonceRing, NONCE_KEY},
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Operation, Path, PathOperation, Request, Response},
    new_path, new_path_internal,
    storage::StorageEntry,
};

use super::super::{PkiBackend, PkiBackendInner};

const DIRECTORY_HELP: &str = "RFC 8555 §7.1.1 — ACME directory listing. Unauthenticated.";
const NEW_NONCE_HELP: &str = "RFC 8555 §7.2 — issue a fresh Replay-Nonce. Unauthenticated.";

impl PkiBackend {
    pub fn acme_directory_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/directory$",
            operations: [{op: Operation::Read, handler: h.handle_acme_directory}],
            help: DIRECTORY_HELP
        })
    }

    pub fn acme_new_nonce_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"acme/new-nonce$",
            operations: [{op: Operation::Read, handler: h.handle_acme_new_nonce}],
            help: NEW_NONCE_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn handle_acme_directory(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        if !cfg.enabled {
            return Err(RvError::ErrString("acme: not enabled on this mount".into()));
        }
        let base = directory_base(&cfg, req);
        let mut data = Map::new();
        data.insert("newNonce".into(), Value::String(format!("{base}/acme/new-nonce")));
        data.insert("newAccount".into(), Value::String(format!("{base}/acme/new-account")));
        data.insert("newOrder".into(), Value::String(format!("{base}/acme/new-order")));
        data.insert("revokeCert".into(), Value::String(format!("{base}/acme/revoke-cert")));
        data.insert("keyChange".into(), Value::String(format!("{base}/acme/key-change")));
        // RFC 8555 §7.1.1 also allows a `meta` object. We surface the
        // engine identity so an audit can spot which BastionVault built
        // a given cert chain at directory-fetch time.
        let mut meta = Map::new();
        meta.insert(
            "externalAccountRequired".into(),
            // EAB lands in Phase 6.2; surface the field today so a
            // forward-compatible client doesn't trip on its absence.
            Value::Bool(false),
        );
        meta.insert(
            "termsOfService".into(),
            Value::String(format!("{base}/acme/terms")),
        );
        data.insert("meta".into(), Value::Object(meta));

        // Replay-Nonce on the directory response too — RFC 8555 §6.5
        // says every response from the server includes a Replay-Nonce
        // header, not only `new-nonce`. Refresh on every call.
        let nonce = self.mint_nonce(req).await?;
        let mut headers = HashMap::new();
        headers.insert("Replay-Nonce".to_string(), nonce);
        headers.insert("Cache-Control".to_string(), "no-store".to_string());
        Ok(Some(Response {
            data: Some(data),
            headers: Some(headers),
            ..Default::default()
        }))
    }

    pub async fn handle_acme_new_nonce(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = self.load_acme_config(req).await?.unwrap_or_default();
        if !cfg.enabled {
            return Err(RvError::ErrString("acme: not enabled on this mount".into()));
        }
        let nonce = self.mint_nonce(req).await?;
        let mut headers = HashMap::new();
        headers.insert("Replay-Nonce".to_string(), nonce);
        headers.insert("Cache-Control".to_string(), "no-store".to_string());
        Ok(Some(Response {
            headers: Some(headers),
            ..Default::default()
        }))
    }

    /// Mint a fresh nonce, push it onto the ring buffer, persist the
    /// updated buffer, and return the nonce. Caller folds it into
    /// the response's `Replay-Nonce` header.
    pub async fn mint_nonce(&self, req: &mut Request) -> Result<String, RvError> {
        let nonce = new_nonce();
        let mut ring = self.load_nonce_ring(req).await?;
        ring.push(nonce.clone());
        self.save_nonce_ring(req, &ring).await?;
        Ok(nonce)
    }

    /// Consume a client-supplied nonce. Returns `Ok(true)` when the
    /// nonce was in the ring (and removes it); `Ok(false)` when it
    /// wasn't (replay or stale). RFC 8555 §6.5 says we must reject
    /// unrecognised nonces with `urn:ietf:params:acme:error:badNonce`
    /// — caller maps the bool to that error shape.
    pub async fn consume_nonce(&self, req: &mut Request, nonce: &str) -> Result<bool, RvError> {
        let mut ring = self.load_nonce_ring(req).await?;
        let ok = ring.consume(nonce);
        if ok {
            self.save_nonce_ring(req, &ring).await?;
        }
        Ok(ok)
    }

    pub async fn load_nonce_ring(&self, req: &Request) -> Result<NonceRing, RvError> {
        match req.storage_get(NONCE_KEY).await? {
            None => Ok(NonceRing::default()),
            Some(e) => Ok(serde_json::from_slice(&e.value).unwrap_or_default()),
        }
    }

    pub async fn save_nonce_ring(&self, req: &mut Request, ring: &NonceRing) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(ring)?;
        req.storage_put(&StorageEntry {
            key: NONCE_KEY.to_string(),
            value: bytes,
        })
        .await
    }
}

/// Compute the absolute URL prefix the directory advertises. We
/// honor `cfg.external_hostname` first; otherwise fall back to the
/// inbound request's `Host` header (folded onto `https://`).
fn directory_base(cfg: &AcmeConfig, req: &Request) -> String {
    if !cfg.external_hostname.trim().is_empty() {
        let host = cfg.external_hostname.trim().trim_end_matches('/');
        if host.starts_with("http://") || host.starts_with("https://") {
            format!("{host}/v1/pki")
        } else {
            format!("https://{host}/v1/pki")
        }
    } else {
        // Best-effort: read the `Host` header off the Request's
        // `headers` map (populated by the HTTP layer). When the
        // header is missing — e.g. an in-process call from tests —
        // default to a stable placeholder so the response still
        // parses; operators in production should pin
        // `external_hostname` to avoid this branch.
        let host = req
            .headers
            .as_ref()
            .and_then(|h| h.get("host").or_else(|| h.get("Host")))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "localhost:8200".to_string());
        format!("https://{host}/v1/pki")
    }
}
