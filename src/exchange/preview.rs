//! In-memory preview store.
//!
//! `POST /v1/sys/exchange/import/preview` decrypts the supplied file,
//! classifies every item against the destination vault, and stores the
//! parsed `ExchangeDocument` keyed by an opaque token. `POST /v1/sys/
//! exchange/import/apply` consumes the token, re-resolves the document,
//! and writes the items.
//!
//! The token store is **process-local** and **in-memory**. Tokens are:
//! - 256-bit random (URL-safe base64)
//! - single-use (consumed on apply)
//! - TTL'd (default 10 minutes)
//! - owner-bound (the apply call must come from the same actor display
//!   name that ran the preview)
//!
//! The store does *not* persist tokens to the barrier. A leader transition
//! or process restart drops in-flight previews; the operator must re-run
//! the preview. This is the right tradeoff: previews carry decrypted
//! plaintext and the smaller the persistence surface the better.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use dashmap::DashMap;
use rand::Rng;

use crate::errors::RvError;
use crate::exchange::schema::ExchangeDocument;
use crate::exchange::scope::ImportClassification;

pub const DEFAULT_PREVIEW_TTL: Duration = Duration::from_secs(600);
pub const TOKEN_BYTES: usize = 32;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PreviewClassificationItem {
    pub mount: String,
    pub path: String,
    pub classification: ImportClassification,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PreviewSummary {
    pub token: String,
    pub expires_in_secs: u64,
    pub total: u64,
    pub new: u64,
    pub identical: u64,
    pub conflict: u64,
    pub items: Vec<PreviewClassificationItem>,
}

struct StoredPreview {
    document: ExchangeDocument,
    owner: String,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct PreviewStore {
    inner: Arc<DashMap<String, StoredPreview>>,
    ttl: Duration,
}

impl Default for PreviewStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            ttl: DEFAULT_PREVIEW_TTL,
        }
    }
}

impl PreviewStore {
    pub fn new(ttl: Duration) -> Self {
        Self { inner: Arc::new(DashMap::new()), ttl }
    }

    /// Insert a parsed document and return a fresh single-use token.
    pub fn insert(&self, document: ExchangeDocument, owner: String) -> String {
        self.sweep_expired();
        let token = generate_token();
        self.inner.insert(
            token.clone(),
            StoredPreview {
                document,
                owner,
                expires_at: Instant::now() + self.ttl,
            },
        );
        token
    }

    /// Look up + remove a preview. Fails if the token is unknown, expired,
    /// or owned by a different actor.
    pub fn consume(&self, token: &str, owner: &str) -> Result<ExchangeDocument, RvError> {
        self.sweep_expired();
        let stored = self
            .inner
            .remove(token)
            .ok_or(RvError::ErrRequestInvalid)?
            .1;
        if stored.expires_at < Instant::now() {
            return Err(RvError::ErrRequestInvalid);
        }
        if stored.owner != owner {
            return Err(RvError::ErrPermissionDenied);
        }
        Ok(stored.document)
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl.as_secs()
    }

    fn sweep_expired(&self) {
        let now = Instant::now();
        self.inner.retain(|_, p| p.expires_at >= now);
    }
}

fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::schema::{ExchangeItems, ExporterInfo, ScopeKind, ScopeSpec};

    fn fake_doc() -> ExchangeDocument {
        ExchangeDocument::new(
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::Full, include: vec![] },
            ExchangeItems::default(),
        )
    }

    #[test]
    fn insert_then_consume_round_trip() {
        let store = PreviewStore::default();
        let tok = store.insert(fake_doc(), "alice".to_string());
        let doc = store.consume(&tok, "alice").unwrap();
        assert_eq!(doc.schema, "bvx.v1");
    }

    #[test]
    fn token_is_single_use() {
        let store = PreviewStore::default();
        let tok = store.insert(fake_doc(), "alice".to_string());
        let _ = store.consume(&tok, "alice").unwrap();
        assert!(store.consume(&tok, "alice").is_err());
    }

    #[test]
    fn other_actor_refused() {
        let store = PreviewStore::default();
        let tok = store.insert(fake_doc(), "alice".to_string());
        let err = store.consume(&tok, "mallory").unwrap_err();
        assert!(matches!(err, RvError::ErrPermissionDenied));
    }

    #[test]
    fn expired_token_refused() {
        let store = PreviewStore::new(Duration::from_millis(0));
        let tok = store.insert(fake_doc(), "alice".to_string());
        std::thread::sleep(Duration::from_millis(5));
        assert!(store.consume(&tok, "alice").is_err());
    }
}
