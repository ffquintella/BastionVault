//! The trait the GUI command layer dispatches through. Two
//! implementations exist:
//!
//! * [`crate::RemoteBackend`] — speaks the BastionVault HTTP API.
//!   Lives in this crate, no `bastion_vault` deps.
//! * `EmbeddedBackend` — wraps `bastion_vault::core::Core` and calls
//!   `handle_request` directly. Lives in the GUI behind the
//!   `embedded_vault` feature.
//!
//! Keeping the trait JSON-only (no server types in the signature)
//! is what lets the GUI compile without `bastion_vault` when
//! `embedded_vault` is off.

use async_trait::async_trait;
use bv_plugin_surface::ActiveSurfaceBundle;
use serde_json::{Map, Value};

use crate::{error::ClientError, types::{JsonResponse, Operation}};

/// Dispatches a logical request and returns the engine's response.
///
/// `Ok(None)` mirrors the server's "204 No Content" / "no response
/// payload" case — the GUI commands already pattern-match on this
/// (`Some(r) => ...`, `None => ...`).
#[async_trait]
pub trait Backend: Send + Sync {
    async fn handle(
        &self,
        operation: Operation,
        path: &str,
        body: Option<Map<String, Value>>,
        token: &str,
    ) -> Result<Option<JsonResponse>, ClientError>;

    /// Plugin Extensibility v1 — fetch the aggregated active-surface
    /// bundle. Implementations supply `etag` (from a prior fetch) so
    /// the server can return [`SurfaceFetch::NotModified`] cheaply.
    /// Default impl returns an empty bundle so backends that haven't
    /// wired surface support yet (older `EmbeddedBackend` builds, an
    /// in-memory test stub) keep compiling.
    async fn active_surfaces(
        &self,
        _token: &str,
        _etag: Option<&str>,
    ) -> Result<SurfaceFetch, ClientError> {
        Ok(SurfaceFetch::Bundle(ActiveSurfaceBundle {
            etag: String::new(),
            entries: Vec::new(),
        }))
    }

    /// Plugin Extensibility v1 / Phase 5 — long-poll variant of
    /// `active_surfaces`. The remote server upgrades to a `?watch=1`
    /// request that returns when the aggregate ETag changes (or
    /// after a 30 s timeout). Backends without long-poll support
    /// fall through to the default impl, which is the regular
    /// `active_surfaces` so callers degrade to short-poll behaviour
    /// rather than hanging.
    async fn watch_active_surfaces(
        &self,
        token: &str,
        etag: Option<&str>,
    ) -> Result<SurfaceFetch, ClientError> {
        self.active_surfaces(token, etag).await
    }

    /// Plugin Extensibility v1 — download a single client asset by
    /// content hash. Returns the raw bytes; the caller is expected to
    /// re-verify the SHA-256 against the manifest declaration before
    /// instantiating the WASM. Default impl returns `Ok(None)` for
    /// the same reason as `active_surfaces`.
    async fn fetch_asset(
        &self,
        _plugin: &str,
        _version: &str,
        _sha256: &str,
        _token: &str,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        Ok(None)
    }
}

/// Result of an `active_surfaces` round-trip. The 304 case is its own
/// variant so the cache layer can short-circuit without re-reading
/// `ActiveSurfaceBundle::etag` to compare.
#[derive(Debug, Clone)]
pub enum SurfaceFetch {
    /// Server returned 200 with a fresh bundle.
    Bundle(ActiveSurfaceBundle),
    /// Server returned 304 Not Modified — the cached bundle the
    /// caller passed `etag` for is still authoritative.
    NotModified,
}
