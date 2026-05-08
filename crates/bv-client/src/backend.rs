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
}
