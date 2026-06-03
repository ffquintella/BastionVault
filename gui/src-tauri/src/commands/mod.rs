use bv_client::{JsonResponse, Operation};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

/// Shared dispatch path for all logical commands. Routes through the
/// `bv_client::Backend` trait object held in `AppState::backend`,
/// which is populated at connect / open time with either an
/// `EmbeddedBackend` (in-process `Core`) or a `RemoteBackend` (HTTP).
///
/// Replaces the per-file `make_request` helpers that each used to
/// reach into `state.vault` directly. Reads the active token out of
/// `AppState::token`; for flows that need a different token (e.g.
/// `login_token` validating a user-supplied token, or `/login`
/// endpoints that take no token), use [`dispatch_with_token`].
pub async fn make_request(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> CmdResult<Option<JsonResponse>> {
    let token = state.token.lock().await.clone().unwrap_or_default();
    dispatch_with_token(state, operation, path, body, &token).await
}

/// Variant of [`make_request`] that takes an explicit token instead
/// of reading `AppState::token`. Used by login flows that either need
/// to validate a user-supplied token (`auth/token/lookup-self`) or
/// call a `/login` endpoint with no token at all.
pub async fn dispatch_with_token(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
    token: &str,
) -> CmdResult<Option<JsonResponse>> {
    let backend_guard = state.backend.lock().await;
    let backend = backend_guard
        .as_ref()
        .ok_or("No vault open or remote server connected")?
        .clone();
    drop(backend_guard);

    backend
        .handle(operation, &path, body, token)
        .await
        .map_err(CommandError::from)
}

pub mod approle;
pub mod asset_groups;
pub mod backup;
pub mod capabilities;
pub mod ferrogate;
pub mod cert_lifecycle;
pub mod cloud_target;
pub mod connect;
pub mod oidc;
pub mod vaults;
pub mod sharing;
pub mod auth;
pub mod fido2;
pub mod fido2_native;
pub mod files;
pub mod groups;
pub mod ldap;
pub mod connection;
pub mod exchange;
pub mod pki;
pub mod plugins;
pub mod plugin_surface;
pub mod scheduled_exports;
pub mod policies;
pub mod resources;
pub mod rustion;
pub mod secrets;
pub mod ssh;
pub mod sso_admin;
pub mod totp;
pub mod system;
pub mod users;
pub mod yubikey;
