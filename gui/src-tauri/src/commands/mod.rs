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
/// reach into `state.vault` directly; once every command file has
/// been migrated to call this, the legacy `state.vault` field can go.
pub async fn make_request(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> CmdResult<Option<JsonResponse>> {
    let backend_guard = state.backend.lock().await;
    let backend = backend_guard
        .as_ref()
        .ok_or("No vault open or remote server connected")?
        .clone();
    drop(backend_guard);

    let token = state.token.lock().await.clone().unwrap_or_default();

    backend
        .handle(operation, &path, body, &token)
        .await
        .map_err(CommandError::from)
}

pub mod approle;
pub mod asset_groups;
pub mod backup;
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
pub mod scheduled_exports;
pub mod policies;
pub mod resources;
pub mod secrets;
pub mod ssh;
pub mod sso_admin;
pub mod totp;
pub mod system;
pub mod users;
pub mod yubikey;
